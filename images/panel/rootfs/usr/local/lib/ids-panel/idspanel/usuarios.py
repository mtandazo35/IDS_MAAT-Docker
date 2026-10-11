"""Usuarios del panel: /srv/ids/panel/usuarios.json (0600).

Solo se guarda el hash PBKDF2-SHA256 (600 000 iteraciones) con su sal en hex; nunca la clave.
Formato (v1):

  {"v": 1, "usuarios": {"admin": {"alg": "pbkdf2_sha256", "iter": 600000, "sal": "<32 hex>",
     "hash": "<64 hex>", "sello": "<16 hex>", "clave_temporal": true,
     "creado": 1760090000, "cambiado": 1760090000}}}

- `iter` va por usuario: si se sube ITERACIONES, el hash se rehace al entrar (transparente).
- `sello` cambia con cada cambio o restablecimiento de clave: invalida todas las sesiones del
  usuario, también las de un servidor que no se ha enterado (el CLI corre en otro proceso).
- `clave_temporal`: la clave la generó el sistema (crear-admin/restablecer); el panel invita a
  cambiarla, sin obligar.
"""

import hashlib
import hmac
import os
import re
import secrets
import string
import threading
import time

from . import util

ALG = "pbkdf2_sha256"
ITERACIONES = 600_000
LARGO_GENERADA = 20
MIN_CLAVE = 12
MAX_CLAVE = 256
RE_USUARIO = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
ALFABETO = string.ascii_letters + string.digits


class ErrorUsuarios(Exception):
    pass


class UsuarioExiste(ErrorUsuarios):
    pass


class UsuarioNoExiste(ErrorUsuarios):
    pass


class ClaveNoValida(ErrorUsuarios):
    pass


def nueva_clave(largo=LARGO_GENERADA):
    return "".join(secrets.choice(ALFABETO) for _ in range(largo))


def hash_clave(clave, sal=None, iteraciones=None):
    iteraciones = iteraciones or ITERACIONES
    sal = sal or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", clave.encode("utf-8"), bytes.fromhex(sal), iteraciones).hex()
    return {"alg": ALG, "iter": iteraciones, "sal": sal, "hash": h}


def verificar(reg, clave):
    try:
        if reg.get("alg") != ALG:
            return False
        calc = hashlib.pbkdf2_hmac("sha256", clave.encode("utf-8"), bytes.fromhex(reg["sal"]),
                                   int(reg["iter"])).hex()
    except (KeyError, ValueError, TypeError, AttributeError):
        return False
    return hmac.compare_digest(calc, str(reg.get("hash", "")))


_FALSO = None


def _hash_falso():
    """Hash de relleno: un usuario que no existe tarda lo mismo que una clave mala."""
    global _FALSO
    if _FALSO is None or _FALSO["iter"] != ITERACIONES:
        _FALSO = hash_clave(secrets.token_hex(16))
    return _FALSO


def validar_usuario(nombre):
    if not isinstance(nombre, str) or not RE_USUARIO.match(nombre):
        raise ErrorUsuarios("usuario inválido: minúsculas, números, . _ - (máx. 32)")
    return nombre


def validar_clave_nueva(clave, usuario=None):
    if not isinstance(clave, str) or len(clave) < MIN_CLAVE:
        raise ClaveNoValida("la clave nueva debe tener al menos %d caracteres" % MIN_CLAVE)
    if len(clave) > MAX_CLAVE:
        raise ClaveNoValida("la clave nueva es demasiado larga (máx. %d)" % MAX_CLAVE)
    if usuario and clave.lower() == usuario.lower():
        raise ClaveNoValida("la clave no puede ser el nombre de usuario")
    if any(ord(c) < 32 for c in clave):
        raise ClaveNoValida("la clave tiene caracteres de control")


class Usuarios:
    """Almacén de usuarios. Relee el fichero si cambia (lo puede tocar el CLI en otro proceso)."""

    def __init__(self, path, reloj=time.time):
        self.path = path
        self.reloj = reloj
        self._lock = threading.RLock()
        self._cache = None
        self._marca = None

    # ---- lectura ------------------------------------------------------------------------------
    def _leer(self):
        try:
            st = os.stat(self.path)
            marca = (st.st_mtime_ns, st.st_size, getattr(st, "st_ino", 0))
        except OSError:
            return {"v": 1, "usuarios": {}}
        # La marca no basta si el fichero cambio hace muy poco: `ids-panel restablecer` lo reescribe
        # desde otro proceso con el mismo tamano y, con un reloj de poca resolucion, el mismo mtime.
        # Un cambio de los ultimos 2 s se relee siempre (es barato: el fichero es pequeno).
        reciente = (time.time_ns() - marca[0]) < 2_000_000_000
        if self._cache is not None and marca == self._marca and not reciente:
            return self._cache
        d = util.leer_json(self.path)
        if not isinstance(d, dict) or not isinstance(d.get("usuarios"), dict):
            d = {"v": 1, "usuarios": {}}
        self._cache, self._marca = d, marca
        return d

    def existe_fichero(self):
        return os.path.exists(self.path)

    def obtener(self, usuario):
        with self._lock:
            reg = self._leer()["usuarios"].get(usuario)
            return dict(reg) if isinstance(reg, dict) else None

    def nombres(self):
        with self._lock:
            return sorted(self._leer()["usuarios"])

    def _guardar(self, d):
        util.escribir_json(self.path, d, modo=0o600)
        self._cache, self._marca = None, None

    # ---- altas y claves -----------------------------------------------------------------------
    def crear(self, usuario, clave=None):
        """Crea el usuario con una clave aleatoria (o la dada). Devuelve la clave en claro."""
        validar_usuario(usuario)
        with self._lock:
            d = self._leer()
            d = {"v": 1, "usuarios": dict(d["usuarios"])}
            if usuario in d["usuarios"]:
                raise UsuarioExiste(usuario)
            clave = clave or nueva_clave()
            t = int(self.reloj())
            reg = hash_clave(clave)
            reg.update({"sello": secrets.token_hex(8), "clave_temporal": True, "creado": t, "cambiado": t})
            d["usuarios"][usuario] = reg
            self._guardar(d)
            return clave

    def restablecer(self, usuario):
        with self._lock:
            d = self._leer()
            if usuario not in d["usuarios"]:
                raise UsuarioNoExiste(usuario)
            clave = nueva_clave()
            self._poner_clave(d, usuario, clave, temporal=True)
            return clave

    def _poner_clave(self, d, usuario, clave, temporal):
        d = {"v": 1, "usuarios": dict(d["usuarios"])}
        reg = dict(d["usuarios"][usuario])
        reg.update(hash_clave(clave))
        reg.update({"sello": secrets.token_hex(8), "clave_temporal": temporal, "cambiado": int(self.reloj())})
        d["usuarios"][usuario] = reg
        self._guardar(d)

    def autenticar(self, usuario, clave):
        """Registro del usuario si la clave es correcta; None si no (mismo coste en los dos casos)."""
        if not isinstance(usuario, str) or not isinstance(clave, str) or len(clave) > MAX_CLAVE:
            verificar(_hash_falso(), "x")
            return None
        reg = self.obtener(usuario) if RE_USUARIO.match(usuario) else None
        if reg is None:
            verificar(_hash_falso(), clave)
            return None
        if not verificar(reg, clave):
            return None
        if int(reg.get("iter", 0)) < ITERACIONES:      # actualización transparente del coste
            with self._lock:
                d = self._leer()
                if usuario in d["usuarios"]:
                    nd = {"v": 1, "usuarios": dict(d["usuarios"])}
                    r2 = dict(nd["usuarios"][usuario])
                    r2.update(hash_clave(clave))
                    nd["usuarios"][usuario] = r2
                    self._guardar(nd)
                    reg = dict(r2)
        return reg

    def cambiar(self, usuario, actual, nueva):
        """Cambia la clave pidiendo la actual. Devuelve el sello nuevo."""
        validar_clave_nueva(nueva, usuario)
        with self._lock:
            reg = self.obtener(usuario)
            if reg is None:
                raise UsuarioNoExiste(usuario)
            if not verificar(reg, actual):
                raise ClaveNoValida("la clave actual no es correcta")
            if verificar(reg, nueva):
                raise ClaveNoValida("la clave nueva es igual a la actual")
            self._poner_clave(self._leer(), usuario, nueva, temporal=False)
            return self.obtener(usuario)["sello"]
