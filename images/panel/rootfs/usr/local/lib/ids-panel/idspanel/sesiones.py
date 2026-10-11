"""Sesiones del panel y freno de login.

Sesiones (PLAN-PANEL §12): token aleatorio de 256 bits en la cookie; en disco solo
sha256(token). 12 h absolutas y 2 h de inactividad; máximo 10 por usuario; cada sesión guarda el
`sello` del usuario y deja de valer cuando cambia (cambio o restablecimiento de clave).

Freno: 8 fallos en 10 min por IP real del cliente y también por usuario.
"""

import hashlib
import secrets
import threading
import time

from . import util

ABSOLUTA_S = 12 * 3600
INACTIVIDAD_S = 2 * 3600
MAX_POR_USUARIO = 10
GUARDAR_CADA_S = 60


def huella(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_csrf(token):
    """Token CSRF de la sesión, derivado del token de la cookie (no se guarda en ningún sitio)."""
    return hashlib.sha256(b"ids-panel-csrf\0" + token.encode("utf-8")).hexdigest()[:40]


class Sesiones:
    def __init__(self, path, reloj=time.time):
        self.path = path
        self.reloj = reloj
        self._lock = threading.RLock()
        self._s = {}
        self._guardado = 0.0
        d = util.leer_json(path, {})
        if isinstance(d, dict) and isinstance(d.get("sesiones"), dict):
            t = self.reloj()
            self._s = {k: v for k, v in d["sesiones"].items()
                       if isinstance(v, dict) and self._viva(v, t)}

    def _viva(self, s, t):
        return (t - s.get("creada", 0) < ABSOLUTA_S) and (t - s.get("ultima", 0) < INACTIVIDAD_S)

    def _guardar(self):
        try:
            util.escribir_json(self.path, {"v": 1, "sesiones": self._s}, modo=0o600)
            self._guardado = self.reloj()
        except OSError:
            pass

    def guardar(self):
        with self._lock:
            self._guardar()

    def crear(self, usuario, sello, ip):
        token = secrets.token_urlsafe(32)
        t = self.reloj()
        with self._lock:
            self._s = {k: v for k, v in self._s.items() if self._viva(v, t)}
            suyas = sorted((v["creada"], k) for k, v in self._s.items() if v.get("usuario") == usuario)
            while len(suyas) >= MAX_POR_USUARIO:
                _, k = suyas.pop(0)
                self._s.pop(k, None)
            self._s[huella(token)] = {"usuario": usuario, "sello": sello, "creada": t, "ultima": t,
                                      "ip": ip}
            self._guardar()
        return token

    def validar(self, token, usuarios):
        """La sesión (dict) si el token vale y el usuario sigue igual; si no, None."""
        if not token or len(token) > 128:
            return None
        k = huella(token)
        t = self.reloj()
        with self._lock:
            s = self._s.get(k)
            if s is None:
                return None
            reg = usuarios.obtener(s.get("usuario"))
            if not self._viva(s, t) or reg is None or reg.get("sello") != s.get("sello"):
                self._s.pop(k, None)
                self._guardar()
                return None
            s["ultima"] = t
            if t - self._guardado > GUARDAR_CADA_S:
                self._guardar()
            out = dict(s)
            out["clave_temporal"] = bool(reg.get("clave_temporal"))
            out["expira"] = min(s["creada"] + ABSOLUTA_S, t + INACTIVIDAD_S)
            return out

    def borrar(self, token):
        with self._lock:
            if self._s.pop(huella(token or ""), None) is not None:
                self._guardar()

    def borrar_usuario(self, usuario):
        with self._lock:
            antes = len(self._s)
            self._s = {k: v for k, v in self._s.items() if v.get("usuario") != usuario}
            if len(self._s) != antes:
                self._guardar()

    def cuantas(self, usuario=None):
        with self._lock:
            return sum(1 for v in self._s.values() if usuario is None or v.get("usuario") == usuario)


class Freno:
    """Fallos de login en una ventana deslizante, por clave ("ip:…" o "u:…")."""

    def __init__(self, max_fallos=8, ventana_s=600, reloj=time.time, max_claves=20000):
        self.max_fallos = max_fallos
        self.ventana_s = ventana_s
        self.reloj = reloj
        self.max_claves = max_claves
        self._f = {}
        self._lock = threading.Lock()

    def _podar(self, clave, t):
        v = [x for x in self._f.get(clave, ()) if t - x < self.ventana_s]
        if v:
            self._f[clave] = v
        else:
            self._f.pop(clave, None)
        return v

    def bloqueado(self, *claves):
        t = self.reloj()
        with self._lock:
            return any(len(self._podar(c, t)) >= self.max_fallos for c in claves)

    def fallo(self, *claves):
        t = self.reloj()
        with self._lock:
            if len(self._f) > self.max_claves:
                for c in list(self._f):
                    self._podar(c, t)
            for c in claves:
                self._f.setdefault(c, []).append(t)
                del self._f[c][:-(self.max_fallos * 4)]

    def limpiar(self, *claves):
        with self._lock:
            for c in claves:
                self._f.pop(c, None)
