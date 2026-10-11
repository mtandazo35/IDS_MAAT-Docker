"""ids-panel servir | crear-admin --usuario U | restablecer --usuario U | salud

El panel es el dashboard de suricata-ids-lab (`dashboard.py`, junto a este paquete). Los
usuarios van en el formato del dashboard (lista con PBKDF2) en `conf/usuarios.json`; este
CLI escribe ESE formato, con rol `admin`, para que el instalador y `ids-orq panel …` sigan
igual (CONTRATO-F2 §7).

Códigos de salida:
  crear-admin   0 creado (stdout: UNA línea CLAVE=<clave>), 3 el usuario ya existe (no se toca nada)
  restablecer   0 hecho (stdout: CLAVE=<clave>), 4 el usuario no existe. Expulsa sus sesiones
                abiertas (la sesión guarda una marca del hash de la clave, que cambia).
  salud         0 si HEAD / al propio servidor da 200, 1 si no
  2             argumentos o configuración no válidos
"""

import argparse
import os
import re
import secrets
import string
import sys
import time
import http.client

RE_USUARIO = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
LARGO_GENERADA = 20
ALFABETO = string.ascii_letters + string.digits


def _err(msg):
    print("ids-panel: " + msg, file=sys.stderr, flush=True)


def _parser():
    ap = argparse.ArgumentParser(prog="ids-panel", description="Panel web de IDS_MAAT-Docker")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("servir", help="servidor HTTP (por defecto)")
    x = sub.add_parser("crear-admin", help="crea el usuario (rol admin) con una clave aleatoria")
    x.add_argument("--usuario", default="admin")
    x = sub.add_parser("restablecer", help="da una clave aleatoria nueva a un usuario y expulsa sus sesiones")
    x.add_argument("--usuario", required=True)
    sub.add_parser("salud", help="comprobación para el healthcheck")
    return ap


def nueva_clave(largo=LARGO_GENERADA):
    return "".join(secrets.choice(ALFABETO) for _ in range(largo))


def _dash():
    """El módulo del panel (mismo almacén de usuarios y mismo hash que usa la web)."""
    import dashboard
    return dashboard


def _puerto(env=None):
    env = os.environ if env is None else env
    try:
        p = int(env.get("IDS_PUERTO") or 5637)
    except ValueError:
        raise ValueError("IDS_PUERTO debe ser un número")
    if not 1 <= p <= 65535:
        raise ValueError("IDS_PUERTO fuera de rango")
    return p


def crear_admin(usuario, dash=None):
    if not isinstance(usuario, str) or not RE_USUARIO.match(usuario):
        _err("usuario inválido: minúsculas, números, . _ - (máx. 32)")
        return 2
    d = dash or _dash()
    d.nodos.asegurar_dirs()
    with d._USR_LOCK:
        lst = d.cargar_usuarios()
        if any(r.get("user") == usuario for r in lst):
            _err("el usuario %s ya existe; no se ha tocado nada (para una clave nueva: "
                 "ids-panel restablecer --usuario %s)" % (usuario, usuario))
            return 3
        clave = nueva_clave()
        salt, h = d._hash_pw(clave)
        lst.append({"user": usuario, "salt": salt, "hash": h, "role": "admin", "nombre": "",
                    "correo": "", "activo": True, "clave_temporal": True, "creado": int(time.time())})
        d.guardar_usuarios(lst)
    print("CLAVE=%s" % clave, flush=True)
    return 0


def restablecer(usuario, dash=None):
    if not isinstance(usuario, str) or not RE_USUARIO.match(usuario):
        _err("usuario inválido: minúsculas, números, . _ - (máx. 32)")
        return 2
    d = dash or _dash()
    with d._USR_LOCK:
        lst = d.cargar_usuarios()
        r = next((x for x in lst if x.get("user") == usuario), None)
        if r is None:
            _err("el usuario %s no existe" % usuario)
            return 4
        clave = nueva_clave()
        r["salt"], r["hash"] = d._hash_pw(clave)
        r["activo"] = True                  # sirve también para recuperar un admin desactivado
        r["clave_temporal"] = True
        r["cambiado"] = int(time.time())
        d.guardar_usuarios(lst)
    # la marca del hash ya no coincide: las sesiones abiertas de ese usuario dejan de valer
    # también en el servidor que está corriendo (otro proceso). Aquí se borran de disco.
    try:
        d.SESSIONS.update(d._cargar_sesiones())
        d.sesiones_cerrar_usuario(usuario)
    except Exception:
        pass
    print("CLAVE=%s" % clave, flush=True)
    return 0


def salud(puerto, timeout=5):
    puerto = getattr(puerto, "puerto", puerto)     # tambien un objeto con .puerto (Config del F1b)
    try:
        c = http.client.HTTPConnection("127.0.0.1", puerto, timeout=timeout)
        try:
            c.request("HEAD", "/")
            return 0 if c.getresponse().status == 200 else 1
        finally:
            c.close()
    except Exception:  # noqa: BLE001 - cualquier fallo = no sano
        return 1


def servir():
    return _dash().main()


def main(argv=None):
    a = _parser().parse_args(argv)
    try:
        puerto = _puerto()
    except ValueError as e:
        _err(str(e))
        return 2
    cmd = a.cmd or "servir"
    if cmd == "crear-admin":
        return crear_admin(a.usuario)
    if cmd == "restablecer":
        return restablecer(a.usuario)
    if cmd == "salud":
        return salud(puerto)
    return servir()
