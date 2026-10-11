"""ids-panel servir | crear-admin --usuario U | restablecer --usuario U | salud

Códigos de salida:
  crear-admin   0 creado (stdout: UNA línea CLAVE=<clave>), 3 el usuario ya existe (no se toca nada)
  restablecer   0 hecho (stdout: CLAVE=<clave>), 4 el usuario no existe
  salud         0 si GET http://127.0.0.1:<IDS_PUERTO>/salud da 200, 1 si no
  2             argumentos o configuración no válidos
"""

import argparse
import os
import signal
import sys
import threading
import urllib.request

from .config import Config, ErrorConfig
from .usuarios import ErrorUsuarios, UsuarioExiste, UsuarioNoExiste, Usuarios, validar_usuario


def _err(msg):
    print("ids-panel: " + msg, file=sys.stderr, flush=True)


def _parser():
    ap = argparse.ArgumentParser(prog="ids-panel", description="Panel web de IDS_MAAT-Docker")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("servir", help="servidor HTTP (por defecto)")
    x = sub.add_parser("crear-admin", help="crea el usuario con una clave aleatoria")
    x.add_argument("--usuario", default="admin")
    x = sub.add_parser("restablecer", help="da una clave aleatoria nueva a un usuario")
    x.add_argument("--usuario", required=True)
    sub.add_parser("salud", help="comprobación para el healthcheck")
    return ap


def crear_admin(cfg, usuario):
    try:
        validar_usuario(usuario)
    except ErrorUsuarios as e:
        _err(str(e))
        return 2
    os.makedirs(str(cfg.panel_dir), exist_ok=True)
    try:
        clave = Usuarios(str(cfg.usuarios_json)).crear(usuario)
    except UsuarioExiste:
        _err("el usuario %s ya existe; no se ha tocado nada (para una clave nueva: "
             "ids-panel restablecer --usuario %s)" % (usuario, usuario))
        return 3
    print("CLAVE=%s" % clave, flush=True)
    return 0


def restablecer(cfg, usuario):
    try:
        validar_usuario(usuario)
    except ErrorUsuarios as e:
        _err(str(e))
        return 2
    try:
        clave = Usuarios(str(cfg.usuarios_json)).restablecer(usuario)
    except UsuarioNoExiste:
        _err("el usuario %s no existe" % usuario)
        return 4
    print("CLAVE=%s" % clave, flush=True)
    return 0


def salud(cfg, timeout=5):
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/salud" % cfg.puerto, timeout=timeout) as r:
            return 0 if r.status == 200 else 1
    except Exception:  # noqa: BLE001 - cualquier fallo = no sano
        return 1


def servir(cfg):
    from .app import Panel, crear_servidor
    panel = Panel(cfg)
    if not panel.usuarios.nombres():
        _err("no hay usuarios: nadie puede entrar hasta crear uno con «ids-panel crear-admin --usuario admin»")
    srv = crear_servidor(panel)
    # la primera cuenta de alertas de 24 h lee hacia atrás el eve de cada punto: mejor ahora
    threading.Thread(target=panel.precalentar, daemon=True).start()

    def _fin(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _fin)
    _err("escuchando en %s:%d (proxies de confianza: %s)" % (
        cfg.escucha, cfg.puerto, ", ".join(str(p) for p in cfg.proxies) or "ninguno"))
    try:
        srv.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        panel.sesiones.guardar()
    return 0


def main(argv=None):
    a = _parser().parse_args(argv)
    try:
        cfg = Config.desde_entorno()
    except ErrorConfig as e:
        _err(str(e))
        return 2
    cmd = a.cmd or "servir"
    if cmd == "crear-admin":
        return crear_admin(cfg, a.usuario)
    if cmd == "restablecer":
        return restablecer(cfg, a.usuario)
    if cmd == "salud":
        return salud(cfg)
    return servir(cfg)
