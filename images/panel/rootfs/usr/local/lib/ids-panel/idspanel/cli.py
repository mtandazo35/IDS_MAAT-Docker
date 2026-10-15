"""ids-panel servir | crear-admin --usuario U | restablecer --usuario U | confianza … | salud

El panel es el dashboard de suricata-ids-lab (`dashboard.py`, junto a este paquete). Los
usuarios van en el formato del dashboard (lista con PBKDF2) en `conf/usuarios.json`; este
CLI escribe ESE formato, con rol `admin`, para que el instalador y `ids-orq panel …` sigan
igual (CONTRATO-F2 §7).

Códigos de salida:
  crear-admin   0 creado (stdout: UNA línea CLAVE=<clave>), 3 si ya hay usuarios (no se toca nada:
                el primer admin solo se crea una vez; los demás, desde Ajustes o con restablecer)
  restablecer   0 hecho (stdout: CLAVE=<clave>), 4 el usuario no existe. Expulsa sus sesiones
                abiertas (la sesión guarda una marca del hash de la clave, que cambia).
  confianza     IPs de confianza del panel, para volver a entrar si te quedas fuera (p. ej. te
                cambio la IP): `ver`, `agregar <IP|rango> [--nota N]` (sin abrir el panel a nadie
                mas) o `vaciar` (lo deja abierto, con bloqueo por fallos, y guarda una copia de la
                lista). 0 hecho o ya estaba, 2 IP o rango no valido. Hace efecto al momento: el
                panel relee la lista en cada peticion.
  salud         0 si HEAD / al propio servidor da 200, 1 si no
  2             argumentos o configuración no válidos
"""

import argparse
import json
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
    x = sub.add_parser("confianza", help="IPs de confianza del panel (para volver a entrar si te quedas fuera)")
    xs = x.add_subparsers(dest="accion", required=True)
    xs.add_parser("ver", help="muestra la lista")
    xa = xs.add_parser("agregar", help="deja entrar una IP o rango sin abrir el panel a nadie más")
    xa.add_argument("red")
    xa.add_argument("--nota", default="")
    xs.add_parser("vaciar", help="vacía la lista: el panel queda abierto (con bloqueo por fallos)")
    sub.add_parser("salud", help="comprobación para el healthcheck")
    return ap


def nueva_clave(largo=LARGO_GENERADA):
    return "".join(secrets.choice(ALFABETO) for _ in range(largo))


def _dash():
    """El módulo del panel (mismo almacén de usuarios y mismo hash que usa la web), con la zona
    de la empresa (IDS_TZ) ya puesta en este proceso, como hace el panel al arrancar: el
    contenedor corre en UTC y, sin ella, la bitácora y el nombre de las copias salían en UTC,
    mezclados con las líneas del panel en hora local. Es la misma función del panel, no una
    copia (también cae en UTC-5 fijo sin tzdata). `salud` no carga el panel: no escribe nada."""
    import dashboard
    dashboard._aplicar_tz()
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


def _cerrojo(d):
    """Cerrojo de usuarios.json compartido con el panel, que corre en otro proceso (flock;
    auditoría B-22). Con un módulo sin él (dobles de las pruebas), el del proceso."""
    c = getattr(d, "usuarios_cerrojo", None)
    return c() if c is not None else d._USR_LOCK


def crear_admin(usuario, dash=None, solo_primero=False):
    """Crea `usuario` con rol admin. Con `solo_primero` (lo que hace `ids-panel crear-admin`,
    CONTRATO-F2 §7) sale con 3 si ya hay CUALQUIER usuario, no solo ese (auditoría B-20)."""
    if not isinstance(usuario, str) or not RE_USUARIO.match(usuario):
        _err("usuario inválido: minúsculas, números, . _ - (máx. 32)")
        return 2
    d = dash or _dash()
    d.nodos.asegurar_dirs()
    with _cerrojo(d):
        lst = d.cargar_usuarios()
        if solo_primero and lst:
            _err("ya hay usuarios en el panel; no se ha tocado nada (para una clave nueva: "
                 "ids-panel restablecer --usuario <usuario>)")
            return 3
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
    with _cerrojo(d):
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


def confianza(accion, red=None, nota="", dash=None):
    """`ids-panel confianza ver|agregar|vaciar`: el rescate cuando la lista de IPs de confianza
    deja fuera al administrador. Usa las mismas funciones que la web (formato, normalización)."""
    d = dash or _dash()
    det = d.cargar_confianza_det()
    if accion == "ver":
        if not det:
            print("(vacía: el panel está abierto a cualquiera, con bloqueo tras %d fallos)" % d.LOGIN_MAX, flush=True)
        for e in det:
            print(e["red"] + ("  # " + e["nota"] if e["nota"] else ""), flush=True)
        return 0
    d.nodos.asegurar_dirs()
    if accion == "vaciar":
        if not det:
            print("YA la lista ya estaba vacía: el panel está abierto", flush=True)
            return 0
        copia = "%s.%s.antes-de-vaciar" % (d.TRUST_FILE, time.strftime("%Y%m%dT%H%M%S"))
        with open(copia, "w", encoding="utf-8") as f:
            json.dump(det, f, ensure_ascii=False)
        os.chmod(copia, 0o600)
        d.guardar_confianza([])
        d.bitacora("CONFIANZA-VACIADA", "%d entradas (copia %s)" % (len(det), os.path.basename(copia)),
                   quien="ids-panel", ip="")
        print("OK lista vaciada (%d entradas; copia en %s): el panel queda abierto, con bloqueo tras %d fallos"
              % (len(det), copia, d.LOGIN_MAX), flush=True)
        return 0
    try:
        val = d.normalizar_red(red)
    except ValueError as e:
        _err(str(e))
        return 2
    nota = " ".join((nota or "").split())[:d.CONF_NOTA_MAX]
    ya = d.red_cubierta_por(val, [e["red"] for e in det])
    if ya:
        print("YA %s ya puede entrar%s" % (val, "" if ya == val else " (la cubre %s)" % ya), flush=True)
        return 0
    d.guardar_confianza(det + [{"red": val, "nota": nota}])
    d.bitacora("CONFIANZA-AGREGADA", val + (" (%s)" % nota if nota else ""), quien="ids-panel", ip="")
    print("OK agregada %s: ya se puede entrar al panel desde ahí" % val, flush=True)
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
        return crear_admin(a.usuario, solo_primero=True)
    if cmd == "restablecer":
        return restablecer(a.usuario)
    if cmd == "confianza":
        return confianza(a.accion, getattr(a, "red", None), getattr(a, "nota", ""))
    if cmd == "salud":
        return salud(puerto)
    return servir()
