"""Nodos del panel: dónde vive cada dato y qué nodo se está mirando.

Un nodo es un punto del orquestador (un MikroTik con su VPN y su Suricata), con id `p001`..`p999`.
El panel heredado de suricata-ids-lab ya sabía de varios MikroTik ("multi-nodo"): cada CPE se
identifica con `pid|ip`, así que dos nodos con la misma IP privada no se mezclan nunca.

Lo comparten dashboard.py y html_report.py: los dos leen y escriben los mismos ficheros.

- Eventos de un nodo (solo lectura, los escribe su Suricata): `DATOS/<pid>/eve.json*`, `dns.json*`.
- Salidas por nodo (report-*.html, cuarentena.json, métricas, historial...): `PANEL/nodos/<pid>/`.
  La vista acumulada ("Todos los nodos") tiene las suyas en `PANEL/nodos/_todos/`.
- Configuración y registros globales: `PANEL/conf`, `PANEL/estado`, `PANEL/log`, `PANEL/feeds`...

El nodo que se está mirando va en un contexto por hilo: el servidor lo pone en cada petición
(`?nodo=` o la sesión) y los hilos de fondo con `contexto(pid)` al recorrer los nodos.
"""

import contextlib
import glob
import json
import os
import re
import threading

PANEL = os.environ.get("IDS_PANEL_DIR", "/srv/ids/panel")
DATOS = os.environ.get("IDS_DATOS", "/srv/ids/datos")
RUN = os.environ.get("IDS_RUN", "/srv/ids/run")
SHARE = os.environ.get("IDS_SHARE", "/usr/local/share/ids-panel")

TODOS = "_todos"
RE_PID = re.compile(r"^p\d{3}$")
TZSP_PUERTO = 37008


def ruta(*partes):
    """Ruta dentro del directorio del panel (el único sitio donde el panel escribe)."""
    return os.path.join(PANEL, *partes)


CONF = ruta("conf")            # configuración (0600: lleva claves)
ESTADO = ruta("estado")        # registros JSON del panel
LOG = ruta("log")              # bitácoras de texto
FEEDS = ruta("feeds")          # feeds de reputación que baja el panel
GEO = ruta("geo")              # base GeoIP (se baja en ejecución)
CACHE = ruta("cache")          # cachés que se pueden perder (PTR/RDAP...)
RESPALDOS = ruta("respaldos")  # respaldos del firewall de los MikroTik
NODOS = ruta("nodos")          # salidas por nodo y la acumulada (_todos)
MAPA = os.path.join(SHARE, "mapa")


def asegurar_dirs():
    for d in (CONF, ESTADO, LOG, FEEDS, GEO, CACHE, RESPALDOS, NODOS):
        try:
            os.makedirs(d, mode=0o700, exist_ok=True)
        except OSError:
            pass


# --------------------------------------------------------------------------------------------
# Puntos que publica el orquestador
# --------------------------------------------------------------------------------------------
_EST = {"marca": None, "datos": {}}
_EST_LOCK = threading.Lock()


def leer_estado():
    """`RUN/estado.json` (lo reescribe el orquestador cada 15 s). Vacío si no existe."""
    p = os.path.join(RUN, "estado.json")
    try:
        st = os.stat(p)
        marca = (st.st_mtime_ns, st.st_size)
    except OSError:
        return {}
    with _EST_LOCK:
        if marca != _EST["marca"]:
            try:
                with open(p, encoding="utf-8") as f:
                    d = json.load(f)
                _EST["datos"] = d if isinstance(d, dict) else {}
            except (OSError, ValueError):
                return _EST["datos"]
            _EST["marca"] = marca
        return _EST["datos"]


def puntos():
    """Puntos existentes, ordenados por pid: [{pid, nombre, n, estado, deseado, redes,
    api_puerto, sensor, tzsp_puerto, ...}]. Lo que falte en estado.json va vacío."""
    ps = leer_estado().get("puntos") or {}
    salida = []
    for pid in sorted(ps):
        if not RE_PID.match(pid) or not isinstance(ps[pid], dict):
            continue
        d = dict(ps[pid])
        d["pid"] = pid
        d.setdefault("nombre", pid)
        d.setdefault("redes", [])
        d.setdefault("tzsp_puerto", TZSP_PUERTO)
        salida.append(d)
    return salida


def pids():
    return [p["pid"] for p in puntos()]


def punto(pid):
    for p in puntos():
        if p["pid"] == pid:
            return p
    return None


def pid_valido(pid):
    return isinstance(pid, str) and bool(RE_PID.match(pid))


def nombre(pid):
    if pid == TODOS:
        return "Todos los nodos"
    p = punto(pid)
    return (p or {}).get("nombre") or pid


# --------------------------------------------------------------------------------------------
# Contexto: qué nodo se mira
# --------------------------------------------------------------------------------------------
_CTX = threading.local()


def nodo_actual():
    """pid del nodo que se mira, o TODOS (la vista acumulada, también por defecto)."""
    return getattr(_CTX, "nodo", None) or TODOS


def poner_nodo(nodo):
    """Fija el nodo del hilo. Lo que no sea un pid válido es la vista acumulada."""
    _CTX.nodo = nodo if pid_valido(nodo) else TODOS
    return _CTX.nodo


@contextlib.contextmanager
def contexto(nodo):
    previo = getattr(_CTX, "nodo", None)
    poner_nodo(nodo)
    try:
        yield _CTX.nodo
    finally:
        _CTX.nodo = previo


def es_todos(nodo=None):
    return (nodo or nodo_actual()) == TODOS


def nodos_de(nodo=None):
    """Los pids que abarca un nodo: él mismo, o todos los puntos en la vista acumulada."""
    nodo = nodo or nodo_actual()
    return pids() if nodo == TODOS else [nodo]


# --------------------------------------------------------------------------------------------
# Rutas por nodo
# --------------------------------------------------------------------------------------------
def dir_eventos(pid):
    """Directorio de eventos de un punto (solo lectura)."""
    return os.path.join(DATOS, pid)


def eve_vivo(pid):
    return os.path.join(DATOS, pid, "eve.json")


def ficheros_eventos(nodo=None, patrones=("eve.json*", "dns.json*")):
    """[(pid, ruta)] de los ficheros de eventos del nodo (o de todos), vivos y rotados."""
    salida = []
    for pid in nodos_de(nodo):
        vistos = set()
        for pat in patrones:
            for f in glob.glob(os.path.join(DATOS, pid, pat)):
                if f not in vistos:
                    vistos.add(f)
                    salida.append((pid, f))
    return salida


def dir_salida(nodo=None, crear=True):
    """Salidas del nodo (o de la vista acumulada): report-*.html, cuarentena.json..."""
    d = os.path.join(NODOS, nodo or nodo_actual())
    if crear:
        try:
            os.makedirs(d, mode=0o700, exist_ok=True)
        except OSError:
            pass
    return d


def salida(nombre_fichero, nodo=None):
    return os.path.join(dir_salida(nodo), nombre_fichero)


def api_sock(pid):
    """Relé del API-SSL del MikroTik de ese punto (socat en su contenedor vpn)."""
    return os.path.join(RUN, pid, "api.sock")


def tzsp_json(pid):
    return os.path.join(RUN, pid, "tzsp.json")


def clave(pid, ip):
    """Identidad de un CPE: SIEMPRE `pid|ip`, aunque haya un solo punto."""
    return "%s|%s" % (pid, ip)
