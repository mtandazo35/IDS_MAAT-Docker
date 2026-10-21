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

Reglas (CONTRATO-F2 §3.1): «Todos» solo se mira si se pide expresamente (`TODOS`); un nodo mal
formado o que no existe es un error, NUNCA se amplía a «Todos». Sin contexto puesto no hay nodo:
`nodo_actual()` falla en vez de suponer uno. El contexto solo decide qué se MIRA; el destino de una
acción sale de la propia operación (`pid|ip` o el pid del formulario), validado con `exigir_pid()`.
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
RE_PID = re.compile(r"\Ap[0-9]{3}\Z")   # ni "p001" con salto de linea final ni digitos no ASCII
TZSP_PUERTO = 37008


def ruta(*partes):
    """Ruta dentro del directorio del panel (el único sitio donde el panel escribe)."""
    return os.path.join(PANEL, *partes)


CONF = ruta("conf")            # configuración (0600: lleva claves)
ESTADO = ruta("estado")        # registros JSON del panel
LOG = ruta("log")              # bitácoras de texto
FEEDS = ruta("feeds")          # feeds de reputación que baja el panel
GEO = ruta("geo")              # base GeoIP renovada por el panel (manda sobre la de la imagen)
CACHE = ruta("cache")          # cachés que se pueden perder (PTR/RDAP...)
RESPALDOS = ruta("respaldos")  # respaldos del firewall de los MikroTik
NODOS = ruta("nodos")          # salidas por nodo y la acumulada (_todos)
MAPA = os.path.join(SHARE, "mapa")
GEO_IMAGEN = os.path.join(SHARE, "geo")   # base GeoIP que trae la imagen (geo_base.py imagen)


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


_PURG = {"marca": None, "pids": frozenset()}


def purgados():
    """pids que el panel ya dio de baja y purgo (ESTADO/bajas-purgadas.json, lo escribe el
    apartado Puntos). Los pid no se reutilizan."""
    p = os.path.join(ESTADO, "bajas-purgadas.json")
    try:
        st = os.stat(p)
        marca = (st.st_mtime_ns, st.st_size)
    except OSError:
        return frozenset()
    with _EST_LOCK:
        if marca != _PURG["marca"]:
            try:
                with open(p, encoding="utf-8") as f:
                    d = json.load(f)
                _PURG["pids"] = frozenset(k for k in d if RE_PID.match(k)) if isinstance(d, dict) else frozenset()
            except (OSError, ValueError):
                return _PURG["pids"]
            _PURG["marca"] = marca
        return _PURG["pids"]


def puntos():
    """Puntos existentes, ordenados por pid: [{pid, nombre, n, estado, deseado, redes,
    api_puerto, sensor, tzsp_puerto, ...}]. Lo que falte en estado.json va vacío. Un punto que
    el panel ya dio de baja no sale aunque estado.json aun lo liste unos segundos."""
    ps = leer_estado().get("puntos") or {}
    fuera = purgados()
    salida = []
    for pid in sorted(ps):
        if not RE_PID.match(pid) or not isinstance(ps[pid], dict) or pid in fuera:
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
    """Solo el FORMATO (p001..p999). Que exista lo dice `existe()`."""
    return isinstance(pid, str) and bool(RE_PID.match(pid))


def existe(pid):
    return pid_valido(pid) and pid in pids()


class NodoInvalido(ValueError):
    """Identificador de nodo mal formado: la petición se rechaza (400)."""


class NodoInexistente(LookupError):
    """Formato correcto pero ese punto no existe (o ya se dio de baja): 404."""


class SinContexto(RuntimeError):
    """Se pidió el nodo del hilo sin haberlo puesto: error de programación."""


def exigir_pid(pid):
    """Destino de una acción: un pid con formato válido y que existe. Nunca TODOS."""
    if not pid_valido(pid):
        raise NodoInvalido(pid)
    if pid not in pids():
        raise NodoInexistente(pid)
    return pid


def validar_nodo(nodo):
    """Lo que se puede MIRAR: TODOS (pedido expresamente) o un pid existente."""
    if nodo == TODOS:
        return TODOS
    return exigir_pid(nodo)


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
    """pid del nodo que se mira, o TODOS. Sin contexto puesto es un error (SinContexto)."""
    n = getattr(_CTX, "nodo", None)
    if n is None:
        raise SinContexto("no hay nodo en el contexto de este hilo")
    return n


def hay_nodo():
    return getattr(_CTX, "nodo", None) is not None


def poner_nodo(nodo):
    """Fija el nodo del hilo tras validarlo (NodoInvalido / NodoInexistente si no vale)."""
    _CTX.nodo = validar_nodo(nodo)
    return _CTX.nodo


def quitar_nodo():
    _CTX.nodo = None


@contextlib.contextmanager
def contexto(nodo):
    """Pone el nodo durante el bloque y deja el anterior al salir, también con excepción."""
    previo = getattr(_CTX, "nodo", None)
    try:
        poner_nodo(nodo)
        yield _CTX.nodo
    finally:
        _CTX.nodo = previo


def es_todos(nodo=None):
    return (nodo if nodo is not None else nodo_actual()) == TODOS


def nodos_de(nodo=None):
    """Los pids que abarca un nodo: él mismo (si existe), o todos en la vista acumulada."""
    nodo = validar_nodo(nodo if nodo is not None else nodo_actual())
    return pids() if nodo == TODOS else [nodo]


# --------------------------------------------------------------------------------------------
# Rutas por nodo
# --------------------------------------------------------------------------------------------
def _pid_ruta(pid):
    if not pid_valido(pid):                        # nunca una ruta con un id sin validar
        raise NodoInvalido(pid)
    return pid


def dir_eventos(pid):
    """Directorio de eventos de un punto (solo lectura)."""
    return os.path.join(DATOS, _pid_ruta(pid))


def eve_vivo(pid):
    return os.path.join(DATOS, _pid_ruta(pid), "eve.json")


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
    nodo = nodo if nodo is not None else nodo_actual()
    if nodo != TODOS and not pid_valido(nodo):     # nunca una ruta con un id sin validar
        raise NodoInvalido(nodo)
    d = os.path.join(NODOS, nodo)
    # solo se crea para la vista acumulada o un punto que existe: una tarea de fondo tardia no
    # resucita nodos/<pid> de un punto dado de baja (auditoria A-09)
    if crear and (nodo == TODOS or nodo in pids()):
        try:
            os.makedirs(d, mode=0o700, exist_ok=True)
        except OSError:
            pass
    return d


def salida(nombre_fichero, nodo=None):
    return os.path.join(dir_salida(nodo), nombre_fichero)


def api_sock(pid):
    """Relé del API-SSL del MikroTik de ese punto (socat en su contenedor vpn)."""
    return os.path.join(RUN, exigir_pid(pid), "api.sock")


def api_sock_claro(pid):
    """Relé fijo a la API normal (8728, sin SSL) del MikroTik de ese punto (socat en su contenedor
    vpn). Solo para entrar una vez y ponerle el certificado a la API-SSL; las imágenes vpn de antes
    no lo tienen."""
    return os.path.join(RUN, exigir_pid(pid), "api-claro.sock")


def tzsp_json(pid):
    return os.path.join(RUN, _pid_ruta(pid), "tzsp.json")


def clave(pid, ip):
    """Identidad de un CPE: SIEMPRE `pid|ip`, aunque haya un solo punto."""
    if not pid_valido(pid):
        raise NodoInvalido(pid)
    return "%s|%s" % (pid, ip)
