"""Pagina Eventos: busqueda en los eve.json/dns.json de cada punto (sustituye al buscador de EveBox).

CONTRATO-F2 §9 y §10.5. Interfaz que usa dashboard.py (P registra las rutas, la pestana y el rol):

- `pagina(consulta, nodo) -> str`: cuerpo HTML (sin <html> ni barra) con el formulario GET de
  filtros, la tabla y la paginacion.
- `detalle(consulta, nodo) -> str`: cuerpo HTML con el JSON completo de un evento y el enlace
  para volver con los mismos filtros.

`consulta` son los parametros GET (un valor por clave) y `nodo` un pid existente o `nodos.TODOS`.

Como se lee (los eventos son de Suricata, append-only y casi ordenados por tiempo):

- Cada fichero (vivo o rotado, plano o `.gz`) es una FUENTE con una «cota»: la marca de tiempo
  maxima que le puede quedar por leer. Se lee siempre la fuente de cota mas alta, asi el
  resultado avanza de lo mas nuevo a lo mas viejo en todos los nodos a la vez.
- Los planos se leen HACIA ATRAS por bloques, empezando en el final de la ventana (que se busca
  por biseccion de `timestamp`, la idea de `abrir_desde` del generador). Los `.gz` no se pueden
  posicionar: se leen enteros, con tope de bytes descomprimidos por fichero.
- Se salta cualquier fichero que no solapa la ventana por su mtime (como `logs_de_la_ventana`).
- Antes de `json.loads` se prefiltra por subcadena (tipo, IP, puerto, SID) y por fecha.
- Se para en cuanto los 100+1 mas recientes estan garantizados (nada sin leer puede ser mas
  nuevo), o al llegar a un tope (bytes descomprimidos o tiempo): entonces la pagina dice que es
  PARCIAL y hasta que fecha y fichero llego, y solo enseña lo que esta garantizado.
- Paginacion por CURSOR: cada evento tiene la clave (marca en µs, pid, huella de la linea) y la
  pagina siguiente pide las claves menores que la ultima mostrada. Las lineas que se añaden al
  vivo entre paginas son mas nuevas que el cursor y no se cuelan; una linea que aparece en dos
  ficheros a la vez por una rotacion (eve.json.1 y eve.json.1.gz) tiene la misma clave y sale
  una sola vez.

Suricata escribe con varios hilos y las marcas no van perfectamente ordenadas en el fichero: se
admite un desorden de `DESORDEN_US` (60 s). Mas desorden que ese puede dejar fuera un evento.
"""

import calendar
import hashlib
import heapq
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import stat
import threading
import time
import zlib
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import nodos

RUTA = "/eventos"
RUTA_DETALLE = "/eventos/detalle"

POR_PAGINA = 100                   # por defecto
TAMANOS = (10, 20, 30, 40, 50, 100)  # lo que se puede elegir abajo, ademas de «todos»
TODOS_MAX = 2000                   # «todos» = hasta esto por pagina: el eve real tiene millones de
                                   # lineas y la busqueda ya tiene topes de bytes y de tiempo
TOPE_BYTES = 200 * 1024 * 1024     # bytes descomprimidos leidos por consulta (todas las fuentes)
TOPE_GZ = 150 * 1024 * 1024        # bytes descomprimidos por fichero .gz
TOPE_SEGUNDOS = 8.0                # tiempo por consulta
BLOQUE = 1 << 20                   # lectura hacia atras de los planos
MAX_LINEA = 1 << 20                # una linea mas larga se salta (y se cuenta)
DESORDEN_US = 60 * 1000000         # desorden admitido entre marcas de un mismo fichero
VENTANA_DEFECTO = 3600             # sin fechas: la ultima hora
CLAVE_HMAC = "eventos.hmac"        # secreto del panel para firmar las referencias del detalle
TOPE_MIEMBROS_GZ = 1000            # miembros gzip por fichero (logrotate escribe 1)
TROZO_GZ = 64 * 1024               # bytes comprimidos por lectura (el tiempo se mira entre trozos)
# disponible_desde() corre en cada carga de la pagina: topes pequeños por fichero y en total
DISP_COMPRIMIDOS = 1 << 20
DISP_MIEMBROS = 64
DISP_SEGUNDOS = 1.0
CONCURRENCIA = 2                   # busquedas/detalles a la vez (cada una: TOPE_BYTES y TOPE_SEGUNDOS)
ESPERA_OCUPADO = 2.0               # segundos que espera una consulta a que quede una plaza libre

TIPOS = (("alert", "Alertas"), ("dns", "DNS"), ("http", "HTTP"), ("tls", "TLS"),
         ("stats", "Estadisticas"), ("todos", "Todos"))
DIRS_IP = (("", "origen o destino"), ("src", "origen"), ("dst", "destino"))
CAMPOS_FILTRO = ("desde", "hasta", "tipo", "firma", "sev", "ip", "ipdir", "puerto", "pdir", "proto", "por")

# Nombres admitidos: eve.json, dns.json y sus rotados (eve.json.1, eve.json.1.gz,
# eve.json-20261011-1200.gz...). Cada separador va seguido de letras o numeros: ni "..", ni
# barras, ni nada que salga del directorio.
RE_FICHERO = re.compile(r"(eve|dns)\.json(?:[._-][A-Za-z0-9]{1,32}){0,8}")
RE_CURSOR = re.compile(r"(\d{1,19})(?:-(p\d{3})-([0-9a-f]{16}))?")
RE_HUELLA = re.compile(r"[0-9a-f]{16}")
RE_FIRMA = re.compile(r"[0-9a-f]{64}")
RE_PROTO = re.compile(r"[A-Za-z0-9-]{1,16}")
_RE_TS_LINEA = re.compile(rb'"timestamp"\s*:\s*"([^"]{10,40})"')
_RE_TS = re.compile(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:?\d\d)?")
_RE_FORM = re.compile(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d)(?::(\d\d))?")


class FiltroInvalido(ValueError):
    """Un filtro del formulario no vale: se dice cual y no se busca."""


class RefInvalida(ValueError):
    """Referencia de detalle manipulada o que ya no apunta a un evento: nunca se lee nada con
    ella. No caduca ni va ligada a la sesion: todos los roles ven todos los eventos (§10.2), asi
    que un enlace no da nada que el usuario no pueda buscar."""


class _Tope(Exception):
    """Se alcanzo el tope de bytes o de tiempo de la consulta."""


class _GzLimite(Exception):
    """Un .gz que pasa de un tope propio (miembros o bytes comprimidos): se omite con aviso."""


# --------------------------------------------------------------------------------------------
# .gz por trozos (sin GzipFile.readline, que no vuelve hasta tener una linea)
# --------------------------------------------------------------------------------------------
class _GzLector:
    """Lee un .gz (uno o varios miembros, con relleno de ceros como admite gzip) por trozos de
    TROZO_GZ con zlib. Al contrario que `GzipFile.readline`, que puede recorrer miles de
    miembros vacios o una cabecera FNAME de decenas de MB sin volver, aqui se llama a
    `comprobar(lector)` entre trozos (tiempo y bytes comprimidos de la consulta) y se cuentan
    los miembros y los bytes comprimidos. `readline(limite)` y `read(n)` como los de un fichero.
    Un final sin el cierre del miembro es EOFError (comprimido cortado), como en gzip."""

    def __init__(self, fh, comprobar=None, max_miembros=TOPE_MIEMBROS_GZ, max_comprimidos=None):
        self.fh = fh
        self.comprobar = comprobar
        self.max_miembros = max_miembros
        self.max_comprimidos = max_comprimidos
        self.d = None
        self.pend = b""
        self.fin = False
        self.miembros = 0
        self.comprimidos = 0
        self.buf = b""
        self.i = 0

    def _entrada(self):
        if self.pend:
            e, self.pend = self.pend, b""
            return e
        e = self.fh.read(TROZO_GZ)
        self.comprimidos += len(e)
        if self.max_comprimidos is not None and self.comprimidos > self.max_comprimidos:
            raise _GzLimite("mas de %d KB comprimidos" % (self.max_comprimidos // 1024))
        return e

    def _mas(self):
        """El siguiente trozo descomprimido (no vacio), o b"" al final."""
        while not self.fin:
            if self.comprobar is not None:
                self.comprobar(self)
            if self.d is None:
                e = self._entrada()
                if not e:
                    self.fin = True
                    break
                if self.miembros:
                    e = e.lstrip(b"\x00")       # relleno tras un miembro (lo admite gzip)
                    if not e:
                        continue
                self.miembros += 1
                if self.miembros > self.max_miembros:
                    raise _GzLimite("mas de %d miembros gzip" % self.max_miembros)
                self.d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            else:
                e = self.d.unconsumed_tail or self._entrada()
                if not e:
                    raise EOFError("comprimido cortado antes del final")
            out = self.d.decompress(e, BLOQUE)
            if self.d.eof:
                self.pend = self.d.unused_data
                self.d = None
            if out:
                return out
        return b""

    def readline(self, limite):
        while True:
            k = self.buf.find(b"\n", self.i, self.i + limite)
            if k >= 0:
                ln = self.buf[self.i:k + 1]
                self.i = k + 1
                return ln
            if len(self.buf) - self.i >= limite:
                ln = self.buf[self.i:self.i + limite]
                self.i += limite
                return ln
            mas = self._mas()
            if not mas:
                ln = self.buf[self.i:]
                self.buf, self.i = b"", 0
                return ln
            self.buf = self.buf[self.i:] + mas
            self.i = 0

    def read(self, n):
        while len(self.buf) - self.i < n:
            mas = self._mas()
            if not mas:
                break
            self.buf = self.buf[self.i:] + mas
            self.i = 0
        out = self.buf[self.i:self.i + n]
        self.i += len(out)
        return out


# --------------------------------------------------------------------------------------------
# Hora local (IDS_TZ) y marcas de Suricata
# --------------------------------------------------------------------------------------------
_ZONAS = {}


def _zona():
    n = (os.environ.get("IDS_TZ") or "America/Guayaquil").strip() or "America/Guayaquil"
    z = _ZONAS.get(n)
    if z is None:
        z = timezone.utc
        if n.upper() != "UTC":
            try:
                from zoneinfo import ZoneInfo
                z = ZoneInfo(n)
            except Exception:              # sin tzdata: Ecuador UTC-5 fijo; otra desconocida, UTC
                z = timezone(timedelta(hours=-5)) if n == "America/Guayaquil" else timezone.utc
        _ZONAS[n] = z
    return z


_TS_CACHE = {}


def ts_us(s):
    """Epoch en µs de una marca de eve.json ("2026-10-11T10:15:30.123456-0500"); None si no vale.
    Sin zona se toma la local (IDS_TZ). Memoria por segundo, como `parse_ts` del generador."""
    if not isinstance(s, str):
        return None
    m = _RE_TS.fullmatch(s)
    if not m:
        return None
    clave = s[:19] + (m.group(8) or "|" + (os.environ.get("IDS_TZ") or ""))
    base = _TS_CACHE.get(clave)
    if base is None:
        y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
        if not (1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and se < 61):
            return None
        tz = m.group(8)
        try:
            if tz is None:
                base = int(datetime(y, mo, d, h, mi, min(se, 59), tzinfo=_zona()).timestamp())
            else:
                off = 0
                if tz != "Z":
                    t = tz.replace(":", "")
                    off = (int(t[1:3]) * 3600 + int(t[3:5]) * 60) * (1 if t[0] == "+" else -1)
                base = calendar.timegm((y, mo, d, h, mi, se, 0, 0, 0)) - off
        except (ValueError, OverflowError):
            return None
        if len(_TS_CACHE) > 100000:
            _TS_CACHE.clear()
        _TS_CACHE[clave] = base
    frac = m.group(7) or ""
    return base * 1000000 + (int(frac[:6].ljust(6, "0")) if frac else 0)


def _ts_linea(ln):
    m = _RE_TS_LINEA.search(ln)
    if not m:
        return None
    try:
        return ts_us(m.group(1).decode("ascii"))
    except UnicodeDecodeError:
        return None


def _fmt(us, segundos=True):
    if us is None:
        return "-"
    try:
        d = datetime.fromtimestamp(us / 1000000.0, _zona())
    except (OverflowError, OSError, ValueError):
        return "-"
    return d.strftime("%Y-%m-%d %H:%M:%S" if segundos else "%Y-%m-%d %H:%M")


def _fmt_form(us):
    try:
        return datetime.fromtimestamp(us // 1000000, _zona()).strftime("%Y-%m-%dT%H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


def _form_us(s, fin):
    """Fecha del formulario en hora local -> µs. `fin`: incluye el minuto/segundo entero."""
    m = _RE_FORM.fullmatch(s)
    if not m:
        raise FiltroInvalido("fecha no valida: use AAAA-MM-DD HH:MM")
    y, mo, d, h, mi = (int(m.group(i)) for i in range(1, 6))
    se = int(m.group(6)) if m.group(6) else 0
    try:
        t = int(datetime(y, mo, d, h, mi, se, tzinfo=_zona()).timestamp())
    except (ValueError, OverflowError):
        raise FiltroInvalido("fecha no valida: use AAAA-MM-DD HH:MM")
    if fin:
        return (t + (1 if m.group(6) else 60)) * 1000000 - 1
    return t * 1000000


# --------------------------------------------------------------------------------------------
# Filtros
# --------------------------------------------------------------------------------------------
def _q(consulta, k, largo=200):
    v = (consulta or {}).get(k, "")
    if isinstance(v, (list, tuple)):
        v = v[0] if len(v) == 1 else ""
    if not isinstance(v, str):
        return ""
    return v.strip()[:largo]


def filtros(consulta, ahora=None):
    """Parametros GET -> filtros validados. FiltroInvalido con el motivo si alguno no vale."""
    f = {"tipo": "alert", "firma": "", "sid": None, "sev": None, "ip": "", "ipdir": "",
         "puerto": None, "pdir": "", "proto": "", "cursor": None}
    ahora = time.time() if ahora is None else ahora
    desde, hasta = _q(consulta, "desde"), _q(consulta, "hasta")
    if hasta:
        f["hasta_us"] = _form_us(hasta, True)
    else:
        f["hasta_us"] = (int(ahora) + 1) * 1000000 - 1
    if desde:
        f["desde_us"] = _form_us(desde, False)
    else:
        f["desde_us"] = (f["hasta_us"] // 1000000 + 1 - VENTANA_DEFECTO) * 1000000
    if f["desde_us"] > f["hasta_us"]:
        raise FiltroInvalido("«desde» es posterior a «hasta»")
    tipo = _q(consulta, "tipo") or "alert"
    if tipo not in dict(TIPOS):
        raise FiltroInvalido("tipo de evento no valido")
    f["tipo"] = tipo
    firma = _q(consulta, "firma")
    if firma.isdigit() and len(firma) <= 10 and firma.isascii():
        f["sid"] = int(firma)
    elif firma:
        f["firma"] = firma
    sev = _q(consulta, "sev")
    if sev:
        if not (sev.isascii() and sev.isdigit() and 1 <= int(sev) <= 255):
            raise FiltroInvalido("severidad no valida (1-255)")
        f["sev"] = int(sev)
    ip = _q(consulta, "ip")
    if ip:
        try:
            f["ip"] = str(ipaddress.ip_address(ip))
        except ValueError:
            raise FiltroInvalido("IP no valida")
    ipdir = _q(consulta, "ipdir")
    if ipdir not in dict(DIRS_IP):
        raise FiltroInvalido("sentido de la IP no valido")
    f["ipdir"] = ipdir
    puerto = _q(consulta, "puerto")
    if puerto:
        if not (puerto.isascii() and puerto.isdigit() and int(puerto) <= 65535):
            raise FiltroInvalido("puerto no valido (0-65535)")
        f["puerto"] = int(puerto)
    pdir = _q(consulta, "pdir")
    if pdir not in dict(DIRS_IP):
        raise FiltroInvalido("sentido del puerto no valido")
    f["pdir"] = pdir
    proto = _q(consulta, "proto")
    if proto:
        if not RE_PROTO.fullmatch(proto):
            raise FiltroInvalido("protocolo no valido")
        f["proto"] = proto.upper()
    por = _q(consulta, "por")
    f["por_todos"] = por == "todos"
    if not por:
        f["por"] = POR_PAGINA
    elif por == "todos":
        f["por"] = TODOS_MAX
    elif por.isascii() and por.isdigit() and int(por) in TAMANOS:
        f["por"] = int(por)
    else:
        raise FiltroInvalido("eventos por pagina no validos")
    cur = _q(consulta, "cursor", 64)
    if cur:
        m = RE_CURSOR.fullmatch(cur)
        if not m:
            raise FiltroInvalido("cursor de pagina no valido")
        f["cursor"] = (int(m.group(1)), m.group(2) or "", m.group(3) or "")
    return f


def _familias(tipo):
    # el eve del contenedor no lleva dns (va aparte en dns.json): solo DNS y Todos miran dns.json
    return ("eve", "dns") if tipo in ("dns", "todos") else ("eve",)


def _agujas(f):
    """Subcadenas (bytes) que una linea TIENE que contener para poder casar: prefiltro barato."""
    a = []
    if f["tipo"] != "todos":
        a.append(('"%s"' % f["tipo"]).encode())
    if f["ip"]:
        a.append(f["ip"].encode())
    if f["sid"] is not None:
        a.append(str(f["sid"]).encode())
    if f["puerto"] is not None:
        a.append(str(f["puerto"]).encode())
    return a


def _aguja_firma(f):
    t = f["firma"]
    if t and t.isascii() and not any(c in t for c in '"\\/') and t.isprintable():
        return t.lower().encode()
    return None


def casa(ev, f):
    """El evento ya parseado cumple todos los filtros (salvo la fecha, que va aparte)."""
    if not isinstance(ev, dict):
        return False
    if f["tipo"] != "todos" and ev.get("event_type") != f["tipo"]:
        return False
    if f["firma"] or f["sid"] is not None or f["sev"] is not None:
        al = ev.get("alert")
        if not isinstance(al, dict):
            return False
        if f["firma"] and f["firma"].lower() not in str(al.get("signature", "")).lower():
            return False
        if f["sid"] is not None and not _ent_igual(al.get("signature_id"), f["sid"]):
            return False
        if f["sev"] is not None and not _ent_igual(al.get("severity"), f["sev"]):
            return False
    if f["ip"]:
        s, d = ev.get("src_ip"), ev.get("dest_ip")
        if f["ipdir"] == "src":
            ok = s == f["ip"]
        elif f["ipdir"] == "dst":
            ok = d == f["ip"]
        else:
            ok = f["ip"] in (s, d)
        if not ok:
            return False
    if f["puerto"] is not None:
        s, d = ev.get("src_port"), ev.get("dest_port")
        if f["pdir"] == "src":
            ok = _ent_igual(s, f["puerto"])
        elif f["pdir"] == "dst":
            ok = _ent_igual(d, f["puerto"])
        else:
            ok = _ent_igual(s, f["puerto"]) or _ent_igual(d, f["puerto"])
        if not ok:
            return False
    if f["proto"] and str(ev.get("proto", "")).upper() != f["proto"]:
        return False
    return True


def _ent_igual(v, n):
    return isinstance(v, int) and not isinstance(v, bool) and v == n


def huella(linea):
    """Huella de una linea (sin el salto): identifica el evento aunque cambie de fichero."""
    return hashlib.sha1(linea.rstrip(b"\r\n")).hexdigest()[:16]


# --------------------------------------------------------------------------------------------
# Ficheros: solo los del punto, sin enlaces que salgan de su directorio
# --------------------------------------------------------------------------------------------
def nombre_valido(nombre):
    return (isinstance(nombre, str) and len(nombre) <= 128 and ".." not in nombre
            and RE_FICHERO.fullmatch(nombre) is not None)


def _fichero_seguro(pid, nombre):
    """(ruta_real, stat) del fichero `nombre` del punto, o None. Rechaza nombres que no son
    eve.json*/dns.json*, enlaces cuyo fichero real esta fuera de DATOS/<pid> y lo que no es
    un fichero regular."""
    if not nombre_valido(nombre):
        return None
    try:
        d = nodos.dir_eventos(pid)
        base = os.path.realpath(d)
        real = os.path.realpath(os.path.join(d, nombre))
        if os.path.dirname(real) != base or not nombre_valido(os.path.basename(real)):
            return None
        st = os.stat(real)
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    return real, st


def _abrir(real, st):
    """Abre en binario y comprueba que es el MISMO fichero que se valido (nadie lo cambio por un
    enlace entre medias). Con O_NONBLOCK: si entre la validacion y el open alguien pone un FIFO
    con ese nombre, el open no se queda esperando a un escritor (B-16); se quita despues de
    comprobar que es un fichero regular."""
    nb = getattr(os, "O_NONBLOCK", 0)
    fl = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | nb
    fd = os.open(real, fl)
    try:
        st2 = os.fstat(fd)
        if (not stat.S_ISREG(st2.st_mode)
                or (st.st_ino and st2.st_ino and (st.st_dev, st.st_ino) != (st2.st_dev, st2.st_ino))):
            raise OSError("el fichero cambio al abrirlo")
        if nb:
            try:
                import fcntl
                fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) & ~nb)
            except (ImportError, OSError):
                pass                       # en un fichero regular O_NONBLOCK no cambia nada
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


# --------------------------------------------------------------------------------------------
# Fuentes
# --------------------------------------------------------------------------------------------
class _Ctx:
    def __init__(self, f, pids_):
        self.f = f
        self.L = f["desde_us"]
        self.U = f["hasta_us"]
        if f["cursor"]:
            self.U = min(self.U, f["cursor"][0])
        self.agujas = _agujas(f)
        self.aguja_firma = _aguja_firma(f)
        self.t0 = time.monotonic()
        self.bytes = 0
        self.incompletas = 0
        self.sin_fecha = 0
        self.rechazados = []
        self.omitidos = []
        self.leidos = 0
        self.heap = []            # min-heap de (clave, fila) con los N+1 mas recientes
        self.claves = set()
        self.pids = pids_

    def tope(self):
        if self.bytes > TOPE_BYTES:
            return "%d MB leidos" % (TOPE_BYTES // (1024 * 1024))
        if time.monotonic() - self.t0 > TOPE_SEGUNDOS:
            return "%g s de busqueda" % TOPE_SEGUNDOS
        return None

    def comprobar(self):
        if self.tope():
            raise _Tope()

    def lleno(self):
        return len(self.heap) >= self.f["por"] + 1

    def minimo(self):
        return self.heap[0][0][0] if self.heap else None


def _meter(heap, claves, clave, fila, cap):
    if clave in claves:
        return                    # la misma linea en dos ficheros (rotacion): una sola vez
    if len(heap) < cap:
        heapq.heappush(heap, (clave, fila))
        claves.add(clave)
    elif clave > heap[0][0]:
        viejo = heapq.heapreplace(heap, (clave, fila))
        claves.discard(viejo[0])
        claves.add(clave)


def _candidata(ctx, pid, ln, heap):
    """Evalua una linea completa (bytes, con o sin salto). Devuelve (clave, ev) o None."""
    for a in ctx.agujas:
        if a not in ln:
            return None
    if ctx.aguja_firma is not None and ctx.aguja_firma not in ln.lower():
        return None
    ts = _ts_linea(ln)
    if ts is None:
        ctx.sin_fecha += 1
        return None
    if ts > ctx.U or ts < ctx.L:
        return None
    if len(heap) >= ctx.f["por"] + 1 and ts < heap[0][0][0]:
        return None
    cur = ctx.f["cursor"]
    if cur and ts > cur[0]:
        return None
    try:
        ev = json.loads(ln.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        ctx.incompletas += 1
        return None
    if not isinstance(ev, dict):
        ctx.incompletas += 1
        return None
    if not casa(ev, ctx.f):
        return None
    clave = (ts, pid, huella(ln))
    if cur and not clave < cur:
        return None
    return clave, ev


class _Fuente:
    def __init__(self, pid, nombre, real, st, inicio):
        self.pid = pid
        self.nombre = nombre
        self.real = real
        self.st = st
        self.gz = nombre.endswith(".gz")
        self.mtime = st.st_mtime_ns // 1000
        self.inicio = inicio          # estimacion de su primera marca (mtime del rotado anterior)
        self.fh = None
        self.cota = None
        self.agotada = False

    def abrir(self, ctx):
        self.fh = _abrir(self.real, self.st)
        self.tam = os.fstat(self.fh.fileno()).st_size
        self.cota = min(self.mtime + DESORDEN_US, ctx.U)

    def cerrar(self):
        if self.fh:
            try:
                self.fh.close()
            except OSError:
                pass
            self.fh = None

    def paso(self, ctx):
        if self.gz:
            self._paso_gz(ctx)
        else:
            self._paso_plano(ctx)

    # -- planos: hacia atras por bloques -----------------------------------------------------
    def _fin(self, ctx):
        """Final de la region a leer: la primera linea con marca > U + desorden, por biseccion."""
        f, tam = self.fh, self.tam
        if ctx.U + DESORDEN_US >= self.mtime:
            return tam
        lo, hi = 0, tam
        while hi - lo > BLOQUE:
            mid = (lo + hi) // 2
            f.seek(mid)
            f.readline(MAX_LINEA)          # la primera suele venir cortada: se tira
            ts = None
            for _ in range(20):            # alguna linea puede no traer marca
                ln = f.readline(MAX_LINEA)
                if not ln:
                    break
                ts = _ts_linea(ln)
                if ts is not None:
                    break
            ctx.bytes += max(0, f.tell() - mid)
            if ts is None:
                break                      # no se pudo orientar: leer desde mas adelante
            if ts > ctx.U + DESORDEN_US:
                hi = mid
            else:
                lo = mid
        if hi >= tam:
            return tam
        f.seek(hi)
        f.readline()                       # alinear al final de la linea que corta `hi`
        return min(f.tell(), tam)

    def _paso_plano(self, ctx):
        if not hasattr(self, "pos"):
            self.pos = self._fin(ctx)
            self.cola = b""
            self.larga = False
        if self.pos <= 0:
            self.agotada = True
            return
        ini = max(0, self.pos - BLOQUE)
        self.fh.seek(ini)
        datos = self.fh.read(self.pos - ini)
        ctx.bytes += len(datos)
        if len(datos) != self.pos - ini:   # truncado mientras se lee (copytruncate)
            ctx.incompletas += 1 if self.cola else 0
            self.agotada = True
            return
        buf = datos + self.cola
        self.pos = ini
        if ini > 0:
            k = buf.find(b"\n")
            if k < 0:
                self.cola = buf
                if len(self.cola) > MAX_LINEA:
                    self.cola = b""
                    self.larga = True
                return
            self.cola = buf[:k + 1]
            if len(self.cola) > MAX_LINEA:
                # El unico salto era el del final de la cola: es la misma linea larga, que va
                # hacia atras sin principio. Se descarta (y se cuenta) sin seguir acumulandola:
                # la memoria queda en MAX_LINEA + BLOQUE aunque la linea mida cientos de MB (B-07).
                self.cola = b""
                self.larga = True
                return
            inicio, cuerpo = ini + k + 1, buf[k + 1:]
        else:
            self.cola = b""
            inicio, cuerpo = 0, buf
        lineas = []
        p = 0
        n = len(cuerpo)
        while p < n:
            q = cuerpo.find(b"\n", p)
            if q < 0:
                # ultimo trozo sin salto: la linea que Suricata esta escribiendo (solo en el
                # primer bloque), o el principio de una linea demasiado larga ya descartada
                if not self.larga:
                    ctx.incompletas += 1
                break
            if q > p:
                lineas.append((inicio + p, cuerpo[p:q + 1]))
            p = q + 1
        if self.larga:
            self.larga = False
            ctx.incompletas += 1
        self._lineas(ctx, lineas)

    def _lineas(self, ctx, lineas):
        primera = None
        for off, ln in lineas:
            if primera is None:
                primera = _ts_linea(ln)
            if len(ln) > MAX_LINEA:
                ctx.incompletas += 1
                continue
            r = _candidata(ctx, self.pid, ln, ctx.heap)
            if r:
                clave, ev = r
                _meter(ctx.heap, ctx.claves, clave,
                       {"pid": self.pid, "fichero": self.nombre, "offset": off, "ev": ev}, ctx.f["por"] + 1)
        ctx.leidos += len(lineas)
        if primera is not None:
            # lo que queda sin leer esta antes de esa linea: como mucho, su marca + el desorden
            self.cota = min(self.cota, primera + DESORDEN_US)

    # -- .gz: enteros, con tope por fichero ----------------------------------------------------
    def _paso_gz(self, ctx):
        """Se lee entero hacia delante. Sus eventos solo pasan al resultado si se termina: un .gz
        cortado a medias dejaria un hueco entre lo leido (lo viejo) y lo demas."""
        local, claves = [], set()
        leidos, pos, seguir_larga = 0, 0, False
        incompletas = sin_fecha = 0
        visto = [0]

        def comprobar(lec):
            # los bytes COMPRIMIDOS tambien cuentan para el tope de la consulta, y el tiempo se
            # mira entre trozos: una cabecera enorme o miles de miembros vacios no producen
            # lineas pero si gastan (B-08)
            ctx.bytes += lec.comprimidos - visto[0]
            visto[0] = lec.comprimidos
            ctx.comprobar()
        g = _GzLector(self.fh, comprobar)
        try:
            while True:
                ln = g.readline(MAX_LINEA + 1)
                if not ln:
                    break
                off = pos
                pos += len(ln)
                leidos += len(ln)
                ctx.bytes += len(ln)
                if leidos > TOPE_GZ:
                    self.agotada = True
                    ctx.omitidos.append((self.pid, self.nombre, self.cota,
                                         "descomprime mas de %d MB" % (TOPE_GZ // (1024 * 1024))))
                    return
                if ctx.bytes > TOPE_BYTES or (ctx.leidos & 1023) == 0:
                    ctx.comprobar()
                ctx.leidos += 1
                if not ln.endswith(b"\n"):
                    incompletas += 1       # linea demasiado larga o final cortado
                    seguir_larga = True
                    continue
                if seguir_larga:           # resto de una linea demasiado larga
                    seguir_larga = False
                    continue
                i0, s0 = ctx.incompletas, ctx.sin_fecha
                r = _candidata(ctx, self.pid, ln, ctx.heap if ctx.lleno() else local)
                incompletas += ctx.incompletas - i0
                sin_fecha += ctx.sin_fecha - s0
                ctx.incompletas, ctx.sin_fecha = i0, s0
                if r:
                    clave, ev = r
                    _meter(local, claves, clave,
                           {"pid": self.pid, "fichero": self.nombre, "offset": off, "ev": ev}, ctx.f["por"] + 1)
        except _GzLimite as e:
            self.agotada = True
            ctx.omitidos.append((self.pid, self.nombre, self.cota, str(e)))
            return
        except (OSError, EOFError, zlib.error):
            self.agotada = True
            ctx.omitidos.append((self.pid, self.nombre, self.cota, "comprimido danado o a medio escribir"))
            return
        ctx.incompletas += incompletas
        ctx.sin_fecha += sin_fecha
        for clave, fila in local:
            _meter(ctx.heap, ctx.claves, clave, fila, ctx.f["por"] + 1)
        self.agotada = True


def _listar(pids_, familias, ctx):
    """Fuentes que pueden solapar la ventana, por pid y familia, con su inicio estimado."""
    fuentes = []
    for pid in pids_:
        grupos = {}
        for _, ruta in nodos.ficheros_eventos(pid):
            nombre = os.path.basename(ruta)
            m = RE_FICHERO.fullmatch(nombre) if nombre_valido(nombre) else None
            if not m:
                ctx.rechazados.append((pid, nombre))
                continue
            if m.group(1) not in familias:
                continue
            ok = _fichero_seguro(pid, nombre)
            if not ok:
                ctx.rechazados.append((pid, nombre))
                continue
            grupos.setdefault(m.group(1), []).append((nombre, ok[0], ok[1]))
        for fam in sorted(grupos):
            fs = sorted(grupos[fam], key=lambda x: (x[2].st_mtime_ns, x[0]))
            previo = None
            for nombre, real, st in fs:
                inicio = previo - DESORDEN_US if previo is not None else None
                previo = st.st_mtime_ns // 1000
                fu = _Fuente(pid, nombre, real, st, inicio)
                if fu.mtime + DESORDEN_US < ctx.L:
                    continue               # se cerro antes de la ventana
                if inicio is not None and inicio > ctx.U:
                    continue               # empieza despues de la ventana
                fuentes.append(fu)
    return fuentes


def _firma_listado(fuentes):
    return sorted((f.pid, f.nombre, f.st.st_dev, f.st.st_ino) for f in fuentes)


def buscar(f, nodo):
    """Busqueda con los filtros `f` (de `filtros()`) en el nodo. Devuelve un dict con `filas`
    (las de la pagina, mas recientes primero), `siguiente` (cursor o None), `parcial`, `motivo`,
    `hasta_us` (fecha a la que llego si es parcial), `fichero_corte` y contadores."""
    pids_ = nodos.nodos_de(nodo)
    ctx = _Ctx(f, pids_)
    familias = _familias(f["tipo"])
    fuentes = []
    try:
        # Una rotacion entre listar y abrir cambiaria los nombres: se abre todo y se vuelve a
        # listar; si cambio algo, se repite (el fichero abierto sigue siendo el mismo aunque lo
        # renombren, y la clave de cada linea no depende del nombre).
        for intento in range(3):
            for fu in fuentes:
                fu.cerrar()
            ctx.rechazados = []
            ctx.omitidos = []
            fuentes = _listar(pids_, familias, ctx)
            abiertas = []
            for fu in fuentes:
                try:
                    fu.abrir(ctx)
                    abiertas.append(fu)
                except (OSError, ValueError) as e:
                    # un fichero de la ventana que no se puede leer deja la busqueda PARCIAL
                    # (§10.5): nunca «sin coincidencias» sin haberlo mirado (A-25)
                    ctx.omitidos.append((fu.pid, fu.nombre, min(fu.mtime + DESORDEN_US, ctx.U),
                                         "no se pudo abrir (%s)" % (getattr(e, "strerror", None)
                                                                    or type(e).__name__)))
            fuentes = abiertas
            if _firma_listado(_listar(pids_, familias, _Ctx(f, pids_))) == _firma_listado(fuentes):
                break
        motivo, corte, cota_corte = None, None, None
        while True:
            activas = [x for x in fuentes if not x.agotada and x.cota >= ctx.L]
            if not activas:
                break
            fu = max(activas, key=lambda x: (x.cota, x.pid, x.nombre))
            if ctx.lleno() and ctx.minimo() > fu.cota:
                break                      # nada de lo que queda puede ser mas nuevo
            motivo = ctx.tope()
            if motivo:
                corte, cota_corte = fu, fu.cota
                break
            try:
                fu.paso(ctx)
            except _Tope:
                motivo = ctx.tope() or "tope"
                corte, cota_corte = fu, fu.cota
                break
            except (OSError, ValueError):
                fu.agotada = True
                ctx.omitidos.append((fu.pid, fu.nombre, fu.cota, "error de lectura"))
    finally:
        for fu in fuentes:
            fu.cerrar()
    todas = sorted(ctx.heap, key=lambda x: x[0], reverse=True)
    por = f["por"]
    res = {"filas": [], "siguiente": None, "parcial": False, "motivo": None, "hasta_us": None,
           "fichero_corte": None, "bytes": ctx.bytes, "incompletas": ctx.incompletas,
           "sin_fecha": ctx.sin_fecha, "rechazados": ctx.rechazados, "omitidos": ctx.omitidos,
           "ficheros": len(fuentes), "desde_us": ctx.L, "techo_us": ctx.U, "sin_garantia": False}
    if motivo:
        # Solo es seguro lo que es mas nuevo que la cota de lo que quedo sin leer.
        garant = [x for x in todas if x[0][0] > cota_corte][:por]
        res["sin_garantia"] = False
        if not garant and cota_corte + 1 >= ctx.U:
            # El tope no alcanza ni para cubrir el margen de desorden: con la cota estricta la
            # pagina siguiente seria esta misma. Se avanza hasta la marca mas vieja que se llego
            # a leer (sin el margen) y se avisa: un evento escrito con mas desorden que ese
            # podria quedarse fuera.
            cota_corte = max(x.cota for x in activas) - DESORDEN_US
            garant = [x for x in todas if x[0][0] > cota_corte][:por]
            res["sin_garantia"] = True
        res["parcial"] = True
        res["motivo"] = motivo
        res["hasta_us"] = cota_corte
        res["fichero_corte"] = (corte.pid, corte.nombre)
        res["filas"] = [_fila(c, x) for c, x in garant]
        if len(garant) == por:
            res["siguiente"] = garant[-1][0]
        else:
            res["siguiente"] = (cota_corte + 1, "", "")
    else:
        pag = todas[:por]
        res["filas"] = [_fila(c, x) for c, x in pag]
        if len(todas) > por:
            res["siguiente"] = pag[-1][0]
    if ctx.omitidos:
        res["parcial"] = True
    return res


def _fila(clave, x):
    d = dict(x)
    d["ts_us"], d["huella"] = clave[0], clave[2]
    return d


def cursor_txt(c):
    if not c:
        return ""
    return "%d-%s-%s" % c if c[1] else "%d" % c[0]


# --------------------------------------------------------------------------------------------
# Referencias firmadas del detalle
# --------------------------------------------------------------------------------------------
_CLAVES = {}
_CLAVES_LOCK = threading.Lock()


def _leer_clave(p):
    try:
        with open(p, encoding="ascii") as fh:
            k = fh.read(200).strip()
    except (OSError, UnicodeDecodeError):
        return None
    return k if RE_FIRMA.fullmatch(k) else None


def clave_hmac():
    """Secreto del panel para firmar referencias (CONF/eventos.hmac, 0600; se crea si falta)."""
    p = os.path.join(nodos.CONF, CLAVE_HMAC)
    with _CLAVES_LOCK:
        k = _CLAVES.get(p)
        if k:
            return k
        k = _leer_clave(p)
        if k is None:
            os.makedirs(nodos.CONF, mode=0o700, exist_ok=True)
            tmp = "%s.%d.%s.tmp" % (p, os.getpid(), secrets.token_hex(4))
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="ascii") as fh:
                    fh.write(secrets.token_hex(32) + "\n")
                try:
                    os.link(tmp, p)        # atomico y sin pisar uno creado a la vez
                except FileExistsError:
                    if _leer_clave(p) is None:
                        os.replace(tmp, p)  # el que habia estaba danado
                except (OSError, AttributeError):
                    os.replace(tmp, p)
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            k = _leer_clave(p)
            if k is None:
                raise OSError("no se pudo crear la clave de eventos")
        _CLAVES[p] = k
        return k


def firmar(pid, nombre, offset, h):
    msg = ("%s\n%s\n%d\n%s" % (pid, nombre, offset, h)).encode()
    return hmac.new(bytes.fromhex(clave_hmac()), msg, hashlib.sha256).hexdigest()


def ref(pid, nombre, offset, h):
    return {"p": pid, "f": nombre, "o": str(offset), "h": h, "s": firmar(pid, nombre, offset, h)}


def validar_ref(consulta, nodo):
    """(pid, nombre, offset, huella) de una referencia valida; RefInvalida si no lo es.
    No se toca el disco hasta que todo cuadra (firma incluida)."""
    pid, nombre, o, h, s = (_q(consulta, k, 300) for k in ("p", "f", "o", "h", "s"))
    if not nodos.pid_valido(pid) or pid not in nodos.pids():
        raise RefInvalida("punto desconocido")
    if pid not in nodos.nodos_de(nodo):
        raise RefInvalida("el evento no es del nodo que se esta mirando")
    if not nombre_valido(nombre):
        raise RefInvalida("fichero no valido")
    if not (o.isascii() and o.isdigit() and len(o) <= 15):
        raise RefInvalida("desplazamiento no valido")
    if not RE_HUELLA.fullmatch(h) or not RE_FIRMA.fullmatch(s):
        raise RefInvalida("referencia mal formada")
    if not hmac.compare_digest(firmar(pid, nombre, int(o), h), s):
        raise RefInvalida("firma no valida")
    return pid, nombre, int(o), h


def _linea_en(pid, nombre, offset, t0):
    """La linea completa que empieza en `offset` del fichero, o None. Nunca sale de DATOS/<pid>."""
    ok = _fichero_seguro(pid, nombre)
    if not ok:
        raise RefInvalida("fichero no valido")
    real, st = ok
    with _abrir(real, st) as fh:
        if nombre.endswith(".gz"):
            if offset > TOPE_GZ:
                raise RefInvalida("desplazamiento fuera de rango")

            def comprobar(lec):
                if time.monotonic() - t0 > TOPE_SEGUNDOS:
                    raise RefInvalida("el comprimido tarda demasiado en leerse")
            g = _GzLector(fh, comprobar, max_comprimidos=TOPE_BYTES)
            try:
                previo, falta = b"\n", offset
                while falta > 0:
                    trozo = g.read(min(falta, BLOQUE))
                    if not trozo:
                        raise RefInvalida("desplazamiento fuera de rango")
                    falta -= len(trozo)
                    previo = trozo[-1:]
                if previo != b"\n":
                    raise RefInvalida("desplazamiento no es un inicio de linea")
                ln = g.readline(MAX_LINEA + 1)
            except _GzLimite as e:
                raise RefInvalida("comprimido no valido: %s" % e)
        else:
            tam = os.fstat(fh.fileno()).st_size
            if offset >= tam:
                raise RefInvalida("desplazamiento fuera de rango")
            if offset > 0:
                fh.seek(offset - 1)
                if fh.read(1) != b"\n":
                    raise RefInvalida("desplazamiento no es un inicio de linea")
            fh.seek(offset)
            ln = fh.readline(MAX_LINEA + 1)
    if not ln.endswith(b"\n"):
        raise RefInvalida("linea incompleta")
    return ln


def leer_evento(consulta, nodo):
    """(pid, nombre_donde_esta, offset, linea) del evento referido. Si una rotacion lo movio
    de fichero, se busca en los otros ficheros del mismo punto con la misma huella."""
    pid, nombre, offset, h = validar_ref(consulta, nodo)
    t0 = time.monotonic()
    try:
        ln = _linea_en(pid, nombre, offset, t0)
    except RefInvalida:
        ln = None
    except (OSError, EOFError, zlib.error):
        ln = None
    if ln is not None and huella(ln) == h:
        return pid, nombre, offset, ln
    fam = nombre.split(".", 1)[0]
    for _, ruta in nodos.ficheros_eventos(pid):
        otro = os.path.basename(ruta)
        if otro == nombre or not nombre_valido(otro) or not otro.startswith(fam + "."):
            continue
        if time.monotonic() - t0 > TOPE_SEGUNDOS:
            break
        try:
            ln = _linea_en(pid, otro, offset, t0)
        except (RefInvalida, OSError, EOFError, zlib.error):
            continue
        if ln is not None and huella(ln) == h:
            return pid, otro, offset, ln
    raise RefInvalida("el evento ya no esta en los ficheros del punto (rotado o borrado)")


# --------------------------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------------------------
_CSS = (
    "<style>"
    ".evw{max-width:1400px}"
    ".evw .card{overflow-x:auto}"
    ".evw form.evf{display:flex;flex-wrap:wrap;gap:10px 14px;align-items:flex-end;padding:14px 16px}"
    ".evw form.evf label{display:flex;flex-direction:column;font-size:12px;color:#52514e;gap:3px}"
    ".evw form.evf input,.evw form.evf select{font:13px system-ui;padding:6px 8px;border:1px solid #d7d6d2;"
    "border-radius:8px;background:#fff;color:#0b0b0b}"
    ".evw form.evf input.corto{width:90px}"
    ".evw form.evf button{font:600 13px system-ui;line-height:18px;padding:8px 16px;border:0;border-radius:8px;"
    "background:#1f65bd;color:#fff;cursor:pointer}"
    # «Limpiar» como boton secundario, misma altura y misma linea que «Buscar»: como enlace suelto
    # centrado a media altura quedaba mas arriba que el boton (el user, 2026-10-13)
    ".evw form.evf a.limpiar{font:600 13px system-ui;line-height:18px;padding:7px 16px;"
    "border:1px solid #d7d6d2;border-radius:8px;background:#fff;color:#0b0b0b;text-decoration:none;"
    "align-self:flex-end}"
    ".evw form.evf a.limpiar:hover{background:#eef4fd;border-color:#2a78d6}"
    ".evw .nodochip{display:inline-block;background:#eef4fd;color:#2a5fa0;border:1px solid #cfe0f6;"
    "border-radius:20px;padding:1px 9px;font-size:11px;font-weight:700;white-space:nowrap}"
    ".evw .pager{display:flex;gap:10px;align-items:center;margin:10px 0;flex-wrap:wrap}"
    ".evw .pager a{font:13px system-ui;padding:6px 12px;border:1px solid #d7d6d2;background:#fff;"
    "border-radius:8px;color:#0b0b0b;text-decoration:none}"
    ".evw .pager a:hover{background:#eef4fd;border-color:#2a78d6}"
    ".evw .pager .porpag{margin-left:auto;font:13px system-ui;color:#52514e}"
    ".evw .pager .porpag select{font:13px system-ui;padding:5px 8px;margin:0 4px;border:1px solid #d7d6d2;"
    "border-radius:8px;background:#fff}"
    ".evw td.res{max-width:460px;word-break:break-word}"
    ".evw td.fecha{white-space:nowrap}"
    ".evw .sev1{color:#b52a2a;font-weight:700}.evw .sev2{color:#a15c12;font-weight:700}"
    ".evw pre.evjson{white-space:pre-wrap;word-break:break-word;font:12.5px/1.45 ui-monospace,Consolas,monospace;"
    "padding:14px 16px;margin:0}"
    ".evw .retencion{margin:4px 0 14px}"
    # movil: la tabla conserva un ancho legible y se desliza dentro de su tarjeta
    ".evw .card table{min-width:760px}"
    "@media(max-width:640px){.evw form.evf label{flex:1 1 140px}"
    ".evw form.evf input,.evw form.evf select{width:100%;box-sizing:border-box}"
    ".evw form.evf input.corto{width:100%}.evw td.res{min-width:220px}}"
    "</style>")


def _e(v):
    return html.escape("" if v is None else str(v), quote=True)


def _corta(s, n=200):
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


def _url(ruta, params):
    return ruta + "?" + urlencode([(k, v) for k, v in params if v not in (None, "")])


def _params_filtro(consulta, nodo, f=None):
    """Los filtros tal como se pidieron (y las fechas efectivas si no se pidieron)."""
    ps = [("nodo", nodo)]
    for k in CAMPOS_FILTRO:
        v = _q(consulta, k)
        if f is not None and k == "desde" and not v:
            v = _fmt_form(f["desde_us"])
        if f is not None and k == "hasta" and not v:
            v = _fmt_form(f["hasta_us"])
        ps.append((k, v))
    return ps


def _nodo_html(pid):
    return "<span class='nodochip' title='%s'>%s</span>" % (_e(pid), _e(nodos.nombre(pid)))


def _ipp(ip, port):
    if not ip:
        return ""
    if isinstance(port, int) and not isinstance(port, bool):
        return "%s:%d" % (ip, port)
    return str(ip)


def _resumen(ev):
    """Lo mas util de cada tipo, ya escapado."""
    t = ev.get("event_type")
    if t == "alert" and isinstance(ev.get("alert"), dict):
        al = ev["alert"]
        sev = al.get("severity")
        cls = " class='sev%d'" % sev if sev in (1, 2) else ""
        return ("%s<div class='muted'>SID %s · <span%s>sev %s</span> · %s</div>"
                % (_e(_corta(al.get("signature"))), _e(al.get("signature_id")), cls, _e(sev),
                   _e(_corta(al.get("category"), 80))))
    if t == "dns" and isinstance(ev.get("dns"), dict):
        d = ev["dns"]
        q = d.get("rrname")
        if q is None and isinstance(d.get("queries"), list) and d["queries"] and isinstance(d["queries"][0], dict):
            q = d["queries"][0].get("rrname")
        extra = " · ".join(_e(_corta(d.get(k), 40)) for k in ("type", "rrtype", "rcode") if d.get(k))
        return "%s<div class='muted'>%s</div>" % (_e(_corta(q)), extra)
    if t == "http" and isinstance(ev.get("http"), dict):
        h = ev["http"]
        return ("%s%s<div class='muted'>%s %s · %s</div>"
                % (_e(_corta(h.get("hostname"), 100)), _e(_corta(h.get("url"), 120)),
                   _e(h.get("http_method", "")), _e(h.get("status", "")), _e(_corta(h.get("http_user_agent"), 120))))
    if t == "tls" and isinstance(ev.get("tls"), dict):
        s = ev["tls"]
        return "%s<div class='muted'>%s</div>" % (_e(_corta(s.get("sni"))), _e(_corta(s.get("version"), 30)))
    if t == "stats" and isinstance(ev.get("stats"), dict):
        s = ev["stats"]
        cap = s.get("capture") if isinstance(s.get("capture"), dict) else {}
        return ("uptime %s s<div class='muted'>paquetes %s · descartes %s</div>"
                % (_e(s.get("uptime")), _e(cap.get("kernel_packets", "-")), _e(cap.get("kernel_drops", "-"))))
    return _e(_corta(ev.get("app_proto") or ""))


def _selector_por(consulta, nodo, f):
    """«Ver N por pagina» junto al paginador: 10, 20, 30, 40, 50, 100 o todos (hasta TODOS_MAX).
    Conserva los filtros y vuelve a la primera pagina (sin cursor)."""
    actual = "todos" if f.get("por_todos") else str(f.get("por") or POR_PAGINA)
    ocultos = "".join("<input type='hidden' name='%s' value='%s'>" % (_e(k), _e(v))
                      for k, v in _params_filtro(consulta, nodo, f) if k != "por" and v)
    opciones = [(str(n), str(n)) for n in TAMANOS] + [("todos", "Todos")]
    return ("<form class='porpag' method='get' action='%s'>%s<label>Ver "
            "<select name='por' onchange='this.form.submit()'>%s</select> por pagina</label>"
            "<noscript><button type='submit'>Aplicar</button></noscript></form>"
            % (_e(RUTA), ocultos, "".join("<option value='%s'%s>%s</option>" % (
                _e(v), " selected" if v == actual else "", _e(t)) for v, t in opciones)))


def _formulario(consulta, nodo, f):
    def sel(nombre, opciones, actual):
        return ("<select name='%s'>%s</select>" % (nombre, "".join(
            "<option value='%s'%s>%s</option>" % (_e(v), " selected" if v == actual else "", _e(t))
            for v, t in opciones)))
    desde = _q(consulta, "desde") or (_fmt_form(f["desde_us"]) if f else "")
    hasta = _q(consulta, "hasta") or (_fmt_form(f["hasta_us"]) if f else "")
    sevs = [("", "todas")] + [(str(i), str(i)) for i in (1, 2, 3, 4)]
    return (
        "<form class='card evf' method='get' action='%s'>" % RUTA
        + "<input type='hidden' name='nodo' value='%s'>" % _e(nodo)
        + "<label>Desde<input type='datetime-local' step='1' name='desde' value='%s'></label>" % _e(desde)
        + "<label>Hasta<input type='datetime-local' step='1' name='hasta' value='%s'></label>" % _e(hasta)
        + "<label>Tipo%s</label>" % sel("tipo", TIPOS, _q(consulta, "tipo") or "alert")
        + "<label>Firma o SID<input name='firma' value='%s' placeholder='texto o numero'></label>" % _e(_q(consulta, "firma"))
        + "<label>Severidad%s</label>" % sel("sev", sevs, _q(consulta, "sev"))
        + "<label>IP<input name='ip' value='%s' placeholder='192.0.2.10'></label>" % _e(_q(consulta, "ip"))
        + "<label>IP como%s</label>" % sel("ipdir", DIRS_IP, _q(consulta, "ipdir"))
        + "<label>Puerto<input class='corto' name='puerto' value='%s' inputmode='numeric'></label>" % _e(_q(consulta, "puerto"))
        + "<label>Puerto como%s</label>" % sel("pdir", DIRS_IP, _q(consulta, "pdir"))
        + "<label>Protocolo<input class='corto' name='proto' value='%s' placeholder='TCP'></label>" % _e(_q(consulta, "proto"))
        + ("<input type='hidden' name='por' value='%s'>" % _e(_q(consulta, "por")) if _q(consulta, "por") else "")
        + "<button type='submit'>Buscar</button>"
        + "<a class='limpiar' href='%s'>Limpiar</a>" % _e(_url(RUTA, [("nodo", nodo)]))
        + "</form>")


_DISP = {}                        # directorio del punto -> (firma del listado, resultado)
_DISP_LOCK = threading.Lock()


def primera_marca(real, st, nombre, limite=None):
    """Marca (µs) de la primera linea de un fichero ya validado por `_fichero_seguro`, o None.
    Un .gz se lee con `_GzLector` y topes pequeños (bytes comprimidos, miembros y, con
    `limite` = instante monotonic, tiempo): un .gz patologico no cuesta mas que eso."""
    try:
        with _abrir(real, st) as fh:
            if nombre.endswith(".gz"):
                def comprobar(lec):
                    if limite is not None and time.monotonic() > limite:
                        raise _GzLimite("sin tiempo")
                g = _GzLector(fh, comprobar, max_miembros=DISP_MIEMBROS, max_comprimidos=DISP_COMPRIMIDOS)
                ln = g.readline(65536)
            else:
                ln = fh.readline(65536)
    except (OSError, EOFError, zlib.error, _GzLimite):
        return None
    return _ts_linea(ln)


def disponible_desde(pid):
    """Marca del primer evento que queda del punto (retencion efectiva), o None. Lee solo la
    primera linea del fichero mas viejo de cada familia, con topes (B-08), y recuerda el
    resultado mientras no cambie el listado de ficheros (corre en cada carga de la pagina)."""
    fs = []
    for _, ruta in nodos.ficheros_eventos(pid):
        ok = _fichero_seguro(pid, os.path.basename(ruta))
        if ok:
            fs.append((ok[1].st_mtime_ns, os.path.basename(ruta), ok))
    fs.sort(key=lambda x: (x[0], x[1]))
    # el vivo cambia de tamaño y mtime a cada evento pero su primera linea no (salvo al rotar,
    # que cambia el inodo): no invalida la memoria
    firma = tuple((n, ok[1].st_ino) + ((0, 0) if n in ("eve.json", "dns.json") else (m, ok[1].st_size))
                  for m, n, ok in fs)
    clave = nodos.dir_eventos(pid)
    with _DISP_LOCK:
        c = _DISP.get(clave)
        if c and c[0] == firma:
            return c[1]
    mejor = None
    vistos = set()
    completo = True
    limite = time.monotonic() + DISP_SEGUNDOS
    for _, nombre, ok in fs:
        fam = nombre.split(".", 1)[0]
        if fam in vistos:                  # basta el mas viejo de cada familia que tenga marca
            continue
        if time.monotonic() > limite:
            completo = False
            break
        t = primera_marca(ok[0], ok[1], nombre, limite)
        if t is not None:
            vistos.add(fam)
            if mejor is None or t < mejor:
                mejor = t
    if completo:
        with _DISP_LOCK:
            if len(_DISP) > 1000:
                _DISP.clear()
            _DISP[clave] = (firma, mejor)
    return mejor


def _retencion(pids_):
    partes = []
    for pid in pids_:
        d = disponible_desde(pid)
        partes.append("%s %s" % (_nodo_html(pid), _e(_fmt(d, False)) if d else "sin eventos"))
    return "<p class='retencion muted'>Eventos disponibles desde: %s</p>" % " &nbsp; ".join(partes)


_CONSULTAS = threading.BoundedSemaphore(CONCURRENCIA)


def _ocupado(titulo, extra=""):
    return ("<main class='evw'>" + _CSS + "<h1>%s</h1>" % _e(titulo) + extra
            + "<div class='banner err'>El buscador de eventos esta ocupado: hay %d consultas en curso, "
              "que es el maximo a la vez. Reintenta en unos segundos.</div></main>" % CONCURRENCIA)


def _con_plaza(fn, titulo):
    """Como mucho CONCURRENCIA consultas a la vez (cada una puede leer TOPE_BYTES durante
    TOPE_SEGUNDOS): la siguiente espera ESPERA_OCUPADO y, si no hay plaza, no lee nada (B-14)."""
    def envuelta(consulta, nodo):
        nodos.nodos_de(nodo)               # nodo invalido o inexistente: 400/404 antes de esperar
        if not _CONSULTAS.acquire(timeout=ESPERA_OCUPADO):
            return _ocupado(titulo)
        try:
            return fn(consulta, nodo)
        finally:
            _CONSULTAS.release()
    envuelta.__doc__ = fn.__doc__
    envuelta.__name__ = fn.__name__
    return envuelta


def _pagina(consulta, nodo):
    """Cuerpo HTML de la pagina Eventos."""
    pids_ = nodos.nodos_de(nodo)
    todos = nodos.es_todos(nodo)
    cab = ("<h1>Eventos</h1><p class='sub'>%s · eventos de Suricata (alertas, DNS, HTTP, TLS, "
           "estadisticas), mas recientes primero.</p>" % (_e(nodos.nombre(nodo)) if todos else _nodo_html(nodo)))
    try:
        f = filtros(consulta)
    except FiltroInvalido as e:
        return ("<main class='evw'>" + _CSS + cab + _retencion(pids_) + _formulario(consulta, nodo, None)
                + "<div class='banner err'>%s</div></main>" % _e(e))
    res = buscar(f, nodo)
    base = _params_filtro(consulta, nodo, f)
    avisos = []
    if res["motivo"]:
        cf = res["fichero_corte"]
        avisos.append(
            "Resultado <b>parcial</b>: se alcanzo el tope de %s. Se reviso desde %s hasta %s; "
            "se paro en el fichero %s de %s. Lo anterior a esa fecha no se reviso."
            % (_e(res["motivo"]), _e(_fmt(res["techo_us"])), _e(_fmt(res["hasta_us"])),
               _e(cf[1]), _e(nodos.nombre(cf[0]))))
        if res.get("sin_garantia"):
            avisos.append("El tope no alcanza para cubrir el margen de desorden de %d s de Suricata en esta "
                          "zona: al continuar puede faltar algun evento escrito fuera de orden."
                          % (DESORDEN_US // 1000000))
    for pid, nombre, cota, por in res["omitidos"]:
        avisos.append("Resultado <b>parcial</b>: el fichero %s de %s (eventos hasta %s) no se reviso: %s."
                      % (_e(nombre), _e(nodos.nombre(pid)), _e(_fmt(cota)), _e(por)))
    if res["rechazados"]:
        avisos.append("Se ignoraron %d fichero(s) no validos (enlace fuera del punto o no regulares): %s."
                      % (len(res["rechazados"]), _e(", ".join("%s/%s" % x for x in res["rechazados"][:5]))))
    filas = []
    for x in res["filas"]:
        ev = x["ev"]
        r = ref(x["pid"], x["fichero"], x["offset"], x["huella"])
        enl = _url(RUTA_DETALLE, base + [("cursor", _q(consulta, "cursor", 64))] + sorted(r.items()))
        filas.append(
            "<tr data-pid='%s'><td class='fecha mono'>%s</td>%s<td>%s</td><td class='res'>%s</td>"
            "<td class='mono'>%s</td><td class='mono'>%s</td><td>%s</td><td><a href='%s'>JSON</a></td></tr>"
            % (_e(x["pid"]), _e(_fmt(x["ts_us"])), ("<td>%s</td>" % _nodo_html(x["pid"])) if todos else "",
               _e(ev.get("event_type")), _resumen(ev), _e(_ipp(ev.get("src_ip"), ev.get("src_port"))),
               _e(_ipp(ev.get("dest_ip"), ev.get("dest_port"))), _e(ev.get("proto", "")), _e(enl)))
    if filas:
        tabla = ("<div class='card'><table><thead><tr><th>Fecha</th>%s<th>Tipo</th><th>Evento</th>"
                 "<th>Origen</th><th>Destino</th><th>Proto</th><th></th></tr></thead><tbody>%s</tbody>"
                 "</table></div>" % ("<th>Nodo</th>" if todos else "", "".join(filas)))
    elif res["parcial"]:
        tabla = ("<div class='banner'>No hay coincidencias en lo que se llego a revisar, pero la busqueda "
                 "es parcial: puede haber eventos en lo que no se reviso.</div>")
    else:
        tabla = "<div class='banner msg'>Sin coincidencias en la ventana elegida.</div>"
    pag = ["<div class='pager'>"]
    if _q(consulta, "cursor", 64):
        pag.append("<a href='%s'>&laquo; Mas recientes</a>" % _e(_url(RUTA, base)))
    if res["siguiente"]:
        txt = "Continuar la busqueda &raquo;" if res["motivo"] and len(res["filas"]) < f["por"] else "Siguientes &raquo;"
        pag.append("<a href='%s'>%s</a>" % (_e(_url(RUTA, base + [("cursor", cursor_txt(res["siguiente"]))])), txt))
    if res["filas"]:
        pag.append("<span class='muted'>%d eventos, del %s al %s</span>"
                   % (len(res["filas"]), _e(_fmt(res["filas"][0]["ts_us"])), _e(_fmt(res["filas"][-1]["ts_us"]))))
    if f["por_todos"] and res["siguiente"] and len(res["filas"]) >= TODOS_MAX:
        pag.append("<span class='muted'>&middot; «Todos» muestra hasta %s por pagina: hay mas, sigue con "
                   "«Siguientes» o acota las fechas</span>" % "{:,}".format(TODOS_MAX).replace(",", "."))
    pag.append(_selector_por(consulta, nodo, f))
    pag.append("</div>")
    pie = ("<p class='muted'>%d fichero(s), %.1f MB leidos%s%s.</p>"
           % (res["ficheros"], res["bytes"] / 1048576.0,
              (", %d linea(s) incompletas o con JSON no valido saltadas" % res["incompletas"]) if res["incompletas"] else "",
              (", %d linea(s) sin marca de tiempo" % res["sin_fecha"]) if res["sin_fecha"] else ""))
    return ("<main class='evw'>" + _CSS + cab + _retencion(pids_) + _formulario(consulta, nodo, f)
            + "".join("<div class='banner'>%s</div>" % a for a in avisos)
            + tabla + "".join(pag) + pie + "</main>")


def _detalle(consulta, nodo):
    """Cuerpo HTML con el JSON completo de un evento (formateado y escapado)."""
    nodos.nodos_de(nodo)
    volver = _url(RUTA, _params_filtro(consulta, nodo) + [("cursor", _q(consulta, "cursor", 64))])
    enlace = "<p><a href='%s'>&laquo; Volver a los eventos</a></p>" % _e(volver)
    try:
        pid, nombre, offset, ln = leer_evento(consulta, nodo)
    except RefInvalida as e:
        return ("<main class='evw'>" + _CSS + "<h1>Evento</h1>" + enlace
                + "<div class='banner err'>Referencia de evento no valida: %s.</div></main>" % _e(e))
    try:
        ev = json.loads(ln.decode("utf-8", "replace"))
        cuerpo = json.dumps(ev, indent=2, ensure_ascii=False)
    except (ValueError, RecursionError):
        ev, cuerpo = None, None
    if cuerpo is None:
        bloque = "<div class='banner err'>La linea del evento no es JSON valido.</div>"
    else:
        bloque = "<div class='card'><pre class='evjson'>%s</pre></div>" % _e(cuerpo)
    ts = ts_us(ev.get("timestamp")) if isinstance(ev, dict) else None
    tipo = ev.get("event_type") if isinstance(ev, dict) else ""
    return ("<main class='evw'>" + _CSS + "<h1>Evento %s</h1>" % _e(tipo or "")
            + "<p class='sub'>%s · %s · fichero <span class='mono'>%s</span>, byte %d</p>"
            % (_nodo_html(pid), _e(_fmt(ts)), _e(nombre), offset)
            + enlace + bloque + "</main>")


pagina = _con_plaza(_pagina, "Eventos")
detalle = _con_plaza(_detalle, "Evento")
