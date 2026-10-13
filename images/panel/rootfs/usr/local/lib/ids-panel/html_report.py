#!/usr/bin/env python3
"""Genera un reporte HTML grafico de ataques desde eve.json de Suricata.

Muestra: puertos de destino atacados, IPs origen (atacantes), IPs destino
(objetivos), linea de tiempo por hora, y una tabla origen IP:puerto -> destino
IP:puerto con firma, protocolo, primera/ultima hora y duracion. Autocontenido
(sin dependencias externas): se abre en el navegador o se imprime a PDF.

Uso: html_report.py [ventana_min] (--nodo pNNN | --todos)   (ventana por defecto 1440)
Lee los eventos de cada punto (nodos.ficheros_eventos: DATOS/<pid>/eve.json*, dns.json*).
Salida: nodos.dir_salida(nodo)/report-AAAAMMDD-HHMM.html (PANEL/nodos/<pid>/ o nodos/_todos/)
"""
import glob, gzip, io, json, os, re, sys, html, time
import array, struct, bisect, argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nodos

# Zona horaria del panel (el contenedor corre con TZ=UTC): los dias de las metricas y las
# horas del informe van en IDS_TZ. Windows no tiene tzset (solo pruebas): ahi se deja.
IDS_TZ = os.environ.get("IDS_TZ", "America/Guayaquil")
if hasattr(time, "tzset"):
    os.environ["TZ"] = IDS_TZ
    time.tzset()
try:
    from zoneinfo import ZoneInfo
    TZ_EC = ZoneInfo(IDS_TZ)
except Exception:                       # sin tzdata: offset fijo (Ecuador no tiene horario de verano)
    TZ_EC = (timezone(timedelta(hours=-5)) if IDS_TZ == "America/Guayaquil"
             else timezone(timedelta(seconds=time.localtime().tm_gmtoff)))

# --- Que nodo se genera: exactamente uno de --nodo pNNN o --todos. Se valida ANTES de
# escribir nada: un id mal formado o que no existe sale con error, nunca se amplia a todos.
_ap = argparse.ArgumentParser(prog="html_report.py")
_ap.add_argument("ventana_min", nargs="?", type=int, default=1440)
_g = _ap.add_mutually_exclusive_group(required=True)
_g.add_argument("--nodo")
_g.add_argument("--todos", action="store_true")
_args = _ap.parse_args()
try:
    if _args.todos:
        NODO = nodos.TODOS
    elif _args.nodo == nodos.TODOS:
        raise nodos.NodoInvalido(_args.nodo)        # --nodo pide un punto; lo acumulado es --todos
    else:
        NODO = nodos.validar_nodo(_args.nodo)
except nodos.NodoInvalido:
    print("html_report: nodo mal formado: %r (se espera pNNN o --todos)" % _args.nodo, file=sys.stderr)
    sys.exit(2)
except nodos.NodoInexistente:
    print("html_report: punto inexistente: %s" % _args.nodo, file=sys.stderr)
    sys.exit(3)

# Extraccion por regex (mucho mas rapida que json.loads por linea sobre cientos de MB).
_RE = {k: re.compile(p) for k, p in {
    "ts": r'"timestamp":"([^"]+)"',
    "src_ip": r'"src_ip":"([^"]+)"',
    "dest_ip": r'"dest_ip":"([^"]+)"',
    "src_port": r'"src_port":(\d+)',
    "dest_port": r'"dest_port":(\d+)',
    "proto": r'"proto":"([^"]+)"',
    "sig": r'"signature":"((?:[^"\\]|\\.)*)"',
    "cat": r'"category":"((?:[^"\\]|\\.)*)"',
    "sev": r'"severity":(\d+)',
    "sid": r'"signature_id":(\d+)',
    "rev": r'"rev":(\d+)',
    "flow_id": r'"flow_id":(\d+)',
    "rrname": r'"rrname":"([^"]+)"',
    # El nodo del CPE NO sale de in_iface (dentro de DATOS/<pid>/ es la interfaz interna del
    # contenedor suricata): sale del fichero de donde se lee el evento (ficheros_eventos).
}.items()}

# Firmas de "infeccion" (CnC/botnet/troyano): mismas claves que el informe. Para marcar
# INFECTADO no basta una: se exige repeticion (UMBRAL_INFECTADO) o >=2 firmas distintas.
CNC_KW = ("cnc", "c2 ", "command and control", "checkin", "check-in", "botnet", "mirai",
          "katana", "trojan", "ransom", " rat ", "coinmin", "cryptomin", "compromised")
UMBRAL_INFECTADO = 3

# DNS SOSPECHOSO (Camino A): alertas de consulta DNS a dominios de botnet/C2/malware.
# Se detecta una firma que hable de DNS y ademas de contexto malicioso. Un CPE que
# consulta esos dominios probablemente esta infectado -> lista aparte en el MikroTik.
DNS_MAL = ("malware", "trojan", "botnet", "c2 ", "cnc", "command and control", "dga",
           "sinkhole", "hostile", "phishing", "stealer", "ransom", "known bad",
           "observed", "suspicious domain")
UMBRAL_DNS = 3
def es_dns_sospechoso(sig, cat):
    s = (sig or "").lower(); c = (cat or "").lower()
    if "dns" not in s and "dns" not in c:
        return False
    return any(k in s for k in DNS_MAL) or "c2" in c or "command and control" in c

# --- Allowlist "nunca bloquear": IPs/CIDR que JAMAS entran a cuarentena (infra, clientes
# criticos). El panel las gestiona; aqui solo se excluyen de las listas de candidatos. ---
import ipaddress as _ipm
NUNCA_FILE = os.path.join(nodos.CONF, "nunca-bloquear.lst")
_NUNCA_IPS = set(); _NUNCA_NETS = []
try:
    for _l in open(NUNCA_FILE, encoding="utf-8"):
        _l = _l.split("#", 1)[0].strip()
        if not _l:
            continue
        try:
            if "/" in _l:
                _NUNCA_NETS.append(_ipm.ip_network(_l, strict=False))
            else:
                _NUNCA_IPS.add(_l)
        except ValueError:
            pass
except OSError:
    pass
def nunca_bloquear(ip):
    if ip in _NUNCA_IPS:
        return True
    if _NUNCA_NETS:
        try:
            a = _ipm.ip_address(ip)
            return any(a in n for n in _NUNCA_NETS)
        except ValueError:
            pass
    return False

DASH_CONF = os.path.join(nodos.CONF, "panel.conf")

def _conf_key(k, default):
    try:
        for _l in open(DASH_CONF, encoding="utf-8"):
            if _l.strip().startswith(k + "="):
                return _l.split("=", 1)[1].strip()
    except OSError:
        pass
    return default
# Doble senal: para CONFIRMAR infeccion se exigen >=2 senales independientes (repeticion,
# variedad de firmas, fan-out, volumen), o una senal abrumadora. Menos falsos positivos.
# Se apaga con DOBLE_SENAL=0 en conf/panel.conf.
DOBLE_SENAL = _conf_key("DOBLE_SENAL", "1") == "1"

# --- Que origenes son CPEs TUYOS ---
# El motor de cuarentena existe para tus abonados. Sin este filtro, una IP de internet
# que dispara una firma ENTRANTE (ET Open trae varias con la palabra "compromised", que
# aqui cuenta como infeccion) entraba como "CPE infectado", puntuaba en el ranking de
# riesgo y, con politicas automaticas, podia acabar en la address-list de cuarentena:
# no bloquea nada util y ensucia la lista. Los ataques de fuera se siguen viendo, pero
# en su propio apartado.
# Configurable con MIS_REDES=CIDR,CIDR en conf/panel.conf (util si das IP
# publica a tus clientes): vale para todos los puntos. Sin MIS_REDES: las `redes` de abonados
# DE CADA PUNTO, y en --todos cada evento con las redes de SU punto, nunca la union (auditoria
# A-14: con la union, una IP de la red de p002 vista en p001 contaba como abonado de p001 y el
# envio masivo de «Todos» la mandaba al router de p001). Si un punto no tiene redes: privadas
# RFC1918 + CGNAT.
_REDES_DEFECTO = [_ipm.ip_network(_t) for _t in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]

def _redes_de_texto(txt):
    out = []
    for _t in (txt or "").replace(";", ",").split(","):
        _t = _t.strip()
        if not _t:
            continue
        try:
            out.append(_ipm.ip_network(_t, strict=False))
        except ValueError:
            pass
    return out

_MIS_NETS_GLOBAL = _redes_de_texto(_conf_key("MIS_REDES", ""))
_MIS_NETS_PID = {}

def mis_redes(pid):
    """Las redes de abonados del punto `pid` (MIS_REDES si esta puesto; si no, las del punto;
    si no tiene, las privadas)."""
    if _MIS_NETS_GLOBAL:
        return _MIS_NETS_GLOBAL
    r = _MIS_NETS_PID.get(pid)
    if r is None:
        r = _redes_de_texto(",".join(x for x in ((nodos.punto(pid) or {}).get("redes") or [])
                                     if isinstance(x, str))) if pid else []
        r = r or _REDES_DEFECTO
        _MIS_NETS_PID[pid] = r
    return r

_MI_CPE_CACHE = {}
_MI_CPE_CACHE_MAX = 100_000     # IPs distintas por corrida; mas alla se calcula sin guardar

def es_mi_cpe(ip, pid=None):
    """True si la IP pertenece a las redes de abonados de SU punto, False si es de internet.

    `ip` puede ser una IP o una identidad `pid|ip` (entonces el punto sale de ahi); si no, el
    punto es `pid` o, en el informe de un solo punto, ese punto. En --todos sin punto no se
    supone ninguno: no es un abonado (nunca se mezclan las redes de varios puntos).

    Con memoria por (punto, IP): se llama por evento (medio millon de veces en 1,5 M de lineas)
    y construir un objeto ipaddress cada vez era el 12%% del generador; las IPs se repiten
    miles de veces, asi que la respuesta se guarda. Acotada para no crecer con un barrido."""
    if "|" in ip:
        pid, ip = ip.split("|", 1)
    if not pid and NODO != nodos.TODOS:
        pid = NODO
    if not pid:
        return False
    k = (pid, ip)
    v = _MI_CPE_CACHE.get(k)
    if v is None:
        try:
            a = _ipm.ip_address(ip)
            v = any(a.version == n.version and a in n for n in mis_redes(pid))
        except ValueError:
            v = False
        if len(_MI_CPE_CACHE) < _MI_CPE_CACHE_MAX:
            _MI_CPE_CACHE[k] = v
    return v


# Destinos CONFIABLES (falsos positivos): p.ej. un DNS que dispara alertas en muchos CPEs.
# Las alertas HACIA estas IPs no cuentan -> los clientes dejan de ser candidatos por su culpa.
DEST_OK_FILE = os.path.join(nodos.CONF, "destinos-confianza.lst")
DEST_OK = set()
try:
    for _l in open(DEST_OK_FILE, encoding="utf-8"):
        _l = _l.split("#", 1)[0].strip()
        if _l:
            DEST_OK.add(_l)
except OSError:
    pass

# Resolutores DNS: un CPE que pregunta un dominio malicioso a uno de estos NO lo esta
# atacando; lo esta USANDO. La prueba es el dominio, no la IP del DNS. Sin esta lista el
# resolutor subia al "Top destinos mas atacados" como victima (y 1.1.1.2 es el DNS de
# Cloudflare que bloquea malware). Los publicos vienen de serie porque no son de nadie
# tuyo y nunca son victima de una consulta; los del ISP se anaden en Ajustes -> DNS.
RESOLUTORES_FILE = os.path.join(nodos.CONF, "resolutores.lst")
RESOLUTORES_DEFECTO = ("1.1.1.1", "1.1.1.2", "1.1.1.3", "1.0.0.1", "8.8.8.8", "8.8.4.4",
                       "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
                       "208.67.222.123", "208.67.220.123")   # OpenDNS FamilyShield
import ipaddress as _ipr
RESOLUTORES = []
try:
    for _l in open(RESOLUTORES_FILE, encoding="utf-8"):
        _l = _l.split("#", 1)[0].strip()
        if _l:
            try:
                RESOLUTORES.append(_ipr.ip_network(_l, strict=False))
            except ValueError:
                pass
except OSError:
    RESOLUTORES = [_ipr.ip_network(x) for x in RESOLUTORES_DEFECTO]

def es_via_resolutor(dst, dport, sig="", cat=""):
    """La alerta es una consulta DNS a un resolutor conocido: cuenta para el CPE, no como
    ataque al destino. Tiene que ser DNS DE VERDAD (puerto 53 o firma de DNS): un resolutor
    tambien puede ser atacado por otro puerto, y eso si es un ataque."""
    if not RESOLUTORES or not dst or dst == "?":
        return False
    if str(dport) != "53" and not es_dns_sospechoso(sig, cat):
        return False
    try:
        o = _ipr.ip_address(dst)
    except ValueError:
        return False
    return any(o.version == r.version and o in r for r in RESOLUTORES)

def campos(line):
    def g(k):
        m = _RE[k].search(line)
        return m.group(1) if m else ""
    return g

# Salidas de este nodo (o de la vista acumulada): PANEL/nodos/<pid>/ o PANEL/nodos/_todos/.
# Los eventos se leen de DATOS/<pid>/ (solo lectura) con nodos.ficheros_eventos.
# Se crea despues de tomar el candado.
OUTDIR = nodos.dir_salida(NODO, crear=False)

# --- De que MikroTik es cada alerta ---
# Del fichero de donde sale: DATOS/<pid>/ es el espejo de UN punto. Un punto = un router
# del multi-nodo viejo (id = pid). En --todos se ven varios: van los chips de nodo.
MULTI_ROUTER = NODO == nodos.TODOS

def nombre_router(rid):
    return nodos.nombre(rid) if rid else ""

def clave_cpe(ip, rid):
    """Identidad de un CPE: SIEMPRE (punto, IP), tambien con un solo punto. La IP sola no
    identifica a nadie cuando dos routers usan el mismo rango privado."""
    return nodos.clave(rid, ip)

def _chip_nodo(clave):
    """Etiqueta del nodo. Con un solo nodo (informe de un punto) no se muestra (seria ruido)."""
    r = rid_de(clave)
    if not r or not MULTI_ROUTER:
        return ""
    return f"<span class='nodochip' title='Espejo de este MikroTik'>{esc(nombre_router(r))}</span>"

def ip_de(clave):
    """La IP pelada de una identidad de CPE (para mostrar, geolocalizar o bloquear)."""
    return clave.split("|", 1)[1] if "|" in clave else clave

def rid_de(clave):
    """El router (pid) de una identidad de CPE ("" si no lo trae)."""
    return clave.split("|", 1)[0] if "|" in clave else ""

def _etq_cpe(clave):
    """Texto de un CPE para el mapa: la IP, y en --todos tambien el nombre de su nodo."""
    r = rid_de(clave)
    return ip_de(clave) + ((" (" + nombre_router(r) + ")") if (MULTI_ROUTER and r) else "")

def _json_js(x):
    """JSON para meter dentro de <script>: un "</script>" en un dato no cierra el bloque."""
    return json.dumps(x).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")

# IPs ya enviadas a la cuarentena del MikroTik (lo escribe el panel): para que el boton
# del Top muestre "En cuarentena" en vez de "Cuarentena" cuando ya se envio.
# Son DOS listas (infectados y DNS sospechoso): si solo se mira la primera, un CPE
# enviado a la de DNS aparece en el Top como si no estuviera en cuarentena.
# El panel publica aqui lo que el reporte necesita saber de el. Va aparte del .conf de
# feeds a proposito: ese lleva las CLAVES y aqui no hace falta ninguna.
try:
    _FLAGS = json.load(open(os.path.join(nodos.ESTADO, "panel-flags.json"), encoding="utf-8"))
except (OSError, ValueError):
    _FLAGS = {}
_AIDB_REPORTAR = bool(_FLAGS.get("aidb_reportar"))

_MK_ENVIADOS = set()      # claves pid|ip (las mismas que usa este generador)
for _pe in (os.path.join(nodos.ESTADO, "cuarentena-enviados.json"),
            os.path.join(nodos.ESTADO, "dns-enviados.json")):
    try:
        _MK_ENVIADOS |= set(json.load(open(_pe, encoding="utf-8")).keys())
    except Exception:
        pass
# Ventana del resumen en MINUTOS (primer argumento); por defecto 24h. Con una ventana corta
# (p.ej. 30 min) los cuadros muestran solo la actividad reciente: una IP atendida hace
# rato se cae sola del top al no tener alertas nuevas.
VENTANA_MIN = _args.ventana_min
if VENTANA_MIN < 5:
    VENTANA_MIN = 5
cutoff = time.time() - VENTANA_MIN * 60
# la linea de tiempo apunta a ~48 barras: el bucket se adapta a la ventana (min 1 min)
BUCKET_MIN = max(1, round(VENTANA_MIN / 48))
BUCKET = BUCKET_MIN * 60
MAX_LINES = 20_000_000
MAX_FLUJOS = 200_000     # tope de flujos unicos guardados (evita agotar la RAM en espejos de ISP)

# Red de seguridad: limitar la memoria del proceso. Si se pasa, muere con MemoryError
# en vez de tumbar el servidor (paso en un espejo real: millones de flujos unicos).
# 1 GiB: el contenedor del panel tiene mas memoria y el generador corre de un nodo en uno.
try:
    import resource
    _cap = 1024 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (_cap, _cap))
except Exception:
    pass

# Candado: si ya hay una generacion en curso, salir (evita dos generadores a la vez, de
# cualquier nodo). Va en /tmp (tmpfs del contenedor): /run es de solo lectura y abrir ahi
# fallaba SIEMPRE, y el generador salia con 0 sin generar nada ni decirlo.
LOCK_FILE = os.environ.get("IDS_HREP_LOCK", "/tmp/ids-hrep.lock")
try:
    import fcntl
except ImportError:                     # Windows (solo pruebas): sin candado
    fcntl = None
try:
    _lock = os.open(LOCK_FILE, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
except OSError as _e:
    print("html_report: no se puede abrir el candado %s: %s" % (LOCK_FILE, _e), file=sys.stderr)
    sys.exit(1)
if fcntl is not None:
    try:
        fcntl.flock(_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("html_report: ya hay una generacion en curso (%s); no se genera" % LOCK_FILE,
              file=sys.stderr)
        sys.exit(75)
try:
    os.makedirs(OUTDIR, mode=0o700, exist_ok=True)
except OSError:
    pass

def _abrir_bin(p):
    """Fichero de eventos del punto en binario, SIN seguir enlaces y solo si es regular (A-26):
    datos/<pid> lo escribe el contenedor suricata; un enlace o una FIFO no se leen."""
    import stat as _st
    fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_BINARY", 0))
    try:
        if not _st.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("%s: no es un fichero regular" % p)
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise

def opener(p):
    if p.endswith(".gz"):
        return io.TextIOWrapper(gzip.GzipFile(fileobj=_abrir_bin(p), mode="rb"),
                                encoding="utf-8", errors="replace")
    return io.TextIOWrapper(_abrir_bin(p), encoding="utf-8", errors="replace")

_RE_TS_LINEA = re.compile(r'"timestamp":"([^"]+)"')

def abrir_desde(p, corte, margen=4 * 1024 * 1024):
    """Abre un log de Suricata posicionado justo antes de `corte`.

    eve.json y dns.json son append-only y van ordenados por tiempo, asi que para una
    ventana de unas horas no hace falta leer el archivo entero: se busca por BISECCION
    el primer punto dentro de la ventana y se empieza ahi. En un dns.json de 1,8 GB con
    ventana de 6 h, esto pasa de leer 1,8 GB a leer unos pocos cientos de MB.

    Los .gz no se pueden posicionar (habria que descomprimir igual), asi que se abren
    como siempre; de todas formas los rotados viejos ya se saltan por su mtime.
    El margen deja un colchon: es preferible leer de mas que perderse eventos."""
    if p.endswith(".gz") or not corte:
        return opener(p)
    try:
        f = opener(p)
        tam = os.fstat(f.fileno()).st_size
    except OSError:
        return opener(p)
    if tam <= margen * 2:
        return f
    lo, hi = 0, tam
    try:
        while hi - lo > margen:
            mid = (lo + hi) // 2
            f.seek(mid)
            f.readline()                  # la primera suele venir cortada: se tira
            ts = None
            for _ in range(20):           # alguna linea puede no traer timestamp
                ln = f.readline()
                if not ln:
                    break
                m = _RE_TS_LINEA.search(ln)
                if m:
                    ts = parse_ts(m.group(1))
                    if ts:
                        break
            if ts is None:
                break                     # no se pudo orientar: leer desde donde se este
            if ts < corte:
                lo = mid
            else:
                hi = mid
        ini = max(0, lo - margen)
        f.seek(ini)
        if ini:
            # alinear al principio de una linea entera. Solo si NO se empieza en 0: en el
            # offset 0 la primera linea ya esta entera y descartarla perdia un evento.
            f.readline()
    except (OSError, ValueError):
        f.seek(0)
    return f

def cargar_exclusiones():
    """Reglas de exclusion: {tipo:'dst'|'src', ip, puertos:[int], nodo}. Desde
    conf/exclusiones.json (apartado Exclusiones) + lineas IGNORAR_* legacy de conf/report.conf.
    `nodo` vacio = todos los nodos; con nodo, la regla solo aplica a los eventos de ese punto."""
    reglas = []; ahora = time.time()
    try:
        data = json.load(open(os.path.join(nodos.CONF, "exclusiones.json"), encoding="utf-8"))
        if isinstance(data, list):
            for r in data:
                if not r.get("ip"):
                    continue
                try: hasta = float(r.get("hasta") or 0)
                except (TypeError, ValueError): hasta = 0
                if hasta and ahora > hasta:
                    continue                             # exclusion temporal vencida
                _rn = str(r.get("nodo") or "")
                reglas.append((r.get("tipo", "dst"), r["ip"],
                               [int(p) for p in (r.get("puertos") or []) if str(p).isdigit()],
                               str(r.get("sid") or ""),
                               "" if _rn == nodos.TODOS else _rn))
    except Exception:
        pass
    try:
        for l in open(os.path.join(nodos.CONF, "report.conf"), encoding="utf-8"):
            l = l.strip()
            if l.startswith("IGNORAR_DESTINOS="):
                reglas += [("dst", x.strip(), [], "", "") for x in l.split("=", 1)[1].split(",") if x.strip()]
            elif l.startswith("IGNORAR_ORIGENES="):
                reglas += [("src", x.strip(), [], "", "") for x in l.split("=", 1)[1].split(",") if x.strip()]
    except OSError:
        pass
    return reglas

EXCL = cargar_exclusiones()

def excluido(src, dst, dport, sid=None):
    """`src` es la identidad del CPE (pid|ip): se compara su IP, y el nodo de la regla
    (si lo tiene) con el punto del evento."""
    for tipo, ip, pts, rsid, rnodo in EXCL:
        if rnodo and rnodo != rid_de(src):
            continue                                     # regla de otro nodo
        quien = dst if tipo == "dst" else ip_de(src)
        if quien != ip:
            continue
        if pts and not (dport is not None and dport in pts):
            continue
        if rsid and str(sid) != rsid:                    # regla ligada a una firma concreta
            continue
        return True
    return False

_TRAD = [
    (("poor reputation", "cins", "compromised ip", "dshield", "spamhaus", "abuse.ch", "known attacker", "cinsscore"), "Mala reputacion"),
    (("tor exit", "tor node", "tor "), "Red Tor"),
    (("katana",), "Botnet Katana"),
    (("mirai",), "Botnet Mirai"),
    (("cnc", "c2 ", "command and control", "checkin", "check-in"), "Botnet CnC"),
    (("botnet",), "Botnet"),
    (("ransom",), "Ransomware"),
    (("trojan",), "Troyano"),
    (("coinmin", "cryptomin", "miner"), "Criptomineria"),
    (("ssh scan",), "Escaneo SSH"),
    (("brute", "password"), "Fuerza bruta"),
    # Sin esta linea, traducir() nunca producia "Spam": la categoria de CPE 'spam', su
    # address-list y la regla del 25/465/587 existian pero no se le aplicaban NUNCA a
    # nadie. Nada fallaba; simplemente no clasificaba. Va aqui, despues de fuerza bruta,
    # para que un "SMTP brute force" siga siendo fuerza bruta.
    (("outbound spam", "spambot", "smtp", "open relay", "mail relay"), "Spam"),
    (("rdp", "vnc"), "RDP/VNC"),
    (("telnet",), "Escaneo Telnet"),
    (("tr-069", "cwmp", "7547"), "Escaneo TR-069"),
    (("port scan", "portscan", "sweep", "recon", "barrido"), "Escaneo de puertos"),
    (("scan",), "Escaneo saliente"),
    (("exploit", "cve-", "shellcode", "attempted-admin"), "Exploit"),
    (("connectivity check", "connectivity-check"), "Chequeo de conectividad"),
    (("403 forbidden",), "Acceso denegado (403)"),
    (("go http client",), "Cliente HTTP Go"),
    (("fake wget", "wget 3.0"), "User-Agent falso"),
    (("user_agent", "user agent", "user-agent"), "User-Agent raro"),
    (("bittorrent", "p2p", "dht"), "BitTorrent / P2P"),
    (("stun ",), "STUN (video)"),
    (("snmp",), "Acceso SNMP"),
    (("dyn_dns", "dynamic_dns", "dyndns", "duckdns", "no-ip"), "DNS dinamico"),
    (("dns query", ".cc tld", ".su tld", ".top domain", " tld", "dns lookup"), "DNS sospechoso"),
    (("adware", "pup"), "Adware / PUP"),
    (("malware", "compromised"), "Trafico de malware"),
    (("quic",), "Anomalia QUIC"),
    (("tls", "ssl"), "Anomalia TLS/SSL"),
    (("http",), "Anomalia HTTP"),
    (("stream", "tcp "), "Anomalia TCP"),
]
_TRAD_CACHE = {}
_TRAD_CACHE_MAX = 20_000        # firmas distintas; ET Open entera cabe de sobra

def traducir(sig):
    """Categoria humana de una firma. Con memoria por firma: la tabla _TRAD se recorria
    entera por ALERTA (11,7 M comparaciones en 1,5 M de lineas) y las firmas distintas
    son pocas centenas."""
    v = _TRAD_CACHE.get(sig)
    if v is not None:
        return v
    v = _traducir_lento(sig)
    if len(_TRAD_CACHE) < _TRAD_CACHE_MAX:
        _TRAD_CACHE[sig] = v
    return v

def _traducir_lento(sig):
    s = sig.lower()
    for claves, txt in _TRAD:
        if any(k in s for k in claves):
            return txt
    # Sin traduccion salia la firma ENTERA, con su prefijo de ruleset, y la columna de
    # categorias quedaba ilegible ("ET HUNTING Terse Unencrypted Request for Google...").
    # Se le quita el prefijo y se acota.
    limpio = re.sub(r"^(?:ET|GPL)\s+(?:[A-Z_]{3,}\s+)?", "", sig).strip() or sig
    return (limpio[:44] + "\u2026") if len(limpio) > 45 else limpio

_TS_CACHE = {}
_TS_CACHE_MAX = 200000

def _parse_ts_lento(s):
    # Parsea con el offset de la marca (eve.json trae -0500) para obtener el epoch absoluto.
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except (ValueError, TypeError):
            pass
    try:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=TZ_EC).timestamp()
    except Exception:
        return None

def parse_ts(s):
    """Epoch de una marca de eve.json, CON MEMORIA.

    strptime es carisimo y en un espejo de ISP esto se llama millones de veces por
    corrida: era el grueso de los 9 minutos de CPU que tardaba el generador. La clave del
    cache es el SEGUNDO (fecha, hora y zona, sin los microsegundos), asi que miles de
    lineas del mismo segundo colapsan en un unico strptime.

    Se pierde la precision por debajo del segundo, y no la usa nadie: todo se compara
    contra la ventana, se agrupa en barras de un minuto o mas, o se guarda como entero."""
    if not s:
        return None
    # "2026-09-23T11:48:39.123456-0500" -> "2026-09-23T11:48:39" + "-0500"
    clave = (s[:19] + s[26:]) if len(s) > 26 else s
    v = _TS_CACHE.get(clave)
    if v is not None:
        return v
    r = _parse_ts_lento(clave)
    if r is not None and len(_TS_CACHE) < _TS_CACHE_MAX:
        _TS_CACHE[clave] = r
    return r

by_dport = Counter()
by_src = Counter()
ultima_by_src = {}                 # clave pid|ip -> epoch de su ultima alerta (evidencia reciente)
by_dst = Counter()
by_hour = Counter()
pais_dst = Counter()   # alertas por PAIS del destino (para el mapa "a donde atacan")
# Detalle por pais para el mapa: que IPs destino, que puertos y que CPEs (tu red) peticionan.
# OJO con la cardinalidad: pais_srcs y pais_ports no guardan "uno por CPE/puerto" sino un
# par (pais, CPE) y (pais, puerto) -> en un espejo de ISP un CPE que toca 20 paises ocupa
# 20 entradas y el crecimiento es MULTIPLICATIVO. Sin tope es el mismo tipo de fuga que
# tumbo la VM por OOM. Solo se muestran los 4-6 primeros de cada lista, asi que acotar no
# cambia lo que se ve (el "+N mas" pasa a ser un minimo, que sigue siendo cierto).
# --- Metricas por DIA: el numero que un ISP tiene que poder ENSEÑAR ---------------
# Los reportes HTML se podan a los 3 dias, asi que la tendencia no se puede reconstruir
# desde ellos. Esto se guarda aparte y sobrevive.
#
# Se acumula de forma INCREMENTAL (solo lo posterior a la ultima corrida) en vez de
# recontar la ventana: la ventana es configurable y si alguien la baja a 30 min, recontar
# daria un "hoy" ridiculamente bajo sin avisar de nada. Con el incremental, el total del
# dia es correcto sea cual sea la ventana.
# Lo que NO es abuso hacia fuera. Molesta en el panel, pero no hace que a nadie le
# baneen una IP: si BitTorrent o un chequeo de conectividad con Google cuentan como
# "ataque saliente", el numero que hay que poder enseñar no significa nada. Se siguen
# viendo, pero aparte.
CATS_NO_ABUSO = {
    "BitTorrent / P2P", "STUN (video)", "Chequeo de conectividad", "Anomalia QUIC",
    "Anomalia TLS/SSL", "Anomalia HTTP", "Anomalia TCP", "Cliente HTTP Go",
    "User-Agent raro", "User-Agent falso", "DNS dinamico", "Acceso denegado (403)",
}

METRICAS_FILE = os.path.join(OUTDIR, "metricas.json")
METRICAS_DIAS = 400          # algo mas de un año de tendencia; el archivo sigue siendo pequeño
METRICAS_MAX_CPES = 5000     # tope del conjunto de CPEs por dia (por encima, el conteo es un minimo)
dias_m = defaultdict(lambda: {"sal": 0, "ent": 0, "ruido": 0, "cpes": set(),
                              "puertos": Counter(), "cats": Counter(), "nodos": Counter()})

MAX_PAIS_CARD = 800
pais_ips = defaultdict(Counter)     # cc -> Counter(ip_destino -> alertas)
pais_ports = defaultdict(Counter)   # cc -> Counter("dport/proto" -> alertas)
pais_srcs = defaultdict(Counter)    # cc -> Counter(cpe_origen -> alertas)

def _cuenta_acotada(contador, clave):
    """Suma 1 solo si la clave ya existe o aun hay sitio: cota la RAM por pais."""
    if clave in contador or len(contador) < MAX_PAIS_CARD:
        contador[clave] += 1

# --- GeoIP IP->pais (offline, base DB-IP lite via ip-location-db, CC-BY-4.0) ---
# Formato compacto en geo/ipv4.bin: [uint32 N][N x start u32]
# [N x end u32][N x 2 bytes cc]. Lo genera el instalador; aqui solo se consulta con
# busqueda binaria (Python puro, sin dependencias). Si falta, pais() devuelve "".
GEOIP_BIN = os.path.join(nodos.GEO, "ipv4.bin")
_G_S = _G_E = _G_C = None
_G_loaded = False
_G_ok = False
_geo_cache = {}

def _geo_load():
    global _G_S, _G_E, _G_C, _G_loaded, _G_ok
    if _G_loaded:
        return
    _G_loaded = True
    try:
        with open(GEOIP_BIN, "rb") as f:
            n = struct.unpack("<I", f.read(4))[0]
            s = array.array("I"); s.fromfile(f, n)
            e = array.array("I"); e.fromfile(f, n)
            c = f.read(n * 2)
        if n > 0 and len(c) == n * 2 and s.itemsize == 4:
            _G_S, _G_E, _G_C, _G_ok = s, e, c, True
    except Exception:
        _G_ok = False

def pais(ip):
    """ISO2 del pais de una IPv4 publica (o '' si no se sabe / es privada / IPv6)."""
    if not ip or ":" in ip:
        return ""
    v = _geo_cache.get(ip)
    if v is not None:
        return v
    _geo_load()
    r = ""
    if _G_ok:
        try:
            a = _ipm.IPv4Address(ip)
            if not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast):
                n = int(a)
                i = bisect.bisect_right(_G_S, n) - 1
                if i >= 0 and n <= _G_E[i]:
                    r = _G_C[2 * i:2 * i + 2].decode("ascii", "ignore")
        except Exception:
            r = ""
    _geo_cache[ip] = r
    return r
flujos = {}            # (src,sport,dst,dport,proto,sig) -> [count, first, last]
ips_vistas = set()     # TODAS las IPs vistas en la ventana (cualquier evento, no solo alertas)
MAX_IPS = 300000       # tope de cardinalidad del set (proteje la RAM en flotas grandes)
# --- Senales para el PUNTAJE DE RIESGO por CPE (IP origen) 0-100 ---
NOW = time.time()
sev_by_src = {}                    # peor severidad Suricata vista (1=alta..3=baja)
dst_by_src = defaultdict(set)      # IPs destino distintas (barrido/propagacion)
via_dns = Counter()                # consultas maliciosas POR resolutor (no es ataque al DNS)
via_dns_src = defaultdict(set)     # que CPEs las hicieron, por resolutor
dpt_by_src = defaultdict(set)      # puertos destino distintos (port-sweep)
# Con CUENTA, no solo distintos: para saber si un CPE es "el del 25/tcp" hace falta el
# volumen, no la variedad. Acotados igual que el resto para no comerse la RAM.
dport_cnt_by_src = defaultdict(Counter)   # CPE -> Counter("25/tcp" -> alertas)
cat_cnt_by_src = defaultdict(Counter)     # CPE -> Counter("Fuerza bruta" -> alertas)
n5_by_src = Counter()              # alertas en los ultimos 5 min (actividad ahora)
n1h_by_src = Counter()             # alertas en la ultima hora (sostenido)
patron_src = defaultdict(set)      # (sig,dport) -> CPEs que lo comparten (correlacion de flota)
inf_hits = Counter()               # alertas CnC/botnet por CPE (para confirmar infeccion)
inf_sids = defaultdict(set)        # firmas CnC distintas por CPE (SID o texto)
inf_sig = {}                       # firma CnC mas reciente por CPE (para el motivo)
inf_sig_ts = {}                    # y cuando fue: leyendo de nuevo a viejo, "la ultima
                                   # leida" seria la mas ANTIGUA. Se ancla al timestamp.
dns_hits = Counter()               # alertas de DNS sospechoso por CPE
dns_sids = defaultdict(set)        # firmas DNS distintas por CPE
dns_sig = {}                       # firma DNS mas reciente por CPE
dns_sig_ts = {}                    # idem: la mas reciente por tiempo, no por orden
pruebas_by_src = defaultdict(list)  # evidencia por alerta (SID/rev/flow_id/dst/ts) por CPE, tope 8
MAX_CARD = 2500                    # tope por set (el score satura mucho antes; protege RAM)
# Por DOMINIO (no solo por CPE): que se pregunta, quien lo pregunta y por donde. Es lo que
# se presenta: el dominio es la prueba, la IP de la red es el culpable, el DNS el canal.
dom_cnt = Counter()                # dominio malicioso -> consultas
dom_src = defaultdict(Counter)     # dominio -> Counter(CPE) (quien y cuantas veces)
dom_por = {}                       # dominio -> por que es malo ("feed: urlhaus" | "firma: ...")
dom_res = defaultdict(Counter)     # dominio -> Counter(resolutor usado)
MAX_DOM = 3000                     # tope de dominios distintos (DGA/tunel DNS crecen sin fin)

def _apuntar_dominio(dom, src, dst, por):
    """Una consulta a un dominio malicioso: la apunta al dominio, al CPE y al resolutor.
    Acotado: dominios nuevos solo hasta MAX_DOM; CPEs por dominio hasta MAX_CARD."""
    if not dom or (dom not in dom_cnt and len(dom_cnt) >= MAX_DOM):
        return
    dom_cnt[dom] += 1
    if src and (src in dom_src[dom] or len(dom_src[dom]) < MAX_CARD):
        dom_src[dom][src] += 1
    if dst and dst != "?" and len(dom_res[dom]) < 8:
        dom_res[dom][dst] += 1
    if dom not in dom_por and por:
        dom_por[dom] = por[:90]
total = 0
seen = 0
ts_min = None          # timestamp del evento mas antiguo dentro de la ventana (cobertura real)
ts_max = 0             # el mas nuevo: la marca desde la que contara la proxima corrida
try:                   # hasta donde se conto ya (para no contar dos veces ni perderse nada)
    _mprev = json.load(open(METRICAS_FILE, encoding="utf-8"))
    METR_DESDE = float(_mprev.get("ultimo_ts") or 0)
except (OSError, ValueError, TypeError):
    _mprev = {}
    METR_DESDE = 0.0

# --- Camino B: dominios malos (feeds URLhaus/ThreatFox) para cruzar con las consultas DNS.
# DEBE definirse ANTES del bucle: el parseo de dns.json usa DOM_OK/dominio_malo. ---
FEEDS_DIR = nodos.FEEDS
DOM_MAL = {}          # dominio -> fuente (procedencia)
DOM_OK = False
try:
    _dm = json.load(open(os.path.join(FEEDS_DIR, "reputation.meta"), encoding="utf-8"))
    # caducidad fina por fuente ya aplicada al rearmar domains.lst; guarda gruesa de 3 dias
    if time.time() - _dm.get("generated", 0) <= 3 * 86400:
        for _l in open(os.path.join(FEEDS_DIR, "domains.lst"), encoding="utf-8"):
            _l = _l.rstrip("\n")
            if not _l or _l[0] in "#;":
                continue
            _d, _, _s = _l.partition("\t")
            _d = _d.strip().lower()
            if _d:
                DOM_MAL[_d] = _s.strip() or "feed"
        DOM_OK = len(DOM_MAL) > 0
except Exception:
    pass

def dominio_malo(dom):
    """Fuente que reporta el dominio (o su dominio padre), o '' si ninguna."""
    s = DOM_MAL.get(dom)
    if s:
        return s
    p = dom.split(".")
    for i in range(1, len(p) - 1):          # a.b.evil.com -> b.evil.com -> evil.com (no el TLD solo)
        s = DOM_MAL.get(".".join(p[i:]))
        if s:
            return s
    return ""

def logs_de_la_ventana(nodo, corte):
    """[(pid, ruta)] de los logs del nodo (o de todos) que tocan la ventana, del MAS NUEVO
    al mas viejo. El pid es el del punto de donde sale el fichero: el nodo de sus eventos.

    El orden no es un detalle. MAX_LINES es un presupuesto GLOBAL y los rotados `.gz` no
    se pueden posicionar (`abrir_desde` solo bisecciona los vivos), asi que se leen
    enteros. Leyendolos primero se llevaban el presupuesto y el log vivo se quedaba sin
    turno: el informe perdia lo MAS RECIENTE, que es lo unico que el panel necesita.
    (cafanet, 2026-09-28: cuatro rotados consumieron 19,5 de los 20 M de lineas y las
    barras se quedaron clavadas cinco horas atras con el sensor alertando 37.000 veces
    por hora.) Del reves, si el tope corta se pierde el extremo VIEJO de la ventana, y eso
    el indicador de cobertura ya lo declara en vez de callarlo.

    El filtro aprovecha que el mtime de un `.gz` es cuando logrotate lo cerro, o sea el
    instante de su ultimo registro: si cae antes de la ventana, el archivo entero esta
    fuera y no hay nada que leer. El margen de una hora solo hace falta para los vivos,
    cuyo mtime es "ahora" y no dice nada de donde empiezan."""
    fs = []
    for pid, p in nodos.ficheros_eventos(nodo, ("eve.json*", "dns.json*")):
        if os.path.islink(p):
            continue                      # Suricata no rota con enlaces: no se siguen
        try:
            m = os.path.getmtime(p)
        except OSError:
            continue
        if corte and m < (corte if p.endswith(".gz") else corte - 3600):
            continue
        fs.append((m, pid, p))
    fs.sort(reverse=True)
    return [(pid, p) for _, pid, p in fs]

files = logs_de_la_ventana(NODO, cutoff)
for _pid, p in files:
    try:
        for line in abrir_desde(p, cutoff):
            seen += 1
            if seen > MAX_LINES:
                break
            # contar TODAS las IPs vistas (cualquier evento: tls, http, snmp, alert...),
            # no solo las que atacan. Solo lineas con src_ip y dentro de la ventana.
            if len(ips_vistas) < MAX_IPS and '"src_ip":"' in line:
                _mt = _RE["ts"].search(line)
                _tv = parse_ts(_mt.group(1)) if _mt else None
                if _tv is None or _tv >= cutoff:
                    _ms = _RE["src_ip"].search(line)
                    _md = _RE["dest_ip"].search(line)
                    # una IP de abonado va con su punto: la misma IP privada en dos puntos son dos
                    # equipos (auditoria A-18); una de internet es la misma en todos
                    for _mm in (_ms, _md):
                        if _mm:
                            _iv = _mm.group(1)
                            ips_vistas.add(clave_cpe(_iv, _pid) if es_mi_cpe(_iv, _pid) else _iv)
            # Camino B: consulta DNS a dominio malo (cruce con feeds de dominios)
            if DOM_OK and '"event_type":"dns"' in line and '"rrname":"' in line:
                _qm = _RE["rrname"].search(line); _sm = _RE["src_ip"].search(line)
                if _qm and _sm:
                    _dom = _qm.group(1).lower().rstrip(".")
                    if dominio_malo(_dom):
                        _mt = _RE["ts"].search(line)
                        _tv = parse_ts(_mt.group(1)) if _mt else None
                        if _tv is None or _tv >= cutoff:
                            # la MISMA identidad que las alertas (pid|ip): si no, los
                            # contadores DNS de este camino no casan con el CPE
                            _s = clave_cpe(_sm.group(1), _pid)
                            dns_hits[_s] += 1
                            if _tv and _tv > ultima_by_src.get(_s, 0):
                                ultima_by_src[_s] = _tv
                            _mdd = _RE["dest_ip"].search(line)
                            _apuntar_dominio(_dom, _s, _mdd.group(1) if _mdd else "",
                                             "feed: " + dominio_malo(_dom))
                            # tope como el de dst_by_src: con tunel DNS o dominios DGA
                            # (subdominios aleatorios bajo un dominio de los feeds) este
                            # set crecia sin fin. Solo se usa su len(), asi que acotarlo
                            # no cambia ninguna decision.
                            if len(dns_sids[_s]) < MAX_CARD:
                                dns_sids[_s].add("dom:" + _dom[:80])
                            if (_tv or 0) >= dns_sig_ts.get(_s, 0):
                                dns_sig[_s] = "DNS a dominio malo: " + _dom[:60]
                                dns_sig_ts[_s] = _tv or 0
            if '"event_type":"alert"' not in line:
                continue
            g = campos(line)
            sig = g("sig"); cat = g("cat")
            if sig.startswith("ET INFO") or "Not Suspicious" in cat or "Misc activity" in cat:
                continue
            ts = parse_ts(g("ts"))
            if ts and ts < cutoff:
                continue
            # La identidad del CPE se compone AQUI, una sola vez: a partir de este punto
            # todos los acumuladores quedan indexados por (punto, IP), con uno o con varios
            # nodos. El punto es el del fichero, nunca in_iface.
            src = clave_cpe(g("src_ip") or "?", _pid)
            dst = g("dest_ip") or "?"
            sport = g("src_port"); dport = g("dest_port")
            proto = g("proto")
            if excluido(src, dst, int(dport) if dport else None, g("sid")):   # exclusiones configuradas
                continue
            if dst in DEST_OK:     # destino marcado confiable (falso positivo): la alerta no cuenta
                continue
            # --- metricas del dia (solo lo que aun no se habia contado) ---
            if ts:
                if ts > ts_max:
                    ts_max = ts
                if ts > METR_DESDE:
                    _mio_src = es_mi_cpe(src); _mio_dst = es_mi_cpe(dst, _pid)
                    if _mio_src and not _mio_dst:          # TU red hacia fuera
                        _d = dias_m[time.strftime("%Y-%m-%d", time.localtime(ts))]
                        _cat = traducir(sig)
                        if _cat in CATS_NO_ABUSO:
                            _d["ruido"] += 1       # se ve, pero no cuenta como abuso
                        else:
                            _d["sal"] += 1
                            if len(_d["cpes"]) < METRICAS_MAX_CPES:
                                _d["cpes"].add(src)
                            _d["cats"][_cat] += 1
                            if dport:
                                _d["puertos"][f"{dport}/{proto}"] += 1
                            _rid = rid_de(src)
                            if _rid:
                                _d["nodos"][_rid] += 1
                    elif _mio_dst and not _mio_src:        # internet golpeando tu red
                        dias_m[time.strftime("%Y-%m-%d", time.localtime(ts))]["ent"] += 1
            # Un resolutor conocido NO es la victima de una consulta DNS maliciosa: es el
            # canal. La alerta sigue contando para el CPE (by_src y todo lo de abajo); solo
            # no se le apunta al DNS como "atacado".
            if es_via_resolutor(dst, dport, sig, cat):
                via_dns[dst] += 1
                if len(via_dns_src[dst]) < MAX_CARD:
                    via_dns_src[dst].add(src)
            else:
                by_dst[dst] += 1
            by_src[src] += 1
            if ts and ts > ultima_by_src.get(src, 0):
                ultima_by_src[src] = ts
            _cc = pais(dst)                    # pais del destino (mapa "a donde atacan")
            if _cc:
                pais_dst[_cc] += 1
                _cuenta_acotada(pais_ips[_cc], dst)    # detalle del mapa: a que IPs, puertos y desde que CPE
                _cuenta_acotada(pais_srcs[_cc], src)
                if dport != "":
                    _cuenta_acotada(pais_ports[_cc], f"{dport}/{proto}")
            if dport != "":
                by_dport[f"{dport}/{proto}"] += 1
            # --- senales de riesgo por CPE ---
            sv = g("sev")
            if sv:
                sv = int(sv)
                if src not in sev_by_src or sv < sev_by_src[src]:
                    sev_by_src[src] = sv     # menor numero = peor severidad
            if dst != "?" and len(dst_by_src[src]) < MAX_CARD:
                dst_by_src[src].add(dst)
            if dport and len(dpt_by_src[src]) < MAX_CARD:
                dpt_by_src[src].add(dport)
            if dport:
                _cuenta_acotada(dport_cnt_by_src[src], f"{dport}/{proto}")
            _cuenta_acotada(cat_cnt_by_src[src], traducir(sig))
            if dport and len(patron_src[(sig, dport)]) < MAX_CARD:
                patron_src[(sig, dport)].add(src)
            _sl = sig.lower()
            _es_cnc = any(k in _sl for k in CNC_KW)
            _es_dns = es_dns_sospechoso(sig, cat)
            if _es_cnc:                           # firma de infeccion (CnC/botnet/troyano)
                inf_hits[src] += 1
                inf_sids[src].add(g("sid") or sig)
                if (ts or 0) >= inf_sig_ts.get(src, 0):
                    inf_sig[src] = sig
                    inf_sig_ts[src] = ts or 0
            if _es_dns:                            # consulta DNS a dominio malicioso
                dns_hits[src] += 1
                dns_sids[src].add(g("sid") or sig)
                _rr = (g("rrname") or "").lower().rstrip(".")
                if _rr:
                    _apuntar_dominio(_rr, src, dst, "firma: " + sig[:70])
                if (ts or 0) >= dns_sig_ts.get(src, 0):
                    dns_sig[src] = sig
                    dns_sig_ts[src] = ts or 0
            # evidencia por alerta (para la ficha): guardar hasta 8 registros por CPE
            if (_es_cnc or _es_dns) and len(pruebas_by_src[src]) < 8:
                pruebas_by_src[src].append({
                    "tipo": "cnc" if _es_cnc else "dns",
                    "sid": g("sid"), "rev": g("rev"), "sig": sig[:120],
                    "ts": int(ts) if ts else 0, "flow_id": g("flow_id"),
                    "dst": dst, "dport": dport,
                    "rrname": g("rrname") if _es_dns else "",
                })
            if ts:
                if ts >= NOW - 300:  n5_by_src[src] += 1
                if ts >= NOW - 3600: n1h_by_src[src] += 1
                by_hour[int(ts // BUCKET)] += 1
                if ts_min is None or ts < ts_min:
                    ts_min = ts
            k = (src, sport, dst, dport, proto, sig)
            f = flujos.get(k)
            if f is None:
                # tope de cardinalidad: si ya hay demasiados flujos unicos, no crear mas
                # (los pesados ya estan dentro); asi la RAM no crece sin limite.
                if len(flujos) < MAX_FLUJOS:
                    flujos[k] = [1, ts or 0, ts or 0]
            else:
                f[0] += 1
                if ts:
                    if not f[1] or ts < f[1]: f[1] = ts
                    if ts > f[2]: f[2] = ts
            total += 1
    except OSError:
        continue

# --- helpers de render (SVG inline, sin JS) ---
BLUE = "#2a78d6"; GRID = "#e7e6e2"; INK = "#0b0b0b"; INK2 = "#52514e"; SURF = "#fcfcfb"

def heat(f):
    """Color segun magnitud (0..1): a mas valor, mas critico -> mas rojo.
    Escala verde (bajo) -> ambar (medio) -> naranja -> rojo (alto)."""
    f = 0.0 if f < 0 else (1.0 if f > 1 else f)
    stops = [(0.0, (43, 120, 214)), (0.35, (27, 175, 122)),
             (0.65, (237, 161, 0)), (0.85, (235, 104, 52)), (1.0, (227, 73, 72))]
    for j in range(len(stops) - 1):
        a, ca = stops[j]; b, cb = stops[j + 1]
        if f <= b:
            t = (f - a) / (b - a) if b > a else 0.0
            r = int(ca[0] + (cb[0] - ca[0]) * t)
            g = int(ca[1] + (cb[1] - ca[1]) * t)
            bl = int(ca[2] + (cb[2] - ca[2]) * t)
            return f"#{r:02x}{g:02x}{bl:02x}"
    return "#e34948"

def esc(x): return html.escape(str(x))

def _cardq(tip):
    """Badge '?' con tooltip explicativo para la cabecera de un cuadro."""
    return f'<span class="chq">?<span class="chtip">{esc(tip)}</span></span>' if tip else ""

def hbar(titulo, pares, unidad="alertas", fmt=str, lblw=125, barw=470, card_class="card",
         label_above=False, tip="", piso=8, que="valor", izq=False):
    """Barras horizontales rankeadas, un solo tono, etiqueta de valor directa.
    label_above=True: el nombre va ENCIMA de la barra (a todo el ancho), no en una
    columna a la izquierda; asi los nombres largos (firmas) no se recortan nunca.
    Escala HONESTA: el largo y el color van contra `ref = max(mx, piso)`, no contra el
    maximo. Asi una sola alerta NO llena la barra ni la pinta de rojo (antes, con todo en
    1, salia todo full y rojo como si fueran ataques intensos). `que` = nombre singular
    de la fila (puerto/IP/firma) para el aviso de 'sin dominante'. izq=True: la etiqueta alineada
    a la izquierda, como las graficas en columnas que van al lado."""
    q = _cardq(tip)
    if not pares:
        return f'<section class="{card_class}"><h2>{esc(titulo)}{q}</h2><p class="muted">Sin datos.</p></section>'
    mx = max(v for _, v in pares) or 1
    ref = max(mx, piso)                       # escala minima: hace falta ~`piso` para llenar/enrojecer
    plano = len(pares) > 1 and len({v for _, v in pares}) <= 1   # todos iguales -> no hay un claro dominante
    rows = []
    if label_above:
        W = 900
        barh, labh, gap = 20, 18, 12
        rowh = labh + barh + gap
        h = len(pares) * rowh + 6
        barmax = W - 90
        maxch = 120
        for i, (name, v) in enumerate(pares):
            top = i * rowh + 4
            w = max(2, int(barmax * v / ref))
            etq = name if len(name) <= maxch else name[:maxch - 1] + "…"
            rows.append(
                f'<text x="2" y="{top+13}" class="lbl">{esc(etq)}</text>'
                f'<rect x="2" y="{top+labh}" width="{w}" height="{barh}" rx="4" fill="{heat(v/ref)}"/>'
                f'<text x="{w+8}" y="{top+labh+barh*0.7:.0f}" class="val">{esc(fmt(v))}</text>')
    else:
        rowh, gap = 26, 8
        # filas en columnas: (ip, nodo, puerto[, extra[, flecha]]); extra = «+N» en gris
        col_ip = 104
        col_pto = 80 if any(isinstance(n, tuple) and n[2] for n, _ in pares) else 0
        col_ext = 30 if any(isinstance(n, tuple) and len(n) > 3 and n[3] for n, _ in pares) else 0
        if all(isinstance(n, tuple) and not n[1] for n, _ in pares):
            # con un solo nodo no hay columna de nodo: la etiqueta se estrecha y la barra gana
            # ese sitio (el ancho total no cambia)
            angosto = col_ip + col_pto + col_ext + 24
            barw, lblw = barw + max(0, lblw - angosto), min(lblw, angosto)
        maxch = max(8, int(lblw / 6.3))
        h = len(pares) * (rowh + gap) + 8
        W = lblw + barw + 80
        for i, (name, v) in enumerate(pares):
            y = i * (rowh + gap) + 4
            w = max(2, int(barw * v / ref))
            ty = f"{y+rowh*0.68:.0f}"
            if isinstance(name, tuple):
                # en columnas: la IP y el nodo alineados a la izquierda; la flecha (si va), el
                # puerto y el «+N» cada uno en su columna fija pegada a la barra. Con todo en un
                # solo texto alineado a la derecha nada caia una fila debajo de otra y las flechas
                # quedaban en escalera (el user, 2026-10-13)
                ip, nodo, pto = name[:3]
                extra = name[3] if len(name) > 3 else ""
                flecha = name[4] if len(name) > 4 else "→"
                col_nodo = lblw - 8 - col_ip - col_pto - col_ext - 16
                def corta(t, ancho):
                    n = max(4, int(ancho / 6.6))
                    return t if len(t) <= n else t[:n - 1] + "…"
                completo = (" · ".join(x for x in (ip, nodo) if x)
                            + ((f" {flecha} " if flecha else " · ") + pto if pto else "")
                            + (f" {extra}" if extra else ""))
                x_pto = lblw - 8 - col_ext - col_pto
                rows.append(
                    f'<g><title>{esc(completo)}</title>'
                    f'<text x="2" y="{ty}" class="lbl">{esc(corta(ip, col_ip))}</text>'
                    + (f'<text x="{2+col_ip+8}" y="{ty}" class="lbl lnodo">{esc(corta(nodo, col_nodo))}</text>'
                       if nodo else "")
                    + (f'<text x="{x_pto}" y="{ty}" class="lbl lflecha">{esc(flecha)}</text>'
                       if pto and flecha else "")
                    + (f'<text x="{x_pto + (16 if flecha else 0)}" y="{ty}" class="lbl lpto">{esc(pto)}</text>'
                       if pto else "")
                    + (f'<text x="{lblw-8-col_ext+6}" y="{ty}" class="lbl lextra">{esc(extra)}</text>'
                       if extra else "")
                    + f'<rect x="{lblw}" y="{y}" width="{w}" height="{rowh}" rx="4" fill="{heat(v/ref)}"/>'
                    f'<text x="{lblw+w+6}" y="{ty}" class="val">{esc(fmt(v))}</text></g>')
                continue
            etq = name if len(name) <= maxch else name[:maxch - 1] + "…"
            pos = 'x="2"' if izq else f'x="{lblw-8}" text-anchor="end"'
            rows.append(
                f'<text {pos} y="{ty}" class="lbl">{esc(etq)}</text>'
                f'<rect x="{lblw}" y="{y}" width="{w}" height="{rowh}" rx="4" fill="{heat(v/ref)}"/>'
                f'<text x="{lblw+w+6}" y="{ty}" class="val">{esc(fmt(v))}</text>')
    # aviso honesto cuando la muestra es plana/pequeña (no hay un dominante real)
    if len(pares) == 1:
        # una sola fila no "empata" con nadie: se dice que es la unica
        aviso = (f' &middot; <b>solo 1 {esc(que)}</b> en {esc(fmt(mx))} {esc(unidad)}'
                 + (' (muestra pequeña)' if mx < piso else ''))
    elif plano:
        aviso = (f' &middot; <b>sin {esc(que)} dominante</b>: los {len(pares)} van empatados '
                 f'en {esc(fmt(mx))} {esc(unidad)} (muestra pequeña)')
    elif mx < piso:
        aviso = f' &middot; pocos datos todavia (maximo {esc(fmt(mx))} {esc(unidad)})'
    else:
        aviso = ""
    return (f'<section class="{card_class}"><h2>{esc(titulo)}{q}</h2>'
            f'<svg viewBox="0 0 {W} {h}" width="100%" role="img" aria-label="{esc(titulo)}">'
            f'{"".join(rows)}</svg>'
            f'<p class="muted leyenda">en {unidad} &middot; el color sube con la intensidad '
            f'(<span style="color:#1baf7a">bajo</span> &rarr; <span style="color:#eda100">medio</span> '
            f'&rarr; <span style="color:#e34948">alto</span>){aviso}</p></section>')

def timeline(by_hour):
    # Ventana FIJA de 24h en intervalos de BUCKET_MIN minutos (detalle hora:minuto),
    # terminando en el intervalo actual, rellenando con 0 los vacios. Tooltip por barra.
    n = int(VENTANA_MIN * 60 // BUCKET)             # nº de barras (~48) segun la ventana
    ahora_b = int(time.time() // BUCKET)
    lo = ahora_b - (n - 1)
    vals = [by_hour.get(lo + i, 0) for i in range(n)]
    mxreal = max(vals)      # maximo real (0 si no hay alertas aun; NO usar para index)
    mx = mxreal or 1        # escala para alturas/color (evita division por 0)
    W, H, pad = 1120, 190, 30
    bw = (W - 2 * pad) / n
    tick_every = max(1, n // 8)     # ~8 etiquetas de hora repartidas en la ventana
    bars, ticks = [], []
    for i, v in enumerate(vals):
        x = pad + i * bw
        bh = (H - 2 * pad) * v / mx
        t0 = datetime.fromtimestamp((lo + i) * BUCKET, TZ_EC)
        t1 = datetime.fromtimestamp((lo + i + 1) * BUCKET, TZ_EC)
        rango = t0.strftime("%H:%M") + "-" + t1.strftime("%H:%M")
        tip = f"{rango} · {v:,} alertas"
        bars.append(
            f'<rect class="tl-bar" x="{x:.1f}" y="{H-pad-bh:.1f}" width="{max(1,bw-1.5):.1f}" '
            f'height="{bh:.1f}" rx="1.5" fill="{heat(v/mx)}" style="animation-delay:{i*10}ms" '
            f'onmousemove="tlShow(evt,\'{tip}\')" onmouseleave="tlHide(evt)">'
            f'<title>{tip}</title></rect>')
        # etiquetas ancladas a la DERECHA: la ultima barra (intervalo actual) siempre
        # lleva su hora, para que se vea que el eje llega hasta "ahora" y no se corta antes
        if (n - 1 - i) % tick_every == 0:
            ticks.append(f'<text x="{x+bw/2:.1f}" y="{H-pad+14:.0f}" text-anchor="middle" class="tick">{t0.strftime("%H:%M")}</text>')
    pico_t = datetime.fromtimestamp((lo + vals.index(mxreal)) * BUCKET, TZ_EC).strftime("%H:%M") if mxreal else "-"
    _tl_tip = ("Numero de alertas en cada intervalo de 30 minutos a lo largo de la ventana. "
               "La altura y el color suben con la intensidad; pasa el raton por una barra para el conteo exacto.")
    return (f'<section class="card wide"><h2>Ataques por hora y minuto ({COB}){_cardq(_tl_tip)}</h2>'
            f'<div class="tlwrap"><div class="tltip"></div>'
            f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" aria-label="alertas por intervalo" style="cursor:default">'
            f'<line x1="{pad}" y1="{H-pad}" x2="{W-pad}" y2="{H-pad}" stroke="{GRID}"/>'
            f'{"".join(bars)}{"".join(ticks)}</svg></div>'
            '<script>'
            'function tlShow(e,t){var c=e.currentTarget.closest(".tlwrap");if(!c)return;'
            'var p=c.querySelector(".tltip"),r=c.getBoundingClientRect();'
            'p.textContent=t;p.style.left=(e.clientX-r.left)+"px";p.style.top=(e.clientY-r.top)+"px";p.style.opacity=1;}'
            'function tlHide(e){var c=e.currentTarget.closest(".tlwrap");if(c){var p=c.querySelector(".tltip");if(p)p.style.opacity=0;}}'
            '</script>'
            f'<p class="muted">1 barra cada {BUCKET_MIN} min &middot; pasa el raton por una barra para ver el rango y el numero de peticiones &middot; pico: {mxreal:,} alertas a las {pico_t}</p></section>')

def dur(a, b):
    if not a or not b or b < a:
        return "-"
    s = int(b - a)
    if s < 60: return f"{s}s"
    if s < 3600: return f"{s//60}m"
    return f"{s//3600}h{(s%3600)//60:02d}m"

host = nodos.nombre(NODO)               # el nombre del punto (o "Todos los nodos"), no el del contenedor
gen = datetime.now(TZ_EC).strftime("%Y-%m-%d %H:%M")

# La ventana del reporte SIEMPRE es de HOURS (24 por defecto): la linea de tiempo
# tiene 48 barras de 30 min terminando "ahora", rellenando con 0 los intervalos sin
# alertas. Por eso la etiqueta es fija; que aun no haya datos en las primeras horas
# no cambia el tamano de la ventana.
if VENTANA_MIN < 60:
    COB = f"ultimos {VENTANA_MIN} min"
elif VENTANA_MIN == 60:
    COB = "ultima hora"
elif VENTANA_MIN % 60 == 0:
    COB = f"ultimas {VENTANA_MIN // 60} horas"
else:
    COB = f"ultimas {VENTANA_MIN / 60:.1f} horas"

def ipnum(s):
    # convierte una IPv4 en entero para ordenar bien (10 antes que 9 no; 9<10 numerico)
    p = s.split(".")
    if len(p) == 4 and all(x.isdigit() for x in p):
        try:
            return (int(p[0]) << 24) + (int(p[1]) << 16) + (int(p[2]) << 8) + int(p[3])
        except ValueError:
            return 0
    return 0

top_flujos = sorted(flujos.items(), key=lambda kv: kv[1][0], reverse=True)[:500]
filas = []
for (src, sport, dst, dport, proto, sig), (cnt, first, last) in top_flujos:
    hp = datetime.fromtimestamp(first, TZ_EC).strftime("%d/%m %H:%M") if first else "-"
    hu = datetime.fromtimestamp(last, TZ_EC).strftime("%H:%M") if last else "-"
    dursec = int((last - first)) if (first and last) else 0
    sig_es = traducir(sig)
    filas.append(
        f"<tr><td class='mono' data-s='{ipnum(ip_de(src))}'>{esc(ip_de(src))}</td>"
        # el nodo en su columna (en «Todos»): pegado a la IP como etiqueta descuadraba la tabla
        # (el user, 2026-10-13)
        + (f"<td class='nodo' data-s='{esc(nombre_router(rid_de(src)))}'>{esc(nombre_router(rid_de(src)))}</td>"
           if MULTI_ROUTER else "")
        + f"<td class='mono num' data-s='{int(sport) if str(sport).isdigit() else -1}'>{esc(sport)}</td>"
        f"<td class='mono dst' data-s='{ipnum(dst)}'>{esc(dst)}</td>"
        f"<td class='mono num' data-s='{int(dport) if str(dport).isdigit() else -1}'>{esc(dport)}</td>"
        f"<td data-s='{esc(proto)}'>{esc(proto)}</td>"
        f"<td title='{esc(sig)}' data-s='{esc(sig_es)}'>{esc(sig_es)}</td>"
        f"<td class='num' data-s='{cnt}'>{cnt}</td>"
        f"<td class='mono' data-s='{int(first or 0)}'>{hp} &rarr; {hu}</td>"
        f"<td data-s='{dursec}'>{dur(first,last)}</td></tr>")

# columnas de la tabla Detalle (clase, titulo); «Nodo» solo en «Todos», como en las filas
_COLS_DETALLE = ([("", "IP origen")] + ([("", "Nodo")] if MULTI_ROUTER else [])
                 + [("num", "Puerto"), ("", "IP destino (atacada)"), ("num", "Puerto"), ("", "Protocolo"),
                    ("", "Firma (tipo de ataque)"), ("num", "Veces"), ("", "Primera &rarr; ultima"),
                    ("", "Duracion")])

def _cabecera_detalle():
    return "".join('<th class="%s" data-col="%d">%s<span class="ar">&#8597;</span></th>'
                   % ((c + " sortable").strip(), i, t) for i, (c, t) in enumerate(_COLS_DETALLE))

def top(counter, n=12, fmt=str):
    return [(fmt(k), v) for k, v in counter.most_common(n)]

by_sig = Counter()
for _k, _v in flujos.items():
    by_sig[traducir(_k[5])] += _v[0]   # agrupar por descripcion en espanol (sin duplicados)
firmas_top = [(s[:60], n) for s, n in by_sig.most_common(10)]

# Atacantes por puerto: el par (CPE, puerto destino) con mas alertas. El puerto solo (443: 6)
# no dice a quien cortar; el par si (10.0.0.5 -> 23/TCP: 312 es un bot, no un cliente normal).
by_src_dport = Counter()
for _s, _c in dport_cnt_by_src.items():
    for _p, _n in _c.items():
        by_src_dport[(_s, _p)] = _n
def _cols_cpe(clave, pto):
    """(ip, nodo, puerto) de un CPE para las columnas de hbar: el nodo solo en «Todos» (con un solo
    nodo seria ruido) y nunca la clave interna pid|ip."""
    r = rid_de(clave)
    return (ip_de(clave), nombre_router(r) if (r and MULTI_ROUTER) else "", pto)

src_dport_top = [(_cols_cpe(_s, _p), n) for (_s, _p), n in by_src_dport.most_common(12)]

# IPs destino con el puerto por el que las atacan: «203.0.113.9 · 443/TCP» (+N si hay mas).
# Los puertos salen de los flujos (acotados) y solo para el top, no se guarda nada por destino.
_dst_top = by_dst.most_common(12)
_dst_pto = {_d: Counter() for _d, _ in _dst_top}
for (_s, _sp, _d, _dp, _pr, _sig), _v in flujos.items():
    if _d in _dst_pto and _dp:
        _dst_pto[_d][f"{_dp}/{(_pr or '').upper()}"] += _v[0]

def _etq_dst(d):
    """(ip, "", puerto mas usado, «+N» otros puertos, sin flecha) para las columnas de hbar."""
    c = _dst_pto.get(d)
    if not c:
        return (d, "", "", "", "")
    p = c.most_common(1)[0][0]
    return (d, "", p, f"+{len(c) - 1}" if len(c) > 1 else "", "")

dst_top = [(_etq_dst(_d), n) for _d, n in _dst_top]

# ---- Dueno de cada IP destino: SOLO de la cache (duenos.py). La red (PTR/RDAP) se consulta bajo
# demanda, cuando se abre Top origenes (GET /duenos del panel), nunca al generar: generar con
# consultas costaba 11-215 s por punto y sin ellas 0,3 s (medido, 2026-10-13) ----
import duenos  # noqa: E402
_ipinfo = duenos.cargar()

def duenio(ip):
    """(etiqueta, legitimo) de la cache, o None si aun no se sabe (la pestana lo pide al abrirse)."""
    ent = _ipinfo.get(ip)
    if not duenos.vigente(ent) or ent.get("via") == "error":
        return None
    return (ent.get("org", "-"), ent.get("legit", False))

def _pend_dueno(ip):
    """Hueco que la pestana Top origenes rellena con /duenos (solo IPs publicas; el resto «-»)."""
    if not duenos.consultable(ip):
        return "<span class='obadge none'>-</span>"
    return (f"<span class='obadge pend' data-dueno='{esc(ip)}' title='Consultando el dueño…'>"
            "&hellip;</span>")

# AbuseIPDB: lo que el PANEL ya consulto. Aqui solo se LEE la cache: el panel es el
# unico que llama a la API, porque la cuota es diaria y con dos procesos gastandola no
# la controlaria nadie. Si el archivo no existe, todo sigue como siempre.
_AIDB_CACHE_F = os.path.join(nodos.FEEDS, "abuseipdb.json")
try:
    _AIDB = json.load(open(_AIDB_CACHE_F, encoding="utf-8"))
except (OSError, ValueError):
    _AIDB = {}

def _aidb_chip(dst):
    """Que ataques se le denuncian a ese destino, si el panel ya lo consulto."""
    d = _AIDB.get(dst)
    if not isinstance(d, dict):
        return ""
    sc = int(d.get("score") or 0)
    if sc <= 0:
        return ""
    nom = ", ".join((d.get("cats_nom") or [])[:2])
    det = f"{d.get('reportes', 0):,} denuncias de {d.get('denunciantes', 0):,} denunciantes"
    ttl = f"AbuseIPDB: {sc}% de confianza de abuso; {det}" + (f". Denunciado por: {nom}" if nom else "")
    col = "#e34948" if sc >= 75 else ("#e07b39" if sc >= 25 else "#e58a00")
    return (f"<div><span class='obadge' style='background:{col};color:#fff;margin-top:4px' "
            f"title='{esc(ttl)}'>abuso {sc}%{(' · ' + esc(nom)) if nom else ''}</span></div>")

def _org_celda(dst):
    aidb = _aidb_chip(dst)
    # 1) si el destino esta en una lista de reputacion, eso manda (aunque no tenga PTR)
    fuente = es_malo(dst)
    if fuente:
        cat = (REP_META.get(fuente, {}) or {}).get("categoria", "")
        etq = ((cat + " · ") if cat else "") + fuente
        return (f"<td class='org'><span class='obadge bad' title='Destino en lista de reputacion "
                f"({esc(fuente)}{(', ' + esc(cat)) if cat else ''}) &mdash; ver ficha para el CIDR y la vigencia'>"
                f"&#9888; {esc(etq)}</span>{aidb}</td>")
    d = duenio(dst)
    if d is None:
        return f"<td class='org'>{_pend_dueno(dst)}{aidb}</td>"
    org, legit = d
    if org == "-":
        return f"<td class='org'>-{aidb}</td>"
    if legit:
        return (f"<td class='org'><span class='obadge ok' title='Servicio conocido "
                f"(CDN/gran empresa): trafico casi siempre legitimo'>{esc(org)}</span>{aidb}</td>")
    if org == "sin PTR":
        return ("<td class='org'><span class='obadge none' title='Sin DNS inverso ni operador identificable'>"
                f"sin PTR</span>{aidb}</td>")
    via = (_ipinfo.get(dst, {}) or {}).get("via", "")
    ttl = ("Operador de red del bloque IP (RDAP); no tiene DNS inverso" if via == "rdap"
           else "Dominio del dueño segun DNS inverso; no es un servicio grande conocido")
    marca = "&#127760; " if via == "rdap" else ""   # globo: viene del operador de red, no de PTR
    return (f"<td class='org'><span class='obadge unk' title='{ttl}'>{marca}{esc(org)}</span>{aidb}</td>")


# --- Reputacion: feeds de IPs/CIDR malos (suricata-feeds-update), con caducidad ---
FEEDS_DIR = nodos.FEEDS
REP_IPS = {}                    # ip -> fuente (procedencia)
REP_CIDR = defaultdict(list)    # primer octeto -> [(net_int, mask_int, fuente)]
REP_WIDE = []                   # CIDRs con prefijo <8 -> [(net, mask, fuente)]
REP_OK = False                  # hay al menos un feed vigente?
REP_INFO = "feeds no instalados"
REP_META = {}                   # meta por fuente (estado, vigencia, caducidad) para la ficha
REP_PORTS = {}                  # ip -> {puertos} de C2 (ThreatFox ip:port), para la ficha
# Categorias que son CONTEXTO y no prueba: se ensenan en la celda del destino, pero no
# suman al riesgo ni a las evidencias ni al barrido, ni se proponen para cortar. Hablar
# con una salida Tor no es estar infectado.
REP_CONTEXTO = ("anonimizador",)

def _ip4_int(ip):
    try:
        a, b, c, d = ip.split(".")
        return (int(a) << 24) | (int(b) << 16) | (int(c) << 8) | int(d)
    except Exception:
        return None

def _cargar_reputacion():
    global REP_OK, REP_INFO, REP_META
    try:
        meta = json.load(open(os.path.join(FEEDS_DIR, "reputation.meta"), encoding="utf-8"))
    except Exception:
        REP_INFO = "feeds no instalados"; return
    REP_META = meta.get("sources", {})
    # guarda gruesa: si el actualizador no corre hace mucho, no confiar (la caducidad fina
    # es por fuente y ya se aplico al rearmar reputation.lst -> solo trae fuentes vigentes)
    if time.time() - meta.get("generated", 0) > 3 * 86400:
        REP_INFO = "feeds sin refrescar (>3d; el actualizador no corre?)"; return
    try:
        for line in open(os.path.join(FEEDS_DIR, "reputation.lst"), encoding="utf-8"):
            line = line.rstrip("\n")
            if not line or line[0] in "#;":
                continue
            ind, _, src = line.partition("\t")
            ind = ind.strip(); src = src.strip() or "feed"
            if "/" in ind:
                try:
                    ipp, pl = ind.split("/"); pl = int(pl)
                    base = _ip4_int(ipp)
                    if base is None:
                        continue
                    mask = (0xffffffff << (32 - pl)) & 0xffffffff if pl else 0
                    net = base & mask
                    if pl >= 8:
                        REP_CIDR[(net >> 24) & 0xff].append((net, mask, src))
                    else:
                        REP_WIDE.append((net, mask, src))
                except Exception:
                    continue
            else:
                REP_IPS[ind] = src
    except Exception:
        pass
    try:
        for line in open(os.path.join(FEEDS_DIR, "c2ports.lst"), encoding="utf-8"):
            ind = line.rstrip("\n").partition("\t")[0].strip()
            ip, _, port = ind.rpartition(":")
            if ip and port.isdigit():
                REP_PORTS.setdefault(ip, set()).add(port)
    except Exception:
        pass
    n = len(REP_IPS) + sum(len(v) for v in REP_CIDR.values()) + len(REP_WIDE)
    vig = ", ".join(k for k, s in REP_META.items() if s.get("vigente"))
    REP_INFO = f"{n:,} IOCs ({vig})" if n else "feeds vacios"
    REP_OK = n > 0

_cargar_reputacion()

def es_malo_firme(ip):
    """Como es_malo, pero '' si la fuente es solo CONTEXTO (Tor): para todo lo que decide
    -riesgo, evidencias, destinos a cortar-, no para lo que solo informa."""
    f = es_malo(ip)
    if f and (REP_META.get(f, {}) or {}).get("categoria", "") in REP_CONTEXTO:
        return ""
    return f

def es_malo(ip):
    """Devuelve la FUENTE que reporta la IP destino (str no vacio) o '' si ninguna."""
    s = REP_IPS.get(ip)
    if s:
        return s
    v = _ip4_int(ip)
    if v is None:
        return ""
    for net, mask, src in REP_CIDR.get((v >> 24) & 0xff, ()):
        if (v & mask) == net:
            return src
    for net, mask, src in REP_WIDE:
        if (v & mask) == net:
            return src
    return ""

def reputacion_de(ip):
    """(fuente, cidr_exacto) que reporta la IP, para la ficha de evidencia; ('','') si ninguna."""
    if ip in REP_IPS:
        return (REP_IPS[ip], ip)
    v = _ip4_int(ip)
    if v is None:
        return ("", "")
    for tabla in (REP_CIDR.get((v >> 24) & 0xff, ()), REP_WIDE):
        for net, mask, src in tabla:
            if (v & mask) == net:
                pl = bin(mask).count("1")
                return (src, f"{(net >> 24) & 255}.{(net >> 16) & 255}.{(net >> 8) & 255}.{net & 255}/{pl}")
    return ("", "")

_FLUJOS_POR_SRC = None

def flujos_de(src):
    """Las claves de `flujos` de ese CPE, por indice construido UNA vez.

    Perezoso a proposito: `flujos` ya esta completo cuando alguien pide el primero (las
    secciones corren despues del bucle). Antes, cada candidato recorria los 200k flujos
    enteros para la correlacion de flota: con 3.000 candidatos eran 600 M comparaciones y
    el 41%% del tiempo del generador (banco de 1,5 M de lineas: 14,8 s de 36)."""
    global _FLUJOS_POR_SRC
    if _FLUJOS_POR_SRC is None:
        idx = defaultdict(list)
        for k in flujos:
            idx[k[0]].append(k)
        _FLUJOS_POR_SRC = idx
    return _FLUJOS_POR_SRC.get(src, ())

def riesgo(src):
    """Puntaje de riesgo 0-100 del CPE (IP origen) combinando senales, en vez de
    clasificar por el texto de la firma. Devuelve (score, banda, color, desglose)."""
    sev = sev_by_src.get(src, 3)
    c_sev = {1: 30, 2: 18, 3: 8}.get(sev, 8)          # severidad Suricata (1=alta)
    c_dst = min(20, len(dst_by_src.get(src, ())) * 2)  # destinos unicos (barrido)
    c_pt  = min(15, len(dpt_by_src.get(src, ())) * 3)  # puertos unicos (port-sweep)
    p = 8 if n5_by_src.get(src, 0) > 0 else 0          # activo en los ultimos 5 min
    p += min(6, n1h_by_src.get(src, 0) / 20 * 6)       # sostenido en la ultima hora
    p += min(6, by_src.get(src, 0) / 60 * 6)           # persistente en la ventana
    c_per = min(20, p)
    otros = 0                                          # correlacion: otros CPE, mismo patron
    for k in flujos_de(src):
        n = len(patron_src.get((k[5], k[3]), ())) - 1
        if n > otros:
            otros = n
    c_cor = min(5, otros)
    rep_hits = 0                                       # destinos del CPE en feeds de reputacion
    if REP_OK:
        for d in dst_by_src.get(src, ()):
            if es_malo_firme(d):           # contexto (Tor) no suma riesgo
                rep_hits += 1
                if rep_hits >= 2:
                    break
    c_rep = min(10, rep_hits * 6)
    score = max(0, min(100, int(round(c_sev + c_dst + c_pt + c_per + c_cor + c_rep))))
    if score >= 70:
        banda, color = "ALTO", "#e34948"
    elif score >= 40:
        banda, color = "MEDIO", "#e58a00"
    else:
        banda, color = "bajo", "#3a9d5d"
    desg = (f"Severidad {c_sev}/30 &middot; Destinos unicos {c_dst}/20 &middot; "
            f"Puertos unicos {c_pt}/15 &middot; Persistencia {int(c_per)}/20 &middot; "
            f"Correlacion flota {c_cor}/5 &middot; Reputacion {c_rep}/10 [{REP_INFO}]")
    return score, banda, color, desg


def top_origenes_section(n_src=5, n_sub=8):
    """Top de IPs origen que mas peticionan, con el desglose de cada una:
    desde que puerto origen, hacia que IP destino y hacia que puerto destino.
    Se arma con by_src (totales reales) + flujos (ya trae sport/dport/proto)."""
    tops = by_src.most_common(n_src)
    if not tops:
        return ("<!--TOP_INI--><section class=\"card\"><h2>Top 5 IPs origen que mas peticionan</h2>"
                "<p class=\"muted\">Sin ataques en la ventana.</p></section><!--TOP_FIN-->")
    cards = []
    for i, (src, tot) in enumerate(tops, 1):
        agg = {}                       # (sport,dst,dport,proto) -> veces
        dsts, dports = set(), set()
        for (s, sp, dst, dp, pr, sig), v in flujos.items():
            if s != src:
                continue
            agg[(sp, dst, dp, pr)] = agg.get((sp, dst, dp, pr), 0) + v[0]
            dsts.add(dst); dports.add(dp)
        sub = sorted(agg.items(), key=lambda kv: kv[1], reverse=True)[:n_sub]
        rows = "".join(
            f"<tr><td class='mono'>{esc(sp or '-')}</td>"
            f"<td class='mono' style='color:#184f95'>{esc(dst or '-')}</td>"
            f"{_org_celda(dst)}"
            f"<td class='mono'>{esc(dp or '-')}</td>"
            f"<td class='mono'>{esc((pr or '-').upper())}</td>"
            f"<td class='num'>{c:,}</td></tr>" for (sp, dst, dp, pr), c in sub)
        rsc, rband, rcol, rdes = riesgo(src)
        if src in _MK_ENVIADOS:
            cuar = ("<span class='qsent' title='Este CPE ya esta en la lista de cuarentena del MikroTik'>"
                    "&#10003; En cuarentena</span>")
        else:
            # se manda la IDENTIDAD entera (router|IP): el panel la guarda tal cual y asi
            # el bloqueo sale hacia SU MikroTik y la marca "En cuarentena" vuelve a casar
            cuar = (f"<button class='qsend' title='Enviar este CPE a la address-list de cuarentena del MikroTik' "
                    f"onclick=\"qcuar(this,'{esc(src)}','{rsc}')\">&#9888; Cuarentena</button>")
        cards.append(
            f"<div class='tcard'>"
            f"<div class='thd'><span class='rank'>#{i}</span>"
            f"<span class='ipx mono'>{esc(ip_de(src))}</span>{_chip_nodo(src)}"
            f"<span class='risk' style='background:{rcol}' title='Puntaje de riesgo del CPE (0-100): {rdes}'>"
            f"Riesgo {rsc} &middot; {rband}</span>"
            f"<span class='tot'>{tot:,} alertas</span>{cuar}"
            f"<span class='meta'>&rarr; {len(dsts):,} IP destino &middot; {len(dports):,} puertos destino</span></div>"
            f"<div class='tablewrap'><table><thead><tr>"
            f"<th>Puerto origen</th><th>IP destino (a donde)</th><th class='org'>Dueño / organización</th>"
            f"<th class='num'>Puerto destino</th>"
            f"<th>Protocolo</th><th class='num'>Peticiones</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div></div>")
    return (
        "<!--TOP_INI-->"
        "<style>"
        ".topwrap .tcard{border:1px solid #e7e6e2;border-radius:12px;background:#fff;margin:0 0 14px;overflow:hidden}"
        ".topwrap .thd{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:11px 15px;background:#f4f4f2;border-bottom:1px solid #e7e6e2}"
        ".topwrap .rank{font-weight:800;color:#2a78d6;font-size:15px}"
        ".topwrap .ipx{font-weight:700;font-size:15px}"
        ".topwrap .tot{background:#e34948;color:#fff;font-size:12px;font-weight:700;padding:3px 9px;border-radius:20px}"
        ".topwrap .risk{color:#fff;font-size:12px;font-weight:800;padding:3px 10px;border-radius:20px;letter-spacing:.3px;cursor:help}"
        ".topwrap .qsend{font:11px system-ui;font-weight:700;color:#fff;background:#e34948;border:0;border-radius:20px;padding:3px 11px;cursor:pointer}"
        ".topwrap .qsend:hover{background:#c93b3a}"
        ".topwrap .qsent{font-size:11px;font-weight:700;color:#1a7f37;background:#e6f4ea;border:1px solid #b7e0c2;border-radius:20px;padding:2px 10px}"
        ".topwrap .meta{color:#52514e;font-size:12px;margin-left:auto}"
        ".topwrap table{table-layout:fixed;width:100%}"
        ".topwrap table th,.topwrap table td{text-align:center!important;padding:11px 8px;font-size:14px}"
        ".topwrap table thead th{font-size:13px;letter-spacing:.2px}"
        ".topwrap table tbody td{border-top:1px solid #eeece7}"
        ".topwrap table th.org{width:23%}"
        ".topwrap td.org{white-space:normal;word-break:break-word;overflow-wrap:anywhere}"
        ".topwrap .obadge{display:inline-block;font-size:12.5px;font-weight:700;padding:3px 10px;border-radius:12px;max-width:100%;white-space:normal;word-break:break-word;overflow-wrap:anywhere;line-height:1.35;vertical-align:middle}"
        ".topwrap .obadge.ok{background:#e6f4ea;color:#1a7f37;border:1px solid #b7e0c2}"
        ".topwrap .obadge.unk{background:#fdf0e6;color:#a15c12;border:1px solid #f2d3ad}"
        # etiqueta del nodo (solo aparece si hay varios MikroTik)
        ".nodochip{display:inline-block;background:#eef4fd;color:#2a5fa0;border:1px solid #cfe0f6;"
        "border-radius:20px;padding:1px 9px;font-size:11px;font-weight:700;white-space:nowrap;margin-left:6px}"
        ".topwrap .obadge.none{background:#f1f1ef;color:#6b6a66;border:1px solid #e0dfda}"
        ".topwrap .obadge.pend{background:#f6f7f9;color:#9a9a95;border:1px dashed #d7d6d2;font-weight:600}"
        ".topwrap .obadge.bad{background:#fdecec;color:#b52a2a;border:1px solid #f3c4c4}"
        "</style>"
        "<script>function qcuar(b,ip,sc){b.disabled=true;var o=b.innerHTML;b.textContent='enviando...';"
        "fetch('/cuarentena/enviar',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
        "body:'ajax=1&ip='+encodeURIComponent(ip)+'&score='+encodeURIComponent(sc)})"
        ".then(function(r){return r.text();}).then(function(t){"
        "if(t.indexOf('OK')===0){b.outerHTML=\"<span class='qsent' title='Ya en cuarentena'>\\u2713 En cuarentena</span>\";}"
        "else{b.disabled=false;b.innerHTML=o;aviso('No se pudo enviar',t.replace(/^ERR: /,''));}})"
        ".catch(function(e){b.disabled=false;b.innerHTML=o;aviso('No se pudo enviar','Error: '+e);});}</script>"
        "<section class=\"card\"><h2>Top 5 IPs origen que mas peticionan</h2>"
        "<p class=\"muted\" style=\"margin:0 0 12px\">Quien ataca mas, hacia que IP destino, desde que puerto origen y hacia que puerto destino. "
        "La columna <b>Dueño / organización</b> viene del DNS inverso (PTR) de la IP destino: "
        "<span style='color:#1a7f37;font-weight:700'>verde</span> = servicio conocido (Facebook, Google, Cloudflare, etc., casi siempre legitimo); "
        "<span style='color:#a15c12;font-weight:700'>naranja</span> = dominio del dueño pero no es un gran servicio; "
        "<b>sin PTR</b> = IP sin nombre publico (frecuente en botnets/hosting sucio).</p>"
        f"<div class=\"topwrap\">{''.join(cards)}</div></section>"
        + top_destinos_section() + dominios_section() + entrantes_section() +
        "<!--TOP_FIN-->")

# id numerico del TopoJSON (countries-110m) -> ISO2, y nombres, para el mapa del cliente.
_MAP_NUM2ISO = ("{4:'AF',8:'AL',10:'AQ',12:'DZ',24:'AO',31:'AZ',32:'AR',36:'AU',40:'AT',44:'BS',50:'BD',"
    "51:'AM',56:'BE',64:'BT',68:'BO',70:'BA',72:'BW',76:'BR',84:'BZ',90:'SB',96:'BN',100:'BG',"
    "104:'MM',108:'BI',112:'BY',116:'KH',120:'CM',124:'CA',140:'CF',144:'LK',148:'TD',152:'CL',"
    "156:'CN',158:'TW',170:'CO',178:'CG',180:'CD',188:'CR',191:'HR',192:'CU',196:'CY',203:'CZ',"
    "204:'BJ',208:'DK',214:'DO',218:'EC',222:'SV',226:'GQ',231:'ET',232:'ER',233:'EE',238:'FK',"
    "242:'FJ',246:'FI',250:'FR',260:'TF',262:'DJ',266:'GA',268:'GE',270:'GM',275:'PS',276:'DE',"
    "288:'GH',300:'GR',304:'GL',320:'GT',324:'GN',328:'GY',332:'HT',340:'HN',348:'HU',352:'IS',"
    "356:'IN',360:'ID',364:'IR',368:'IQ',372:'IE',376:'IL',380:'IT',384:'CI',388:'JM',392:'JP',"
    "398:'KZ',400:'JO',404:'KE',408:'KP',410:'KR',414:'KW',417:'KG',418:'LA',422:'LB',426:'LS',"
    "428:'LV',430:'LR',434:'LY',440:'LT',442:'LU',450:'MG',454:'MW',458:'MY',466:'ML',478:'MR',"
    "484:'MX',496:'MN',498:'MD',499:'ME',504:'MA',508:'MZ',512:'OM',516:'NA',524:'NP',528:'NL',"
    "540:'NC',548:'VU',554:'NZ',558:'NI',562:'NE',566:'NG',578:'NO',586:'PK',591:'PA',598:'PG',"
    "600:'PY',604:'PE',608:'PH',616:'PL',620:'PT',624:'GW',626:'TL',630:'PR',634:'QA',642:'RO',"
    "643:'RU',646:'RW',682:'SA',686:'SN',688:'RS',694:'SL',703:'SK',704:'VN',705:'SI',706:'SO',"
    "710:'ZA',716:'ZW',724:'ES',728:'SS',729:'SD',732:'EH',740:'SR',748:'SZ',752:'SE',756:'CH',"
    "760:'SY',762:'TJ',764:'TH',768:'TG',780:'TT',784:'AE',788:'TN',792:'TR',795:'TM',800:'UG',"
    "804:'UA',807:'MK',818:'EG',826:'GB',834:'TZ',840:'US',854:'BF',858:'UY',860:'UZ',862:'VE',"
    "887:'YE',894:'ZM'}")
_MAP_NAMES = ("{AF:'Afganistan',AR:'Argentina',AU:'Australia',AT:'Austria',BD:'Bangladesh',BE:'Belgica',"
    "BO:'Bolivia',BR:'Brasil',BG:'Bulgaria',CA:'Canada',CL:'Chile',CN:'China',CO:'Colombia',CR:'Costa Rica',"
    "CU:'Cuba',CZ:'Chequia',DK:'Dinamarca',DO:'Rep. Dominicana',EC:'Ecuador',EG:'Egipto',SV:'El Salvador',"
    "FI:'Finlandia',FR:'Francia',DE:'Alemania',GR:'Grecia',GT:'Guatemala',HN:'Honduras',HU:'Hungria',"
    "IN:'India',ID:'Indonesia',IR:'Iran',IQ:'Irak',IE:'Irlanda',IL:'Israel',IT:'Italia',JP:'Japon',"
    "KZ:'Kazajistan',KE:'Kenia',KR:'Corea del Sur',KP:'Corea del Norte',MX:'Mexico',MA:'Marruecos',"
    "NL:'Paises Bajos',NZ:'Nueva Zelanda',NI:'Nicaragua',NG:'Nigeria',NO:'Noruega',PK:'Pakistan',"
    "PA:'Panama',PY:'Paraguay',PE:'Peru',PH:'Filipinas',PL:'Polonia',PT:'Portugal',RO:'Rumania',"
    "RU:'Rusia',SA:'Arabia Saudita',RS:'Serbia',SG:'Singapur',ZA:'Sudafrica',ES:'Espana',SE:'Suecia',"
    "CH:'Suiza',SY:'Siria',TW:'Taiwan',TH:'Tailandia',TR:'Turquia',UA:'Ucrania',AE:'Emiratos AU',"
    "GB:'Reino Unido',US:'Estados Unidos',UY:'Uruguay',UZ:'Uzbekistan',VE:'Venezuela',VN:'Vietnam',"
    "HK:'Hong Kong',BY:'Bielorrusia',MD:'Moldavia',BZ:'Belice'}")

def _mapa_origen():
    """Punto de origen del mapa (tu red) como [lon, lat]. Configurable con MAPA_ORIGEN=lon,lat
    en el .conf; por defecto Ecuador. Es solo el punto de partida de los arcos, no un dato real."""
    try:
        v = (_conf_key("MAPA_ORIGEN", "") or "").split(",")
        return [float(v[0]), float(v[1])]
    except Exception:
        return [-78.1, -1.8]

def mapa_ataques_section():
    """Mapa mundial (coropleta por pais) de los DESTINOS de las alertas + arcos animados desde
    tu red hacia cada pais (de donde -> a donde). Con zoom por pais y detalle de que IPs,
    que puertos y que CPEs peticionan. Se dibuja en el navegador con el TopoJSON."""
    datos = {k: v for k, v in pais_dst.items() if k}
    total = sum(datos.values())
    # Detalle por pais para el tooltip y el panel: a que IPs destino, por que puertos y desde
    # que CPEs de tu red. Se recortan los top para no inflar el HTML (se indica cuantos faltan).
    det = {}
    for cc in datos:
        det[cc] = {
            "ips": [[ip, n] for ip, n in pais_ips[cc].most_common(6)],
            "ports": [[p, n] for p, n in pais_ports[cc].most_common(6)],
            "srcs": [[_etq_cpe(s), n] for s, n in pais_srcs[cc].most_common(4)],
            "nip": len(pais_ips[cc]), "npt": len(pais_ports[cc]), "nsr": len(pais_srcs[cc]),
        }
    intro = ("Los paises <b>destino</b> de las alertas (a donde va el trafico sospechoso de tus "
             "CPEs). El color sube con el nº de alertas; los <b>arcos animados</b> muestran el flujo "
             "desde tu red hacia cada pais. <b>Pasa el mouse</b> por un pais para ver a que IPs y "
             "puertos se peticiona, y <b>haz clic para acercar</b>. Geolocalizacion <b>offline</b>; "
             "las IPs privadas o sin pais no cuentan.")
    # Sin paises el mapa se dibuja igual (gris): no hace falta un aviso encima. En un sensor
    # por VPN, que solo ve redes privadas, saldria SIEMPRE y era ruido.
    return (
        "<style>"
        ".attmap .mapwrap{display:block}"
        ".attmap .mapsvg{position:relative;width:100%;background:#f7f9fc;border:1px solid #e7e6e2;border-radius:10px;overflow:hidden}"
        ".attmap #attackmap{width:100%;height:auto;display:block;cursor:grab}"
        ".attmap #attackmap.grab{cursor:grabbing}"
        ".attmap #attackmap path{transition:fill .2s}.attmap #attackmap path:hover{stroke:#0b0b0b;stroke-width:1}"
        ".attmap #attackmap path.sel{stroke:#0b0b0b;stroke-width:1.4}"
        # --- controles de zoom (esquina del mapa) ---
        ".attmap .mapctl{position:absolute;top:8px;right:8px;display:flex;gap:6px;z-index:3}"
        ".attmap .mapctl button{height:28px;min-width:28px;padding:0;border:1px solid #d7d6d2;background:#fff;color:#33322f;"
        "border-radius:7px;font:700 15px system-ui;line-height:1;cursor:pointer;box-shadow:0 1px 3px rgba(0,0,0,.12)}"
        ".attmap .mapctl button.wide{padding:0 10px;font:600 12px system-ui}"
        ".attmap .mapctl button:hover{background:#eef2f7;border-color:#2a78d6;color:#2a78d6}"
        # --- tooltip flotante con el detalle del pais ---
        ".attmap .maptip{position:absolute;z-index:4;display:none;width:266px;background:#fff;border:1px solid #d7d6d2;"
        "border-radius:10px;box-shadow:0 8px 26px rgba(0,0,0,.18);padding:10px 12px;font-size:12.5px;line-height:1.45;pointer-events:none}"
        ".attmap .maptip h4{margin:0 0 3px;font-size:13.5px;display:flex;align-items:center;gap:7px}"
        ".attmap .maptip .dir{color:#6b6a66;font-size:11.5px;margin:0 0 4px}"
        ".attmap .grp{margin:7px 0 0}"
        ".attmap .glbl{font-weight:700;font-size:10.5px;color:#8a8984;text-transform:uppercase;letter-spacing:.4px;margin-bottom:2px}"
        ".attmap .it{display:flex;justify-content:space-between;gap:10px;font:12px ui-monospace,Consolas,monospace}"
        ".attmap .it span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
        ".attmap .mas{color:#9a9a95;font-size:11px;margin-top:1px}"
        ".attmap .cc{font:700 11px ui-monospace,Consolas,monospace;background:#eef2f7;color:#33322f;border-radius:5px;padding:2px 6px}"
        # --- panel de detalle (al hacer clic en un pais): se queda fijo y se lee en movil ---
        ".attmap .mapdet{display:none;margin-top:10px;border:1px solid #e7e6e2;border-radius:10px;padding:12px 14px;background:#fbfcfe}"
        ".attmap .mapdethdr{display:flex;align-items:center;gap:9px;flex-wrap:wrap}"
        ".attmap .mapdethdr b{font-size:14.5px}"
        ".attmap .mapdethdr .dsub{color:#6b6a66;font-size:12px;flex:1;min-width:180px}"
        ".attmap .dclose{margin-left:auto;border:1px solid #d7d6d2;background:#fff;width:26px;height:26px;border-radius:50%;"
        "font-size:16px;line-height:1;cursor:pointer;color:#6b6a66}"
        ".attmap .dclose:hover{background:#f2f1ee;color:#0b0b0b}"
        ".attmap .mapdetgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px 20px;margin-top:10px}"
        ".attmap .maphint{color:#9a9a95;font-size:11.5px;margin:7px 0 0}"
        ".attmap .maptop{margin-top:12px}"
        ".attmap .maptophdr{display:flex;align-items:baseline;gap:10px;font-weight:700;font-size:13px;margin:0 0 6px}"
        ".attmap .maptophdr .sub{margin-left:auto;font-weight:400;font-size:12px;color:#6b6a66}"
        # ranking en 2 columnas que se leen hacia abajo (1-5 | 6-10); --filas lo pone el JS
        ".attmap .maptopgrid{display:grid;grid-template-columns:1fr 1fr;grid-auto-flow:column;"
        "grid-template-rows:repeat(var(--filas,5),auto);gap:0 32px}"
        "@media(max-width:760px){.attmap .maptopgrid{grid-template-columns:1fr;grid-auto-flow:row;grid-template-rows:none}}"
        # puesto | codigo | pais | carril de la barra | alertas | % del total: columnas fijas, todo alineado
        ".attmap .maprow{display:grid;grid-template-columns:20px 34px minmax(80px,150px) minmax(60px,1fr) 40px 38px;"
        "align-items:center;gap:10px;padding:6px 4px;border-bottom:1px solid #f2f1ee;font-size:13px;cursor:pointer}"
        ".attmap .maprow:hover{background:#f4f7fb}"
        ".attmap .maprow .rk{color:#9a9a95;text-align:right;font-variant-numeric:tabular-nums}"
        ".attmap .maprow .cc{text-align:center}"
        ".attmap .maprow .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
        ".attmap .maprow .ct{font-weight:700;text-align:right;font-variant-numeric:tabular-nums}"
        ".attmap .maprow .pc{color:#6b6a66;font-size:12px;text-align:right;font-variant-numeric:tabular-nums}"
        ".attmap .mapcarril{height:6px;border-radius:4px;background:#efeeea;overflow:hidden}"
        ".attmap .mapbar{display:block;height:100%;border-radius:4px;background:#e34948;min-width:3px}"
        ".attmap .mapempty{color:#6b6a66;font-size:13px;background:#faf9f6;border:1px dashed #e0dfda;border-radius:8px;padding:12px 14px;margin-top:8px}"
        "</style>"
        "<section class=\"card attmap\" style=\"margin-top:16px\"><h2>A donde atacan tus CPEs (destino por pais)</h2>"
        "<p class=\"muted\" style=\"margin:0 0 12px\">" + intro + "</p>" +
        "<div class=mapwrap><div class=mapsvg><svg id=attackmap viewBox=\"0 20 1000 392\" "
        "preserveAspectRatio=\"xMidYMid meet\" role=img aria-label=\"Mapa de destinos\"></svg>"
        "<div class=mapctl>"
        "<button type=button id=mzin title=\"Acercar\">+</button>"
        "<button type=button id=mzout title=\"Alejar\">&minus;</button>"
        "<button type=button id=mzrst class=wide title=\"Volver al mundo entero\">Vista completa</button>"
        "</div><div class=maptip id=maptip></div></div>"
        "<div class=mapdet id=mapdet></div>"
        "<p class=maphint>Clic en un pais para acercarlo y ver su detalle &middot; arrastra para mover "
        "&middot; <b>Ctrl + rueda</b> para zoom &middot; <b>Vista completa</b> para volver.</p>"
        "<div class=maptop id=attacktop></div></div>"
        "<script>window.__ATTACK_GEO=" + _json_js(datos) + ";window.__ATTACK_TOTAL=" + str(total) +
        ";window.__ATTACK_DET=" + _json_js(det) +
        ";window.__ATTACK_HOME=" + json.dumps(_mapa_origen()) + ";</script>"
        "<script src=\"/vendor/mapa/topojson-client.min.js\"></script>"
        "<script>(function(){"
        "var DATA=window.__ATTACK_GEO||{},DET=window.__ATTACK_DET||{},NUM2=" + _MAP_NUM2ISO + ",NAMES=" + _MAP_NAMES + ";"
        "var W=1000,H=500,svg=document.getElementById('attackmap');if(!svg)return;"
        "var tip=document.getElementById('maptip'),panel=document.getElementById('mapdet'),box=svg.parentNode;"
        "var BBOX={},NMAP={},sel='';"
        # nombre del pais: el traducido si lo tenemos, si no el del propio mapa (ingles), si no el codigo
        "function nombre(iso){return NAMES[iso]||NMAP[iso]||iso||'?';}"
        "function proj(lo,la){return [(lo+180)*(W/360),(90-la)*(H/180)];}"
        "function heat(f){f=f<0?0:(f>1?1:f);var st=[[0,[43,120,214]],[.35,[27,175,122]],[.65,[237,161,0]],[.85,[235,104,52]],[1,[227,73,72]]];"
        "for(var j=0;j<st.length-1;j++){var a=st[j][0],ca=st[j][1],b=st[j+1][0],cb=st[j+1][1];"
        "if(f<=b){var t=b>a?(f-a)/(b-a):0,r=Math.round(ca[0]+(cb[0]-ca[0])*t),g=Math.round(ca[1]+(cb[1]-ca[1])*t),bl=Math.round(ca[2]+(cb[2]-ca[2])*t);"
        "return 'rgb('+r+','+g+','+bl+')';}}return '#e34948';}"
        "function ringD(r){var d='',prev=null;for(var i=0;i<r.length;i++){var lo=r[i][0],p=proj(lo,r[i][1]);"
        # cruce del antimeridiano (salto de lon >180): cortar el trazo para evitar la banda horizontal
        "if(prev!==null&&Math.abs(lo-prev)>180){d+='ZM'+p[0].toFixed(1)+' '+p[1].toFixed(1);}"
        "else{d+=(i?'L':'M')+p[0].toFixed(1)+' '+p[1].toFixed(1);}prev=lo;}return d+'Z';}"
        "function geomD(g){var d='';if(!g)return d;if(g.type==='Polygon'){g.coordinates.forEach(function(r){d+=ringD(r);});}"
        "else if(g.type==='MultiPolygon'){g.coordinates.forEach(function(pl){pl.forEach(function(r){d+=ringD(r);});});}return d;}"
        "var mx=0;for(var k in DATA){if(DATA[k]>mx)mx=DATA[k];}if(mx<1)mx=1;"
        "function esc(s){return String(s).replace(/[&<>\"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c];});}"
        "function centroid(g){var best=null,bn=0;function c(r){if(r.length>bn){bn=r.length;best=r;}}"
        "if(!g)return null;if(g.type==='Polygon')g.coordinates.forEach(c);else if(g.type==='MultiPolygon')g.coordinates.forEach(function(pl){pl.forEach(c);});"
        "if(!best)return null;var sx=0,sy=0;for(var i=0;i<best.length;i++){var p=proj(best[i][0],best[i][1]);sx+=p[0];sy+=p[1];}return [sx/best.length,sy/best.length];}"
        # bbox del anillo MAS GRANDE (no de toda la geometria): asi el zoom de EEUU va al territorio
        # continental y no se estira hasta Alaska/Hawaii, ni Rusia cruza el antimeridiano.
        "function bboxMain(g){var best=null,bn=0;function c(r){if(r.length>bn){bn=r.length;best=r;}}"
        "if(!g)return null;if(g.type==='Polygon')g.coordinates.forEach(c);else if(g.type==='MultiPolygon')g.coordinates.forEach(function(pl){pl.forEach(c);});"
        "if(!best)return null;var x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;"
        "for(var i=0;i<best.length;i++){var p=proj(best[i][0],best[i][1]);"
        "if(p[0]<x0)x0=p[0];if(p[0]>x1)x1=p[0];if(p[1]<y0)y0=p[1];if(p[1]>y1)y1=p[1];}"
        "return {x:x0,y:y0,w:Math.max(x1-x0,4),h:Math.max(y1-y0,4)};}"
        # --- zoom / desplazamiento: se mueve el viewBox del SVG (nitido a cualquier escala) ---
        "var VB0={x:0,y:20,w:1000,h:392},AR=VB0.w/VB0.h,vb={x:VB0.x,y:VB0.y,w:VB0.w,h:VB0.h};"
        "function setVB(){svg.setAttribute('viewBox',vb.x.toFixed(1)+' '+vb.y.toFixed(1)+' '+vb.w.toFixed(1)+' '+vb.h.toFixed(1));}"
        "function fit(b){if(!b)return;var pad=Math.max(b.w,b.h)*0.30+8,w=b.w+pad*2,h=b.h+pad*2;"
        "if(w/h<AR)w=h*AR;else h=w/AR;if(w<60){w=60;h=w/AR;}"
        "vb={x:b.x+b.w/2-w/2,y:b.y+b.h/2-h/2,w:w,h:h};setVB();}"
        "function reset(){vb={x:VB0.x,y:VB0.y,w:VB0.w,h:VB0.h};setVB();}"
        "function zoom(f,cx,cy){var nw=vb.w*f,nh=vb.h*f;"
        "if(nw>VB0.w){nw=VB0.w;nh=VB0.h;}if(nw<60){nw=60;nh=nw/AR;}"
        "if(cx===undefined){cx=vb.x+vb.w/2;cy=vb.y+vb.h/2;}"
        "vb.x=cx-(cx-vb.x)*(nw/vb.w);vb.y=cy-(cy-vb.y)*(nh/vb.h);vb.w=nw;vb.h=nh;setVB();}"
        "function at(e){var r=svg.getBoundingClientRect();"
        "return [vb.x+(e.clientX-r.left)/r.width*vb.w,vb.y+(e.clientY-r.top)/r.height*vb.h];}"
        # --- detalle de un pais: a que IPs, por que puertos y desde que CPEs (direccion saliente) ---
        "function grupo(lbl,items,tot){if(!items||!items.length)return '';"
        "var h='<div class=grp><div class=glbl>'+lbl+'</div>';"
        "items.forEach(function(kv){h+='<div class=it><span>'+esc(kv[0])+'</span><b>'+kv[1]+'</b></div>';});"
        "if(tot>items.length)h+='<div class=mas>+'+(tot-items.length)+' mas</div>';return h+'</div>';}"
        "function dirTxt(iso){var nm=nombre(iso),c=DATA[iso]||0;"
        "return c?('Direccion <b>saliente</b>: tus CPEs &rarr; '+esc(nm)+' &middot; <b>'+c+'</b> alertas')"
        ":('Sin alertas hacia '+esc(nm)+' en la ventana.');}"
        "function grupos(iso){var d=DET[iso];if(!d)return '';"
        "return grupo('IPs destino (a donde)',d.ips,d.nip)+grupo('Puertos destino',d.ports,d.npt)"
        "+grupo('CPEs de tu red (de donde)',d.srcs,d.nsr);}"
        "function showTip(iso,e){if(!tip)return;"
        "tip.innerHTML='<h4><span class=cc>'+esc(iso)+'</span>'+esc(nombre(iso))+'</h4>'"
        "+'<div class=dir>'+dirTxt(iso)+'</div>'+grupos(iso);"
        "tip.style.display='block';var r=box.getBoundingClientRect();"
        "var x=e.clientX-r.left+16,y=e.clientY-r.top+16,tw=tip.offsetWidth,th=tip.offsetHeight;"
        "if(x+tw>r.width-6)x=e.clientX-r.left-tw-16;if(x<4)x=4;"
        "if(y+th>r.height-6)y=Math.max(4,e.clientY-r.top-th-16);"
        "tip.style.left=x+'px';tip.style.top=y+'px';}"
        "function hideTip(){if(tip)tip.style.display='none';}"
        # ojo: sin el guard de 'iso', marcar('') seleccionaba TODOS los paises sin codigo
        # (data-iso=\"\") y les pintaba el borde negro al pulsar 'Vista completa'.
        "function marcar(iso){sel=iso;Array.prototype.forEach.call(svg.querySelectorAll('path[data-iso]'),function(p){"
        "if(iso&&p.getAttribute('data-iso')===iso)p.classList.add('sel');else p.classList.remove('sel');});}"
        "function panelDe(iso){if(!panel)return;"
        "panel.innerHTML='<div class=mapdethdr><span class=cc>'+esc(iso)+'</span><b>'+esc(nombre(iso))+'</b>'"
        "+'<span class=dsub>'+dirTxt(iso)+'</span>'"
        "+'<button type=button class=dclose title=\"Cerrar\">&times;</button></div>'"
        "+'<div class=mapdetgrid>'+grupos(iso)+'</div>';"
        "panel.style.display='block';"
        "var b=panel.querySelector('.dclose');if(b)b.addEventListener('click',cerrar);}"
        "function abrir(iso){if(!panel)return;marcar(iso);fit(BBOX[iso]);panelDe(iso);guardarVista();}"
        "function cerrar(){if(panel)panel.style.display='none';marcar('');reset();guardarVista();}"
        # --- la pagina se recarga sola cada 5 min: sin esto el mapa volvia al mundo entero
        # y perdias el pais que estabas mirando ---
        "var MK='mapa:'+location.pathname,guardaPend=null;"
        "function guardarVista(){clearTimeout(guardaPend);guardaPend=setTimeout(function(){"
        "try{sessionStorage.setItem(MK,JSON.stringify({v:vb,s:sel}));}catch(e){}},300);}"
        "function restaurarVista(){try{var g=JSON.parse(sessionStorage.getItem(MK)||'null');"
        "if(!g||!g.v||!g.v.w)return;"
        "vb={x:+g.v.x,y:+g.v.y,w:+g.v.w,h:+g.v.h};setVB();"
        # se repone la vista exacta (incluido el desplazamiento), no se re-encuadra el pais
        "if(g.s&&DATA[g.s]){marcar(g.s);panelDe(g.s);}}catch(e){}}"
        "var HOME=window.__ATTACK_HOME||[-78.1,-1.8],home=proj(HOME[0],HOME[1]);"
        "fetch('/vendor/mapa/countries-110m.json').then(function(r){return r.json();}).then(function(topo){"
        "var feats=topojson.feature(topo,topo.objects.countries).features,frag='',cents={};"
        "feats.forEach(function(ft){var iso=NUM2[+ft.id]||'',pn=(ft.properties&&ft.properties.name)||'';"
        "if(!iso&&pn==='Kosovo')iso='XK';"   # Kosovo no trae id ISO en el mapa; GeoIP si lo reporta
        "if(iso&&pn)NMAP[iso]=pn;var c=DATA[iso]||0;"
        "var fill=c>0?heat(c/mx):'#e7ebf0';var nm=nombre(iso)||pn||'?';"
        "frag+='<path data-iso=\"'+esc(iso)+'\" d=\"'+geomD(ft.geometry)+'\" fill=\"'+fill+'\" stroke=\"#fff\" "
        "stroke-width=\"0.4\" vector-effect=\"non-scaling-stroke\">"
        "<title>'+esc(nm)+(c>0?': '+c+' alertas':'')+'</title></path>';"
        "if(iso){var bb=bboxMain(ft.geometry);if(bb)BBOX[iso]=bb;}"
        "if(c>0){var ce=centroid(ft.geometry);if(ce)cents[iso]=ce;}});"
        # --- flujo de donde -> a donde: arcos animados desde tu red hacia cada pais destino ---
        "var arcs='';Object.keys(cents).forEach(function(iso,idx){var ce=cents[iso],n=DATA[iso];"
        "var dx=ce[0]-home[0],dy=ce[1]-home[1],len=Math.sqrt(dx*dx+dy*dy);"
        "var mid=[(home[0]+ce[0])/2-dy*0.18,(home[1]+ce[1])/2+dx*0.18];"
        "var d='M'+home[0].toFixed(1)+' '+home[1].toFixed(1)+' Q'+mid[0].toFixed(1)+' '+mid[1].toFixed(1)+' '+ce[0].toFixed(1)+' '+ce[1].toFixed(1);"
        "var w=(0.8+1.8*(n/mx)).toFixed(2);"
        "arcs+='<path d=\"'+d+'\" fill=\"none\" stroke=\"#e34948\" stroke-opacity=\"0.5\" stroke-width=\"'+w+'\" "
        "vector-effect=\"non-scaling-stroke\" pointer-events=\"none\"/>';"
        "arcs+='<circle r=\"2.1\" fill=\"#e34948\" pointer-events=\"none\"><animateMotion dur=\"'+(1.6+len/900).toFixed(1)+'s\" repeatCount=\"indefinite\" path=\"'+d+'\"/></circle>';"
        # punta del arco: mismo latido que el origen, para ver de un vistazo donde cae cada
        # flujo. Se desfasa un poco cada uno (begin) para que no parpadeen todos a la vez.
        "var cx=ce[0].toFixed(1),cy=ce[1].toFixed(1),dl=((idx%7)*0.22).toFixed(2);"
        "arcs+='<circle cx=\"'+cx+'\" cy=\"'+cy+'\" r=\"2.6\" fill=\"#e34948\" pointer-events=\"none\"/>';"
        "arcs+='<circle cx=\"'+cx+'\" cy=\"'+cy+'\" r=\"2.6\" fill=\"none\" stroke=\"#e34948\" "
        "stroke-width=\"1.2\" vector-effect=\"non-scaling-stroke\" pointer-events=\"none\">"
        "<animate attributeName=\"r\" values=\"2.6;10\" dur=\"1.8s\" begin=\"'+dl+'s\" repeatCount=\"indefinite\"/>"
        "<animate attributeName=\"stroke-opacity\" values=\"0.7;0\" dur=\"1.8s\" begin=\"'+dl+'s\" repeatCount=\"indefinite\"/>"
        "</circle>';});"
        "if(Object.keys(cents).length){arcs+='<circle cx=\"'+home[0].toFixed(1)+'\" cy=\"'+home[1].toFixed(1)+'\" r=\"3\" fill=\"#0b0b0b\" pointer-events=\"none\"/>';"
        "arcs+='<circle cx=\"'+home[0].toFixed(1)+'\" cy=\"'+home[1].toFixed(1)+'\" r=\"3\" fill=\"none\" stroke=\"#0b0b0b\" pointer-events=\"none\">"
        "<animate attributeName=\"r\" values=\"3;12\" dur=\"1.8s\" repeatCount=\"indefinite\"/>"
        "<animate attributeName=\"stroke-opacity\" values=\"0.55;0\" dur=\"1.8s\" repeatCount=\"indefinite\"/></circle>';}"
        "svg.innerHTML=frag+arcs;if(sel)marcar(sel);pintarTop();restaurarVista();"
        "}).catch(function(e){var w=document.getElementById('attacktop');if(w)w.innerHTML='<div class=mapempty>No se pudo cargar el mapa.</div>';});"
        # --- interaccion: hover = detalle, clic = acercar el pais, arrastrar = mover, Ctrl+rueda = zoom ---
        "function isoDe(e){var t=e.target;return (t&&t.getAttribute)?(t.getAttribute('data-iso')||''):'';}"
        "var drag=null,movido=false;"
        "svg.addEventListener('mousedown',function(e){drag={x:e.clientX,y:e.clientY,vx:vb.x,vy:vb.y};movido=false;svg.classList.add('grab');});"
        "window.addEventListener('mouseup',function(){if(drag){drag=null;svg.classList.remove('grab');"
        "if(movido)guardarVista();}});"
        "svg.addEventListener('mousemove',function(e){"
        "if(drag){var r=svg.getBoundingClientRect(),dx=e.clientX-drag.x,dy=e.clientY-drag.y;"
        "if(Math.abs(dx)>3||Math.abs(dy)>3){movido=true;hideTip();"
        "vb.x=drag.vx-dx/r.width*vb.w;vb.y=drag.vy-dy/r.height*vb.h;setVB();}return;}"
        "var iso=isoDe(e);if(iso)showTip(iso,e);else hideTip();});"
        "svg.addEventListener('mouseleave',hideTip);"
        "svg.addEventListener('click',function(e){if(movido){movido=false;return;}"
        "var iso=isoDe(e);if(iso)abrir(iso);else cerrar();});"
        "svg.addEventListener('wheel',function(e){if(!(e.ctrlKey||e.metaKey))return;"
        "e.preventDefault();var p=at(e);zoom(e.deltaY<0?0.82:1.22,p[0],p[1]);guardarVista();},{passive:false});"
        "var bi=document.getElementById('mzin'),bo=document.getElementById('mzout'),br=document.getElementById('mzrst');"
        "if(bi)bi.addEventListener('click',function(){zoom(0.7);guardarVista();});"
        "if(bo)bo.addEventListener('click',function(){zoom(1.43);guardarVista();});"
        "if(br)br.addEventListener('click',cerrar);"
        "var w=document.getElementById('attacktop');"
        # se pinta ya (aunque el mapa tarde) y otra vez al cargarlo, cuando ya hay nombres de pais
        "function pintarTop(){if(!w)return;"
        "var todos=Object.keys(DATA).map(function(k){return [k,DATA[k]];}).sort(function(a,b){return b[1]-a[1];});"
        "var rows=todos.slice(0,10),tot=window.__ATTACK_TOTAL||0,html='';"
        # barra: proporcional al primero, en un carril igual para todos; %: sobre el total de alertas
        "rows.forEach(function(kv,i){var iso=kv[0],c=kv[1],nm=nombre(iso),ancho=Math.round(c/rows[0][1]*100),"
        "p=tot?c/tot*100:0,pc=!tot?'':(p>0&&p<1?'<1%':Math.round(p)+'%');"
        "html+='<div class=maprow data-iso=\"'+esc(iso)+'\" title=\"Ver detalle y acercar\"><span class=rk>'+(i+1)+'</span>"
        "<span class=cc>'+esc(iso)+'</span><span class=nm>'+esc(nm)+'</span>"
        "<span class=mapcarril><span class=mapbar style=\"width:'+ancho+'%\"></span></span>"
        "<span class=ct>'+c+'</span><span class=pc>'+pc+'</span></div>';});"
        "w.innerHTML=html?('<div class=maptophdr>Top paises destino<span class=sub>'+tot+' alertas &middot; '+todos.length+"
        "(todos.length===1?' pais':' paises')+'</span></div><div class=maptopgrid style=\"--filas:'+Math.ceil(rows.length/2)+'\">'+html+'</div>'):'';}"
        "pintarTop();"
        # clic en una fila del top = mismo efecto que clic en el pais (acerca y abre el detalle)
        "if(w)w.addEventListener('click',function(e){var r=e.target.closest?e.target.closest('.maprow'):null;"
        "if(r&&r.getAttribute('data-iso')){abrir(r.getAttribute('data-iso'));"
        "var s=document.getElementById('attackmap');if(s&&s.scrollIntoView)s.scrollIntoView({behavior:'smooth',block:'nearest'});}});"
        "})();</script></section>")

def _dst_badge(dst):
    """Chip del dueño/reputacion de una IP destino, para la cabecera de su tarjeta."""
    fuente = es_malo(dst)
    if fuente:
        return (f"<span class='obadge bad' title='Destino en lista de reputacion ({esc(fuente)})'>"
                f"&#9888; {esc(fuente)}</span>")
    d = duenio(dst)
    if d is None:
        return _pend_dueno(dst)
    org, legit = d
    if org in ("-", "sin PTR"):
        return "<span class='obadge none'>sin PTR</span>"
    cls = "ok" if legit else "unk"
    return f"<span class='obadge {cls}'>{esc(org)}</span>"

def top_destinos_section(n_dst=5, n_sub=8):
    """Espejo del anterior: IPs DESTINO mas atacadas (las mas golpeadas) y QUE CPEs las
    atacan. Sirve para ver blancos comunes (un mismo C2/servidor tocado por varios CPEs)."""
    tops = [(d, c) for d, c in by_dst.most_common() if d and d != "?"][:n_dst]
    if not tops:
        return ("<section class=\"card\"><h2>Top IPs destino mas atacadas</h2>"
                "<p class=\"muted\">Sin ataques en la ventana.</p></section>")
    cards = []
    for i, (dst, tot) in enumerate(tops, 1):
        agg = {}                       # (src,sport,dport,proto) -> veces
        srcs = set()
        for (s, sp, d, dp, pr, sig), v in flujos.items():
            if d != dst:
                continue
            agg[(s, sp, dp, pr)] = agg.get((s, sp, dp, pr), 0) + v[0]
            srcs.add(s)
        sub = sorted(agg.items(), key=lambda kv: kv[1], reverse=True)[:n_sub]
        rows = "".join(
            f"<tr><td class='mono' style='color:#184f95'>{esc(ip_de(s) or '-')}{_chip_nodo(s)}</td>"
            f"<td class='mono'>{esc(sp or '-')}</td>"
            f"<td class='mono'>{esc(dp or '-')}</td>"
            f"<td class='mono'>{esc((pr or '-').upper())}</td>"
            f"<td class='num'>{c:,}</td></tr>" for (s, sp, dp, pr), c in sub)
        cards.append(
            f"<div class='tcard'>"
            f"<div class='thd'><span class='rank'>#{i}</span>"
            f"<span class='ipx mono'>{esc(dst)}</span>{_dst_badge(dst)}"
            f"<span class='tot'>{tot:,} alertas</span>"
            f"<span class='meta'>&larr; {len(srcs):,} CPE origen lo atacan</span></div>"
            f"<div class='tablewrap'><table><thead><tr>"
            f"<th>CPE origen (quien ataca)</th><th>Puerto origen</th>"
            f"<th class='num'>Puerto destino</th><th>Protocolo</th><th class='num'>Peticiones</th>"
            f"</tr></thead><tbody>{rows}</tbody></table></div></div>")
    # Los resolutores, aparte y con la lectura correcta: no "atacados", sino "usados para
    # preguntar dominios maliciosos". Lo que importa de esta fila es cuantos CPEs lo hacen.
    res_html = ""
    if via_dns:
        filas = ""
        for d, n in via_dns.most_common(5):
            filas += ("<tr><td class='mono'>%s</td><td class='num'>%s</td>"
                      "<td class='num'>%s</td></tr>"
                      % (esc(d), format(n, ","), format(len(via_dns_src.get(d, ())), ",")))
        res_html = (
            "<div style='margin:0 0 12px;background:#f3f7fd;border:1px solid #d8e5f7;"
            "border-radius:8px;padding:10px 12px'>"
            "<b>Resolutores DNS usados para consultar dominios maliciosos</b>"
            "<p class='muted' style='margin:4px 0 8px;font-size:13px'>No son blancos: son "
            "los DNS a los que tus CPEs preguntan por dominios fichados. "
            "La prueba es el dominio, no el DNS. Las alertas cuentan en el CPE, no aqui. Se gestionan en "
            "<b>Ajustes &rarr; DNS</b>.</p>"
            "<table style='font-size:13px'><thead><tr><th>Resolutor</th>"
            "<th class='num'>Consultas maliciosas</th><th class='num'>CPEs distintos</th>"
            "</tr></thead><tbody>" + filas + "</tbody></table></div>")
    return (
        "<section class=\"card\" style=\"margin-top:16px\"><h2>Top IPs destino mas atacadas (y quien las ataca)</h2>"
        + res_html +
        "<p class=\"muted\" style=\"margin:0 0 12px\">El espejo del cuadro anterior: los blancos que reciben mas alertas y "
        "los CPEs de tu red que los atacan. Util para detectar un <b>destino comun</b> (un mismo C2 o servidor tocado por "
        "varios CPEs a la vez). El chip muestra el dueño/reputacion del destino.</p>"
        f"<div class=\"topwrap\">{''.join(cards)}</div></section>")

DOMINIOS_FILE = os.path.join(OUTDIR, "dominios-malos.json")

def dominios_section(n=15, n_ips=4):
    """Dominios maliciosos consultados y desde que IP de la red. Es la lista que se
    presenta: el dominio es la prueba, no la IP del DNS. Tambien se deja en JSON (top 200)
    para el panel."""
    if not dom_cnt:
        return ""
    top = dom_cnt.most_common(n)
    filas = ""
    for d, nq in top:
        quien = dom_src.get(d, Counter())
        ej = ", ".join("%s (%d)" % (esc(ip_de(k)), c) for k, c in quien.most_common(n_ips))
        if len(quien) > n_ips:
            ej += " +%d mas" % (len(quien) - n_ips)
        res = ", ".join(esc(r) for r, _c in dom_res.get(d, Counter()).most_common(3)) or "&mdash;"
        por = dom_por.get(d, "")
        filas += ("<tr><td class='mono' style='word-break:break-all'>%s</td><td>%s</td>"
                  "<td class='num'>%s</td><td class='num'>%s</td>"
                  "<td class='mono' style='color:#184f95'>%s</td><td class='mono'>%s</td></tr>"
                  % (esc(d), esc(por), format(nq, ","), format(len(quien), ","), ej or "&mdash;", res))
    try:
        salida = []
        for d, nq in dom_cnt.most_common(200):
            quien = dom_src.get(d, Counter())
            salida.append({"dominio": d, "por": dom_por.get(d, ""), "consultas": nq,
                           "cpes": len(quien),
                           "ips": [[ip_de(k), c] for k, c in quien.most_common(8)],
                           "resolutores": [r for r, _c in dom_res.get(d, Counter()).most_common(3)]})
        _t = DOMINIOS_FILE + ".tmp"
        with open(_t, "w", encoding="utf-8") as _f:
            json.dump({"generado": int(time.time()), "ventana_min": VENTANA_MIN,
                       "total_dominios": len(dom_cnt), "dominios": salida}, _f)
        os.replace(_t, DOMINIOS_FILE)
    except Exception:
        pass
    return (
        "<section class=\"card\" style=\"margin-top:16px\"><h2>Dominios maliciosos consultados (y desde que IP de tu red)</h2>"
        "<p class=\"muted\" style=\"margin:0 0 12px\">Lo que se pregunta al DNS y quien lo pregunta. "
        "El <b>dominio</b> es la prueba; la columna <b>por que</b> dice si lo ficha un feed "
        "(URLhaus, ThreatFox) o una firma de Suricata; <b>IPs de tu red</b> son los CPEs que lo "
        "consultaron (y cuantas veces); el <b>resolutor</b> es solo el canal, no una victima.</p>"
        "<div class='tablewrap'><table><thead><tr><th>Dominio</th><th>Por que es malicioso</th>"
        "<th class='num'>Consultas</th><th class='num'>CPEs</th><th>IPs de tu red (consultas)</th>"
        "<th>Resolutor</th></tr></thead><tbody>" + filas + "</tbody></table></div>"
        + ("<p class='muted' style='margin:8px 0 0;font-size:12px'>Se muestran %d de %s dominios distintos "
           "en la ventana.</p>" % (len(top), format(len(dom_cnt), ",")) if len(dom_cnt) > n else "")
        + "</section>")

def entrantes_section(n_src=8, n_sub=6, max_src=5000, max_det=60):
    """Ataques ENTRANTES: origenes de INTERNET golpeando IPs de TU red.

    Van aparte a proposito. No son abonados tuyos, asi que no se pueden mandar a la
    cuarentena de CPEs (ahi solo entran tus IPs): se cortan en el borde, o se cierra la
    exposicion del equipo golpeado. Mezclarlos con los CPEs hacia que un escaner de
    internet insistente apareciera como 'CPE infectado'."""
    agg = {}
    for (s, sp, d, dp, pr, sig), v in flujos.items():
        if es_mi_cpe(s) or not es_mi_cpe(d, rid_de(s)):
            continue                      # solo internet -> tu red (CPE propio nunca es «entrante»)
        e = agg.get(s)
        if e is None:
            if len(agg) >= max_src:       # cota de RAM, como el resto del script
                continue
            e = agg[s] = {"n": 0, "dst": set(), "det": {}}
        e["n"] += v[0]
        if len(e["dst"]) < 200:
            e["dst"].add(d)
        k = (d, dp, pr, sig)
        if k in e["det"] or len(e["det"]) < max_det:
            e["det"][k] = e["det"].get(k, 0) + v[0]
    if not agg:
        return ""                          # sin ataques entrantes: no se muestra el apartado
    tops = sorted(agg.items(), key=lambda kv: kv[1]["n"], reverse=True)[:n_src]
    cards = []
    for i, (src, e) in enumerate(tops, 1):
        sub = sorted(e["det"].items(), key=lambda kv: kv[1], reverse=True)[:n_sub]
        rows = "".join(
            f"<tr><td class='mono' style='color:#184f95'>{esc(d or '-')}</td>"
            f"<td class='mono'>{esc(dp or '-')}</td>"
            f"<td class='mono'>{esc((pr or '-').upper())}</td>"
            f"<td class='fw'>{esc((sig or '-')[:70])}</td>"
            f"<td class='num'>{c:,}</td></tr>" for (d, dp, pr, sig), c in sub)
        _pa = pais(ip_de(src))
        _chip = f"<span class='obadge unk'>{esc(_pa)}</span>" if _pa else ""
        _ipa = ip_de(src)
        # que se le denuncia a ESTE atacante (si el panel ya lo consulto en AbuseIPDB)
        _aidb = _aidb_chip(_ipa)
        # denunciarlo de vuelta: solo si el admin lo habilito en Ajustes
        _den = ""
        if _AIDB_REPORTAR:
            _tf = sub[0][0] if sub else ("", "", "", "")
            _den = (f"<button class='qsend' title='Denunciar esta IP a AbuseIPDB "
                    f"(accion publica y a tu nombre)' onclick=\"qden(this,'{esc(_ipa)}',"
                    f"'{esc((_tf[3] or '')[:90])}','{esc(_tf[1] or '')}','{esc(_tf[2] or '')}',"
                    f"'{e['n']}')\">&#9873; Denunciar</button>")
        cards.append(
            f"<div class='tcard'>"
            f"<div class='thd'><span class='rank'>#{i}</span>"
            f"<span class='ipx mono'>{esc(_ipa)}</span>{_chip}{_dst_badge(_ipa)}{_chip_nodo(src)}"
            f"<span class='tot'>{e['n']:,} alertas</span>{_den}"
            f"<span class='meta'>&rarr; ataco {len(e['dst']):,} IP(s) de tu red</span></div>"
            + (f"<div style='padding:0 15px 10px'>{_aidb}</div>" if _aidb else "")
            + f"<div class='tablewrap'><table><thead><tr>"
            f"<th>Equipo tuyo atacado</th><th>Puerto destino</th>"
            f"<th>Protocolo</th><th>Firma</th><th class='num'>Peticiones</th>"
            f"</tr></thead><tbody>{rows}</tbody></table></div></div>")
    return (
        "<section class=\"card\" style=\"margin-top:16px\"><h2>Ataques entrantes desde internet</h2>"
        "<p class=\"muted\" style=\"margin:0 0 12px\">Direcciones de <b>internet</b> que estan atacando "
        "equipos de tu red. "
        "<b>No son abonados tuyos</b>, asi que no entran al motor de cuarentena: mandarlos a la "
        "address-list de CPEs no bloquearia nada util. Lo que corresponde es <b>cortarlos en el borde</b> "
        "(firewall de entrada) o <b>cerrar la exposicion</b> del equipo atacado: si algo tuyo recibe "
        "escaneo constante desde internet, casi siempre es que tiene un puerto publicado que no hacia falta.</p>"
        + ("<script>function qden(b,ip,f,dp,pr,n){"
           "if(!ask(b,'Denunciar a AbuseIPDB','Se denuncia '+ip+' publicamente y queda a tu "
           "nombre. No se envia ninguna IP tuya.','Denunciar','danger'))return;"
           "b.disabled=true;var o=b.innerHTML;b.textContent='enviando...';"
           "fetch('/reputacion/denunciar',{method:'POST',credentials:'same-origin',"
           "headers:{'Content-Type':'application/x-www-form-urlencoded'},"
           "body:'ip='+encodeURIComponent(ip)+'&firma='+encodeURIComponent(f)+'&dport='+"
           "encodeURIComponent(dp)+'&proto='+encodeURIComponent(pr)+'&n='+encodeURIComponent(n)})"
           ".then(function(r){return r.text();}).then(function(t){"
           "if(t.indexOf('OK')===0){b.outerHTML=\"<span class='qsent'>\\u2713 Denunciado</span>\";}"
           "else{b.disabled=false;b.innerHTML=o;aviso('No se pudo denunciar',t.replace(/^ERR: /,''));}})"
           ".catch(function(e){b.disabled=false;b.innerHTML=o;aviso('No se pudo denunciar','Error: '+e);});}</script>"
           if _AIDB_REPORTAR else "")
        + f"<div class=\"topwrap\">{''.join(cards)}</div></section>")

top_sec = top_origenes_section()

# --- Destinos de MALA REPUTACION que tus CPEs estan contactando --------------------
# Distinto de los atacantes entrantes: estos son destinos a los que sale trafico desde tu
# red y que estan fichados en los feeds. Bloquearlos corta el canal de control de las
# botnets, que es lo que mantiene vivo al equipo infectado.
DESTINOS_FILE = os.path.join(OUTDIR, "destinos-malos.json")
try:
    _dm = {}
    for (_s, _sp, _d, _dp, _pr, _sig), _v in flujos.items():
        if not es_mi_cpe(_s) or es_mi_cpe(_d, rid_de(_s)):
            continue                      # solo TU red -> internet
        _fuente, _cidr = reputacion_de(_d)
        if not _fuente or not es_malo_firme(_d):
            continue                      # sin ficha, o solo contexto (Tor): no se corta
        _e = _dm.get(_d)
        if _e is None:
            if len(_dm) >= 5000:
                continue
            _mm = REP_META.get(_fuente, {})
            _e = _dm[_d] = {"alertas": 0, "cpes": set(), "puertos": set(),
                            "fuente": _fuente, "categoria": _mm.get("categoria", ""),
                            "cidr": _cidr, "vigente": bool(_mm.get("vigente")),
                            "firma": "", "ultima": 0}
        _e["alertas"] += _v[0]
        if len(_e["cpes"]) < 200:
            _e["cpes"].add(_s)
        if _dp and len(_e["puertos"]) < 10:
            _e["puertos"].add(_dp)
        if not _e["firma"]:
            _e["firma"] = (_sig or "")[:90]
        if _v[2] > _e["ultima"]:
            _e["ultima"] = _v[2]
    _sal_dm = {k: {"alertas": v["alertas"], "cpes": len(v["cpes"]),
                   "cpes_ej": sorted(v["cpes"])[:8], "puertos": sorted(v["puertos"])[:10],
                   "fuente": v["fuente"], "categoria": v["categoria"], "cidr": v["cidr"],
                   "vigente": v["vigente"], "firma": v["firma"],
                   "ultima": int(v["ultima"] or 0), "pais": pais(k)}
               for k, v in sorted(_dm.items(), key=lambda kv: kv[1]["alertas"], reverse=True)}
    _tmpd = DESTINOS_FILE + ".tmp"
    with open(_tmpd, "w", encoding="utf-8") as _f:
        json.dump({"generado": int(time.time()), "ventana_min": VENTANA_MIN,
                   "destinos": _sal_dm}, _f)
    os.replace(_tmpd, DESTINOS_FILE)
except Exception:
    pass

# --- Quien nos ataca desde internet ------------------------------------------------
# Se guarda aparte porque el panel lo necesita para armar la lista de bloqueo del borde.
# La cadena es: el atacante de fuera infecta al CPE, el CPE infectado ensucia tu IP
# publica. Cortar la entrada es lo que corta infecciones NUEVAS.
ENTRANTES_FILE = os.path.join(OUTDIR, "entrantes.json")
try:
    _ent = {}
    for (_s, _sp, _d, _dp, _pr, _sig), _v in flujos.items():
        _sip = ip_de(_s)
        if es_mi_cpe(_s) or not es_mi_cpe(_d, rid_de(_s)):
            continue                      # solo internet -> tu red
        _e = _ent.get(_sip)
        if _e is None:
            if len(_ent) >= 20000:        # cota: un dia malo son decenas de miles de origenes
                continue
            _e = _ent[_sip] = {"alertas": 0, "dst": set(), "puertos": set(),
                               "firma": "", "ultima": 0}
        _e["alertas"] += _v[0]
        if len(_e["dst"]) < 50:
            _e["dst"].add(_d)
        if _dp and len(_e["puertos"]) < 20:
            _e["puertos"].add(_dp)
        if not _e["firma"]:
            _e["firma"] = (_sig or "")[:90]
        if _v[2] > _e["ultima"]:
            _e["ultima"] = _v[2]
    _sal_ent = {k: {"alertas": v["alertas"], "destinos": len(v["dst"]),
                    "puertos": sorted(v["puertos"])[:10], "firma": v["firma"],
                    "ultima": int(v["ultima"] or 0), "pais": pais(k)}
                for k, v in sorted(_ent.items(), key=lambda kv: kv[1]["alertas"],
                                   reverse=True)[:5000]}
    _tmpe = ENTRANTES_FILE + ".tmp"
    with open(_tmpe, "w", encoding="utf-8") as _f:
        json.dump({"generado": int(time.time()), "ventana_min": VENTANA_MIN,
                   "origenes": _sal_ent}, _f)
    os.replace(_tmpe, ENTRANTES_FILE)
except Exception:
    pass

# --- Cuarentena (Fase A, dry-run): CPEs INFECTADOS CONFIRMADOS (repeticion/contexto).
# Solo se ESCRIBE la lista de candidatos; NO se toca el MikroTik. El panel la muestra.
try:
    # correlacion de flota: CPEs que comparten un patron (misma firma+puerto) con >=3 CPEs
    correlacionados = set()
    for _k, _srcs in patron_src.items():
        if len(_srcs) >= 3:
            correlacionados |= _srcs

    def _reputacion_src(src):
        """Coincidencias de reputacion de los destinos del CPE: (fuente, CIDR exacto,
        categoria, vigencia). Para la ficha de evidencia."""
        out = []; vistos = set()
        for d in dst_by_src.get(src, ()):
            fuente, cidr = reputacion_de(d)
            if fuente and (fuente, cidr) not in vistos:
                vistos.add((fuente, cidr))
                mm = REP_META.get(fuente, {})
                # el puerto de C2 coincide? (ThreatFox ip:port): es la diferencia entre
                # "toco una IP fichada" y "hablo con el C2 por donde el C2 escucha"
                _pc2 = REP_PORTS.get(d)
                _coincide = bool(_pc2) and any(
                    k[2] == d and str(k[3]) in _pc2 for k in flujos_de(src))
                out.append({"ip": d, "cidr": cidr, "fuente": fuente,
                            "categoria": mm.get("categoria", ""), "vigente": mm.get("vigente", False),
                            "fetched_valid": mm.get("fetched_valid", 0), "expira": mm.get("expira", 0),
                            "puerto_c2": _coincide, "contexto": mm.get("categoria", "") in REP_CONTEXTO})
                if len(out) >= 8:
                    break
        return out

    def _evidencias_inf(src):
        """Evidencias INDEPENDIENTES (tipos distintos) que respaldan una infeccion. La
        repeticion o el volumen del MISMO conjunto de alertas NO son evidencia independiente;
        aqui se cuentan solo TIPOS distintos. Devuelve (n, lista de etiquetas)."""
        ev = []
        nsids = len(inf_sids.get(src, ()))
        if nsids >= 2:
            ev.append(f"{nsids} firmas CnC distintas")
        _dm = [d for d in dst_by_src.get(src, ()) if es_malo_firme(d)]
        if _dm:
            ev.append(f"destino en lista de reputacion ({len(_dm)})")
        if (src in n5_by_src) and (n1h_by_src.get(src, 0) > n5_by_src.get(src, 0)):
            ev.append("actividad sostenida (5 min y 1 h)")
        if src in correlacionados:
            ev.append("patron compartido con otros CPE (campana)")
        if dns_hits.get(src, 0) >= 1:
            ev.append("consulto dominio malicioso (DNS)")
        return len(ev), ev

    def _ultima(clave):
        """Epoch de la ultima alerta (o consulta DNS mala) de esa clave pid|ip: con ella el panel
        comprueba que la evidencia es reciente antes de una cuarentena (CONTRATO-F2 §10.4)."""
        t = ultima_by_src.get(clave)
        return int(t) if t else None

    cand = []
    for src in inf_hits:
        if not es_mi_cpe(src):
            continue            # atacante de internet, no un abonado: va al apartado de entrantes
        if nunca_bloquear(ip_de(src)):
            continue                                    # allowlist: nunca a cuarentena
        # gatillo minimo para siquiera considerarlo (repeticion o >=2 firmas)
        if not (inf_hits[src] >= UMBRAL_INFECTADO or len(inf_sids[src]) >= 2):
            continue
        n_ev, evid = _evidencias_inf(src)
        # nivel de confianza: la evidencia INDEPENDIENTE manda, no el volumen.
        #  - alta: >=2 tipos de evidencia independientes -> investigar / cuarentena
        #  - sospechoso: solo repeticion o una sola pista -> vigilar (no auto-cuarentena)
        confianza = "alta" if n_ev >= 2 else "sospechoso"
        sc, band, _c, _d = riesgo(src)
        cand.append({
            "ip": ip_de(src), "router": rid_de(src), "ultima": _ultima(src),
            "puertos_top": dict(dport_cnt_by_src.get(src, Counter()).most_common(8)),
            "cats_top": dict(cat_cnt_by_src.get(src, Counter()).most_common(6)),
            "riesgo": sc,
            "banda": band,
            "confianza": confianza,
            "n_evidencias": n_ev,
            "evidencias": evid,
            "alertas_cnc": inf_hits[src],
            "firmas_cnc": len(inf_sids[src]),
            "firma": inf_sig.get(src, ""),
            "destinos": len(dst_by_src.get(src, ())),
            "destinos_ip": sorted(dst_by_src.get(src, set()))[:12],   # para atribuir falsos positivos
            "puertos": len(dpt_by_src.get(src, ())),
            "total_alertas": by_src.get(src, 0),
            "pruebas": pruebas_by_src.get(src, []),
            "reputacion": _reputacion_src(src),
        })
    # ordenar: primero los confirmados (2+ pruebas independientes), luego por riesgo
    cand.sort(key=lambda c: (c["confianza"] == "alta", c["riesgo"], c["alertas_cnc"]), reverse=True)
    # DNS sospechoso: CPEs que consultaron dominios de botnet/C2 (Camino A: alertas DNS)
    def _evidencias_dns(src):
        ev = []
        nd = len(dns_sids.get(src, ()))
        if nd >= 2:
            ev.append(f"{nd} firmas DNS distintas")
        _dm = [d for d in dst_by_src.get(src, ()) if es_malo_firme(d)]
        if _dm:
            ev.append(f"destino en lista de reputacion ({len(_dm)})")
        if src in correlacionados:
            ev.append("patron compartido con otros CPE (campana)")
        if inf_hits.get(src, 0) >= 1:
            ev.append("tambien alertas CnC")
        return len(ev), ev
    cand_dns = []
    for src in dns_hits:
        if not es_mi_cpe(src):
            continue            # solo tus abonados consultan "tu" DNS; lo de fuera no se cuarentena
        if nunca_bloquear(ip_de(src)):
            continue                                    # allowlist: nunca a cuarentena
        if dns_hits[src] >= UMBRAL_DNS or len(dns_sids[src]) >= 2:
            n_ev, evid = _evidencias_dns(src)
            confianza = "alta" if n_ev >= 2 else "sospechoso"
            sc, band, _c, _d = riesgo(src)
            cand_dns.append({
                "ip": ip_de(src), "router": rid_de(src), "ultima": _ultima(src),
                "riesgo": sc,
                "banda": band,
                "confianza": confianza,
                "n_evidencias": n_ev,
                "evidencias": evid,
                "alertas_dns": dns_hits[src],
                "firmas_dns": len(dns_sids[src]),
                "firma": dns_sig.get(src, ""),
                "destinos": len(dst_by_src.get(src, ())),
                "destinos_ip": sorted(dst_by_src.get(src, set()))[:12],   # para atribuir falsos positivos
                "puertos": len(dpt_by_src.get(src, ())),
                "total_alertas": by_src.get(src, 0),
                "pruebas": pruebas_by_src.get(src, []),
                "reputacion": _reputacion_src(src),
            })
    cand_dns.sort(key=lambda c: (c["confianza"] == "alta", c["alertas_dns"], c["riesgo"]), reverse=True)
    # top con su banda de riesgo, para el motor de politicas del panel (tope 50 CPEs)
    top_r = []
    for _s, _t in by_src.most_common(80):
        if not es_mi_cpe(_s):
            continue            # el ranking de riesgo es de TUS CPEs; lo de fuera no se cuarentena
        if nunca_bloquear(ip_de(_s)):
            continue                                    # allowlist: fuera del motor de politicas
        _sc, _bd, _c2, _d2 = riesgo(_s)
        # Se guarda tambien POR QUE puntua asi: las politicas envian a cuarentena desde
        # esta lista (no desde 'candidatos'), y sin estos datos el bloqueo quedaba sin
        # motivo que mostrar y el panel lo rotulaba como "manual / sin motivo".
        top_r.append({"ip": ip_de(_s), "router": rid_de(_s), "ultima": _ultima(_s),
                      # con que puertos y que tipo de trafico: es lo que permite cruzar
                      # la reputacion de la IP publica con el abonado que la ensucia
                      "puertos_top": dict(dport_cnt_by_src.get(_s, Counter()).most_common(8)),
                      "cats_top": dict(cat_cnt_by_src.get(_s, Counter()).most_common(6)),
                      "riesgo": _sc, "banda": _bd, "desglose": _d2, "alertas": _t,
                      "destinos": len(dst_by_src.get(_s, ())), "puertos": len(dpt_by_src.get(_s, ()))})
    _cq = {"generado": int(time.time()), "ventana_min": VENTANA_MIN,
           "umbral": UMBRAL_INFECTADO, "umbral_dns": UMBRAL_DNS,
           "candidatos": cand, "dns_candidatos": cand_dns, "top_riesgo": top_r}
    _tmpq = os.path.join(OUTDIR, "cuarentena.json.tmp")
    with open(_tmpq, "w", encoding="utf-8") as _f:
        json.dump(_cq, _f)
    os.replace(_tmpq, os.path.join(OUTDIR, "cuarentena.json"))
except Exception:
    pass

# el mismo modal que el panel: este informe es una pagina suelta y no hereda su barra
_ASK = ('<style>.askov{display:none;position:fixed;inset:0;background:rgba(11,11,11,.55);z-index:160;align-items:center;justify-content:center;padding:24px}.askov .askbox{background:#fff;color:#0b0b0b;border-radius:14px;max-width:460px;width:100%;padding:22px 24px;box-shadow:0 16px 54px rgba(0,0,0,.45)}.askov h3{margin:0 0 8px;font-size:19px}.askov p{margin:0 0 18px;color:#52514e;font-size:14px;line-height:1.5}.askov .askacts{display:flex;gap:10px;justify-content:flex-end}.askov .askno{background:#eef0f2;color:#33322f;border:1px solid #d7d6d2;padding:10px 16px;border-radius:9px;font:600 14px system-ui;cursor:pointer}.askov .askno:hover{background:#e2e5e8}.askov .askok{background:#2a78d6;color:#fff;border:0;padding:10px 18px;border-radius:9px;font:600 14px system-ui;cursor:pointer}.askov .askok:hover{background:#1c5cab}.askov .askok.danger{background:#c0392b}.askov .askok.danger:hover{background:#9c2f22}</style><div id=askov class=askov onmousedown="this._dn=event.target" onclick="if(event.target===this&&this._dn===this){askNo()}"><div class=askbox role=dialog aria-modal=true aria-labelledby=asktit><h3 id=asktit></h3><p id=asktxt></p><div class=askacts><button type=button class=askno id=askno onclick=askNo()>Cancelar</button><button type=button class=askok id=askok>Confirmar</button></div></div></div>'
        "<script>var _askE=null;function askNo(){var m=document.getElementById('askov');if(m)m.style.display='none';_askE=null;}function _askAbrir(t,x,ok,tono,solo){document.getElementById('asktit').textContent=t;document.getElementById('asktxt').textContent=x||'';var k=document.getElementById('askok'),n=document.getElementById('askno');k.textContent=ok||'Confirmar';k.className='askok'+(tono?' '+tono:'');n.style.display=solo?'none':'';document.getElementById('askov').style.display='flex';k.focus();}function ask(e,t,x,ok,tono){if(e.dataset.ok){e.dataset.ok='';return true;}_askE=e;_askAbrir(t,x,ok,tono,0);return false;}function aviso(t,x){_askE=null;_askAbrir(t,x,'Entendido','',1);}document.getElementById('askok').addEventListener('click',function(){var e=_askE;askNo();if(!e)return;if(e.tagName==='FORM'){e.submit();return;}e.dataset.ok='1';e.click();});document.addEventListener('keydown',function(ev){if(ev.key==='Escape')askNo();});</script>")

doc = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reporte de ataques - {esc(host)}</title>
<style>
:root{{color-scheme:light}}
*{{box-sizing:border-box}}
body{{margin:0;background:{SURF};color:{INK};font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
header{{padding:22px 28px;border-bottom:2px solid {INK};display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:12px}}
h1{{margin:0;font-size:20px}} h2{{margin:0 0 10px;font-size:15px}}
.sub{{color:{INK2};font-size:13px}}
main{{padding:20px 28px;max-width:1200px;margin:0 auto}}
.tiles{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}}
.tile{{border:1px solid {GRID};border-radius:10px;padding:14px 16px;background:#fff;position:relative;cursor:help}}
.tile:hover{{border-color:#c9d4e3;box-shadow:0 2px 10px rgba(0,0,0,.06)}}
.tile .q{{position:absolute;right:11px;top:11px;width:16px;height:16px;border-radius:50%;border:1px solid {GRID};
color:{INK2};font:700 11px system-ui;text-align:center;line-height:15px}}
.tile .tip{{visibility:hidden;opacity:0;position:absolute;left:0;top:100%;margin-top:8px;z-index:40;
width:max-content;max-width:290px;background:#0b0b0b;color:#fff;font:400 12px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;
padding:10px 12px;border-radius:9px;box-shadow:0 6px 18px rgba(0,0,0,.25);transition:opacity .12s;white-space:normal;text-align:left}}
.tile .tip b{{color:#8fc0ff}}
.tile .tip::before{{content:"";position:absolute;left:18px;top:-6px;border:6px solid transparent;border-bottom-color:#0b0b0b;border-top:0}}
.tile:hover .tip{{visibility:visible;opacity:1}}
@media print{{.tile .q,.tile .tip{{display:none}}}}
.chq{{position:relative;display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;
border-radius:50%;border:1px solid {GRID};color:{INK2};font:700 11px system-ui;margin-left:8px;cursor:help;vertical-align:middle}}
.chq .chtip{{visibility:hidden;opacity:0;position:absolute;left:0;top:135%;z-index:50;width:max-content;max-width:300px;
background:#0b0b0b;color:#fff;font:400 12px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;padding:9px 11px;border-radius:8px;
box-shadow:0 6px 18px rgba(0,0,0,.25);transition:opacity .12s;white-space:normal;text-align:left;font-weight:400}}
.chq .chtip::before{{content:"";position:absolute;left:5px;top:-6px;border:6px solid transparent;border-bottom-color:#0b0b0b;border-top:0}}
.chq:hover .chtip{{visibility:visible;opacity:1}}
h2{{position:relative}}
@media print{{.chq{{display:none}}}}
.tile .big{{font-size:30px;font-weight:700;line-height:1}}
.tile .lab{{font-size:12px;color:{INK2};margin-top:6px;display:flex;align-items:center;gap:6px}}
.dot{{width:11px;height:11px;border-radius:3px;display:inline-block}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
.card{{border:1px solid {GRID};border-radius:10px;padding:16px;background:#fff;margin-bottom:16px;display:flex;flex-direction:column;min-width:0}}
.card>*{{min-width:0;max-width:100%}}  /* los hijos flex encogen y no desbordan la tarjeta (tablas anchas scrollean en su .tablewrap) */
.card.wide{{grid-column:1/-1}}
.lbl{{font-size:12.5px;fill:#2b2a27;font-weight:600}} .lbl.lnodo{{fill:#6b6a66;font-weight:500}} .lbl.lpto{{font-variant-numeric:tabular-nums}} .lbl.lflecha{{fill:#9a9a95;font-weight:500}} .lbl.lextra{{fill:#9a9a95;font-weight:500;font-size:11.5px}} .val{{font-size:12px;fill:{INK};font-weight:600}}
.tick{{font-size:11px;fill:{INK2}}}
.tlwrap{{position:relative}}
.tl-bar{{transform-box:fill-box;transform-origin:bottom;animation:tlgrow .6s cubic-bezier(.2,.75,.3,1) both;transition:filter .12s}}
.tl-bar:hover{{filter:brightness(1.18)}}
@keyframes tlgrow{{from{{transform:scaleY(0)}}to{{transform:scaleY(1)}}}}
.tltip{{position:absolute;left:0;top:0;transform:translate(-50%,-145%);background:#0b0b0b;color:#fff;
font-size:12px;font-weight:600;padding:5px 9px;border-radius:6px;pointer-events:none;white-space:nowrap;
opacity:0;transition:opacity .1s;z-index:6;box-shadow:0 2px 8px rgba(0,0,0,.25)}}
@media(prefers-reduced-motion:reduce){{.tl-bar{{animation:none}}}}
.muted{{color:{INK2};font-size:12px;margin:8px 0 0}}
.leyenda{{margin:16px -16px -16px;margin-top:auto;padding:9px 16px;border-top:1px solid {GRID};background:#fafafa;border-radius:0 0 10px 10px}}
table{{width:100%;border-collapse:collapse;font-size:12.5px}}
th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid {GRID};vertical-align:top}}
th{{color:{INK2};font-weight:600;position:sticky;top:0;background:#fff}}
th.sortable{{cursor:pointer;user-select:none;white-space:nowrap}}
th.sortable:hover{{color:{BLUE}}}
th.sortable .ar{{opacity:.35;font-size:10px;margin-left:3px}}
th.sortable.asc .ar,th.sortable.desc .ar{{opacity:1;color:{BLUE}}}
td.num,td.mono{{white-space:nowrap}} .mono{{font-family:ui-monospace,Consolas,monospace}}
td.num{{text-align:right;font-variant-numeric:tabular-nums}}
.tablewrap{{overflow-x:auto}}
.detbar{{display:flex;align-items:center;gap:12px;margin:2px 0 12px;flex-wrap:wrap}}
.detsearch{{padding:8px 12px;border:1px solid {GRID};border-radius:8px;font:13px system-ui;width:300px;max-width:100%}}
.detsearch:focus{{outline:none;border-color:{BLUE};box-shadow:0 0 0 3px rgba(42,120,214,.15)}}
@media print{{.detbar{{display:none}}}}
.pager{{display:flex;align-items:center;gap:12px;margin-top:12px;flex-wrap:wrap}}
.pager button{{font:13px system-ui;padding:6px 12px;border:1px solid {GRID};background:#fff;border-radius:8px;cursor:pointer;color:{INK}}}
.pager button:hover:not(:disabled){{background:#eef4fd;border-color:{BLUE}}}
.pager button:disabled{{opacity:.4;cursor:default}}
.pager #pgi{{font-weight:600;font-size:13px}}
.pgnote{{margin-left:auto}}
#detalle td.nodo{{color:#6b6a66;white-space:nowrap}}
#detalle th,#detalle td{{text-align:center}}   /* todo centrado, tambien puertos y veces (el user, 2026-10-13) */
@media print{{.pager{{display:none!important}} #detalle tbody tr{{display:table-row!important}}}}
@media(max-width:820px){{.tiles{{grid-template-columns:repeat(2,1fr)}}.grid{{grid-template-columns:1fr}}}}
@media print{{.card,.tile{{break-inside:avoid}}header{{position:static}}}}
</style></head><body>
<header>
  <div><h1>Reporte de ataques - IDS {esc(host)}</h1>
  <div class="sub">{COB[0].upper() + COB[1:]} &middot; {total:,} alertas graves &middot; generado {gen}</div></div>
</header>
<main><!--COB:{COB}-->
  <div class="tiles">
    <div class="tile"><span class="q">?</span><div class="big">{total:,}</div><div class="lab">alertas graves</div>
      <span class="tip"><b>Total de alertas en {COB}</b>, ya sin el ruido informativo (ET INFO). Es la suma de todas las barras de la linea de tiempo de abajo.</span></div>
    <div class="tile"><span class="q">?</span><div class="big">{len(by_src):,}</div><div class="lab"><span class="dot" style="background:#e34948"></span>IPs origen (atacantes)</div>
      <span class="tip"><b>IPs de ORIGEN distintas</b> que dispararon al menos una alerta en {COB}. Ojo: muchas son equipos que solo hicieron una consulta DNS sospechosa, no ataque real. La grafica de abajo muestra solo el top.</span></div>
    <div class="tile"><span class="q">?</span><div class="big">{len(by_dst):,}</div><div class="lab"><span class="dot" style="background:#eb6834"></span>IPs destino (objetivos)</div>
      <span class="tip"><b>IPs de DESTINO distintas</b> hacia donde se dirigio el trafico alertado en {COB} (el objetivo). Suele ser tu propio DNS y unos pocos servidores.</span></div>
    <div class="tile"><span class="q">?</span><div class="big">{len(ips_vistas):,}{'+' if len(ips_vistas) >= MAX_IPS else ''}</div><div class="lab"><span class="dot" style="background:#2a78d6"></span>IPs unicas vistas (todo el trafico)</div>
      <span class="tip"><b>Todas las IPs distintas</b> que el MikroTik le envio al sensor en {COB}, no solo las que atacan: cuenta cualquier evento (TLS, HTTP, DNS, SNMP, alertas...), origen y destino, sin duplicar. Es el alcance real de lo que esta sensando.</span></div>
    <div class="tile"><span class="q">?</span><div class="big">{len(by_dport):,}</div><div class="lab"><span class="dot" style="background:#eda100"></span>puertos destino distintos</div>
      <span class="tip"><b>Puertos de destino distintos</b> que aparecieron en las alertas de {COB} (443, 80, 53, 22...). Quien ataca cada puerto esta en la grafica "Atacantes por puerto".</span></div>
  </div>
  {timeline(by_hour)}
  {mapa_ataques_section()}
  <div class="grid">
    {hbar("Atacantes por puerto", src_dport_top, "alertas", que="atacante", lblw=300, barw=300, tip="Pares IP origen -> puerto destino con mas alertas: QUIEN golpea QUE servicio (23 Telnet, 445 SMB, 22 SSH, 443 HTTPS...). Una misma IP sale en varias filas si ataca varios puertos. Solo el top; el total de puertos distintos esta en el recuadro de arriba.")}
    {hbar("IPs origen (atacantes)", top(by_src, fmt=lambda k: _cols_cpe(k, "")), "alertas", que="IP", lblw=230, barw=365, tip="IPs de ORIGEN que mas alertas dispararon (los equipos/CPE que generan el trafico). Ojo: muchas pueden ser solo consultas DNS sospechosas, no ataque real. Solo el top; el total esta arriba.")}
    {hbar("IPs destino (objetivos)", dst_top, "alertas", que="IP", lblw=300, barw=300, tip="IPs de DESTINO mas frecuentes: hacia donde va el trafico alertado (el objetivo) y por que puerto (el mas usado; +N = otros puertos). Los resolutores DNS conocidos NO cuentan aqui: una consulta maliciosa es culpa del CPE, no un ataque al DNS; van aparte, mas abajo, como resolutores usados (Ajustes -> DNS).")}
    {hbar("Firmas mas frecuentes (tipo de ataque)", firmas_top, "alertas", que="firma", lblw=165, barw=430, izq=True, tip="Tipos de ataque (firmas de Suricata) mas frecuentes, agrupados y traducidos al espanol. Indica que clase de amenaza predomina.")}
  </div>
  {top_sec}
  <section class="card">
    <h2>Detalle: quien ataca, a donde, por que puerto, cuando y por cuanto tiempo</h2>
    <div class="detbar"><input id="detbuscar" class="detsearch" placeholder="Filtrar por IP, puerto, protocolo, firma..."><span id="detcount" class="muted"></span></div>
    <div class="tablewrap"><table id="detalle">
      <thead><tr>{_cabecera_detalle()}</tr></thead>
      <tbody>{"".join(filas) if filas else '<tr><td colspan="%d" class="muted">Sin ataques en la ventana.</td></tr>' % len(_COLS_DETALLE)}</tbody>
    </table></div>
    <div class="pager" id="pager">
      <button id="prev" type="button">&larr; Anterior</button>
      <span id="pgi">Pagina 1</span>
      <button id="next" type="button">Siguiente &rarr;</button>
      <span class="pgnote muted">{len(filas)} flujos, 20 por pagina &middot; al imprimir salen todos</span>
    </div>
    <script>
    (function(){{
      var tbody=document.querySelector('#detalle tbody');
      var all=[].slice.call(tbody.querySelectorAll('tr'));
      var rows=all.slice();
      var per=20, p=1;
      var pager=document.getElementById('pager');
      var buscar=document.getElementById('detbuscar');
      var cnt=document.getElementById('detcount');
      function npag(){{return Math.max(1,Math.ceil(rows.length/per));}}
      function draw(){{
        for(var i=0;i<all.length;i++) all[i].style.display='none';
        var small=rows.length<=per;
        if(pager) pager.style.display=(small||rows.length===0)?'none':'';
        for(var i=0;i<rows.length;i++) rows[i].style.display=(small||(i>=(p-1)*per&&i<p*per))?'':'none';
        if(pager && !small){{
          document.getElementById('pgi').textContent='Pagina '+p+' de '+npag();
          document.getElementById('prev').disabled=(p<=1);
          document.getElementById('next').disabled=(p>=npag());
        }}
        if(cnt) cnt.textContent=(rows.length===all.length? '' : rows.length+' de '+all.length+' filas');
      }}
      function go(x){{p=Math.min(npag(),Math.max(1,x)); draw();}}
      function filtrar(){{
        var q=((buscar&&buscar.value)||'').toLowerCase().trim();
        try{{sessionStorage.setItem('detq',q);}}catch(e){{}}
        rows = q ? all.filter(function(tr){{return tr.textContent.toLowerCase().indexOf(q)>=0;}}) : all.slice();
        p=1; draw();
      }}
      // ordenar al pulsar un encabezado: 1er clic ascendente, 2do descendente (sobre lo filtrado)
      var ths=[].slice.call(document.querySelectorAll('#detalle thead th.sortable'));
      function val(tr,i){{
        var td=tr.children[i]; if(!td) return '';
        var s=td.getAttribute('data-s'); if(s===null) s=td.textContent;
        if(s!=='' && /^-?\\d/.test(s) && !isNaN(parseFloat(s))) return parseFloat(s);
        return String(s).toLowerCase();
      }}
      ths.forEach(function(th){{
        th.onclick=function(){{
          var col=+th.getAttribute('data-col');
          var asc=!th.classList.contains('asc');
          ths.forEach(function(o){{o.classList.remove('asc','desc'); var a=o.querySelector('.ar'); if(a) a.innerHTML='&#8597;';}});
          th.classList.add(asc?'asc':'desc');
          var ar=th.querySelector('.ar'); if(ar) ar.innerHTML=asc?'&#8593;':'&#8595;';
          rows.sort(function(a,b){{var x=val(a,col),y=val(b,col); if(x<y)return asc?-1:1; if(x>y)return asc?1:-1; return 0;}});
          rows.forEach(function(r){{tbody.appendChild(r);}});
          p=1; draw();
        }};
      }});
      if(pager){{
        document.getElementById('prev').onclick=function(){{go(p-1);}};
        document.getElementById('next').onclick=function(){{go(p+1);}};
      }}
      if(buscar){{
        buscar.oninput=filtrar;
        try{{var sq=sessionStorage.getItem('detq'); if(sq) buscar.value=sq;}}catch(e){{}}
      }}
      filtrar();
    }})();
    </script>
    <p class="muted">Top {len(filas)} flujos por numero de alertas. Se excluye ruido informativo (ET INFO).</p>
  </section>
{_ASK}</main></body></html>"""

out = os.path.join(OUTDIR, "report-" + datetime.now(TZ_EC).strftime("%Y%m%d-%H%M") + ".html")
# Escritura atomica (.tmp + replace), como el resto del script. Si no, el archivo existe
# con mtime nuevo desde el primer byte: el panel lo elige por mtime, no encuentra el
# <main> y sirve "En vivo" en blanco mientras se escribe; y si el generador muere a
# media escritura, ese HTML truncado queda como el mas reciente hasta el ciclo siguiente.
_tmp_out = out + ".tmp"
with open(_tmp_out, "w", encoding="utf-8") as _fo:
    _fo.write(doc)
os.replace(_tmp_out, out)

# Solo se conserva el reporte MAS NUEVO del nodo: la lista de instantaneas por hora del
# Historico se quito (no se usaba) y el resto del panel solo mira el ultimo. Los contadores
# diarios (metricas.json) no dependen de los HTML.
try:
    hs = glob.glob(os.path.join(OUTDIR, "report-*.html"))
    nuevo = max(hs, key=os.path.getmtime) if hs else None
    for f in hs:
        if f != nuevo:
            try: os.remove(f)
            except OSError: pass
except OSError:
    pass

# --- Metricas por dia: se SUMAN a lo ya guardado (el bucle solo conto lo nuevo) --------
# Esto es lo que permite responder "bajo el abuso?" con un numero, meses despues, cuando
# los reportes HTML de entonces ya no existen.
def fusionar_metricas(prev, nuevos, ts_max, hueco, ahora=None):
    """Suma lo contado en esta corrida a lo que ya habia. Devuelve el dict a guardar.

    Se SUMA en vez de sobrescribir porque el bucle solo conto lo posterior a la ultima
    corrida; recontar la ventana daria mal el total del dia en cuanto la ventana sea mas
    corta que 24 h."""
    ahora = time.time() if ahora is None else ahora
    dias = prev.get("dias")
    if not isinstance(dias, dict):
        dias = {}
    for d, v in (nuevos or {}).items():
        e = dias.get(d)
        if not isinstance(e, dict):
            e = {"sal": 0, "ent": 0, "ruido": 0, "cpes_n": 0, "cpes": [],
                 "puertos": {}, "cats": {}, "nodos": {}}
        e["sal"] = int(e.get("sal", 0)) + int(v.get("sal", 0))
        e["ent"] = int(e.get("ent", 0)) + int(v.get("ent", 0))
        e["ruido"] = int(e.get("ruido", 0)) + int(v.get("ruido", 0))
        # CPEs distintos del dia: se guarda el conjunto mientras el dia es reciente y
        # despues solo el numero (400 dias de listas no tendrian sentido).
        conj = set(e.get("cpes") or []) | set(v.get("cpes") or ())
        if len(conj) > METRICAS_MAX_CPES:
            conj = set(sorted(conj)[:METRICAS_MAX_CPES])
        e["cpes"] = sorted(conj)
        e["cpes_n"] = len(conj)
        for campo in ("puertos", "cats", "nodos"):
            acum = dict(e.get(campo) or {})
            for k, n in (v.get(campo) or {}).items():
                acum[k] = int(acum.get(k, 0)) + int(n)
            e[campo] = dict(sorted(acum.items(), key=lambda kv: kv[1], reverse=True)[:20])
        if hueco is True or (hueco and d in hueco):
            e["hueco"] = True
        dias[d] = e
    # un dia perdido ENTERO (el panel no conto nada de el) tiene que existir, y gris: si
    # no, no aparece en la serie y se lee como un dia tranquilo
    if hueco and hueco is not True:
        for d in hueco:
            if d not in dias:
                dias[d] = {"sal": 0, "ent": 0, "ruido": 0, "cpes_n": 0, "cpes": [],
                           "puertos": {}, "cats": {}, "nodos": {}, "hueco": True}
    corte_set = time.strftime("%Y-%m-%d", time.localtime(ahora - 3 * 86400))
    for k, v2 in dias.items():
        if k < corte_set and isinstance(v2, dict):
            v2.pop("cpes", None)
    lim = time.strftime("%Y-%m-%d", time.localtime(ahora - METRICAS_DIAS * 86400))
    dias = {k: v for k, v in dias.items() if k >= lim}
    return {"ultimo_ts": ts_max, "generado": int(ahora), "dias": dias}

try:
    # Si el generador estuvo parado mas que la ventana hay un agujero: se deja anotado en
    # vez de fingir que esos dias fueron tranquilos.
    # Solo los DIAS que toca el agujero [ultimo contado, primer evento leido]. Antes se
    # marcaba todo dia que tocara la corrida, para siempre: con ventana corta y un
    # reinicio de 35 min quedaban grises dias enteros.
    _hueco = set()
    if METR_DESDE and ts_min and ts_min > METR_DESDE + 60:
        _t = int(METR_DESDE)
        while _t <= int(ts_min):
            _hueco.add(time.strftime("%Y-%m-%d", time.localtime(_t)))
            _t += 3600
        _hueco.add(time.strftime("%Y-%m-%d", time.localtime(ts_min)))
    _nuevos = {d: {"sal": v["sal"], "ent": v["ent"], "ruido": v["ruido"], "cpes": v["cpes"],
                   "puertos": dict(v["puertos"]), "cats": dict(v["cats"]),
                   "nodos": dict(v["nodos"])}
               for d, v in dias_m.items()}
    _sal = fusionar_metricas(_mprev, _nuevos, ts_max or METR_DESDE, _hueco)
    _tmpm = METRICAS_FILE + ".tmp"
    with open(_tmpm, "w", encoding="utf-8") as _f:
        json.dump(_sal, _f)
    os.replace(_tmpm, METRICAS_FILE)
except OSError:
    pass

print(out)
