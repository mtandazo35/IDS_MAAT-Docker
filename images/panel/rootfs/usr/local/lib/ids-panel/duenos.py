"""Dueño de una IP pública (DNS inverso -> marca conocida; sin PTR, operador por RDAP).

Solo se consulta la red BAJO DEMANDA: cuando alguien abre Top orígenes y el navegador pide las IPs
que aún no tienen dueño (GET /duenos del panel). El generador de reportes solo LEE la caché: antes
consultaba en cada regeneración, en serie y sin tope real (setdefaulttimeout no vale para
gethostbyaddr), y un cambio de ventana en En vivo —que ni muestra este dato— esperaba minutos
(el user, 2026-10-13: «no debe hacerlo seguido, solo cuando se necesite»).

El panel es el único que escribe la caché (nodos.CACHE/ipinfo-cache.json).
"""

import ipaddress
import json
import os
import socket
import threading
import time
import re
import urllib.error
import urllib.parse
import urllib.request

import nodos

CACHE = os.path.join(nodos.CACHE, "ipinfo-cache.json")
TTL = 7 * 24 * 3600          # 7 dias: pasado eso se vuelve a resolver
TTL_ERROR = 15 * 60          # si RDAP fallo: se reintenta pronto (no se guarda «sin PTR» 7 dias)
PTR_S = 1.5                  # un PTR inexistente tarda 5-16 s en fallar (medido); RDAP contesta en ~0,5 s
PTR_VENTAJA = 0.3            # s que el PTR va solo: si contesta antes (marcas grandes) no se pregunta a RDAP
MAX_POR_PETICION = 40        # IPs por llamada a /duenos (lo que cabe en el Top)
# IPs resolviendose a la vez. Casi todo es esperar al PTR, que no carga a nadie; lo que va a los
# registros lo limita RDAP_PARALELO. Con 8 eran tandas de ~2,5 s: 27 IP del Top = 8-11 s de «…».
PARALELO = MAX_POR_PETICION

# dominio PTR conocido -> nombre humano de la empresa (trafico casi siempre legitimo)
_ORG_DOM = {
    "fbcdn.net": "Facebook", "facebook.com": "Facebook", "tfbnw.net": "Facebook",
    "instagram.com": "Instagram", "whatsapp.net": "WhatsApp",
    "1e100.net": "Google", "google.com": "Google", "googlevideo.com": "Google/YouTube",
    "googleusercontent.com": "Google", "gvt1.com": "Google",
    "amazonaws.com": "Amazon AWS", "amazon.com": "Amazon", "cloudfront.net": "Amazon CloudFront",
    "cloudflare.com": "Cloudflare", "cloudflare-dns.com": "Cloudflare",
    "akamaitechnologies.com": "Akamai", "akamai.net": "Akamai", "akamaiedge.net": "Akamai",
    "microsoft.com": "Microsoft", "azure.com": "Microsoft Azure", "windows.net": "Microsoft",
    "apple.com": "Apple", "icloud.com": "Apple", "aaplimg.com": "Apple",
    "netflix.com": "Netflix", "nflxvideo.net": "Netflix", "nflxso.net": "Netflix",
    "tiktokcdn.com": "TikTok", "tiktokv.com": "TikTok", "ttlivecdn.com": "TikTok",
    "twitter.com": "Twitter/X", "twimg.com": "Twitter/X", "fastly.net": "Fastly",
    "edgecastcdn.net": "Edgecast", "level3.net": "Lumen/Level3",
}

def _reg_dom(host):
    """Dominio registrable aproximado (2 ultimas etiquetas; 3 si es tipo co.uk)."""
    p = host.lower().rstrip(".").split(".")
    if len(p) < 2:
        return host.lower()
    if len(p) >= 3 and p[-2] in ("co", "com", "net", "org", "gov", "edu") and len(p[-1]) == 2:
        return ".".join(p[-3:])
    return ".".join(p[-2:])

class ErrorRdap(Exception):
    """RDAP no contesto (limite de rdap.org, tiempo agotado, red): no es «no hay dueño»."""


RDAP_PARALELO = 3            # por registro: los registros limitan a quien manda rafagas
_LOCK_BOOT = threading.Lock()
RDAP_TIMEOUT_S = 4.0
_RDAP_SEMS = {}              # host del registro -> semaforo (ARIN y APNIC no comparten limite)
_LOCK_SEMS = threading.Lock()


def _sem_rdap(url):
    host = urllib.parse.urlsplit(url).hostname or ""
    with _LOCK_SEMS:
        return _RDAP_SEMS.setdefault(host, threading.BoundedSemaphore(RDAP_PARALELO))


# A que registro regional (ARIN, RIPE, APNIC, LACNIC, AFRINIC) preguntar por cada IP: tabla oficial
# de IANA, bajada una vez y renovada cada 7 dias. Antes todo iba a rdap.org, que es solo un
# redirector y corta con 429 a partir de ~10 consultas seguidas (18 de 32 fallaban); directo a los
# registros, 32 de 32 en 5,5 s (medido, 2026-10-13). Y un tercero menos ve que IPs se investigan.
BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv4.json"
BOOTSTRAP = os.path.join(nodos.CACHE, "rdap-bootstrap.json")
BOOTSTRAP_TTL = 7 * 86400
_BOOT = {"marca": None, "tabla": []}


def _tabla_rdap():
    """[(red, url base)] de la tabla de IANA (de disco; si falta o es vieja, se baja). [] si no
    hay manera: entonces se pregunta a rdap.org."""
    with _LOCK_BOOT:
        try:
            viejo = time.time() - os.path.getmtime(BOOTSTRAP) > BOOTSTRAP_TTL
        except OSError:
            viejo = True
        if viejo:
            try:
                with urllib.request.urlopen(BOOTSTRAP_URL, timeout=10) as r:
                    txt = r.read().decode("utf-8")
                json.loads(txt)
                os.makedirs(os.path.dirname(BOOTSTRAP), mode=0o700, exist_ok=True)
                tmp = BOOTSTRAP + ".%d.tmp" % os.getpid()
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write(txt)
                os.replace(tmp, BOOTSTRAP)
            except (OSError, ValueError):
                pass                                  # sigue valiendo la que haya en disco
        try:
            marca = os.path.getmtime(BOOTSTRAP)
        except OSError:
            return []
        if marca != _BOOT["marca"]:
            tabla = []
            try:
                with open(BOOTSTRAP, encoding="utf-8") as f:
                    for redes, urls in json.load(f).get("services") or []:
                        base = next((u for u in urls if u.startswith("https://")), None)
                        if base:
                            tabla += [(ipaddress.ip_network(r), base) for r in redes]
            except (OSError, ValueError, TypeError):
                tabla = []
            _BOOT.update(marca=marca, tabla=tabla)
        return _BOOT["tabla"]


def url_rdap(ip):
    """URL RDAP de la IP en su registro regional (o rdap.org si no hay tabla)."""
    a = ipaddress.ip_address(ip)
    cand = [(n.prefixlen, base) for n, base in _tabla_rdap() if a in n]
    base = max(cand)[1] if cand else "https://rdap.org/"
    return base.rstrip("/") + "/ip/" + ip


def _rdap_org(ip):
    """(operador, pais) del bloque de la IP por RDAP (su registro regional, sin clave); ('', '') si
    contesta sin nombre. Si no contesta lanza ErrorRdap, tras UN reintento a 1 s si fue limite
    (429) o tiempo agotado."""
    url = url_rdap(ip)
    req = urllib.request.Request(url, headers={"User-Agent": "ids-maat-report/1.0",
                                               "Accept": "application/rdap+json"})
    ultimo = None
    for intento in range(2):
        if intento:
            time.sleep(1.0)
        try:
            with _sem_rdap(url):
                with urllib.request.urlopen(req, timeout=RDAP_TIMEOUT_S) as r:
                    d = json.load(r)
            break
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ("", "")
            ultimo = e
            if e.code != 429 and e.code < 500:
                raise ErrorRdap(str(e))
        except (OSError, ValueError) as e:          # tiempo agotado, red, JSON roto
            ultimo = e
    else:
        raise ErrorRdap(str(ultimo))
    cc = (d.get("country") or "").strip()
    return (titular(d)[:44], cc)


def _vcard(ent, campo):
    vc = ent.get("vcardArray")
    for it in (vc[1] if isinstance(vc, list) and len(vc) > 1 else []):
        if isinstance(it, list) and len(it) > 3 and it[0] == campo and it[3]:
            return str(it[3]).strip()
    return ""


def titular(d):
    """Empresa titular del bloque segun la respuesta RDAP: la entidad «registrant» de tipo
    organizacion (puede venir anidada); si no hay, el nombre de la red («CHINANET-FJ»). Nunca un
    contacto: antes se tomaba la primera entidad y salian «Abuse-C Role», «IRT-CHINANET-CN» o el
    nombre del tecnico de turno (abuse/technical/administrative). '' si no hay nada mejor."""
    pila = list(d.get("entities") or [])
    while pila:
        e = pila.pop(0)
        if not isinstance(e, dict):
            continue
        if "registrant" in (e.get("roles") or []) and _vcard(e, "kind") == "org" and _vcard(e, "fn"):
            return _vcard(e, "fn")
        pila += e.get("entities") or []
    name = (d.get("name") or "").strip()
    # LACNIC pone el rango como nombre («200.107.0.0 - 200.107.31.255»): eso no es un dueño
    return "" if re.fullmatch(r"[0-9a-fA-F.:]+\s*-\s*[0-9a-fA-F.:]+", name) else name


def cargar():
    """La cache entera ({} si no hay o esta rota)."""
    try:
        with open(CACHE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


VERSION = 2                  # 2: RDAP da el titular, no el primer contacto (abuse/tecnico)


def vigente(ent, ahora=None):
    if not ent:
        return False
    if ent.get("via") == "rdap" and ent.get("v", 1) < VERSION:
        return False             # nombre sacado con la regla vieja: se vuelve a preguntar
    ttl = TTL_ERROR if ent.get("via") == "error" else TTL
    return (ahora or time.time()) - ent.get("ts", 0) < ttl


def consultable(ip):
    """Solo IPv4 publicas: ni privadas, ni de documentacion, ni basura."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and a.is_global


def resolver_red(ip):
    """(org, legitimo, via) preguntando a la red. Lenta: solo desde resolver().

    PTR y RDAP van a la vez: el PTR sale solo PTR_VENTAJA s (las marcas grandes contestan antes y
    no se molesta al registro) y luego RDAP corre mientras el PTR sigue hasta PTR_S. Gana el PTR si
    llega a tiempo. Antes era PTR_S de espera y DESPUES RDAP: ~2 s por IP, casi siempre perdidos
    esperando un PTR que no existe (medido: 8 de 8 IP del Top sin PTR, 4,6-15,6 s en fallar)."""
    caja = {}

    def ptr():
        try:
            caja["host"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

    def rdap():
        try:
            caja["rdap"] = _rdap_org(ip)
        except Exception:                       # ErrorRdap o lo que sea: no se sabe
            caja["rdap"] = None
    fin = time.monotonic() + PTR_S
    h = threading.Thread(target=ptr, daemon=True)
    h.start()
    h.join(min(PTR_VENTAJA, PTR_S))
    r = None
    if "host" not in caja:
        r = threading.Thread(target=rdap, daemon=True)
        r.start()
        h.join(max(0.0, fin - time.monotonic()))
    host = caja.get("host")
    if host:
        dom = _reg_dom(host)
        return (_ORG_DOM[dom], True, "ptr") if dom in _ORG_DOM else (dom, False, "ptr")
    r.join()                                    # _rdap_org tiene su tope (2 x RDAP_TIMEOUT_S + 1 s)
    if caja.get("rdap") is None:
        return ("?", False, "error")            # no se sabe: vale TTL_ERROR, no 7 dias
    aso, cc = caja["rdap"]
    if aso:
        return (aso + (f" · {cc}" if cc else ""), False, "rdap")
    return ("sin PTR", False, "")


_LOCK = threading.Lock()
_SEM = threading.BoundedSemaphore(PARALELO)
_VUELO = {}                  # ip -> Event: la misma IP pedida dos veces se consulta una


def _guardar(nuevas):
    """Mezcla `nuevas` con lo que haya en disco (leido dentro del cerrojo) y escribe atomico."""
    with _LOCK:
        d = cargar()
        d.update(nuevas)
        lim = time.time() - TTL
        d = {k: v for k, v in d.items() if v.get("ts", 0) >= lim and vigente(v)}
        try:
            os.makedirs(os.path.dirname(CACHE), mode=0o700, exist_ok=True)
            tmp = "%s.%d.%d.tmp" % (CACHE, os.getpid(), threading.get_ident())
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f)
            os.replace(tmp, CACHE)
        except OSError:
            pass


def _lanzar(ip):
    with _LOCK:
        ev = _VUELO.get(ip)
        if ev is not None:
            return ev
        ev = _VUELO[ip] = threading.Event()

    def trabajo():
        try:
            with _SEM:
                try:
                    org, legit, via = resolver_red(ip)
                except Exception:
                    org, legit, via = "?", False, "error"
            # se guarda aunque quien la pidio ya no espere: la proxima vez esta
            _guardar({ip: {"org": org, "legit": legit, "ts": time.time(), "via": via, "v": VERSION}})
        finally:
            with _LOCK:
                _VUELO.pop(ip, None)
            ev.set()
    threading.Thread(target=trabajo, daemon=True).start()
    return ev


def resolver(ips, espera=8.0):
    """{ip: entrada} de las IPs pedidas: las vigentes de la cache al momento y las demas
    consultadas en paralelo, esperando como mucho `espera` s. Las que no lleguen no salen
    (siguen en vuelo y quedan en la cache al terminar)."""
    ips = [ip for ip in dict.fromkeys(ips) if consultable(ip)][:MAX_POR_PETICION]
    cache = cargar()
    ahora = time.time()
    out = {ip: cache[ip] for ip in ips if vigente(cache.get(ip), ahora)}
    eventos = {ip: _lanzar(ip) for ip in ips if ip not in out}
    fin = time.monotonic() + espera
    for ev in eventos.values():
        resta = fin - time.monotonic()
        if resta <= 0:
            break
        ev.wait(resta)
    if eventos:
        cache = cargar()
        for ip in eventos:
            if vigente(cache.get(ip)):
                out[ip] = cache[ip]
    return out
