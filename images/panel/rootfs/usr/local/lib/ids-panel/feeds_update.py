#!/usr/bin/env python3
"""Baja feeds de reputacion (IPs y dominios) CON PROCEDENCIA y CADUCIDAD POR FUENTE.
Cada fuente se guarda por separado en src/<fuente>.lst (indicador por linea); si una
descarga falla o no es valida, se CONSERVA la ultima version valida de esa fuente y se
marca su estado (valido/vacio/error/sin-clave). reputation.lst/domains.lst se rearman
uniendo solo las fuentes NO caducadas, con la fuente en cada linea (indicador<TAB>fuente).
Auth-Key de abuse.ch (URLhaus/ThreatFox) opcional en conf/feeds.conf del panel.

En el contenedor del panel (CONTRATO-F2 §8): escribe en nodos.FEEDS y lee nodos.CONF/feeds.conf;
las claves van cifradas con la clave maestra (secretos.py). Solo baja las listas que usan la
pantalla y el generador: el dataset de dominios de Suricata lo genera el orquestador
(reglas.actualizar), asi que aqui no hay dataset, ni `suricata -T`, ni recarga."""
import ipaddress, json, os, sys, time, urllib.request, urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nodos  # noqa: E402
import secretos  # noqa: E402

DIR = nodos.FEEDS
SRCDIR = os.path.join(DIR, "src")
CONF = os.path.join(nodos.CONF, "feeds.conf")
os.makedirs(SRCDIR, mode=0o700, exist_ok=True)

def _conf(k, d=""):
    try:
        for l in open(CONF, encoding="utf-8"):
            l = l.strip()
            if l.startswith(k + "="):
                return l.split("=", 1)[1].strip()
    except OSError:
        pass
    return d

def _secreto(k):
    """Clave de una fuente: en feeds.conf va cifrada (enc1:...). Sin clave maestra o con el valor
    manipulado no se usa (la fuente queda sin-clave) y se dice por stderr, nunca el valor."""
    try:
        return secretos.descifrar(_conf(k, ""), "feeds:" + k)
    except secretos.SecretoNoDisponible as e:
        sys.stderr.write("%s: no se puede descifrar (%s): la fuente queda sin clave\n" % (k, e))
        return ""

AUTH_KEY = _secreto("ABUSE_CH_AUTH_KEY")
AIDB_KEY = _secreto("ABUSEIPDB_KEY")
# Cada fuente dice COMO se autentica, porque no todas lo hacen igual: abuse.ch manda la
# clave en la cabecera Auth-Key y AbuseIPDB en la cabecera Key. "" = fuente abierta.
CLAVES = {"abusech": AUTH_KEY, "aidb": AIDB_KEY}
CABECERA = {"abusech": "Auth-Key", "aidb": "Key"}

def _clave_de(auth):
    return CLAVES.get(auth, "")

# Cada clave va SOLO a su proveedor: feeds.conf puede cambiar la URL de cualquier fuente, y una
# URL que no sea https a ese dominio (o a un subdominio suyo) se baja sin la clave.
PROVEEDOR = {"abusech": ("abuse.ch",), "aidb": ("abuseipdb.com",)}

def _de_su_proveedor(url, auth):
    """La URL es https a un host del proveedor de esa clave? El host se corta como lo corta
    urllib (hasta / ? o #) y solo vale con letras, digitos, puntos y guiones, y como mucho :443:
    un usuario (@), un %, corchetes, otro puerto o cualquier otra cosa se quedan sin clave."""
    if url[:8].lower() != "https://":
        return False
    host = url[8:]
    for corte in "/?#":
        host = host.split(corte, 1)[0]
    host = host.lower()
    if host.endswith(":443"):
        host = host[:-4]
    if not host or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in host):
        return False
    return any(host == d or host.endswith("." + d) for d in PROVEEDOR.get(auth, ()))

class _RedirClave(urllib.request.HTTPRedirectHandler):
    """Al seguir una redireccion urllib copia las cabeceras, tambien la de la clave, a la URL que
    diga la respuesta (otro host, o http). La clave solo sigue si la URL nueva tambien es de su
    proveedor; si no, la peticion redirigida sale sin ella."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        nueva = super().redirect_request(req, fp, code, msg, headers, newurl)
        if nueva is not None:
            for auth, cab in CABECERA.items():
                if nueva.has_header(cab.capitalize()) and not _de_su_proveedor(newurl, auth):
                    nueva.remove_header(cab.capitalize())     # urllib guarda "Auth-key", "Key"
        return nueva

urllib.request.install_opener(urllib.request.build_opener(_RedirClave))   # el de siempre + esto

# fuente: (nombre, url, ttl_horas[caducidad], tipo[ip|dom], categoria, auth, min_min[intervalo minimo de descarga])
# EDROP se ELIMINO como fuente aparte: se fusiono en Spamhaus DROP (abr-2024).
# Feodo: lista RECOMENDADA (servidores C2 activos/recientes), refresca cada 5 min upstream.
IPF = [
    ("feodo",         _conf("FEODO_URL", "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"), 6, "ip", "c2-activo", "", 10),
    ("cins",          _conf("CINS_URL", "https://cinsscore.com/list/ci-badguys.txt"), 48, "ip", "atacante-observado", "", 720),
    ("spamhaus-drop", _conf("SPAMHAUS_DROP_URL", "https://www.spamhaus.org/drop/drop.txt"), 192, "cidr", "infra-delictiva", "", 1440),
    # AbuseIPDB: IPs denunciadas por la comunidad. El plan gratuito da 5 descargas al dia
    # y devuelve las de confianza 100 (acotar el umbral es de pago), asi que se baja como
    # mucho cada 6 h: la lista queda fresca y sobra cuota. Una peticion trae hasta 10.000.
    ("abuseipdb",     _conf("ABUSEIPDB_URL", "https://api.abuseipdb.com/api/v2/blacklist?plaintext&limit=10000"), 24, "ip", "atacante-denunciado", "aidb", 360),
    # ET compromised: hosts comprometidos vistos atacando (Proofpoint, diario, lista plana).
    ("et-compromised", _conf("ET_COMPROMISED_URL", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"), 48, "ip", "atacante-observado", "", 720),
    # Salidas Tor: CONTEXTO, no prueba. Hablar con Tor no es estar infectado; hay quien lo
    # usa a proposito. La categoria 'anonimizador' hace que el reporte lo ensene pero no lo
    # sume al riesgo ni lo proponga para cortar.
    ("tor-exit",      _conf("TOR_EXIT_URL", "https://check.torproject.org/torbulkexitlist"), 24, "ip", "anonimizador", "", 360),
    # ThreatFox por IP y PUERTO: los C2 con el puerto por el que mandan. Va por la API
    # (POST con la misma Auth-Key); el export en archivo exige entrar al portal.
    ("threatfox-c2",  _conf("THREATFOX_API_URL", "https://threatfox-api.abuse.ch/api/v1/"), 24, "ipport", "c2-ioc", "abusech", 60,
     {"query": "get_iocs", "days": 7}),
]
# SSLBL (IPs de C2 por certificado TLS) no esta a proposito: el CSV lleva vacio desde
# 2025-01-03 (deprecado) y los JA3 de SSLBL no se actualizan desde 2021.
TFX_CONFIANZA_MIN = 50   # ThreatFox: confidence_level por debajo no entra (menos FP)
# Dominios por la API de abuse.ch (2026-10-28): las descargas en archivo (downloads/hostfile,
# export/...) responden 410 Gone, con clave o sin ella. URLhaus: las URLs recientes (1000), de las
# que siguen en linea se toma el dominio; ThreatFox: los IOC de 7 dias de tipo dominio, con la
# misma confianza minima que threatfox-c2. Las dos con la Auth-Key. Si feeds.conf apunta a una
# lista en texto (hostfile), se sigue leyendo como antes.
DOMF = [
    ("urlhaus",   _conf("URLHAUS_URL", "https://urlhaus-api.abuse.ch/v1/urls/recent/"), 24, "dom", "distribucion-malware", "abusech", 60),
    ("threatfox", _conf("THREATFOX_URL", "https://threatfox-api.abuse.ch/api/v1/"), 24, "dom", "c2-ioc", "abusech", 60,
     {"query": "get_iocs", "days": 7}),
]

def _fetch(url, auth="", post=None):
    hdrs = {"User-Agent": "suricata-feeds/2.0", "Accept": "text/plain, application/json"}
    clave = _clave_de(auth)
    if clave and not _de_su_proveedor(url, auth):       # ni en la cabecera ni en {AUTH}
        sys.stderr.write("una fuente con clave '%s' apunta fuera de su proveedor (o sin https): "
                         "se baja sin la clave\n" % auth)
        clave = ""
    if clave:
        hdrs[CABECERA.get(auth, "Auth-Key")] = clave    # abuse.ch: Auth-Key; AbuseIPDB: Key
    url = url.replace("{AUTH}", clave)                  # o clave en la URL, si la fuente la usa asi
    if not url.lower().startswith(("http://", "https://")):
        # urlopen tambien abre file://, ftp://...: una fuente solo se baja por HTTP(S).
        # El mensaje no lleva la URL: puede llevar la clave dentro ({AUTH})
        raise ValueError("la URL de la fuente no es http:// ni https://: no se descarga")
    datos = None
    if post is not None:                                # fuentes que son una API (ThreatFox)
        datos = json.dumps(post).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=datos, headers=hdrs)
    with urllib.request.urlopen(req, timeout=30) as r:
        ctype = (r.headers.get("Content-Type", "") or "").lower()
        body = r.read().decode("utf-8", "replace")
    return body, ctype

def _es_html(body):
    b = body.lstrip()[:400].lower()
    return b.startswith("<!doctype html") or b.startswith("<html") or "<head" in b or "<title" in b

def _parse_ip(body):
    out = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        tok = line.split(";")[0].split()[0].strip()
        try:
            if "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
                if net.version == 4:
                    out.add(str(net))
            else:
                ip = ipaddress.ip_address(tok)
                if ip.version == 4:
                    out.add(str(ip))
        except ValueError:
            continue
    return out

def _dom_valido(dom):
    """El dominio normalizado (minusculas, sin punto final) o "" si no es plausible."""
    dom = str(dom or "").strip().lower().rstrip(".")
    if not dom or "." not in dom or dom in ("localhost", "0.0.0.0", "127.0.0.1", "::1"):
        return ""
    # dominio plausible: labels validos, TLD alfabetico
    labs = dom.split(".")
    if len(labs) < 2 or not labs[-1].isalpha() or any(not l or len(l) > 63 for l in labs):
        return ""
    return dom

# Plataformas compartidas: el malware se aloja EN ellas (un repo, un archivo de Drive, un adjunto de
# Discord), pero el dominio es de todos. Por la API de URLhaus las URLs recientes son sobre todo de
# github.com y raw.githubusercontent.com (medido 2026-10-28: 715 de 1000): marcar el dominio seria
# marcar a cualquiera que use GitHub o Drive. Se quitan el dominio y sus subdominios. Los de
# inquilino propio (pub-xxx.r2.dev, x.trycloudflare.com, x.workers.dev) SI quedan: son del atacante.
COMPARTIDOS = ("github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "google.com",
               "googleusercontent.com", "googleapis.com", "discordapp.com", "discord.com", "dropbox.com",
               "dropboxusercontent.com", "microsoft.com", "live.com", "sharepoint.com", "onedrive.com",
               "1drv.ms", "mediafire.com", "telegram.org", "t.me", "apple.com", "icloud.com",
               "amazon.com", "facebook.com", "whatsapp.net", "cloudflare.com")

def _compartido(dom):
    return any(dom == c or dom.endswith("." + c) for c in COMPARTIDOS)

def _parse_dom(body):
    out = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line[0] == "#":
            continue
        parts = line.split()
        dom = _dom_valido(parts[-1] if len(parts) >= 2 else parts[0])
        if dom:
            out.add(dom)
    return out

def _json_o_none(body):
    try:
        d = json.loads(body)
    except ValueError:
        return None
    return d if isinstance(d, dict) else None

def _parse_urlhaus(body):
    """API de URLhaus (urls/recent): el dominio de cada URL que sigue en linea (las de IP ya
    entran por las fuentes de IPs). Un texto que no es JSON se lee como hostfile."""
    d = _json_o_none(body)
    if d is None:
        return _parse_dom(body)
    out = set()
    for it in d.get("urls") or []:
        if not isinstance(it, dict) or it.get("url_status") != "online":
            continue
        host = str(it.get("host") or "")
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        dom = _dom_valido(host)
        if dom and not _compartido(dom):
            out.add(dom)
    return out

def _parse_tfx_dom(body):
    """API de ThreatFox (get_iocs): los IOC de tipo dominio con confianza suficiente. Un texto
    que no es JSON se lee como hostfile."""
    d = _json_o_none(body)
    if d is None:
        return _parse_dom(body)
    out = set()
    data = d.get("data") or []
    if not isinstance(data, list):
        return out
    for it in data:
        if not isinstance(it, dict) or it.get("ioc_type") != "domain":
            continue
        try:
            if int(it.get("confidence_level") or 0) < TFX_CONFIANZA_MIN:
                continue
        except (TypeError, ValueError):
            continue
        dom = _dom_valido(it.get("ioc"))
        if dom and not _compartido(dom):
            out.add(dom)
    return out

def _parse_ipport(body):
    """Respuesta JSON de la API de ThreatFox: se quedan los IOC de tipo ip:port con
    confianza suficiente, como 'ip:puerto' (IPv4). Un dominio, una URL o una IP rara se
    ignoran: ya hay otras fuentes para eso."""
    out = set()
    try:
        data = json.loads(body).get("data") or []
    except (ValueError, AttributeError):
        return out
    if not isinstance(data, list):
        return out
    for it in data:
        if not isinstance(it, dict) or it.get("ioc_type") != "ip:port":
            continue
        try:
            if int(it.get("confidence_level") or 0) < TFX_CONFIANZA_MIN:
                continue
        except (TypeError, ValueError):
            continue
        ioc = str(it.get("ioc") or "").strip()
        ip, _, port = ioc.rpartition(":")
        if not ip or not port.isdigit() or not (0 < int(port) < 65536):
            continue
        try:
            if ipaddress.ip_address(ip).version != 4:
                continue
        except ValueError:
            continue
        out.add(f"{ip}:{int(port)}")
    return out

PARSERS = {"dom": _parse_dom, "ipport": _parse_ipport}
PARSERS_FUENTE = {"urlhaus": _parse_urlhaus, "threatfox": _parse_tfx_dom}   # las que son una API

def _cargar_meta():
    try:
        return json.load(open(os.path.join(DIR, "reputation.meta"), encoding="utf-8"))
    except Exception:
        return {}

meta_prev = _cargar_meta()
src_prev = meta_prev.get("sources", {})
sources = {}
now = int(time.time())

def procesar(name, url, ttl_h, tipo, cat, auth, min_min, post=None):
    prev = src_prev.get(name, {})
    estado = "error"; n = prev.get("count", 0); fv = prev.get("fetched_valid", 0)
    parse = PARSERS_FUENTE.get(name) or PARSERS.get(tipo, _parse_ip)
    if fv and prev.get("estado") == "valido" and (now - fv) < min_min * 60 \
            and os.path.exists(os.path.join(SRCDIR, name + ".lst")):
        estado = "valido"                   # descargado hace poco: no re-bajar (respeta el upstream)
    elif auth and not _clave_de(auth):
        estado = "sin-clave"                # necesita clave y no hay -> se conserva lo viejo
    else:
        try:
            body, ctype = _fetch(url, auth, post)
            if "text/html" in ctype or _es_html(body):
                estado = "error"            # respuesta HTML (login/portal/error), NO una lista
            else:
                items = parse(body)
                if not items:
                    estado = "vacio"        # descarga OK pero sin entradas validas
                else:
                    tmp = os.path.join(SRCDIR, name + ".lst.tmp")
                    open(tmp, "w", encoding="utf-8").write("\n".join(sorted(items)) + "\n")
                    os.replace(tmp, os.path.join(SRCDIR, name + ".lst"))
                    estado, n, fv = "valido", len(items), now
        except urllib.error.HTTPError as e:
            if e.code in (401, 403) and auth:
                estado = "sin-clave"
            elif e.code == 429 and fv:
                estado = prev.get("estado", "valido")   # cuota diaria agotada: lo de ayer vale
            else:
                estado = "error"
            sys.stderr.write(f"{name}: HTTP {e.code}\n")
        except Exception as e:
            estado = "error"; sys.stderr.write(f"{name}: {e}\n")
    expira = (fv + ttl_h * 3600) if fv else 0
    caducado = fv and now > expira
    sources[name] = {"estado": estado, "count": n, "url": url, "tipo": tipo, "categoria": cat,
                     "ttl_horas": ttl_h, "fetched_valid": fv, "expira": expira,
                     "vigente": bool(fv and not caducado), "requiere_auth": bool(auth),
                     "auth": auth}

for f in IPF + DOMF:
    procesar(*f)

def _leer_src(name):
    try:
        return [l.strip() for l in open(os.path.join(SRCDIR, name + ".lst"), encoding="utf-8") if l.strip()]
    except OSError:
        return []

# rearmar reputation.lst / domains.lst uniendo SOLO fuentes vigentes (no caducadas),
# con la fuente en cada linea: "indicador<TAB>fuente".
rep_lines = []; dom_lines = []; port_lines = []; n_ip = 0; n_dom = 0
for name, s in sources.items():
    if not s["vigente"]:
        continue
    vistas = set()
    for ind in _leer_src(name):
        if s["tipo"] == "dom":
            dom_lines.append(f"{ind}\t{name}"); n_dom += 1
        elif s["tipo"] == "ipport":
            # la IP va a la lista general (casa con el cruce que ya existe); el puerto,
            # aparte: es lo que permite decir "hablo con el C2 POR SU PUERTO"
            ip, _, _p = ind.rpartition(":")
            port_lines.append(f"{ind}\t{name}")
            if ip and ip not in vistas:
                vistas.add(ip)
                rep_lines.append(f"{ip}\t{name}"); n_ip += 1
        else:
            rep_lines.append(f"{ind}\t{name}"); n_ip += 1
if port_lines:
    tmp = os.path.join(DIR, "c2ports.lst.tmp")
    open(tmp, "w", encoding="utf-8").write("\n".join(port_lines) + "\n")
    os.replace(tmp, os.path.join(DIR, "c2ports.lst"))
if rep_lines:
    tmp = os.path.join(DIR, "reputation.lst.tmp")
    open(tmp, "w", encoding="utf-8").write("\n".join(rep_lines) + "\n")
    os.replace(tmp, os.path.join(DIR, "reputation.lst"))
if dom_lines:
    tmp = os.path.join(DIR, "domains.lst.tmp")
    open(tmp, "w", encoding="utf-8").write("\n".join(dom_lines) + "\n")
    os.replace(tmp, os.path.join(DIR, "domains.lst"))

meta = {"generated": now, "total": n_ip, "total_dominios": n_dom, "sources": sources}
tmp = os.path.join(DIR, "reputation.meta.tmp")
open(tmp, "w", encoding="utf-8").write(json.dumps(meta, indent=2))
os.replace(tmp, os.path.join(DIR, "reputation.meta"))
vig = sum(1 for s in sources.values() if s["vigente"])
print(f"reputation.lst: {n_ip} IPs; domains.lst: {n_dom} dominios; {vig}/{len(sources)} fuentes vigentes")
for name, s in sources.items():
    print(f"  {name}: {s['estado']} ({s['count']}) vigente={s['vigente']}")
if not rep_lines and not dom_lines:
    sys.exit(1)
