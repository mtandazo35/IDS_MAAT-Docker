#!/usr/bin/env python3
"""Baja feeds de reputacion (IPs y dominios) CON PROCEDENCIA y CADUCIDAD POR FUENTE.
Cada fuente se guarda por separado en src/<fuente>.lst (indicador por linea); si una
descarga falla o no es valida, se CONSERVA la ultima version valida de esa fuente y se
marca su estado (valido/vacio/error/sin-clave). reputation.lst/domains.lst se rearman
uniendo solo las fuentes NO caducadas, con la fuente en cada linea (indicador<TAB>fuente).
Auth-Key de abuse.ch (URLhaus/ThreatFox) opcional en /etc/suricata-feeds.conf."""
import ipaddress, json, os, sys, time, urllib.request, urllib.error

DIR = "/var/lib/suricata-feeds"
SRCDIR = os.path.join(DIR, "src")
CONF = "/etc/suricata-feeds.conf"
os.makedirs(SRCDIR, exist_ok=True)

def _conf(k, d=""):
    try:
        for l in open(CONF, encoding="utf-8"):
            l = l.strip()
            if l.startswith(k + "="):
                return l.split("=", 1)[1].strip()
    except OSError:
        pass
    return d

AUTH_KEY = _conf("ABUSE_CH_AUTH_KEY", "")
AIDB_KEY = _conf("ABUSEIPDB_KEY", "")
# Cada fuente dice COMO se autentica, porque no todas lo hacen igual: abuse.ch manda la
# clave en la cabecera Auth-Key y AbuseIPDB en la cabecera Key. "" = fuente abierta.
CLAVES = {"abusech": AUTH_KEY, "aidb": AIDB_KEY}
CABECERA = {"abusech": "Auth-Key", "aidb": "Key"}

def _clave_de(auth):
    return CLAVES.get(auth, "")

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
DOMF = [
    ("urlhaus",   _conf("URLHAUS_URL", "https://urlhaus.abuse.ch/downloads/hostfile/"), 24, "dom", "distribucion-malware", "abusech", 60),
    ("threatfox", _conf("THREATFOX_URL", "https://threatfox.abuse.ch/downloads/hostfile/"), 24, "dom", "c2-ioc", "abusech", 60),
]

def _fetch(url, auth="", post=None):
    hdrs = {"User-Agent": "suricata-feeds/2.0", "Accept": "text/plain, application/json"}
    clave = _clave_de(auth)
    if clave:
        hdrs[CABECERA.get(auth, "Auth-Key")] = clave    # abuse.ch: Auth-Key; AbuseIPDB: Key
    url = url.replace("{AUTH}", clave)                  # o clave en la URL, si la fuente la usa asi
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

def _parse_dom(body):
    out = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line[0] == "#":
            continue
        parts = line.split()
        dom = (parts[-1] if len(parts) >= 2 else parts[0]).strip().lower().rstrip(".")
        if not dom or "." not in dom or dom in ("localhost", "0.0.0.0", "127.0.0.1", "::1"):
            continue
        # dominio plausible: labels validos, TLD alfabetico
        labs = dom.split(".")
        if len(labs) < 2 or not labs[-1].isalpha() or any(not l or len(l) > 63 for l in labs):
            continue
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
    parse = PARSERS.get(tipo, _parse_ip)
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

# El mismo listado como DATASET de Suricata, para que la consulta a un dominio fichado sea
# una alerta en el momento y no un cruce posterior. Un dataset de tipo string va en
# BASE64 por linea: en claro no casa nunca y no da error. Solo dominios bien formados; un
# dato raro de un feed no puede romper la carga de reglas.
import base64, subprocess
ds_lines = []
for l in dom_lines:
    d = l.split("\t", 1)[0].strip().lower().rstrip(".")
    if d and len(d) <= 253 and all(p and len(p) <= 63 for p in d.split(".")) and " " not in d:
        ds_lines.append(base64.b64encode(d.encode("utf-8")).decode("ascii"))
ds_path = os.path.join(DIR, "domains.dataset")
try:
    viejo = open(ds_path, encoding="utf-8").read()
except OSError:
    viejo = ""
nuevo = "\n".join(sorted(set(ds_lines))) + ("\n" if ds_lines else "")
# sin dominios (p.ej. sin clave de abuse.ch) el archivo tiene que EXISTIR igual, vacio:
# la regla que lo carga tumba todas las demas si no esta
if nuevo != viejo or not os.path.exists(ds_path):
    tmp = ds_path + ".tmp"
    open(tmp, "w", encoding="utf-8").write(nuevo)
    os.replace(tmp, ds_path)
    # recargar solo si valida: un dataset que no carga deja el sensor sin reglas
    try:
        t = subprocess.run(["suricata", "-T", "-c", "/etc/suricata/suricata.yaml"],
                           capture_output=True, text=True, timeout=120)
        if t.returncode == 0:
            for cmd in (["suricatasc", "-c", "reload-rules"], ["systemctl", "reload", "suricata"]):
                try:
                    if subprocess.run(cmd, capture_output=True, timeout=60).returncode == 0:
                        break
                except (OSError, subprocess.TimeoutExpired):
                    continue
        else:
            print("dataset: suricata -T fallo, no se recarga: " + (t.stderr or "")[-200:])
    except (OSError, subprocess.TimeoutExpired) as e:
        print("dataset: no se pudo validar/recargar: %s" % e)

meta = {"generated": now, "total": n_ip, "total_dominios": n_dom, "sources": sources}
open(os.path.join(DIR, "reputation.meta"), "w", encoding="utf-8").write(json.dumps(meta, indent=2))
vig = sum(1 for s in sources.values() if s["vigente"])
print(f"reputation.lst: {n_ip} IPs; domains.lst: {n_dom} dominios; {vig}/{len(sources)} fuentes vigentes")
for name, s in sources.items():
    print(f"  {name}: {s['estado']} ({s['count']}) vigente={s['vigente']}")
if not rep_lines and not dom_lines:
    sys.exit(1)
