#!/usr/bin/env python3
"""Informe diario de Suricata en lenguaje claro: quien esta infectado y que hacer."""
import glob, gzip, io, json, os, socket, time, urllib.request, urllib.parse, urllib.error
from collections import Counter, defaultdict

CONF = "/etc/suricata-report.conf"
LOGDIR = "/var/log/suricata"
HOURS = 24
cutoff = time.time() - HOURS * 3600
MAX_LINES = 20_000_000
try:
    import resource
    _cap = 1024 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (_cap, _cap))
except Exception:
    pass

def conf():
    d = {}
    try:
        for l in open(CONF, encoding="utf-8"):
            l = l.strip()
            if l and not l.startswith("#") and "=" in l:
                k, v = l.split("=", 1); d[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return d

def opener(p):
    return io.TextIOWrapper(gzip.open(p, "rb")) if p.endswith(".gz") else open(p, encoding="utf-8", errors="replace")

# Clasificacion: (claves, nivel, explicacion, accion). nivel 1=infectado, 2=atacando, 3=sospechoso.
# Gana la primera regla cuya palabra clave aparece en la firma.
REGLAS = [
    # Nivel 1 (rojo) = comunicacion real con el atacante = infeccion confirmada. Una
    # simple consulta DNS a un dominio de mala fama NO es nivel 1 (por eso "malware" a
    # secas cae en nivel 3): el destino suele ser tu propio DNS, no el atacante.
    (("cnc", "c2 ", "command and control", "checkin", "check-in", "botnet", "mirai", "katana",
      "trojan", "ransom", " rat ", "coinmin", "cryptomin", "compromised"),
     1, "equipo infectado hablando con su centro de mando", "aislar/cuarentena y avisar al cliente"),
    (("ssh scan", "brute", "password"),
     2, "atacando contrasenas (SSH/servicios) hacia afuera", "bloquear salida y revisar el equipo"),
    (("scan", "recon", "sweep", "escanea", "barrido", "portscan"),
     2, "escaneando puertos hacia internet (tipico de infeccion)", "revisar el equipo, muy probable infeccion"),
    (("exploit", "attack", "cve-", "shellcode", "attempted-admin"),
     2, "intentando explotar/atacar hacia afuera", "revisar el equipo"),
    (("malware", "dns query", "tld", "dyn_dns", "dynamic_dns", "duckdns", "dyndns", "no-ip",
      "suspicious", "likely hostile", "adware", "pup", "observed dns"),
     3, "consultas a dominios sospechosos (dyndns/.cc/.su/.top/reputacion malware)", "vigilar; comun en equipos comprometidos"),
]

def clasifica(sig):
    s = sig.lower()
    for claves, nivel, expl, accion in REGLAS:
        if any(k in s for k in claves):
            return nivel, expl, accion
    return 3, "actividad sospechosa", "vigilar"

# Exclusiones (apartado Exclusiones del panel + lineas IGNORAR_* legacy)
def cargar_exclusiones():
    reglas = []; ahora = time.time()
    try:
        data = json.load(open("/etc/suricata-exclusiones.json", encoding="utf-8"))
        if isinstance(data, list):
            for r in data:
                if not r.get("ip"):
                    continue
                try: hasta = float(r.get("hasta") or 0)
                except (TypeError, ValueError): hasta = 0
                if hasta and ahora > hasta:
                    continue                             # exclusion temporal vencida
                reglas.append((r.get("tipo", "dst"), r["ip"],
                               [int(p) for p in (r.get("puertos") or []) if str(p).isdigit()],
                               str(r.get("sid") or "")))
    except Exception:
        pass
    _c = conf()
    reglas += [("dst", x.strip(), [], "") for x in _c.get("IGNORAR_DESTINOS", "").split(",") if x.strip()]
    reglas += [("src", x.strip(), [], "") for x in _c.get("IGNORAR_ORIGENES", "").split(",") if x.strip()]
    return reglas
EXCL = cargar_exclusiones()
def excluido(src, dst, dport, sid=None):
    for tipo, ip, pts, rsid in EXCL:
        quien = dst if tipo == "dst" else src
        if quien != ip:
            continue
        if pts and not (dport is not None and dport in pts):
            continue
        if rsid and str(sid) != rsid:                    # regla ligada a una firma concreta
            continue
        return True
    return False

# Confianza para marcar INFECTADO (nivel 1): no basta el texto de UNA firma. Se exige
# REPETICION (>= UMBRAL_INFECTADO alertas de nivel 1) o >=2 firmas CnC distintas (SIDs).
# Una sola alerta de CnC aislada se degrada a nivel 2 "posible, sin confirmar".
try:
    UMBRAL_INFECTADO = max(1, int(conf().get("UMBRAL_INFECTADO", "3") or "3"))
except Exception:
    UMBRAL_INFECTADO = 3

by_src_nivel = {}
by_src_expl = {}
by_src_accion = {}
by_src_total = Counter()
n1_hits = Counter()            # alertas de nivel 1 (CnC/botnet) por IP -> repeticion
n1_sids = defaultdict(set)     # firmas CnC distintas por IP (SID o texto) -> contexto
pair = defaultdict(Counter)
total = 0
seen = 0

files = sorted(glob.glob(f"{LOGDIR}/eve.json*"), key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)
for p in files:
    try:
        if os.path.getmtime(p) < cutoff - 3600:
            continue
    except OSError:
        continue
    try:
        for line in opener(p):
            seen += 1
            if seen > MAX_LINES:
                break
            if '"event_type":"alert"' not in line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("event_type") != "alert":
                continue
            a = e.get("alert", {})
            sig = a.get("signature", "")
            cat = a.get("category") or ""
            if sig.startswith("ET INFO") or "Not Suspicious" in cat or "Misc activity" in cat:
                continue
            src = e.get("src_ip", "?"); dst = e.get("dest_ip", "?")
            if excluido(src, dst, e.get("dest_port"), a.get("signature_id")):   # exclusiones configuradas
                continue
            nivel, expl, accion = clasifica(sig)
            by_src_total[src] += 1
            pair[src][sig] += 1
            if nivel == 1:
                n1_hits[src] += 1
                n1_sids[src].add(a.get("signature_id") or sig)
            if src not in by_src_nivel or nivel < by_src_nivel[src]:
                by_src_nivel[src] = nivel; by_src_expl[src] = expl; by_src_accion[src] = accion
            total += 1
    except OSError:
        continue

host = socket.gethostname()
NOMBRE = {1: "INFECTADOS (actuar ya)", 2: "ATACANDO / ESCANEANDO (revisar)", 3: "SOSPECHOSOS (vigilar)"}

# Confirmacion de INFECTADO: solo se queda en nivel 1 si hubo repeticion (>= UMBRAL_INFECTADO
# alertas de nivel 1) o >=2 firmas CnC distintas. Una alerta de CnC aislada baja a nivel 2
# como "posible, sin confirmar" (evita marcar infectado por el texto de UNA sola firma).
for ip in list(by_src_nivel):
    if by_src_nivel[ip] == 1 and not (n1_hits[ip] >= UMBRAL_INFECTADO or len(n1_sids[ip]) >= 2):
        by_src_nivel[ip] = 2
        by_src_expl[ip] = (f"posible infeccion SIN confirmar: solo {n1_hits[ip]} alerta(s) de "
                           f"CnC aislada(s) (se piden {UMBRAL_INFECTADO} o 2 firmas distintas)")
        by_src_accion[ip] = "confirmar primero: ver si se repite o hay mas indicadores antes de aislar"

grupos = defaultdict(list)
for ip in by_src_total:
    grupos[by_src_nivel[ip]].append(ip)

L = []
L.append(f"IDS {host} - resumen de {HOURS}h")
n1 = len(grupos.get(1, [])); n2 = len(grupos.get(2, [])); n3 = len(grupos.get(3, []))
L.append(f"Infectados: {n1}   Atacando: {n2}   Sospechosos: {n3}   (alertas graves: {total})")
if not total:
    L.append("")
    L.append("Sin alertas graves. Revisa que este llegando trafico del espejo.")
for nivel in (1, 2, 3):
    ips = grupos.get(nivel, [])
    if not ips:
        continue
    ips.sort(key=lambda ip: by_src_total[ip], reverse=True)
    L.append("")
    L.append(f"== {NOMBRE[nivel]} ==")
    for ip in ips[:15]:
        veces = by_src_total[ip]
        L.append(f"  {ip:16s}  {by_src_expl[ip]}")
        L.append(f"  {'':16s}  -> {by_src_accion[ip]}  ({veces} alertas)")
    if len(ips) > 15:
        L.append(f"  ... y {len(ips)-15} equipos mas en este grupo")
report = "\n".join(L)

out = os.path.join(LOGDIR, "report-" + time.strftime("%Y%m%d") + ".txt")
try:
    open(out, "w", encoding="utf-8").write(report + "\n")
except OSError:
    pass
# conservar solo los 20 informes de texto mas recientes
try:
    import glob as _g
    ts = sorted(_g.glob(os.path.join(LOGDIR, "report-*.txt")), key=os.path.getmtime, reverse=True)
    for _v in ts[20:]:
        try:
            os.remove(_v)
        except OSError:
            pass
except OSError:
    pass

c = conf()
tok, chat = c.get("TELEGRAM_TOKEN"), c.get("TELEGRAM_CHAT_ID")
if tok and chat:
    try:
        data = urllib.parse.urlencode({"chat_id": chat, "text": report[:4000]}).encode()
        urllib.request.urlopen(f"https://api.telegram.org/bot{tok}/sendMessage", data=data, timeout=20)
    except Exception as ex:
        print("Telegram fallo:", ex)
print(report)
