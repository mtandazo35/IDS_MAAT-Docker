"""Datos de laboratorio para el panel de IDS_MAAT-Docker corriendo en local.

Escribe lo que en produccion escriben el orquestador y Suricata:
  RUN/estado.json            puntos publicados por el orquestador
  RUN/<pid>/tzsp.json        contadores del espejo
  DATOS/<pid>/eve.json       eventos de Suricata (alert, dns, tls, http, flow, stats)
  PANEL/estado/abonados.json mapa pid|ip -> abonado (lo que daria la API del MikroTik)

  python generar_datos.py <dir-base> [--horas 26] [--vivo]

Lo normal es no llamarlo a mano: scripts/local/panel_local.py lo lanza con el panel.

Con --vivo, despues del historico sigue anadiendo eventos cada pocos segundos (En vivo).
IPs: abonados en 10.x (redes de cada punto); internet = direcciones al azar de rangos de varios
paises de la base GeoIP del panel (para el mapa) e IPs de su feed de reputacion. Nombres genericos.
"""

import argparse, json, os, random, time
from datetime import datetime, timedelta, timezone

TZ = timezone(timedelta(hours=-5))
R = random.Random(2026)

CAT = {
    "trojan": "A Network Trojan was detected",
    "cnc": "Malware Command and Control Activity Detected",
    "recon": "Attempted Information Leak",
    "attack": "Misc Attack",
    "policy": "Potential Corporate Privacy Violation",
    "mining": "Crypto Currency Mining Activity Detected",
    "bad": "Potentially Bad Traffic",
    "misc": "Misc activity",
    "admin": "Attempted Administrator Privilege Gain",
    "proto": "Generic Protocol Command Decode",
}
# clave: (sid, firma, categoria, severidad)
FIRMAS = {
    "mirai_cnc":  (2030490, "ET MALWARE Mirai Botnet CnC Checkin", "cnc", 1),
    "mirai_scan": (2023333, "ET SCAN Telnet Scan Outbound (Possible Mirai)", "recon", 2),
    "emotet":     (2025431, "ET MALWARE Win32/Emotet CnC Activity (POST)", "cnc", 1),
    "trojan":     (2030173, "ET TROJAN Win32/AgentTesla Exfil via SMTP", "trojan", 1),
    "miner":      (2024792, "ET POLICY Cryptocurrency Miner Checkin", "mining", 1),
    "ssh_out":    (2003068, "ET SCAN Potential SSH Scan OUTBOUND", "recon", 2),
    "rdp_brute":  (2001972, "ET SCAN RDP Brute Force Attempt Outbound", "recon", 2),
    "spam":       (2002087, "ET POLICY Outbound Spam Detected via SMTP", "policy", 2),
    "dns_top":    (2027758, "ET DNS Query for .top Domain - Likely Hostile", "bad", 2),
    "p2p":        (2008581, "ET P2P BitTorrent DHT ping request", "policy", 3),
    "stun":       (2016149, "ET INFO Session Traversal Utilities for NAT (STUN Binding Request)", "misc", 3),
    "info_tld":   (2031071, "ET INFO Observed DNS Query to .cloud TLD", "misc", 3),
    "stream":     (2210045, "SURICATA STREAM Packet with invalid ack", "proto", 3),
    "dshield":    (2402000, "ET DROP Dshield Block Listed Source group 1", "attack", 2),
    "cins":       (2403300, "ET CINS Active Threat Intelligence Poor Reputation IP group 1", "attack", 2),
    "ssh_in":     (2001219, "ET SCAN Potential SSH Scan", "recon", 2),
    "tr069":      (2024916, "ET EXPLOIT Possible TR-069 RCE Attempt (CVE-2016-10372)", "admin", 1),
    "tor":        (2520000, "ET TOR Known Tor Exit Node Traffic group 1", "attack", 2),
}

POOL = []          # IPs publicas de varios paises, sacadas de la base GeoIP del panel
FEED = {}          # fuente del feed de reputacion -> [ip]
PAISES = ["CN", "RU", "US", "BR", "NL", "DE", "IN", "VN", "KR", "IR", "ID", "FR", "GB", "UA",
          "CO", "EC", "PE", "AR", "MX", "TR"]

def cargar_internet(panel):
    """Sin GeoIP el mapa queda vacio: entonces internet = RFC 5737 (sin pais)."""
    import array, ipaddress, struct
    try:
        with open(os.path.join(panel, "geo", "ipv4.bin"), "rb") as f:
            n = struct.unpack("<I", f.read(4))[0]
            st = array.array("I"); st.fromfile(f, n)
            en = array.array("I"); en.fromfile(f, n)
            cc = f.read(n * 2)
        por = {}
        for i in range(n):
            c = cc[2 * i:2 * i + 2].decode("ascii", "replace")
            if c in PAISES and en[i] - st[i] >= 255:
                por.setdefault(c, []).append(i)
        for k, c in enumerate(PAISES):
            idx = por.get(c) or []
            for _ in range(min(len(idx), 90 - k * 3)):      # mas peso a los primeros paises
                i = R.choice(idx)
                ip = ipaddress.IPv4Address(R.randint(st[i] + 1, en[i] - 1))
                if ip.is_global and str(ip).split(".")[-1] not in ("0", "255"):
                    POOL.append(str(ip))
    except (OSError, ValueError):
        pass
    if not POOL:
        POOL.extend(b + str(10 + (k * 7) % 240) for k in range(300)
                    for b in [("192.0.2.", "198.51.100.", "203.0.113.")[k % 3]])
    try:
        for ln in open(os.path.join(panel, "feeds", "reputation.lst"), encoding="utf-8"):
            ip, _, fuente = ln.strip().partition("	")
            try:
                if not ipaddress.IPv4Address(ip).is_global:
                    continue
            except ValueError:                 # redes CIDR (spamhaus-drop) y basura
                continue
            if True:
                FEED.setdefault(fuente.split(",")[0] or "otro", []).append(ip)
    except OSError:
        pass
    malos = FEED.get("feodo") or []
    R.shuffle(malos)
    C2.update(mirai=(malos[0:1] or [POOL[1]])[0], emotet=(malos[1:2] or [POOL[2]])[0],
              miner=POOL[len(POOL) // 3], agent=(malos[2:3] or [POOL[3]])[0])
    print("internet: %d IPs publicas; feed: %s" % (len(POOL),
          ", ".join("%s=%d" % (k, len(v)) for k, v in sorted(FEED.items()))))

def ext(n):
    return POOL[n % len(POOL)]

def atacante():
    """Entrantes: la mitad de IPs del feed (salen en Reputacion), el resto del pool."""
    conocidos = [ip for k, v in FEED.items() if k != "feodo" for ip in v[:400]]
    if conocidos and R.random() < .5:
        return R.choice(conocidos[:200])
    return ext(R.choice([1, 2, 3, 4]) if R.random() < .4 else R.randint(0, 5000))

C2 = {}
RESOLVER = "10.255.0.53"

# ---------------------------------------------------------------------------------------------
# Puntos y escenarios. p003 repite las redes de p001 (aislamiento pid|ip).
# ---------------------------------------------------------------------------------------------
PUNTOS = {
    "p001": {"nombre": "Nodo Centro", "n": 1, "redes": ["10.10.0.0/16"], "pref": "10.10",
             "estado": "activo", "deseado": "activo", "ros": "7.16"},
    "p002": {"nombre": "Nodo Norte", "n": 2, "redes": ["10.20.0.0/16"], "pref": "10.20",
             "estado": "activo", "deseado": "activo", "ros": "6.49"},
    "p003": {"nombre": "Nodo Sur", "n": 3, "redes": ["10.10.0.0/16"], "pref": "10.10",
             "estado": "activo", "deseado": "activo", "ros": "7.12", "sin_espejo_h": 3},
    "p004": {"nombre": "Nodo Este", "n": 4, "redes": ["10.40.0.0/16"], "pref": "10.40",
             "estado": "pausado", "deseado": "pausado", "ros": "7.16", "sin_eventos": True},
}

# (ip relativa, escenario, eventos/hora). Escenarios: ver emitir_escenario().
# (ip relativa, escenario, eventos/hora, empieza hace N horas o None = todo el periodo,
#  termina hace N horas). Varios caen en su categoria a mitad de semana: el informe lo dice.
ESCENARIOS = {
    "p001": [("1.15", "mirai", 6, None, 0), ("1.22", "miner", 4, 110, 0), ("2.8", "ssh_out", 12, 72, 0),
             ("2.40", "p2p", 5, None, 0), ("3.5", "spam", 4, 30, 0), ("0.25", "limpio", 4, None, 0),
             ("1.30", "emotet", 3, 14, 0), ("1.31", "rdp_brute", 8, 50, 0), ("1.32", "dns_top", 3, 20, 0),
             ("1.33", "ssh_out", 9, 5, 0), ("2.50", "p2p", 3, 90, 0), ("3.10", "spam", 3, 140, 96),
             ("3.11", "miner", 3, 40, 0), ("3.12", "mirai", 5, 2, 0), ("0.30", "limpio", 3, None, 0)],
    "p002": [("4.10", "trojan_dns", 4, 120, 0), ("4.11", "rdp_brute", 9, None, 0), ("4.30", "p2p", 3, None, 0),
             ("5.2", "limpio", 4, None, 0), ("4.31", "mirai", 6, 8, 0), ("4.32", "miner", 3, 60, 0),
             ("4.33", "dns_top", 3, 36, 0), ("5.3", "ssh_out", 7, 15, 0), ("5.4", "emotet", 2, 100, 48),
             ("5.5", "spam", 3, 26, 0)],
    "p003": [("0.25", "mirai", 6, None, 3), ("1.22", "limpio", 4, None, 3), ("6.7", "ssh_out", 7, 80, 3),
             ("6.8", "spam", 3, 48, 3), ("6.9", "emotet", 2, 24, 3), ("6.10", "p2p", 3, None, 3)],
}
ENTRANTE = {"p001": 40, "p002": 25, "p003": 15}   # alertas entrantes por hora contra abonados

def abonados(pid):
    p = PUNTOS[pid]
    out = {}
    ips = ["%s.%s" % (p["pref"], e[0]) for e in ESCENARIOS.get(pid, [])]
    for i in range(30):
        ips.append("%s.%d.%d" % (p["pref"], 1 + i // 10, 100 + i))
    for k, ip in enumerate(ips):
        pppoe = k % 3 != 2
        mac = "02:00:%02X:%02X:%02X:%02X" % (p["n"], k // 256, k % 256, R.randint(0, 255))
        out["%s|%s" % (pid, ip)] = {
            "nombre": ("abonado-%s-%03d" % (pid, k + 1)) if pppoe else ("Cliente Demo %d" % (k + 1)),
            "tipo": "PPPoE" if pppoe else "DHCP", "mac": mac,
            "extra": ("uptime %dh%dm" % (R.randint(1, 300), R.randint(0, 59))) if pppoe else "bound",
            "router": pid, "router_nombre": p["nombre"]}
    return out

# ---------------------------------------------------------------------------------------------
# Eventos
# ---------------------------------------------------------------------------------------------
_flow = [10 ** 15]

def ts(t):
    return datetime.fromtimestamp(t, TZ).strftime("%Y-%m-%dT%H:%M:%S.%f%z")

def base(t, tipo, src, sp, dst, dp, proto="TCP", app=None):
    _flow[0] += R.randint(1, 9999)
    e = {"timestamp": ts(t), "flow_id": _flow[0], "in_iface": "tzsp0", "event_type": tipo,
         "src_ip": src, "src_port": sp, "dest_ip": dst, "dest_port": dp, "proto": proto}
    if app:
        e["app_proto"] = app
    return e

def alerta(t, clave, src, sp, dst, dp, proto="TCP", app=None):
    sid, sig, cat, sev = FIRMAS[clave]
    e = base(t, "alert", src, sp, dst, dp, proto, app)
    e["direction"] = "to_server"
    e["alert"] = {"action": "allowed", "gid": 1, "signature_id": sid, "rev": R.randint(1, 6),
                  "signature": sig, "category": CAT[cat], "severity": sev}
    e["flow"] = {"pkts_toserver": R.randint(1, 40), "pkts_toclient": R.randint(0, 30),
                 "bytes_toserver": R.randint(60, 9000), "bytes_toclient": R.randint(0, 20000),
                 "start": ts(t - R.uniform(0, 5)), "src_ip": src, "dest_ip": dst,
                 "src_port": sp, "dest_port": dp}
    return e

def dns(t, cli, nombre, rrtype="A"):
    e = base(t, "dns", cli, R.randint(1024, 65000), RESOLVER, 53, "UDP", "dns")
    e["dns"] = {"version": 2, "type": "query", "id": R.randint(1, 65535), "rrname": nombre,
                "rrtype": rrtype, "tx_id": 0, "opcode": 0}
    return e

def tls(t, cli, dst, sni):
    e = base(t, "tls", cli, R.randint(1024, 65000), dst, 443, "TCP", "tls")
    e["tls"] = {"sni": sni, "version": R.choice(["TLS 1.2", "TLS 1.3"])}
    return e

def http(t, cli, dst, host, url, ua, st=200):
    e = base(t, "http", cli, R.randint(1024, 65000), dst, 80, "TCP", "http")
    e["http"] = {"hostname": host, "url": url, "http_user_agent": ua, "http_method": "GET",
                 "protocol": "HTTP/1.1", "status": st, "length": R.randint(100, 50000)}
    return e

def flow(t, cli, dst, dp, proto="TCP"):
    e = base(t, "flow", cli, R.randint(1024, 65000), dst, dp, proto)
    e["flow"] = {"pkts_toserver": R.randint(2, 900), "pkts_toclient": R.randint(2, 1500),
                 "bytes_toserver": R.randint(200, 900000), "bytes_toclient": R.randint(200, 4000000),
                 "start": ts(t - 30), "end": ts(t), "age": 30, "state": "closed", "reason": "timeout"}
    return e

def stats(t, uptime, pkts, drops, memcap=0):
    return {"timestamp": ts(t), "event_type": "stats", "stats": {
        "uptime": uptime,
        "capture": {"kernel_packets": pkts, "kernel_drops": drops, "errors": 0},
        "decoder": {"pkts": pkts, "bytes": pkts * 640},
        "detect": {"engines": [{"id": 0, "last_reload": ts(t - uptime), "rules_loaded": 48211,
                                "rules_failed": 0, "rules_skipped": 312}], "alert": 0},
        "flow": {"memcap": 0, "memuse": 41000000},
        "tcp": {"ssn_memcap_drop": 0, "segment_memcap_drop": 0, "reassembly_memcap_drop": memcap},
        "defrag": {"max_frag_hits": 0}}}

def emitir_escenario(t, ip, esc):
    """Eventos de UN instante para un abonado segun su escenario."""
    sp = R.randint(1024, 65000)
    if esc == "mirai":
        if R.random() < .5:
            return [alerta(t, "mirai_cnc", ip, sp, C2["mirai"], 8080), dns(t, ip, "cnc-demo.top")]
        return [alerta(t, "mirai_scan", ip, sp, ext(R.randint(0, 900)), R.choice([23, 2323]))]
    if esc == "miner":
        return [alerta(t, "miner", ip, sp, C2["miner"], 3333), dns(t, ip, "pool-demo.example")]
    if esc == "ssh_out":
        return [alerta(t, "ssh_out", ip, sp, ext(R.randint(0, 900)), 22)]
    if esc == "rdp_brute":
        return [alerta(t, "rdp_brute", ip, sp, R.choice([ext(5), ext(6), ext(7)]), 3389)]
    if esc == "p2p":
        return [alerta(t, "p2p", ip, 6881, ext(R.randint(0, 900)), R.randint(1025, 65000), "UDP")]
    if esc == "spam":
        return [alerta(t, "spam", ip, sp, ext(R.randint(0, 60)), R.choice([25, 587]), app="smtp")]
    if esc == "emotet":
        if R.random() < .6:
            return [alerta(t, "emotet", ip, sp, C2["emotet"], 443, app="tls"), tls(t, ip, C2["emotet"], "upd-demo.top")]
        return [alerta(t, "dns_top", ip, sp, RESOLVER, 53, "UDP", "dns"), dns(t, ip, "upd-demo.top")]
    if esc == "dns_top":
        return [alerta(t, "dns_top", ip, sp, RESOLVER, 53, "UDP", "dns"), dns(t, ip, R.choice(["cdn-demo.top", "pago-demo.top", "login-demo.top"]))]
    if esc == "trojan_dns":
        if R.random() < .4:
            return [alerta(t, "trojan", ip, sp, C2["agent"], 587, app="smtp")]
        return [alerta(t, "dns_top", ip, sp, RESOLVER, 53, "UDP", "dns"), dns(t, ip, "update-demo.top")]
    # limpio: solo ruido que el panel debe filtrar o tratar como no-abuso
    return [alerta(t, R.choice(["stun", "info_tld", "stream"]), ip, sp, ext(R.randint(0, 50)),
                   R.choice([3478, 443, 53]), "UDP")]

ENTRANTES = ["dshield", "cins", "ssh_in", "tr069", "tor"]
PUERTO_ENT = {"dshield": 8728, "cins": 23, "ssh_in": 22, "tr069": 7547, "tor": 443}
SITIOS = ["www.example.com", "cdn.example.net", "api.example.org", "video.example.net",
          "correo.example.com", "banca.example", "juegos.example.net", "musica.example.org",
          "mapas.example", "tienda2.example", "redsocial.example.com", "noticias2.example",
          "noticias.example", "tienda.example"]

REF = [0.0]   # instante de referencia (arranque del script) para empieza/termina hace N horas

def cuantos(tasa_h, horas):
    """Cuantos eventos en la ventana: la parte entera y la fraccion por sorteo (vale para 5 s)."""
    n = tasa_h * horas * R.uniform(.7, 1.3)
    return int(n) + (1 if R.random() < n - int(n) else 0)

def eventos_ventana(pid, t0, t1, todos_abonados):
    """Todos los eventos de un punto entre t0 y t1, ya ordenados."""
    p = PUNTOS[pid]
    out = []
    horas = (t1 - t0) / 3600.0
    for rel, esc, ph, desde_h, hasta_h in ESCENARIOS.get(pid, []):
        ip = "%s.%s" % (p["pref"], rel)
        a = max(t0, REF[0] - desde_h * 3600) if desde_h else t0
        b = min(t1, REF[0] - hasta_h * 3600) if hasta_h else t1
        if b <= a:
            continue
        for _ in range(cuantos(ph, (b - a) / 3600.0)):
            out += emitir_escenario(R.uniform(a, b), ip, esc)
    cpes = [k.split("|", 1)[1] for k in todos_abonados if k.startswith(pid + "|")]
    # entrantes: unas pocas IPs muy activas y una cola larga
    for _ in range(cuantos(ENTRANTE.get(pid, 0), horas)):
        k = R.choice(ENTRANTES)
        src = atacante()
        out.append(alerta(R.uniform(t0, t1), k, src, R.randint(1024, 65000), R.choice(cpes), PUERTO_ENT[k]))
    # trafico normal: dns, tls, http, flow
    for _ in range(cuantos(150, horas)):
        t = R.uniform(t0, t1); cli = R.choice(cpes); sitio = R.choice(SITIOS); dst = ext(R.randint(0, 30))
        r = R.random()
        if r < .45:
            out.append(dns(t, cli, sitio))
        elif r < .75:
            out.append(tls(t, cli, dst, sitio))
        elif r < .85:
            out.append(http(t, cli, dst, sitio, R.choice(["/", "/inicio", "/api/v1/datos", "/img/logo.png", "/login"]),
                            R.choice(["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (Linux; Android 14)",
                                      "okhttp/4.9.3", "Go-http-client/1.1", "curl/8.5.0"]),
                            R.choice([200, 200, 200, 301, 304, 404])))
        else:
            out.append(flow(t, cli, dst, R.choice([443, 80, 53])))
    out.sort(key=lambda e: e["timestamp"])
    return out

def escribir(ruta, eventos, modo="a"):
    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    with open(ruta, modo, encoding="utf-8", newline="\n") as f:
        for e in eventos:
            f.write(json.dumps(e, separators=(",", ":"), ensure_ascii=False) + "\n")

# ---------------------------------------------------------------------------------------------
# estado.json (misma forma que construir_estado() del orquestador)
# ---------------------------------------------------------------------------------------------
CONT = {}

def estado(run, datos, t, inicio, ultimo_stats):
    puntos = {}
    for pid, p in PUNTOS.items():
        activo = p["estado"] == "activo"
        sin_esp = p.get("sin_espejo_h")
        tz = {"edad_s": None, "rx": None, "tx": None, "rechazados": None}
        if activo:
            tx = CONT.setdefault(pid, 5_000_000) + (0 if sin_esp else int((t - inicio) * 800))
            tz = {"edad_s": 3, "rx": tx + 120, "tx": tx, "rechazados": 0}
            escribir_json(os.path.join(run, pid, "tzsp.json"),
                          {"ts": int(t), "rx": tz["rx"], "tx": tx, "rechazados": 0})
        st = ultimo_stats.get(pid)
        su = {"stats_edad_s": None, "reglas_cargadas": None, "reglas_fallidas": None,
              "kernel_packets": None, "kernel_drops": None}
        if st:
            s = st["stats"]
            su = {"stats_edad_s": int(t - st["_t"]), "reglas_cargadas": 48211, "reglas_fallidas": 0,
                  "kernel_packets": s["capture"]["kernel_packets"], "kernel_drops": s["capture"]["kernel_drops"]}
        avisos = ["SIN-ESPEJO"] if sin_esp else []
        img = "ghcr.io/example/ids-maat-%s:dev"
        cont = {parte: {"estado": "running" if activo else "exited",
                        "salud": "healthy" if activo else "none", "inicio": int(inicio),
                        "reinicios_1h": 0, "imagen": img % parte} for parte in ("vpn", "suricata")}
        n = p["n"]
        puntos[pid] = {
            "nombre": p["nombre"], "n": n, "puerto": 1194 + n, "tun_net": "100.64.%d.0/24" % n,
            "perfil": "medio", "hilos": 2, "ros_version": p["ros"], "compat_v6": p["ros"].startswith("6"),
            "deseado": p["deseado"], "estado": p["estado"], "redes": p["redes"], "api_puerto": 8729,
            "sensor": "100.64.%d.1" % n, "mk": "100.64.%d.2" % n, "tzsp_puerto": 37008,
            "contenedores": cont,
            "netns": {"coherente": True if activo else None, "vpn": None, "suricata": None},
            "vpn_cliente": {"conectado": activo, "desde": int(inicio) if activo else None,
                            "ip_real": "192.0.2.%d" % (200 + n) if activo else None,
                            "usuario": "mk-%s" % pid if activo else None},
            "tzsp": tz, "suricata": su, "avisos": avisos,
            "retencion": {"objetivo_dias": 30, "desde": int(inicio) if not p.get("sin_eventos") else None,
                          "dias": round((t - inicio) / 86400.0, 1) if not p.get("sin_eventos") else None,
                          "anticipado": False, "ultimo_anticipado": None},
        }
    est = {"v": 1, "ts": int(t), "orq_version": "lab-local", "version": "dev-local", "dev": True,
           "tun_base": "100.64", "cola": {"en_curso": None, "pendientes": 0},
           "capacidad": {"mem_total_mb": 16000, "mem_comprometida_mb": 3000,
                         "mem_disponible_mb": 12000, "caben": {"bajo": 20, "medio": 12, "alto": 6}},
           "reglas": {}, "disco": {"srv_ids_libre_pct": 62}, "puntos": puntos}
    escribir_json(os.path.join(run, "estado.json"), est)

def escribir_json(ruta, d):
    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    tmp = ruta + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    # En Windows os.replace falla (WinError 5) mientras el panel tiene el fichero abierto
    # leyendolo: reintentar un momento en vez de tumbar el modo vivo.
    for intento in range(20):
        try:
            os.replace(tmp, ruta)
            return
        except PermissionError:
            if intento == 19:
                raise
            time.sleep(0.1)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("--horas", type=float, default=26)
    ap.add_argument("--vivo", action="store_true")
    a = ap.parse_args()
    panel, datos, run = (os.path.join(a.base, x) for x in ("panel", "datos", "run"))

    cargar_internet(panel)
    ab = {}
    for pid in PUNTOS:
        if not PUNTOS[pid].get("sin_eventos"):
            ab.update(abonados(pid))
    escribir_json(os.path.join(panel, "estado", "abonados.json"), {"ts": int(time.time()), "mapa": ab})

    ahora = time.time()
    REF[0] = ahora
    inicio = ahora - a.horas * 3600
    ultimo_stats = {}
    for pid, p in PUNTOS.items():
        ruta = os.path.join(datos, pid, "eve.json")
        # vaciar, no borrar: en Windows os.remove falla (WinError 32) si el panel lo tiene abierto
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        open(ruta, "w").close()
        if p.get("sin_eventos"):
            continue
        fin = ahora - p.get("sin_espejo_h", 0) * 3600
        evs = eventos_ventana(pid, inicio, fin, ab)
        # stats cada 5 min; p002 con descartes por memoria en la ultima hora
        pk = 0
        st = []
        t = inicio
        while t < fin:
            pk += R.randint(400_000, 900_000)
            mem = (R.randint(50, 400) if pid == "p002" and t > fin - 3600 else 0)
            s = stats(t, int(t - inicio), pk, pk // 2000, mem)
            st.append(s); ultimo_stats[pid] = dict(s, _t=t)
            t += 300
        evs = sorted(evs + st, key=lambda e: e["timestamp"])
        escribir(ruta, evs, "w")
        print("%s %-12s %6d eventos (%d alertas)" % (pid, p["nombre"], len(evs),
              sum(1 for e in evs if e["event_type"] == "alert")))
    estado(run, datos, ahora, inicio, ultimo_stats)
    print("abonados: %d   estado.json: %s" % (len(ab), os.path.join(run, "estado.json")))

    if not a.vivo:
        return
    print("modo vivo: anadiendo eventos cada 5 s (Ctrl+C para parar)", flush=True)
    t_prev = time.time()
    while True:
        time.sleep(5)
        t = time.time()
        for pid, p in PUNTOS.items():
            if p.get("sin_eventos") or p.get("sin_espejo_h"):
                continue
            evs = eventos_ventana(pid, t_prev, t, ab)
            if int(t) // 60 != int(t_prev) // 60:          # un stats por minuto
                s0 = ultimo_stats[pid]["stats"]
                pk = s0["capture"]["kernel_packets"] + R.randint(80_000, 200_000)
                mem = s0["tcp"]["reassembly_memcap_drop"]
                s = stats(t, int(t - inicio), pk, pk // 2000, mem)
                ultimo_stats[pid] = dict(s, _t=t)
                evs.append(s)
            escribir(os.path.join(datos, pid, "eve.json"), evs)
        estado(run, datos, t, inicio, ultimo_stats)
        t_prev = t

if __name__ == "__main__":
    main()
