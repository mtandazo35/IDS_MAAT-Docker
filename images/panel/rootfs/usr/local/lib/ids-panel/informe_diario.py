#!/usr/bin/env python3
"""Informe diario de Suricata en lenguaje claro: quien esta infectado y que hacer.

En el contenedor del panel (CONTRATO-F2 §8) el informe va POR NODO: cada punto se lee de sus
propios eventos (nodos.ficheros_eventos), su texto se guarda en su directorio de salida
(nodos/<pid>/report-AAAAMMDD.txt) y el mensaje de Telegram es uno solo, con una seccion por
nodo y el nombre de la empresa (IDS_EMPRESA) en vez del hostname del contenedor.

  informe_diario.py [--nodo pNNN | --todos] [--sin-enviar]

Sin argumentos (como lo lanza el panel, en un subproceso, a las 07:30 en IDS_TZ): todos los
puntos, un mensaje de Telegram (si esta configurado) y el texto por stdout. Al ser subproceso, el
tope de memoria (RLIMIT_AS 1 GiB) es del informe y no del servidor. --sin-enviar: solo imprime.
El token de Telegram va cifrado en conf/report.conf (secretos.py, asociado "report:TELEGRAM_TOKEN").
"""
import argparse, gzip, io, json, os, stat, sys, time, urllib.request, urllib.parse, urllib.error
from collections import Counter, defaultdict
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nodos  # noqa: E402
import secretos  # noqa: E402

CONF = os.path.join(nodos.CONF, "report.conf")
EXCL_FILE = os.path.join(nodos.CONF, "exclusiones.json")
HOURS = 24
MAX_LINES = 20_000_000
TELEGRAM_MAX = 4000
ASOC_TOKEN = "report:TELEGRAM_TOKEN"
RC_TELEGRAM = 4        # el informe se hizo pero Telegram fallo: el panel lo anota como fallo (A-25)

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
    """Abre un eve.json(.gz) del punto SIN seguir enlaces y solo si es un fichero regular (A-26):
    datos/<pid> lo escribe el contenedor suricata; un enlace o una FIFO no se leen."""
    fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_BINARY", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("%s: no es un fichero regular" % p)
        f = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    if p.endswith(".gz"):
        return io.TextIOWrapper(gzip.GzipFile(fileobj=f, mode="rb"), encoding="utf-8", errors="replace")
    return io.TextIOWrapper(f, encoding="utf-8", errors="replace")

def _ts(txt):
    """Epoch de una marca de Suricata (2026-10-12T07:00:00.123456-0500), o None."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(str(txt), fmt).timestamp()
        except (ValueError, TypeError):
            pass
    return None

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
     2, "atacando contraseñas (SSH/servicios) hacia afuera", "bloquear salida y revisar el equipo"),
    (("scan", "recon", "sweep", "escanea", "barrido", "portscan"),
     2, "escaneando puertos hacia internet (típico de infección)", "revisar el equipo, muy probable infección"),
    (("exploit", "attack", "cve-", "shellcode", "attempted-admin"),
     2, "intentando explotar/atacar hacia afuera", "revisar el equipo"),
    (("malware", "dns query", "tld", "dyn_dns", "dynamic_dns", "duckdns", "dyndns", "no-ip",
      "suspicious", "likely hostile", "adware", "pup", "observed dns"),
     3, "consultas a dominios sospechosos (dyndns/.cc/.su/.top/reputación malware)", "vigilar; común en equipos comprometidos"),
]

def clasifica(sig):
    s = sig.lower()
    for claves, nivel, expl, accion in REGLAS:
        if any(k in s for k in claves):
            return nivel, expl, accion
    return 3, "actividad sospechosa", "vigilar"

# Exclusiones (apartado Exclusiones del panel + lineas IGNORAR_* legacy). Cada regla puede
# llevar `nodo`: vacio (o _todos) = todos los nodos; con pid, solo los eventos de ese nodo.
def cargar_exclusiones():
    reglas = []; ahora = time.time()
    try:
        data = json.load(open(EXCL_FILE, encoding="utf-8"))
        if isinstance(data, list):
            for r in data:
                if not isinstance(r, dict) or not r.get("ip"):
                    continue
                try: hasta = float(r.get("hasta") or 0)
                except (TypeError, ValueError): hasta = 0
                if hasta and ahora > hasta:
                    continue                             # exclusion temporal vencida
                nodo = str(r.get("nodo") or "")
                reglas.append((r.get("tipo", "dst"), r["ip"],
                               [int(p) for p in (r.get("puertos") or []) if str(p).isdigit()],
                               str(r.get("sid") or ""), "" if nodo == nodos.TODOS else nodo))
    except Exception:
        pass
    _c = conf()
    reglas += [("dst", x.strip(), [], "", "") for x in _c.get("IGNORAR_DESTINOS", "").split(",") if x.strip()]
    reglas += [("src", x.strip(), [], "", "") for x in _c.get("IGNORAR_ORIGENES", "").split(",") if x.strip()]
    return reglas

def excluido(excl, pid, src, dst, dport, sid=None):
    for tipo, ip, pts, rsid, nodo in excl:
        if nodo and nodo != pid:                         # regla de otro nodo
            continue
        quien = dst if tipo == "dst" else src
        if quien != ip:
            continue
        if pts and not (dport is not None and dport in pts):
            continue
        if rsid and str(sid) != rsid:                    # regla ligada a una firma concreta
            continue
        return True
    return False

NOMBRE = {1: "INFECTADOS (actuar ya)", 2: "ATACANDO / ESCANEANDO (revisar)", 3: "SOSPECHOSOS (vigilar)"}

def analizar(pid, excl, cutoff, umbral):
    """Alertas de las ultimas HOURS h de UN nodo. Las IPs son de ese nodo: dos nodos con la
    misma IP privada salen en secciones distintas, nunca sumadas."""
    by_src_nivel = {}
    by_src_expl = {}
    by_src_accion = {}
    by_src_total = Counter()
    n1_hits = Counter()            # alertas de nivel 1 (CnC/botnet) por IP -> repeticion
    n1_sids = defaultdict(set)     # firmas CnC distintas por IP (SID o texto) -> contexto
    total = 0
    seen = 0
    files = [f for _pid, f in nodos.ficheros_eventos(pid, ("eve.json*",))
             if not os.path.islink(f)]
    files.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)
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
                if not isinstance(e, dict) or e.get("event_type") != "alert":
                    continue
                # por la marca de CADA evento, no solo por el mtime del fichero: el eve.json vivo
                # trae tambien alertas de antes de las ultimas 24 h (A-25)
                _t = _ts(e.get("timestamp"))
                if _t is not None and _t < cutoff:
                    continue
                a = e.get("alert") or {}
                sig = str(a.get("signature", ""))
                cat = a.get("category") or ""
                if sig.startswith("ET INFO") or "Not Suspicious" in cat or "Misc activity" in cat:
                    continue
                src = str(e.get("src_ip", "?")); dst = str(e.get("dest_ip", "?"))
                if excluido(excl, pid, src, dst, e.get("dest_port"), a.get("signature_id")):
                    continue
                nivel, expl, accion = clasifica(sig)
                by_src_total[src] += 1
                if nivel == 1:
                    n1_hits[src] += 1
                    n1_sids[src].add(a.get("signature_id") or sig)
                if src not in by_src_nivel or nivel < by_src_nivel[src]:
                    by_src_nivel[src] = nivel; by_src_expl[src] = expl; by_src_accion[src] = accion
                total += 1
        except (OSError, EOFError, ValueError):
            continue
    # Confirmacion de INFECTADO: solo se queda en nivel 1 si hubo repeticion (>= umbral
    # alertas de nivel 1) o >=2 firmas CnC distintas. Una alerta de CnC aislada baja a nivel 2
    # como "posible, sin confirmar" (evita marcar infectado por el texto de UNA sola firma).
    for ip in list(by_src_nivel):
        if by_src_nivel[ip] == 1 and not (n1_hits[ip] >= umbral or len(n1_sids[ip]) >= 2):
            by_src_nivel[ip] = 2
            by_src_expl[ip] = (f"posible infección SIN confirmar: solo {n1_hits[ip]} alerta(s) de "
                               f"CnC aislada(s) (se piden {umbral} o 2 firmas distintas)")
            by_src_accion[ip] = "confirmar primero: ver si se repite o hay más indicadores antes de aislar"
    grupos = defaultdict(list)
    for ip in by_src_total:
        grupos[by_src_nivel[ip]].append(ip)
    return {"grupos": grupos, "total": total, "por_ip": by_src_total, "expl": by_src_expl,
            "accion": by_src_accion}

def seccion(pid, r):
    L = []
    grupos = r["grupos"]
    n1 = len(grupos.get(1, [])); n2 = len(grupos.get(2, [])); n3 = len(grupos.get(3, []))
    L.append(f"== Nodo {nodos.nombre(pid)} ({pid}) ==")
    L.append(f"Infectados: {n1}   Atacando: {n2}   Sospechosos: {n3}   (alertas graves: {r['total']})")
    if not r["total"]:
        L.append("Sin alertas graves. Revisa que esté llegando tráfico del espejo.")
    for nivel in (1, 2, 3):
        ips = grupos.get(nivel, [])
        if not ips:
            continue
        ips.sort(key=lambda ip: r["por_ip"][ip], reverse=True)
        L.append("")
        L.append(f"-- {NOMBRE[nivel]} --")
        for ip in ips[:15]:
            veces = r["por_ip"][ip]
            L.append(f"  {ip:16s}  {r['expl'][ip]}")
            L.append(f"  {'':16s}  -> {r['accion'][ip]}  ({veces} alertas)")
        if len(ips) > 15:
            L.append(f"  ... y {len(ips)-15} equipos más en este grupo")
    return "\n".join(L)

def guardar(pid, texto, ahora):
    """report-AAAAMMDD.txt en la salida del nodo; se conservan los 20 mas recientes."""
    d = nodos.dir_salida(pid)
    out = os.path.join(d, "report-" + time.strftime("%Y%m%d", time.localtime(ahora)) + ".txt")
    try:
        tmp = out + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(texto + "\n")
        os.replace(tmp, out)
    except OSError:
        pass
    try:
        ts = sorted((os.path.join(d, x) for x in os.listdir(d)
                     if x.startswith("report-") and x.endswith(".txt")), key=os.path.getmtime, reverse=True)
        for _v in ts[20:]:
            try:
                os.remove(_v)
            except OSError:
                pass
    except OSError:
        pass

def informe(nodo=nodos.TODOS, ahora=None):
    """Texto del informe del nodo (o de todos, una seccion por nodo). Guarda el de cada nodo."""
    ahora = time.time() if ahora is None else ahora
    cutoff = ahora - HOURS * 3600
    try:
        umbral = max(1, int(conf().get("UMBRAL_INFECTADO", "3") or "3"))
    except Exception:
        umbral = 3
    excl = cargar_exclusiones()
    secciones = []
    for pid in nodos.nodos_de(nodos.validar_nodo(nodo)):
        try:
            texto = seccion(pid, analizar(pid, excl, cutoff, umbral))
            guardar(pid, texto, ahora)
        except (nodos.NodoInexistente, nodos.NodoInvalido):
            # dado de baja mientras se hacia el informe: se salta ese punto, no se cancela todo (A-25)
            print("informe: %s ya no existe; se salta" % pid, file=sys.stderr)
            continue
        secciones.append(texto)
    empresa = os.environ.get("IDS_EMPRESA") or "IDS"
    cab = f"IDS {empresa} - resumen de {HOURS}h"
    if not secciones:
        secciones = ["Sin nodos dados de alta."]
    return cab, secciones

def mensajes(cab, secciones, maximo=TELEGRAM_MAX):
    """Un mensaje con todas las secciones; si no cabe en el limite de Telegram, se parte por
    secciones (nunca a mitad de un nodo, salvo que uno solo no quepa) con (k/n) en la cabecera."""
    trozos = [[]]
    for s in secciones:
        s = s[:maximo - len(cab) - 20]
        actual = "\n\n".join(trozos[-1] + [s])
        if trozos[-1] and len(cab) + 2 + len(actual) + 8 > maximo:
            trozos.append([s])
        else:
            trozos[-1].append(s)
    n = len(trozos)
    salida = []
    for k, t in enumerate(trozos, 1):
        titulo = cab if n == 1 else f"{cab} ({k}/{n})"
        salida.append(titulo + "\n\n" + "\n\n".join(t))
    return salida

def token_telegram(c):
    """Token de Telegram descifrado (va cifrado con la clave maestra); "" si no se puede."""
    try:
        return secretos.descifrar(c.get("TELEGRAM_TOKEN", ""), ASOC_TOKEN)
    except secretos.SecretoNoDisponible as e:
        print("Telegram: el token no se puede descifrar (%s): no se envia" % e, file=sys.stderr)
        return ""

def enviar(textos):
    """True si se envio todo; False si Telegram esta configurado y algo fallo (o el token no se
    puede descifrar); None si Telegram no esta configurado (no hay nada que enviar)."""
    c = conf()
    if not (c.get("TELEGRAM_TOKEN") and c.get("TELEGRAM_CHAT_ID")):
        return None
    tok, chat = token_telegram(c), c.get("TELEGRAM_CHAT_ID")
    if not tok:
        return False
    ok = True
    for texto in textos:
        try:
            data = urllib.parse.urlencode({"chat_id": chat, "text": texto[:TELEGRAM_MAX]}).encode()
            urllib.request.urlopen(f"https://api.telegram.org/bot{tok}/sendMessage", data=data, timeout=20)
        except Exception as ex:
            # el error de urllib puede llevar la URL (con el token): solo el tipo
            print("Telegram fallo: %s" % type(ex).__name__, file=sys.stderr)
            ok = False
    return ok

def main(argv=None):
    p = argparse.ArgumentParser(description="Informe diario por nodo (Telegram).")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--nodo", help="pNNN: solo ese nodo")
    g.add_argument("--todos", action="store_true", help="todos los nodos (por defecto)")
    p.add_argument("--sin-enviar", action="store_true", help="solo imprimir, sin Telegram")
    a = p.parse_args(argv)
    try:
        import resource
        _cap = 1024 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (_cap, _cap))
    except Exception:
        pass
    try:
        cab, secciones = informe(a.nodo if a.nodo else nodos.TODOS)
    except nodos.NodoInvalido:
        print("nodo mal formado: %r" % a.nodo, file=sys.stderr)
        return 2
    except nodos.NodoInexistente:
        print("punto inexistente: %s" % a.nodo, file=sys.stderr)
        return 3
    textos = mensajes(cab, secciones)
    rc = 0
    if not a.sin_enviar and enviar(textos) is False:
        rc = RC_TELEGRAM                 # el informe esta hecho, pero no ha llegado (A-25)
    print("\n\n".join(textos))
    return rc

if __name__ == "__main__":
    sys.exit(main())
