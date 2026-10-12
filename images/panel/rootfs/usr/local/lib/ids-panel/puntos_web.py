"""Apartado Puntos del dashboard (CONTRATO-F2 §5, §10.2, §10.6).

Un punto es un MikroTik con su propia VPN y su propio Suricata (contenedores que crea el
orquestador). Aqui se da de alta, se mira su salud por etapas y su retencion efectiva, se
configura la API del router, se monta el espejo (vista previa sin ningun `accept`), se cambian
sus prefijos, se ven sus logs y se da de baja.

Lo pinta el dashboard con su barra (`nav`) y sus modales (`ask`/`aviso`, nunca alert/confirm):
este modulo no importa el dashboard (puede correr como __main__); usa el modulo del manejador
que lo llama (`sys.modules[type(h).__module__]`). Todo es solo de admin y se comprueba aqui, en
el servidor, en cada ruta (GET y POST).

Reutiliza la logica del panel F1b-min (idspanel/app.py y vistas.py: validar_formulario_punto,
vista_op, la tabla y la ficha) y sus clientes idspanel/orq.py y operaciones.py.

Rutas (h = manejador H del dashboard; consulta/form = dict con un valor por campo):
  GET  /puntos                         lista con salud por etapas y retencion efectiva
  GET  /puntos/nuevo   POST /puntos/nuevo   alta -> punto.crear -> 303 /operaciones/<op_id>
  GET  /operaciones/<op_id>             avance; al terminar, usuario y clave VPN UNA sola vez
  GET  /puntos/<pid>                    ficha (Resumen, VPN, API, Espejo, Prefijos, Logs, Baja)
  GET  /puntos/<pid>/logs?parte=vpn|suricata
  POST /puntos/<pid>/{borrar,regenerar,arrancar,parar,reiniciar,ajustar,api,espejo}
"""

import hashlib
import html
import inspect
import ipaddress
import json
import os
import re
import shutil
import stat
import sys
import threading
import time
import uuid
import zlib

import eventos_web
import nodos
from idspanel import operaciones as _operaciones
from idspanel import orq as _orq

ORQ_SOCK = os.environ.get("IDS_ORQ_SOCK", "/run/ids-orq/orq.sock")
ORQ_TOKEN = os.environ.get("IDS_ORQ_TOKEN", "/run/secrets/orq_token")
TRANSPORTE = None            # pruebas: callable(peticion) -> respuesta (sin socket)

RE_NOMBRE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}$")
# solo ASCII y sin salto final (`$` admite un salto; `\d`, digitos de cualquier escritura): B-13
RE_RUTA_PID = re.compile(r"^/puntos/(p[0-9]{3})(?:/([a-z]+))?\Z")
RE_RUTA_OP = re.compile(r"^/operaciones/([0-9a-f-]{36})\Z")
PERFILES = ("reducido", "completo")
MAX_REDES = 64
PREFIJO_MINIMO = 8           # una red de abonados mas ancha que /8 es un error (A-28)
RETENCION_OBJETIVO_DIAS = 30

ESTADOS = {"creando": "creando", "activo": "activo", "parado": "parado", "error": "con error",
           "borrando": "borrando"}
AVISOS = {
    "SIN-ESPEJO": "No llega el espejo del MikroTik desde hace 10 min o mas",
    "ESPEJO-NO-LLEGA": "El espejo llega a la VPN pero Suricata no ve paquetes",
    "NETNS-DISTINTO": "VPN y Suricata quedaron en redes distintas (el orquestador lo corrige)",
    "REINICIOS": "3 o mas reinicios en la ultima hora",
    "DISCO": "Queda poco disco libre en el servidor (< 15 %): pueden borrarse eventos antes de 30 dias",
}
# estados de la salud por etapas (CONTRATO-F2 §10.6)
SALUD_TXT = {"operativa": "operativa", "degradada": "degradada", "sin datos": "sin datos",
             "desconectada": "desconectada", "deshabilitada": "deshabilitada",
             "desconocido": "desconocido"}
SALUD_COLOR = {"operativa": "#1a7f37", "degradada": "#e58a00", "sin datos": "#8a8a86",
               "desconectada": "#c0392b", "deshabilitada": "#6b6a66", "desconocido": "#9a9a95"}
ETAPAS = (("vpn", "VPN conectada"), ("tzsp", "TZSP recibido"), ("suricata", "Trafico procesado"),
          ("eventos", "Eventos actualizados"), ("datos", "Datos consultables"))
ORDENES = {"punto.crear": "Crear punto", "punto.borrar": "Borrar punto",
           "punto.vpn.regenerar": "Regenerar la clave de la VPN", "punto.arrancar": "Arrancar el punto",
           "punto.parar": "Parar el punto", "punto.reiniciar": "Reiniciar el punto",
           "punto.ajustar": "Cambiar los prefijos del punto"}
ACCIONES_COLA = {"arrancar": "punto.arrancar", "parar": "punto.parar", "reiniciar": "punto.reiniciar"}

_OPS = {}
_OPS_LOCK = threading.Lock()
_ALERTAS = {}            # pid -> (marca, (n, completo), ts)
_RET = {}                # pid -> (marca, dict)
TOPE_ALERTAS_BYTES = 8 * 1024 * 1024
MAX_LINEA = eventos_web.MAX_LINEA
TOPE_TZSP_BYTES = 1 << 20
RETENCION_SEGUNDOS = 1.0     # tope de tiempo de la retencion por ficheros (en cada carga de /puntos)


def esc(v):
    """Escape HTML de cualquier dato (tambien numeros y None)."""
    return html.escape("" if v is None else str(v), quote=True)


# --------------------------------------------------------------------------------------------
# Clientes y datos
# --------------------------------------------------------------------------------------------
def cliente():
    return _orq.ClienteOrq(ORQ_SOCK, ORQ_TOKEN, TRANSPORTE)


def ops():
    """Registro de las operaciones que pidio el panel (estado/operaciones.json, 0600)."""
    p = os.path.join(nodos.ESTADO, "operaciones.json")
    with _OPS_LOCK:
        if p not in _OPS:
            try:
                os.makedirs(nodos.ESTADO, mode=0o700, exist_ok=True)
            except OSError:
                pass
            _OPS[p] = _operaciones.Operaciones(p)
        return _OPS[p]


def _dash(h):
    """El modulo del dashboard que atiende la peticion (vale aunque corra como __main__)."""
    return sys.modules[type(h).__module__]


def _usuario(d):
    return getattr(d.CTX, "user", None) or "?"


def _ip(d):
    return getattr(d.CTX, "ip", "") or ""


def _bit(d, accion, pid="", objetivo="", resultado="", extra=""):
    """Una linea de bitacora: usuario (lo pone bitacora), punto, objetivo, operacion y resultado.
    Nunca claves."""
    det = "punto=%s" % (pid or "-")
    if objetivo:
        det += " objetivo=%s" % objetivo
    if resultado:
        det += " resultado=%s" % resultado
    if extra:
        det += " " + extra
    try:
        d.bitacora(accion, det[:400])
    except Exception:
        pass


def validar_formulario_punto(f):
    """(params para punto.crear, mensaje de error). Igual que idspanel/app.py (F1b-min)."""
    nombre = (f.get("nombre") or "").strip()
    if not RE_NOMBRE.match(nombre):
        return None, ("El nombre solo admite minusculas, numeros y guiones, de 2 a 31 caracteres, "
                      "empezando por letra o numero (p. ej. norte).")
    redes, err = validar_redes(f.get("redes") or "")
    if err:
        return None, err
    ros = (f.get("ros_version") or "7").strip()
    if ros not in ("6", "7"):
        return None, "La version de RouterOS tiene que ser 6 o 7."
    perfil = (f.get("perfil") or "reducido").strip()
    if perfil not in PERFILES:
        return None, "El perfil tiene que ser reducido o completo."
    return {"nombre": nombre, "redes_abonados": redes, "perfil": perfil, "ros_version": int(ros)}, ""


def validar_redes(texto):
    trozos = [x.strip() for x in re.split(r"[\s,;]+", texto or "") if x.strip()]
    if not trozos:
        return None, "Escribe al menos una red de abonados (p. ej. 10.0.0.0/24)."
    if len(trozos) > MAX_REDES:
        return None, "Como mucho %d redes de abonados por punto." % MAX_REDES
    redes = []
    for r in trozos:
        try:
            net = ipaddress.IPv4Network(r, strict=False)
        except ValueError:
            return None, "«%s» no es una red IPv4 valida (ejemplo: 10.0.0.0/24)." % r[:45]
        if net.prefixlen < PREFIJO_MINIMO:
            return None, ("«%s» es demasiado ancha para una red de abonados (como mucho /%d)."
                          % (str(net), PREFIJO_MINIMO))
        if str(net) not in redes:
            redes.append(str(net))
    return redes, ""


def _porcentaje(avance):
    try:
        hechos, total = str(avance).split("/")
        return max(0, min(100, int(100 * int(hechos) / int(total))))
    except (ValueError, ZeroDivisionError):
        return 0


def salud(fn, pid):
    """Salud por etapas normalizada: {"estado", "etapas": [{id, nombre, estado, detalle}], "nota"}.

    `fn` es salud_punto(pid) del nucleo. Sin ella, o si falla, el estado es "desconocido": nunca
    se da por sana una etapa que no se midio (VPN arriba o cero alertas no son «sano»)."""
    vacio = {"estado": "desconocido", "etapas": [], "nota": ""}
    if fn is None:
        return vacio
    try:
        s = fn(pid)
    except Exception:
        return vacio
    if isinstance(s, str):
        return {"estado": s if s in SALUD_TXT else "desconocido", "etapas": [], "nota": ""}
    if not isinstance(s, dict):
        return vacio
    etapas = []
    crudas = s.get("etapas") or []
    if isinstance(crudas, dict):
        crudas = [dict(v, id=k) if isinstance(v, dict) else {"id": k, "estado": v} for k, v in crudas.items()]
    nombres = dict(ETAPAS)
    for e in crudas:
        if not isinstance(e, dict):
            continue
        ide = str(e.get("id") or e.get("etapa") or "")
        etapas.append({"id": ide, "nombre": str(e.get("nombre") or nombres.get(ide, ide)),
                       "estado": str(e.get("estado") or "desconocido"),
                       "detalle": str(e.get("detalle") or "")})
    est = str(s.get("estado") or "desconocido")
    return {"estado": est if est in SALUD_TXT else "desconocido", "etapas": etapas,
            "nota": str(s.get("nota") or s.get("detalle") or "")}


def salud_chip(sal):
    est = sal.get("estado", "desconocido")
    return ("<span class=pchip style='background:%s'>%s</span>"
            % (SALUD_COLOR.get(est, "#9a9a95"), esc(SALUD_TXT.get(est, est))))


def salud_etapas_html(sal):
    if not sal.get("etapas"):
        return ("<div class=hint>Sin medicion por etapas todavia: estado <b>%s</b>.</div>"
                % esc(SALUD_TXT.get(sal.get("estado"), sal.get("estado"))))
    out = "<ul class=etapas>"
    for e in sal["etapas"]:
        out += ("<li><span class=edot style='background:%s'></span><b>%s</b> &middot; %s%s</li>"
                % (SALUD_COLOR.get(e["estado"], "#9a9a95"), esc(e["nombre"]), esc(e["estado"]),
                   (" <span class=hint>%s</span>" % esc(e["detalle"])) if e["detalle"] else ""))
    return out + "</ul>" + (("<div class=hint>%s</div>" % esc(sal["nota"])) if sal.get("nota") else "")


def _a_epoch(v):
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        from datetime import datetime
        t = str(v).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(t).timestamp()
        except ValueError:
            return datetime.strptime(t, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except (ValueError, TypeError):
        return None


def _primer_ts(real, st, nombre, tope=64 * 1024, limite=None):
    """Marca de tiempo del primer evento de un fichero de eventos (gz o plano), leyendo poco.
    `real, st` vienen de `eventos_web._fichero_seguro` (fichero regular dentro de datos/<pid>)
    y se abre con `eventos_web._abrir` (O_NOFOLLOW|O_NONBLOCK y el mismo inodo). Un .gz se lee
    con topes de bytes comprimidos, miembros y tiempo (B-09)."""
    try:
        with eventos_web._abrir(real, st) as f:
            if nombre.endswith(".gz"):
                def comprobar(lec):
                    if limite is not None and time.monotonic() > limite:
                        raise eventos_web._GzLimite("sin tiempo")
                g = eventos_web._GzLector(f, comprobar, max_miembros=eventos_web.DISP_MIEMBROS,
                                          max_comprimidos=eventos_web.DISP_COMPRIMIDOS)
                bloque = g.read(tope)
            else:
                bloque = f.read(tope)
    except (OSError, EOFError, zlib.error, eventos_web._GzLimite):
        return None
    for linea in bloque.splitlines()[:50]:
        try:
            ev = json.loads(linea.decode("utf-8", "replace"))
        except (ValueError, RecursionError):
            continue
        t = _a_epoch(ev.get("timestamp")) if isinstance(ev, dict) else None
        if t:
            return t
    return None


def _ficheros_seguros(pid):
    """[(nombre, real, st)] de los ficheros de eventos del punto que son regulares y estan de
    verdad dentro de datos/<pid> (los mismos que acepta la pagina Eventos)."""
    try:
        fs = nodos.ficheros_eventos(pid)
    except (nodos.NodoInvalido, nodos.NodoInexistente):
        return []
    out = []
    for _p, ruta in fs:
        nombre = os.path.basename(ruta)
        ok = eventos_web._fichero_seguro(pid, nombre)
        if ok:
            out.append((nombre, ok[0], ok[1]))
    return out


def retencion(pid, punto=None):
    """Retencion efectiva de un punto: desde que fecha hay eventos y si hubo borrado anticipado.

    Manda lo que publica el orquestador en estado.json (`retencion`: {desde, anticipado});
    si no viene, se mira el fichero de eventos mas viejo del punto (solo ficheros regulares
    dentro de datos/<pid>, con topes). Nunca se promete el objetivo de 30 dias: se dice desde
    cuando hay datos de verdad."""
    p = punto if punto is not None else (nodos.punto(pid) or {})
    r = p.get("retencion") if isinstance(p.get("retencion"), dict) else {}
    desde = _a_epoch(r.get("desde"))
    anticipado = r.get("anticipado")
    if anticipado is None:
        anticipado = r.get("borrado_anticipado")
    fuente = "orquestador" if desde else ""
    if not desde:
        fs = _ficheros_seguros(pid)
        marca = tuple(sorted((n, st.st_mtime, st.st_size, st.st_ino) for n, _r, st in fs))
        cache = _RET.get(pid)
        if cache and cache[0] == marca:
            return cache[1]
        viejo = None
        limite = time.monotonic() + RETENCION_SEGUNDOS
        for nombre, real, st in sorted(fs, key=lambda x: (x[2].st_mtime, x[0]))[:1]:
            viejo = _primer_ts(real, st, nombre, limite=limite) or st.st_mtime
        desde = viejo
        fuente = "ficheros" if desde else ""
        res = {"desde": desde, "anticipado": anticipado, "fuente": fuente}
        _RET[pid] = (marca, res)
        return res
    return {"desde": desde, "anticipado": anticipado, "fuente": fuente}


def retencion_html(ret, ahora=None):
    ahora = ahora or time.time()
    if not ret.get("desde"):
        return "<span class=hint>sin eventos todavia</span>"
    dias = max(0, int((ahora - ret["desde"]) // 86400))
    txt = ("desde <b>%s</b> (%d dia%s)" % (time.strftime("%d/%m/%Y", time.localtime(ret["desde"])), dias,
                                           "" if dias == 1 else "s"))
    if ret.get("anticipado"):
        txt += (" <span class=pwarn>borrado anticipado por disco: no hay %d dias</span>"
                % RETENCION_OBJETIVO_DIAS)
    elif dias < RETENCION_OBJETIVO_DIAS:
        txt += " <span class=hint>(objetivo %d dias)</span>" % RETENCION_OBJETIVO_DIAS
    return txt


def _cuenta_alertas(f, ahora, inicio_cortado):
    """(alertas de 24 h, leido todo) de las lineas de `f` hasta TOPE_ALERTAS_BYTES leidos.
    Lineas de mas de MAX_LINEA, JSON que no es objeto o demasiado anidado: se saltan (B-10)."""
    n, leidos, larga = 0, 0, inicio_cortado
    while leidos < TOPE_ALERTAS_BYTES:
        ln = f.readline(MAX_LINEA + 1)
        if not ln:
            return n, True
        leidos += len(ln)
        if not ln.endswith(b"\n"):
            larga = True                   # linea demasiado larga (o la que se esta escribiendo)
            continue
        if larga:                          # el final de esa linea
            larga = False
            continue
        if b'"event_type":"alert"' not in ln:
            continue
        try:
            ev = json.loads(ln)
        except (ValueError, RecursionError):
            continue
        if not isinstance(ev, dict):
            continue
        t = _a_epoch(ev.get("timestamp"))
        if t and ahora - t <= 86400:
            n += 1
    return n, False


def alertas_24h(pid, ahora=None):
    """(alertas de las ultimas 24 h, completo) leyendo el final del eve.json vivo con tope REAL
    de bytes (no solo el seek inicial). Un eve.json que no es fichero regular o cuya ruta real
    sale de datos/<pid> no se abre: (0, True) (B-09)."""
    ahora = ahora or time.time()
    ok = eventos_web._fichero_seguro(pid, "eve.json")
    if not ok:
        return 0, True
    real, st = ok
    marca = (st.st_mtime_ns, st.st_size, st.st_ino)
    c = _ALERTAS.get(pid)
    if c and c[0] == marca and ahora - c[2] < 60:
        return c[1]
    n, completo = 0, True
    try:
        with eventos_web._abrir(real, st) as f:
            cortado = False
            if st.st_size > TOPE_ALERTAS_BYTES:
                f.seek(st.st_size - TOPE_ALERTAS_BYTES)
                cortado = not f.readline(MAX_LINEA + 1).endswith(b"\n")
                completo = False
            n, todo = _cuenta_alertas(f, ahora, cortado)
            completo = completo and todo
    except OSError:
        pass
    _ALERTAS[pid] = (marca, (n, completo), ahora)
    return n, completo


def _leer_json_pequeno(ruta, tope):
    """JSON de un fichero regular, sin seguir enlaces ni esperar a un FIFO, con tope de bytes."""
    fl = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
          | getattr(os, "O_NONBLOCK", 0))
    fd = os.open(ruta, fl)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError("no es un fichero regular")
        return json.loads(f.read(tope))


def espejo_pps(pid):
    """Paquetes de espejo por segundo aceptados en la ultima ventana del receptor TZSP."""
    try:
        d = _leer_json_pequeno(nodos.tzsp_json(pid), TOPE_TZSP_BYTES)
    except (OSError, ValueError, RecursionError, nodos.NodoInvalido):
        return None, None
    if not isinstance(d, dict):
        return None, None
    v = d.get("ventana") if isinstance(d.get("ventana"), dict) else {}
    seg = v.get("segundos") if isinstance(v.get("segundos"), (int, float)) else 0
    acep = v.get("aceptados") if isinstance(v.get("aceptados"), dict) else {}
    vis = d.get("ultimo_visto") if isinstance(d.get("ultimo_visto"), dict) else {}
    acept = sum(x for x in acep.values() if isinstance(x, (int, float)) and not isinstance(x, bool))
    ult = [x for x in vis.values() if isinstance(x, (int, float)) and not isinstance(x, bool)]
    return (acept / seg if seg else None), (max(ult) if ult else None)


def _edad(seg):
    seg = int(max(0, seg))
    if seg < 90:
        return "%d s" % seg
    if seg < 5400:
        return "%d min" % (seg // 60)
    if seg < 172800:
        return "%d h" % (seg // 3600)
    return "%d dias" % (seg // 86400)


def _num(n):
    try:
        return "{:,}".format(int(n)).replace(",", ".")
    except (TypeError, ValueError):
        return "-"


def _contenedor(c):
    c = c or {}
    est, sal = c.get("estado"), c.get("salud")
    if est in (None, "ausente"):
        return "no existe"
    if est != "running":
        return est
    return {"healthy": "sano", "unhealthy": "enfermo", "starting": "arrancando"}.get(sal, "en marcha")


# --------------------------------------------------------------------------------------------
# Esqueleto de pagina (estilo del dashboard)
# --------------------------------------------------------------------------------------------
_CSS = (
    "main{max-width:1100px;padding:20px 24px 40px}"
    ".ptit{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:0 0 12px}"
    ".card{padding:16px 18px}"
    ".pchip{display:inline-block;color:#fff;font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px}"
    ".pwarn{color:#b06a00;font-weight:600}"
    ".hint{color:#8a8a86;font-size:12px}"
    ".etapas{list-style:none;margin:6px 0;padding:0;font-size:13px}.etapas li{margin:3px 0}"
    ".edot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:middle}"
    ".btn{display:inline-block;padding:9px 16px;background:#2a78d6;color:#fff;border:0;border-radius:9px;"
    "font:600 13px system-ui;cursor:pointer;text-decoration:none}"
    ".btn:hover{background:#1c5cab}.btn.sec{background:#fff;color:#33322f;border:1px solid #d7d6d2}"
    ".btn.sec:hover{background:#f4f4f2}.btn.peligro{background:#c0392b}.btn.peligro:hover{background:#9c2f22}"
    ".btn[disabled]{opacity:.5;cursor:default}"
    ".acciones{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.acciones form{margin:0}"
    ".datos{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}"
    ".dato .et{color:#6b6a66;font-size:12px}"
    "pre.cmd{background:#0f1720;color:#e6edf3;border-radius:8px;padding:12px;overflow-x:auto;font-size:12.5px;"
    "white-space:pre-wrap;word-break:break-all}"
    ".bloque{margin:10px 0}.bloque .bcab{display:flex;align-items:center;justify-content:space-between;gap:8px}"
    "label.l{display:block;font-size:12.5px;color:#52514e;font-weight:600;margin:10px 0 4px}"
    "input.t,textarea.t,select.t{width:100%;padding:8px 10px;border:1px solid #d7d6d2;border-radius:8px;"
    "font:14px system-ui;box-sizing:border-box}"
    "textarea.t{font:12.5px ui-monospace,Consolas,monospace}"
    ".aviso{border-radius:9px;padding:10px 13px;margin:0 0 12px;font-size:13px}"
    ".aviso.ok{background:#e6f4ea;color:#1a7f37;border:1px solid #b7e0c2}"
    ".aviso.err{background:#fdecec;color:#b52a2a;border:1px solid #f3c4c4}"
    ".aviso.amb{background:#fff7ed;color:#7a4a12;border:1px solid #f2d3ad}"
    ".aviso.info{background:#eef4fd;color:#2a5fa0;border:1px solid #cfe0f6}"
    ".cred{display:grid;gap:10px;margin:10px 0}.cred code{font-size:15px;padding:4px 8px}"
    ".secnav{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 12px}.secnav a{font-size:13px;padding:5px 11px;"
    "border:1px solid #d7d6d2;border-radius:20px;text-decoration:none;color:#33322f;background:#fff}"
    "progress{width:100%;height:14px}"
    ".tablewrap{overflow-x:auto}"
)

_JS = ("<script>function pcopiar(id,b){var e=document.getElementById(id);if(!e)return;"
       "var t=e.textContent;function ok(){var o=b.textContent;b.textContent='Copiado';"
       "setTimeout(function(){b.textContent=o;},1500);}"
       "if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(ok,"
       "function(){aviso('No se pudo copiar','Selecciona el texto y copialo a mano.');});}"
       "else{aviso('No se pudo copiar','Selecciona el texto y copialo a mano.');}}"
       "function pnombre(i){var f=i.form,b=f.querySelector('button[type=submit]');"
       "if(b)b.disabled=(i.value!==f.getAttribute('data-nombre'));}</script>")


def aviso(texto, tipo="err"):
    if not texto:
        return ""
    return "<div class='aviso %s'>%s</div>" % (tipo, esc(texto))


def pagina(d, titulo, cuerpo, refresco=0):
    meta = "<meta http-equiv=refresh content=%d>" % refresco if refresco else ""
    return ("<!doctype html><html lang=es><head><meta charset=utf-8>"
            "<link rel=icon type=image/png href=/favicon.ico>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>" + meta +
            "<title>%s</title><style>%s%s</style></head><body>" % (esc(titulo), d.BASE_CSS, _CSS)
            + d.nav("/puntos") + "<main>" + cuerpo + "</main>" + _JS + "</body></html>")


def _prohibido(h):
    d = _dash(h)
    return h._html(pagina(d, "Sin permiso", "<h1>Sin permiso</h1><p>Esta parte del panel es solo "
                          "para administradores.</p>"), 403)


def _bloque(ide, titulo, texto):
    return ("<div class=bloque><div class=bcab><b>%s</b><button type=button class='btn sec' "
            "onclick=\"pcopiar('%s',this)\">Copiar</button></div><pre class=cmd id='%s'>%s</pre></div>"
            % (esc(titulo), esc(ide), esc(ide), esc(texto)))


def comandos_html(texto, ros_version, prefijo):
    """Bloques v7/v6 (el declarado primero) y el del certificado API-SSL, cada uno con Copiar."""
    partes = _orq.partir_comandos(texto)
    if "todo" in partes:
        return _bloque(prefijo + "-todo", "Comandos para el MikroTik", partes["todo"])
    try:
        ros = int(ros_version)
    except (TypeError, ValueError):
        ros = 7
    orden = ["v7", "v6"] if ros != 6 else ["v6", "v7"]
    out = ""
    if partes.get("cabecera"):
        out += "<pre class=cmd>%s</pre>" % esc(partes["cabecera"])
    for i, k in enumerate(orden):
        tit = "RouterOS %s" % k[1] + (" (la version declarada de este punto)" if i == 0 else "")
        b = _bloque("%s-%s" % (prefijo, k), tit, partes.get(k, ""))
        out += b if i == 0 else ("<details><summary>Ver el bloque de RouterOS %s</summary>%s</details>"
                                 % (k[1], b))
    if partes.get("certificado"):
        out += _bloque(prefijo + "-cert", "Certificado API-SSL (una sola vez por router)", partes["certificado"])
    return out


# --------------------------------------------------------------------------------------------
# Lista
# --------------------------------------------------------------------------------------------
def lista(h, consulta):
    d = _dash(h)
    barrer_bajas(d)              # limpieza de bajas sin depender de quien las pidio (A-09)
    est = nodos.leer_estado() or {}
    ahora = time.time()
    filas = ""
    fn = getattr(d, "salud_punto", None)
    for p in nodos.puntos():
        pid = p["pid"]
        sal = salud(fn, pid)
        pps, ultimo = espejo_pps(pid)
        n24, completo = alertas_24h(pid, ahora)
        cont = p.get("contenedores") or {}
        su = p.get("suricata") or {}
        estado = ESTADOS.get(p.get("estado"), p.get("estado") or "-")
        if p.get("deseado") == "parado" and p.get("estado") != "parado":
            estado += " (se esta parando)"
        avisos = "".join("<div class=pwarn>%s</div>" % esc(AVISOS.get(a, a)) for a in (p.get("avisos") or []))
        descarte = ""
        try:
            if su.get("kernel_packets"):
                descarte = " &middot; descarte %.1f %%" % (100.0 * float(su.get("kernel_drops") or 0)
                                                           / float(su["kernel_packets"]))
        except (TypeError, ValueError, ZeroDivisionError):
            descarte = ""
        filas += (
            "<tr><td><a href='/puntos/%s'><b>%s</b></a><div class=hint>%s</div></td>"
            "<td>%s%s</td><td>%s<div class=hint>%s</div></td>"
            "<td>%s</td><td>%s</td><td>%s%s</td><td class=num>%s%s</td><td>%s</td></tr>"
            % (esc(pid), esc(p.get("nombre") or pid), esc(pid), esc(estado), avisos,
               salud_chip(sal), " &middot; ".join(esc("%s: %s" % (e["nombre"], e["estado"])) for e in sal["etapas"]),
               "conectado" if (p.get("vpn_cliente") or {}).get("conectado") else "desconectado",
               ("%.0f paq/s" % pps if pps is not None else "-")
               + (("<div class=hint>hace %s</div>" % _edad(ahora - ultimo)) if ultimo else ""),
               esc(_contenedor(cont.get("suricata"))), descarte,
               _num(n24), "+" if not completo else "",
               retencion_html(retencion(pid, p), ahora)))
    if not filas:
        filas = ("<tr><td colspan=8 class=hint style='padding:16px'>Todavia no hay puntos. "
                 "<a href='/puntos/nuevo'>Agrega el primero</a>.</td></tr>")
    cola = est.get("cola") or {}
    en = cola.get("en_curso")
    linea_cola = ("en curso: %s %s (%s)" % (en.get("orden"), en.get("pid") or "", en.get("paso") or "")
                  if isinstance(en, dict) else "libre")
    cap = ((est.get("capacidad") or {}).get("caben")) or {}
    caben = ", ".join("%s %s" % (k, v) for k, v in cap.items()) if cap else "-"
    viejo = ""
    try:
        edad_est = int(ahora - float(est.get("ts", 0))) if est else None
    except (TypeError, ValueError):
        edad_est = None
    if edad_est is None:
        viejo = aviso("No se puede leer el estado del orquestador (estado.json). Si acabas de instalar, "
                      "espera unos segundos; si sigue, revisa el servicio ids-orq en el servidor.", "amb")
    elif edad_est > 60:
        viejo = aviso("El estado tiene %s: el orquestador no lo esta actualizando (deberia ser cada 15 s)."
                      % _edad(edad_est), "amb")
    cuerpo = (
        "<div class=ptit><div><h1>Puntos</h1><p class=sub>Cada punto es un MikroTik con su propia VPN y su "
        "propio Suricata. Cola del orquestador: %s &middot; pendientes: %s &middot; caben mas puntos: %s</p></div>"
        "<a class=btn href='/puntos/nuevo'>Agregar punto</a></div>%s"
        "<div class='card tablewrap'><table><thead><tr><th>Punto</th><th>Estado</th><th>Salud por etapas</th>"
        "<th>VPN</th><th>Espejo</th><th>Suricata</th><th class=num>Alertas 24 h</th>"
        "<th>Retencion efectiva</th></tr></thead><tbody>%s</tbody></table></div>"
        "<p class=hint>Retencion: el objetivo es %d dias de eventos por punto; la columna dice desde cuando "
        "hay datos de verdad (si el disco se llena, se borran antes los mas viejos y aqui se ve). La "
        "captura es reducida: los primeros 10 KB de cada conexion de los prefijos elegidos.</p>"
        % (esc(linea_cola), esc(cola.get("pendientes", 0)), esc(caben), viejo, filas, RETENCION_OBJETIVO_DIAS))
    return h._html(pagina(d, "Puntos", cuerpo, refresco=30))


# --------------------------------------------------------------------------------------------
# Alta
# --------------------------------------------------------------------------------------------
def form_nuevo(h, valores=None, mensaje="", codigo=200):
    d = _dash(h)
    v = valores or {}
    ros = str(v.get("ros_version") or "7")
    perfil = v.get("perfil") or "reducido"
    token = v.get("op") if _operaciones.RE_OPID.match(v.get("op") or "") else str(uuid.uuid4())
    cap = (((nodos.leer_estado() or {}).get("capacidad") or {}).get("caben")) or {}

    def marcado(a, b):
        return " checked" if a == b else ""
    cuerpo = (
        "<h1>Agregar punto</h1><p class=sub>Un punto es un MikroTik que manda una copia de su trafico (el "
        "espejo) al sensor por una VPN propia. Al crearlo, el servidor prepara su VPN y su Suricata y te da "
        "los comandos para pegar en el MikroTik.</p>%s%s"
        "<form method=post action='/puntos/nuevo' class=card onsubmit=\"var b=this.querySelector('button');"
        "if(b){b.disabled=true;b.textContent='Creando...';}\">"
        "<input type=hidden name=op value='%s'>"
        "<label class=l>Nombre del punto <span class=hint>(minusculas, numeros y guiones; p. ej. norte)</span></label>"
        "<input class=t name=nombre required maxlength=31 value='%s'>"
        "<label class=l>Prefijos de abonados que se espejan <span class=hint>(CIDR, uno por linea)</span></label>"
        "<textarea class=t name=redes rows=4 required placeholder='10.0.0.0/24'>%s</textarea>"
        "<label class=l>Version de RouterOS</label>"
        "<label><input type=radio name=ros_version value=7%s> RouterOS 7</label> "
        "<label><input type=radio name=ros_version value=6%s> RouterOS 6 (6.49 o superior)</label>"
        "<label class=l>Perfil de reglas</label>"
        "<label><input type=radio name=perfil value=reducido%s> Reducido (por defecto; menos memoria)</label> "
        "<label><input type=radio name=perfil value=completo%s> Completo (casi el doble de memoria)</label>"
        "<div class=acciones><button class=btn type=submit>Crear punto</button>"
        "<a class='btn sec' href='/puntos'>Cancelar</a></div></form>"
        % (aviso(mensaje), ("<p class=hint>Caben ahora en el servidor: %s.</p>"
                            % esc(", ".join("%s %s" % kv for kv in cap.items()))) if cap else "",
           esc(token), esc(v.get("nombre", "")), esc(v.get("redes", "")), marcado(ros, "7"), marcado(ros, "6"),
           marcado(perfil, "reducido"), marcado(perfil, "completo")))
    return h._html(pagina(d, "Agregar punto", cuerpo), codigo)


def crear(h, form):
    """punto.crear con un op_id que viene del formulario: un doble clic o un reintento con el mismo
    formulario no pide un segundo punto, lleva a la misma operacion."""
    d = _dash(h)
    usuario = _usuario(d)
    token = form.get("op") or ""
    op_id = token if _operaciones.RE_OPID.match(token) else str(uuid.uuid4())
    previa = ops().obtener(op_id)
    if previa is None:
        params, err = validar_formulario_punto(form)
        if err:
            return form_nuevo(h, form, err, 400)
        # reserva atomica: dos envios a la vez del mismo formulario no piden dos puntos
        previa = _reservar_op(op_id, usuario, "punto.crear", nombre=params["nombre"],
                              ros_version=params["ros_version"])
    if previa is not None:
        if previa.get("usuario") != usuario or previa.get("orden") != "punto.crear":
            return h._html(pagina(d, "Operacion duplicada", aviso("Ese formulario ya se uso para otra "
                                                                   "operacion. Recarga la pagina.")), 409)
        _bit(d, "PUNTO-CREAR", objetivo=previa.get("nombre") or "", resultado="REPETIDA",
             extra="op=%s" % op_id)
        return h._redirect("/operaciones/%s" % op_id)
    r = cliente().pedir("punto.crear", params, quien="panel:%s" % usuario, ip=_ip(d), op_id=op_id)
    _bit(d, "PUNTO-CREAR", objetivo=params["nombre"], resultado=r.get("codigo"),
         extra="redes=%d perfil=%s ros=%s op=%s" % (len(params["redes_abonados"]), params["perfil"],
                                                    params["ros_version"], op_id))
    if r.get("codigo") in ("ACEPTADA", "OK"):
        return h._redirect("/operaciones/%s" % op_id)
    ops().quitar(op_id)
    codigo = 503 if r.get("codigo") in (_orq.SIN_SERVICIO, _orq.SIN_TOKEN) else (
        409 if "CONFLICTO" in str(r.get("codigo")) else 400)
    form = dict(form, op=str(uuid.uuid4()))
    return form_nuevo(h, form, _orq.traducir(r.get("codigo"), r.get("mensaje"), r.get("datos")), codigo)


# --------------------------------------------------------------------------------------------
# Formularios de un solo uso (A-08): un doble clic o un reintento no repite la orden
# --------------------------------------------------------------------------------------------
# Las ordenes de cola (arrancar, parar, reiniciar, regenerar, ajustar, borrar) usan el token del
# formulario como op_id, como el alta: el orquestador tambien deduplica por op_id. Las que el
# panel hace por si mismo (espejo aplicar/pausar/retirar, API guardar/probar/olvidar huella)
# apuntan el token aqui, en memoria del proceso: el primer envio lo reserva («en curso») y
# guarda su resultado; los repetidos reciben ese resultado sin repetir nada. Un formulario sin
# token (cliente viejo) se atiende sin esta proteccion.
FORMS_TTL = 86400
FORMS_MAX = 5000
_FORMS = {}                  # token -> {"clave": (usuario, pid, accion), "estado", "resultado", "ts"}
_FORMS_LOCK = threading.Lock()
_RESERVA_LOCK = threading.Lock()


def campo_token():
    """Campo oculto con un token nuevo para un formulario de la ficha."""
    return "<input type=hidden name=op value='%s'>" % str(uuid.uuid4())


def _reservar_op(op_id, usuario, orden, pid=None, nombre=None, ros_version=None):
    """Registra la operacion si el op_id esta libre (None) o devuelve la que ya lo usa."""
    with _RESERVA_LOCK:
        previa = ops().obtener(op_id)
        if previa is None:
            with _FORMS_LOCK:
                if op_id in _FORMS:
                    return {"usuario": None, "orden": None}
            ops().registrar(op_id, usuario, orden, pid=pid, nombre=nombre, ros_version=ros_version)
        return previa


def _estado_token(tok, clave):
    """None si el token esta libre; ("otro",), ("en_curso",) o ("hecho", resultado)."""
    with _FORMS_LOCK:
        r = _FORMS.get(tok)
        if r is not None:
            if r["clave"] != clave:
                return ("otro",)
            return (r["estado"], r.get("resultado"))
    if ops().obtener(tok) is not None:
        return ("otro",)
    return None


def _tomar_token(tok, clave):
    """Reserva atomica del token: None si es nuestro, o el estado de quien lo tiene."""
    with _FORMS_LOCK:
        ahora = time.time()
        if len(_FORMS) >= FORMS_MAX:
            for k in [k for k, v in _FORMS.items() if ahora - v["ts"] > FORMS_TTL]:
                _FORMS.pop(k, None)
            if len(_FORMS) >= FORMS_MAX:
                hechos = sorted((v["ts"], k) for k, v in _FORMS.items() if v["estado"] == "hecho")
                for _ts, k in hechos[:len(_FORMS) - FORMS_MAX + 1]:
                    _FORMS.pop(k, None)
        r = _FORMS.get(tok)
        if r is None:
            _FORMS[tok] = {"clave": clave, "estado": "en_curso", "resultado": None, "ts": ahora}
            return None
        if r["clave"] != clave:
            return ("otro",)
        return (r["estado"], r.get("resultado"))


def _cerrar_token(tok, resultado):
    with _FORMS_LOCK:
        r = _FORMS.get(tok)
        if r is not None:
            r.update(estado="hecho", resultado=resultado, ts=time.time())


def _soltar_token(tok):
    with _FORMS_LOCK:
        _FORMS.pop(tok, None)


def _responder(h, pid, res):
    mensaje, codigo, ok, extra = res
    return ficha(h, pid, mensaje, codigo, ok=ok, extra_espejo=extra)


def _repetida(h, pid, accion, est):
    d = _dash(h)
    if est[0] == "otro":
        return ficha(h, pid, "Ese formulario ya se uso para otra orden u otro punto. Recarga la ficha.", 409)
    if est[0] == "en_curso":
        _bit(d, "PUNTO-" + accion.upper(), pid=pid, resultado="REPETIDA-EN-CURSO")
        return ficha(h, pid, "Esa orden ya se esta haciendo (doble clic o reintento): espera unos segundos "
                             "y recarga la ficha.", 409)
    _bit(d, "PUNTO-" + accion.upper(), pid=pid, resultado="REPETIDA")
    mensaje, codigo, ok, extra = est[1]
    return ficha(h, pid, ((mensaje + " ") if mensaje else "")
                 + "(Ese formulario ya se habia enviado: no se repitio la orden.)", codigo, ok=ok, extra_espejo=extra)


def _con_token(h, pid, accion, form, hacer, validar=None):
    """Orden de la ficha que hace el panel, de un solo uso por formulario (A-08).

    `validar()` (sin efectos: puede leer el router) devuelve None o la respuesta
    (mensaje, codigo, ok, extra_espejo) si no se puede hacer; `hacer()` hace la orden y
    devuelve su respuesta. Con dos envios a la vez del mismo formulario, los dos pueden validar
    pero solo uno hace la orden; el otro recibe 409 (en curso) o el resultado del primero."""
    usuario = _usuario(_dash(h))
    tok = form.get("op") or ""
    clave = (usuario, pid, accion)
    if not _operaciones.RE_OPID.match(tok):
        tok = None
    else:
        est = _estado_token(tok, clave)
        if est is not None:
            return _repetida(h, pid, accion, est)
    if validar is not None:
        pre = validar()
        if pre is not None:
            return _responder(h, pid, pre)
    if tok:
        est = _tomar_token(tok, clave)
        if est is not None:
            return _repetida(h, pid, accion, est)
    try:
        res = hacer()
    except BaseException:
        if tok:
            _soltar_token(tok)
        raise
    if tok:
        _cerrar_token(tok, res)
    return _responder(h, pid, res)


# --------------------------------------------------------------------------------------------
# Operaciones
# --------------------------------------------------------------------------------------------
# La pagina de una operacion puede llevar la clave de la VPN de una sola vez: ni el navegador
# ni un proxy la guardan, y no se puede enmarcar (B-11). Si el nucleo ofrece
# `H._html(s, code=200, cabeceras=())`, se usa; si no, se responde aqui con los mismos pasos.
CABECERAS_PRIVADAS = (("Cache-Control", "no-store"), ("Pragma", "no-cache"),
                      ("X-Frame-Options", "DENY"), ("Content-Security-Policy", "frame-ancestors 'none'"),
                      ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "same-origin"))


def _acepta(fn, nombre):
    try:
        return nombre in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


def _html_privado(h, s, code=200):
    if _acepta(h._html, "cabeceras"):
        return h._html(s, code, cabeceras=CABECERAS_PRIVADAS)
    b = s.encode("utf-8")
    h.send_response(code)
    h.send_header("Content-Type", "text/html; charset=utf-8")
    h.send_header("Content-Length", str(len(b)))
    for k, v in CABECERAS_PRIVADAS:
        h.send_header(k, v)
    h.end_headers()
    h.wfile.write(b)


def _pasos_limpios(pasos):
    return [{k: p.get(k) for k in ("nombre", "estado", "detalle") if p.get(k) is not None} for p in pasos]


def vista_op(d, op_id, usuario):
    """Modelo de la pagina de una operacion. None si no existe o no es de este usuario."""
    rec = ops().obtener(op_id)
    if rec is None or rec.get("usuario") != usuario:
        return None
    vm = {"orden": rec.get("orden"), "pid": rec.get("pid"), "titulo": rec.get("nombre") or rec.get("pid"),
          "ros_version": rec.get("ros_version")}
    if rec.get("terminada"):
        vm.update({"terminada": True, "ok": rec.get("codigo") == "OK", "pasos": rec.get("pasos"),
                   "mensaje": _orq.traducir(rec.get("codigo"), rec.get("mensaje")),
                   "ya_existia": rec.get("ya_existia")})
        return vm
    r = cliente().pedir("op.estado", {"op_id": op_id}, quien="panel:%s" % usuario, ip=_ip(d))
    if r.get("codigo") not in ("OK", "NO_EXISTE"):
        vm.update({"terminada": False, "error_canal": _orq.traducir(r.get("codigo"), r.get("mensaje"))})
        return vm
    if r.get("codigo") == "NO_EXISTE":
        ops().terminar(op_id, codigo="FALLO", mensaje="el orquestador no conoce esta operacion")
        vm.update({"terminada": True, "ok": False,
                   "mensaje": "El orquestador no conoce esta operacion (¿se reinicio el servidor?). "
                              "Mira el estado en Puntos antes de repetirla."})
        return vm
    dd = r.get("datos") or {}
    pasos = [p for p in (dd.get("pasos") or []) if isinstance(p, dict)]
    vm.update({"pasos": pasos, "paso": dd.get("paso"), "avance": dd.get("avance"),
               "porcentaje": _porcentaje(dd.get("avance")), "delante": dd.get("delante")})
    if dd.get("estado") != "terminada":
        vm["terminada"] = False
        return vm
    codigo, mensaje = dd.get("codigo") or "FALLO", dd.get("mensaje") or ""
    res = dd.get("resultado") if isinstance(dd.get("resultado"), dict) else {}
    pid = res.get("pid") or rec.get("pid")
    ya = bool(res.get("ya_entregada"))
    primera = ops().terminar(op_id, codigo=codigo, mensaje=mensaje, pid=pid, pasos=_pasos_limpios(pasos),
                             ya_existia=ya)
    if not primera:
        # Otra peticion la cerro a la vez. El orquestador entrega la clave UNA vez, a la primera
        # op.estado que ve la operacion terminada: si vino en ESTA respuesta, solo esta peticion
        # la tiene y la ensena aunque haya perdido la carrera de `terminar` (B-12).
        rec = ops().obtener(op_id) or {}
        vm.update({"terminada": True, "ok": rec.get("codigo") == "OK", "pasos": rec.get("pasos"),
                   "mensaje": _orq.traducir(rec.get("codigo"), rec.get("mensaje"))})
        if res.get("clave"):
            vm.update({"ok": codigo == "OK", "pid": pid, "resultado": res, "ya_existia": ya,
                       "mensaje": _orq.traducir(codigo, mensaje, res)})
        return vm
    _bit(d, (rec.get("orden") or "op").upper().replace(".", "-") + "-FIN", pid=pid or "",
         resultado=codigo, extra="op=%s" % op_id)
    if codigo == "OK" and rec.get("orden") == "punto.borrar" and pid:
        barrer_bajas(d, esperar=True)
    vm.update({"terminada": True, "ok": codigo == "OK", "pid": pid, "resultado": res, "ya_existia": ya,
               "mensaje": _orq.traducir(codigo, mensaje, res)})
    return vm


def _pasos(pasos):
    if not pasos:
        return ""
    out = "<ol>"
    for p in pasos:
        ok = p.get("estado") == "ok"
        out += "<li>%s <span class=hint>%s%s</span></li>" % (
            esc(p.get("nombre")), "hecho" if ok else "fallo",
            (" &mdash; " + esc(p.get("detalle"))) if p.get("detalle") else "")
    return out + "</ol>"


def pagina_op(h, op_id):
    d = _dash(h)
    # la limpieza de las bajas no depende de quien abra la operacion (A-09)
    barrer_bajas(d)
    vm = vista_op(d, op_id, _usuario(d))
    if vm is None:
        return _html_privado(h, pagina(d, "Operacion", "<h1>Operacion desconocida</h1><p>Esa operacion no "
                                       "existe o no la pediste tu.</p>"), 404)
    tit = "<h1>%s%s</h1>" % (esc(ORDENES.get(vm.get("orden"), vm.get("orden") or "Operacion")),
                             (" &middot; " + esc(vm.get("titulo"))) if vm.get("titulo") else "")
    if not vm.get("terminada"):
        cuerpo = tit + aviso(vm.get("error_canal"), "amb")
        if vm.get("delante"):
            cuerpo += "<p>En cola: %s operacion(es) delante.</p>" % esc(vm.get("delante"))
        else:
            cuerpo += "<p>%s</p>" % esc(("Paso actual: %s (%s)" % (vm.get("paso"), vm.get("avance")))
                                        if vm.get("paso") else "Esperando al orquestador...")
        cuerpo += ("<progress max=100 value='%s'></progress>%s<p class=hint>Esta pagina se actualiza sola.</p>"
                   % (esc(vm.get("porcentaje", 0)), _pasos(vm.get("pasos"))))
        return _html_privado(h, pagina(d, "Operacion", cuerpo, refresco=2))
    cuerpo = tit + _pasos(vm.get("pasos"))
    pid = vm.get("pid")
    if not vm.get("ok"):
        cuerpo += aviso(vm.get("mensaje"))
        if vm.get("orden") == "punto.crear":
            cuerpo += "<p><a class=btn href='/puntos/nuevo'>Volver a intentarlo</a></p>"
        return _html_privado(h, pagina(d, "Operacion", cuerpo))
    if vm.get("orden") == "punto.borrar":
        cuerpo += aviso("Punto borrado: se quitaron su VPN, su Suricata y sus datos del servidor y del panel.", "ok")
        cuerpo += ("<p class=hint>En el MikroTik quedan la interfaz <code>ids-vpn</code>, la ruta, el usuario "
                   "<code>ids-api</code> y lo que lleve el comentario <code>IDS ids-maat:%s</code>: "
                   "quitalos a mano (Documentacion &rarr; Puntos).</p>"
                   "<p><a class=btn href='/puntos'>Volver a Puntos</a></p>" % esc(pid))
        return _html_privado(h, pagina(d, "Operacion", cuerpo))
    r = vm.get("resultado") or {}
    if r.get("clave"):
        cuerpo += aviso("Listo. Copia ahora la clave: el panel NO la vuelve a mostrar. Si la pierdes, "
                        "regenerala desde la ficha del punto.", "amb")
        cuerpo += ("<div class='card cred'><div><span class=hint>Usuario de la VPN</span><br>"
                   "<code id=cred-usuario>%s</code> <button type=button class='btn sec' "
                   "onclick=\"pcopiar('cred-usuario',this)\">Copiar</button></div>"
                   "<div><span class=hint>Clave de la VPN (se muestra una sola vez)</span><br>"
                   "<code id=cred-clave>%s</code> <button type=button class='btn sec' "
                   "onclick=\"pcopiar('cred-clave',this)\">Copiar</button></div></div>"
                   % (esc(r.get("usuario")), esc(r.get("clave"))))
        cuerpo += ("<h2>Comandos para el MikroTik</h2><p class=hint>Ya llevan la clave de la VPN. "
                   "<code>&lt;CLAVE-API&gt;</code> es la clave que elijas para el usuario de la API del router; "
                   "despues ponla en la ficha del punto (API).</p>")
        cuerpo += comandos_html(r.get("comandos", ""), vm.get("ros_version"), "op")
    elif vm.get("orden") == "punto.crear" and (r.get("ya_entregada") or vm.get("ya_existia")):
        cuerpo += aviso("Ese punto ya existia con los mismos datos. La clave de la VPN ya se entrego; si no "
                        "la tienes, regenerala desde la ficha del punto.", "amb")
    elif vm.get("orden") == "punto.ajustar":
        cuerpo += aviso("Prefijos cambiados en el Suricata del punto. Falta llevarlos al MikroTik: vuelve a "
                        "aplicar el espejo (address-list ids-vigilados) desde la ficha, con su vista previa.", "info")
    else:
        cuerpo += aviso("La operacion termino bien. Si mostraba una clave, ya se enseño una vez y el panel "
                        "no la guarda.", "info")
    if pid and nodos.pid_valido(pid):
        ancla = "#espejo" if vm.get("orden") == "punto.ajustar" else ""
        cuerpo += "<p><a class=btn href='/puntos/%s%s'>Ir a la ficha del punto</a></p>" % (esc(pid), ancla)
    return _html_privado(h, pagina(d, "Operacion", cuerpo))


def _encolar(h, pid, orden, params, nombre=None, token="", al_fallar=None):
    """Una orden de cola del orquestador -> 303 a su avance. El op_id es el token del formulario
    (A-08, como el alta): el mismo formulario enviado dos veces lleva a la misma operacion y el
    orquestador no la encola dos veces. Sin token valido (cliente viejo), uno nuevo."""
    d = _dash(h)
    usuario = _usuario(d)
    p = nodos.punto(pid) or {}
    op_id = token if _operaciones.RE_OPID.match(token or "") else str(uuid.uuid4())
    previa = _reservar_op(op_id, usuario, orden, pid=pid, nombre=nombre or p.get("nombre") or pid,
                          ros_version=p.get("ros_version"))
    if previa is not None:
        if (previa.get("usuario"), previa.get("orden"), previa.get("pid")) != (usuario, orden, pid):
            return ficha(h, pid, "Ese formulario ya se uso para otra orden u otro punto. Recarga la ficha.", 409)
        _bit(d, orden.upper().replace(".", "-"), pid=pid, resultado="REPETIDA", extra="op=%s" % op_id)
        return h._redirect("/operaciones/%s" % op_id)
    r = cliente().pedir(orden, params, quien="panel:%s" % usuario, ip=_ip(d), op_id=op_id)
    _bit(d, orden.upper().replace(".", "-"), pid=pid, resultado=r.get("codigo"), extra="op=%s" % op_id)
    if r.get("codigo") in ("ACEPTADA", "OK"):
        return h._redirect("/operaciones/%s" % op_id)
    ops().quitar(op_id)
    if al_fallar is not None:
        al_fallar(pid)
    return ficha(h, pid, _orq.traducir(r.get("codigo"), r.get("mensaje"), r.get("datos")), 409)


# --------------------------------------------------------------------------------------------
# Baja: lo del panel (A-09)
# --------------------------------------------------------------------------------------------
# La limpieza del panel tras una baja no depende de que quien la pidio abra su operacion:
# `barrer_bajas` mira las bajas que pidio el panel (cualquier usuario) y el estado del
# orquestador, y la llaman la lista de Puntos (cada 30 s mientras alguien la mira), cualquier
# pagina de operacion y, si el nucleo lo hace, su tarea de fondo. Un punto se limpia cuando:
#   - el orquestador confirma su baja (op.estado OK), aunque estado.json aun lo liste;
#   - el panel pidio su baja y ya no esta en un estado.json reciente (orquestador reiniciado:
#     la operacion se perdio pero la baja se hizo);
#   - sin baja del panel (CLI): falta de dos estado.json recientes distintos separados al menos
#     BAJA_PERSISTENCIA_S (un estado suelto o viejo no borra nada).
# Nunca se toca un punto que esta en estado.json salvo con la confirmacion del orquestador. Lo
# limpiado se apunta en estado/bajas-purgadas.json: si una tarea de fondo vuelve a crear
# nodos/<pid>/ de un punto dado de baja, se quita otra vez sin repetir la purga.
BAJA_PERSISTENCIA_S = 60
ESTADO_FRESCO_S = 60
_BAJAS_LOCK = threading.Lock()
_AUSENTES = {}               # pid -> (ts del estado.json, instante) de la primera vez que faltaba


def _ruta_purgadas():
    return os.path.join(nodos.ESTADO, "bajas-purgadas.json")


def _leer_purgadas():
    try:
        with open(_ruta_purgadas(), encoding="utf-8") as f:
            dd = json.load(f)
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in dd.items() if nodos.pid_valido(k)} if isinstance(dd, dict) else {}


def _guardar_purgadas(dd):
    p = _ruta_purgadas()
    tmp = "%s.%d.%d.tmp" % (p, os.getpid(), threading.get_ident())
    try:
        os.makedirs(nodos.ESTADO, mode=0o700, exist_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(dd, f, sort_keys=True)
        os.replace(tmp, p)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _ops_baja():
    """[(op_id, registro)] de las bajas que pidio el panel, de cualquier usuario."""
    o = ops()
    lock, datos = getattr(o, "_lock", None), getattr(o, "_ops", None)
    if lock is None or not isinstance(datos, dict):
        return []
    with lock:
        items = [(k, dict(v)) for k, v in datos.items() if isinstance(v, dict)]
    return [(k, v) for k, v in items if v.get("orden") == "punto.borrar" and nodos.pid_valido(v.get("pid") or "")]


def _confirmar_baja(d, op_id, rec):
    """Pregunta al orquestador por una baja aun abierta. True si termino bien."""
    r = cliente().pedir("op.estado", {"op_id": op_id}, quien="panel:barrido-bajas", ip=_ip(d))
    if r.get("codigo") == "NO_EXISTE":
        ops().terminar(op_id, codigo="FALLO", mensaje="el orquestador no conoce esta operacion")
        return False
    dd = (r.get("datos") or {}) if r.get("codigo") == "OK" else {}
    if dd.get("estado") != "terminada":
        return False
    codigo = dd.get("codigo") or "FALLO"
    pasos = [p for p in (dd.get("pasos") or []) if isinstance(p, dict)]
    if ops().terminar(op_id, codigo=codigo, mensaje=dd.get("mensaje") or "", pid=rec.get("pid"),
                      pasos=_pasos_limpios(pasos)):
        _bit(d, "PUNTO-BORRAR-FIN", pid=rec.get("pid") or "", resultado=codigo, extra="op=%s barrido" % op_id)
    return codigo == "OK"


def _candidatos(d):
    """pids que tienen algo en el panel: nodos/<pid>/, routers.json y registros de enviados."""
    pids = set()
    try:
        pids |= {x for x in os.listdir(nodos.NODOS) if nodos.pid_valido(x)}
    except OSError:
        pass
    leer = getattr(d, "_routers_guardados", None)
    if callable(leer):
        try:
            pids |= {k for k in leer() if nodos.pid_valido(k)}
        except Exception:
            pass
    if callable(getattr(d, "cargar_enviados", None)):
        for nom in ("MK_SENT", "MK_SENT_DNS", "MK_SENT_GRAD"):
            reg = getattr(d, nom, None)
            if not reg:
                continue
            try:
                pids |= {k.split("|", 1)[0] for k in d.cargar_enviados(reg) if "|" in k}
            except Exception:
                pass
    return {x for x in pids if nodos.pid_valido(x)}


def _quitar_restos(pid):
    dirp = os.path.join(nodos.NODOS, pid)
    if os.path.isdir(dirp) and not os.path.islink(dirp):
        shutil.rmtree(dirp, ignore_errors=True)


def barrer_bajas(d, ahora=None, esperar=False):
    """Limpia del panel los puntos dados de baja (ver arriba). Devuelve los pids limpiados.
    Si otro hilo esta barriendo, no espera (salvo `esperar`) y devuelve []."""
    if not _BAJAS_LOCK.acquire(blocking=esperar):
        return []
    try:
        return _barrer(d, time.time() if ahora is None else ahora)
    except Exception:
        return []
    finally:
        _BAJAS_LOCK.release()


def _barrer(d, ahora):
    est = nodos.leer_estado() or {}
    vivos = est.get("puntos") if isinstance(est.get("puntos"), dict) else None
    try:
        ts_est = float(est.get("ts"))
    except (TypeError, ValueError):
        ts_est = None
    fresco = vivos is not None and ts_est is not None and abs(ahora - ts_est) <= ESTADO_FRESCO_S
    vivos = set(vivos or ())
    confirmadas, pedidas = set(), set()
    for op_id, rec in _ops_baja():
        pid = rec["pid"]
        if rec.get("terminada"):
            (confirmadas if rec.get("codigo") == "OK" else pedidas).add(pid)
        elif _confirmar_baja(d, op_id, rec):
            confirmadas.add(pid)
        else:
            pedidas.add(pid)
    pedidas -= confirmadas
    purgadas = _leer_purgadas()
    cambio, hechos = False, []
    for pid in sorted(_candidatos(d) | confirmadas | pedidas | set(purgadas)):
        vivo = pid in vivos
        if pid in purgadas:
            if vivo and pid not in confirmadas:
                purgadas.pop(pid, None)    # vuelve a estar (los pid no se reutilizan: raro)
                cambio = True
            elif not vivo:
                _quitar_restos(pid)
            continue
        if pid in confirmadas:
            motivo = "baja terminada en el orquestador"
        elif vivo:
            _AUSENTES.pop(pid, None)
            continue
        elif not fresco:
            continue
        elif pid in pedidas:
            motivo = "baja pedida desde el panel; el punto ya no esta en estado.json"
        else:
            prev = _AUSENTES.get(pid)
            if prev is None:
                _AUSENTES[pid] = (ts_est, ahora)
                continue
            if ts_est == prev[0] or ahora - prev[1] < BAJA_PERSISTENCIA_S:
                continue
            motivo = "falta de estado.json desde hace %d s (baja fuera del panel)" % int(ahora - prev[1])
        if limpiar_punto(d, pid, motivo):
            purgadas[pid] = int(ahora)
            cambio = True
            hechos.append(pid)
        _AUSENTES.pop(pid, None)
    if cambio:
        _guardar_purgadas(purgadas)
    return hechos


def limpiar_punto(d, pid, motivo=""):
    """Tras la baja en el orquestador: fuera nodos/<pid>/, su router y sus claves pid|... .
    True si se pudo (la purga del nucleo no fallo)."""
    if not nodos.pid_valido(pid):
        return False
    hecho, ok = [], True
    dirp = os.path.join(nodos.NODOS, pid)
    if (os.path.isdir(dirp) and not os.path.islink(dirp)
            and os.path.dirname(os.path.abspath(dirp)) == os.path.abspath(nodos.NODOS)):
        shutil.rmtree(dirp, ignore_errors=True)
        hecho.append("salidas")
    purgar = getattr(d, "purgar_punto", None)
    if purgar is not None:
        try:
            purgar(pid)
            hecho.append("registros")
        except Exception as e:
            ok = False
            hecho.append("registros: fallo %s" % str(e)[:80])
    else:
        try:
            d.guardar_routers([r for r in d.cargar_routers() if r.get("id") != pid])
            hecho.append("router")
        except Exception:
            pass
        for nom in ("MK_SENT", "MK_SENT_DNS", "MK_SENT_GRAD"):
            reg = getattr(d, nom, None)
            if not reg:
                continue
            try:
                claves = [k for k in d.cargar_enviados(reg) if k.startswith(pid + "|")]
                if claves:
                    d.quitar_enviados(claves, reg)
            except Exception:
                pass
        hecho.append("enviados")
    _bit(d, "PUNTO-BAJA-PANEL", pid=pid, resultado="ok" if ok else "parcial",
         extra=("borrado=" + ",".join(hecho) + ((" motivo=" + motivo) if motivo else "")))
    return ok


# --------------------------------------------------------------------------------------------
# Ficha
# --------------------------------------------------------------------------------------------
def _router(d, pid):
    try:
        for r in d.cargar_routers():
            if r.get("id") == pid:
                return r
    except Exception:
        pass
    return None


def _textos(v):
    if v is None or v == "":
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, dict):
        v = [v]
    if not isinstance(v, (list, tuple)):
        return [str(v)]
    out = []
    for x in v:
        if isinstance(x, dict):
            x = x.get("que") or x.get("texto") or json.dumps(x, ensure_ascii=False, sort_keys=True)
        out.append(str(x))
    return out


def plan_lineas(res):
    """(ok, mensaje, lineas del plan, avisos) de lo que devuelva espejo_plan/aplicar/... .
    Las ordenes salen de `lineas` y, si no vienen, de `terminal` (lo que devuelve
    mikrotik_init.plan(): A-01). Una clave que no es texto ni lista (p. ej. el `plan`
    recalculado que devuelve aplicar) no se toma por ordenes."""
    if isinstance(res, tuple):
        ok = bool(res[0]) if res else False
        msg = str(res[1]) if len(res) > 1 else ""
        extra = res[2] if len(res) > 2 else None
        res = extra if isinstance(extra, dict) else {"lineas": extra} if extra is not None else {}
        res = dict(res, ok=ok, mensaje=msg)
    if isinstance(res, str):
        return True, "", res.splitlines(), []
    if not isinstance(res, dict):
        return False, "respuesta ilegible", [], []
    lin = []
    for k in ("lineas", "terminal", "comandos", "rsc", "plan"):
        v = res.get(k)
        if isinstance(v, str) and v.strip():
            lin = v.splitlines()
            break
        if isinstance(v, (list, tuple)) and v:
            lin = list(v)
            break
    return bool(res.get("ok", True)), str(res.get("mensaje") or res.get("msg") or ""), \
        [str(x) for x in lin], _textos(res.get("avisos"))


RE_HUELLA_PLAN = re.compile(r"[0-9a-f]{16,64}")


def plan_espejo(res):
    """La vista previa del espejo normalizada para la ficha (A-01):
    {ok, mensaje, lineas, avisos, bloqueos, fasttrack, huella, huella_nucleo, accept}.

    Contrato con el nucleo (`espejo_plan(pid)`): un dict con al menos ok, mensaje y las ordenes
    (`lineas`, o `terminal` como lo da mikrotik_init); si trae `bloqueos` (lista de textos),
    `fasttrack` (lista de {que, accion, ...}) y `huella` (hex de 16 a 64, la de SU plan), se
    usan; si no, se degrada: sin bloqueos y huella = sha256 de las lineas mostradas."""
    ok, msg, lineas, avisos = plan_lineas(res)
    dd = res if isinstance(res, dict) else {}
    fast = dd.get("fasttrack")
    if isinstance(fast, dict):            # forma del respaldo: {".id": {...}}
        fast = [dict(v, **{".id": k}) if isinstance(v, dict) else {"que": "%s: %s" % (k, v)}
                for k, v in fast.items()]
    hn = dd.get("huella")
    hn = hn if isinstance(hn, str) and RE_HUELLA_PLAN.fullmatch(hn) else None
    return {"ok": ok, "mensaje": msg, "lineas": lineas, "avisos": avisos,
            "bloqueos": _textos(dd.get("bloqueos")),
            "fasttrack": [x for x in _textos(fast) if x],
            "huella": hn or _huella_plan(lineas), "huella_nucleo": hn,
            "accept": tiene_accept(lineas) or _cambios_con_accept(dd.get("cambios"))}


def tiene_accept(lineas):
    """El espejo NUNCA puede autorizar trafico: ninguna linea con action=accept (OPERACION §2)."""
    return any(re.search(r"\baction\s*=\s*accept\b", x) for x in lineas)


def _cambios_con_accept(cambios):
    """Lo mismo sobre los cambios estructurados del plan ({"orden", "args": ["=action=accept"]})."""
    if not isinstance(cambios, (list, tuple)):
        return False
    for c in cambios:
        args = c.get("args") if isinstance(c, dict) else None
        if isinstance(args, (list, tuple)) and any(re.fullmatch(r"=action=accept\s*", str(a)) for a in args):
            return True
    return False


def ficha(h, pid, mensaje="", codigo=200, ok=False, extra_espejo=""):
    d = _dash(h)
    p = nodos.punto(pid) or {}
    nombre = p.get("nombre") or pid
    ahora = time.time()
    sal = salud(getattr(d, "salud_punto", None), pid)
    pps, ultimo = espejo_pps(pid)
    su = p.get("suricata") or {}
    vc = p.get("vpn_cliente") or {}
    cont = p.get("contenedores") or {}
    n24, completo = alertas_24h(pid, ahora)
    datos = "".join(
        "<div class=dato><div class=et>%s</div><div>%s</div></div>" % (esc(a), b) for a, b in (
            ("Estado", esc(ESTADOS.get(p.get("estado"), p.get("estado") or "sin datos"))
             + "".join("<div class=pwarn>%s</div>" % esc(AVISOS.get(x, x)) for x in (p.get("avisos") or []))),
            ("Salud", salud_chip(sal)),
            ("VPN", esc(_contenedor(cont.get("vpn"))) + " &middot; MikroTik "
             + ("conectado desde %s" % esc(vc.get("ip_real") or "?") if vc.get("conectado") else "desconectado")),
            ("Espejo", ("%.0f paq/s" % pps if pps is not None else "sin medida")
             + (" &middot; ultimo hace %s" % _edad(ahora - ultimo) if ultimo else "")),
            ("Suricata", esc(_contenedor(cont.get("suricata"))) + " &middot; %s / %s paquetes vistos/descartados"
             % (_num(su.get("kernel_packets")), _num(su.get("kernel_drops")))),
            ("Alertas 24 h", "<a href='/eventos?nodo=%s'>%s%s</a>" % (esc(pid), _num(n24), "+" if not completo else "")),
            ("Retencion efectiva", retencion_html(retencion(pid, p), ahora)),
            ("Puerto VPN / red del tunel", esc("%s/tcp · %s" % (p.get("puerto") or "-", p.get("tun_net") or "-"))),
            ("Perfil / RouterOS", esc("%s · v%s" % (p.get("perfil") or "-", p.get("ros_version") or "-"))),
            ("Prefijos espejados", esc(", ".join(p.get("redes") or []) or "-")),
        ))
    # VPN: comandos sin la clave
    r = cliente().pedir("punto.comandos", {"pid": pid}, quien="panel:%s" % _usuario(d), ip=_ip(d))
    cmds = (r.get("datos") or {}).get("comandos") if r.get("codigo") == "OK" else None
    vpn_html = (comandos_html(cmds, p.get("ros_version"), "ficha") if cmds else
                aviso("No se pudieron obtener los comandos: %s" % _orq.traducir(r.get("codigo"), r.get("mensaje")),
                      "amb"))
    # API
    rt = _router(d, pid) or {}
    hu = cliente().pedir("punto.api.huella", {"pid": pid}, quien="panel:%s" % _usuario(d), ip=_ip(d))
    huella = (hu.get("datos") or {}).get("sha256") if hu.get("codigo") == "OK" else ""
    fijada = (rt.get("CERT_FP") or "").lower().replace(":", "")
    api_html = (
        "<form method=post action='/puntos/%s/api'><input type=hidden name=accion value=guardar>%s"
        "<div class=datos><div><label class=l>Usuario de la API</label>"
        "<input class=t name=user value='%s' maxlength=64 autocomplete=off></div>"
        "<div><label class=l>Clave de la API %s</label>"
        "<input class=t type=password name=pass autocomplete=new-password placeholder='%s'></div></div>"
        "<label><input type=checkbox name=enabled value=1%s> Permitir enviar IPs a este MikroTik "
        "(cuarentena)</label>"
        "<div class=acciones><button class=btn type=submit>Guardar</button>"
        "<button class='btn sec' type=submit name=accion value=probar>Probar la conexion</button></div></form>"
        "<p class=hint>La conexion va por el relé del tunel del punto (API-SSL, puerto %s del router) con TLS "
        "extremo a extremo. La clave se guarda cifrada con la clave maestra y no se vuelve a mostrar.</p>"
        "<p class=hint>Huella del certificado que ve el servidor: <code>%s</code><br>Huella fijada en el panel: "
        "<code>%s</code></p>%s"
        % (esc(pid), campo_token(), esc(rt.get("USER", "")), "(guardada)" if rt.get("PASS") else "",
           "dejar vacio para conservar" if rt.get("PASS") else "clave del usuario ids-api",
           " checked" if rt.get("ENABLED") == "1" else "", esc(p.get("api_puerto") or 8729),
           esc(huella or "sin dato"), esc(fijada or "ninguna (se fija en la primera conexion)"),
           ("<form method=post action='/puntos/%s/api' onsubmit=\"return ask(this,'Olvidar la huella',"
            "'La proxima conexion fijara la huella que presente el router. Hazlo solo si cambiaste su "
            "certificado.','Olvidar','danger')\"><input type=hidden name=accion value=olvidar_huella>%s"
            "<button class='btn sec' type=submit>Olvidar la huella fijada</button></form>" % (esc(pid), campo_token()))
           if fijada else ""))
    # Espejo
    espejo_html = (
        "<p class=sub>Copia hacia el sensor del trafico de los prefijos elegidos (primeros 10 KB de cada "
        "conexion), por el tunel. Nunca anade reglas <code>accept</code>: no autoriza nada que tu firewall "
        "rechazaba. Siempre con vista previa y respaldo (export en el router y copia en el panel).</p>"
        + extra_espejo +
        "<div class=acciones>"
        "<form method=post action='/puntos/%s/espejo'><input type=hidden name=accion value=plan>"
        "<button class=btn type=submit>Ver el plan (vista previa)</button></form>"
        "<form method=post action='/puntos/%s/espejo' onsubmit=\"return ask(this,'Pausar el espejo',"
        "'Se deshabilitan las dos reglas mangle del punto. El fasttrack queda como esta.','Pausar')\">"
        "<input type=hidden name=accion value=pausar>%s<button class='btn sec' type=submit>Pausar</button></form>"
        "<form method=post action='/puntos/%s/espejo' onsubmit=\"return ask(this,'Retirar el espejo',"
        "'Se borra lo que lleva el comentario del punto y la regla fasttrack recupera sus valores del "
        "respaldo. No toca reglas ajenas.','Retirar','danger')\">"
        "<input type=hidden name=accion value=retirar>%s<button class='btn sec' type=submit>Retirar</button></form>"
        "</div>" % (esc(pid), esc(pid), campo_token(), esc(pid), campo_token()))
    # Prefijos
    pref_html = (
        "<form method=post action='/puntos/%s/ajustar' onsubmit=\"return ask(this,'Cambiar los prefijos',"
        "'El Suricata del punto se recrea con los prefijos nuevos. Despues vuelve a aplicar el espejo para "
        "llevarlos al MikroTik.','Cambiar')\">%s"
        "<label class=l>Prefijos de abonados (uno por linea)</label>"
        "<textarea class=t name=redes rows=4>%s</textarea>"
        "<div class=acciones><button class=btn type=submit>Guardar prefijos</button></div></form>"
        % (esc(pid), campo_token(), esc("\n".join(p.get("redes") or []))))
    # Servicio
    serv = "".join(
        "<form method=post action='/puntos/%s/%s' onsubmit=\"return ask(this,'%s','%s','%s'%s)\">%s"
        "<button class='btn sec' type=submit>%s</button></form>"
        % (esc(pid), acc, tit, txt, tit, ",'danger'" if acc == "parar" else "", campo_token(), tit)
        for acc, tit, txt in (
            ("arrancar", "Arrancar", "Arranca la VPN y el Suricata del punto."),
            ("reiniciar", "Reiniciar", "Reinicia la VPN y el Suricata del punto: el espejo se corta unos segundos."),
            ("parar", "Parar", "Para la VPN y el Suricata del punto: deja de vigilarse hasta que lo arranques."),
            ("regenerar", "Regenerar la clave VPN", "Se crea una clave nueva y la VPN actual del MikroTik se corta "
                                                    "hasta que pongas la nueva en el router.")))
    baja = (
        "<div class=card style='border-color:#f3c4c4'><h2>Dar de baja el punto</h2>"
        "<p>Quita del servidor su VPN, su Suricata y <b>todos sus datos</b>, y del panel sus salidas, su "
        "conexion y sus registros. No se puede deshacer.</p>"
        "<p class=hint>Antes, mientras el tunel sigue arriba, el panel limpia el MikroTik: retira el espejo "
        "(devuelve el fasttrack como estaba) y saca de sus address-lists las IPs que puso en cuarentena y los "
        "destinos bloqueados. Si el router no responde, la baja <b>no sigue</b> y te dice que falta; si ese "
        "router ya no existe, desmarca la casilla.</p>"
        "<form method=post action='/puntos/%s/borrar' data-nombre='%s'>%s"
        "<label class=l><input type=checkbox name=limpiar_router value=1 checked> Limpiar antes el MikroTik "
        "(espejo y cuarentena)</label>"
        "<label class=l>Para confirmar, escribe el nombre del punto: <b>%s</b></label>"
        "<input class=t name=confirmar autocomplete=off maxlength=31 oninput='pnombre(this)'>"
        "<div class=acciones><button class='btn peligro' type=submit disabled>Dar de baja</button></div></form>"
        "</div>" % (esc(pid), esc(nombre), campo_token(), esc(nombre)))
    cuerpo = (
        "<div class=ptit><h1>%s <span class=hint>%s</span></h1><a class='btn sec' href='/puntos'>Volver a "
        "Puntos</a></div>%s%s"
        "<nav class=secnav><a href='#resumen'>Resumen</a><a href='#vpn'>VPN</a><a href='#api'>API</a>"
        "<a href='#espejo'>Espejo</a><a href='#prefijos'>Prefijos</a><a href='/puntos/%s/logs?parte=vpn'>Logs</a>"
        "<a href='#baja'>Baja</a></nav>"
        "<section class=card id=resumen><h2>Resumen</h2><div class=datos>%s</div>"
        "<h3 style='font-size:14px'>Salud por etapas</h3>%s</section>"
        "<section class=card><h2>Servicio</h2><div class=acciones>%s</div></section>"
        "<section class=card id=vpn><h2>VPN: comandos para el MikroTik</h2><p class=hint>Sin la clave: donde dice "
        "<code>&lt;CLAVE-VPN&gt;</code> va la que se mostro al crear el punto.</p>%s</section>"
        "<section class=card id=api><h2>API del MikroTik</h2>%s</section>"
        "<section class=card id=espejo><h2>Espejo</h2>%s</section>"
        "<section class=card id=prefijos><h2>Prefijos del espejo</h2>%s</section>"
        "<div id=baja>%s</div>"
        % (esc(nombre), esc(pid), aviso(mensaje, "ok" if ok else "err"),
           "" if p else aviso("El punto aun no aparece en el estado del orquestador (se actualiza cada 15 s).", "info"),
           esc(pid), datos, salud_etapas_html(sal), serv, vpn_html, api_html, espejo_html, pref_html, baja))
    return h._html(pagina(d, nombre, cuerpo), codigo)


def logs(h, pid, consulta):
    d = _dash(h)
    parte = consulta.get("parte") if consulta.get("parte") in ("vpn", "suricata") else "vpn"
    r = cliente().pedir("punto.logs", {"pid": pid, "parte": parte, "lineas": 200},
                        quien="panel:%s" % _usuario(d), ip=_ip(d))
    lineas = (r.get("datos") or {}).get("lineas") if r.get("codigo") == "OK" else None
    _bit(d, "PUNTO-LOGS", pid=pid, objetivo=parte, resultado=r.get("codigo"))
    cuerpo = ("<div class=ptit><h1>Logs de %s <span class=hint>%s</span></h1>"
              "<a class='btn sec' href='/puntos/%s'>Volver a la ficha</a></div>"
              "<nav class=secnav><a href='?parte=vpn'>VPN</a><a href='?parte=suricata'>Suricata</a></nav>%s"
              % (esc(nodos.nombre(pid)), esc(parte), esc(pid),
                 ("<pre class=cmd>%s</pre>" % esc("\n".join(str(x) for x in lineas))) if lineas is not None else
                 aviso(_orq.traducir(r.get("codigo"), r.get("mensaje")), "amb")))
    return h._html(pagina(d, "Logs", cuerpo))


# --------------------------------------------------------------------------------------------
# Acciones de la ficha
# --------------------------------------------------------------------------------------------
def accion_api(h, pid, form):
    """Guardar, probar u olvidar la huella de la API del router del punto. Un solo uso por
    formulario (A-08)."""
    d = _dash(h)
    acc = form.get("accion") or "guardar"
    if acc not in ("guardar", "probar", "olvidar_huella"):
        return ficha(h, pid, "Accion de la API desconocida.", 400)
    user = (form.get("user") or "").strip()[:64]

    def validar():
        if not any(x.get("id") == pid for x in d.cargar_routers()):
            return ("Ese punto todavia no tiene router en el panel (espera a que aparezca en el "
                    "estado del orquestador).", 409, False, "")
        if acc != "olvidar_huella" and user and not re.match(r"^[A-Za-z0-9._@-]+\Z", user):
            return "El usuario de la API tiene caracteres no validos.", 400, False, ""
        return None

    def hacer():
        rs = d.cargar_routers()
        r = next((x for x in rs if x.get("id") == pid), None)
        if r is None:
            return ("Ese punto todavia no tiene router en el panel (espera a que aparezca en el "
                    "estado del orquestador).", 409, False, "")
        if acc == "olvidar_huella":
            r["CERT_FP"] = ""
            d.guardar_routers(rs)
            _bit(d, "PUNTO-API", pid=pid, objetivo="huella", resultado="olvidada")
            return "Huella olvidada: la proxima conexion fijara la del router.", 200, True, ""
        r["USER"] = user
        if form.get("pass"):
            r["PASS"] = form["pass"]             # guardar_routers la cifra (router:<pid>:PASS)
        r["ENABLED"] = "1" if form.get("enabled") else "0"
        try:
            d.guardar_routers(rs)
        except Exception as e:
            return "No se pudo guardar: %s" % str(e)[:160], 500, False, ""
        if acc != "probar":
            _bit(d, "PUNTO-API", pid=pid, objetivo="conexion", resultado="guardada",
                 extra="usuario=%s enviar=%s" % (user or "-", r["ENABLED"]))
            return "Conexion de la API guardada.", 200, True, ""
        ok, msg = probar_api(d, pid)
        _bit(d, "PUNTO-API", pid=pid, objetivo="probar", resultado="ok" if ok else "fallo")
        return "Prueba: " + msg, 200 if ok else 502, ok, ""
    return _con_token(h, pid, "api-" + acc, form, hacer, validar)


def probar_api(d, pid):
    r = _router(d, pid)
    if not r or not (r.get("USER") and r.get("PASS")):
        return False, "Falta el usuario o la clave de la API del punto."
    try:
        s = d.mk_conectar(d.cargar_mk_de(r))
        try:
            d._mk_send(s, ["/system/identity/print"])
            ok, frases, err = d._mk_reply(s)
        finally:
            try:
                s.close()
            except Exception:
                pass
        nombre = ""
        for f in frases or []:
            for a in f:
                if a.startswith("=name="):
                    nombre = a[len("=name="):]
        return (True, "conexion OK con '%s'." % (nombre or pid)) if ok else (False, err or "sin respuesta")
    except Exception as e:
        return False, "no conecto: %s" % str(e)[:200]


def _plan_html(pe, pid, con_boton=False, titulo=""):
    """La vista previa del espejo (A-01): las ordenes que se aplicarian, los cambios del
    fasttrack, los avisos y los bloqueos. El boton Aplicar solo con un plan que se puede aplicar
    (ok, con ordenes, sin bloqueos, sin accept) y con la huella de ESTE plan."""
    out = ""
    if titulo:
        out += "<p><b>%s</b></p>" % esc(titulo)
    if pe["mensaje"]:
        out += aviso(pe["mensaje"], "info" if pe["ok"] else "err")
    for b in pe["bloqueos"]:
        out += aviso("Bloqueo: " + b, "err")
    for a in pe["avisos"]:
        out += aviso(a, "amb")
    if pe["fasttrack"]:
        out += ("<p class=hint>Reglas fasttrack del router:</p><ul class=etapas>%s</ul>"
                % "".join("<li>%s</li>" % esc(x) for x in pe["fasttrack"]))
    if pe["lineas"]:
        out += "<pre class=cmd id=plan-%s>%s</pre>" % (esc(pid), esc("\n".join(pe["lineas"])))
    elif pe["ok"] and not pe["bloqueos"]:
        out += aviso("El plan no tiene ordenes: el espejo del router ya esta como pide el punto.", "info")
    if con_boton and pe["ok"] and pe["lineas"] and not pe["bloqueos"] and not pe["accept"]:
        out += ("<form method=post action='/puntos/%s/espejo' onsubmit=\"return ask(this,'Aplicar el espejo',"
                "'Se respalda el firewall (export en el router y copia en el panel) y se aplican exactamente "
                "estas %d ordenes.','Aplicar')\"><input type=hidden name=accion value=aplicar>%s"
                "<input type=hidden name=plan value='%s'>"
                "<button class=btn type=submit>Aplicar este plan</button></form>"
                % (esc(pid), len(pe["lineas"]), campo_token(), esc(pe["huella"])))
    return out


def _resultado_html(res, pid):
    """Lo que hizo aplicar/pausar/retirar: lineas hecho/SIN APLICAR y avisos; si el router cambio
    desde la vista previa, el plan nuevo (sin boton: hay que volver a pedir la vista previa)."""
    ok, _msg, lineas, avisos = plan_lineas(res)
    out = "".join(aviso(a, "amb") for a in avisos)
    if lineas:
        out += "<pre class=cmd id=resultado-%s>%s</pre>" % (esc(pid), esc("\n".join(lineas)))
    nuevo = res.get("plan") if isinstance(res, dict) else None
    if isinstance(nuevo, dict):
        out += _plan_html(plan_espejo(nuevo), pid, titulo="El router cambio: este seria el plan ahora "
                                                          "(pide otra vez la vista previa para aplicarlo)")
    return out


def _huella_plan(lineas):
    return hashlib.sha256("\n".join(lineas).encode("utf-8")).hexdigest()[:32]


MSG_ACCEPT = ("El plan incluye una regla accept y el espejo nunca puede autorizar trafico: no se aplica. "
              "Avisa al soporte.")


def accion_espejo(h, pid, form):
    """Vista previa, aplicar, pausar y retirar el espejo del punto.

    Contrato con el nucleo: `espejo_plan(pid)` -> dict (ver `plan_espejo`); `espejo_aplicar(pid)`
    o, si lo admite, `espejo_aplicar(pid, huella=<la de su plan>)` para que aplique ese plan y no
    uno recalculado distinto (A-21); `espejo_pausar(pid)`, `espejo_retirar(pid)` -> dict con ok,
    mensaje, lineas, avisos (y `plan` si el router cambio)."""
    d = _dash(h)
    acc = form.get("accion") or "plan"
    nombres = {"plan": "espejo_plan", "aplicar": "espejo_aplicar", "pausar": "espejo_pausar",
               "retirar": "espejo_retirar"}
    if acc not in nombres:
        return ficha(h, pid, "Accion de espejo desconocida.", 400)
    fplan = getattr(d, "espejo_plan", None)
    fn = getattr(d, nombres[acc], None)
    if fn is None or fplan is None:
        return ficha(h, pid, "El montaje del espejo no esta disponible en este panel.", 501)
    if acc == "plan":
        try:
            pe = plan_espejo(fplan(pid))
        except Exception as e:
            return ficha(h, pid, "No se pudo calcular el plan: %s" % str(e)[:200], 502)
        if pe["accept"]:
            _bit(d, "ESPEJO-PLAN", pid=pid, resultado="rechazado-accept")
            return ficha(h, pid, MSG_ACCEPT, 500, extra_espejo=_plan_html(pe, pid))
        _bit(d, "ESPEJO-PLAN", pid=pid, resultado="ok" if pe["ok"] else "fallo",
             extra="lineas=%d bloqueos=%d" % (len(pe["lineas"]), len(pe["bloqueos"])))
        return ficha(h, pid, extra_espejo=_plan_html(pe, pid, con_boton=True))
    visto = {}

    def validar():
        if acc != "aplicar":
            return None
        try:
            pe = plan_espejo(fplan(pid))
        except Exception as e:
            return "No se pudo calcular el plan: %s" % str(e)[:200], 502, False, ""
        if pe["accept"]:
            _bit(d, "ESPEJO-APLICAR", pid=pid, resultado="rechazado-accept")
            return MSG_ACCEPT, 500, False, _plan_html(pe, pid)
        if not pe["ok"]:
            return ("No se pudo calcular el plan: %s" % (pe["mensaje"] or "sin detalle"), 502, False,
                    _plan_html(pe, pid))
        if pe["bloqueos"]:
            _bit(d, "ESPEJO-APLICAR", pid=pid, resultado="bloqueado")
            return ("El plan tiene bloqueos: no se aplica. Resuelvelos en el router y vuelve a pedir la vista "
                    "previa.", 409, False, _plan_html(pe, pid))
        if not pe["lineas"]:
            _bit(d, "ESPEJO-APLICAR", pid=pid, resultado="plan-vacio")
            return "No hay nada que aplicar: el espejo del router ya esta como pide el plan.", 409, False, \
                _plan_html(pe, pid)
        if (form.get("plan") or "") != pe["huella"]:
            _bit(d, "ESPEJO-APLICAR", pid=pid, resultado="plan-cambiado")
            return ("El plan cambio desde la vista previa (el router o los prefijos se movieron). Revisa el "
                    "plan nuevo antes de aplicarlo.", 409, False, _plan_html(pe, pid, con_boton=True))
        visto["pe"] = pe
        return None

    def hacer():
        kw = {}
        pe = visto.get("pe")
        if pe and pe["huella_nucleo"] and _acepta(fn, "huella"):
            kw["huella"] = pe["huella_nucleo"]
        try:
            res = fn(pid, **kw)
        except Exception as e:
            res = {"ok": False, "mensaje": "no se pudo: %s" % str(e)[:200]}
        ok, msg, _lineas, _avisos = plan_lineas(res)
        _bit(d, "ESPEJO-" + acc.upper(), pid=pid, resultado="ok" if ok else "fallo", extra=msg[:120])
        return msg or ("Hecho." if ok else "No se pudo."), 200 if ok else 502, ok, _resultado_html(res, pid)
    return _con_token(h, pid, "espejo-" + acc, form, hacer, validar)


# --------------------------------------------------------------------------------------------
# Entrada desde el dashboard
# --------------------------------------------------------------------------------------------
def get(h, ruta, consulta):
    """Atiende un GET del apartado. True si la ruta es suya (ya respondio)."""
    if not (ruta == "/puntos" or ruta.startswith("/puntos/") or ruta.startswith("/operaciones/")):
        return False
    if not h._admin():
        _prohibido(h)
        return True
    if ruta == "/puntos":
        lista(h, consulta)
        return True
    if ruta == "/puntos/nuevo":
        form_nuevo(h)
        return True
    m = RE_RUTA_OP.match(ruta)
    if m:
        if not _operaciones.RE_OPID.match(m.group(1)):
            h._html("<h1>No encontrado</h1>", 404)
        else:
            pagina_op(h, m.group(1))
        return True
    m = RE_RUTA_PID.match(ruta)
    if not m or m.group(2) not in (None, "logs"):
        h._html("<h1>No encontrado</h1>", 404)
        return True
    pid = m.group(1)
    if not nodos.existe(pid):
        h._html(pagina(_dash(h), "Punto inexistente", "<h1>Punto inexistente</h1><p>No hay ningun punto %s "
                       "(quiza se dio de baja).</p>" % esc(pid)), 404)
        return True
    if m.group(2) == "logs":
        logs(h, pid, consulta)
    else:
        ficha(h, pid)
    return True


def post(h, ruta, form):
    """Atiende un POST del apartado. True si la ruta es suya (ya respondio)."""
    if not ruta.startswith("/puntos/"):
        return False
    if not h._admin():
        _prohibido(h)
        return True
    if ruta == "/puntos/nuevo":
        crear(h, form)
        return True
    m = RE_RUTA_PID.match(ruta)
    acciones = ("borrar", "regenerar", "arrancar", "parar", "reiniciar", "ajustar", "api", "espejo")
    if not m or m.group(2) not in acciones:
        h._html("<h1>No encontrado</h1>", 404)
        return True
    pid, acc = m.group(1), m.group(2)
    try:
        nodos.exigir_pid(pid)
    except (nodos.NodoInvalido, nodos.NodoInexistente):
        h._html(pagina(_dash(h), "Punto inexistente", "<h1>Punto inexistente</h1>"), 404)
        return True
    p = nodos.punto(pid) or {}
    tok = form.get("op") or ""
    if acc == "borrar":
        confirmar = (form.get("confirmar") or "").strip()
        if not confirmar or confirmar != (p.get("nombre") or pid):
            _bit(_dash(h), "PUNTO-BORRAR", pid=pid, resultado="nombre-no-coincide")
            ficha(h, pid, "Para dar de baja hay que escribir exactamente el nombre del punto.", 400)
            return True
        d = _dash(h)
        limpiar = getattr(d, "baja_limpiar_router", None)
        if form.get("limpiar_router") and limpiar is not None:
            # antes de la baja: despues ya no hay tunel para llegar al router (A-21(5))
            res = limpiar(pid, usuario=_usuario(d))
            if not res.get("ok"):
                _bit(d, "PUNTO-BORRAR", pid=pid, resultado="router-sin-limpiar")
                ficha(h, pid, "No se dio de baja: %s. Arregla la conexion con el router y vuelve a intentarlo; "
                              "si ese router ya no existe, desmarca \"Limpiar antes el MikroTik\" (lo que el "
                              "panel le puso tendras que quitarlo a mano)." % res.get("mensaje", "fallo"), 409)
                return True
        else:
            _bit(d, "PUNTO-BORRAR", pid=pid, resultado="sin-limpiar-router")
        _encolar(h, pid, "punto.borrar", {"pid": pid, "confirmar": confirmar}, nombre=confirmar, token=tok,
                 al_fallar=getattr(d, "baja_cancelada", None))
    elif acc == "regenerar":
        _encolar(h, pid, "punto.vpn.regenerar", {"pid": pid}, token=tok)
    elif acc in ACCIONES_COLA:
        _encolar(h, pid, ACCIONES_COLA[acc], {"pid": pid}, token=tok)
    elif acc == "ajustar":
        redes, err = validar_redes(form.get("redes") or "")
        if err:
            ficha(h, pid, err, 400)
            return True
        _encolar(h, pid, "punto.ajustar", {"pid": pid, "redes_abonados": redes}, token=tok)
    elif acc == "api":
        accion_api(h, pid, form)
    else:
        accion_espejo(h, pid, form)
    return True
