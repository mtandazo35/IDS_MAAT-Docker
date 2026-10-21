"""Apartado Puntos del dashboard (CONTRATO-F2 §5, §10.2, §10.6).

Un punto es un MikroTik con su propia VPN y su propio Suricata (contenedores que crea el
orquestador). Aqui se da de alta, se mira su salud por etapas y su retencion efectiva, se
configura la API del router, se cambian sus prefijos, se ven sus logs y se da de baja. El espejo
lo monta el operador a mano en el MikroTik (reglas sniff-tzsp): el panel ya no lo toca (el user,
2026-10-16).

Lo pinta el dashboard con su barra (`nav`) y sus modales (`ask`/`aviso`, nunca alert/confirm):
este modulo no importa el dashboard (puede correr como __main__); usa el modulo del manejador
que lo llama (`sys.modules[type(h).__module__]`). Todo es solo de admin y se comprueba aqui, en
el servidor, en cada ruta (GET y POST).

Reutiliza la logica del panel F1b-min (idspanel/app.py y vistas.py: validar_formulario_punto,
vista_op, la tabla y la ficha) y sus clientes idspanel/orq.py y operaciones.py.

Rutas (h = manejador H del dashboard; consulta/form = dict con un valor por campo):
  GET  /puntos                         lista con salud por etapas y retencion efectiva
  GET  /puntos/nuevo   POST /puntos/nuevo   alta -> punto.crear -> 303 /operaciones/<op_id>
                                        (solo el nombre; la lista la abre en un modal y manda
                                        ajax=1: {op_id} o {error}; /puntos?alta=1 abre el modal)
  GET  /operaciones/<op_id>             avance; al terminar, usuario y clave VPN UNA sola vez
  GET  /operaciones/<op_id>?json=1      el mismo avance en JSON (la pagina y la ficha lo consultan
                                        sin recargar; al terminar trae el cuerpo del resultado)
  GET  /puntos/<pid>                    ficha (Resumen, VPN, API, Prefijos, Logs, Baja)
  GET  /puntos/<pid>/logs?parte=vpn|suricata
  GET  /puntos/<pid>/huella             huella que presenta el certificado API-SSL del router y la caja
                                        de la ficha que la confirma (JSON, cache 10 min; VPN-06)
  POST /puntos/<pid>/{borrar,regenerar,arrancar,parar,reiniciar,ajustar,api,desbanear}
       con ajax=1: la baja devuelve {trabajo} (un hilo del panel habla con el router),
       ajustar {op_id}, api (guardar, probar, confirmar u olvidar la huella) y desbanear
       {ok, mensaje}; sin ajax, la pagina de siempre.
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
import secretos
from idspanel import operaciones as _operaciones
from idspanel import orq as _orq

ORQ_SOCK = os.environ.get("IDS_ORQ_SOCK", "/run/ids-orq/orq.sock")
ORQ_TOKEN = os.environ.get("IDS_ORQ_TOKEN", "/run/secrets/orq_token")
TRANSPORTE = None            # pruebas: callable(peticion) -> respuesta (sin socket)

RE_NOMBRE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}$")
# solo ASCII y sin salto final (`$` admite un salto; `\d`, digitos de cualquier escritura): B-13
RE_RUTA_PID = re.compile(r"^/puntos/(p[0-9]{3})(?:/([a-z]+))?\Z")
RE_RUTA_OP = re.compile(r"^/operaciones/([0-9a-f-]{36})\Z")
MAX_REDES = 64
PREFIJO_MINIMO = 8           # una red de abonados mas ancha que /8 es un error (A-28)
RETENCION_OBJETIVO_DIAS = 30

ESTADOS = {"creando": "creando", "activo": "activo", "parado": "parado", "error": "con error",
           "borrando": "borrando"}
AVISOS = {
    "SIN-ESPEJO": "No llega el espejo del MikroTik desde hace 10 min o más",
    "ESPEJO-NO-LLEGA": "El espejo llega al receptor del punto pero Suricata no ve paquetes",
    "NETNS-DISTINTO": "VPN y Suricata quedaron en redes distintas (el orquestador lo corrige)",
    "REINICIOS": "3 o más reinicios en la última hora",
    "DISCO": "Queda poco disco libre en el servidor (< 15 %): pueden borrarse eventos antes de 30 días",
}
# estados de la salud por etapas (CONTRATO-F2 §10.6). Tras un alta correcta el punto NO es rojo:
# la VPN sana esperando al MikroTik es ámbar («esperando MikroTik»), mientras se crea o arranca es
# gris, y rojo queda para lo que de verdad falla (VPN caída o el punto con error, con su motivo).
SALUD_TXT = {"operativa": "operativa", "degradada": "degradada", "sin datos": "sin datos",
             "desconectada": "VPN caída", "deshabilitada": "deshabilitada",
             "desconocido": "desconocido", "creando": "creando…", "arrancando": "arrancando",
             "esperando": "esperando MikroTik", "error": "con error"}
SALUD_COLOR = {"operativa": "#1a7f37", "degradada": "#e58a00", "sin datos": "#8a8a86",
               "desconectada": "#c0392b", "deshabilitada": "#6b6a66", "desconocido": "#9a9a95",
               "creando": "#8a8a86", "arrancando": "#8a8a86", "esperando": "#d4a000", "error": "#c0392b"}
MAX_MOTIVO = 300             # paso_error: el orquestador ya lo corta a 300; aqui tambien
ETAPAS = (("vpn", "VPN conectada"), ("tzsp", "TZSP recibido"), ("suricata", "Tráfico procesado"),
          ("eventos", "Eventos actualizados"), ("datos", "Datos consultables"))
ORDENES = {"punto.crear": "Crear punto", "punto.borrar": "Borrar punto",
           "punto.vpn.regenerar": "Regenerar la clave de la VPN", "punto.arrancar": "Arrancar el punto",
           "punto.parar": "Parar el punto", "punto.reiniciar": "Reiniciar el punto",
           "punto.ajustar": "Ajustar el punto (prefijos o puerto de la API)",
           # trabajos que hace el propio panel contra el router (no van al orquestador); los del
           # espejo son de antes del 2026-10-16 (la ficha ya no lo monta) y siguen en el historial
           "panel.espejo.plan": "Vista previa del espejo", "panel.espejo.aplicar": "Aplicar el espejo",
           "panel.espejo.pausar": "Pausar el espejo", "panel.espejo.retirar": "Retirar el espejo",
           "panel.baja": "Dar de baja el punto"}
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


def _bit(d, accion, pid="", objetivo="", resultado="", extra="", quien=None, ip=None):
    """Una linea de bitacora: usuario (lo pone bitacora), punto, objetivo, operacion y resultado.
    Nunca claves. Un trabajo del panel corre en su propio hilo, sin el contexto de la peticion:
    pasa `quien` e `ip` de quien lo pidio."""
    det = "punto=%s" % (pid or "-")
    if objetivo:
        det += " objetivo=%s" % objetivo
    if resultado:
        det += " resultado=%s" % resultado
    if extra:
        det += " " + extra
    try:
        if quien is None and ip is None:
            d.bitacora(accion, det[:400])
        else:
            d.bitacora(accion, det[:400], quien=quien, ip=ip)
    except Exception:
        pass


# El alta solo pide el nombre (el user, 2026-10-15: «los prefijos no van, solo es nombre del punto»).
# Los prefijos los pone el orquestador (redes_por_defecto: lo privado y el CGNAT sin sus redes
# reservadas) y se estrechan luego en la ficha. RouterOS 7 no negocia el cifrado de datos (solo
# manda IV_PROTO=2: lab, p001 y p002) y OpenVPN usa el respaldo del servidor; con ros_version 6 ese
# respaldo es AES-256-CBC y conectan igual un RouterOS 6.49+ (cipher=aes256) y un 7 (su bloque sale
# con cipher=aes256-cbc). El perfil, el de por defecto.
ROS_ALTA = 6
PERFIL_ALTA = "reducido"


# Conexión directa (sin VPN): solo LAN (el user, 2026-10-18). La IP del MikroTik, privada o CGNAT;
# el orquestador además la saca de sus redes internas (túneles, Docker, panel).
REDES_LAN = tuple(ipaddress.IPv4Network(r) for r in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))


def validar_formulario_punto(f):
    """(params para punto.crear, mensaje de error). El nombre y la conexión: por VPN (lo de siempre)
    o directa por la LAN con la IP del MikroTik. Prefijos, RouterOS y perfil no se preguntan (si
    llegan, se ignoran)."""
    nombre = (f.get("nombre") or "").strip()
    if not RE_NOMBRE.match(nombre):
        return None, ("El nombre solo admite minúsculas, números y guiones, de 2 a 31 caracteres, "
                      "empezando por letra o número (p. ej. norte).")
    params = {"nombre": nombre, "perfil": PERFIL_ALTA, "ros_version": ROS_ALTA}
    modo = (f.get("modo") or "vpn").strip()
    if modo not in ("vpn", "directo"):
        return None, "Elige cómo se conecta el MikroTik: por VPN o directo por la red local."
    if modo == "directo":
        txt = (f.get("mk_ip") or "").strip()
        try:
            ip = ipaddress.IPv4Address(txt)
        except ValueError:
            return None, ("Para la conexión directa pon la IP del MikroTik en la red local "
                          "(p. ej. 192.168.88.1).")
        if not any(ip in r for r in REDES_LAN):
            return None, ("La conexión directa es solo para la red local: %s es una IP pública. Pon la "
                          "IP privada del MikroTik o crea el punto por VPN." % ip)
        params.update(modo="directo", mk_ip=str(ip))
    return params, ""


def validar_redes(texto):
    """Prefijos ADICIONALES (lo privado y el CGNAT van siempre): vacio vale."""
    trozos = [x.strip() for x in re.split(r"[\s,;]+", texto or "") if x.strip()]
    if not trozos:
        return [], ""
    if len(trozos) > MAX_REDES:
        return None, "Como mucho %d redes de abonados por punto." % MAX_REDES
    redes = []
    for r in trozos:
        try:
            net = ipaddress.IPv4Network(r, strict=False)
        except ValueError:
            return None, "«%s» no es una red IPv4 válida (ejemplo: 10.0.0.0/24)." % r[:45]
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
            "nota": str(s.get("nota") or s.get("detalle") or ""), "directo": bool(s.get("directo"))}


def salud_texto(sal):
    """El texto del estado de salud. Un punto directo no tiene VPN: «desconectada» es su receptor
    del espejo caído, no «VPN caída»."""
    est = (sal or {}).get("estado", "desconocido")
    if est == "desconectada" and (sal or {}).get("directo"):
        return "receptor caído"
    return SALUD_TXT.get(est, est)


def salud_chip(sal):
    est = sal.get("estado", "desconocido")
    return ("<span class=pchip style='background:%s'>%s</span>"
            % (SALUD_COLOR.get(est, "#9a9a95"), esc(salud_texto(sal))))


def salud_etapas_html(sal):
    if not sal.get("etapas"):
        return ("<div class=hint>Sin medición por etapas todavía: estado <b>%s</b>.</div>"
                % esc(salud_texto(sal)))
    out = "<ul class=etapas>"
    for e in sal["etapas"]:
        out += ("<li><span class=edot style='background:%s'></span><b>%s</b> &middot; %s%s</li>"
                % (_COLOR_ETAPA.get(e["estado"], SALUD_COLOR.get(e["estado"], "#9a9a95")), esc(e["nombre"]), esc(e["estado"]),
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
        return "<span class=hint>sin eventos todavía</span>"
    dias = max(0, int((ahora - ret["desde"]) // 86400))
    txt = ("desde <b>%s</b> (%d día%s)" % (time.strftime("%d/%m/%Y", time.localtime(ret["desde"])), dias,
                                           "" if dias == 1 else "s"))
    if ret.get("anticipado"):
        txt += (" <span class=pwarn>borrado anticipado por disco: no hay %d días</span>"
                % RETENCION_OBJETIVO_DIAS)
    elif dias < RETENCION_OBJETIVO_DIAS:
        txt += " <span class=hint>(objetivo %d días)</span>" % RETENCION_OBJETIVO_DIAS
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
    """(alertas de las ultimas 24 h, completo). Manda el recuento del orquestador
    (alertas_24h_orq): con espejo real, 8 MB del eve vivo son pocos minutos y el «0+» que salia no
    eran 24 h. Sin el (orquestador de antes), el final del eve.json vivo con tope REAL de bytes
    (no solo el seek inicial). Un eve.json que no es fichero regular o cuya ruta real sale de
    datos/<pid> no se abre: (0, True) (B-09)."""
    a = alertas_24h_orq(nodos.punto(pid))
    if a:
        return a["n"], a["completo"]
    ahora = ahora or time.time()
    ok = eventos_web._fichero_seguro(pid, "eve.json")
    if not ok:
        return 0, True
    real, st = ok
    marca = (st.st_mtime_ns, st.st_size, st.st_ino)
    c = _ALERTAS.get(pid)
    # el eve.json vivo cambia a cada segundo: con la marca exacta la cache casi nunca valia y cada
    # carga de la lista o la ficha releia hasta 8 MB por punto. Un recuento de hace menos de 60 s
    # vale aunque el fichero haya crecido (P4).
    if c and 0 <= ahora - c[2] < 60:
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


def alertas_24h_orq(punto):
    """{"n", "desde", "completo"} que publica el orquestador en estado.json (el contador de
    alertas del Suricata del punto, en cubos de 5 min), o None si no lo publica (orquestador de
    antes, o el Suricata aun sin estadisticas)."""
    a = (punto or {}).get("alertas_24h")
    if not isinstance(a, dict):
        return None
    n = a.get("n")
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        return None
    return {"n": n, "desde": _a_epoch(a.get("desde")), "completo": bool(a.get("completo"))}


def _desde_txt(t, ahora):
    """«las 17:05» si es de hoy; «el 14/10 17:05» si no."""
    lt = time.localtime(t)
    if time.strftime("%Y-%m-%d", lt) == time.strftime("%Y-%m-%d", time.localtime(ahora)):
        return time.strftime("las %H:%M", lt)
    return time.strftime("el %d/%m %H:%M", lt)


def alertas_24h_html(pid, ahora=None, punto=None):
    """(html de la celda «Alertas 24 h», numero). Si el orquestador aun no lleva 24 h contando
    (punto nuevo, o recien puesto el recuento) se dice desde cuando cuenta; el recuento de reserva
    (cola del eve) lleva «+» cuando no llega a cubrir las 24 h."""
    ahora = ahora or time.time()
    a = alertas_24h_orq(punto if punto is not None else nodos.punto(pid))
    if a:
        if a["completo"] or not a["desde"]:
            return _num(a["n"]), a["n"]
        return ("%s <span class=hint>desde %s</span>" % (_num(a["n"]), esc(_desde_txt(a["desde"], ahora))),
                a["n"])
    n, completo = alertas_24h(pid, ahora)
    return _num(n) + ("" if completo else "+"), n


# Redes del espejo fuera de los prefijos. El Suricata ya las analiza (su HOME_NET es todo lo
# privado y CGNAT, ids_orq.home_net), pero el panel solo trata como abonados los prefijos: los
# equipos de esas redes salen en las alertas y no entran en la cuarentena, el ranking de riesgo
# ni las metricas (lab, p001, 2026-10-15: espejo puesto a mano con otras redes). Se mira una
# muestra del eve vivo.
COB_TOPE_BYTES = 4 * 1024 * 1024     # final del eve.json vivo que se mira (miles de eventos)
COB_MIN_MUESTRA = 200                # IPs privadas minimas para opinar
COB_AVISO_PCT = 20                   # desde este % de IPs privadas fuera de los prefijos: aviso
COB_SUGERIR_PCT = 1                  # una /24 se sugiere si pasa de este % de la muestra
COB_MAX_SUGERIDAS = 8
COB_CACHE_S = 300
_COB = {}                            # pid -> (ts, resultado)
_RE_IP_EVE = re.compile(rb'"(?:src|dest)_ip":"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"')
# Redes de abonado de un ISP: RFC 1918 y CGNAT. No `is_private` de Python, que mete tambien las
# de documentacion y pruebas (192.0.2/24, 198.18/15, 198.51.100/24, 203.0.113/24...).
_REDES_ABONADO = tuple(ipaddress.ip_network(r) for r in
                       ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))


def _ip_de_abonado(ip):
    """IPv4Address si `ip` puede ser de un abonado (RFC 1918 o CGNAT), si no None."""
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    return a if any(a in r for r in _REDES_ABONADO) else None


def cobertura_prefijos(pid, punto=None, ahora=None):
    """Que parte del trafico espejado cae dentro de los prefijos del punto, de una muestra del
    final del eve.json vivo (src_ip y dest_ip de cada evento: tls, http, alertas...). Cuenta solo
    IPs de abonado posibles (RFC 1918 o CGNAT) y deja fuera la red del tunel del punto.

    None si no hay eve o la muestra es pequeña; si no, {"muestra", "dentro", "pct_fuera",
    "fuera": [(red /24, veces)] de mas a menos, "sugeridas": [red /24]} (las /24 de fuera que
    pasan de COB_SUGERIR_PCT, como mucho COB_MAX_SUGERIDAS). Cache de COB_CACHE_S por punto."""
    ahora = ahora or time.time()
    c = _COB.get(pid)
    if c and 0 <= ahora - c[0] < COB_CACHE_S:
        return c[1]
    p = punto if punto is not None else (nodos.punto(pid) or {})
    redes = []
    for r in p.get("redes_espejo") or p.get("redes") or []:
        try:
            redes.append(ipaddress.ip_network(str(r), strict=False))
        except ValueError:
            pass
    try:
        tunel = ipaddress.ip_network(str(p.get("tun_net")), strict=False) if p.get("tun_net") else None
    except ValueError:
        tunel = None
    res = None
    ok = eventos_web._fichero_seguro(pid, "eve.json")
    if ok:
        real, st = ok
        try:
            with eventos_web._abrir(real, st) as f:
                if st.st_size > COB_TOPE_BYTES:
                    f.seek(st.st_size - COB_TOPE_BYTES)
                    f.readline(MAX_LINEA + 1)          # la primera, cortada
                bloque = f.read(COB_TOPE_BYTES)
        except OSError:
            bloque = b""
        vistas = {}
        for m in _RE_IP_EVE.finditer(bloque):
            ip = m.group(1)
            vistas[ip] = vistas.get(ip, 0) + 1
        dentro, fuera, muestra = 0, {}, 0
        for ip, n in vistas.items():
            a = _ip_de_abonado(ip.decode("ascii"))
            if a is None or (tunel is not None and a in tunel):
                continue
            muestra += n
            if any(a in r for r in redes):
                dentro += n
            else:
                red = str(ipaddress.ip_network("%s/24" % a, strict=False))
                fuera[red] = fuera.get(red, 0) + n
        if muestra >= COB_MIN_MUESTRA:
            orden = sorted(fuera.items(), key=lambda kv: (-kv[1], kv[0]))
            res = {"muestra": muestra, "dentro": dentro,
                   "pct_fuera": round(100.0 * (muestra - dentro) / muestra, 1), "fuera": orden,
                   "sugeridas": [r for r, n in orden if 100.0 * n / muestra >= COB_SUGERIR_PCT]
                   [:COB_MAX_SUGERIDAS]}
    _COB[pid] = (ahora, res)
    return res


def fuera_de_prefijos(cob):
    """Texto corto para la salud («62 % del tráfico espejado fuera de los prefijos») si la
    cobertura pasa del umbral del aviso; "" si no."""
    if not cob or cob.get("pct_fuera", 0) < COB_AVISO_PCT:
        return ""
    return "%d %% del tráfico espejado fuera de los prefijos" % round(cob["pct_fuera"])


def cobertura_html(cob):
    """Aviso de la ficha: que redes llegan por el espejo sin estar en los prefijos, y un boton que
    las añade al cuadro de Prefijos (no guarda: el admin revisa y pulsa «Guardar prefijos»)."""
    if not fuera_de_prefijos(cob):
        return ""
    total = cob["muestra"]
    # con su % solo las que pesan (las mismas que el boton); las sueltas, juntas: un «1 %»
    # redondeado hacia arriba hacia parecer importante una red con tres IPs
    grandes = [(r, 100.0 * n / total) for r, n in cob["fuera"] if 100.0 * n / total >= COB_SUGERIR_PCT]
    partes = ["<b>%s</b> (%d %%)" % (esc(r), round(pc)) for r, pc in grandes[:COB_MAX_SUGERIDAS]]
    mas = len(grandes) - COB_MAX_SUGERIDAS
    if mas > 0:
        partes.append("%d red%s más" % (mas, "" if mas == 1 else "es"))
    sueltas = len(cob["fuera"]) - len(grandes)
    if sueltas:
        partes.append("%d red%s con menos del 1 %% cada una" % (sueltas, "" if sueltas == 1 else "es"))
    lista = ", ".join(partes[:-1]) + " y " + partes[-1] if len(partes) > 1 else "".join(partes)
    if cob["dentro"]:
        cabeza = ("El %d %% del tráfico que llega por el espejo es de redes que no están en los prefijos "
                  "de este punto" % round(cob["pct_fuera"]))
    else:
        cabeza = "Nada del tráfico que llega por el espejo es de los prefijos de este punto"
    boton = ""
    if cob["sugeridas"]:
        boton = ("<div class=acciones><button type=button class=btn data-redes='%s' onclick=\"var t="
                 "document.querySelector('#prefijos textarea[name=redes]');if(t){var v=t.value.split(/\\s+/)"
                 ".filter(Boolean);this.dataset.redes.split(' ').forEach(function(x){if(v.indexOf(x)<0)"
                 "v.push(x)});t.value=v.join('\\n');t.scrollIntoView({behavior:'smooth',block:'center'});"
                 "t.focus()}return false\">Añadir estas redes a los prefijos</button></div>"
                 % esc(" ".join(cob["sugeridas"])))
    return ("<div class='aviso amb'><b>%s</b>: %s. El Suricata ya las analiza, pero el panel solo trata "
            "como tus abonados los prefijos: los equipos de esas redes salen en las alertas y no entran en la "
            "cuarentena, el ranking de riesgo ni las métricas de tu red. Si son redes de tus abonados, "
            "añádelas a los prefijos y guárdalos (el Suricata no se reinicia). <span class=hint>Muestra: %s "
            "IPs de los últimos eventos.</span>%s</div>" % (esc(cabeza), lista, _num(total), boton))


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
    return "%d días" % (seg // 86400)


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


def es_directo(p):
    """Punto «directo» (sin VPN, solo LAN; el user, 2026-10-18): el MikroTik manda el espejo al host
    por la red local y el panel llega a su API en su IP de la LAN."""
    return (p or {}).get("modo") == "directo"


# un punto directo cuenta como conectado si el espejo de su MikroTik llegó hace menos de esto
ESPEJO_VIVO_S = 120


def mk_conectado(p):
    """El MikroTik tiene el tunel arriba segun estado.json. Un openvpn-status.log viejo
    (`vpn_cliente.viejo`) no es «conectado» aunque diga que si. En un punto directo no hay tunel:
    conectado = llega su espejo (tzsp.visto_s, del receptor)."""
    if es_directo(p):
        visto = ((p or {}).get("tzsp") or {}).get("visto_s")
        return isinstance(visto, (int, float)) and not isinstance(visto, bool) and visto < ESPEJO_VIVO_S
    vc = (p or {}).get("vpn_cliente") or {}
    return bool(vc.get("conectado")) and not vc.get("viejo")


def situacion_vpn(p):
    """Como esta la VPN de un punto, igual en la lista, la ficha, la salud y el selector:
    {"clave", "texto", "motivo"}. La clave es una de:
      conectada   contenedor vivo y el MikroTik conectado
      esperando   contenedor sano (o sin healthcheck) y el MikroTik aun sin conectar: lo normal
                  tras un alta correcta, mientras no se pegan los comandos en el router (ámbar)
      arrancando  contenedor en marcha con el healthcheck aun en `starting` (gris)
      creando     el orquestador esta creando el punto (gris); parada / borrando, igual
      caida       contenedor ausente, parado o `unhealthy` (rojo)
    Manda `salud` (healthy) y no solo `running`; sin `salud` (orquestador viejo) o `none`
    (imagen sin healthcheck) se toma `running` como vivo."""
    p = p or {}
    c = (p.get("contenedores") or {}).get("vpn") or {}
    est, sal = c.get("estado"), c.get("salud")
    if p.get("estado") == "creando":
        return {"clave": "creando", "texto": "creando…", "motivo": "el orquestador está creando el punto"}
    if p.get("estado") == "borrando":
        return {"clave": "creando", "texto": "borrando", "motivo": "el orquestador está borrando el punto"}
    if p.get("estado") == "parado" or p.get("deseado") == "parado":
        return {"clave": "parada", "texto": "parada", "motivo": "punto parado"}
    if est in (None, "ausente"):
        return {"clave": "caida", "texto": "caída", "motivo": "el contenedor vpn no existe"}
    if est != "running":
        return {"clave": "caida", "texto": "caída", "motivo": "contenedor vpn %s" % est}
    if sal == "unhealthy":
        return {"clave": "caida", "texto": "caída", "motivo": "contenedor vpn enfermo (unhealthy)"}
    if mk_conectado(p):
        if es_directo(p):
            return {"clave": "conectada", "texto": "conectado",
                    "motivo": "llega el espejo del MikroTik %s (directo, sin VPN)" % (p.get("mk_ip") or "?")}
        ip = (p.get("vpn_cliente") or {}).get("ip_real")
        return {"clave": "conectada", "texto": "conectado",
                "motivo": "MikroTik conectado desde %s" % (ip or "?")}
    if sal == "starting":
        return {"clave": "arrancando", "texto": "arrancando",
                "motivo": "contenedor vpn arrancando (comprobando su salud)"}
    if es_directo(p):
        return {"clave": "esperando", "texto": "esperando MikroTik",
                "motivo": "receptor listo: esperando el espejo del MikroTik %s (directo, sin VPN)"
                          % (p.get("mk_ip") or "?")}
    viejo = " (el registro de la VPN no se actualiza: dato viejo)" if (p.get("vpn_cliente") or {}).get("viejo") else ""
    return {"clave": "esperando", "texto": "esperando MikroTik",
            "motivo": "VPN lista: esperando a que el MikroTik conecte" + viejo}


def error_punto(p):
    """(motivo, desde) de un punto en estado `error`: `paso_error` y `error_desde` del orquestador,
    tolerando que falten. (None, None) si el punto no esta en error."""
    p = p or {}
    if p.get("estado") != "error":
        return None, None
    motivo = p.get("paso_error")
    motivo = str(motivo)[:MAX_MOTIVO] if motivo not in (None, "") else ""
    return motivo, _a_epoch(p.get("error_desde"))


def error_html(p, ahora=None, boton=""):
    """El motivo del error de un punto (escapado) y desde cuando, con un boton opcional."""
    motivo, desde = error_punto(p)
    if motivo is None:
        return ""
    ahora = ahora or time.time()
    txt = ("Motivo: <b>%s</b>" % esc(motivo)) if motivo else "El orquestador no publicó el motivo."
    if desde:
        txt += (" &middot; desde hace %s (%s)"
                % (_edad(ahora - desde), esc(time.strftime("%d/%m/%Y %H:%M", time.localtime(desde)))))
    return "<div class=perr>%s%s</div>" % (txt, boton)


# --------------------------------------------------------------------------------------------
# Esqueleto de pagina (estilo del dashboard)
# --------------------------------------------------------------------------------------------
_CSS = (
    "main{max-width:1360px;padding:20px 28px 40px}"
    ".ptit{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:0 0 12px}"
    ".ptbtns{display:flex;gap:8px;flex-wrap:wrap}"
    ".card{padding:16px 18px}"
    ".pchip{display:inline-block;color:#fff;font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px}"
    ".pwarn{color:#b06a00;font-weight:600}"
    ".hint{color:#8a8a86;font-size:12px}"
    ".etapas{list-style:none;margin:6px 0;padding:0;font-size:13px}.etapas li{margin:3px 0}"
    ".edot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:middle}"
    ".btn{display:inline-block;padding:9px 16px;background:#2a78d6;color:#fff;border:0;border-radius:9px;"
    "font:600 13px system-ui;cursor:pointer;text-decoration:none}"
    # el color va tambien en :hover: el `a:hover{color:var(--brand-ink)}` del CSS comun pesa mas que
    # `.btn` en un <a class=btn> y dejaba el texto azul sobre el fondo azul («desaparecen las letras»).
    # Y el :hover NO cambia el fondo: pasaba del degradado de la capa comun a un color plano oscuro de
    # golpe (un degradado no se anima), y al recorrer la lista los botones «palpitaban» (el user,
    # 2026-10-14). Queda el aclarado suave de la capa comun (filter), con transicion.
    ".btn{transition:filter .15s,box-shadow .15s,transform .05s}"
    ".btn:hover{color:#fff}.btn.sec{background:#fff;color:#33322f;border:1px solid #d7d6d2}"
    ".btn.sec:hover{background:#f4f4f2;color:#33322f}.btn.peligro{background:#c0392b}"
    ".btn.peligro:hover{color:#fff}"
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
    ".pacc{display:flex;gap:6px;flex-wrap:nowrap}.pacc form{margin:0}"
    ".btn.chico{padding:6px 11px;font-size:13px}"
    ".pbajaov{display:none;position:fixed;inset:0;background:rgba(11,11,11,.55);z-index:150;align-items:center;"
    "justify-content:center;padding:24px}"
    ".pbajabox{background:#fff;border-radius:14px;max-width:520px;width:100%;padding:22px 24px;"
    "box-shadow:0 16px 54px rgba(0,0,0,.45)}.pbajabox h3{margin:0 0 8px;font-size:19px}"
    # motivo del error de un punto (lista y ficha) y el pill de la VPN en ámbar/gris (el Tailwind
    # compilado solo trae el verde y el rojo)
    ".perr{color:#b52a2a;font-size:12.5px;margin-top:3px;overflow-wrap:anywhere}"
    ".perr form{display:inline-block;margin:6px 0 0}"
    ".vpill{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:2px 10px;font-size:12px;"
    "font-weight:600}.vpill i{display:inline-block;width:6px;height:6px;border-radius:50%}"
    ".vpill.amb{background:#fff7ed;color:#8a5a00}.vpill.amb i{background:#d4a000}"
    ".vpill.gris{background:#f1f1ef;color:#5f5e5a}.vpill.gris i{background:#9a9a95}"
    "details.plogs{margin:10px 0}details.plogs summary{cursor:pointer;font-weight:600;font-size:13px}"
    # comandos del MikroTik: botones de copiar fuera y los bloques v7/v6 plegados debajo
    ".pcopias{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}"
    "details.pver{margin:6px 0}details.pver summary{cursor:pointer;font-weight:600;font-size:13px}"
    # la cabecera del script como recomendaciones plegadas, en texto normal (no en un <pre>)
    "details.precom{margin:8px 0}details.precom summary{cursor:pointer;font-weight:600;font-size:13px}"
    "details.precom ul{margin:6px 0 0;padding-left:20px;font-size:13px;color:#52514e;line-height:1.5}"
    # avance sin recargar (trabajos del panel y operaciones del orquestador) y su modal
    ".pjspin{width:26px;height:26px;border:3px solid #e7e6e2;border-top-color:#2a78d6;border-radius:50%;"
    "animation:pjgira .9s linear infinite;margin:6px 0}@keyframes pjgira{to{transform:rotate(360deg)}}"
    ".pjest{font-size:13.5px;margin:6px 0}.pjpasos{font-size:13px;margin:8px 0;padding-left:20px}"
    ".pjcaja{border:1px solid #cfe0f6;background:#f6f9fe;border-radius:9px;padding:10px 13px;margin:10px 0}"
    "#pjov .pbajabox{max-width:820px;max-height:88vh;overflow:auto}"
    # huella del certificado API-SSL en bloques (VPN-06) y el desbaneo de la ficha
    "code.phue{display:inline-block;font-size:13px;letter-spacing:.4px;line-height:1.7;padding:3px 7px}"
    ".pdesban{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:4px 0 0}"
    ".pdesban input.t{width:auto;min-width:200px;flex:0 1 240px}"
)

# Copiar: el panel va por HTTP (sin HTTPS en el VPS) y ahi el navegador NO da navigator.clipboard
# (solo en HTTPS o localhost): «Copiar» fallaba siempre (el user, 2026-10-15). Fuera de un contexto
# seguro se copia con un textarea + execCommand('copy'), en el MISMO clic (fuera del gesto el
# navegador lo niega); si ni asi, el texto queda seleccionado para Ctrl+C.
_JS = ("<script>function pcopiar(id,b){var e=document.getElementById(id);if(!e)return;"
       "var t=e.textContent;function ok(){var o=b.textContent;b.textContent='Copiado';"
       "setTimeout(function(){b.textContent=o;},1500);}"
       "function viejo(){var a=document.createElement('textarea'),r=false;a.value=t;a.setAttribute('readonly','');"
       "a.style.position='fixed';a.style.top='0';a.style.left='0';a.style.opacity='0';"
       "document.body.appendChild(a);a.focus();a.select();a.setSelectionRange(0,t.length);"
       "try{r=document.execCommand('copy');}catch(x){r=false;}document.body.removeChild(a);return r;}"
       # el bloque puede estar plegado (se copia sin abrirlo): para dejarlo seleccionado hay que abrirlo
       "function mano(){try{var dt=e.closest?e.closest('details'):null;if(dt)dt.open=true;"
       "var s=window.getSelection(),g=document.createRange();g.selectNodeContents(e);"
       "s.removeAllRanges();s.addRange(g);}catch(x){}"
       "aviso('No se pudo copiar','El texto quedó seleccionado: pulsa Ctrl+C para copiarlo.');}"
       "if(window.isSecureContext&&navigator.clipboard&&navigator.clipboard.writeText){"
       "navigator.clipboard.writeText(t).then(ok,function(){if(viejo())ok();else mano();});}"
       "else if(viejo()){ok();}else{mano();}}"
       "function pnombre(i){var f=i.form,b=f.querySelector('button[type=submit]');"
       "if(b)b.disabled=(i.value!==f.getAttribute('data-nombre'));}</script>")

# Lo que tarda (hablar con el MikroTik, la cola del orquestador) va por debajo y se ve sin recargar
# (el user, 2026-10-14: «el agregar nuevas IPs no debe demorar tanto»). La peticion (fetch, ajax=1)
# devuelve enseguida el id del trabajo o de la operacion; GET /operaciones/<id>?json=1 dice el avance
# por etapas (cada 2 s; 5 s si tarda o pasa del minuto: el orquestador admite 240 peticiones/min) y,
# al terminar, el resultado se ve en un MODAL (nunca un aviso arriba que recargue la pagina).
_MODAL_TRABAJO = (
    "<div id=pjov class=pbajaov data-id=''><div class=pbajabox role=dialog aria-modal=true "
    "aria-labelledby=pjtit><h3 id=pjtit></h3><div id=pjcuerpo></div><div class=acciones id=pjacc></div>"
    "</div></div>")

_JS_TRABAJOS = """<script>
function pjEsc(t){return String(t==null?'':t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
var PJSEG="<button type=button class='btn sec' onclick='pjCerrar()'>Seguir en segundo plano</button>";
function pjAbrir(tit,cuerpo,botones,id,siAbierto){var o=document.getElementById('pjov');if(!o)return;
 if(siAbierto&&(o.style.display!=='flex'||o.getAttribute('data-id')!==(id||'')))return;
 o.setAttribute('data-id',id||'');document.getElementById('pjtit').textContent=tit||'';
 document.getElementById('pjcuerpo').innerHTML=cuerpo||'';
 document.getElementById('pjacc').innerHTML=botones||"<button type=button class='btn sec' onclick='pjCerrar()'>Cerrar</button>";
 o.style.display='flex';}
function pjCerrar(){var o=document.getElementById('pjov');if(o){o.style.display='none';o.setAttribute('data-id','');}}
function pjEspera(t){return "<div class=pjspin></div><p class=pjest>"+pjEsc(t)+"</p>";}
function pjPasos(j){var h='';(j.pasos||[]).forEach(function(p){var e=p.estado==='ok'?'hecho':(p.estado==='fallo'?'falló':(p.estado||''));
 h+='<li>'+pjEsc(p.nombre)+' <span class=hint>'+pjEsc(e)+(p.dur_s!=null?' · '+pjEsc(String(p.dur_s).replace('.',','))+' s':'')+(p.detalle?' — '+pjEsc(p.detalle):'')+'</span></li>';});
 return h?'<ol class=pjpasos>'+h+'</ol>':'';}
function pjProgreso(j){var t=j.delante?('En cola: '+j.delante+' operación(es) delante.'):(j.etapa?('Paso actual: '+j.etapa+((j.avance&&String(j.etapa).indexOf(j.avance)<0)?' ('+j.avance+')':'')):'Esperando…');
 return (j.aviso?"<p class=pwarn>"+pjEsc(j.aviso)+"</p>":'')+"<p class=pjest>"+pjEsc(t)+"</p>"+(j.porcentaje!=null?"<progress max=100 value='"+(+j.porcentaje||0)+"'></progress>":"<progress></progress>")+pjPasos(j);}
var PJLOGIN='La sesión caducó: vuelve a entrar';
function pjLogin(r){return r.redirected||((r.headers&&r.headers.get('content-type'))||'').indexOf('json')<0;}
function pjSeguir(id,pinta,fin){var t0=Date.now();function mira(){var t=Date.now();
 fetch('/operaciones/'+id+'?json=1',{credentials:'same-origin',cache:'no-store'})
 .then(function(r){if(r.status===404)throw 'nf';if(!r.ok)throw r.status;if(pjLogin(r))throw 'login';return r.json();})
 .then(function(j){if(j.terminada){fin(j);return;}pinta(j);setTimeout(mira,((Date.now()-t>1500)||(Date.now()-t0>60000))?5000:2000);})
 .catch(function(e){if(e==='nf'){fin({terminada:true,ok:false,mensaje:'Esa operación ya no existe o no la pediste tú.'});return;}
  if(e==='login'){fin({terminada:true,ok:false,mensaje:PJLOGIN+' (la operación sigue en el servidor).'});return;}
  pinta({etapa:'sin respuesta del panel; se reintenta en 5 s'});setTimeout(mira,5000);});}mira();}
function pjPost(f,extra,ok,mal){var d=new URLSearchParams(new FormData(f));d.set('ajax','1');for(var k in extra){d.set(k,extra[k]);}
 fetch(f.getAttribute('action'),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:d.toString()})
 .then(function(r){if(r.ok&&pjLogin(r))throw 'login';return r.json();})
 .then(function(j){if(j.token&&f.elements.op)f.elements.op.value=j.token;ok(j);})
 .catch(function(e){mal(e==='login'?PJLOGIN+'.':'No se pudo hablar con el panel. Vuelve a intentarlo.');});}
var PJTIT={'panel.baja':'Dar de baja el punto'};
function pjTrabajo(id,orden,nota){var tit=PJTIT[orden]||'Operación',n=nota?"<p class=hint>"+pjEsc(nota)+"</p>":'';
 pjAbrir(tit,n+pjEspera('Empezando…'),PJSEG,id);
 pjSeguir(id,function(j){pjAbrir(j.titulo||tit,n+pjProgreso(j),PJSEG,id,1);},
  function(j){if(j.siguiente&&j.ok){location.href=j.siguiente;return;}pjAbrir(j.titulo_fin||j.titulo||tit,j.html||("<p>"+pjEsc(j.mensaje)+"</p>"),'',id);});}
function pjOrq(id,orden){var c=(orden==='punto.ajustar')?document.getElementById('pprog'):null;
 if(c){c.style.display='block';c.innerHTML='<b>Cambiando los prefijos</b>'+pjEspera('Preguntando al orquestador…');}
 else{pjAbrir('Operación en curso',pjEspera('Preguntando al orquestador…'),PJSEG,id);}
 pjSeguir(id,function(j){if(c){c.innerHTML='<b>'+pjEsc(j.titulo||'Operación')+'</b>'+pjProgreso(j);}else{pjAbrir(j.titulo||'Operación',pjProgreso(j),PJSEG,id,1);}},
  function(j){if(c){c.innerHTML='<b>'+pjEsc(j.titulo||'Operación')+(j.ok?' · terminó bien':' · terminó mal')+'</b>'+pjPasos(j);}
   if(orden==='punto.ajustar'&&j.ok){pjAbrir('Prefijos guardados',"<p>"+pjEsc(j.mensaje||'')+"</p><p>Si tu espejo del MikroTik filtra por una address-list (p. ej. «Redes Privadas»), añade ahí también los prefijos adicionales.</p>","<button type=button class=btn onclick='pjCerrar()'>Cerrar</button>",id);return;}
   pjAbrir(j.titulo_fin||j.titulo||'Operación',j.html||("<p>"+pjEsc(j.mensaje)+"</p>"),'',id);});}
function ppref(f){var c=document.getElementById('pprog');if(c){c.style.display='block';c.innerHTML='<b>Cambiando los prefijos</b>'+pjEspera('Encolando el cambio…');}
 pjPost(f,{},function(j){if(j.op_id){pjOrq(j.op_id,'punto.ajustar');return;}if(c)c.style.display='none';aviso('No se cambiaron los prefijos',j.error||'Sin respuesta del panel.');},
  function(m){if(c)c.style.display='none';aviso('No se pudo',m);});return false;}
function papiProbar(b){var f=b.form;pjAbrir('Probar la conexión',pjEspera('Probando la API del MikroTik por el túnel (hasta 35 s si el router no responde)…'),' ','');
 pjPost(f,{accion:'probar'},function(j){pjAbrir(j.ok?'Conexión correcta':'La conexión falló','<p>'+pjEsc(j.mensaje||j.error||'')+'</p>');pjHuella(1);},
  function(m){pjAbrir('No se pudo','<p>'+pjEsc(m)+'</p>');});return false;}
function phueConf(f){pjAbrir('Confirmar la huella',pjEspera('Volviendo a leer la huella que presenta el router…'),' ','');
 pjPost(f,{},function(j){pjAbrir(j.ok?'Huella confirmada':'No se confirmó la huella','<p>'+pjEsc(j.mensaje||j.error||'')+'</p>');pjHuella(1);},
  function(m){pjAbrir('No se pudo','<p>'+pjEsc(m)+'</p>');});return false;}
function pdesban(f){pjAbrir('Desbanear IP del MikroTik',pjEspera('Pidiendo el desbaneo al servidor…'),' ','');
 pjPost(f,{},function(j){pjAbrir(j.ok?'Desbanear IP del MikroTik':'No se desbaneó','<p>'+pjEsc(j.mensaje||j.error||'')+'</p>');},
  function(m){pjAbrir('No se pudo','<p>'+pjEsc(m)+'</p>');});return false;}
function pbajaAjax(f){if(typeof pbajano==='function')pbajano();pjAbrir('Dar de baja el punto',pjEspera('Empezando la baja…'),' ','');
 pjPost(f,{},function(j){if(j.trabajo){pjTrabajo(j.trabajo,'panel.baja',j.nota);return;}pjAbrir(j.titulo||'No se dio de baja','<p>'+pjEsc(j.error||'Sin respuesta del panel.')+'</p>');},
  function(m){pjAbrir('No se pudo','<p>'+pjEsc(m)+'</p>');});return false;}
function popSeguir(id){pjSeguir(id,function(j){var v=document.getElementById('opvivo');if(v)v.innerHTML=pjProgreso(j);},
 function(j){var c=document.getElementById('opcuerpo');if(c)c.innerHTML=j.html||('<p>'+pjEsc(j.mensaje)+'</p>');if(!j.ok)aviso(j.titulo_fin||'La operación no terminó bien',j.mensaje||'');});}
function pjHuella(forzar){var e=document.getElementById('phuellabox');if(!e||(!forzar&&!e.hasAttribute('data-pedir')))return;
 fetch('/puntos/'+e.getAttribute('data-pid')+'/huella',{credentials:'same-origin',cache:'no-store'})
 .then(function(r){if(r.ok&&pjLogin(r))throw 'login';return r.json();}).then(function(j){if(j.html){e.outerHTML=j.html;}else{var c=document.getElementById('phuella');if(c)c.textContent=j.texto||'sin dato';}})
 .catch(function(x){var c=document.getElementById('phuella');if(c)c.textContent=(x==='login'?PJLOGIN.toLowerCase():'no se pudo leer');});}
function pjRetomar(){pjHuella();var e=document.getElementById('pjretomar');if(!e)return;var L=[];
 try{L=JSON.parse(e.getAttribute('data-ops')||'[]');}catch(x){L=[];}
 L.forEach(function(o){if(String(o.orden).indexOf('panel.')===0){pjTrabajo(o.id,o.orden);}else{pjOrq(o.id,o.orden);}});}
document.addEventListener('DOMContentLoaded',pjRetomar);
document.addEventListener('keydown',function(e){if(e.key==='Escape')pjCerrar();});
</script>"""


def aviso(texto, tipo="err"):
    if not texto:
        return ""
    return "<div class='aviso %s'>%s</div>" % (tipo, esc(texto))


def pagina(d, titulo, cuerpo, refresco=0, refresco_sin_js=0):
    meta = "<meta http-equiv=refresh content=%d>" % refresco if refresco else ""
    if refresco_sin_js:
        # solo sin JavaScript: con JS la pagina sigue el JSON y no se recarga entera
        meta += "<noscript><meta http-equiv=refresh content=%d></noscript>" % refresco_sin_js
    # Sin la ruta «← Ajustes / Puntos» de arriba (puesta el 2026-10-14 y quitada a peticion del
    # user el 2026-10-15): se vuelve con «Volver a Puntos» de cada pagina y con Ajustes, que la
    # barra ya marca.
    return ("<!doctype html><html lang=es><head><meta charset=utf-8>"
            "<link rel=icon type=image/png href=/favicon.ico>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>" + meta +
            "<title>%s</title><style>%s%s</style></head><body>" % (esc(titulo), d.BASE_CSS, _CSS)
            + d.nav("/ajustes") + "<main>" + cuerpo + "</main>" + _MODAL_TRABAJO + _JS + _JS_TRABAJOS
            + "</body></html>")


def _prohibido(h):
    d = _dash(h)
    return h._html(pagina(d, "Sin permiso", "<h1>Sin permiso</h1><p>Esta parte del panel es solo "
                          "para administradores.</p>"), 403)


def _bloque(ide, titulo, texto):
    return ("<div class=bloque><div class=bcab><b>%s</b><button type=button class='btn sec' "
            "onclick=\"pcopiar('%s',this)\">Copiar</button></div><pre class=cmd id='%s'>%s</pre></div>"
            % (esc(titulo), esc(ide), esc(ide), esc(texto)))


def avisos_script(texto):
    """Las lineas «# AVISO: …» del script del orquestador (p. ej. certificado del servidor de antes
    de la verificacion), juntas en un aviso rojo encima de los bloques: dentro del <pre> se perdian."""
    lineas = [x[len("# AVISO:"):].strip() for x in str(texto or "").splitlines() if x.startswith("# AVISO:")]
    if not lineas:
        return ""
    return ("<div class='aviso err'><b>Aviso del servidor sobre este script:</b> %s</div>"
            % esc(" ".join(x for x in lineas if x)))


def recomendaciones_html(cabecera):
    """La cabecera del script (los «# …» del orquestador: punto, puerto y tunel, que bloque conecta,
    el reloj del router) como «Recomendaciones antes de pegar», plegada y en texto normal: en un <pre>
    se leia como parte del script (el user, 2026-10-16). Una frase por punto; una linea que empieza en
    minuscula sigue la frase anterior (el orquestador las corta a ~100 columnas). Las «# AVISO:» no van:
    ya salen en rojo arriba (avisos_script)."""
    items, nueva = [], True
    for ln in str(cabecera or "").splitlines():
        t = ln.lstrip("#").strip()
        if not t or ln.startswith("# AVISO:"):
            nueva = True
            continue
        if items and not nueva and t[:1].islower():
            items[-1] += " " + t
        else:
            items.append(t)
        nueva = False
    if not items:
        return ""
    return ("<details class=precom><summary>Recomendaciones antes de pegar</summary><ul>%s</ul></details>"
            % "".join("<li>%s</li>" % esc(x) for x in items))


def ros_txt(ros_version):
    """RouterOS del punto en la ficha: con 6 (respaldo CBC) conectan los dos, 6.49+ y 7."""
    return {"6": "RouterOS 6.49+ o 7", "7": "RouterOS 7"}.get(str(ros_version), "-")


def comandos_html(texto, ros_version, prefijo):
    """Un boton «Copiar RouterOS 7/6» por version, fuera, y debajo los dos bloques plegados (el v7
    primero) por si se quieren mirar: se copia sin abrir el bloque (el user, 2026-10-16). Despues, el
    del certificado API-SSL si lo hay. Con ros_version 6 (respaldo CBC en el servidor) conectan los
    dos y ninguno es «el declarado». Las lineas «# AVISO:» salen ademas destacadas arriba, y el resto
    de la cabecera, como recomendaciones plegadas (recomendaciones_html)."""
    partes = _orq.partir_comandos(texto)
    if "todo" in partes:
        return avisos_script(texto) + _bloque(prefijo + "-todo", "Comandos para el MikroTik", partes["todo"])
    try:
        ros = int(ros_version)
    except (TypeError, ValueError):
        ros = 7
    orden = ["v7", "v6"]
    out = avisos_script(partes.get("cabecera", "")) + recomendaciones_html(partes.get("cabecera", ""))
    botones, bloques = [], []
    for i, k in enumerate(orden):
        ide = "%s-%s" % (prefijo, k)
        decl = " (la versión declarada de este punto)" if i == 0 and ros != 6 else ""
        botones.append("<button type=button class='btn%s' onclick=\"pcopiar('%s',this)\">Copiar RouterOS %s"
                       "</button>" % ("" if i == 0 else " sec", esc(ide), k[1]))
        bloques.append("<details class=pver><summary>Ver el bloque de RouterOS %s%s</summary>%s</details>"
                       % (k[1], decl, _bloque(ide, "RouterOS %s" % k[1], partes.get(k, ""))))
    out += "<div class=pcopias>%s</div>%s" % ("".join(botones), "".join(bloques))
    if partes.get("certificado"):
        out += _bloque(prefijo + "-cert", "Certificado API-SSL (una sola vez por router)", partes["certificado"])
    return out


# --------------------------------------------------------------------------------------------
# Lista
# --------------------------------------------------------------------------------------------
_COLOR_ETAPA = {"ok": "#1a7f37", "sano": "#1a7f37", "aviso": "#e58a00", "degradada": "#e58a00",
                "fallo": "#c0392b", "error": "#c0392b", "caido": "#c0392b",
                # la etapa aun no se puede medir (se esta creando o falta el MikroTik): no es un fallo
                "pendiente": "#b5b3ad"}


def pill_vpn(p):
    """El pill de la columna VPN: verde conectado, ámbar esperando MikroTik, gris creando /
    arrancando / parada y rojo caída. El `title` lleva el motivo."""
    s = situacion_vpn(p)
    if s["clave"] in ("conectada", "caida"):
        tonos = (("tw-bg-green-50 tw-text-ok", "tw-bg-ok") if s["clave"] == "conectada"
                 else ("tw-bg-red-50 tw-text-bad", "tw-bg-bad"))
        return ("<span class='tw-inline-flex tw-items-center tw-gap-1.5 tw-rounded-full tw-px-2.5 tw-py-0.5 "
                "tw-text-xs tw-font-semibold %s' title='%s'><span class='tw-h-1.5 tw-w-1.5 tw-rounded-full %s'>"
                "</span>%s</span>" % (tonos[0], esc(s["motivo"]), tonos[1], esc(s["texto"])))
    return ("<span class='vpill %s' title='%s'><i></i>%s</span>"
            % ("amb" if s["clave"] == "esperando" else "gris", esc(s["motivo"]), esc(s["texto"])))


def _kpis(total, operativos, vpn, alertas):
    """Franja de cuatro indicadores sobre la lista (Tailwind compilado, prefijo tw-)."""
    def k(titulo, valor, sub, tono):
        return ("<div class='tw-rounded-md tw-border tw-border-line tw-bg-surface tw-p-4 tw-shadow-1'>"
                "<div class='tw-text-xs tw-font-semibold tw-uppercase tw-tracking-wide tw-text-ink-2'>%s</div>"
                "<div class='tw-mt-1 tw-break-words tw-text-2xl tw-font-bold tw-tabular-nums sm:tw-text-3xl %s'>%s</div>"
                "<div class='tw-mt-0.5 tw-text-xs tw-text-ink-3'>%s</div></div>"
                % (esc(titulo), tono, esc(valor), esc(sub)))
    sano = "tw-text-ok" if total and operativos == total else ("tw-text-warn" if total else "tw-text-ink")
    return ("<div class='tw-mb-4 tw-grid tw-grid-cols-[repeat(2,minmax(0,1fr))] tw-gap-3 lg:tw-grid-cols-[repeat(4,minmax(0,1fr))]'>"
            + k("Puntos", _num(total), "registrados", "tw-text-ink")
            + k("Operativos", "%s / %s" % (_num(operativos), _num(total)), "salud por etapas", sano)
            + k("MikroTik conectados", "%s / %s" % (_num(vpn), _num(total)), "por VPN o directo",
                "tw-text-ok" if total and vpn == total else "tw-text-warn")
            + k("Alertas 24 h", _num(alertas), "todos los puntos", "tw-text-ink")
            + "</div>")


def lista(h, consulta):
    d = _dash(h)
    barrer_bajas(d)              # limpieza de bajas sin depender de quien las pidio (A-09)
    est = nodos.leer_estado() or {}
    ahora = time.time()
    filas = ""
    n_ok = n_vpn = tot_24 = 0
    fn = getattr(d, "salud_punto", None)
    for p in nodos.puntos():
        pid = p["pid"]
        ip_mikrotik(p)               # apunta la IP del MikroTik conectado (la ficha la ofrece al desbanear)
        sal = salud(fn, pid)
        pps, ultimo = espejo_pps(pid)
        celda_24, n24 = alertas_24h_html(pid, ahora, p)
        cont = p.get("contenedores") or {}
        su = p.get("suricata") or {}
        estado = ESTADOS.get(p.get("estado"), p.get("estado") or "-")
        if p.get("deseado") == "parado" and p.get("estado") != "parado":
            estado += " (se está parando)"
        avisos = "".join("<div class=pwarn>%s</div>" % esc(AVISOS.get(a, a)) for a in (p.get("avisos") or []))
        avisos += error_html(p, ahora)       # punto en error: su motivo y desde cuando (D3)
        descarte = ""
        try:
            if su.get("kernel_packets"):
                descarte = " &middot; descarte %.1f %%" % (100.0 * float(su.get("kernel_drops") or 0)
                                                           / float(su["kernel_packets"]))
        except (TypeError, ValueError, ZeroDivisionError):
            descarte = ""
        vpn_ok = situacion_vpn(p)["clave"] == "conectada"
        n_ok += 1 if sal.get("estado") == "operativa" else 0
        n_vpn += 1 if vpn_ok else 0
        tot_24 += n24 or 0
        puntos_etapas = "".join(
            "<span class='tw-inline-block tw-h-2.5 tw-w-2.5 tw-rounded-full' title='%s' style='background:%s'></span>"
            % (esc("%s: %s%s" % (e["nombre"], e["estado"], (" - " + e["detalle"]) if e["detalle"] else "")),
               _COLOR_ETAPA.get(e["estado"], SALUD_COLOR.get(e["estado"], "#9a9a95"))) for e in sal["etapas"])
        filas += (
            "<tr><td><a href='/puntos/%s'><b>%s</b></a><div class=hint>%s</div></td>"
            "<td>%s%s</td>"
            "<td><div class='tw-flex tw-items-center tw-gap-2'>%s<span class='tw-flex tw-gap-1'>%s</span></div>"
            "<div class=hint>%s</div></td>"
            "<td>%s</td><td>%s</td><td>%s%s</td><td class=num>%s</td><td>%s</td><td>%s</td></tr>"
            % (esc(pid), esc(p.get("nombre") or pid), esc(pid), esc(estado), avisos,
               salud_chip(sal), puntos_etapas, esc(sal.get("nota") or ""),
               pill_vpn(p),
               ("%.0f paq/s" % pps if pps is not None else "-")
               + (("<div class=hint>hace %s</div>" % _edad(ahora - ultimo)) if ultimo else ""),
               esc(_contenedor(cont.get("suricata"))), descarte,
               celda_24,
               retencion_html(retencion(pid, p), ahora), _acciones_fila(p)))
    if not filas:
        filas = ("<tr><td colspan=9 class=hint style='padding:16px'>Todavía no hay puntos. "
                 "<a href='/puntos/nuevo' onclick='palta();return false;'>Agrega el primero</a>.</td></tr>")
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
        viejo = aviso("El estado tiene %s: el orquestador no lo está actualizando (debería ser cada 15 s)."
                      % _edad(edad_est), "amb")
    cuerpo = (
        "<div class=ptit><div><h1>Puntos</h1><p class=sub>Cada punto es un MikroTik con su propia VPN (o "
        "directo por la red local) y su propio Suricata. Cola del orquestador: %s &middot; pendientes: %s &middot; caben más puntos: %s</p></div>"
        "<div class=ptbtns><a class='btn sec' href='/ajustes'>Volver a Ajustes</a>"
        "<a class=btn href='/puntos/nuevo' onclick='palta();return false;'>Agregar punto</a></div></div>%s%s"
        "<div class='card tablewrap'><table><thead><tr><th>Punto</th><th>Estado</th><th>Salud por etapas</th>"
        "<th>Conexión</th><th>Espejo</th><th>Suricata</th><th class=num>Alertas 24 h</th>"
        "<th>Retención efectiva</th><th>Acciones</th></tr></thead><tbody>%s</tbody></table></div>"
        "<p class=hint>Retención: el objetivo es %d días de eventos por punto; la columna dice desde cuando "
        "hay datos de verdad (si el disco se llena, se borran antes los más viejos y aquí se ve). La "
        "captura es reducida: los primeros 10 KB de cada conexión de los prefijos elegidos.</p>"
        % (esc(linea_cola), esc(cola.get("pendientes", 0)), esc(caben), viejo, _kpis(len(nodos.puntos()), n_ok, n_vpn, tot_24),
           filas, RETENCION_OBJETIVO_DIAS))
    # sin <meta refresh>: recargaria la pagina con el modal de Eliminar a medio escribir. Se recarga
    # cada 30 s solo si no hay ningun modal abierto.
    return h._html(pagina(d, "Puntos", cuerpo + _MODAL_BAJA + modal_alta(cap) + _RECARGA_LISTA
                          + _retomar_lista_html(d)))


def _acciones_fila(p):
    """Iniciar o Detener (segun como este el punto) y Eliminar, en la propia lista. Iniciar/Detener
    son las ordenes de la ficha (punto.arrancar / punto.parar, con su token y el modal de confirmar);
    Eliminar abre el modal de baja con lo mismo que la ficha: escribir el nombre y limpiar el MikroTik."""
    pid, nombre = p["pid"], p.get("nombre") or p["pid"]
    parado = p.get("deseado") == "parado" or p.get("estado") == "parado"
    # textos fijos: el nombre no entra en el JavaScript del onsubmit
    acc, tit, txt, tono = (("arrancar", "Iniciar", "Arranca la VPN y el Suricata del punto.", "")
                           if parado else
                           ("parar", "Detener", "Para la VPN y el Suricata del punto: deja de vigilarse hasta "
                                                "que lo inicies.", ",'danger'"))
    return ("<div class=pacc>"
            "<form method=post action='/puntos/%s/%s' onsubmit=\"return ask(this,'%s','%s','%s'%s)\">%s"
            "<button class='btn sec chico' type=submit>%s</button></form>"
            "<button class='btn peligro chico' type=button data-pid='%s' data-nombre='%s' data-op='%s' "
            "onclick='pbaja(this)'>Eliminar</button></div>"
            % (esc(pid), acc, tit, txt, tit, tono, campo_token(), tit,
               esc(pid), esc(nombre), uuid.uuid4()))


_MODAL_BAJA = (
    "<div id=pbajaov class=pbajaov><form method=post id=pbajaf class=pbajabox data-nombre='' "
    "onsubmit='return pbajaAjax(this)'>"
    "<h3>Eliminar el punto <span id=pbajan></span></h3>"
    "<p>Quita del servidor su VPN, su Suricata y <b>todos sus datos</b>, y del panel sus salidas, su conexión "
    "y sus registros. No se puede deshacer.</p>"
    "<p class=hint>Antes, mientras el túnel sigue arriba, el panel limpia el MikroTik: saca de sus "
    "address-lists las IPs que puso en cuarentena (y el espejo, si lo montó el panel: tus reglas a mano no se "
    "tocan). Si el router no responde, no se elimina; "
    "si ese router ya no existe, desmarca la casilla.</p>"
    "<input type=hidden name=op id=pbajaop value=''>"
    "<label class=l><input type=checkbox name=limpiar_router value=1 checked> Limpiar antes el MikroTik "
    "(cuarentena)</label>"
    "<label class=l>Para confirmar, escribe el nombre del punto: <b id=pbajan2></b></label>"
    "<input class=t name=confirmar id=pbajac autocomplete=off maxlength=31 oninput='pnombre(this)'>"
    "<div class=acciones><button class='btn sec' type=button onclick='pbajano()'>Cancelar</button>"
    "<button class='btn peligro' type=submit disabled>Eliminar</button></div></form></div>"
    "<script>function pbaja(b){var f=document.getElementById('pbajaf'),n=b.getAttribute('data-nombre');"
    "f.action='/puntos/'+b.getAttribute('data-pid')+'/borrar';f.setAttribute('data-nombre',n);"
    "document.getElementById('pbajan').textContent=n;document.getElementById('pbajan2').textContent=n;"
    "document.getElementById('pbajaop').value=b.getAttribute('data-op');var c=document.getElementById('pbajac');"
    "c.value='';pnombre(c);document.getElementById('pbajaov').style.display='flex';c.focus();}"
    "function pbajano(){document.getElementById('pbajaov').style.display='none';}"
    "document.addEventListener('keydown',function(e){if(e.key==='Escape')pbajano();});</script>")

# tampoco con el modal de un trabajo abierto (pjov): la baja desde la lista sigue su avance ahi y
# recargar se llevaba el avance y el resultado
_RECARGA_LISTA = (
    "<script>setInterval(function(){function abierto(id){var m=document.getElementById(id);"
    "return m&&m.style.display&&m.style.display!=='none';}"
    "if(!abierto('pbajaov')&&!abierto('paltaov')&&!abierto('askov')&&!abierto('pjov'))location.reload();},"
    "30000);</script>")


def _retomar_lista_html(d):
    """La baja (panel.baja) que esta persona pidio desde la lista y no llego a ver terminar (cerro la
    pestaña o recargo): la lista la retoma al abrir, el avance si sigue o el resultado UNA vez."""
    usuario, ahora = _usuario(d), time.time()
    ultima = None
    for op_id, rec in sorted(ops().listar().items(), key=lambda kv: kv[1].get("creada") or 0):
        if rec.get("usuario") != usuario or rec.get("orden") != "panel.baja":
            continue
        if ahora - (rec.get("creada") or 0) > RETOMAR_S or (rec.get("terminada") and rec.get("vista")):
            continue
        ultima = {"id": op_id, "orden": "panel.baja"}
    if not ultima:
        return ""
    return "<div id=pjretomar hidden data-ops='%s'></div>" % esc(json.dumps([ultima]))


# --------------------------------------------------------------------------------------------
# Alta
# --------------------------------------------------------------------------------------------
_TXT_NOMBRE = ("<label class=l>Nombre del punto <span class=hint>(minúsculas, números y guiones; p. ej. "
               "norte)</span></label>")
_TXT_ALTA = ("<p class=hint>Los prefijos de abonados se ponen solos (todas las redes privadas y el CGNAT); "
             "si hace falta, se cambian luego en la ficha del punto.</p>")


_JS_MODO = ("<script>function paltaModo(f){var d=f.querySelector('input[name=modo]:checked'),"
            "b=f.querySelector('.pmkip');if(b)b.hidden=!(d&&d.value==='directo');}</script>")


def _campos_conexion(v=None, ocultar=True):
    """Cómo se conecta el MikroTik (el user, 2026-10-18): por VPN, lo de siempre, o directo por la red
    local con su IP. La IP solo se ve con «Directa» (`ocultar`: el modal; la página sin JavaScript la
    enseña siempre)."""
    v = v or {}
    directo = v.get("modo") == "directo"
    fila = "display:flex;gap:6px;align-items:baseline;margin:4px 0;font-weight:400"
    return (
        "<label class=l>Conexión del MikroTik</label>"
        "<label style='%s'><input type=radio name=modo value=vpn%s onchange='paltaModo(this.form)'> "
        "<span>Por VPN <span class=hint>(recomendado: el MikroTik puede estar en cualquier sitio)</span></span></label>"
        "<label style='%s'><input type=radio name=modo value=directo%s onchange='paltaModo(this.form)'> "
        "<span>Directa, sin VPN <span class=hint>(solo si el MikroTik está en la misma red local que este "
        "servidor)</span></span></label>"
        "<div class=pmkip%s><label class=l>IP del MikroTik en la red local <span class=hint>(privada, p. ej. "
        "192.168.88.1)</span></label>"
        "<input class=t name=mk_ip maxlength=15 autocomplete=off inputmode=decimal value='%s'>"
        "<p class=hint>Sin VPN, el espejo va sin cifrar por la red local y solo se acepta desde esa IP.</p></div>"
        % (fila, "" if directo else " checked", fila, " checked" if directo else "",
           " hidden" if ocultar and not directo else "", esc(v.get("mk_ip") or "")))


def _caben_html(cap):
    caben = (cap or {}).get(PERFIL_ALTA)
    if not isinstance(caben, int):
        return ""
    return "<p class=hint>Caben ahora en el servidor: %d punto%s más.</p>" % (caben, "" if caben == 1 else "s")


def modal_alta(cap):
    """«Agregar punto» de la lista: un modal que solo pide el nombre (el user, 2026-10-15). Va por
    fetch (ajax=1): si el orquestador acepta, a /operaciones/<op_id>, donde sale el avance y, al
    terminar, la clave VPN una sola vez; si no, el error dentro del modal. Sin JavaScript, el enlace
    lleva a /puntos/nuevo, la misma pregunta en una pagina."""
    return (
        "<div id=paltaov class=pbajaov><form method=post action='/puntos/nuevo' id=paltaf class=pbajabox "
        "onsubmit='return paltaAjax(this)'>"
        "<h3>Agregar punto</h3>"
        "<input type=hidden name=op value='%s'>%s"
        "<input class=t name=nombre id=paltan required maxlength=31 autocomplete=off "
        "pattern='[a-z0-9][a-z0-9\\-]{1,30}' title='minúsculas, números y guiones, de 2 a 31 caracteres' "
        "oninput='this.value=this.value.toLowerCase()'>%s"
        "<p class=pwarn id=paltaerr hidden></p>%s%s"
        "<div class=acciones><button class='btn sec' type=button onclick='paltano()'>Cancelar</button>"
        "<button class=btn type=submit>Crear punto</button></div></form></div>%s"
        "<script>function palta(){var n=document.getElementById('paltan'),f=document.getElementById('paltaf');"
        "document.getElementById('paltaerr').hidden=true;n.value='';"
        "f.modo.value='vpn';f.mk_ip.value='';paltaModo(f);"
        "document.getElementById('paltaov').style.display='flex';n.focus();}"
        "function paltano(){document.getElementById('paltaov').style.display='none';}"
        "function paltaMal(f,m){var b=f.querySelector('button[type=submit]'),e=document.getElementById('paltaerr');"
        "b.disabled=false;b.textContent='Crear punto';e.textContent=m;e.hidden=false;}"
        "function paltaAjax(f){var b=f.querySelector('button[type=submit]');b.disabled=true;b.textContent='Creando…';"
        "document.getElementById('paltaerr').hidden=true;"
        "pjPost(f,{},function(j){if(j.op_id){location.href='/operaciones/'+j.op_id;return;}"
        "paltaMal(f,j.error||'Sin respuesta del panel.');},function(m){paltaMal(f,m);});return false;}"
        "document.addEventListener('keydown',function(e){if(e.key==='Escape')paltano();});"
        "if(/[?&]alta=1/.test(location.search))document.addEventListener('DOMContentLoaded',palta);</script>"
        % (esc(str(uuid.uuid4())), _TXT_NOMBRE, _campos_conexion(), _caben_html(cap), _TXT_ALTA, _JS_MODO))


def form_nuevo(h, valores=None, mensaje="", codigo=200):
    """La pregunta del modal en una pagina: sin JavaScript, o el error de un envio sin ajax."""
    d = _dash(h)
    v = valores or {}
    token = v.get("op") if _operaciones.RE_OPID.match(v.get("op") or "") else str(uuid.uuid4())
    cap = (((nodos.leer_estado() or {}).get("capacidad") or {}).get("caben")) or {}
    cuerpo = (
        "<div class=ptit><h1>Agregar punto</h1><a class='btn sec' href='/puntos'>Volver a Puntos</a></div>"
        "<p class=sub>Un punto es un MikroTik que manda una copia de su tráfico (el "
        "espejo) al sensor por una VPN propia o, si está en la misma red local que este servidor, directo "
        "y sin VPN. Al crearlo, el servidor prepara su Suricata (y su VPN, si la lleva) y te da "
        "los comandos para el MikroTik: sirven para RouterOS 6.49 o superior y para RouterOS 7.</p>%s%s"
        "<form method=post action='/puntos/nuevo' class=card onsubmit=\"var b=this.querySelector('button');"
        "if(b){b.disabled=true;b.textContent='Creando...';}\">"
        "<input type=hidden name=op value='%s'>%s"
        "<input class=t name=nombre required maxlength=31 value='%s'>%s%s"
        "<div class=acciones><button class=btn type=submit>Crear punto</button>"
        "<a class='btn sec' href='/puntos'>Cancelar</a></div></form>%s"
        % (aviso(mensaje), _caben_html(cap), esc(token), _TXT_NOMBRE, esc(v.get("nombre", "")),
           _campos_conexion(v, ocultar=False), _TXT_ALTA, _JS_MODO))
    return h._html(pagina(d, "Agregar punto", cuerpo), codigo)


def crear(h, form):
    """punto.crear con un op_id que viene del formulario: un doble clic o un reintento con el mismo
    formulario no pide un segundo punto, lleva a la misma operacion. Con ajax=1 (el modal de la
    lista): {op_id} si va, {error} si no."""
    d = _dash(h)
    usuario = _usuario(d)
    ajax = bool(form.get("ajax"))
    token = form.get("op") or ""
    op_id = token if _operaciones.RE_OPID.match(token) else str(uuid.uuid4())
    previa = ops().obtener(op_id)
    if previa is None:
        params, err = validar_formulario_punto(form)
        if err:
            return h._json({"error": err}, 400) if ajax else form_nuevo(h, form, err, 400)
        # reserva atomica: dos envios a la vez del mismo formulario no piden dos puntos
        previa = _reservar_op(op_id, usuario, "punto.crear", nombre=params["nombre"],
                              ros_version=params["ros_version"])
    if previa is not None:
        if previa.get("usuario") != usuario or previa.get("orden") != "punto.crear":
            msg = "Ese formulario ya se uso para otra operación. Recarga la página."
            if ajax:
                return h._json({"error": msg, "token": str(uuid.uuid4())}, 409)
            return h._html(pagina(d, "Operación duplicada", aviso(msg)), 409)
        _bit(d, "PUNTO-CREAR", objetivo=previa.get("nombre") or "", resultado="REPETIDA",
             extra="op=%s" % op_id)
        return h._json({"op_id": op_id}) if ajax else h._redirect("/operaciones/%s" % op_id)
    r = cliente().pedir("punto.crear", params, quien="panel:%s" % usuario, ip=_ip(d), op_id=op_id)
    _bit(d, "PUNTO-CREAR", objetivo=params["nombre"], resultado=r.get("codigo"),
         extra="perfil=%s ros=%s%s op=%s" % (params["perfil"], params["ros_version"],
                                              " directo mk=%s" % params["mk_ip"] if params.get("modo") == "directo" else "",
                                              op_id))
    if r.get("codigo") in ("ACEPTADA", "OK"):
        return h._json({"op_id": op_id}) if ajax else h._redirect("/operaciones/%s" % op_id)
    ops().quitar(op_id)
    codigo = 503 if r.get("codigo") in (_orq.SIN_SERVICIO, _orq.SIN_TOKEN) else (
        409 if "CONFLICTO" in str(r.get("codigo")) else 400)
    msg = _orq.traducir(r.get("codigo"), r.get("mensaje"), r.get("datos"))
    if ajax:
        return h._json({"error": msg, "token": str(uuid.uuid4())}, codigo)
    return form_nuevo(h, dict(form, op=str(uuid.uuid4())), msg, codigo)


# --------------------------------------------------------------------------------------------
# Formularios de un solo uso (A-08): un doble clic o un reintento no repite la orden
# --------------------------------------------------------------------------------------------
# Las ordenes de cola (arrancar, parar, reiniciar, regenerar, ajustar, borrar) usan el token del
# formulario como op_id, como el alta: el orquestador tambien deduplica por op_id. Las que el
# panel hace por si mismo (API guardar/probar/olvidar huella)
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


def _responder(h, pid, res, ajax=False):
    mensaje, codigo, ok, extra = res
    if ajax:
        # el formulario sigue en la pagina: se le da un token nuevo para la siguiente vez
        return h._json({"ok": bool(ok), "mensaje": mensaje, "token": str(uuid.uuid4())}, codigo)
    return ficha(h, pid, mensaje, codigo, ok=ok, extra_espejo=extra)


def _repetida(h, pid, accion, est, ajax=False):
    d = _dash(h)
    if est[0] == "otro":
        return _responder(h, pid, ("Ese formulario ya se uso para otra orden u otro punto. Recarga la ficha.",
                                   409, False, ""), ajax)
    if est[0] == "en_curso":
        _bit(d, "PUNTO-" + accion.upper(), pid=pid, resultado="REPETIDA-EN-CURSO")
        return _responder(h, pid, ("Esa orden ya se está haciendo (doble clic o reintento): espera unos "
                                   "segundos y recarga la ficha.", 409, False, ""), ajax)
    _bit(d, "PUNTO-" + accion.upper(), pid=pid, resultado="REPETIDA")
    if isinstance(est[1], str):
        # ese formulario lanzo un trabajo del panel (por fetch): su resultado esta en el trabajo
        return _responder(h, pid, ("Esa orden ya se lanzó desde la ficha: su resultado se vio allí. "
                                   "(Ese formulario ya se había enviado: no se repitió la orden.)", 409, False, ""), ajax)
    mensaje, codigo, ok, extra = est[1]
    return _responder(h, pid, (((mensaje + " ") if mensaje else "")
                               + "(Ese formulario ya se había enviado: no se repitió la orden.)", codigo, ok, extra),
                      ajax)


def _con_token(h, pid, accion, form, hacer, validar=None, ajax=False):
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
            return _repetida(h, pid, accion, est, ajax)
    if validar is not None:
        pre = validar()
        if pre is not None:
            return _responder(h, pid, pre, ajax)
    if tok:
        est = _tomar_token(tok, clave)
        if est is not None:
            return _repetida(h, pid, accion, est, ajax)
    try:
        res = hacer()
    except BaseException:
        if tok:
            _soltar_token(tok)
        raise
    if tok:
        _cerrar_token(tok, res)
    return _responder(h, pid, res, ajax)


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
    """Los pasos que se guardan y se ensenan: nombre, estado, detalle y cuanto duro (dur_s)."""
    return [{k: p.get(k) for k in ("nombre", "estado", "detalle", "dur_s") if p.get(k) is not None}
            for p in (pasos or []) if isinstance(p, dict)]


ORDENES_CON_CLAVE = ("punto.crear", "punto.vpn.regenerar")

# --------------------------------------------------------------------------------------------
# Clave de la VPN de cada punto, guardada CIFRADA en el panel (el user, 2026-10-15: los comandos
# de la ficha salian con <CLAVE-VPN> y el MikroTik se quedaba con ese texto de clave). El
# orquestador solo guarda su hash (ovpn-auth la verifica); el panel, que es quien la USA para
# armar los comandos, la guarda cifrada con la clave maestra, como la clave de la API del router
# (routers.json). Sin clave maestra no se guarda nada en claro: la ficha pide regenerarla.
# --------------------------------------------------------------------------------------------
_VPN_CLAVES_LOCK = threading.Lock()
PLACEHOLDER_VPN = "<CLAVE-VPN>"


def _vpn_claves_ruta():
    return nodos.ruta("conf", "vpn-claves.json")


def _asoc_vpn(pid):
    return "vpn:%s" % pid


def _vpn_claves(apartar=False):
    """{pid: {usuario, clave cifrada, clave_id, ts}}. Un fichero ilegible se lee como vacío; con
    `apartar` (antes de reescribirlo) se mueve a .corrupto-<ts>, para no perder en silencio las
    claves de los demás puntos al guardar la de uno."""
    ruta = _vpn_claves_ruta()
    try:
        with open(ruta, encoding="utf-8") as f:
            v = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        if apartar and os.path.exists(ruta):
            destino = "%s.corrupto-%d" % (ruta, int(time.time()))
            try:
                os.replace(ruta, destino)
                sys.stderr.write("puntos: %s ilegible (%s): apartado en %s\n" % (ruta, e, destino))
            except OSError:
                pass
        return {}
    v = v.get("puntos") if isinstance(v, dict) else None
    return {k: x for k, x in (v or {}).items() if nodos.pid_valido(k) and isinstance(x, dict)}


def _escribir_vpn_claves(todo):
    ruta = _vpn_claves_ruta()
    os.makedirs(os.path.dirname(ruta), mode=0o700, exist_ok=True)
    tmp = "%s.%d.%d.tmp" % (ruta, os.getpid(), threading.get_ident())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"v": 1, "puntos": todo}, f, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, ruta)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def guardar_clave_vpn(pid, usuario, clave, clave_id=None):
    """Guarda cifrada la clave de la VPN de `pid` (la ultima entregada) con la huella de la clave
    vigente que da el orquestador (`clave_id`). True si quedo guardada. Sin clave maestra, o si el
    disco falla, no guarda nada (nunca en claro) y no lanza: la clave se sigue mostrando."""
    if not (nodos.pid_valido(pid) and usuario and clave):
        return False
    try:
        enc = secretos.cifrar(str(clave), _asoc_vpn(pid))
    except Exception as e:
        sys.stderr.write("puntos: clave VPN de %s sin guardar: %s\n" % (pid, e))
        return False
    try:
        with _VPN_CLAVES_LOCK:
            todo = _vpn_claves(apartar=True)
            todo[pid] = {"usuario": str(usuario), "clave": enc, "clave_id": clave_id or "",
                         "ts": int(time.time())}
            _escribir_vpn_claves(todo)
    except OSError as e:
        sys.stderr.write("puntos: clave VPN de %s sin guardar: %s\n" % (pid, e))
        return False
    return True


def clave_vpn(pid, clave_id=None):
    """(usuario, clave) de la VPN de `pid` si el panel la tiene y se puede descifrar; si no, None.
    Con `clave_id` (la huella de la clave VIGENTE que da el orquestador), solo si es la misma que
    se guardo: tras regenerarla por la CLI o con la entrega perdida, la guardada ya no vale."""
    g = _vpn_claves().get(pid) if nodos.pid_valido(pid) else None
    if not g or not g.get("usuario") or not g.get("clave"):
        return None
    if clave_id is not None and g.get("clave_id") != clave_id:
        return None
    try:
        return g["usuario"], secretos.descifrar(g["clave"], _asoc_vpn(pid))
    except Exception:
        return None


def olvidar_clave_vpn(pid):
    """Borra la clave guardada de `pid` (baja del punto, o regenerada sin llegar al panel). True si
    habia una."""
    with _VPN_CLAVES_LOCK:
        todo = _vpn_claves()
        if todo.pop(pid, None) is None:
            return False
        _escribir_vpn_claves(todo)
    return True


def con_clave_vpn(texto, pid, clave_id=None):
    """Los comandos del orquestador (con <CLAVE-VPN>) con la clave guardada puesta. Solo si es la
    vigente (`clave_id`, ver clave_vpn) y el usuario de los comandos es el de la clave guardada;
    si no, se dejan como vienen. Devuelve (texto, clave puesta o None)."""
    cv = clave_vpn(pid, clave_id)
    if not texto or not cv or PLACEHOLDER_VPN not in texto:
        return texto, None
    usuario, clave = cv
    if not re.search(r"(^|\s)user=%s(\s|$)" % re.escape(usuario), texto, re.M):
        return texto, None
    return texto.replace(PLACEHOLDER_VPN, clave), clave


def cred_html(usuario, clave, prefijo="cred"):
    """Usuario y clave de la VPN a la vista, cada uno con «Copiar» (página de la operación y ficha)."""
    return ("<div class='card cred'><div><span class=hint>Usuario de la VPN</span><br>"
            "<code id=%s-usuario>%s</code> <button type=button class='btn sec' "
            "onclick=\"pcopiar('%s-usuario',this)\">Copiar</button></div>"
            "<div><span class=hint>Clave de la VPN</span><br>"
            "<code id=%s-clave>%s</code> <button type=button class='btn sec' "
            "onclick=\"pcopiar('%s-clave',this)\">Copiar</button></div></div>"
            % (prefijo, esc(usuario), prefijo, prefijo, esc(clave), prefijo))


def orden_set_clave(clave):
    """La orden que pone la clave en la ids-vpn que el router ya tiene (y la activa). Con la
    verificacion del servidor, como el script del alta: un router de antes de VPN-01 la necesita
    tras renovar el certificado, y en los demas ya estaba."""
    return "/interface ovpn-client set [find name=ids-vpn] password=%s verify-server-certificate=yes disabled=no\n" % clave


def regenerar_form(pid, texto="Regenerar la clave VPN", clase="btn"):
    return ("<form method=post action='/puntos/%s/regenerar' onsubmit=\"return ask(this,"
            "'Regenerar la clave VPN','Se crea una clave nueva para la VPN de este punto. El MikroTik deja "
            "de conectar hasta que le pongas la nueva (el panel te da la orden con la clave ya puesta).',"
            "'Regenerar')\">%s<button class='%s' type=submit>%s</button></form>"
            % (esc(pid), campo_token(), clase, esc(texto)))


MAX_LOG_LINEAS = 120
MAX_LOG_LARGO = 600
# lo que nunca se ensena de un log aunque el orquestador ya lo filtre (password|key, como logs())
RE_LOG_SECRETO = re.compile(r"password|passwd|key|clave|secret|token", re.I)


def log_limpio(lineas):
    """Las ultimas lineas de log de una operacion para la pagina: texto, con tope de lineas y de
    largo, y sin las que puedan llevar una clave. [] si no hay nada que ensenar."""
    if not isinstance(lineas, (list, tuple)):
        return []
    out = []
    for x in lineas[-MAX_LOG_LINEAS:]:
        if x is None or isinstance(x, (dict, list)):
            continue
        t = str(x)
        if RE_LOG_SECRETO.search(t):
            continue
        out.append(t[:MAX_LOG_LARGO])
    return out


def _anotar_op(op_id, sobrescribir=True, **campos):
    """Apunta en el registro de la operacion lo que `Operaciones.terminar` no admite: solo
    `entrega_clave` («mostrada» o «no_llego»), nunca la clave (ver Operaciones.anotar)."""
    return ops().anotar(op_id, sobrescribir=sobrescribir, **campos)


def _entrega_clave(orden, codigo, res):
    """Que paso con la clave de la VPN de una operacion recien terminada que la entrega: «mostrada»
    (vino en esta respuesta), «ya_existia» (alta repetida: se entrego en su dia) o «no_llego»
    (el orquestador la tenia solo en memoria y se reinicio antes de que el panel la pidiera)."""
    if orden not in ORDENES_CON_CLAVE or codigo != "OK":
        return None
    if res.get("modo") == "directo":            # sin VPN no hay clave que entregar
        return None
    if res.get("clave"):
        return "mostrada"
    if res.get("ya_entregada"):
        return "ya_existia"
    return "no_llego"


def vista_op(d, op_id, usuario):
    """Modelo de la pagina de una operacion. None si no existe o no es de este usuario."""
    rec = ops().obtener(op_id)
    if rec is None or rec.get("usuario") != usuario:
        return None
    if es_panel(rec.get("orden")):
        return _vm_trabajo(op_id, rec)        # lo hace el panel: el orquestador no lo conoce
    vm = {"orden": rec.get("orden"), "pid": rec.get("pid"), "titulo": rec.get("nombre") or rec.get("pid"),
          "ros_version": rec.get("ros_version")}
    if rec.get("terminada"):
        vm.update({"terminada": True, "ok": rec.get("codigo") == "OK", "pasos": rec.get("pasos"),
                   "mensaje": _orq.traducir(rec.get("codigo"), rec.get("mensaje")),
                   "ya_existia": rec.get("ya_existia"), "entrega_clave": rec.get("entrega_clave")})
        if not vm["ok"]:
            # los logs del fallo no se guardan en el panel: se vuelven a pedir (una operacion que
            # termino mal no lleva clave). Si el orquestador ya no la conoce, sin logs.
            r = cliente().pedir("op.estado", {"op_id": op_id}, quien="panel:%s" % usuario, ip=_ip(d))
            if r.get("codigo") == "OK":
                vm["log_tail"] = log_limpio((r.get("datos") or {}).get("log_tail"))
        return vm
    r = cliente().pedir("op.estado", {"op_id": op_id}, quien="panel:%s" % usuario, ip=_ip(d))
    if r.get("codigo") not in ("OK", "NO_EXISTE"):
        vm.update({"terminada": False, "error_canal": _orq.traducir(r.get("codigo"), r.get("mensaje"))})
        return vm
    if r.get("codigo") == "NO_EXISTE":
        ops().terminar(op_id, codigo="FALLO", mensaje="el orquestador no conoce esta operación")
        vm.update({"terminada": True, "ok": False,
                   "mensaje": "El orquestador no conoce esta operación (¿se reinició el servidor?). "
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
    if codigo != "OK":
        vm["log_tail"] = log_limpio(dd.get("log_tail"))
    if (codigo == "OK" and rec.get("orden") in ORDENES_CON_CLAVE and res.get("clave")
            and guardar_clave_vpn(pid, res.get("usuario"), res.get("clave"), res.get("clave_id"))):
        # la entrega el orquestador una sola vez, a esta respuesta: el panel se la queda cifrada
        # para que la ficha del punto de los comandos con la clave puesta
        vm["clave_guardada"] = True
        _bit(d, "PUNTO-VPN-CLAVE-GUARDADA", pid=pid or "", resultado="ok", extra="op=%s" % op_id)
    elif (codigo == "OK" and rec.get("orden") == "punto.vpn.regenerar" and not res.get("clave")
          and pid and nodos.pid_valido(pid)):
        # regenerada pero la clave no llego (orquestador reiniciado): la guardada ya no vale
        try:
            olvidar_clave_vpn(pid)
        except OSError:
            pass
    entrega = _entrega_clave(rec.get("orden"), codigo, res)
    primera = ops().terminar(op_id, codigo=codigo, mensaje=mensaje, pid=pid, pasos=_pasos_limpios(pasos),
                             ya_existia=ya)
    if not primera:
        # Otra peticion la cerro a la vez. El orquestador entrega la clave UNA vez, a la primera
        # op.estado que ve la operacion terminada: si vino en ESTA respuesta, solo esta peticion
        # la tiene y la ensena aunque haya perdido la carrera de `terminar` (B-12).
        rec = ops().obtener(op_id) or {}
        vm.update({"terminada": True, "ok": rec.get("codigo") == "OK", "pasos": rec.get("pasos"),
                   "mensaje": _orq.traducir(rec.get("codigo"), rec.get("mensaje")),
                   "entrega_clave": rec.get("entrega_clave")})
        if res.get("clave"):
            # la que gano `terminar` pudo apuntar «no_llego»: la clave SI llego, a esta
            _anotar_op(op_id, entrega_clave="mostrada")
            vm.update({"ok": codigo == "OK", "pid": pid, "resultado": res, "ya_existia": ya,
                       "mensaje": _orq.traducir(codigo, mensaje, res), "entrega_clave": "mostrada"})
        return vm
    if entrega:
        # D8: con esto una visita posterior sabe si la clave se ensenó o no llego nunca
        # sin pisar el «mostrada» de una peticion a la vez que si recibio la clave (B-12)
        _anotar_op(op_id, sobrescribir=False, entrega_clave=entrega)
    vm["entrega_clave"] = entrega
    _bit(d, (rec.get("orden") or "op").upper().replace(".", "-") + "-FIN", pid=pid or "",
         resultado=codigo, extra="op=%s" % op_id)
    if codigo == "OK" and rec.get("orden") == "punto.borrar" and pid:
        barrer_bajas(d, esperar=True)
    vm.update({"terminada": True, "ok": codigo == "OK", "pid": pid, "resultado": res, "ya_existia": ya,
               "mensaje": _orq.traducir(codigo, mensaje, res)})
    return vm


def _dur(v):
    try:
        return " · %s s" % ("%.1f" % float(v)).replace(".", ",")
    except (TypeError, ValueError):
        return ""


def _pasos(pasos):
    if not pasos:
        return ""
    out = "<ol>"
    for p in pasos:
        if not isinstance(p, dict):
            continue
        ok = p.get("estado") == "ok"
        out += "<li>%s <span class=hint>%s%s%s</span></li>" % (
            esc(p.get("nombre")), "hecho" if ok else "fallo",
            _dur(p.get("dur_s")) if p.get("dur_s") is not None else "",
            (" &mdash; " + esc(p.get("detalle"))) if p.get("detalle") else "")
    return out + "</ol>"


def _avance_html(vm):
    """El avance de una operacion aun abierta (la primera pintura; luego lo cambia el JS)."""
    out = aviso(vm.get("error_canal"), "amb")
    if vm.get("delante"):
        out += "<p class=pjest>En cola: %s operación(es) delante.</p>" % esc(vm.get("delante"))
    else:
        out += "<p class=pjest>%s</p>" % esc(("Paso actual: %s (%s)" % (vm.get("paso"), vm.get("avance")))
                                             if vm.get("paso") else "Esperando al orquestador...")
    if vm.get("porcentaje") is None:
        out += "<progress></progress>"
    else:
        out += "<progress max=100 value='%s'></progress>" % esc(vm.get("porcentaje", 0))
    return out + _pasos(vm.get("pasos"))


def pagina_op(h, op_id):
    d = _dash(h)
    # la limpieza de las bajas no depende de quien abra la operacion (A-09)
    barrer_bajas(d)
    vm = vista_op(d, op_id, _usuario(d))
    if vm is None:
        return _html_privado(h, pagina(d, "Operación", "<h1>Operación desconocida</h1><p>Esa operación no "
                                       "existe o no la pediste tu.</p>"), 404)
    tit = ("<div class=ptit><h1>%s%s</h1><a class='btn sec' href='/puntos'>Volver a Puntos</a></div>"
           % (esc(ORDENES.get(vm.get("orden"), vm.get("orden") or "Operación")),
              (" &middot; " + esc(vm.get("titulo"))) if vm.get("titulo") else ""))
    if not vm.get("terminada"):
        # sin <meta refresh>: antes la pagina entera se recargaba cada 2 s (saltaba y parpadeaba).
        # Ahora el JS pide /operaciones/<op_id>?json=1 y cambia la barra, los pasos y, al terminar,
        # el resultado (con la clave de un solo uso si la trae: la entrega esa misma respuesta).
        cuerpo = (tit + "<div id=opcuerpo><div id=opvivo>" + _avance_html(vm) + "</div>"
                  "<p class=hint>Esta página sigue el avance sola, sin recargarse.</p></div>"
                  "<script>document.addEventListener('DOMContentLoaded',function(){popSeguir('%s');});</script>"
                  % esc(op_id))
        # sin JS no avanzaria nunca (revision 2026-10-15, B4): ahi si, recarga cada 5 s
        return _html_privado(h, pagina(d, "Operación", cuerpo, refresco_sin_js=5))
    _anotar_op(op_id, vista=True)
    return _html_privado(h, pagina(d, "Operación", tit + "<div id=opcuerpo>" + _cuerpo_fin(d, vm) + "</div>"))


def _cuerpo_fin(d, vm):
    """Lo que se ve de una operacion terminada, sin el titulo: la pagina de la operacion y el
    JSON del avance (que lo pinta sin recargar) usan esto mismo. Si la operacion entrega la clave
    de la VPN y vino en esta respuesta, va aqui: se pinta UNA vez."""
    cuerpo = _pasos(vm.get("pasos"))
    pid = vm.get("pid")
    if vm.get("panel"):
        cuerpo += vm.get("html_panel") or aviso(vm.get("mensaje"), "info" if vm.get("ok") else "err")
        if vm.get("siguiente"):
            cuerpo += ("<p><a class=btn href='%s'>Seguir la baja en el orquestador</a></p>"
                       % esc(vm.get("siguiente")))
        elif pid and nodos.pid_valido(pid) and nodos.existe(pid):
            cuerpo += "<p><a class='btn sec' href='/puntos/%s'>Ir a la ficha del punto</a></p>" % esc(pid)
        return cuerpo
    if not vm.get("ok"):
        cuerpo += aviso(vm.get("mensaje"))
        lineas = vm.get("log_tail") or []
        if lineas:
            # D2: lo que dijeron los contenedores antes de deshacer (el orquestador lo filtra de
            # claves; aqui se vuelve a filtrar y todo va escapado)
            cuerpo += ("<details class=plogs><summary>Ver los últimos logs</summary>"
                       "<pre class=cmd>%s</pre></details>" % esc("\n".join(lineas)))
        if vm.get("orden") == "punto.crear":
            cuerpo += "<p><a class=btn href='/puntos?alta=1'>Volver a intentarlo</a></p>"
        return cuerpo
    if vm.get("orden") == "punto.borrar":
        cuerpo += aviso("Punto borrado: se quitaron su VPN, su Suricata y sus datos del servidor y del panel.", "ok")
        # el script del alta ya no pone firewall ni rutas (decision del 2026-10-15): en el router
        # queda la VPN y la CA (y el usuario de la API si lo creo el operador: el script ya no lo
        # crea); la ruta y las reglas solo las tienen los routers dados de alta con el script
        # anterior (comentario EXACTO: no toca el `:espejo`)
        cuerpo += ("<p class=hint>En el MikroTik quedan la interfaz <code>ids-vpn</code>, la CA del VPS que "
                   "importó el alta y el usuario de la API si lo creaste (p. ej. <code>ids-api</code>). Quítalos "
                   "a mano (<a "
                   "href='/documentacion?p=puntos-un-mikrotik-su-vpn-y-su-suricata' target=_blank rel=noopener>"
                   "Documentación &rarr; Puntos: un MikroTik, su VPN y su Suricata</a>, apartado <b>Baja</b>); "
                   "la CA, con:</p>"
                   "<pre class=cmd>/certificate remove [find name~\"^ids-maat-ca-%s\"]\n"
                   "/file remove [find name~\"^ids-maat-ca-%s\"]</pre>"
                   "<p class=hint>Si el router se dio de alta con el script anterior, lleva además una ruta y "
                   "reglas de firewall con el comentario <code>IDS ids-maat:%s</code>. Se quitan con estas dos "
                   "órdenes (comentario exacto: no tocan nada del espejo):</p>"
                   "<pre class=cmd>/ip firewall filter remove [find comment=\"IDS ids-maat:%s\"]\n"
                   "/ip route remove [find comment=\"IDS ids-maat:%s\"]</pre>"
                   "<p><a class=btn href='/puntos'>Volver a Puntos</a></p>"
                   % (esc(pid), esc(pid), esc(pid), esc(pid), esc(pid)))
        return cuerpo
    r = vm.get("resultado") or {}
    # un punto directo (sin VPN): no hay clave ni comandos que pegar; solo los datos del espejo
    directo = r.get("modo") == "directo" or bool(
        pid and nodos.pid_valido(pid) and es_directo(nodos.punto(pid)))
    if vm.get("orden") == "punto.crear" and directo:
        cuerpo += aviso(("Ese punto ya existía con los mismos datos. " if (r.get("ya_entregada") or vm.get("ya_existia"))
                         else "Listo. ")
                        + "Es un punto directo, sin VPN: no hay nada que pegar en el MikroTik para "
                        "conectarlo. Solo falta su espejo, con los datos de abajo (también en la ficha, "
                        "Conexión).", "ok")
        if r.get("comandos"):
            cuerpo += "<pre class=cmd>%s</pre>" % esc(r["comandos"])
    elif r.get("clave"):
        cuerpo += aviso("Listo. La clave de la VPN ya va puesta en los comandos de abajo y la ficha del punto "
                        "los vuelve a dar completos." if vm.get("clave_guardada") else
                        "Listo. Copia ahora la clave: el panel no la pudo guardar (falta la clave maestra) y no "
                        "la vuelve a mostrar. Si la pierdes, regenérala desde la ficha del punto.",
                        "ok" if vm.get("clave_guardada") else "amb")
        cuerpo += cred_html(r.get("usuario"), r.get("clave"))
        if vm.get("orden") == "punto.vpn.regenerar":
            # el router ya tiene ids-vpn: no se vuelve a crear, se le cambia la clave con UNA orden,
            # ya con la clave puesta. Si el servidor renovo su certificado (punto de antes de VPN-01),
            # el router necesita ademas la CA del VPS y la verificacion, que traen los bloques de abajo.
            renovado = "certificado del servidor renovado" in str(vm.get("mensaje") or "")
            cuerpo += ("<h2>Si el router ya tiene la VPN</h2><p class=hint>Pega solo esta orden: cambia la "
                       "clave de <code>ids-vpn</code> y el túnel vuelve a conectar.</p>")
            cuerpo += _bloque("op-set", "Cambiar la clave en el MikroTik", orden_set_clave(r.get("clave")))
            if renovado:
                cuerpo += aviso("El servidor renovó además su certificado: antes, pega en el router las líneas "
                                "de la CA del VPS del bloque de abajo.", "amb")
        cuerpo += ("<h2>Comandos para el MikroTik</h2><p class=hint>Ya llevan la clave de la VPN: "
                   "solo crean la VPN.</p>")
        cuerpo += comandos_html(r.get("comandos", ""), vm.get("ros_version"), "op")
    elif vm.get("orden") == "punto.crear" and (r.get("ya_entregada") or vm.get("ya_existia")):
        cuerpo += aviso("Ese punto ya existía con los mismos datos. Los comandos para el MikroTik están en la "
                        "ficha del punto (VPN); si allí salen sin la clave, regenérala desde la misma ficha.", "amb")
    elif vm.get("orden") == "punto.ajustar" and r.get("api_puerto"):
        sin_ssl = str(r.get("api_puerto")) == "8728"
        cuerpo += aviso("Puerto de la API cambiado: el panel habla con el MikroTik por la %s. En el router: "
                        "%s. Después, «Probar la conexión» en la ficha (API)."
                        % ("API sin SSL (8728)" if sin_ssl else "API-SSL (8729)",
                           "/ip service set api disabled=no" if sin_ssl else CMD_CERT_API_SSL), "info")
    elif vm.get("orden") == "punto.ajustar":
        cuerpo += aviso("Prefijos cambiados en el punto. Si tu espejo del MikroTik filtra por una address-list (p. ej. «Redes Privadas»), añade ahí también los prefijos adicionales.", "info")
    elif vm.get("orden") in ORDENES_CON_CLAVE and vm.get("entrega_clave") == "no_llego":
        # D8: la clave solo vive en la memoria del orquestador hasta que el panel la pide; si se
        # reinicio antes, se perdio. Sin ella el MikroTik no puede conectar: hay que regenerarla.
        cuerpo += aviso("La clave no llegó al panel (el orquestador se reinició antes de entregarla) y ya no "
                        "se puede recuperar. Regénérala: el MikroTik no puede conectar sin ella.", "err")
        if pid and nodos.pid_valido(pid):
            cuerpo += "<p>%s</p>" % regenerar_form(pid)
    elif vm.get("orden") in ORDENES_CON_CLAVE:
        cuerpo += aviso("La operación terminó bien. Los comandos para el MikroTik, con la clave de la VPN "
                        "puesta, están en la ficha del punto (VPN).", "info")
    else:
        cuerpo += aviso("La operación terminó bien.", "info")
    if pid and nodos.pid_valido(pid):
        ancla = (("#api" if r.get("api_puerto") else "#prefijos") if vm.get("orden") == "punto.ajustar"
                 else "")
        cuerpo += "<p><a class=btn href='/puntos/%s%s'>Ir a la ficha del punto</a></p>" % (esc(pid), ancla)
    return cuerpo


RE_AVANCE_TOTAL = re.compile(r"^[0-9]+/[0-9]+$")


def _json_privado(h, obj, code=200):
    """JSON con las cabeceras de la pagina de la operacion (puede llevar la clave de un solo uso
    de la VPN): ni cache ni marcos (B-11)."""
    b = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    h.send_response(code)
    h.send_header("Content-Type", "application/json; charset=utf-8")
    h.send_header("Content-Length", str(len(b)))
    for k, v in CABECERAS_PRIVADAS:
        h.send_header(k, v)
    h.end_headers()
    h.wfile.write(b)


def json_op(h, op_id):
    """GET /operaciones/<op_id>?json=1: el avance de una operacion (del orquestador o del panel)
    para pintarlo sin recargar. Al terminar trae el cuerpo del resultado (`html`, el mismo de la
    pagina) y se apunta como vista (la ficha ya no lo vuelve a ensenar)."""
    d = _dash(h)
    barrer_bajas(d)
    vm = vista_op(d, op_id, _usuario(d))
    if vm is None:
        return _json_privado(h, {"error": "Esa operación no existe o no la pediste tú."}, 404)
    orden = vm.get("orden")
    j = {"orden": orden, "titulo": ORDENES.get(orden, orden or "Operación"), "pid": vm.get("pid"),
         "terminada": bool(vm.get("terminada"))}
    if not j["terminada"]:
        av = vm.get("avance")
        j.update(etapa=vm.get("paso") or "", avance=av or "",
                 porcentaje=_porcentaje(av) if RE_AVANCE_TOTAL.match(str(av or "")) else None,
                 delante=vm.get("delante") or 0, pasos=_pasos_limpios(vm.get("pasos")),
                 aviso=vm.get("error_canal") or "")
        return _json_privado(h, j)
    j.update(ok=bool(vm.get("ok")), mensaje=vm.get("mensaje") or "", pasos=_pasos_limpios(vm.get("pasos")),
             html=_cuerpo_fin(d, vm), titulo_fin=vm.get("titulo_fin") or "",
             siguiente=vm.get("siguiente") or "")
    _anotar_op(op_id, vista=True)
    return _json_privado(h, j)


def encolar_orden(d, pid, orden, params, usuario, ip, nombre=None, token=""):
    """Una orden de cola del orquestador SIN el manejador HTTP (la usa tambien un trabajo del panel,
    p. ej. la baja): ("aceptada"|"repetida"|"otro"|"fallo", op_id, mensaje). El op_id es el token
    del formulario (A-08, como el alta): el mismo formulario enviado dos veces lleva a la misma
    operacion y el orquestador no la encola dos veces. Sin token valido (cliente viejo), uno nuevo."""
    p = nodos.punto(pid) or {}
    op_id = token if _operaciones.RE_OPID.match(token or "") else str(uuid.uuid4())
    previa = _reservar_op(op_id, usuario, orden, pid=pid, nombre=nombre or p.get("nombre") or pid,
                          ros_version=p.get("ros_version"))
    accion = orden.upper().replace(".", "-")
    if previa is not None:
        if (previa.get("usuario"), previa.get("orden"), previa.get("pid")) != (usuario, orden, pid):
            return "otro", op_id, "Ese formulario ya se uso para otra orden u otro punto. Recarga la ficha."
        _bit(d, accion, pid=pid, resultado="REPETIDA", extra="op=%s" % op_id, quien=usuario, ip=ip)
        return "repetida", op_id, ""
    r = cliente().pedir(orden, params, quien="panel:%s" % usuario, ip=ip, op_id=op_id)
    _bit(d, accion, pid=pid, resultado=r.get("codigo"), extra="op=%s" % op_id, quien=usuario, ip=ip)
    if r.get("codigo") in ("ACEPTADA", "OK"):
        return "aceptada", op_id, ""
    ops().quitar(op_id)
    return "fallo", op_id, _orq.traducir(r.get("codigo"), r.get("mensaje"), r.get("datos"))


def _encolar(h, pid, orden, params, nombre=None, token="", al_fallar=None, nota_fallo="", ajax=False):
    """Una orden de cola del orquestador -> 303 a su avance (con ajax=1, {op_id} para seguirla en la
    ficha sin recargar)."""
    d = _dash(h)
    est, op_id, msg = encolar_orden(d, pid, orden, params, _usuario(d), _ip(d), nombre=nombre, token=token)
    if est in ("aceptada", "repetida"):
        if ajax:
            return h._json({"op_id": op_id, "token": str(uuid.uuid4())})
        return h._redirect("/operaciones/%s" % op_id)
    if al_fallar is not None:
        al_fallar(pid)
    if ajax:
        return h._json({"error": nota_fallo + msg, "token": str(uuid.uuid4())}, 409)
    return ficha(h, pid, nota_fallo + msg, 409)


# --------------------------------------------------------------------------------------------
# Trabajos del panel: lo que habla con el router va en un hilo y la pagina sigue su avance
# --------------------------------------------------------------------------------------------
# La baja (limpiar el router) tardaba 15-45 s o mas DENTRO de la peticion (y el espejo de la ficha,
# hasta 2026-10-16). Ahora la peticion (fetch, ajax=1) devuelve enseguida el id
# del trabajo y GET /operaciones/<id>?json=1 dice su avance por etapas y su resultado.
#
# Registro: el mismo de las operaciones del orquestador (operaciones.json, 0600) con ordenes
# «panel.*»: asi una sola pantalla y un solo JSON sirven para las dos, la ficha retoma lo que
# quedo a medias si se cerro la pestaña y el resultado se ve UNA vez (`vista`). El avance vive
# solo en memoria; un trabajo abierto de otro proceso (el panel se reinicio) se cierra como
# interrumpido al mirarlo. Un solo trabajo con el router por punto: un segundo clic (o una
# segunda pestaña) recibe el id del que esta en marcha y se engancha a el, sin esperar 120 s a
# un cerrojo. El hilo no tiene el contexto de la peticion: usuario e IP van explicitos.
ARRANQUE = uuid.uuid4().hex          # este proceso del panel
RETOMAR_S = 2 * 3600                 # la ficha retoma lo de las ultimas 2 h que no se vio
RETOMABLES = ("punto.ajustar", "punto.arrancar", "punto.parar", "punto.reiniciar")
MAX_HTML_TRABAJO = 200 * 1024
RE_CUENTA = re.compile(r"[0-9]+/[0-9]+")
_TRAB_LOCK = threading.Lock()
_TRAB_EN_CURSO = {}                  # pid -> op_id del trabajo del panel que habla con su router


def es_panel(orden):
    return str(orden or "").startswith("panel.")


def _cerrar_huerfano(op_id, rec):
    """Un trabajo del panel abierto que no es de este proceso ya no corre: se cierra."""
    if rec and es_panel(rec.get("orden")) and not rec.get("terminada") and rec.get("proceso") != ARRANQUE:
        ops().terminar(op_id, codigo="FALLO", mensaje=(
            "el panel se reinició mientras se hacía: mira cómo quedó el router "
            "antes de repetirlo"))
        rec = ops().obtener(op_id) or rec
    return rec


def _vm_trabajo(op_id, rec):
    """Modelo de un trabajo del panel para la pagina de la operacion y su JSON."""
    rec = _cerrar_huerfano(op_id, rec)
    vm = {"panel": True, "orden": rec.get("orden"), "pid": rec.get("pid"),
          "titulo": rec.get("nombre") or rec.get("pid"), "terminada": bool(rec.get("terminada"))}
    if not vm["terminada"]:
        av = rec.get("avance")
        vm.update(paso=rec.get("etapa") or "", avance=av or "",
                  porcentaje=_porcentaje(av) if RE_AVANCE_TOTAL.match(str(av or "")) else None,
                  pasos=rec.get("pasos") or [])
        return vm
    r = rec.get("resultado") if isinstance(rec.get("resultado"), dict) else {}
    vm.update(ok=rec.get("codigo") == "OK", mensaje=rec.get("mensaje") or "", pasos=rec.get("pasos") or [],
              html_panel=str(r.get("html") or ""), titulo_fin=str(r.get("titulo_fin") or ""),
              siguiente=str(r.get("siguiente") or ""))
    return vm


def trabajo_en_curso(pid):
    """(op_id, registro) del trabajo del panel que habla ahora con el router del punto, o (None, None)."""
    with _TRAB_LOCK:
        op_id = _TRAB_EN_CURSO.get(pid)
        rec = ops().obtener(op_id) if op_id else None
        if rec and not rec.get("terminada"):
            return op_id, rec
        _TRAB_EN_CURSO.pop(pid, None)
    return None, None


def lanzar_trabajo(d, pid, orden, usuario, ip, fn, nombre=None):
    """Arranca `fn(avance)` en un hilo como trabajo `orden` del punto. (op_id, nuevo): si ya habia
    uno con el router de ese punto, devuelve el suyo (nuevo=False) y no lanza otro.

    `fn` devuelve {"ok", "mensaje", "resultado": {"html", "titulo_fin", "siguiente"}}; `avance`
    acepta `avance(etapa="orden 2/6")`: cada etapa nueva cierra la anterior con su duracion y una
    cuenta «i/N» da la barra.

    El trabajo en marcha de OTRO usuario no se comparte: (None, False) y quien llama responde 409
    («otro administrador está usando el router»); engancharse a el acababa en un 404 confuso,
    porque solo quien pidio una operacion puede ver su avance."""
    with _TRAB_LOCK:
        previo = _TRAB_EN_CURSO.get(pid)
        rec = ops().obtener(previo) if previo else None
        if rec and not rec.get("terminada"):
            if rec.get("usuario") != usuario:
                return None, False
            return previo, False
        op_id = str(uuid.uuid4())
        ops().registrar(op_id, usuario, orden, pid=pid,
                        nombre=nombre or (nodos.punto(pid) or {}).get("nombre") or pid,
                        extra={"proceso": ARRANQUE, "ip": ip, "etapa": "en cola"})
        _TRAB_EN_CURSO[pid] = op_id
    try:
        threading.Thread(target=_correr_trabajo, args=(d, op_id, pid, usuario, ip, fn), daemon=True,
                         name="panel-%s-%s" % (orden, pid)).start()
    except Exception as e:
        # sin hilo (sin memoria, demasiados hilos): la operacion se cierra y el router queda libre;
        # si no, _TRAB_EN_CURSO apuntaria para siempre a un trabajo que nunca corre
        ops().terminar(op_id, codigo="FALLO", mensaje=("el panel no pudo arrancar el trabajo (%s): "
                                                      "vuelve a intentarlo" % (str(e)[:120] or type(e).__name__)),
                       etapa=None, avance=None)
        with _TRAB_LOCK:
            if _TRAB_EN_CURSO.get(pid) == op_id:
                _TRAB_EN_CURSO.pop(pid, None)
    return op_id, True


MSG_ROUTER_OCUPADO = ("Otro administrador está usando el router de este punto (%s). Espera a que "
                      "termine y vuelve a intentarlo.")


def _router_ocupado(pid):
    """Texto del 409 cuando el router del punto lo esta usando otro administrador."""
    _op, rec = trabajo_en_curso(pid)
    return MSG_ROUTER_OCUPADO % ORDENES.get((rec or {}).get("orden"), (rec or {}).get("orden") or "otra orden")


def _correr_trabajo(d, op_id, pid, usuario, ip, fn):
    ctx = getattr(d, "CTX", None)
    if ctx is not None:                       # la bitacora del nucleo toma de aqui quien e IP
        ctx.user, ctx.ip = usuario, ip
    pasos = []
    actual = {"clave": None, "etapa": None, "t": time.monotonic()}

    def cerrar(estado):
        if actual["etapa"] is not None:
            pasos.append({"nombre": actual["etapa"], "estado": estado,
                          "dur_s": round(time.monotonic() - actual["t"], 1)})
            actual["etapa"] = None

    def avance(etapa=None, **_otros):
        etapa = str(etapa or "")[:160]
        clave = RE_CUENTA.sub("", etapa).strip()
        if clave != actual["clave"] or actual["etapa"] is None:
            cerrar("ok")
            actual.update(clave=clave, t=time.monotonic())
        actual["etapa"] = etapa
        m = RE_CUENTA.search(etapa)
        ops().avanzar(op_id, etapa=etapa, avance=m.group(0) if m else None, pasos=list(pasos))

    res = None
    try:
        res = fn(avance)
    except Exception as e:
        res = {"ok": False, "mensaje": "fallo inesperado del panel: %s" % (str(e)[:200] or type(e).__name__)}
    finally:
        try:
            if not isinstance(res, dict):
                res = {"ok": False, "mensaje": "el trabajo no terminó (se cortó a medias)"}
            cerrar("ok" if res.get("ok") else "fallo")
            r = res.get("resultado") if isinstance(res.get("resultado"), dict) else {}
            if len(str(r.get("html") or "")) > MAX_HTML_TRABAJO:
                r = dict(r, html=aviso("El resultado es demasiado largo para enseñarlo aquí.", "amb"))
            ops().terminar(op_id, codigo="OK" if res.get("ok") else "FALLO",
                           mensaje=str(res.get("mensaje") or "")[:600], resultado=r, pasos=pasos,
                           etapa=None, avance=None)
        finally:
            with _TRAB_LOCK:
                if _TRAB_EN_CURSO.get(pid) == op_id:
                    _TRAB_EN_CURSO.pop(pid, None)
            if ctx is not None:
                ctx.user = ctx.ip = None


def _retomar_html(d, pid):
    """Lo de este punto que la persona dejo a medias o termino sin verlo (cerro la pestaña): la ficha
    lo retoma al abrir (el avance si sigue, o el resultado en un modal UNA vez). Como mucho uno de
    prefijos (panel de la ficha) y uno del modal; nunca alta, regenerar ni baja del orquestador."""
    usuario, ahora = _usuario(d), time.time()
    pref = modal = None
    for op_id, rec in sorted(ops().listar().items(), key=lambda kv: kv[1].get("creada") or 0):
        orden = rec.get("orden")
        if rec.get("usuario") != usuario or rec.get("pid") != pid:
            continue
        if not (es_panel(orden) or orden in RETOMABLES):
            continue
        if ahora - (rec.get("creada") or 0) > RETOMAR_S or (rec.get("terminada") and rec.get("vista")):
            continue
        if orden == "punto.ajustar":
            pref = {"id": op_id, "orden": orden}
        else:
            modal = {"id": op_id, "orden": orden}
    lista_ops = [x for x in (pref, modal) if x]
    if not lista_ops:
        return ""
    return "<div id=pjretomar hidden data-ops='%s'></div>" % esc(json.dumps(lista_ops))


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
        ops().terminar(op_id, codigo="FALLO", mensaje="el orquestador no conoce esta operación")
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
    cancelar = getattr(d, "baja_cancelada", None)
    for op_id, rec in _ops_baja():
        pid = rec["pid"]
        if rec.get("terminada"):
            (confirmadas if rec.get("codigo") == "OK" else pedidas).add(pid)
        elif _confirmar_baja(d, op_id, rec):
            confirmadas.add(pid)
        else:
            pedidas.add(pid)
        # una baja que termino mal (REVERTIDA, FALLO...): el punto sigue vivo y vuelve al fondo.
        # Solo suelta la marca de ESA operacion (auditoria ap2 H1)
        rec2 = ops().obtener(op_id)          # releido: _confirmar_baja pudo terminarla ahora
        cod = (rec2 or rec).get("codigo") if (rec2 or rec).get("terminada") else None
        if cod and cod != "OK" and cancelar is not None:
            cancelar(pid, op=op_id)
        elif not cod and hasattr(d, "baja_renovar"):
            d.baja_renovar(pid, op_id)     # sigue en curso: su marca no caduca a mitad
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
            motivo = "baja pedida desde el panel; el punto ya no está en estado.json"
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
    try:
        if olvidar_clave_vpn(pid):
            hecho.append("clave-vpn")
    except OSError as e:
        ok = False
        hecho.append("clave-vpn: fallo %s" % str(e)[:80])
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
    sit = situacion_vpn(p)
    directo = es_directo(p)
    if directo:
        # sin VPN (el user, 2026-10-18): «conectado» = llega su espejo por la red local
        mk_txt = ("%s &middot; directo, sin VPN" % esc(p.get("mk_ip") or "?")
                  + {"conectada": " &middot; llega su espejo",
                     "esperando": " &middot; esperando su espejo"}.get(sit["clave"], ""))
    elif sit["clave"] == "conectada":
        mk_txt = "conectado desde %s" % esc(vc.get("ip_real") or "?")
    elif sit["clave"] == "esperando":
        mk_txt = "esperando a que conecte" + (" (dato de la VPN viejo)" if vc.get("viejo") else "")
    else:
        mk_txt = "sin conectar"
    # punto en error: el motivo, desde cuando y «Reintentar arranque» (encola punto.arrancar como el
    # boton Arrancar de Servicio: mismo token de un solo uso y la misma pagina de operacion). Toda la
    # ficha es solo de admin (get/post lo comprueban en el servidor).
    reintentar = (
        "<form method=post action='/puntos/%s/arrancar' onsubmit=\"return ask(this,'Reintentar arranque',"
        "'El orquestador vuelve a levantar la VPN y el Suricata del punto. Si falla otra vez, verás el "
        "motivo y los últimos logs.','Reintentar')\">%s<button class=btn type=submit>Reintentar arranque"
        "</button></form>" % (esc(pid), campo_token()))
    caja_error = error_html(p, ahora, boton=reintentar)
    if caja_error:
        caja_error = ("<div class='aviso err'><b>El punto está con error.</b> %s</div>"
                      % caja_error)
    datos = "".join(
        "<div class=dato><div class=et>%s</div><div>%s</div></div>" % (esc(a), b) for a, b in (
            ("Estado", esc(ESTADOS.get(p.get("estado"), p.get("estado") or "sin datos"))
             + "".join("<div class=pwarn>%s</div>" % esc(AVISOS.get(x, x)) for x in (p.get("avisos") or []))),
            ("Salud", salud_chip(sal)),
            ("Conexión" if directo else "VPN",
             pill_vpn(p) + " " + esc(_contenedor(cont.get("vpn"))) + " &middot; MikroTik " + mk_txt),
            ("Espejo", ("%.0f paq/s" % pps if pps is not None else "sin medida")
             + (" &middot; último hace %s" % _edad(ahora - ultimo) if ultimo else "")),
            ("Suricata", esc(_contenedor(cont.get("suricata"))) + " &middot; %s / %s paquetes vistos/descartados"
             % (_num(su.get("kernel_packets")), _num(su.get("kernel_drops")))),
            ("Alertas 24 h", "<a href='/eventos?nodo=%s'>%s</a>" % (esc(pid), alertas_24h_html(pid, ahora, p)[0])),
            ("Retención efectiva", retencion_html(retencion(pid, p), ahora)),
        ) + ((("Espejo directo", esc("a %s:%s/udp · desde cualquier IP · API en %s:%s"
                                     % (p.get("sensor") or "?", p.get("tzsp_puerto") or "-",
                                        p.get("mk_ip") or "?", p.get("api_puerto") or 8729))),)
             if directo else
             (("Puerto VPN / red del túnel", esc("%s/tcp · %s" % (p.get("puerto") or "-", p.get("tun_net") or "-"))),)
             + ((("Origen de la VPN", origen_html(pid, p)),) if "origen_ip" in p else ())) + (
            ("Perfil / RouterOS", esc("%s · %s" % (p.get("perfil") or "-", ros_txt(p.get("ros_version"))))),
            ("Prefijos espejados", "todas las redes privadas y el CGNAT" + (
                " + " + esc(", ".join(p.get("redes") or [])) if p.get("redes") else "")),
        ))
    # VPN: el orquestador da los comandos con <CLAVE-VPN>; el panel pone la clave que guarda cifrada
    # (la del alta o la ultima regenerada). Sin ella, se dice y se ofrece regenerarla.
    r = cliente().pedir("punto.comandos", {"pid": pid}, quien="panel:%s" % _usuario(d), ip=_ip(d))
    cmds = (r.get("datos") or {}).get("comandos") if r.get("codigo") == "OK" else None
    # Desde 2026-10-16 el orquestador guarda la clave cifrada y da los comandos ya con ella (y la
    # clave aparte). Si no la tiene (orquestador viejo, sin clave maestra), la pone el panel con la
    # suya: la huella de la clave vigente decide (un orquestador viejo no la da y solo se mira el
    # usuario; si no es la de la clave guardada, regenerada por la CLI, no se pone)
    dd = r.get("datos") or {}
    if cmds and isinstance(dd.get("clave"), str) and dd["clave"] and PLACEHOLDER_VPN not in cmds:
        cmds_txt, puesta = cmds, dd["clave"]
    else:
        cmds_txt, puesta = con_clave_vpn(cmds, pid, dd.get("clave_id"))
    if directo:
        # sin VPN no hay nada que pegar para conectar: los datos del espejo y de la API
        vpn_html = (("<p class=hint>Este punto no lleva VPN: el MikroTik manda el espejo por la red local y el "
                     "panel entra a su API por la misma red. No hay nada que pegar para conectarlo; en las reglas "
                     "del espejo del MikroTik usa estos datos.</p><pre class=cmd>%s</pre>" % esc(cmds))
                    if cmds else
                    aviso("No se pudieron obtener los datos del espejo: %s"
                          % _orq.traducir(r.get("codigo"), r.get("mensaje")), "amb"))
    elif not cmds:
        vpn_html = aviso("No se pudieron obtener los comandos: %s" % _orq.traducir(r.get("codigo"), r.get("mensaje")),
                         "amb")
    elif puesta:
        # la clave SIEMPRE a la vista, en claro y fuera de los bloques plegados (el user, 2026-10-16:
        # «la clave debe siempre estar visible»); en disco sigue cifrada. Sin el atajo «el router ya
        # tiene ids-vpn» (quitado a peticion del user; esa orden la da la pagina de Regenerar)
        m = re.search(r"(?:^|\s)user=(\S+)", cmds_txt or "")
        vpn_html = (cred_html(m.group(1) if m else "-", puesta, "ficha")
                    + "<p class=hint>Los comandos llevan la clave de la VPN puesta: cópialos y pégalos en el "
                      "router tal cual. Solo crean la VPN.</p>"
                    + comandos_html(cmds_txt, p.get("ros_version"), "ficha"))
    else:
        vpn_html = (aviso("El panel no tiene la clave vigente de la VPN de este punto (se creó antes de que el "
                          "panel la guardara, se regeneró desde la consola del servidor, o falta la clave maestra). "
                          "Regenérala desde aquí: el panel te da la orden para "
                          "el router con la clave puesta, y desde entonces estos comandos salen completos. No "
                          "pegues password=<CLAVE-VPN> tal cual: el router se queda con ese texto de clave y no "
                          "conecta.", "amb")
                    + "<p>%s</p>" % regenerar_form(pid)
                    + comandos_html(cmds_txt, p.get("ros_version"), "ficha"))
    # API
    rt = _router(d, pid) or {}
    # la huella se lee por el tunel: sin el MikroTik conectado (lo normal tras el alta) la lectura
    # esperaba hasta 15 s y la ficha tardaba eso en abrir. Solo se pide con el router conectado, y
    # ni asi frena la ficha: se pide por fetch despues de pintarla (GET /puntos/<pid>/huella) y se
    # guarda 10 min por punto (P4). La huella es opcional: sin certificado no hay (2026-10-15).
    hc = huella_cacheada(d, pid)
    caja_huella = huella_caja(d, pid, p, rt, hc, pedir=sit["clave"] == "conectada" and not hc)
    api_html = (
        "<form method=post action='/puntos/%s/api'><input type=hidden name=accion value=guardar>%s"
        "<div class=datos><div><label class=l>Usuario de la API</label>"
        "<input class=t name=user value='%s' maxlength=64 autocomplete=off></div>"
        "<div><label class=l>Clave de la API %s</label>"
        "<input class=t type=password name=pass autocomplete=new-password placeholder='%s'></div></div>"
        "<label><input type=checkbox name=enabled value=1%s> Permitir enviar IPs a este MikroTik "
        "(cuarentena)</label>"
        "<div class=acciones><button class=btn type=submit>Guardar</button>"
        "<button class='btn sec' type=submit name=accion value=probar onclick='return papiProbar(this)'>"
        "Probar la conexión</button></div></form>"
        "<p class=hint>La conexión va por %s (%s). La clave se guarda cifrada con la clave maestra y no se "
        "vuelve a mostrar.</p>%s%s"
        % (esc(pid), campo_token(), esc(rt.get("USER", "")), "(guardada)" if rt.get("PASS") else "",
           "dejar vacío para conservar" if rt.get("PASS") else "clave del usuario ids-api",
           " checked" if rt.get("ENABLED") == "1" else "",
           ("la red local directa a %s" % esc(p.get("mk_ip") or "?")) if directo else "el relé del túnel del punto",
           "API sin SSL, puerto 8728 del router: la clave viaja sin cifrar" if str(p.get("api_puerto")) == "8728"
           else "API-SSL, puerto %s del router, sin exigir certificado salvo que fijes uno abajo"
           % esc(p.get("api_puerto") or 8729),
           api_puerto_form(pid, p), caja_huella))
    # Espejo: ya no hay seccion (el espejo lo monta el operador a mano en el MikroTik, el user
    # 2026-10-16); lo que traiga extra_espejo (el resultado de una accion de la API) sale tras la API
    # Prefijos
    # P2: por fetch; el avance del orquestador (con lo que tarda cada paso) se ve aqui sin recargar y
    # al terminar sale un modal con el resultado
    pref_html = (
        "<form method=post action='/puntos/%s/ajustar'>%s"
        "<p class=hint style='margin-top:0'><b>Siempre incluidas</b>, sin escribirlas: todas las redes "
        "privadas y el CGNAT (<code>10/8</code>, <code>172.16/12</code>, <code>192.168/16</code>, "
        "<code>100.64/10</code>), menos las que usa el propio servidor (túneles, Docker y gestión).</p>"
        "<label class=l>Prefijos adicionales (opcional, uno por línea)</label>"
        "<textarea class=t name=redes rows=4>%s</textarea>"
        "<div class=acciones><button class=btn type=submit onclick=\"if(ask(this,'Cambiar los prefijos',"
        "'Se guardan los prefijos adicionales del punto (el avance se ve aquí, sin recargar). El Suricata "
        "solo se reinicia si entra o sale un prefijo público.','Cambiar'))ppref(this.form);"
        "return false;\">Guardar prefijos</button></div></form><div id=pprog class=pjcaja style='display:none'></div>"
        "<p class=hint>Aquí solo van rangos <b>que no sean privados</b>, p. ej. IPs públicas de abonados. El "
        "panel trata como abonados todo lo privado y el CGNAT más estos prefijos. Déjalo vacío si no hace "
        "falta ninguno. Si tu espejo del MikroTik filtra por una address-list (p. ej. «Redes Privadas»), añade ahí también los prefijos adicionales.</p>"
        % (esc(pid), campo_token(), esc("\n".join(p.get("redes") or []))))
    # Servicio
    # «Regenerar»: el router que reintenta con la clave vieja ya no acaba baneado (fail2ban solo cuenta
    # usuarios desconocidos, VPN-04); un punto de antes de VPN-01 (el script lo avisa con «# AVISO:»)
    # renueva ademas el certificado del servidor y el router necesita la CA y la verificacion.
    txt_regenerar = ("Se crea una clave nueva y el panel te da la orden para el router con ella puesta (también "
                     "quedan completos los comandos de esta ficha). La VPN actual del MikroTik se corta hasta que "
                     "pongas la nueva en el router; mientras tanto el router no queda baneado por reintentar con "
                     "la vieja.")
    if cmds and "# AVISO:" in cmds:
        txt_regenerar += (" Este punto tiene el certificado del servidor de antes de la verificación: también se "
                          "renueva, y en el router hay que pegar las líneas de la CA del VPS y activar "
                          "verify-server-certificate=yes además de poner la clave nueva.")
    # un punto directo no tiene VPN: arranca y para su receptor del espejo, y no hay clave que regenerar
    parte = "el receptor del espejo" if directo else "la VPN"
    serv = "".join(
        "<form method=post action='/puntos/%s/%s' onsubmit=\"return ask(this,'%s','%s','%s'%s)\">%s"
        "<button class='btn sec' type=submit>%s</button></form>"
        % (esc(pid), acc, tit, txt, tit, ",'danger'" if acc == "parar" else "", campo_token(), tit)
        for acc, tit, txt in (
            ("arrancar", "Arrancar", "Arranca %s y el Suricata del punto." % parte),
            ("reiniciar", "Reiniciar", "Reinicia %s y el Suricata del punto: el espejo se corta unos segundos." % parte),
            ("parar", "Parar", "Para %s y el Suricata del punto: deja de vigilarse hasta que lo arranques." % parte),
            ("regenerar", "Regenerar la clave VPN", txt_regenerar))
        if not (directo and acc == "regenerar"))
    baja = (
        "<div class=card style='border-color:#f3c4c4'><h2>Dar de baja el punto</h2>"
        "<p>Quita del servidor su VPN, su Suricata y <b>todos sus datos</b>, y del panel sus salidas, su "
        "conexión y sus registros. No se puede deshacer.</p>"
        "<p class=hint>Antes, mientras el túnel sigue arriba, el panel limpia el MikroTik: saca de sus "
        "address-lists las IPs que puso en cuarentena y los destinos bloqueados (y el espejo, si lo montó el "
        "panel: tus reglas a mano no se tocan). Si el router no responde, la baja <b>no sigue</b> y te dice que falta; si ese "
        "router ya no existe, desmarca la casilla.</p>"
        "<form method=post action='/puntos/%s/borrar' data-nombre='%s' onsubmit='return pbajaAjax(this)'>%s"
        "<label class=l><input type=checkbox name=limpiar_router value=1 checked> Limpiar antes el MikroTik "
        "(cuarentena)</label>"
        "<label class=l>Para confirmar, escribe el nombre del punto: <b>%s</b></label>"
        "<input class=t name=confirmar autocomplete=off maxlength=31 oninput='pnombre(this)'>"
        "<div class=acciones><button class='btn peligro' type=submit disabled>Dar de baja</button></div></form>"
        "</div>" % (esc(pid), esc(nombre), campo_token(), esc(nombre)))
    cuerpo = (
        "<div class=ptit><h1>%s <span class=hint>%s</span></h1><a class='btn sec' href='/puntos'>Volver a "
        "Puntos</a></div>%s%s%s"
        "<nav class=secnav><a href='#resumen'>Resumen</a><a href='#vpn'>%s</a><a href='#api'>API</a>"
        "<a href='#prefijos'>Prefijos</a><a href='/puntos/%s/logs?parte=vpn'>Logs</a>"
        "<a href='#baja'>Baja</a></nav>"
        "<section class=card id=resumen><h2>Resumen</h2><div class=datos>%s</div>%s"
        "<h3 style='font-size:14px'>Salud por etapas</h3>%s</section>"
        "<section class=card><h2>Servicio</h2><div class=acciones>%s</div>%s</section>"
        "<section class=card id=vpn><h2>%s</h2>%s</section>"
        "<section class=card id=api><h2>API del MikroTik</h2>%s</section>"
        "%s"
        "<section class=card id=prefijos><h2>Prefijos adicionales</h2>%s</section>"
        "<div id=baja>%s</div>%s"
        % (esc(nombre), esc(pid), aviso(mensaje, "ok" if ok else "err"), caja_error,
           "" if p else aviso("El punto aún no aparece en el estado del orquestador (se actualiza cada 15 s).", "info"),
           "Conexión" if directo else "VPN", esc(pid), datos, cobertura_html(cobertura_prefijos(pid, p, ahora)),
           salud_etapas_html(sal), serv, desbanear_html(p, pid),
           "Conexión directa: datos para el MikroTik" if directo else "VPN: comandos para el MikroTik",
           vpn_html, api_html, extra_espejo,
           pref_html, baja,
           _retomar_html(d, pid)))
    # lleva la clave de la VPN: ni el navegador ni un proxy la guardan (como la pagina de la operacion)
    return _html_privado(h, pagina(d, nombre, cuerpo), codigo)


HUELLA_CACHE_S = 600
RE_HUELLA_API = re.compile(r"[0-9a-f]{64}")
# Los comandos de RouterOS (6.49 y v7) que dan la huella del certificado de la API-SSL: el primero
# dice cual usa y el segundo su `fingerprint`, el SHA-256 del certificado en hexadecimal seguido.
CMD_SERVICIO_API = "/ip service print detail where name=api-ssl"
CMD_HUELLA_ROUTER = "/certificate print detail where name=<certificado>"
# lo que «presenta» un router sin certificado (cifrado anonimo): no hay huella que fijar
SHA256_VACIO = hashlib.sha256(b"").hexdigest()


def huella_cacheada(d, pid):
    """La huella que presento el router al panel hace menos de 10 min ("" si no hay): la apuntan
    la lectura de la ficha y cada conexion del panel, acepte o no (dashboard.huella_vista)."""
    f = getattr(d, "huella_vista", None)
    v = f(pid, HUELLA_CACHE_S) if f is not None else ""
    return v if isinstance(v, str) and RE_HUELLA_API.fullmatch(v) else ""


def huella_bloques(fp):
    """La huella en bloques de 4 (dos lineas de 8), para compararla a ojo con el `fingerprint`
    del router, que la da seguida."""
    fp = str(fp or "")
    b = [fp[i:i + 4] for i in range(0, len(fp), 4)]
    return "<code class=phue>%s<br>%s</code>" % (esc(" ".join(b[:8])), esc(" ".join(b[8:])))


def _huella_form(pid, fp, boton, titulo, texto, tono=""):
    """«La huella coincide: confirmar» (o «Volver a confirmar»): por fetch y con ask(); el servidor
    vuelve a leer la huella del router y solo guarda si sigue siendo ESTA."""
    return ("<form method=post action='/puntos/%s/api'><input type=hidden name=accion value=confirmar_huella>"
            "%s<input type=hidden name=huella value='%s'><button class='btn%s' type=submit "
            "onclick=\"if(ask(this,'%s','%s','Confirmar'%s))phueConf(this.form);return false;\">%s</button></form>"
            % (esc(pid), campo_token(), esc(fp), " peligro" if tono else "", esc(titulo), esc(texto),
               ",'danger'" if tono else "", esc(boton)))


def huella_caja(d, pid, p, rt, presentada="", error="", pedir=False):
    """El estado de la huella del certificado API-SSL del router en la ficha (solo admin, VPN-06).
    La API-SSL va sin certificado (2026-10-15) y la huella es opcional: sin fijar (el panel conecta
    sin exigir certificado; si el router presenta uno, su huella y «La huella coincide: confirmar»;
    sin certificado, que no hay huella que fijar), confirmada, fijada automaticamente (de antes: se
    exige y se puede revisar) o distinta (aviso rojo y «Volver a confirmar»). `presentada`: la que
    presenta ahora el router, si se sabe; `pedir`: la ficha la trae por fetch (GET
    /puntos/<pid>/huella) y sustituye esta caja."""
    if str(p.get("api_puerto") or "") == "8728":
        # 2026-10-20 («debe aceptar sin ssl»): el panel habla la API en claro por el relé del punto
        return ("<p class=hint>Este punto usa la API sin TLS (puerto 8728, el servicio <code>api</code> del "
                "router): no hay certificado ni huella que fijar, y la clave de la API viaja sin cifrar por la "
                "red del punto.</p>")
    if hasattr(d, "huella_fijada"):
        fijada = d.huella_fijada(rt)
    else:
        fijada = str(rt.get("CERT_FP") or "").lower().replace(":", "")
        fijada = "" if fijada == SHA256_VACIO else fijada
    est = d.huella_estado(rt) if hasattr(d, "huella_estado") else ("confirmada" if fijada else "sin")
    sin_cert = presentada == SHA256_VACIO
    comparar = ("<p class=hint>Compárala en el router: <code>%s</code> dice qué certificado usa la API-SSL y "
                "<code>%s</code> da su <code>fingerprint</code> (la misma huella, seguida).</p>"
                % (esc(CMD_SERVICIO_API), esc(CMD_HUELLA_ROUTER)))
    out = "<h3 style='font-size:14px;margin:14px 0 6px'>Huella del certificado API-SSL</h3>"
    if fijada and presentada and presentada != fijada:
        out += ("<div class='aviso err'><b>El MikroTik presenta un certificado distinto del confirmado.</b> Puede "
                "ser una suplantación (alguien en medio) o que se cambió el certificado del router. El panel "
                "<b>no le manda la clave</b> de <code>ids-api</code> hasta que lo revises.</div>"
                "<p>Confirmada:<br>%s</p><p>Presenta ahora:<br>%s</p>%s"
                % (huella_bloques(fijada), huella_bloques(presentada), comparar))
        out += _huella_form(pid, presentada, "Volver a confirmar", "Volver a confirmar la huella",
                            "Solo si comparaste en el router la huella nueva y es la suya: el panel la fijará "
                            "y volverá a mandarle la clave de ids-api.", tono="danger")
        return "<div id=phuellabox data-pid='%s'>%s</div>" % (esc(pid), out)
    if est == "confirmada":
        cuando = rt.get("CERT_FP_CUANDO") or ""
        try:
            cuando = time.strftime("%d/%m/%Y %H:%M", time.localtime(int(cuando)))
        except (TypeError, ValueError):
            cuando = ""
        out += ("<p>Confirmada por <b>%s</b>%s:<br>%s</p>"
                % (esc(rt.get("CERT_FP_QUIEN")), (" el " + esc(cuando)) if cuando else "", huella_bloques(fijada)))
    elif est == "automatica":
        out += ("<div class='aviso amb'><b>Fijada automáticamente</b> en la primera conexión, antes de que el "
                "panel pidiera confirmarla. Se sigue exigiendo; conviene revisarla.</div><p>%s</p>"
                "<details><summary>Revisar la huella</summary>%s%s</details>"
                % (huella_bloques(fijada), comparar,
                   _huella_form(pid, fijada, "La huella coincide: confirmar", "Confirmar la huella",
                                "Confirmas que comparaste esta huella con la del router y es la misma.")))
    else:
        out += ("<div class='aviso info'>Sin huella fijada: el panel conecta con la API-SSL tal como la tenga "
                "el router (lo normal, sin certificado) y la clave de <code>ids-api</code> va protegida por el "
                "túnel.</div>")
        if sin_cert:
            out += "<p>El router no presenta certificado (cifrado anónimo): no hay huella que fijar.</p>"
        elif presentada:
            out += ("<p>El router presenta un certificado. Si quieres que el panel lo exija, compara su huella "
                    "y fíjala:<br>%s</p>%s" % (huella_bloques(presentada), comparar)
                    + _huella_form(pid, presentada, "La huella coincide: confirmar", "Confirmar la huella",
                                   "Confirmas que comparaste esta huella con la del router y es la misma. Desde "
                                   "ahora el panel solo le manda la clave de ids-api si presenta este "
                                   "certificado."))
        elif pedir:
            # sin JavaScript nadie la pide: el enlace la lee en el servidor y trae el boton de confirmar
            out += ("<p>Huella que presenta el router: <code id=phuella>comprobando…</code><noscript> "
                    "<a href='/puntos/%s/huella?ver=1'>Leer la huella ahora</a></noscript></p>" % esc(pid))
        elif error:
            out += "<p>Huella que presenta el router: <code>no se pudo leer</code></p>" + aviso(error, "amb")
        else:
            out += "<p>Huella que presenta el router: <code>se comprobará cuando el MikroTik conecte</code></p>"
    if fijada and presentada == fijada:
        out += "<p class=hint>El router presenta ahora esta misma huella.</p>"
    elif fijada and pedir:
        out += ("<p class=hint>Huella que presenta ahora el router: <code id=phuella>comprobando…</code>"
                "<noscript> <a href='/puntos/%s/huella?ver=1'>Leer la huella ahora</a></noscript></p>" % esc(pid))
    elif fijada and error:
        out += aviso(error, "amb")
    if fijada:
        out += ("<form method=post action='/puntos/%s/api' onsubmit=\"return ask(this,'Olvidar la huella',"
                "'El panel dejará de exigir este certificado y conectará con la API-SSL tal como la tenga el "
                "router. Hazlo si le quitaste o cambiaste el certificado.','Olvidar','danger')\">"
                "<input type=hidden name=accion value=olvidar_huella>%s"
                "<button class='btn sec' type=submit>Olvidar la huella</button></form>" % (esc(pid), campo_token()))
    return "<div id=phuellabox data-pid='%s'%s>%s</div>" % (esc(pid), " data-pedir=1" if pedir else "", out)


def huella_json(h, pid, consulta=None):
    """GET /puntos/<pid>/huella: la huella que presenta el certificado API-SSL del router, leida por
    el panel con el mismo TLS que usa para conectar y sin login (hasta 8 s por el tunel), con cache
    de 10 min por punto. {"texto": huella o motivo, "html": la caja de la huella de la ficha}.
    Con ?ver=1 (el enlace <noscript> de la ficha, sin JavaScript) la misma caja en una pagina, con
    el boton de confirmar si el router presento la huella."""
    d = _dash(h)
    p = nodos.punto(pid) or {}
    rt = _router(d, pid) or {}
    if situacion_vpn(p)["clave"] != "conectada":
        texto, caja = "se comprobará cuando el MikroTik conecte", huella_caja(d, pid, p, rt)
    else:
        sha, error = huella_cacheada(d, pid), ""
        leer = getattr(d, "mk_huella_presentada", None)
        if not sha and leer is not None:
            try:
                v = leer(pid)
                sha = v if isinstance(v, str) and RE_HUELLA_API.fullmatch(v) else ""
            except Exception as e:
                error = "No se pudo leer la huella del router: %s" % str(e)[:200]
        texto = "sin certificado" if sha == SHA256_VACIO else (sha or "sin dato")
        caja = huella_caja(d, pid, p, rt, sha, error)
    if (consulta or {}).get("ver"):
        return h._html(pagina(d, "Huella", "<div class=ptit><h1>Huella de %s</h1><a class='btn sec' "
                                           "href='/puntos/%s'>Volver a la ficha</a></div><div class=card>%s</div>"
                              % (esc(nodos.nombre(pid)), esc(pid), caja)))
    return h._json({"texto": texto, "html": caja})


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
def api_puerto_form(pid, p):
    """Cambiar el puerto de la API del punto (2026-10-20): 8729 (API-SSL) u 8728 (API sin SSL). Es una
    orden de la cola (punto.ajustar con api_puerto) que recrea los dos contenedores del punto."""
    actual = 8728 if str(p.get("api_puerto")) == "8728" else 8729
    otro = 8729 if actual == 8728 else 8728
    nombre = {8729: "API-SSL (8729)", 8728: "API sin SSL (8728)"}
    return ("<form method=post action='/puntos/%s/api' onsubmit=\"return confirm('¿Pasar la API de este punto "
            "a %s? Se recrean sus contenedores: un par de minutos sin análisis.')\">"
            "<input type=hidden name=accion value=puerto><input type=hidden name=api_puerto value=%d>%s"
            "<p class=hint>Puerto de la API: <b>%s</b>. <button class='btn sec' type=submit>Pasar a %s</button>"
            " Con %s, en el router: <code>%s</code>.</p></form>"
            % (esc(pid), nombre[otro], otro, campo_token(), nombre[actual], nombre[otro], nombre[otro],
               esc("/ip service set api disabled=no" if otro == 8728 else CMD_CERT_API_SSL)))


# El certificado para la API-SSL del router (2026-10-20; = COMANDOS_CERT_API_SSL del orquestador):
# hay RouterOS 7 que cierran la API-SSL sin certificado y conectan con este
CMD_CERT_API_SSL = ("/certificate add name=ids-api common-name=ids-api days-valid=3650 trusted=yes "
                    "key-usage=key-cert-sign,crl-sign,digital-signature,key-encipherment,tls-server ; "
                    "/certificate sign ids-api ; /ip service set api-ssl certificate=ids-api disabled=no")


def accion_api(h, pid, form, ajax=False):
    """Guardar, probar u olvidar la huella de la API del router del punto. Un solo uso por
    formulario (A-08). Con ajax=1 (el boton «Probar la conexion»), {ok, mensaje} para un modal: la
    prueba tarda 20-35 s con el router caido y la ficha no se queda en blanco. «puerto» cambia el
    puerto de la API del punto (orden de la cola)."""
    d = _dash(h)
    acc = form.get("accion") or "guardar"
    if acc not in ("guardar", "probar", "olvidar_huella", "confirmar_huella", "puerto"):
        return _responder(h, pid, ("Acción de la API desconocida.", 400, False, ""), ajax)
    if acc == "puerto":
        puerto = (form.get("api_puerto") or "").strip()
        if puerto not in ("8729", "8728"):
            return _responder(h, pid, ("El puerto de la API tiene que ser 8729 (API-SSL) u 8728 (sin SSL).",
                                       400, False, ""), ajax)
        _bit(d, "PUNTO-API", pid=pid, objetivo="puerto", resultado=puerto)
        return _encolar(h, pid, "punto.ajustar", {"pid": pid, "api_puerto": int(puerto)},
                        token=form.get("op") or "")
    user = (form.get("user") or "").strip()[:64]
    huella = (form.get("huella") or "").strip().lower()

    def validar():
        if not any(x.get("id") == pid for x in d.cargar_routers()):
            return ("Ese punto todavía no tiene router en el panel (espera a que aparezca en el "
                    "estado del orquestador).", 409, False, "")
        if acc in ("guardar", "probar") and user and not re.match(r"^[A-Za-z0-9._@-]+\Z", user):
            return "El usuario de la API tiene caracteres no válidos.", 400, False, ""
        if acc == "confirmar_huella" and not RE_HUELLA_API.fullmatch(huella):
            return "Falta la huella que comparaste (64 caracteres hexadecimales).", 400, False, ""
        if acc == "confirmar_huella" and huella == SHA256_VACIO:
            return "El router no presenta certificado: no hay huella que fijar.", 400, False, ""
        return None

    def hacer():
        if acc == "confirmar_huella":
            return confirmar_huella(d, pid, huella)
        rs = d.cargar_routers()
        r = next((x for x in rs if x.get("id") == pid), None)
        if r is None:
            return ("Ese punto todavía no tiene router en el panel (espera a que aparezca en el "
                    "estado del orquestador).", 409, False, "")
        if acc == "olvidar_huella":
            r.update({"CERT_FP": "", "CERT_FP_QUIEN": "", "CERT_FP_CUANDO": ""})
            d.guardar_routers([r], huella=True)
            _bit(d, "PUNTO-API", pid=pid, objetivo="huella", resultado="olvidada")
            return ("Huella olvidada: el panel conecta con este router sin exigir certificado.", 200, True, "")
        r["USER"] = user
        if form.get("pass"):
            r["PASS"] = form["pass"]             # guardar_routers la cifra (router:<pid>:PASS)
        r["ENABLED"] = "1" if form.get("enabled") else "0"
        try:
            d.guardar_routers([r])               # solo este punto; la huella no se toca aqui
        except Exception as e:
            return "No se pudo guardar: %s" % str(e)[:160], 500, False, ""
        if acc != "probar":
            _bit(d, "PUNTO-API", pid=pid, objetivo="conexion", resultado="guardada",
                 extra="usuario=%s enviar=%s" % (user or "-", r["ENABLED"]))
            return "Conexión de la API guardada.", 200, True, ""
        ok, msg = probar_api(d, pid)
        _bit(d, "PUNTO-API", pid=pid, objetivo="probar", resultado="ok" if ok else "fallo")
        return "Prueba: " + msg, 200 if ok else 502, ok, ""
    return _con_token(h, pid, "api-" + acc, form, hacer, validar, ajax=ajax)


def confirmar_huella(d, pid, huella):
    """«La huella coincide: confirmar» / «Volver a confirmar» (VPN-06): se vuelve a leer la huella que
    presenta el router (sin login) y solo se fija si sigue siendo la que el administrador comparo.
    (mensaje, codigo, ok, extra). Queda en el Registro quien la confirmo y cual (sus 16 primeros)."""
    leer = getattr(d, "mk_huella_presentada", None)
    if leer is None or getattr(d, "confirmar_huella", None) is None:
        return "Este panel no puede confirmar huellas (núcleo viejo).", 501, False, ""
    try:
        ahora = leer(pid)
    except Exception as e:
        _bit(d, "PUNTO-API", pid=pid, objetivo="huella", resultado="sin-leer")
        return ("No se pudo leer la huella del router, así que no se confirmó nada: %s" % str(e)[:200],
                502, False, "")
    if ahora != huella:
        _bit(d, "PUNTO-API", pid=pid, objetivo="huella", resultado="cambio-al-confirmar",
             extra="vista=%s… ahora=%s…" % (huella[:16], str(ahora)[:16]))
        return ("El router presenta ahora otra huella (%s…), no la que comparaste: no se confirmó nada. "
                "Vuelve a compararla con la del router." % str(ahora)[:16], 409, False, "")
    try:
        antes = d.confirmar_huella(pid, huella, _usuario(d))
    except (OSError, ValueError) as e:
        return "No se pudo guardar la huella: %s" % str(e)[:160], 500, False, ""
    _bit(d, "PUNTO-API", pid=pid, objetivo="huella", resultado="reconfirmada" if antes else "confirmada",
         extra="sha256=%s…%s" % (huella[:16], (" antes=%s…" % antes[:16]) if antes and antes != huella else ""))
    return ("Huella confirmada: desde ahora el panel solo le manda la clave de ids-api a este MikroTik si "
            "presenta este certificado.", 200, True, "")


# --------------------------------------------------------------------------------------------
# Desbanear la IP del MikroTik (VPN-04)
# --------------------------------------------------------------------------------------------
# fail2ban (jaula ids-vpn) banea en todo lo que el servidor publica por Docker (la VPN de todos los
# puntos y el panel; el SSH tiene su propia jaula, sshd). Cuando el router esta baneado
# su tunel esta caido y estado.json ya no trae su IP: por eso el panel apunta la ultima IP desde la
# que conecto (nodos/<pid>/mk-ip.json, que la baja borra con el resto de nodos/<pid>/).
def _ruta_ip_mk(pid):
    return os.path.join(nodos.NODOS, pid, "mk-ip.json")


def _ip_valida(v):
    try:
        return str(ipaddress.ip_address(str(v or "").strip()))
    except ValueError:
        return ""


def origen_html(pid, p):
    """Origen de la VPN en la ficha (revisión 2026-10-15, C6). Con origen fijo la VPN solo acepta
    conexiones desde esa IP y nadie más ocupa sus plazas; sin él cualquiera puede abrir el puerto y
    unas 10 IP llenarían las 32 plazas: se recomienda fijarlo, con la IP desde la que conecta."""
    fijo = _ip_valida(p.get("origen_ip"))
    if fijo:
        return "solo desde <code>%s</code> (origen fijo)" % esc(fijo)
    vc = p.get("vpn_cliente") or {}
    ip = _ip_valida(vc.get("ip_real")) if vc.get("conectado") else ""
    orden = "ids-orq punto ajustar %s --origen-ip %s" % (pid, ip or "<IP pública del MikroTik>")
    return ("cualquiera<div class=hint>Si el MikroTik sale siempre por la misma IP pública, fíjala y nadie "
            "más podrá ocupar las plazas de su VPN: <code>%s</code></div>" % esc(orden))


def ip_mikrotik(p):
    """(ip, instante) de la IP publica del MikroTik del punto: la del tunel conectado (y se apunta)
    o la ultima apuntada; ("", None) si nunca se vio."""
    pid = (p or {}).get("pid") or ""
    if not nodos.pid_valido(pid):
        return "", None
    ruta = _ruta_ip_mk(pid)
    try:
        previa = _leer_json_pequeno(ruta, 4096)
    except (OSError, ValueError, RecursionError):
        previa = None
    previa = previa if isinstance(previa, dict) else {}
    vc = (p or {}).get("vpn_cliente") or {}
    ip = _ip_valida(vc.get("ip_real")) if vc.get("conectado") else ""
    if ip:
        if previa.get("ip") != ip:
            try:
                os.makedirs(os.path.dirname(ruta), mode=0o700, exist_ok=True)
                tmp = "%s.%d.tmp" % (ruta, threading.get_ident())
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump({"ip": ip, "ts": int(time.time())}, f)
                os.replace(tmp, ruta)
            except OSError:
                pass
        return ip, time.time()
    ip = _ip_valida(previa.get("ip"))
    return (ip, previa.get("ts") if isinstance(previa.get("ts"), (int, float)) else None) if ip else ("", None)


def desbanear_html(p, pid):
    """El formulario «Desbanear IP del MikroTik» de la ficha (solo admin): la IP por defecto es la
    del tunel o la ultima conocida, editable; ask() y el resultado en un modal. Un punto directo no
    tiene VPN ni jaula de fail2ban: nada."""
    if es_directo(p):
        return ""
    ip, cuando = ip_mikrotik(p)
    if ip and cuando and not mk_conectado(p):
        de = "la última desde la que conectó el MikroTik (%s)" % time.strftime("%d/%m/%Y %H:%M", time.localtime(cuando))
    elif ip:
        de = "desde la que está conectado ahora el MikroTik"
    else:
        de = ""
    return ("<form method=post action='/puntos/%s/desbanear' class=pdesban>%s"
            "<input class=t name=ip value='%s' maxlength=45 autocomplete=off placeholder='IP pública del MikroTik' "
            "aria-label='IP pública del MikroTik'>"
            "<button class='btn sec' type=submit onclick=\"if(ask(this,'Desbanear IP del MikroTik','Se quita el ban "
            "de fail2ban (jaula ids-vpn) a '+this.form.ip.value+' en la VPN de todos los puntos y en el panel. Si desde esa "
            "IP algo sigue llamando con un usuario VPN que no existe, vuelve a banearse.','Desbanear'))"
            "pdesban(this.form);return false;\">Desbanear IP del MikroTik</button></form>"
            "<p class=hint>Si la IP del MikroTik quedó baneada por fail2ban (por ejemplo, porque detrás de la misma "
            "IP pública un router viejo sigue llamando con un usuario que ya no existe), no conecta a ninguna VPN "
            "de este servidor.%s</p>"
            % (esc(pid), campo_token(), esc(ip),
               (" La IP propuesta es %s." % esc(de)) if de else " Escribe su IP pública."))


def accion_desbanear(h, pid, form, ajax=False):
    """POST /puntos/<pid>/desbanear: orden inmediata vpn.desbanear del orquestador (fail2ban-client set
    ids-vpn unbanip). Un solo uso por formulario; queda en el Registro con la IP y el resultado."""
    d = _dash(h)
    ip = _ip_valida(form.get("ip"))

    def validar():
        if not ip:
            return "Escribe una dirección IP válida (la IP pública del MikroTik).", 400, False, ""
        return None

    def hacer():
        r = cliente().pedir("vpn.desbanear", {"ip": ip}, quien="panel:%s" % _usuario(d), ip=_ip(d))
        dd = r.get("datos") or {}
        if r.get("codigo") != "OK":
            _bit(d, "PUNTO-VPN-DESBANEAR", pid=pid, objetivo=ip, resultado=r.get("codigo") or "FALLO")
            return _orq.traducir(r.get("codigo"), r.get("mensaje"), dd), 502, False, ""
        if dd.get("desbaneada"):
            _bit(d, "PUNTO-VPN-DESBANEAR", pid=pid, objetivo=ip, resultado="desbaneada")
            return ("%s desbaneada: el MikroTik puede volver a conectar. Si sigue con una clave mal puesta, "
                    "fail2ban no lo vuelve a banear por eso (solo frena los intentos)." % ip, 200, True, "")
        _bit(d, "PUNTO-VPN-DESBANEAR", pid=pid, objetivo=ip, resultado="no-estaba")
        return ("%s no estaba baneada en la VPN (jaula ids-vpn): si el MikroTik no conecta, la causa es otra "
                "(mira los logs de la VPN del punto)." % ip, 200, True, "")
    return _con_token(h, pid, "desbanear", form, hacer, validar, ajax=ajax)


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
        return (True, "conexión OK con '%s'." % (nombre or pid)) if ok else (False, err or "sin respuesta")
    except Exception as e:
        # 600: lo que hay que hacer en el router va delante del detalle y con 200 se cortaba
        return False, "no conectó: %s" % str(e)[:600]


def _kw_avance(fn, avance):
    """{"avance": avance} si `fn` lo admite (el nucleo si; los sustitutos de las pruebas viejas no)."""
    return {"avance": avance} if avance is not None and _acepta(fn, "avance") else {}


# --------------------------------------------------------------------------------------------
# Baja en segundo plano (P3)
# --------------------------------------------------------------------------------------------
def _baja_en_trabajo(h, d, pid, confirmar, limpiar_pedido, tok):
    """La baja con fetch: un trabajo del panel limpia el MikroTik (avance «IPs quitadas i/N»), retira
    el espejo y, solo si el router quedo limpio, encola punto.borrar con el token del formulario
    como op_id (la marca _PREBAJA va ligada a ESA operacion y se renueva mientras dura). Si el
    router no responde, la baja no sigue."""
    usuario, ip = _usuario(d), _ip(d)
    limpiar = getattr(d, "baja_limpiar_router", None) if limpiar_pedido else None
    cancelar = getattr(d, "baja_cancelada", None)
    renovar = getattr(d, "baja_renovar", None)

    def trabajo(avance):
        def av(etapa=None, **k):
            avance(etapa=etapa, **k)
            if renovar is not None:
                try:
                    renovar(pid, tok)          # la marca de 900 s no caduca a mitad de la limpieza
                except Exception:
                    pass
        nota = ""
        if limpiar is not None:
            av(etapa="limpiar el MikroTik")
            res = limpiar(pid, usuario=usuario, op=tok, **_kw_avance(limpiar, av))
            if not res.get("ok"):
                _bit(d, "PUNTO-BORRAR", pid=pid, resultado="router-sin-limpiar", quien=usuario, ip=ip)
                msg = ("No se dio de baja: %s.%s Arregla la conexión con el router y vuelve a intentarlo; si "
                       "ese router ya no existe, desmarca «Limpiar antes el MikroTik» (lo que el panel le puso "
                       "tendrás que quitarlo a mano)." % (
                           res.get("mensaje", "fallo"),
                           " OJO: el router ya se tocó (se quitaron IPs de sus listas)." if res.get("tocado") else ""))
                return {"ok": False, "mensaje": msg,
                        "resultado": {"titulo_fin": "No se dio de baja", "html": aviso(msg)}}
            nota = ("El router YA se limpió (%s): el punto sigue activo; repite la baja. "
                    % res.get("mensaje", ""))
        else:
            _bit(d, "PUNTO-BORRAR", pid=pid, resultado="sin-limpiar-router", quien=usuario, ip=ip)
        av(etapa="encolar la baja en el orquestador")
        try:
            est, op_id, msg = encolar_orden(d, pid, "punto.borrar", {"pid": pid, "confirmar": confirmar},
                                            usuario, ip, nombre=confirmar, token=tok)
        except BaseException:
            if cancelar is not None:
                cancelar(pid, op=tok)
            raise
        if est in ("aceptada", "repetida"):
            return {"ok": True, "mensaje": "Baja encolada en el orquestador.",
                    "resultado": {"siguiente": "/operaciones/%s" % op_id, "titulo_fin": "Baja en marcha",
                                  "html": aviso("Router limpio y baja encolada en el orquestador.", "ok")}}
        if cancelar is not None:
            cancelar(pid, op=tok)
        return {"ok": False, "mensaje": nota + msg,
                "resultado": {"titulo_fin": "No se dio de baja", "html": aviso(nota + msg)}}
    op_id, nuevo = lanzar_trabajo(d, pid, "panel.baja", usuario, ip, trabajo, nombre=confirmar)
    if op_id is None:                         # la marca de prebaja la pone el trabajo: no hay nada que soltar
        return h._json({"error": _router_ocupado(pid), "titulo": "Router ocupado"}, 409)
    rec = ops().obtener(op_id) or {}
    nota = "" if nuevo else ("Ya había otra orden de este punto hablando con el MikroTik (%s): se muestra la "
                             "suya. Cuando termine, vuelve a pedir la baja."
                             % ORDENES.get(rec.get("orden"), rec.get("orden") or "?"))
    return h._json({"trabajo": op_id, "orden": rec.get("orden") or "panel.baja", "nota": nota})


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
        elif consulta.get("json"):
            json_op(h, m.group(1))
        else:
            pagina_op(h, m.group(1))
        return True
    m = RE_RUTA_PID.match(ruta)
    if not m or m.group(2) not in (None, "logs", "huella"):
        h._html("<h1>No encontrado</h1>", 404)
        return True
    pid = m.group(1)
    if not nodos.existe(pid):
        h._html(pagina(_dash(h), "Punto inexistente", "<h1>Punto inexistente</h1><p>No hay ningún punto %s "
                       "(quizá se dio de baja).</p>" % esc(pid)), 404)
        return True
    if m.group(2) == "logs":
        logs(h, pid, consulta)
    elif m.group(2) == "huella":
        huella_json(h, pid, consulta)
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
    acciones = ("borrar", "regenerar", "arrancar", "parar", "reiniciar", "ajustar", "api", "desbanear")
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
    ajax = bool(form.get("ajax"))
    if acc == "borrar":
        confirmar = (form.get("confirmar") or "").strip()
        if not confirmar or confirmar != (p.get("nombre") or pid):
            _bit(_dash(h), "PUNTO-BORRAR", pid=pid, resultado="nombre-no-coincide")
            msg = "Para dar de baja hay que escribir exactamente el nombre del punto."
            if ajax:
                h._json({"error": msg, "titulo": "No se dio de baja"}, 400)
            else:
                ficha(h, pid, msg, 400)
            return True
        d = _dash(h)
        # el op_id de la baja es el token del formulario: la marca de «en baja» del punto va ligada
        # a ESA operacion (si termina mal, el barrido la suelta: auditoria ap2 H1)
        if not _operaciones.RE_OPID.match(tok):
            tok = str(uuid.uuid4())
        if ajax:
            _baja_en_trabajo(h, d, pid, confirmar, bool(form.get("limpiar_router")), tok)
            return True
        limpiar = getattr(d, "baja_limpiar_router", None)
        nota = ""
        if form.get("limpiar_router") and limpiar is not None:
            # antes de la baja: despues ya no hay tunel para llegar al router (A-21(5))
            res = limpiar(pid, usuario=_usuario(d), op=tok)
            if not res.get("ok"):
                _bit(d, "PUNTO-BORRAR", pid=pid, resultado="router-sin-limpiar")
                ficha(h, pid, "No se dio de baja: %s.%s Arregla la conexión con el router y vuelve a intentarlo; "
                              "si ese router ya no existe, desmarca \"Limpiar antes el MikroTik\" (lo que el "
                              "panel le puso tendrás que quitarlo a mano)." % (
                                  res.get("mensaje", "fallo"),
                                  " OJO: el router ya se tocó (se quitaron IPs de sus listas)." if res.get("tocado")
                                  else ""), 409)
                return True
            nota = ("El router YA se limpio (%s): el punto sigue activo; repite la baja. "
                    % res.get("mensaje", ""))
        else:
            _bit(d, "PUNTO-BORRAR", pid=pid, resultado="sin-limpiar-router")
        cancelar = getattr(d, "baja_cancelada", None)
        try:
            _encolar(h, pid, "punto.borrar", {"pid": pid, "confirmar": confirmar}, nombre=confirmar, token=tok,
                     al_fallar=(lambda p_: cancelar(p_, op=tok)) if cancelar else None, nota_fallo=nota)
        except BaseException:
            if cancelar:
                cancelar(pid, op=tok)
            raise
    elif acc == "regenerar":
        _encolar(h, pid, "punto.vpn.regenerar", {"pid": pid}, token=tok)
    elif acc in ACCIONES_COLA:
        _encolar(h, pid, ACCIONES_COLA[acc], {"pid": pid}, token=tok)
    elif acc == "ajustar":
        redes, err = validar_redes(form.get("redes") or "")
        if err:
            if ajax:
                h._json({"error": err, "token": str(uuid.uuid4())}, 400)
            else:
                ficha(h, pid, err, 400)
            return True
        _encolar(h, pid, "punto.ajustar", {"pid": pid, "redes_abonados": redes}, token=tok, ajax=ajax)
    elif acc == "api":
        accion_api(h, pid, form, ajax=ajax)
    elif acc == "desbanear":
        accion_desbanear(h, pid, form, ajax=ajax)
    return True
