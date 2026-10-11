"""HTML del panel. TODO dato que no es literal de este fichero pasa por esc().

Sin scripts ni estilos en línea (la CSP solo permite 'self'): el comportamiento está en
/static/panel.js y el aspecto en /static/panel.css.
"""

from . import VERSION
from .estado import AVISOS, ESTADOS, semaforo, texto_contenedor
from .orq import partir_comandos
from .util import edad, esc, fecha

NAV = (("puntos", "/puntos", "Puntos"), ("alertas", "/alertas", "Alertas"),
       ("documentacion", "/documentacion", "Documentación"))

SEVERIDAD = {1: "alta", 2: "media", 3: "baja"}


def num(n):
    if n is None:
        return "-"
    try:
        return "{:,}".format(int(n)).replace(",", " ")
    except (TypeError, ValueError):
        return esc(n)


# --------------------------------------------------------------------------------------------
# Esqueleto
# --------------------------------------------------------------------------------------------

def _cabeza(titulo):
    return ('<!doctype html><html lang="es"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta name="referrer" content="same-origin">'
            '<title>%s · IDS MAAT</title>'
            '<link rel="stylesheet" href="/static/panel.css">'
            '<script src="/static/tema.js"></script>'
            '<script src="/static/panel.js" defer></script></head>' % esc(titulo))


def _modales():
    return ('<div class="modal" id="modal-ask" hidden role="dialog" aria-modal="true" aria-labelledby="ask-tit">'
            '<div class="caja"><h3 id="ask-tit"></h3><p id="ask-txt"></p>'
            '<div class="acciones"><button type="button" class="btn sec" id="ask-no">Cancelar</button>'
            '<button type="button" class="btn" id="ask-ok">Confirmar</button></div></div></div>')


def pagina(titulo, cuerpo, ctx, activa=""):
    usuario = ctx.get("usuario") or ""
    tabs = "".join('<a class="tab%s" href="%s">%s</a>' % (" on" if k == activa else "", h, esc(t))
                   for k, h, t in NAV)
    empresa = ctx.get("empresa") or ""
    marca = ('<a class="marca" href="/puntos"><span class="logo" aria-hidden="true"></span>'
             '<span>IDS MAAT</span>%s</a>'
             % ('<span class="empresa">%s</span>' % esc(empresa) if empresa else ""))
    menu = ('<details class="umenu"><summary title="Mi cuenta"><span class="av">%s</span>'
            '<span class="un">%s</span></summary><div class="umenu-caja">'
            '<div class="uhd">Sesión de <b>%s</b></div>'
            '<a href="/cuenta/clave">Cambiar mi clave</a>'
            '<button type="button" class="enlace" data-cambiar-tema>Tema: claro / oscuro</button>'
            '<form method="post" action="/salir"><input type="hidden" name="csrf" value="%s">'
            '<button type="submit" class="enlace salir">Cerrar sesión</button></form>'
            '<div class="ufin">ids-panel %s</div></div></details>'
            % (esc(usuario[:1].upper()), esc(usuario), esc(usuario), esc(ctx.get("csrf")), esc(VERSION)))
    invitacion = ""
    if ctx.get("clave_temporal") and activa != "cuenta":
        invitacion = ('<div class="aviso info invitacion">Entraste con una clave generada por el sistema. '
                      'Te recomendamos <a href="/cuenta/clave">cambiarla ahora</a>.</div>')
    return (_cabeza(titulo) + '<body><header class="nav"><div class="navwrap">' + marca +
            '<nav class="tabs">' + tabs + '</nav><div class="push"></div>' + menu +
            '</div></header><main>' + invitacion + cuerpo + '</main>' + _modales() + '</body></html>')


def pagina_suelta(titulo, cuerpo):
    """Páginas sin sesión (entrar, errores)."""
    return (_cabeza(titulo) + '<body class="suelta"><main class="estrecho">' + cuerpo + '</main>'
            + _modales() + '</body></html>')


def aviso(texto, tipo="error"):
    if not texto:
        return ""
    return '<div class="aviso %s" role="%s">%s</div>' % (esc(tipo), "alert" if tipo == "error" else "status",
                                                          esc(texto))


def error_pagina(codigo, titulo, texto):
    return pagina_suelta(titulo, '<div class="tarjeta"><h1>%s</h1><p>%s</p><p><a href="/puntos">Volver al panel</a>'
                         '</p></div>' % (esc(titulo), esc(texto)))


# --------------------------------------------------------------------------------------------
# Entrar y cuenta
# --------------------------------------------------------------------------------------------

def entrar(mensaje="", usuario="", empresa=""):
    return pagina_suelta("Entrar", (
        '<div class="tarjeta login"><div class="login-marca"><span class="logo" aria-hidden="true"></span>'
        '<div><b>IDS MAAT</b>%s</div></div>'
        '<h1>Entrar al panel</h1>%s'
        '<form method="post" action="/entrar" class="formulario">'
        '<label>Usuario<input name="usuario" autocomplete="username" required maxlength="32" value="%s" autofocus></label>'
        '<label>Clave<input name="clave" type="password" autocomplete="current-password" required maxlength="256"></label>'
        '<button type="submit" class="btn ancho">Entrar</button></form></div>'
        % ('<div class="sub">%s</div>' % esc(empresa) if empresa else "", aviso(mensaje), esc(usuario))))


def cambiar_clave(ctx, mensaje="", ok=""):
    texto = ""
    if ctx.get("clave_temporal"):
        texto = ('<p class="nota">Tu clave actual la generó el sistema (al crear el usuario o al '
                 'restablecerla). Cámbiala por una tuya. Puedes hacerlo más tarde: '
                 '<a href="/puntos">ahora no</a>.</p>')
    cuerpo = ('<h1>Cambiar mi clave</h1>%s%s%s'
              '<form method="post" action="/cuenta/clave" class="formulario tarjeta estrecho-form">'
              '<input type="hidden" name="csrf" value="%s">'
              '<label>Clave actual<input name="actual" type="password" autocomplete="current-password" required maxlength="256"></label>'
              '<label>Clave nueva <small>(mínimo 12 caracteres)</small><input name="nueva" type="password" '
              'autocomplete="new-password" required minlength="12" maxlength="256"></label>'
              '<label>Repite la clave nueva<input name="repetir" type="password" autocomplete="new-password" '
              'required minlength="12" maxlength="256"></label>'
              '<button type="submit" class="btn">Cambiar la clave</button></form>'
              '<p class="nota">Al cambiarla se cierran tus otras sesiones abiertas.</p>'
              % (aviso(ok, "ok"), aviso(mensaje), texto, esc(ctx.get("csrf"))))
    return pagina("Cambiar mi clave", cuerpo, ctx, "cuenta")


# --------------------------------------------------------------------------------------------
# Puntos
# --------------------------------------------------------------------------------------------

def _punto_celda(pid, p):
    s = semaforo(p)
    return ('<td><span class="dot %s" title="%s"></span><a class="fuerte" href="/puntos/%s">%s</a>'
            '<div class="sub">%s</div></td>' % (s, esc(s), esc(pid), esc(p.get("nombre") or pid), esc(pid)))


def _avisos_html(p):
    av = p.get("avisos") or []
    if not av:
        return ""
    return '<ul class="avisos">' + "".join('<li>%s</li>' % esc(AVISOS.get(a, a)) for a in av) + "</ul>"


def _mikrotik(p, t, tz):
    vc = p.get("vpn_cliente") or {}
    if vc.get("conectado"):
        desde = vc.get("desde")
        return ('<span class="ok">conectado</span><div class="sub">%s%s</div>'
                % (esc(vc.get("ip_real") or ""), (" · hace " + esc(edad(t - desde))) if desde else ""))
    return '<span class="mal">desconectado</span>'


def _espejo(ultimo, t, tz):
    if not ultimo:
        return '<span class="sub">sin espejo aún</span>'
    clase = "ok" if t - ultimo < 120 else ("ambar" if t - ultimo < 600 else "mal")
    return '<span class="%s">hace %s</span><div class="sub">%s</div>' % (clase, esc(edad(t - ultimo)),
                                                                      esc(fecha(ultimo, tz)))


def _suricata(p):
    su = p.get("suricata") or {}
    c = (p.get("contenedores") or {}).get("suricata")
    extra = []
    if su.get("reglas_cargadas") is not None:
        extra.append("%s reglas" % num(su.get("reglas_cargadas")))
    kp, kd = su.get("kernel_packets"), su.get("kernel_drops")
    if kp:
        try:
            extra.append("descarte %.1f %%" % (100.0 * float(kd or 0) / float(kp)))
        except (TypeError, ValueError, ZeroDivisionError):
            pass
    return '%s<div class="sub">%s</div>' % (esc(texto_contenedor(c)), esc(" · ".join(extra)))


def tabla_puntos(filas, empresa_fila, edad_estado, t, tz):
    """filas: [(pid, punto, ultimo_espejo, (alertas24, completo))]."""
    cab = ('<table class="tabla"><thead><tr><th>Punto</th><th>Estado</th><th>VPN</th><th>MikroTik</th>'
           '<th>Último espejo</th><th>Suricata</th><th class="num">Alertas 24 h</th><th>Puerto</th>'
           '<th>Red del túnel</th></tr></thead><tbody>')
    e = empresa_fila
    cuerpo = ('<tr class="fila-empresa"><td><b>Toda la empresa</b><div class="sub">%s puntos</div></td>'
              '<td>%s activos</td><td>%s con VPN sana</td><td>%s conectados</td><td>%s con espejo</td>'
              '<td>%s sanos</td><td class="num"><a href="/alertas">%s%s</a></td><td></td><td></td></tr>'
              % (num(e["puntos"]), num(e["activos"]), num(e["vpn_sana"]), num(e["conectados"]),
                 num(e["con_espejo"]), num(e["suricata_sana"]), num(e["alertas"]), "+" if not e["completo"] else ""))
    for pid, p, ultimo, (n24, completo) in filas:
        estado = ESTADOS.get(p.get("estado"), p.get("estado") or "-")
        if p.get("deseado") == "parado" and p.get("estado") != "parado":
            estado += " (se está parando)"
        cuerpo += ('<tr>%s<td>%s%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>'
                   '<td class="num"><a href="/alertas?punto=%s">%s%s</a></td><td>%s/tcp</td><td>%s</td></tr>'
                   % (_punto_celda(pid, p), esc(estado), _avisos_html(p),
                      esc(texto_contenedor((p.get("contenedores") or {}).get("vpn"))),
                      _mikrotik(p, t, tz), _espejo(ultimo, t, tz), _suricata(p),
                      esc(pid), num(n24), "+" if not completo else "", esc(p.get("puerto")), esc(p.get("tun_net"))))
    if not filas:
        cuerpo += ('<tr><td colspan="9" class="vacio">Todavía no hay puntos. '
                   '<a href="/puntos/nuevo">Agrega el primero</a>.</td></tr>')
    pie = '</tbody></table>'
    viejo = ""
    if edad_estado is None:
        viejo = aviso("No se puede leer el estado del orquestador (estado.json). Si acabas de instalar, "
                      "espera unos segundos; si sigue, revisa el servicio ids-orq en el servidor.", "ambar")
    elif edad_estado > 60:
        viejo = aviso("El estado tiene %s: el orquestador no lo está actualizando (debería ser cada 15 s)."
                      % edad(edad_estado), "ambar")
    return viejo + '<div class="tabla-scroll">' + cab + cuerpo + pie + '</div>'


def puntos(ctx, tabla_html, sistema):
    cola = (sistema or {}).get("cola") or {}
    en = cola.get("en_curso")
    linea_cola = ("en curso: %s %s (%s)" % (en.get("orden"), en.get("pid") or "", en.get("paso") or "")
                  if isinstance(en, dict) else "libre")
    cap = ((sistema or {}).get("capacidad") or {}).get("caben") or {}
    caben = ", ".join("%s %s" % (k, v) for k, v in cap.items()) if cap else "-"
    cuerpo = ('<div class="titulo"><h1>Puntos</h1><a class="btn" href="/puntos/nuevo">Agregar punto</a></div>'
              '<p class="sub">Cola del orquestador: %s · pendientes: %s · caben más puntos: %s</p>'
              '<div id="tabla-puntos" data-refrescar="/puntos/tabla" data-cada="15000">%s</div>'
              '<p class="sub">Se actualiza solo cada 15 s.</p>'
              % (esc(linea_cola), esc(cola.get("pendientes", 0)), esc(caben), tabla_html))
    return pagina("Puntos", cuerpo, ctx, "puntos")


# --------------------------------------------------------------------------------------------
# Crear punto
# --------------------------------------------------------------------------------------------

def nuevo_punto(ctx, valores=None, mensaje="", caben=None):
    v = valores or {}
    ros = str(v.get("ros_version") or "7")
    perfil = v.get("perfil") or "reducido"

    def marcado(a, b):
        return " checked" if a == b else ""
    cab = ""
    if caben:
        cab = '<p class="sub">Caben ahora en el servidor: %s.</p>' % esc(
            ", ".join("%s %s" % (k, n) for k, n in caben.items()))
    cuerpo = (
        '<h1>Agregar punto</h1>'
        '<p class="nota">Un punto es un MikroTik de la red que envía una copia de su tráfico (espejo) al '
        'sensor por una VPN propia. Al crearlo, el servidor prepara su VPN y su Suricata y te da los '
        'comandos para pegar en el MikroTik.</p>%s%s'
        '<form method="post" action="/puntos/nuevo" class="formulario tarjeta">'
        '<input type="hidden" name="csrf" value="%s">'
        '<label>Nombre del punto <small>(minúsculas, números y guiones; p. ej. norte)</small>'
        '<input name="nombre" required maxlength="31" pattern="[a-z0-9][a-z0-9\\-]{1,30}" value="%s"></label>'
        '<label>Redes de abonados <small>(CIDR, una por línea o separadas por comas)</small>'
        '<textarea name="redes" rows="4" required placeholder="10.0.0.0/24">%s</textarea></label>'
        '<fieldset><legend>Versión de RouterOS del MikroTik</legend>'
        '<label class="opcion"><input type="radio" name="ros_version" value="7"%s> RouterOS 7</label>'
        '<label class="opcion"><input type="radio" name="ros_version" value="6"%s> RouterOS 6 (6.49 o superior)</label>'
        '</fieldset>'
        '<fieldset><legend>Perfil de reglas</legend>'
        '<label class="opcion"><input type="radio" name="perfil" value="reducido"%s> Reducido '
        '<small>(por defecto; menos memoria, más puntos por servidor)</small></label>'
        '<label class="opcion"><input type="radio" name="perfil" value="completo"%s> Completo '
        '<small>(todas las reglas; usa casi el doble de memoria)</small></label>'
        '</fieldset>'
        '<button type="submit" class="btn">Crear punto</button></form>'
        % (aviso(mensaje), cab, esc(ctx.get("csrf")), esc(v.get("nombre", "")), esc(v.get("redes", "")),
           marcado(ros, "7"), marcado(ros, "6"), marcado(perfil, "reducido"), marcado(perfil, "completo")))
    return pagina("Agregar punto", cuerpo, ctx, "puntos")


# --------------------------------------------------------------------------------------------
# Comandos MikroTik
# --------------------------------------------------------------------------------------------

def _bloque(id_, titulo, texto, nota=""):
    return ('<div class="bloque"><div class="bloque-cab"><b>%s</b>'
            '<button type="button" class="btn sec chico" data-copiar="%s">Copiar</button></div>%s'
            '<pre id="%s" class="cmd">%s</pre></div>' % (esc(titulo), esc(id_), nota, esc(id_), esc(texto)))


def comandos(texto, ros_version, prefijo="cmd"):
    """Bloques v7/v6 (el declarado primero) y el del certificado API-SSL, cada uno con Copiar."""
    partes = partir_comandos(texto)
    if "todo" in partes:
        return _bloque(prefijo + "-todo", "Comandos para el MikroTik", partes["todo"])
    try:
        ros = int(ros_version)
    except (TypeError, ValueError):
        ros = 7
    orden = ["v7", "v6"] if ros != 6 else ["v6", "v7"]
    html_ = ""
    if partes.get("cabecera"):
        html_ += '<pre class="cmd cab">%s</pre>' % esc(partes["cabecera"])
    for i, k in enumerate(orden):
        titulo = "RouterOS %s" % k[1]
        if i == 0:
            titulo += " (la versión declarada de este punto)"
            html_ += _bloque("%s-%s" % (prefijo, k), titulo, partes.get(k, ""))
        else:
            html_ += ('<details class="otro"><summary>Ver el bloque de RouterOS %s</summary>'
                      '<p class="nota">Solo conecta si se cambia la versión declarada del punto '
                      '(en el servidor: <code>ids-orq punto ajustar</code>).</p>%s</details>'
                      % (k[1], _bloque("%s-%s" % (prefijo, k), titulo, partes.get(k, ""))))
    if partes.get("certificado"):
        html_ += _bloque(prefijo + "-cert", "Certificado API-SSL (una sola vez por router)",
                         partes["certificado"])
    return html_


# --------------------------------------------------------------------------------------------
# Operaciones (crear, borrar, regenerar)
# --------------------------------------------------------------------------------------------

def _pasos(pasos, total):
    if not pasos:
        return ""
    out = '<ol class="pasos">'
    for p in pasos:
        ok = p.get("estado") == "ok"
        out += '<li class="%s">%s <span class="sub">%s%s</span></li>' % (
            "ok" if ok else "mal", esc(p.get("nombre")), "hecho" if ok else "falló",
            (" — " + esc(p.get("detalle"))) if p.get("detalle") else "")
    return out + "</ol>"


ORDENES = {"punto.crear": "Crear punto", "punto.borrar": "Borrar punto",
           "punto.vpn.regenerar": "Regenerar la clave de la VPN"}


def op_cuerpo(vm):
    """Fragmento que el navegador refresca. vm: dict del modelo de la operación (app.vista_op)."""
    term = "1" if vm.get("terminada") else "0"
    out = '<div id="op-cuerpo" data-terminada="%s">' % term
    out += '<h1>%s%s</h1>' % (esc(ORDENES.get(vm.get("orden"), vm.get("orden") or "Operación")),
                              (" · " + esc(vm.get("titulo_punto"))) if vm.get("titulo_punto") else "")
    if vm.get("error_canal"):
        out += aviso(vm["error_canal"], "ambar")
    if not vm.get("terminada"):
        if vm.get("delante"):
            out += '<p class="espera">En cola: %s operación(es) delante.</p>' % esc(vm.get("delante"))
        else:
            out += ('<p class="espera"><span class="girando" aria-hidden="true"></span>%s</p>'
                    % esc(("Paso actual: %s (%s)" % (vm.get("paso"), vm.get("avance")))
                          if vm.get("paso") else "Esperando al orquestador…"))
        out += '<progress class="barra" max="100" value="%s"></progress>' % esc(vm.get("porcentaje", 0))
        out += _pasos(vm.get("pasos"), vm.get("total"))
        out += '<p class="sub">Puedes dejar esta página abierta: se actualiza sola.</p>'
        return out + "</div>"
    out += _pasos(vm.get("pasos"), vm.get("total"))
    if not vm.get("ok"):
        out += aviso(vm.get("mensaje_claro"))
        if vm.get("orden") == "punto.crear":
            out += '<p><a class="btn" href="/puntos/nuevo">Volver a intentarlo</a></p>'
        return out + "</div>"
    pid = vm.get("pid")
    if vm.get("orden") == "punto.borrar":
        out += aviso("Punto borrado: se quitaron su VPN, su Suricata y sus datos del servidor.", "ok")
        out += ('<p class="nota">En el MikroTik quedan la interfaz <code>ids-vpn</code>, la ruta, el usuario '
                '<code>ids-api</code> y la regla de firewall con el comentario <code>IDS ids-maat:%s</code>: '
                'bórralos a mano.</p><p><a class="btn" href="/puntos">Volver a Puntos</a></p>' % esc(pid))
        return out + "</div>"
    r = vm.get("resultado") or {}
    if r.get("clave"):
        out += aviso("Listo. Copia ahora la clave: el panel NO la vuelve a mostrar. Si la pierdes, "
                     "tendrás que regenerarla desde la ficha del punto.", "ambar")
        out += ('<div class="credenciales tarjeta"><div><span class="sub">Usuario de la VPN</span>'
                '<code id="cred-usuario">%s</code><button type="button" class="btn sec chico" '
                'data-copiar="cred-usuario">Copiar</button></div>'
                '<div><span class="sub">Clave de la VPN (se muestra una sola vez)</span>'
                '<code id="cred-clave">%s</code><button type="button" class="btn sec chico" '
                'data-copiar="cred-clave">Copiar</button></div></div>'
                % (esc(r.get("usuario")), esc(r.get("clave"))))
        out += ('<h2>Comandos para el MikroTik</h2><p class="nota">Ya llevan la clave de la VPN puesta. '
                '<code>&lt;CLAVE-API&gt;</code> es la clave que elijas para el usuario de la API del '
                'router.</p>')
        out += comandos(r.get("comandos", ""), vm.get("ros_version"), prefijo="op")
    elif vm.get("orden") == "punto.crear" and (r.get("ya_entregada") or vm.get("ya_existia")):
        out += aviso("Ese punto ya existía con los mismos datos. La clave de la VPN ya se entregó; si no "
                     "la tienes, regénerala desde la ficha del punto.", "ambar")
    else:
        out += aviso("La operación terminó bien. La clave ya se mostró una vez y el panel no la guarda; "
                     "si no la copiaste, regénerala desde la ficha del punto.", "info")
    if pid:
        out += '<p><a class="btn" href="/puntos/%s">Ir a la ficha del punto</a></p>' % esc(pid)
    return out + "</div>"


def operacion(ctx, op_id, vm):
    cuerpo = ('<div id="op" data-op="%s" data-refrescar="/operaciones/%s/fragmento" data-cada="1500">%s</div>'
              % (esc(op_id), esc(op_id), op_cuerpo(vm)))
    return pagina("Operación", cuerpo, ctx, "puntos")


# --------------------------------------------------------------------------------------------
# Ficha y alertas
# --------------------------------------------------------------------------------------------

def tabla_alertas(alertas, tz, con_punto=True, nombres=None):
    nombres = nombres or {}
    if not alertas:
        return '<p class="vacio">No hay alertas con este filtro.</p>'
    cab = ('<div class="tabla-scroll"><table class="tabla alertas"><thead><tr><th>Hora</th>%s<th>Origen</th>'
           '<th>Destino</th><th>Proto</th><th>Firma</th><th>Severidad</th></tr></thead><tbody>'
           % ("<th>Punto</th>" if con_punto else ""))
    filas = ""
    for a in alertas:
        sev = a.get("severidad")
        filas += ('<tr><td class="hora">%s</td>%s<td>%s<span class="sub">:%s</span></td>'
                  '<td>%s<span class="sub">:%s</span></td><td>%s</td><td>%s<div class="sub">%s%s</div></td>'
                  '<td><span class="sev s%s">%s</span></td></tr>'
                  % (esc(fecha(a.get("ts"), tz)),
                     ('<td><a href="/puntos/%s">%s</a><div class="sub">%s</div></td>'
                      % (esc(a["punto"]), esc(nombres.get(a["punto"], a["punto"])), esc(a["punto"])))
                     if con_punto else "",
                     esc(a.get("src_ip")), esc(a.get("src_port") if a.get("src_port") is not None else "-"),
                     esc(a.get("dest_ip")), esc(a.get("dest_port") if a.get("dest_port") is not None else "-"),
                     esc(a.get("proto")), esc(a.get("firma")), esc(a.get("categoria")),
                     (" · sid %s" % esc(a.get("sid"))) if a.get("sid") else "",
                     esc(sev if sev in (1, 2, 3) else 0), esc(SEVERIDAD.get(sev, sev if sev is not None else "-"))))
    return cab + filas + "</tbody></table></div>"


def _dato(etiqueta, valor_html):
    return '<div class="dato"><span class="sub">%s</span><div>%s</div></div>' % (esc(etiqueta), valor_html)


def ficha(ctx, pid, p, ultimo, n24, comandos_txt, comandos_err, alertas, ip, ip_err, t, tz, mensaje=""):
    p = p or {}
    nombre = p.get("nombre") or pid
    s = semaforo(p) if p else "gris"
    su = p.get("suricata") or {}
    resumen = "".join([
        _dato("Estado", esc(ESTADOS.get(p.get("estado"), p.get("estado") or "sin datos todavía")) + _avisos_html(p)),
        _dato("VPN", esc(texto_contenedor((p.get("contenedores") or {}).get("vpn")))),
        _dato("MikroTik", _mikrotik(p, t, tz)),
        _dato("Último espejo", _espejo(ultimo, t, tz)),
        _dato("Suricata", _suricata(p)),
        _dato("Alertas 24 h", '<a href="/alertas?punto=%s">%s%s</a>' % (esc(pid), num(n24[0]), "+" if not n24[1] else "")),
        _dato("Puerto VPN", esc("%s/tcp" % p.get("puerto")) if p.get("puerto") else "-"),
        _dato("Red del túnel", esc(p.get("tun_net") or "-")),
        _dato("Perfil", esc("%s · %s hilo(s)" % (p.get("perfil"), p.get("hilos"))) if p.get("perfil") else "-"),
        _dato("RouterOS declarado", esc("v%s" % p.get("ros_version")) if p.get("ros_version") else "-"),
        _dato("Paquetes vistos / descartados", "%s / %s" % (num(su.get("kernel_packets")), num(su.get("kernel_drops")))),
    ])
    if comandos_err:
        cmds = aviso(comandos_err, "ambar")
    else:
        cmds = ('<p class="nota">Sin la clave de la VPN: donde dice <code>&lt;CLAVE-VPN&gt;</code> va la que se '
                'mostró al crear el punto. <code>&lt;CLAVE-API&gt;</code> es la que elijas para el usuario de '
                'la API del router.</p>' + comandos(comandos_txt, p.get("ros_version"), prefijo="ficha"))
    regenerar = ('<form method="post" action="/puntos/%s/regenerar" class="enlinea" data-ask-titulo="¿Regenerar la '
                 'clave de la VPN?" data-ask-texto="Se crea una clave nueva y la sesión VPN actual del MikroTik se '
                 'corta hasta que pongas la clave nueva en el router." data-ask-ok="Regenerar">'
                 '<input type="hidden" name="csrf" value="%s"><button type="submit" class="btn sec">'
                 'Regenerar la clave de la VPN</button></form>' % (esc(pid), esc(ctx.get("csrf"))))
    filtro = ('<form method="get" action="/puntos/%s" class="filtro"><label>IP<input name="ip" value="%s" '
              'placeholder="10.0.0.5" maxlength="45"></label><button type="submit" class="btn sec">Filtrar</button>%s'
              '</form>' % (esc(pid), esc(ip or ""), ' <a href="/puntos/%s">quitar filtro</a>' % esc(pid) if ip else ""))
    borrar = (
        '<div class="tarjeta peligro"><h2>Borrar el punto</h2><p>Quita del servidor la VPN, el Suricata y '
        '<b>todos los datos</b> de este punto. No se puede deshacer.</p>'
        '<button type="button" class="btn peligro" data-abrir="modal-borrar">Borrar punto…</button></div>'
        '<div class="modal" id="modal-borrar" hidden role="dialog" aria-modal="true" aria-labelledby="borrar-tit">'
        '<div class="caja"><h3 id="borrar-tit">Borrar el punto %s</h3>'
        '<p>Se borran su VPN, su Suricata y todas sus alertas. Para confirmar, escribe el nombre del punto: '
        '<b>%s</b></p>'
        '<form method="post" action="/puntos/%s/borrar" data-confirmar-nombre="%s">'
        '<input type="hidden" name="csrf" value="%s">'
        '<input name="confirmar" autocomplete="off" required aria-label="Nombre del punto" maxlength="31">'
        '<div class="acciones"><button type="button" class="btn sec" data-cerrar>Cancelar</button>'
        '<button type="submit" class="btn peligro" disabled>Borrar definitivamente</button></div></form>'
        '</div></div>' % (esc(nombre), esc(nombre), esc(pid), esc(nombre), esc(ctx.get("csrf"))))
    cuerpo = (
        '<div class="titulo"><h1><span class="dot %s"></span>%s <span class="sub">%s</span></h1>'
        '<a class="btn sec" href="/puntos">Volver a Puntos</a></div>'
        '%s%s<div class="tarjeta"><div class="datos">%s</div></div>'
        '<h2>Comandos para el MikroTik</h2>%s<div class="acciones-fila">%s</div>'
        '<h2>Últimas alertas de este punto</h2>%s%s%s%s'
        % (s, esc(nombre), esc(pid), aviso(mensaje),
           "" if p else aviso("El punto todavía no aparece en el estado del orquestador (se actualiza cada 15 s).", "info"),
           resumen, cmds, regenerar, filtro, aviso(ip_err), tabla_alertas(alertas, tz, con_punto=False),
           borrar))
    return pagina(nombre, cuerpo, ctx, "puntos")


def alertas(ctx, alertas_, puntos_, sel, ip, ip_err, tz):
    nombres = {pid: (p.get("nombre") or pid) for pid, p in puntos_}
    opciones = '<option value="">Toda la empresa</option>' + "".join(
        '<option value="%s"%s>%s (%s)</option>' % (esc(pid), " selected" if pid == sel else "", esc(nombres[pid]), esc(pid))
        for pid, _p in puntos_)
    cuerpo = (
        '<h1>Alertas</h1>'
        '<form method="get" action="/alertas" class="filtro"><label>Punto<select name="punto">%s</select></label>'
        '<label>IP<input name="ip" value="%s" placeholder="10.0.0.5" maxlength="45"></label>'
        '<button type="submit" class="btn sec">Filtrar</button></form>'
        '<p class="nota">Cada fila es de un punto. Una misma IP privada en dos puntos son dos abonados '
        'distintos: aparecen en filas separadas, cada una con su punto.</p>%s%s'
        % (opciones, esc(ip or ""), aviso(ip_err), tabla_alertas(alertas_, tz, con_punto=True, nombres=nombres)))
    return pagina("Alertas", cuerpo, ctx, "alertas")


# --------------------------------------------------------------------------------------------
# Documentación
# --------------------------------------------------------------------------------------------

def documentacion(ctx):
    cuerpo = """<h1>Documentación</h1><div class="doc tarjeta">
<h2>Qué es un punto</h2>
<p>Un <b>punto</b> es un MikroTik de tu red que manda una copia de su tráfico (el <b>espejo</b>) a este
servidor. Cada punto tiene su propia VPN y su propio Suricata, separados de los demás: la misma IP
privada en dos puntos son dos abonados distintos y nunca se mezclan.</p>
<h2>Pantalla Puntos</h2>
<ul>
<li><b>Estado</b>: activo, creando, parado, con error o borrando.</li>
<li><b>VPN</b> y <b>Suricata</b>: si sus contenedores están sanos.</li>
<li><b>MikroTik</b>: si el router tiene la VPN conectada, desde qué IP pública y desde cuándo.</li>
<li><b>Último espejo</b>: cuándo llegó el último paquete del espejo. Si pasan más de 10 minutos sin
espejo, el punto se marca en ámbar.</li>
<li><b>Alertas 24 h</b>: las alertas de Suricata del último día.</li>
</ul>
<p>El punto de color: verde = todo bien; ámbar = aviso (MikroTik sin conectar, sin espejo…);
rojo = error o VPN/Suricata caídos; gris = parado.</p>
<h2>Crear un punto</h2>
<ol>
<li>En <b>Puntos</b> pulsa <b>Agregar punto</b>: nombre, redes de abonados (CIDR), versión de RouterOS y perfil.</li>
<li>El servidor crea la VPN y el Suricata del punto. Verás el avance paso a paso.</li>
<li>Al terminar se muestran <b>una sola vez</b> el usuario y la clave de la VPN, y los comandos para el
MikroTik con la clave ya puesta. Cópialos: la clave no se vuelve a mostrar.</li>
<li>Pega los comandos en la terminal del MikroTik. En unos segundos el punto aparece como conectado.</li>
</ol>
<p>Si perdiste la clave, en la ficha del punto está <b>Regenerar la clave de la VPN</b>: crea una nueva,
corta la sesión actual del router y la muestra una vez.</p>
<h2>Comandos del MikroTik</h2>
<ul>
<li><code>/interface ovpn-client add name=ids-vpn …</code> crea la VPN hacia este servidor (TCP, solo hacia
el puerto del punto). Hay un bloque para RouterOS 7 y otro para RouterOS 6 (6.49 o superior).</li>
<li>La ruta <code>blackhole</code> de la red del túnel evita que ese tráfico salga por otro lado si la VPN cae.</li>
<li>El usuario <code>ids-api</code> y la regla de firewall solo dejan entrar a la API del router desde el
sensor y por la VPN. <code>&lt;CLAVE-API&gt;</code> la eliges tú.</li>
<li>El certificado <code>ids-promax</code> es para la API-SSL; solo hace falta una vez por router.</li>
</ul>
<h2>La VPN solo trae el espejo</h2>
<p>La VPN de cada punto no da acceso a nada: el servidor solo acepta por ella el espejo (TZSP) que manda
el MikroTik y solo habla con la API del propio router. No enruta tráfico de abonados ni lleva a otras
redes, y un punto no ve a otro.</p>
<h2>Borrar un punto</h2>
<p>En la ficha del punto, <b>Borrar punto…</b> pide escribir su nombre. Se borran su VPN, su Suricata y
todos sus datos del servidor. En el MikroTik hay que quitar a mano la interfaz <code>ids-vpn</code>, la
ruta, el usuario <code>ids-api</code> y la regla con el comentario <code>IDS ids-maat:&lt;punto&gt;</code>.</p>
<h2>Acceso al panel</h2>
<p>Al panel solo se entra a través del <b>proxy inverso</b> de la empresa (HTTPS). El panel no confía en
cabeceras de reenvío que no vengan de ese proxy, frena los intentos de entrada fallidos por IP y por
usuario, y cierra la sesión tras 2 horas sin uso (12 horas como máximo). En una emergencia, el
administrador del servidor puede entrar con un túnel SSH
(<code>ssh -L 5637:10.210.255.2:5637 root@&lt;servidor&gt;</code>) y abrir <code>http://localhost:5637</code>.</p>
<p>Si olvidaste tu clave, el administrador del servidor la restablece con
<code>ids-orq panel restablecer &lt;usuario&gt;</code>: imprime una clave nueva, que el panel te invitará a
cambiar al entrar.</p>
</div>"""
    return pagina("Documentación", cuerpo, ctx, "documentacion")
