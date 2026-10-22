"""Permisos del panel, a la carta (el dueño, 2026-10-22: «algo así», un acordeón por sección con
«Activos X/Y» como el de Mikrowisp).

Cada usuario tendrá una lista `permisos` en usuarios.json con claves de este catálogo. Los roles de
siempre (admin, operador, lectura) pasan a ser PLANTILLAS: un usuario sin lista tiene los de su rol,
así que al actualizar nadie gana ni pierde nada.

Se hace por fases (cada una sube sola a main): en la fase 1 solo existe el catálogo y las
plantillas; cada fase siguiente pasa una sección del panel a pedir su permiso concreto en vez del
rol. Las secciones que aún no han pasado siguen decidiendo por rol.

Los permisos marcados como globales cambian algo de todos los puntos: solo valen para quien ve
todos los puntos (sin lista `puntos`). Nadie puede dar permisos ni puntos que él no tenga.
"""

# (clave del grupo, título, [(permiso, etiqueta, global)])
CATALOGO = (
    ("resumen", "Resumen", (
        ("resumen.ver", "En vivo, Top y Detalle", False),
        ("resumen.historico", "Histórico", False),
        ("resumen.conducta", "Conducta de abonados (y su CSV)", False),
        ("resumen.informe", "Informe PDF", False),
        ("resumen.eventos", "Eventos", False),
        ("resumen.todos", "Vista «Todos» (acumulado de todos los puntos)", True),
    )),
    ("cuarentena", "Cuarentena", (
        ("cuarentena.ver", "Ver candidatos, enviados y destinos", False),
        ("cuarentena.enviar", "Enviar y quitar de cuarentena", False),
        ("cuarentena.graduada", "Cuarentena graduada", False),
        ("cuarentena.dns", "Lista DNS", False),
        ("cuarentena.masivo", "Envío masivo de confirmados", False),
        ("cuarentena.destinos", "Bloquear destinos", False),
        ("cuarentena.confianza", "Destinos de confianza (lista global)", True),
    )),
    ("reputacion", "Reputación", (
        ("reputacion.ver", "Ver las IPs públicas y su estado", False),
        ("reputacion.consultar", "Consultar AbuseIPDB", False),
        ("reputacion.denunciar", "Denunciar a AbuseIPDB", True),
    )),
    ("puntos", "Puntos", (
        ("puntos.ver", "Ver la lista y la ficha", False),
        ("puntos.api", "API del MikroTik (guardar, probar, huella)", False),
        ("puntos.prefijos", "Prefijos", False),
        ("puntos.vpn_ver", "Ver los comandos y la clave de la VPN", False),
        ("puntos.vpn_regenerar", "Regenerar la clave de la VPN", False),
        ("puntos.arrancar", "Arrancar, parar y reiniciar", False),
        ("puntos.logs", "Logs", False),
        ("puntos.crear", "Crear puntos", True),
        ("puntos.borrar", "Borrar puntos", False),
        ("puntos.desbanear", "Desbanear una IP (fail2ban, global)", True),
    )),
    ("usuarios", "Usuarios", (
        ("usuarios.ver", "Ver los usuarios", False),
        ("usuarios.editar", "Crear y editar usuarios", False),
        ("usuarios.borrar", "Borrar y desactivar usuarios", False),
    )),
    ("ajustes", "Ajustes", (
        ("ajustes.empresa", "Empresa (nombre y logo)", True),
        ("ajustes.mikrotik", "MikroTik: políticas, listas y reglas globales", True),
        ("ajustes.publicas", "IPs públicas de los puntos", True),
        ("ajustes.feeds", "Feeds e IA", True),
        ("ajustes.telegram", "Telegram", True),
        ("ajustes.dns", "Resolutores DNS", True),
        ("ajustes.exclusiones", "Exclusiones", True),
        ("ajustes.confianza", "IPs de confianza del panel", True),
        ("ajustes.ventana", "Ventana del resumen", True),
        ("ajustes.reglas", "Actualizar las reglas", True),
        ("ajustes.actualizar", "Actualizar el panel", True),
        ("ajustes.bitacora", "Bitácora y registro", True),
    )),
)

TODOS = tuple(p for _g, _t, ps in CATALOGO for p, _e, _gl in ps)
GLOBALES = frozenset(p for _g, _t, ps in CATALOGO for p, _e, gl in ps if gl)

# Las plantillas reproducen lo que cada rol puede hoy (2026-10-22): un usuario sin lista
# `permisos` tiene los de su rol.
_LECTURA = ("resumen.ver", "resumen.historico", "resumen.conducta", "resumen.informe", "resumen.eventos",
            "resumen.todos", "cuarentena.ver", "reputacion.ver")
_OPERADOR = _LECTURA + (
    "cuarentena.enviar", "cuarentena.graduada", "cuarentena.dns", "cuarentena.masivo",
    "cuarentena.destinos", "cuarentena.confianza", "reputacion.consultar", "reputacion.denunciar",
    "puntos.ver", "puntos.api", "puntos.prefijos", "puntos.vpn_ver", "puntos.vpn_regenerar",
    "puntos.arrancar", "puntos.logs")
PLANTILLAS = {
    "lectura": frozenset(_LECTURA),
    "operador": frozenset(_OPERADOR),
    "admin": frozenset(TODOS),
}


def de_usuario(r):
    """Los permisos de un usuario: su lista `permisos` (solo claves del catálogo) o, sin lista, los
    de la plantilla de su rol. Un rol desconocido no tiene ninguno. Los globales solo cuentan si
    ve todos los puntos (sin lista `puntos`)."""
    if not r:
        return frozenset()
    if "permisos" in r:
        p = r.get("permisos")
        efectivos = frozenset(x for x in p if x in TODOS) if isinstance(p, list) else frozenset()
    else:
        efectivos = PLANTILLAS.get(r.get("role"), frozenset())
    if "puntos" in r:
        efectivos = efectivos - GLOBALES
    return efectivos


def activos(permisos, grupo):
    """(activos, total) de un grupo del catálogo, para el «Activos X/Y» del acordeón."""
    for g, _t, ps in CATALOGO:
        if g == grupo:
            return sum(1 for p, _e, _gl in ps if p in permisos), len(ps)
    raise KeyError(grupo)
