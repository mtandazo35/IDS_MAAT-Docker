# -*- coding: utf-8 -*-
"""La tendencia del abuso saliente: el numero que hay que poder enseñar.

Los reportes HTML se podan a los 3 dias, asi que la tendencia NO se puede reconstruir
desde ellos. Se acumula aparte, y de forma incremental: recontar la ventana daria mal el
total del dia en cuanto alguien la baje de 24 h, y lo haria sin avisar.

Lo que se protege aqui es que los contadores sumen bien entre corridas, que un dia sin
datos se vea como hueco y no como un dia tranquilo, y que la pagina calcule la tendencia
como toca.

Adaptada al panel portado (CONTRATO-F2 §1, §3, §4). El generador (fusionar_metricas,
traducir) no cambia. En el panel, las salidas del generador son POR PUNTO: metricas.json,
cuarentena.json y entrantes.json viven en `nodos.salida(nombre, pid)` (PANEL/nodos/<pid>/),
no en LOGDIR ni en /var/log; acciones.json es global (`nodos.ruta("estado", ...)`). Se usa
el `nodos.py` real sobre un arbol temporal con el nodo p001 puesto, un router por punto
(§1: id = pid) y la clave de CPE real (`clave_cpe`: siempre `pid|ip`). §4 quita el
`/tool fetch` de `/blocklist.rsc`: esa comprobacion pasa a la del comportamiento nuevo
(la lista se pega como script; el router no descarga nada del panel).
"""
import ast
import json
import os
import sys
import unittest
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ

GEN = extraer.fuente("HREP")
DASH = extraer.fuente("DASH")

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def piezas(fuente, nombres, extra=None):
    arbol = ast.parse(fuente)
    ns = {"json": json, "os": os, "time": time, "html": __import__("html"),
          "glob": __import__("glob"), "threading": __import__("threading")}
    ns.update(extra or {})
    for n in arbol.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in nombres:
            exec(ast.get_source_segment(fuente, n) or "", ns)
    return ns


def dia(delta):
    return time.strftime("%Y-%m-%d", time.localtime(time.time() + delta * 86400))


def main():
    # ---------- generador: fusion incremental ----------
    g = piezas(GEN, ("METRICAS_DIAS", "METRICAS_MAX_CPES", "fusionar_metricas"))
    fus = g["fusionar_metricas"]

    hoy = dia(0)
    r1 = fus({}, {hoy: {"sal": 100, "ent": 5, "cpes": {"10.0.0.1", "10.0.0.2"},
                        "puertos": {"25/tcp": 80}, "cats": {"Spam": 80}, "nodos": {}}},
             1000, False)
    check("primera corrida: se guarda el dia", r1["dias"][hoy]["sal"] == 100, r1["dias"][hoy])
    check("y la marca de hasta donde se conto", r1["ultimo_ts"] == 1000, r1["ultimo_ts"])

    r2 = fus(r1, {hoy: {"sal": 40, "ent": 2, "cpes": {"10.0.0.2", "10.0.0.9"},
                        "puertos": {"25/tcp": 30, "22/tcp": 10}, "cats": {"Spam": 30}, "nodos": {}}},
             2000, False)
    check("segunda corrida: SUMA, no reemplaza", r2["dias"][hoy]["sal"] == 140, r2["dias"][hoy]["sal"])
    check("los entrantes tambien suman", r2["dias"][hoy]["ent"] == 7, r2["dias"][hoy]["ent"])
    check("los CPEs distintos se unen sin duplicar", r2["dias"][hoy]["cpes_n"] == 3,
          r2["dias"][hoy]["cpes_n"])
    check("los puertos suman y aparecen los nuevos",
          r2["dias"][hoy]["puertos"] == {"25/tcp": 110, "22/tcp": 10}, r2["dias"][hoy]["puertos"])

    # un dia con corte de datos queda marcado
    r3 = fus(r2, {hoy: {"sal": 1, "ent": 0, "cpes": set(), "puertos": {}, "cats": {}, "nodos": {}}},
             3000, True)
    check("un corte de datos deja el dia marcado", r3["dias"][hoy].get("hueco") is True, r3["dias"][hoy])
    # el agujero marca SOLO los dias que toca: ayer perdido entero aparece gris, hoy no se
    # mancha por estar en la misma corrida
    ayer = dia(-1); otro = dia(-2)
    # prev fresco: fusionar_metricas trabaja sobre el dict que recibe (r1 ya arrastra r3)
    r4 = fus({"dias": {}}, {hoy: {"sal": 5, "ent": 0, "cpes": set(), "puertos": {}, "cats": {}, "nodos": {}}},
             4000, {ayer})
    check("el dia del agujero aparece aunque no tenga datos, y gris",
          r4["dias"].get(ayer, {}).get("hueco") is True and r4["dias"][ayer]["sal"] == 0, r4["dias"].get(ayer))
    check("y el dia de la corrida que NO toca el agujero no se marca",
          r4["dias"][hoy].get("hueco") is not True, r4["dias"][hoy])
    check("un dia fuera del agujero no se inventa", otro not in r4["dias"], "")

    # retencion y colapso de la lista de CPEs
    viejo = dia(-10)
    antiguo = dia(-500)
    base = {"dias": {viejo: {"sal": 9, "ent": 0, "cpes": ["10.0.0.7"], "cpes_n": 1,
                             "puertos": {}, "cats": {}, "nodos": {}},
                     antiguo: {"sal": 5, "ent": 0, "cpes_n": 1, "puertos": {}, "cats": {}, "nodos": {}}}}
    r4 = fus(base, {}, 4000, False)
    check("de los dias viejos se guarda el numero, no la lista de CPEs",
          "cpes" not in r4["dias"][viejo] and r4["dias"][viejo]["cpes_n"] == 1, r4["dias"][viejo])
    check("y lo mas viejo que la retencion se cae", antiguo not in r4["dias"], list(r4["dias"]))

    # ---------- panel: contadores de accion y pagina ----------
    tmp = tempfile.mkdtemp()
    nod, sec = _comun.panel(tmp, nodo="p001")      # CONTRATO-F2 §3: se mira el punto p001
    nod.asegurar_dirs()                            # lo que hace el panel al arrancar
    d = piezas(DASH, ("ACCIONES_FILE", "ACCIONES_DIAS", "_ACC_LOCK", "_leer_acciones", "cargar_acciones",
                      "contar_accion", "METRICAS_FILE", "cargar_metricas", "_serie",
                      "_media", "tendencia_txt", "_DIAS_SEM", "_grafico", "historico_page",
                      "_CPES_CACHE", "_cpes_de_reporte",
                      "DIAG_FILE", "diagnostico_de",
                      "ENTRANTES_FILE", "BL_LISTA", "BL_MIN_ALERTAS", "BL_MIN_DESTINOS",
                      "BL_TOPE", "_REP_CACHE", "_REP_MAX", "rep_fuente", "cargar_entrantes",
                      "blocklist_borde", "blocklist_rsc", "blocklist_reglas",
                      # la tabla de atacantes con detalle (dueño, que hizo, feeds; 2026-10-16)
                      "BL_VISTAS", "FEEDS_IP_INFO", "rep_fuentes", "_JS_DUENOS",
                      "ros_lista", "_RE_ROS_RARO",
                      # CONTRATO-F2 §1/§3: rutas por nodo, nodo en los enlaces, clave pid|ip
                      "cuarentena_json", "_salida_ctx", "_CPES_LOCK", "qs_nodo",
                      "clave_cpe", "ip_de"),
               extra={"BASE_CSS": "", "nav": lambda a="": "<!--nav-->",
                      "wrap": lambda b, refresh=True, active="": b,
                      "nodos": nod, "secretos": sec, "_up": __import__("urllib.parse").parse,
                      # CONTRATO-F2 §1: un router por punto, id = pid
                      "cargar_routers": lambda: [{"id": p_, "nombre": nod.nombre(p_)}
                                                 for p_ in nod.pids()],
                      "ipaddress": __import__("ipaddress"), "re": __import__("re"),
                      "es_mi_cpe": lambda ip: ip.startswith("10."),
                      "nunca_bloquear": lambda ip: False,
                      "CFG": {"PORT": "5637"},
                      "ip_del_sensor": lambda hacia="": "10.0.0.9",
                      "FEEDS_META": os.path.join(tmp, "reputation.meta"),
                      "cargar_feeds_meta": lambda: {},
                      "traducir": lambda s: s,
                      # dueños: cache vacia (la tabla deja el hueco que la pagina pide a /duenos)
                      "duenos": type("D", (), {"cargar": staticmethod(lambda: {}),
                                               "vigente": staticmethod(lambda e: bool(e)),
                                               "consultable": staticmethod(lambda ip: True)}),
                      "mis_redes": lambda: ["10.0.0.0/8"]})
    # CONTRATO-F2 §3: acciones.json es global (PANEL/estado); metricas.json, cuarentena.json
    # y entrantes.json son salidas del generador DEL PUNTO (PANEL/nodos/<pid>/)
    check("las acciones van al estado global del panel",
          d["ACCIONES_FILE"] == nod.ruta("estado", "acciones.json"), d["ACCIONES_FILE"])
    MET = nod.salida(d["METRICAS_FILE"], "p001")
    ENT = nod.salida(d["ENTRANTES_FILE"], "p001")
    CUAR = d["cuarentena_json"]("p001")

    # auditoria A-18: cada punto lleva su cuenta (y la empresa el total); se mira p001
    d["contar_accion"]("ENVIADO", "p001"); d["contar_accion"]("ENVIADO", "p001"); d["contar_accion"]("QUITADO", "p001")
    acc = d["cargar_acciones"]()
    check("las acciones se cuentan por dia", acc[hoy] == {"ENVIADO": 2, "QUITADO": 1}, acc)
    check("y el total de la empresa tambien",
          d["cargar_acciones"](nod.TODOS)[hoy] == {"ENVIADO": 2, "QUITADO": 1}, d["cargar_acciones"](nod.TODOS))

    # serie con un dia flojo y otro fuerte para que la tendencia se note
    dias = {}
    for i in range(14, 7, -1):
        dias[dia(-i)] = {"sal": 1000, "ent": 0, "cpes_n": 20, "puertos": {}, "cats": {}}
    for i in range(7, 0, -1):
        dias[dia(-i)] = {"sal": 500, "ent": 0, "cpes_n": 10,
                         "puertos": {"25/tcp": 400}, "cats": {"Spam": 400}}
    dias[hoy] = {"sal": 123, "ent": 4, "cpes_n": 7, "puertos": {"22/tcp": 100},
                 "cats": {"Escaneo SSH": 100}}
    json.dump({"dias": dias}, open(MET, "w", encoding="utf-8"))

    check("por defecto, la ultima semana (7 dias)", "ataques salientes en 7 días" in d["historico_page"](), "")
    pag = d["historico_page"](30)
    check("ya no sale 'hoy' en el cuadro del periodo (eran las ultimas horas)", "hoy (parcial)" not in pag, "")
    check("el cuadro grande es el total del periodo elegido, y dice que dias abarca",
          "ataques salientes en 30 días" in pag and "del " in pag, "")
    check("la media es de los dias CON datos (15 de 30), no de 30",
          "media diaria (15 días con datos)" in pag and "solo 15 tienen datos" in pag, "")
    pag7 = d["historico_page"](7)
    check("y cambia con el periodo", "ataques salientes en 7 días" in pag7 and "media diaria (7 días)" in pag7, "")
    check("la tendencia de 30 dias compara 30 con 30 (no 7 con 7)",
          "tendencia (30 días vs los 30 anteriores)" in pag and "7 días vs" not in pag, "")
    check("  y sin 60 dias de historia lo dice", "hacen falta 60 días de datos (hay 15)" in pag, "")
    check("la de 7 dias compara 7 con 7, y SALE (antes solo cargaba 7 y hacian falta 14)",
          "tendencia (7 días vs los 7 anteriores)" in pag7 and "frente a los 7 días anteriores" in pag7, "")
    check("y la tendencia a la baja, en verde", "&darr;" in pag7 and "#3a9d5d" in pag7,
          "flecha=%s" % ("&darr;" in pag7))
    # hoy va a medias: si contara, 7 dias de 500 + hoy 123 parecerian una bajada que no es
    dias_planos = {dia(-i): {"sal": 500, "cpes_n": 1} for i in range(14, 0, -1)}
    dias_planos[hoy] = {"sal": 10, "cpes_n": 1}
    json.dump({"dias": dias_planos}, open(MET, "w", encoding="utf-8"))
    pp = d["historico_page"](7)
    check("hoy (parcial) no cuenta para la tendencia: plano es plano", "&rarr;" in pp and "&darr;" not in pp, "")
    dias_planos[dia(-1)] = {"sal": 20, "cpes_n": 1, "hueco": True}
    json.dump({"dias": dias_planos}, open(MET, "w", encoding="utf-8"))
    pg = d["historico_page"](7)
    check("un dia gris (faltan datos) tampoco: no es una mejora", "&rarr;" in pg and "&darr;" not in pg, "")
    check("  y el cuadro dice cuantos dias incompletos hay", "1 día(s) incompleto(s)" in pg, "")
    for i in range(6, 1, -1):
        dias_planos[dia(-i)] = {"sal": 900, "cpes_n": 1, "hueco": True}
    json.dump({"dias": dias_planos}, open(MET, "w", encoding="utf-8"))
    pg2 = d["historico_page"](7)
    check("con casi todo el periodo en gris NO se calcula tendencia (1 dia completo no es una semana)",
          "pocos días completos (0 de 7)" in pg2 and "&uarr;" not in pg2 and "&darr;" not in pg2, "")
    json.dump({"dias": dias}, open(MET, "w", encoding="utf-8"))
    check("se cuentan las cuarentenas del periodo", "puestos en cuarentena" in pag)
    check("se dice por que atacan", "Spam" in pag and "Escaneo SSH" in pag)
    check("y por que puerto salen", "25/tcp" in pag and "22/tcp" in pag)
    # (adaptada 2026-10-12: el grafico paso de SVG estirado a columnas HTML/CSS; lo que se exige
    # es lo mismo: grafico propio, sin librerias externas)
    check("hay grafico sin librerias externas", "class=hg" in pag and "cdn" not in pag.lower())
    # el eje: con 7 dias cada barra lleva dia de la semana y dd/mm; con 30, una fecha cada pocos
    import re as _re
    sem = ("lun", "mar", "mie", "jue", "vie", "sab", "dom")
    f7 = [time.strftime("%d/%m", time.localtime(time.time() - k * 86400)) for k in range(6, -1, -1)]
    d7 = [sem[time.localtime(time.time() - k * 86400).tm_wday] for k in range(6, -1, -1)]
    check("eje de 7 dias: las 7 fechas en dd/mm y su dia de la semana",
          all(">%s<" % x in pag7 for x in f7) and all(">%s<" % x in pag7 for x in d7), (f7, d7))
    rot30 = _re.findall(r"<i>(\d\d/\d\d)</i>", pag)
    check("eje de 30 dias: fechas dd/mm repartidas (ni 3 ni 30), y la de hoy al final",
          8 <= len(rot30) <= 12 and rot30[-1] == f7[-1], rot30)
    # el user quito la lista de reportes guardados del Historico (2026-10-12)
    check("la lista de reportes guardados ya no sale", "Reportes guardados" not in pag)
    # CONTRATO-F2 §3: las metricas son del punto que se mira; p002 no hereda las de p001
    with nod.contexto("p002"):
        _otro = d["historico_page"](30)
    check("otro punto sin metricas propias no ensena las de p001",
          "Todavía no hay histórico" in _otro, "")

    vacia = d["historico_page"](30)
    json.dump({"dias": {}}, open(MET, "w", encoding="utf-8"))
    vacia = d["historico_page"](30)
    check("sin historico se explica, no se muestra un cero enganoso",
          "Todavía no hay histórico" in vacia)

    # un dia con hueco se pinta distinto
    json.dump({"dias": {hoy: {"sal": 10, "hueco": True, "cpes_n": 1}}},
              open(MET, "w", encoding="utf-8"))
    ph = d["historico_page"](7)
    check("un dia con datos incompletos no se pinta como bueno",
          "#c8ccd1" in ph and "el panel estuvo parado" in ph and "sensor estuvo parado" not in ph)

    # ---------- que cuenta como abuso, y como se nombra ----------
    t = piezas(GEN, ("_TRAD", "_TRAD_CACHE", "_TRAD_CACHE_MAX", "_traducir_lento", "traducir", "CATS_NO_ABUSO"), extra={"re": __import__("re")})
    tr = t["traducir"]
    casos = [
        ("ET HUNTING Terse Unencrypted Request for Google - Likely Connectivity Check",
         "Chequeo de conectividad"),
        ("ET HUNTING Suspicious Empty User-Agent", "User-Agent raro"),
        ("GPL WEB_SERVER 403 Forbidden", "Acceso denegado (403)"),
        ("ET SCAN Potential SSH Scan", "Escaneo SSH"),
        ("ET CNC Feodo checkin", "Botnet CnC"),
    ]
    for sig, esperado in casos:
        check("se traduce %r" % sig[:40], tr(sig) == esperado, tr(sig))

    largo = tr("ET FOOBAR Una firma larguisima que nadie tradujo y que no cabe en la columna ni de broma")
    check("una firma sin traducir se acorta y pierde el prefijo del ruleset",
          len(largo) <= 45 and not largo.startswith("ET "), largo)

    check("BitTorrent NO cuenta como abuso saliente", "BitTorrent / P2P" in t["CATS_NO_ABUSO"])
    check("ni un chequeo de conectividad", "Chequeo de conectividad" in t["CATS_NO_ABUSO"])
    check("pero el escaneo SI", "Escaneo SSH" not in t["CATS_NO_ABUSO"])
    check("y la botnet tambien", "Botnet CnC" not in t["CATS_NO_ABUSO"])

    # el ruido se guarda aparte, no se tira ni se suma
    r5 = fus({}, {hoy: {"sal": 10, "ent": 0, "ruido": 900, "cpes": set(),
                        "puertos": {}, "cats": {}, "nodos": {}}}, 5000, False)
    check("el ruido se guarda en su propio contador",
          r5["dias"][hoy]["sal"] == 10 and r5["dias"][hoy]["ruido"] == 900, r5["dias"][hoy])
    r6 = fus(r5, {hoy: {"sal": 5, "ent": 0, "ruido": 100, "cpes": set(),
                        "puertos": {}, "cats": {}, "nodos": {}}}, 6000, False)
    check("y tambien suma entre corridas", r6["dias"][hoy]["ruido"] == 1000, r6["dias"][hoy])

    # ---------- Historico sin «Reglas de salida» (el user, 2026-10-13) ----------
    json.dump({"top_riesgo": [
        {"ip": "10.0.0.1", "router": "", "puertos_top": {"25/tcp": 4000}},
        {"ip": "10.0.0.2", "router": "", "puertos_top": {"25/tcp": 3000, "443/tcp": 50}},
        {"ip": "10.0.0.3", "router": "", "puertos_top": {"25/tcp": 1000}},
        {"ip": "10.0.0.4", "router": "", "puertos_top": {"22/tcp": 1500, "23/tcp": 500}},
        {"ip": "10.0.0.5", "router": "", "puertos_top": {"443/tcp": 9000}},
    ], "candidatos": [], "dns_candidatos": []},
        open(CUAR, "w", encoding="utf-8"))

    # el cache del reporte tiene que darse cuenta de que el archivo cambio, aunque se
    # reescriba dentro del mismo tick del reloj: si no, la pagina muestra datos viejos
    # sin que nada lo delate (paso con getmtime a secas)
    _antes = len(d["_cpes_de_reporte"](None))
    json.dump({"top_riesgo": [
        {"ip": "10.0.0.1", "router": "", "puertos_top": {"25/tcp": 4000},
         "cats_top": {"Spam": 4000}},
        {"ip": "10.0.0.4", "router": "", "puertos_top": {"22/tcp": 1500, "23/tcp": 500},
         "cats_top": {"Escaneo SSH": 1200, "Escaneo de puertos": 600, "Fuerza bruta": 200}},
        {"ip": "10.0.0.5", "router": "", "puertos_top": {"443/tcp": 9000},
         "cats_top": {"Anomalia TLS/SSL": 9000}},
    ], "candidatos": [], "dns_candidatos": []},
        open(CUAR, "w", encoding="utf-8"))
    check("el cache nota que el reporte cambio, aunque sea al instante",
          len(d["_cpes_de_reporte"](None)) != _antes or _antes == 3,
          (_antes, len(d["_cpes_de_reporte"](None))))

    pag_r = d["historico_page"](30)
    check("Historico ya no tiene la tarjeta 'Reglas de salida' ni sus reglas",
          "Reglas de salida" not in pag_r and "/ip firewall filter" not in pag_r
          and "analisis_salida" not in DASH and "GRUPOS_CONTROL" not in DASH, "")
    check("y el total no abusivo sigue en la cabecera", "no abusivo" in pag_r)

    # ---------- bloqueo en el borde: cortar a los que nos atacan ----------
    check("sin datos de entrantes no se propone bloquear a nadie",
          d["blocklist_borde"]() == [], d["blocklist_borde"]())

    # Aqui NO se pueden usar 203.0.113.x ni 198.51.100.x: son rangos de documentacion,
    # no son direcciones publicas enrutables, y el codigo los rechaza a proposito (eso se
    # comprueba mas abajo). Se usan resolutores publicos conocidos como relleno.
    json.dump({"origenes": {
        # golpea fuerte y a muchos: se bloquea
        "1.1.1.1": {"alertas": 900, "destinos": 40, "pais": "CN", "firma": "SSH scan"},
        # una sola alerta contra un solo destino: ruido de fondo de internet
        "8.8.8.8": {"alertas": 1, "destinos": 1, "pais": "US", "firma": "x"},
        # pocas alertas PERO fichada en un feed: entra igual
        "9.9.9.9": {"alertas": 2, "destinos": 1, "pais": "RU", "firma": "y"},
        # una IP nuestra que aparezca por error NO se bloquea jamas
        "10.6.1.10": {"alertas": 5000, "destinos": 80, "pais": "EC", "firma": "z"},
        # un rango de documentacion no es publico: no se bloquea aunque golpee
        "203.0.113.50": {"alertas": 900, "destinos": 40, "pais": "XX", "firma": "w"},
    }}, open(ENT, "w", encoding="utf-8"))
    io = __import__("io")
    with io.open(os.path.join(tmp, "reputation.lst"), "w", encoding="utf-8") as fh:
        fh.write("9.9.9.9\tfeodo\n")
    with io.open(os.path.join(tmp, "reputation.meta"), "w", encoding="utf-8") as fh:
        fh.write("{}")

    bl = {x["ip"]: x for x in d["blocklist_borde"]()}
    check("se bloquea al que golpea fuerte y a muchos destinos", "1.1.1.1" in bl, list(bl))
    check("el ruido de fondo NO se bloquea", "8.8.8.8" not in bl, list(bl))
    check("pero si esta fichada en un feed, entra aunque golpee poco",
          "9.9.9.9" in bl and bl["9.9.9.9"]["fuente"] == "feodo", bl.get("9.9.9.9"))
    check("un rango de documentacion no se bloquea: no es una IP publica",
          "203.0.113.50" not in bl, list(bl))
    check("una IP de TUS redes no se bloquea nunca", "10.6.1.10" not in bl, list(bl))
    check("se dice por que esta cada una",
          bl["1.1.1.1"]["alertas"] == 900 and bl["1.1.1.1"]["destinos"] == 40,
          bl["1.1.1.1"])
    check("y en que feeds esta (todos, no solo uno)",
          bl["9.9.9.9"]["fuentes"] == ["feodo"] and bl["1.1.1.1"]["fuentes"] == [], bl)
    check("un entrantes.json sin puertos ni ultima no rompe: [] y 0",
          bl["1.1.1.1"]["puertos"] == [] and bl["1.1.1.1"]["ultima"] == 0, bl["1.1.1.1"])

    # la tabla de la pagina va con todas las columnas centradas (el user, 2026-10-13)
    hp = d["historico_page"](7)
    check("la tabla de atacantes de internet sale centrada",
          "Cortar a los que te atacan desde internet" in hp and "<table class=tcentro>" in hp
          and ".tcentro th,.tcentro td{text-align:center!important}" in hp, "")
    check("y con relleno interior: nada pegado al borde de la tarjeta",
          "<section class='card cardp'>" in hp and ".cardp{padding:18px 22px}" in hp, "")
    check("y sin el bloque 'Como montarlo en el MikroTik' (ya no aplica)",
          "Como montarlo en el MikroTik" not in hp, "")

    rsc = d["blocklist_rsc"]()
    check("el script limpia la lista vieja antes de escribir",
          "remove $i" in rsc and "find list=suricata-atacantes" in rsc, rsc[:200])
    check("y agrega las IPs con caducidad", "add list=suricata-atacantes" in rsc and "timeout=1d" in rsc)
    check("sin meter comillas ni cosas raras en el comentario",
          '"' not in rsc.split("comment=")[1].split('"')[1] if "comment=" in rsc else True)

    reg = d["blocklist_reglas"]()
    check("EL detalle que evita romper clientes: solo conexiones NUEVAS",
          reg.count("connection-state=new") >= 2, reg)
    check("no se corta en raw, que tiraria tambien las respuestas",
          "/ip firewall raw" not in reg, reg)
    # CONTRATO-F2 §4: el MikroTik no llega al panel por el tunel; se quita el /tool fetch
    # (y su scheduler). Sigue sin meterse miles de entradas por la API: la lista va como
    # script que se pega en el router (blocklist_rsc, comprobado arriba).
    check("la lista no se mete por la API ni se descarga del panel: se pega como script",
          "/tool fetch" not in reg and "scheduler" not in reg and "script" in reg, reg)
    check("se cubre lo que entra a la red y lo que entra al router",
          "chain=forward" in reg and "chain=input" in reg)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada a salidas por punto y router por punto (CONTRATO-F2 §1, §3: nodos/<pid>/metricas.json, cuarentena.json, entrantes.json; clave pid|ip) y sin /tool fetch (§4); acciones por punto (auditoria A-18). La tendencia del abuso saliente: el numero que hay que poder enseñar."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
