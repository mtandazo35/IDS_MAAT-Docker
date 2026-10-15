# -*- coding: utf-8 -*-
"""El formulario del MikroTik: conexion por un lado, listas por tipo de abuso por otro.

Lo que estaba mal no era el orden de los campos. El formulario enseñaba LIST y LIST_DNS
como "la lista de cuarentena", y el envio NO manda ahi: enruta por categoria
(clientes-botnet, clientes-dns-malware, clientes-escaneo...). Esas listas, que son las que
de verdad reciben a los CPEs, solo se podian cambiar editando MK_CONF a mano.

Lo que se protege:
  - que haya un campo por categoria con el nombre por defecto CARGADO (editable); vacio o
    el propio defecto significan "el de siempre" y no se guardan como cambio;
  - que lo configurado en MK_CONF se vea en el campo (si no, guardar el formulario lo
    borraria sin querer);
  - que las listas heredadas ya NO esten en el formulario: ningun envio nuevo va ahi.
    Pero la CLAVE se conserva en el .conf -libera entradas anteriores al enrutado por
    categoria, sirve al diagnostico y de guardia-, asi que la ruta no puede borrarla al
    guardar un formulario que ya no la trae;
  - que los TTL si sigan: son vivos para todas las listas, tambien las de categoria;
  - y que un nombre con comillas no rompa el HTML: lo pone el ISP y puede llevar lo que sea.
"""
import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ

DASH = extraer.fuente("DASH")
ARBOL = ast.parse(DASH)

PIEZAS = ("CAT_CPE", "CAT_OTROS", "_card_listas",
          "ACCIONES", "ACCIONES_POR_CAT", "ACCION_DEFECTO", "accion_de_clase")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def pieza():
    # la tarjeta ya trae la accion por categoria: dobles de lo que consulta
    ns = {"html": __import__("html"), "cargar_routers": lambda: [],
          "cargar_reglas_propias": lambda c: "", "_mk_globales": lambda: {}}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


def main():
    ns = pieza()
    cats = ns["CAT_CPE"] + [ns["CAT_OTROS"]]

    # --- sin nada configurado: un campo por categoria, vacio, con el defecto a la vista --
    h = ns["_card_listas"]({})
    for cat, nom, _c, por_defecto in cats:
        check("hay campo para '%s'" % cat, "name=lista_%s" % cat in h, "")
        check("  con el nombre por defecto CARGADO como valor (editable)",
              'name=lista_%s value="%s"' % (cat, por_defecto) in h, "")
    check("son las ocho (siete categorias mas otros)",
          h.count("name=lista_") == 8, h.count("name=lista_"))

    # --- lo configurado en MK_CONF se ve en el campo ------------------------------------
    # Si no se viera, guardar el formulario mandaria vacio y borraria la configuracion.
    h2 = ns["_card_listas"]({"LISTA_BOTNET": "abusivos-botnet", "LISTA_P2P": "cola-p2p"})
    check("una lista cambiada en MK_CONF aparece en su campo",
          'name=lista_botnet value="abusivos-botnet"' in h2, "")
    check("y otra tambien", 'name=lista_p2p value="cola-p2p"' in h2, "")
    check("las no cambiadas traen su defecto cargado",
          'name=lista_escaneo value="clientes-escaneo"' in h2, "")

    # --- las heredadas ya no se ensenan; los TTL si ---------------------------------------
    # Ningun envio nuevo va a LIST ni a LIST_DNS: ensenarlas como "la lista de cuarentena"
    # era prometer un destino y usar otro. Fuera del formulario.
    # (adaptada, 2026-10-14) el TTL vive en cada router y Ajustes lo pone igual en todos: el
    # campo enseña el que tienen los routers, no un TTL de MK_CONF (que nunca se guardaba ahi)
    ns["cargar_routers"] = lambda: [{"id": "p001", "TTL": "2h", "TTL_DNS": "12h"},
                                    {"id": "p002", "TTL": "2h", "TTL_DNS": "12h"}]
    ns["nodos"] = type("N", (), {"hay_nodo": staticmethod(lambda: False),
                                 "nodo_actual": staticmethod(lambda: "")})   # selector de router
    h3 = ns["_card_listas"]({"LIST": "Cliente Virus", "LIST_DNS": "suricata-dns-sospechoso"})
    ns["cargar_routers"] = lambda: []
    check("la lista de cuarentena heredada ya no esta en el formulario",
          "name=list " not in h3 and "name=list value" not in h3, h3[-400:])
    check("ni la de DNS heredada", "name=list_dns" not in h3, "")
    check("y ya no se habla de 'heredadas'", "heredada" not in h3, "")
    # el TTL es vivo: cuanto dura cada entrada en el router, en todas las listas
    # (adaptada, 2026-10-14) la cuarentena de abonados ya no caduca por tiempo: sale cuando el CPE
    # deja de enviar virus. Fuera los campos TTL; el apartado lo explica
    check("los TTL ya no estan: la cuarentena no caduca por tiempo",
          "name=ttl" not in h3 and "name=ttl_dns" not in h3, "")
    check("y el apartado dice cuando sale un abonado",
          "Cuándo sale un abonado de la cuarentena</h3>" in h3 and "deja de enviar virus" in h3, "")

    # La clave NO puede borrarse al guardar: el formulario ya no la manda, asi que la ruta
    # tiene que conservar el valor existente (es lo que libera entradas antiguas).
    # (adaptada, CONTRATO-F2 §4) /routers/guardar desaparece: la ruta acaba en la siguiente
    ruta_mk = DASH[DASH.index('if ruta == "/mikrotik":'):]
    ruta_mk = ruta_mk[:ruta_mk.index('\n        if ruta == ', 10)]
    # (adaptada, 2026-10-14) antes la ruta la ponia al defecto y la copiaba al router elegido;
    # ahora no la toca: ni la escribe en m ni en ningun router
    check("al guardar, LIST se conserva aunque el formulario ya no la traiga",
          'm["LIST"]' not in ruta_mk and '_r["LIST"]' not in ruta_mk
          and 'for _k in ("LIST", "TTL"' not in ruta_mk, "")

    # Telegram decia que el CPE fue a LIST cuando fue a la de su categoria
    env = DASH[DASH.index("if ruta == \"/cuarentena/enviar\":"):]
    env = env[:env.index("\n        if ruta == ", 10)]
    # (adaptada, CONTRATO-F2 §3) el aviso se deduplica por `pid|ip`: notificar_cuarentena
    # recibe la clave del CPE, no la IP pelada; lo que se protege (la lista) es lo mismo
    check("el aviso de Telegram nombra la lista a la que FUE, no la heredada",
          'notificar_cuarentena(clave, "Infección CnC", _lst' in env
          and '"Infeccion CnC", m.get("LIST"' not in env, "")

    # --- un nombre con comillas no rompe el HTML -----------------------------------------
    h4 = ns["_card_listas"]({"LISTA_BOTNET": 'mi "lista" <rara>'})
    check("las comillas y los angulos se escapan",
          'value="mi &quot;lista&quot; &lt;rara&gt;"' in h4
          and 'value="mi "lista"' not in h4, h4[h4.find("lista_botnet"):][:90])

    # --- el guardado --------------------------------------------------------------------
    ruta = DASH[DASH.index('if ruta == "/mikrotik":'):]
    ruta = ruta[:ruta.index('\n        if ruta == ', 10)]
    check("la ruta guarda las listas por categoria",
          'for _cat, _nom, _cs, _def in CAT_CPE + [CAT_OTROS]:' in ruta
          and '"LISTA_" + _cat.upper()' in ruta, "")
    # vacio o el propio defecto = borrar la clave: no se guarda el defecto como cambio
    check("un campo vacio o con el defecto borra la clave",
          "m.pop(_k, None)" in ruta and "_v != _def" in ruta, "")
    # (adaptada, CONTRATO-F2 §4) ya no hay HOST ni puerto que guardar (el router se alcanza
    # por el rele unix de su punto); la conexion que queda (usuario, clave, enviar si/no) es
    # la del router del NODO del formulario y va a routers.json en el mismo envio
    # (adaptada, 2026-10-14) la conexion (usuario, clave, enviar) ya no esta en Ajustes: es de
    # la ficha del punto (/puntos/<pid>/api). Esta ruta solo guarda lo comun y el TTL de todos
    check("y la conexion ya no se guarda aqui (es de la ficha del punto)",
          '_r["USER"]' not in ruta and '_r["PASS"]' not in ruta and '_r["ENABLED"]' not in ruta
          and "lista_" in ruta and 'm["HOST"]' not in ruta, "")

    # --- guardar de verdad: lo que la ruta mete en m tiene que llegar al archivo ----------
    # (2026-10-09: guardar_mk escribia una lista fija de claves y tiraba LISTA_* y POL_*;
    # el usuario rellenaba sus listas, guardaba, y volvian vacias)
    import json, tempfile, threading
    td = tempfile.mkdtemp()
    nod, sec = _comun.panel(td)          # nodos y secretos reales (puntos p001 y p002)
    ns_g = _comun.piezas({"os": os, "json": json, "threading": threading,
                          "nodos": nod, "secretos": sec},
                         ("guardar_mk", "_mk_globales", "_MK_CONEXION"))
    ns_g["MK_CONF"] = os.path.join(td, "mk.conf")
    ns_g["guardar_mk"]({"HOST": "192.0.2.1", "USER": "u", "PASS": "p", "ENABLED": "1",
                        "AUTO_MANTENER": "1", "POL_AUTO": "1",
                        "LISTA_BOTNET": "abusivos-botnet", "LISTA_DNS": "clientes-malware",
                        "POL_BOTNET": "alto", "POL_P2P": "nada", "LISTA_SPAM": ""})
    g = ns_g["_mk_globales"]()
    check("guardar_mk conserva las listas por categoria",
          g.get("LISTA_BOTNET") == "abusivos-botnet" and g.get("LISTA_DNS") == "clientes-malware", g)
    check("y las politicas por clase", g.get("POL_BOTNET") == "alto" and g.get("POL_P2P") == "nada", g)
    check("una lista vacia no se escribe (vuelve el defecto)", "LISTA_SPAM" not in g, g)
    # (adaptada, CONTRATO-F2 §4 y §10.3) "lo de siempre" se reparte: los ajustes globales
    # siguen en MK_CONF; la conexion (host, usuario, clave, enviar si/no) ya no va ahi -nada
    # de claves en claro en ese fichero- sino por punto en routers.json, con la clave cifrada.
    txt = open(ns_g["MK_CONF"], encoding="utf-8").read()
    check("y lo de siempre sigue: los ajustes globales en MK_CONF, la conexion fuera",
          g.get("AUTO_MANTENER") == "1" and g.get("POL_AUTO") == "1"
          and "HOST" not in g and "ENABLED" not in g and "PASS=" not in txt
          and "192.0.2.1" not in txt, (g, txt))
    ns_r = _comun.piezas({"os": os, "json": json, "threading": threading,
                          "nodos": nod, "secretos": sec},
                         ("ROUTERS_CONF", "CAMPOS_USUARIO", "_ROUTERS_LOCK", "SECRETOS_AVISO",
                          "_asoc_router", "_router_vacio", "_routers_guardados", "cargar_routers",
                          "guardar_routers", "ROUTERS_MAP", "publicar_routers_map"))
    rs = ns_r["cargar_routers"]()
    for r in rs:
        if r["id"] == "p001":
            r.update({"USER": "u", "PASS": "p", "ENABLED": "1"})
    ns_r["guardar_routers"](rs)
    r1 = {r["id"]: r for r in ns_r["cargar_routers"]()}
    crudo = open(ns_r["ROUTERS_CONF"], encoding="utf-8").read()
    check("  y la conexion se guarda en el router de SU punto (usuario, clave, enviar)",
          r1["p001"]["USER"] == "u" and r1["p001"]["PASS"] == "p" and r1["p001"]["ENABLED"] == "1"
          and r1["p002"]["USER"] == "" and r1["p002"]["ENABLED"] == "0", r1)
    check("  sin HOST que teclear: el rele unix de su punto",
          r1["p001"]["HOST"].startswith("unix:") and r1["p001"]["HOST"].endswith("api.sock"), r1["p001"])
    check("  y la clave en disco va cifrada, no en claro",
          '"PASS": "p"' not in crudo and json.load(open(ns_r["ROUTERS_CONF"], encoding="utf-8"))
          ["routers"]["p001"]["PASS"] not in ("", "p"), crudo)

    # --- la tarjeta ya no se llama 'cuarentena' a secas ---------------------------------
    # (adaptada, 2026-10-14) la tarjeta es «MikroTik — cuarentena» y la conexion queda como un
    # resumen por nodo con enlace a su ficha
    check("la tarjeta separa la conexion de lo demas",
          "Conexión de cada MikroTik" in DASH and "MikroTik &mdash; cuarentena" in DASH, "")
    check("y las listas tienen su propio apartado",
          "Listas por tipo de abuso" in DASH, "")
    check("que explica por que son distintas",
          "una botnet se corta, el P2P se encola" in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada (CONTRATO-F2 §4, §5, §10.3; 2026-10-14): sin HOST/puerto ni /routers/guardar; guardar_mk solo guarda lo global; la conexion de cada nodo es de la ficha del punto (routers.json, clave cifrada) y Ajustes pone el TTL en todos. El formulario del MikroTik: conexion por un lado, listas por tipo de abuso por otro."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
