# -*- coding: utf-8 -*-
"""Politicas por clase de abuso: que hacer depende de QUE hace el CPE, no solo de cuanto puntua.

Lo que se protege:
  - herencia: una caja con ALTO=cuarentena y sin POL_<CLASE> sigue haciendo lo mismo en
    todas las clases (nada cambia en produccion por actualizar); 'dns' contaba como corte;
  - la decision: 'alto' corta solo en ALTO, 'medio' en MEDIO y ALTO, 'siempre' en todas,
    'notificar' avisa, 'nada' nada;
  - aplicar_politicas manda a la lista de la CLASE (no a la heredada), guarda clase y lista
    en el registro, y libera de la lista guardada, no de la que tocaria hoy;
  - un CPE de clase P2P con politica 'nada' no se corta aunque su riesgo sea ALTO;
  - el barrido rapido se rige por la politica de botnet, no por POL_ALTO;
  - el formulario tiene un select por clase con su lista al lado, y la ruta guarda
    POL_<CLASE> ignorando valores que no sean de la lista.
"""
import ast
import contextlib
import json
import os
import sys
import unittest
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ
DASH = extraer.fuente("DASH")
ARBOL = ast.parse(DASH)

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def piezas(nombres, extra=None):
    ns = {"json": json, "os": os, "time": __import__("time"), "html": __import__("html")}
    ns.update(extra or {})
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in nombres:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


BASE = ("CAT_CPE", "CAT_OTROS", "POL_CLASE", "POL_CLASE_VALORES", "_BANDA_NIVEL", "_POL_UMBRAL",
        "_politica_heredada", "politica_de_clase", "accion_para", "categoria_de_cats")


def main():
    ns = piezas(BASE, {"_mk_globales": lambda: {}})
    pdc = ns["politica_de_clase"]; acc = ns["accion_para"]

    # --- herencia desde las bandas ----------------------------------------------------
    viejo = {"POL_BAJO": "nada", "POL_MEDIO": "nada", "POL_ALTO": "cuarentena"}
    check("ALTO=cuarentena sin POL_<CLASE> -> 'alto' en todas las clases (P2P incluido)",
          all(pdc(c, viejo) == "alto" for c, *_ in ns["CAT_CPE"] + [ns["CAT_OTROS"]]), "")
    check("MEDIO=cuarentena -> 'medio'", pdc("botnet", {"POL_MEDIO": "cuarentena"}) == "medio", "")
    check("BAJO=dns (era una cuarentena a la lista DNS) -> 'siempre'",
          pdc("dns", {"POL_BAJO": "dns"}) == "siempre", "")
    check("solo notificar en alguna banda -> 'notificar'", pdc("spam", {"POL_ALTO": "notificar"}) == "notificar", "")
    check("nada de nada -> 'nada'", pdc("spam", {}) == "nada", "")
    check("y POL_<CLASE> manda sobre lo heredado",
          pdc("p2p", {"POL_ALTO": "cuarentena", "POL_P2P": "nada"}) == "nada"
          and pdc("botnet", {"POL_ALTO": "cuarentena", "POL_P2P": "nada"}) == "alto", "")
    check("un valor raro en POL_<CLASE> se ignora y cae a lo heredado",
          pdc("botnet", {"POL_ALTO": "cuarentena", "POL_BOTNET": "zzz"}) == "alto", "")

    # --- la decision --------------------------------------------------------------------
    for pol, esperado in (("alto", {"BAJO": "nada", "MEDIO": "nada", "ALTO": "cuarentena"}),
                          ("medio", {"BAJO": "nada", "MEDIO": "cuarentena", "ALTO": "cuarentena"}),
                          ("siempre", {"BAJO": "cuarentena", "MEDIO": "cuarentena", "ALTO": "cuarentena"}),
                          ("notificar", {"BAJO": "notificar", "MEDIO": "notificar", "ALTO": "notificar"}),
                          ("nada", {"BAJO": "nada", "MEDIO": "nada", "ALTO": "nada"})):
        got = {b: acc("botnet", b, {"POL_BOTNET": pol}) for b in ("BAJO", "MEDIO", "ALTO")}
        check("politica '%s' decide bien por banda" % pol, got == esperado, got)
    check("banda desconocida nunca corta", acc("botnet", "", {"POL_BOTNET": "siempre"}) == "nada", "")

    # --- aplicar_politicas con dobles ---------------------------------------------------
    # Panel portado (CONTRATO-F2 §1, §3): aplicar_politicas corre POR PUNTO (pid), lee el
    # cuarentena.json de ese punto (nodos.salida), las claves son `pid|ip` (clave_cpe, ip_de,
    # rid_de y _suf_nodo REALES) y el router es el del punto; el "r0" del multi-nodo viejo es
    # p001. La conexion y la politica llegan juntas en cargar_mk_de(r) (cargar_mk ya no trae
    # router) y "habilitado" es mk_listo de ESE router. La lista heredada sigue siendo LIST.
    td = tempfile.mkdtemp()
    nod, _sec = _comun.panel(td)
    cq = {"top_riesgo": [
        {"ip": "10.0.0.7", "router": "", "riesgo": 85, "banda": "ALTO", "cats_top": {"Botnet CnC": 20}},
        {"ip": "10.0.0.8", "router": "", "riesgo": 80, "banda": "ALTO", "cats_top": {"BitTorrent / P2P": 90}},
        {"ip": "10.0.0.9", "router": "", "riesgo": 50, "banda": "MEDIO", "cats_top": {"Fuerza bruta": 30}},
        {"ip": "10.0.0.10", "router": "", "riesgo": 45, "banda": "MEDIO", "cats_top": {"Spam": 30}},
        # (nuevos, §3 y §10.4) uno de otro punto y uno con evidencia vieja
        {"ip": "10.0.0.12", "router": "p002", "riesgo": 90, "banda": "ALTO", "cats_top": {"Botnet CnC": 20}},
        {"ip": "10.0.0.11", "router": "", "riesgo": 88, "banda": "ALTO", "cats_top": {"Botnet CnC": 20}},
        # (nuevo, 2026-10-15, auditoria A-12) en «Nunca bloquear» de ESTE punto: no se manda
        # aunque la politica de botnet diga cortar
        {"ip": "10.0.0.13", "router": "", "riesgo": 92, "banda": "ALTO", "cats_top": {"Botnet CnC": 20}},
        # ... y en «Nunca bloquear» solo de OTRO punto: aqui si se manda
        {"ip": "10.0.0.14", "router": "", "riesgo": 91, "banda": "ALTO", "cats_top": {"Botnet CnC": 20}},
    ]}
    nunca = os.path.join(td, "nunca-bloquear.lst")
    with open(nunca, "w", encoding="utf-8") as f:
        f.write("# prueba\np001|10.0.0.13\np002|10.0.0.14\n")
    os.makedirs(nod.dir_salida("p001"), exist_ok=True)
    with open(nod.salida("cuarentena.json", "p001"), "w", encoding="utf-8") as f:
        json.dump(cq, f)
    m = {"ENABLED": "1", "POL_AUTO": "1", "POL_BOTNET": "alto", "POL_P2P": "nada",
         "POL_FUERZA": "medio", "POL_SPAM": "notificar", "POL_ALTO": "cuarentena"}
    anadidos = []; quitados = []; logs = []
    envs = {"sent": {"p001|10.0.0.99": {"pol": True, "lista": "lista-vieja", "router": "p001"},
                     # (nuevo, §3) uno de OTRO punto que tampoco esta en el Top de p001
                     "p002|10.0.0.98": {"pol": True, "lista": "lista-otro", "router": "p002"}},
            "dns": {}}
    # (adaptada, 2026-10-14) la tanda usa UNA conexion por router (mk_sesion + _mk_add_en /
    # _mk_quitar_en) en vez de mk_add/mk_remove por IP; los dobles hacen lo mismo que antes
    conexiones = []
    @contextlib.contextmanager
    def mk_sesion(router):
        conexiones.append(router["id"]); yield object(), {"LIST": "heredada"}
    def _mk_add_en(s, ip, lista, tt="", comment=""):
        anadidos.append((ip, lista)); return True, ""
    def _mk_quitar_en(s, ip, lista):
        quitados.append((ip, lista)); return True, "1 entrada(s) quitada(s)"
    def cargar_enviados(path):
        return dict(envs["sent"] if path == "SENT" else envs["dns"])
    def guardar_enviados(env, path):
        envs["sent" if path == "SENT" else "dns"] = env
    extra = {"_mk_globales": lambda: m, "nodos": nod, "threading": threading,
             "POL_NOTIF": os.path.join(td, "notif.json"),
             "router_por_id": lambda pid: {"id": pid},
             "cargar_mk_de": lambda r: dict(m, ROUTER_ID=r["id"], USER="u", PASS="p", LIST="heredada"),
             "evidencia_reciente": lambda k, cq=None: (
                 {"ok": False, "detalle": "ultima alerta hace 3 dias"} if k.endswith("|10.0.0.11")
                 else {"ok": True, "detalle": ""}),
             "lista_de_categoria": lambda c: "clientes-" + c, "mk_sesion": mk_sesion,
             "_mk_add_en": _mk_add_en, "_mk_quitar_en": _mk_quitar_en, "sys": sys,
             "bitacora": lambda *a, **k: None,
             "cargar_enviados": cargar_enviados, "guardar_enviados": guardar_enviados,
             "MK_SENT": "SENT", "MK_SENT_DNS": "DNS", "_motivo_bloqueo": lambda k: {},
             "notificar_cuarentena": lambda *a, **k: None,
             "mk_log": lambda accion, ip, quien, det="": logs.append((accion, ip, det)),
             # «Nunca bloquear» REAL (nunca_bloquear y su lectura) sobre un archivo de prueba
             "ipaddress": __import__("ipaddress"), "NUNCA_FILE": nunca}
    ns2 = piezas(BASE + ("aplicar_politicas", "clave_cpe", "ip_de", "rid_de", "_suf_nodo", "mk_listo",
                         "_registrar_enviados", "_ENV_LOCK", "cuarentena_json", "_cargar_cuarentena",
                         # F1 (auditoria A-15): las bajas del registro quedan fechadas
                         "_marcar_quitada", "_QUITADAS_TS",
                         # (adaptada, 2026-10-14) la tanda de una conexion y la pausa de routers caidos
                         "_mk_tanda", "mk_pausa", "_mk_conexion_ok", "_mk_conexion_fallida",
                         "_MK_PAUSA", "_MK_PAUSA_LOCK", "MK_PAUSA_FALLOS", "MK_PAUSA_BASE",
                         "MK_PAUSA_TOPE", "PuntoEnBaja",
                         # (nuevo, 2026-10-15) la lista «Nunca bloquear» por punto, pieza real
                         "nunca_bloquear", "_nunca_listas", "_nunca_entrada", "_NUNCA_CACHE",
                         "cargar_nunca", "_sello", "_SELLO_VISTO", "_SELLO_CADA"),
                 extra)
    ns2["aplicar_politicas"]("p001")
    check("la botnet ALTA va a la lista de SU clase, no a la heredada",
          ("10.0.0.7", "clientes-botnet") in anadidos, anadidos)
    check("la fuerza bruta MEDIA tambien (politica 'medio')", ("10.0.0.9", "clientes-fuerza") in anadidos, anadidos)
    check("el P2P ALTO con politica 'nada' NO se corta", not any(ip == "10.0.0.8" for ip, _l in anadidos), anadidos)
    check("el spam 'notificar' no se corta y deja bitacora",
          not any(ip == "10.0.0.10" for ip, _l in anadidos)
          and any(a == "POLITICA-NOTIFICAR" and ip == "10.0.0.10" and "clase=spam" in d for a, ip, d in logs), logs)
    e7 = envs["sent"].get("p001|10.0.0.7", {})
    check("el registro guarda clase y lista", e7.get("categoria") == "botnet" and e7.get("lista") == "clientes-botnet"
          and e7.get("pol") is True, e7)
    check("el que ya no califica sale de la lista GUARDADA, no de la de hoy",
          ("10.0.0.99", "lista-vieja") in quitados and "p001|10.0.0.99" not in envs["sent"], quitados)
    check("nadie va a la lista heredada", not any(l == "heredada" for _ip, l in anadidos), anadidos)
    # (nuevo, 2026-10-14) altas y bajas de la vuelta van por UNA sola conexion al router del punto
    check("una sola conexion para toda la tanda, al router del punto", conexiones == ["p001"], conexiones)
    # (nuevo, CONTRATO-F2 §3) corre por punto: lo de otro punto ni entra ni sale
    check("un CPE del Top marcado de otro punto no se envia desde este",
          not any(ip == "10.0.0.12" for ip, _l in anadidos), anadidos)
    check("y el registrado por politica en OTRO punto no se libera (no esta en el Top de este)",
          ("10.0.0.98", "lista-otro") not in quitados and "p002|10.0.0.98" in envs["sent"], (quitados, envs))
    check("el registro usa la clave pid|ip y el router del punto",
          e7.get("router") == "p001" and not any("|" not in k for k in envs["sent"]), envs["sent"])
    # (nuevo, CONTRATO-F2 §10.4) con evidencia vieja la accion automatica no se hace
    check("evidencia vieja: no se envia y queda en la bitacora",
          not any(ip == "10.0.0.11" for ip, _l in anadidos)
          and any(a == "POLITICA-EVIDENCIA-VIEJA" and ip == "10.0.0.11" for a, ip, _d in logs), logs)
    # (nuevo, 2026-10-15) «Nunca bloquear» por punto (claves pNNN|IP, auditoria A-12)
    check("en «Nunca bloquear» de este punto: no se manda aunque la politica diga cortar",
          not any(ip == "10.0.0.13" for ip, _l in anadidos) and "p001|10.0.0.13" not in envs["sent"],
          (anadidos, envs["sent"]))
    check("en «Nunca bloquear» solo de OTRO punto: aqui si se manda",
          ("10.0.0.14", "clientes-botnet") in anadidos and "p001|10.0.0.14" in envs["sent"], anadidos)

    # --- barrido rapido: se rige por la politica de botnet ------------------------------
    br = DASH[DASH.index("def barrido_alto_rapido"):]
    br = br[:br.index("\ndef ", 10)]
    check("el barrido rapido mira la politica de botnet, no POL_ALTO",
          'politica_de_clase("botnet", m) not in _POL_UMBRAL' in br and "POL_ALTO" not in br, "")
    check("y ya no exige la lista heredada", 'lst = m.get("LIST", "")' not in br, "")

    # --- formulario y ruta ---------------------------------------------------------------
    ns3 = piezas(BASE + ("_card_politicas",), {"_mk_globales": lambda: {}, "lista_de_categoria": lambda c: "clientes-" + c})
    h = ns3["_card_politicas"]({"POL_ALTO": "cuarentena", "POL_P2P": "nada", "POL_AUTO": "1"})
    check("un select por clase (8)", h.count("<select name='pol_") == 8, h.count("<select name='pol_"))
    check("con la lista de la clase al lado", "clientes-botnet" in h and "clientes-p2p" in h, "")
    check("P2P sale en 'nada' y botnet heredado en 'alto'",
          "<option value='nada' selected>" in h[h.index("pol_p2p"):]
          and "<option value='alto' selected>" in h[h.index("pol_botnet"):h.index("pol_dns")], "")
    check("ya no hay selects por banda", "pol_bajo" not in h and "pol_alto'" not in h and "Riesgo BAJO" not in h, "")
    # (adaptada, CONTRATO-F2 §4) /routers/guardar desaparece: la ruta acaba en la siguiente
    ruta = DASH[DASH.index('if ruta == "/mikrotik":'):]
    ruta = ruta[:ruta.index('\n        if ruta == ', 10)]
    check("la ruta guarda POL_<CLASE> validando contra la lista",
          '_v in POL_CLASE_VALORES' in ruta and 'm["POL_" + _cat.upper()] = _v' in ruta
          and 'm["POL_ALTO"] =' not in ruta, "")
    check("la documentacion explica el por que",
          "políticas por clase de abuso" in DASH and "el riesgo mide <i>cuánto</i>, no <i>qué</i>" in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada (CONTRATO-F2 §1, §3, §4, §10.4): aplicar_politicas(pid) por punto con claves pid|ip reales, cuarentena.json del punto y mk_listo del router del punto; subcasos nuevos de otro punto y de evidencia vieja. Politicas por clase de abuso: que hacer depende de QUE hace el CPE, no solo de cuanto puntua."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
