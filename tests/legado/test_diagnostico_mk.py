# -*- coding: utf-8 -*-
"""Diagnostico del MikroTik: que le falta para poder cortar.

Con un espejo TZSP, Suricata NUNCA bloquea: ve una copia y el paquete ya paso. El que
corta es el router, asi que lo que importa es si el router esta en condiciones. Lo que
se protege aqui es que el diagnostico no mienta: el fallo mas caro es decir "todo bien"
cuando la address-list no la usa ninguna regla, porque entonces el panel dice "enviado"
y el abonado sigue atacando.

Adaptada al panel portado (CONTRATO-F2 §3, §4; OPERACION §2): el diagnostico es SIEMPRE de
un router dado (un punto, `_router_destino` real: sin router no hay "el de por defecto"); el
espejo ya no es `/tool sniffer` sino las dos reglas mangle `sniff-tzsp` hacia el sensor del
punto (`punto.sensor`/`tzsp_puerto` de estado.json, `sensor_del_punto` real con `nodos.py`
real), asi que el router "bien montado" lleva esas dos reglas en vez del sniffer.
"""
import ast
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ

DASH = extraer.fuente("DASH")
ARBOL = ast.parse(DASH)
TMP = tempfile.TemporaryDirectory()

# + _router_destino y sensor_del_punto REALES (CONTRATO-F2 §3/§4)
# + _mk_reglas_usan_lista (2026-10-14): la comprobacion de «la lista corta» en las cuatro tablas
PIEZAS = ("_mk_print", "mk_diagnostico", "ros_lista", "_RE_ROS_RARO", "ACCIONES", "CAT_CPE", "CAT_OTROS",
          "_router_destino", "sensor_del_punto", "_mk_reglas_usan_lista")
R1 = {"id": "p001"}     # el router del punto p001 (sensor 100.64.1.1, TZSP 37008 en _comun.PUNTOS)
# el espejo del punto (OPERACION §2): dos reglas mangle sniff-tzsp (ida y vuelta) hacia su sensor
ESPEJO_P001 = [{"action": "sniff-tzsp", "sniff-target": "100.64.1.1", "sniff-target-port": "37008",
                "comment": "IDS ids-maat:p001 ida"},
               {"action": "sniff-tzsp", "sniff-target": "100.64.1.1", "sniff-target-port": "37008",
                "comment": "IDS ids-maat:p001 vuelta"}]

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tablas, listas=None):
    """mk_diagnostico contra un router de mentira que devuelve las tablas dadas."""
    _l = listas or {"LIST": "suricata-cuarentena", "LIST_GRAD": "suricata-graduada"}
    nod, _sec = _comun.panel(TMP.name)
    ns = {"ipaddress": __import__("ipaddress"), "re": __import__("re"), "nodos": nod,
          # como el real: los datos del router llevan su ROUTER_ID (= pid)
          "cargar_mk_de": lambda r: dict(_l, ROUTER_ID=r.get("id", "")),
          "cargar_mk": lambda: dict(_l),
          "mk_conectar": lambda d: type("S", (), {"close": lambda self: None})(),
          "_mk_send": lambda s, w: None,
          "_mk_reply": lambda s: (True, [], ""),
          # la IP del sensor ya no se adivina (ip_del_sensor): es punto.sensor de estado.json,
          # que da sensor_del_punto REAL (CONTRATO-F2 §4; antes un doble con 10.0.0.9)
          # sin nadie enviado, no hay listas de categoria que vigilar: aqui se prueba
          # el diagnostico base, y que con listas en uso tambien las mire va en
          # tests/test_listas_categoria.py
          "listas_en_uso": lambda *a: [],      # auditoria A-18: recibe los puntos del router
          # la accion por clase: por defecto ninguna configurada (se prueba aparte abajo)
          "_mk_globales": lambda: {},
          "accion_de_clase": lambda cat, m=None: "nada",
          "_plan_en": lambda s_, cat, accion=None, m=None, **k: {"cambios": 0, "acciones": [], "aviso": "", "lista": "l"}}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["_mk_print"] = lambda s_, cmd, props: tablas.get(cmd, [])
    return ns


def estados(checks):
    return {t: e for e, t, _d, _f in checks}


def main():
    # --- router recien montado: le falta todo ---
    ns = entorno({})
    # CONTRATO-F2 §3: sin router de destino no se diagnostica "el de por defecto"
    try:
        ns["mk_diagnostico"](); sin = ""
    except ValueError as ex:
        sin = str(ex)
    check("sin router no hay a quien preguntar (no hay router por defecto)", "sin router" in sin, sin)
    c = ns["mk_diagnostico"](R1)
    txt = " | ".join(t for _e, t, _d, _f in c)
    check("sin espejo se dice lo primero de todo",
          any(e == "falta" and "espejo" in t for e, t, _d, _f in c), txt)
    check("y se avisa de que la lista de cuarentena no corta nada",
          any(e == "falta" and "cuarentena NO corta" in t for e, t, _d, _f in c), txt)
    fix = [f for _e, t, _d, f in c if "cuarentena NO corta" in t][0]
    # (adaptada, 2026-10-14) el arreglo ya no es un drop suelto en filter, que duplicaba la
    # plantilla del panel y quedaba fuera de su gestion: remite a Ajustes -> MikroTik
    check("con el camino para arreglarlo (la plantilla del panel, no un drop suelto)",
          "suricata-cuarentena" in fix and "Ver / aplicar en el router" in fix
          and "action=drop" not in fix, fix)
    # --- una lista con espacios en el nombre -------------------------------------------
    # "Cliente Virus" es un nombre real de un ISP. (adaptada, 2026-10-14) Ya no se propone
    # un comando para pegar, asi que el riesgo de partirlo en el espacio desaparece: basta
    # con que el arreglo nombre la lista entera.
    ns2 = entorno({}, {"LIST": "Cliente Virus", "LIST_GRAD": "suricata-graduada"})
    c2 = ns2["mk_diagnostico"](R1)
    fix2 = [f for _e, t, _d, f in c2 if "cuarentena NO corta" in t][0]
    check("una lista con espacios sale entera en el arreglo",
          "'Cliente Virus'" in fix2, fix2)
    check("y la graduada tambien remite a la plantilla",
          "Ver / aplicar en el router" in
          [f for _e, t, _d, f in c2 if "graduada NO corta" in t][0], "")

    ros = ns2["ros_lista"]
    check("las comillas de dentro se escapan", ros('a"b') == '"a\\"b"', ros('a"b'))
    check("y un nombre vacio no revienta", ros("") == '""' and ros(None) == '""', "")

    check("se avisa del origen falsificado", any("falsificada" in t for _e, t, _d, _f in c), txt)
    check("y de que el router no detecta escaneos",
          any("no detecta escaneos" in t for _e, t, _d, _f in c), txt)

    # --- router bien montado ---
    # espejo = las dos sniff-tzsp del punto hacia SU sensor (OPERACION §2), no /tool sniffer
    ns2 = entorno({
        "/ip/firewall/mangle/print": ESPEJO_P001,
        "/ip/firewall/filter/print": [
            {"chain": "forward", "action": "drop", "src-address-list": "suricata-cuarentena"},
            {"chain": "forward", "action": "drop", "src-address-list": "suricata-graduada"},
            {"chain": "forward", "action": "add-src-to-address-list", "psd": "21,3s,3,1"},
            {"chain": "forward", "action": "drop", "connection-limit": "200,32"},
        ],
        "/ip/firewall/raw/print": [{"action": "drop", "src-address-list": "suricata-cuarentena"}],
        "/ip/settings/print": [{"rp-filter": "strict"}],
    })
    c2 = ns2["mk_diagnostico"](R1)
    check("un router bien montado no tiene ningun 'falta'",
          not [t for e, t, _d, _f in c2 if e == "falta"],
          [t for e, t, _d, _f in c2 if e == "falta"])
    check("se reconoce el espejo activo", any("espejo esta activo" in t for _e, t, _d, _f in c2))
    check("y que detecta escaneos por si solo",
          any("detecta escaneos por si solo" in t for _e, t, _d, _f in c2))
    # CONTRATO-F2 §4: el espejo cuenta si va al sensor de ESTE punto y en los dos sentidos
    for nom_, esp_ in (("hacia el sensor de otro punto", [dict(f, **{"sniff-target": "100.64.2.1"}) for f in ESPEJO_P001]),
                       ("solo en un sentido", ESPEJO_P001[:1]),
                       ("con las reglas desactivadas", [dict(f, disabled="true") for f in ESPEJO_P001])):
        c_e = entorno({"/ip/firewall/mangle/print": esp_})["mk_diagnostico"](R1)
        check("  espejo %s: NO se da por activo" % nom_,
              any(e == "falta" and "espejo" in t for e, t, _d, _f in c_e), [t for _e, t, _d, _f in c_e][:1])

    # --- el fallo mas caro: la regla EXISTE pero esta desactivada ---
    ns3 = entorno({
        "/ip/firewall/filter/print": [
            {"chain": "forward", "action": "drop",
             "src-address-list": "suricata-cuarentena", "disabled": "true"},
        ],
    })
    c3 = ns3["mk_diagnostico"](R1)
    check("una regla DESACTIVADA no cuenta como que corta",
          any(e == "falta" and "cuarentena NO corta" in t for e, t, _d, _f in c3),
          [t for e, t, _d, _f in c3 if "cuarentena" in t])

    # --- cortar en raw tambien vale ---
    ns4 = entorno({
        "/ip/firewall/raw/print": [{"action": "drop", "src-address-list": "suricata-cuarentena"}],
    })
    c4 = ns4["mk_diagnostico"](R1)
    check("cortar en raw cuenta igual que en filter",
          not any("cuarentena NO corta" in t for _e, t, _d, _f in c4),
          [t for e, t, _d, _f in c4 if "cuarentena" in t])

    # --- rp-filter a medias ---
    ns5 = entorno({"/ip/settings/print": [{"rp-filter": "loose"}]})
    c5 = ns5["mk_diagnostico"](R1)
    check("'loose' no se da por bueno", any("falsificada" in t for _e, t, _d, _f in c5))
    det = [d for _e, t, d, _f in c5 if "falsificada" in t][0]
    check("y se avisa de que 'strict' rompe con rutas asimetricas",
          "asimetric" in det.lower(), det[:120])

    # --- la accion configurada por clase: aplicada o le faltan cambios ---
    ns6 = entorno({"/ip/firewall/mangle/print": ESPEJO_P001,
                   "/ip/settings/print": [{"rp-filter": "strict"}]})
    ns6["accion_de_clase"] = lambda cat, m=None: {"botnet": "cortar", "spam": "sin-correo"}.get(cat, "nada")
    ns6["_plan_en"] = lambda s_, cat, accion=None, m=None, **k: (
        {"cambios": 0, "acciones": [1], "aviso": "", "lista": "clientes-botnet"} if cat == "botnet"
        else {"cambios": 3, "acciones": [1, 2, 3], "aviso": "", "lista": "clientes-spam"})
    c6 = ns6["mk_diagnostico"](R1)
    e6 = estados(c6)
    check("la accion aplicada sale en verde", any(k.startswith("Botnet / CnC: 'Cortar todo' aplicada") and v == "ok" for k, v in e6.items()), e6)
    check("la accion sin aplicar sale como falta, con los cambios que le faltan",
          any(k.startswith("Spam: 'Sin correo saliente (25/465/587/2525)' NO esta aplicada (3 cambio(s))") and v == "falta" for k, v in e6.items()), e6)
    check("una clase sin accion no aparece", not any(k.startswith("Escaneo:") for k in e6), e6)
    check("y el arreglo apunta a Ajustes", any("Ver / aplicar en el router" in f for _e, _t, _d, f in c6), "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada (CONTRATO-F2 §3, §4; OPERACION §2): router = punto p001 obligatorio (sin router por defecto), espejo = dos sniff-tzsp hacia punto.sensor en vez de /tool sniffer (sensor_del_punto real). Diagnostico del MikroTik: que le falta para poder cortar."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
