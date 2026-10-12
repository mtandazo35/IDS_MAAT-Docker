# -*- coding: utf-8 -*-
"""Identidad (router, IP): dos nodos con el MISMO rango no se confunden.

Es el motivo de todo el multi-nodo. Con 3 MikroTik usando 10.0.0.x cada uno,
"10.0.0.5" no identifica a nadie: hay tres clientes distintos. Si se mezclaran,
se sumarian sus alertas, se culparia al abonado equivocado y el bloqueo podria
acabar en el router que no es.

ADAPTADA (CONTRATO-F2 §1 y §3): en IDS_MAAT-Docker un nodo es un punto (pid) del
orquestador y el router de cada evento es el pid del directorio de donde sale el fichero,
no `in_iface` con un mapa de routers (ROUTERS_MAP/router_de ya no existen). Cambio
deliberado: la identidad es SIEMPRE `pid|ip`, tambien con un solo punto (antes, con un solo
router, era la IP pelada). Se ejecutan las piezas REALES de html_report.py con el nodos.py real.
"""
import ast
import html
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402

REP = extraer.fuente("HREP")
ARBOL = ast.parse(REP)

PIEZAS = ("MULTI_ROUTER", "nombre_router", "clave_cpe", "_chip_nodo", "ip_de", "rid_de")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def cargar(puntos, nodo):
    """Monta las funciones de identidad del generador para el nodo dado (pid o TODOS)."""
    tmp = tempfile.mkdtemp()
    nodos = _comun.cargar_nodos(tmp, puntos)
    ns = {"nodos": nodos, "NODO": nodos.TODOS if nodo is None else nodo, "esc": html.escape}
    for n in ARBOL.body:
        nombre = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nombre in PIEZAS:
            exec(ast.get_source_segment(REP, n), ns)
    return ns


def main():
    tres = {"p001": {"nombre": "Nodo Centro"}, "p002": {"nombre": "Nodo Norte"},
            "p003": {"nombre": "Nodo Sur"}}
    # --- tres nodos, vista acumulada (--todos) ---
    ns = cargar(tres, None)
    check("en la vista acumulada hay varios MikroTik", ns["MULTI_ROUTER"] is True)
    check("muestra el nombre legible del nodo", ns["nombre_router"]("p002") == "Nodo Norte")
    check("y la etiqueta de nodo sale en la vista acumulada",
          "Nodo Norte" in ns["_chip_nodo"](ns["clave_cpe"]("10.0.0.5", "p002")))

    # --- EL caso: la misma IP en dos nodos distintos ---
    a = ns["clave_cpe"]("10.0.0.5", "p001")
    b = ns["clave_cpe"]("10.0.0.5", "p002")
    check("la MISMA IP en dos nodos son dos clientes distintos", a != b, (a, b))
    check("y de cada uno se recupera su IP para bloquear",
          (ns["ip_de"](a), ns["ip_de"](b)) == ("10.0.0.5", "10.0.0.5"), (a, b))
    check("y a que router hay que mandar cada bloqueo",
          (ns["rid_de"](a), ns["rid_de"](b)) == ("p001", "p002"), (a, b))

    # si se usaran como claves de un contador, no se sumarian entre si
    cont = {}
    for k in (a, a, b):
        cont[k] = cont.get(k, 0) + 1
    check("sus alertas NO se suman entre nodos", sorted(cont.values()) == [1, 2], cont)

    # --- el informe de UN punto (--nodo p001) ---
    uno = cargar(tres, "p001")
    check("el informe de un punto no es multi-nodo (sin chips: serian ruido)",
          uno["MULTI_ROUTER"] is False and uno["_chip_nodo"](uno["clave_cpe"]("10.0.0.5", "p001")) == "")
    k = uno["clave_cpe"]("10.0.0.5", "p001")
    # cambio deliberado (CONTRATO-F2 §1): antes, con un solo router, la identidad era la IP pelada
    check("la identidad es SIEMPRE pid|ip, tambien con un solo punto", k == "p001|10.0.0.5", k)
    check("y ip_de devuelve la IP", uno["ip_de"](k) == "10.0.0.5")
    check("y rid_de el punto", uno["rid_de"](k) == "p001")

    # --- un punto sin nombre en estado.json ---
    sin = cargar({"p004": {}}, "p004")
    check("sin nombre publicado se usa el pid, sin reventar", sin["nombre_router"]("p004") == "p004")
    try:
        sin["clave_cpe"]("10.0.0.5", "r1")
        mala = None
    except ValueError as e:
        mala = e
    check("un id de router que no es un pid se rechaza (no se inventa identidad)",
          mala is not None, mala)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion + correccion de defecto (identidad pid|ip siempre). Identidad (router, IP): dos nodos con el MISMO rango no se confunden."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
