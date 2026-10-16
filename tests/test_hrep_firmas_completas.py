"""html_report.py: «Firmas más frecuentes» con el nombre entero (el user, 2026-10-15).

Tipo: corrección de defecto; cada prueba falla sin su arreglo.
- La regla propia de los feeds (sid 9000050) salía «LOCAL DNS a dominio ficha…»: el _TRAD de
  html_report no tenía su línea (solo la de dashboard) y la columna de nombres cortaba a ~26
  caracteres. Sale «DNS a dominio fichado en feeds de reputación», fila propia y en dos líneas.
- Las dos tablas _TRAD son la misma: que se separaran es lo que dejó la regla sin traducir en
  el informe cuando el panel ya la traducía.
- El cats_top que el informe deja en cuarentena.json lleva el nombre que CAT_CPE busca: si no,
  el abonado que solo tiene esa alerta cae en «Otros» en Cuarentena.
Reusa el entorno de test_hrep_nodos (generador como subproceso, sin red). Datos RFC 5737 / 10.x.
"""
import ast
import html
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_hrep_nodos import LIB, Entorno, alerta  # noqa: E402
from test_hrep_atacantes_puerto import tarjeta  # noqa: E402

FEEDS = "LOCAL DNS a dominio fichado en feeds de reputacion"
FEEDS_ES = "DNS a dominio fichado en feeds de reputación"
TITULO = "Firmas más frecuentes (tipo de ataque)"


def tabla(fichero):
    """La lista _TRAD de ese módulo, leída con ast (sin importarlo)."""
    with open(os.path.join(LIB, fichero), encoding="utf-8") as f:
        arbol = ast.parse(f.read())
    for n in arbol.body:
        if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "_TRAD" for t in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError("sin _TRAD en " + fichero)


def etiquetas(t):
    """Las etiquetas de la gráfica, cada una como la lista de sus líneas."""
    out = []
    for m in re.finditer(r'<text [^>]*class="lbl">(.*?)</text>', t, re.S):
        partes = re.split(r"<tspan [^>]*>", m.group(1).replace("</tspan>", ""))
        out.append([html.unescape(x) for x in partes])
    return out


class Tablas(unittest.TestCase):
    def test_las_dos_tablas_son_la_misma(self):
        self.assertEqual(tabla("html_report.py"), tabla("dashboard.py"))
        self.assertIn((("dominio fichado",), FEEDS_ES), tabla("html_report.py"))


class FirmasCompletas(Entorno):
    def test_la_regla_de_los_feeds_sale_entera_y_aparte(self):
        self.eventos("p001", "eve.json",
                     [alerta("10.0.0.5", "192.0.2.53", sig=FEEDS, sid=9000050, dport=53,
                             hace_s=60 + i, flow_id=100 + i) for i in range(5)]
                     + [alerta("10.0.0.6", "192.0.2.10", dport=23, flow_id=200 + i) for i in range(2)])
        self.ok("60", "--nodo", "p001")
        t = tarjeta(self.html("p001"), TITULO)
        filas = etiquetas(t)
        self.assertEqual(filas[0], ["DNS a dominio fichado en", "feeds de reputación"], filas)
        self.assertIn(["Botnet CnC"], filas)
        self.assertNotIn("…", t)
        self.assertNotIn("LOCAL DNS", t)
        # la segunda línea empieza donde las demás etiquetas (alineadas a la izquierda)
        self.assertEqual(set(re.findall(r'<tspan x="([\d.]+)"', t)), {"2"})
        # y el abonado sigue siendo de «DNS de malware»: CAT_CPE busca este mismo nombre
        cuar = self.salida("p001", "cuarentena.json")
        cats = [c["cats_top"] for c in cuar["top_riesgo"] if c["ip"] == "10.0.0.5"]
        self.assertEqual(cats, [{FEEDS_ES: 5}], cuar["top_riesgo"])

    def test_lo_que_no_cabe_en_dos_lineas_lleva_el_nombre_entero_al_pasar_el_raton(self):
        largo = "LOCAL " + "x" * 38
        self.eventos("p001", "eve.json",
                     [alerta("10.0.0.5", "192.0.2.10", sig=largo, sid=9000999, dport=80,
                             cat="Misc activity", flow_id=300 + i) for i in range(2)])
        self.ok("60", "--nodo", "p001")
        t = tarjeta(self.html("p001"), TITULO)
        filas = etiquetas(t)
        self.assertEqual(len(filas), 1, filas)
        self.assertEqual(filas[0][0], "LOCAL")
        self.assertTrue(filas[0][1].endswith("…"), filas)
        self.assertIn("<title>%s</title>" % largo, t)


if __name__ == "__main__":
    unittest.main()
