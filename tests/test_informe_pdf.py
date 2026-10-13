"""Informe PDF del Reporte: que clientes hay en cada categoria y cuando cayeron en ella.

Tipo: capacidad nueva (el user, 2026-10-13): «Generar reporte» solo mandaba a imprimir la pagina;
ahora el panel genera un PDF de verdad (informe_pdf.py, reportlab) para el nodo que se mira o
«Todos», con periodo elegible. Se comprueba el documento (sin comprimir, para leer su texto), los
datos que lo alimentan (dashboard.informe_datos) y la ruta /informe.pdf. Datos RFC 5737 / 10.x.
"""
import json
import os
import re
import sys
import tempfile
import time
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, "fixtures", "panel2"))
import _dash  # noqa: E402

sys.path.insert(0, _dash.LIB)
import informe_pdf  # noqa: E402  (exige reportlab: obligatoria en tests/obligatorias.txt)

from test_reporte_ruido import INFECTADO, LIMPIO, lineas  # noqa: E402


def texto(pdf):
    """Lo que se lee del PDF sin comprimir: las cadenas de los operadores de texto."""
    crudo = pdf.decode("latin-1")
    return " ".join(re.findall(r"\(((?:[^()\\]|\\.)*)\)\s*Tj", crudo))


class Documento(unittest.TestCase):
    def datos(self):
        ahora = time.time()
        return {"empresa": "ISP Ejemplo", "nodo": "Todos los nodos", "desde": ahora - 3 * 86400,
                "hasta": ahora, "dias": 3, "generado": ahora, "usuario": "ana", "zona": None,
                "totales": {"abonados": 1, "alertas": 5, "cortar": 1},
                "categorias": [
                    {"clave": "botnet", "nombre": "Botnet / CnC", "gravedad": "Critico",
                     "color": "#d03b3b", "que_es": "Infectado.", "que_hacer": "Aislar.",
                     "abonados": [{"ip": "10.0.0.21", "cliente": "Cliente Uno", "nodo": "Nodo Norte",
                                   "desde": ahora - 3600, "hasta": ahora - 60, "aprox": False,
                                   "alertas": 5, "dias": 1, "repetido": "Botnet Mirai",
                                   "firmas": [["Botnet Mirai", "ET MALWARE Mirai Botnet CnC Checkin", 5,
                                               ahora - 3600, ahora - 60, False]],
                                   "destinos": [["192.0.2.50", 5]], "puertos": [["8080", 5]],
                                   "malos": []}]},
                    {"clave": "spam", "nombre": "Spam", "gravedad": "Grave", "color": "#ec835a",
                     "que_es": "", "que_hacer": "", "abonados": []}],
                "metodologia": ["Se descarta el ruido informativo."]}

    def test_es_un_pdf_con_quien_y_cuando(self):
        d = self.datos()
        pdf = informe_pdf.generar(d, comprimir=False)
        self.assertTrue(pdf.startswith(b"%PDF-"))
        t = texto(pdf)
        for esperado in ("Informe de seguridad", "ISP Ejemplo", "Botnet / CnC", "10.0.0.21",
                         "Cliente Uno", "Nodo Norte", "ET MALWARE Mirai Botnet CnC Checkin",
                         informe_pdf.fecha(d["categorias"][0]["abonados"][0]["desde"])):
            self.assertIn(esperado, t)

    def test_una_categoria_sin_abonados_no_sale(self):
        t = texto(informe_pdf.generar(self.datos(), comprimir=False))
        self.assertNotIn("Spam", t)                  # sin abonados: ni seccion ni fila del resumen

    def test_fecha_aproximada_dice_el_dia_y_lo_marca(self):
        d = self.datos()
        a = d["categorias"][0]["abonados"][0]
        a["aprox"] = True
        a["firmas"][0][5] = True
        t = texto(informe_pdf.generar(d, comprimir=False))
        self.assertIn(informe_pdf.fecha(a["desde"], con_hora=False) + " \\(aprox.\\)", t)

    def test_sin_abonados_lo_dice(self):
        d = self.datos()
        d["categorias"][0]["abonados"] = []
        t = texto(informe_pdf.generar(d, comprimir=False))
        self.assertIn("alertas reales en el per", t)


class Datos(unittest.TestCase):
    """informe_datos con los mismos casos que test_reporte_ruido: limpio, infectado, navega."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = _dash.Arbol(self.tmp.name, puntos={"p001": _dash.punto("norte", 1)})
        self.a.eve("p001", lineas())
        self.d = _dash.cargar(self.a)
        self.n = self.d.nodos
        self.n.asegurar_dirs()
        with open(os.path.join(self.a.panel, "estado", "abonados.json"), "w", encoding="utf-8") as f:
            json.dump({"ts": int(time.time()), "mapa": {"p001|" + INFECTADO: {"nombre": "Cliente Uno",
                                                                              "tipo": "PPPoE"}}}, f)

    def tearDown(self):
        self.n.quitar_nodo()
        _dash.restaurar()
        self.tmp.cleanup()

    def test_quien_esta_en_cada_categoria_y_desde_cuando(self):
        with self.n.contexto("p001"):
            self.d.hist_ingerir()
            d = self.d.informe_datos(3, "ana")
        cats = {c["clave"]: c for c in d["categorias"]}
        botnet = cats["botnet"]["abonados"]
        self.assertEqual([a["ip"] for a in botnet], [INFECTADO])
        a = botnet[0]
        self.assertEqual(a["cliente"], "Cliente Uno")
        self.assertFalse(a["aprox"])
        self.assertAlmostEqual(a["desde"], time.time() - 64, delta=5)
        self.assertEqual(a["alertas"], 5)
        self.assertTrue(all(not f[1].startswith("ET INFO") for f in a["firmas"]))
        # el limpio no esta en ninguna categoria
        self.assertNotIn(LIMPIO, [x["ip"] for c in d["categorias"] for x in c["abonados"]])
        self.assertEqual(d["totales"], {"abonados": 1, "alertas": 5, "cortar": 1})
        self.assertEqual((d["dias"], d["usuario"]), (3, "ana"))

    def test_periodo_fuera_de_lo_permitido_vuelve_al_de_defecto(self):
        with self.n.contexto("p001"):
            self.assertEqual(self.d.informe_datos(999)["dias"], self.d.CONDUCTA_DIAS)


class Ruta(unittest.TestCase):
    def setUp(self):
        from fixtures.panel2._dash_p import PanelP
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")
        # un Reporte ya generado: sin el, la pagina dice «generando» y no pinta la barra
        fila = {"ip": "10.0.0.21", "nodo": "p001", "alertas": 5, "eventos": 5, "bytes": 0, "dias": 1,
                "primera": int(time.time()) - 3600, "ultima": int(time.time()), "destinos": [],
                "puertos": [], "firmas": [["ET MALWARE Mirai Botnet CnC Checkin", 5]], "dominios": [],
                "malos": [], "destinos_n": 0, "puertos_n": 0}
        with self.p.d.nodos.contexto("p001"):
            self.p.d.guardar_conducta({"generado": int(time.time()), "dias": 3, "lineas": 5,
                                       "cpes": 1, "filas": [fila]})

    def test_descarga_el_pdf(self):
        r = self.p.pedir("GET", "/informe.pdf?nodo=_todos&dias=7", cookie=self.ana)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.cab("Content-Type"), "application/pdf")
        self.assertRegex(r.cab("Content-Disposition"), r"attachment; filename=informe-todos-7d-\d{8}-\d{4}\.pdf")
        self.assertTrue(r.texto.startswith("%PDF-"))           # el fixture decodifica: la firma es ASCII
        self.assertEqual(r.cab("Cache-Control"), "no-store")

    def test_el_boton_pide_el_pdf_con_periodo_y_ya_no_imprime(self):
        h = self.p.pedir("GET", "/conducta?nodo=p001", cookie=self.ana).texto
        self.assertIn("action='/informe.pdf'", h)
        self.assertEqual(re.findall(r"<option value=(\d+)", h.split("action='/informe.pdf'")[1])[:4],
                         ["1", "3", "7", "30"])
        self.assertNotIn("cdPdf", h)                         # ya no se manda a imprimir la pagina


class Traduccion(unittest.TestCase):
    def test_un_minero_no_es_botnet(self):
        """Correccion de defecto: «ET POLICY Cryptocurrency Miner Checkin» (firma real de ET
        Open) salia «Botnet CnC» porque «checkin» se miraba antes que «miner»; en el panel y en
        el generador (dos copias de la tabla)."""
        import ast
        for fichero in ("dashboard.py", "html_report.py"):
            fuente = open(os.path.join(_dash.LIB, fichero), encoding="utf-8").read()
            ns = {}
            for n in ast.parse(fuente).body:
                nom = getattr(n, "name", None) or (getattr(n.targets[0], "id", "")
                                                   if isinstance(n, ast.Assign) else "")
                if nom in ("_TRAD", "_TRAD_CACHE", "_TRAD_CACHE_MAX", "_traducir_lento", "traducir"):
                    exec(ast.get_source_segment(fuente, n), ns)
            with self.subTest(fichero=fichero):
                self.assertEqual(ns["traducir"]("ET POLICY Cryptocurrency Miner Checkin"), "Criptomineria")
                self.assertEqual(ns["traducir"]("ET MALWARE Win32/Emotet CnC Activity (POST)"), "Botnet CnC")
                self.assertEqual(ns["traducir"]("ET MALWARE Mirai Botnet CnC Checkin"), "Botnet Mirai")


if __name__ == "__main__":
    unittest.main()
