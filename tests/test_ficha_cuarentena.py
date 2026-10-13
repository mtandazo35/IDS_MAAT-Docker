"""Ficha de evidencia y tabla de Cuarentena: lectura (el user, 2026-10-12).

Tipo de cada prueba en su docstring. Datos: 10.0.0.0/24 en los dos puntos, destinos RFC 5737.
"""
import os
import re
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures.panel2._dash_p import PanelP  # noqa: E402

IP = "10.0.0.5"


class Ficha(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        c = PanelP.candidato(IP, "p001", confianza="sospechoso")
        c["pruebas"] = [{"sid": "2000001", "sig": "ET MALWARE prueba", "dst": "203.0.113.9", "dport": 443,
                         "ts": int(time.time()) - 120 + i} for i in range(3)]
        self.p.cuarentena("p001", [c])
        self.ana = self.p.entrar("ana")

    def ficha(self):
        r = self.p.pedir("GET", "/cuarentena/ficha?embed=1&nodo=p001&ip=p001%7C" + IP, cookie=self.ana)
        self.assertEqual(r.status, 200, r.texto[:300])
        return r.texto

    def test_cliente_con_ip_y_nodo_sin_clave_interna(self):
        """Correccion de defecto: «Cliente» decia «p001|10.0.0.5»; ahora la IP y su nodo."""
        f = self.ficha()
        cli = re.search(r"<tr><th>Cliente</th><td>(.*?)</td></tr>", f, re.S).group(1)
        self.assertIn(IP + " &middot; norte", cli)
        self.assertIn("(p001)", cli)
        self.assertNotIn("p001|", cli)

    def test_cabecera_riesgo_y_etiqueta_con_estilo(self):
        """Correccion de defecto: la etiqueta de nodo salia pegada a la IP («10.0.0.5norte») porque
        su estilo venia con el menu y el modal no lo tiene; el riesgo lleva su escala y banda."""
        f = self.ficha()
        self.assertIn(".nodochip{", f)
        self.assertIn("Riesgo 80/100 &middot; alto", f)

    def test_decision_arriba_resumen_y_una_fila_de_reputacion(self):
        """Capacidad nueva: la decision va en una caja antes de la tabla, hay franja de resumen y
        Coincidencia + Vigencia son una sola fila «Reputacion del destino»."""
        f = self.ficha()
        self.assertLess(f.index("class='fdec vig'"), f.index("<table class=ficha>"))
        self.assertIn("<div class=fkl>Alertas</div><div class=fkv>5</div>", f)
        self.assertIn("<div class=fkl>Ultima alerta</div>", f)
        self.assertIn("<th>Reputacion del destino</th>", f)
        self.assertNotIn("<th>Coincidencia</th>", f)
        self.assertNotIn("<th>Vigencia</th>", f)
        self.assertNotIn("<th>Decision</th>", f)

    def test_sin_rev_no_sale_guion_y_veces_centrado(self):
        """Correccion de defecto: sin revision no sale «rev -»; «Veces» centrado bajo su titulo."""
        f = self.ficha()
        self.assertIn("SID 2000001</div>", f)
        self.assertNotIn("rev -", f)
        self.assertIn(".fichat th.num,.fichat td.num{text-align:center}", f)


class Tabla(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        c = PanelP.candidato
        self.p.cuarentena("_todos", [c(IP, "p001"), c(IP, "p002")])
        self.ana = self.p.entrar("ana")

    def test_columna_router_y_centrados(self):
        """Capacidad nueva: el router va en su columna al lado del CPE; Riesgo y Accion centrados;
        el modal se ajusta al alto de la ficha."""
        h = self.p.pedir("GET", "/cuarentena?nodo=_todos", cookie=self.ana).texto
        self.assertIn("<th>CPE (IP origen)</th><th>Router</th><th class='cen'>Riesgo / confianza</th>", h)
        self.assertIn("<th class='cen'>Accion</th>", h)
        routers = re.findall(r"<td data-label='Router'><span class=rnom>([^<]+)</span>", h)
        self.assertEqual(sorted(routers), ["norte", "sur"])
        # guardado: el iframe vacio dispara onload antes de que exista fichaAlto (error JS)
        self.assertIn("onload='window.fichaAlto&&fichaAlto(this)'", h)


if __name__ == "__main__":
    unittest.main()
