"""La cabecera del script del MikroTik sale como «Recomendaciones antes de pegar», plegada.

El user (2026-10-16), viendo en la ficha los comentarios del script («# ids-maat p001 (nodo1) · N=1 ·
puerto 1194…», «# El bloque v6 solo conecta tras…», «# Antes de pegar: el reloj…») dentro de un bloque
de código: «esto debe estar como recomendaciones como desplegable». Texto de cabecera del contrato
(CONTRATO-F1a §5.12), datos RFC 5737 / 100.64.
"""
import os
import sys
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
from fixtures.panel2._dash_p import PanelP  # noqa: E402

SCRIPT = (
    "# ids-maat p003 (norte) · N=3 · puerto 1196 · túnel 100.64.3.0/24 · declarado RouterOS v7\n"
    "# El bloque v6 solo conecta tras: ids-orq punto ajustar p003 --ros 6\n"
    "# Antes de pegar: el reloj del router en hora (/system ntp client). El certificado del\n"
    "# servidor vale desde 2 días antes de emitirse; con el reloj más atrasado, el MikroTik lo rechaza.\n"
    "# AVISO: el certificado del servidor de este punto no lleva el nombre del VPS\n"
    "#\n"
    "# --- RouterOS v7 ---\n"
    "/interface ovpn-client add name=ids-vpn connect-to=vps.example.net port=1196\n"
    "#\n"
    "# --- RouterOS v6 (6.49 o superior) ---\n"
    "/interface ovpn-client add name=ids-vpn connect-to=vps.example.net port=1196\n")


class Recomendaciones(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = PanelP()
        cls.h = cls.p.pw.comandos_html(SCRIPT, 7, "op")

    @classmethod
    def tearDownClass(cls):
        cls.p.cerrar()

    def test_plegadas_y_fuera_del_bloque_de_codigo(self):
        """Corrección de defecto: la cabecera ya no va en un <pre> sino en un desplegable cerrado."""
        self.assertIn("<details class=precom><summary>Recomendaciones antes de pegar</summary>", self.h)
        self.assertNotIn("<pre class=cmd># ids-maat", self.h)
        self.assertNotIn("<details class=precom open", self.h)

    def test_una_frase_por_punto(self):
        """Capacidad nueva: cada frase es un punto; la que el orquestador corta en dos líneas sale entera."""
        self.assertIn("<li>ids-maat p003 (norte) · N=3 · puerto 1196 · túnel 100.64.3.0/24 · declarado "
                      "RouterOS v7</li>", self.h)
        self.assertIn("<li>El bloque v6 solo conecta tras: ids-orq punto ajustar p003 --ros 6</li>", self.h)
        self.assertIn("<li>Antes de pegar: el reloj del router en hora (/system ntp client). El certificado "
                      "del servidor vale desde 2 días antes de emitirse; con el reloj más atrasado, el "
                      "MikroTik lo rechaza.</li>", self.h)

    def test_el_aviso_sigue_arriba_y_no_se_repite(self):
        """Conservación: el «# AVISO:» sigue en rojo arriba y no se repite dentro de las recomendaciones."""
        self.assertIn("Aviso del servidor sobre este script:", self.h)
        self.assertEqual(self.h.count("no lleva el nombre del VPS"), 1)

    def test_antes_de_los_botones_de_copiar(self):
        """Conservación: los botones de copiar siguen antes que los bloques plegados de RouterOS."""
        self.assertLess(self.h.index("<details class=precom>"), self.h.index("<div class=pcopias>"))
        self.assertLess(self.h.index("<div class=pcopias>"), self.h.index("<details class=pver>"))

    def test_sin_cabecera_no_sale_nada(self):
        """Conservación: un script sin comentarios de cabecera no deja un desplegable vacío."""
        h = self.p.pw.comandos_html(SCRIPT.split("#\n", 1)[1], 7, "op")
        self.assertNotIn("precom", h)


if __name__ == "__main__":
    unittest.main()
