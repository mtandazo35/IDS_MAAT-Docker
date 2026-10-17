"""«Nunca bloquear» vive en la página Exclusiones, como apartado propio.

El user (2026-10-16), viendo el campo en Ajustes → MikroTik: «esto lo veo redundante porque lo veo en
exclusiones». No es lo mismo (Exclusiones = no se ve; Nunca bloquear = se ve pero nunca se corta), así
que va junto a Exclusiones con la diferencia escrita, y sale de Ajustes. Mismo archivo
(conf/nunca-bloquear.lst) y mismo efecto. Datos RFC 5737 / 10.x.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures.panel2._dash_p import PanelP  # noqa: E402


class NuncaEnExclusiones(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")
        self.luis = self.p.entrar("luis")
        self.d = self.p.d

    def test_apartado_en_exclusiones_con_la_lista(self):
        """Capacidad nueva: Exclusiones lleva el apartado «Nunca bloquear» con lo guardado y la diferencia."""
        self.d.guardar_nunca("192.0.2.10\np001|10.0.0.5\n")
        h = self.p.pedir("GET", "/exclusiones", cookie=self.ana).texto
        self.assertIn("<h2 id=nunca style='margin-top:30px'>Nunca bloquear</h2>", h)
        self.assertIn("No es lo mismo que una exclusión", h)
        self.assertRegex(h, r"<textarea name=nunca[^>]*>192\.0\.2\.10\np001\|10\.0\.0\.5\n</textarea>")
        self.assertIn('<a href="#nunca">Nunca bloquear</a>', h)
        # el user: «debes poner una descripción ya que es algo medio confuso»: arriba, cuál usar
        self.assertIn("<b>¿Cuál uso?</b>", h)
        self.assertLess(h.index("¿Cuál uso?"), h.index("Exclusiones activas"))
        self.assertIn("la IP <b>no se ve</b>", h)
        self.assertIn("la IP <b>se sigue viendo</b>", h)

    def test_guardar_desde_exclusiones(self):
        """Capacidad nueva: se guarda desde Exclusiones y dice cuántas entradas y cuántas descartó."""
        r = self.p.pedir("POST", "/exclusiones", {"accion": "nunca", "nunca": "192.0.2.10\n198.51.100.0/24\n"},
                         cookie=self.ana)
        self.assertEqual(r.status, 200)
        self.assertIn("guardado: 2 entrada(s)", r.texto)
        self.assertEqual(self.d.cargar_nunca(), "192.0.2.10\n198.51.100.0/24\n")
        self.assertTrue(self.d.nunca_bloquear("192.0.2.10"))
        r = self.p.pedir("POST", "/exclusiones", {"accion": "nunca", "nunca": "192.0.2.10\nno-es-ip\n"},
                         cookie=self.ana)
        self.assertIn("1 línea(s) descartada(s)", r.texto)
        self.assertEqual(self.d.cargar_nunca(), "192.0.2.10\n")

    def test_lectura_no_lo_cambia(self):
        """Conservación: como el resto de Exclusiones, solo el admin lo cambia."""
        self.d.guardar_nunca("192.0.2.10\n")
        r = self.p.pedir("POST", "/exclusiones", {"accion": "nunca", "nunca": ""}, cookie=self.luis)
        self.assertNotEqual(r.status, 200)
        self.assertEqual(self.d.cargar_nunca(), "192.0.2.10\n")

class AjustesMikrotik(unittest.TestCase):
    """La tarjeta MikroTik de Ajustes (montaje de test_ajustes_mikrotik: ahí sale la tarjeta)."""
    def setUp(self):
        from test_f1_cuarentena import Panel
        self.p = Panel(http=True)
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d

    def tarjeta(self):
        st, _c, h = self.p.pedir("GET", "/ajustes")
        self.assertEqual(st, 200)
        ini = h.index("MikroTik &mdash; cuarentena")
        return h[ini:h.index("</section>", ini)]

    def test_ajustes_ya_no_lo_tiene_y_enlaza(self):
        """Corrección de defecto: Ajustes → MikroTik ya no tiene el campo; deja un enlace a Exclusiones."""
        card = self.tarjeta()
        self.assertNotIn("name=nunca", card)
        # el panel añade el nodo que se mira a los enlaces internos (?nodo=…): el ancla #nunca sigue al final
        self.assertRegex(card, r"<a href='/exclusiones(\?nodo=[^'#]*)?#nunca'>Exclusiones &rarr; Nunca bloquear</a>")

    def test_guardar_ajustes_no_borra_la_lista(self):
        """Corrección de defecto evitado: guardar Ajustes → MikroTik sin el campo no vacía la lista
        (antes se guardaba siempre lo que llegara, y sin el campo llegaba vacío)."""
        self.d.guardar_nunca("192.0.2.10\n")
        st, _c, txt = self.p.pedir("POST", "/mikrotik", {"doble": "1"})
        self.assertEqual(st, 200)
        self.assertIn("Ajustes de MikroTik guardados", txt)
        self.assertEqual(self.d.cargar_nunca(), "192.0.2.10\n")


if __name__ == "__main__":
    unittest.main()
