"""Hoja de estilos versionada y recarga rapida mientras se genera otra ventana.

Tipo: correccion de defecto. Sin tailwind.css el panel respondia 200 con un fichero vacio que el
navegador guardaba una hora: las paginas seguian sin estilos aunque el fichero volviera, y tras
una actualizacion del CSS se seguia viendo el viejo. Y al cambiar la ventana el aviso «generando…»
se quedaba hasta 20 s aunque el informe nuevo tardara 4 (visto en local, 2026-10-12).
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures.panel2._dash_p import PanelP  # noqa: E402


class Estilos(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.css = os.path.join(self.p.tmp.name, "share", "tailwind.css")

    def test_sin_fichero_404_sin_cache(self):
        """Correccion de defecto: si falta el CSS, 404 y no-store (nada que el navegador guarde)."""
        r = self.p.pedir("GET", "/vendor/tailwind.css")
        self.assertEqual(r.status, 404)
        self.assertEqual(r.cab("Cache-Control"), "no-store")

    def test_enlace_con_huella_y_url_nueva_si_cambia(self):
        """Capacidad nueva: el enlace lleva ?v=<huella>; esa URL se guarda para siempre y, si el
        CSS cambia, la huella cambia y el navegador baja el nuevo sin Ctrl+F5."""
        with open(self.css, "w", encoding="utf-8") as f:
            f.write(".tw-a{color:red}")
        ana = self.p.entrar("ana")
        h = self.p.pedir("GET", "/cuarentena?nodo=p001", cookie=ana).texto
        v1 = re.search(r"href=/vendor/tailwind\.css\?v=([0-9a-f]{12})>", h).group(1)
        r = self.p.pedir("GET", "/vendor/tailwind.css?v=" + v1)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.texto, ".tw-a{color:red}")
        self.assertIn("immutable", r.cab("Cache-Control"))
        # sin huella (o con una vieja) no se guarda a largo plazo
        self.assertEqual(self.p.pedir("GET", "/vendor/tailwind.css").cab("Cache-Control"), "no-cache")
        with open(self.css, "w", encoding="utf-8") as f:
            f.write(".tw-a{color:blue}")
        h = self.p.pedir("GET", "/cuarentena?nodo=p001", cookie=ana).texto
        v2 = re.search(r"href=/vendor/tailwind\.css\?v=([0-9a-f]{12})>", h).group(1)
        self.assertNotEqual(v1, v2)
        self.assertEqual(self.p.pedir("GET", "/vendor/tailwind.css?v=" + v1).cab("Cache-Control"),
                         "no-cache")


class Recarga(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.p.cuarentena("_todos", [])      # generado con ventana_min=1440
        self.ana = self.p.entrar("ana")

    def recarga(self):
        h = self.p.pedir("GET", "/?nodo=_todos", cookie=self.ana).texto
        return re.search(r"<meta http-equiv=refresh content=(\d+)>", h).group(1), h

    def test_20_s_normal_y_3_s_mientras_genera_otra_ventana(self):
        """Correccion de defecto: con la ventana elegida ya generada se recarga cada 20 s; si se
        eligio otra y aun se muestra la vieja («generando…»), cada 3 s."""
        self.p.d.CFG["VENTANA_MIN"] = "1440"
        self.assertEqual(self.recarga()[0], "20")
        self.p.d.CFG["VENTANA_MIN"] = "30"
        seg, h = self.recarga()
        self.assertEqual(seg, "3")
        self.assertIn("generando 30 min", h)
        self.assertIn("var s=3,", h)


if __name__ == "__main__":
    unittest.main()
