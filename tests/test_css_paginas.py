"""El CSS de todas las páginas se puede leer: ninguna regla queda sin selector.

Tipo: corrección de defecto. Al portar el panel se quitó el botón «Actualizar panel» y su regla CSS
perdió la línea del selector pero no la del cuerpo. El trozo suelto
(`border:0;padding:...}`) hacía que el navegador descartara la regla siguiente,
`.askov{display:none...}`, y el modal de confirmación salía abierto en TODAS las páginas
(visto en el laboratorio, 2026-10-12). Un selector CSS nunca lleva «;»: si lo lleva, es eso.
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures.panel2._dash_p import PanelP  # noqa: E402

RUTAS = ["/", "/top", "/detalle", "/cuarentena", "/reputacion", "/historico", "/conducta", "/eventos",
         "/exclusiones", "/ajustes", "/log", "/bitacora", "/documentacion", "/puntos", "/puntos/p001",
         "/puntos/nuevo"]


def selectores_rotos(css):
    """Lo que el navegador no puede leer: una «}» fuera de cualquier bloque (cuerpo de regla sin
    selector: arrastra la regla siguiente) o un selector con «;»."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    malos, prelude, prof = [], "", 0
    for ch in css:
        if ch == "{":
            if ";" in prelude:
                malos.append(prelude.strip()[:120])
            prelude, prof = "", prof + 1
        elif ch == "}":
            if prof == 0:
                malos.append(("} suelta tras: " + prelude.strip())[:120])
            prelude, prof = "", max(0, prof - 1)
        else:
            prelude += ch
    return malos


class CSS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = PanelP()
        cls.ana = cls.p.entrar("ana")

    @classmethod
    def tearDownClass(cls):
        cls.p.cerrar()

    def test_ninguna_regla_sin_selector(self):
        for ruta in RUTAS:
            for nodo in ("_todos", "p001"):
                r = self.p.pedir("GET", "%s?nodo=%s" % (ruta, nodo), cookie=self.ana)
                self.assertEqual(r.status, 200, ruta)
                css = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", r.texto, flags=re.S))
                self.assertEqual(selectores_rotos(css), [], "%s?nodo=%s" % (ruta, nodo))

    def test_el_modal_de_confirmar_nace_oculto(self):
        r = self.p.pedir("GET", "/top?nodo=_todos", cookie=self.ana)
        css = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", r.texto, flags=re.S))
        css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        self.assertRegex(css, r"(^|\})\s*\.askov\{display:none")
        self.assertEqual(selectores_rotos(css), [])

    def test_cuarentena_conteos_centrados(self):
        """Correccion de defecto: en Cuarentena los conteos (Destinos, Puertos, Alertas) van
        centrados bajo su titulo; en movil, donde la fila se apila, vuelven a la izquierda."""
        r = self.p.pedir("GET", "/cuarentena?nodo=_todos", cookie=self.ana)
        css = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", r.texto, flags=re.S))
        self.assertIn("th.num,td.num{text-align:center}", css)
        # el bloque movil de la propia pagina (el que apila las filas como tarjetas)
        movil = css[css.index("@media(max-width:820px){h1{font-size:19px}"):]
        self.assertIn(".num,td.num{text-align:left}", movil)

    def test_detalle_con_el_ancho_del_panel(self):
        """Correccion de defecto: /detalle trae el CSS del reporte (main a 1200px) y salia mas
        estrecha que el menu y que las demas tablas (1360px); la ultima regla de main manda."""
        r = self.p.pedir("GET", "/detalle?nodo=_todos", cookie=self.ana)
        css = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", r.texto, flags=re.S))
        anchos = re.findall(r"(?:^|\})\s*main\{[^}]*max-width:(\d+)px", css)
        self.assertTrue(anchos, "sin regla main con max-width")
        self.assertEqual(anchos[-1], "1360")


if __name__ == "__main__":
    unittest.main()
