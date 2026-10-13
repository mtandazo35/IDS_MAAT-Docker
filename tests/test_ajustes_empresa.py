"""Ajustes > Empresa: modal compacto con el logo actual, vista previa y Cancelar.

Tipo: correccion de defecto (el user, 2026-10-13): el modal media 980 px para dos campos, tenia
un marco dentro de otro, el selector de archivo del navegador salia cortado, «Quitar imagen»
aparecia sin logo, no habia vista previa y decia que el logo sale «al lado de las pestanas»
cuando sale en la franja de debajo del menu. Fixture del panel (sin red).
"""
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures.panel2._dash_p import PanelP  # noqa: E402

PNG = ("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
       "YPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")


class ModalEmpresa(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")

    def modal(self):
        h = self.p.pedir("GET", "/ajustes", cookie=self.ana).texto
        m = re.search(r"<div class=aptmodal id=m-empresa.*?</form>", h, re.S)
        self.assertIsNotNone(m)
        return h, m.group(0)

    def guardar_empresa(self, nombre, logo):
        with open(os.path.join(self.p.tmp.name, "panel", "conf", "empresa.json"), "w", encoding="utf-8") as f:
            json.dump({"nombre": nombre, "logo": logo}, f)

    def test_compacto_con_cancelar_y_texto_correcto(self):
        h, m = self.modal()
        self.assertIn("<div class='aptbox chico'>", m)
        self.assertIn(".aptmodal .aptbox.chico{max-width:560px}", h)
        self.assertIn("franja blanca de debajo del menu", m)
        self.assertNotIn("al lado de las pesta", m)
        self.assertIn("onclick=closem()>Cancelar</button>", m)
        self.assertIn("PNG, JPG, SVG o WebP", m)

    def test_sin_logo_no_ofrece_quitarlo(self):
        self.guardar_empresa("ISP Ejemplo", "")
        _h, m = self.modal()
        self.assertRegex(m, r"<span id=lvacio class=vacio>Sin logo</span>")
        self.assertRegex(m, r"id=lquitar onclick='empQuitar\(\)' hidden>")
        self.assertIn("<span id=vnom class=vn>ISP Ejemplo</span>", m)

    def test_con_logo_lo_muestra_y_deja_quitarlo(self):
        self.guardar_empresa("ISP Ejemplo", PNG)
        _h, m = self.modal()
        self.assertIn("<img id=lpreview src=\"%s\"" % PNG, m)
        self.assertRegex(m, r"<span id=lvacio class=vacio hidden>")
        self.assertRegex(m, r"id=lquitar onclick='empQuitar\(\)'>")
        self.assertIn("<img id=vlogo src=\"%s\" alt=''>" % PNG, m)    # la vista previa ya lo trae


class AvisoCentrado(unittest.TestCase):
    """El aviso tras guardar es un modal centrado con «Aceptar», no la franja de arriba
    (el user, 2026-10-13: «esta horrible, mejor al centro»)."""

    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")

    def test_guardar_empresa_muestra_modal_ok(self):
        h = self.p.pedir("POST", "/empresa", {"nombre": "ISP Ejemplo", "logo": ""}, cookie=self.ana).texto
        self.assertIn("<div id=notif class='avm ok' role=alertdialog", h)
        self.assertIn("onclick=avmCerrar()>Aceptar</button>", h)
        self.assertIn(".avm{position:fixed;inset:0;", h)                       # tapa toda la pantalla
        self.assertIn("align-items:center;justify-content:center", h)          # y centra la caja
        self.assertIn("setTimeout(function(){window.avmCerrar();},4000);", h)  # el ok se cierra solo
        self.assertNotIn("notifm", h)

    def test_error_no_se_cierra_solo_y_escapa(self):
        d = self.p.d
        h = d.perfil_page("<b>clave</b> corta", ok=False)
        self.assertIn("class='avm err'", h)
        self.assertIn("&lt;b&gt;clave&lt;/b&gt; corta", h)
        self.assertNotIn("window.avmCerrar();},4000", h)

    def test_sin_mensaje_no_hay_aviso(self):
        self.assertEqual(self.p.d.aviso_modal(""), "")
        self.assertNotIn("id=notif", self.p.pedir("GET", "/ajustes", cookie=self.ana).texto)


if __name__ == "__main__":
    unittest.main()
