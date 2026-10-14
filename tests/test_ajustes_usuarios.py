"""Ajustes > Usuarios y roles: lista clara, roles explicados, tu cuenta protegida y claves de 10.

Tipo: correccion de defecto (el user, 2026-10-13): doble marco, columna ID, correo vacio en todas
las filas, ningun texto de que hace cada rol, papelera e interruptor en tu propia fila (te sacaban
del panel), selector de archivo del navegador cortado, «Quitar» sin foto y claves de 6 sin forma
de verlas ni de generarlas. Fixture del panel (sin red).
"""
import html
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures.panel2._dash_p import PanelP  # noqa: E402


class Usuarios(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")
        self.d = self.p.d

    def modal(self):
        h = self.p.pedir("GET", "/ajustes", cookie=self.ana).texto
        i = h.index("<div class=aptmodal id=m-usuarios")
        return h, h[i:h.index("<div id=ovlNew", i)]

    def fila(self, m, usuario):
        f = re.search(r"<tr data-f=\"[^\"]*\b%s\b[^\"]*\">.*?</tr>" % re.escape(usuario), m, re.S)
        self.assertIsNotNone(f, usuario)
        return f.group(0)

    def post(self, **form):
        return self.p.pedir("POST", "/perfil", form, cookie=self.ana).texto

    # ---- lista ----
    def test_un_solo_marco_y_sin_columna_id(self):
        h, m = self.modal()
        self.assertIn("<div class='aptbox plano'>", m)
        self.assertIn(".aptbox.plano section.card{border:0;", h)
        self.assertNotIn("<th>ID</th>", m)
        self.assertIn("<th>Usuario</th><th>Rol</th><th>Estado</th>", m)   # nadie tiene correo
        self.assertIn("Usuarios <span class=cnt>3</span>", m)

    def test_correo_solo_si_alguien_lo_tiene(self):
        us = self.d.cargar_usuarios()
        us[1]["correo"] = "olga@example.com"
        self.d.guardar_usuarios(us)
        _h, m = self.modal()
        self.assertIn("<th>Usuario</th><th>Correo</th><th>Rol</th>", m)
        self.assertIn("<td class=cmail>olga@example.com</td>", self.fila(m, "olga"))

    def test_leyenda_de_roles(self):
        _h, m = self.modal()
        for k in ("admin", "operador", "lectura"):
            self.assertIn("<p>%s</p>" % html.escape(self.d.ROL_DESC[k]), m)

    def test_tu_fila_sin_papelera_ni_interruptor(self):
        _h, m = self.modal()
        mia, otra = self.fila(m, "ana"), self.fila(m, "olga")
        self.assertIn("<span class=me>tu</span>", mia)
        self.assertNotIn("del_user", mia)
        self.assertNotIn("toggle_user", mia)
        self.assertIn("class='estado on fijo'", mia)
        self.assertIn("del_user", otra)
        self.assertIn("toggle_user", otra)
        self.assertIn("'Desactivar usuario'", otra)          # desactivar pide confirmacion
        self.assertIn(">Activo</button>", otra)

    def test_formularios_con_clave_y_foto_nuevas(self):
        h = self.p.pedir("GET", "/ajustes", cookie=self.ana).texto
        nuevo = h[h.index("<div id=ovlNew"):h.index("<div id=ovlEdit")]
        self.assertIn("minlength=10 required>", nuevo)
        self.assertIn("generarClave('npw','npwh')", nuevo)
        self.assertIn("verClave('npw',this)", nuevo)
        self.assertIn("<span class=fbtn>Elegir imagen</span>", nuevo)
        self.assertRegex(nuevo, r"id=nquitar onclick=\"ufQuitar\('n'\)\" hidden>")   # sin foto, sin Quitar
        self.assertIn("pattern='[A-Za-z0-9][A-Za-z0-9._\\-]{0,31}'", nuevo)
        self.assertIn("var ROLD={", h)

    # ---- servidor ----
    def test_clave_minima_10(self):
        t = self.post(accion="add_user", nuser="pepe", npass="123456789", nrole="lectura")
        self.assertIn("al menos 10 caracteres", t)
        self.assertFalse(any(u["user"] == "pepe" for u in self.d.cargar_usuarios()))
        t = self.post(accion="add_user", nuser="pepe", npass="1234567890", nrole="lectura")
        self.assertIn("Usuario &#x27;pepe&#x27; creado", t)
        t = self.post(accion="edit_user", user="pepe", nombre="", correo="", role="lectura", npass="corta")
        self.assertIn("al menos 10 caracteres", t)

    def test_no_te_borras_ni_te_desactivas(self):
        us = self.d.cargar_usuarios()
        us[1]["role"] = "admin"                     # hay otro admin: antes si dejaba borrarse
        self.d.guardar_usuarios(us)
        t = self.post(accion="del_user", user="ana")
        self.assertIn("No puedes eliminar tu propia cuenta", t)
        t = self.post(accion="toggle_user", user="ana")
        self.assertIn("No puedes desactivar tu propia cuenta", t)
        ana = next(u for u in self.d.cargar_usuarios() if u["user"] == "ana")
        self.assertTrue(ana.get("activo", True))
        t = self.post(accion="toggle_user", user="olga")
        self.assertIn("Usuario &#x27;olga&#x27; desactivado.", t)


if __name__ == "__main__":
    unittest.main()
