"""Acciones destructivas con confirmación y textos de permisos que dicen la verdad (QA U-03, U-13).

U-03: «Eliminar» una exclusión, «×» quitar un destino de confianza y «Excluir y liberar» se enviaban
sin preguntar, cuando borrar un usuario o una IP de confianza sí pedía confirmar. Ahora los tres
pasan por ask(this, …, 'danger') con la consecuencia. U-13: la página 403 y la documentación decían
«tu rol» y que «el administrador ve siempre todos», cuando manda el permiso y un administrador
también puede quedar limitado. Datos RFC 5737.
"""
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures.panel2._dash_p import PanelP  # noqa: E402


class Confirmaciones(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")
        self.d = self.p.d
        self.d.guardar_exclusiones([{"tipo": "dst", "ip": "192.0.2.10", "motivo": "x", "puertos": [], "sid": "",
                                     "hasta": 0, "nodo": "", "autor": "ana", "creado": 1}])
        self.d.modificar_dest_ok(poner="203.0.113.53")        # un destino de confianza: sale su «×»

    def formularios(self, ruta, accion):
        t = self.p.pedir("GET", ruta, cookie=self.ana).texto
        # el panel añade ?nodo=… a la action de cada formulario (html_con_nodo)
        return re.findall(r"<form method=post action=['\"]%s(?:\?[^'\"]*)?['\"][^>]*>" % re.escape(accion), t)

    def onsubmit(self, form):
        m = re.search(r'onsubmit="([^"]*)"', form) or re.search(r"onsubmit='([^']*)'", form)
        self.assertTrue(m, form)
        return html.unescape(m.group(1))

    def test_eliminar_exclusion_pide_confirmar(self):
        """Corrección de defecto: «Eliminar» de una exclusión pide confirmar, en rojo y con la consecuencia."""
        fs = [f for f in self.formularios("/exclusiones", "/exclusiones") if "onsubmit=\"return ask(this,'Eliminar" in f]
        self.assertEqual(len(fs), 1)
        js = self.onsubmit(fs[0])
        self.assertIn("'danger'", js)
        self.assertIn("192.0.2.10", js)

    def test_destinos_de_confianza_piden_confirmar(self):
        """Corrección de defecto: «×» quitar un destino de confianza y «Excluir y liberar» piden confirmar."""
        for accion, titulo in (("/cuarentena/excluir-destino", "Excluir destino y liberar"),
                               ("/cuarentena/quitar-destino", "Quitar de confiables")):
            fs = self.formularios("/cuarentena", accion)
            with self.subTest(accion=accion):
                self.assertTrue(fs, accion)
                for f in fs:
                    js = self.onsubmit(f)
                    self.assertIn("return ask(this,'%s'" % titulo, js)
                    self.assertIn("'danger'", js)

    def test_sin_confirmar_no_se_envia(self):
        """Capacidad nueva (comportamiento, con node): el onsubmit devuelve false (no envía) hasta que se
        confirma en el modal; con la confirmación (dataset.ok) sí. Sin node se salta."""
        node = shutil.which("node")
        if not node:
            self.skipTest("sin node")
        fs = [f for f in self.formularios("/exclusiones", "/exclusiones") if "ask(this,'Eliminar" in f]
        js_on = self.onsubmit(fs[0])
        prog = """
var abiertos = [];
// en globalThis: el onsubmit se evalúa con new Function, que solo ve el ámbito global
globalThis.ask = function(e, t, x, ok, tono){ if (e.dataset.ok) { e.dataset.ok = ''; return true; }
  abiertos.push([t, tono]); return false; };
var f = {dataset: {}};
var h = new Function(%s);
var r1 = h.call(f), primero = abiertos.slice();
f.dataset.ok = '1';
var r2 = h.call(f);
console.log(JSON.stringify([r1, r2, primero]));
""" % json.dumps(js_on)
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8",
                                         dir=os.environ.get("TMPDIR", "/tmp")) as fh:
            fh.write(prog)
        self.addCleanup(os.unlink, fh.name)
        r = subprocess.run([node, fh.name], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        r1, r2, abiertos = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual((r1, r2), (False, True))
        self.assertEqual(abiertos, [["Eliminar exclusión", "danger"]])


class TextosDePermisos(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)

    def test_la_pagina_403_habla_de_permisos(self):
        """Corrección de defecto (U-13): la página «Sin permiso» dice «tus permisos», no «tu rol»."""
        luis = self.p.entrar("luis")
        r = self.p.pedir("GET", "/exclusiones", cookie=luis)
        self.assertEqual(r.status, 403)
        self.assertIn("Tus permisos no incluyen esta acción", r.texto)
        self.assertNotIn("Tu rol no permite", r.texto)

    def test_la_documentacion_no_dice_que_el_admin_ve_todo(self):
        """Corrección de defecto (U-13): la documentación ya no dice que el administrador ve siempre todos."""
        t = self.p.pedir("GET", "/documentacion?p=todo", cookie=self.p.entrar("ana")).texto
        self.assertNotIn("administrador ve siempre todos", t)
        self.assertIn("Cada acción exige su permiso", t)


if __name__ == "__main__":
    unittest.main()
