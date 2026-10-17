"""operaciones.json del panel: anotar lo que no cambia no reescribe el fichero.

Corrección de defecto (revisión 2026-10-15, B6): la página de una operación terminada anota
`vista=True` en cada visita y eso reescribía operaciones.json entero (hasta 300 operaciones) aunque
ya estuviera vista. Ahora solo se escribe si algún campo cambia.
"""
import os
import shutil
import sys
import tempfile
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(AQUI, "..", "images", "panel", "rootfs", "usr", "local", "lib", "ids-panel")
if LIB not in sys.path:
    sys.path.insert(0, LIB)
from idspanel import operaciones  # noqa: E402

OP = "0123abcd-0000-4000-8000-000000000001"


class Anotar(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ops-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ops = operaciones.Operaciones(os.path.join(self.tmp, "operaciones.json"))
        self.ops.registrar(OP, "ana", "panel.baja", pid="p001")
        self.escrituras = 0
        guardar = self.ops._guardar

        def contar():
            self.escrituras += 1
            guardar()
        self.ops._guardar = contar

    def test_lo_que_no_cambia_no_se_escribe(self):
        self.assertTrue(self.ops.anotar(OP, vista=True))
        self.assertEqual(self.escrituras, 1)
        for _ in range(3):                                   # cada visita a la página
            self.assertTrue(self.ops.anotar(OP, vista=True))
        self.assertEqual(self.escrituras, 1)
        self.assertTrue(self.ops.obtener(OP)["vista"])

    def test_lo_que_cambia_si_se_escribe(self):
        self.ops.anotar(OP, entrega_clave="pendiente")
        self.ops.anotar(OP, entrega_clave="entregada")
        self.assertEqual(self.escrituras, 2)
        self.assertEqual(self.ops.obtener(OP)["entrega_clave"], "entregada")

    def test_sin_sobrescribir_no_pisa_y_no_escribe(self):
        self.ops.anotar(OP, entrega_clave="entregada")
        self.ops.anotar(OP, sobrescribir=False, entrega_clave="otra")
        self.assertEqual(self.escrituras, 1)
        self.assertEqual(self.ops.obtener(OP)["entrega_clave"], "entregada")

    def test_operacion_que_no_existe(self):
        self.assertFalse(self.ops.anotar("no-existe", vista=True))
        self.assertEqual(self.escrituras, 0)


if __name__ == "__main__":
    unittest.main()
