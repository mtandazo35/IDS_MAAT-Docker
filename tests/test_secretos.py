"""secretos.py: los secretos del panel se guardan cifrados con la clave maestra (CONTRATO-F2 §10.3).

Tipo: capacidad nueva.
"""
import importlib
import os
import sys
import tempfile
import unittest

LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "images", "panel", "rootfs", "usr", "local", "lib", "ids-panel")


def cargar(ruta_clave):
    os.environ["IDS_MASTER_KEY"] = ruta_clave
    if LIB not in sys.path:
        sys.path.insert(0, LIB)
    import secretos
    return importlib.reload(secretos)


class Secretos(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.k = os.path.join(self.tmp.name, "master_key")
        with open(self.k, "w") as f:
            f.write("ab" * 32 + "\n")
        self.s = cargar(self.k)

    def tearDown(self):
        self.tmp.cleanup()

    def test_ida_y_vuelta_y_no_en_claro(self):
        v = self.s.cifrar("clave-del-router", "router:p001:PASS")
        self.assertTrue(v.startswith("enc1:"))
        self.assertNotIn("clave-del-router", v)
        self.assertEqual(self.s.descifrar(v, "router:p001:PASS"), "clave-del-router")
        self.assertNotEqual(v, self.s.cifrar("clave-del-router", "router:p001:PASS"))  # nonce nuevo

    def test_ligado_a_su_sitio(self):
        v = self.s.cifrar("x", "router:p001:PASS")
        with self.assertRaises(self.s.SecretoNoDisponible):
            self.s.descifrar(v, "router:p002:PASS")

    def test_manipulado_se_rechaza(self):
        v = self.s.cifrar("x", "a")
        malo = v[:-4] + ("AAAA" if not v.endswith("AAAA") else "BBBB")
        with self.assertRaises(self.s.SecretoNoDisponible):
            self.s.descifrar(malo, "a")

    def test_claro_viejo_se_lee_y_se_marca(self):
        self.assertEqual(self.s.descifrar("viejo"), "viejo")
        self.assertTrue(self.s.necesita_cifrar("viejo"))
        self.assertFalse(self.s.necesita_cifrar(self.s.cifrar("viejo")))
        self.assertEqual(self.s.cifrar(""), "")

    def test_sin_clave_maestra(self):
        s = cargar(os.path.join(self.tmp.name, "no-existe"))
        self.assertFalse(s.disponible())
        with self.assertRaises(s.SecretoNoDisponible):
            s.cifrar("x")


if __name__ == "__main__":
    unittest.main()
