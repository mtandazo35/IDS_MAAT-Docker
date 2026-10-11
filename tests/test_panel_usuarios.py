"""Panel: ids-panel crear-admin / restablecer (proceso real) y almacén de usuarios."""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import shutil
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures" / "panel"))
import _ayuda_panel as A  # noqa: E402
from idspanel import usuarios as U  # noqa: E402

LINUX = sys.platform.startswith("linux")


def ejecutar(dir_panel, *args):
    env = dict(os.environ, IDS_PANEL_DIR=str(dir_panel), PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, str(A.SCRIPT)] + list(args), capture_output=True, text=True,
                          env=env, timeout=120)


def pbkdf2(clave, reg):
    return hashlib.pbkdf2_hmac("sha256", clave.encode(), bytes.fromhex(reg["sal"]), reg["iter"]).hex()


class CrearAdmin(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="ids-panel-u-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.fichero = self.dir / "usuarios.json"

    def test_crea_imprime_una_linea_y_guarda_solo_el_hash(self):
        r = ejecutar(self.dir, "crear-admin", "--usuario", "admin")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r"\ACLAVE=[A-Za-z0-9]{20}\n\Z")       # exactamente UNA línea
        clave = r.stdout.strip().split("=", 1)[1]
        txt = self.fichero.read_text(encoding="utf-8")
        self.assertNotIn(clave, txt)
        reg = json.loads(txt)["usuarios"]["admin"]
        self.assertEqual(reg["alg"], "pbkdf2_sha256")
        self.assertEqual(reg["iter"], 600000)
        self.assertRegex(reg["sal"], r"^[0-9a-f]{32}$")
        self.assertEqual(reg["hash"], pbkdf2(clave, reg))
        self.assertNotEqual(reg["hash"], pbkdf2(clave + "x", reg))
        self.assertTrue(reg["clave_temporal"])
        if LINUX:
            self.assertEqual(self.fichero.stat().st_mode & 0o777, 0o600)
        self.assertEqual([p.name for p in self.dir.iterdir()], ["usuarios.json"])   # sin temporales

    def test_si_ya_existe_sale_3_sin_tocar_nada(self):
        r1 = ejecutar(self.dir, "crear-admin", "--usuario", "admin")
        self.assertEqual(r1.returncode, 0)
        antes = self.fichero.read_bytes()
        r2 = ejecutar(self.dir, "crear-admin", "--usuario", "admin")
        self.assertEqual(r2.returncode, 3)
        self.assertEqual(r2.stdout, "")
        self.assertIn("ya existe", r2.stderr)
        self.assertEqual(self.fichero.read_bytes(), antes)

    def test_otro_usuario_se_anade_sin_tocar_el_primero(self):
        ejecutar(self.dir, "crear-admin", "--usuario", "admin")
        admin = json.loads(self.fichero.read_text(encoding="utf-8"))["usuarios"]["admin"]
        r = ejecutar(self.dir, "crear-admin", "--usuario", "tecnico")
        self.assertEqual(r.returncode, 0)
        d = json.loads(self.fichero.read_text(encoding="utf-8"))["usuarios"]
        self.assertEqual(sorted(d), ["admin", "tecnico"])
        self.assertEqual(d["admin"], admin)

    def test_usuario_invalido_sale_2(self):
        r = ejecutar(self.dir, "crear-admin", "--usuario", "Admin<b>")
        self.assertEqual(r.returncode, 2)
        self.assertFalse(self.fichero.exists())

    def test_restablecer(self):
        r = ejecutar(self.dir, "crear-admin", "--usuario", "admin")
        vieja = r.stdout.strip().split("=", 1)[1]
        sello = json.loads(self.fichero.read_text(encoding="utf-8"))["usuarios"]["admin"]["sello"]
        r = ejecutar(self.dir, "restablecer", "--usuario", "admin")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r"\ACLAVE=[A-Za-z0-9]{20}\n\Z")
        nueva = r.stdout.strip().split("=", 1)[1]
        self.assertNotEqual(nueva, vieja)
        reg = json.loads(self.fichero.read_text(encoding="utf-8"))["usuarios"]["admin"]
        self.assertEqual(reg["hash"], pbkdf2(nueva, reg))
        self.assertNotEqual(reg["hash"], pbkdf2(vieja, reg))
        self.assertNotEqual(reg["sello"], sello)          # invalida las sesiones abiertas
        self.assertTrue(reg["clave_temporal"])

    def test_restablecer_inexistente_sale_4(self):
        r = ejecutar(self.dir, "restablecer", "--usuario", "nadie")
        self.assertEqual(r.returncode, 4)
        self.assertEqual(r.stdout, "")


class Almacen(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="ids-panel-u-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.u = U.Usuarios(str(self.dir / "usuarios.json"))

    def test_autenticar(self):
        with A.iteraciones_rapidas():
            self.u.crear("admin", "una-clave-larga-1")
            self.assertIsNotNone(self.u.autenticar("admin", "una-clave-larga-1"))
            self.assertIsNone(self.u.autenticar("admin", "una-clave-larga-2"))
            self.assertIsNone(self.u.autenticar("nadie", "una-clave-larga-1"))
            self.assertIsNone(self.u.autenticar("admin", ""))

    def test_rehash_transparente_al_subir_iteraciones(self):
        with A.iteraciones_rapidas(1000):
            self.u.crear("admin", "una-clave-larga-1")
        with A.iteraciones_rapidas(2000):
            self.assertIsNotNone(self.u.autenticar("admin", "una-clave-larga-1"))
            self.assertEqual(self.u.obtener("admin")["iter"], 2000)
            self.assertIsNotNone(self.u.autenticar("admin", "una-clave-larga-1"))

    def test_cambiar_pide_la_actual_y_valida_la_nueva(self):
        with A.iteraciones_rapidas():
            self.u.crear("admin", "una-clave-larga-1")
            sello = self.u.obtener("admin")["sello"]
            with self.assertRaises(U.ClaveNoValida):
                self.u.cambiar("admin", "mala", "otra-clave-larga-2")
            with self.assertRaises(U.ClaveNoValida):
                self.u.cambiar("admin", "una-clave-larga-1", "corta")
            with self.assertRaises(U.ClaveNoValida):
                self.u.cambiar("admin", "una-clave-larga-1", "una-clave-larga-1")
            self.assertIsNotNone(self.u.autenticar("admin", "una-clave-larga-1"))
            nuevo = self.u.cambiar("admin", "una-clave-larga-1", "otra-clave-larga-2")
            self.assertNotEqual(nuevo, sello)
            self.assertFalse(self.u.obtener("admin")["clave_temporal"])
            self.assertIsNone(self.u.autenticar("admin", "una-clave-larga-1"))
            self.assertIsNotNone(self.u.autenticar("admin", "otra-clave-larga-2"))

    def test_clave_generada(self):
        claves = {U.nueva_clave() for _ in range(50)}
        self.assertEqual(len(claves), 50)
        self.assertTrue(all(re.match(r"^[A-Za-z0-9]{20}$", c) for c in claves))


if __name__ == "__main__":
    unittest.main()
