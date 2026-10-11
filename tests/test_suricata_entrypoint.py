"""entrypoint-suricata (CONTRATO-F1a §5.2): umask, validación del entorno, espera a
ids-mon con sondeo cada 1 s y exec de suricata con los argumentos exactos."""
import io
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_suricata as A  # noqa: E402

E = A.cargar("entrypoint-suricata")
ARGV_SURICATA = ["/usr/bin/suricata", "-c", "/etc/ids/suricata/suricata.yaml", "--af-packet",
                 "--pidfile", "/run/suricata.pid"]


class Reloj:
    """Reloj simulado: dormir() avanza el tiempo."""

    def __init__(self):
        self.t = 1000.0
        self.dormidas = []

    def reloj(self):
        return self.t

    def dormir(self, s):
        self.dormidas.append(s)
        self.t += s


class Entorno(unittest.TestCase):
    def test_validos(self):
        self.assertEqual(E.validar_entorno({"PUNTO": "p003", "IDS_ESPERA_MON_S": "60"}), ("p003", 60))
        self.assertEqual(E.validar_entorno({"PUNTO": "p999", "IDS_ESPERA_MON_S": "1"}), ("p999", 1))
        self.assertEqual(E.validar_entorno({"PUNTO": "p001", "IDS_ESPERA_MON_S": "600"}), ("p001", 600))

    def test_invalidos(self):
        for env in ({}, {"PUNTO": "p3", "IDS_ESPERA_MON_S": "60"},
                    {"PUNTO": "p0031", "IDS_ESPERA_MON_S": "60"},
                    {"PUNTO": "P003", "IDS_ESPERA_MON_S": "60"},
                    {"PUNTO": "p003\n", "IDS_ESPERA_MON_S": "60"},
                    {"PUNTO": "p003", "IDS_ESPERA_MON_S": "0"},
                    {"PUNTO": "p003", "IDS_ESPERA_MON_S": "601"},
                    {"PUNTO": "p003", "IDS_ESPERA_MON_S": "-3"},
                    {"PUNTO": "p003", "IDS_ESPERA_MON_S": "3.5"},
                    {"PUNTO": "p003", "IDS_ESPERA_MON_S": "tres"}):
            with self.assertRaises(E.ErrorArranque, msg=repr(env)):
                E.validar_entorno(env)


class Espera(unittest.TestCase):
    def test_aparece_al_tercer_sondeo(self):
        r = Reloj()
        sondeos = iter([False, False, True])
        self.assertTrue(E.esperar_mon(60, lambda: next(sondeos), r.dormir, r.reloj))
        self.assertEqual(r.dormidas, [1, 1])

    def test_ya_existe_no_espera(self):
        r = Reloj()
        self.assertTrue(E.esperar_mon(60, lambda: True, r.dormir, r.reloj))
        self.assertEqual(r.dormidas, [])

    def test_no_aparece_se_rinde_a_los_n_segundos(self):
        r = Reloj()
        llamadas = []
        self.assertFalse(E.esperar_mon(3, lambda: llamadas.append(1) or False, r.dormir, r.reloj))
        self.assertEqual(r.dormidas, [1, 1, 1])          # sondeo cada 1 s
        self.assertEqual(r.t - 1000.0, 3)                # se rinde a los 3 s
        self.assertEqual(len(llamadas), 4)               # t = 0, 1, 2, 3


class Main(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.reglas = base / "reglas" / "current" / "reducido"
        self.reglas.mkdir(parents=True)
        (self.reglas / "suricata.rules").write_text("alert ip any any -> any any (sid:1;)\n")
        self.yaml = base / "suricata.yaml"
        self.yaml.write_text("%%YAML 1.1\n---\ndefault-rule-path: %s\n" % self.reglas.as_posix())
        self.exec = []
        self.umasks = []
        self.reloj = Reloj()
        self.err = io.StringIO()

    def tearDown(self):
        self.tmp.cleanup()

    def correr(self, env, existe):
        return E.main(env=env, existe=existe, dormir=self.reloj.dormir, reloj=self.reloj.reloj,
                      execv=lambda p, a: self.exec.append((p, a)),
                      umask=lambda m: self.umasks.append(m) or 0o022,
                      yaml=str(self.yaml), err=self.err)

    def test_arranca_suricata_con_los_argumentos_exactos(self):
        rc = self.correr({"PUNTO": "p003", "IDS_ESPERA_MON_S": "60"}, lambda: True)
        self.assertEqual(self.exec, [("/usr/bin/suricata", ARGV_SURICATA)])
        self.assertEqual(self.umasks, [0o027])
        self.assertEqual(rc, 1)                          # solo vuelve porque execv es falso

    def test_sin_ids_mon_sale_con_1_y_el_mensaje(self):
        rc = self.correr({"PUNTO": "p003", "IDS_ESPERA_MON_S": "3"}, lambda: False)
        self.assertEqual(rc, 1)
        self.assertEqual(self.exec, [])
        self.assertIn("entrypoint-suricata: ids-mon no existe tras 3 s", self.err.getvalue())
        self.assertEqual(self.reloj.t - 1000.0, 3)

    def test_entorno_malo_no_espera_ni_arranca(self):
        rc = self.correr({"PUNTO": "norte", "IDS_ESPERA_MON_S": "60"}, lambda: True)
        self.assertEqual(rc, 1)
        self.assertEqual(self.exec, [])
        self.assertEqual(self.reloj.dormidas, [])
        self.assertIn("PUNTO", self.err.getvalue())

    def test_sin_reglas_no_arranca_ciego(self):
        (self.reglas / "suricata.rules").unlink()
        rc = self.correr({"PUNTO": "p003", "IDS_ESPERA_MON_S": "60"}, lambda: True)
        self.assertEqual(rc, 1)
        self.assertEqual(self.exec, [])
        self.assertIn("suricata.rules", self.err.getvalue())

    def test_sin_yaml_no_arranca(self):
        self.yaml.unlink()
        rc = self.correr({"PUNTO": "p003", "IDS_ESPERA_MON_S": "60"}, lambda: True)
        self.assertEqual(rc, 1)
        self.assertEqual(self.exec, [])

    def test_ruta_de_reglas_del_yaml(self):
        self.assertEqual(E.ruta_reglas("a: 1\ndefault-rule-path: /reglas/current/completo\n"),
                         "/reglas/current/completo")
        self.assertEqual(E.ruta_reglas(A.render_imagen()), "/reglas/current/reducido")
        self.assertIsNone(E.ruta_reglas("#default-rule-path: /x\n"))

    def test_programa_real_sin_ids_mon(self):
        """El script de verdad, sin ids-mon (no existe en la máquina de pruebas)."""
        if E.existe_ids_mon():
            self.skipTest("esta máquina tiene una interfaz ids-mon")
        env = dict(os.environ, PUNTO="p003", IDS_ESPERA_MON_S="1")
        t0 = time.monotonic()
        r = subprocess.run([sys.executable, str(A.BIN / "entrypoint-suricata")], env=env,
                           capture_output=True, text=True, timeout=30)
        dur = time.monotonic() - t0
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("ids-mon no existe tras 1 s", r.stderr)
        self.assertGreaterEqual(dur, 0.9)


if __name__ == "__main__":
    unittest.main()
