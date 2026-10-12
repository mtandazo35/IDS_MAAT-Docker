"""scripts/lab-actualizar.sh: exige el CI en verde (auditoría B-02) y su respaldo no lleva la clave
maestra pero sí el panel (B-05/B-06).

Se ejecutan las FUNCIONES reales del script (sacadas con sed) en bash, con `curl` sustituido por una
función que devuelve la respuesta de la API de GitHub que pone la prueba; `/root/backups` va a un
directorio temporal. Necesita bash, python3, tar y sha256sum (Linux). Tipo de cada prueba en su
docstring.
"""
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LAB = REPO / "scripts" / "lab-actualizar.sh"
LINUX = sys.platform.startswith("linux")


def run_ci(numero, conclusion, status="completed", path=".github/workflows/ci.yml", intento=1):
    return {"run_number": numero, "run_attempt": intento, "status": status, "conclusion": conclusion,
            "path": path, "name": "ci"}


@unittest.skipUnless(LINUX and shutil.which("bash") and shutil.which("python3"), "bash + python3 de Linux")
class Lab(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="ids-lab-"))
        self.addCleanup(shutil.rmtree, self.d, True)

    def bash(self, cuerpo, funciones, entorno=None):
        script = self.d / "arnes.sh"
        cargar = ("eval \"$(sed -n %s %s)\"\n" % (" ".join("-e '/^%s() {/,/^}/p'" % f for f in funciones), LAB)
                  if funciones else "")
        script.write_text(
            "set -euo pipefail\n"
            "TS=20261012T000000Z\nGUARDA=%s\nAPI_RUNS=https://api.example.invalid/runs\n"
            "log() { echo \"LOG $*\"; }\nfallar() { echo \"FALLO $*\"; exit 1; }\n%s%s\n"
            % (self.d / "guarda", cargar, cuerpo),
            encoding="utf-8")
        return subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=60,
                              env=dict(os.environ, **(entorno or {})))

    def ci(self, runs, sin_ci=0, curl_falla=False):
        respuesta = self.d / "api.json"
        respuesta.write_text(json.dumps({"workflow_runs": runs}), encoding="utf-8")
        curl = "curl() { return 22; }" if curl_falla else "curl() { cat %s; }" % respuesta
        return self.bash("%s\nexigir_ci 0123456789abcdef %d\necho FIN" % (curl, sin_ci),
                         ["estado_ci", "exigir_ci"])

    def test_ci_en_verde_deja_seguir(self):
        """Capacidad nueva (B-02): con la última ejecución de ci.yml en verde, sigue."""
        r = self.ci([run_ci(7, "failure"), run_ci(8, "success")])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("en verde", r.stdout)
        self.assertIn("FIN", r.stdout)

    def test_ci_rojo_sin_ejecuciones_o_sin_red_no_carga(self):
        """Corrección de defecto (B-02): CI en rojo, en curso, sin ninguna ejecución (el workflow no
        arrancó) o sin poder consultar GitHub: no se carga nada."""
        for runs, falla, texto in (([run_ci(8, "failure")], False, "no está en verde"),
                                   ([run_ci(9, None, status="in_progress")], False, "no está en verde"),
                                   ([run_ci(3, "success", path=".github/workflows/release.yml")], False,
                                    "ninguna ejecución"),
                                   ([], False, "ninguna ejecución"),
                                   ([], True, "no se pudo consultar")):
            with self.subTest(texto=texto, runs=runs):
                r = self.ci(runs, curl_falla=falla)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(texto, r.stdout)
                self.assertNotIn("FIN", r.stdout)

    def test_sin_ci_explicito_avisa_y_queda_anotado(self):
        """Capacidad nueva (B-02): `--sin-ci` carga sin mirar el CI, con aviso y una línea en
        sin-ci.log."""
        r = self.ci([run_ci(8, "failure")], sin_ci=1)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("AVISO", r.stdout)
        self.assertIn("0123456789abcdef", (self.d / "guarda" / "sin-ci.log").read_text(encoding="utf-8"))

    def test_respaldo_sin_clave_maestra_y_con_el_panel(self):
        """Corrección de defecto (B-06/B-05): el tar del laboratorio no lleva master.key (la clave y
        los secretos que cifra no van juntos) y sí lleva /srv/ids/panel."""
        etc = self.d / "etc" / "ids-maat"
        etc.mkdir(parents=True)
        (etc / "master.key").write_text("ab" * 32 + "\n", encoding="utf-8")
        (etc / "imagenes.json").write_text("{}", encoding="utf-8")
        panel = self.d / "srv" / "ids" / "panel" / "conf"
        panel.mkdir(parents=True)
        (panel / "routers.json").write_text('{"p001": {"PASS": "enc1:x"}}', encoding="utf-8")
        backups = self.d / "backups"
        # la función real, con /root/backups y /srv/ids del sistema cambiados por los temporales
        texto = LAB.read_text(encoding="utf-8")
        ini = texto.index("respaldar() {")
        fin = texto.index("\n}\n", ini) + 3
        fn = (texto[ini:fin].replace("respaldar()", "respaldar_t()").replace("/root/backups", str(backups))
              .replace("/srv/ids/", str(self.d / "srv" / "ids") + "/"))
        r = self.bash("ETC=%s\nLIB=%s\n%s\nrespaldar_t\n" % (etc, self.d / "no-existe", fn), ())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        tars = list(backups.glob("ids-maat-lab-*.tar.gz"))
        self.assertEqual(len(tars), 1, r.stdout)
        with tarfile.open(tars[0]) as t:
            nombres = t.getnames()
        self.assertFalse([n for n in nombres if n.endswith("master.key")], nombres)
        self.assertTrue([n for n in nombres if n.endswith("imagenes.json")], nombres)
        self.assertTrue([n for n in nombres if n.endswith("panel/conf/routers.json")], nombres)


if __name__ == "__main__":
    unittest.main()
