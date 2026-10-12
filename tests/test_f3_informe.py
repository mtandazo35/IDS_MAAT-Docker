"""informe_diario.py: ventana por marca de cada evento, punto dado de baja a mitad, resultado de
Telegram en el código de salida (auditoría A-25) y ficheros que no son regulares (A-26).
Mismo arnés que tests/test_informe_diario.py. Tipo de cada prueba en su docstring."""
import json
import os
import subprocess
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_informe_diario import LIB, HAY_CRYPTO, TOKEN, Base, alerta  # noqa: E402


class Ventana(Base):
    def test_alertas_viejas_del_eve_vivo_no_cuentan(self):
        """Corrección de defecto (A-25): el eve.json vivo (mtime de ahora) trae alertas de hace 3
        días; el informe de 24 h solo cuenta las de las últimas 24 h, por la marca de cada evento."""
        self.eve("p001", [alerta("10.0.0.5", "ET SCAN Masscan", 7, hace_s=3 * 86400 + i) for i in range(5)]
                 + [alerta("10.0.0.6", "ET SCAN Masscan", 7, hace_s=600)])
        r = self.correr("--nodo", "p001", "--sin-enviar")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("10.0.0.5", r.stdout)
        self.assertIn("10.0.0.6", r.stdout)
        self.assertIn("(alertas graves: 1)", r.stdout)


class Arnes(Base):
    def main(self, cuerpo, *args):
        """Ejecuta informe_diario.main() en un subproceso con `cuerpo` (código) antes."""
        arnes = ("import sys, json, urllib.request, urllib.parse; sys.path.insert(0, %r)\n"
                 "import informe_diario as I, nodos\n%s\n"
                 "rc = I.main(sys.argv[1:])\n"
                 "print('@@' + json.dumps({'rc': rc}))\n") % (str(LIB), cuerpo)
        r = subprocess.run([sys.executable, "-c", arnes] + list(args), capture_output=True, text=True,
                           env=self.env(), timeout=60)
        lin = [x for x in r.stdout.splitlines() if x.startswith("@@")]
        self.assertTrue(lin, r.stderr)
        return json.loads(lin[-1][2:])["rc"], r

    def test_punto_dado_de_baja_a_mitad_no_cancela_el_informe(self):
        """Corrección de defecto (A-25): si un punto desaparece mientras se hace el informe, se salta
        ese punto y los demás salen (antes: NodoInexistente cancelaba todo con rc 3 y el panel daba
        el día por hecho)."""
        self.eve("p002", [alerta("10.0.0.9", "ET SCAN Masscan", 7)])
        cuerpo = ("_orig = I.analizar\n"
                  "def analizar(pid, *a):\n"
                  "    if pid == 'p001':\n"
                  "        raise nodos.NodoInexistente(pid)\n"
                  "    return _orig(pid, *a)\n"
                  "I.analizar = analizar\n")
        rc, r = self.main(cuerpo, "--sin-enviar")
        self.assertEqual(rc, 0, r.stderr)
        self.assertIn("(p002)", r.stdout)
        self.assertNotIn("(p001)", r.stdout)

    def test_sin_telegram_configurado_sale_con_0(self):
        """Conservación: sin Telegram configurado no hay nada que enviar y sale con 0."""
        rc, r = self.main("")
        self.assertEqual(rc, 0, r.stderr)

    @unittest.skipUnless(HAY_CRYPTO, "falta cryptography (python3-cryptography en la imagen)")
    def test_fallo_de_telegram_da_codigo_distinto(self):
        """Corrección de defecto (A-25): si Telegram está configurado y el envío falla, el informe se
        imprime igual pero sale con RC_TELEGRAM (4): el panel lo anota como fallo en la bitácora."""
        cod = ("import sys; sys.path.insert(0, %r); import secretos; "
               "print(secretos.cifrar(%r, 'report:TELEGRAM_TOKEN'))" % (str(LIB), TOKEN))
        valor = subprocess.run([sys.executable, "-c", cod], capture_output=True, text=True,
                               env=self.env(), timeout=60).stdout.strip()
        (self.panel / "conf" / "report.conf").write_text(
            "TELEGRAM_TOKEN=%s\nTELEGRAM_CHAT_ID=-100123\n" % valor, encoding="utf-8")
        cuerpo = ("def falso(url, data=None, timeout=None):\n"
                  "    raise OSError('red cortada en la prueba')\n"
                  "urllib.request.urlopen = falso\n")
        rc, r = self.main(cuerpo)
        self.assertEqual(rc, 4, r.stderr)
        self.assertIn("== Nodo", r.stdout)
        self.assertNotIn(TOKEN, r.stderr + r.stdout)


class Ficheros(Base):
    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo: solo POSIX")
    def test_fifo_en_lugar_del_eve_no_cuelga(self):
        """Corrección de defecto (A-26): una FIFO como eve.json no cuelga el informe."""
        os.mkfifo(self.datos / "p001" / "eve.json")
        res = {}

        def correr():
            res["r"] = self.correr("--nodo", "p001", "--sin-enviar")
        h = threading.Thread(target=correr, daemon=True)
        h.start()
        h.join(60)
        self.assertFalse(h.is_alive(), "el informe se ha quedado colgado en la FIFO")
        self.assertEqual(res["r"].returncode, 0, res["r"].stderr)

    def test_eve_que_es_enlace_no_se_lee(self):
        """Corrección de defecto (A-26): un eve.json que es un enlace (a un fichero fuera del punto)
        no se lee."""
        fuera = Path(self.dir) / "fuera.json"
        fuera.write_text(alerta("10.0.0.77", "ET SCAN Masscan", 7) + "\n", encoding="utf-8")
        try:
            os.symlink(str(fuera), str(self.datos / "p001" / "eve.json"))
        except (OSError, NotImplementedError):
            self.skipTest("este sistema no deja crear enlaces simbolicos")
        r = self.correr("--nodo", "p001", "--sin-enviar")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("10.0.0.77", r.stdout)


if __name__ == "__main__":
    unittest.main()
