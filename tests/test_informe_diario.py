"""informe_diario.py por nodo (CONTRATO-F2 §8): lectura de los eventos de cada punto, salida en su
directorio, un mensaje con una sección por nodo y el nombre de la empresa, exclusiones con nodo y token
de Telegram cifrado. Se ejecuta como subproceso con IDS_PANEL_DIR/IDS_DATOS/IDS_RUN temporales."""

import gzip
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "images" / "panel" / "rootfs" / "usr" / "local" / "lib" / "ids-panel"
SCRIPT = LIB / "informe_diario.py"
CLAVE_MAESTRA = "ffeeddccbbaa99887766554433221100" * 2
TOKEN = "123456:token-de-prueba-AbC"

HAY_CRYPTO = importlib.util.find_spec("cryptography") is not None


def alerta(src, sig, sid, dst="192.0.2.80", hace_s=600):
    ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(time.time() - hace_s))
    return json.dumps({"timestamp": ts, "event_type": "alert", "src_ip": src, "dest_ip": dst,
                       "dest_port": 443, "in_iface": "ids-mon",
                       "alert": {"signature": sig, "signature_id": sid, "category": "A Network Trojan was detected"}},
                      separators=(",", ":"))                     # como lo escribe Suricata


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="ids-inf-"))
        self.panel = self.dir / "panel"
        self.datos = self.dir / "datos"
        self.run_ = self.dir / "run"
        for d in (self.panel / "conf", self.datos / "p001", self.datos / "p002", self.run_):
            d.mkdir(parents=True)
        (self.run_ / "estado.json").write_text(json.dumps({"puntos": {
            "p001": {"nombre": "Nodo Norte", "redes": ["10.0.0.0/24"]},
            "p002": {"nombre": "Nodo Sur", "redes": ["10.0.0.0/24"]}}}), encoding="utf-8")
        self.clave = self.dir / "master_key"
        self.clave.write_text(CLAVE_MAESTRA + "\n", encoding="ascii")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def env(self):
        return dict(os.environ, IDS_PANEL_DIR=str(self.panel), IDS_DATOS=str(self.datos), IDS_RUN=str(self.run_),
                    IDS_EMPRESA="Empresa Ejemplo", IDS_MASTER_KEY=str(self.clave), PYTHONDONTWRITEBYTECODE="1")

    def correr(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT)] + list(args), capture_output=True, text=True,
                              env=self.env(), timeout=120)

    def eve(self, pid, lineas, nombre="eve.json"):
        p = self.datos / pid / nombre
        datos = "\n".join(lineas) + "\n"
        if nombre.endswith(".gz"):
            with gzip.open(p, "wb") as g:
                g.write(datos.encode())
        else:
            p.write_text(datos, encoding="utf-8")


class PorNodo(Base):
    def test_misma_ip_en_dos_nodos_va_en_secciones_separadas(self):
        """Caso obligatorio §10.5 «misma IP en dos puntos»: cada nodo tiene su sección, sus
        contadores y su fichero; nada se suma entre nodos. Cabecera con IDS_EMPRESA."""
        self.eve("p001", [alerta("10.0.0.5", "ET MALWARE Botnet CnC Checkin", 1)] * 4)
        self.eve("p002", [alerta("10.0.0.5", "ET SCAN Nmap Scripting Engine", 2)])
        r = self.correr("--todos")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("IDS Empresa Ejemplo - resumen de 24h"), r.stdout[:80])
        norte, sur = r.stdout.split("== Nodo Nodo Sur (p002) ==")
        self.assertIn("== Nodo Nodo Norte (p001) ==", norte)
        self.assertIn("Infectados: 1   Atacando: 0", norte)
        self.assertIn("(4 alertas)", norte)
        self.assertIn("Infectados: 0   Atacando: 1", sur)
        self.assertIn("(1 alertas)", sur)
        hoy = time.strftime("%Y%m%d")
        f1 = (self.panel / "nodos" / "p001" / ("report-%s.txt" % hoy)).read_text(encoding="utf-8")
        f2 = (self.panel / "nodos" / "p002" / ("report-%s.txt" % hoy)).read_text(encoding="utf-8")
        self.assertIn("(4 alertas)", f1)
        self.assertNotIn("(4 alertas)", f2)

    def test_un_nodo_solo_lee_sus_ficheros_tambien_gz(self):
        """Conservación + capacidad nueva: --nodo lee solo datos/<pid> (vivo y .gz rotado), y el
        in_iface no decide el nodo."""
        self.eve("p001", [alerta("10.0.0.7", "ET SCAN Masscan", 3)], nombre="eve.json-20261010-120000.gz")
        self.eve("p002", [alerta("10.0.0.9", "ET SCAN Masscan", 3)] * 2)
        r = self.correr("--nodo", "p001")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("10.0.0.7", r.stdout)
        self.assertNotIn("10.0.0.9", r.stdout)
        self.assertNotIn("p002", r.stdout)
        self.assertFalse((self.panel / "nodos" / "p002").exists())

    def test_nodo_invalido_o_inexistente(self):
        """Capacidad nueva (§10.1): un nodo mal formado o inexistente no amplía a todos ni escribe."""
        self.eve("p001", [alerta("10.0.0.5", "ET SCAN x", 4)])
        r = self.correr("--nodo", "../p001")
        self.assertEqual(r.returncode, 2)
        r = self.correr("--nodo", "p009")
        self.assertEqual(r.returncode, 3)
        self.assertFalse((self.panel / "nodos").exists())

    def test_exclusion_con_nodo_solo_aplica_a_ese_nodo(self):
        """Capacidad nueva (§3): una exclusión con `nodo` solo filtra los eventos de ese nodo; sin
        `nodo`, los de todos."""
        self.eve("p001", [alerta("10.0.0.5", "ET SCAN Masscan", 5, dst="198.51.100.9")])
        self.eve("p002", [alerta("10.0.0.5", "ET SCAN Masscan", 5, dst="198.51.100.9")])
        excl = self.panel / "conf" / "exclusiones.json"
        excl.write_text(json.dumps([{"tipo": "dst", "ip": "198.51.100.9", "nodo": "p001"}]), encoding="utf-8")
        r = self.correr()
        norte, sur = r.stdout.split("(p002) ==")
        self.assertIn("alertas graves: 0", norte)
        self.assertIn("alertas graves: 1", sur)
        excl.write_text(json.dumps([{"tipo": "dst", "ip": "198.51.100.9"}]), encoding="utf-8")
        r = self.correr()
        self.assertEqual(r.stdout.count("alertas graves: 0"), 2, r.stdout)

    def test_mensaje_largo_se_parte_por_nodos(self):
        """Capacidad nueva: si las secciones no caben en un mensaje de Telegram (4000), se parten
        por nodo, cada parte con (k/n), sin cortar a mitad de un nodo."""
        for pid in ("p001", "p002"):
            self.eve(pid, [alerta("10.0.%d.%d" % (i // 200, i % 200 + 1), "ET SCAN Nmap %d" % i, 10 + i)
                           for i in range(60)])
        cod = ("import sys; sys.path.insert(0, %r); import informe_diario as I; "
               "cab, s = I.informe(); m = I.mensajes(cab, s); "
               "print(len(m), max(len(x) for x in m), [x.splitlines()[0] for x in m])" % str(LIB))
        r = subprocess.run([sys.executable, "-c", cod], capture_output=True, text=True, env=self.env(), timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        n, mayor, cabeceras = r.stdout.split(" ", 2)
        self.assertEqual(n, "2")
        self.assertLessEqual(int(mayor), 4000)
        self.assertIn("(1/2)", cabeceras)
        self.assertIn("(2/2)", cabeceras)


@unittest.skipUnless(HAY_CRYPTO, "falta cryptography (python3-cryptography en la imagen)")
class Telegram(Base):
    ARNES = ("import sys, json, urllib.request; sys.path.insert(0, %r); import informe_diario as I; "
             "vistas = []\n"
             "def falso(url, data=None, timeout=None):\n"
             "    vistas.append(url); raise OSError('red cortada en la prueba ' + url)\n"
             "urllib.request.urlopen = falso\n"
             "ok = I.enviar(['hola'])\n"
             "print(json.dumps({'ok': ok, 'urls': vistas}))\n")

    def conf_token(self, valor):
        (self.panel / "conf" / "report.conf").write_text(
            "TELEGRAM_TOKEN=%s\nTELEGRAM_CHAT_ID=-100123\n" % valor, encoding="utf-8")

    def cifrado(self):
        cod = ("import sys; sys.path.insert(0, %r); import secretos; "
               "print(secretos.cifrar(%r, 'report:TELEGRAM_TOKEN'))" % (str(LIB), TOKEN))
        return subprocess.run([sys.executable, "-c", cod], capture_output=True, text=True, env=self.env(),
                              timeout=60).stdout.strip()

    def test_token_cifrado_se_usa_y_no_sale_en_errores(self):
        """Capacidad nueva (§10.3): el token cifrado se descifra solo para la URL de Telegram; el
        error de red no lo imprime."""
        valor = self.cifrado()
        self.assertTrue(valor.startswith("enc1:"))
        self.conf_token(valor)
        r = subprocess.run([sys.executable, "-c", self.ARNES % str(LIB)], capture_output=True, text=True,
                           env=self.env(), timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual(d["urls"], ["https://api.telegram.org/bot%s/sendMessage" % TOKEN])
        self.assertFalse(d["ok"])
        self.assertNotIn(TOKEN, r.stderr)
        self.assertIn("Telegram fallo: OSError", r.stderr)

    def test_sin_argumentos_envia_todos_los_nodos(self):
        """Capacidad nueva (firma de N): `informe_diario.py` sin argumentos recorre todos los
        puntos y manda UN mensaje con una sección por nodo; --sin-enviar no manda nada."""
        self.conf_token(self.cifrado())
        self.eve("p001", [alerta("10.0.0.5", "ET SCAN Masscan", 7)])
        arnes = ("import sys, json, urllib.request, urllib.parse; sys.path.insert(0, %r); import informe_diario as I\n"
                 "textos = []\n"
                 "def falso(url, data=None, timeout=None):\n"
                 "    textos.append(urllib.parse.parse_qs(data.decode())['text'][0])\n"
                 "urllib.request.urlopen = falso\n"
                 "rc = I.main(sys.argv[1:])\n"
                 "print('@@' + json.dumps({'rc': rc, 'textos': textos}))\n") % str(LIB)
        for args, n in (([], 1), (["--sin-enviar"], 0)):
            r = subprocess.run([sys.executable, "-c", arnes] + args, capture_output=True, text=True,
                               env=self.env(), timeout=60)
            d = json.loads([x for x in r.stdout.splitlines() if x.startswith("@@")][-1][2:])
            self.assertEqual((d["rc"], len(d["textos"])), (0, n), (args, r.stderr))
        texto = json.loads([x for x in subprocess.run(
            [sys.executable, "-c", arnes], capture_output=True, text=True, env=self.env(),
            timeout=60).stdout.splitlines() if x.startswith("@@")][-1][2:])["textos"][0]
        self.assertIn("== Nodo Nodo Norte (p001) ==", texto)
        self.assertIn("== Nodo Nodo Sur (p002) ==", texto)
        self.assertNotIn(TOKEN, texto)

    def test_token_de_otro_campo_no_vale(self):
        """Corrección de defecto evitado: un valor cifrado para otro campo no se descifra aquí
        (asociado distinto) y no se envía nada."""
        cod = ("import sys; sys.path.insert(0, %r); import secretos; "
               "print(secretos.cifrar(%r, 'feeds:ABUSEIPDB_KEY'))" % (str(LIB), TOKEN))
        otro = subprocess.run([sys.executable, "-c", cod], capture_output=True, text=True, env=self.env(),
                              timeout=60).stdout.strip()
        self.conf_token(otro)
        r = subprocess.run([sys.executable, "-c", self.ARNES % str(LIB)], capture_output=True, text=True,
                           env=self.env(), timeout=60)
        d = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual((d["ok"], d["urls"]), (False, []))
        self.assertIn("no se puede descifrar", r.stderr)


if __name__ == "__main__":
    unittest.main()
