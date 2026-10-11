"""PKI con openssl real (se omite si no hay openssl): CA común y certificado de servidor por punto."""

import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402


def openssl(*args):
    return subprocess.run(["openssl"] + list(args), capture_output=True, text=True, check=True).stdout


@unittest.skipUnless(shutil.which("openssl"), "sin openssl")
class Pki(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(openssl_real=True)
        # dh ffdhe2048 es instantáneo; la CA y el servidor son RSA 2048 reales

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_ca_y_servidor(self):
        key, crt = self.mod.cert_servidor("p003", "ids.empresa.example")
        pki = self.e.ruta("/srv/ids/pki")
        ca = pki / "ca.crt"
        self.assertIn("CN=ids-maat-ca ids.empresa.example", openssl("x509", "-in", str(ca), "-noout", "-subject")
                      .replace(" = ", "="))
        texto = openssl("x509", "-in", str(crt), "-noout", "-text")
        self.assertIn("CN=server-p003", texto.replace(" = ", "="))
        self.assertIn("TLS Web Server Authentication", texto)
        self.assertIn("sha256WithRSAEncryption", texto)
        self.assertIn("Public-Key: (2048 bit)", texto)
        self.assertIn("CA:FALSE", texto)
        r = subprocess.run(["openssl", "verify", "-CAfile", str(ca), str(crt)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-----BEGIN DH PARAMETERS-----", (pki / "dh.pem").read_text(encoding="utf-8"))
        self.assertFalse(list((pki / "servidores").glob("*.csr")))
        # la CA no se regenera en el segundo punto
        antes = ca.read_bytes()
        self.mod.cert_servidor("p004", "ids.empresa.example")
        self.assertEqual(ca.read_bytes(), antes)
        self.mod.borrar_cert("p003")
        self.assertEqual(sorted(x.name for x in (pki / "servidores").iterdir()), ["p004.crt", "p004.key"])

    def test_crear_copia_pki_al_punto(self):
        r = A.ejecutar_orden(self.orq, "punto.crear", {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]})
        self.assertEqual(r["codigo"], "OK", r)
        vpn = self.e.ruta("/srv/ids/puntos/p001/vpn")
        self.assertEqual(sorted(x.name for x in vpn.iterdir()),
                         ["ca.crt", "ccd", "dh.pem", "server.conf", "server.crt", "server.key", "usuarios"])
        for f in vpn.iterdir():
            self.assertFalse(f.is_symlink(), f)        # copias, no enlaces
        self.assertEqual((vpn / "server.key").read_bytes(),
                         self.e.ruta("/srv/ids/pki/servidores/p001.key").read_bytes())


if __name__ == "__main__":
    unittest.main()
