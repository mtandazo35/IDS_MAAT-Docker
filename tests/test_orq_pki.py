"""PKI con openssl real (se omite si no hay openssl): CA común y certificado de servidor por punto."""

import shutil
import subprocess
import sys
import time
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
        # VPN-01: el nombre del VPS (connect-to del MikroTik) en el CN y en el SAN; el pid en el OU
        self.assertIn("Subject: OU=server-p003, CN=ids.empresa.example", texto.replace(" = ", "="))
        self.assertIn("DNS:ids.empresa.example", texto)
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

    def test_validos_desde_dos_dias_antes(self):
        """Corrección de defecto (revisión 2026-10-15, C3): un router con el reloj atrasado acepta la
        cadena. El certificado de servidor ya valía desde 2 días antes, pero la CA desde «ahora»: con
        el reloj un día atrás, la cadena fallaba por la CA."""
        _, crt = self.mod.cert_servidor("p003", "ids.empresa.example")
        ca = self.e.ruta("/srv/ids/pki/ca.crt")
        base = ["openssl", "verify", "-CAfile", str(ca), "-purpose", "sslserver",
                "-verify_hostname", "ids.empresa.example"]
        ayer = str(int(time.time()) - 86400)
        r = subprocess.run(base + ["-attime", ayer, str(crt)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        hace3 = str(int(time.time()) - 3 * 86400)                  # el margen es de 2 días, no más
        r = subprocess.run(base + ["-attime", hace3, str(crt)], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        texto = openssl("x509", "-in", str(ca), "-noout", "-text")
        self.assertIn("CA:TRUE", texto)
        self.assertIn("Certificate Sign, CRL Sign", texto)
        self.assertIn("Subject Key Identifier", texto)
        self.assertIn("Subject: CN=ids-maat-ca ids.empresa.example", texto.replace(" = ", "="))
        self.assertFalse(list(self.e.ruta("/srv/ids/pki").glob(".ca.*")))   # sin restos

    def test_lo_que_comprueba_el_mikrotik(self):
        """verify-server-certificate=yes: cadena hasta la CA importada, uso de servidor y el
        connect-to (NOMBRE_DNS) en el certificado. openssl verify con -purpose sslserver y
        -verify_hostname hace las mismas tres comprobaciones."""
        _, crt = self.mod.cert_servidor("p003", "ids.empresa.example")
        ca = self.e.ruta("/srv/ids/pki/ca.crt")
        base = ["openssl", "verify", "-CAfile", str(ca), "-purpose", "sslserver"]
        r = subprocess.run(base + ["-verify_hostname", "ids.empresa.example", str(crt)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = subprocess.run(base + ["-verify_hostname", "otro.example", str(crt)], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue(self.mod.cert_lleva_nombre(crt, "ids.empresa.example"))
        self.assertFalse(self.mod.cert_lleva_nombre(crt, "otro.example"))
        self.assertFalse(self.mod.cert_lleva_nombre(crt, "empresa.example"))       # sin coincidencias parciales
        # NOMBRE_DNS que es una IP: SAN IP (RouterOS: «The IP or hostname must be present»)
        _, crt_ip = self.mod.cert_servidor("p004", "203.0.113.5")
        self.assertIn("IP Address:203.0.113.5", openssl("x509", "-in", str(crt_ip), "-noout", "-text"))
        self.assertTrue(self.mod.cert_lleva_nombre(crt_ip, "203.0.113.5"))

    def test_certificado_de_antes_no_lleva_el_nombre(self):
        """Un certificado como los de antes de VPN-01 (CN=server-<pid>, sin SAN): cert_lleva_nombre
        lo detecta, que es lo que dispara la renovación en «Regenerar»."""
        self.mod.asegurar_ca("ids.empresa.example")
        pki = self.e.ruta("/srv/ids/pki")
        viejo = pki / "servidores" / "viejo.crt"
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
                "-keyout", str(pki / "servidores" / "viejo.key"), "-out", str(viejo), "-subj", "/CN=server-p009")
        self.assertFalse(self.mod.cert_lleva_nombre(viejo, "ids.empresa.example"))
        self.assertFalse(self.mod.cert_lleva_nombre(pki / "servidores" / "no-existe.crt", "ids.empresa.example"))

    def test_ca_para_el_mikrotik(self):
        """La CA real cabe en una cadena RouterOS (sin comillas, $, \\, [ ni ?) y por debajo del
        límite de /file set contents de v6; nunca sale una clave privada."""
        self.mod.asegurar_ca("ids.empresa.example")
        pem = self.mod.leer_ca_pem()
        self.assertTrue(pem.startswith("-----BEGIN CERTIFICATE-----"), pem[:40])
        self.assertLess(len(pem), 4000)
        txt = self.mod.lineas_ca_mikrotik("p003", pem)
        self.assertNotIn("PRIVATE", txt)
        for c in '$[?':
            self.assertNotIn(c, pem)
        with self.assertRaises(self.mod.ErrorOrden):
            self.mod.leer_ca_pem(self.e.ruta("/srv/ids/pki/ca.key"))

    def test_crear_copia_pki_al_punto(self):
        r = A.crear(self, self.orq, {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]})
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
