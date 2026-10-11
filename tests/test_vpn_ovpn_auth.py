"""ovpn-auth: hash de §4.5, freno ANTES de scrypt (§5.6) y líneas de log de §5.13."""
import contextlib
import hashlib
import io
import os
import re
import secrets
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_vpn as ay  # noqa: E402

USUARIO = "vpn3a9f2c"
CLAVE = "Kq3ZtV9xLm2PwR7sYb4NcD8e"      # 24 de [A-Za-z0-9], como las que genera C
IP = "203.0.113.45"
PUERTO = "51234"

# Filtro de fail2ban de §5.13, con <HOST> como lo expande fail2ban para IPv4.
FAILREGEX = [r"^<HOST>:\d+ TLS Auth Error:",
             r"^<HOST>:\d+ TLS Error: TLS handshake failed",
             r"^<HOST>:\d+ ovpn-auth: rechazado"]
HOST = r"(?P<host>\d{1,3}(?:\.\d{1,3}){3})"


def casa_fail2ban(linea):
    for r in FAILREGEX:
        m = re.search(r.replace("<HOST>", HOST), linea)
        if m:
            return m.group("host")
    return None


def linea_usuarios(usuario, clave, sal=None):
    """Línea del fichero `usuarios` según §4.5, implementada aquí (no con el código probado)."""
    sal = secrets.token_bytes(16) if sal is None else sal
    h = hashlib.scrypt(clave.encode("utf-8"), salt=sal, n=16384, r=8, p=1, dklen=32)
    return f"{usuario}:scrypt$16384$8$1${sal.hex()}${h.hex()}"


class Base(unittest.TestCase):
    """Cada prueba carga ovpn-auth de nuevo, con rutas y reloj en un directorio temporal."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        d = Path(self.dir.name)
        self.mod = ay.cargar(ay.BIN / "ovpn-auth", "ids_vpn_ovpn_auth")
        self.mod.RUTA_USUARIOS = str(d / "usuarios")
        self.mod.DIR_FRENO = str(d / "freno")
        self.mod.FRENO_LOCK = str(d / "freno" / "freno.lock")
        self.mod.FRENO_JSON = str(d / "freno" / "freno.json")
        self.t = 1760090000.0
        self.mod.ahora = lambda: self.t
        (d / "usuarios").write_text(
            "# ids-maat p003 — generado por ids-orq; no editar\n\n"
            + linea_usuarios(USUARIO, CLAVE) + "\n", encoding="utf-8")
        self.cred = d / "cred"
        # contador de scrypt: envuelve el real para poder contar cuántas veces se calcula
        self.real_scrypt = hashlib.scrypt
        self.llamadas = 0

        def contador(*a, **k):
            self.llamadas += 1
            return self.real_scrypt(*a, **k)
        p = mock.patch.object(self.mod.hashlib, "scrypt", side_effect=contador)
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        self.dir.cleanup()

    def intento(self, usuario=USUARIO, clave=CLAVE, ip=IP, puerto=PUERTO, crudo=None):
        """Llama a main() como OpenVPN: fichero de 2 líneas y entorno. Devuelve (rc, línea)."""
        if crudo is None:
            crudo = f"{usuario}\n{clave}\n".encode("utf-8")
        self.cred.write_bytes(crudo)
        env = {"untrusted_ip": ip, "untrusted_port": puerto, "username": "ignorado"}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = self.mod.main([str(self.cred)], env)
        # además de la línea del resultado puede haber avisos propios ("ovpn-auth: aviso: ..."),
        # que no empiezan por IP y fail2ban no casa
        lineas = [l for l in err.getvalue().splitlines() if not l.startswith("ovpn-auth: aviso: ")]
        self.assertEqual(len(lineas), 1, lineas)
        return rc, lineas[0]


class Verificacion(Base):
    def test_clave_buena(self):
        rc, l = self.intento()
        self.assertEqual(rc, 0)
        self.assertEqual(l, f"{IP}:{PUERTO} ovpn-auth: aceptado usuario={USUARIO}")
        self.assertEqual(self.llamadas, 1)

    def test_clave_mala(self):
        rc, l = self.intento(clave=CLAVE[:-1] + "X")
        self.assertEqual(rc, 1)
        self.assertEqual(l, f"{IP}:{PUERTO} ovpn-auth: rechazado usuario={USUARIO} motivo=clave")
        self.assertEqual(self.llamadas, 1)

    def test_parametros_de_la_linea(self):
        # se usan N/r/p de la línea, no unos fijos
        sal = bytes(range(16))
        h = self.real_scrypt(b"otra", salt=sal, n=1024, r=4, p=2, dklen=32)
        Path(self.mod.RUTA_USUARIOS).write_text(
            f"vpn000001:scrypt$1024$4$2${sal.hex()}${h.hex()}\n", encoding="utf-8")
        self.assertEqual(self.intento("vpn000001", "otra")[0], 0)
        self.assertEqual(self.intento("vpn000001", "otrA")[0], 1)

    def test_usuario_inexistente_sin_scrypt(self):
        rc, l = self.intento(usuario="vpn000000")
        self.assertEqual(rc, 1)
        self.assertEqual(l, f"{IP}:{PUERTO} ovpn-auth: rechazado usuario=vpn000000 motivo=usuario")
        self.assertEqual(self.llamadas, 0)

    def test_linea_mal_formada_es_usuario_inexistente(self):
        Path(self.mod.RUTA_USUARIOS).write_text(f"{USUARIO}:scrypt$16384$8$1$zz$zz\n",
                                                encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(self.mod.buscar_usuario(USUARIO))
        self.assertEqual(self.llamadas, 0)

    def test_parametros_desorbitados_no_se_calculan(self):
        sal, h = "00" * 16, "00" * 32
        for linea in (f"{USUARIO}:scrypt$4194304$8$1${sal}${h}",     # N > 2^20
                      f"{USUARIO}:scrypt$16000$8$1${sal}${h}",       # N no potencia de 2
                      f"{USUARIO}:scrypt$16384$64$1${sal}${h}"):     # r > 32
            with self.subTest(linea=linea):
                Path(self.mod.RUTA_USUARIOS).write_text(linea + "\n", encoding="utf-8")
                rc, l = self.intento()
                self.assertTrue(l.endswith("motivo=usuario"), l)
        self.assertEqual(self.llamadas, 0)

    def test_formato_malo_sin_scrypt_y_sin_texto_del_atacante(self):
        casos = {
            "usuario raro": (f"{USUARIO}\n{CLAVE}\n".replace(USUARIO, "admin';--")).encode(),
            "usuario con mayúsculas": f"VPN3A9F2C\n{CLAVE}\n".encode(),
            "usuario con texto añadido": f"{USUARIO} motivo=x\n{CLAVE}\n".encode(),
            "clave vacía": f"{USUARIO}\n\n".encode(),
            "clave de 129": f"{USUARIO}\n{'a' * 129}\n".encode(),
            "clave con control": f"{USUARIO}\nab\x07cd\n".encode(),
            "clave no ASCII": f"{USUARIO}\nclaveñ\n".encode("utf-8"),
            "una sola línea": f"{USUARIO}".encode(),
            "no UTF-8": b"\xff\xfe\n\xff\n",
            "vacío": b"",
        }
        for nombre, crudo in casos.items():
            with self.subTest(nombre):
                rc, l = self.intento(crudo=crudo)
                self.assertEqual(rc, 1)
                self.assertEqual(l, f"{IP}:{PUERTO} ovpn-auth: rechazado usuario=- motivo=formato")
        self.assertEqual(self.llamadas, 0)

    def test_clave_de_128_imprimibles_es_formato_valido(self):
        rc, l = self.intento(clave="a b~" * 32)
        self.assertTrue(l.endswith("motivo=clave"), l)

    def test_crlf_se_tolera(self):
        rc, _ = self.intento(crudo=f"{USUARIO}\r\n{CLAVE}\r\n".encode())
        self.assertEqual(rc, 0)

    def test_sin_fichero(self):
        # sin argumento
        with contextlib.redirect_stderr(io.StringIO()) as err:
            rc = self.mod.main([], {"untrusted_ip": IP, "untrusted_port": PUERTO})
        self.assertEqual(rc, 1)
        self.assertEqual(err.getvalue().strip(),
                         f"{IP}:{PUERTO} ovpn-auth: rechazado usuario=- motivo=formato")
        # con un fichero que no existe
        with contextlib.redirect_stderr(io.StringIO()) as err:
            rc = self.mod.main([str(self.cred) + ".no"], {"untrusted_ip": IP, "untrusted_port": PUERTO})
        self.assertEqual(rc, 1)
        self.assertEqual(err.getvalue().strip(),
                         f"{IP}:{PUERTO} ovpn-auth: rechazado usuario=- motivo=formato")
        self.assertEqual(self.llamadas, 0)

    def test_ip_del_entorno_invalida_no_se_escribe(self):
        rc, l = self.intento(ip="1.2.3.4 ovpn-auth: rechazado", puerto="x")
        self.assertTrue(l.startswith("-:- ovpn-auth: "), l)
        self.assertIsNone(casa_fail2ban(l))


class Freno(Base):
    def test_freno_por_ip_no_llama_a_scrypt(self):
        for _ in range(5):
            self.assertTrue(self.intento(clave="mala")[1].endswith("motivo=clave"))
        self.assertEqual(self.llamadas, 5)
        # 6.º intento, aunque traiga la clave BUENA: rechazo inmediato sin scrypt
        rc, l = self.intento()
        self.assertEqual(rc, 1)
        self.assertEqual(l, f"{IP}:{PUERTO} ovpn-auth: rechazado usuario=- motivo=freno")
        self.assertEqual(self.llamadas, 5)
        # otra IP no está frenada
        rc, l = self.intento(ip="198.51.100.7")
        self.assertEqual(rc, 0)

    def test_rechazos_sin_scrypt_tambien_cuentan(self):
        for _ in range(3):
            self.intento(usuario="vpn000000")
        for _ in range(2):
            self.intento(crudo=b"basura")
        self.assertTrue(self.intento()[1].endswith("motivo=freno"))
        self.assertEqual(self.llamadas, 0)

    def test_freno_caduca_a_los_600s(self):
        for _ in range(5):
            self.intento(clave="mala")
        self.t += 599
        self.assertTrue(self.intento()[1].endswith("motivo=freno"))
        # los rechazos por freno no alargan el castigo: a los 600 s del último intento real
        self.t += 2
        rc, l = self.intento()
        self.assertEqual(rc, 0, l)

    def test_cuatro_rechazos_no_frenan(self):
        for _ in range(4):
            self.intento(clave="mala")
        self.assertEqual(self.intento()[0], 0)

    def test_freno_global_no_llama_a_scrypt(self):
        for i in range(30):
            rc, _ = self.intento(ip=f"192.0.2.{i + 1}")
            self.assertEqual(rc, 0)
        self.assertEqual(self.llamadas, 30)
        rc, l = self.intento(ip="198.51.100.9")
        self.assertEqual(rc, 1)
        self.assertEqual(l, "198.51.100.9:51234 ovpn-auth: rechazado usuario=- motivo=freno-global")
        self.assertEqual(self.llamadas, 30)
        # el freno global no se cuenta como rechazo de la IP
        self.t += 61
        self.assertEqual(self.intento(ip="198.51.100.9")[0], 0)
        self.assertEqual(self.llamadas, 31)

    def test_freno_va_antes_que_el_usuario(self):
        for _ in range(5):
            self.intento(clave="mala")
        rc, l = self.intento(usuario="vpn000000")
        self.assertTrue(l.endswith("motivo=freno"), l)

    def test_formato_va_antes_que_el_freno(self):
        for _ in range(5):
            self.intento(clave="mala")
        self.assertTrue(self.intento(crudo=b"x")[1].endswith("motivo=formato"))

    def test_estado_corrupto_se_reinicia(self):
        os.makedirs(self.mod.DIR_FRENO, exist_ok=True)
        Path(self.mod.FRENO_JSON).write_text("{no es json", encoding="utf-8")
        self.assertEqual(self.intento()[0], 0)

    def test_estado_acotado(self):
        # los rechazos por formato se apuntan siempre (van antes del freno): la lista de una
        # IP no crece sin límite
        for _ in range(40):
            self.intento(crudo=b"x")
            self.t += 1
        est = self.mod.leer_estado()
        self.assertEqual(list(est["rechazos"]), [IP])
        self.assertLessEqual(len(est["rechazos"][IP]), 2 * self.mod.FRENO_IP_MAX)


class Log(Base):
    def test_lineas_y_fail2ban(self):
        rc_ok, ok = self.intento()
        _, clave = self.intento(clave="mala")
        _, formato = self.intento(crudo=b"x\n")
        _, usuario = self.intento(usuario="vpn000000")
        for _ in range(2):
            self.intento(clave="mala")
        _, freno = self.intento()
        self.assertEqual(ok, "203.0.113.45:51234 ovpn-auth: aceptado usuario=vpn3a9f2c")
        self.assertEqual(clave, "203.0.113.45:51234 ovpn-auth: rechazado usuario=vpn3a9f2c motivo=clave")
        self.assertEqual(formato, "203.0.113.45:51234 ovpn-auth: rechazado usuario=- motivo=formato")
        self.assertEqual(freno, "203.0.113.45:51234 ovpn-auth: rechazado usuario=- motivo=freno")
        for l in (clave, formato, usuario, freno):
            self.assertEqual(casa_fail2ban(l), IP, l)
        self.assertIsNone(casa_fail2ban(ok))
        # las mismas líneas que el contrato fija en §5.13 (fixture copiado de allí)
        fixture = (ay.FIXTURES / "ids-vpn.log").read_text(encoding="utf-8").splitlines()
        self.assertIn(clave, fixture)
        self.assertIn(freno, fixture)
        self.assertIn(ok, fixture)

    def test_fixture_del_contrato_casa_como_dice_513(self):
        fixture = (ay.FIXTURES / "ids-vpn.log").read_text(encoding="utf-8").splitlines()
        self.assertEqual([casa_fail2ban(l) is not None for l in fixture],
                         [True, True, True, True, False, False])


if __name__ == "__main__":
    unittest.main()
