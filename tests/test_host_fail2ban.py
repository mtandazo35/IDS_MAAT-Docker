"""fail2ban: el filtro ids-vpn casa con las líneas de §5.13 — tal cual y con el prefijo que añade el
backend systemd — solo en «ovpn-auth: rechazado» con motivo=formato o motivo=usuario (una por
intento fallido de quien no conoce el usuario; «TLS Auth Error» es el mismo intento y no cuenta, y
la clave vieja del dueño tampoco: VPN-04), y la jaula SSH ve las líneas de sshd-session (Debian 13).

Sin fail2ban se emula su sustitución de <HOST> (la misma regex que usa fail2ban); con fail2ban
instalado (CI de Linux) se ejecuta además `fail2ban-regex` de verdad."""

import configparser
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
F2B = REPO / "host" / "fail2ban"
FIX = REPO / "tests" / "fixtures" / "orq"
# fail2ban/server/failregex.py: <HOST> = (?:::f{4,6}:)?(?P<host>[\w\-.^_]*\w)
HOST_RE = r"(?:::f{4,6}:)?(?P<host>[\w\-.^_]*\w)"


def leer_ini(path):
    cp = configparser.RawConfigParser(strict=False)
    cp.optionxform = str
    cp.read_string(Path(path).read_text(encoding="utf-8"))
    return cp


def regex_filtro():
    cp = leer_ini(F2B / "filter.d" / "ids-vpn.conf")
    d = dict(cp.items("Definition"))
    out = []
    for linea in [x.strip() for x in d["failregex"].splitlines() if x.strip()]:
        linea = re.sub(r"%\((\w+)\)s", lambda m: d[m.group(1)], linea)
        out.append(re.compile(linea.replace("<HOST>", HOST_RE)))
    return out


def regex_ignorar():
    cp = leer_ini(F2B / "filter.d" / "ids-vpn.conf")
    d = dict(cp.items("Definition"))
    return [re.compile(x.strip()) for x in (d.get("ignoreregex") or "").splitlines() if x.strip()]


def casa(regexes, linea):
    # como fail2ban: una linea que casa con ignoreregex no cuenta aunque case con failregex
    if any(r.search(linea) for r in regex_ignorar()):
        return None
    for r in regexes:
        m = r.search(linea)
        if m:
            return m.group("host")
    return None


class FiltroIdsVpn(unittest.TestCase):
    def setUp(self):
        self.r = regex_filtro()
        self.lineas = (FIX / "ids-vpn.log").read_text(encoding="utf-8").splitlines()

    # De las 8 líneas del contrato (§5.13) solo banean la 5.ª (formato) y la 6.ª (usuario desconocido)
    ESPERADO = [None, None, None, None, "203.0.113.45", "203.0.113.45", None, None]

    def test_lineas_del_contrato(self):
        self.assertEqual(len(self.lineas), 8)
        resultados = [casa(self.r, x) for x in self.lineas]
        self.assertEqual(resultados, self.ESPERADO)

    def test_clave_y_frenos_no_banean_al_duenio_del_usuario(self):
        # VPN-04: tras «Regenerar la clave VPN» el MikroTik reintenta con la vieja (motivo=clave y,
        # tras 5, motivo=freno): no se banea su IP (cortaba todos los puertos). El freno global
        # salta por la carga de todos.
        for motivo in ("usuario=vpn3a9f2c motivo=clave", "usuario=- motivo=freno", "usuario=- motivo=freno-global"):
            linea = "203.0.113.45:51234 ovpn-auth: rechazado " + motivo
            self.assertIsNone(casa(self.r, linea), linea)
            self.assertIsNone(casa(self.r, "ids ids-vpn[812]: " + linea), linea)
        # lo de un escáner (no conoce el usuario) sí
        for motivo in ("usuario=- motivo=formato", "usuario=vpn000000 motivo=usuario"):
            linea = "203.0.113.45:51234 ovpn-auth: rechazado " + motivo
            self.assertEqual(casa(self.r, "ids ids-vpn[812]: " + linea), "203.0.113.45", linea)
        # ni un motivo que solo empieza igual
        self.assertIsNone(casa(self.r, "203.0.113.45:51234 ovpn-auth: rechazado usuario=- motivo=formatox"))

    def test_con_prefijo_del_backend_systemd(self):
        # formatJournalEntry: "<_HOSTNAME> <SYSLOG_IDENTIFIER>[<pid>]: <MESSAGE>"
        for prefijo in ("ids ids-vpn[812]: ", "ids-vpn[812]: ", "ids-vpn: "):
            resultados = [casa(self.r, prefijo + x) for x in self.lineas]
            self.assertEqual(resultados, self.ESPERADO, prefijo)

    def test_router_con_la_clave_vieja_nunca_se_banea(self):
        """Las líneas de verdad de ovpn-auth: un MikroTik que reintenta 60 veces en 10 min con la
        clave vieja no suma ni un fallo; un escáner con usuarios inventados se banea al 5.º."""
        sys.path.insert(0, str(REPO / "tests"))
        import _ayuda_vpn as ay
        auth = ay.cargar(ay.BIN / "ovpn-auth", "ids_vpn_ovpn_auth_f2b")
        d = Path(tempfile.mkdtemp(prefix="f2b-auth-"))
        try:
            auth.RUTA_USUARIOS = str(d / "usuarios")
            auth.DIR_FRENO = str(d / "freno")
            auth.FRENO_LOCK = str(d / "freno" / "freno.lock")
            auth.FRENO_JSON = str(d / "freno" / "freno.json")
            Path(auth.RUTA_USUARIOS).write_text("vpn3a9f2c:scrypt$2$1$1$%s$%s\n" % ("00" * 16, "00" * 32),
                                                encoding="utf-8")
            t = [1760090000.0]
            auth.ahora = lambda: t[0]
            cred = d / "cred"

            def fallos(usuario, veces, ip):
                n = 0
                for _ in range(veces):
                    cred.write_text("%s\nclave-vieja-123\n" % usuario, encoding="utf-8")
                    _, linea = auth.autenticar(str(cred), {"untrusted_ip": ip, "untrusted_port": "51234"})
                    n += casa(self.r, "ids ids-vpn[812]: " + linea) is not None
                    t[0] += 10
                return n

            self.assertEqual(fallos("vpn3a9f2c", 60, "203.0.113.45"), 0)
            self.assertEqual(fallos("vpn00beef", 5, "198.51.100.9"), 5)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_un_intento_fallido_cuenta_una_vez(self):
        # Lo que OpenVPN + ovpn-auth escriben por cada intento de un escáner: con maxretry = 5 el ban
        # llega al 5.º intento, no al 3.º (antes casaban también «TLS Auth Error» y «TLS Error»).
        intento = ["203.0.113.45:51234 ovpn-auth: rechazado usuario=vpn000000 motivo=usuario",
                   "203.0.113.45:51234 TLS Auth Error: Auth Username/Password verification failed for peer",
                   "203.0.113.45:51234 TLS Error: TLS handshake failed"]
        maxretry = int(Jaula.leer_jaula()["DEFAULT"]["maxretry"])
        for n in range(1, 6):
            fallos = sum(1 for _ in range(n) for x in intento if casa(self.r, "ids ids-vpn[812]: " + x))
            self.assertEqual(fallos, n)
            self.assertEqual(fallos >= maxretry, n >= 5, n)

    def test_no_se_puede_inyectar_otra_ip(self):
        # texto de un cliente dentro de una línea de OpenVPN no puede banear otra IP (regex anclada)
        for linea in ("203.0.113.45:51234 peer info: IV_GUI_VER=x 192.0.2.10:1 TLS Auth Error:",
                      "ids ids-vpn[1]: 203.0.113.45:51234 peer info: x 192.0.2.10:1 ovpn-auth: rechazado",
                      "otro-servicio[3]: 192.0.2.10:1 TLS Auth Error:"):
            self.assertIsNone(casa(self.r, linea), linea)


class Jaula(unittest.TestCase):
    @staticmethod
    def leer_jaula():
        txt = (F2B / "jail.d" / "10-ids.local.tmpl").read_text(encoding="utf-8")
        cp = configparser.RawConfigParser(strict=False, inline_comment_prefixes=None)
        cp.optionxform = str
        cp.read_string(txt.replace("@@IGNOREIP_DUENO@@", "203.0.113.20"))
        return cp

    def setUp(self):
        self.cp = self.leer_jaula()

    def test_jaulas(self):
        d = self.cp["DEFAULT"]
        self.assertEqual(d["backend"], "systemd")
        self.assertEqual(d["ignoreip"].split(), ["127.0.0.1/8", "::1", "203.0.113.20"])
        self.assertEqual((d["bantime"], d["findtime"], d["maxretry"]), ("1h", "10m", "5"))
        s = self.cp["sshd"]
        self.assertEqual((s["enabled"], s["mode"], s["journalmatch"]), ("true", "aggressive",
                                                                       "_SYSTEMD_UNIT=ssh.service"))
        v = self.cp["ids-vpn"]
        self.assertEqual((v["enabled"], v["filter"], v["journalmatch"]), ("true", "ids-vpn", "CONTAINER_TAG=ids-vpn"))
        self.assertEqual(v["banaction"], "nftables[type=allports, chain_hook=forward]")
        self.assertNotEqual(v.get("chain"), "f2b-chain")

    def test_sshd_session(self):
        cp = leer_ini(F2B / "filter.d" / "sshd.local.tmpl")
        daemon = cp["DEFAULT"]["_daemon"]
        for ident in ("sshd", "sshd-session"):
            self.assertTrue(re.fullmatch(daemon, ident), ident)
        self.assertFalse(re.fullmatch(daemon, "sshd-sessionx"))
        # las líneas de sshd-session del fixture llevan el identificador que se admite
        for linea in (FIX / "sshd-session.log").read_text(encoding="utf-8").splitlines():
            ident = linea.split()[2].split("[")[0]
            self.assertTrue(re.fullmatch(daemon, ident), linea)


F2B_REGEX = shutil.which("fail2ban-regex")


@unittest.skipUnless(F2B_REGEX and sys.platform.startswith("linux"), "sin fail2ban-regex")
class Fail2banReal(unittest.TestCase):
    def contar(self, lineas, filtro, extra=()):
        r = subprocess.run([F2B_REGEX] + list(extra) + [str(lineas), str(filtro)], capture_output=True, text=True)
        m = re.search(r"^Lines: .* (\d+) matched", r.stdout, re.M)
        self.assertIsNotNone(m, r.stdout + r.stderr)
        return int(m.group(1))

    def test_ids_vpn_dos_de_ocho(self):
        self.assertEqual(self.contar(FIX / "ids-vpn.log", F2B / "filter.d" / "ids-vpn.conf", ["-d", "{NONE}"]), 2)

    def test_ids_vpn_con_prefijo_journal(self):
        d = Path(tempfile.mkdtemp(prefix="f2b-"))
        try:
            f = d / "journal.log"
            f.write_text("".join("ids ids-vpn[812]: " + x + "\n"
                                 for x in (FIX / "ids-vpn.log").read_text(encoding="utf-8").splitlines()),
                         encoding="utf-8")
            self.assertEqual(self.contar(f, F2B / "filter.d" / "ids-vpn.conf", ["-d", "{NONE}"]), 2)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    @unittest.skipUnless(Path("/etc/fail2ban/filter.d/sshd.conf").exists(), "sin el filtro sshd del sistema")
    def test_sshd_session_con_sshd_local(self):
        d = Path(tempfile.mkdtemp(prefix="f2b-"))
        try:
            shutil.copytree("/etc/fail2ban/filter.d", d / "filter.d")
            shutil.copyfile(F2B / "filter.d" / "sshd.local.tmpl", d / "filter.d" / "sshd.local")
            n = self.contar(FIX / "sshd-session.log", d / "filter.d" / "sshd.conf")
            self.assertGreaterEqual(n, 3)       # Invalid user / Failed password ×2 (sin el Accepted)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
