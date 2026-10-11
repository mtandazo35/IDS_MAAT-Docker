"""fail2ban: el filtro ids-vpn casa con las líneas de §5.13 — tal cual y con el prefijo que añade el
backend systemd — solo en «ovpn-auth: rechazado» (una por intento fallido; «TLS Auth Error» es el
mismo intento y no cuenta), y la jaula SSH ve las líneas de sshd-session (Debian 13).

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

    def test_lineas_del_contrato(self):
        self.assertEqual(len(self.lineas), 6)
        resultados = [casa(self.r, x) for x in self.lineas]
        self.assertEqual(resultados, [None, None, "203.0.113.45", "203.0.113.45", None, None])

    def test_freno_global_no_banea_a_quien_lo_encuentra(self):
        # el freno global salta por la carga de todos: un MikroTik legitimo que reintenta no es culpable
        linea = "203.0.113.45:51234 ovpn-auth: rechazado usuario=- motivo=freno-global"
        self.assertIsNone(casa(self.r, linea))
        self.assertIsNone(casa(self.r, "ids ids-vpn[812]: " + linea))
        # el freno POR IP si cuenta (esa IP es la que insiste)
        self.assertEqual(casa(self.r, "203.0.113.45:51234 ovpn-auth: rechazado usuario=- motivo=freno"),
                         "203.0.113.45")

    def test_con_prefijo_del_backend_systemd(self):
        # formatJournalEntry: "<_HOSTNAME> <SYSLOG_IDENTIFIER>[<pid>]: <MESSAGE>"
        for prefijo in ("ids ids-vpn[812]: ", "ids-vpn[812]: ", "ids-vpn: "):
            resultados = [casa(self.r, prefijo + x) for x in self.lineas]
            self.assertEqual(resultados, [None, None, "203.0.113.45", "203.0.113.45", None, None], prefijo)

    def test_un_intento_fallido_cuenta_una_vez(self):
        # Lo que OpenVPN + ovpn-auth escriben por cada clave mala: con maxretry = 5 el ban llega al
        # 5.º intento, no al 3.º (antes casaban también «TLS Auth Error» y «TLS Error»).
        intento = ["203.0.113.45:51234 ovpn-auth: rechazado usuario=vpn3a9f2c motivo=clave",
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

    def test_ids_vpn_dos_de_seis(self):
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
