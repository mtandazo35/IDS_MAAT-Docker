"""render.py: validación del entorno (CONTRATO-F1a §4.1) y texto exacto de las tablas (§4.7)."""
import io
import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_vpn as ay  # noqa: E402

render = ay.cargar(ay.RENDER, "ids_vpn_render")


def entorno(**cambios):
    env = dict(ay.ENTORNO_BUENO)
    for k, v in cambios.items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = v
    return env


class Validacion(unittest.TestCase):
    def test_entorno_bueno(self):
        cfg = render.validar(entorno())
        self.assertEqual(cfg["punto"], "p003")
        self.assertEqual(cfg["n"], 3)
        self.assertEqual(str(cfg["tun_mk"]), "100.64.3.2")
        self.assertEqual(cfg["api_puerto"], 8729)
        self.assertEqual(cfg["tzsp_puerto"], 37008)
        self.assertEqual(cfg["tzsp_bytes"], 10000)

    def test_base_198_18_y_n_12(self):
        cfg = render.validar(entorno(N="12", TUN_NET="198.18.12.0/24", TUN_SENSOR="198.18.12.1",
                                     TUN_MK="198.18.12.2"))
        self.assertEqual(cfg["n"], 12)

    def test_valores_buenos_limite(self):
        for cambios in ({"N": "1"}, {"N": "250"}, {"API_PUERTO": "8728"}, {"TZSP_PUERTO": "1"},
                        {"TZSP_PUERTO": "65535"}, {"TZSP_BYTES": "0"}, {"PUNTO": "p999"},
                        {"PUNTO": "p000"}, {"TZ": None}):
            with self.subTest(cambios=cambios):
                render.validar(entorno(**cambios))

    def test_valores_malos(self):
        malos = {
            "PUNTO": ["", "p3", "p0003", "P003", "p00a", "p003 ", "x003", "p003\n"],
            "N": ["", "0", "251", "-1", "3.0", "tres", " 3", "+3", "03"],
            "TUN_NET": ["", "100.64.3.0", "100.64.3.0/25", "100.64.3.0/16", "100.64.3.1/24",
                        "100.64.3.0/024", "fd00::/24", "100.64.3.0/24 "],
            "TUN_SENSOR": ["", "100.64.3.2", "100.64.4.1", "100.64.3.01", "x"],
            "TUN_MK": ["", "100.64.3.1", "100.64.3.3", "100.64.4.2", "192.0.2.2", "100.64.3.02"],
            "API_PUERTO": ["", "0", "70000", "08729", "8729 "],   # cualquier puerto 1-65535 desde 2026-10-20
            "TZSP_PUERTO": ["", "0", "65536", "-1", "x", "37008/udp"],
            "TZSP_BYTES": ["", "-1", "1e4", "10k", "10 000"],
        }
        for var, valores in malos.items():
            for v in valores:
                with self.subTest(var=var, valor=v):
                    with self.assertRaises(render.ErrorEntorno) as cm:
                        render.validar(entorno(**{var: v}))
                    self.assertIn(var, str(cm.exception))
            with self.subTest(var=var, valor="(ausente)"):
                with self.assertRaises(render.ErrorEntorno):
                    render.validar(entorno(**{var: None}))

    def test_tun_mk_fuera_de_tun_net(self):
        with self.assertRaises(render.ErrorEntorno) as cm:
            render.validar(entorno(TUN_MK="100.64.9.2"))
        self.assertIn("TUN_MK", str(cm.exception))
        self.assertIn("100.64.3.0/24", str(cm.exception))


class TextoNft(unittest.TestCase):
    def test_ids_punto_exacto(self):
        esperado = (ay.FIXTURES / "ids_punto_p003.nft").read_text(encoding="utf-8")
        self.assertEqual(render.nft_punto(render.validar(entorno())), esperado)

    def test_ids_punto_usa_el_entorno(self):
        txt = render.nft_punto(render.validar(entorno(
            N="12", TUN_NET="198.18.12.0/24", TUN_SENSOR="198.18.12.1", TUN_MK="198.18.12.2",
            API_PUERTO="8728", TZSP_PUERTO="40000")))
        self.assertIn('iifname "tun0" ip saddr 198.18.12.2 udp dport 40000 counter accept', txt)
        # API_PUERTO=8728 es el mismo puerto del relé claro: una sola regla, sin conjunto
        self.assertIn('oifname "tun0" ip daddr 198.18.12.2 tcp dport 8728 accept', txt)
        self.assertNotIn("dport {", txt)
        self.assertNotIn("100.64", txt)
        self.assertNotIn("8729", txt)
        self.assertNotIn("flush", txt)

    def test_ids_mon_exacto(self):
        esperado = (ay.FIXTURES / "ids_mon.nft").read_text(encoding="utf-8")
        self.assertEqual(render.nft_mon(), esperado)


DIRECTO = {"MODO": "directo", "MK_IP": "192.168.88.1"}


class Directo(unittest.TestCase):
    """Punto directo (sin VPN, solo LAN; el user, 2026-10-18): el MikroTik manda el espejo y atiende
    la API en su IP de la LAN."""

    def test_entorno_directo(self):
        cfg = render.validar(entorno(**DIRECTO))
        self.assertEqual(cfg["modo"], "directo")
        self.assertEqual(str(cfg["mk_ip"]), "192.168.88.1")

    def test_sin_modo_es_vpn(self):
        """Los compose de antes no traen MODO: siguen siendo puntos con VPN."""
        cfg = render.validar(entorno())
        self.assertEqual(cfg["modo"], "vpn")
        self.assertIsNone(cfg["mk_ip"])
        self.assertEqual(render.nft_punto(cfg), (ay.FIXTURES / "ids_punto_p003.nft").read_text(encoding="utf-8"))

    def test_ips_de_lan_validas(self):
        for ip in ("10.0.0.1", "172.16.5.9", "172.31.255.254", "192.168.1.1", "100.100.0.1"):
            with self.subTest(ip=ip):
                render.validar(entorno(MODO="directo", MK_IP=ip))

    def test_ips_malas(self):
        """Solo LAN: una IP publica, la del tunel del punto o algo que no es una IP, fuera."""
        for ip, txt in (("8.8.8.8", "privada"), ("203.0.113.5", "privada"), ("172.32.0.1", "privada"),
                        ("100.64.3.5", "TUN_NET"), ("", "MK_IP"), ("192.168.1.01", "MK_IP"),
                        ("192.168.1.0/24", "MK_IP")):
            with self.subTest(ip=ip):
                with self.assertRaises(render.ErrorEntorno) as cm:
                    render.validar(entorno(MODO="directo", MK_IP=ip))
                self.assertIn(txt, str(cm.exception))
        with self.assertRaises(render.ErrorEntorno):
            render.validar(entorno(MODO="directo", MK_IP=None))

    def test_modo_malo_y_mk_ip_sin_directo(self):
        with self.assertRaises(render.ErrorEntorno) as cm:
            render.validar(entorno(MODO="lan"))
        self.assertIn("MODO", str(cm.exception))
        with self.assertRaises(render.ErrorEntorno) as cm:
            render.validar(entorno(MK_IP="192.168.88.1"))
        self.assertIn("MK_IP", str(cm.exception))

    def test_nft_directo_exacto(self):
        esperado = (ay.FIXTURES / "ids_punto_p003_directo.nft").read_text(encoding="utf-8")
        self.assertEqual(render.nft_punto(render.validar(entorno(**DIRECTO))), esperado)

    def test_nft_directo_sin_tun0_ni_openvpn(self):
        txt = render.nft_punto(render.validar(entorno(API_PUERTO="8728", TZSP_PUERTO="40000", **DIRECTO)))
        # el espejo entra desde cualquier IP (2026-10-20); la API sigue saliendo solo hacia el MikroTik
        self.assertIn('iifname "eth0" udp dport 40000 counter accept', txt)
        self.assertNotIn("ip saddr", txt)
        self.assertIn('oifname "eth0" ip daddr 192.168.88.1 tcp dport 8728 accept', txt)
        for nada in ("tun0", "1194", "100.64", "flush"):
            self.assertNotIn(nada, txt)

    def test_cli_validar_dice_directo(self):
        p = subprocess.run([sys.executable, str(ay.RENDER), "validar"],
                           env={**os.environ, **entorno(**DIRECTO), "PYTHONUTF8": "1"},
                           capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("directo, MikroTik 192.168.88.1", p.stderr)


class ApiClaro(unittest.TestCase):
    """2026-10-20 (el dueño: «si no tiene certificado lo creas»): el relé fijo rele-api-claro va al
    8728, la API normal, para que «Probar la conexión» cree el certificado de la API-SSL. La salida
    hacia el MikroTik abre el puerto del punto y el 8728, con VPN y en directo."""

    REGLAS = (
        ({}, '    oifname "tun0" ip daddr 100.64.3.2 %s accept comment "API via rele"\n'),
        (DIRECTO, '    oifname "eth0" ip daddr 192.168.88.1 %s accept comment "API via rele (directo)"\n'),
    )

    def test_puerto_del_punto_y_8728(self):
        """Conjunto en orden ascendente (numérico: 10000 va después de 8728) y un solo puerto si son
        el mismo."""
        for puerto, dport in (("8729", "tcp dport { 8728, 8729 }"), ("8728", "tcp dport 8728"),
                              ("2290", "tcp dport { 2290, 8728 }"), ("10000", "tcp dport { 8728, 10000 }")):
            for modo, regla in self.REGLAS:
                with self.subTest(puerto=puerto, modo=modo.get("MODO", "vpn")):
                    txt = render.nft_punto(render.validar(entorno(API_PUERTO=puerto, **modo)))
                    self.assertIn(regla % dport, txt)
                    self.assertEqual(sum("API via rele" in l for l in txt.splitlines()), 1)

    def test_solo_hacia_el_mikrotik(self):
        """El 8728 tampoco abre la salida a otro destino: la regla sigue atada a la IP del MikroTik."""
        for modo, _ in self.REGLAS:
            with self.subTest(modo=modo.get("MODO", "vpn")):
                txt = render.nft_punto(render.validar(entorno(**modo)))
                salida = txt.split("chain output", 1)[1]
                lineas = [l for l in salida.splitlines() if "8728" in l]
                self.assertEqual(len(lineas), 1, lineas)
                self.assertIn("ip daddr ", lineas[0])


# Lo que imprime `nft list table` (nftables 1.1) de las tablas de los fixtures: otra forma,
# comillas en iif/oif y contadores. test_vpn_arranque.sh lo compara con ay.comparar_nft.
LISTADO_PUNTO = """table inet ids_punto {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tiif "lo" accept
\t\tct state established,related accept
\t\tiifname "eth0" tcp dport 1194 accept comment "OpenVPN (DNAT del host)"
\t\tiifname "tun0" ip saddr 100.64.3.2 udp dport 37008 counter packets 12 bytes 3456 accept comment "espejo TZSP"
\t\tiifname "tun0" ip saddr 100.64.3.2 icmp type echo-request limit rate 5/second accept comment "ping del MikroTik"
\t\tcounter packets 0 bytes 0 comment "resto"
\t}

\tchain output {
\t\ttype filter hook output priority filter; policy drop;
\t\toif "lo" accept
\t\tct state established,related accept
\t\toifname "tun0" ip daddr 100.64.3.2 tcp dport { 8728, 8729 } accept comment "API via rele"
\t\tcounter packets 0 bytes 0 comment "resto"
\t}

\tchain forward {
\t\ttype filter hook forward priority filter; policy drop;
\t}
}
"""
LISTADO_MON = """table netdev ids_mon {
\tchain ingreso {
\t\ttype filter hook ingress device "ids-mon" priority -500; policy drop;
\t}
}
"""


class CompararNft(unittest.TestCase):
    def setUp(self):
        self.punto = (ay.FIXTURES / "ids_punto_p003.nft").read_text(encoding="utf-8")

    def test_listado_igual_al_cargado(self):
        self.assertIsNone(ay.comparar_nft(self.punto, LISTADO_PUNTO))
        mon = (ay.FIXTURES / "ids_mon.nft").read_text(encoding="utf-8")
        self.assertIsNone(ay.comparar_nft(mon, LISTADO_MON))

    def test_tabla_ausente(self):
        dif = ay.comparar_nft(self.punto, "Error: No such file or directory\n")
        self.assertIsNotNone(dif)
        self.assertIsNotNone(ay.comparar_nft(self.punto, ""))
        self.assertIsNotNone(ay.comparar_nft("", ""))

    def test_regla_distinta_de_menos_o_de_mas(self):
        self.assertIsNotNone(ay.comparar_nft(self.punto, LISTADO_PUNTO.replace("100.64.3.2 udp", "100.64.3.9 udp")))
        sin_api = "\n".join(l for l in LISTADO_PUNTO.split("\n") if "8729" not in l)
        self.assertIsNotNone(ay.comparar_nft(self.punto, sin_api))
        # la tabla de una imagen sin rele-api-claro (solo el puerto del punto) tampoco vale
        self.assertIsNotNone(ay.comparar_nft(self.punto, LISTADO_PUNTO.replace("{ 8728, 8729 }", "8729")))
        de_mas = LISTADO_PUNTO.replace('\t\tcounter packets 0 bytes 0 comment "resto"\n\t}\n\n\tchain output',
                                       '\t\ttcp dport 22 accept\n\t\tcounter comment "resto"\n\t}\n\n\tchain output')
        self.assertNotEqual(de_mas, LISTADO_PUNTO)
        self.assertIsNotNone(ay.comparar_nft(self.punto, de_mas))
        self.assertIsNotNone(ay.comparar_nft(self.punto, LISTADO_PUNTO.replace("policy drop", "policy accept")))


class Cli(unittest.TestCase):
    def ejecutar(self, orden, env):
        p = subprocess.run([sys.executable, str(ay.RENDER), orden], env={**os.environ, **env, "PYTHONUTF8": "1"},
                           capture_output=True, text=True, encoding="utf-8", timeout=30)
        return p.returncode, p.stdout, p.stderr

    def limpio(self, **cambios):
        base = {k: "" for k in ay.ENTORNO_BUENO}
        base.update(entorno(**cambios))
        return {k: v for k, v in base.items() if v is not None}

    def test_validar_bueno(self):
        rc, out, _ = self.ejecutar("validar", self.limpio())
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_validar_malo_sale_con_error_y_mensaje(self):
        rc, out, err = self.ejecutar("validar", self.limpio(TUN_MK="100.64.3.9"))
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertIn("TUN_MK", err)

    def test_nft_punto_por_stdout(self):
        rc, out, _ = self.ejecutar("nft-punto", self.limpio())
        self.assertEqual(rc, 0)
        self.assertEqual(out, (ay.FIXTURES / "ids_punto_p003.nft").read_text(encoding="utf-8"))

    def test_nft_punto_no_imprime_nada_si_el_entorno_es_malo(self):
        rc, out, _ = self.ejecutar("nft-punto", self.limpio(API_PUERTO="70000"))
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")

    def test_api_en_cualquier_puerto(self):
        """2026-10-20: el puerto de la API puede estar cambiado en el router; la imagen acepta 1-65535
        y la tabla del punto deja salir la API a ese puerto (y al 8728 del relé claro). Lo que no es un
        puerto, no."""
        txt = render.nft_punto(render.validar(entorno(API_PUERTO="2290", **DIRECTO)))
        self.assertIn('oifname "eth0" ip daddr 192.168.88.1 tcp dport { 2290, 8728 } accept', txt)
        for malo in ("0", "70000", "abc", "", "8729 ", "²"):
            with self.subTest(malo=malo):
                with self.assertRaises(render.ErrorEntorno):
                    render.validar(entorno(API_PUERTO=malo))

    def test_orden_desconocida(self):
        salida, errores = io.StringIO(), io.StringIO()
        self.assertEqual(render.main(["flush"], entorno(), salida, errores), 2)
        self.assertEqual(render.main([], entorno(), salida, errores), 2)
        self.assertEqual(salida.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
