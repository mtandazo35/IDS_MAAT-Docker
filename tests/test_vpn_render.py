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
            "API_PUERTO": ["", "443", "8730", "08729", "8729 "],
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
        self.assertIn('oifname "tun0" ip daddr 198.18.12.2 tcp dport 8728 accept', txt)
        self.assertNotIn("100.64", txt)
        self.assertNotIn("8729", txt)
        self.assertNotIn("flush", txt)

    def test_ids_mon_exacto(self):
        esperado = (ay.FIXTURES / "ids_mon.nft").read_text(encoding="utf-8")
        self.assertEqual(render.nft_mon(), esperado)


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
\t\toifname "tun0" ip daddr 100.64.3.2 tcp dport 8729 accept comment "API via rele"
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
        rc, out, _ = self.ejecutar("nft-punto", self.limpio(API_PUERTO="22"))
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")

    def test_orden_desconocida(self):
        salida, errores = io.StringIO(), io.StringIO()
        self.assertEqual(render.main(["flush"], entorno(), salida, errores), 2)
        self.assertEqual(render.main([], entorno(), salida, errores), 2)
        self.assertEqual(salida.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
