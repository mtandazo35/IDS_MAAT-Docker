"""VPN-04: `ids-orq vpn desbanear <ip>` y su orden por socket `vpn.desbanear {ip}`: se ejecuta sin
esperar a la cola, solo con una IP validada (nada de opciones ni rangos para fail2ban-client) y deja
su línea en orq.jsonl sin la IP en claro."""

import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402


class Desbanear(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()
        self.e.ruta("/srv/ids/estado").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def pedir(self, params, op_id=None):
        return self.orq.atender(A.peticion("vpn.desbanear", params, op_id))

    def f2b(self):
        return self.s.ordenes("fail2ban-client")

    def test_desbanea_una_ip_baneada(self):
        self.s.baneadas = {"203.0.113.45"}
        r = self.pedir({"ip": "203.0.113.45"})
        self.assertEqual(r["codigo"], "OK", r)
        self.assertEqual(r["datos"], {"ip": "203.0.113.45", "desbaneada": True, "jaula": "ids-vpn"})
        self.assertEqual(self.f2b(), [["fail2ban-client", "set", "ids-vpn", "unbanip", "203.0.113.45"]])
        self.assertEqual(self.s.baneadas, set())
        # inmediata: no pasa por la cola
        self.assertIsNone(self.orq.q1("SELECT 1 FROM op"))

    def test_no_estaba_baneada_no_es_un_error(self):
        r = self.pedir({"ip": "203.0.113.45"})
        self.assertEqual((r["codigo"], r["datos"]["desbaneada"]), ("OK", False))
        self.assertIn("no estaba baneada", r["mensaje"])
        # fail2ban viejo: error «is not banned»
        self.s._fail2ban_client = lambda a: (255, "", "ERROR  IP 203.0.113.45 is not banned\n")
        r = self.pedir({"ip": "203.0.113.45"})
        self.assertEqual((r["codigo"], r["datos"]["desbaneada"]), ("OK", False))

    def test_otro_fallo_de_fail2ban_es_fallo(self):
        self.s.fallar["unbanip"] = 255
        r = self.pedir({"ip": "203.0.113.45"})
        self.assertEqual(r["codigo"], "FALLO", r)

    def test_solo_una_ip_valida_llega_a_fail2ban(self):
        for malo in ("203.0.113.0/24", "--all", "203.0.113.45; reboot", "", "x" * 60, None, 5,
                     "203.0.113.256", "-v"):
            with self.subTest(ip=malo):
                r = self.pedir({"ip": malo})
                self.assertEqual(r["codigo"], "INVALIDO", r)
        r = self.pedir({"ip": "203.0.113.45", "jaula": "sshd"})          # parámetros de más
        self.assertEqual(r["codigo"], "INVALIDO", r)
        self.assertEqual(self.f2b(), [])
        # IPv6 y forma canónica
        r = self.pedir({"ip": " 2001:DB8::0001 "})
        self.assertEqual((r["codigo"], r["datos"]["ip"]), ("OK", "2001:db8::1"))

    def test_diario_sin_la_ip_en_claro(self):
        self.s.baneadas = {"203.0.113.45"}
        self.orq.atender(dict(A.peticion("vpn.desbanear", {"ip": "203.0.113.45"}), quien="panel:admin"))
        lineas = [json.loads(x) for x in self.e.ruta("/srv/ids/estado/orq.jsonl").read_text(
            encoding="utf-8").splitlines()]
        d = [x for x in lineas if x["orden"] == "vpn.desbanear"]
        self.assertEqual(len(d), 1)
        self.assertEqual((d[0]["quien"], d[0]["codigo"]), ("panel:admin", "OK"))
        self.assertNotIn("203.0.113.45", json.dumps(d[0]))
        self.assertRegex(d[0]["params_sha256"], r"^[0-9a-f]{64}$")

    def test_sin_token_no(self):
        r = self.orq.atender(A.peticion("vpn.desbanear", {"ip": "203.0.113.45"}, token="x" * 64))
        self.assertEqual(r["codigo"], "INVALIDO")
        self.assertEqual(self.f2b(), [])

    def test_cli(self):
        self.s.baneadas = {"203.0.113.45"}
        out = io.StringIO()

        def transporte(pet):
            return json.loads(json.dumps(self.orq.atender(pet)))
        c = self.mod.Cliente(transporte=transporte, dormir=lambda s: None, salida=out)
        rc = self.mod.main(["vpn", "desbanear", "203.0.113.45"], cliente=c)
        self.assertEqual(rc, 0, out.getvalue())
        self.assertTrue(out.getvalue().startswith("OK 203.0.113.45 desbaneada de ids-vpn"), out.getvalue())
        out.truncate(0)
        out.seek(0)
        rc = self.mod.main(["vpn", "desbanear", "203.0.113.0/24"], cliente=c)
        self.assertEqual(rc, 2, out.getvalue())
        self.assertTrue(out.getvalue().startswith("INVALIDO"), out.getvalue())


if __name__ == "__main__":
    unittest.main()
