"""punto.ajustar con api_puerto (2026-10-20, el dueño: «debe aceptar sin ssl»): 8729 (API-SSL) u 8728
(API sin SSL) en un punto ya creado. Va solo; guarda el puerto y hace un reconfigurar: el compose lleva
el API_PUERTO nuevo (el relé y la tabla ids_punto del contenedor vpn), se recrean vpn y suricata y el
estado lo dice. Si el recreado falla, vuelven el puerto y los ficheros de antes. Los datos para el
MikroTik de un punto directo dicen qué encender: el certificado de la API-SSL o la API sin SSL.
Con el Docker simulado."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

NORTE = {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]}
LAN = {"nombre": "lan", "modo": "directo", "mk_ip": "192.168.88.1"}


class ApiPuerto(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(ncpu=8)
        A.crear(self, self.orq, NORTE)

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def compose(self, pid="p001"):
        return self.e.ruta("/srv/ids/puntos/%s/compose.yml" % pid).read_text(encoding="utf-8")

    def puerto_guardado(self, pid="p001"):
        return self.orq.q("SELECT api_puerto FROM punto WHERE pid=?", (pid,))[0][0]

    def test_pasa_a_8728_y_vuelve_a_8729(self):
        self.assertIn('API_PUERTO: "8729"', self.compose())
        antes = (self.s.contenedores["ids-p001-vpn"]["pid"], self.s.contenedores["ids-p001-suricata"]["pid"])
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "api_puerto": 8728})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertEqual(r["resultado"]["api_puerto"], 8728)
        self.assertEqual(sorted(r["resultado"]["recreado"]), ["suricata", "vpn"])
        self.assertIn("sin SSL", r["mensaje"])
        self.assertIn('API_PUERTO: "8728"', self.compose())
        self.assertEqual(self.puerto_guardado(), 8728)
        self.assertNotEqual(self.s.contenedores["ids-p001-vpn"]["pid"], antes[0])
        self.assertNotEqual(self.s.contenedores["ids-p001-suricata"]["pid"], antes[1])
        est = A.ejecutar_orden(self.orq, "punto.estado", {"pid": "p001"})
        self.assertEqual(est.get("datos", est).get("api_puerto", 8728), 8728)
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "api_puerto": 8729})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertIn('API_PUERTO: "8729"', self.compose())
        self.assertEqual(self.puerto_guardado(), 8729)

    def test_mismo_puerto_no_toca_nada(self):
        antes = self.s.contenedores["ids-p001-vpn"]["pid"]
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "api_puerto": 8729})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertEqual(r["resultado"]["recreado"], [])
        self.assertIn("sin cambios", r["mensaje"])
        self.assertEqual(self.s.contenedores["ids-p001-vpn"]["pid"], antes)

    def test_si_falla_el_recreado_vuelve_el_puerto_de_antes(self):
        self.s.fallar["--force-recreate"] = 1
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "api_puerto": 8728})
        self.assertNotEqual(r["codigo"], "OK", A.explicar(r))
        self.assertEqual(self.puerto_guardado(), 8729)
        self.assertIn('API_PUERTO: "8729"', self.compose())

    def test_validacion(self):
        for params in ({"pid": "p001", "api_puerto": 8080},
                       {"pid": "p001", "api_puerto": 8728, "perfil": "reducido"}):
            with self.subTest(params=params):
                r = self.orq.atender(A.peticion("punto.ajustar", params))
                self.assertEqual(r["codigo"], "INVALIDO", r)
        self.assertEqual(self.puerto_guardado(), 8729)

    def test_cli(self):
        a = self.mod.construir_parser().parse_args(["punto", "ajustar", "p001", "--api-puerto", "8728"])
        self.assertEqual(self.mod.orden_desde_args(a), ("punto.ajustar", {"pid": "p001", "api_puerto": 8728}))
        with self.assertRaises(SystemExit):
            self.mod.construir_parser().parse_args(["punto", "ajustar", "p001", "--api-puerto", "8080"])


class ComandosDirecto(unittest.TestCase):
    """Los datos para el MikroTik de un punto directo: con API-SSL, el certificado que piden algunos
    RouterOS 7 (con él conectó el router de un cliente, 2026-10-20); con 8728, encender la API."""

    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(ncpu=8)

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def p(self, **k):
        return dict({"pid": "p002", "nombre": "lan", "n": 2, "puerto": 37009, "mk_ip": "192.168.88.1",
                     "api_puerto": 8729}, **k)

    def test_api_ssl_trae_el_certificado(self):
        txt = self.mod.comandos_directo(self.p(), "192.168.88.10")
        self.assertIn("API-SSL (puerto 8729)", txt)
        self.assertIn("/certificate add name=ids-api common-name=ids-api", txt)
        self.assertIn("/certificate sign ids-api\n", txt)
        self.assertIn("/ip service set api-ssl certificate=ids-api disabled=no\n", txt)
        self.assertNotIn("/ip service set api disabled=no", txt)

    def test_api_sin_ssl_enciende_la_api(self):
        txt = self.mod.comandos_directo(self.p(api_puerto=8728), "192.168.88.10")
        self.assertIn("API sin SSL (puerto 8728)", txt)
        self.assertIn("/ip service set api disabled=no\n", txt)
        self.assertIn("viaja sin cifrar", txt)
        self.assertNotIn("/certificate", txt)


if __name__ == "__main__":
    unittest.main()
