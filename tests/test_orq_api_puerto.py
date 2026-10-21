"""punto.ajustar con api_puerto (2026-10-20, el dueño: «debe aceptar sin ssl»; «falta indicar qué puerto es
la API, puede estar cambiada en el MikroTik»): cualquier puerto 1-65535 en un punto ya creado; uno que no
sea 8729/8728 exige una imagen vpn con ids-maat.api-puerto=libre. Va solo; guarda el puerto y hace un reconfigurar: el compose lleva
el API_PUERTO nuevo (el relé y la tabla ids_punto del contenedor vpn), se recrean vpn y suricata y el
estado lo dice. Si el recreado falla, vuelven el puerto y los ficheros de antes. Los datos para el
MikroTik de un punto directo no llevan órdenes de la API (el dueño, 2026-10-20): remiten a la ficha
del punto y a «Probar la conexión», y nombran los puertos que dejar pasar. Con el Docker simulado."""

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
        self.assertIn("puerto 8728", r["mensaje"])
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

    def test_puerto_cambiado_en_el_router(self):
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "api_puerto": 2290})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertIn('API_PUERTO: "2290"', self.compose())
        self.assertEqual(self.puerto_guardado(), 2290)
        self.assertIn("puerto 2290", r["mensaje"])

    def test_imagen_anterior_solo_8729_u_8728(self):
        """Una imagen vpn de antes no arranca con otro puerto: CONFLICTO antes de tocar nada."""
        self.s.api_puerto_vpn = ""
        antes = self.s.contenedores["ids-p001-vpn"]["pid"]
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "api_puerto": 2290})
        self.assertEqual(r["codigo"], "CONFLICTO", A.explicar(r))
        self.assertIn("install.sh", r["mensaje"])
        self.assertEqual(self.puerto_guardado(), 8729)
        self.assertEqual(self.s.contenedores["ids-p001-vpn"]["pid"], antes)
        # 8728 sí, con la imagen que sea
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "api_puerto": 8728})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        # y el alta igual: otro puerto sobre la imagen de antes no se crea
        r = A.ejecutar_orden(self.orq, "punto.crear", {"nombre": "sur", "api_puerto": 2290})
        self.assertEqual(r["codigo"], "CONFLICTO", A.explicar(r))

    def test_validacion(self):
        for params in ({"pid": "p001", "api_puerto": 70000}, {"pid": "p001", "api_puerto": 0},
                       {"pid": "p001", "api_puerto": 8728, "perfil": "reducido"}):
            with self.subTest(params=params):
                r = self.orq.atender(A.peticion("punto.ajustar", params))
                self.assertEqual(r["codigo"], "INVALIDO", r)
        self.assertEqual(self.puerto_guardado(), 8729)

    def test_cli(self):
        a = self.mod.construir_parser().parse_args(["punto", "ajustar", "p001", "--api-puerto", "8728"])
        self.assertEqual(self.mod.orden_desde_args(a), ("punto.ajustar", {"pid": "p001", "api_puerto": 8728}))
        a = self.mod.construir_parser().parse_args(["punto", "ajustar", "p001", "--api-puerto", "2290"])
        self.assertEqual(self.mod.orden_desde_args(a)[1]["api_puerto"], 2290)
        for malo in ("70000", "0", "api"):
            with self.subTest(malo=malo), self.assertRaises(SystemExit):
                self.mod.construir_parser().parse_args(["punto", "ajustar", "p001", "--api-puerto", malo])


class ComandosDirecto(unittest.TestCase):
    """Los datos para el MikroTik de un punto directo (el dueño, 2026-10-20): de la API, ninguna orden.
    Se configura en la ficha del punto (usuario, clave, puerto y «Con certificado») y «Probar la
    conexión» la comprueba y, con certificado, lo crea si el router no tiene, entrando una vez por la
    API normal. Solo queda qué dejar pasar si el router filtra: el puerto de la API y el 8728."""

    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(ncpu=8)

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def p(self, **k):
        return dict({"pid": "p002", "nombre": "lan", "n": 2, "puerto": 37009, "mk_ip": "192.168.88.1",
                     "api_puerto": 8729}, **k)

    def ordenes(self, txt):
        """Las líneas que RouterOS ejecutaría si se pegara el bloque: cualquiera que no sea comentario."""
        return [x for x in txt.splitlines() if x.strip() and not x.lstrip().startswith("#")]

    def test_sin_ordenes_de_la_api(self):
        txt = self.mod.comandos_directo(self.p(api_puerto=2290), "192.168.88.10")
        self.assertEqual(self.ordenes(txt), [], txt)
        self.assertEqual([x for x in txt.splitlines() if x.lstrip().startswith("/")], [], txt)
        self.assertNotIn("/certificate", txt)
        self.assertNotIn("/ip service", txt)
        # remite a la ficha y a «Probar la conexión», que crea el certificado si falta
        self.assertIn("ficha del punto", txt)
        self.assertIn("Con certificado", txt)
        self.assertIn("«Probar la conexión»", txt)
        self.assertIn("puerto 2290", txt)
        # si el router filtra: el puerto de la API y el 8728 (la API normal, para crear el certificado)
        self.assertIn("deja pasar desde 192.168.88.10 los puertos 2290 y 8728\n", txt)
        self.assertIn("el 8728 es la API normal", txt)
        # el espejo, como siempre
        self.assertIn("sniff-target=192.168.88.10 sniff-target-port=37009", txt)

    def test_api_normal_en_8728_no_se_repite(self):
        txt = self.mod.comandos_directo(self.p(api_puerto=8728), "192.168.88.10")
        self.assertEqual(self.ordenes(txt), [], txt)
        self.assertIn("deja pasar desde 192.168.88.10 el puerto 8728.\n", txt)
        self.assertNotIn("8728 y", txt)

    def test_sin_ruta_al_mikrotik(self):
        txt = self.mod.comandos_directo(self.p())
        self.assertEqual(self.ordenes(txt), [], txt)
        self.assertIn("deja pasar desde <IP-DEL-HOST> los puertos 8729 y 8728\n", txt)


if __name__ == "__main__":
    unittest.main()
