"""Alta sin prefijos (decisión del dueño 2026-10-15: el panel solo pide el nombre). El orquestador
pone todo lo privado y el CGNAT menos sus redes reservadas (base de túneles, pool de Docker,
redes de gestión), que validar_redes rechazaría."""
import ipaddress
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

RED = ipaddress.IPv4Network


def direcciones(redes):
    return sum(RED(r).num_addresses for r in redes)


def cfg(gestion=("192.0.2.0/25",), tuneles="100.64.0.0/16", pool="10.210.0.0/16"):
    return types.SimpleNamespace(red_tuneles=RED(tuneles), pool=RED(pool), redes_gestion=[RED(g) for g in gestion])


class RedesPorDefecto(unittest.TestCase):
    def setUp(self):
        self.mod = A.cargar_orq()

    def test_privadas_y_cgnat_menos_las_reservadas(self):
        c = cfg(gestion=("192.0.2.0/25", "10.1.2.0/24"))
        redes = self.mod.redes_por_defecto(c)
        bases = [RED(b) for b in self.mod.REDES_POR_DEFECTO]
        reservadas = [c.red_tuneles, c.pool] + c.redes_gestion
        for r in map(RED, redes):
            self.assertTrue(any(r.subnet_of(b) for b in bases), r)
            self.assertFalse(any(r.overlaps(x) for x in reservadas), r)
        self.assertIn("192.168.0.0/16", redes)
        self.assertIn("172.16.0.0/12", redes)
        self.assertNotIn("10.0.0.0/8", redes)
        # ni una dirección de menos: lo privado salvo túneles (/16), pool (/16) y 10.1.2.0/24
        esperado = direcciones(self.mod.REDES_POR_DEFECTO) - 2 * 65536 - 256
        self.assertEqual(direcciones(redes), esperado)
        self.assertEqual(redes, self.mod.validar_redes(redes, c))      # ya son válidas, en orden

    def test_base_de_tuneles_fuera_del_cgnat(self):
        """Con TUN_BASE=198.18 el CGNAT entra entero."""
        redes = self.mod.redes_por_defecto(cfg(tuneles="198.18.0.0/16"))
        self.assertIn("100.64.0.0/10", redes)

    def test_demasiados_huecos_pide_redes(self):
        gestion = ["10.%d.0.1/32" % i for i in range(0, 256, 64)] + ["172.16.0.1/32", "192.168.0.1/32"]
        with self.assertRaises(self.mod.ErrorOrden) as e:
            self.mod.redes_por_defecto(cfg(gestion=gestion))
        self.assertEqual(e.exception.codigo, "INVALIDO")
        self.assertIn("como mucho 64", str(e.exception))

    def test_cli_sin_redes(self):
        a = self.mod.construir_parser().parse_args(["punto", "crear", "--nombre", "x1"])
        self.assertEqual(self.mod.orden_desde_args(a), ("punto.crear", {"nombre": "x1"}))
        a = self.mod.construir_parser().parse_args(["punto", "crear", "--nombre", "x1", "--redes", "10.0.0.0/24"])
        self.assertEqual(self.mod.orden_desde_args(a), ("punto.crear", {"nombre": "x1",
                                                                        "redes_abonados": ["10.0.0.0/24"]}))


class AltaSinRedes(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_punto_creado_solo_con_el_nombre(self):
        A.crear(self, self.orq, {"nombre": "norte"})
        redes = self.orq.punto("p001")["redes"]
        self.assertEqual(redes, self.mod.redes_por_defecto(self.mod.config()))
        yaml = self.e.ruta("/srv/ids/puntos/p001/suricata/suricata.yaml").read_text(encoding="utf-8")
        self.assertIn("192.168.0.0/16", yaml)                              # en HOME_NET

    def test_lista_vacia_sigue_siendo_invalida(self):
        r = self.orq.atender(A.peticion("punto.crear", {"nombre": "norte", "redes_abonados": []}))
        self.assertEqual(r["codigo"], "INVALIDO")


if __name__ == "__main__":
    unittest.main()
