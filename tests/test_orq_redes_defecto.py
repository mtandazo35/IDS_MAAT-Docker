"""Prefijos del espejo (decisiones del dueño 2026-10-15 y 2026-10-16): el alta solo pide el nombre y las
VPN reciben SIEMPRE todo lo privado y el CGNAT menos las redes reservadas (base de túneles, pool de
Docker, redes de gestión); la lista del punto es solo lo ADICIONAL."""
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
        """Decisión del dueño 2026-10-16: las VPN reciben siempre todo lo privado y el CGNAT; la lista
        del punto es solo lo ADICIONAL y nace vacía. Lo que va al MikroTik (redes_espejo, en estado.json)
        es todo lo privado menos lo reservado."""
        A.crear(self, self.orq, {"nombre": "norte"})
        self.assertEqual(self.orq.punto("p001")["redes"], [])
        est = self.orq.escribir_estado()["puntos"]["p001"]
        self.assertEqual(est["redes"], [])
        self.assertEqual(est["redes_espejo"], self.mod.redes_por_defecto(self.mod.config()))
        yaml = self.e.ruta("/srv/ids/puntos/p001/suricata/suricata.yaml").read_text(encoding="utf-8")
        self.assertIn("192.168.0.0/16", yaml)                              # en HOME_NET

    def test_lista_vacia_es_valida(self):
        """Capacidad nueva: una lista vacía = sin prefijos adicionales."""
        r = A.ejecutar_orden(self.orq, "punto.crear", {"nombre": "norte", "redes_abonados": []})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertEqual(self.orq.punto("p001")["redes"], [])

    def test_adicional_publico_va_al_espejo_y_el_privado_no_se_repite(self):
        """Capacidad nueva: un rango público se suma a lo privado; uno privado ya va incluido."""
        A.crear(self, self.orq, {"nombre": "norte", "redes_abonados": ["203.0.113.0/24", "10.12.0.0/16"]})
        est = self.orq.escribir_estado()["puntos"]["p001"]
        esperado = self.mod.redes_espejo([], self.mod.config()) + ["203.0.113.0/24"]
        self.assertEqual(sorted(est["redes_espejo"]), sorted(esperado))
        self.assertNotIn("10.12.0.0/16", est["redes_espejo"])     # cubierto por las privadas


class MigracionPrefijos(unittest.TestCase):
    """0.1.7: los puntos que ya existían tenían la lista rellena con todo lo privado (o una más estrecha):
    al abrir orq.db, una sola vez, se queda solo lo adicional (lo no privado)."""

    def test_quita_lo_privado_una_vez(self):
        import json
        import sqlite3
        mod = A.cargar_orq()
        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        db.executescript(mod.ESQUEMA)
        db.execute("INSERT INTO punto (pid, n, nombre, puerto, subred, cluster_id, perfil, hilos, ros_version, "
                   "compat_v6, api_puerto, redes, deseado, estado, creado, actualizado) VALUES "
                   "('p001', 1, 'norte', 1194, '10.211.1.0/29', 101, 'reducido', 1, 7, 'no', 8729, ?, 'activo', "
                   "'activo', 0, 0)",
                   (json.dumps(["10.0.0.0/9", "172.16.0.0/12", "192.168.0.0/16", "100.65.0.0/16",
                                "203.0.113.0/24"]),))
        mod.migrar_db(db)
        self.assertEqual(json.loads(db.execute("SELECT redes FROM punto").fetchone()[0]), ["203.0.113.0/24"])
        # una vez: lo que se guarde despues (aunque sea privado) se respeta
        db.execute("UPDATE punto SET redes=?", (json.dumps(["10.12.0.0/16"]),))
        mod.migrar_db(db)
        self.assertEqual(json.loads(db.execute("SELECT redes FROM punto").fetchone()[0]), ["10.12.0.0/16"])


if __name__ == "__main__":
    unittest.main()
