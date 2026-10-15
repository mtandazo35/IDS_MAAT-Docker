"""punto.ajustar (Puntos, apartado A): cambiar los prefijos SÍ llega a Suricata, cambiar perfil o
hilos recrea de verdad, avance con total y ajustes repetidos juntados en uno. Con el Docker
simulado, que ahora (como Docker) no recrea nada en un `compose up -d` sin cambios."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

NORTE = {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]}


class Base(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(ncpu=8)
        A.crear(self, self.orq, NORTE)
        self.s.llamadas.clear()

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def pid_proc(self, parte):
        return self.s.contenedores["ids-p001-%s" % parte]["pid"]

    def yaml(self):
        return self.e.ruta("/srv/ids/puntos/p001/suricata/suricata.yaml").read_text(encoding="utf-8")


class Simulador(Base):
    def test_compose_up_sin_cambios_no_reinicia(self):
        """Lo que hace Docker: con el compose igual, `up -d` deja los contenedores como están."""
        antes = (self.pid_proc("vpn"), self.pid_proc("suricata"))
        self.s(self.mod.compose_args("p001", "up", "-d", "--pull", "never"))
        self.assertEqual((self.pid_proc("vpn"), self.pid_proc("suricata")), antes)

    def test_compose_cambiado_recrea_solo_ese_servicio(self):
        antes = (self.pid_proc("vpn"), self.pid_proc("suricata"))
        f = self.e.ruta("/srv/ids/puntos/p001/compose.yml")
        f.write_text(f.read_text(encoding="utf-8").replace("cpus: 1", "cpus: 2"), encoding="utf-8")
        self.s(self.mod.compose_args("p001", "up", "-d", "--pull", "never"))
        self.assertEqual(self.pid_proc("vpn"), antes[0])
        self.assertNotEqual(self.pid_proc("suricata"), antes[1])

    def test_compose_up_levanta_lo_parado(self):
        self.s.contenedores["ids-p001-suricata"]["estado"] = "exited"
        antes = self.pid_proc("suricata")
        self.s(self.mod.compose_args("p001", "up", "-d", "--pull", "never"))
        c = self.s.contenedores["ids-p001-suricata"]
        self.assertEqual(c["estado"], "running")
        self.assertNotEqual(c["pid"], antes)


class SoloRedes(Base):
    def test_cambiar_prefijos_reinicia_suricata(self):
        """Corrección de defecto: compose.yml no depende de las redes y suricata.yaml va montado, así
        que `compose up -d` no recreaba nada y HOME_NET seguía con las redes viejas."""
        vpn, sur = self.pid_proc("vpn"), self.pid_proc("suricata")
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001",
                                                         "redes_abonados": ["10.0.0.0/24", "10.1.0.0/24"]})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertEqual(r["resultado"]["recreado"], ["suricata"])
        self.assertIn('HOME_NET: "[10.0.0.0/24,10.1.0.0/24]"', self.yaml())
        self.assertNotEqual(self.pid_proc("suricata"), sur)        # Suricata arrancó con el yaml nuevo
        self.assertEqual(self.pid_proc("vpn"), vpn)                # la VPN no se toca
        self.assertFalse([a for a in self.s.llamadas if "-T" in a])  # el -T no aporta nada aquí
        self.assertTrue(self.s.ordenes("docker restart --time 30 ids-p001-suricata"))
        self.assertEqual(self.orq.punto("p001")["redes"], ["10.0.0.0/24", "10.1.0.0/24"])
        hechos, total = r["avance"].split("/")
        self.assertEqual(hechos, total)

    def test_punto_parado_solo_escribe(self):
        A.ejecutar_orden(self.orq, "punto.parar", {"pid": "p001"})
        self.s.llamadas.clear()
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "redes_abonados": ["10.2.0.0/24"]})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertIn('HOME_NET: "[10.2.0.0/24]"', self.yaml())
        self.assertFalse(self.s.ordenes("docker restart"))
        self.assertEqual(self.s.contenedores["ids-p001-suricata"]["estado"], "exited")


class PerfilHilos(Base):
    def test_perfil_recrea_suricata_de_verdad(self):
        vpn, sur = self.pid_proc("vpn"), self.s.contenedores["ids-p001-suricata"]["id"]
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "perfil": "completo-low"})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        up = [a for a in self.s.llamadas if "up" in a][-1]
        self.assertIn("--force-recreate", up)
        self.assertEqual(up[-1], "suricata")
        self.assertNotEqual(self.s.contenedores["ids-p001-suricata"]["id"], sur)
        self.assertEqual(self.pid_proc("vpn"), vpn)
        self.assertTrue([a for a in self.s.llamadas if "-T" in a])
        hechos, total = r["avance"].split("/")
        self.assertEqual(hechos, total)


class Avance(Base):
    def test_total_en_las_ordenes_de_punto(self):
        for orden, params in (("punto.parar", {"pid": "p001"}), ("punto.arrancar", {"pid": "p001"}),
                              ("punto.reiniciar", {"pid": "p001", "parte": "todo"}),
                              ("punto.reiniciar", {"pid": "p001", "parte": "suricata"}),
                              ("punto.vpn.regenerar", {"pid": "p001"}),
                              ("punto.ajustar", {"pid": "p001", "origen_ip": "203.0.113.45"})):
            with self.subTest(orden=orden, params=params):
                r = A.ejecutar_orden(self.orq, orden, params)
                self.assertEqual(r["codigo"], "OK", A.explicar(r))
                hechos, total = r["avance"].split("/")
                self.assertEqual(hechos, total)


class Juntar(Base):
    def encolar(self, params):
        r = self.orq.atender(A.peticion("punto.ajustar", dict(params, pid="p001")))
        self.assertEqual(r["codigo"], "ACEPTADA")
        return r["op_id"]

    def estado(self, op_id):
        return self.orq.atender(A.peticion("op.estado", {"op_id": op_id}))["datos"]

    def test_varios_cambios_de_prefijos_cuentan_como_uno(self):
        a = self.encolar({"redes_abonados": ["10.1.0.0/24"]})
        b = self.encolar({"redes_abonados": ["10.2.0.0/24"]})
        c = self.encolar({"redes_abonados": ["10.3.0.0/24"]})
        while self.orq.procesar_una():
            pass
        ra, rb, rc = self.estado(a), self.estado(b), self.estado(c)
        self.assertEqual((ra["codigo"], rb["codigo"], rc["codigo"]), ("OK", "OK", "OK"))
        self.assertEqual(ra["resultado"]["sustituida_por"], b)
        self.assertEqual(rb["resultado"]["sustituida_por"], c)
        self.assertEqual(rc["resultado"]["recreado"], ["suricata"])
        self.assertIn('HOME_NET: "[10.3.0.0/24]"', self.yaml())
        self.assertEqual(len(self.s.ordenes("docker restart --time 30 ids-p001-suricata")), 1)

    def test_campos_distintos_no_se_pierden(self):
        """Un ajuste de perfil seguido de uno de prefijos: el segundo no cubre el primero."""
        a = self.encolar({"perfil": "completo-low"})
        b = self.encolar({"redes_abonados": ["10.4.0.0/24"]})
        while self.orq.procesar_una():
            pass
        self.assertNotIn("sustituida_por", self.estado(a)["resultado"])
        self.assertEqual(self.estado(b)["codigo"], "OK")
        p = self.orq.punto("p001")
        self.assertEqual((p["perfil"], p["redes"]), ("completo-low", ["10.4.0.0/24"]))


if __name__ == "__main__":
    unittest.main()
