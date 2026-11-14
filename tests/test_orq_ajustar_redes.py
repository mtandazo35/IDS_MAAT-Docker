"""punto.ajustar (Puntos, apartado A): HOME_NET fijo (privadas y CGNAT más los prefijos públicos),
así que los prefijos privados solo se guardan y uno público SÍ llega a Suricata (reinicio);
cambiar perfil o hilos recrea de verdad, avance con total y ajustes repetidos juntados en uno.
Con el Docker simulado, que (como Docker) no recrea nada en un `compose up -d` sin cambios."""

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


BASE = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10"


class HomeNet(unittest.TestCase):
    """HOME_NET fijo (decisión del dueño 2026-10-15): todo lo privado y CGNAT, y detrás los
    prefijos públicos del punto (sensor POST-NAT)."""

    def setUp(self):
        self.mod = A.cargar_orq()

    def test_prefijos_privados_no_cambian_nada(self):
        for redes in (["10.0.0.0/24"], ["192.168.117.0/24", "172.16.32.0/24", "100.70.0.0/16"],
                      ["10.0.0.0/8", "172.16.0.0/12"]):
            with self.subTest(redes=redes):
                self.assertEqual(self.mod.home_net(redes), "[%s]" % BASE)

    def test_prefijos_publicos_van_detras_sin_repetir(self):
        self.assertEqual(self.mod.home_net(["10.0.0.0/24", "203.0.113.0/24", "198.51.100.7/32", "203.0.113.0/24"]),
                         "[%s,203.0.113.0/24,198.51.100.7/32]" % BASE)

    def test_una_red_que_solo_pisa_en_parte_lo_privado_va_entera(self):
        """172.0.0.0/8 no cabe en 172.16/12: se añade tal cual (no es «privada» entera)."""
        self.assertEqual(self.mod.home_net(["172.0.0.0/8"]), "[%s,172.0.0.0/8]" % BASE)


class SoloRedes(Base):
    def test_prefijos_privados_no_reinician_suricata(self):
        """Decisión del dueño 2026-10-15: con HOME_NET fijo, cambiar prefijos privados solo los
        guarda (espejo del MikroTik y panel). Antes reiniciaba Suricata (~75 s sin inspeccionar)."""
        vpn, sur = self.pid_proc("vpn"), self.pid_proc("suricata")
        yaml_antes = self.yaml()
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001",
                                                         "redes_abonados": ["10.0.0.0/24", "10.1.0.0/24"]})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertEqual(r["resultado"]["recreado"], [])
        self.assertIn("no se reinicia", r["mensaje"])
        self.assertEqual(self.yaml(), yaml_antes)
        self.assertIn('HOME_NET: "[%s]"' % BASE, self.yaml())
        self.assertEqual((self.pid_proc("vpn"), self.pid_proc("suricata")), (vpn, sur))
        self.assertFalse(self.s.ordenes("docker restart"))
        self.assertEqual(self.orq.punto("p001")["redes"], ["10.0.0.0/24", "10.1.0.0/24"])
        hechos, total = r["avance"].split("/")
        self.assertEqual(hechos, total)

    def test_prefijo_publico_reinicia_suricata(self):
        """Un prefijo público (POST-NAT) cambia HOME_NET: suricata.yaml nuevo y reinicio, que el
        yaml va montado y `compose up -d` no recrearía nada. La VPN no se toca."""
        vpn, sur = self.pid_proc("vpn"), self.pid_proc("suricata")
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001",
                                                         "redes_abonados": ["10.0.0.0/24", "203.0.113.0/24"]})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertEqual(r["resultado"]["recreado"], ["suricata"])
        self.assertIn('HOME_NET: "[%s,203.0.113.0/24]"' % BASE, self.yaml())
        self.assertNotEqual(self.pid_proc("suricata"), sur)        # Suricata arrancó con el yaml nuevo
        self.assertEqual(self.pid_proc("vpn"), vpn)                # la VPN no se toca
        self.assertFalse([a for a in self.s.llamadas if "-T" in a])  # el -T no aporta nada aquí
        self.assertTrue(self.s.ordenes("docker restart --time 30 ids-p001-suricata"))
        hechos, total = r["avance"].split("/")
        self.assertEqual(hechos, total)

    def test_punto_parado_solo_escribe(self):
        A.ejecutar_orden(self.orq, "punto.parar", {"pid": "p001"})
        self.s.llamadas.clear()
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "redes_abonados": ["203.0.113.0/24"]})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertIn('HOME_NET: "[%s,203.0.113.0/24]"' % BASE, self.yaml())
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


class VueltaAtras(Base):
    """QA O-02 (2026-11-14): si punto.ajustar falla después de escribir, vuelve a los ficheros y los
    datos de antes y los pone en marcha (REVERTIDA), como punto.reconfigurar. Antes el punto quedaba
    con lo nuevo a medias y sin servicio."""

    def fallar_una_vez(self, *trozos):
        """La primera orden que lleva cada trozo falla; las siguientes (la vuelta atrás) van bien."""
        orig, hechas, quedan = self.mod.ejecutar, [], list(trozos)

        def una_vez(args, entrada=None, timeout=600):
            linea = " ".join(str(a) for a in args)
            for t in quedan:
                if t in linea:
                    quedan.remove(t)
                    hechas.append(args)
                    return self.mod.Resultado(1, "", "fallo simulado: %s" % t)
            return orig(args, entrada, timeout)
        self.mod.ejecutar = una_vez
        self.addCleanup(setattr, self.mod, "ejecutar", orig)
        return hechas

    def ficheros(self):
        b = "/srv/ids/puntos/p001/"
        return {r: self.e.ruta(b + r).read_text(encoding="utf-8")
                for r in ("suricata/suricata.yaml", "compose.yml", "vpn/server.conf")}

    def test_perfil_que_falla_al_recrear_vuelve_a_lo_de_antes(self):
        """Corrección de defecto: falla el recreado con el perfil nuevo -> ficheros, perfil e hilos de
        antes, Suricata recreado otra vez con ellos y el punto sano."""
        antes, p0 = self.ficheros(), self.orq.punto("p001")
        hechas = self.fallar_una_vez("--force-recreate")
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "perfil": "completo-low"})
        self.assertEqual(r["codigo"], "REVERTIDA", A.explicar(r))
        self.assertTrue(hechas)
        self.assertEqual(self.ficheros(), antes)
        p = self.orq.punto("p001")
        self.assertEqual((p["perfil"], p["hilos"], p["estado"]), (p0["perfil"], p0["hilos"], "activo"))
        self.assertEqual(len([a for a in self.s.llamadas if "--force-recreate" in a]), 1)   # la de vuelta
        self.assertEqual(self.s.contenedores["ids-p001-suricata"]["estado"], "running")

    def test_prefijo_publico_que_falla_al_reiniciar_vuelve_a_lo_de_antes(self):
        """Corrección de defecto: no arranca con el HOME_NET nuevo (falla el restart y también su plan B,
        el recreado) -> yaml y prefijos de antes, y Suricata reiniciado con ellos."""
        antes = self.ficheros()
        self.fallar_una_vez("docker restart", "--force-recreate")
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001",
                                                         "redes_abonados": ["10.0.0.0/24", "203.0.113.0/24"]})
        self.assertEqual(r["codigo"], "REVERTIDA", A.explicar(r))
        self.assertEqual(self.ficheros(), antes)
        self.assertNotIn("203.0.113.0/24", self.yaml())
        self.assertEqual(self.orq.punto("p001")["redes"], ["10.0.0.0/24"])

    def test_menos_T_fallido_no_reinicia_nada(self):
        """Conservación: si el -T rechaza el perfil nuevo no se ha tocado nada, así que la vuelta atrás
        no recrea ni reinicia Suricata."""
        antes = self.ficheros()
        self.s.fallar["-T"] = 1
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "perfil": "completo-low"})
        self.assertNotEqual(r["codigo"], "OK", A.explicar(r))
        self.assertEqual(self.ficheros(), antes)
        self.assertFalse([a for a in self.s.llamadas if "up" in a or "restart" in a])
        self.assertEqual(self.orq.punto("p001")["estado"], "activo")

    def test_si_tampoco_vuelve_queda_en_error(self):
        """Corrección de defecto: si lo de antes tampoco arranca, el punto queda en `error` con el motivo
        (no «activo» sin servicio)."""
        self.s.fallar["--force-recreate"] = 1
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "perfil": "completo-low"})
        self.assertNotEqual(r["codigo"], "OK", A.explicar(r))
        p = self.orq.punto("p001")
        self.assertEqual(p["estado"], "error")
        self.assertIn("ajustar: falló y lo anterior tampoco", p["paso_error"])


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
        """Prefijos públicos (los que reinician): de tres seguidos solo se aplica el último."""
        a = self.encolar({"redes_abonados": ["203.0.113.0/24"]})
        b = self.encolar({"redes_abonados": ["198.51.100.128/25"]})
        c = self.encolar({"redes_abonados": ["192.0.2.128/25"]})
        while self.orq.procesar_una():
            pass
        ra, rb, rc = self.estado(a), self.estado(b), self.estado(c)
        self.assertEqual((ra["codigo"], rb["codigo"], rc["codigo"]), ("OK", "OK", "OK"))
        self.assertEqual(ra["resultado"]["sustituida_por"], b)
        self.assertEqual(rb["resultado"]["sustituida_por"], c)
        self.assertEqual(rc["resultado"]["recreado"], ["suricata"])
        self.assertIn('HOME_NET: "[%s,192.0.2.128/25]"' % BASE, self.yaml())
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
