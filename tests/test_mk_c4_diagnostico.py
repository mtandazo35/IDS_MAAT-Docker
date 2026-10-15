"""Diagnostico y abonados del MikroTik: mk_lista_en_uso, mk_diagnostico y mk_abonados.

Tipo: correccion de defecto (tanda MikroTik del 2026-10-14, C4), contra el panel real y el
router simulado de `_mikrotik_simulado.py` (ampliado AQUI, por herencia, con las tablas que
estas funciones leen: raw, nat, /ip/settings, PPPoE, DHCP, colas simples, hotspot y ARP).

- mk_lista_en_uso solo miraba filter: con la plantilla del panel puesta (raw/nat/mangle)
  avisaba de «esta lista no corta nada» en falso.
- mk_diagnostico no miraba nat ni mangle (redirigir-dns, limitar), leia raw sin `disabled`
  y su arreglo era un drop suelto en filter que duplicaba la plantilla.
- mk_abonados solo usaba PPPoE y DHCP: los abonados con IP estatica salian sin nombre.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_f1_cuarentena import Panel  # noqa: E402
import _mikrotik_simulado as sim  # noqa: E402

RAW, NAT, MANGLE, FILTER = ("/ip/firewall/raw", "/ip/firewall/nat", "/ip/firewall/mangle",
                            "/ip/firewall/filter")
LISTA = "suricata-cuarentena"


class RouterCompleto(sim.RouterSimulado):
    """El simulado de siempre mas las tablas que leen el diagnostico y los abonados. Sin
    `hotspot` el router contesta !trap a /ip/hotspot (paquete no instalado), como uno real.
    Apunta cada print para poder contar cuantas veces se lee cada tabla."""

    EXTRA = (RAW, NAT, "/ip/settings", "/ppp/active", "/ip/dhcp-server/lease",
             "/queue/simple", "/ip/arp", "/queue/tree")

    def __init__(self, identidad="router-lab", hotspot=True):
        super().__init__(identidad)
        for t in self.EXTRA + (("/ip/hotspot/active",) if hotspot else ()):
            self.tablas[t] = []
        self.prints = []

    def _print(self, tabla, attrs, consultas):
        self.prints.append(tabla)
        return super()._print(tabla, attrs, consultas)


class Base(unittest.TestCase):
    def setUp(self):
        self.p = Panel()
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d
        self.r = RouterCompleto("norte")
        self.p.routers["p001"] = self.r
        self.rt = self.d.router_por_id("p001")


class ListaEnUso(Base):
    def en_uso(self, lista=LISTA):
        return self.d.mk_lista_en_uso(lista, router=self.rt)

    def test_sin_reglas_no_esta_en_uso(self):
        self.assertFalse(self.en_uso())

    def test_la_plantilla_en_raw_cuenta(self):
        # lo que pone «Cortar todo»: raw prerouting, ninguna regla en filter
        self.r.cargar(RAW, [{"chain": "prerouting", "action": "drop", "src-address-list": LISTA}])
        self.assertTrue(self.en_uso())

    def test_nat_y_mangle_de_las_plantillas_cuentan(self):
        self.r.cargar(NAT, [{"chain": "dstnat", "action": "redirect", "protocol": "udp",
                             "dst-port": "53", "to-ports": "53", "src-address-list": "clientes-dns-malware"}])
        self.r.cargar(MANGLE, [{"chain": "prerouting", "action": "mark-connection",
                                "new-connection-mark": "suricata-p2p", "src-address-list": "clientes-p2p"}])
        self.assertTrue(self.en_uso("clientes-dns-malware"))
        self.assertTrue(self.en_uso("clientes-p2p"))
        self.assertFalse(self.en_uso(LISTA))

    def test_como_destino_tambien_cuenta(self):
        self.r.cargar(FILTER, [{"chain": "forward", "action": "drop", "dst-address-list": LISTA}])
        self.assertTrue(self.en_uso())

    def test_desactivada_o_negada_no_cuenta(self):
        self.r.cargar(RAW, [{"chain": "prerouting", "action": "drop", "src-address-list": LISTA,
                             "disabled": "yes"}])
        self.r.cargar(NAT, [{"chain": "dstnat", "action": "redirect", "to-ports": "53",
                             "src-address-list": "!" + LISTA}])
        self.assertFalse(self.en_uso())

    def test_una_tabla_ilegible_no_da_un_falso_no_corta(self):
        # si el router rechaza leer raw, no se puede afirmar que la lista no se usa: se lanza
        # (quien llama calla el aviso) en vez de devolver False
        self.r.fallar_print = RAW + "/print"
        with self.assertRaises(IOError):
            self.en_uso()


class Diagnostico(Base):
    def setUp(self):
        super().setUp()
        # la accion por clase tiene su propia prueba: aqui ninguna, para contar las lecturas
        # de la comprobacion de listas sin las del plan de cada clase
        self.d.accion_de_clase = lambda cat, m=None: "nada"

    def checks(self):
        return {t: (e, det, fix) for e, t, det, fix in self.d.mk_diagnostico(self.rt)}

    def test_cuarentena_en_nat_o_mangle_corta(self):
        self.r.cargar(NAT, [{"chain": "dstnat", "action": "redirect", "to-ports": "53",
                             "src-address-list": LISTA}])
        self.r.cargar(MANGLE, [{"chain": "prerouting", "action": "mark-connection",
                                "new-connection-mark": "x", "src-address-list": "suricata-graduada"}])
        c = self.checks()
        self.assertEqual(c["La lista de cuarentena corta"][0], "ok", c)
        self.assertEqual(c["La lista de cuarentena graduada corta"][0], "ok", c)

    def test_raw_desactivada_no_corta_ni_cuenta_como_raw(self):
        self.r.cargar(RAW, [{"chain": "prerouting", "action": "drop", "src-address-list": LISTA,
                             "disabled": "yes"}])
        c = self.checks()
        self.assertEqual(c["La lista de cuarentena NO corta nada"][0], "falta", c)
        self.assertNotIn("Hay reglas en raw", c)
        self.assertEqual(c["Los cortes van por filter, no por raw"][0], "aviso")

    def test_el_arreglo_remite_a_la_plantilla_y_no_a_un_drop(self):
        c = self.checks()
        for titulo in ("La lista de cuarentena NO corta nada", "Los cortes van por filter, no por raw"):
            fix = c[titulo][2]
            self.assertIn("Ajustes -> MikroTik", fix)
            self.assertIn("Ver / aplicar en el router", fix)
            self.assertNotIn("action=drop", fix)
            self.assertNotIn("/ip firewall", fix)

    def test_lista_de_clase_remite_a_su_clase(self):
        self.d._registrar_enviados(self.d.MK_SENT, {"p001|10.0.0.5": {
            "cuando": 1, "router": "p001", "lista": "clientes-botnet"}}, [])
        c = self.checks()
        e, det, fix = c["La lista de categoría botnet / cnc NO corta nada"]
        self.assertEqual(e, "falta")
        self.assertIn("Botnet / CnC", fix)
        self.assertIn("Ver / aplicar en el router", fix)
        # y con la plantilla puesta en raw deja de faltar
        self.r.cargar(RAW, [{"chain": "prerouting", "action": "drop", "src-address-list": "clientes-botnet"}])
        self.assertEqual(self.checks()["La lista de categoría botnet / cnc corta"][0], "ok")

    def test_cada_tabla_se_lee_una_vez(self):
        self.checks()
        for t in (FILTER, RAW, NAT, MANGLE):
            self.assertEqual(self.r.prints.count(t), 1, (t, self.r.prints))


class Abonados(Base):
    def cargar_todo(self):
        r = self.r
        r.cargar("/ppp/active", [{"name": "pppoe-ana", "address": "10.0.0.10",
                                  "caller-id": "02:00:00:00:00:10", "uptime": "1h"}])
        r.cargar("/ip/dhcp-server/lease", [
            {"address": "10.0.0.20", "active-address": "10.0.0.20", "mac-address": "02:00:00:00:00:20",
             "host-name": "casa-luis", "comment": "", "status": "bound"},
            # misma IP que el PPPoE: gana el PPPoE
            {"address": "10.0.0.10", "mac-address": "02:00:00:00:00:99", "host-name": "otro",
             "status": "bound"}])
        r.cargar("/queue/simple", [
            {"name": "CLIENTE-ESTATICO", "target": "10.0.0.30/32", "max-limit": "5M/5M"},
            {"name": "DOS-IPS", "target": "10.0.0.31/32,10.0.0.32", "max-limit": "2M/2M"},
            {"name": "RED-ENTERA", "target": "10.0.1.0/24", "max-limit": "100M/100M"},
            {"name": "hs-maria", "target": "10.0.0.40/32", "dynamic": "yes"},
            {"name": "COLA-DHCP", "target": "10.0.0.20/32"}])         # el DHCP gana a la cola
        r.cargar("/ip/arp", [
            {"address": "10.0.0.30", "mac-address": "02:00:00:00:00:30", "interface": "ether2"},
            {"address": "10.0.0.50", "mac-address": "02:00:00:00:00:50", "interface": "vlan20"},
            {"address": "10.0.0.51", "interface": "vlan20"},           # incompleta: sin MAC
            {"address": "10.0.0.10", "mac-address": "02:00:00:00:00:11", "interface": "ether2"}])

    def test_fuentes_y_prioridades(self):
        self.cargar_todo()
        self.r.cargar("/ip/hotspot/active", [
            {"user": "maria", "address": "10.0.0.40", "mac-address": "02:00:00:00:00:40", "uptime": "5m"},
            {"user": "pisa-cola", "address": "10.0.0.30", "mac-address": "02:00:00:00:00:31"}])
        m = self.d.mk_abonados(router=self.rt)
        # lo de antes, con el mismo formato exacto
        self.assertEqual(m["10.0.0.10"], {"nombre": "pppoe-ana", "tipo": "PPPoE",
                                          "mac": "02:00:00:00:00:10", "extra": "uptime 1h"})
        self.assertEqual(m["10.0.0.20"], {"nombre": "casa-luis", "tipo": "DHCP",
                                          "mac": "02:00:00:00:00:20", "extra": "bound"})
        # IP estatica: el nombre de su cola, con la MAC que da el ARP
        self.assertEqual(m["10.0.0.30"], {"nombre": "CLIENTE-ESTATICO", "tipo": "Cola",
                                          "mac": "02:00:00:00:00:30", "extra": "max-limit 5M/5M"})
        self.assertEqual(m["10.0.0.31"]["nombre"], "DOS-IPS")
        self.assertEqual(m["10.0.0.32"]["nombre"], "DOS-IPS")
        # una cola de una red entera no le pone nombre a cada IP de dentro
        self.assertFalse(any(ip.startswith("10.0.1.") for ip in m), m)
        # la cola dinamica del hotspot no tapa al usuario del hotspot
        self.assertEqual(m["10.0.0.40"], {"nombre": "maria", "tipo": "Hotspot",
                                          "mac": "02:00:00:00:00:40", "extra": "uptime 5m"})
        # ARP: sin nombre, pero la IP existe con su MAC e interfaz; sin MAC no prueba nada
        self.assertEqual(m["10.0.0.50"], {"nombre": "", "tipo": "ARP",
                                          "mac": "02:00:00:00:00:50", "extra": "vlan20"})
        self.assertNotIn("10.0.0.51", m)

    def test_sin_hotspot_instalado_no_rompe_el_resto(self):
        self.r = RouterCompleto("norte", hotspot=False)
        self.p.routers["p001"] = self.r
        self.cargar_todo()
        m = self.d.mk_abonados(router=self.rt)
        self.assertNotIn("/ip/hotspot/active", self.r.tablas)
        self.assertEqual(m["10.0.0.10"]["tipo"], "PPPoE")
        self.assertEqual(m["10.0.0.30"]["nombre"], "CLIENTE-ESTATICO")
        # el ARP se lee DESPUES del hotspot rechazado: la conexion sigue en orden
        self.assertEqual(m["10.0.0.50"]["tipo"], "ARP")
        self.assertIn("/ip/arp", self.r.prints)


if __name__ == "__main__":
    unittest.main()
