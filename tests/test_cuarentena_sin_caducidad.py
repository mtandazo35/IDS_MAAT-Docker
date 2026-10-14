"""La cuarentena de un abonado no caduca por tiempo: sale cuando deja de enviar virus.

Tipo: cambio de comportamiento pedido por el user (2026-10-14: «necesito que se saque de manera
automatica cuando ya no envie virus», y no antes por un TTL). Antes, con «Mantener
automaticamente» apagado, la IP entraba con el TTL de Ajustes (1 h) y el router la soltaba a esa
hora aunque el abonado siguiera infectado. Ahora:
  - las listas de abonados (cuarentena por categoria y DNS sospechoso) van siempre sin TTL, y un
    AUTO_MANTENER=0 viejo del .conf no vale;
  - el reconciliador las libera cuando el CPE ya no es candidato (deja de atacar);
  - lo que ya estaba en el router con timeout pasa a permanente (si sigue atacando), una vez;
  - las listas de terceros (destinos malos, graduada) conservan su TTL: nadie las libera.
  - una IP enviada A MANO (sin deteccion) sale cuando ya no tiene ninguna alerta como origen;
    en banda baja todavia se queda. El reporte publica 'vigiladas' (las en cuarentena con
    alertas, sin el tope de 80 de top_riesgo) para medirlo.
Panel real con el MikroTik simulado (Panel de test_f1_cuarentena); el generador, de verdad
(Entorno de test_hrep_nodos).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_f1_cuarentena import Panel  # noqa: E402
from test_hrep_nodos import Entorno, alerta  # noqa: E402

SIGUE, DEJO, OTRA = "10.0.0.41", "10.0.0.42", "10.0.0.43"
LISTA, LISTA_DNS = "clientes-escaneo", "clientes-dns-malware"


class SinCaducidad(unittest.TestCase):
    def setUp(self):
        self.p = Panel()
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d
        self.r1 = self.p.routers["p001"]

    def entrada(self, lista, ip):
        return next((f for f in self.r1.tablas["/ip/firewall/address-list"]
                     if f["list"] == lista and f["address"] == ip), None)

    def test_un_auto_mantener_apagado_ya_no_vale(self):
        self.d.guardar_mk({"AUTO_MANTENER": "0"})
        self.assertEqual(self.d.cargar_mk()["AUTO_MANTENER"], "1")
        self.assertEqual(self.d.cargar_mk_de(self.d.router_por_id("p001"))["AUTO_MANTENER"], "1")

    def test_abonados_sin_ttl_y_terceros_con_su_ttl(self):
        m = dict(self.d.cargar_mk_de(self.d.router_por_id("p001")), TTL="1h", TTL_DNS="1d")
        self.assertEqual(self.d._ttl_efectivo(m, "TTL"), "")
        self.assertEqual(self.d._ttl_efectivo(m, "TTL_DNS"), "")
        self.assertEqual(self.d._ttl_efectivo(m, "TTL_DST"), m["TTL_DST"])      # 7d por defecto
        self.assertEqual(self.d._ttl_efectivo(m, "TTL_GRAD"), m["TTL_GRAD"])
        self.assertTrue(m["TTL_DST"] and m["TTL_GRAD"])

    def test_sale_cuando_deja_de_atacar_y_lo_viejo_con_ttl_pasa_a_permanente(self):
        # en el router, de cuando la cuarentena caducaba: las tres con timeout
        self.r1.cargar("/ip/firewall/address-list", [
            {"list": LISTA, "address": SIGUE, "timeout": "45m", "comment": "suricata escaneo riesgo 80"},
            {"list": LISTA, "address": DEJO, "timeout": "45m"},
            {"list": LISTA_DNS, "address": OTRA, "timeout": "20h"}])
        self.d._registrar_enviados(self.d.MK_SENT, {
            "p001|" + SIGUE: {"cuando": 1, "router": "p001", "lista": LISTA},
            "p001|" + DEJO: {"cuando": 1, "router": "p001", "lista": LISTA}}, [])
        self.d._registrar_enviados(self.d.MK_SENT_DNS, {
            "p001|" + OTRA: {"cuando": 1, "router": "p001", "lista": LISTA_DNS}}, [])
        # SIGUE y OTRA siguen atacando; DEJO ya no sale en el reporte
        self.p.a.salida("p001", "cuarentena.json", {
            "candidatos": [{"ip": SIGUE, "router": "p001"}],
            "dns_candidatos": [{"ip": OTRA, "router": "p001"}]})
        self.d.reconciliar_cuarentena("p001")

        self.assertIsNone(self.entrada(LISTA, DEJO))                       # dejo de atacar -> fuera
        self.assertNotIn("p001|" + DEJO, self.d.cargar_enviados(self.d.MK_SENT))
        e = self.entrada(LISTA, SIGUE)
        self.assertIsNotNone(e)                                            # sigue atacando -> dentro
        self.assertFalse(e.get("timeout"))                                 # y ya no caduca
        self.assertEqual(e.get("comment"), "suricata escaneo riesgo 80")   # con su comentario
        self.assertFalse(self.entrada(LISTA_DNS, OTRA).get("timeout"))     # la DNS igual
        self.assertIn("p001|" + SIGUE, self.d.cargar_enviados(self.d.MK_SENT))

        # el paso a permanente es una vez por punto: la vuelta siguiente sin bajas no se conecta
        conexiones = []
        conectar = self.d.mk_conectar
        self.d.mk_conectar = lambda dd, timeout=6: conexiones.append(1) or conectar(dd, timeout)
        self.d.reconciliar_cuarentena("p001")
        self.assertEqual(conexiones, [])

    def test_no_toca_lo_que_alguien_puso_a_mano_en_el_router(self):
        """Una entrada que el panel encontro en el router sin haberla puesto («por» mikrotik) es de
        quien la escribio: ni se le quita el timeout."""
        self.r1.cargar("/ip/firewall/address-list", [{"list": LISTA, "address": SIGUE, "timeout": "2h"}])
        self.d._registrar_enviados(self.d.MK_SENT, {"p001|" + SIGUE: {
            "cuando": 1, "router": "p001", "lista": LISTA, "por": "mikrotik", "manual": True}}, [])
        self.p.a.salida("p001", "cuarentena.json", {"candidatos": [{"ip": SIGUE, "router": "p001"}],
                                                     "dns_candidatos": []})
        self.d.reconciliar_cuarentena("p001")
        self.assertEqual(self.entrada(LISTA, SIGUE).get("timeout"), "2h")

    def test_si_no_se_puede_leer_el_router_se_reintenta(self):
        self.r1.cargar("/ip/firewall/address-list", [{"list": LISTA, "address": SIGUE, "timeout": "45m"}])
        self.d._registrar_enviados(self.d.MK_SENT, {"p001|" + SIGUE: {"cuando": 1, "router": "p001",
                                                                       "lista": LISTA}}, [])
        self.p.a.salida("p001", "cuarentena.json", {"candidatos": [{"ip": SIGUE, "router": "p001"}],
                                                     "dns_candidatos": []})
        self.r1.fallar_print = "/ip/firewall/address-list/print"
        self.d.reconciliar_cuarentena("p001")
        self.assertEqual(self.entrada(LISTA, SIGUE).get("timeout"), "45m")
        self.r1.fallar_print = None
        self.d.reconciliar_cuarentena("p001")
        self.assertFalse(self.entrada(LISTA, SIGUE).get("timeout"))


    # --- IPs enviadas a mano --------------------------------------------------------------
    def manual(self, ip, **extra):
        self.r1.cargar("/ip/firewall/address-list", [{"list": LISTA, "address": ip}])
        self.d._registrar_enviados(self.d.MK_SENT, {"p001|" + ip: dict(
            {"cuando": 1, "router": "p001", "lista": LISTA, "por": "ana", "manual": True}, **extra)}, [])

    def test_manual_sale_cuando_ya_no_tiene_alertas_y_en_bajo_se_queda(self):
        self.manual(SIGUE)          # sigue con alertas en banda baja
        self.manual(DEJO)           # ya no tiene ninguna alerta
        self.p.a.salida("p001", "cuarentena.json", {"candidatos": [], "dns_candidatos": [], "vigiladas": [
            {"ip": SIGUE, "router": "p001", "riesgo": 12, "banda": "bajo", "alertas": 1}]})
        self.d.reconciliar_cuarentena("p001")
        self.assertIsNotNone(self.entrada(LISTA, SIGUE))
        self.assertIsNone(self.entrada(LISTA, DEJO))
        self.assertEqual(sorted(self.d.cargar_enviados(self.d.MK_SENT)), ["p001|" + SIGUE])

    def test_manual_con_un_reporte_viejo_sin_vigiladas_no_se_toca(self):
        self.manual(DEJO)
        self.p.a.salida("p001", "cuarentena.json", {"candidatos": [], "dns_candidatos": []})
        self.d.reconciliar_cuarentena("p001")
        self.assertIsNotNone(self.entrada(LISTA, DEJO))

    def test_lo_escrito_a_mano_en_el_router_no_se_libera(self):
        self.manual(DEJO, por="mikrotik")
        self.p.a.salida("p001", "cuarentena.json", {"candidatos": [], "dns_candidatos": [], "vigiladas": []})
        self.d.reconciliar_cuarentena("p001")
        self.assertIsNotNone(self.entrada(LISTA, DEJO))


class Vigiladas(Entorno):
    """El reporte publica las IPs en cuarentena que aun tienen alertas, SIN el tope de 80 de
    top_riesgo: una enviada a mano con pocas alertas quedaba fuera del top y se habria soltado."""

    def test_en_cuarentena_con_alertas_aunque_no_entre_en_el_top(self):
        evs = []
        for i in range(85):                          # 85 CPEs con mas alertas: llenan el top
            evs += [alerta("10.0.0.%d" % (100 + i), "192.0.2.10", hace_s=60 + j, flow_id=5000 + i * 3 + j)
                    for j in range(3)]
        # una sola alerta de las que cuentan (las INFO / «Misc activity» no suman riesgo ni
        # cuentan como actuar mal: esas no la mantendrian)
        evs.append(alerta(SIGUE, "192.0.2.20", flow_id=9001))
        self.eventos("p001", "eve.json", evs)
        self.global_("estado/cuarentena-enviados.json", {
            "p001|" + SIGUE: {"router": "p001", "manual": True},        # 1 alerta, fuera del top
            "p001|" + DEJO: {"router": "p001", "manual": True}})        # sin alertas
        self.ok("60", "--nodo", "p001")
        cuar = self.salida("p001", "cuarentena.json")
        self.assertNotIn(("p001", SIGUE), self.cpes(cuar, "top_riesgo"))
        self.assertEqual(self.cpes(cuar, "vigiladas"), [("p001", SIGUE)])
        v = cuar["vigiladas"][0]
        self.assertEqual(v["alertas"], 1)
        self.assertIn(v["banda"], ("bajo", "MEDIO", "ALTO"))


if __name__ == "__main__":
    unittest.main()
