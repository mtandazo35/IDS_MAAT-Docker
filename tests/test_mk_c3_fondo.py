"""Tareas de fondo contra el MikroTik: una conexion por tanda, liberar solo con confirmacion y
pausa de un router que no responde (tanda MikroTik del 2026-10-14, C3).

Panel real con el MikroTik simulado de `_mikrotik_simulado.py` (via Panel de
test_f1_cuarentena). Se cuentan las conexiones envolviendo mk_conectar.

  - Correccion de defecto (A-05): aplicar_politicas sacaba del registro la IP liberada aunque
    el router NO la hubiera quitado (ignoraba lo que devuelve mk_remove), tambien en la lista
    DNS heredada: el CPE quedaba cortado y fuera del panel.
  - Correccion de defecto (rendimiento): aplicar_politicas, barrido_alto_rapido,
    reconciliar_cuarentena y excluir_destino abrian TLS + login por cada IP.
  - Capacidad nueva: tras 3 fallos de conexion seguidos, las tareas de FONDO de ese punto no
    lo intentan durante una pausa creciente; el primer exito la levanta; la bitacora lo dice
    una vez; las acciones manuales no se frenan.
"""
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
from test_f1_cuarentena import Panel  # noqa: E402
import _dash  # noqa: E402

IPS = ["10.0.0.%d" % i for i in (31, 32, 33)]
DST = "198.51.100.77"


class Fondo(unittest.TestCase):
    def setUp(self):
        self.p = Panel()
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d
        self.conexiones = []
        conectar = self.d.mk_conectar
        self.d.mk_conectar = lambda dd, timeout=6: (self.conexiones.append(dd.get("ROUTER_ID"))
                                                     or conectar(dd, timeout))
        self.d.guardar_mk({"AUTO_MANTENER": "1", "POL_AUTO": "1", "POL_BOTNET": "alto"})

    # --- utilidades ------------------------------------------------------------------------
    def top(self, pid, ips):
        ahora = int(time.time())
        self.p.a.salida(pid, "cuarentena.json", {"candidatos": [], "dns_candidatos": [], "top_riesgo": [
            {"ip": ip, "router": pid, "banda": "ALTO", "riesgo": 90, "ultima": ahora,
             "cats_top": {"Botnet CnC": 5}} for ip in ips]})

    def registrar(self, path, entradas):
        self.d._registrar_enviados(path, entradas, [])

    def bitacora(self):
        try:
            with open(self.d.BITACORA_LOG, encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""

    def mklog(self):
        try:
            with open(self.d.MK_LOG, encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""

    def con(self, pid, fn, *a):
        with self.p.n.contexto(pid):
            return fn(*a)


class UnaConexion(Fondo):
    def test_politicas_altas_y_bajas_en_una_conexion(self):
        """aplicar_politicas mete tres CPEs y saca dos que ya no califican (uno de la lista DNS
        heredada) con UNA conexion al router de p001; p002 no recibe nada."""
        r1 = self.p.routers["p001"]
        r1.cargar("/ip/firewall/address-list", [{"list": "clientes-botnet", "address": "10.0.0.40"},
                                                 {"list": "lista-dns-vieja", "address": "10.0.0.41"}])
        self.registrar(self.d.MK_SENT, {"p001|10.0.0.40": {"cuando": 1, "pol": True, "router": "p001",
                                                           "lista": "clientes-botnet"}})
        self.registrar(self.d.MK_SENT_DNS, {"p001|10.0.0.41": {"cuando": 1, "pol": True, "router": "p001",
                                                               "lista": "lista-dns-vieja"}})
        self.top("p001", IPS)
        self.con("p001", self.d.aplicar_politicas, "p001")
        self.assertEqual(self.conexiones, ["p001"])
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), sorted(IPS))
        self.assertEqual(self.p.lista("p001", "lista-dns-vieja"), [])
        self.assertEqual(sorted(self.d.cargar_enviados(self.d.MK_SENT)), sorted("p001|" + ip for ip in IPS))
        self.assertEqual(self.d.cargar_enviados(self.d.MK_SENT_DNS), {})
        self.assertEqual(self.p.lista("p002", "clientes-botnet"), [])
        self.assertEqual(self.mklog().count("POLITICA-ENVIADO"), 3)
        self.assertEqual(self.mklog().count("POLITICA-LIBERADO"), 2)

    def test_barrido_rapido_varios_cpes_una_conexion(self):
        """El barrido manda a cuarentena tres CPEs con infeccion confirmada en una sola conexion."""
        self.p.a.eve("p001", [_dash.alerta(src=ip, hace=30 - i) for ip in IPS for i in range(4)])
        self.con("p001", self.d.barrido_alto_rapido, "p001")
        self.assertEqual(self.conexiones, ["p001"])
        # sin reporte, la clase sale de categoria_cpe (otros): la lista es la de esa clase
        lst = self.con("p001", lambda: self.d.lista_de_categoria(self.d.categoria_cpe("p001|" + IPS[0])))
        self.assertEqual(self.p.lista("p001", lst), sorted(IPS))
        env = self.d.cargar_enviados()
        self.assertEqual(sorted(env), sorted("p001|" + ip for ip in IPS))
        self.assertTrue(all(e["lista"] == lst and e["pol"] for e in env.values()))
        self.assertEqual(self.mklog().count("POLITICA-RAPIDA"), 3)

    def test_reconciliar_dos_listas_una_conexion(self):
        """El reconciliador libera de las dos listas (candidatos y DNS) con una conexion."""
        r1 = self.p.routers["p001"]
        r1.cargar("/ip/firewall/address-list", [{"list": "clientes-escaneo", "address": IPS[0]},
                                                 {"list": "clientes-escaneo", "address": IPS[1]},
                                                 {"list": "clientes-dns-malware", "address": IPS[2]}])
        self.registrar(self.d.MK_SENT, {"p001|" + IPS[0]: {"cuando": 1, "router": "p001", "lista": "clientes-escaneo"},
                                        "p001|" + IPS[1]: {"cuando": 1, "router": "p001", "lista": "clientes-escaneo"}})
        self.registrar(self.d.MK_SENT_DNS, {"p001|" + IPS[2]: {"cuando": 1, "router": "p001",
                                                               "lista": "clientes-dns-malware"}})
        self.p.a.salida("p001", "cuarentena.json", {"candidatos": [], "dns_candidatos": []})
        self.con("p001", self.d.reconciliar_cuarentena, "p001")
        self.assertEqual(self.conexiones, ["p001"])
        self.assertEqual(self.p.lista("p001", "clientes-escaneo"), [])
        self.assertEqual(self.p.lista("p001", "clientes-dns-malware"), [])
        self.assertEqual(self.d.cargar_enviados(self.d.MK_SENT), {})
        self.assertEqual(self.d.cargar_enviados(self.d.MK_SENT_DNS), {})
        self.assertEqual(self.mklog().count("AUTO-LIBERADO"), 3)

    def test_sin_nada_que_hacer_no_se_conecta(self):
        """Una vuelta sin altas ni bajas no abre ninguna conexion al router."""
        self.top("p001", [])
        self.p.a.salida("p001", "cuarentena.json", {"candidatos": [], "dns_candidatos": [], "top_riesgo": []})
        self.con("p001", self.d.aplicar_politicas, "p001")
        self.con("p001", self.d.reconciliar_cuarentena, "p001")
        self.assertEqual(self.conexiones, [])

    def test_excluir_destino_una_conexion_por_router(self):
        """excluir_destino libera los CPEs bloqueados por ese destino con UNA conexion por router
        (dos en p001, uno de ellos en el registro DNS, y uno en p002)."""
        motivo = {"destinos_ip": [DST]}
        for pid, ip, lst in (("p001", IPS[0], "clientes-botnet"), ("p001", IPS[1], "clientes-dns-malware"),
                             ("p002", IPS[2], "clientes-botnet")):
            self.p.routers[pid].cargar("/ip/firewall/address-list", [{"list": lst, "address": ip}])
        self.registrar(self.d.MK_SENT, {
            "p001|" + IPS[0]: {"cuando": 1, "router": "p001", "lista": "clientes-botnet", "motivo": motivo},
            "p002|" + IPS[2]: {"cuando": 1, "router": "p002", "lista": "clientes-botnet", "motivo": motivo}})
        self.registrar(self.d.MK_SENT_DNS, {
            "p001|" + IPS[1]: {"cuando": 1, "router": "p001", "lista": "clientes-dns-malware", "motivo": motivo}})
        n, msg = self.d.excluir_destino(DST)
        self.assertEqual(n, 3, msg)
        self.assertEqual(sorted(self.conexiones), ["p001", "p002"])
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), [])
        self.assertEqual(self.p.lista("p001", "clientes-dns-malware"), [])
        self.assertEqual(self.p.lista("p002", "clientes-botnet"), [])
        self.assertEqual(self.d.cargar_enviados(self.d.MK_SENT), {})
        self.assertEqual(self.d.cargar_enviados(self.d.MK_SENT_DNS), {})


class LiberarConConfirmacion(Fondo):
    def test_politica_no_suelta_lo_que_el_router_no_quito(self):
        """Correccion de defecto (A-05): con el remove rechazado (!trap) la IP sigue en el
        registro (y en el router) y no se anota como liberada; la vuelta siguiente, con el
        router bien, la libera. Igual en la lista DNS heredada."""
        r1 = self.p.routers["p001"]
        r1.cargar("/ip/firewall/address-list", [{"list": "clientes-botnet", "address": "10.0.0.40"},
                                                 {"list": "lista-dns-vieja", "address": "10.0.0.41"}])
        k, kd = "p001|10.0.0.40", "p001|10.0.0.41"
        self.registrar(self.d.MK_SENT, {k: {"cuando": 1, "pol": True, "router": "p001", "lista": "clientes-botnet"}})
        self.registrar(self.d.MK_SENT_DNS, {kd: {"cuando": 1, "pol": True, "router": "p001",
                                                 "lista": "lista-dns-vieja"}})
        self.top("p001", [])
        r1.fallar_en = r1._n + 1          # el primer remove: rechazado
        self.con("p001", self.d.aplicar_politicas, "p001")
        self.assertIn(k, self.d.cargar_enviados(self.d.MK_SENT))
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), ["10.0.0.40"])
        self.assertNotIn("POLITICA-LIBERADO 10.0.0.40", self.mklog())
        # la DNS heredada (segundo remove) si se confirmo: sale
        self.assertNotIn(kd, self.d.cargar_enviados(self.d.MK_SENT_DNS))
        # ahora la DNS heredada falla y la otra va bien
        self.registrar(self.d.MK_SENT_DNS, {kd: {"cuando": 1, "pol": True, "router": "p001",
                                                 "lista": "lista-dns-vieja"}})
        r1.cargar("/ip/firewall/address-list", [{"list": "lista-dns-vieja", "address": "10.0.0.41"}])
        r1.fallar_en = r1._n + 2          # el segundo remove (el de la DNS heredada)
        self.con("p001", self.d.aplicar_politicas, "p001")
        self.assertNotIn(k, self.d.cargar_enviados(self.d.MK_SENT))
        self.assertIn(kd, self.d.cargar_enviados(self.d.MK_SENT_DNS))
        self.assertEqual(self.p.lista("p001", "lista-dns-vieja"), ["10.0.0.41"])
        r1.fallar_en = None
        self.con("p001", self.d.aplicar_politicas, "p001")
        self.assertNotIn(kd, self.d.cargar_enviados(self.d.MK_SENT_DNS))
        self.assertEqual(self.p.lista("p001", "lista-dns-vieja"), [])

    def test_router_caido_no_suelta_nada(self):
        """Sin conexion nada se da por liberado ni por enviado: todo queda para la vuelta siguiente."""
        k = "p001|10.0.0.40"
        self.registrar(self.d.MK_SENT, {k: {"cuando": 1, "pol": True, "router": "p001", "lista": "clientes-botnet"}})
        self.top("p001", [IPS[0]])
        self.p.caidos.add("p001")
        self.con("p001", self.d.aplicar_politicas, "p001")
        self.assertEqual(sorted(self.d.cargar_enviados()), [k])


class Pausa(Fondo):
    def caer_tres_veces(self):
        self.p.caidos.add("p001")
        self.registrar(self.d.MK_SENT, {"p001|10.0.0.40": {"cuando": 1, "router": "p001",
                                                           "lista": "clientes-escaneo"}})
        self.p.a.salida("p001", "cuarentena.json", {"candidatos": [], "dns_candidatos": []})
        for _ in range(3):
            self.con("p001", self.d.reconciliar_cuarentena, "p001")

    def test_tres_fallos_pausan_solo_ese_punto_y_se_dice_una_vez(self):
        self.caer_tres_veces()
        self.assertEqual(self.conexiones, ["p001"] * 3)
        pausa = self.d.mk_pausa("p001")
        self.assertIsNotNone(pausa)
        self.assertEqual(pausa["fallos"], 3)
        self.assertGreater(pausa["restante"], 60)
        self.assertIsNone(self.d.mk_pausa("p002"))
        # mientras dura: ni reconciliar, ni politicas, ni barrido intentan conectar
        self.top("p001", IPS)
        for _ in range(5):
            self.con("p001", self.d.reconciliar_cuarentena, "p001")
            self.con("p001", self.d.aplicar_politicas, "p001")
            self.con("p001", self.d.barrido_alto_rapido, "p001")
        self.assertEqual(self.conexiones, ["p001"] * 3)
        self.assertEqual(self.bitacora().count("MK-PAUSA\t"), 1)
        # el otro punto sigue a lo suyo
        self.top("p002", [IPS[0]])
        self.con("p002", self.d.aplicar_politicas, "p002")
        self.assertEqual(self.p.lista("p002", "clientes-botnet"), [IPS[0]])

    def test_la_espera_crece_con_tope_y_el_primer_exito_la_levanta(self):
        self.caer_tres_veces()
        primera = self.d.mk_pausa("p001")["restante"]
        # vence la pausa y vuelve a fallar: espera mas larga, sin otra linea en la bitacora
        self.d._MK_PAUSA["p001"]["hasta"] = time.time() - 1
        self.con("p001", self.d.reconciliar_cuarentena, "p001")
        segunda = self.d.mk_pausa("p001")["restante"]
        self.assertGreater(segunda, primera)
        for _ in range(20):               # muchas prorrogas: no pasa del tope
            self.d._MK_PAUSA["p001"]["hasta"] = time.time() - 1
            self.con("p001", self.d.reconciliar_cuarentena, "p001")
        self.assertLessEqual(self.d.mk_pausa("p001")["restante"], self.d.MK_PAUSA_TOPE + 1)
        self.assertEqual(self.bitacora().count("MK-PAUSA\t"), 1)
        # vuelve el router y vence la pausa: el primer exito la levanta y se dice una vez
        self.p.caidos.discard("p001")
        self.p.routers["p001"].cargar("/ip/firewall/address-list",
                                      [{"list": "clientes-escaneo", "address": "10.0.0.40"}])
        self.d._MK_PAUSA["p001"]["hasta"] = time.time() - 1
        self.con("p001", self.d.reconciliar_cuarentena, "p001")
        self.assertIsNone(self.d.mk_pausa("p001"))
        self.assertNotIn("p001", self.d._MK_PAUSA)
        self.assertEqual(self.d.cargar_enviados(), {})
        self.assertEqual(self.bitacora().count("MK-PAUSA-FIN"), 1)

    def test_menos_de_tres_fallos_no_pausa_y_un_exito_reinicia_la_cuenta(self):
        self.p.caidos.add("p001")
        self.registrar(self.d.MK_SENT, {"p001|10.0.0.40": {"cuando": 1, "router": "p001",
                                                           "lista": "clientes-escaneo"}})
        self.p.a.salida("p001", "cuarentena.json", {"candidatos": [], "dns_candidatos": []})
        for _ in range(2):
            self.con("p001", self.d.reconciliar_cuarentena, "p001")
        self.p.caidos.discard("p001")
        self.con("p001", self.d.reconciliar_cuarentena, "p001")      # exito: cuenta a cero
        self.registrar(self.d.MK_SENT, {"p001|10.0.0.40": {"cuando": 1, "router": "p001",
                                                           "lista": "clientes-escaneo"}})
        self.p.caidos.add("p001")
        for _ in range(2):
            self.con("p001", self.d.reconciliar_cuarentena, "p001")
        self.assertIsNone(self.d.mk_pausa("p001"))
        self.assertNotIn("MK-PAUSA", self.bitacora())

    def test_la_accion_manual_no_se_frena_y_levanta_la_pausa(self):
        """excluir_destino (accion del operador) habla con el router aunque este en pausa; si
        conecta, la pausa se levanta para las tareas de fondo."""
        self.caer_tres_veces()
        self.p.caidos.discard("p001")
        self.p.routers["p001"].cargar("/ip/firewall/address-list",
                                      [{"list": "clientes-botnet", "address": IPS[0]}])
        self.registrar(self.d.MK_SENT, {"p001|" + IPS[0]: {"cuando": 1, "router": "p001", "lista": "clientes-botnet",
                                                           "motivo": {"destinos_ip": [DST]}}})
        antes = len(self.conexiones)
        n, msg = self.d.excluir_destino(DST)
        self.assertEqual(n, 1, msg)
        self.assertEqual(self.conexiones[antes:], ["p001"])
        self.assertIsNone(self.d.mk_pausa("p001"))
        self.assertIn("MK-PAUSA-FIN", self.bitacora())

    def test_diagnostico_no_insiste_con_un_router_en_pausa(self):
        """guardar_diagnostico cuenta sus fallos de conexion, se salta el router en pausa
        (dice por que) y sigue midiendo los demas."""
        d = self.d
        d.mk_diagnostico = lambda r: d.mk_conectar(d.cargar_mk_de(r)).close() or [("ok", "t", "", "")]
        self.p.caidos.add("p001")
        for _ in range(3):
            d.guardar_diagnostico()
        self.assertIsNotNone(d.mk_pausa("p001"))
        antes = list(self.conexiones)
        d.guardar_diagnostico()
        self.assertEqual(self.conexiones[len(antes):], ["p002"])
        with open(d.DIAG_FILE, encoding="utf-8") as f:
            diag = json.load(f)
        self.assertIn("sin conexion con el MikroTik", diag["p001"]["error"])
        self.assertIn("checks", diag["p002"])


if __name__ == "__main__":
    unittest.main()
