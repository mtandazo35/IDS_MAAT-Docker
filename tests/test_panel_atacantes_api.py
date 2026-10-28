"""«Cortar atacantes de internet» por la API (el user, 2026-10-28): el panel manda al MikroTik de cada
punto, por la API, las IPs de internet que atacan a SUS abonados (las de Histórico) a la address-list
suricata-atacantes con caducidad de 1 dia, y pone dos reglas de filter (forward e input,
connection-state=new) con el mecanismo de las politicas. Por punto: apagado (de fabrica),
automatico (cada 15 min) o solo a mano.

- Nucleo contra el MikroTik simulado (_mikrotik_simulado, ampliado con raw/nat/queue tree como en
  test_mk_c4_diagnostico): reglas y lista, idempotencia, renovacion, tope y orden, filtros, apagar
  quita solo lo nuestro, punto en baja, automatico, y los hallazgos de la auditoria (M1-M8, B3, B5).
- Panel por HTTP (montaje de test_panel_alcance: olga operador [p001], luis lectura [p001], dora
  operador [p003, p001]): la seccion de la ficha y su POST con el permiso puntos.atacantes y solo en
  sus puntos; «Enviar al MikroTik ahora» de Histórico; la columna «En el router» (B1, B2).

Tipo: capacidad nueva (todas). Datos RFC 5737 (auditoria B4): los rangos de documentacion no son
globales y blocklist_borde los descarta; aqui se tratan como de internet parcheando is_global.
"""
import importlib.util
import ipaddress
import json
import os
import sys
import threading
import time
import unittest
from unittest import mock

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
sys.path.insert(0, os.path.join(AQUI, "fixtures", "panel2"))
from test_f1_cuarentena import Panel  # noqa: E402
from test_mk_c4_diagnostico import RouterCompleto  # noqa: E402
import test_panel_alcance as A  # noqa: E402

HAY_CRYPTO = importlib.util.find_spec("cryptography") is not None
FILTER, ALIST = "/ip/firewall/filter", "/ip/firewall/address-list"
LISTA = "suricata-atacantes"
# de mas a menos alertas (todas por encima del criterio: 20 alertas contra 3 destinos). Ojo: el
# MikroTik de p001 conecta desde 198.51.100.11 y el de p002 desde 198.51.100.12 (fixture _dash)
ATQ = [("203.0.113.10", 900, 40), ("198.51.100.20", 300, 12), ("192.0.2.30", 120, 6), ("203.0.113.40", 60, 4)]
PRIVADA = "10.0.0.77"          # una IP de tus redes: nunca va
WAN_P2 = "198.51.100.12"       # desde donde conecta el MikroTik de p002 (M8)
_DOC = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
_G4 = ipaddress.IPv4Address.is_global.fget
_G6 = ipaddress.IPv6Address.is_global.fget


def doc_global(caso):
    """B4: las IPs de documentacion cuentan como de internet durante la prueba."""
    for cls, orig in ((ipaddress.IPv4Address, _G4), (ipaddress.IPv6Address, _G6)):
        p = mock.patch.object(cls, "is_global", property(
            lambda a, o=orig: any(a.version == n.version and a in n for n in _DOC) or o(a)))
        p.start()
        caso.addCleanup(p.stop)


def entrantes(ips, generado=None):
    ahora = int(time.time())
    return {"generado": ahora if generado is None else generado,
            "origenes": {ip: {"alertas": al, "destinos": ds, "pais": "XX", "ultima": ahora - 60,
                              "firma": "ET SCAN Potential SSH Scan", "puertos": [22]} for ip, al, ds in ips}}


@unittest.skipUnless(HAY_CRYPTO, "falta cryptography (python3-cryptography en la imagen)")
class Nucleo(unittest.TestCase):
    def setUp(self):
        doc_global(self)
        self.p = Panel()
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d
        if not self.d.secretos.disponible():
            self.skipTest("sin clave maestra: no se guardan los routers")
        self.p.routers["p001"] = RouterCompleto("norte")
        self.p.routers["p002"] = RouterCompleto("sur")
        self.r1, self.r2 = self.p.routers["p001"], self.p.routers["p002"]
        self.p.a.salida("p001", "entrantes.json", entrantes(ATQ + [(PRIVADA, 500, 9)]))
        self.p.a.salida("p002", "entrantes.json", entrantes([("203.0.113.50", 700, 20)]))

    # ---- ayudas ----
    def reglas(self, r):
        return [f for f in r.tablas[FILTER] if (f.get("comment") or "").startswith("Suricata:atacantes:")]

    def lista(self, r):
        return {f["address"]: f for f in r.tablas[ALIST] if f["list"] == LISTA}

    def reg(self):
        try:
            with open(self.d.ATAC_SENT, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def activar(self, pid="p001", modo="manual"):
        self.d.guardar_atacantes_modo(pid, modo, "ana")

    def todas(self):
        return sorted(ip for ip, _a, _d in ATQ)

    # ---- lo basico ----
    def test_apagado_de_fabrica_no_manda_nada(self):
        self.assertEqual(self.d.atacantes_modo("p001"), "")
        res = self.d.atacantes_enviar("p001", "ana")
        self.assertFalse(res["ok"])
        self.assertIn("no tiene activado", res["mensaje"])
        self.assertEqual((self.r1.escrituras, self.r2.escrituras), ([], []))

    def test_envio_pone_las_dos_reglas_y_la_lista_solo_en_su_router(self):
        self.activar()
        res = self.d.atacantes_enviar("p001", "ana")
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["enviadas"], len(ATQ))
        reglas = self.reglas(self.r1)
        self.assertEqual(sorted(f["chain"] for f in reglas), ["forward", "input"])
        for f in reglas:
            self.assertEqual((f["action"], f["connection-state"], f["src-address-list"]), ("drop", "new", LISTA))
        lst = self.lista(self.r1)
        self.assertEqual(sorted(lst), self.todas())
        for f in lst.values():
            self.assertEqual(f.get("timeout"), "1d")
            self.assertTrue(f.get("comment", "").startswith("Suricata atacante"))
        self.assertNotIn(PRIVADA, lst)
        self.assertEqual(self.r2.escrituras, [])                # el router del otro punto, intacto
        self.assertEqual(sorted(self.reg()), sorted("p001|" + ip for ip in self.todas()))
        self.assertTrue(os.listdir(self.d.RESPALDOS_MK))          # respaldo antes del primer cambio

    def test_las_reglas_van_arriba_de_su_cadena(self):
        self.r1.cargar(FILTER, [{"chain": "forward", "action": "accept", "comment": "aceptar todo"},
                                {"chain": "input", "action": "accept", "comment": "aceptar todo input"}])
        self.activar()
        self.assertTrue(self.d.atacantes_enviar("p001", "ana")["ok"])
        for cadena in ("forward", "input"):
            primera = next(f for f in self.r1.tablas[FILTER] if f["chain"] == cadena)
            self.assertTrue(primera.get("comment", "").startswith("Suricata:atacantes:"), primera)

    def test_segundo_envio_no_repite_nada(self):
        self.activar()
        self.d.atacantes_enviar("p001", "ana")
        n = len(self.r1.escrituras)
        res = self.d.atacantes_enviar("p001", "ana")
        self.assertTrue(res["ok"], res)
        self.assertEqual((res["enviadas"], res["renovadas"], res["al_dia"]), (0, 0, len(ATQ)))
        self.assertEqual(len(self.r1.escrituras), n)              # ni reglas ni IPs otra vez
        self.assertEqual(len(self.reglas(self.r1)), 2)

    def test_renueva_la_que_caduca_pronto(self):
        self.activar()
        self.d.atacantes_enviar("p001", "ana")
        reg = self.reg()
        reg["p001|203.0.113.10"]["hasta"] = int(time.time()) + 3600   # le queda 1 h (< 12 h)
        with open(self.d.ATAC_SENT, "w", encoding="utf-8") as f:
            json.dump(reg, f)
        res = self.d.atacantes_enviar("p001", "ana")
        self.assertEqual((res["renovadas"], res["enviadas"]), (1, 0), res)
        self.assertGreater(self.reg()["p001|203.0.113.10"]["hasta"], time.time() + 23 * 3600)
        self.assertEqual(len(self.lista(self.r1)), len(ATQ))     # renovada, no duplicada

    def test_tope_por_envio_las_de_mas_alertas(self):
        self.d.ATAC_TOPE = 2
        self.activar()
        self.d.atacantes_enviar("p001", "ana")
        self.assertEqual(sorted(self.lista(self.r1)), ["198.51.100.20", "203.0.113.10"])

    def test_nunca_bloquear_y_publicas_de_otro_punto_no_van(self):
        with open(self.d.NUNCA_FILE, "w", encoding="utf-8") as f:
            f.write("p001|192.0.2.30\n")
        self.d.guardar_publicas({"p002": ["203.0.113.40"]})       # publica declarada de OTRO punto
        self.activar()
        self.d.atacantes_enviar("p001", "ana")
        self.assertEqual(sorted(self.lista(self.r1)), ["198.51.100.20", "203.0.113.10"])

    def test_apagar_quita_solo_lo_nuestro(self):
        self.r1.cargar(FILTER, [{"chain": "forward", "action": "drop", "src-address-list": LISTA,
                                 "comment": "Suricata: atacantes de internet"}])     # pegada a mano
        self.r1.cargar(ALIST, [{"list": LISTA, "address": "192.0.2.200", "comment": "cins"},  # /blocklist.rsc
                               {"list": "otra", "address": "203.0.113.10", "comment": "Suricata atacante: x",
                                "timeout": "1d"}])
        self.activar()
        self.d.atacantes_enviar("p001", "ana")
        ok, msg = self.d.atacantes_apagar("p001", "ana")
        self.assertTrue(ok, msg)
        self.assertEqual(self.reglas(self.r1), [])
        self.assertEqual(sorted(self.lista(self.r1)), ["192.0.2.200"])
        self.assertTrue(any(f.get("comment") == "Suricata: atacantes de internet" for f in self.r1.tablas[FILTER]))
        self.assertTrue(any(f["list"] == "otra" for f in self.r1.tablas[ALIST]))
        self.assertEqual(self.reg(), {})
        self.assertEqual(self.d.atacantes_modo("p001"), "")        # apagar deja el modo apagado

    def test_apagar_con_el_router_caido_no_olvida_nada(self):
        self.activar()
        self.d.atacantes_enviar("p001", "ana")
        self.p.caidos.add("p001")
        ok, msg = self.d.atacantes_apagar("p001", "ana")
        self.assertFalse(ok)
        self.assertEqual(len(self.reg()), len(ATQ))
        self.assertEqual(self.d.atacantes_modo("p001"), "manual")

    def test_punto_en_baja_no_recibe_nada(self):
        self.activar()
        self.d._BAJAS.add("p001")
        self.addCleanup(self.d._BAJAS.discard, "p001")
        res = self.d.atacantes_enviar("p001", "ana")
        self.assertFalse(res["ok"])
        self.assertEqual(self.r1.escrituras, [])

    def test_automatico_solo_en_modo_auto_y_cada_15_min(self):
        self.activar(modo="manual")
        self.assertIsNone(self.d.atacantes_auto("p001"))
        self.assertEqual(self.r1.escrituras, [])
        self.activar(modo="auto")
        self.assertTrue(self.d.atacantes_auto("p001")["ok"])
        n = len(self.r1.escrituras)
        self.assertIsNone(self.d.atacantes_auto("p001"))         # aun no tocan los 15 min
        self.assertEqual(len(self.r1.escrituras), n)
        self.assertAlmostEqual(self.d._ATAC_PROX["p001"][0] - time.time(), self.d.ATAC_CADA_S, delta=5)

    def test_automatico_espera_mas_si_el_router_falla(self):
        self.activar(modo="auto")
        self.p.caidos.add("p001")
        self.assertFalse(self.d.atacantes_auto("p001")["ok"])
        prox, fallos = self.d._ATAC_PROX["p001"]
        self.assertEqual(fallos, 1)
        self.assertGreater(prox - time.time(), self.d.ATAC_CADA_S)

    def test_baja_del_punto_olvida_modo_y_registro(self):
        self.activar("p001")
        self.activar("p002")
        self.d.atacantes_enviar("p001", "ana")
        self.d.atacantes_enviar("p002", "ana")
        self.d.purgar_punto("p001", quien="ana")
        self.addCleanup(self.d._BAJAS.discard, "p001")
        self.assertEqual(self.d.atacantes_modo("p001"), "")
        self.assertEqual(self.d.atacantes_modo("p002"), "manual")
        self.assertEqual(sorted(self.reg()), ["p002|203.0.113.50"])

    def test_modo_no_valido(self):
        with self.assertRaises(ValueError):
            self.d.guardar_atacantes_modo("p001", "siempre", "ana")

    def test_literales_casan_con_las_constantes(self):
        """lista_de_categoria y reglas_de_accion llevan literales (las pruebas heredadas las sacan por
        ast): tienen que seguir casando con ATAC_CAT, ATAC_ACCION y BL_LISTA."""
        d = self.d
        self.assertEqual(d.lista_de_categoria(d.ATAC_CAT), d.BL_LISTA)
        self.assertEqual(len(d.reglas_de_accion(d.ATAC_CAT, d.ATAC_ACCION, d.BL_LISTA)), 2)

    # ---- auditoria ----
    def test_m1_apagado_mientras_espera_el_cerrojo_gana(self):
        """M1: un envio que espera el cerrojo del punto relee el modo dentro: si entre tanto se apago,
        no pone nada."""
        self.activar()
        out = {}
        with self.d.cerrojo_operacion("p001", "atacantes", espera=1):
            t = threading.Thread(target=lambda: out.update(self.d.atacantes_enviar("p001", "ana")))
            t.start()
            time.sleep(0.3)
            self.d.guardar_atacantes_modo("p001", "", "ana")
        t.join(20)
        self.assertFalse(out.get("ok"), out)
        self.assertIn("se apagó", out.get("mensaje", ""))
        self.assertEqual(self.r1.escrituras, [])
        self.assertEqual(self.reg(), {})

    def test_m1_apagar_durante_un_envio_queda_todo_quitado(self):
        """M1: un apagado pedido mientras un envio habla con el router espera a que termine y despues
        quita todo: no queda nada nuestro en el router, ni en el registro, y el modo queda apagado."""
        self.activar(modo="auto")
        orig = self.d._atac_add_en
        hilo = {}

        def add(s_, ip, com, ents):
            if "t" not in hilo:
                hilo["t"] = threading.Thread(target=lambda: hilo.update(r=self.d.atacantes_apagar("p001", "ana")))
                hilo["t"].start()
                time.sleep(0.3)
            return orig(s_, ip, com, ents)
        self.d._atac_add_en = add
        res = self.d.atacantes_enviar("p001", "ana")
        hilo["t"].join(30)
        self.assertTrue(res["ok"], res)
        self.assertTrue(hilo["r"][0], hilo["r"])
        self.assertEqual(self.lista(self.r1), {})
        self.assertEqual(self.reglas(self.r1), [])
        self.assertEqual(self.reg(), {})
        self.assertEqual(self.d.atacantes_modo("p001"), "")
        self.d._atac_add_en = orig
        self.assertIsNone(self.d.atacantes_auto("p001"))          # y el automatico ya no manda

    def test_m2_lo_puesto_a_mano_no_se_toca(self):
        self.r1.cargar(ALIST, [{"list": LISTA, "address": "203.0.113.10", "comment": "cins"},
                               {"list": LISTA, "address": "198.51.100.20", "comment": "Suricata atacante: a mano"}])
        antes = {f[".id"]: dict(f) for f in self.r1.tablas[ALIST]}
        self.activar()
        res = self.d.atacantes_enviar("p001", "ana")
        self.assertEqual(res["ajenas"], 2, res)
        for rid, f in antes.items():
            self.assertEqual(self.r1.fila(ALIST, rid), f)           # ni set ni remove
        self.assertNotIn("p001|203.0.113.10", self.reg())
        self.assertNotIn("p001|198.51.100.20", self.reg())
        self.assertIn("p001|192.0.2.30", self.reg())

    def test_m3_router_reiniciado_se_reenvia_y_el_registro_se_corrige(self):
        self.activar()
        self.d.atacantes_enviar("p001", "ana")
        reg = self.reg()
        reg["p001|192.0.2.222"] = {"ts": int(time.time()), "hasta": int(time.time()) + 80000, "por": "x"}
        with open(self.d.ATAC_SENT, "w", encoding="utf-8") as f:
            json.dump(reg, f)
        self.r1.tablas[ALIST] = []                                   # lista vaciada (router reiniciado)
        res = self.d.atacantes_enviar("p001", "ana")
        self.assertEqual(res["enviadas"], len(ATQ), res)
        self.assertEqual(sorted(self.lista(self.r1)), self.todas())
        self.assertNotIn("p001|192.0.2.222", self.reg())

    def test_m4_apagar_sin_api_no_olvida_salvo_sin_limpiar(self):
        self.activar()
        self.d.atacantes_enviar("p001", "ana")
        self.d.guardar_routers([{"id": "p001", "USER": "u", "PASS": ""}])
        self.assertFalse(self.d.atacantes_api_lista("p001"))
        n = len(self.r1.escrituras)
        ok, msg = self.d.atacantes_apagar("p001", "ana")
        self.assertFalse(ok)
        self.assertIn("sin la API", msg)
        self.assertEqual((self.d.atacantes_modo("p001"), len(self.reg())), ("manual", len(ATQ)))
        ok, msg = self.d.atacantes_apagar("p001", "ana", sin_limpiar=True)
        self.assertTrue(ok, msg)
        self.assertEqual((self.d.atacantes_modo("p001"), self.reg()), ("", {}))
        self.assertEqual(len(self.r1.escrituras), n)                 # el router no se toco
        self.assertFalse(self.d.atacantes_api_lista("p001", {"USER": "u", "PASS": "", "_PASS_ILEGIBLE": "1"}))

    def test_m5_la_baja_quita_reglas_y_lista(self):
        self.activar()
        self.d.atacantes_enviar("p001", "ana")
        self.assertEqual(self.d._pendientes_router("p001"), len(ATQ))
        acum = {"quitadas": 0, "fallos": []}
        s_ = self.r1.conexion()
        self.d._quitar_de_router(s_, "p001", self.d.cargar_mk_de(self.d.router_por_id("p001")), "ana", acum)
        self.assertEqual((acum["quitadas"], acum["fallos"]), (len(ATQ), []))
        self.assertEqual((self.lista(self.r1), self.reglas(self.r1)), ({}, []))
        self.assertEqual(self.reg(), {})

    def test_m6_ipv6_fuera_y_un_rechazo_no_es_corte(self):
        self.p.a.salida("p001", "entrantes.json", entrantes(ATQ + [("2001:db8::5", 999, 50)]))
        self.assertNotIn("2001:db8::5", [f["ip"] for f in self.d.atacantes_de_punto("p001")])
        self.activar(modo="auto")
        self.r1.fallar_en = 3            # 2 escrituras de las reglas; la 3.a (la primera IP) se rechaza
        res = self.d.atacantes_auto("p001")
        self.assertEqual((res["fallos"], res["corte"]), (1, False), res)
        self.assertEqual(res["enviadas"], len(ATQ) - 1)
        prox, fallos = self.d._ATAC_PROX["p001"]
        self.assertEqual(fallos, 0)
        self.assertAlmostEqual(prox - time.time(), self.d.ATAC_CADA_S, delta=5)

    def test_m6_envio_en_curso_no_cuenta_para_la_espera(self):
        self.activar(modo="auto")
        with self.d.cerrojo_operacion("p001", "atacantes", espera=1):
            res = self.d.atacantes_auto("p001")
        self.assertTrue(res["en_curso"], res)
        prox, fallos = self.d._ATAC_PROX["p001"]
        self.assertEqual(fallos, 0)
        self.assertLess(prox - time.time(), 120)

    def test_m7_enviar_no_respeta_y_apagar_si(self):
        self.activar()
        self.d.guardar_routers([{"id": "p001", "ENABLED": "0"}])
        res = self.d.atacantes_enviar("p001", "ana")
        self.assertFalse(res["ok"])
        self.assertIn("solo sugerencias", res["mensaje"])
        self.assertEqual(self.r1.escrituras, [])
        ok, msg = self.d.atacantes_apagar("p001", "ana")
        self.assertTrue(ok, msg)
        self.assertEqual(self.d.atacantes_modo("p001"), "")

    def test_m8_ni_la_wan_de_un_mikrotik_ni_la_del_panel(self):
        self.p.a.salida("p001", "entrantes.json", entrantes(ATQ + [(WAN_P2, 800, 30), ("203.0.113.99", 700, 30)]))
        orig = self.d.conf_dash_get
        self.d.conf_dash_get = lambda k, dflt="": "https://203.0.113.99:5637" if k == "PANEL_URL" else orig(k, dflt)
        ips = [f["ip"] for f in self.d.atacantes_de_punto("p001")]
        self.assertNotIn(WAN_P2, ips)
        self.assertNotIn("203.0.113.99", ips)
        self.assertEqual(sorted(ips), self.todas())

    def test_b3_automatico_no_manda_con_datos_viejos(self):
        self.p.a.salida("p001", "entrantes.json", entrantes(ATQ, generado=int(time.time()) - 3 * 86400))
        self.activar(modo="auto")
        self.assertIsNone(self.d.atacantes_auto("p001"))
        self.assertEqual(self.r1.escrituras, [])

    def test_b5_el_ciclo_del_punto_lo_manda_solo_en_auto(self):
        d = self.d
        for nom in ("generar_reporte",):
            setattr(d, nom, lambda pid, vmin: 0)
        for nom in ("reconciliar_cuarentena", "evaluar_bloqueos", "aplicar_politicas"):
            setattr(d, nom, lambda pid: None)
        self.activar(modo="manual")
        d._ciclo_nodo("p001", 5)
        self.assertEqual(self.r1.escrituras, [])
        self.activar(modo="auto")
        d._ciclo_nodo("p001", 5)
        self.assertEqual(sorted(self.lista(self.r1)), self.todas())


# ============================================================================================
# Panel por HTTP (montaje de test_panel_alcance)
# ============================================================================================
@unittest.skipUnless(HAY_CRYPTO, "falta cryptography (python3-cryptography en la imagen)")
class Ficha(A.Base):
    def setUp(self):
        doc_global(self)
        super().setUp()
        d = self.d
        # los routers son de mentira (PanelP): reglas, lectura, alta y vaciado, dobles que apuntan
        self.reglas = []
        d._atac_reglas_en = lambda s_, r, enc, q: (self.reglas.append((s_, enc)) or (True, "sin cambios"))
        d._atac_vaciar_en = lambda s_: (self.reglas.append((s_, "vaciar")) or (0, []))
        d._atac_leer_lista_en = lambda s_: {}
        d._atac_add_en = lambda s_, ip, com, ents: (self.p.mk.append(("add", ip, s_)) or "puesta")
        with self.n.sin_alcance():           # usuario y clave de la API en los tres puntos
            d.guardar_routers([{"id": pid, "USER": "ids-api", "PASS": "x", "ENABLED": "1"}
                               for pid in ("p001", "p002", "p003")])
        for pid, ip in (("p001", "203.0.113.10"), ("p002", "198.51.100.20"), ("p003", "192.0.2.30")):
            dd = os.path.join(self.raiz, "panel", "nodos", pid)
            os.makedirs(dd, exist_ok=True)
            with open(os.path.join(dd, "entrantes.json"), "w", encoding="utf-8", newline="\n") as f:
                json.dump(entrantes([(ip, 500, 9)]), f)

    def conf(self):
        try:
            with open(self.d.ATAC_CONF, encoding="utf-8") as f:
                return {k: v["modo"] for k, v in json.load(f).items()}
        except FileNotFoundError:
            return {}

    def pedir(self, pid, quien, **form):
        form.setdefault("ajax", "1")
        return self.post("/puntos/%s/atacantes" % pid, form, quien)

    def test_operador_ve_la_seccion_de_su_punto(self):
        r = self.get("/puntos/p001", "olga")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.esta("id=atacantes", r.texto, "ficha p001")
        self.esta("/puntos/p001/atacantes", r.texto, "ficha p001")
        self.sin_ajenos(r.texto, "ficha p001")

    def test_activar_manda_ya_y_apagar_limpia(self):
        r = self.pedir("p001", "olga", accion="guardar", modo="auto")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.assertEqual(self.conf(), {"p001": "auto"})
        self.assertIn(("add", "203.0.113.10", "p001"), self.p.mk)
        self.assertEqual([x for x in self.p.mk if x[2] != "p001"], [])
        self.esta("sin_limpiar", self.get("/puntos/p001", "olga").texto, "casilla de apagar sin limpiar")
        r = self.pedir("p001", "olga", accion="enviar")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        r = self.pedir("p001", "olga", accion="guardar", modo="")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.assertEqual(self.conf(), {})
        self.assertIn(("p001", False), self.reglas)
        self.assertIn(("p001", "vaciar"), self.reglas)

    def test_m7_con_enviar_en_no_la_ficha_no_lo_activa(self):
        with self.n.sin_alcance():
            self.d.guardar_routers([{"id": "p001", "ENABLED": "0"}])
        r = self.pedir("p001", "olga", accion="guardar", modo="auto")
        self.assertEqual(r.status, 409, A.plano(r.texto))
        self.assertIn("solo sugerencias", r.texto)
        self.assertEqual((self.conf(), self.p.mk), ({}, []))

    def test_punto_ajeno_es_404_y_no_toca_nada(self):
        for form in ({"accion": "guardar", "modo": "auto"}, {"accion": "enviar"}):
            with self.subTest(form=form):
                r = self.pedir("p002", "olga", **form)
                self.assertEqual(r.status, 404, A.plano(r.texto))
        self.assertEqual(self.conf(), {})
        self.assertEqual(self.p.mk, [])

    def test_lectura_sin_permiso_403_y_sin_seccion(self):
        r = self.get("/puntos/p001", "luis")
        if r.status == 200:
            self.no_esta("id=atacantes", r.texto, "ficha de luis")
        r = self.pedir("p001", "luis", accion="guardar", modo="auto")
        self.assertEqual(r.status, 403, A.plano(r.texto))
        r = self.post("/atacantes/enviar?nodo=p001", {"ajax": "1"}, "luis")
        self.assertEqual(r.status, 403, A.plano(r.texto))
        self.assertEqual((self.conf(), self.p.mk), ({}, []))

    def test_modo_no_valido_400(self):
        r = self.pedir("p001", "olga", accion="guardar", modo="siempre")
        self.assertEqual(r.status, 400, A.plano(r.texto))
        self.assertEqual(self.conf(), {})

    def test_b2_enviar_en_todos_en_segundo_plano_solo_sus_puntos(self):
        for pid in ("p001", "p002", "p003"):
            self.d.guardar_atacantes_modo(pid, "manual", "ana")
        r = self.post("/atacantes/enviar?nodo=_todos", {"ajax": "1"}, "dora")       # p003 y p001
        self.assertEqual(r.status, 200, A.plano(r.texto))
        j = json.loads(r.texto)
        self.assertTrue(j.get("fondo"), j)
        self.assertEqual(sorted(x["pid"] for x in j["puntos"]), ["p001", "p003"])
        for t in threading.enumerate():
            if t.name == "atac-envio":
                t.join(30)
        self.assertEqual(sorted({x[2] for x in self.p.mk}), ["p001", "p003"])
        self.assertNotIn(A.NOMBRES["p002"], r.texto)
        r = self.post("/atacantes/enviar?nodo=p002", {"ajax": "1"}, "olga")
        self.assertEqual(r.status, 404, A.plano(r.texto))
        self.assertNotIn("p002", {x[2] for x in self.p.mk})

    def test_enviar_un_punto_responde_con_su_resultado(self):
        self.d.guardar_atacantes_modo("p001", "manual", "ana")
        r = self.post("/atacantes/enviar?nodo=p001", {"ajax": "1"}, "olga")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        j = json.loads(r.texto)
        self.assertEqual([x["pid"] for x in j["puntos"]], ["p001"])
        self.assertEqual(j["puntos"][0]["enviadas"], 1)

    def test_enviar_sin_ningun_punto_activado_409(self):
        r = self.post("/atacantes/enviar?nodo=p001", {"ajax": "1"}, "olga")
        self.assertEqual(r.status, 409, A.plano(r.texto))
        self.assertEqual(self.p.mk, [])

    def test_historico_columna_y_boton(self):
        self.d.guardar_atacantes_modo("p001", "manual", "ana")
        r = self.get("/historico?nodo=p001", "olga")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.esta("<th>En el router</th>", r.texto, "historico")
        self.esta("pendiente", r.texto, "historico antes de enviar")
        self.esta("atacEnviar(this)", r.texto, "boton")
        self.post("/atacantes/enviar?nodo=p001", {"ajax": "1"}, "olga")
        r = self.get("/historico?nodo=p001", "olga")
        self.esta("&#10004;", r.texto, "historico tras enviar")
        r = self.get("/historico?nodo=p001", "luis")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.no_esta("atacEnviar(this)", r.texto, "historico de luis")

    def test_b1_la_que_no_se_manda_dice_no_va(self):
        self.d.guardar_atacantes_modo("p001", "manual", "ana")
        with open(self.d.NUNCA_FILE, "w", encoding="utf-8") as f:
            f.write("p001|203.0.113.10\n")
        r = self.get("/historico?nodo=p001", "olga")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.esta(">no va</span>", r.texto, "historico")
        self.no_esta(">pendiente</span>", r.texto, "historico")


if __name__ == "__main__":
    unittest.main()
