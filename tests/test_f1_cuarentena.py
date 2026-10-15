"""F1 (correcciones de la auditoria): cuarentena, registros y destinos en el panel real.

Cada prueba es de CORRECCION DE DEFECTO (CONTRATO-F2 §10.5): reproduce el hallazgo de la
auditoria (falla con el dashboard de b9dcd02) y demuestra la correccion. Panel real
(`dashboard.py`) sobre el arbol de `fixtures/panel2/_dash.py` (p001 y p002 con la misma red
10.0.0.0/24 y alertas recientes de 10.0.0.5), routers con el MikroTik simulado de
`_mikrotik_simulado.py` cuando hace falta ver la address-list de verdad.
"""
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
sys.path.insert(0, os.path.join(AQUI, "fixtures", "panel2"))
import _dash  # noqa: E402
import _mikrotik_simulado as sim  # noqa: E402

IP = _dash.IP
K1, K2 = "p001|" + IP, "p002|" + IP


class Panel:
    """dashboard.py real sobre un arbol temporal, con un MikroTik simulado por punto y,
    si se pide, su servidor HTTP con usuarios admin/operador/lectura."""

    def __init__(self, http=False, **entorno):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = _dash.Arbol(self.tmp.name)
        self.d = _dash.cargar(self.a, **entorno)
        self.n = self.d.nodos
        self.n.asegurar_dirs()
        self.routers = {"p001": sim.RouterSimulado("norte"), "p002": sim.RouterSimulado("sur")}
        self.caidos = set()
        self.d.mk_conectar = self._conectar
        self.d.enviar_telegram = lambda *a, **k: False
        self.d.notificar_cuarentena = lambda *a, **k: None
        if self.d.secretos.disponible():
            self.d.guardar_routers([{"id": "p001", "USER": "u", "PASS": "c1", "ENABLED": "1"},
                                    {"id": "p002", "USER": "u", "PASS": "c2", "ENABLED": "1"}])
        self.srv = None
        if http:
            self._usuarios()
            self.srv = self.d.crear_servidor("127.0.0.1", 0)
            threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05},
                             daemon=True).start()

    def _conectar(self, dd, timeout=6):
        rid = dd.get("ROUTER_ID")
        if rid in self.caidos:
            raise OSError("sin conexion con el router %s" % rid)
        return self.routers[rid].conexion()

    def lista(self, pid, nombre):
        return sorted(f["address"] for f in self.routers[pid].tablas["/ip/firewall/address-list"]
                      if f["list"] == nombre)

    def _usuarios(self):
        lst = []
        for u, rol in (("ana", "admin"), ("olga", "operador"), ("luis", "lectura")):
            salt, h = self.d._hash_pw("clave-de-prueba-1")
            lst.append({"user": u, "salt": salt, "hash": h, "role": rol, "activo": True})
        self.d.guardar_usuarios(lst)
        self.cookies = {u: "sid=" + self.d.sesion_abrir(u, r) for u, r in
                        (("ana", "admin"), ("olga", "operador"), ("luis", "lectura"))}

    def pedir(self, metodo, ruta, form=None, quien="ana", cabeceras=None, cuerpo=None, timeout=20):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=timeout)
        cab = {"Cookie": self.cookies[quien]} if quien else {}
        if form is not None:
            cuerpo = urllib.parse.urlencode(form, doseq=True)
            cab["Content-Type"] = "application/x-www-form-urlencoded"
        cab.update(cabeceras or {})
        try:
            c.request(metodo, ruta, body=cuerpo, headers=cab)
            r = c.getresponse()
            return r.status, dict(r.getheaders()), r.read().decode("utf-8", "replace")
        finally:
            c.close()

    def cerrar(self):
        if self.srv:
            self.srv.shutdown()
            self.srv.server_close()
        self.n.quitar_nodo()
        _dash.restaurar()
        self.tmp.cleanup()


class Base(unittest.TestCase):
    HTTP = False

    def setUp(self):
        self.p = Panel(http=self.HTTP)
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d


# --------------------------------------------------------------------------------------------
class RegistrosSinFotoVieja(Base):
    """A-03: los registros de enviados no pierden ni resucitan entradas de otros hilos."""

    def test_masivo_no_pisa_lo_que_otros_anotan_o_liberan(self):
        """Correccion de defecto (A-03, reproduccion ctx/r2): mientras el envio masivo de p001
        habla con su router, el fondo anota p002|10.0.0.7 y otro operador libera p002|10.0.0.9.
        Antes: el masivo guardaba su foto vieja (perdida + resurreccion). Ahora: las dos
        cosas se conservan."""
        d = self.d
        nueva, liberada = "p002|10.0.0.7", "p002|10.0.0.9"
        with open(d.MK_SENT, "w") as f:
            json.dump({liberada: {"cuando": 1, "router": "p002", "manual": True}}, f)
        self.p.a.salida("p001", "cuarentena.json", {"candidatos": [
            {"ip": IP, "router": "p001", "confianza": "alta", "riesgo": 90, "ultima": int(time.time())}]})
        dentro, seguir = threading.Event(), threading.Event()

        # (adaptada, 2026-10-14) el masivo ya no llama a mk_add por IP: manda con _mk_add_en
        # sobre una sesion por nodo (el router simulado de p001 pone la conexion)
        def mk_add_lento(s, ip, lst, tt="", comment=""):
            dentro.set()
            seguir.wait(10)
            return True, ""
        d._mk_add_en = mk_add_lento
        res = {}

        def masivo():
            d.CTX.user = "olga"
            res["r"] = d._enviar_confirmados("p001", "cuar")
        t = threading.Thread(target=masivo)
        t.start()
        self.assertTrue(dentro.wait(10))
        d._registrar_enviados(d.MK_SENT, {nueva: {"cuando": 2, "router": "p002", "pol": True}}, [])
        d.quitar_enviados([liberada])
        seguir.set()
        t.join(20)
        fin = d.cargar_enviados()
        self.assertEqual(res["r"][0], 1, res)
        self.assertIn(K1, fin)
        self.assertIn(nueva, fin, "se perdio lo que anoto el fondo")
        self.assertNotIn(liberada, fin, "resucito lo que libero otro operador")

    def test_sync_no_resucita_ni_borra_con_una_lectura_vieja(self):
        """Correccion de defecto (A-15): mk_sync_enviados lee el router fuera del cerrojo; lo
        liberado y lo anotado DESPUES de esa lectura no se toca. Antes: la liberada volvia
        como «manual» y la recien enviada (con TTL) se borraba del registro."""
        d = self.d
        vieja, recien = "p001|10.0.0.7", "p001|10.0.0.8"
        d._registrar_enviados(d.MK_SENT, {vieja: {"cuando": 1, "router": "p001", "lista": "suricata-cuarentena"}}, [])

        def leer(r, listas):
            if r["id"] == "p001":
                # mientras se lee el router: otro libera la vieja y el barrido anota una nueva
                d.quitar_enviados([vieja])
                d._registrar_enviados(d.MK_SENT, {recien: {"cuando": int(time.time()), "router": "p001",
                                                           "lista": "suricata-cuarentena"}}, [])
                return {"suricata-cuarentena": {"10.0.0.7"}}
            return {}
        d._mk_ips_listas = leer
        d.mk_sync_enviados()
        fin = d.cargar_enviados()
        self.assertNotIn(vieja, fin, "la liberada volvio como manual")
        self.assertIn(recien, fin, "la recien enviada se borro con la foto vieja")

    def test_publicas_de_dos_nodos_a_la_vez(self):
        """Correccion de defecto (A-16): dos nodos guardan sus publicas a la vez; no se pierde
        ninguna (antes: leer-modificar-guardar sin cerrojo, ganaba el ultimo)."""
        d = self.d
        d.aidb_red_valida = lambda t: (t, "")          # la validacion de redes tiene su prueba
        orig = d.cargar_publicas

        def lento():
            v = orig()
            time.sleep(0.2)
            return v
        d.cargar_publicas = lento
        hilos = [threading.Thread(target=d.guardar_publicas_de, args=(pid, red))
                 for pid, red in (("p001", "198.51.100.0/28"), ("p002", "203.0.113.0/28"))]
        for t in hilos:
            t.start()
        for t in hilos:
            t.join(10)
        d.cargar_publicas = orig
        self.assertEqual(sorted(d.cargar_publicas()), ["p001", "p002"])

    def test_abonados_de_un_router_caido_se_conservan(self):
        """Correccion de defecto (A-17): si el router de p002 no responde, su mapa de
        abonados se conserva (antes se borraba entero)."""
        d = self.d
        with open(d.ABONADOS_FILE, "w") as f:
            json.dump({"ts": 1, "mapa": {K2: {"nombre": "ABONADO-SUR", "router": "p002"}}}, f)

        def mk_abonados(router=None):
            if router["id"] == "p002":
                raise OSError("no responde")
            return {IP: {"nombre": "ABONADO-NORTE"}}
        d.mk_abonados = mk_abonados
        d.refrescar_abonados()
        mapa = d.cargar_abonados()["mapa"]
        self.assertEqual(mapa[K1]["nombre"], "ABONADO-NORTE")
        self.assertEqual(mapa.get(K2, {}).get("nombre"), "ABONADO-SUR")


# --------------------------------------------------------------------------------------------
class Liberar(Base):
    """A-05: liberar sale de la lista donde se puso y solo se da por hecho si el router lo confirma."""

    def test_mk_remove_no_da_exito_con_trap(self):
        """Correccion de defecto (A-05, dest/r1_mk_remove_falso_exito): con !trap en el remove,
        antes devolvia exito y el registro perdia la clave con el CPE aun bloqueado."""
        r1 = self.p.routers["p001"]
        r1.cargar("/ip/firewall/address-list", [{"list": "clientes-botnet", "address": IP}])
        r1.fallar_en = 1
        ok, err = self.d.mk_remove(IP, lista="clientes-botnet", router=self.d.router_por_id("p001"))
        self.assertFalse(ok, err)
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), [IP])
        r1.fallar_en = None
        ok, err = self.d.mk_remove(IP, lista="clientes-botnet", router=self.d.router_por_id("p001"))
        self.assertTrue(ok, err)
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), [])

    def test_reconciliar_libera_de_la_lista_guardada(self):
        """Correccion de defecto (A-05, dest/r2): el CPE estaba en clientes-botnet (su
        categoria); el reconciliador lo quitaba de LIST (otra lista) y lo soltaba del
        registro: seguia bloqueado y fuera del panel."""
        d = self.d
        d.guardar_mk({"AUTO_MANTENER": "1"})
        self.p.routers["p001"].cargar("/ip/firewall/address-list", [{"list": "clientes-botnet", "address": IP}])
        d._registrar_enviados(d.MK_SENT, {K1: {"cuando": 1, "router": "p001", "lista": "clientes-botnet"}}, [])
        self.p.a.salida("p001", "cuarentena.json", {"candidatos": []})       # ya no ataca
        with self.p.n.contexto("p001"):
            d.reconciliar_cuarentena("p001")
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), [])
        self.assertNotIn(K1, d.cargar_enviados())
        # y si el router rechaza, se queda en el registro para el siguiente ciclo
        self.p.routers["p001"].cargar("/ip/firewall/address-list", [{"list": "clientes-botnet", "address": IP}])
        d._registrar_enviados(d.MK_SENT, {K1: {"cuando": 1, "router": "p001", "lista": "clientes-botnet"}}, [])
        self.p.routers["p001"].fallar_en = self.p.routers["p001"]._n + 1   # la siguiente escritura
        with self.p.n.contexto("p001"):
            d.reconciliar_cuarentena("p001")
        self.assertIn(K1, d.cargar_enviados())


class LiberarHTTP(Base):
    HTTP = True

    def test_quitar_uno_usa_la_lista_guardada(self):
        """Correccion de defecto (A-05, dest/r1): /cuarentena/quitar-uno quitaba de LIST y daba
        ok; el CPE seguia en clientes-otros del router y salia del panel."""
        d = self.d
        self.p.routers["p002"].cargar("/ip/firewall/address-list", [{"list": "clientes-otros", "address": IP}])
        d._registrar_enviados(d.MK_SENT, {K2: {"cuando": 1, "router": "p002", "lista": "clientes-otros"}}, [])
        st, _c, txt = self.p.pedir("POST", "/cuarentena/quitar-uno?nodo=p002", {"sel": "cuar|" + K2}, "olga")
        self.assertEqual(json.loads(txt)["ok"], True, txt)
        self.assertEqual(self.p.lista("p002", "clientes-otros"), [])
        self.assertNotIn(K2, d.cargar_enviados())

    def test_quitar_varios_un_router_caido_no_corta_los_demas(self):
        """Correccion de defecto (A-19, dest/r9): con p001 caido, quitar-varios desde «Todos»
        cortaba tambien p002. Ahora sigue con p002 y dice cual no responde."""
        d = self.d
        for pid in ("p001", "p002"):
            self.p.routers[pid].cargar("/ip/firewall/address-list", [{"list": "clientes-botnet", "address": IP}])
        d._registrar_enviados(d.MK_SENT, {k: {"cuando": 1, "router": k[:4], "lista": "clientes-botnet"}
                                          for k in (K1, K2)}, [])
        self.p.caidos.add("p001")
        st, cab, _t = self.p.pedir("POST", "/cuarentena/quitar-varios?nodo=_todos",
                                   {"sel": ["cuar|" + K1, "cuar|" + K2]}, "olga")
        self.assertEqual(st, 303)
        self.assertEqual(self.p.lista("p002", "clientes-botnet"), [])
        fin = d.cargar_enviados()
        self.assertIn(K1, fin)
        self.assertNotIn(K2, fin)


# --------------------------------------------------------------------------------------------
class EvidenciaReciente(Base):
    """A-06: la evidencia reciente (§10.4) se mira tambien en el masivo y en el envio manual."""

    def _vieja(self):
        for pid in ("p001", "p002"):
            self.p.a.eve(pid, [_dash.alerta(hace=3 * 86400)])
        self.p.a.salida("p001", "cuarentena.json", {"candidatos": [
            {"ip": IP, "router": "p001", "confianza": "alta", "riesgo": 90}]})

    def test_masivo_omite_y_lista_la_evidencia_vieja(self):
        """Correccion de defecto (A-06, lead/l1): con alertas de hace 3 dias el masivo enviaba."""
        self._vieja()
        n, msg = self.d._enviar_confirmados("p001", "cuar")
        self.assertEqual(n, 0, msg)
        self.assertIn("evidencia vieja", msg)
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), [])
        self.assertNotIn(K1, self.d.cargar_enviados())

    def test_masivo_sin_nodo_del_formulario_no_usa_la_sesion(self):
        """Correccion de defecto (A-11): sin el nodo de la lista no se envia nada (antes salia
        de la sesion, que comparten las pestanas)."""
        self.p.n.poner_nodo("p001")
        n, msg = self.d._enviar_confirmados("", "cuar")
        self.assertEqual(n, 0)
        self.assertIn("Falta el nodo", msg)


class EvidenciaRecienteHTTP(EvidenciaReciente):
    HTTP = True

    def test_manual_pide_confirmacion_con_la_antiguedad(self):
        """Correccion de defecto (A-06): el envio manual con evidencia vieja pide confirmacion
        explicita con la antiguedad; confirmado, se envia."""
        self._vieja()
        st, _c, txt = self.p.pedir("POST", "/cuarentena/enviar?nodo=p001", {"ip": K1, "score": "9"}, "olga")
        self.assertEqual(st, 200)
        self.assertIn("es vieja", txt)
        self.assertIn("última alerta hace", txt)
        self.assertIn("name=confirmar_vieja value=1", txt)
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), [])
        st, _c, _t = self.p.pedir("POST", "/cuarentena/enviar?nodo=p001",
                                  {"ip": K1, "score": "9", "confirmar_vieja": "1"}, "olga")
        self.assertEqual(st, 303)
        self.assertNotEqual([a for p in ("p001",) for a in self.p.routers[p].tablas["/ip/firewall/address-list"]], [])
        self.assertIn(K1, self.d.cargar_enviados())


# --------------------------------------------------------------------------------------------
class DestinoMalo(Base):
    HTTP = True

    def test_resultado_y_registro_por_punto(self):
        """Correccion de defecto (A-07, dest/r3): con p002 caido, bloquear lo daba por hecho en
        todos y quitar borraba la marca aunque p002 lo conservara. Ahora el registro dice en
        que puntos esta y solo se quita la marca de los que confirman."""
        d, dst = self.d, "203.0.113.77"
        d.destino_bloqueable = lambda ip: (True, "")   # RFC 5737 no es «global»: aqui da igual
        self.p.caidos.add("p002")
        self.p.pedir("POST", "/cuarentena/destino/bloquear?nodo=p001", {"ip": dst}, "olga")
        self.assertEqual(d.cargar_enviados(d.MK_SENT_DST)[dst]["puntos"], ["p001"])
        self.p.caidos.clear()
        self.p.pedir("POST", "/cuarentena/destino/bloquear?nodo=p001", {"ip": dst}, "olga")
        self.assertEqual(d.cargar_enviados(d.MK_SENT_DST)[dst]["puntos"], ["p001", "p002"])
        self.p.caidos.add("p002")
        self.p.pedir("POST", "/cuarentena/destino/quitar?nodo=p001", {"ip": dst}, "olga")
        self.assertEqual(d.cargar_enviados(d.MK_SENT_DST)[dst]["puntos"], ["p002"])
        self.assertEqual(self.p.lista("p002", "suricata-destinos-malos"), [dst])


# --------------------------------------------------------------------------------------------
class NuncaBloquearPorPunto(Base):
    def test_entrada_de_un_punto_no_protege_al_otro(self):
        """Correccion de defecto (A-12, datos/r_ip_dash_registros R5): `nunca bloquear` con la IP
        pelada eximia al abonado con la misma IP en OTRO punto. Ahora `p001|IP` vale solo en
        p001; una entrada sin punto, en todos."""
        d = self.d
        d.guardar_nunca("p001|%s\n192.0.2.0/24\np002|10.0.9.0/24\np0x|10.0.0.9\n" % IP)
        self.assertTrue(d.nunca_bloquear(K1))
        self.assertFalse(d.nunca_bloquear(K2))
        self.assertTrue(d.nunca_bloquear("10.0.9.4", "p002"))
        self.assertFalse(d.nunca_bloquear("10.0.9.4", "p001"))
        self.assertTrue(d.nunca_bloquear("p001|192.0.2.7") and d.nunca_bloquear("p002|192.0.2.7"))
        self.assertNotIn("p0x", d.cargar_nunca())        # formato de punto invalido: fuera


class ThresholdConMotivo(Base):
    def test_el_orquestador_acepta_el_threshold_con_motivo(self):
        """Correccion de defecto (A-13, infra/i1): el motivo iba al final de la linea suppress y
        el orquestador rechazaba el fichero entero. Ahora va en su propia linea de comentario."""
        sys.path.insert(0, os.path.join(os.path.dirname(AQUI), "orquestador"))
        import ids_orq
        reglas = [{"tipo": "src", "ip": IP, "sid": "2000001", "puertos": [], "hasta": 0,
                   "motivo": "falso positivo # con almohadilla\ty tab", "nodo": "p001"}]
        cont = self.d.threshold_contenido(reglas, "p001")
        self.assertEqual(ids_orq.validar_threshold(cont), cont)
        lineas = cont.splitlines()
        i = next(n for n, x in enumerate(lineas) if x.startswith("suppress"))
        self.assertTrue(lineas[i - 1].startswith("# falso positivo"), lineas)
        self.assertNotIn("#", lineas[i])


if __name__ == "__main__":
    unittest.main()
