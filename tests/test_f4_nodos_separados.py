"""Apartado 2: cada nodo ve solo lo suyo (auditoria A-18) y la baja limpia antes el MikroTik
(auditoria A-21(5)).

Arbol de prueba con dos puntos (p001 «norte», p002 «sur») que usan la MISMA IP privada 10.0.0.5:
son dos abonados distintos y nada de uno puede aparecer en la vista del otro. Sin red: el router
y el espejo son falsos y apuntan lo que se les pide. El tipo de cada prueba va en su docstring.
"""
import json
import os
import re
import sys
import tempfile
import time
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, "fixtures", "panel2"))
sys.path.insert(0, AQUI)
import _dash  # noqa: E402
from _dash_p import PanelP  # noqa: E402
from test_hrep_nodos import Entorno  # noqa: E402

IP = "10.0.0.5"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = _dash.Arbol(self.tmp.name)
        self.d = _dash.cargar(self.a)
        self.n = self.d.nodos
        self.n.asegurar_dirs()

    def tearDown(self):
        self.n.quitar_nodo()
        _dash.restaurar()
        self.tmp.cleanup()

    def cuarentenas(self, valor):
        m = re.search(r"<div class=kv>([\d,]+)</div><div class=kt>puestos en cuarentena", valor)
        return int(m.group(1)) if m else None


class Historico(Base):
    def test_cada_nodo_cuenta_sus_cuarentenas(self):
        """Correccion de defecto (A-18): una cuarentena en p002 no aparece en el Historico de p001;
        en «Todos» cuenta una vez."""
        self.d.mk_log("ENVIADO", IP, "op", "lista=x nodo=p002")
        with self.n.contexto("p001"):
            self.assertEqual(self.cuarentenas(self.d.historico_page(7)), 0)
        with self.n.contexto("p002"):
            self.assertEqual(self.cuarentenas(self.d.historico_page(7)), 1)
        with self.n.contexto(self.n.TODOS):
            self.assertEqual(self.cuarentenas(self.d.historico_page(7)), 1)

    def test_identidad_en_la_ip_tambien_cuenta(self):
        """Capacidad nueva: con la identidad `pid|ip` (sin nodo= en el detalle) va a ese punto."""
        self.d.mk_log("QUITADO", "p001|" + IP, "op", "")
        self.assertEqual(self.d.cargar_acciones("p001")[time.strftime("%Y-%m-%d")], {"QUITADO": 1})
        self.assertEqual(self.d.cargar_acciones("p002"), {})

    def test_la_baja_borra_su_cuenta(self):
        """Capacidad nueva (baja = se borra todo): purgar_punto quita la cuenta del punto y deja
        el total de la empresa."""
        self.d.mk_log("ENVIADO", IP, "op", "nodo=p002")
        self.d.purgar_punto("p002")
        self.assertEqual(self.d.cargar_acciones("p002"), {})
        self.assertEqual(self.d.cargar_acciones(self.n.TODOS)[time.strftime("%Y-%m-%d")], {"ENVIADO": 1})


class Ficha(Base):
    def setUp(self):
        super().setUp()
        self.d.guardar_enviados({"p002|" + IP: {"cuando": int(time.time()), "por": "op", "router": "p002",
                                                "lista": "clientes-botnet", "motivo": {"tipo": "infeccion"}}},
                                self.d.MK_SENT)

    def test_ip_sola_toma_el_nodo_que_se_mira(self):
        """Correccion de defecto (A-18): el enlace de Telegram (?ip=IP&nodo=pid) abre la ficha del
        CPE de ese punto, no «No hay evidencia»."""
        with self.n.contexto("p002"):
            f = self.d.ficha_page(IP, embed=True)
        self.assertIn("En cuarentena", f)
        with self.n.contexto("p001"):
            self.assertIn("No hay evidencia", self.d.ficha_page(IP, embed=True))

    def test_en_todos_con_un_solo_nodo_va_a_ese(self):
        """Capacidad nueva: en «Todos», si la IP solo esta en un punto, la ficha es la de ese."""
        with self.n.contexto(self.n.TODOS):
            self.assertIn("En cuarentena", self.d.ficha_page(IP, embed=True))

    def test_en_todos_con_varios_nodos_pregunta(self):
        """Capacidad nueva: la misma IP en dos puntos son dos abonados: no se elige uno al azar,
        se ofrece la ficha de cada uno."""
        env = self.d.cargar_enviados(self.d.MK_SENT)
        env["p001|" + IP] = {"cuando": 1, "router": "p001", "lista": "clientes-botnet"}
        self.d.guardar_enviados(env, self.d.MK_SENT)
        with self.n.contexto(self.n.TODOS):
            f = self.d.ficha_page(IP, embed=True)
        self.assertNotIn("En cuarentena", f)
        self.assertIn("ip=p001%7C10.0.0.5&embed=1", f)
        self.assertIn("ip=p002%7C10.0.0.5&embed=1", f)

    def test_historial_del_punto_del_cpe(self):
        """Correccion de defecto (A-18): la ficha de p002|IP mirada desde p001 o desde «Todos» usa el
        abonado y el historial de p002, nunca los de p001."""
        t0 = int(time.time()) - 3600
        with open(self.d.ABON_HIST_FILE, "w", encoding="utf-8") as f:
            for pid, nom in (("p001", "ABONADO-NORTE"), ("p002", "ABONADO-SUR")):
                f.write(json.dumps({"ts": t0, "ip": "%s|%s" % (pid, IP), "nombre": nom, "mac": "02:00:00:00:00:0%s"
                                    % pid[-1], "tipo": "PPPoE"}) + "\n")
        mapa = {"%s|%s" % (pid, IP): {"nombre": nom, "mac": "02:00:00:00:00:0%s" % pid[-1], "tipo": "PPPoE",
                                       "router": pid} for pid, nom in (("p001", "ABONADO-NORTE"), ("p002", "ABONADO-SUR"))}
        with open(self.d.ABONADOS_FILE, "w", encoding="utf-8") as f:
            json.dump({"ts": int(time.time()), "mapa": mapa}, f)
        for ctx in ("p001", self.n.TODOS, "p002"):
            with self.n.contexto(ctx):
                f = self.d.ficha_page("p002|" + IP, embed=True)
            self.assertNotIn("ABONADO-NORTE", f, ctx)
            self.assertIn("ABONADO-SUR", f, ctx)
            self.assertIn("momento del evento", f, ctx)


class ListasEnUso(Base):
    def test_cuenta_solo_los_del_nodo(self):
        """Correccion de defecto (A-18): la columna de cuantos hay en cada lista cuenta los CPEs del
        nodo que se mira; en «Todos», todos; el diagnostico de un router, los de ese router."""
        self.d.guardar_enviados({"p001|" + IP: {"cuando": 1, "router": "p001", "lista": "clientes-botnet"},
                                 "p002|" + IP: {"cuando": 1, "router": "p002", "lista": "clientes-botnet"},
                                 "p002|10.0.0.6": {"cuando": 1, "router": "p002", "lista": "clientes-botnet"}},
                                self.d.MK_SENT)

        def botnet(lst):
            return sum(n for _c, _nom, l, n in lst if l == "clientes-botnet")
        with self.n.contexto("p001"):
            self.assertEqual(botnet(self.d.listas_en_uso()), 1)
        with self.n.contexto("p002"):
            self.assertEqual(botnet(self.d.listas_en_uso()), 2)
        with self.n.contexto(self.n.TODOS):
            self.assertEqual(botnet(self.d.listas_en_uso()), 3)
        self.assertEqual(botnet(self.d.listas_en_uso(["p002"])), 2)


class BajaLimpiaRouter(Base):
    """baja_limpiar_router con el router falso: espejo_retirar y _mk_quitar_en apuntan."""

    def setUp(self):
        super().setUp()
        self.orden, self.fallan, self.revientan = [], set(), set()
        self.api = {"USER": "ids-api", "PASS": "x", "ROUTER_ID": "p001", "LIST": "suricata-cuarentena"}
        d = self.d
        d.cargar_mk_de = lambda r: dict(self.api)
        d.router_por_id = lambda pid: {"id": pid}
        self.espejo_ok = True
        d.espejo_retirar = lambda pid, usuario=None: (self.orden.append(("espejo", pid)) or
                                                      {"ok": self.espejo_ok, "mensaje": "retirado" if self.espejo_ok
                                                       else "sin respuesta"})

        class Con:
            def close(self):
                pass
        d.mk_conectar = lambda m, timeout=15: Con()

        def quitar(s_, ip, lst):
            self.activos_durante = list(d.pids_activos())
            self.orden.append((ip, lst))
            if ip in self.revientan:
                raise TimeoutError("timed out")
            return (False, "timeout") if ip in self.fallan else (True, "1 entrada(s) quitada(s) de " + lst)
        d._mk_quitar_en = quitar
        d.guardar_enviados({"p001|" + IP: {"cuando": 1, "router": "p001", "lista": "clientes-botnet"},
                            "p002|" + IP: {"cuando": 1, "router": "p002", "lista": "clientes-botnet"}}, d.MK_SENT)
        d.guardar_enviados({"p001|10.0.0.7": {"cuando": 1, "router": "p001"}}, d.MK_SENT_DNS)
        d.guardar_enviados({"192.0.2.66": {"cuando": 1, "puntos": ["p001", "p002"], "nodos": 2}}, d.MK_SENT_DST)

    def quitadas(self):
        return [x for x in self.orden if x[0] != "espejo"]

    def test_sin_api_y_sin_nada_apuntado_no_toca_nada(self):
        """Conservacion: un punto sin API y sin nada en el registro: ok sin hablar con el router."""
        self.api = {}
        for path in (self.d.MK_SENT, self.d.MK_SENT_DNS, self.d.MK_SENT_DST):
            self.d.guardar_enviados({k: v for k, v in self.d.cargar_enviados(path).items()
                                     if "p001" not in k and "p001" not in (v.get("puntos") or [])}, path)
        res = self.d.baja_limpiar_router("p001", "ana")
        self.assertEqual((res["ok"], res["api"]), (True, False))
        self.assertEqual(self.orden, [])

    def test_sin_api_con_ips_apuntadas_no_dice_ok(self):
        """Correccion de defecto (auditoria ap2 H5): sin API pero con IPs del punto en el registro, no
        se da por limpio (quedarian cortadas): dice cuantas y que hacer."""
        self.api = {}
        res = self.d.baja_limpiar_router("p001", "ana")
        self.assertFalse(res["ok"])
        self.assertIn("3 IP(s)", res["mensaje"])

    def test_quita_lo_del_punto_y_al_final_el_espejo(self):
        """Capacidad nueva (A-21(5), H3, H10): saca del router los CPEs del punto (de su lista guardada y
        de la configurada hoy) y su parte de los destinos, y retira el espejo AL FINAL; lo de p002 queda
        intacto. Mientras dura, el fondo no trabaja con ese punto."""
        res = self.d.baja_limpiar_router("p001", "ana")
        self.assertTrue(res["ok"], res["mensaje"])
        self.assertEqual(self.orden[-1], ("espejo", "p001"))
        self.assertEqual(sorted(self.quitadas()), sorted([(IP, "clientes-botnet"), (IP, "suricata-cuarentena"),
                                                          ("10.0.0.7", "suricata-dns-sospechoso"),
                                                          ("192.0.2.66", "suricata-destinos-malos")]))
        self.assertEqual(list(self.d.cargar_enviados(self.d.MK_SENT)), ["p002|" + IP])
        self.assertEqual(self.d.cargar_enviados(self.d.MK_SENT_DNS), {})
        self.assertEqual(self.d.cargar_enviados(self.d.MK_SENT_DST)["192.0.2.66"]["puntos"], ["p002"])
        self.assertNotIn("p001", self.activos_durante)
        self.assertIn("p002", self.activos_durante)

    def test_no_cuenta_como_liberados(self):
        """Correccion de defecto (auditoria ap2 H6): lo que quita la baja no suma a «liberados» del
        Historico (no son CPEs que se limpiaron)."""
        self.d.baja_limpiar_router("p001", "ana")
        hoy = self.d.cargar_acciones(self.n.TODOS)[time.strftime("%Y-%m-%d")]
        self.assertNotIn("QUITADO", hoy)
        self.assertEqual(hoy.get("QUITADO-BAJA"), 2)

    def test_espejo_que_falla_deja_el_punto_vivo(self):
        """Capacidad nueva: si no se puede retirar el espejo, ok=False, dice que las IPs ya se quitaron y
        el punto vuelve al fondo."""
        self.espejo_ok = False
        res = self.d.baja_limpiar_router("p001", "ana")
        self.assertFalse(res["ok"])
        self.assertTrue(res["tocado"])
        self.assertIn("espejo", res["mensaje"])
        self.assertIn("p001", self.d.pids_activos())

    def test_ip_que_no_sale_se_queda_y_el_espejo_tambien(self):
        """Correccion de defecto evitado: una IP que el router no confirma sigue en el registro (si no,
        quedaria cortada e invisible), no se retira el espejo y la baja no sigue."""
        self.fallan = {IP}
        res = self.d.baja_limpiar_router("p001", "ana")
        self.assertFalse(res["ok"])
        self.assertIn("p001|" + IP, self.d.cargar_enviados(self.d.MK_SENT))
        self.assertEqual(self.d.cargar_enviados(self.d.MK_SENT_DNS), {})
        self.assertNotIn(("espejo", "p001"), self.orden)
        self.assertIn("p001", self.d.pids_activos())

    def test_timeout_del_router_no_revienta(self):
        """Correccion de defecto (auditoria ap2 H2): un timeout a mitad sale como fallo explicado (no
        500 ni respuesta vacia), lo que no se quito sigue registrado y el punto vuelve al fondo."""
        self.revientan = {"10.0.0.7"}
        res = self.d.baja_limpiar_router("p001", "ana")
        self.assertFalse(res["ok"])
        self.assertIn("falló hablando con el router", res["mensaje"])
        self.assertIn("p001|10.0.0.7", self.d.cargar_enviados(self.d.MK_SENT_DNS))
        self.assertNotIn(("espejo", "p001"), self.orden)
        self.assertIn("p001", self.d.pids_activos())

    def test_dos_bajas_a_la_vez(self):
        """Correccion de defecto (auditoria ap2 H12): con una baja del punto en curso, otra no entra ni
        suelta la marca de la primera."""
        self.d._PREBAJA["p001"] = (time.time() + 60, "op-1")
        with self.d.cerrojo_operacion("p001", "baja"):
            res = self.d.baja_limpiar_router("p001", "ana")
        self.assertIn("ya hay una baja", res["mensaje"])
        self.assertEqual(self.orden, [])
        self.assertNotIn("p001", self.d.pids_activos())

    def test_cerrojo_de_fondo_ocupado_espera_poco(self):
        """Correccion de defecto (auditoria ap2 H3): con la tarea de fondo del punto en marcha no se
        espera minutos ni se toca el router: se pide reintentar."""
        lk = self.d.cerrojo_operacion("p001", "fondo")
        lk.espera = 0
        cerrojo = self.d.cerrojo_operacion
        self.d.cerrojo_operacion = lambda pid, op, espera=120: cerrojo(pid, op, 0 if op == "fondo" else espera)
        with lk:
            res = self.d.baja_limpiar_router("p001", "ana")
        self.d.cerrojo_operacion = cerrojo
        self.assertIn("tarea de fondo", res["mensaje"])
        self.assertEqual(self.orden, [])


    def test_segunda_baja_seguida_no_pisa_la_primera(self):
        """Correccion de defecto (auditoria ap2 N1): con la baja A esperando al orquestador, una baja B del
        mismo punto no limpia ni pisa la marca de A; si B falla, la marca de A sigue."""
        self.assertTrue(self.d.baja_limpiar_router("p001", "ana", op="op-A")["ok"])
        self.orden.clear()
        res = self.d.baja_limpiar_router("p001", "ana", op="op-B")
        self.assertIn("ya hay una baja", res["mensaje"])
        self.assertEqual(self.orden, [])
        self.d.baja_cancelada("p001", op="op-B")
        self.assertEqual(self.d._PREBAJA["p001"][1], "op-A")
        self.assertNotIn("p001", self.d.pids_activos())

    def test_lista_de_fabrica_tambien(self):
        """Correccion de defecto (auditoria ap2 H10): una entrada vieja sin lista guardada con la lista
        renombrada se busca tambien en la de fabrica."""
        self.api["LIST"] = "lista-renombrada"
        self.d.guardar_enviados({"p001|10.0.0.9": {"cuando": 1, "router": "p001"}}, self.d.MK_SENT)
        self.d.baja_limpiar_router("p001", "ana")
        self.assertIn(("10.0.0.9", "suricata-cuarentena"), self.quitadas())
        self.assertIn(("10.0.0.9", "lista-renombrada"), self.quitadas())


class MarcaDeBaja(Base):
    def test_renovar_solo_la_de_su_operacion(self):
        """Capacidad nueva (auditoria ap2): una baja que sigue en curso renueva su marca; otra no."""
        self.d._PREBAJA["p001"] = (time.time() + 1, "op-1")
        self.d.baja_renovar("p001", "op-2")
        self.assertLess(self.d._PREBAJA["p001"][0], time.time() + 5)
        self.d.baja_renovar("p001", "op-1")
        self.assertGreater(self.d._PREBAJA["p001"][0], time.time() + 600)

    def test_no_cuenta_para_puntos_que_no_existen(self):
        """Correccion de defecto (auditoria ap2 H8): un nodo= de un punto que no existe solo suma al total."""
        self.d.mk_log("QUITADO", IP, "op", "nodo=p009")
        with open(self.d.ACCIONES_FILE, encoding="utf-8") as f:
            self.assertNotIn("p009", json.load(f).get("nodos", {}))

    def test_envio_durante_la_baja_se_niega(self):
        """Correccion de defecto (auditoria ap2 H4): mientras se da de baja, mk_add (manual o de fondo) no
        manda nada a ese router; a otro punto si."""
        self.d._PREBAJA["p001"] = (time.time() + 60, None)
        ok, msg = self.d.mk_add(IP, router={"id": "p001"})
        self.assertFalse(ok)
        self.assertIn("se está dando de baja", msg)

    def test_caduca_y_va_ligada_a_su_operacion(self):
        """Correccion de defecto (auditoria ap2 H1): la marca caduca sola y baja_cancelada solo suelta la
        de su operacion."""
        self.d._PREBAJA["p001"] = (time.time() + 60, "op-1")
        self.d.baja_cancelada("p001", op="op-vieja")
        self.assertNotIn("p001", self.d.pids_activos())
        self.d.baja_cancelada("p001", op="op-1")
        self.assertIn("p001", self.d.pids_activos())
        self.d._PREBAJA["p001"] = (time.time() - 1, "op-2")
        self.assertIn("p001", self.d.pids_activos())

    def test_nodo_del_final_del_detalle(self):
        """Correccion de defecto (auditoria ap2 H8): el texto del router puede llevar otro «nodo=»; cuenta
        el del final (el que pone _suf_nodo)."""
        self.d.mk_log("QUITADO", IP, "op", "error del router nodo=p002 x nodo=p001")
        self.assertIn(time.strftime("%Y-%m-%d"), self.d.cargar_acciones("p001"))
        self.assertEqual(self.d.cargar_acciones("p002"), {})


class AccionesViejas(unittest.TestCase):
    def test_un_solo_punto_hereda_lo_de_antes(self):
        """Conservacion (auditoria ap2 H7): con un acciones.json de antes (sin cuenta por punto) y un
        solo punto, su Historico enseña lo de antes y sigue sumando encima."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        a = _dash.Arbol(tmp.name, puntos={"p001": _dash.punto("norte", 1)})
        d = _dash.cargar(a)
        self.addCleanup(_dash.restaurar)
        d.nodos.asegurar_dirs()
        hoy = time.strftime("%Y-%m-%d")
        with open(d.ACCIONES_FILE, "w", encoding="utf-8") as f:
            json.dump({"dias": {hoy: {"ENVIADO": 7}}}, f)
        self.assertEqual(d.cargar_acciones("p001")[hoy], {"ENVIADO": 7})
        d.mk_log("ENVIADO", "p001|" + IP, "op")
        self.assertEqual(d.cargar_acciones("p001")[hoy], {"ENVIADO": 8})
        self.assertEqual(d.cargar_acciones(d.nodos.TODOS)[hoy], {"ENVIADO": 8})


class BajaFormulario(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")
        self.limpiezas, self.canceladas = [], []
        self.resultado = {"ok": True, "mensaje": "0 IP(s) quitadas del router y espejo retirado"}
        self.p.d.baja_limpiar_router = lambda pid, usuario=None, op=None: (
            self.limpiezas.append((pid, usuario, len(self.p.orq.ordenes("punto.borrar")), op))
            or dict(self.resultado))
        self.p.d.baja_cancelada = lambda pid, op=None: self.canceladas.append((pid, op))

    def baja(self, **extra):
        return self.p.pedir("POST", "/puntos/p001/borrar", dict({"confirmar": "norte"}, **extra), cookie=self.ana)

    def test_la_ficha_ofrece_limpiar_marcado(self):
        """Capacidad nueva: el formulario de baja trae «Limpiar antes el MikroTik» marcado."""
        r = self.p.pedir("GET", "/puntos/p001", cookie=self.ana)
        self.assertRegex(r.texto, r"<input type=checkbox name=limpiar_router value=1 checked>")

    def test_limpia_antes_de_pedir_la_baja(self):
        """Capacidad nueva (A-21(5)): con la casilla, primero se limpia el router (con el op_id de la
        baja) y despues se pide punto.borrar con ese mismo op_id."""
        r = self.baja(limpiar_router="1")
        self.assertEqual(r.status, 303)
        (pid, usuario, antes, op), = self.limpiezas
        self.assertEqual((pid, usuario, antes), ("p001", "ana", 0))
        self.assertEqual(self.p.orq.ordenes("punto.borrar")[0]["op_id"], op)

    def test_router_que_falla_para_la_baja(self):
        """Capacidad nueva: si el router no se pudo limpiar, NO se pide la baja y se explica, diciendo si
        el router ya se toco."""
        self.resultado = {"ok": False, "tocado": True, "mensaje": "2 IP(s) quitadas, pero no se pudo retirar el espejo"}
        r = self.baja(limpiar_router="1")
        self.assertEqual(r.status, 409)
        self.assertIn("No se dio de baja", r.texto)
        self.assertIn("el router ya se tocó", r.texto)
        self.assertEqual(self.p.orq.ordenes("punto.borrar"), [])

    def test_sin_casilla_no_toca_el_router(self):
        """Conservacion: desmarcada (router que ya no existe), la baja sigue sin hablar con el router."""
        r = self.baja()
        self.assertEqual(r.status, 303)
        self.assertEqual(self.limpiezas, [])
        self.assertEqual(len(self.p.orq.ordenes("punto.borrar")), 1)

    def test_baja_rechazada_devuelve_el_punto_y_avisa(self):
        """Capacidad nueva (auditoria ap2 H3): si el orquestador no acepta la baja tras limpiar, el punto
        vuelve al fondo y el aviso dice que el router ya se limpio."""
        orq = self.p.orq
        pw = sys.modules["puntos_web"]

        def rechaza(pet):
            if pet["orden"] == "punto.borrar":
                orq.pedidas.append(pet)
                return {"op_id": pet["op_id"], "ok": False, "codigo": "OCUPADO", "mensaje": "hay otra", "datos": {}}
            return orq(pet)
        pw.TRANSPORTE = rechaza
        self.addCleanup(setattr, pw, "TRANSPORTE", orq)
        r = self.baja(limpiar_router="1")
        self.assertEqual(r.status, 409)
        self.assertIn("El router YA se limpio", r.texto)
        self.assertEqual(self.canceladas, [("p001", self.limpiezas[0][3])])

    def test_baja_que_termina_mal_suelta_el_punto(self):
        """Correccion de defecto (auditoria ap2 H1): aceptada pero terminada mal (REVERTIDA), el barrido
        devuelve el punto al fondo (solo la marca de esa operacion)."""
        pw = sys.modules["puntos_web"]
        r = self.baja(limpiar_router="1")
        op = r.cab("Location").rsplit("/", 1)[1]
        pw.ops().terminar(op, codigo="REVERTIDA", mensaje="no se pudo")
        pw.barrer_bajas(self.p.d, esperar=True)
        self.assertIn(("p001", op), self.canceladas)


class BajaPorHttpDeVerdad(unittest.TestCase):
    """La ruta HTTP con la limpieza REAL (auditoria ap2 H11): solo el router de mas abajo es falso."""

    def test_baja_completa(self):
        """Capacidad nueva: POST de la baja -> se quitan del router las IPs de p001, se retira el espejo,
        se pide punto.borrar y el punto queda marcado con el op_id de esa baja."""
        p = PanelP()
        self.addCleanup(p.cerrar)
        ana = p.entrar("ana")
        d, hechas = p.d, []

        class Con:
            def close(self):
                pass
        mk_de = d.cargar_mk_de
        d.cargar_mk_de = lambda r: dict(mk_de(r), USER="ids-api", PASS="x")      # API configurada
        d.mk_conectar = lambda m, timeout=15: Con()
        d._mk_quitar_en = lambda s_, ip, lst: (hechas.append((ip, lst)) or (True, "1 quitada"))
        d.espejo_retirar = lambda pid, usuario=None: (hechas.append(("espejo", pid)) or {"ok": True, "mensaje": "ok"})
        d.guardar_enviados({"p001|" + IP: {"cuando": 1, "router": "p001", "lista": "clientes-botnet"},
                            "p002|" + IP: {"cuando": 1, "router": "p002", "lista": "clientes-botnet"}}, d.MK_SENT)
        r = p.pedir("POST", "/puntos/p001/borrar", {"confirmar": "norte", "limpiar_router": "1"}, cookie=ana)
        self.assertEqual(r.status, 303)
        self.assertEqual(hechas[-1], ("espejo", "p001"))
        self.assertIn((IP, "clientes-botnet"), hechas)
        self.assertEqual(list(d.cargar_enviados(d.MK_SENT)), ["p002|" + IP])
        op = p.orq.ordenes("punto.borrar")[0]["op_id"]
        self.assertEqual(d._PREBAJA["p001"][1], op)


class TokenIlegible(unittest.TestCase):
    def test_pedir_no_lanza(self):
        """Correccion de defecto (auditoria ap2 H1): un token del orquestador que no es UTF-8 da
        SIN_TOKEN en vez de lanzar (la baja ya habia limpiado el router y salia un 500)."""
        sys.path.insert(0, _dash.LIB)
        from idspanel import orq
        with tempfile.TemporaryDirectory() as t:
            ruta = os.path.join(t, "token")
            with open(ruta, "wb") as f:
                f.write(bytes([0xff, 0xfe, 0x00]) + b"roto")
            r = orq.ClienteOrq(os.path.join(t, "sock"), ruta, transporte=lambda pet: {}).pedir("punto.borrar", {})
        self.assertEqual((r["ok"], r["codigo"]), (False, orq.SIN_TOKEN))


class IpsUnicas(Entorno):
    def test_misma_ip_privada_en_dos_nodos_cuenta_dos(self):
        """Correccion de defecto (A-18): en «Todos», 10.0.0.5 de p001 y de p002 son dos equipos; el
        destino de internet comun es uno solo."""
        self.tres_cnc("p001")
        self.tres_cnc("p002")
        self.ok("60", "--todos")
        m = re.search(r'<div class="big">([\d,]+)\+?</div><div class="lab"><span class="dot"[^>]*></span>'
                      r'IPs únicas vistas', self.html("_todos"))
        self.assertEqual(m.group(1), "3")
        self.ok("60", "--nodo", "p001")
        m = re.search(r'<div class="big">([\d,]+)\+?</div><div class="lab"><span class="dot"[^>]*></span>'
                      r'IPs únicas vistas', self.html("p001"))
        self.assertEqual(m.group(1), "2")


class AccionesEnLaLista(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")

    def test_iniciar_detener_eliminar_por_punto(self):
        """Capacidad nueva (el user, 2026-10-12): cada fila de Puntos trae Detener (o Iniciar si esta
        parado) con su token y el modal de confirmar, y Eliminar abre el modal de baja (nombre + limpiar
        el MikroTik). La lista no lleva <meta refresh> (cerraria el modal a medio escribir)."""
        r = self.p.pedir("GET", "/puntos", cookie=self.ana)
        self.assertEqual(r.status, 200)
        self.assertIn("<th>Acciones</th>", r.texto)
        self.assertRegex(r.texto, r"<form method=post action='/puntos/p001/parar' onsubmit=\"return ask\(this,"
                                  r"'Detener'.*?name=op value='[0-9a-f-]{36}'")
        self.assertIn("data-pid='p002' data-nombre='sur'", r.texto)
        self.assertIn("name=limpiar_router value=1 checked", r.texto)
        self.assertNotIn("http-equiv=refresh", r.texto)

    def test_detener_desde_la_lista_pide_la_orden(self):
        """Capacidad nueva: el formulario de la fila pide punto.parar del punto de esa fila."""
        r = self.p.pedir("GET", "/puntos", cookie=self.ana)
        tok = re.search(r"action='/puntos/p002/parar'.*?name=op value='([0-9a-f-]{36})'", r.texto, re.S).group(1)
        r = self.p.pedir("POST", "/puntos/p002/parar", {"op": tok}, cookie=self.ana)
        self.assertEqual(r.status, 303)
        self.assertEqual(self.p.orq.ordenes("punto.parar")[-1]["params"], {"pid": "p002"})

    def test_parado_ofrece_iniciar(self):
        """Capacidad nueva: un punto parado ofrece Iniciar (punto.arrancar) en vez de Detener."""
        est = json.load(open(os.path.join(self.p.nodos.RUN, "estado.json"), encoding="utf-8"))
        est["puntos"]["p001"].update(estado="parado", deseado="parado")
        with open(os.path.join(self.p.nodos.RUN, "estado.json"), "w", encoding="utf-8") as f:
            json.dump(est, f)
        r = self.p.pedir("GET", "/puntos", cookie=self.ana)
        self.assertIn("action='/puntos/p001/arrancar'", r.texto)
        self.assertNotIn("action='/puntos/p001/parar'", r.texto)


class BajaSeVeAlMomento(Base):
    def test_punto_purgado_no_sale_aunque_estado_lo_liste(self):
        """Correccion de defecto (el user: «acabo de eliminar y seguia»): un punto que el panel ya dio de
        baja y purgo no sale en la lista ni en el selector aunque estado.json aun lo liste unos segundos."""
        self.assertIn("p002", self.n.pids())
        with open(os.path.join(self.n.ESTADO, "bajas-purgadas.json"), "w", encoding="utf-8") as f:
            json.dump({"p002": int(time.time())}, f)
        self.assertEqual(self.n.pids(), ["p001"])
        self.assertFalse(self.n.existe("p002"))


class EstadoTrasLaOrden(unittest.TestCase):
    def test_estado_json_se_reescribe_al_terminar(self):
        """Correccion de defecto (el user: «acabo de eliminar y seguia»): al terminar punto.borrar el
        orquestador reescribe estado.json en el acto, sin esperar al ciclo de 15 s."""
        import _ayuda_orq as A
        mod, e, s_, orq = A.preparar(ncpu=8)
        self.addCleanup(A.cerrar, orq, e)
        A.crear(self, orq, {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]})
        orq.escribir_estado()
        est = e.ruta("/srv/ids/run/estado.json")
        self.assertIn("p001", json.loads(est.read_text(encoding="utf-8"))["puntos"])
        r = A.ejecutar_orden(orq, "punto.borrar", {"pid": "p001", "confirmar": "norte"})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertNotIn("p001", json.loads(est.read_text(encoding="utf-8"))["puntos"])


class UsuarioConMayusculas(unittest.TestCase):
    def test_vicente_se_guarda_en_minusculas_y_entra(self):
        """Correccion de defecto (el user: «error al crear el user Vicente»): el usuario con mayusculas
        se guarda en minusculas en vez de rechazarse, y en el login se puede escribir con mayusculas."""
        from _dash_p import CLAVE
        p = PanelP()
        self.addCleanup(p.cerrar)
        ana = p.entrar("ana")
        r = p.pedir("POST", "/perfil", {"accion": "add_user", "nuser": "Vicente", "npass": CLAVE,
                                        "nrole": "lectura"}, cookie=ana)
        self.assertNotIn("Usuario inválido", r.texto)
        self.assertIn("vicente", [u["user"] for u in p.d.cargar_usuarios()])
        self.assertNotIn("Vicente", [u["user"] for u in p.d.cargar_usuarios()])
        self.assertTrue(p.entrar("Vicente"))
        self.assertTrue(p.entrar("vicente"))


class AuthKeyAbuseCh(Base):
    def test_no_acepta_cualquier_clave(self):
        """Correccion de defecto (el user: «por que acepta cualquier clave api»): la Auth-Key de abuse.ch
        se validaba descargando el hostfile de URLhaus, que se sirve SIN clave. Ahora se pregunta a la API
        de ThreatFox (servidor local que la imita): clave mala -> False; buena -> True; un 200 que no es
        de la API (el hostfile) -> None, nunca True."""
        import http.server
        import threading

        class AbuseCh(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                k = self.headers.get("Auth-Key", "")
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if k == "hostfile":
                    cod, cuerpo = 200, b"# abuse.ch URLhaus Host file" + bytes([10])
                elif k == "buena":
                    cod, cuerpo = 200, b'{"query_status": "no_result"}'
                else:
                    cod, cuerpo = 403, b'{"query_status": "unknown_auth_key"}'
                self.send_response(cod)
                self.send_header("Content-Length", str(len(cuerpo)))
                self.end_headers()
                self.wfile.write(cuerpo)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), AbuseCh)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.d.ABUSECH_PRUEBA_URL = "http://127.0.0.1:%d/api/v1/" % srv.server_address[1]
        self.assertIs(self.d.feeds_auth_probar("clave-de-abuseipdb-0123")[0], False)
        self.assertEqual(self.d.feeds_auth_probar("buena"), (True, "valida"))
        self.assertIsNone(self.d.feeds_auth_probar("hostfile")[0])


class HistPodar(Base):
    def test_recorta_el_top_sin_atascarse(self):
        """Corrección de defecto (un VPS de producción, 2026-10-16): un abonado con miles de destinos en un día
        dejaba hist_podar sin terminar (subconsulta correlacionada: el grupo se reordenaba por cada fila)
        y el refrescador parado, sin informes nuevos en ningún punto. Ahora es una pasada: queda el top
        HIST_TOP de cada (día, CPE, tipo) y el resto de grupos intacto."""
        dia = time.strftime("%Y-%m-%d")
        c = self.d._hist_con("p001")
        try:
            filas = [(dia, IP, "destino", "198.51.100.%d:%d" % (i % 250, i), i) for i in range(4000)]
            filas += [(dia, "10.0.0.6", "destino", "192.0.2.%d" % i, 1) for i in range(3)]
            filas += [(dia, IP, "firma", "firma %d" % i, 100 - i) for i in range(20)]
            c.executemany("INSERT INTO detalle(dia,cpe,tipo,clave,n) VALUES(?,?,?,?,?)", filas)
            c.commit()
            t0 = time.time()
            self.d.hist_podar(c)
            dur = time.time() - t0
            top = self.d.HIST_TOP
            ns = sorted((r[0] for r in c.execute(
                "SELECT n FROM detalle WHERE cpe=? AND tipo='destino'", (IP,))), reverse=True)
            self.assertEqual(ns, list(range(3999, 3999 - top, -1)))          # los de mayor n
            self.assertEqual(c.execute("SELECT COUNT(*) FROM detalle WHERE cpe='10.0.0.6'").fetchone()[0], 3)
            self.assertEqual(c.execute("SELECT COUNT(*) FROM detalle WHERE tipo='firma'").fetchone()[0], top)
            self.assertLess(dur, 3.0, "hist_podar tardó %.1f s con un grupo de 4000 filas" % dur)
        finally:
            c.close()


class PrefijosAdicionales(Base):
    """Decisión del dueño 2026-10-16: las VPN reciben siempre todo lo privado y el CGNAT; los prefijos
    del punto son solo los adicionales."""

    def test_ficha_vacia_vale(self):
        """Capacidad nueva: la lista de prefijos de la ficha puede ir vacía (sin adicionales)."""
        pw = sys.modules["puntos_web"]
        self.assertEqual(pw.validar_redes(""), ([], ""))
        self.assertEqual(pw.validar_redes("198.51.100.0/24"), (["198.51.100.0/24"], ""))

    def test_espejo_con_la_lista_efectiva_del_orquestador(self):
        """Capacidad nueva: al MikroTik va redes_espejo (todo lo privado sin lo reservado + adicionales);
        con un orquestador anterior que no la publica, sus prefijos de siempre."""
        efectiva = ["10.0.0.0/9", "172.16.0.0/12", "192.168.0.0/16", "198.51.100.0/24"]
        self.a.puntos["p001"].update(redes=["198.51.100.0/24"], redes_espejo=efectiva)
        self.a.puntos["p002"].update(redes=["10.0.0.0/24"])
        self.a.puntos["p002"].pop("redes_espejo", None)
        self.a.escribir_estado()
        self.assertEqual(self.d._espejo_datos("p001")[2], efectiva)
        self.assertEqual(self.d._espejo_datos("p002")[2], ["10.0.0.0/24"])


class FichaPrefijos(unittest.TestCase):
    def test_la_ficha_pide_solo_adicionales(self):
        """Capacidad nueva: la ficha dice que lo privado va siempre y pide solo prefijos adicionales."""
        p = PanelP()
        self.addCleanup(p.cerrar)
        r = p.pedir("GET", "/puntos/p001", cookie=p.entrar("ana"))
        self.assertEqual(r.status, 200)
        self.assertIn("Prefijos adicionales (opcional, uno por línea)", r.texto)
        self.assertIn("Siempre incluidas", r.texto)


class AbonadosSinAdicionales(Entorno):
    PUNTOS = {"p001": {"nombre": "Nodo A", "redes": []}}

    def test_privadas_son_abonados_aunque_no_haya_prefijos(self):
        """Corrección de defecto evitado: con la lista del punto vacía (solo adicionales), los abonados
        privados siguen siendo abonados en el informe (cuarentena, métricas)."""
        self.tres_cnc("p001")
        self.ok("60", "--nodo", "p001")
        self.assertEqual(self.cpes(self.salida("p001", "cuarentena.json")), [("p001", "10.0.0.5")])


class HiloHistorial(Base):
    """La ingesta del historial va en su propio hilo (un VPS de producción, 2026-10-16: con mucho DNS, o el
    atraso tras una parada, el refrescador pasaba minutos ingiriendo y no regeneraba ningún informe)."""

    def test_el_refrescador_ya_no_ingiere(self):
        """Corrección de defecto: una vuelta del refrescador con la ingesta «vencida» no llama a
        hist_ingerir (eso es del hilo del historial)."""
        llamadas = []
        self.d.hist_ingerir = lambda pid=None, **k: llamadas.append(pid)
        estado = {k: 0.0 for k in ("ult_poda", "ult_sensor", "ult_fast", "ult_dur", "ult_fin", "ult_aidb",
                                   "ult_pub", "ult_diag", "ult_feeds", "ult_forzado", "ult_cond", "ult_hist",
                                   "ult_bajas")}
        hecho = {}
        for k in ("barrido_alto_rapido", "medir_sensor", "generar_reporte", "_conducta_nodo",
                  "guardar_diagnostico", "actualizar_feeds_async", "barrer_bajas"):
            if hasattr(self.d, k):
                setattr(self.d, k, (lambda nombre: lambda *a, **kw: hecho.setdefault(nombre, True))(k))
        try:
            self.d._vuelta_refrescador(estado)
        except Exception:
            pass                         # lo que importa es que no haya llamado a hist_ingerir
        self.assertEqual(llamadas, [])

    def test_el_hilo_ingiere_cada_punto(self):
        """Capacidad nueva: una vuelta de _hist_hilo ingiere todos los puntos activos."""
        llamadas = []
        self.d.hist_ingerir = lambda pid=None, **k: llamadas.append(pid)
        espera = self.d._PARAR.wait
        self.d._PARAR.wait = lambda t=None: True          # una sola vuelta
        try:
            self.d._hist_hilo()
        finally:
            self.d._PARAR.wait = espera
        self.assertEqual(sorted(llamadas), ["p001", "p002"])
        self.assertIn("historial", self.d.LATIDO)

    def test_la_baja_espera_al_hilo_del_historial(self):
        """Corrección de defecto evitado: purgar_punto espera a que el hilo del historial suelte el
        punto (si no, podría volver a crear nodos/<pid>/historial.db después de borrarlo)."""
        import threading
        with self.d._OPS_CERROJOS_LOCK:
            lk = self.d._OPS_CERROJOS.setdefault(("p002", "historial"), threading.Lock())
        lk.acquire()
        t0 = time.time()
        threading.Timer(1.0, lk.release).start()
        self.d.purgar_punto("p002")
        self.assertGreaterEqual(time.time() - t0, 0.9)


class SoloElUltimoReporte(Entorno):
    def test_borra_las_instantaneas_viejas(self):
        """Capacidad nueva (el user quito «Reportes guardados», 2026-10-12): el generador deja solo el
        reporte mas nuevo del nodo, tambien los de esta misma hora."""
        d = os.path.join(self.panel, "nodos", "p001")
        os.makedirs(d, exist_ok=True)
        for nombre, hace in (("report-20261001-1000.html", 86400), ("report-20261012-0000.html", 120)):
            ruta = os.path.join(d, nombre)
            with open(ruta, "w", encoding="utf-8") as f:
                f.write("<html></html>")
            os.utime(ruta, (time.time() - hace, time.time() - hace))
        self.tres_cnc("p001")
        self.ok("60", "--nodo", "p001")
        self.assertEqual(len([n for n in os.listdir(d) if n.startswith("report-")]), 1)
        self.assertNotIn("report-20261001-1000.html", os.listdir(d))

if __name__ == "__main__":
    unittest.main()
