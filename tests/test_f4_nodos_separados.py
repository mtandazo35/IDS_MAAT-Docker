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
        self.hechas, self.espejo, self.fallan = [], [], set()
        self.api = {"USER": "ids-api", "PASS": "x", "ROUTER_ID": "p001", "LIST": "suricata-cuarentena"}
        d = self.d
        d.cargar_mk_de = lambda r: dict(self.api)
        d.router_por_id = lambda pid: {"id": pid}
        self.espejo_ok = True
        d.espejo_retirar = lambda pid, usuario=None: (self.espejo.append(pid) or
                                                      {"ok": self.espejo_ok, "mensaje": "retirado" if self.espejo_ok
                                                       else "sin respuesta"})

        class Con:
            def close(self):
                pass
        d.mk_conectar = lambda m, timeout=15: Con()

        def quitar(s_, ip, lst):
            self.activos_durante = list(d.pids_activos())
            self.hechas.append((ip, lst))
            return (False, "timeout") if ip in self.fallan else (True, "1 entrada(s) quitada(s) de " + lst)
        d._mk_quitar_en = quitar
        d.guardar_enviados({"p001|" + IP: {"cuando": 1, "router": "p001", "lista": "clientes-botnet"},
                            "p002|" + IP: {"cuando": 1, "router": "p002", "lista": "clientes-botnet"}}, d.MK_SENT)
        d.guardar_enviados({"p001|10.0.0.7": {"cuando": 1, "router": "p001"}}, d.MK_SENT_DNS)
        d.guardar_enviados({"192.0.2.66": {"cuando": 1, "puntos": ["p001", "p002"], "nodos": 2}}, d.MK_SENT_DST)

    def test_sin_api_no_toca_nada(self):
        """Conservacion: un punto sin usuario/clave de la API nunca recibio nada del panel: ok sin
        hablar con el router."""
        self.api = {}
        res = self.d.baja_limpiar_router("p001", "ana")
        self.assertEqual((res["ok"], res["api"]), (True, False))
        self.assertEqual((self.espejo, self.hechas), ([], []))

    def test_retira_espejo_y_quita_solo_lo_del_punto(self):
        """Capacidad nueva (A-21(5)): retira el espejo y saca del router los CPEs del punto (cada uno
        de su lista) y su parte de los destinos bloqueados; lo de p002 queda intacto. Mientras dura,
        el fondo no trabaja con ese punto."""
        res = self.d.baja_limpiar_router("p001", "ana")
        self.assertTrue(res["ok"], res["mensaje"])
        self.assertEqual(self.espejo, ["p001"])
        self.assertEqual(sorted(self.hechas), sorted([(IP, "clientes-botnet"),
                                                      ("10.0.0.7", "suricata-dns-sospechoso"),
                                                      ("192.0.2.66", "suricata-destinos-malos")]))
        self.assertEqual(list(self.d.cargar_enviados(self.d.MK_SENT)), ["p002|" + IP])
        self.assertEqual(self.d.cargar_enviados(self.d.MK_SENT_DNS), {})
        self.assertEqual(self.d.cargar_enviados(self.d.MK_SENT_DST)["192.0.2.66"]["puntos"], ["p002"])
        self.assertNotIn("p001", self.activos_durante)
        self.assertIn("p002", self.activos_durante)

    def test_espejo_que_falla_no_sigue(self):
        """Capacidad nueva: si no se puede retirar el espejo, no se quita nada mas, sale ok=False y
        el punto vuelve al fondo."""
        self.espejo_ok = False
        res = self.d.baja_limpiar_router("p001", "ana")
        self.assertFalse(res["ok"])
        self.assertIn("espejo", res["mensaje"])
        self.assertEqual(self.hechas, [])
        self.assertIn("p001|" + IP, self.d.cargar_enviados(self.d.MK_SENT))
        self.assertIn("p001", self.d.pids_activos())

    def test_ip_que_no_sale_se_queda_registrada(self):
        """Correccion de defecto evitado: una IP que el router no confirma sigue en el registro (si
        no, quedaria cortada e invisible) y la baja no sigue."""
        self.fallan = {IP}
        res = self.d.baja_limpiar_router("p001", "ana")
        self.assertFalse(res["ok"])
        self.assertIn("p001|" + IP, self.d.cargar_enviados(self.d.MK_SENT))
        self.assertEqual(self.d.cargar_enviados(self.d.MK_SENT_DNS), {})
        self.assertIn("p001", self.d.pids_activos())


class BajaFormulario(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")
        self.limpiezas, self.canceladas = [], []
        self.resultado = {"ok": True, "mensaje": "espejo retirado y 0 IP(s) quitadas del router"}
        self.p.d.baja_limpiar_router = lambda pid, usuario=None: (
            self.limpiezas.append((pid, usuario, len(self.p.orq.ordenes("punto.borrar")))) or dict(self.resultado))
        self.p.d.baja_cancelada = lambda pid: self.canceladas.append(pid)

    def baja(self, **extra):
        return self.p.pedir("POST", "/puntos/p001/borrar", dict({"confirmar": "norte"}, **extra), cookie=self.ana)

    def test_la_ficha_ofrece_limpiar_marcado(self):
        """Capacidad nueva: el formulario de baja trae «Limpiar antes el MikroTik» marcado."""
        r = self.p.pedir("GET", "/puntos/p001", cookie=self.ana)
        self.assertRegex(r.texto, r"<input type=checkbox name=limpiar_router value=1 checked>")

    def test_limpia_antes_de_pedir_la_baja(self):
        """Capacidad nueva (A-21(5)): con la casilla, primero se limpia el router y despues se pide
        punto.borrar."""
        r = self.baja(limpiar_router="1")
        self.assertEqual(r.status, 303)
        self.assertEqual(self.limpiezas, [("p001", "ana", 0)])
        self.assertEqual(len(self.p.orq.ordenes("punto.borrar")), 1)

    def test_router_que_falla_para_la_baja(self):
        """Capacidad nueva: si el router no se pudo limpiar, NO se pide la baja y se explica."""
        self.resultado = {"ok": False, "mensaje": "no se pudo retirar el espejo: sin respuesta"}
        r = self.baja(limpiar_router="1")
        self.assertEqual(r.status, 409)
        self.assertIn("No se dio de baja", r.texto)
        self.assertEqual(self.p.orq.ordenes("punto.borrar"), [])

    def test_sin_casilla_no_toca_el_router(self):
        """Conservacion: desmarcada (router que ya no existe), la baja sigue sin hablar con el router."""
        r = self.baja()
        self.assertEqual(r.status, 303)
        self.assertEqual(self.limpiezas, [])
        self.assertEqual(len(self.p.orq.ordenes("punto.borrar")), 1)

    def test_baja_rechazada_devuelve_el_punto_al_fondo(self):
        """Capacidad nueva: si el orquestador no acepta la baja tras limpiar, el punto vuelve al fondo."""
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
        self.assertEqual(self.canceladas, ["p001"])


class IpsUnicas(Entorno):
    def test_misma_ip_privada_en_dos_nodos_cuenta_dos(self):
        """Correccion de defecto (A-18): en «Todos», 10.0.0.5 de p001 y de p002 son dos equipos; el
        destino de internet comun es uno solo."""
        self.tres_cnc("p001")
        self.tres_cnc("p002")
        self.ok("60", "--todos")
        m = re.search(r'<div class="big">([\d,]+)\+?</div><div class="lab"><span class="dot"[^>]*></span>'
                      r'IPs unicas vistas', self.html("_todos"))
        self.assertEqual(m.group(1), "3")
        self.ok("60", "--nodo", "p001")
        m = re.search(r'<div class="big">([\d,]+)\+?</div><div class="lab"><span class="dot"[^>]*></span>'
                      r'IPs unicas vistas', self.html("p001"))
        self.assertEqual(m.group(1), "2")


if __name__ == "__main__":
    unittest.main()
