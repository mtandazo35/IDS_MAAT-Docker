"""Apartado B de Puntos (2026-10-14): «lo que demora, por debajo; que visualmente se vea bien».

- T1 (Espejo en segundo plano) ya no está: la ficha no monta el espejo desde 2026-10-16 (lo monta el
  operador a mano en el MikroTik); la prueba de que la ruta ya no existe está en test_p_puntos.SinEspejo.
- T2 Prefijos por fetch: {op_id} y el avance en JSON con la duración de cada paso. La clave de un
  solo uso de punto.crear sale UNA vez en el JSON (y nunca en operaciones.json).
- T3 La página de una operación ya no se recarga entera (sin <meta refresh>): sigue el JSON.
- T4 Ficha liviana: alertas_24h acepta su caché de <60 s aunque el eve.json crezca; «Probar la
  conexión» por fetch devuelve {ok, mensaje} para un modal. (La huella por fetch: test_panel_puntos_estados.)
- T5 Baja en segundo plano: limpiar el router (avance «IPs quitadas i/N»), retirar el espejo y
  encolar punto.borrar con el token del formulario; si el router no queda limpio, no se encola.
- T6 Públicas: «Agregar» por fetch revisa SOLO la nueva (listas negras y AbuseIPDB) y una entrada
  no se revisa dos veces a la vez.
- T7 Telegram: un punto que espera a su MikroTik (nunca conectó) no avisa «Sin tráfico».
- T8 Si se cierra la pestaña: la ficha retoma el trabajo sin ver y lo enseña una sola vez.

Tipo «corrección de defecto» salvo las marcadas «conservación»: cada una falla sin el arreglo.
Panel de verdad sobre un directorio temporal (fixtures/panel2/_dash_p.py), sin red; los hilos se
esperan con tope.
"""
import json
import os
import re
import sys
import threading
import time
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(TESTS, "fixtures", "panel2"))
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)
from _dash_p import PanelP  # noqa: E402

RE_TOKEN = r"name=op value='([0-9a-f-]{36})'"
RE_UUID = r"^[0-9a-f-]{36}$"
TOPE = 10


def esperar(cond, tope=TOPE):
    fin = time.time() + tope
    while time.time() < fin:
        v = cond()
        if v:
            return v
        time.sleep(0.03)
    raise AssertionError("no paso a tiempo")


class _Base(unittest.TestCase):
    Panel = PanelP

    def setUp(self):
        self.p = self.Panel()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")

    def get(self, ruta):
        r = self.p.pedir("GET", ruta, cookie=self.ana)
        self.assertEqual(r.status, 200, r.texto[:300])
        return r.texto

    def ficha(self, pid="p001"):
        return self.get("/puntos/%s" % pid)

    def token(self, texto, accion, valor=None, pid="p001"):
        patron = r"action='/puntos/%s/%s'[^>]*>(?:(?!</form>).)*?" % (pid, accion)
        if valor:
            patron += r"name=accion value=%s>(?:(?!</form>).)*?" % valor
        return re.search(patron + RE_TOKEN, texto, re.S).group(1)

    def ajax(self, ruta, form):
        t0 = time.time()
        r = self.p.pedir("POST", ruta, dict(form, ajax="1"), cookie=self.ana)
        return r, json.loads(r.texto), time.time() - t0

    def estado(self, op_id):
        r = self.p.pedir("GET", "/operaciones/%s?json=1" % op_id, cookie=self.ana)
        self.assertEqual(r.status, 200, r.texto[:300])
        self.assertEqual(r.cab("Cache-Control"), "no-store")
        return json.loads(r.texto)

    def fin(self, op_id):
        return esperar(lambda: (lambda j: j if j["terminada"] else None)(self.estado(op_id)))

    def bitacora(self):
        try:
            with open(self.p.d.BITACORA_LOG, encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""


# --------------------------------------------------------------------------------------------
# T2 y T3: prefijos por fetch, JSON del avance, página de operación sin recargar, clave una vez
# --------------------------------------------------------------------------------------------
class Avance(_Base):
    def responder(self, datos_por_vez):
        """El orquestador falso contesta op.estado con lo que toque en cada pregunta."""
        real, vez = self.p.orq, {"n": 0}

        def transporte(pet):
            if pet["orden"] == "op.estado":
                real.pedidas.append(pet)
                d = datos_por_vez[min(vez["n"], len(datos_por_vez) - 1)]
                vez["n"] += 1
                return {"op_id": pet["op_id"], "ok": True, "codigo": "OK", "mensaje": "", "datos": d}
            return real(pet)
        self.p.pw.TRANSPORTE = transporte

    def test_prefijos_por_fetch_con_pasos_y_duraciones(self):
        """«Guardar prefijos» por fetch: {op_id} (antes, 303 y la página de la operación) y el avance
        en JSON con la duración de cada paso (antes _pasos_limpios la quitaba)."""
        tok = self.token(self.ficha(), "ajustar")
        r, j, _dt = self.ajax("/puntos/p001/ajustar", {"redes": "10.5.0.0/24", "op": tok})
        self.assertEqual(r.status, 200)
        self.assertEqual(j["op_id"], tok)
        self.assertRegex(j["token"], RE_UUID)
        self.assertEqual(self.p.orq.ordenes("punto.ajustar")[0]["params"]["redes_abonados"], ["10.5.0.0/24"])
        pasos = [{"n": 1, "nombre": "validar", "estado": "ok", "dur_s": 0.4},
                 {"n": 2, "nombre": "reiniciar suricata", "estado": "ok", "dur_s": 12.5}]
        self.responder([{"estado": "en_curso", "paso": "esperar salud", "avance": "2/4", "pasos": pasos},
                        {"estado": "terminada", "codigo": "OK", "mensaje": "prefijos aplicados", "avance": "4/4",
                         "pasos": pasos, "resultado": {"pid": "p001"}}])
        e = self.estado(tok)
        self.assertEqual((e["terminada"], e["etapa"], e["porcentaje"]), (False, "esperar salud", 50))
        self.assertEqual(e["pasos"][1], {"nombre": "reiniciar suricata", "estado": "ok", "dur_s": 12.5})
        f = self.estado(tok)
        self.assertTrue(f["terminada"] and f["ok"])
        self.assertIn("12,5 s", f["html"])
        self.assertIn("Prefijos cambiados en el punto", f["html"])
        # el espejo lo monta el operador a mano: el aviso le dice a donde llevar los adicionales (2026-10-16)
        self.assertIn("Redes Privadas", f["html"])
        self.assertNotIn("#espejo", f["html"])
        # un error de validación también vuelve en JSON (para el modal)
        r, j, _dt = self.ajax("/puntos/p001/ajustar", {"redes": "no-es-red"})
        self.assertEqual(r.status, 400)
        self.assertIn("no es una red", j["error"])

    def test_pagina_de_operacion_sin_recarga(self):
        """Antes: <meta refresh=2> recargaba la página entera. Ahora pinta el avance y lo sigue por
        JSON (popSeguir), sin recargarse."""
        tok = self.token(self.ficha(), "reiniciar")
        r = self.p.pedir("POST", "/puntos/p001/reiniciar", {"op": tok}, cookie=self.ana)
        self.responder([{"estado": "en_curso", "paso": "parar", "avance": "1/3", "pasos": []}])
        h = self.get(r.cab("Location"))
        self.assertNotIn("http-equiv=refresh", h)
        self.assertIn("popSeguir('%s')" % tok, h)
        self.assertIn("id=opvivo", h)
        self.assertIn("Paso actual: parar (1/3)", h)

    def test_clave_de_un_solo_uso_sale_una_vez_en_el_json(self):
        """punto.crear entrega la clave en la primera op.estado terminada: el JSON (que es lo que
        pregunta la página) la trae en su `html` UNA vez; la siguiente ya no, ni la página, ni
        operaciones.json."""
        tok = re.search(RE_TOKEN, self.get("/puntos/nuevo")).group(1)
        self.p.pedir("POST", "/puntos/nuevo", {"op": tok, "nombre": "este", "redes": "10.1.0.0/24",
                                               "ros_version": "7", "perfil": "reducido"}, cookie=self.ana)
        f = self.estado(tok)
        self.assertTrue(f["terminada"])
        self.assertEqual(f["html"].count("CLAVE-VPN-UNICA-7Q2"), 1)
        self.assertNotIn("CLAVE-VPN-UNICA-7Q2", json.dumps(self.estado(tok)))
        self.assertNotIn("CLAVE-VPN-UNICA-7Q2", self.get("/operaciones/%s" % tok))
        with open(os.path.join(self.p.nodos.ESTADO, "operaciones.json"), encoding="utf-8") as fh:
            self.assertNotIn("CLAVE-VPN-UNICA-7Q2", fh.read())

    def test_json_de_otro_usuario_o_inexistente(self):
        """Conservación: el avance solo lo ve quien pidió la operación."""
        tok = self.token(self.ficha(), "reiniciar")
        self.p.pedir("POST", "/puntos/p001/reiniciar", {"op": tok}, cookie=self.ana)
        olga = self.p.entrar("olga")
        self.assertEqual(self.p.pedir("GET", "/operaciones/%s?json=1" % tok, cookie=olga).status, 403)
        r = self.p.pedir("GET", "/operaciones/%s?json=1" % ("0" * 8 + "-0000-4000-8000-" + "0" * 12), cookie=self.ana)
        self.assertEqual(r.status, 404)


# --------------------------------------------------------------------------------------------
# T4: ficha liviana
# --------------------------------------------------------------------------------------------
class Ficha(_Base):
    def eve(self, texto):
        with open(os.path.join(self.p.tmp.name, "datos", "p001", "eve.json"), "a", encoding="utf-8",
                  newline="") as f:
            f.write(texto)

    @staticmethod
    def alerta(t):
        iso = time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(t))
        return '{"timestamp":"%s","event_type":"alert","src_ip":"10.0.0.5"}\n' % iso

    def test_alertas_24h_acepta_su_cache_de_menos_de_60_s(self):
        """El eve.json vivo crece a cada segundo: con la marca exacta la caché nunca valía y cada
        carga releía hasta 8 MB por punto. Ahora vale 60 s aunque el fichero haya crecido."""
        ahora = time.time()
        self.eve(self.alerta(ahora - 60))
        self.assertEqual(self.p.pw.alertas_24h("p001", ahora), (1, True))
        self.eve(self.alerta(ahora - 30))
        self.assertEqual(self.p.pw.alertas_24h("p001", ahora + 30), (1, True))
        self.assertEqual(self.p.pw.alertas_24h("p001", ahora + 61), (2, True))

    def test_probar_la_conexion_por_fetch(self):
        """«Probar la conexión» (20-35 s con el router caído) por fetch: {ok, mensaje} para el modal
        y un token nuevo para el formulario, que sigue en la página."""
        def caido(*a, **k):
            raise TimeoutError("timed out")
        self.p.d.mk_conectar = caido
        h = self.ficha()
        self.assertIn("onclick='return papiProbar(this)'", h)
        tok = self.token(h, "api", "guardar")
        r, j, _dt = self.ajax("/puntos/p001/api", {"accion": "probar", "user": "ids-api", "pass": "clave-api", "op": tok})
        self.assertEqual(r.status, 502)
        self.assertFalse(j["ok"])
        self.assertIn("no conectó", j["mensaje"])
        self.assertRegex(j["token"], RE_UUID)


# --------------------------------------------------------------------------------------------
# T5: baja en segundo plano
# --------------------------------------------------------------------------------------------
class Baja(_Base):
    def setUp(self):
        super().setUp()
        d, self.orden = self.p.d, []

        class Con:
            def close(self):
                pass
        d.mk_conectar = lambda m, timeout=15: Con()
        d.router_por_id = lambda pid: {"id": pid, "USER": "ids-api", "PASS": "x"}
        self.para = threading.Event()
        self.addCleanup(self.para.set)

        def quitar(s_, ip, lst):
            self.orden.append(ip)
            if ip == "10.0.0.9":
                self.para.wait(TOPE)          # la prueba mira el avance a mitad
            return True, "1 quitada"
        d._mk_quitar_en = quitar
        d.espejo_retirar = lambda pid, usuario=None, avance=None: (
            self.orden.append("espejo") or {"ok": True, "mensaje": "retirado"})
        d.guardar_enviados({"p001|10.0.0.%d" % i: {"cuando": 1, "router": "p001"} for i in (5, 7, 9, 11)},
                           d.MK_SENT)
        self.renovadas = []
        real = d.baja_renovar
        d.baja_renovar = lambda pid, op: (self.renovadas.append(op), real(pid, op))

    def test_baja_por_fetch_limpia_con_avance_y_encola(self):
        """Antes la limpieza del router iba dentro del POST (decenas de s a minutos). Ahora: {trabajo}
        enseguida, avance «IPs quitadas i/N», espejo al final, punto.borrar con el token del
        formulario y, al terminar, a su página de avance. La marca de prebaja se renueva."""
        tok = self.token(self.ficha(), "borrar")
        r, j, dt = self.ajax("/puntos/p001/borrar", {"confirmar": "norte", "limpiar_router": "1", "op": tok})
        self.assertLess(dt, 3)
        tid = j["trabajo"]
        # 10.0.0.11, .5 y .7 salen; la cuarta (.9) se queda esperando en el router
        e = esperar(lambda: (lambda x: x if x.get("etapa") == "IPs quitadas 3/4" else None)(self.estado(tid)))
        self.assertEqual(e["porcentaje"], 75)
        self.assertEqual([x["nombre"] for x in e["pasos"]], ["limpiar el MikroTik", "conectar"])
        self.assertEqual(self.p.orq.ordenes("punto.borrar"), [])          # aún no
        # a mitad de la baja la marca existe y es de ESTA operación (al final no se mira: el barrido
        # de fondo la suelta en cuanto la baja termina, y en el runner lento del CI llega antes)
        self.assertEqual(self.p.d._PREBAJA["p001"][1], tok)
        self.para.set()
        f = self.fin(tid)
        self.assertTrue(f["ok"], f)
        self.assertEqual(f["siguiente"], "/operaciones/%s" % tok)
        self.assertEqual(self.orden[-1], "espejo")
        self.assertEqual([x["op_id"] for x in self.p.orq.ordenes("punto.borrar")], [tok])
        self.assertIn(tok, self.renovadas)
        marca = self.p.d._PREBAJA.get("p001")
        if marca is not None:                       # si el barrido aún no la soltó, sigue siendo la suya
            self.assertEqual(marca[1], tok)

    def test_router_sin_limpiar_no_encola_la_baja(self):
        """Si el router no queda limpio, la baja no sigue y lo dice (en el modal)."""
        self.para.set()
        self.p.d.espejo_retirar = lambda pid, usuario=None, avance=None: {"ok": False, "mensaje": "sin respuesta"}
        tok = self.token(self.ficha(), "borrar")
        _r, j, _dt = self.ajax("/puntos/p001/borrar", {"confirmar": "norte", "limpiar_router": "1", "op": tok})
        f = self.fin(j["trabajo"])
        self.assertFalse(f["ok"])
        self.assertEqual(f["titulo_fin"], "No se dio de baja")
        self.assertIn("no se pudo retirar el espejo", f["mensaje"])
        self.assertEqual(self.p.orq.ordenes("punto.borrar"), [])
        self.assertNotIn("p001", self.p.d._PREBAJA)

    def test_nombre_que_no_coincide(self):
        """Por fetch, sin el nombre exacto: 400 en JSON (para el modal), ni trabajo ni orden."""
        r, j, _dt = self.ajax("/puntos/p001/borrar", {"confirmar": "sur"})
        self.assertEqual(r.status, 400)
        self.assertNotIn("trabajo", j)
        self.assertEqual(self.orden, [])


# --------------------------------------------------------------------------------------------
# T6: públicas en Reputación
# --------------------------------------------------------------------------------------------
class Publicas(_Base):
    def test_agregar_por_fetch_revisa_solo_la_nueva(self):
        """Antes: «Agregar» recargaba y lanzaba la revisión DNSBL de TODAS (sin AbuseIPDB de la
        nueva). Ahora JSON sin recargar y las dos revisiones, solo de la nueva."""
        d = self.p.d
        real_valida = d.aidb_ip_valida
        d.aidb_ip_valida = lambda ip: (ip.startswith("198.51.100."), "no es una IP pública")  # RFC 5737
        d.guardar_publicas_de("p001", "198.51.100.1", origen_nuevas="manual")
        lanzadas = []
        d.vigilar_dnsbl = lambda solo=None: lanzadas.append(("dnsbl", solo))
        d.vigilar_publicas = lambda forzar=False, solo=None: lanzadas.append(("aidb", solo))
        r, j, _dt = self.ajax("/publicas/agregar", {"rid": "p001", "entrada": "198.51.100.7"})
        self.assertEqual(r.status, 200)
        self.assertTrue(j["ok"])
        self.assertEqual(j["nuevas"], ["198.51.100.7"])
        esperar(lambda: len(lanzadas) == 2)
        self.assertEqual(sorted(lanzadas), [("aidb", ["198.51.100.7"]), ("dnsbl", ["198.51.100.7"])])
        d.aidb_ip_valida = real_valida
        r, j, _dt = self.ajax("/publicas/agregar", {"rid": "p001", "entrada": "no-es-ip"})
        self.assertFalse(j["ok"])
        self.assertIn("No se agregó", j["msg"])
        h = self.get("/reputacion")
        self.assertIn("id='pubsec-p001'", h)
        self.assertIn("onsubmit='return pubAgregar(this)'", h)

    def test_una_entrada_no_se_revisa_dos_veces_a_la_vez(self):
        """Dos clics lanzaban dos hilos que se pisaban el historial. Ahora el segundo no revisa lo
        que ya se está revisando, la pantalla lo dice («revisando…») y solo se revisa la pedida."""
        d = self.p.d
        d.aidb_ip_valida = lambda ip: (True, "")          # 198.51.100.x (RFC 5737) cuenta como pública
        d.guardar_publicas_de("p001", "198.51.100.1 198.51.100.7", origen_nuevas="manual")
        suelta, vistas = threading.Event(), []
        self.addCleanup(suelta.set)

        def revisar(ent, tope=None):
            vistas.append(ent)
            suelta.wait(TOPE)
            return {"n_listadas": 0, "n_pbl": 0, "ips": {}, "ts": int(time.time())}
        d.dnsbl_revisar = revisar
        h1 = threading.Thread(target=d.vigilar_dnsbl, kwargs={"solo": ["198.51.100.7"]})
        h1.start()
        esperar(lambda: vistas)
        self.assertEqual(d.publicas_revisando(), ["198.51.100.7"])
        self.assertEqual(d.vigilar_dnsbl(solo=["198.51.100.7"]), 0)      # no la repite
        self.assertIn("data-rev='198.51.100.7'>revisando…", self.get("/reputacion"))
        self.assertEqual(json.loads(self.get("/publicas/estado")), {"revisando": ["198.51.100.7"]})
        suelta.set()
        h1.join(TOPE)
        self.assertEqual(vistas, ["198.51.100.7"])
        self.assertEqual(d.publicas_revisando(), [])
        self.assertIn("198.51.100.7", d._dnsbl_hist())


# --------------------------------------------------------------------------------------------
# T7: Telegram «Sin tráfico» de un punto que espera a su MikroTik
# --------------------------------------------------------------------------------------------
class Telegram(_Base):
    def test_esperando_mikrotik_no_avisa_y_conectado_si(self):
        d, avisos = self.p.d, []
        d.enviar_telegram = lambda t: avisos.append(t) or True
        d.medir_sensor("p002")
        time.sleep(0.05)
        o = d.medir_sensor("p002")             # sin tráfico (antes: «Sin trafico» por Telegram)
        self.assertTrue(o.get("esperando_mk"))
        self.assertIn("Esperando al MikroTik", o["titulo"])
        self.assertEqual([x for x in avisos if "sur" in x], [])
        # conservación: el que estaba conectado y se queda sin tráfico sí avisa
        d.medir_sensor("p001")
        time.sleep(0.05)
        d.medir_sensor("p001")
        self.assertTrue([x for x in avisos if "norte" in x])
        # y si p002 llegó a conectar y se cayó, también
        sen = self.p.nodos.salida("sensor.json", "p002")
        with open(sen, encoding="utf-8") as f:
            prev = json.load(f)
        prev["mk_visto"] = True
        with open(sen, "w", encoding="utf-8") as f:
            json.dump(prev, f)
        time.sleep(0.05)
        d.medir_sensor("p002")
        self.assertTrue([x for x in avisos if "sur" in x])


# --------------------------------------------------------------------------------------------
# T8: si se cierra la pestaña
# --------------------------------------------------------------------------------------------
class Retomar(_Base):
    def test_la_ficha_retoma_lo_no_visto_una_vez(self):
        """Un trabajo del panel en la ficha (una baja que no siguió) terminó con la pestaña cerrada
        sin verlo: la ficha lo retoma (pjretomar) y, visto el resultado, ya no lo vuelve a enseñar."""
        tid, nuevo = self.p.pw.lanzar_trabajo(
            self.p.d, "p001", "panel.baja", "ana", "127.0.0.1",
            lambda avance: {"ok": False, "mensaje": "el router no respondió",
                            "resultado": {"titulo_fin": "No se dio de baja", "html": ""}})
        self.assertTrue(nuevo)
        esperar(lambda: self.p.pw.ops().obtener(tid).get("terminada"))
        h = self.ficha()
        m = re.search(r"<div id=pjretomar hidden data-ops='([^']*)'>", h)
        self.assertIsNotNone(m)
        self.assertIn(tid, m.group(1))
        self.assertTrue(self.estado(tid)["terminada"])          # lo que hace el JS al retomarlo
        self.assertNotIn("<div id=pjretomar", self.ficha())
        self.assertNotIn("<div id=pjretomar", self.ficha("p002"))      # el de otro punto no

    def test_trabajo_de_un_panel_que_se_reinicio(self):
        """Un trabajo abierto de otro proceso (el panel se reinició a mitad) no se queda «en curso»
        para siempre: al mirarlo se cierra como interrumpido."""
        o = self.p.pw.ops()
        tid = "1" * 8 + "-1111-4111-8111-" + "1" * 12
        o.registrar(tid, "ana", "panel.espejo.aplicar", pid="p001", extra={"proceso": "otro", "etapa": "export"})
        self.assertIn(tid, self.ficha())
        f = self.estado(tid)
        self.assertTrue(f["terminada"])
        self.assertFalse(f["ok"])
        self.assertIn("se reinició", f["mensaje"])


if __name__ == "__main__":
    unittest.main()
