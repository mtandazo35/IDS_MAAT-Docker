"""Apartado B de Puntos (2026-10-14): «lo que demora, por debajo; que visualmente se vea bien».

- T1 Espejo en segundo plano: «Ver el plan», «Aplicar», «Pausar» y «Retirar» por fetch (ajax=1)
  devuelven enseguida {trabajo}; un hilo del panel habla con el router y GET
  /operaciones/<id>?json=1 da el avance por etapas y el resultado (el plan con su huella). Aplicar
  lee el router 2 veces (antes 3); un segundo clic se engancha al trabajo en marcha; con un
  punto.ajustar pendiente, Aplicar se bloquea; la bitácora lleva usuario e IP aunque corra en un hilo.
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
import importlib
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
# T1: espejo en segundo plano
# --------------------------------------------------------------------------------------------
class EspejoFondo(_Base):
    def plan_lento(self):
        """espejo_plan que cuenta sus etapas y espera a que la prueba lo suelte."""
        self.suelta = threading.Event()
        self.addCleanup(self.suelta.set)
        p = self.p

        def plan(pid, avance=None):
            p.espejo.append(("plan", pid))
            if avance:
                avance(etapa="conectar")
                avance(etapa="leer router")
            self.suelta.wait(TOPE)
            return {"ok": True, "mensaje": "plan", "lineas": list(p.plan)}
        p.d.espejo_plan = plan

    def test_plan_responde_enseguida_y_se_sigue_por_etapas(self):
        """Antes: «Ver el plan» esperaba al router dentro de la petición (hasta 45 s). Ahora responde
        {trabajo} enseguida; el JSON dice la etapa y, al terminar, el plan con su Aplicar y su huella."""
        self.plan_lento()
        r, j, dt = self.ajax("/puntos/p001/espejo", {"accion": "plan"})
        self.assertEqual(r.status, 200)
        self.assertLess(dt, 3)
        tid = j["trabajo"]
        self.assertEqual(j["orden"], "panel.espejo.plan")
        e = esperar(lambda: (lambda x: x if x.get("etapa") == "leer router" else None)(self.estado(tid)))
        self.assertFalse(e["terminada"])
        self.assertEqual([x["nombre"] for x in e["pasos"]], ["conectar"])
        self.assertIn("dur_s", e["pasos"][0])
        self.suelta.set()
        f = self.fin(tid)
        self.assertTrue(f["ok"])
        self.assertIn("Aplicar este plan", f["html"])
        self.assertIn("sniff-tzsp", f["html"])
        self.assertRegex(f["html"], r"name=plan value='[0-9a-f]{32}'")
        self.assertIn("pesp(this.form)", f["html"])            # Aplicar también por fetch
        # el orquestador no sabe nada de los trabajos del panel (vista_op no le pregunta)
        self.assertEqual([x for x in self.p.orq.ordenes("op.estado") if x["params"].get("op_id") == tid], [])
        # la bitácora del hilo lleva usuario e IP de quien lo pidió
        linea = [x for x in self.bitacora().splitlines() if "\tESPEJO-PLAN\t" in x][-1]
        self.assertEqual(linea.split("\t")[1:3], ["ana", "127.0.0.1"])

    def test_segundo_clic_se_engancha_al_que_esta_en_marcha(self):
        """Dos a la vez en el mismo punto: el segundo no espera 120 s a un cerrojo ni lanza otro;
        recibe el id del que está en marcha."""
        self.plan_lento()
        _r, j1, _dt = self.ajax("/puntos/p001/espejo", {"accion": "plan"})
        tok = self.token(self.ficha(), "espejo", "pausar")
        r, j2, dt = self.ajax("/puntos/p001/espejo", {"accion": "pausar", "op": tok})
        self.assertLess(dt, 3)
        self.assertEqual(j2["trabajo"], j1["trabajo"])
        self.assertEqual(j2["orden"], "panel.espejo.plan")
        self.assertIn("Ya había otra orden", j2["nota"])
        self.suelta.set()
        self.fin(j1["trabajo"])
        self.assertNotIn(("pausar", "p001"), self.p.espejo)
        # el token no se gastó: ahora sí pausa, y un reintento del mismo formulario no repite
        _r, j3, _dt = self.ajax("/puntos/p001/espejo", {"accion": "pausar", "op": tok})
        self.fin(j3["trabajo"])
        _r, j4, _dt = self.ajax("/puntos/p001/espejo", {"accion": "pausar", "op": tok})
        self.assertEqual(j4["trabajo"], j3["trabajo"])
        self.assertEqual(self.p.espejo.count(("pausar", "p001")), 1)

    def test_aplicar_se_bloquea_con_un_ajuste_pendiente(self):
        """Con un punto.ajustar de ese punto aún en el orquestador, Aplicar no se lanza (llevaría la
        lista de redes vieja) y lo explica; terminado el ajuste, sí."""
        tok = self.token(self.ficha(), "ajustar")
        self.assertEqual(self.ajax("/puntos/p001/ajustar", {"redes": "10.9.0.0/24", "op": tok})[0].status, 200)
        real = self.p.orq

        def transporte(pet):                    # el ajuste sigue en curso
            if pet["orden"] == "op.estado":
                real.pedidas.append(pet)
                return {"op_id": pet["op_id"], "ok": True, "codigo": "OK", "mensaje": "",
                        "datos": {"estado": "en_curso", "paso": "validar", "avance": "1/4", "pasos": []}}
            return real(pet)
        self.p.pw.TRANSPORTE = transporte
        r, j, _dt = self.ajax("/puntos/p001/espejo", {"accion": "aplicar", "plan": "ab" * 16})
        self.assertEqual(r.status, 409)
        self.assertIn("cambio de prefijos", j["error"])
        self.assertNotIn("trabajo", j)
        # sin JavaScript, lo mismo
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "aplicar", "plan": "ab" * 16}, cookie=self.ana)
        self.assertEqual(r.status, 409)
        self.assertNotIn(("aplicar", "p001"), self.p.espejo)
        # también cuando lo dice la cola de estado.json (de otro panel o de la CLI)
        self.p.pw.TRANSPORTE = real
        ruta = os.path.join(self.p.tmp.name, "run", "estado.json")
        with open(ruta, encoding="utf-8") as f:
            est = json.load(f)
        est["cola"]["en_curso"] = {"op_id": "x", "orden": "punto.ajustar", "pid": "p001", "paso": "x"}
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(est, f)
        os.utime(ruta, (time.time() + 5, time.time() + 5))
        self.assertEqual(self.ajax("/puntos/p001/espejo", {"accion": "aplicar", "plan": "ab" * 16})[0].status, 409)
        est["cola"]["en_curso"] = None
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(est, f)
        os.utime(ruta, (time.time() + 9, time.time() + 9))
        r, j, _dt = self.ajax("/puntos/p001/espejo", {"accion": "aplicar", "plan": "ab" * 16})
        self.assertIn("trabajo", j)


class _PanelEspejoReal(PanelP):
    """espejo_* REALES del núcleo, mikrotik_init real y el MikroTik simulado."""

    def _sustitutos(self):
        reales = {k: getattr(self.d, k) for k in ("espejo_plan", "espejo_aplicar", "espejo_pausar",
                                                  "espejo_retirar")}
        super()._sustitutos()
        for k, v in reales.items():
            setattr(self.d, k, v)
        import _mikrotik_simulado as sim
        self.router = sim.router_isp()
        self.d.mk_conectar = lambda dd, timeout=6: self.router.conexion()


class EspejoReal(_Base):
    Panel = _PanelEspejoReal

    def setUp(self):
        super().setUp()
        self.p.d.guardar_routers([{"id": "p001", "USER": "ids-api", "PASS": "clave-api", "ENABLED": "1"}])
        mi = sys.modules.get("mikrotik_init")
        if mi is None or not hasattr(mi, "_calcular"):     # otra prueba pudo dejar un sustituto
            sys.modules.pop("mikrotik_init", None)
            mi = importlib.import_module("mikrotik_init")
        self.mi = mi
        self.lecturas = 0
        real = mi._calcular

        def contar(*a, **k):
            self.lecturas += 1
            return real(*a, **k)
        mi._calcular = contar
        self.addCleanup(setattr, mi, "_calcular", real)

    def test_aplicar_lee_el_router_dos_veces_y_cuenta_ordenes(self):
        """Aplicar: antes 3 lecturas del router (la del panel en validar(), la de espejo_aplicar y
        la de mikrotik_init.aplicar); ahora 2, porque espejo_aplicar(huella=) ya revisa huella,
        bloqueos y accept. Por fetch, el avance llega a «orden i/N» y termina «Espejo aplicado»."""
        _r, j, _dt = self.ajax("/puntos/p001/espejo", {"accion": "plan"})
        f = self.fin(j["trabajo"])
        huella = re.search(r"name=plan value='([0-9a-f]{32})'", f["html"]).group(1)
        tok = re.search(RE_TOKEN, f["html"]).group(1)
        self.assertEqual(self.lecturas, 1)
        n0 = len(self.p.router.escrituras)
        _r, j, _dt = self.ajax("/puntos/p001/espejo", {"accion": "aplicar", "plan": huella, "op": tok})
        f = self.fin(j["trabajo"])
        self.assertTrue(f["ok"], f)
        self.assertEqual(f["titulo_fin"], "Espejo aplicado")
        self.assertEqual(self.lecturas, 3)                  # 1 del plan + 2 de aplicar
        self.assertEqual(len(self.p.router.escrituras) - n0, 6)
        nombres = [x["nombre"] for x in f["pasos"]]
        self.assertEqual(nombres[:4], ["conectar", "leer router", "verificar", "respaldo"])
        self.assertIn("export", nombres)
        self.assertRegex(nombres[-1], r"^orden [0-9]+/[0-9]+$")
        # aplicado: el plan siguiente está vacío y no ofrece Aplicar
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "plan"}, cookie=self.ana)
        self.assertNotIn("Aplicar este plan", r.texto)

    def test_plan_cambiado_se_ensena_con_su_huella_nueva(self):
        """Si el router cambió desde la vista previa, el núcleo no toca nada y lo que se enseña es el
        plan de ahora con SU huella (sin la lectura de más del panel)."""
        _r, j, _dt = self.ajax("/puntos/p001/espejo", {"accion": "plan"})
        f = self.fin(j["trabajo"])
        huella = re.search(r"name=plan value='([0-9a-f]{32})'", f["html"]).group(1)
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "aplicar", "plan": "cd" * 16}, cookie=self.ana)
        self.assertEqual(r.status, 409)
        self.assertIn("El plan cambio desde la vista previa", r.texto)
        self.assertIn("name=plan value='%s'" % huella, r.texto)
        self.assertEqual(self.lecturas, 2)


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
        self.assertIn("Prefijos cambiados en el Suricata", f["html"])
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
        self.assertIn("no conecto", j["mensaje"])
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
        d.aidb_ip_valida = lambda ip: (ip.startswith("198.51.100."), "no es una IP publica")  # RFC 5737
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
        """Se pidió el plan y se cerró la pestaña sin verlo: la ficha lo retoma (pjretomar) y, visto
        el resultado, ya no lo vuelve a enseñar."""
        _r, j, _dt = self.ajax("/puntos/p001/espejo", {"accion": "plan"})
        tid = j["trabajo"]
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
