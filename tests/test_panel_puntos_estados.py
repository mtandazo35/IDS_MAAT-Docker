"""Apartado A de Puntos, lo que ve el panel (puntos_web.py y salud_punto de dashboard.py):

- D4: estados visibles. Tras un alta correcta el punto no sale en rojo: VPN sana sin MikroTik =
  ámbar «esperando MikroTik» con las etapas del MikroTik «pendiente»; creando = gris; VPN caída o
  enferma (salud, no solo running) o el punto en error = rojo con su motivo. `vpn_cliente.viejo`
  no es «conectado».
- D3: un punto en error dice su motivo (`paso_error`, escapado) y desde cuándo (`error_desde`), y
  la ficha trae «Reintentar arranque» (punto.arrancar por el camino de siempre).
- D2: la página de una operación que terminó mal enseña su `log_tail` (escapado y sin claves).
- D8: un alta (o regenerar) terminada OK cuya clave no llegó al panel lo dice y ofrece regenerarla,
  también en las visitas siguientes; si la clave sí se mostró, la visita siguiente no dice que no llegó.
- P4: la ficha no pide la huella del API (hasta 15 s por el túnel) si el MikroTik no está conectado.

Tipo «corrección de defecto»: cada prueba falla sin el arreglo, salvo las dos marcadas «conservación». Panel de verdad sobre un directorio
temporal y orquestador falso (fixtures/panel2/_dash_p.py), sin red.
"""
import json
import os
import re
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
from _dash_p import PanelP  # noqa: E402

RE_TOKEN = r"name=op value='([0-9a-f-]{36})'"


class _Base(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")

    def cambiar(self, pid, **campos):
        """Cambia campos de un punto en estado.json (como lo publicaría el orquestador)."""
        ruta = os.path.join(self.p.tmp.name, "run", "estado.json")
        with open(ruta, encoding="utf-8") as f:
            est = json.load(f)
        est["puntos"][pid].update(campos)
        est["ts"] = int(time.time())
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(est, f)
        t = time.time() + len(json.dumps(campos))          # otra marca: nodos.leer_estado relee
        os.utime(ruta, (t, t))

    def get(self, ruta):
        r = self.p.pedir("GET", ruta, cookie=self.ana)
        self.assertEqual(r.status, 200, r.texto[:400])
        return r.texto

    def fila(self, texto, pid):
        m = re.search(r"<tr><td><a href='/puntos/%s'>.*?</tr>" % pid, texto, re.S)
        self.assertIsNotNone(m, pid)
        return m.group(0)


# --------------------------------------------------------------------------------------------
# D4: estados visibles
# --------------------------------------------------------------------------------------------
class Estados(_Base):
    def test_vpn_sana_sin_mikrotik_es_ambar_y_no_rojo(self):
        """p002: contenedores sanos y el MikroTik aún sin conectar (lo normal tras el alta). Antes:
        rojo «desconectada» y 4 de 5 etapas en «fallo». Ahora: ámbar «esperando MikroTik», las
        etapas del MikroTik «pendiente» y ninguna en fallo; en la lista, pill ámbar y no «caída»."""
        s = self.p.d.salud_punto("p002")
        self.assertEqual(s["estado"], "esperando")
        por = {e["id"]: e["estado"] for e in s["etapas"]}
        self.assertEqual(por, {"vpn": "pendiente", "tzsp": "pendiente", "suricata": "pendiente",
                               "eventos": "pendiente", "datos": por["datos"]})
        self.assertNotIn("fallo", por.values())
        fila = self.fila(self.get("/puntos"), "p002")
        self.assertIn("esperando MikroTik", fila)
        self.assertIn("class='vpill amb'", fila)
        self.assertNotIn("desconectad", fila)
        self.assertNotIn("tw-bg-red-50", fila)
        self.assertNotIn(self.p.pw.SALUD_COLOR["desconectada"], fila)
        # el selector de nodo de la barra usa la misma salud
        sel = re.search(r"class=nodosel>.*?</form>", self.get("/cuarentena?nodo=p002"), re.S).group(0)
        self.assertIn("sur (p002) &middot; esperando MikroTik", sel)
        self.assertIn("background:%s" % self.p.pw.SALUD_COLOR["esperando"], sel)

    def test_creando_es_gris(self):
        """Mientras el orquestador crea el punto (sin contenedores aún): gris «creando…», no rojo."""
        self.cambiar("p002", estado="creando", contenedores={"vpn": {"estado": "ausente", "salud": "none"},
                                                             "suricata": {"estado": "ausente", "salud": "none"}})
        s = self.p.d.salud_punto("p002")
        self.assertEqual(s["estado"], "creando")
        self.assertNotIn("fallo", {e["estado"] for e in s["etapas"]})
        self.assertEqual(s["etapas_por_id"]["vpn"]["estado"], "pendiente")
        fila = self.fila(self.get("/puntos"), "p002")
        self.assertIn("creando…", fila)
        self.assertIn("class='vpill gris'", fila)
        self.assertNotIn("tw-bg-red-50", fila)

    def test_vpn_enferma_o_caida_es_rojo_con_motivo(self):
        """Manda `salud`, no solo `running`: un vpn running/unhealthy es una VPN caída (antes contaba
        como viva). Y un vpn exited también; los dos en rojo con el motivo."""
        self.cambiar("p001", contenedores={"vpn": {"estado": "running", "salud": "unhealthy"},
                                           "suricata": {"estado": "running", "salud": "healthy"}})
        s = self.p.d.salud_punto("p001")
        self.assertEqual(s["estado"], "desconectada")
        self.assertIn("unhealthy", s["motivo"])
        self.assertEqual(s["etapas_por_id"]["vpn"]["estado"], "fallo")
        fila = self.fila(self.get("/puntos"), "p001")
        self.assertIn("tw-bg-red-50", fila)
        self.assertIn("caída", fila)
        self.cambiar("p002", contenedores={"vpn": {"estado": "exited", "salud": "none"},
                                           "suricata": {"estado": "running", "salud": "healthy"}})
        self.assertEqual(self.p.d.salud_punto("p002")["estado"], "desconectada")

    def test_estado_viejo_no_es_mikrotik_conectado(self):
        """`vpn_cliente.viejo`: el openvpn-status.log no se actualiza. Aunque diga conectado, ni la
        salud ni la ficha dan el MikroTik por conectado."""
        self.cambiar("p001", vpn_cliente={"conectado": True, "viejo": True, "ip_real": "198.51.100.7",
                                          "desde": int(time.time()) - 600})
        self.assertNotEqual(self.p.d.salud_punto("p001")["etapas_por_id"]["vpn"]["estado"], "ok")
        h = self.get("/puntos/p001")
        self.assertNotIn("conectado desde", h)
        self.assertIn("dato de la VPN viejo", h)


# --------------------------------------------------------------------------------------------
# D3: motivo del error y Reintentar
# --------------------------------------------------------------------------------------------
class Error(_Base):
    MOTIVO = "esperar salud: suricata=running/starting tras 300 s <b>x</b>"

    def setUp(self):
        super().setUp()
        self.desde = int(time.time()) - 7200
        self.cambiar("p001", estado="error", paso_error=self.MOTIVO, error_desde=self.desde)

    def test_lista_y_ficha_dicen_el_motivo_y_desde_cuando(self):
        """Antes: «con error» sin motivo. Ahora el paso_error (escapado) y desde cuándo."""
        self.assertEqual(self.p.d.salud_punto("p001")["estado"], "error")
        esc = "esperar salud: suricata=running/starting tras 300 s &lt;b&gt;x&lt;/b&gt;"
        hora = time.strftime("%d/%m/%Y %H:%M", time.localtime(self.desde))
        fila = self.fila(self.get("/puntos"), "p001")
        self.assertIn(esc, fila)
        self.assertIn("desde hace 2 h (%s)" % hora, fila)
        self.assertNotIn("<b>x</b>", fila)
        h = self.get("/puntos/p001")
        self.assertIn("El punto está con error.", h)
        self.assertIn(esc, h)
        self.assertNotIn("<b>x</b>", h)

    def test_reintentar_encola_punto_arrancar(self):
        """La ficha (admin) trae «Reintentar arranque»: encola punto.arrancar con el token del
        formulario como op_id y lleva a la página de la operación, como el botón Arrancar."""
        h = self.get("/puntos/p001")
        m = re.search(r"<form method=post action='/puntos/p001/arrancar' onsubmit=\"return ask\(this,"
                      r"'Reintentar arranque'[^>]*><input type=hidden " + RE_TOKEN + r"><button class=btn type=submit>"
                      r"Reintentar arranque</button></form>", h)
        self.assertIsNotNone(m)
        tok = m.group(1)
        r = self.p.pedir("POST", "/puntos/p001/arrancar", {"op": tok}, cookie=self.ana)
        self.assertEqual(r.status, 303)
        self.assertEqual(r.cab("Location"), "/operaciones/%s" % tok)
        pet = self.p.orq.ordenes("punto.arrancar")
        self.assertEqual([(x["op_id"], x["params"]) for x in pet], [(tok, {"pid": "p001"})])
        # un punto sano no lo trae
        self.assertNotIn("Reintentar arranque", self.get("/puntos/p002"))

    def test_operador_no_ve_la_ficha(self):
        """Conservación. Reintentar es solo de admin: el resto de roles no llega a la ficha ni al POST."""
        olga = self.p.entrar("olga")
        self.assertEqual(self.p.pedir("GET", "/puntos/p001", cookie=olga).status, 403)
        self.assertEqual(self.p.pedir("POST", "/puntos/p001/arrancar", {}, cookie=olga).status, 403)
        self.assertEqual(self.p.orq.ordenes("punto.arrancar"), [])


# --------------------------------------------------------------------------------------------
# D2 y D8: la página de la operación
# --------------------------------------------------------------------------------------------
class Operacion(_Base):
    def responder(self, datos):
        """El orquestador falso contesta op.estado con `datos` (terminada) para cualquier op."""
        real = self.p.orq

        def transporte(pet):
            if pet["orden"] == "op.estado":
                real.pedidas.append(pet)
                return {"op_id": pet["op_id"], "ok": True, "codigo": "OK", "mensaje": "",
                        "datos": dict({"estado": "terminada", "avance": "3/9",
                                       "pasos": [{"nombre": "validar", "estado": "ok"}]}, **datos)}
            return real(pet)
        self.p.pw.TRANSPORTE = transporte

    def encolar(self, accion, pid="p001"):
        tok = re.search(r"action='/puntos/%s/%s'[^>]*>(?:(?!</form>).)*?%s" % (pid, accion, RE_TOKEN),
                        self.get("/puntos/%s" % pid), re.S).group(1)
        r = self.p.pedir("POST", "/puntos/%s/%s" % (pid, accion), {"op": tok}, cookie=self.ana)
        self.assertEqual(r.status, 303)
        return r.cab("Location")

    def test_fallo_muestra_los_ultimos_logs_escapados_y_sin_claves(self):
        """D2: terminó mal y el orquestador mandó log_tail: se ve plegado en «Ver los últimos logs»,
        escapado y sin las líneas con claves; también al volver a abrir la operación."""
        url = self.encolar("reiniciar")
        self.responder({"codigo": "REVERTIDA", "mensaje": "falló «esperar salud»: tras 300 s; deshecho",
                        "log_tail": ["[vpn] Initialization Sequence Completed",
                                     "[suricata] <script>alert(1)</script>",
                                     "[vpn] auth password=SECRETO-1",
                                     "[suricata] private key SECRETO-2"]})
        for vez in (1, 2):
            h = self.get(url)
            self.assertIn("<details class=plogs><summary>Ver los últimos logs</summary><pre class=cmd>", h, vez)
            self.assertIn("[vpn] Initialization Sequence Completed", h)
            self.assertIn("[suricata] &lt;script&gt;alert(1)&lt;/script&gt;", h)
            self.assertNotIn("<script>alert(1)", h)
            self.assertNotIn("SECRETO", h)

    def test_ok_sin_logs_desplegables(self):
        """Conservación. Una operación que terminó bien no despliega logs."""
        url = self.encolar("reiniciar")
        self.responder({"codigo": "OK", "mensaje": "hecho", "log_tail": ["[vpn] algo"],
                        "resultado": {"pid": "p001"}})
        self.assertNotIn("Ver los últimos logs", self.get(url))

    def _crear(self):
        tok = re.search(RE_TOKEN, self.get("/puntos/nuevo")).group(1)
        r = self.p.pedir("POST", "/puntos/nuevo", {"op": tok, "nombre": "este", "redes": "10.1.0.0/24",
                                                   "ros_version": "7", "perfil": "reducido"}, cookie=self.ana)
        self.assertEqual(r.status, 303)
        return r.cab("Location")

    def test_clave_que_no_llego_lo_dice_y_ofrece_regenerar(self):
        """D8: alta OK sin clave ni «ya entregada» (el orquestador se reinició y perdió la clave de su
        memoria). Antes: «Si mostraba una clave, ya se enseñó una vez» (falso). Ahora lo dice y trae
        el botón de regenerar del punto; también en la visita siguiente y con el panel reiniciado."""
        url = self._crear()
        self.responder({"codigo": "OK", "mensaje": "ok",
                        "resultado": {"pid": "p003", "usuario": "ids-p003", "comandos": "# x"}})
        for vez in (1, 2, 3):
            if vez == 3:
                self.p.pw._OPS.clear()                    # panel reiniciado: se relee operaciones.json
            h = self.get(url)
            self.assertIn("La clave no llegó al panel", h, vez)
            self.assertNotIn("ya se enseñó", h)
            self.assertRegex(h, r"<form method=post action='/puntos/p003/regenerar' onsubmit=\"return ask\("
                                r"this,'Regenerar la clave VPN'[^>]*><input type=hidden " + RE_TOKEN)
        with open(os.path.join(self.p.nodos.ESTADO, "operaciones.json"), encoding="utf-8") as f:
            self.assertIn('"entrega_clave": "no_llego"', f.read())

    def test_clave_mostrada_no_dice_que_no_llego(self):
        """La clave llegó y se mostró: la visita siguiente dice que ya se mostró, no que no llegó."""
        url = self._crear()
        self.assertIn("CLAVE-VPN-UNICA-7Q2", self.get(url))
        h = self.get(url)
        self.assertNotIn("CLAVE-VPN-UNICA-7Q2", h)
        self.assertNotIn("La clave no llegó", h)
        self.assertIn("La clave ya se mostró una vez", h)
        with open(os.path.join(self.p.nodos.ESTADO, "operaciones.json"), encoding="utf-8") as f:
            texto = f.read()
        self.assertNotIn("CLAVE-VPN-UNICA-7Q2", texto)
        self.assertIn('"entrega_clave": "mostrada"', texto)

    def test_regenerar_sin_clave_tambien(self):
        """punto.vpn.regenerar terminado OK sin clave: el mismo aviso."""
        url = self.encolar("regenerar")
        self.responder({"codigo": "OK", "mensaje": "credencial regenerada", "resultado": {"pid": "p001"}})
        self.assertIn("La clave no llegó al panel", self.get(url))


# --------------------------------------------------------------------------------------------
# P4: la ficha no espera la huella con el MikroTik sin conectar
# --------------------------------------------------------------------------------------------
class Huella(_Base):
    def test_sin_mikrotik_no_pide_la_huella(self):
        """p002 (MikroTik sin conectar): la ficha no pide punto.api.huella y dice cuándo se hará.
        p001 (conectado): desde el apartado B tampoco la espera la ficha: la pinta «comprobando…» y
        la pide por fetch (GET /puntos/p001/huella), que la guarda 10 min; la ficha siguiente ya la
        trae sin preguntar otra vez (tests/test_panel_puntos_fondo.py, Ficha)."""
        h = self.get("/puntos/p002")
        self.assertEqual([x for x in self.p.orq.ordenes("punto.api.huella")], [])
        self.assertIn("se comprobará cuando el MikroTik conecte", h)
        h = self.get("/puntos/p001")
        self.assertEqual(self.p.orq.ordenes("punto.api.huella"), [])
        self.assertIn("<code id=phuella data-pid='p001'>comprobando…</code>", h)
        self.assertEqual(json.loads(self.get("/puntos/p001/huella")), {"texto": "ab" * 32})
        self.assertIn("<code>%s</code>" % ("ab" * 32), self.get("/puntos/p001"))
        pet = self.p.orq.ordenes("punto.api.huella")
        self.assertEqual([x["params"] for x in pet], [{"pid": "p001"}])


if __name__ == "__main__":
    unittest.main()
