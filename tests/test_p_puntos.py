"""Apartado Puntos (puntos_web.py): alta, avance, clave VPN una sola vez, espejo sin `accept`,
prefijos, API y baja (CONTRATO-F2 §5, §9, §10.2, OPERACION §2). Orquestador falso, sin red."""
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
from _dash_p import PanelP  # noqa: E402


class Puntos(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")

    def _token(self):
        r = self.p.pedir("GET", "/puntos/nuevo", cookie=self.ana)
        self.assertEqual(r.status, 200)
        return re.search(r"name=op value='([0-9a-f-]{36})'", r.texto).group(1)

    def _crear(self, token, nombre="este"):
        return self.p.pedir("POST", "/puntos/nuevo", {"op": token, "nombre": nombre}, cookie=self.ana)

    def test_alta_llama_punto_crear_y_redirige(self):
        """Capacidad nueva: el alta pide punto.crear con los datos del formulario y lleva al avance."""
        tok = self._token()
        r = self._crear(tok)
        self.assertEqual(r.status, 303)
        self.assertEqual(r.cab("Location"), "/operaciones/%s" % tok)
        pet = self.p.orq.ordenes("punto.crear")
        self.assertEqual(len(pet), 1)
        self.assertEqual(pet[0]["op_id"], tok)
        self.assertEqual(pet[0]["params"], {"nombre": "este", "perfil": "reducido", "ros_version": 6})
        self.assertEqual(pet[0]["quien"], "panel:ana")

    def test_alta_solo_pide_el_nombre(self):
        """Capacidad nueva (el user, 2026-10-15: «los prefijos no van, solo es nombre del punto»): el
        alta no pregunta prefijos, RouterOS ni perfil. Sin redes_abonados el orquestador pone las de por
        defecto; la VPN sale compatible con 6.49+ y 7 y el perfil es el reducido, aunque el POST traiga
        otra cosa."""
        r = self.p.pedir("GET", "/puntos/nuevo", cookie=self.ana)
        self.assertIn("name=nombre", r.texto)
        for campo in ("name=redes", "name=ros_version", "name=perfil"):
            self.assertNotIn(campo, r.texto)
        tok = re.search(r"name=op value='([0-9a-f-]{36})'", r.texto).group(1)
        self.p.pedir("POST", "/puntos/nuevo", {"op": tok, "nombre": "otro", "redes": "10.3.0.0/24",
                                               "ros_version": "7", "perfil": "completo"}, cookie=self.ana)
        self.assertEqual(self.p.orq.ordenes("punto.crear")[0]["params"],
                         {"nombre": "otro", "perfil": "reducido", "ros_version": 6})

    def test_la_lista_abre_el_alta_en_un_modal(self):
        """Capacidad nueva (el user, 2026-10-15: «crea un modal nomas para eso y solicita el nombre»):
        «Agregar punto» abre en la lista un modal con solo el nombre; sin JavaScript, el enlace sigue
        llevando a /puntos/nuevo. La lista no se recarga sola con el modal abierto."""
        h = self.p.pedir("GET", "/puntos", cookie=self.ana).texto
        self.assertIn("<a class=btn href='/puntos/nuevo' onclick='palta();return false;'>Agregar punto</a>", h)
        modal = h.split("<div id=paltaov", 1)[1].split("</form>", 1)[0]
        self.assertIn("action='/puntos/nuevo'", modal)
        self.assertIn("onsubmit='return paltaAjax(this)'", modal)
        self.assertRegex(modal, r"name=op value='[0-9a-f-]{36}'")
        self.assertIn("name=nombre", modal)
        for campo in ("name=redes", "name=ros_version", "name=perfil", "<textarea"):
            self.assertNotIn(campo, modal)
        self.assertIn("!abierto('paltaov')", h)

    def test_alta_desde_el_modal(self):
        """Capacidad nueva: con ajax=1 (el modal) el alta responde {op_id} para ir al avance, y un
        nombre malo, {error} para verlo dentro del modal, sin pedir nada al orquestador."""
        tok = self._token()
        r = self.p.pedir("POST", "/puntos/nuevo", {"op": tok, "nombre": "Mal Nombre", "ajax": "1"}, cookie=self.ana)
        self.assertEqual(r.status, 400)
        self.assertIn("minúsculas", json.loads(r.texto)["error"])
        self.assertEqual(self.p.orq.ordenes("punto.crear"), [])
        r = self.p.pedir("POST", "/puntos/nuevo", {"op": tok, "nombre": "norte", "ajax": "1"}, cookie=self.ana)
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.texto), {"op_id": tok})
        r = self.p.pedir("POST", "/puntos/nuevo", {"op": tok, "nombre": "norte", "ajax": "1"}, cookie=self.ana)
        self.assertEqual(json.loads(r.texto), {"op_id": tok})               # doble clic: la misma
        self.assertEqual(len(self.p.orq.ordenes("punto.crear")), 1)

    def test_doble_envio_no_crea_dos(self):
        """Capacidad nueva (idempotencia): el mismo formulario enviado dos veces es una sola orden."""
        tok = self._token()
        r1, r2 = self._crear(tok), self._crear(tok)
        self.assertEqual((r1.status, r2.status), (303, 303))
        self.assertEqual(r1.cab("Location"), r2.cab("Location"))
        self.assertEqual(len(self.p.orq.ordenes("punto.crear")), 1)

    def test_formulario_de_otro_usuario_no_se_reutiliza(self):
        """Correccion de defecto: el op_id de otro usuario no da acceso a su operacion (409/404)."""
        tok = self._token()
        self._crear(tok)
        otro_admin = self.p.d.cargar_usuarios()
        salt, h = self.p.d._hash_pw("clave-de-prueba-1")
        otro_admin.append({"user": "eva", "salt": salt, "hash": h, "role": "admin", "activo": True})
        self.p.d.guardar_usuarios(otro_admin)
        eva = self.p.entrar("eva")
        self.assertEqual(self.p.pedir("GET", "/operaciones/%s" % tok, cookie=eva).status, 404)
        r = self.p.pedir("POST", "/puntos/nuevo", {"op": tok, "nombre": "otro"}, cookie=eva)
        self.assertEqual(r.status, 409)
        self.assertEqual(len(self.p.orq.ordenes("punto.crear")), 1)

    def test_clave_vpn_solo_una_vez(self):
        """Capacidad nueva: al terminar se ven usuario, clave y comandos v7/v6; la segunda vez ya no."""
        tok = self._token()
        self._crear(tok)
        r = self.p.pedir("GET", "/operaciones/%s" % tok, cookie=self.ana)
        self.assertEqual(r.status, 200)
        self.assertIn("CLAVE-VPN-UNICA-7Q2", r.texto)
        # ros_version 6: conectan los dos bloques, el v7 primero y ninguno «declarado»
        self.assertIn("Ver el bloque de RouterOS 6", r.texto)
        self.assertNotIn("versión declarada", r.texto)
        r = self.p.pedir("GET", "/operaciones/%s" % tok, cookie=self.ana)
        self.assertEqual(r.status, 200)
        self.assertNotIn("CLAVE-VPN-UNICA-7Q2", r.texto)
        with open(os.path.join(self.p.nodos.ESTADO, "operaciones.json"), encoding="utf-8") as f:
            self.assertNotIn("CLAVE-VPN-UNICA-7Q2", f.read())

    def test_formulario_invalido_no_llama(self):
        """Conservacion: validacion del nombre antes de pedir nada al orquestador."""
        tok = self._token()
        for nombre in ("Mal Nombre", "", "a", "-norte", "x" * 32):
            r = self.p.pedir("POST", "/puntos/nuevo", {"op": tok, "nombre": nombre}, cookie=self.ana)
            self.assertEqual(r.status, 400, nombre)
        self.assertEqual(self.p.orq.ordenes("punto.crear"), [])

    def test_lista_y_ficha(self):
        """Capacidad nueva: la lista muestra salud por etapas y retencion efectiva; la ficha, sus
        apartados y los comandos sin clave."""
        with open(os.path.join(self.p.tmp.name, "datos", "p001", "eve.json"), "w", encoding="utf-8") as f:
            f.write('{"timestamp":"2026-10-01T10:00:00.000000+0000","event_type":"alert"}\n')
        r = self.p.pedir("GET", "/puntos", cookie=self.ana)
        self.assertEqual(r.status, 200)
        self.assertIn("operativa", r.texto)
        self.assertIn("desde <b>01/10/2026</b>", r.texto)
        r = self.p.pedir("GET", "/puntos/p001", cookie=self.ana)
        self.assertEqual(r.status, 200)
        for sec in ("id=resumen", "id=vpn", "id=api", "id=espejo", "id=prefijos", "id=baja"):
            self.assertIn(sec, r.texto)
        self.assertIn("&lt;CLAVE-VPN&gt;", r.texto)
        self.assertIn("reducido · RouterOS 7", r.texto)
        self.assertIn("reducido · RouterOS 6.49+ o 7", self.p.pedir("GET", "/puntos/p002", cookie=self.ana).texto)
        self.assertEqual(self.p.pedir("GET", "/puntos/p009", cookie=self.ana).status, 404)


class BotonEnlace(unittest.TestCase):
    def test_el_texto_del_boton_no_desaparece_al_pasar_el_raton(self):
        """Correccion de defecto (2026-10-14): «Agregar punto» es un <a class=btn> y el
        `a:hover{color:var(--brand-ink)}` comun pesa mas que `.btn{color:#fff}`: al pasar el raton el
        texto quedaba azul sobre el fondo azul. Cada :hover de .btn fija su color."""
        p = PanelP()
        self.addCleanup(p.cerrar)
        h = p.pedir("GET", "/puntos", cookie=p.entrar("ana")).texto
        self.assertIn("<a class=btn href='/puntos/nuevo' onclick='palta();return false;'>Agregar punto</a>", h)
        self.assertRegex(h, r"a:hover\{color:var\(--brand-ink\)\}")       # la regla que lo provocaba
        for sel, color in ((r"\.btn:hover", "#fff"), (r"\.btn\.sec:hover", "#33322f"),
                           (r"\.btn\.peligro:hover", "#fff")):
            self.assertRegex(h, sel + r"\{[^}]*(?<![-\w])color:" + color)

    def test_desde_puntos_se_vuelve_a_ajustes(self):
        """Correccion de defecto (2026-10-14, «puntos cuando ingreso no tiene para regresar a
        ajustes»; 2026-10-15, la ruta «← Ajustes / Puntos» de arriba «no debe estar asi» y «en la
        ventana Puntos falta el boton de regresar a Ajustes»): sin ruta arriba en ninguna pagina; la
        lista lleva el boton «Volver a Ajustes» y la ficha y el alta, «Volver a Puntos»."""
        p = PanelP()
        self.addCleanup(p.cerrar)
        ana = p.entrar("ana")
        lista = p.pedir("GET", "/puntos", cookie=ana).texto
        self.assertIn("<div class=ptbtns><a class='btn sec' href='/ajustes'>Volver a Ajustes</a>"
                      "<a class=btn href='/puntos/nuevo' onclick='palta();return false;'>Agregar punto</a></div>",
                      lista)
        for ruta, h in (("/puntos", lista), ("/puntos/p001", p.pedir("GET", "/puntos/p001", cookie=ana).texto),
                        ("/puntos/nuevo", p.pedir("GET", "/puntos/nuevo", cookie=ana).texto)):
            self.assertNotIn("class=migas", h, ruta)
            self.assertNotIn("&larr; Ajustes", h, ruta)
            if ruta != "/puntos":
                self.assertIn("<a class='btn sec' href='/puntos'>Volver a Puntos</a>", h, ruta)

    def test_los_botones_no_palpitan_al_pasar_el_raton(self):
        """Correccion de defecto (2026-10-14, «estos botones como que palpitan»): el :hover de .btn y
        .btn.peligro cambiaba el degradado por un color plano oscuro de golpe (un degradado no se
        anima) y al recorrer la lista de Puntos cada boton parpadeaba. El :hover ya no toca el fondo."""
        p = PanelP()
        self.addCleanup(p.cerrar)
        h = p.pedir("GET", "/puntos", cookie=p.entrar("ana")).texto
        for sel in (r"\.btn:hover", r"\.btn\.peligro:hover"):
            for regla in re.findall(sel + r"\{([^}]*)\}", h):
                self.assertNotRegex(regla, r"(?<![-\w])background", sel)


class Espejo(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")

    def _post(self, form):
        return self.p.pedir("POST", "/puntos/p001/espejo", form, cookie=self.ana)

    def test_aplicar_exige_el_plan_visto(self):
        """Capacidad nueva: aplicar solo con la huella del plan que se vio; si cambio, no se aplica."""
        r = self._post({"accion": "plan"})
        huella = re.search(r"name=plan value='([0-9a-f]{32})'", r.texto).group(1)
        self.assertNotIn(("aplicar", "p001"), self.p.espejo)
        self.p.plan.append("/ip firewall mangle add chain=forward comment=otra")
        self.assertEqual(self._post({"accion": "aplicar", "plan": huella}).status, 409)
        self.assertNotIn(("aplicar", "p001"), self.p.espejo)
        r = self._post({"accion": "plan"})
        huella = re.search(r"name=plan value='([0-9a-f]{32})'", r.texto).group(1)
        self.assertEqual(self._post({"accion": "aplicar", "plan": huella}).status, 200)
        self.assertEqual(self.p.espejo.count(("aplicar", "p001")), 1)

    def test_plan_con_accept_nunca_se_aplica(self):
        """Correccion de defecto (OPERACION §2): un plan con action=accept no se aplica ni se ofrece."""
        self.p.plan.append("/ip firewall filter add chain=forward action=accept connection-bytes=0-10000")
        r = self._post({"accion": "plan"})
        self.assertEqual(r.status, 500)
        self.assertNotIn("name=plan value=", r.texto)
        import hashlib
        h = hashlib.sha256("\n".join(self.p.plan).encode()).hexdigest()[:32]
        self.assertEqual(self._post({"accion": "aplicar", "plan": h}).status, 500)
        self.assertNotIn(("aplicar", "p001"), self.p.espejo)

    def test_pausar_y_retirar(self):
        """Capacidad nueva: pausar y retirar van al espejo del punto de la ruta."""
        self._post({"accion": "pausar"})
        self.p.pedir("POST", "/puntos/p002/espejo", {"accion": "retirar"}, cookie=self.ana)
        self.assertEqual(self.p.espejo, [("pausar", "p001"), ("retirar", "p002")])


class OrdenesDelPunto(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")

    def test_prefijos_con_punto_ajustar(self):
        """Capacidad nueva (§9): los prefijos se cambian con punto.ajustar {redes_abonados}."""
        r = self.p.pedir("POST", "/puntos/p001/ajustar", {"redes": "10.5.0.0/24, 10.6.0.0/24"}, cookie=self.ana)
        self.assertEqual(r.status, 303)
        pet = self.p.orq.ordenes("punto.ajustar")
        self.assertEqual(pet[0]["params"], {"pid": "p001", "redes_abonados": ["10.5.0.0/24", "10.6.0.0/24"]})
        r = self.p.pedir("GET", r.cab("Location"), cookie=self.ana)
        self.assertIn("/puntos/p001#espejo", r.texto)

    def test_baja_exige_el_nombre(self):
        """Conservacion: la baja pide escribir el nombre; con el nombre pide punto.borrar."""
        self.assertEqual(self.p.pedir("POST", "/puntos/p001/borrar", {"confirmar": "sur"}, cookie=self.ana).status, 400)
        self.assertEqual(self.p.orq.ordenes("punto.borrar"), [])
        r = self.p.pedir("POST", "/puntos/p001/borrar", {"confirmar": "norte"}, cookie=self.ana)
        self.assertEqual(r.status, 303)
        self.assertEqual(self.p.orq.ordenes("punto.borrar")[0]["params"], {"pid": "p001", "confirmar": "norte"})

    def test_baja_limpia_lo_del_panel(self):
        """Capacidad nueva (§5): al terminar la baja se borran nodos/<pid>/ y sus enviados pid|...,
        sin tocar los del otro punto."""
        d = os.path.join(self.p.nodos.NODOS, "p001")
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "cuarentena.json"), "w").close()
        reg = self.p.d.MK_SENT
        self.p.d.guardar_enviados({"p001|10.0.0.5": {"cuando": 1}, "p002|10.0.0.5": {"cuando": 1}}, reg)
        r = self.p.pedir("POST", "/puntos/p001/borrar", {"confirmar": "norte"}, cookie=self.ana)
        self.p.pedir("GET", r.cab("Location"), cookie=self.ana)
        self.assertFalse(os.path.exists(d))
        self.assertEqual(list(self.p.d.cargar_enviados(reg)), ["p002|10.0.0.5"])

    def test_arrancar_parar_reiniciar_regenerar(self):
        """Capacidad nueva: cada boton es su orden de cola, con el pid de la ruta."""
        for acc, orden in (("arrancar", "punto.arrancar"), ("parar", "punto.parar"),
                           ("reiniciar", "punto.reiniciar"), ("regenerar", "punto.vpn.regenerar")):
            r = self.p.pedir("POST", "/puntos/p002/%s" % acc, {}, cookie=self.ana)
            self.assertEqual(r.status, 303, acc)
            self.assertEqual(self.p.orq.ordenes(orden)[-1]["params"], {"pid": "p002"})
        self.assertEqual(self.p.pedir("POST", "/puntos/p009/parar", {}, cookie=self.ana).status, 404)

    def test_api_guarda_en_el_router_del_punto(self):
        """Capacidad nueva: usuario y clave de la API van al router de ESE punto, no a otro."""
        self.p.pedir("POST", "/puntos/p002/api", {"accion": "guardar", "user": "ids-api", "pass": "otra-clave",
                                                  "enabled": "1"}, cookie=self.ana)
        rs = {r["id"]: r for r in self.p.d.cargar_routers()}
        self.assertEqual(rs["p002"]["PASS"], "otra-clave")
        self.assertNotEqual(rs["p001"].get("PASS"), "otra-clave")


if __name__ == "__main__":
    unittest.main()
