"""F1 (correcciones de la auditoria): espejo, servidor web, usuarios y tareas de fondo.

Correccion de defecto (CONTRATO-F2 §10.5): cada prueba reproduce un hallazgo (falla con el
dashboard de b9dcd02) y demuestra la correccion. El espejo usa el `mikrotik_init` REAL contra
el MikroTik simulado: nada de dobles que devuelvan `lineas` (auditoria A-01).
"""
import contextlib
import hashlib
import html
import io
import json
import os
import re
import socket
import sys
import threading
import time
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
from test_f1_cuarentena import Panel, IP, K1  # noqa: E402
import _mikrotik_simulado as sim  # noqa: E402


class Base(unittest.TestCase):
    HTTP = False

    def setUp(self):
        self.p = Panel(http=self.HTTP)
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d


# --------------------------------------------------------------------------------------------
class Espejo(Base):
    """A-01 y A-08: vista previa, huella y aplicar con el plan REAL de mikrotik_init."""

    def setUp(self):
        super().setUp()
        self.r = sim.router_isp()
        self.p.routers["p001"] = self.r

    def _mangles(self):
        return [f for f in self.r.tablas["/ip/firewall/mangle"] if "ids-maat:p001" in f.get("comment", "")]

    def test_vista_previa_con_las_ordenes_reales(self):
        """Correccion de defecto (A-01, espejo/r01): el plan real trae `terminal`, no `lineas`;
        la vista previa salia vacia, sin boton y con la huella de sha256("")."""
        import mikrotik_init
        v = self.d.espejo_plan("p001")
        self.assertTrue(v["ok"], v)
        self.assertGreater(len(v["lineas"]), 0)
        conex = self.r.conexion()
        real = mikrotik_init.plan(conex, "p001", "100.64.1.1", 37008, ["10.0.0.0/24"], "ids-vigilados")
        self.assertEqual(v["lineas"], real["terminal"])
        self.assertEqual(v["huella"], hashlib.sha256("\n".join(real["terminal"]).encode()).hexdigest()[:32])
        self.assertNotEqual(v["huella"], hashlib.sha256(b"").hexdigest()[:32])
        self.assertIn("bloqueos", v)
        self.assertEqual(self.r.escrituras, [])          # la vista previa no toca el router

    def test_aplicar_exige_la_huella_del_plan_mostrado(self):
        """Correccion de defecto (A-01, espejo/r02): se aplicaba sin huella o con la de un plan
        vacio. Ahora sin huella, con la vacia o con otra NO se escribe nada; con la del plan
        mostrado se aplica exactamente ese plan."""
        v = self.d.espejo_plan("p001")
        for mala in (None, "", hashlib.sha256(b"").hexdigest()[:32], "0" * 32):
            r = self.d.espejo_aplicar("p001", "ana", huella=mala)
            self.assertFalse(r["ok"], (mala, r))
        self.assertEqual(self.r.escrituras, [])
        r = self.d.espejo_aplicar("p001", "ana", huella=v["huella"])
        self.assertTrue(r["ok"], r)
        self.assertEqual(len(self.r.escrituras), len(v["lineas"]))
        # la huella del formulario de la peticion (campo `plan`) vale igual que el parametro
        self.d.CTX.form = {"plan": "f" * 32}
        self.assertFalse(self.d.espejo_aplicar("p001")["ok"])
        self.d.CTX.form = None

    def test_un_plan_con_accept_o_vacio_no_se_aplica(self):
        """Correccion de defecto (A-01): la comprobacion «sin accept» miraba una lista vacia."""
        import mikrotik_init
        orig = mikrotik_init.plan

        def con_accept(*a, **k):
            p = orig(*a, **k)
            p["terminal"] = p["terminal"] + ["/ip firewall filter add chain=forward action=accept"]
            p["cambios"] = p["cambios"] + [{"que": "x", "orden": "/ip/firewall/filter/add",
                                            "args": ["=chain=forward", "=action=accept"]}]
            return p
        mikrotik_init.plan = con_accept
        try:
            v = self.d.espejo_plan("p001")
            self.assertFalse(v["ok"])
            self.assertIn("accept", v["mensaje"])
            self.assertEqual(v["huella"], "")
            r = self.d.espejo_aplicar("p001", huella=self.d.espejo_huella(v["lineas"]))
            self.assertFalse(r["ok"])
        finally:
            mikrotik_init.plan = orig
        self.assertEqual(self.r.escrituras, [])
        v = self.d.espejo_plan("p001")
        self.assertTrue(self.d.espejo_aplicar("p001", huella=v["huella"])["ok"])
        v2 = self.d.espejo_plan("p001")                     # ya aplicado: plan vacio
        self.assertEqual((v2["lineas"], v2["huella"], v2["aplicable"]), ([], "", False))

    def test_doble_clic_no_duplica_el_espejo(self):
        """Correccion de defecto (A-08, dest/r4): dos «Aplicar» a la vez con la misma vista
        previa dejaban el espejo duplicado. Ahora uno aplica y el otro ve que el plan cambio."""
        import mikrotik_init
        v = self.d.espejo_plan("p001")
        orig = mikrotik_init.plan

        def lento(*a, **k):
            p = orig(*a, **k)
            time.sleep(0.3)               # la ventana de la VPN entre planificar y aplicar
            return p
        mikrotik_init.plan = lento
        res = []
        try:
            hilos = [threading.Thread(target=lambda: res.append(self.d.espejo_aplicar("p001", huella=v["huella"])))
                     for _ in range(2)]
            for t in hilos:
                t.start()
            for t in hilos:
                t.join(30)
        finally:
            mikrotik_init.plan = orig
        self.assertEqual(sorted(r["ok"] for r in res), [False, True], res)
        self.assertEqual(len([f for f in self._mangles() if f.get("action") == "sniff-tzsp"]), 2)


# --------------------------------------------------------------------------------------------
class Web(Base):
    HTTP = True

    def test_enlaces_formularios_y_redirecciones_llevan_el_nodo(self):
        """Correccion de defecto (A-11, ctx/r3 a): la pestana A (p001) envia mientras la B puso
        la sesion en p002; antes volvia mirando p002. Ahora cada enlace y formulario de la
        pagina y la redireccion llevan el nodo de la pagina."""
        st, _c, txt = self.p.pedir("GET", "/cuarentena?nodo=p001", quien="olga")
        self.assertEqual(st, 200)
        posts = re.findall(r"<form[^>]*method=post[^>]*action=['\"]?(/[^'\" >]*)", txt, re.I)
        self.assertTrue(posts)
        self.assertTrue(all("nodo=p001" in a for a in posts), posts)
        hrefs = [h for h in re.findall(r"href=['\"]?(/[^'\" >]*)", txt)
                 if not h.startswith(("/logo", "/favicon", "/mi-foto", "/login", "/logout", "/mapa/", "/vendor/",
                                      "/puntos", "/ajustes", "/log", "/bitacora", "/documentacion"))]
        self.assertTrue(hrefs)
        self.assertTrue(all("nodo=" in h for h in hrefs), [h for h in hrefs if "nodo=" not in h])
        self.p.pedir("GET", "/cuarentena?nodo=p002", quien="olga")          # la otra pestana
        st, cab, _t = self.p.pedir("POST", "/cuarentena/enviar?nodo=p001", {"ip": K1, "score": "9"}, "olga")
        self.assertEqual(st, 303)
        self.assertIn("nodo=p001", cab["Location"])
        st, _c, _t = self.p.pedir("POST", "/cuarentena/enviar-todos?nodo=p001", {"x": "1"}, "olga")
        self.assertEqual(st, 400)                                           # sin el nodo de la lista

    def test_cabeceras_de_seguridad(self):
        """Correccion de defecto (B-11): las paginas salen sin cache y sin dejarse enmarcar."""
        st, cab, _t = self.p.pedir("GET", "/cuarentena?nodo=p001")
        self.assertEqual(cab.get("Cache-Control"), "no-store")
        self.assertEqual(cab.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(cab.get("X-Content-Type-Options"), "nosniff")
        self.assertNotIn("suricata", cab.get("Server", "").lower())         # B-23

    def test_cuerpo_enorme_se_rechaza_sin_leerlo(self):
        """Correccion de defecto (B-15): el cuerpo se leia entero antes de comprobar nada. Ahora
        un Content-Length de 50 MB da 413 al momento (sin esperar el cuerpo) y sin sesion ni
        se mira: a /login."""
        for quien, esperado in (("olga", 413), (None, 303)):
            s = socket.create_connection(("127.0.0.1", self.p.srv.server_address[1]), timeout=5)
            try:
                cab = "POST /cuarentena/enviar HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 50000000\r\n"
                if quien:
                    cab += "Cookie: %s\r\n" % self.p.cookies[quien]
                s.sendall((cab + "Content-Type: application/x-www-form-urlencoded\r\n\r\nip=").encode())
                linea = s.recv(200).decode("latin-1").split("\r\n", 1)[0]
            finally:
                s.close()
            self.assertIn(" %d " % esperado, linea + " ")

    def test_usuario_con_comilla_no_rompe_el_js(self):
        """Correccion de defecto (B-17, repro/usuario_js): el alta web admitia `x');y();//` y el
        nombre acababa dentro de la cadena JS del modal «Eliminar usuario»."""
        st, _c, txt = self.p.pedir("POST", "/perfil", {"accion": "add_user", "nuser": "x');y();//",
                                                       "npass": "clave-larga-1", "nrole": "lectura"})
        self.assertIn("Usuario inválido", txt)
        self.assertNotIn("x');y();//", json.dumps(self.d.cargar_usuarios()))
        us = self.d.cargar_usuarios()                    # uno heredado con comilla (edicion a mano)
        salt, h = self.d._hash_pw("otra-clave-1")
        us.append({"user": "x'y", "salt": salt, "hash": h, "role": "lectura", "activo": True})
        self.d.guardar_usuarios(us)
        st, _c, txt = self.p.pedir("GET", "/ajustes")
        attrs = [html.unescape(a) for a in re.findall(r'onsubmit="([^"]*Eliminar usuario[^"]*)"', txt)]
        js = next(a for a in attrs if "x'y" in a)
        self.assertIn('"x\'y dejar\\u00e1 de poder entrar', js)               # cadena JS entre comillas dobles
        self.assertNotIn("'x'y", js)

    def test_roles_segun_la_precision_del_contrato(self):
        """Correccion de defecto (B-18): lectura ve la ficha de evidencia; revisar publicas es de
        admin; lectura no ve los botones que el servidor le rechaza."""
        st, _c, _t = self.p.pedir("GET", "/cuarentena/ficha?ip=" + K1 + "&nodo=p001", quien="luis")
        self.assertEqual(st, 200)
        st, _c, _t = self.p.pedir("POST", "/publicas/revisar?nodo=p001", {"rid": "p001"}, "olga")
        self.assertEqual(st, 403)
        _s, _c, txt = self.p.pedir("GET", "/reputacion?nodo=p001", quien="luis")
        self.assertNotIn("Buscar IP o red", txt)
        _s, _c, txt = self.p.pedir("GET", "/reputacion?nodo=p001", quien="olga")
        self.assertIn("Buscar IP o red", txt)
        _s, _c, txt = self.p.pedir("GET", "/conducta?nodo=p001", quien="luis")
        self.assertNotIn("Generar ahora</button>", txt)

    def test_telegram_se_cifra_al_guardar(self):
        """Correccion de defecto (B-20): el token de Telegram no tenia interfaz y quedaba en claro
        hasta el siguiente arranque. Ahora se guarda cifrado en el momento."""
        tok = "123456789:" + "A" * 35
        # (adaptada, 2026-10-14) ahora se pregunta a Telegram antes de guardar (getMe y getChat):
        # respuestas simuladas, sin red
        self.d._tg_api = lambda t, metodo, params=None, timeout=12: (
            True, {"username": "prueba_bot"} if metodo == "getMe" else
            {"id": -1001234567890, "title": "Grupo", "type": "supergroup"}, 200)
        st, _c, txt = self.p.pedir("POST", "/telegram", {"tgtoken": tok, "tgchat": "-1001234567890"})
        self.assertIn("Telegram guardado", txt)
        conf = open(self.d.REPORT_CONF, encoding="utf-8").read()
        self.assertNotIn(tok, conf)
        self.assertEqual(self.d.telegram_token(), tok)
        st, _c, _t = self.p.pedir("POST", "/telegram", {"tgtoken": tok}, "olga")
        self.assertEqual(st, 403)


class SinClaveMaestra(unittest.TestCase):
    """B-04: sin clave maestra nunca se dice «guardada» y /mikrotik no deja nada a medias."""

    def setUp(self):
        self.p = Panel(http=True, IDS_MASTER_KEY=os.path.join(AQUI, "no-existe-master-key"))
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d

    def test_no_se_dice_guardada_si_no_se_guardo(self):
        """Correccion de defecto (B-04, repro/sin_clave_maestra): «VALIDA y guardada» sin haber
        guardado, y /mikrotik con 500 tras escribir la configuracion global."""
        self.assertFalse(self.d.secretos.disponible())
        self.d.aidb_probar = lambda k: (True, "")
        self.d.groq_probar = lambda k: (True, "", ["m1"])
        self.d.feeds_auth_probar = lambda k: (True, "")
        # (adaptada, 2026-10-14) Groq exige ahora que la clave empiece por gsk_: con otra forma se
        # rechazaria antes de llegar a la clave maestra, que es lo que esta prueba mira
        for ruta, campo, clave in (("/feeds/aidb", "aidbkey", "clave-de-prueba-123"),
                                   ("/feeds/groq", "groqkey", "gsk_clave-de-prueba-123"),
                                   ("/feeds", "authkey", "clave-de-prueba-123")):
            st, _c, txt = self.p.pedir("POST", ruta, {campo: clave})
            self.assertEqual(st, 200, ruta)
            self.assertIn("No se guardó", txt, ruta)
            self.assertIn("clave maestra", txt, ruta)
            self.assertNotIn("guardada (solo", txt, ruta)
        # Ajustes > MikroTik ya no recibe la clave de la API (es de la ficha del punto, 2026-10-14):
        # aunque un formulario viejo la mande, no acaba en ningun fichero, ni en claro ni cifrada
        st, _c, txt = self.p.pedir("POST", "/mikrotik", {"nodo": "p001", "user": "api", "pass": "clave-nueva-b04",
                                                          "list": "otra-lista", "enabled": "1"})
        self.assertEqual(st, 200)
        for f in (self.d.MK_CONF, self.d.ROUTERS_CONF):
            if os.path.exists(f):
                self.assertNotIn("clave-nueva-b04", open(f, encoding="utf-8").read(), f)
        self.assertNotEqual(self.p.pedir("POST", "/mikrotik/test", {"nodo": "p001", "ajax": "1"})[0], 200)


# --------------------------------------------------------------------------------------------
class Usuarios(Base):
    def test_crear_admin_sale_con_3_si_ya_hay_usuarios(self):
        """Correccion de defecto (B-20): `ids-panel crear-admin` solo salia con 3 si existia ESE
        usuario; con otro nombre creaba un segundo admin (§7: 3 si ya hay usuarios)."""
        from idspanel import cli
        sys.modules["dashboard"] = self.d
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["crear-admin", "--usuario", "admin"]), 0)
            self.assertEqual(cli.main(["crear-admin", "--usuario", "otro"]), 3)
        self.assertEqual([u["user"] for u in self.d.cargar_usuarios()], ["admin"])
        self.assertEqual(out.getvalue().count("CLAVE="), 1)

    def test_restablecer_espera_al_panel_y_no_se_pierde_nada(self):
        """Correccion de defecto (B-22): el panel leia-modificaba-guardaba usuarios.json sin un
        cerrojo comun con `ids-panel restablecer`: uno de los dos cambios se perdia. Ahora los
        dos pasan por usuarios_cerrojo (flock entre procesos en Linux)."""
        from idspanel import cli
        d = self.d
        salt, h = d._hash_pw("clave-vieja-1")
        d.guardar_usuarios([{"user": "ana", "salt": salt, "hash": h, "role": "admin", "activo": True}])
        hecho = threading.Event()
        with d.usuarios_cerrojo():
            lst = d.cargar_usuarios()
            t = threading.Thread(target=lambda: (cli.restablecer("ana", dash=d), hecho.set()))
            with contextlib.redirect_stdout(io.StringIO()):
                t.start()
                time.sleep(0.3)
                self.assertFalse(hecho.is_set(), "restablecer no espero al cerrojo")
                salt2, h2 = d._hash_pw("clave-luis-1")
                lst.append({"user": "luis", "salt": salt2, "hash": h2, "role": "lectura", "activo": True})
                d.guardar_usuarios(lst)
        t.join(10)
        us = {u["user"]: u for u in d.cargar_usuarios()}
        self.assertIn("luis", us)                         # el alta del panel sigue
        self.assertNotEqual(us["ana"]["hash"], h)         # y el restablecer tambien


# --------------------------------------------------------------------------------------------
class Fondo(Base):
    def test_purga_completa_y_el_fondo_no_recrea_el_punto(self):
        """Correccion de defecto (A-09, espejo/r5): tras purgar, el refrescador volvia a crear
        nodos/<pid>/ y quedaban abonados-hist.jsonl y respaldos/espejo/<pid>."""
        d, n = self.d, self.p.n
        os.makedirs(os.path.join(d.ESPEJO_RESPALDOS, "p001"), exist_ok=True)
        with open(d.ABON_HIST_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps({"ip": K1, "nombre": "ABONADO"}) + "\n")
            f.write(json.dumps({"ip": "p002|" + IP, "nombre": "OTRO"}) + "\n")
        d._registrar_enviados(d.MK_SENT, {K1: {"cuando": 1}}, [])
        d.purgar_punto("p001")
        self.assertFalse(os.path.exists(os.path.join(d.ESPEJO_RESPALDOS, "p001")))
        hist = open(d.ABON_HIST_FILE, encoding="utf-8").read()
        self.assertNotIn(K1, hist)
        self.assertIn("p002|", hist)
        d._por_nodo(d.medir_sensor, ["p001", "p002"])    # estado.json aun lista p001
        self.assertFalse(os.path.exists(os.path.join(n.NODOS, "p001")))
        self.assertTrue(os.path.exists(os.path.join(n.NODOS, "p002")))

    def test_baja_sin_abrir_la_operacion_la_barre_el_fondo(self):
        """Correccion de defecto (A-09, espejo/r03 casos A-C y baja por la CLI): si nadie abre la
        operacion, los restos del punto quedaban para siempre. Ahora el barrido de fondo los
        purga cuando el punto falta de un estado.json fresco durante 10 min (y nunca con un
        estado.json viejo)."""
        d, a = self.d, self.p.a
        d._registrar_enviados(d.MK_SENT, {"p002|" + IP: {"cuando": 1}}, [])
        a.puntos.pop("p002")
        a.escribir_estado()
        t0 = time.time()
        self.assertEqual(d.barrer_bajas(ahora=t0), [])
        self.assertEqual(d.barrer_bajas(ahora=t0 + 60), [])
        self.assertEqual(d.barrer_bajas(ahora=t0 + 700), ["p002"])
        self.assertNotIn("p002|" + IP, d.cargar_enviados())
        self.assertNotIn("p002", d._pids_con_restos())
        a.escribir_estado(ts=time.time() - 3600)          # estado viejo: no decide nada
        d._registrar_enviados(d.MK_SENT, {"p003|" + IP: {"cuando": 1}}, [])
        self.assertEqual(d.barrer_bajas(ahora=time.time() + 5000), [])

    def test_el_refrescador_sobrevive_y_el_supervisor_relanza(self):
        """Correccion de defecto (A-10, ctx/r5): un FileNotFoundError en una vuelta mataba el
        refrescador (y las tareas de fondo de todos los puntos) sin aviso."""
        d = self.d
        vueltas = []

        class Parar:
            def __init__(self):
                self.ev = threading.Event()

            def is_set(self):
                return self.ev.is_set()

            def set(self):
                self.ev.set()

            def wait(self, t=None):
                return self.ev.wait(0.01)

        d._PARAR = Parar()
        d._DESPERTAR = Parar()          # la espera entre vueltas (10 s), corta en la prueba
        d._provisionar_geo = lambda: None

        def vuelta(estado):
            vueltas.append(1)
            if len(vueltas) == 1:
                raise FileNotFoundError("nodos/p002/report-x.html")
            d._PARAR.set()
        d._vuelta_refrescador = vuelta
        t = threading.Thread(target=d.refrescador, daemon=True)
        t.start()
        t.join(10)
        self.assertEqual(len(vueltas), 2)                 # siguio tras la vuelta fallida
        self.assertIn("FONDO-ERROR", open(d.BITACORA_LOG, encoding="utf-8").read())
        d._PARAR = threading.Event()
        d._DESPERTAR = threading.Event()
        d.lanzar_hilo("prueba", lambda: None)
        d._HILOS["prueba"][1].join(5)
        self.assertEqual(d.supervisar_hilos(), ["prueba"])
        self.assertIn("HILO-RELANZADO", open(d.BITACORA_LOG, encoding="utf-8").read())


if __name__ == "__main__":
    unittest.main()
