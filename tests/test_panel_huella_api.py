"""Apartado C de Puntos, parte del panel (2026-10-14): VPN-06, VPN-04 y los textos de la VPN.

Cambiado a propósito (decisión del dueño 2026-10-15): la API-SSL va SIN certificado, como en el
proyecto original. La huella pasa a ser opcional: sin huella fijada el panel hace /login con lo que
presente el router (anónimo o con certificado), protegido por el túnel; nunca la fija solo.

- H1 Sin huella fijada, el panel conecta TLS por el relé del punto y hace /login, sin guardar nada; la
  huella que presenta queda vista para la ficha. Con la huella confirmada, conecta como siempre; con otra
  distinta, NO hay login y el Registro lo apunta una vez. Una huella fijada sola por una versión de
  antes se sigue exigiendo (no rompe producción).
- H2 Todo camino que hace login pasa por esa comprobación (cuarentena, quitar, probar, tandas de fondo,
  espejo, reglas, diagnóstico, abonados, baja): con una huella distinta ninguno manda /login.
- H3 Sin certificado (API-SSL anónima) se prueba primero ADH y hay login; no hay huella que fijar. Con una
  huella fijada no se baja a ADH (nadie en medio se salta la huella). Una huella vieja de API anónima
  (sha256 de nada) cuenta como ninguna. Si el router cierra sin contestar, el mensaje dice primero qué
  revisar en el router (certificate=none) y «Probar» no lo recorta.
- H4 La ficha (solo admin) enseña la huella en bloques con los comandos de RouterOS y «La huella coincide:
  confirmar»; al confirmar se vuelve a leer la del router y solo se guarda si sigue siendo esa; con una
  distinta, aviso rojo y «Volver a confirmar»; una fijada sola sale «Fijada automáticamente» con
  «Revisar la huella»; sin certificado, que no hay huella que fijar; con 8728, un aviso discreto.
- D1 «Desbanear IP del MikroTik» (VPN-04): IP del túnel o la última conocida, orden inmediata
  vpn.desbanear del orquestador, resultado en JSON para el modal y línea en el Registro.
- T1 Textos: lo que queda en el MikroTik tras la baja (CA y, si es de antes, ruta y reglas), el «# AVISO:» del
  script destacado y el aviso de «Regenerar» para un punto con el certificado viejo; documentación.

Tipo «corrección de defecto» o «capacidad nueva»: cada una falla sin el arreglo. Sin red: el router es
un servidor TLS de mentira (test_n_routers.RouterOSFalso) y el orquestador, un transporte falso.
"""
import hashlib
import json
import os
import re
import socket
import sys
import tempfile
import types
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(TESTS, "fixtures", "panel2"))
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)
import _dash  # noqa: E402
from _dash_p import PanelP  # noqa: E402
from test_n_routers import RouterOSFalso, certificado  # noqa: E402

RE_TOKEN = r"name=op value='([0-9a-f-]{36})'"


def _logins(srv):
    return [w for w in srv.recibido if w and w[0] == "/login"]


# --------------------------------------------------------------------------------------------
# H1-H3: el núcleo (dashboard.mk_conectar) con un router TLS de mentira
# --------------------------------------------------------------------------------------------
class _Nucleo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.a = _dash.Arbol(self.tmp.name)
        self.d = _dash.cargar(self.a)
        self.n = self.d.nodos
        self.n.asegurar_dirs()
        self.cert, self.key, self.der = certificado(self.tmp.name)
        self.fp = hashlib.sha256(self.der).hexdigest()
        self.srv = RouterOSFalso(self.d, self.cert, self.key)

        self.aperturas = 0

        def abrir(ruta, timeout):
            self.aperturas += 1
            a, b = socket.socketpair()
            a.settimeout(timeout)
            self.srv.atender(b)
            return a
        self.d._mk_abrir_unix = abrir
        self.d.guardar_routers([{"id": "p001", "USER": "ids-api", "PASS": "clave-api-1", "ENABLED": "1"},
                                {"id": "p002", "USER": "ids-api", "PASS": "clave-api-2", "ENABLED": "1"}])

    def conectar(self, pid="p001"):
        return self.d.mk_conectar(self.d.cargar_mk_de(self.d.router_por_id(pid)))

    def guardados(self):
        with open(self.d.ROUTERS_CONF, encoding="utf-8") as f:
            return json.load(f)["routers"]

    def bitacora(self):
        try:
            with open(self.d.BITACORA_LOG, encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""


class HuellaNucleo(_Nucleo):
    def test_sin_huella_conecta_y_no_la_fija(self):
        """Cambiado a propósito (2026-10-15, API-SSL sin certificado): sin huella fijada hay /login con
        lo que presente el router (antes: HuellaNoConfirmada y ninguna clave). La huella NO se fija sola
        (VPN-06): queda vista para la ficha y nada en routers.json."""
        self.conectar().close()
        self.assertEqual(_logins(self.srv), [["/login", "=name=ids-api", "=password=clave-api-1"]])
        self.assertFalse(self.guardados()["p001"].get("CERT_FP"))
        self.assertEqual(self.d.huella_vista("p001"), self.fp)
        self.assertEqual(self.d.huella_estado(self.d.router_por_id("p001")), "sin")

    def test_confirmada_conecta_y_la_lectura_no_hace_login(self):
        """mk_huella_presentada lee la huella sin login; tras confirmar_huella, mk_conectar hace login."""
        self.assertEqual(self.d.mk_huella_presentada("p001"), self.fp)
        self.assertEqual(_logins(self.srv), [])
        self.assertEqual(self.d.confirmar_huella("p001", self.fp.upper(), "ana"), "")
        r = self.d.router_por_id("p001")
        self.assertEqual(self.d.huella_estado(r), "confirmada")
        self.assertEqual(r["CERT_FP_QUIEN"], "ana")
        self.conectar().close()
        self.assertEqual(_logins(self.srv), [["/login", "=name=ids-api", "=password=clave-api-1"]])
        with self.assertRaises(ValueError):
            self.d.confirmar_huella("p001", "no-es-una-huella", "ana")

    def test_fijada_sola_antes_se_sigue_usando(self):
        """Conservación: un routers.json de antes (CERT_FP sin quién la confirmó) conecta como hasta
        ahora; la ficha la marca «automatica»."""
        self.d.guardar_routers([{"id": "p001", "CERT_FP": self.fp}], huella=True)
        r = self.d.router_por_id("p001")
        self.assertEqual(self.d.huella_estado(r), "automatica")
        self.conectar().close()
        self.assertEqual(len(_logins(self.srv)), 1)

    def test_con_8728_no_intenta_tls_y_dice_por_que(self):
        """Corrección de defecto (revisión 2026-10-15, C7): con la API en claro (8728) el saludo
        TLS fallaba culpando al TLS; ahora mk_conectar dice la causa y no abre nada."""
        d = self.d.cargar_mk_de(self.d.router_por_id("p001"))
        d["PORT"] = "8728"
        antes = self.aperturas
        with self.assertRaises(IOError) as cm:
            self.d.mk_conectar(d)
        self.assertIn("8728", str(cm.exception))
        self.assertIn("API-SSL", str(cm.exception))
        self.assertEqual(self.aperturas, antes)
        self.assertEqual(_logins(self.srv), [])

    def test_guardar_otra_cosa_no_pisa_la_huella_confirmada_entre_medias(self):
        """Corrección de defecto (revisión 2026-10-15, C9): la ficha lee los routers, otro admin
        confirma la huella en ese momento y luego se guarda la foto vieja (usuario, clave): la
        huella confirmada se quedaba en blanco. Solo olvidarla (huella=True) la escribe."""
        rs = self.d.cargar_routers()                     # foto de antes, sin huella
        self.d.confirmar_huella("p001", self.fp, "ana")  # otro admin, a la vez
        for r in rs:
            r["USER"] = "ids-api-2"
        self.d.guardar_routers(rs)
        g = self.guardados()
        self.assertEqual(g["p001"]["CERT_FP"], self.fp)
        self.assertEqual(g["p001"]["CERT_FP_QUIEN"], "ana")
        self.assertEqual(g["p001"]["USER"], "ids-api-2")            # lo demás sí se guarda
        self.d.guardar_routers([{"id": "p001", "CERT_FP": ""}], huella=True)
        self.assertEqual(self.guardados()["p001"]["CERT_FP"], "")     # olvidarla sí la escribe

    def test_distinta_no_hay_login_y_el_registro_lo_dice_una_vez(self):
        self.d.confirmar_huella("p001", "00" * 32, "ana")
        for _ in range(2):
            with self.assertRaises(self.d.HuellaNoConfirmada) as cm:
                self.conectar()
            self.assertEqual(cm.exception.motivo, "distinta")
        self.assertIn("distinto del confirmado", str(cm.exception))
        self.assertEqual(_logins(self.srv), [])
        self.assertEqual(self.d.huella_vista("p001"), self.fp)
        lineas = [x for x in self.bitacora().splitlines() if "MK-HUELLA-DISTINTA" in x]
        self.assertEqual(len(lineas), 1, lineas)
        self.assertIn(self.fp[:16], lineas[0])
        # volver a confirmar la nueva: sustituye y conecta
        self.assertEqual(self.d.confirmar_huella("p001", self.fp, "ana"), "00" * 32)
        self.conectar().close()
        self.assertEqual(len(_logins(self.srv)), 1)

    def test_no_es_un_fallo_de_conexion_para_la_pausa(self):
        """Una huella distinta no es un router caído: las tareas de fondo no lo ponen en pausa."""
        self.d.confirmar_huella("p001", "00" * 32, "ana")
        r = self.d.router_por_id("p001")
        for _ in range(self.d.MK_PAUSA_FALLOS + 1):
            self.assertFalse(self.d._mk_tanda(r, lambda s, d: None))
        self.assertIsNone(self.d.mk_pausa("p001"))
        self.assertEqual(_logins(self.srv), [])


class TodosLosCaminos(_Nucleo):
    def test_ningun_camino_manda_login_con_huella_distinta(self):
        """Cuarentena (añadir/quitar), sesión de tandas, probar (núcleo y ficha), espejo, reglas,
        diagnóstico, abonados y la limpieza de la baja: todos pasan por mk_conectar y ninguno manda
        /login si el router presenta otro certificado que el de la huella fijada."""
        import puntos_web
        d = self.d
        d.confirmar_huella("p001", "00" * 32, "ana")
        r = d.router_por_id("p001")
        llamadas = {
            "mk_add": lambda: d.mk_add("10.0.0.5", router=r),
            "mk_remove": lambda: d.mk_remove("10.0.0.5", router=r),
            "mk_sesion": lambda: d.mk_sesion(r).__enter__(),
            "_mk_tanda": lambda: d._mk_tanda(r, lambda s, dd: None, fondo=False),
            "mk_probar": lambda: d.mk_probar("p001"),
            "probar_api": lambda: puntos_web.probar_api(d, "p001"),
            "espejo_plan": lambda: d.espejo_plan("p001"),
            "estado_reglas": lambda: d.estado_reglas(r),
            "mk_diagnostico": lambda: d.mk_diagnostico(r),
            "mk_abonados": lambda: d.mk_abonados(r),
            "baja_limpiar_router": lambda: d.baja_limpiar_router("p001", usuario="ana", op="op-prueba"),
        }
        textos = {}
        for nombre, f in llamadas.items():
            antes = self.aperturas
            try:
                textos[nombre] = repr(f())
            except Exception as e:  # noqa: BLE001 - lo que importa es que no haya login
                textos[nombre] = repr(e)
            self.assertGreater(self.aperturas, antes, (nombre, textos[nombre]))   # llegó al router
            self.assertEqual(_logins(self.srv), [], nombre)
        for nombre in ("mk_probar", "probar_api", "espejo_plan"):
            self.assertIn("distinto del confirmado", textos[nombre], (nombre, textos[nombre]))

    def test_solo_mk_conectar_hace_login(self):
        """Guarda estructural: en el panel solo mk_conectar manda "/login" a un router y solo
        _mk_tls_wrap abre TLS; un camino nuevo que se saltara la comprobación fallaría aquí."""
        import ast
        lib = _dash.LIB
        for fichero in ("dashboard.py", "puntos_web.py", "mikrotik_init.py", "eventos_web.py"):
            with open(os.path.join(lib, fichero), encoding="utf-8") as f:
                arbol = ast.parse(f.read())
            for fn in ast.walk(arbol):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for n in ast.walk(fn):
                    if isinstance(n, ast.List) and n.elts and isinstance(n.elts[0], ast.Constant) \
                            and n.elts[0].value == "/login":
                        self.assertEqual((fichero, fn.name), ("dashboard.py", "mk_conectar"))
                    if isinstance(n, ast.Attribute) and n.attr == "wrap_socket":
                        self.assertEqual((fichero, fn.name), ("dashboard.py", "_mk_tls_wrap"))


class SinCertificado(_Nucleo):
    def ssl_falso(self, der=None, falla=None):
        """TLS de mentira: todo handshake vale y el router presenta `der` (None = sin certificado).
        Con `falla`, todo handshake lanza esa excepción (el router cierra sin contestar)."""
        probados, enviado = [], []
        resp = bytearray()
        for _ in range(4):
            resp += self.d._mk_len(5) + b"!done" + b"\x00"

        class Sk:
            def getpeercert(self, binary_form=False):
                return der

            def settimeout(self, t):
                pass

            def sendall(self, b):
                enviado.append(bytes(b))

            def recv(self, n):
                out = bytes(resp[:n])
                del resp[:n]
                return out

            def close(self):
                pass

        class Ctx:
            check_hostname, verify_mode, c = True, None, None

            def set_ciphers(self, c):
                self.c = c

            def wrap_socket(self, raw, server_hostname=None):
                probados.append(self.c)
                if falla is not None:
                    raise falla
                return Sk()

        viejo = self.d._ssl
        self.addCleanup(setattr, self.d, "_ssl", viejo)
        self.d._ssl = types.SimpleNamespace(create_default_context=Ctx, CERT_NONE=0,
                                            TLSVersion=types.SimpleNamespace(TLSv1=1))
        self.d._mk_abrir_unix = lambda ruta, timeout: types.SimpleNamespace(close=lambda: None)
        self.d._MK_TLS_OK.clear()
        return probados, enviado

    def test_sin_certificado_conecta_por_adh(self):
        """Cambiado a propósito (2026-10-15): la API-SSL sin certificado es lo normal. Se prueba primero
        el cifrado anónimo y hay login (antes: ni ADH ni login, y pedía pegar ids-promax). No hay huella
        que fijar: la lectura da la de «nada» y confirmarla se rechaza."""
        probados, enviado = self.ssl_falso(None)
        self.conectar().close()
        self.assertEqual(probados[0], "ADH:@SECLEVEL=0")
        self.assertTrue(any(b"/login" in x for x in enviado))
        vacio = hashlib.sha256(b"").hexdigest()
        self.assertEqual(self.d.huella_vista("p001"), vacio)
        self.assertEqual(self.d.mk_huella_presentada("p001"), vacio)
        with self.assertRaises(ValueError):
            self.d.confirmar_huella("p001", vacio, "ana")
        self.assertFalse(self.guardados()["p001"].get("CERT_FP"))

    def test_con_huella_fijada_no_baja_a_adh(self):
        """Con la huella de un certificado fijada, un router que contesta sin certificado (alguien en
        medio, o le quitaron el certificado) no recibe la clave: ni se prueba ADH ni hay login, y el
        mensaje dice que se olvide la huella si se quitó el certificado."""
        self.d.confirmar_huella("p001", self.fp, "ana")
        probados, enviado = self.ssl_falso(None)
        with self.assertRaises(IOError) as cm:
            self.conectar()
        self.assertIn("no presentó certificado", str(cm.exception))
        self.assertIn("olvida la huella", str(cm.exception))
        self.assertNotIn("ADH:@SECLEVEL=0", probados)
        self.assertEqual(enviado, [])
        with self.assertRaises(IOError):
            self.d.mk_huella_presentada("p001")

    def test_router_que_cierra_dice_que_revisar_y_probar_no_lo_corta(self):
        """Corrección de defecto (lab 2026-10-15): el MikroTik cerraba la API-SSL sin contestar y
        «Probar» enseñaba «TLS handshake falló con los 2 cifrados probados (… UNEXPECTED_E» cortado a 200
        caracteres, sin decir qué hacer. Ahora el mensaje empieza por lo que hay que revisar en el router
        y la ficha no lo recorta."""
        import puntos_web
        eof = OSError("[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1029)")
        probados, enviado = self.ssl_falso(None, falla=eof)
        with self.assertRaises(IOError) as cm:
            self.conectar()
        txt = str(cm.exception)
        self.assertTrue(txt.startswith("el MikroTik cerró la API-SSL sin contestar al saludo TLS"), txt)
        self.assertLess(txt.index("certificate=none"), txt.index("UNEXPECTED_EOF"))
        self.assertIn("Detalle de los 3 cifrados probados", txt)
        self.assertEqual(probados, ["ADH:@SECLEVEL=0", "DEFAULT:@SECLEVEL=0", None])
        self.assertEqual(enviado, [])
        ok, msg = puntos_web.probar_api(self.d, "p001")
        self.assertFalse(ok)
        self.assertIn("/ip service set api-ssl certificate=none", msg)

    def test_huella_vieja_de_api_anonima_se_respeta(self):
        """Conservación: un router que se fijó sin certificado (sha256 de nada) sigue conectando."""
        probados, enviado = self.ssl_falso(None)
        self.d.guardar_routers([{"id": "p001", "CERT_FP": hashlib.sha256(b"").hexdigest()}], huella=True)
        self.conectar().close()
        self.assertEqual(probados[0], "ADH:@SECLEVEL=0")
        self.assertTrue(any(b"/login" in x for x in enviado))


# --------------------------------------------------------------------------------------------
# H4, D1, T1: la ficha y sus acciones por HTTP (panel de verdad, orquestador falso)
# --------------------------------------------------------------------------------------------
class _Panel(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")
        self.presenta = "c3" * 32            # lo que presenta ahora el router (mk_huella_presentada)
        self.leidas = []
        d = self.p.d

        def leer(pid, timeout=8):
            self.leidas.append(pid)
            d._ver_huella(pid, self.presenta)
            return self.presenta
        d.mk_huella_presentada = leer
        self.pedidas = []
        self.respuesta_desbanear = {"codigo": "OK", "mensaje": "198.51.100.7 desbaneada de ids-vpn",
                                    "datos": {"ip": "198.51.100.7", "desbaneada": True, "jaula": "ids-vpn"}}
        self.comandos = None
        orq = self.p.orq

        def transporte(pet):
            self.pedidas.append(pet)
            if pet["orden"] == "vpn.desbanear":
                return dict(self.respuesta_desbanear, op_id=pet["op_id"], ok=True)
            if pet["orden"] == "punto.comandos" and self.comandos is not None:
                return {"op_id": pet["op_id"], "ok": True, "codigo": "OK", "mensaje": "",
                        "datos": {"comandos": self.comandos}}
            return orq(pet)
        self.p.pw.TRANSPORTE = transporte

    def get(self, ruta, cookie=None):
        r = self.p.pedir("GET", ruta, cookie=cookie or self.ana)
        self.assertEqual(r.status, 200, r.texto[:300])
        return r.texto

    def ajax(self, ruta, form, cookie=None):
        r = self.p.pedir("POST", ruta, dict(form, ajax="1"), cookie=cookie or self.ana)
        return r, json.loads(r.texto) if r.texto.strip().startswith("{") else {}

    def token_de(self, html, marca):
        """El token del formulario que contiene `marca`."""
        for m in re.finditer(r"<form[^>]*>(?:(?!</form>).)*?</form>", html, re.S):
            if marca in m.group(0):
                return re.search(RE_TOKEN, m.group(0)).group(1)
        raise AssertionError("sin formulario con %r" % marca)

    def guardados(self):
        try:
            with open(self.p.d.ROUTERS_CONF, encoding="utf-8") as f:
                return json.load(f)["routers"]
        except FileNotFoundError:          # nadie guardó nada todavía
            return {}

    def bitacora(self):
        try:
            with open(self.p.d.BITACORA_LOG, encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""

    def estado_p001(self, **vpn_cliente):
        ruta = os.path.join(self.p.tmp.name, "run", "estado.json")
        with open(ruta, encoding="utf-8") as f:
            e = json.load(f)
        e["puntos"]["p001"]["vpn_cliente"] = dict(e["puntos"]["p001"]["vpn_cliente"], **vpn_cliente)
        e["puntos"]["p001"]["relleno"] = "x" * 40        # otro tamaño: nodos relee estado.json
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(e, f)


class FichaHuella(_Panel):
    def test_sin_javascript_la_huella_se_lee_en_su_pagina(self):
        """Corrección de defecto (revisión 2026-10-15, B5): sin JavaScript la ficha se quedaba en
        «comprobando…» y no había forma de confirmar la huella. El enlace <noscript> lleva a
        /puntos/<pid>/huella?ver=1: la misma caja en una página, con el botón de confirmar."""
        h = self.get("/puntos/p001")
        self.assertIn("<noscript> <a href='/puntos/p001/huella?ver=1'>Leer la huella ahora</a></noscript>", h)
        self.assertEqual(self.leidas, [])                         # la ficha no la lee: la pide el JS
        pag = self.get("/puntos/p001/huella?ver=1")
        self.assertTrue(pag.lstrip().lower().startswith("<!doctype html"), pag[:80])
        self.assertIn("Volver a la ficha", pag)
        self.assertIn("c3c3 c3c3 c3c3 c3c3", pag)
        self.assertIn("La huella coincide: confirmar", pag)
        self.assertIn("name=huella value='%s'" % self.presenta, pag)
        self.assertEqual(self.leidas, ["p001"])

    def test_sin_huella_se_ve_y_se_confirma(self):
        """La ficha la pide por fetch; el JSON trae la huella en bloques, el comando de RouterOS y
        «La huella coincide: confirmar»; confirmar vuelve a leerla y la guarda con quién."""
        h = self.get("/puntos/p001")
        self.assertIn("Sin huella fijada: el panel conecta", h)
        self.assertIn("data-pedir=1", h)
        j = json.loads(self.get("/puntos/p001/huella"))
        self.assertEqual(j["texto"], self.presenta)
        caja = j["html"]
        self.assertIn("c3c3 c3c3 c3c3 c3c3 c3c3 c3c3 c3c3 c3c3<br>c3c3", caja)
        self.assertIn("El router presenta un certificado", caja)
        self.assertIn("/ip service print detail where name=api-ssl", caja)
        self.assertIn("/certificate print detail where name=&lt;certificado&gt;", caja)
        self.assertNotIn("ids-promax", caja)
        self.assertIn("fingerprint", caja)
        self.assertIn("La huella coincide: confirmar", caja)
        self.assertIn("name=huella value='%s'" % self.presenta, caja)
        tok = self.token_de(caja, "confirmar_huella")
        r, jj = self.ajax("/puntos/p001/api", {"accion": "confirmar_huella", "huella": self.presenta, "op": tok})
        self.assertEqual(r.status, 200, jj)
        self.assertTrue(jj["ok"])
        self.assertIn("Huella confirmada", jj["mensaje"])
        g = self.guardados()["p001"]
        self.assertEqual((g["CERT_FP"], g["CERT_FP_QUIEN"]), (self.presenta, "ana"))
        self.assertEqual(self.leidas, ["p001", "p001"])           # la ficha y, otra vez, al confirmar
        self.assertRegex(self.bitacora(), r"PUNTO-API\t.*objetivo=huella resultado=confirmada")
        caja = json.loads(self.get("/puntos/p001/huella"))["html"]
        self.assertIn("Confirmada por <b>ana</b>", caja)
        self.assertIn("presenta ahora esta misma huella", caja)
        # el mismo formulario otra vez no repite nada
        r, jj = self.ajax("/puntos/p001/api", {"accion": "confirmar_huella", "huella": self.presenta, "op": tok})
        self.assertEqual(self.leidas, ["p001", "p001"])

    def test_sin_certificado_no_hay_huella_que_fijar(self):
        """Capacidad nueva (2026-10-15): con la API-SSL sin certificado la ficha lo dice, sin botón de
        confirmar, y una «huella» de nada no se puede confirmar a mano."""
        self.presenta = hashlib.sha256(b"").hexdigest()
        j = json.loads(self.get("/puntos/p001/huella"))
        self.assertEqual(j["texto"], "sin certificado")
        self.assertIn("El router no presenta certificado (cifrado anónimo): no hay huella que fijar", j["html"])
        self.assertNotIn("La huella coincide: confirmar", j["html"])
        tok = self.token_de(self.get("/puntos/p001"), "papiProbar")
        n = len(self.leidas)
        r, jj = self.ajax("/puntos/p001/api", {"accion": "confirmar_huella", "huella": self.presenta, "op": tok})
        self.assertEqual(r.status, 400)
        self.assertIn("no hay huella que fijar", jj["mensaje"])
        self.assertEqual(len(self.leidas), n)
        self.assertFalse(self.guardados().get("p001", {}).get("CERT_FP"))

    def test_si_cambio_al_confirmar_no_se_guarda(self):
        caja = json.loads(self.get("/puntos/p001/huella"))["html"]
        tok = self.token_de(caja, "confirmar_huella")
        visto, self.presenta = self.presenta, "d4" * 32
        r, j = self.ajax("/puntos/p001/api", {"accion": "confirmar_huella", "huella": visto, "op": tok})
        self.assertEqual(r.status, 409)
        self.assertFalse(j["ok"])
        self.assertIn("otra huella", j["mensaje"])
        self.assertFalse(self.guardados().get("p001", {}).get("CERT_FP"))

    def test_huella_mal_formada_se_rechaza_sin_leer(self):
        caja = json.loads(self.get("/puntos/p001/huella"))["html"]
        tok = self.token_de(caja, "confirmar_huella")
        n = len(self.leidas)
        r, j = self.ajax("/puntos/p001/api", {"accion": "confirmar_huella", "huella": "zz", "op": tok})
        self.assertEqual(r.status, 400)
        self.assertEqual(len(self.leidas), n)

    def test_distinta_aviso_rojo_y_volver_a_confirmar(self):
        self.p.d.confirmar_huella("p001", "ab" * 32, "ana")
        self.p.d._ver_huella("p001", self.presenta)
        h = self.get("/puntos/p001")
        self.assertIn("presenta un certificado distinto del confirmado", h)
        self.assertIn("suplantación", h)
        self.assertIn("Volver a confirmar", h)
        self.assertIn("abab abab", h)
        self.assertIn("c3c3 c3c3", h)
        tok = self.token_de(h, "Volver a confirmar")
        r, j = self.ajax("/puntos/p001/api", {"accion": "confirmar_huella", "huella": self.presenta, "op": tok})
        self.assertTrue(j["ok"], j)
        self.assertEqual(self.guardados()["p001"]["CERT_FP"], self.presenta)
        self.assertRegex(self.bitacora(), r"resultado=reconfirmada .*antes=abababab")

    def test_fijada_automaticamente_se_marca_sin_bloquear(self):
        self.p.d.guardar_routers([{"id": "p001", "CERT_FP": self.presenta}], huella=True)
        h = self.get("/puntos/p001")
        self.assertIn("Fijada automáticamente", h)
        self.assertIn("Revisar la huella", h)
        self.assertIn("La huella coincide: confirmar", h)
        self.assertNotIn("distinto del confirmado", h)

    def test_puerto_8728_aviso_discreto(self):
        ruta = os.path.join(self.p.tmp.name, "run", "estado.json")
        with open(ruta, encoding="utf-8") as f:
            e = json.load(f)
        e["puntos"]["p002"]["api_puerto"] = 8728
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(e, f)
        h = self.get("/puntos/p002")
        self.assertIn("API sin TLS (puerto 8728)", h)
        # revisión 2026-10-15, C7: con 8728 el panel no conecta (habla siempre API-SSL); antes
        # decía que «la clave va protegida solo por el túnel», como si funcionara
        self.assertIn("<b>no conecta</b>", h)
        self.assertNotIn("protegida solo por el túnel", h)
        self.assertNotIn("La huella coincide: confirmar", h)

    def test_solo_admin(self):
        olga = self.p.entrar("olga")
        r = self.p.pedir("POST", "/puntos/p001/api", {"accion": "confirmar_huella", "huella": self.presenta,
                                                       "ajax": "1"}, cookie=olga)
        self.assertEqual(r.status, 403)
        self.assertEqual(self.p.pedir("GET", "/puntos/p001/huella", cookie=olga).status, 403)
        self.assertFalse(self.guardados().get("p001", {}).get("CERT_FP"))

    def test_probar_con_huella_distinta_dice_por_que_y_no_manda_la_clave(self):
        """«Probar la conexión» con una huella fijada y otro certificado en el router: el modal dice que
        es distinto del confirmado y la clave no sale."""
        enviado = []
        d = self.p.d
        d.confirmar_huella("p001", "ab" * 32, "ana")

        class Sk:
            def getpeercert(self, binary_form=False):
                return b"certificado-de-prueba"

            def sendall(self, b):
                enviado.append(b)

            def close(self):
                pass
        d._mk_tls_wrap = lambda host, port, timeout, con_certificado=False: Sk()
        d.cargar_mk_de = lambda r: dict(r or {}, ROUTER_ID=(r or {}).get("id", ""))
        h = self.get("/puntos/p001")
        tok = self.token_de(h, "papiProbar")
        r, j = self.ajax("/puntos/p001/api", {"accion": "probar", "user": "ids-api", "pass": "clave-api", "op": tok})
        self.assertEqual(r.status, 502)
        self.assertIn("distinto del confirmado", j["mensaje"])
        self.assertEqual(enviado, [])


class Desbanear(_Panel):
    def test_ip_del_tunel_y_luego_la_ultima_conocida(self):
        h = self.get("/puntos/p001")
        self.assertIn("Desbanear IP del MikroTik", h)
        self.assertRegex(h, r"action='/puntos/p001/desbanear'.*?name=ip value='198\.51\.100\.7'")
        self.assertIn("desde la que está conectado ahora", h)
        # baneado: el túnel cae y estado.json ya no trae su IP; la ficha propone la última conocida
        self.estado_p001(conectado=False, ip_real=None)
        h = self.get("/puntos/p001")
        self.assertRegex(h, r"name=ip value='198\.51\.100\.7'")
        self.assertIn("la última desde la que conectó", h)
        # p002 nunca conectó: vacío, editable
        self.assertRegex(self.get("/puntos/p002"), r"action='/puntos/p002/desbanear'.*?name=ip value=''")

    def test_desbanea_por_el_orquestador_y_queda_en_el_registro(self):
        h = self.get("/puntos/p001")
        tok = self.token_de(h, "/desbanear")
        r, j = self.ajax("/puntos/p001/desbanear", {"ip": "198.51.100.7", "op": tok})
        self.assertEqual(r.status, 200, j)
        self.assertTrue(j["ok"])
        self.assertIn("desbaneada", j["mensaje"])
        pet = [x for x in self.pedidas if x["orden"] == "vpn.desbanear"]
        self.assertEqual([(x["params"], x["quien"]) for x in pet], [({"ip": "198.51.100.7"}, "panel:ana")])
        self.assertRegex(self.bitacora(), r"PUNTO-VPN-DESBANEAR\t.*punto=p001 objetivo=198\.51\.100\.7 "
                                          r"resultado=desbaneada")
        # el mismo formulario otra vez no repite la orden
        self.ajax("/puntos/p001/desbanear", {"ip": "198.51.100.7", "op": tok})
        self.assertEqual(len([x for x in self.pedidas if x["orden"] == "vpn.desbanear"]), 1)

    def test_no_estaba_baneada_y_fallo(self):
        self.respuesta_desbanear = {"codigo": "OK", "mensaje": "no estaba",
                                    "datos": {"ip": "203.0.113.45", "desbaneada": False}}
        tok = self.token_de(self.get("/puntos/p001"), "/desbanear")
        r, j = self.ajax("/puntos/p001/desbanear", {"ip": "203.0.113.45", "op": tok})
        self.assertTrue(j["ok"])
        self.assertIn("no estaba baneada", j["mensaje"])
        self.respuesta_desbanear = {"codigo": "FALLO", "mensaje": "fail2ban-client salió con 255", "datos": {}}
        tok = self.token_de(self.get("/puntos/p001"), "/desbanear")
        r, j = self.ajax("/puntos/p001/desbanear", {"ip": "203.0.113.45", "op": tok})
        self.assertEqual(r.status, 502)
        self.assertIn("fail2ban-client", j["mensaje"])

    def test_ip_invalida_y_solo_admin(self):
        tok = self.token_de(self.get("/puntos/p001"), "/desbanear")
        r, j = self.ajax("/puntos/p001/desbanear", {"ip": "198.51.100.7; reboot", "op": tok})
        self.assertEqual(r.status, 400)
        olga = self.p.entrar("olga")
        r = self.p.pedir("POST", "/puntos/p001/desbanear", {"ip": "198.51.100.7", "ajax": "1"}, cookie=olga)
        self.assertEqual(r.status, 403)
        self.assertEqual([x for x in self.pedidas if x["orden"] == "vpn.desbanear"], [])


class Textos(_Panel):
    def test_baja_dice_como_quitar_la_ca_y_lo_del_script_anterior(self):
        """El script de hoy no lleva firewall ni rutas (2026-10-15): la baja da la CA y, para routers
        dados de alta con el script anterior, quitar su ruta y sus reglas por el comentario EXACTO
        del alta (sin `~`, que casaría también el `:espejo` y otros puntos)."""
        html = self.p.pw._cuerpo_fin(self.p.d, {"orden": "punto.borrar", "ok": True, "pid": "p001"})
        self.assertIn('/certificate remove [find name~"^ids-maat-ca-p001"]', html)
        self.assertIn('/file remove [find name~"^ids-maat-ca-p001"]', html)
        self.assertIn('/ip firewall filter remove [find comment="IDS ids-maat:p001"]', html)
        self.assertIn('/ip route remove [find comment="IDS ids-maat:p001"]', html)
        self.assertNotIn("comment~", html)
        self.assertIn("script anterior", html)

    def test_aviso_del_script_destacado_y_regenerar(self):
        """Con el script real del orquestador para un punto con el certificado viejo: el «# AVISO:» sale
        en un aviso rojo y «Regenerar» avisa de la CA y la verificación."""
        import _ayuda_orq
        orq = _ayuda_orq.cargar_orq()
        p = {"pid": "p001", "nombre": "norte", "n": 1, "puerto": 1194, "tun_net": "100.64.1.0/24",
             "sensor": "100.64.1.1", "ros_version": 7, "api_puerto": 8729, "usuario": "vpn3a9f2c"}
        ca = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n"
        self.comandos = orq.comandos_mikrotik(p, "ids.empresa.example", ca_pem=ca,
                                              aviso_cert=orq.AVISO_CERT_VIEJO.replace("<pid>", "p001"))
        h = self.get("/puntos/p001")
        self.assertRegex(h, r"<div class='aviso err'><b>Aviso del servidor sobre este script:</b> el certificado "
                            r"del servidor de este punto es anterior")
        self.assertIn("certificado del servidor de antes de la verificación", h)
        self.assertIn("verify-server-certificate=yes además de poner la clave nueva", h)
        self.comandos = orq.comandos_mikrotik(p, "ids.empresa.example", ca_pem=ca)
        h = self.get("/puntos/p001")
        self.assertNotIn("Aviso del servidor sobre este script", h)
        self.assertNotIn("certificado del servidor de antes de la verificación", h)
        self.assertIn("no queda baneado por reintentar con la vieja", h)

    def test_regenerar_con_certificado_renovado(self):
        vm = {"orden": "punto.vpn.regenerar", "ok": True, "pid": "p001", "ros_version": 7,
              "mensaje": "credencial regenerada y certificado del servidor renovado",
              "resultado": {"pid": "p001", "usuario": "vpn3a9f2c", "clave": "CLAVE-UNICA",
                            "comandos": "# --- RouterOS v7\n/x\n# --- RouterOS v6\n/y\n"}}
        html = self.p.pw._cuerpo_fin(self.p.d, vm)
        self.assertIn("renovó además su certificado", html)
        self.assertIn("verify-server-certificate=yes", html)
        vm["mensaje"] = "credencial regenerada"
        self.assertNotIn("renovó además su certificado", self.p.pw._cuerpo_fin(self.p.d, vm))

    def test_documentacion(self):
        doc = self.p.d.documentacion_page(pagina="todo")
        for txt in ("La huella coincide: confirmar", "Fijada automáticamente", "Desbanear IP del MikroTik",
                    # la API-SSL va sin certificado (2026-10-15) y la doc dice qué revisar en el router
                    "API-SSL sin certificado", "/ip service set api-ssl certificate=none",
                    "verify-server-certificate", "ids-maat-ca-",
                    # el script no lleva firewall ni rutas (2026-10-15): lo dice y explica la limpieza
                    "Firewall y rutas del router: los gestionas tú", "no lleva reglas de firewall ni rutas",
                    '/ip firewall filter remove [find comment="IDS ids-maat:&lt;punto&gt;"]'):
            self.assertIn(txt, doc, txt)


if __name__ == "__main__":
    unittest.main()
