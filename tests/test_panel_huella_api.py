"""Apartado C de Puntos, parte del panel (2026-10-14): VPN-06, VPN-04 y los textos de la VPN.

- H1 Sin huella confirmada, el panel NO manda la clave de ids-api: conecta TLS por el relé del punto,
  lee la huella, cierra y lo dice (antes la fijaba sola y hacía /login en esa misma conexión). Con la
  huella confirmada, conecta como siempre; con otra distinta, tampoco hay login y el Registro lo apunta
  una vez. Una huella fijada sola por una versión de antes se sigue usando (no rompe producción).
- H2 Todo camino que hace login pasa por esa comprobación (cuarentena, quitar, probar, tandas de fondo,
  espejo, reglas, diagnóstico, abonados, baja): con la huella sin confirmar ninguno manda /login.
- H3 Sin certificado (API-SSL anónima) no hay huella que confirmar: ni se prueba ADH ni hay login; una
  huella vieja de ese caso (sha256 de nada) se respeta como estaba.
- H4 La ficha (solo admin) enseña la huella en bloques con el comando de RouterOS y «La huella coincide:
  confirmar»; al confirmar se vuelve a leer la del router y solo se guarda si sigue siendo esa; con una
  distinta, aviso rojo y «Volver a confirmar»; una fijada sola sale «Fijada automáticamente» con
  «Revisar la huella»; con 8728, un aviso discreto.
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
    def test_sin_huella_no_manda_la_clave_ni_la_fija(self):
        """Antes: la primera conexión fijaba la huella sola y mandaba /login con la clave en esa misma
        conexión (TOFU sin confirmar). Ahora: lee la huella, cierra, lanza HuellaNoConfirmada y no
        guarda nada; la huella vista queda para la ficha."""
        with self.assertRaises(self.d.HuellaNoConfirmada) as cm:
            self.conectar()
        self.assertEqual(cm.exception.motivo, "sin_confirmar")
        self.assertEqual(cm.exception.presentada, self.fp)
        self.assertIn("sin confirmar", str(cm.exception))
        self.assertEqual(_logins(self.srv), [])
        self.assertFalse(any("clave-api-1" in " ".join(w) for w in self.srv.recibido))
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
        self.d.guardar_routers([{"id": "p001", "CERT_FP": self.fp}])
        r = self.d.router_por_id("p001")
        self.assertEqual(self.d.huella_estado(r), "automatica")
        self.conectar().close()
        self.assertEqual(len(_logins(self.srv)), 1)

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
        """Una huella sin confirmar no es un router caído: las tareas de fondo no lo ponen en pausa."""
        r = self.d.router_por_id("p001")
        for _ in range(self.d.MK_PAUSA_FALLOS + 1):
            self.assertFalse(self.d._mk_tanda(r, lambda s, d: None))
        self.assertIsNone(self.d.mk_pausa("p001"))
        self.assertEqual(_logins(self.srv), [])


class TodosLosCaminos(_Nucleo):
    def test_ningun_camino_manda_login_sin_huella_confirmada(self):
        """Cuarentena (añadir/quitar), sesión de tandas, probar (núcleo y ficha), espejo, reglas,
        diagnóstico, abonados y la limpieza de la baja: todos pasan por mk_conectar y ninguno manda
        /login con la huella sin confirmar."""
        import puntos_web
        d = self.d
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
            self.assertIn("sin confirmar", textos[nombre], (nombre, textos[nombre]))

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
    def ssl_falso(self, der=None):
        """TLS de mentira: todo handshake vale y el router presenta `der` (None = sin certificado)."""
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
                return Sk()

        viejo = self.d._ssl
        self.addCleanup(setattr, self.d, "_ssl", viejo)
        self.d._ssl = types.SimpleNamespace(create_default_context=Ctx, CERT_NONE=0,
                                            TLSVersion=types.SimpleNamespace(TLSv1=1))
        self.d._mk_abrir_unix = lambda ruta, timeout: types.SimpleNamespace(close=lambda: None)
        self.d._MK_TLS_OK.clear()
        return probados, enviado

    def test_sin_certificado_ni_adh_ni_login(self):
        probados, enviado = self.ssl_falso(None)
        with self.assertRaises(IOError) as cm:
            self.conectar()
        self.assertIn("no presentó certificado", str(cm.exception))
        self.assertIn("ids-promax", str(cm.exception))
        self.assertNotIn("ADH:@SECLEVEL=0", probados)
        self.assertEqual(enviado, [])
        with self.assertRaises(IOError):
            self.d.mk_huella_presentada("p001")

    def test_huella_vieja_de_api_anonima_se_respeta(self):
        """Conservación: un router que se fijó sin certificado (sha256 de nada) sigue conectando."""
        probados, enviado = self.ssl_falso(None)
        self.d.guardar_routers([{"id": "p001", "CERT_FP": hashlib.sha256(b"").hexdigest()}])
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
    def test_sin_huella_se_ve_y_se_confirma(self):
        """La ficha la pide por fetch; el JSON trae la huella en bloques, el comando de RouterOS y
        «La huella coincide: confirmar»; confirmar vuelve a leerla y la guarda con quién."""
        h = self.get("/puntos/p001")
        self.assertIn("Sin huella confirmada", h)
        self.assertIn("data-pedir=1", h)
        j = json.loads(self.get("/puntos/p001/huella"))
        self.assertEqual(j["texto"], self.presenta)
        caja = j["html"]
        self.assertIn("c3c3 c3c3 c3c3 c3c3 c3c3 c3c3 c3c3 c3c3<br>c3c3", caja)
        self.assertIn('/certificate print detail where name~&quot;ids-promax&quot;', caja)
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
        self.p.d.guardar_routers([{"id": "p001", "CERT_FP": self.presenta}])
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
        self.assertIn("Se recomienda API-SSL", h)
        self.assertNotIn("La huella coincide: confirmar", h)

    def test_solo_admin(self):
        olga = self.p.entrar("olga")
        r = self.p.pedir("POST", "/puntos/p001/api", {"accion": "confirmar_huella", "huella": self.presenta,
                                                       "ajax": "1"}, cookie=olga)
        self.assertEqual(r.status, 403)
        self.assertEqual(self.p.pedir("GET", "/puntos/p001/huella", cookie=olga).status, 403)
        self.assertFalse(self.guardados().get("p001", {}).get("CERT_FP"))

    def test_probar_sin_huella_dice_por_que_y_no_manda_la_clave(self):
        """«Probar la conexión» con la huella sin confirmar: el modal dice que falta confirmarla."""
        enviado = []
        d = self.p.d

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
        self.assertIn("sin confirmar", j["mensaje"])
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
                    "verify-server-certificate", "ids-maat-ca-",
                    # el script no lleva firewall ni rutas (2026-10-15): lo dice y explica la limpieza
                    "Firewall y rutas del router: los gestionas tú", "no lleva reglas de firewall ni rutas",
                    '/ip firewall filter remove [find comment="IDS ids-maat:&lt;punto&gt;"]'):
            self.assertIn(txt, doc, txt)


if __name__ == "__main__":
    unittest.main()
