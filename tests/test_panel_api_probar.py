"""«Probar la conexión» de la ficha del punto, según la casilla «Con certificado» (el dueño, 2026-10-20:
«el probar la conexión debe confirmar si está con ssl: confirmar conexión y certificado; si en caso no
tiene certificado lo creas; en el que no es con ssl solo confirma conexión»).

- A1 Sin SSL (TLS «0»): solo la conexión, y el mensaje dice que fue por la API normal y su puerto; nunca
  se crea un certificado.
- A2 API-SSL con certificado: la conexión y los 16 primeros de su huella (para fijarla abajo); no se crea
  nada.
- A3 API-SSL que cierra el saludo TLS o que conecta sin certificado (cifrado anónimo): el panel crea el
  certificado (mk_crear_certificado(pid, puerto), UNA vez) y vuelve a probar por API-SSL; el mensaje dice
  qué hizo y cómo fue la segunda prueba.
- A4 Si no se puede crear (el núcleo dice por qué, revienta, o es un núcleo sin mk_crear_certificado): el
  fallo de antes, con las órdenes para pegar y su tope de 600, y el motivo.
- A5 Con la casilla marcada y el 8728 (el de la API normal) no se crea: pondría la API-SSL encima.
- A6 Conservación: con una huella distinta, con una huella fijada o ante otro fallo (router caído, clave
  mala, relé cerrado) no se crea nada y el fallo sale tal cual.
- A7 La ficha explica qué hace «Probar la conexión» y ya no da las órdenes del certificado.

El modal (el dueño, 2026-10-20, de «Prueba: conexión OK con 'X'.»: «ese mensaje debes mejorar»):
- B1 probar_api_detalle da, además del texto de siempre y con la MISMA prueba (una conexión), los datos del
  modal: router (identity), modelo y versión de RouterOS (/system/resource, en esa misma conexión),
  conexión, puerto, por dónde va (túnel o red local), certificado (inicio de la huella, fijada o no, creado
  ahora), usuario y si se permite enviar IPs a la cuarentena. Si esa lectura extra falla, no pasa nada.
- B2 Si falla: título, QUÉ HACER (una frase según el fallo), las órdenes de RouterOS para pegar y el detalle
  técnico tal cual. Nunca la clave.
- B3 Por HTTP: el JSON de «Probar» trae `prueba` y «mensaje» es la misma prueba en texto (si falla, qué
  hacer delante del detalle), sin «Prueba: » repetido (antes: «Prueba: El router no tenía certificado….
  Prueba: …»); sin JavaScript, la ficha da ese texto, escapado.
- B4 El JS del modal pasa por pjEsc todo lo que viene del router (con node, además, se ejecuta de verdad:
  un nombre con <script> sale escapado y, si falla, qué hacer va delante de las órdenes y del detalle).

Tipo «capacidad nueva»: A1-A5, A7 y B1-B4 fallan sin el cambio; A6 es conservación. Sin red: el núcleo es
un sustituto con el contrato de dashboard (mk_conectar, _mk_send/_mk_reply, huella_vista,
mk_crear_certificado) y la ficha sale del panel de verdad con el orquestador falso
(tests/fixtures/panel2/_dash_p.py).
"""
import hashlib
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import types
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(TESTS, "fixtures", "panel2"))
importlib.import_module("_dash")   # solo por su efecto: pone la carpeta del panel en sys.path
from _dash_p import PanelP  # noqa: E402

FP = hashlib.sha256(b"certificado-de-prueba").hexdigest()     # lo que presenta un router con certificado
VACIO = hashlib.sha256(b"").hexdigest()                        # sin certificado (cifrado anónimo)
CREADO = "creado y firmado el certificado ids-api y asignado a la API-SSL en el puerto %d"
RECURSO = ("RB5009UG+S+", "7.16.2 (stable)")                   # board-name y version de /system/resource
# el punto de la ficha (nodos.punto) en las pruebas sin panel: por VPN o directo por la red local
PUNTO_VPN = {"pid": "p001", "nombre": "norte", "sensor": "100.64.1.1", "mk": "100.64.1.2"}
PUNTO_DIRECTO = {"pid": "p001", "nombre": "norte", "modo": "directo", "mk_ip": "192.0.2.10", "sensor": "192.0.2.1"}
RE_TOKEN = r"name=op value='([0-9a-f-]{36})'"


def _pw():
    import puntos_web
    return puntos_web


def cerro(pw, detalle="ADH:@SECLEVEL=0: EOF | DEFAULT:@SECLEVEL=0: EOF | cifrados por defecto: EOF"):
    """El fallo del núcleo (dashboard._mk_tls_wrap) cuando el router cierra la API-SSL sin contestar al
    saludo TLS: lo que hay que hacer, con las órdenes del certificado, delante del detalle."""
    return IOError("el MikroTik cerró la API-SSL sin contestar al saludo TLS — revisa en el MikroTik /ip "
                   "service print detail where name=api-ssl: habilitada y address con el sensor o vacía. Si "
                   "no tiene certificado (RouterOS 7 no acepta la API-SSL sin él), o tiene uno y corta igual, "
                   "ponle este: " + pw.CMD_CERT_API_SSL + ". O cambia el punto a la API sin SSL (8728) "
                   "en su ficha. Detalle de los 3 cifrados probados: " + detalle)


def token_de(html, marca):
    """El token del formulario de la ficha que contiene `marca`."""
    for m in re.finditer(r"<form[^>]*>(?:(?!</form>).)*?</form>", html, re.S):
        if marca in m.group(0):
            return re.search(RE_TOKEN, m.group(0)).group(1)
    raise AssertionError("sin formulario con %r" % marca)


class HuellaNoConfirmada(RuntimeError):
    """La del núcleo: el router presenta otro certificado que el de la huella fijada (no hubo /login)."""


class NucleoFalso:
    """Lo que probar_api usa de dashboard, con su contrato: un router por punto; mk_conectar según un
    guion (por conexión, la excepción que lanza o la huella que presenta el router; None = API normal,
    sin TLS); huella_vista, la de la última conexión TLS; y mk_crear_certificado si `crear` no es None
    (lo que devuelve, o la excepción que lanza). _mk_send/_mk_reply contestan /system/identity con
    `nombre` y /system/resource con `recurso`: (modelo, versión), None (un !trap) o la excepción que
    lanza."""
    HuellaNoConfirmada = HuellaNoConfirmada

    def __init__(self, guion, tls="1", puerto="8729", cert_fp="", crear=(True, CREADO % 8729),
                 nombre="router-prueba", recurso=RECURSO):
        self.router = {"id": "p001", "USER": "ids-api", "PASS": "clave-api", "TLS": tls, "PORT": puerto,
                       "CERT_FP": cert_fp, "ENABLED": "1"}
        self.guion = list(guion)
        self.conexiones = []          # lo que recibió mk_conectar en cada conexión
        self.creados = []             # (pid, puerto) de cada mk_crear_certificado
        self.enviado = []
        self.vista = ""
        self.nombre, self.recurso = nombre, recurso
        if crear is not None:
            self.crear = crear
            self.mk_crear_certificado = self._crear

    def cargar_routers(self):
        return [dict(self.router)]

    def cargar_mk_de(self, r):
        return dict(r or {}, ROUTER_ID=(r or {}).get("id", ""))

    def mk_conectar(self, m):
        self.conexiones.append(dict(m))
        if not self.guion:
            raise AssertionError("conexión de más (la %d)" % len(self.conexiones))
        paso = self.guion.pop(0)
        if isinstance(paso, BaseException):
            raise paso
        if paso is not None:
            self.vista = paso
        return types.SimpleNamespace(close=lambda: None)

    def huella_vista(self, pid, max_edad=600):
        return self.vista if pid == "p001" else ""

    def _mk_send(self, s, palabras):
        self.enviado.append(palabras)

    def _mk_reply(self, s):
        if self.enviado and self.enviado[-1] == ["/system/resource/print"]:
            if isinstance(self.recurso, BaseException):
                raise self.recurso
            if self.recurso is None:
                return False, [["!trap", "=message=no such command"], ["!done"]], "no such command"
            return True, [["!re", "=uptime=3d", "=version=%s" % self.recurso[1],
                           "=board-name=%s" % self.recurso[0]], ["!done"]], ""
        return True, [["!re", "=name=%s" % self.nombre], ["!done"]], ""

    def _crear(self, pid, puerto):
        self.creados.append((pid, puerto))
        if isinstance(self.crear, BaseException):
            raise self.crear
        return self.crear


class ProbarApi(unittest.TestCase):
    def setUp(self):
        self.pw = _pw()

    def cerro(self, detalle="ADH:@SECLEVEL=0: EOF | DEFAULT:@SECLEVEL=0: EOF | cifrados por defecto: EOF"):
        return cerro(self.pw, detalle)

    def probar(self, d):
        return self.pw.probar_api(d, "p001")

    # ---- A1 ------------------------------------------------------------------------------------
    def test_sin_ssl_solo_confirma_la_conexion(self):
        """Con la casilla desmarcada solo se confirma la conexión y el mensaje dice por dónde (antes:
        «conexión OK con 'X'.», sin decirlo). Ni se mira el certificado ni se crea; si no conecta, el
        fallo tal cual."""
        d = NucleoFalso([None], tls="0", puerto="8728")
        ok, msg = self.probar(d)
        self.assertTrue(ok, msg)
        self.assertEqual(msg, "conexión OK con 'router-prueba' por la API normal (sin SSL, puerto 8728).")
        self.assertEqual([c["TLS"] for c in d.conexiones], ["0"])
        # (2026-10-20, el modal) y, en la misma conexión, el modelo y la versión de RouterOS
        self.assertEqual(d.enviado, [["/system/identity/print"], ["/system/resource/print"]])
        self.assertEqual(d.creados, [])
        e = IOError("no se pudo abrir el relé de la API del punto (API sin SSL, puerto 8728): conexión rechazada")
        d = NucleoFalso([e], tls="0", puerto="8728")
        self.assertEqual(self.probar(d), (False, "no conectó: " + str(e)))
        self.assertEqual(d.creados, [])

    # ---- A2 ------------------------------------------------------------------------------------
    def test_con_ssl_y_certificado_lo_confirma_sin_crear(self):
        d = NucleoFalso([FP])
        ok, msg = self.probar(d)
        self.assertTrue(ok, msg)
        self.assertEqual(msg, "conexión OK con 'router-prueba' por API-SSL (puerto 8729); certificado del router "
                              "%s… (puedes fijar su huella abajo)." % FP[:16])
        self.assertEqual(len(d.conexiones), 1)
        self.assertEqual(d.creados, [])
        # con su huella ya fijada, lo dice
        d = NucleoFalso([FP], cert_fp=FP)
        ok, msg = self.probar(d)
        self.assertTrue(ok, msg)
        self.assertIn("certificado del router %s… (es el de la huella fijada)." % FP[:16], msg)
        self.assertEqual(d.creados, [])

    # ---- A3 ------------------------------------------------------------------------------------
    def test_saludo_tls_cerrado_crea_el_certificado_y_vuelve_a_probar(self):
        """El router cierra la API-SSL sin contestar (RouterOS 7 sin certificado): se crea el certificado
        en SU puerto, una vez, y la segunda prueba va otra vez por API-SSL."""
        d = NucleoFalso([self.cerro(), FP], puerto="2291", crear=(True, CREADO % 2291))
        ok, msg = self.probar(d)
        self.assertTrue(ok, msg)
        self.assertEqual(d.creados, [("p001", 2291)])
        self.assertEqual([c["TLS"] for c in d.conexiones], ["1", "1"])
        self.assertEqual(msg, "El router no tenía certificado en la API-SSL: %s. Prueba: conexión OK con "
                              "'router-prueba' por API-SSL (puerto 2291); certificado del router %s… (puedes "
                              "fijar su huella abajo)." % (CREADO % 2291, FP[:16]))

    def test_si_la_segunda_prueba_falla_lo_dice_y_no_crea_otra_vez(self):
        e = IOError("TLS handshake falló — revisa en el MikroTik /ip service print detail where name=api-ssl. "
                    "Detalle de los 3 cifrados probados: ADH:@SECLEVEL=0: no shared cipher")
        d = NucleoFalso([e, e])
        ok, msg = self.probar(d)
        self.assertFalse(ok)
        self.assertEqual(d.creados, [("p001", 8729)])
        self.assertEqual(len(d.conexiones), 2)
        self.assertEqual(msg, "El router no tenía certificado en la API-SSL: %s. Prueba: no conectó: %s"
                         % (CREADO % 8729, e))

    def test_conecta_sin_certificado_lo_crea(self):
        """Conecta con el cifrado anónimo (el router no tiene certificado): con «Con certificado» se le
        crea y se vuelve a probar. Si tras crearlo sigue sin presentarlo, fallo con las órdenes y no se
        crea otra vez."""
        d = NucleoFalso([VACIO, FP])
        ok, msg = self.probar(d)
        self.assertTrue(ok, msg)
        self.assertEqual(d.creados, [("p001", 8729)])
        self.assertEqual(len(d.conexiones), 2)
        self.assertTrue(msg.startswith("El router no tenía certificado en la API-SSL: %s. Prueba: " % (CREADO % 8729)),
                        msg)
        self.assertIn("Prueba: conexión OK con 'router-prueba' por API-SSL (puerto 8729); certificado del router "
                      "%s…" % FP[:16], msg)
        d = NucleoFalso([VACIO, VACIO])
        ok, msg = self.probar(d)
        self.assertFalse(ok)
        self.assertEqual(d.creados, [("p001", 8729)])
        self.assertEqual(len(d.conexiones), 2)
        self.assertIn("Prueba: el MikroTik no presenta certificado en la API-SSL: ponle este: "
                      + self.pw.CMD_CERT_API_SSL, msg)

    # ---- A4 ------------------------------------------------------------------------------------
    def test_si_no_se_puede_crear_da_el_fallo_original_y_el_motivo(self):
        e = self.cerro(detalle="x" * 2000)          # detalle largo: el fallo conserva su tope de 600
        d = NucleoFalso([e], crear=(False, "no se pudo entrar por la API normal (8728): conexión rechazada"))
        ok, msg = self.probar(d)
        self.assertFalse(ok)
        self.assertEqual(d.creados, [("p001", 8729)])
        self.assertEqual(len(d.conexiones), 1)      # sin certificado nuevo no se vuelve a probar
        antes, sep, motivo = msg.partition(" — no se pudo crear el certificado: ")
        self.assertEqual(antes, "no conectó: " + str(e)[:600])
        self.assertIn(self.pw.CMD_CERT_API_SSL, antes)               # las órdenes para pegar siguen
        self.assertEqual(motivo, "no se pudo entrar por la API normal (8728): conexión rechazada")
        # si mk_crear_certificado revienta, lo mismo con su error
        d = NucleoFalso([self.cerro()], crear=OSError("relé cerrado"))
        ok, msg = self.probar(d)
        self.assertFalse(ok)
        self.assertTrue(msg.startswith("no conectó: el MikroTik cerró la API-SSL sin contestar"), msg)
        self.assertTrue(msg.endswith(" — no se pudo crear el certificado: relé cerrado"), msg)
        # conecta sin certificado y no se puede crear: fallo, con las órdenes delante
        d = NucleoFalso([VACIO], crear=(False, "motivo de prueba"))
        ok, msg = self.probar(d)
        self.assertFalse(ok)
        self.assertTrue(msg.startswith("el MikroTik no presenta certificado en la API-SSL: ponle este: "
                                       + self.pw.CMD_CERT_API_SSL), msg)
        self.assertTrue(msg.endswith(" — no se pudo crear el certificado: motivo de prueba"), msg)

    def test_nucleo_sin_crear_certificado_da_el_fallo_original(self):
        e = self.cerro()
        d = NucleoFalso([e], crear=None)
        ok, msg = self.probar(d)
        self.assertFalse(ok)
        self.assertEqual(len(d.conexiones), 1)
        self.assertEqual(msg, "no conectó: %s — no se pudo crear el certificado: este panel no sabe crearlo "
                              "(núcleo anterior)" % str(e)[:600])

    # ---- A5 ------------------------------------------------------------------------------------
    def test_con_la_casilla_y_el_8728_no_crea(self):
        """«Con certificado» con el puerto de la API normal: crearlo movería la API-SSL al 8728 del router."""
        e = IOError("TLS handshake falló — revisa en el MikroTik /ip service print detail where name=api-ssl")
        d = NucleoFalso([e], puerto="8728")
        ok, msg = self.probar(d)
        self.assertFalse(ok)
        self.assertEqual(d.creados, [])
        self.assertTrue(msg.startswith("no conectó: " + str(e)), msg)
        self.assertIn("no se creó el certificado: con «Con certificado» el puerto no puede ser el 8728", msg)

    # ---- A6 ------------------------------------------------------------------------------------
    def test_huella_distinta_u_otro_fallo_no_crea_nada(self):
        """Conservación: una huella distinta (no hubo /login), una huella fijada con el router sin
        certificado (el núcleo pide olvidarla) o un fallo que no es del saludo TLS: ningún certificado
        nuevo, una sola conexión y el fallo tal cual."""
        casos = [
            (HuellaNoConfirmada("el MikroTik de p001 presenta un certificado API-SSL distinto del confirmado "
                                "(confirmada 0000000000000000…, presenta %s…)" % FP[:16]), "00" * 32),
            (IOError("TLS handshake falló — este punto tiene fijada la huella de un certificado y el panel lo "
                     "exige: si le quitaste el certificado a la API-SSL del router, olvida la huella"), FP),
            (TimeoutError("timed out"), ""),
            (IOError("invalid user name or password (6)"), ""),
            (IOError("[Errno 2] No such file or directory"), ""),
        ]
        for e, fijada in casos:
            with self.subTest(fallo=str(e)[:40]):
                d = NucleoFalso([e], cert_fp=fijada)
                self.assertEqual(self.probar(d), (False, "no conectó: " + str(e)))
                self.assertEqual(d.creados, [])
                self.assertEqual(len(d.conexiones), 1)


# ---- A7: la ficha ------------------------------------------------------------------------------
class FichaAyuda(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")

    def test_la_ficha_explica_probar_y_no_da_las_ordenes_del_certificado(self):
        r = self.p.pedir("GET", "/puntos/p001", cookie=self.ana)
        self.assertEqual(r.status, 200, r.texto[:300])
        ini = r.texto.index("Puerto de la API en el MikroTik")
        api = r.texto[ini:r.texto.index("<div id=phuellabox", ini)]
        self.assertIn("«Probar la conexión» con <b>«Con certificado»</b> confirma la conexión y el certificado del "
                      "router y, si el router no tiene, lo crea (entra una vez por la API normal, 8728, que "
                      "RouterOS trae encendida)", api)
        self.assertIn("<b>sin certificado</b> solo confirma la conexión (la API normal se enciende con "
                      "<code>/ip service set api disabled=no</code>)", api)
        self.assertNotIn("/certificate add", api)
        self.assertNotIn("certificate=ids-api", api)


# ---- B1-B2: los datos del modal ------------------------------------------------------------------
OK_SSL = ("conexión OK con 'router-prueba' por API-SSL (puerto 8729); certificado del router %s… (puedes fijar "
          "su huella abajo)." % FP[:16])
TLS_FALLA = IOError("TLS handshake falló — revisa en el MikroTik /ip service print detail where name=api-ssl. "
                    "Detalle de los 3 cifrados probados: ADH:@SECLEVEL=0: no shared cipher")


class DatosDelModal(unittest.TestCase):
    def setUp(self):
        self.pw = _pw()
        self.punto = dict(PUNTO_VPN)
        m = mock.patch.object(self.pw.nodos, "punto", lambda pid: self.punto if pid == "p001" else None)
        m.start()
        self.addCleanup(m.stop)

    def detalle(self, d):
        return self.pw.probar_api_detalle(d, "p001")

    def test_ok_con_ssl_trae_router_modelo_conexion_y_certificado(self):
        d = NucleoFalso([FP])
        ok, msg, t = self.detalle(d)
        self.assertTrue(ok, msg)
        # la prueba es la de siempre: el mismo texto de probar_api y UNA conexión, que lee también el modelo
        self.assertEqual(msg, OK_SSL)
        self.assertEqual(len(d.conexiones), 1)
        self.assertEqual(d.enviado, [["/system/identity/print"], ["/system/resource/print"]])
        self.assertEqual(d.creados, [])
        self.assertEqual(t["titulo"], "Conexión correcta")
        self.assertEqual((t["router"], t["modelo"], t["version"]), ("router-prueba",) + RECURSO)
        self.assertEqual((t["conexion"], t["ssl"], t["puerto"], t["via"]),
                         ("API-SSL (con certificado)", True, 8729, "el túnel VPN del punto"))
        self.assertEqual(t["certificado"], {"huella": FP[:16], "fijada": False, "creado": "",
                                            "texto": "%s… · sin fijar: puedes fijar su huella abajo" % FP[:16]})
        self.assertEqual((t["usuario"], t["enviar"]), ("ids-api", True))
        self.assertEqual((t["que_hacer"], t["ordenes"], t["detalle"]), ("", "", ""))
        self.assertEqual(self.pw._texto_prueba(t),
                         "Conexión correcta. Router: «router-prueba» (RB5009UG+S+, RouterOS 7.16.2 (stable)). "
                         "Conexión: API-SSL (con certificado), puerto 8729, por el túnel VPN del punto. Certificado: "
                         "%s… · sin fijar: puedes fijar su huella abajo. Usuario de la API: ids-api; enviar IPs a la "
                         "cuarentena: permitido." % FP[:16])
        # con su huella fijada, lo dice
        _ok, _msg, t = self.detalle(NucleoFalso([FP], cert_fp=FP))
        self.assertTrue(t["certificado"]["fijada"])
        self.assertEqual(t["certificado"]["texto"], "%s… · es el de la huella fijada" % FP[:16])

    def test_sin_ssl_por_la_red_local(self):
        """Punto directo con la API normal: sin certificado, por la red local a la IP del MikroTik."""
        self.punto = dict(PUNTO_DIRECTO)
        d = NucleoFalso([None], tls="0", puerto="8728")
        d.router["ENABLED"] = "0"
        ok, msg, t = self.detalle(d)
        self.assertTrue(ok, msg)
        self.assertEqual(msg, "conexión OK con 'router-prueba' por la API normal (sin SSL, puerto 8728).")
        self.assertEqual((t["conexion"], t["ssl"], t["puerto"], t["via"], t["certificado"]),
                         ("API normal (sin SSL)", False, 8728, "la red local, directo a 192.0.2.10", None))
        self.assertFalse(t["enviar"])
        self.assertIn("enviar IPs a la cuarentena: no permitido.", self.pw._texto_prueba(t))

    def test_si_no_se_lee_el_modelo_la_prueba_no_cambia(self):
        for recurso in (IOError("se cortó la conexión"), None):
            with self.subTest(recurso=recurso):
                d = NucleoFalso([FP], recurso=recurso)
                ok, msg, t = self.detalle(d)
                self.assertTrue(ok, msg)
                self.assertEqual(msg, OK_SSL)
                self.assertEqual((t["router"], t["modelo"], t["version"]), ("router-prueba", "", ""))
                self.assertEqual(len(d.conexiones), 1)
                self.assertTrue(self.pw._texto_prueba(t).startswith(
                    "Conexión correcta. Router: «router-prueba». Conexión: "), self.pw._texto_prueba(t))

    def test_certificado_creado_ahora(self):
        d = NucleoFalso([cerro(self.pw), FP])
        ok, msg, t = self.detalle(d)
        self.assertTrue(ok, msg)
        self.assertEqual(d.creados, [("p001", 8729)])
        self.assertEqual(t["titulo"], "Conexión correcta: certificado creado")
        self.assertEqual(t["certificado"]["creado"], CREADO % 8729)
        self.assertEqual(t["certificado"]["texto"], "creado ahora: ids-api (%s); su huella empieza por %s…: puedes "
                                                    "fijarla abajo" % (CREADO % 8729, FP[:16]))
        # si el router ya lo tenía, el núcleo solo lo asigna: lo dice así
        ya = "el certificado ids-api ya estaba; asignado a la API-SSL en el puerto 8729"
        _ok, _msg, t = self.detalle(NucleoFalso([VACIO, FP], crear=(True, ya)))
        self.assertEqual(t["titulo"], "Conexión correcta: certificado asignado")
        self.assertTrue(t["certificado"]["texto"].startswith("asignado ahora: ids-api (%s)" % ya), t)

    def test_si_falla_primero_que_hacer_luego_ordenes_y_detalle(self):
        cert = "\n".join(x.strip() for x in self.pw.CMD_CERT_API_SSL.split(";"))
        hnc = HuellaNoConfirmada("el MikroTik de p001 presenta un certificado API-SSL distinto del confirmado "
                                 "(confirmada 0000000000000000…, presenta %s…)" % FP[:16])
        casos = [
            ("clave mala", NucleoFalso([IOError("invalid user name or password (6)")]), "No conectó",
             "El MikroTik rechazó el usuario o la clave", "/user print"),
            ("sin certificado y no se pudo crear", NucleoFalso([cerro(self.pw)], crear=(False, "motivo de prueba")),
             "No conectó: no se pudo crear el certificado", "Ponle el certificado a la API-SSL pegando estas órdenes",
             cert),
            ("router caído", NucleoFalso([TimeoutError("timed out")]), "No conectó",
             "El MikroTik no contestó a tiempo: comprueba en el Resumen que su VPN está conectada y, en el router, "
             "que el servicio api-ssl esté encendido en el puerto 8729 y que su address esté vacía o incluya la IP "
             "del sensor (100.64.1.1).", "/ip service print detail where name=api-ssl"),
            ("creado y sigue sin conectar", NucleoFalso([cerro(self.pw), TLS_FALLA]),
             "Certificado creado, pero no conectó", "El panel ya le puso el certificado ids-api",
             self.pw.CMD_SERVICIO_API),
            ("huella distinta", NucleoFalso([hnc], cert_fp="00" * 32), "No conectó",
             "El router presenta otro certificado que el de la huella fijada",
             "%s\n%s" % (self.pw.CMD_SERVICIO_API, self.pw.CMD_HUELLA_ROUTER)),
            ("casilla con el 8728", NucleoFalso([TLS_FALLA], puerto="8728"), "No conectó",
             "Con «Con certificado» el puerto tiene que ser el de la API-SSL", ""),
            ("relé sin abrir", NucleoFalso([IOError("no se pudo abrir el relé de la API del punto (API sin SSL, "
                                                    "puerto 8728): conexión rechazada")], tls="0", puerto="8728"),
             "No conectó", "El panel no pudo abrir el relé de la API del punto", ""),
        ]
        for nombre, d, titulo, que, ordenes in casos:
            with self.subTest(caso=nombre):
                ok, msg, t = self.detalle(d)
                self.assertFalse(ok)
                self.assertEqual(t["titulo"], titulo)
                self.assertTrue(t["que_hacer"].startswith(que), t["que_hacer"])
                self.assertEqual(t["ordenes"], ordenes)
                self.assertEqual(t["detalle"], msg)               # el fallo de siempre, entero
                txt = self.pw._texto_prueba(t)
                self.assertTrue(txt.startswith("%s. Qué hacer: %s" % (titulo, t["que_hacer"])), txt)
                self.assertTrue(txt.endswith(" Detalle: " + msg), txt)
                self.assertNotIn("clave-api", json.dumps(t) + txt)
        # sin usuario o clave: no se conecta y se dice que se escriban
        d = NucleoFalso([])
        d.router["PASS"] = ""
        ok, msg, t = self.detalle(d)
        self.assertFalse(ok)
        self.assertEqual(t["titulo"], "Falta el usuario o la clave")
        self.assertTrue(t["que_hacer"].startswith("Escribe el usuario y la clave de la API"), t)
        self.assertEqual(d.conexiones, [])

    def test_directo_caido_dice_que_mire_la_red_local(self):
        self.punto = dict(PUNTO_DIRECTO)
        _ok, _msg, t = self.detalle(NucleoFalso([TimeoutError("timed out")], tls="0", puerto="8728"))
        self.assertTrue(t["que_hacer"].startswith("El MikroTik no contestó a tiempo: comprueba que el servidor "
                                                  "llega a 192.0.2.10 por la red local"), t["que_hacer"])
        self.assertEqual(t["ordenes"], "/ip service print detail where name=api\n/ip service set api disabled=no")

    def test_nunca_la_clave(self):
        for d in (NucleoFalso([FP]), NucleoFalso([cerro(self.pw)], crear=(False, "motivo"))):
            _ok, _msg, t = self.detalle(d)
            self.assertNotIn("clave-api", json.dumps(t) + self.pw._texto_prueba(t))
            self.assertNotIn("PASS", json.dumps(t))


# ---- B3: por HTTP --------------------------------------------------------------------------------
class ModalPorHttp(unittest.TestCase):
    """El panel de verdad (orquestador falso) con el router sustituido en el núcleo: mk_conectar según
    un guion, _mk_send/_mk_reply, huella_vista y mk_crear_certificado."""

    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")
        d = self.p.d
        self.guion, self.vista, self.enviado, self.creados = [], [""], [], []
        self.nombre, self.crear = "router-prueba", (True, CREADO % 8729)

        def conectar(m, timeout=6, rele=None):
            paso = self.guion.pop(0)
            if isinstance(paso, BaseException):
                raise paso
            if paso is not None:
                self.vista[0] = paso
            return types.SimpleNamespace(close=lambda: None, settimeout=lambda t: None)

        def responder(s):
            if self.enviado[-1] == ["/system/resource/print"]:
                return True, [["!re", "=version=%s" % RECURSO[1], "=board-name=%s" % RECURSO[0]], ["!done"]], ""
            return True, [["!re", "=name=%s" % self.nombre], ["!done"]], ""

        def crear(pid, puerto, **k):
            self.creados.append((pid, puerto))
            return self.crear
        d.mk_conectar = conectar
        d._mk_send = lambda s, palabras: self.enviado.append(palabras)
        d._mk_reply = responder
        d.huella_vista = lambda pid, max_edad=600: self.vista[0]
        d.mk_crear_certificado = crear

    def ficha(self):
        r = self.p.pedir("GET", "/puntos/p001", cookie=self.ana)
        self.assertEqual(r.status, 200, r.texto[:300])
        return r.texto

    def probar(self, ajax=True):
        form = {"accion": "probar", "user": "ids-api", "pass": "clave-api", "api_puerto": "8729", "tls": "1",
                "enabled": "1", "op": token_de(self.ficha(), "papiProbar")}
        if ajax:
            form["ajax"] = "1"
        r = self.p.pedir("POST", "/puntos/p001/api", form, cookie=self.ana)
        return r, (json.loads(r.texto) if ajax else None)

    def test_el_json_trae_los_datos_y_el_mensaje_en_texto(self):
        self.guion = [FP]
        r, j = self.probar()
        self.assertEqual(r.status, 200, r.texto[:300])
        self.assertTrue(j["ok"])
        t = j["prueba"]
        self.assertEqual(t["titulo"], "Conexión correcta")
        self.assertEqual((t["router"], t["modelo"], t["version"]), ("router-prueba",) + RECURSO)
        self.assertEqual((t["conexion"], t["puerto"], t["via"]), ("API-SSL (con certificado)", 8729,
                                                                  "el túnel VPN del punto"))
        self.assertEqual((t["certificado"]["huella"], t["certificado"]["fijada"]), (FP[:16], False))
        self.assertEqual((t["usuario"], t["enviar"]), ("ids-api", True))
        self.assertEqual(j["mensaje"], "Conexión correcta. Router: «router-prueba» (RB5009UG+S+, RouterOS 7.16.2 "
                                       "(stable)). Conexión: API-SSL (con certificado), puerto 8729, por el túnel "
                                       "VPN del punto. Certificado: %s… · sin fijar: puedes fijar su huella abajo. "
                                       "Usuario de la API: ids-api; enviar IPs a la cuarentena: permitido." % FP[:16])
        self.assertRegex(j["token"], r"^[0-9a-f-]{36}$")
        self.assertNotIn("clave-api", r.texto)

    def test_con_el_certificado_creado_prueba_no_sale_dos_veces(self):
        """Corrección de defecto: accion_api anteponía «Prueba: » al texto de probar_api, que con el
        certificado recién creado ya traía otro («Prueba: El router no tenía certificado…. Prueba: …»)."""
        self.guion = [cerro(self.p.pw), FP]
        r, j = self.probar()
        self.assertTrue(j["ok"], j)
        self.assertEqual(self.creados, [("p001", 8729)])
        self.assertEqual(j["prueba"]["titulo"], "Conexión correcta: certificado creado")
        self.assertEqual(j["prueba"]["certificado"]["creado"], CREADO % 8729)
        self.assertTrue(j["mensaje"].startswith("Conexión correcta: certificado creado. Router: «router-prueba»"),
                        j["mensaje"])
        self.assertNotIn("Prueba: ", j["mensaje"])
        # y si la segunda prueba falla, una sola vez (la del detalle)
        self.guion = [cerro(self.p.pw), TLS_FALLA]
        r, j = self.probar()
        self.assertEqual(r.status, 502, r.texto[:300])
        self.assertEqual(j["prueba"]["titulo"], "Certificado creado, pero no conectó")
        self.assertEqual(j["mensaje"].count("Prueba: "), 1, j["mensaje"])

    def test_si_falla_el_mensaje_empieza_por_que_hacer(self):
        self.guion = [IOError("invalid user name or password (6)")]
        r, j = self.probar()
        self.assertEqual(r.status, 502, r.texto[:300])
        self.assertFalse(j["ok"])
        t = j["prueba"]
        self.assertEqual(t["titulo"], "No conectó")
        self.assertTrue(t["que_hacer"].startswith("El MikroTik rechazó el usuario o la clave"), t)
        self.assertEqual(t["detalle"], "no conectó: invalid user name or password (6)")
        m = j["mensaje"]
        self.assertTrue(m.startswith("No conectó. Qué hacer: El MikroTik rechazó el usuario o la clave"), m)
        self.assertLess(m.index("Qué hacer"), m.index("Detalle: no conectó: invalid user name or password"))
        self.assertNotIn("clave-api", r.texto)

    def test_un_nombre_de_router_con_script_sale_escapado(self):
        self.nombre = "<script>alert(1)</script>"
        self.guion = [FP]
        _r, j = self.probar()
        self.assertEqual(j["prueba"]["router"], self.nombre)       # en el JSON es un dato: lo escapa quien lo pinta
        # el JS del modal pasa por pjEsc TODO lo que viene del router o del servidor antes de meterlo en el HTML
        h = self.ficha()
        self.assertIn("papiModal(j)", h)
        ini = h.index("function papiModal(")
        js = h[ini:h.index("\nfunction ", ini)]
        for campo in ("p.router", "p.modelo", "p.version", "p.conexion", "p.puerto", "p.via", "p.usuario",
                      "p.que_hacer", "p.ordenes", "p.detalle", "c.texto"):
            with self.subTest(campo=campo):
                usos = len(re.findall(r"\b%s\b" % re.escape(campo), js))
                self.assertGreater(usos, 0)
                self.assertEqual(js.count("pjEsc(%s)" % campo), usos)
        # si falla, qué hacer va delante de las órdenes y del detalle técnico
        self.assertLess(js.index("Qué hacer"), js.index("<pre class=cmd"))
        self.assertLess(js.index("<pre class=cmd"), js.index("Detalle técnico"))
        # sin JavaScript (formulario normal): el texto en el aviso de la ficha, escapado
        self.guion = [FP]
        r, _j = self.probar(ajax=False)
        self.assertEqual(r.status, 200, r.texto[:300])
        self.assertIn("Router: «&lt;script&gt;alert(1)&lt;/script&gt;»", r.texto)
        self.assertNotIn("<script>alert(1)", r.texto)


# ---- B4: el JS de verdad, con node ---------------------------------------------------------------
ARNES = r"""
const JS = %s;
global.document = {getElementById: () => null, addEventListener() {}};
eval(JS.replace(/^<script>|<\/script>$/g, ''));
process.stdout.write(JSON.stringify(%s.map((j) => papiModal(j))));
"""


@unittest.skipUnless(shutil.which("node"), "sin node")
class ModalJs(unittest.TestCase):
    """papiModal (en _JS_TRABAJOS) con los datos de verdad de probar_api_detalle."""

    @classmethod
    def setUpClass(cls):
        pw = _pw()
        with mock.patch.object(pw.nodos, "punto", lambda pid: dict(PUNTO_VPN)):
            _ok, _msg, bien = pw.probar_api_detalle(NucleoFalso([FP], nombre="<script>alert(1)</script>"), "p001")
            _ok, _msg, mal = pw.probar_api_detalle(
                NucleoFalso([cerro(pw)], crear=(False, "<img src=x onerror=alert(1)>")), "p001")
        cls.cmd = pw.CMD_CERT_API_SSL
        casos = [{"ok": True, "prueba": bien}, {"ok": False, "prueba": mal}, {"ok": False, "mensaje": "<b>m</b>"}]
        r = subprocess.run(["node", "-e", ARNES % (json.dumps(pw._JS_TRABAJOS), json.dumps(casos))],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise AssertionError(r.stderr)
        cls.bien, cls.mal, cls.sin = json.loads(r.stdout)

    def test_ok_tabla_con_todo_escapado(self):
        h = self.bien
        self.assertTrue(h.startswith("<table class=papi>"), h)
        self.assertIn("<b>&lt;script&gt;alert(1)&lt;/script&gt;</b> · RB5009UG+S+ · RouterOS 7.16.2 (stable)", h)
        self.assertNotIn("<script>", h)
        for x in ("API-SSL (con certificado), puerto 8729", "el túnel VPN del punto", FP[:16], "ids-api",
                  "Enviar a cuarentena</th><td>permitido"):
            self.assertIn(x, h)

    def test_fallo_que_hacer_ordenes_y_detalle_en_ese_orden(self):
        h = self.mal
        self.assertTrue(h.startswith("<p class=papiqh><b>Qué hacer:</b> Ponle el certificado"), h)
        lineas = "\n".join(x.strip() for x in self.cmd.split(";"))
        self.assertIn("<pre class=cmd id=papiord>%s</pre>" % lineas, h)
        self.assertLess(h.index("<pre class=cmd"), h.index("Detalle técnico"))
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", h)
        self.assertNotIn("<img", h)

    def test_sin_datos_el_mensaje_escapado(self):
        self.assertEqual(self.sin, "<p>&lt;b&gt;m&lt;/b&gt;</p>")


if __name__ == "__main__":
    unittest.main()
