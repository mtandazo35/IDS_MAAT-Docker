"""«Probar la conexión» con «Con certificado (API-SSL)» crea el certificado del router (el dueño, 2026-10-20).

Hay RouterOS 7 que cierran la API-SSL sin certificado. dashboard.mk_crear_certificado entra UNA vez por la
API normal (8728) por el relé fijo del punto (nodos.api_sock_claro, api-claro.sock) con el usuario de
ids-api y, si el router no tiene el certificado ids-api, lo crea, lo firma y lo asigna a la API-SSL; si ya
estaba, solo lo asigna. El /login sigue estando solo en mk_conectar (guarda estructural de
test_panel_huella_api), que admite ese relé y ningún otro.

- C1 Sin certificado: /login, /certificate/print, /certificate/add (con sus parámetros), /certificate/sign
  (esperando `timeout`, con !re de progreso) y /ip/service/set (puerto y certificado), en ese orden y por
  el relé de la API normal; ok, y una línea en el Registro sin la clave.
- C2 Con el certificado ya presente: ni add ni sign, solo se asigna. Uno que el router da sin firmar (una
  firma cortada a medias) se firma sin volver a crearlo.
- C3 Sin el relé api-claro (contenedor vpn de una versión anterior): (False) con las órdenes para pegar,
  sin abrir nada.
- C4 Un !trap del router: (False) con su mensaje y no sigue; un login rechazado: «no se pudo entrar por la
  API normal (8728)», sin la clave.
- C5 mk_conectar con un `rele` que no es el de la API normal de ESE punto (o con API-SSL): ValueError, sin
  abrir nada.
- C6 Documentación.

Tipo «capacidad nueva»: cada una falla sin el cambio. Sin red: el router es un hilo que lee con _mk_read y
contesta con _mk_send por un socket.socketpair (como test_panel_huella_api).
"""
import os
import socket
import sys
import tempfile
import threading
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(TESTS, "fixtures", "panel2"))
import _dash  # noqa: E402

ADD = ["/certificate/add", "=name=ids-api", "=common-name=ids-api", "=days-valid=3650", "=trusted=yes",
       "=key-usage=key-cert-sign,crl-sign,digital-signature,key-encipherment,tls-server"]
CERT_FIRMADO = ["!re", "=.id=*1", "=name=ids-api", "=common-name=ids-api", "=private-key=true", "=trusted=true"]


class RouterClaro:
    """La API normal de RouterOS, de mentira: apunta cada sentencia y contesta con las de `respuestas`
    para esa orden (por defecto, !done)."""

    def __init__(self, d):
        self.d = d
        self.respuestas = {}
        self.recibido = []

    def atender(self, b):
        def servir():
            try:
                while True:
                    w = self.d._mk_read(b)
                    if not w:
                        continue
                    self.recibido.append(w)
                    for frase in self.respuestas.get(w[0], [["!done"]]):
                        self.d._mk_send(b, frase)
            except (IOError, OSError, IndexError):
                pass
            finally:
                b.close()
        threading.Thread(target=servir, daemon=True).start()

    def ordenes(self):
        return [w[0] for w in self.recibido]


class _Sock:
    """El socket del panel, apuntando los settimeout (la firma espera más que el resto)."""

    def __init__(self, s, tiempos):
        self._s, self._t = s, tiempos

    def settimeout(self, t):
        self._t.append(t)
        self._s.settimeout(t)

    def __getattr__(self, n):
        return getattr(self._s, n)


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = _dash.Arbol(self.tmp.name)
        self.d = _dash.cargar(self.a)
        self.n = self.d.nodos
        self.n.asegurar_dirs()
        self.d.guardar_routers([{"id": "p001", "USER": "ids-api", "PASS": "clave-api-1", "ENABLED": "1"},
                                {"id": "p002", "USER": "ids-api", "PASS": "clave-api-2", "ENABLED": "1"}])
        self.router = RouterClaro(self.d)
        self.abiertos, self.tiempos = [], []

        def abrir(ruta, timeout):
            self.abiertos.append(ruta)
            a, b = socket.socketpair()
            a.settimeout(timeout)
            self.router.atender(b)
            return _Sock(a, self.tiempos)

        def sin_tls(*a, **k):
            raise AssertionError("por la API normal no se intenta TLS")
        self.d._mk_abrir_unix = abrir
        self.d._mk_tls_wrap = sin_tls

    def tearDown(self):
        self.n.quitar_nodo()
        _dash.restaurar()
        self.tmp.cleanup()

    def rele_claro(self, pid="p001"):
        """El relé de la API normal que pone el contenedor vpn (aquí, un fichero: basta con que exista)."""
        ruta = self.n.api_sock_claro(pid)
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        open(ruta, "w").close()
        return ruta

    def bitacora(self):
        try:
            with open(self.d.BITACORA_LOG, encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""


class CrearCertificado(_Base):
    def test_sin_certificado_lo_crea_lo_firma_y_lo_asigna(self):
        ruta = self.rele_claro()
        self.assertEqual(ruta, os.path.join(self.n.RUN, "p001", "api-claro.sock"))
        # la firma tarda: RouterOS manda !re de progreso antes del !done
        self.router.respuestas["/certificate/sign"] = [["!re", "=progress=calculando la clave"],
                                                      ["!re", "=progress=firmando"], ["!done"]]
        ok, msg = self.d.mk_crear_certificado("p001", 8729, timeout=90, quien="ana")
        self.assertTrue(ok, msg)
        self.assertEqual(msg, "creado y firmado el certificado ids-api y asignado a la API-SSL en el puerto 8729")
        self.assertEqual(self.abiertos, [ruta])                     # una sola vez y por la API normal
        self.assertEqual(self.router.ordenes(), ["/login", "/certificate/print", "/certificate/add",
                                                 "/certificate/sign", "/ip/service/set"])
        login, consulta, add, firma, servicio = self.router.recibido
        self.assertEqual(login, ["/login", "=name=ids-api", "=password=clave-api-1"])
        self.assertIn("?name=ids-api", consulta)
        self.assertEqual(sorted(add), sorted(ADD))
        self.assertIn("=number=ids-api", firma)
        self.assertEqual(sorted(servicio[1:]), sorted(["=numbers=api-ssl", "=certificate=ids-api", "=port=8729",
                                                       "=disabled=no"]))
        self.assertIn(90, self.tiempos)                             # la firma espera `timeout`
        lineas = [x for x in self.bitacora().splitlines() if "\tMK-API-SSL\t" in x]
        self.assertEqual(len(lineas), 1, lineas)
        self.assertIn("\tana\t", lineas[0])
        self.assertIn("p001: creado y firmado el certificado ids-api", lineas[0])
        self.assertNotIn("clave-api-1", self.bitacora() + msg)

    def test_ya_presente_ni_add_ni_sign(self):
        self.rele_claro()
        self.router.respuestas["/certificate/print"] = [CERT_FIRMADO, ["!done"]]
        ok, msg = self.d.mk_crear_certificado("p001", "2290")
        self.assertTrue(ok, msg)
        self.assertEqual(msg, "el certificado ids-api ya estaba; asignado a la API-SSL en el puerto 2290")
        self.assertEqual(self.router.ordenes(), ["/login", "/certificate/print", "/ip/service/set"])
        self.assertIn("=port=2290", self.router.recibido[-1])
        self.assertIn("=certificate=ids-api", self.router.recibido[-1])

    def test_presente_sin_firmar_se_firma_sin_volver_a_crearlo(self):
        self.rele_claro()
        sin_firmar = [w.replace("=private-key=true", "=private-key=false") for w in CERT_FIRMADO]
        self.router.respuestas["/certificate/print"] = [sin_firmar, ["!done"]]
        ok, msg = self.d.mk_crear_certificado("p001", 8729)
        self.assertTrue(ok, msg)
        self.assertIn("sin firmar: firmado y asignado", msg)
        self.assertEqual(self.router.ordenes(), ["/login", "/certificate/print", "/certificate/sign",
                                                 "/ip/service/set"])

    def test_sin_rele_de_la_api_normal_da_las_ordenes_y_no_abre_nada(self):
        """Un contenedor vpn de antes no tiene api-claro.sock: se dice cómo seguir y no se intenta nada."""
        ok, msg = self.d.mk_crear_certificado("p001", 8729)
        self.assertFalse(ok)
        self.assertIn("versión anterior", msg)
        self.assertIn("install.sh", msg)
        self.assertIn(self.d.CMD_CERT_API_SSL, msg)
        self.assertEqual(self.abiertos, [])
        self.assertEqual(self.router.recibido, [])

    def test_trap_del_router_da_su_mensaje_y_no_sigue(self):
        self.rele_claro()
        casos = (("/certificate/add", "not enough permissions (9)",
                  "no se pudo crear el certificado ids-api: not enough permissions (9)",
                  ["/login", "/certificate/print", "/certificate/add"]),
                 ("/ip/service/set", "failure: certificate not found",
                  "no se pudo asignar el certificado ids-api a la API-SSL: failure: certificate not found",
                  ["/login", "/certificate/print", "/certificate/add", "/certificate/sign", "/ip/service/set"]))
        for orden, motivo, esperado, ordenes in casos:
            with self.subTest(orden=orden):
                self.router.recibido = []
                self.router.respuestas = {orden: [["!trap", "=message=" + motivo], ["!done"]]}
                ok, msg = self.d.mk_crear_certificado("p001", 8729)
                self.assertFalse(ok)
                self.assertEqual(msg, esperado)
                self.assertEqual(self.router.ordenes(), ordenes)
        # en el Registro, como fallo (_registro_tipo)
        self.assertRegex(self.bitacora(), r"\tMK-API-SSL-FALLO\tp001: no se pudo asignar el certificado")
        self.assertTrue(self.d._registro_tipo("MK-API-SSL-FALLO")[1])

    def test_login_rechazado_no_se_pudo_entrar_sin_la_clave(self):
        self.rele_claro()
        self.router.respuestas["/login"] = [["!trap", "=message=invalid user name or password (6)"], ["!done"]]
        ok, msg = self.d.mk_crear_certificado("p001", 8729)
        self.assertFalse(ok)
        self.assertTrue(msg.startswith("no se pudo entrar por la API normal (8728): "), msg)
        self.assertIn("invalid user name or password (6)", msg)
        self.assertEqual(self.router.ordenes(), ["/login"])
        self.assertNotIn("clave-api-1", msg + self.bitacora())

    def test_sin_usuario_o_con_un_puerto_que_no_vale_no_abre_nada(self):
        self.rele_claro("p002")
        self.d.guardar_routers([{"id": "p002", "USER": "", "PASS": ""}])
        ok, msg = self.d.mk_crear_certificado("p002", 8729)
        self.assertFalse(ok)
        self.assertIn("Falta usuario o clave", msg)
        self.rele_claro("p001")
        for puerto in (8728, 0, 70000, "no-es"):          # 8728: la API-SSL encima de la API normal
            with self.subTest(puerto=puerto):
                ok, msg = self.d.mk_crear_certificado("p001", puerto)
                self.assertFalse(ok)
                self.assertIn("puerto" if puerto != 8728 else "8728", msg)
        self.assertEqual(self.abiertos, [])
        with self.assertRaises(self.n.NodoInvalido):        # destino validado, como mk_probar
            self.d.mk_crear_certificado("../p001", 8729)


class ReleAdmitido(_Base):
    def test_mk_conectar_solo_admite_el_rele_de_la_api_normal_del_punto(self):
        d = self.d.cargar_mk_de(self.d.router_por_id("p001"))
        claro = dict(d, TLS="0", PORT="8728")
        for rele in (self.n.api_sock_claro("p002"), self.n.api_sock("p001"),
                     os.path.join(self.tmp.name, "otro.sock"), self.n.api_sock_claro("p001") + "x", ""):
            with self.subTest(rele=rele), self.assertRaises(ValueError):
                self.d.mk_conectar(claro, rele=rele)
        with self.assertRaises(ValueError):                         # el suyo, pero con API-SSL: tampoco
            self.d.mk_conectar(dict(d, TLS="1"), rele=self.n.api_sock_claro("p001"))
        self.assertEqual(self.abiertos, [])
        self.assertEqual(self.router.recibido, [])
        # el de la API normal de ese punto sí: /login por ese relé
        self.d.mk_conectar(claro, rele=self.n.api_sock_claro("p001")).close()
        self.assertEqual(self.abiertos, [self.n.api_sock_claro("p001")])
        self.assertEqual(self.router.ordenes(), ["/login"])


class Documentacion(_Base):
    def test_documentacion(self):
        doc = self.d.documentacion_page(pagina="todo")
        for txt in ("confirma la conexión y el certificado", "el panel <b>lo crea</b> entrando una vez por la",
                    "(8728, que RouterOS trae encendida)", "Sin la casilla solo confirma la conexión",
                    "el aviso dice el motivo y da las órdenes para pegar",
                    "/ip service set api-ssl certificate=ids-api disabled=no"):
            self.assertIn(txt, doc, txt)


if __name__ == "__main__":
    unittest.main()
