"""Núcleo del panel (N): un router por punto, secretos cifrados, API por el relé AF_UNIX con
TLS y huella TOFU por punto, destino de cada acción (CONTRATO-F2 §4, §10.1, §10.3).
"""
import datetime as dt
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
import _dash  # noqa: E402


def certificado(dirx):
    """Certificado autofirmado de prueba (como el de RouterOS) -> (cert.pem, key.pem)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    k = ec.generate_private_key(ec.SECP256R1())
    nom = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ids-promax")])
    ahora = dt.datetime.now(dt.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(nom).issuer_name(nom).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(ahora - dt.timedelta(days=1))
         .not_valid_after(ahora + dt.timedelta(days=30)).sign(k, hashes.SHA256()))
    pc, pk = os.path.join(dirx, "cert.pem"), os.path.join(dirx, "key.pem")
    with open(pc, "wb") as f:
        f.write(c.public_bytes(serialization.Encoding.PEM))
    with open(pk, "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))
    return pc, pk, c.public_bytes(serialization.Encoding.DER)


class RouterOSFalso:
    """API de RouterOS de mentira sobre TLS: contesta !done a todo y apunta lo que recibe."""

    def __init__(self, d, cert, key):
        self.d = d
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.recibido = []
        self.hilos = []

    def atender(self, sock):
        def _run():
            try:
                s = self.ctx.wrap_socket(sock, server_side=True)
            except (ssl.SSLError, OSError):
                sock.close()
                return
            try:
                while True:
                    w = self.d._mk_read(s)
                    self.recibido.append(w)
                    self.d._mk_send(s, ["!done"])
            except (IOError, OSError, IndexError):
                pass
            finally:
                try:
                    s.close()
                except OSError:
                    pass
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        self.hilos.append(t)


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


class RoutersSonPuntos(Base):
    def test_un_router_por_punto(self):
        """Tipo: capacidad nueva. cargar_routers() = un router por punto, en orden, con
        id = iface = pid, HOST unix:<api.sock> y PORT = api_puerto; sin «router por defecto»."""
        rs = self.d.cargar_routers()
        self.assertEqual([(r["id"], r["iface"], r["nombre"]) for r in rs],
                         [("p001", "p001", "norte"), ("p002", "p002", "sur")])
        self.assertEqual(rs[1]["HOST"], "unix:" + self.n.api_sock("p002"))
        self.assertEqual((rs[0]["PORT"], rs[0]["TLS"], rs[0]["ENABLED"]), ("8729", "1", "0"))

    def test_secreto_guardado_cifrado(self):
        """Tipo: capacidad nueva (§10.3). La clave de la API va cifrada en routers.json
        (asociada a su punto), se lee en claro en memoria, y copiarla a otro punto no vale."""
        self.d.guardar_routers([{"id": "p002", "USER": "ids-api", "PASS": "clave-de-prueba-1", "ENABLED": "1"}])
        txt = open(self.d.ROUTERS_CONF, encoding="utf-8").read()
        self.assertNotIn("clave-de-prueba-1", txt)
        g = json.loads(txt)["routers"]
        self.assertTrue(g["p002"]["PASS"].startswith("enc1:"))
        self.assertNotIn("p001", g)
        self.assertEqual(self.d.router_por_id("p002")["PASS"], "clave-de-prueba-1")
        # el texto cifrado de p002 copiado a p001 no se puede usar alli
        g["p001"] = dict(g["p002"])
        with open(self.d.ROUTERS_CONF, "w", encoding="utf-8") as f:
            json.dump({"routers": g}, f)
        r1 = self.d.router_por_id("p001")
        self.assertEqual(r1["PASS"], "")
        self.assertEqual(r1.get("_PASS_ILEGIBLE"), "1")
        self.assertIn("router:p001:PASS", self.d.SECRETOS_AVISO)
        # guardar sin tocar la clave ilegible no la borra
        self.d.guardar_routers([dict(r1, LIST="otra-lista")])
        self.assertEqual(json.load(open(self.d.ROUTERS_CONF, encoding="utf-8"))["routers"]["p001"]["PASS"],
                         g["p002"]["PASS"])

    def test_clave_vieja_en_claro_se_cifra(self):
        """Tipo: corrección de defecto. Una clave en claro (configuracion vieja) se acepta y
        al guardar (o al arrancar, migrar_secretos) queda cifrada."""
        with open(self.d.ROUTERS_CONF, "w", encoding="utf-8") as f:
            json.dump({"routers": {"p001": {"USER": "ids-api", "PASS": "vieja-en-claro"}}}, f)
        self.assertEqual(self.d.router_por_id("p001")["PASS"], "vieja-en-claro")
        self.assertGreaterEqual(self.d.migrar_secretos(), 1)
        txt = open(self.d.ROUTERS_CONF, encoding="utf-8").read()
        self.assertNotIn("vieja-en-claro", txt)
        self.assertEqual(self.d.router_por_id("p001")["PASS"], "vieja-en-claro")

    def test_sin_clave_maestra_no_se_guarda_en_claro(self):
        """Tipo: capacidad nueva. Sin clave maestra el panel no escribe el secreto (ni en
        claro) y lo dice; lo ya guardado no se borra."""
        self.d.guardar_routers([{"id": "p001", "USER": "u", "PASS": "secreto-1"}])
        os.remove(self.a.clave)
        self.d.secretos._cache.update(ruta=None, clave=None)
        with self.assertRaises(self.d.secretos.SecretoNoDisponible):
            self.d.guardar_routers([{"id": "p002", "USER": "u", "PASS": "secreto-2"}])
        self.assertNotIn("secreto-2", open(self.d.ROUTERS_CONF, encoding="utf-8").read())
        self.assertFalse(self.d._feeds_conf_set("ABUSEIPDB_KEY", "clave-feeds"))
        self.assertFalse(os.path.exists(self.d.FEEDS_CONF) and "clave-feeds" in open(self.d.FEEDS_CONF).read())
        self.assertTrue(json.load(open(self.d.ROUTERS_CONF, encoding="utf-8"))["routers"]["p001"]["PASS"])

    def test_claves_de_feeds_ia_y_telegram_cifradas(self):
        """Tipo: capacidad nueva (§10.3). Las claves de AbuseIPDB/abuse.ch/Groq y el token
        de Telegram van cifrados; el panel los usa en claro."""
        self.assertTrue(self.d.aidb_set("clave-aidb-1"))
        self.assertTrue(self.d.groq_set("clave-groq-1"))
        self.assertTrue(self.d.feeds_auth_set("clave-abusech-1"))
        self.d.telegram_set(token="123:tok-1", chat="-100")
        for f in (self.d.FEEDS_CONF, self.d.REPORT_CONF):
            txt = open(f, encoding="utf-8").read()
            for s in ("clave-aidb-1", "clave-groq-1", "clave-abusech-1", "123:tok-1"):
                self.assertNotIn(s, txt)
        self.assertEqual(self.d.aidb_key(), "clave-aidb-1")
        self.assertEqual(self.d.groq_key(), "clave-groq-1")
        self.assertEqual(self.d.telegram_token(), "123:tok-1")
        self.assertIn("TELEGRAM_CHAT_ID=-100", open(self.d.REPORT_CONF, encoding="utf-8").read())


class Destinos(Base):
    def test_accion_va_al_router_de_la_clave(self):
        """Tipo: capacidad nueva (caso obligatorio «accion sobre una IP repetida»). Con
        p002|10.0.0.5 la orden va al router de p002 y nunca al de p001, mire lo que mire
        el selector."""
        self.d.guardar_routers([{"id": "p001", "USER": "a", "PASS": "b", "ENABLED": "1"},
                                {"id": "p002", "USER": "a", "PASS": "b", "ENABLED": "1"}])
        registro = []
        self.d.mk_conectar = _dash.conectar_falso(registro)
        with self.n.contexto("p001"):                  # el selector mira p001...
            r = self.d.router_de_clave("p002|" + _dash.IP)
            ok, _ = self.d.mk_add(self.d.ip_de("p002|" + _dash.IP), lista="clientes-botnet", router=r)
        self.assertTrue(ok)
        self.assertEqual({rid for rid, _w in registro}, {"p002"})
        self.assertIn("=address=" + _dash.IP, registro[0][1])

    def test_sin_destino_no_se_ejecuta(self):
        """Tipo: corrección de defecto (§10.1). Una clave sin pid, con un pid mal formado o
        de un punto que no existe no tiene router: lanza y no se habla con ninguno (el
        heredado caia en «el router por defecto»)."""
        registro = []
        self.d.mk_conectar = _dash.conectar_falso(registro)
        with self.assertRaises(self.n.NodoInvalido):
            self.d.router_de_clave(_dash.IP)
        with self.assertRaises(self.n.NodoInvalido):
            self.d.router_de_clave("p1|" + _dash.IP)
        with self.assertRaises(self.n.NodoInexistente):
            self.d.router_de_clave("p009|" + _dash.IP)
        with self.assertRaises(ValueError):
            self.d.mk_add(_dash.IP, router=None)
        with self.assertRaises(ValueError):
            self.d.mk_remove(_dash.IP, router=None)
        with self.assertRaises(self.n.NodoInexistente):
            self.d.mk_add(_dash.IP, router={"id": "p009"})
        self.assertEqual(registro, [])


class APIporRele(Base):
    def setUp(self):
        super().setUp()
        self.cert, self.key, self.der = certificado(self.tmp.name)
        self.srv = RouterOSFalso(self.d, self.cert, self.key)
        self.abiertas = []

        def abrir(ruta, timeout):
            self.abiertas.append(ruta)
            a, b = socket.socketpair()
            a.settimeout(timeout)
            self.srv.atender(b)
            return a
        self._abrir_real = self.d._mk_abrir_unix
        self.d._mk_abrir_unix = abrir
        self.d.guardar_routers([{"id": "p001", "USER": "ids-api", "PASS": "c1", "ENABLED": "1"},
                                {"id": "p002", "USER": "ids-api", "PASS": "c2", "ENABLED": "1"}])

    def test_tls_sobre_el_rele_del_punto_y_huella_confirmada_por_punto(self):
        """Tipo: capacidad nueva + corrección de defecto (inv_A §10: la huella iba al MK_CONF
        global y no se fijaba nunca). La conexion abre el api.sock DEL PUNTO y hace TLS encima.
        (Adaptada, 2026-10-14, VPN-06: antes la primera conexion fijaba sola la huella y mandaba
        la clave en esa misma conexion. Adaptada otra vez, 2026-10-15, decision del dueno: la
        API-SSL va sin certificado.) Sin huella fijada hay login y NO se guarda nada; la huella
        solo la fija un administrador y queda en routers.json SOLO para ese punto."""
        import hashlib
        fp = hashlib.sha256(self.der).hexdigest()
        self.d.mk_conectar(self.d.cargar_mk_de(self.d.router_por_id("p002"))).close()
        self.assertEqual(set(self.abiertas), {self.n.api_sock("p002")})
        self.assertIn(["/login", "=name=ids-api", "=password=c2"], self.srv.recibido)
        g = json.load(open(self.d.ROUTERS_CONF, encoding="utf-8"))["routers"]
        self.assertFalse(g["p002"].get("CERT_FP"))
        self.assertEqual(self.d.huella_vista("p002"), fp)
        self.srv.recibido.clear()
        self.d.confirmar_huella("p002", fp, "ana")
        s = self.d.mk_conectar(self.d.cargar_mk_de(self.d.router_por_id("p002")))
        s.close()
        self.assertIn(["/login", "=name=ids-api", "=password=c2"], self.srv.recibido)
        g = json.load(open(self.d.ROUTERS_CONF, encoding="utf-8"))["routers"]
        self.assertEqual(g["p002"]["CERT_FP"], fp)
        self.assertEqual(g["p002"]["CERT_FP_QUIEN"], "ana")
        self.assertFalse(g["p001"].get("CERT_FP"))
        self.assertNotIn("CERT_FP", open(self.d.MK_CONF, encoding="utf-8").read() if os.path.exists(self.d.MK_CONF) else "")

    def test_huella_distinta_se_rechaza_sin_mandar_la_clave(self):
        """Tipo: conservación (TOFU del heredado). Con otra huella fijada la conexion se corta
        antes del /login: la clave no sale."""
        self.d.guardar_routers([{"id": "p001", "CERT_FP": "00" * 32}], huella=True)
        with self.assertRaises(RuntimeError):
            self.d.mk_conectar(self.d.cargar_mk_de(self.d.router_por_id("p001")))
        self.assertFalse(any(w and w[0] == "/login" for w in self.srv.recibido))

    def test_mk_add_por_el_rele(self):
        """Tipo: capacidad nueva. Una accion completa (mk_add) sobre p002|10.0.0.5 viaja por
        el rele de p002 con TLS y llega al router como address-list/add. (Adaptada, VPN-06: con
        la huella de p002 confirmada antes, como en producción.)"""
        import hashlib
        self.d.confirmar_huella("p002", hashlib.sha256(self.der).hexdigest(), "ana")
        r = self.d.router_de_clave("p002|" + _dash.IP)
        ok, err = self.d.mk_add(_dash.IP, lista="clientes-botnet", ttl="", router=r)
        self.assertTrue(ok, err)
        self.assertEqual(set(self.abiertas), {self.n.api_sock("p002")})
        self.assertTrue(any(w[:3] == ["/ip/firewall/address-list/add", "=list=clientes-botnet",
                                      "=address=" + _dash.IP] for w in self.srv.recibido))

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "AF_UNIX no existe en esta plataforma")
    def test_af_unix_real(self):
        """Tipo: capacidad nueva. Con un socket AF_UNIX de verdad en run/<pid>/api.sock. (Adaptada,
        VPN-06: con la huella de p001 confirmada antes.)"""
        import hashlib
        self.d.confirmar_huella("p001", hashlib.sha256(self.der).hexdigest(), "ana")
        self.d._mk_abrir_unix = self._abrir_real   # el de verdad
        ruta = self.n.api_sock("p001")
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        ls = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        ls.bind(ruta)
        ls.listen(4)

        def aceptar():
            for _ in range(3):
                try:
                    c, _a = ls.accept()
                except OSError:
                    return
                self.srv.atender(c)
        threading.Thread(target=aceptar, daemon=True).start()
        try:
            ok, msg = self.d.mk_probar("p001")
        finally:
            ls.close()
        self.assertTrue(ok, msg)


if __name__ == "__main__":
    unittest.main()
