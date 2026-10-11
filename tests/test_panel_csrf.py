"""Panel: CSRF (Origin/Referer/Sec-Fetch-Site + token de sesión), cabeceras de seguridad y proxy."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures" / "panel"))
import _ayuda_panel as A  # noqa: E402
from idspanel.config import redes_proxy  # noqa: E402
from idspanel.red import Origen, origen_ajeno  # noqa: E402


class OrigenAjeno(unittest.TestCase):
    def test_reglas(self):
        h = ["ids.empresa.example"]
        casos = [
            ({}, True),                                                          # curl: sin Origin
            ({"Origin": "https://ids.empresa.example"}, True),
            ({"Origin": "https://ids.empresa.example:443"}, True),
            ({"Origin": "https://otro.example"}, False),
            ({"Origin": "https://ids.empresa.example.otro.example"}, False),
            ({"Referer": "https://otro.example/x"}, False),
            ({"Referer": "https://ids.empresa.example/puntos"}, True),
            ({"Sec-Fetch-Site": "cross-site"}, False),
            ({"Sec-Fetch-Site": "same-site", "Origin": "https://ids.empresa.example"}, False),
            ({"Sec-Fetch-Site": "same-origin", "Origin": "https://x.example"}, True),
            ({"Origin": "null"}, False),
            ({"Origin": "null", "Sec-Fetch-Site": "none"}, True),
            ({"Origin": "file:///etc/passwd"}, False),
        ]
        for cab, pasa in casos:
            self.assertEqual(origen_ajeno(cab, h) == "", pasa, cab)

    def test_puerto_cuenta_si_el_host_lo_lleva(self):
        self.assertEqual(origen_ajeno({"Origin": "http://127.0.0.1:5637"}, ["127.0.0.1:5637"]), "")
        self.assertNotEqual(origen_ajeno({"Origin": "http://127.0.0.1:8080"}, ["127.0.0.1:5637"]), "")

    def test_cabeceras_del_proxy_solo_si_viene_del_proxy(self):
        cab = {"Host": "10.210.255.2:5637", "X-Forwarded-Host": "evil.example",
               "X-Forwarded-For": "192.0.2.9", "X-Forwarded-Proto": "https"}
        directo = Origen(cab, "198.51.100.3", redes_proxy("203.0.113.50"))
        self.assertEqual(directo.hosts(), ["10.210.255.2:5637"])
        self.assertEqual(directo.ip, "198.51.100.3")
        self.assertFalse(directo.https)
        proxy = Origen(cab, "203.0.113.50", redes_proxy("203.0.113.50"))
        self.assertIn("evil.example", proxy.hosts())
        self.assertEqual(proxy.ip, "192.0.2.9")
        self.assertTrue(proxy.https)
        # CIDR y Forwarded (RFC 7239)
        fw = Origen({"Host": "x", "Forwarded": 'for="192.0.2.60:1234";proto=https;host=ids.empresa.example'},
                    "203.0.113.51", redes_proxy("203.0.113.48/29"))
        self.assertEqual(fw.ip, "192.0.2.60")
        self.assertTrue(fw.https)
        self.assertIn("ids.empresa.example", fw.hosts())
        self.assertEqual(Origen({}, "::ffff:203.0.113.50", redes_proxy("203.0.113.50")).de_proxy, True)


class CsrfHttp(unittest.TestCase):
    proxies = ""

    def setUp(self):
        self._it = A.iteraciones_rapidas()
        self._it.__enter__()
        self.addCleanup(self._it.__exit__, None, None, None)
        self.p = A.PanelPrueba(proxies=self.proxies)
        self.addCleanup(self.p.cerrar)
        self.clave = self.p.usuario()

    def login(self, cab):
        return self.p.pedir("POST", "/entrar", {"usuario": "admin", "clave": self.clave}, cabeceras=cab)

    def test_login_desde_otro_origen_es_403(self):
        r = self.login({"Origin": "https://evil.example"})
        self.assertEqual(r.status, 403)
        self.assertEqual(r.cookies(), [])
        self.assertIn("csrf.rechazado", self.p.bitacora())
        self.assertEqual(self.login({"Sec-Fetch-Site": "cross-site"}).status, 403)
        self.assertEqual(self.login({}).status, 303)                          # mismo origen pasa

    def test_x_forwarded_host_ignorado_si_no_viene_del_proxy(self):
        r = self.login({"Origin": "https://evil.example", "X-Forwarded-Host": "evil.example",
                        "Forwarded": "host=evil.example"})
        self.assertEqual(r.status, 403)

    def test_post_autenticado_exige_el_token_de_la_sesion(self):
        ck = self.p.entrar(clave=self.clave)
        form = {"nombre": "sur", "redes": "10.1.0.0/24", "ros_version": "7", "perfil": "reducido"}
        r = self.p.pedir("POST", "/puntos/nuevo", form, cookie=ck)                       # sin csrf
        self.assertEqual(r.status, 403)
        r = self.p.pedir("POST", "/puntos/nuevo", dict(form, csrf="0" * 40), cookie=ck)  # csrf falso
        self.assertEqual(r.status, 403)
        r = self.p.post("/puntos/nuevo", form, ck, cabeceras={"Origin": "https://evil.example"})
        self.assertEqual(r.status, 403)                                      # token bueno, origen malo
        self.assertEqual(self.p.orq.ordenes("punto.crear"), [])
        r = self.p.post("/puntos/nuevo", form, ck)
        self.assertEqual(r.status, 303)
        self.assertEqual(len(self.p.orq.ordenes("punto.crear")), 1)

    def test_cabeceras_de_seguridad(self):
        ck = self.p.entrar(clave=self.clave)
        for ruta, cookie in (("/entrar", None), ("/puntos", ck), ("/salud", None), ("/static/panel.js", None)):
            r = self.p.pedir("GET", ruta, cookie=cookie)
            csp = r.cab("content-security-policy")
            self.assertIn("default-src 'self'", csp, ruta)
            self.assertIn("frame-ancestors 'none'", csp)
            self.assertNotIn("unsafe-inline", csp)
            self.assertEqual(r.cab("x-frame-options"), "DENY")
            self.assertEqual(r.cab("x-content-type-options"), "nosniff")
            self.assertEqual(r.cab("referrer-policy"), "same-origin")
        r = self.p.pedir("GET", "/puntos", cookie=ck)
        self.assertEqual(r.cab("cache-control"), "no-store")
        self.assertNotIn("<script>", r.texto)                    # nada de scripts en línea (CSP)
        self.assertNotIn(" style=", r.texto)


class CsrfTrasProxy(CsrfHttp):
    proxies = "127.0.0.1/32"

    def test_x_forwarded_host_ignorado_si_no_viene_del_proxy(self):
        # aquí SÍ viene del proxy: el host público que pasa el proxy cuenta
        r = self.login({"Origin": "https://ids.empresa.example", "X-Forwarded-Host": "ids.empresa.example",
                        "X-Forwarded-Proto": "https"})
        self.assertEqual(r.status, 303)
        r = self.login({"Origin": "https://evil.example", "X-Forwarded-Host": "ids.empresa.example"})
        self.assertEqual(r.status, 403)


if __name__ == "__main__":
    unittest.main()
