"""Panel: login, cookie de sesión, freno por IP real y por usuario, cerrar sesión y cambiar la clave."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures" / "panel"))
import _ayuda_panel as A  # noqa: E402
from idspanel import usuarios as U  # noqa: E402
from idspanel.app import MSG_FRENO, MSG_LOGIN  # noqa: E402


class Base(unittest.TestCase):
    proxies = ""

    def setUp(self):
        self._it = A.iteraciones_rapidas()
        self._it.__enter__()
        self.addCleanup(self._it.__exit__, None, None, None)
        self.p = A.PanelPrueba(proxies=self.proxies)
        self.addCleanup(self.p.cerrar)
        self.clave = self.p.usuario()


class Login(Base):
    def test_sin_sesion_redirige_a_entrar(self):
        for ruta in ("/", "/puntos", "/puntos/p003", "/alertas", "/documentacion", "/cuenta/clave"):
            r = self.p.pedir("GET", ruta)
            self.assertEqual(r.status, 303, ruta)
            self.assertEqual(r.cab("location"), "/entrar")
        self.assertEqual(self.p.pedir("GET", "/puntos/tabla").status, 401)
        self.assertEqual(self.p.pedir("GET", "/salud").status, 200)

    def test_login_correcto_da_cookie_httponly_strict(self):
        r = self.p.pedir("POST", "/entrar", {"usuario": "admin", "clave": self.clave})
        self.assertEqual(r.status, 303)
        self.assertEqual(r.cab("location"), "/puntos")
        galletas = r.cookies()
        self.assertEqual(len(galletas), 1)
        g = galletas[0]
        self.assertTrue(g.startswith("ids_s="))
        self.assertIn("HttpOnly", g)
        self.assertIn("SameSite=Strict", g)
        self.assertNotIn("Secure", g)                  # conexión directa, sin proxy https
        self.assertNotIn(self.clave, g)
        cookie = g.split(";", 1)[0]
        r = self.p.pedir("GET", "/puntos", cookie=cookie)
        self.assertEqual(r.status, 200)
        self.assertIn("Toda la empresa", r.texto)
        # en disco solo el hash del token
        token = cookie.split("=", 1)[1]
        self.assertNotIn(token, self.p.cfg.sesiones_json.read_text(encoding="utf-8"))

    def test_clave_mala_y_usuario_inexistente_dan_el_mismo_mensaje(self):
        r1 = self.p.pedir("POST", "/entrar", {"usuario": "admin", "clave": "mala"})
        r2 = self.p.pedir("POST", "/entrar", {"usuario": "nadie", "clave": "mala"})
        self.assertEqual((r1.status, r2.status), (401, 401))
        for r in (r1, r2):
            self.assertIn(MSG_LOGIN, r.texto)
            self.assertEqual(r.cookies(), [])

    def test_cookie_inventada_no_vale(self):
        r = self.p.pedir("GET", "/puntos", cookie="ids_s=" + "A" * 43)
        self.assertEqual(r.status, 303)

    def test_freno_por_ip_ignora_x_forwarded_for_si_no_viene_del_proxy(self):
        for i in range(8):
            r = self.p.pedir("POST", "/entrar", {"usuario": "u%d" % i, "clave": "mala"},
                             cabeceras={"X-Forwarded-For": "192.0.2.%d" % (i + 1)})
            self.assertEqual(r.status, 401)
        # la IP real es la misma (127.0.0.1): frenado aunque la clave sea buena y cambie el XFF
        r = self.p.pedir("POST", "/entrar", {"usuario": "admin", "clave": self.clave},
                         cabeceras={"X-Forwarded-For": "192.0.2.200"})
        self.assertEqual(r.status, 429)
        self.assertIn(MSG_FRENO, r.texto)
        self.assertEqual(r.cookies(), [])
        self.assertIn('"resultado": "frenado"', self.p.bitacora())

    def test_freno_por_usuario(self):
        for _ in range(8):
            self.p.panel.freno.fallo("u:admin")
        r = self.p.pedir("POST", "/entrar", {"usuario": "admin", "clave": self.clave})
        self.assertEqual(r.status, 429)

    def test_salir_invalida_la_sesion(self):
        ck = self.p.entrar(clave=self.clave)
        r = self.p.post("/salir", {}, ck)
        self.assertEqual(r.status, 303)
        self.assertTrue(any("Max-Age=0" in g for g in r.cookies()))
        self.assertEqual(self.p.pedir("GET", "/puntos", cookie=ck).status, 303)

    def test_restablecer_desde_el_cli_cierra_las_sesiones(self):
        ck = self.p.entrar(clave=self.clave)
        self.assertEqual(self.p.pedir("GET", "/puntos", cookie=ck).status, 200)
        nueva = U.Usuarios(str(self.p.cfg.usuarios_json)).restablecer("admin")
        self.assertEqual(self.p.pedir("GET", "/puntos", cookie=ck).status, 303)
        self.assertEqual(self.p.pedir("POST", "/entrar", {"usuario": "admin", "clave": nueva}).status, 303)

    def test_invitacion_a_cambiar_la_clave_y_cambio(self):
        ck = self.p.entrar(clave=self.clave)
        r = self.p.pedir("GET", "/puntos", cookie=ck)
        self.assertIn("invitacion", r.texto)                    # se invita…
        self.assertEqual(r.status, 200)                          # …pero no se obliga
        otra = self.p.entrar(clave=self.clave)                   # segunda sesión
        # la actual es obligatoria
        r = self.p.post("/cuenta/clave", {"actual": "mala", "nueva": "nueva-clave-larga-1",
                                          "repetir": "nueva-clave-larga-1"}, ck)
        self.assertEqual(r.status, 400)
        self.assertIsNotNone(self.p.panel.usuarios.autenticar("admin", self.clave))
        r = self.p.post("/cuenta/clave", {"actual": self.clave, "nueva": "nueva-clave-larga-1",
                                          "repetir": "otra-cosa-distinta"}, ck)
        self.assertEqual(r.status, 400)
        r = self.p.post("/cuenta/clave", {"actual": self.clave, "nueva": "nueva-clave-larga-1",
                                          "repetir": "nueva-clave-larga-1"}, ck)
        self.assertEqual(r.status, 200)
        self.assertIn("Clave cambiada", r.texto)
        nueva_ck = r.cookies()[0].split(";", 1)[0]
        # la otra sesión (y la vieja) quedan cerradas; la nueva funciona y ya no invita
        self.assertEqual(self.p.pedir("GET", "/puntos", cookie=otra).status, 303)
        self.assertEqual(self.p.pedir("GET", "/puntos", cookie=ck).status, 303)
        r = self.p.pedir("GET", "/puntos", cookie=nueva_ck)
        self.assertEqual(r.status, 200)
        self.assertNotIn("invitacion", r.texto)
        self.assertNotIn("nueva-clave-larga-1", self.p.bitacora())
        self.assertNotIn(self.clave, self.p.bitacora())


class LoginTrasProxy(Base):
    proxies = "127.0.0.1"

    def test_cookie_secure_host_si_el_proxy_dice_https(self):
        r = self.p.pedir("POST", "/entrar", {"usuario": "admin", "clave": self.clave},
                         cabeceras={"X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.20",
                                    "X-Forwarded-Host": "ids.empresa.example",
                                    "Origin": "https://ids.empresa.example"})
        self.assertEqual(r.status, 303)
        g = r.cookies()[0]
        self.assertTrue(g.startswith("__Host-ids_s="))
        self.assertIn("Secure", g)
        self.assertIn("Path=/", g)
        self.assertIn('"ip": "203.0.113.20"', self.p.bitacora())      # IP real desde el proxy

    def test_freno_usa_la_ip_real_que_pasa_el_proxy(self):
        for i in range(8):
            self.p.pedir("POST", "/entrar", {"usuario": "x%d" % i, "clave": "mala"},
                         cabeceras={"X-Forwarded-For": "198.51.100.9"})
        r = self.p.pedir("POST", "/entrar", {"usuario": "admin", "clave": self.clave},
                         cabeceras={"X-Forwarded-For": "198.51.100.9"})
        self.assertEqual(r.status, 429)
        # otra IP real detrás del mismo proxy no queda frenada
        r = self.p.pedir("POST", "/entrar", {"usuario": "admin", "clave": self.clave},
                         cabeceras={"X-Forwarded-For": "198.51.100.10"})
        self.assertEqual(r.status, 303)

    def test_xff_toma_la_ultima_entrada(self):
        self.p.pedir("POST", "/entrar", {"usuario": "admin", "clave": "mala"},
                     cabeceras={"X-Forwarded-For": "192.0.2.66, 198.51.100.77"})
        self.assertIn('"ip": "198.51.100.77"', self.p.bitacora())


if __name__ == "__main__":
    unittest.main()
