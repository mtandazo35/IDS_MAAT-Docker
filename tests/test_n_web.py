"""Núcleo del panel (N): servidor, sesiones, roles, proxy y CLI (CONTRATO-F2 §7, §10.1, §10.2).
"""
import contextlib
import email.message
import http.client
import io
import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
import _dash  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = _dash.Arbol(self.tmp.name)
        self.d = _dash.cargar(self.a)
        self.n = self.d.nodos
        self.n.asegurar_dirs()
        from idspanel import cli
        self.cli = cli

    def tearDown(self):
        self.n.quitar_nodo()
        _dash.restaurar()
        self.tmp.cleanup()

    def crear(self, usuario, rol):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(self.cli.crear_admin(usuario, dash=self.d), 0)
        clave = out.getvalue().strip().split("=", 1)[1]
        if rol != "admin":
            us = self.d.cargar_usuarios()
            for r in us:
                if r["user"] == usuario:
                    r["role"] = rol
            self.d.guardar_usuarios(us)
        return clave


class Servidor(Base):
    def setUp(self):
        super().setUp()
        self.srv = self.d.crear_servidor("127.0.0.1", 0)
        self.puerto = self.srv.server_address[1]
        self.hilo = threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.hilo.start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        super().tearDown()

    def pedir(self, metodo, ruta, cabeceras=None, cuerpo=None):
        c = http.client.HTTPConnection("127.0.0.1", self.puerto, timeout=20)
        try:
            c.request(metodo, ruta, body=cuerpo, headers=cabeceras or {})
            r = c.getresponse()
            return r.status, dict(r.getheaders()), r.read().decode("utf-8", "replace")
        finally:
            c.close()

    def test_nodo_mal_formado_400_e_inexistente_404(self):
        """Tipo: capacidad nueva (§10.1). ?nodo= mal formado da 400 y uno que no existe 404;
        nunca se amplia a «Todos»."""
        self.crear("ana", "lectura")
        tok = self.d.sesion_abrir("ana", "lectura")
        ck = {"Cookie": "sid=" + tok}
        self.assertEqual(self.pedir("GET", "/?nodo=p1", ck)[0], 400)
        self.assertEqual(self.pedir("GET", "/?nodo=..%2Fp001", ck)[0], 400)
        self.assertEqual(self.pedir("GET", "/?nodo=p009", ck)[0], 404)
        self.assertNotIn(self.pedir("GET", "/?nodo=p002", ck)[0], (400, 404))
        # se recuerda en la sesion; la siguiente sin parametro mira p002
        self.assertEqual(self.d.SESSIONS[self.d._hash_token(tok)]["nodo"], "p002")

    def test_sin_usuarios_no_se_entra(self):
        """Tipo: corrección de defecto. Sin usuarios el heredado abria el panel sin login
        (modo sin autenticacion); ahora se va al login y el login no da sesion."""
        st, cab, _ = self.pedir("GET", "/")
        self.assertEqual(st, 303)
        self.assertEqual(cab.get("Location"), "/login")
        st, cab, _ = self.pedir("POST", "/login", {"Content-Type": "application/x-www-form-urlencoded"},
                                "user=admin&pass=")
        self.assertNotIn("sid=", cab.get("Set-Cookie", "") if "Set-Cookie" in cab else "")
        self.assertEqual(self.d.SESSIONS, {})

    def test_restablecer_expulsa_la_sesion(self):
        """Tipo: capacidad nueva (§7). `ids-panel restablecer` cambia el hash y la sesion
        abierta deja de valer al instante (tambien en el servidor que ya corre)."""
        self.crear("admin", "admin")
        tok = self.d.sesion_abrir("admin", "admin")
        self.assertIsNotNone(self.d.sesion_de(tok))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(self.cli.restablecer("admin", dash=self.d), 0)
        self.assertRegex(out.getvalue(), r"^CLAVE=[A-Za-z0-9]{20}\n$")
        self.assertIsNone(self.d.sesion_de(tok))
        st, cab, _ = self.pedir("GET", "/", {"Cookie": "sid=" + tok})
        self.assertEqual((st, cab.get("Location")), (303, "/login"))

    def test_post_con_x_forwarded_host_falso_se_rechaza(self):
        """Tipo: corrección de defecto (§7). X-Forwarded-Host/Forwarded de un cliente que no
        es un proxy de confianza no valen para dar por bueno un Origin ajeno (CSRF)."""
        st, _c, _b = self.pedir("POST", "/login", {
            "Origin": "http://ajeno.example", "X-Forwarded-Host": "ajeno.example",
            "Content-Type": "application/x-www-form-urlencoded", "Content-Length": "0"})
        self.assertEqual(st, 403)

    def test_salud_hace_head_al_servidor(self):
        """Tipo: conservación. `ids-panel salud` = HEAD / al propio servidor: 0 si responde."""
        self.assertEqual(self.cli.salud(self.puerto), 0)
        self.assertEqual(self.cli.salud(1), 1)


class Sesiones(Base):
    def test_token_no_se_guarda(self):
        """Tipo: capacidad nueva (§7). En disco solo va el sha256 del token."""
        self.crear("admin", "admin")
        tok = self.d.sesion_abrir("admin", "admin")
        txt = open(self.d.SESSIONS_FILE, encoding="utf-8").read()
        self.assertNotIn(tok, txt)
        self.assertIn(self.d._hash_token(tok), txt)

    def test_desactivar_o_cambiar_rol_se_nota_al_momento(self):
        """Tipo: corrección de defecto. El rol se relee del usuario en cada peticion (antes
        quedaba congelado 12 h en la sesion) y un usuario desactivado queda fuera."""
        self.crear("ana", "operador")
        tok = self.d.sesion_abrir("ana", "operador")
        us = self.d.cargar_usuarios()
        us[0]["role"] = "lectura"
        self.d.guardar_usuarios(us)
        self.assertEqual(self.d.sesion_de(tok)["role"], "lectura")
        us[0]["activo"] = False
        self.d.guardar_usuarios(us)
        self.assertIsNone(self.d.sesion_de(tok))

    def test_crear_admin_formato_y_codigos(self):
        """Tipo: conservación (interfaz del CLI). crear-admin imprime UNA linea CLAVE=, crea
        rol admin en el formato del dashboard (conf/usuarios.json), y sale con 3 si ya
        existe sin tocar nada; usuario invalido = 2; restablecer de uno que no existe = 4."""
        clave = self.crear("admin", "admin")
        antes = open(self.d.USERS_FILE, encoding="utf-8").read()
        us = json.loads(antes)
        self.assertEqual(us[0]["user"], "admin")
        self.assertEqual(us[0]["role"], "admin")
        self.assertNotIn(clave, antes)
        self.assertEqual(self.d.verificar_login("admin", clave), "admin")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(self.cli.crear_admin("admin", dash=self.d), 3)
            self.assertEqual(self.cli.crear_admin("Admin!", dash=self.d), 2)
            self.assertEqual(self.cli.restablecer("nadie", dash=self.d), 4)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(open(self.d.USERS_FILE, encoding="utf-8").read(), antes)

    def test_login_coste_igual_y_rol_valido(self):
        """Tipo: conservación. verificar_login respeta activo y solo devuelve roles validos."""
        clave = self.crear("ana", "lectura")
        self.assertEqual(self.d.verificar_login("ana", clave), "lectura")
        self.assertIsNone(self.d.verificar_login("ana", "mala"))
        self.assertIsNone(self.d.verificar_login("nadie", clave))
        us = self.d.cargar_usuarios()
        us[0]["role"] = "superadmin"
        self.d.guardar_usuarios(us)
        self.assertIsNone(self.d.verificar_login("ana", clave))


class Roles(Base):
    def handler(self, peer="127.0.0.1", **cab):
        h = self.d.H.__new__(self.d.H)
        m = email.message.Message()
        for k, v in cab.items():
            m[k.replace("_", "-")] = v
        h.headers = m
        h.client_address = (peer, 40000)
        h.path = "/"
        return h

    def test_roles_en_el_servidor(self):
        """Tipo: corrección de defecto (§10.2). _admin/_operador ya no aceptan el rol None
        del modo sin autenticacion; lectura no es operador ni admin; operador no es admin."""
        h = self.handler()
        self.assertFalse(h._admin())
        self.assertFalse(h._operador())
        self.assertFalse(h._auth_ok())
        for rol, adm, ope in (("lectura", False, False), ("operador", False, True), ("admin", True, True)):
            self.crear(rol + "1", rol)
            tok = self.d.sesion_abrir(rol + "1", rol)
            h = self.handler(Cookie="sid=" + tok)
            self.assertEqual((h._admin(), h._operador(), h._auth_ok()), (adm, ope, True), rol)

    def test_xff_solo_de_proxy_de_confianza(self):
        """Tipo: corrección de defecto (§7). X-Forwarded-For solo cuenta si el par TCP es un
        proxy de confianza (IDS_PROXY admite CIDR), y entonces vale el ULTIMO salto que no es
        de confianza: el primero lo puede escribir el cliente."""
        self.d.PROXIES_OK = self.d._redes_proxy("192.0.2.0/28")
        h = self.handler(peer="198.51.100.7", X_Forwarded_For="203.0.113.50")
        self.assertEqual(h._client_ip(), "198.51.100.7")
        h = self.handler(peer="192.0.2.3", X_Forwarded_For="203.0.113.50, 198.51.100.20")
        self.assertEqual(h._client_ip(), "198.51.100.20")
        h = self.handler(peer="192.0.2.3", X_Forwarded_For="203.0.113.50, 192.0.2.9")
        self.assertEqual(h._client_ip(), "203.0.113.50")
        h = self.handler(peer="192.0.2.3", X_Forwarded_For="no-es-ip")
        self.assertEqual(h._client_ip(), "192.0.2.3")
        h = self.handler(peer="198.51.100.7", X_Forwarded_Proto="https")
        self.assertEqual(h._cookie_secure(), "")
        h = self.handler(peer="192.0.2.3", X_Forwarded_Proto="https")
        self.assertEqual(h._cookie_secure(), "; Secure")

    def test_contexto_de_nodo_por_peticion(self):
        """Tipo: capacidad nueva (§10.1). Sin parametro: el de la sesion o «Todos»; el
        contexto se quita al terminar la peticion, tambien con error."""
        self.crear("ana", "lectura")
        tok = self.d.sesion_abrir("ana", "lectura")
        h = self.handler(Cookie="sid=" + tok)
        h._set_ctx()
        self.assertEqual(self.n.nodo_actual(), self.n.TODOS)
        self.d.SESSIONS[self.d._hash_token(tok)]["nodo"] = "p001"
        h = self.handler(Cookie="sid=" + tok)
        h._set_ctx()
        self.assertEqual(self.n.nodo_actual(), "p001")
        h._limpiar_ctx()
        self.assertFalse(self.n.hay_nodo())


if __name__ == "__main__":
    unittest.main()
