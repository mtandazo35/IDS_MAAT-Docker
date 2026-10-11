"""Panel: crear punto, borrar punto y regenerar la clave con un orquestador FALSO.

El falso valida cada petición con `validar_params` del ids_orq.py real y genera los comandos con
su `comandos_mikrotik`: si el panel manda algo que el orquestador no acepta, falla aquí.
"""

import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures" / "panel"))
import _ayuda_panel as A  # noqa: E402

FORM = {"nombre": "sur", "redes": "10.1.0.0/24\n10.2.0.0/24, 10.2.0.0/24", "ros_version": "6", "perfil": "reducido"}


class Base(unittest.TestCase):
    def setUp(self):
        self._it = A.iteraciones_rapidas()
        self._it.__enter__()
        self.addCleanup(self._it.__exit__, None, None, None)
        self.p = A.PanelPrueba()
        self.addCleanup(self.p.cerrar)
        self.p.usuario()
        self.ck = self.p.entrar()

    def seguir(self, loc, ck=None, maximo=10):
        """Pide el fragmento como lo hace panel.js hasta que la operación termina."""
        for _ in range(maximo):
            r = self.p.pedir("GET", loc + "/fragmento", cookie=ck or self.ck)
            self.assertEqual(r.status, 200, r.texto[:300])
            if 'data-terminada="1"' in r.texto:
                return r.texto
        self.fail("la operación no terminó")


class CrearPunto(Base):
    def test_flujo_completo_y_clave_una_sola_vez(self):
        r = self.p.post("/puntos/nuevo", FORM, self.ck)
        self.assertEqual(r.status, 303)
        loc = r.cab("location")
        self.assertRegex(loc, r"^/operaciones/[0-9a-f-]{36}$")
        pet = self.p.orq.ordenes("punto.crear")[0]
        # parámetros EXACTOS del orquestador (ya validados por su validar_params)
        self.assertEqual(pet["params"], {"nombre": "sur", "redes_abonados": ["10.1.0.0/24", "10.2.0.0/24"],
                                         "perfil": "reducido", "ros_version": 6})
        self.assertEqual(pet["quien"], "panel:admin")
        self.assertEqual(pet["ip"], "127.0.0.1")
        self.assertEqual(pet["token"], A.TOKEN)
        self.assertEqual(loc, "/operaciones/" + pet["op_id"])          # op_id generado por el panel
        # avance antes de terminar
        r = self.p.pedir("GET", loc, cookie=self.ck)
        self.assertIn('data-terminada="0"', r.texto)
        self.assertIn("Paso actual", r.texto)
        self.assertIn("<progress", r.texto)
        final = self.seguir(loc)
        sec = [s for s in self.p.orq.peticiones if s["orden"] == "op.estado"]
        self.assertTrue(sec)
        clave = re.search(r'<code id="cred-clave">([A-Za-z0-9]{24})</code>', final).group(1)
        usuario = re.search(r'<code id="cred-usuario">(vpn[0-9a-f]{6})</code>', final).group(1)
        self.assertIn("password=%s" % clave, final)                    # comandos con la clave puesta
        self.assertIn("user=%s" % usuario, final)
        self.assertIn("RouterOS 6 (la versión declarada", final)      # el declarado primero
        self.assertIn("Ver el bloque de RouterOS 7", final)
        self.assertEqual(final.count("/interface ovpn-client add"), 2)
        self.assertIn("NO la vuelve a mostrar", final)
        self.assertIn("data-copiar=\"cred-clave\"", final)
        # NUNCA más: ni la página, ni el fragmento, ni la ficha, ni los ficheros del panel
        for ruta in (loc, loc + "/fragmento", "/puntos/p003", "/puntos"):
            self.assertNotIn(clave, self.p.pedir("GET", ruta, cookie=self.ck).texto, ruta)
        self.assertIn("La clave ya se mostró", self.p.pedir("GET", loc, cookie=self.ck).texto)
        for f in self.p.cfg.panel_dir.iterdir():
            self.assertNotIn(clave, f.read_text(encoding="utf-8"), f.name)
        # bitácora: quién hizo qué, sin secretos
        lineas = [json.loads(x) for x in self.p.bitacora().splitlines()]
        acciones = [(x["accion"], x["resultado"]) for x in lineas]
        self.assertIn(("punto.crear", "ACEPTADA"), acciones)
        self.assertIn(("punto.crear.fin", "OK"), acciones)
        fin = [x for x in lineas if x["accion"] == "punto.crear.fin"][0]
        self.assertEqual((fin["usuario"], fin["punto"]), ("admin", "p003"))

    def test_la_ficha_tras_crear_muestra_comandos_sin_clave(self):
        loc = self.p.post("/puntos/nuevo", FORM, self.ck).cab("location")
        self.seguir(loc)
        html_ = self.p.pedir("GET", "/puntos/p003", cookie=self.ck).texto
        self.assertIn("password=&lt;CLAVE-VPN&gt;", html_)
        self.assertNotRegex(html_, r"password=[A-Za-z0-9]{24}")

    def test_otro_usuario_no_ve_la_operacion(self):
        loc = self.p.post("/puntos/nuevo", FORM, self.ck).cab("location")
        self.p.usuario("tecnico", "otra-clave-larga-9")
        ck2 = self.p.entrar("tecnico", "otra-clave-larga-9")
        self.assertEqual(self.p.pedir("GET", loc, cookie=ck2).status, 404)
        self.assertEqual(self.p.pedir("GET", loc + "/fragmento", cookie=ck2).status, 404)
        self.assertEqual(self.p.orq.ordenes("op.estado"), [])          # ni siquiera se consulta
        self.assertIn("cred-clave", self.seguir(loc))                     # el dueño sí la recibe

    def test_formulario_invalido_no_llega_al_orquestador(self):
        malos = [dict(FORM, nombre="Sur Grande"), dict(FORM, redes="10.1.0.0/33"), dict(FORM, redes=""),
                 dict(FORM, redes="0.0.0.0/0"), dict(FORM, ros_version="5"), dict(FORM, perfil="enorme"),
                 dict(FORM, redes="2001:db8::/32")]
        for f in malos:
            r = self.p.post("/puntos/nuevo", f, self.ck)
            self.assertEqual(r.status, 400, f)
            self.assertIn('class="aviso error"', r.texto)
        self.assertEqual(self.p.orq.ordenes("punto.crear"), [])
        r = self.p.post("/puntos/nuevo", dict(FORM, nombre='"><script>x</script>'), self.ck)
        self.assertNotIn("<script>x</script>", r.texto)

    def test_error_del_orquestador_en_lenguaje_claro(self):
        # el validar_params real rechaza el solape con las redes de gestión
        r = self.p.post("/puntos/nuevo", dict(FORM, redes="192.0.2.0/24"), self.ck)
        self.assertEqual(r.status, 400)
        self.assertIn("Los datos no son válidos", r.texto)
        self.assertIn("se solapa con las redes de gestión", r.texto)
        self.p.orq.forzar["punto.crear"] = ("CONFLICTO", "no cabe un punto completo con 1 hilo(s)",
                                            {"caben": {"reducido": 1, "completo": 0}})
        r = self.p.post("/puntos/nuevo", FORM, self.ck)
        self.assertEqual(r.status, 409)
        self.assertIn("No se puede hacer ahora", r.texto)
        self.assertIn("Caben ahora: reducido 1, completo 0", r.texto)
        self.assertIn('value="sur"', r.texto)                             # no se pierde lo escrito
        self.p.orq.caido = True
        r = self.p.post("/puntos/nuevo", FORM, self.ck)
        self.assertEqual(r.status, 503)
        self.assertIn("No se puede hablar con el orquestador", r.texto)
        self.assertNotIn("Errno", r.texto)

    def test_token_equivocado(self):
        self.p.orq.token = "0" * 64
        r = self.p.post("/puntos/nuevo", FORM, self.ck)
        self.assertIn("el token no coincide", r.texto)

    def test_creacion_revertida(self):
        loc = self.p.post("/puntos/nuevo", FORM, self.ck).cab("location")
        op_id = loc.rsplit("/", 1)[1]
        self.p.orq.ops[op_id]["fin"] = ("REVERTIDA", "falló «suricata -T»: reglas rotas; deshecho", {})
        final = self.seguir(loc)
        self.assertIn("se deshizo todo lo hecho", final)
        self.assertNotIn("cred-clave", final)
        self.assertIn("/puntos/nuevo", final)


class BorrarPunto(Base):
    def setUp(self):
        super().setUp()
        A.escribir_estado(self.p.cfg.run_dir, {"p003": A.punto_estado("norte", 3)})
        self.p.orq.anadir_punto("norte", 3)

    def test_exige_el_nombre(self):
        for confirmar in ("", "nortee", "NORTE", "p003"):
            r = self.p.post("/puntos/p003/borrar", {"confirmar": confirmar}, self.ck)
            self.assertEqual(r.status, 400, confirmar)
            self.assertIn("exactamente el nombre", r.texto)
        self.assertEqual(self.p.orq.ordenes("punto.borrar"), [])
        self.assertIn("p003", self.p.orq.puntos)

    def test_borrar_con_el_nombre(self):
        html_ = self.p.pedir("GET", "/puntos/p003", cookie=self.ck).texto
        self.assertIn('data-confirmar-nombre="norte"', html_)              # modal propio, no confirm()
        r = self.p.post("/puntos/p003/borrar", {"confirmar": "norte"}, self.ck)
        self.assertEqual(r.status, 303)
        pet = self.p.orq.ordenes("punto.borrar")[0]
        self.assertEqual(pet["params"], {"pid": "p003", "confirmar": "norte"})
        final = self.seguir(r.cab("location"))
        self.assertIn("Punto borrado", final)
        self.assertNotIn("p003", self.p.orq.puntos)
        self.assertIn('"accion": "punto.borrar.fin"', self.p.bitacora())

    def test_el_orquestador_tambien_compara_el_nombre(self):
        # estado.json aún no tiene el punto: el panel no puede comprobarlo y lo hace el orquestador
        A.escribir_estado(self.p.cfg.run_dir, {})
        r = self.p.post("/puntos/p003/borrar", {"confirmar": "otro"}, self.ck)
        self.assertEqual(r.status, 303)
        final = self.seguir(r.cab("location"))
        self.assertIn("confirmar no coincide", final)
        self.assertIn("p003", self.p.orq.puntos)


class RegenerarClave(Base):
    def test_regenerar_muestra_la_clave_una_vez(self):
        A.escribir_estado(self.p.cfg.run_dir, {"p003": A.punto_estado("norte", 3)})
        self.p.orq.anadir_punto("norte", 3)
        r = self.p.post("/puntos/p003/regenerar", {}, self.ck)
        self.assertEqual(r.status, 303)
        self.assertEqual(self.p.orq.ordenes("punto.vpn.regenerar")[0]["params"], {"pid": "p003"})
        final = self.seguir(r.cab("location"))
        clave = re.search(r'<code id="cred-clave">([A-Za-z0-9]{24})</code>', final).group(1)
        self.assertNotIn(clave, self.p.pedir("GET", r.cab("location"), cookie=self.ck).texto)


if __name__ == "__main__":
    unittest.main()
