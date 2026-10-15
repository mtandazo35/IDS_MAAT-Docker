"""Ajustes > IPs de confianza: estado claro, nota por entrada, normalizado, confirmaciones,
bloqueo por fallos siempre y rescate por CLI si te quedas fuera.

Tipo: correccion de defecto (el user, 2026-10-13): doble marco, titulo distinto del apartado,
botones sin estilo (clase mini inexistente), ejemplo con IP publica real, sin confirmacion al
restringir ni al abrir, sin «Usar mi IP», sin nota, se guardaba tal cual se escribia, sin
salida si te quedabas fuera y, con lista activa, el bloqueo por fallos apagado. Fixture del panel.
"""
import contextlib
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures.panel2._dash_p import PanelP, CLAVE  # noqa: E402


class Confianza(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")
        self.d = self.p.d

    def modal(self):
        h = self.p.pedir("GET", "/ajustes", cookie=self.ana).texto
        i = h.index("<div class=aptmodal id=m-acceso")
        return h[i:h.index("</section>", i)]

    def post(self, **form):
        return self.p.pedir("POST", "/perfil", form, cookie=self.ana).texto

    def lista(self):
        with open(self.d.TRUST_FILE, encoding="utf-8") as f:
            return json.load(f)

    # ---- la tarjeta ----
    def test_vacia_dice_abierto_y_pide_confirmar_la_primera(self):
        m = self.modal()
        self.assertIn("<div class='aptbox plano medio'>", m)
        self.assertIn("<h2>IPs de confianza</h2>", m)
        self.assertIn("<div class='cestado abierto'>", m)
        self.assertIn("bloqueada 10 min tras 8 claves mal puestas", m)
        self.assertIn("return ask(this,'Restringir el acceso',", m)
        self.assertIn("placeholder='IP o rango, ej. 203.0.113.10 o 192.0.2.0/24'", m)
        self.assertNotIn("200.10.20.30", m)
        self.assertIn("onclick=\"usarMiIp(this)\">Usar mi IP</button>", m)
        self.assertIn("ids-orq panel confianza vaciar", m)

    def test_llena_dice_restringido_marca_tu_ip_y_confirma_quitar(self):
        self.d.guardar_confianza([{"red": "127.0.0.0/8", "nota": "Local"}, "192.0.2.0/24"])
        m = self.modal()
        self.assertIn("<div class='cestado cerrado'>", m)
        self.assertIn("las 2 IPs o rangos", m)
        self.assertIn("<span class=mono>127.0.0.0/8</span> <span class=me>tu IP</span></td><td>Local</td>", m)
        self.assertIn("<span class=mono>192.0.2.0/24</span></td><td><span class=dash>&mdash;</span></td>", m)
        self.assertIn("'Quitar IP de confianza'", m)
        self.assertIn("<span class=cok>entra por 127.0.0.0/8</span>", m)
        self.assertNotIn("Usar mi IP", m)                    # ya entras: no hace falta
        self.assertNotIn("'Restringir el acceso'", m)        # ya esta restringido

    def test_quitar_la_ultima_avisa_que_abre(self):
        self.d.guardar_confianza(["127.0.0.1"])
        self.assertIn("'Abrir el panel',", self.modal())

    def test_formato_viejo_se_sigue_leyendo(self):
        with open(self.d.TRUST_FILE, "w", encoding="utf-8") as f:
            json.dump(["127.0.0.1", "192.0.2.0/24"], f)
        self.assertEqual(self.d.cargar_confianza(), ["127.0.0.1", "192.0.2.0/24"])
        self.assertEqual(self.d.cargar_confianza_det()[1], {"red": "192.0.2.0/24", "nota": ""})

    # ---- agregar / quitar ----
    def test_agregar_normaliza_guarda_la_nota_y_rechaza_lo_cubierto(self):
        t = self.post(accion="add_trust", ip=" 127.0.0.5/8 ", nota="  Mi   equipo ")
        self.assertIn("Agregada 127.0.0.0/8. Desde ahora solo las IPs de la lista", t)
        self.assertEqual(self.lista(), [{"red": "127.0.0.0/8", "nota": "Mi equipo"}])
        t = self.post(accion="add_trust", ip="127.0.0.1")
        self.assertIn("127.0.0.1 ya entra: la cubre 127.0.0.0/8.", t)
        t = self.post(accion="add_trust", ip="127.0.0.0/8")
        self.assertIn("127.0.0.0/8 ya está en la lista.", t)
        t = self.post(accion="add_trust", ip="203.0.113.10/32")
        self.assertIn("Agregada 203.0.113.10.", t)               # /32 se guarda como IP suelta
        self.assertEqual([e["red"] for e in self.lista()], ["127.0.0.0/8", "203.0.113.10"])

    def test_agregar_rechaza_lo_invalido_y_todo_internet(self):
        self.assertIn("no es una IP ni un rango válido", self.post(accion="add_trust", ip="10.0.0.300"))
        self.assertIn("es todo internet", self.post(accion="add_trust", ip="0.0.0.0/0"))
        self.assertIn("quedarías fuera", self.post(accion="add_trust", ip="192.0.2.0/24"))
        self.assertFalse(os.path.exists(self.d.TRUST_FILE) and self.lista())

    def test_quitar(self):
        self.d.guardar_confianza(["127.0.0.1", "192.0.2.0/24"])
        self.assertIn("No puedes quitar tu propia IP", self.post(accion="del_trust", ip="127.0.0.1"))
        self.assertIn("IP 192.0.2.0/24 quitada", self.post(accion="del_trust", ip="192.0.2.0/24"))
        self.assertIn("Esa IP ya no estaba", self.post(accion="del_trust", ip="192.0.2.0/24"))
        self.assertIn("acceso abierto", self.post(accion="del_trust", ip="127.0.0.1"))
        self.assertEqual(self.lista(), [])

    # ---- acceso ----
    def test_fuera_de_la_lista_ve_su_ip(self):
        self.d.guardar_confianza(["192.0.2.0/24"])
        r = self.p.pedir("GET", "/login")
        self.assertEqual(r.status, 403)
        self.assertIn("Tu IP: <b style='font-family:ui-monospace,Consolas,monospace'>127.0.0.1</b>", r.texto)

    def test_con_lista_tambien_se_bloquea_tras_8_fallos(self):
        """Antes, con lista activa, una IP permitida podia probar claves sin limite."""
        self.d.guardar_confianza(["127.0.0.0/8"])
        self.d.LOGIN_FAILS.clear()
        original = self.d.time.sleep
        self.addCleanup(setattr, self.d.time, "sleep", original)
        self.d.time.sleep = lambda s: None              # el freno de 1 s por fallo, fuera de la prueba
        for _ in range(self.d.LOGIN_MAX):
            self.p.pedir("POST", "/login", {"usuario": "ana", "clave": "mala"})
        t = self.p.pedir("POST", "/login", {"usuario": "ana", "clave": CLAVE}).texto
        self.assertIn("Demasiados intentos fallidos", t)


class Rescate(unittest.TestCase):
    """`ids-panel confianza ver|agregar|vaciar`, lo que corre `ids-orq panel confianza`."""

    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d
        from idspanel import cli
        self.cli = cli
        sys.modules["dashboard"] = self.d

    def correr(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = self.cli.main(["confianza"] + list(args))
        return rc, out.getvalue(), err.getvalue()

    def test_ver_agregar_y_vaciar(self):
        rc, out, _ = self.correr("ver")
        self.assertEqual(rc, 0)
        self.assertIn("vacía", out)
        rc, out, _ = self.correr("agregar", "198.51.100.7/24", "--nota", "Casa")
        self.assertEqual((rc, out.strip()), (0, "OK agregada 198.51.100.0/24: ya se puede entrar al panel desde ahí"))
        rc, out, _ = self.correr("agregar", "198.51.100.9")
        self.assertEqual(rc, 0)
        self.assertIn("YA 198.51.100.9 ya puede entrar (la cubre 198.51.100.0/24)", out)
        rc, out, _ = self.correr("ver")
        self.assertEqual(out, "198.51.100.0/24  # Casa\n")
        rc, out, _ = self.correr("vaciar")
        self.assertEqual(rc, 0)
        self.assertIn("OK lista vaciada (1 entradas; copia en ", out)
        self.assertEqual(self.d.cargar_confianza(), [])
        copias = [f for f in os.listdir(os.path.dirname(self.d.TRUST_FILE)) if ".antes-de-vaciar" in f]
        self.assertEqual(len(copias), 1)

    def test_agregar_invalido_sale_con_2(self):
        rc, out, err = self.correr("agregar", "no-es-ip")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("no es una IP", err)


if __name__ == "__main__":
    unittest.main()
