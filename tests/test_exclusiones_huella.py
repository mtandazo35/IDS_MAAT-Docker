"""Exclusiones: Editar y Eliminar por la huella de la regla, y Post/Redirect/Get (QA U-02, 2026-11-14).

Antes las dos acciones iban por la POSICION en la lista y el POST devolvía la página: un F5 tras
«Eliminar» repetía el envío y borraba la regla que hubiera quedado en esa posición; lo mismo con
otra persona editando a la vez. Ahora cada regla se identifica por su huella (tipo, IP, puertos,
firma, punto y cuándo se creó) y toda acción responde 303 a /exclusiones?msg=<código de un solo uso>.
Datos RFC 5737.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures.panel2._dash_p import PanelP  # noqa: E402


def regla(ip, tipo="dst", puertos=(), creado=1000):
    return {"tipo": tipo, "ip": ip, "motivo": "prueba", "puertos": list(puertos), "sid": "",
            "hasta": 0, "nodo": "", "autor": "ana", "creado": creado}


class Huella(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")
        self.d = self.p.d
        self.d.guardar_exclusiones([regla("192.0.2.1", creado=1001), regla("192.0.2.2", creado=1002),
                                    regla("192.0.2.3", creado=1003)])

    def ips(self):
        return [r["ip"] for r in self.d.cargar_exclusiones(incluir_vencidas=True) if r.get("motivo") != "(conf)"]

    def h(self, ip):
        r = next(r for r in self.d.cargar_exclusiones(incluir_vencidas=True) if r["ip"] == ip)
        return self.d.huella_exclusion(r)

    def post(self, form):
        r = self.p.pedir("POST", "/exclusiones", form, cookie=self.ana)
        self.assertEqual(r.status, 303, r.texto[:300])
        self.assertRegex(r.cab("Location"), r"^/exclusiones\?msg=[\w-]+")
        return r

    def seguir(self, r):
        return self.p.pedir("GET", r.cab("Location"), cookie=self.ana)

    def test_la_pagina_enlaza_por_huella(self):
        """Capacidad nueva: Editar y Eliminar llevan la huella, no la posición."""
        t = self.p.pedir("GET", "/exclusiones", cookie=self.ana).texto
        self.assertIn('name=huella value="%s"' % self.h("192.0.2.2"), t)
        self.assertRegex(t, r'href="/exclusiones\?edit=%s' % self.h("192.0.2.2"))
        self.assertNotIn("name=idx", t)

    def test_f5_tras_eliminar_no_borra_otra(self):
        """Corrección de defecto: repetir el mismo «Eliminar» (F5 o doble envío) no borra la regla que
        quedó en su posición: dice que ya no está y deja las demás."""
        form = {"accion": "del", "huella": self.h("192.0.2.2")}
        self.assertIn("Exclusión eliminada: 192.0.2.2.", self.seguir(self.post(form)).texto)
        self.assertEqual(self.ips(), ["192.0.2.1", "192.0.2.3"])
        self.assertIn("ya no está", self.seguir(self.post(form)).texto)
        self.assertEqual(self.ips(), ["192.0.2.1", "192.0.2.3"])

    def test_editar_una_que_otro_borro_no_crea_otra(self):
        """Corrección de defecto: si otra persona borró la regla que se editaba, guardar no la convierte
        en una regla nueva ni pisa otra: no guarda nada y lo dice."""
        editar = self.h("192.0.2.1")
        self.post({"accion": "del", "huella": editar})              # la «otra persona»
        r = self.post({"accion": "add", "editar": editar, "tipo": "dst", "ip": "192.0.2.9",
                       "puertos": "", "sid": "", "vigencia": "0", "motivo": "x", "nodo": ""})
        self.assertIn("no se guardó nada", self.seguir(r).texto)
        self.assertEqual(self.ips(), ["192.0.2.2", "192.0.2.3"])

    def test_editar_cambia_esa_y_no_otra(self):
        """Conservación: editar por huella cambia exactamente esa regla y conserva su «creado»."""
        r = self.post({"accion": "add", "editar": self.h("192.0.2.3"), "tipo": "dst", "ip": "192.0.2.30",
                       "puertos": "443", "sid": "", "vigencia": "0", "motivo": "x", "nodo": ""})
        self.assertIn("Exclusión actualizada: 192.0.2.30.", self.seguir(r).texto)
        self.assertEqual(self.ips(), ["192.0.2.1", "192.0.2.2", "192.0.2.30"])
        nueva = [x for x in self.d.cargar_exclusiones(incluir_vencidas=True) if x["ip"] == "192.0.2.30"][0]
        self.assertEqual((nueva["puertos"], nueva["creado"]), ([443], 1003))

    def test_el_aviso_es_de_un_solo_uso(self):
        """Capacidad nueva: el resultado viaja como código de un solo uso; recargar no lo repite, y un
        código inventado no pinta nada."""
        r = self.post({"accion": "add", "tipo": "src", "ip": "198.51.100.5", "puertos": "", "sid": "",
                       "vigencia": "0", "motivo": "x", "nodo": ""})
        t = self.seguir(r).texto
        self.assertIn("Exclusión agregada: 198.51.100.5.", t)
        self.assertIn("<div id=notif class='avm ok'", t)            # en modal, no franja (QA U-04)
        self.assertNotIn('<div class="banner"', t)
        self.assertNotIn("Exclusión agregada", self.seguir(r).texto)          # F5 sobre la página
        t = self.p.pedir("GET", "/exclusiones?msg=Inventado", cookie=self.ana).texto
        self.assertNotIn("id=notif", t)                 # ni el modal de aviso (QA U-04)

    def test_un_error_tambien_redirige(self):
        """Corrección de defecto: un error de validación también es 303 (F5 no reenvía el formulario)."""
        r = self.post({"accion": "add", "tipo": "dst", "ip": "no-es-ip", "puertos": "", "sid": "",
                       "vigencia": "0", "motivo": "x", "nodo": ""})
        self.assertIn("IP inválida.", self.seguir(r).texto)
        self.assertEqual(len(self.ips()), 3)


if __name__ == "__main__":
    unittest.main()
