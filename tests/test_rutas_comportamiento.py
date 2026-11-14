"""Rutas que solo tenían prueba de permiso o de la función de dentro (QA T-07, 2026-11-14).

Se piden de verdad al servidor del panel (fixture PanelP) y se mira el EFECTO: lo que devuelven, sus
cabeceras y lo que cambian. Sin permiso, 403. Datos RFC 5737.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures.panel2._dash_p import PanelP  # noqa: E402


class Rutas(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")        # administrador
        self.luis = self.p.entrar("luis")      # lectura
        self.d = self.p.d

    def test_exportar_exclusiones(self):
        """Capacidad: /exclusiones/export descarga las exclusiones propias en JSON (las del .conf no);
        sin el permiso, 403."""
        propias = [{"tipo": "dst", "ip": "192.0.2.10", "motivo": "monitoreo", "puertos": [161], "sid": "",
                    "hasta": 0, "nodo": "", "autor": "ana", "creado": 1}]
        self.d.guardar_exclusiones(propias)
        r = self.p.pedir("GET", "/exclusiones/export", cookie=self.ana)
        self.assertEqual(r.status, 200)
        self.assertIn("application/json", r.cab("Content-Type"))
        self.assertIn("attachment; filename=exclusiones.json", r.cab("Content-Disposition"))
        datos = json.loads(r.texto)
        self.assertEqual([(x["ip"], x["puertos"]) for x in datos], [("192.0.2.10", [161])])
        self.assertEqual(self.p.pedir("GET", "/exclusiones/export", cookie=self.luis).status, 403)

    def test_favicon_publico(self):
        """Capacidad: /favicon.ico es un PNG público y cacheable (el login lo pide sin sesión)."""
        r = self.p.pedir("GET", "/favicon.ico")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.cab("Content-Type"), "image/png")
        self.assertIn("max-age=", r.cab("Cache-Control") or "")
        self.assertGreater(int(r.cab("Content-Length") or 0), 100)

    def test_destinos_para_el_router(self):
        """Capacidad: /destinos.rsc descarga el script para importar en el MikroTik; sin el permiso de
        MikroTik, 403."""
        r = self.p.pedir("GET", "/destinos.rsc", cookie=self.ana)
        self.assertEqual(r.status, 200)
        self.assertIn("text/plain", r.cab("Content-Type"))
        self.assertIn("attachment; filename=destinos.rsc", r.cab("Content-Disposition"))
        self.assertIn("/ip firewall address-list", r.texto)
        self.assertEqual(self.p.pedir("GET", "/destinos.rsc", cookie=self.luis).status, 403)

    def test_cambiar_la_ventana(self):
        """Capacidad: POST /ventana cambia la ventana del resumen y lo deja en la bitácora; un valor
        que no está en la lista vuelve a 24 h; sin el permiso, 403 y no cambia."""
        bita = []
        real = self.d.bitacora
        self.d.bitacora = lambda tipo, det, **k: (bita.append((tipo, det)), real(tipo, det, **k))[1]
        r = self.p.pedir("POST", "/ventana", {"min": "60"}, cookie=self.ana)
        self.assertIn(r.status, (200, 303))
        self.assertEqual(self.d.ventana_actual(), 60)
        self.assertTrue(any(t == "CONFIG-VENTANA" and det.endswith("60 min") for t, det in bita), bita)
        self.p.pedir("POST", "/ventana", {"min": "999"}, cookie=self.ana)
        self.assertEqual(self.d.ventana_actual(), 1440)
        self.assertEqual(self.p.pedir("POST", "/ventana", {"min": "30"}, cookie=self.luis).status, 403)
        self.assertEqual(self.d.ventana_actual(), 1440)


if __name__ == "__main__":
    unittest.main()
