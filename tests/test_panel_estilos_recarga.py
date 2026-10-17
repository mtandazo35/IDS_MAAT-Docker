"""Hoja de estilos versionada y recarga rapida mientras se genera otra ventana.

Tipo: correccion de defecto. Sin tailwind.css el panel respondia 200 con un fichero vacio que el
navegador guardaba una hora: las paginas seguian sin estilos aunque el fichero volviera, y tras
una actualizacion del CSS se seguia viendo el viejo. Y al cambiar la ventana el aviso «generando…»
se quedaba hasta 20 s aunque el informe nuevo tardara 4 (visto en local, 2026-10-12); despues, la
recarga de 1 s parecia un bucle (2026-10-13): ahora se pregunta a /ventana-estado.
"""
import json
import os
import re
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures.panel2._dash_p import PanelP  # noqa: E402


class Estilos(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.css = os.path.join(self.p.tmp.name, "share", "tailwind.css")

    def test_sin_fichero_404_sin_cache(self):
        """Correccion de defecto: si falta el CSS, 404 y no-store (nada que el navegador guarde)."""
        r = self.p.pedir("GET", "/vendor/tailwind.css")
        self.assertEqual(r.status, 404)
        self.assertEqual(r.cab("Cache-Control"), "no-store")

    def test_enlace_con_huella_y_url_nueva_si_cambia(self):
        """Capacidad nueva: el enlace lleva ?v=<huella>; esa URL se guarda para siempre y, si el
        CSS cambia, la huella cambia y el navegador baja el nuevo sin Ctrl+F5."""
        with open(self.css, "w", encoding="utf-8") as f:
            f.write(".tw-a{color:red}")
        ana = self.p.entrar("ana")
        h = self.p.pedir("GET", "/cuarentena?nodo=p001", cookie=ana).texto
        v1 = re.search(r"href=/vendor/tailwind\.css\?v=([0-9a-f]{12})>", h).group(1)
        r = self.p.pedir("GET", "/vendor/tailwind.css?v=" + v1)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.texto, ".tw-a{color:red}")
        self.assertIn("immutable", r.cab("Cache-Control"))
        # sin huella (o con una vieja) no se guarda a largo plazo
        self.assertEqual(self.p.pedir("GET", "/vendor/tailwind.css").cab("Cache-Control"), "no-cache")
        with open(self.css, "w", encoding="utf-8") as f:
            f.write(".tw-a{color:blue}")
        h = self.p.pedir("GET", "/cuarentena?nodo=p001", cookie=ana).texto
        v2 = re.search(r"href=/vendor/tailwind\.css\?v=([0-9a-f]{12})>", h).group(1)
        self.assertNotEqual(v1, v2)
        self.assertEqual(self.p.pedir("GET", "/vendor/tailwind.css?v=" + v1).cab("Cache-Control"),
                         "no-cache")


class Recarga(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.p.cuarentena("_todos", [])      # generado con ventana_min=1440
        self.ana = self.p.entrar("ana")

    def recarga(self):
        """(segundos de la recarga o None si no se recarga sola, html)."""
        h = self.p.pedir("GET", "/?nodo=_todos", cookie=self.ana).texto
        m = re.search(r"<meta http-equiv=refresh content=(\d+)>", h)
        return (m.group(1) if m else None), h

    def estado(self):
        r = self.p.pedir("GET", "/ventana-estado?nodo=_todos", cookie=self.ana)
        self.assertEqual(r.status, 200)
        return json.loads(r.texto)

    def test_sin_recarga_entera_ni_mientras_genera_otra_ventana(self):
        """Correccion de defecto: con la ventana elegida ya generada la pagina ya no se recarga
        entera cada 20 s (las barras «palpitaban»; el user, 2026-10-16): lo cubre
        tests/test_envivo_sin_recarga.py. Si se eligio otra y aun se muestra la vieja
        («generando…»), tampoco se recarga entera cada segundo (parecia un bucle y un clic en el
        selector a mitad de recarga se reenviaba; el user, 2026-10-13): pregunta a
        /ventana-estado y enseña cuanto va."""
        self.p.d.CFG["VENTANA_MIN"] = "1440"
        self.assertIsNone(self.recarga()[0])
        self.p.d.CFG["VENTANA_MIN"] = "30"
        seg, h = self.recarga()
        self.assertIsNone(seg)
        self.assertIn("generando 30 min", h)
        self.assertIn("fetch('/ventana-estado'", h)
        self.assertIn("<span id='wprog' data-l='0' data-t='", h)
        self.assertNotIn("id='cd'", h)
        # una consulta colgada no puede congelar la pagina (se quedo en «0 de 5 · 2 s» con el
        # servidor ya terminado; el user, 2026-10-13): tope de 5 s, contador propio y, tras 3
        # fallos seguidos, recarga entera
        self.assertIn("c.abort();},5000)", h)
        self.assertIn("setInterval(pinta,1000)", h)
        self.assertIn("if(fallos>=3){location.reload()", h)

    def test_ventana_estado_dice_si_falta_y_cuanto_va(self):
        """Capacidad nueva: /ventana-estado dice la ventana elegida, la que se muestra, si falta
        y cuantos reportes (puntos activos y «Todos») van ya hechos con la elegida."""
        self.p.d.CFG["VENTANA_MIN"] = "1440"
        e = self.estado()
        self.assertFalse(e["pendiente"])
        self.p.d.CFG["VENTANA_MIN"] = "30"
        e = self.estado()
        self.assertEqual((e["pendiente"], e["elegida"], e["generada"]), (True, 30, 1440))
        self.assertEqual(e["total"], len(self.p.d.pids_activos()) + 1)
        self.assertEqual(e["listos"], 0)
        self.generar_en(0, 30)
        time.sleep(0.3)
        e = self.estado()
        self.assertFalse(e["pendiente"])
        self.assertEqual(e["listos"], 1)

    def test_la_bitacora_apunta_la_ventana_que_habia_elegida(self):
        """Correccion de defecto: «antes» salia de la ventana del resumen ya generado, asi que
        mientras se generaba apuntaba siempre lo mismo («30 -> 60», «30 -> 30»...)."""
        self.p.d.VENTANA_ESPERA = 0
        self.p.d.CFG["VENTANA_MIN"] = "1440"
        self.p.pedir("POST", "/ventana?nodo=_todos", {"min": "30"}, cookie=self.ana)
        self.p.pedir("POST", "/ventana?nodo=_todos", {"min": "60"}, cookie=self.ana)
        with open(os.path.join(self.p.tmp.name, "panel", "log", "bitacora.log"), encoding="utf-8") as f:
            b = f.read()
        self.assertIn("CONFIG-VENTANA	1440 -> 30 min", b)
        self.assertIn("CONFIG-VENTANA	30 -> 60 min", b)

    def generar_en(self, segundos, vmin):
        """Simula el refrescador: escribe el resumen de «Todos» con esa ventana al cabo de un rato."""
        def hilo():
            time.sleep(segundos)
            self.p.cuarentena("_todos", [])
            ruta = os.path.join(self.p.tmp.name, "panel", "nodos", "_todos", "cuarentena.json")
            with open(ruta, encoding="utf-8") as f:
                d = json.load(f)
            d["ventana_min"] = vmin
            with open(ruta, "w", encoding="utf-8") as f:
                json.dump(d, f)
        threading.Thread(target=hilo, daemon=True).start()

    def test_elegir_ventana_vuelve_con_el_resumen_nuevo(self):
        """Correccion de defecto: el POST espera al resumen nuevo antes de volver a «/», asi la
        pagina ya sale con la ventana elegida y sin «generando…»."""
        self.generar_en(0.6, 30)
        t = time.time()
        r = self.p.pedir("POST", "/ventana?nodo=_todos", {"min": "30"}, cookie=self.ana)
        self.assertEqual(r.status, 303)
        self.assertGreaterEqual(time.time() - t, 0.5)
        seg, h = self.recarga()
        self.assertEqual(seg, "20")
        self.assertNotIn("generando 30 min", h)
        self.assertNotIn("class='wpend'", h)

    def test_si_tarda_mas_vuelve_igual(self):
        """Capacidad nueva: con trafico real puede tardar; pasado VENTANA_ESPERA se vuelve igual y
        la pagina sigue mirando sola (por /ventana-estado, sin recargarse entera)."""
        self.p.d.VENTANA_ESPERA = 0.5
        t = time.time()
        r = self.p.pedir("POST", "/ventana?nodo=_todos", {"min": "30"}, cookie=self.ana)
        self.assertEqual(r.status, 303)
        self.assertLess(time.time() - t, 5)
        seg, h = self.recarga()
        self.assertIsNone(seg)
        self.assertIn("fetch('/ventana-estado'", h)

    def test_elegir_no_congela_el_navegador_10_s(self):
        """Correccion de defecto: el POST esperaba hasta 10 s al resumen nuevo con el navegador
        congelado; ahora como mucho VENTANA_ESPERA (2 s) y luego la pagina enseña el progreso."""
        self.assertLessEqual(self.p.d.VENTANA_ESPERA, 2)


if __name__ == "__main__":
    unittest.main()
