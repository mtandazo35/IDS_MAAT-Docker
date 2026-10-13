"""Cambio de ventana del Resumen: se genera ya, no tras el freno de un minuto ni tras 5 min.

Tipo: correccion de defecto (visto en local, 2026-10-12). Generar el resumen tardaba 3 s, pero:
  - un segundo cambio de ventana dentro del mismo minuto esperaba a REGEN_MIN_SECS (54 s medidos);
  - tras reiniciar el panel la marca FORCE_REGEN (en memoria) se perdia y el aviso «generando…»
    seguia hasta el ciclo de 5 min.
Una vuelta del refrescador sobre el arbol de pruebas, con el generador sustituido (apunta la
ventana con la que se le llama).
"""
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
import _dash  # noqa: E402

CLAVES = ("ult_poda", "ult_sensor", "ult_fast", "ult_dur", "ult_fin", "ult_aidb", "ult_pub", "ult_diag",
          "ult_feeds", "ult_forzado", "ult_cond", "ult_hist", "ult_bajas")


class VentanaInmediata(unittest.TestCase):
    def setUp(self):
        self.raiz = tempfile.mkdtemp(prefix="ventana-")
        self.addCleanup(shutil.rmtree, self.raiz, True)
        self.arbol = _dash.Arbol(self.raiz)
        self.d = _dash.cargar(self.arbol)
        self.addCleanup(_dash.restaurar)
        self.llamadas = []
        self.d.generar_reporte = lambda nodo, vmin: self.llamadas.append((nodo, vmin)) or 0.1
        ahora = time.time()
        # todo lo periodico recien hecho, y una regeneracion forzada hace 5 s (el freno de 60 s activo)
        self.estado = {k: ahora for k in CLAVES}
        self.estado.update(ult_dur=0.1, ult_fin=ahora - 5, ult_forzado=ahora - 5)
        self.generado(1440)
        self.d.FORCE_REGEN = False

    def generado(self, vmin):
        """El resumen que se esta mostrando (el de «Todos») se genero con esa ventana, y los
        informes de cada punto son recientes (si no, el ciclo de 5 min regeneraria igual)."""
        self.arbol.salida(self.d.nodos.TODOS, "cuarentena.json", {"ventana_min": vmin, "candidatos": []})
        for n in ("p001", "p002", self.d.nodos.TODOS):
            d = os.path.join(self.arbol.panel, "nodos", n)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "report-20261012-2300.html"), "w", encoding="utf-8") as f:
                f.write("<html></html>")

    def vuelta(self, vmin_elegida):
        self.d.CFG["VENTANA_MIN"] = str(vmin_elegida)
        self.llamadas.clear()
        self.d._vuelta_refrescador(self.estado)
        return sorted({v for _n, v in self.llamadas})

    def test_ventana_nueva_se_genera_ya_aunque_haya_freno_y_sin_marca(self):
        """Sin FORCE_REGEN (reinicio) y con una forzada hace 5 s, la ventana elegida se genera en
        esta misma vuelta, para todos los puntos y para «Todos»."""
        self.assertEqual(self.vuelta(30), [30])
        self.assertEqual({n for n, _v in self.llamadas}, {"p001", "p002", self.d.nodos.TODOS})

    def test_otra_ventana_seguida_tambien_es_inmediata(self):
        """Dos cambios seguidos (30 y luego 60) se atienden los dos al momento."""
        self.assertEqual(self.vuelta(30), [30])
        self.assertEqual(self.vuelta(60), [60])

    def test_la_misma_pendiente_no_se_relanza_cada_10_s(self):
        """Si el generador no llega a escribir la ventana nueva (falla), la MISMA no se vuelve a
        lanzar en cada vuelta: espera REGEN_MIN_SECS."""
        self.assertEqual(self.vuelta(30), [30])
        self.assertEqual(self.vuelta(30), [])
        v, _t = self.estado["vpend"]
        self.estado["vpend"] = (v, time.time() - self.d.REGEN_MIN_SECS - 1)
        self.assertEqual(self.vuelta(30), [30])

    def test_sin_cambio_no_genera(self):
        """Con la ventana elegida ya generada y nada vencido, la vuelta no genera nada."""
        self.assertEqual(self.vuelta(1440), [])


if __name__ == "__main__":
    unittest.main()
