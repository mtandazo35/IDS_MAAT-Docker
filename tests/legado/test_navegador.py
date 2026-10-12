# -*- coding: utf-8 -*-
"""Las pruebas de navegador heredadas de suricata-ids-lab (tests/legado/test_*.js).

Cada .js se ejecuta con node contra el JavaScript REAL que sirve el panel, sacado por
extraer.py de dashboard.py y html_report.py (DOM simulado, sin navegador). Si node no esta
instalado, se omiten con el motivo «node no disponible»: en el CI (Ubuntu) node viene con la
imagen del runner.

Tipo: conservacion (las siete pruebas .js no cambian; solo cambia de donde sale el JS).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402


class Navegador(unittest.TestCase):
    def test_mapa(self):
        """Tipo: conservacion. Mapa del reporte: zoom por pais, detalle y sin bordes negros."""
        _comun.correr_node(self, "test_mapa.js", "mapa.js")

    def test_orden(self):
        """Tipo: conservacion. Tablas: orden ascendente/descendente y fechas por tiempo real."""
        _comun.correr_node(self, "test_orden.js", "sort.js")

    def test_orden_persiste(self):
        """Tipo: conservacion. Tablas: el orden sobrevive a la recarga."""
        _comun.correr_node(self, "test_orden_persiste.js", "sort.js")

    def test_posicion(self):
        """Tipo: conservacion. Pagina: conserva la posicion tras una accion."""
        _comun.correr_node(self, "test_posicion.js", "pos.js")

    def test_masivo_ui(self):
        """Tipo: conservacion. Quitado masivo: seleccion y contenido del modal."""
        _comun.correr_node(self, "test_masivo_ui.js", "masivo.js")

    def test_masivo_progreso(self):
        """Tipo: conservacion. Quitado masivo: avance, fallo a mitad y cierre."""
        _comun.correr_node(self, "test_masivo_progreso.js", "masivo.js")

    def test_modal_confirm(self):
        """Tipo: conservacion. Modal propio: confirmar repite la pulsacion, no la pierde."""
        _comun.correr_node(self, "test_modal_confirm.js", "ask.js")


if __name__ == "__main__":
    unittest.main()
