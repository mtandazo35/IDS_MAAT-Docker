# -*- coding: utf-8 -*-
"""Seleccionar texto dentro de un modal no lo cierra.

El usuario arrastraba para seleccionar un valor dentro del formulario de MikroTik, soltaba
el raton fuera de la caja y el modal se cerraba (y con el, todo lo escrito). El navegador
dispara `click` en el elemento donde se SUELTA, y la capa de fondo cerraba con cualquier
click sobre si misma. Ahora cierra solo si el raton tambien se PULSO sobre la capa.

Lo que se protege: toda capa que cierre al pulsar fuera lleva la guarda (mousedown y click
en la misma capa); no queda ninguna con el cierre antiguo; y la guarda hace lo que dice
(se simula en un DOM minimo: pulsar dentro y soltar fuera no cierra; pulsar y soltar
fuera si cierra).
"""
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ
# (adaptada) antes se recorria install-suricata.sh entero; ahora, los programas del panel que
# pintan HTML: dashboard.py y html_report.py
SRC = extraer.fuente("DASH") + "\n" + extraer.fuente("HREP")



def capas():
    """[(nombre, onmousedown, onclick)] de cada capa que cierra al pulsar fuera, tal como llega
    al navegador (sin el escapado de Python ni las llaves dobles de los f-strings)."""
    pares = []
    for m in re.finditer(r'onmousedown=\\?"([^"]*?)\\?" onclick=\\?"(if\(event\.target===this[^"]*?)\\?">', SRC):
        md, ck = (x.replace('\\"', '"').replace("{{", "{").replace("}}", "}") for x in m.groups())
        pares.append(("capa %d (%s)" % (len(pares) + 1, ck[ck.find("{") + 1:ck.rfind("}")]), md, ck))
    return pares


fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


class Nodo(object):
    """Lo justo de un elemento para ejecutar los dos manejadores inline."""
    def __init__(self):
        self._dn = None
        self.cerrado = False

    def mousedown(self, target):
        self._dn = target          # onmousedown="this._dn=event.target"

    def click(self, target):       # onclick="if(event.target===this&&this._dn===this){cerrar}"
        if target is self and self._dn is self:
            self.cerrado = True


def main():
    viejos = re.findall(r'onclick=\\?"if\(event\.target===this\)(?!&&this\._dn===this)', SRC)
    check("ninguna capa cierra solo con el click (sin mirar donde se pulso)", not viejos, len(viejos))
    con_guarda = re.findall(
        r'onmousedown=\\?"this\._dn=event\.target\\?" onclick=\\?"if\(event\.target===this&&this\._dn===this\)\{', SRC)
    check("las capas que cierran al pulsar fuera llevan la guarda (hay %d)" % len(con_guarda),
          len(con_guarda) >= 11, len(con_guarda))
    for nombre in ("aptmodal", "fichamodal", "askov", "exmodal", "mmasivo", "mkwait", "ovlNew"):
        i = SRC.find("id=" + nombre) if ("id=" + nombre) in SRC else SRC.find(nombre)
        trozo = SRC[max(0, i - 40): i + 320]
        check("la capa %s lleva la guarda" % nombre, "this._dn===this" in trozo, trozo[:140])

    # la guarda, simulada: el navegador manda el click al elemento donde se SUELTA
    capa = Nodo(); caja = object()
    capa.mousedown(caja); capa.click(capa)        # pulsar dentro de la caja, soltar fuera
    check("pulsar dentro y soltar fuera NO cierra", capa.cerrado is False, "")
    capa = Nodo()
    capa.mousedown(capa); capa.click(capa)        # pulsar y soltar fuera
    check("pulsar y soltar fuera SI cierra", capa.cerrado is True, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion (prueba heredada de suricata-ids-lab). Seleccionar texto dentro de un modal no lo cierra."""
        _comun.correr_main(self, main)

    def test_guarda_real_en_node(self):
        """Tipo: conservacion (adaptada a comportamiento). Los manejadores REALES de cada capa,
        ejecutados con node: pulsar dentro y soltar fuera no cierra; pulsar y soltar fuera, si."""
        pares = capas()
        self.assertTrue(pares, "no se encontro ninguna capa con onmousedown/onclick")
        import json as _json
        with tempfile.TemporaryDirectory() as td:
            ruta = os.path.join(td, "pares.json")
            with open(ruta, "w", encoding="utf-8") as f:
                _json.dump(pares, f)
            _comun.correr_node(self, "guarda_capas.js", ruta)


if __name__ == "__main__":
    unittest.main()
