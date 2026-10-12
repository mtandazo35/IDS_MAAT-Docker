# -*- coding: utf-8 -*-
"""Ni un confirm(), alert() o prompt() del navegador en todo el proyecto.

El dialogo nativo sale rotulado con el host ("JavaScript de https://suricata.ejemplo.net"),
no admite formato ni un boton con el verbo de la accion, y no deja distinguir a la vista
una pregunta inofensiva de una que corta el internet de un abonado. Encima bloquea el hilo
del navegador.

Lo que protege esta prueba:
  - que no vuelva a colarse uno al añadir un boton (es lo comodo de escribir);
  - que el modal este REALMENTE en la pagina: el panel lo mete en la barra de navegacion,
    que llevan todas sus paginas, y el informe —que es un HTML suelto, sin esa barra— se
    lleva su propia copia. Si faltara, ask() seria un ReferenceError y el boton no haria
    nada en absoluto, que es peor que el dialogo feo.
"""
import os
import re
import sys

import unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402


def heredoc(nombre):
    """(adaptada) el programa es ahora un fichero del panel."""
    return extraer.fuente(nombre)


def _todo_el_panel():
    """(adaptada) antes, install-suricata.sh entero; ahora, todo lo que sirve o pinta el panel:
    cada .py y .js bajo lib/ids-panel/ (tambien lo que anadan Puntos y Eventos) y share/ids-panel/."""
    textos = []
    for raiz in (extraer.LIB, extraer.SHARE):
        for d, _subdirs, fs in os.walk(raiz):
            for f in sorted(fs):
                if f.endswith((".py", ".js", ".html")) and not f.endswith(".min.js"):
                    with open(os.path.join(d, f), encoding="utf-8", errors="replace") as fh:
                        textos.append(fh.read())
    return "\n".join(textos)


SRC = _todo_el_panel()


DASH = heredoc("suricata-dashboard")
HREP = heredoc("suricata-html-report")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1

def main():
    global fallos
    fallos = 0
    # --- ni uno, en ningun programa --------------------------------------------------------
    # Se busca en TODO el archivo, no solo en los dos programas con paginas: un confirm() en
    # cualquier otro heredoc seria igual de nativo. Los comentarios no cuentan.
    _sin_comentarios = "\n".join(l for l in SRC.split("\n") if not l.lstrip().startswith("#"))
    for fn in ("confirm", "alert", "prompt"):
        usos = re.findall(r"(?<![A-Za-z0-9_.])" + fn + r"\s*\(", _sin_comentarios)
        check("no queda ningun %s() del navegador" % fn, not usos, "%d uso(s)" % len(usos))

    # --- y el reemplazo esta donde hace falta -----------------------------------------------
    for nom, prog in (("panel", DASH), ("informe", HREP)):
        check("el %s define el modal (markup)" % nom,
              "id=askov" in prog and "id=asktit" in prog and "id=asktxt" in prog
              and "id=askok" in prog and "id=askno" in prog, "")
        check("el %s define ask() y aviso()" % nom,
              "function ask(e,t,x,ok,tono)" in prog and "function aviso(t,x)" in prog, "")
        check("en el %s se puede cerrar pulsando fuera" % nom,
              "if(event.target===this&&this._dn===this){askNo()}" in prog, "")   # con guarda de seleccion

    # El panel lo cuelga de la barra de navegacion, que es lo unico que llevan TODAS sus
    # paginas. Si estuviera en una sola pagina, los botones de las demas no harian nada.
    check("el panel lo sirve desde la barra de navegacion, no pagina a pagina",
          "+ _ASK)" in DASH and DASH.count("_ASK = (") == 1, "")

    # El informe es un HTML suelto que se guarda y se abre a mano: tiene que llevarlo dentro.
    check("el informe se lo lleva dentro del documento",
          "{_ASK}</main></body></html>" in HREP, "")
    check("y con su propio estilo, que no hereda ninguno",
          "_ASK = ('<style>.askov{" in HREP, "")

    # --- cada llamada pasa el elemento que se pulso ------------------------------------------
    # ask() necesita el boton (o el form) para poder repetir la pulsacion al confirmar. Pasarle
    # otra cosa lo dejaria abriendo el modal y sin ejecutar nunca la accion.
    llamadas = re.findall(r"return ask\((\w+)\s*,", DASH) + re.findall(r"ask\((\w+)\s*,'", HREP)
    check("toda confirmacion le pasa a ask() el elemento pulsado",
          llamadas and all(x in ("this", "b") for x in llamadas), llamadas)
    check("estan las confirmaciones de las acciones que tocan el router",
          DASH.count("return ask(this,") >= 7, DASH.count("return ask(this,"))

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada a los ficheros del panel (prueba heredada de suricata-ids-lab). Ni un confirm(), alert() o prompt() del navegador en todo el panel."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
