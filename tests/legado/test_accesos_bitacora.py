# -*- coding: utf-8 -*-
"""Accesos y Bitacora: cada pestana responde una sola pregunta.

Lo que protege:
  - Que el Log dejo de repetir la bitacora. Las dos paginas ensenaban casi lo mismo
    porque mk_log() escribe cada cuarentena TAMBIEN en la bitacora, y los logins
    correctos van igualmente a las dos. Con dos pestanas gemelas nadie sabe cual mirar.
  - Que al quitarlo NO se perdio nada: las cuarentenas siguen estando en la bitacora.
  - Que los intentos FALLIDOS siguen saliendo en Accesos. Son el unico dato que no esta
    en la bitacora (solo anota los logins que entraron), asi que si se cayeran de aqui
    una fuerza bruta contra el panel no se veria en ninguna parte.
"""
import ast
import io
import os
import tempfile
import time

import sys
import unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ

DASH = extraer.fuente("DASH")
ARBOL = extraer.arbol("DASH")

# (adaptada, 2026-10-14) Accesos y Bitacora son ahora un solo Registro: log_page y bitacora_page
# lo abren con su filtro, asi que entran sus piezas
PIEZAS = ("LOG_RETENCION_DIAS", "_cola_lineas", "_ev_ts", "accesos_recientes",
          "_registro_tipo", "_ACCESO_TXT", "registro_eventos", "REGISTRO_TIPOS", "registro_page",
          "log_page", "bitacora_page", "BITACORA_LOG", "LOGIN_LOG", "MK_LOG")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp):
    ns = {"os": os, "time": time, "io": io, "html": __import__("html"), "json": __import__("json"),
          "BASE_CSS": "/*base*/", "nav": lambda r: "<div class=nav></div>"}
    # panel portado: LOGIN_LOG/MK_LOG/BITACORA_LOG se definen con nodos.ruta(); se carga el
    # nodos REAL sobre el arbol temporal y luego se apuntan al tmp como antes
    ns["nodos"], ns["secretos"] = _comun.panel(tmp)
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["LOGIN_LOG"] = os.path.join(tmp, "login.log")
    ns["MK_LOG"] = os.path.join(tmp, "cuarentena.log")
    ns["BITACORA_LOG"] = os.path.join(tmp, "bitacora.log")
    return ns


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)

    # --- lo que hay en cada archivo ------------------------------------------------------
    io.open(ns["LOGIN_LOG"], "w", encoding="utf-8", newline="\n").write(
        "2026-09-25 09:00:00\t203.0.113.7\tadmin\tOK\n"
        "2026-09-25 09:05:00\t198.51.100.4\tadmin\tFAIL\n"
        "2026-09-25 09:06:00\t198.51.100.4\tadmin\tBLOQUEADO\n")
    io.open(ns["MK_LOG"], "w", encoding="utf-8", newline="\n").write(
        "2026-09-25 09:10:00 ENVIADO 192.168.1.50 por=admin botnet\n")
    # mk_log() ya la habia escrito aqui tambien: por eso se veia dos veces
    io.open(ns["BITACORA_LOG"], "w", encoding="utf-8", newline="\n").write(
        "2026-09-25 09:00:00\tadmin\t203.0.113.7\tLOGIN\trol=admin\n"
        "2026-09-25 09:10:00\tadmin\t203.0.113.7\tENVIADO\t192.168.1.50 botnet\n"
        "2026-09-25 09:20:00\tadmin\t203.0.113.7\tCONFIG-MIKROTIK\thost=192.0.2.1 enviar=si\n")

    # --- la fuente de Accesos ------------------------------------------------------------
    rec = ns["accesos_recientes"]()
    check("cada intento de acceso es una fila", len(rec) == 3, rec)
    check("y viene mas nuevo primero", rec[0][0] > rec[-1][0], [r[0] for r in rec])
    check("con fecha, IP, usuario y resultado",
          rec[0] == ("2026-09-25 09:06:00", "198.51.100.4", "admin", "BLOQUEADO"), rec[0])
    check("la cuarentena ya NO entra por aqui",
          not any("192.168.1.50" in " ".join(r) for r in rec), rec)

    # (adaptada, 2026-10-14: «vamos hacer un solo LOG») Accesos y Bitacora son UN registro.
    # Lo que se sigue protegiendo: los fallidos se ven, nada sale dos veces y nada se pierde.
    acc = ns["log_page"]()
    check("/log abre el Registro con el filtro Accesos puesto",
          "<h1>Registro</h1>" in acc and "class='rtipo on' data-tipo='accesos'" in acc, acc[:400])
    check("los intentos fallidos se ven: son el unico sitio donde estan",
          "CLAVE INCORRECTA" in acc and "BLOQUEADO" in acc, "")
    bit = ns["bitacora_page"]()
    check("/bitacora abre el Registro completo", "class='rtipo on' data-tipo=''" in bit, "")
    check("el que entro sale UNA vez (login.log y el LOGIN de la bitacora eran el mismo)",
          bit.count("ENTRÓ") == 1 and ">LOGIN<" not in bit, bit.count("ENTRÓ"))
    check("la cuarentena sale UNA vez, con su IP (no se relee el log de MikroTik)",
          bit.count("192.168.1.50") == 2, bit.count("192.168.1.50"))       # celda + texto de busqueda
    check("junto a los cambios de configuracion", "CONFIG-MIKROTIK" in bit, "")
    check("cada fila lleva su tipo para filtrar",
          'data-t="accesos"' in bit and 'data-t="cuarentena"' in bit and 'data-t="configuracion"' in bit, "")
    check("y los fallos se marcan para el filtro Fallos", bit.count('data-e="1"') == 2, bit.count('data-e="1"'))

    # --- la separacion, dicha de una vez ------------------------------------------------------
    # Si algun dia vuelve a leerse MK_LOG desde Accesos, esto lo caza.
    fuente = ast.get_source_segment(DASH, next(
        n for n in ARBOL.body
        if getattr(n, "name", "") == "accesos_recientes")) or ""
    check("Accesos no vuelve a leer el log de cuarentena", "MK_LOG" not in fuente, fuente)
    fuente_r = ast.get_source_segment(DASH, next(
        n for n in ARBOL.body if getattr(n, "name", "") == "registro_eventos")) or ""
    check("ni el Registro: la cuarentena ya esta en la bitacora", "MK_LOG" not in fuente_r.split('"""')[-1], "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada (2026-10-14): Accesos y Bitacora son un solo Registro; los intentos fallidos se siguen viendo y nada sale dos veces."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
