# -*- coding: utf-8 -*-
"""Una pagina que revienta no debe tumbar la conexion.

Sin red de seguridad, una excepcion mataba el hilo y la conexion se cerraba sin
respuesta. Detras de un proxy inverso (nginx/openresty) eso le llega al usuario como
un "502 Bad Gateway" pelado: no dice que fallo, ni donde mirar, ni si el panel entero
esta caido. Aqui se comprueba que en su lugar sale un 500 explicado y que el fallo
queda anotado.
"""
import ast
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ

DASH = extraer.fuente("DASH")
ARBOL = ast.parse(DASH)

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


NODOS = []      # el nodos REAL del panel portado (lo carga main con _comun.panel)


def cargar_seguro(anotadas, err):
    """Devuelve el _seguro real de la clase del servidor, con dobles.

    Panel portado: _seguro tambien limpia el contexto (usuario y nodo del hilo) antes y
    despues de cada peticion con H._limpiar_ctx, y convierte NodoInvalido/NodoInexistente
    en 400/404 (CONTRATO-F2 §10.1). Por eso se extrae tambien el _limpiar_ctx REAL y se
    le dan el nodos real y un CTX por hilo, como en el modulo."""
    import threading
    fns = {}
    for n in ast.walk(ARBOL):
        if isinstance(n, ast.ClassDef) and n.name == "H":
            for m in n.body:
                if isinstance(m, ast.FunctionDef) and m.name in ("_seguro", "_limpiar_ctx"):
                    fns[m.name] = m
    assert "_seguro" in fns, "no se encontro H._seguro"
    assert "_limpiar_ctx" in fns, "no se encontro H._limpiar_ctx"
    ns = {"sys": type("S", (), {"stderr": err})(),
          "traceback": __import__("traceback"), "html": __import__("html"),
          "bitacora": lambda a, d="": anotadas.append((a, d)),
          "nodos": NODOS[0], "CTX": threading.local()}
    exec(compile(ast.Module(body=[fns["_seguro"], fns["_limpiar_ctx"]], type_ignores=[]),
                 "<h>", "exec"), ns)
    Peticion._limpiar_ctx = ns["_limpiar_ctx"]       # el real, como metodo del doble
    Peticion.CTX = ns["CTX"]
    return ns["_seguro"]


class Peticion:
    """Un 'self' de mentira con lo justo que usa _seguro (_limpiar_ctx: el real, lo pone
    cargar_seguro)."""
    def __init__(self, respondido=False):
        self.path = "/documentacion?embed=1"
        self.command = "GET"
        self.close_connection = False
        self._respondido = respondido
        self.respuestas = []

    def _html(self, s, code=200):
        self.respuestas.append((code, s))


def main():
    import tempfile
    nod, _sec = _comun.panel(tempfile.mkdtemp(prefix="legado-500-"))
    NODOS[:] = [nod]

    # --- 1) la pagina revienta antes de responder ---
    anotadas = []; err = io.StringIO()
    seguro = cargar_seguro(anotadas, err)
    p = Peticion()
    def revienta():
        raise ValueError("algo se rompio generando la guia")
    seguro(p, revienta)

    check("no se propaga: la conexion no se queda muerta", True)
    check("se responde una pagina de error", len(p.respuestas) == 1, p.respuestas)
    code, cuerpo = p.respuestas[0] if p.respuestas else (0, "")
    check("con codigo 500", code == 500, code)
    check("que dice QUE peticion fallo", "/documentacion" in cuerpo, cuerpo[:200])
    check("y que el resto del panel sigue vivo", "sigue funcionando" in cuerpo, cuerpo[:200])
    # adaptada (CONTRATO-F2 §1: lo del servidor viejo, systemctl/journalctl, se quita): el
    # panel corre en el contenedor ids-panel y su registro es el del contenedor
    check("y donde mirar el detalle", "docker logs ids-panel" in cuerpo
          and "journalctl -u suricata-dashboard" not in cuerpo, cuerpo[:200])
    check("el traceback completo va al log del servicio",
          "ValueError" in err.getvalue() and "Traceback" in err.getvalue(), err.getvalue()[:200])
    check("y queda en la bitacora, con la ruta",
          anotadas and anotadas[0][0] == "ERROR-PANEL" and "/documentacion" in anotadas[0][1],
          anotadas)

    # --- 2) si ya habia empezado a responder, no se escribe una segunda respuesta ---
    anotadas2 = []; err2 = io.StringIO()
    seguro2 = cargar_seguro(anotadas2, err2)
    # adaptada: el _seguro portado pone _respondido=False al EMPEZAR cada peticion (en el
    # original no se reiniciaba nunca y, con keep-alive, un error de la peticion siguiente
    # se tomaba por «a medias»). La respuesta a medias se marca, pues, DENTRO de la
    # peticion, como hace el send_response real (self._respondido = True) antes de reventar.
    p2 = Peticion()
    def empieza_y_revienta():
        p2._respondido = True           # lo que hace H.send_response
        revienta()
    seguro2(p2, empieza_y_revienta)
    check("una respuesta a medias no se pisa con otra", p2.respuestas == [], p2.respuestas)
    check("se corta la conexion en su lugar", p2.close_connection is True)
    check("pero el fallo igual queda anotado", len(anotadas2) == 1, anotadas2)
    # y la marca de la peticion anterior no contamina la siguiente (keep-alive)
    p2.respuestas = []; p2.close_connection = False
    seguro2(p2, revienta)
    check("la peticion siguiente de la misma conexion si recibe su 500",
          [c for c, _ in p2.respuestas] == [500], [c for c, _ in p2.respuestas])

    # --- 3) si el que se fue es el cliente, no hay nada que responder ---
    p3 = Peticion()
    def se_fue():
        raise BrokenPipeError(32, "Broken pipe")
    try:
        seguro(p3, se_fue)
        subio = False
    except BrokenPipeError:
        subio = True
    check("un cliente que cuelga no genera pagina de error", subio and p3.respuestas == [],
          p3.respuestas)

    # --- 4) lo normal sigue siendo normal ---
    p4 = Peticion()
    seguro(p4, lambda: p4.respuestas.append((200, "ok")))
    check("una peticion correcta no se toca", p4.respuestas == [(200, "ok")], p4.respuestas)

    # --- 5) panel portado: el contexto no sobrevive a la peticion, tampoco con error ---
    # (CONTRATO-F2 §10.1: «el contexto se restablece tambien con excepcion»; el hilo se
    # reutiliza entre peticiones keep-alive)
    p5 = Peticion()
    def pone_y_revienta():
        nod.poner_nodo("p001")
        Peticion.CTX.user = "admin"
        raise ValueError("revienta con el nodo puesto")
    seguro(p5, pone_y_revienta)
    check("tras un error no queda nodo en el hilo", not nod.hay_nodo(), nod.hay_nodo())
    check("ni el usuario de la peticion", getattr(Peticion.CTX, "user", None) is None,
          getattr(Peticion.CTX, "user", None))
    check("y aun asi se respondio el 500", [c for c, _ in p5.respuestas] == [500], p5.respuestas)

    # --- 6) panel portado: nodo mal escrito -> 400, inexistente -> 404 (CONTRATO-F2 §10.1) ---
    p6 = Peticion()
    seguro(p6, lambda: nod.exigir_pid("p00x"))
    check("un nodo mal escrito es 400, no 500", [c for c, _ in p6.respuestas] == [400],
          [c for c, _ in p6.respuestas])
    p7 = Peticion()
    seguro(p7, lambda: nod.exigir_pid("p999"))
    check("uno que no existe es 404", [c for c, _ in p7.respuestas] == [404],
          [c for c, _ in p7.respuestas])

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada (prueba heredada de suricata-ids-lab). Una pagina que revienta no debe tumbar la conexion.

        Adaptada: el detalle se mira en `docker logs ids-panel` y no en journalctl
        (CONTRATO-F2 §1); _seguro limpia el contexto con el _limpiar_ctx real tambien con
        error y da 400/404 a un nodo invalido/inexistente (CONTRATO-F2 §10.1); la «respuesta
        a medias» se marca dentro de la peticion porque _seguro reinicia _respondido en cada
        una (keep-alive)."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
