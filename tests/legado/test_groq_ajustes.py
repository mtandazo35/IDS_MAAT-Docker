# -*- coding: utf-8 -*-
"""La clave de Groq: se valida antes de guardarla y no vuelve a salir de aqui.

Una clave de API es un secreto que se USA, no que se verifica: no se puede hashear, asi
que lo unico que queda es que no salga del servidor. Por eso lo que se prueba aqui no es
que "funcione", sino lo que pasaria si no funcionara:

  - que una clave invalida se rechace ANTES de guardarse. Guardarla y descubrirlo en la
    primera consulta deja el panel con una clave rota y el error aparece lejos de donde se
    configuro.
  - que una caida de red NO se confunda con una clave mala: se guarda avisando, en vez de
    rechazar una clave buena porque el servidor no tenia salida en ese momento.
  - que el modelo salga de la lista REAL de la cuenta. Groq retira modelos cada cierto
    tiempo; un nombre que ya no existe no falla al guardarlo, falla en la primera consulta.
  - y que el valor de la clave no aparezca en ninguna pagina.
"""
import ast
import json
import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ

DASH = extraer.fuente("DASH")
ARBOL = extraer.arbol("DASH")

PIEZAS = ("GROQ_URL", "FEEDS_SECRETOS", "SECRETOS_AVISO", "_feeds_conf_crudo", "_feeds_conf_get", "_feeds_conf_set", "groq_key", "groq_configurada",
          "groq_set", "groq_modelo", "groq_set_modelo", "groq_modelos", "groq_probar")

fallos = 0
_PAN = []      # (nodos, secretos) del panel portado, uno para toda la prueba (lo pone main)


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


class HTTPError(Exception):
    def __init__(self, code):
        self.code = code


class URLError(Exception):
    pass


class _Resp(object):
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return json.dumps(self.payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def entorno(respuesta=None, conf=None):
    """El panel con un Groq de mentira. `respuesta` es el objeto a devolver o la excepcion
    a lanzar; se guarda tambien la peticion para poder mirarla."""
    visto = {}

    def _urlopen(req, timeout=0):
        visto["url"] = req.url
        visto["headers"] = dict(getattr(req, "headers", {}) or {})
        if isinstance(respuesta, Exception):
            raise respuesta
        return _Resp(respuesta or {})

    req_mod = type("R", (), {"Request": None, "urlopen": staticmethod(_urlopen)})

    class _Req(object):
        def __init__(self, url, headers=None, **k):
            self.url = url
            self.headers = headers or {}
    req_mod.Request = _Req

    urllib_falso = type("U", (), {
        "request": req_mod,
        "error": type("E", (), {"HTTPError": HTTPError, "URLError": URLError}),
    })
    # panel portado (CONTRATO-F2 §2, §10.3): `secretos` REAL; la clave de Groq se guarda
    # cifrada en feeds.conf con la clave maestra de prueba y se descifra al leerla
    ns = {"nodos": _PAN[0][0], "secretos": _PAN[0][1], "threading": __import__("threading"),
          "json": json, "os": os, "urllib": urllib_falso,
          "TimeoutError": TimeoutError,
          "FEEDS_CONF": conf or os.path.join(tempfile.mkdtemp(), "feeds.conf")}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["_visto"] = visto
    return ns


def main():
    _PAN[:] = [_comun.panel(tempfile.mkdtemp())]
    MS = {"data": [{"id": "modelo-grande"}, {"id": "modelo-chico"}]}

    # --- una clave que Groq rechaza no se guarda ---------------------------------------
    ns = entorno(HTTPError(401))
    est, det, ms = ns["groq_probar"]("mala")
    check("una clave rechazada devuelve False", est is False, (est, det))
    check("y se dice que la rechazo Groq, no otra cosa", "rechazó la clave" in det, det)
    check("sin modelos que ofrecer", ms == [], ms)

    ns = entorno(HTTPError(403))
    check("403 tambien es rechazo", ns["groq_probar"]("x")[0] is False, "")

    # --- pero una caida de red no es una clave mala -------------------------------------
    # Rechazar aqui seria tirar una clave buena porque el servidor no tenia salida.
    ns = entorno(URLError("sin ruta"))
    est, det, _ = ns["groq_probar"]("buena")
    check("sin red no se decide: ni valida ni invalida", est is None, (est, det))
    check("y se dice que no se pudo comprobar", "no se pudo comprobar" in det, det)

    ns = entorno(HTTPError(500))
    check("un error del servidor tampoco condena la clave",
          ns["groq_probar"]("x")[0] is None, "")

    # 429 es cuota, no clave mala: la clave sirve, solo que ahora no se puede usar
    ns = entorno(HTTPError(429))
    check("429 es cuota agotada, y la clave vale", ns["groq_probar"]("x")[0] is True, "")

    # --- clave buena: ademas dice que modelos hay --------------------------------------
    ns = entorno(MS)
    est, det, ms = ns["groq_probar"]("buena")
    check("una clave valida devuelve True", est is True, (est, det))
    check("con los modelos de la cuenta, ordenados",
          ms == ["modelo-chico", "modelo-grande"], ms)
    check("se pregunta por los modelos y no se gasta una consulta de chat",
          ns["_visto"]["url"].endswith("/models"), ns["_visto"]["url"])
    check("la clave viaja en la cabecera, no en la URL",
          "Bearer buena" in str(ns["_visto"]["headers"].values())
          and "buena" not in ns["_visto"]["url"], ns["_visto"]["url"])

    # Una cuenta sin modelos no sirve para nada, aunque la clave sea correcta.
    ns = entorno({"data": []})
    check("una cuenta sin modelos no se da por buena",
          ns["groq_probar"]("x")[0] is None, "")

    # --- guardar y leer ----------------------------------------------------------------
    d = tempfile.mkdtemp()
    cf = os.path.join(d, "feeds.conf")
    ns = entorno(MS, conf=cf)
    check("sin clave, no esta configurada", ns["groq_configurada"] () is False, "")
    ns["groq_set"]("clave-secreta")
    ns["groq_set_modelo"]("modelo-grande")
    ns2 = entorno(MS, conf=cf)      # proceso nuevo: tiene que leerlo del archivo
    check("la clave sobrevive a un reinicio", ns2["groq_key"]() == "clave-secreta", "")
    check("y el modelo tambien", ns2["groq_modelo"]() == "modelo-grande", "")
    check("y ya consta como configurada", ns2["groq_configurada"]() is True, "")

    # el archivo es el de los demas secretos, no uno nuevo suelto por ahi
    # (adaptada, CONTRATO-F2 §10.3: la clave de Groq es un secreto y va CIFRADA con la
    # clave maestra; el original la dejaba en claro. Sigue en feeds.conf, con su nombre)
    with open(cf, encoding="utf-8") as f:
        txt = f.read()
    check("se guarda en el archivo de claves de siempre",
          "GROQ_API_KEY=" in txt, txt)
    check("  y cifrada, nunca en claro (§10.3)", "clave-secreta" not in txt, txt)

    ns2["groq_set"]("")
    ns2["groq_set_modelo"]("")
    check("borrar deja el archivo sin la clave",
          "GROQ_API_KEY" not in open(cf, encoding="utf-8").read(), "")

    # --- lo que no se puede probar aqui, pero se puede exigir --------------------------
    # El valor de la clave nunca se pinta: las paginas preguntan si ESTA configurada, no
    # cual es. Un `value=` con la clave la dejaria en el HTML de cualquiera que entre.
    # (adaptada, 2026-10-14) la ventana se arma por bloques (b_abusech, b_aidb, b_groq...) antes de
    # card_feeds: se mira desde el primer bloque hasta el final de la tarjeta
    _ini = DASH.index("b_abusech = _bloque(")
    _pag = DASH[_ini:DASH.index("card_feeds = (", _ini) + 6000]
    check("la pagina pregunta si hay clave, no cual es",
          "groq_configurada()" in _pag and "groq_key()" not in _pag, "")
    check("el campo es de tipo password y no lleva valor precargado",
          "name=groqkey" in DASH and "value='" + "' name=groqkey" not in DASH, "")

    # Guardar la clave es de administrador: con operador o lectura, no.
    _rt = DASH[DASH.index('if ruta == "/feeds/groq":'):]
    _rt = _rt[:_rt.index('if ruta == "/feeds/actualizar":')]
    # (adaptada, CONTRATO-F2 §10.2: el rol se comprueba en el servidor y el que no lo tiene
    # recibe un 403 que queda en la bitacora, `_prohibido()`; el `_deny()` viejo solo
    # mandaba al login. La barrera de administrador es la misma.)
    _proh = DASH[DASH.index("    def _prohibido(self):"):]
    _proh = _proh[:_proh.index("\n    def ", 10)]
    check("guardar la clave es solo de administrador",
          'if not self._puede("ajustes.feeds"):\n                return self._prohibido()' in _rt
          and "403" in _proh and "SIN-PERMISO" in _proh, _rt[:120])
    check("BORRAR se lleva tambien el modelo, no deja uno huerfano",
          'groq_set(""); groq_set_modelo("")' in _rt, "")
    # Un modelo que la cuenta ya no tiene no se guarda: fallaria en la primera consulta,
    # lejos de la pantalla donde se configuro.
    check("no se guarda un modelo que la cuenta no ofrece",
          "mod in modelos" in _rt, "")
    check("y queda registrado en la bitacora quien toco la clave",
          'bitacora("CONFIG-GROQ"' in _rt, "")

    # La promesa de diseno: la IA no corta a nadie. Si algun dia deja de ser verdad, que
    # al menos no se siga diciendo en pantalla.
    check("la pantalla dice que la IA no corta a nadie",
          "La IA no corta a nadie" in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada (CONTRATO-F2 §2, §10.2, §10.3): secretos real; la clave de Groq se guarda CIFRADA en feeds.conf (antes en claro); sin rol de admin, 403 con `_prohibido()` (antes `_deny()`). La clave de Groq: se valida antes de guardarla y no vuelve a salir de aqui."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
