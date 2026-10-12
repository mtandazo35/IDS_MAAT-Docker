# -*- coding: utf-8 -*-
"""Cobertura del sensor: sin alertas no es lo mismo que sin ataques.

Esto nace de un caso real. El MikroTik empezo a mandar el espejo a otra direccion; el
receptor lo rechazo entero por no estar en la lista de origenes autorizados; Suricata
dejo de ver practicamente todo. Y el panel siguio diciendo "viendo trafico" durante
horas, porque SI entraban algunos paquetes. Una red sin alertas parecia limpia y era
un sensor ciego.

Lo que se comprueba aqui es que ese estado se detecta y se dice con todas las letras,
y que un nodo que deja de mandar espejo no pasa desapercibido.
"""
import ast
import json
import os
import sys
import unittest
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ

DASH = extraer.fuente("DASH")
ARBOL = ast.parse(DASH)

PIEZAS = ("TZSP_ESTADO", "COBERTURA_MUDO", "COBERTURA_RECHAZO", "cobertura_tzsp",
          "DESPERDICIO_AVISO", "desperdicio_espejo")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp):
    ns = {"json": json, "os": os, "time": time}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["TZSP_ESTADO"] = os.path.join(tmp, "tzsp.json")
    return ns


def estado(ns, aceptados, rechazados, ultimo_visto, esperados, edad=10):
    with open(ns["TZSP_ESTADO"], "w", encoding="utf-8") as f:
        json.dump({"ts": int(time.time() - edad),
                   "ventana": {"aceptados": aceptados, "rechazados": rechazados},
                   "ultimo_visto": ultimo_visto, "esperados": esperados}, f)


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)
    ahora = time.time()

    # --- todo bien ------------------------------------------------------------------
    estado(ns, {"100.64.0.2": 1900000}, {}, {"100.64.0.2": int(ahora - 5)},
           ["100.64.0.2/32"])
    c = ns["cobertura_tzsp"](ahora)
    check("con un nodo sano la cobertura es del 100%", c["cobertura"] == 100.0, c)
    check("y no hay nodos mudos", c["mudos"] == [], c["mudos"])
    check("ni rechazo", c["ratio_rechazo"] == 0.0, c["ratio_rechazo"])

    # --- EL CASO REAL: el espejo llega, pero de quien no debe -------------------------
    estado(ns, {"100.64.0.2": 2547}, {"203.0.113.9": 3773590},
           {"100.64.0.2": int(ahora - 5)}, ["100.64.0.2/32"])
    c = ns["cobertura_tzsp"](ahora)
    check("se detecta que casi todo el espejo se esta tirando",
          c["ratio_rechazo"] > 0.99, c["ratio_rechazo"])
    check("y se dice DE QUIEN llega, para poder arreglarlo",
          c["intrusos"] == ["203.0.113.9"], c["intrusos"])
    check("el umbral de aviso se cruza de sobra",
          c["ratio_rechazo"] >= ns["COBERTURA_RECHAZO"])
    check("aunque el nodo bueno siga mandando algo, no lo tapa",
          c["aceptados"] == 2547 and c["rechazados"] == 3773590, c)

    # --- un nodo se calla -------------------------------------------------------------
    estado(ns, {"100.64.0.2": 1000}, {},
           {"100.64.0.2": int(ahora - 5), "100.64.0.3": int(ahora - 3600)},
           ["100.64.0.2/32", "100.64.0.3/32"])
    c = ns["cobertura_tzsp"](ahora)
    check("un nodo que lleva una hora sin mandar sale como mudo",
          c["mudos"] == ["100.64.0.3/32"], c["mudos"])
    check("y la cobertura deja de ser del 100%", c["cobertura"] == 50.0, c["cobertura"])
    check("el nodo que si manda no se marca",
          "100.64.0.2/32" not in c["mudos"], c["mudos"])

    # un silencio corto no es un nodo caido: no se avisa por cada microcorte
    estado(ns, {"100.64.0.2": 10}, {},
           {"100.64.0.2": int(ahora - 60)}, ["100.64.0.2/32"])
    check("un silencio de un minuto no dispara el aviso",
          ns["cobertura_tzsp"](ahora)["mudos"] == [])

    # --- sin receptor TZSP no se inventa nada ------------------------------------------
    os.remove(ns["TZSP_ESTADO"])
    check("si no hay receptor, no se reporta cobertura falsa",
          ns["cobertura_tzsp"](ahora) == {})

    # --- el aviso envejece -------------------------------------------------------------
    estado(ns, {"100.64.0.2": 5}, {}, {"100.64.0.2": int(ahora - 5)},
           ["100.64.0.2/32"], edad=900)
    check("se sabe cuando se midio, para no confiar en un dato viejo",
          ns["cobertura_tzsp"](ahora)["edad"] >= 890)

    # --- el espejo que se tira al llegar -------------------------------------------
    # El dia que el panel iba pesado se busco en el codigo: caches, consultas, GIL. No
    # era nada de eso. El MikroTik tenia dos juegos de reglas conviviendo y mandaba
    # 886 Mbps para que el receptor tirase el 91%. El enlace lleno perdia paquetes, y
    # como el TZSP es UDP no se retrasaba: desaparecia. El dato estaba en los contadores
    # del receptor desde el principio y nadie lo miraba.
    d = ns["desperdicio_espejo"]({"rx": 4000000000, "recortados": 3640000000,
                                  "recorte_bytes": 10000})
    check("un 91% recortado se reconoce como desperdicio",
          d["desperdicio_alto"] is True and d["desperdicio"] == 0.91, d)

    d = ns["desperdicio_espejo"]({"rx": 1000, "recortados": 120, "recorte_bytes": 10000})
    check("un recorte pequeno es normal y no avisa", d["desperdicio_alto"] is False, d)

    # Sin recorte activo el contador no dice nada de lo que manda el router: no se puede
    # deducir desperdicio de un dato que no se esta midiendo.
    d = ns["desperdicio_espejo"]({"rx": 4000000000, "recortados": 0, "recorte_bytes": 0})
    check("sin recorte activo no se inventa un diagnostico", d["desperdicio"] is None, d)
    d = ns["desperdicio_espejo"]({"rx": 0, "recortados": 0, "recorte_bytes": 10000})
    check("sin trafico tampoco", d["desperdicio"] is None, d)

    check("el umbral del aviso es explicito y esta por encima de la mitad",
          0.4 <= ns["DESPERDICIO_AVISO"] <= 0.8, ns["DESPERDICIO_AVISO"])

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion (prueba heredada de suricata-ids-lab). Cobertura del sensor: sin alertas no es lo mismo que sin ataques."""
        _comun.correr_main(self, main)

    def test_tzsp_json_del_receptor_nuevo(self):
        """Tipo: capacidad nueva (compatibilidad). cobertura_tzsp() y desperdicio_espejo() leen el
        tzsp.json que escribe el receptor REAL del contenedor vpn (images/vpn/.../tzsp-decap),
        uno por punto en RUN/<pid>/tzsp.json, no el del tzsp-decap viejo del host."""
        sys.path.insert(0, os.path.dirname(_comun.AQUI))          # tests/: _ayuda_vpn
        import _ayuda_vpn as ay
        td = ay.cargar(ay.BIN / "tzsp-decap", "legado_tzsp_decap")
        mk = "100.64.3.2"
        with tempfile.TemporaryDirectory() as tmp:
            ns = entorno(tmp)
            ahora = time.time()
            r = td.Receptor(td.leer_allow(mk + "/32"), 10000, ns["TZSP_ESTADO"], "p003",
                            ahora=ahora - 60)
            trama = ay.tzsp(ay.trama_tcp())
            for _ in range(40):
                r.procesar(trama, mk, ahora - 2, lambda f: None)
            for _ in range(200):
                r.procesar(trama, "192.0.2.9", ahora - 1, lambda f: None)   # quien no debe
            r.escribir_estado(ahora)
            c = ns["cobertura_tzsp"](ahora)
            self.assertEqual(c["mudos"], [])
            self.assertEqual(c["cobertura"], 100.0)
            self.assertEqual(c["intrusos"], ["192.0.2.9"])
            self.assertGreaterEqual(c["ratio_rechazo"], ns["COBERTURA_RECHAZO"])
            with open(ns["TZSP_ESTADO"], encoding="utf-8") as f:
                d = ns["desperdicio_espejo"](json.load(f))
            self.assertIn("desperdicio", d)
            # el MikroTik se calla: pasada la ventana de silencio sale como mudo
            r.escribir_estado(ahora + 3600)
            c = ns["cobertura_tzsp"](ahora + 3600)
            self.assertEqual(c["mudos"], [mk + "/32"])


if __name__ == "__main__":
    unittest.main()
