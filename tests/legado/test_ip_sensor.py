# -*- coding: utf-8 -*-
"""La IP del sensor va puesta en los comandos que se copian al MikroTik.

De donde sale: el panel imprimia `streaming-server=IP_DEL_SENSOR:37008` tal cual. Quien lo
copia pega en el router un nombre que no existe, el espejo no llega a ninguna parte y el
sensor se queda ciego — y el panel sigue diciendo exactamente lo mismo, "El espejo NO esta
enviando", sin ninguna pista de que el problema fue eso.

Lo que se prueba:
  - que se elija la IP con la que se llega A ESE router y no una cualquiera. Estas cajas
    tienen varias interfaces (gestion, tunel, red del cliente) y con varios nodos la buena
    cambia segun el nodo: acertar por casualidad con una sola interfaz no demuestra nada.
  - que ante la duda devuelva el hueco en vez de inventarse una IP. Una IP equivocada
    manda el espejo a otra caja y nadie se entera; el hueco al menos se ve.
  - que nunca salga una direccion de loopback ni 0.0.0.0, que romperian el espejo en
    silencio igual.

Adaptada al panel portado (CONTRATO-F2 §2, §4; PRUEBAS-HEREDADAS «Al integrar N/P»): la IP
del sensor ya no se adivina abriendo un socket hacia el router (`ip_del_sensor` desaparece;
en el contenedor saldria la IP de la red de Docker). Es `punto.sensor` (y `tzsp_puerto`) de
estado.json, por punto: `sensor_del_punto(pid)` y `_espejo_datos(pid)` REALES con `nodos.py`
real. Se conserva lo mismo: la IP de ESE punto y no la de otro; ante la duda, el hueco (vacio
y el espejo se niega) en vez de una IP inventada o la "salida por defecto"; nunca loopback ni
0.0.0.0; y que el hueco no vuelva a los comandos.
"""
import ast
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ

DASH = extraer.fuente("DASH")
ARBOL = ast.parse(DASH)
TMP = tempfile.TemporaryDirectory()

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


class SocketFalso(object):
    """Imita lo justo: connect() fija la ruta y getsockname() dice por donde saldria."""

    def __init__(self, rutas, fallan=()):
        self.rutas = rutas          # destino -> IP local con la que se sale
        self.fallan = set(fallan)   # destinos sin ruta
        self.pedidos = []

    def socket(self, *a, **k):
        return self

    def connect(self, par):
        dst = par[0]
        self.pedidos.append(dst)
        if dst in self.fallan or dst not in self.rutas:
            raise OSError("sin ruta a " + dst)

    def getsockname(self):
        return (self.rutas[self.pedidos[-1]], 0)

    def close(self):
        pass


AF_INET = 2
SOCK_DGRAM = 2


_ARBOLES = []


def entorno(sock, puntos=None, mk_host=""):
    """sensor_del_punto y _espejo_datos REALES sobre un estado.json con `puntos` (por defecto
    los de _comun: p001 sensor 100.64.1.1, p002 sensor 100.64.2.1). El socket falso queda en
    el espacio de nombres para comprobar que ya NO se usa para adivinar nada."""
    raiz = os.path.join(TMP.name, "a%d" % len(_ARBOLES))
    _ARBOLES.append(raiz)
    nod, _sec = _comun.panel(raiz, puntos=puntos)
    ns = {"ipaddress": __import__("ipaddress"), "_socket": sock, "nodos": nod, "cargar_mk": lambda: {"HOST": mk_host}}
    sock.AF_INET, sock.SOCK_DGRAM = AF_INET, SOCK_DGRAM
    for n in ARBOL.body:
        if isinstance(n, ast.FunctionDef) and n.name in ("sensor_del_punto", "_espejo_datos"):
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


def espejo_se_niega(ns, pid):
    """Sin sensor valido el espejo no se arma: _espejo_datos lanza (y ningun comando sale)."""
    try:
        ns["_espejo_datos"](pid)
    except ValueError as ex:
        return str(ex)
    return ""


def main():
    # --- con varios nodos, cada router ve una IP distinta de este mismo sensor ---------
    # CONTRATO-F2 §4: ya no se averigua con un socket; cada punto publica la suya en
    # estado.json (p001 -> 100.64.1.1, p002 -> 100.64.2.1, con su puerto TZSP)
    sk = SocketFalso({"100.64.1.2": "10.87.87.3",        # el socket daria otra cosa:
                      "100.64.2.2": "172.19.1.3",        # no se le pregunta
                      "192.0.2.1": "203.0.113.9"})       # salida por defecto
    puntos = {"p001": dict(_comun.PUNTOS["p001"]),
              "p002": dict(_comun.PUNTOS["p002"], tzsp_puerto=37010)}
    ns = entorno(sk, puntos=puntos, mk_host="100.64.1.2")
    ip = ns["sensor_del_punto"]
    check("da la IP con la que se llega a ESE router", ip("p001") == ("100.64.1.1", 37008),
          ip("p001"))
    check("y con otro nodo da la otra, no la primera", ip("p002") == ("100.64.2.1", 37010),
          ip("p002"))
    check("  y eso es lo que recibe el espejo de cada punto (sensor, puerto, sus redes)",
          ns["_espejo_datos"]("p002") == ("100.64.2.1", 37010, ["10.0.0.0/8"]), ns["_espejo_datos"]("p002"))

    # Sin nodo concreto caia al router configurado y despues a la salida por defecto.
    # CONTRATO-F2 §3/§10.1: sin punto concreto no hay "router configurado" ni salida por
    # defecto a la que caer: el hueco, y el espejo no se arma.
    check("sin nodo concreto no se usa ningun router configurado: el hueco",
          ip("")[0] == "" and ip("p009")[0] == "" and "sensor" in espejo_se_niega(ns, ""),
          (ip(""), ip("p009")))
    check("y no se adivina por la salida por defecto: ningun socket abierto",
          sk.pedidos == [], sk.pedidos)

    # --- ante la duda, el hueco: una IP equivocada es peor que ninguna ------------------
    sin = {"p001": {k: v for k, v in _comun.PUNTOS["p001"].items() if k != "sensor"}}
    ns3 = entorno(SocketFalso({"192.0.2.1": "203.0.113.9"}), puntos=sin)
    check("sin ninguna ruta devuelve el hueco, no una IP inventada",
          ns3["sensor_del_punto"]("p001")[0] == "" and "no publica" in espejo_se_niega(ns3, "p001"),
          (ns3["sensor_del_punto"]("p001"), espejo_se_niega(ns3, "p001")))
    # (se mide ya: nodos es un solo modulo y el siguiente entorno() lo recarga con otro arbol)
    respaldo = (ns3["sensor_del_punto"]("p001"), espejo_se_niega(ns3, "p001"))

    # Un loopback rompe el espejo igual que un nombre inexistente, y encima parece valido.
    malos = {"p001": dict(_comun.PUNTOS["p001"], sensor="127.0.0.1"),
             "p002": dict(_comun.PUNTOS["p002"], sensor="0.0.0.0")}
    ns4 = entorno(SocketFalso({}), puntos=malos)
    check("nunca devuelve loopback ni 0.0.0.0",
          ns4["sensor_del_punto"]("p001")[0] == "" and ns4["sensor_del_punto"]("p002")[0] == ""
          and espejo_se_niega(ns4, "p001") and espejo_se_niega(ns4, "p002"),
          (ns4["sensor_del_punto"]("p001"), ns4["sensor_del_punto"]("p002")))

    # Un router inalcanzable no puede dejar sin respuesta al resto del diagnostico.
    sk5 = SocketFalso({}, fallan=["100.64.2.2", "192.0.2.1"])
    ns5 = entorno(sk5)
    check("si ese router no responde, sigue probando",
          ns5["sensor_del_punto"]("p002") == ("100.64.2.1", 37008) and sk5.pedidos == [],
          (ns5["sensor_del_punto"]("p002"), sk5.pedidos))

    # --- y que el hueco no haya vuelto a los comandos ----------------------------------
    # el espejo ya no es /tool sniffer sino las sniff-tzsp de "Montar espejo" (§4, OPERACION
    # §2): el diagnostico compara con el sensor del punto en vez de imprimir un comando
    check("el espejo del diagnostico ya no lleva el hueco",
          "streaming-server=IP_DEL_SENSOR" not in DASH and "IP_DEL_SENSOR" not in DASH
          and "sensor_del_punto(_pid)" in DASH, "")
    check("los dos schedulers tampoco",
          "IP_DEL_SENSOR:PUERTO" not in DASH, "")
    check("ni el ejemplo de mangle de la documentacion",
          "sniff-target=IP_IDS" not in DASH, "")
    # el hueco sigue existiendo como ultimo recurso, que es lo que hace segura la funcion:
    # ahora es el sensor vacio, y _espejo_datos se niega a armar el espejo sin el
    check("pero se conserva como valor de respaldo",
          respaldo[0] == ("", 37008) and "no publica" in respaldo[1], respaldo)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada (CONTRATO-F2 §3, §4): la IP del sensor es punto.sensor/tzsp_puerto de estado.json (sensor_del_punto y _espejo_datos reales) en vez de adivinarla por la ruta (ip_del_sensor desaparece); sin punto concreto, el hueco (sin router por defecto). La IP del sensor va puesta en los comandos que se copian al MikroTik."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
