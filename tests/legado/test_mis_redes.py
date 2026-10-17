# -*- coding: utf-8 -*-
"""es_mi_cpe(): solo las IPs de TUS redes pueden ir a la cuarentena de CPEs.

Nace de un caso real: 97 IPs publicas golpeando un host interno aparecian como
"CPE origen (quien ataca)", y nada impedia que el motor las tratara como abonados
infectados (ET Open trae firmas ENTRANTES con la palabra "compromised", que este
panel cuenta como infeccion). Con politicas automaticas, podian acabar en la
address-list del MikroTik."""
import ast, os, sys

import unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402


def heredoc(nombre):
    """(adaptada) el programa es ahora un fichero del panel."""
    return extraer.fuente(nombre)


def cargar(nombre, conf, redes_punto=None):
    """Ejecuta el bloque de redes propias de ese script con la config dada.

    (adaptada) el generador corre por nodo y, sin MIS_REDES, toma las `redes` del punto de
    estado.json: se le da un nodos.py real con un punto p001 que tiene `redes_punto`."""
    import tempfile
    _nodos = _comun.cargar_nodos(tempfile.mkdtemp(), {"p001": {"redes": list(redes_punto or [])}})
    cuerpo = heredoc(nombre)
    arbol = ast.parse(cuerpo)
    # mis_redes() cachea por el sello del .conf. Aqui la config la pone la prueba, asi
    # que el sello es fijo; cada caso arma su propio ns, de modo que la cache no se
    # arrastra de un caso al siguiente.
    ns = {"_ipm": __import__("ipaddress"), "ipaddress": __import__("ipaddress"),
          "_conf_key": lambda k, d: conf.get(k, d),
          "conf": lambda: conf,
          "CONF": "(prueba)", "_sello": lambda _p: "fija",
          "_CONF_CACHE": {}, "_REDES_CACHE": {},
          "nodos": _nodos, "NODO": "p001"}
    trozos = []
    for n in arbol.body:
        seg = ast.get_source_segment(cuerpo, n) or ""
        # la memoria por IP del generador (_MI_CPE_CACHE) va con la funcion
        # (adaptada, A-14) el generador tiene las redes por punto: _REDES_DEFECTO y _redes_de_texto
        if ("_MIS_NETS" in seg or "_mis_txt" in seg or "_MI_CPE_CACHE" in seg or "def es_mi_cpe" in seg
                or "def mis_redes" in seg or "_REDES_DEFECTO" in seg or "def _redes_de_texto" in seg):
            trozos.append(seg)
    if not trozos:
        raise SystemExit("no se encontro el bloque de redes propias en " + nombre)
    exec("\n".join(trozos), ns)
    return ns["es_mi_cpe"]


fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c: fallos += 1

def main():
    global fallos
    fallos = 0
    for script in ("suricata-html-report", "suricata-dashboard"):
        print("--- %s ---" % script)
        es_mio = cargar(script, {})

        # por defecto: privadas + CGNAT
        for ip in ("10.0.0.67", "10.6.4.61", "172.19.1.3", "192.168.1.10", "100.64.0.5"):
            check("%s se reconoce como abonado tuyo" % ip, es_mio(ip) is True)

        # las del caso real: atacantes de internet
        # (adaptada: las IPs reales del caso se cambian por las de documentacion, RFC 5737)
        for ip in ("192.0.2.23", "198.51.100.191", "203.0.113.138", "192.0.2.21",
                   "198.51.100.163", "8.8.8.8"):
            check("%s NO puede entrar a la cuarentena de CPEs" % ip, es_mio(ip) is False)

        check("una IP mal formada no se toma por abonado", es_mio("no-es-ip") is False)
        check("vacio tampoco", es_mio("") is False)

        # configurable: un ISP que da IP publica a sus clientes
        es_mio2 = cargar(script, {"MIS_REDES": "203.0.113.0/24, 10.0.0.0/8"})
        check("con MIS_REDES, un cliente con IP publica SI cuenta", es_mio2("203.0.113.9") is True)
        check("y lo de fuera de esas redes sigue sin contar", es_mio2("192.0.2.23") is False)
        check("MIS_REDES reemplaza el valor por defecto (192.168 ya no entra)",
              es_mio2("192.168.1.10") is False)
        print()

    # (capacidad nueva) el generador, sin MIS_REDES: lo privado SIEMPRE (decision del dueño 2026-10-16:
    # las VPN reciben todo lo privado) mas los prefijos adicionales del punto
    es_mio3 = cargar("suricata-html-report", {}, ["198.51.100.0/24"])
    check("generador: sin MIS_REDES valen los prefijos adicionales del punto (198.51.100.0/24 entra)",
          es_mio3("198.51.100.7") is True)
    check("generador: y lo privado siempre (10.0.0.67 entra aunque no este en los adicionales)",
          es_mio3("10.0.0.67") is True)
    check("generador: lo publico fuera de los adicionales no entra", es_mio3("192.0.2.23") is False)

    print("TODO OK" if not fallos else "%d fallo(s)" % fallos)
    return 1 if fallos else 0


class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion + capacidad nueva (redes del punto: lo privado siempre + adicionales, 2026-10-16) (prueba heredada de suricata-ids-lab). es_mi_cpe(): solo las IPs de TUS redes pueden ir a la cuarentena de CPEs."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
