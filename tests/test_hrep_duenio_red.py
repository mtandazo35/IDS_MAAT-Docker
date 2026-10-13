"""html_report.py: el dueño de cada IP (PTR / RDAP) no puede retener la generacion.

Tipo: correccion de defecto (visto en local, 2026-10-13). `socket.setdefaulttimeout` no vale para
`gethostbyaddr`: cada IP sin PTR bloqueaba lo que quisiera el resolvedor (~12 s medidos), una
detras de otra, hasta 60 por corrida. Un punto tardaba minutos y el cambio de ventana del panel se
quedaba en «generando…» detras. Se ejecutan las funciones REALES del generador (extraidas del
fuente) con un resolvedor falso: colgado o lento, sin red.
"""
import ast
import os
import socket
import threading
import time
import unittest

FUENTE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "images", "panel", "rootfs", "usr", "local", "lib", "ids-panel", "html_report.py")
FUNCIONES = ("_resolver_red", "_lanzar", "_hace_falta", "precargar_duenios", "duenio", "cerrar_duenios")


def generador(gethostbyaddr, rdap=lambda ip: ("", ""), presupuesto=1.0, por_ip=0.5, paralelo=8, ptr=1.5):
    """Espacio de nombres con las funciones reales de html_report.py y un resolvedor falso."""
    arbol = ast.parse(open(FUENTE, encoding="utf-8").read())
    defs = [n for n in arbol.body if isinstance(n, ast.FunctionDef) and n.name in FUNCIONES]
    assert len(defs) == len(FUNCIONES), [n.name for n in defs]

    class Socket:
        pass
    falso = Socket()
    falso.gethostbyaddr = gethostbyaddr
    ns = {"socket": falso, "threading": threading, "time": time, "_rdap_org": rdap,
          "_reg_dom": lambda h: ".".join(h.split(".")[-2:]), "_ORG_DOM": {"google.com": "Google"},
          "_IPINFO_TTL": 3600, "_IPINFO_MAX_NUEVOS": 60, "_SIN_RED": False,
          "_IPINFO_PRESUPUESTO_S": presupuesto, "_IPINFO_ESPERA_IP_S": por_ip,
          "_IPINFO_PTR_S": ptr, "_IPINFO_FIN_S": 2.0, "guardados": [],
          "_ipinfo": {}, "_ipinfo_nuevos": 0, "_ipinfo_sucio": False, "_ipinfo_gasto": 0.0,
          "_ipinfo_vuelo": {}, "_IPINFO_LOCK": threading.Lock(),
          "_IPINFO_SEM": threading.BoundedSemaphore(paralelo)}
    exec(compile(ast.Module(body=defs, type_ignores=[]), FUENTE, "exec"), ns)
    ns["_guardar_ipinfo"] = lambda: ns["guardados"].append(dict(ns["_ipinfo"]))
    return ns


IPS = ["203.0.113.%d" % i for i in range(1, 21)]


class DuenioRed(unittest.TestCase):
    def test_resolvedor_colgado_no_retiene_mas_que_el_presupuesto(self):
        """20 IPs con un resolvedor que no contesta nunca: la corrida espera como mucho el
        presupuesto (1 s), no 20 x lo que tarde el resolvedor, y salen «-»."""
        para = threading.Event()
        self.addCleanup(para.set)
        def colgado(ip):
            para.wait(60)
            raise socket.herror("sin respuesta")
        ns = generador(colgado)
        t = time.monotonic()
        res = [ns["duenio"](ip) for ip in IPS]
        self.assertLess(time.monotonic() - t, 1.6)
        self.assertEqual(set(res), {("-", False)})

    def test_las_consultas_van_en_paralelo(self):
        """10 IPs que tardan 0,5 s cada una: en serie serian 5 s; precargadas en paralelo, todas
        resueltas en poco mas de 0,5 s."""
        def lento(ip):
            time.sleep(0.5)
            return ("srv-%s.google.com" % ip.replace(".", "-"), [], [ip])
        ns = generador(lento, presupuesto=4.0, por_ip=2.0)
        t = time.monotonic()
        ns["precargar_duenios"](IPS[:10])
        res = [ns["duenio"](ip) for ip in IPS[:10]]
        self.assertLess(time.monotonic() - t, 1.5)
        self.assertEqual(set(res), {("Google", True)})

    def test_sin_ptr_va_a_rdap_y_queda_en_cache(self):
        """Sin PTR se pregunta el operador por RDAP; lo resuelto queda en la cache (para guardar)
        y la segunda vez no se vuelve a la red."""
        llamadas = []
        def sin_ptr(ip):
            llamadas.append(ip)
            raise socket.herror("sin PTR")
        ns = generador(sin_ptr, rdap=lambda ip: ("Operador Ejemplo", "EC"))
        self.assertEqual(ns["duenio"](IPS[0]), ("Operador Ejemplo · EC", False))
        self.assertEqual(ns["_ipinfo"][IPS[0]]["via"], "rdap")
        self.assertTrue(ns["_ipinfo_sucio"])
        self.assertEqual(ns["duenio"](IPS[0]), ("Operador Ejemplo · EC", False))
        self.assertEqual(llamadas, [IPS[0]])

    def test_lo_que_llega_tarde_queda_para_la_proxima(self):
        """Una IP que contesta despues del presupuesto sale «-» en esta corrida, pero su resultado
        entra en la cache en cuanto llega (lo guarda _guardar_ipinfo o la corrida siguiente)."""
        def tarde(ip):
            time.sleep(0.4)
            return ("x.google.com", [], [ip])
        ns = generador(tarde, presupuesto=0.1, por_ip=0.1)
        self.assertEqual(ns["duenio"](IPS[0]), ("-", False))
        time.sleep(0.6)
        self.assertEqual(ns["duenio"](IPS[0]), ("Google", True))

    def test_ptr_colgado_pasa_a_rdap_y_entra_en_la_cache(self):
        """Correccion de defecto: un PTR inexistente tarda 5-16 s en fallar (medido) y la consulta
        se quedaba colgada de el: esas IPs no llegaban NUNCA a la cache y salian «-» en cada
        corrida. Ahora, pasado _IPINFO_PTR_S, se pregunta a RDAP."""
        para = threading.Event()
        self.addCleanup(para.set)
        def colgado(ip):
            para.wait(60)
            raise socket.herror("sin respuesta")
        ns = generador(colgado, rdap=lambda ip: ("Operador Ejemplo", "EC"), presupuesto=2.0,
                       por_ip=1.0, ptr=0.3)
        t = time.monotonic()
        self.assertEqual(ns["duenio"](IPS[0]), ("Operador Ejemplo · EC", False))
        self.assertLess(time.monotonic() - t, 0.9)
        self.assertEqual(ns["_ipinfo"][IPS[0]]["via"], "rdap")

    def test_al_cerrar_espera_lo_que_va_en_vuelo_y_guarda(self):
        """Lo que no llego a la pagina aterriza antes de guardar la cache (como mucho
        _IPINFO_FIN_S): la proxima corrida ya lo tiene."""
        def lento(ip):
            time.sleep(0.4)
            return ("x.google.com", [], [ip])
        ns = generador(lento, presupuesto=0.05, por_ip=0.05)
        ns["precargar_duenios"](IPS[:5])
        self.assertEqual(ns["duenio"](IPS[0]), ("-", False))
        ns["cerrar_duenios"]()
        self.assertEqual(len(ns["guardados"]), 1)
        self.assertEqual(set(ns["guardados"][0]), set(IPS[:5]))


if __name__ == "__main__":
    unittest.main()
