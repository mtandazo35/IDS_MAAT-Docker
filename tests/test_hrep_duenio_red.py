"""Dueño de las IP (PTR / RDAP): solo bajo demanda y nunca reteniendo la generacion.

Tipo: correccion de defecto (visto en local, 2026-10-13). El generador consultaba el DNS inverso de
cada IP en cada regeneracion, en serie y sin tope real (`setdefaulttimeout` no vale para
`gethostbyaddr`; un PTR inexistente tarda 5-16 s): 11-215 s por punto, y el cambio de ventana de
En vivo —que ni muestra el dato— esperaba detras. Ahora el generador solo lee la cache y la pestana
Top origenes pide lo que falta a /duenos (duenos.py). Sin red: resolvedor falso. Las IP «publicas»
son del 192.88.99.0/24 (anycast 6to4 retirado, RFC 7526): Python las da por globales y no son de
nadie.
"""
import ast
import importlib
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(RAIZ, "images", "panel", "rootfs", "usr", "local", "lib", "ids-panel")
IPS = ["192.88.99.%d" % i for i in range(1, 21)]


class Duenos(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        sys.path.insert(0, LIB)
        self.addCleanup(sys.path.remove, LIB)
        import duenos
        self.d = importlib.reload(duenos)          # cerrojos y consultas en vuelo de cero
        self.d.CACHE = os.path.join(self.tmp.name, "cache", "ipinfo-cache.json")
        # tabla de registros falsa y ya «fresca»: las pruebas no bajan nada de IANA
        self.d.BOOTSTRAP = os.path.join(self.tmp.name, "cache", "rdap-bootstrap.json")
        os.makedirs(os.path.dirname(self.d.BOOTSTRAP), exist_ok=True)
        with open(self.d.BOOTSTRAP, "w", encoding="utf-8") as f:
            json.dump({"services": [[["192.0.0.0/8"], ["https://rdap.ejemplo-a.test/"]],
                                    [["192.88.0.0/16"], ["http://x.test/", "https://rdap.ejemplo-b.test/rdap/"]]]}, f)
        self.para = threading.Event()
        self.addCleanup(self.para.set)
        self.ptr_llamadas = []
        self.rdap = lambda ip: ("", "")
        self.d.socket = type("S", (), {})()
        self.d.socket.gethostbyaddr = self._ptr
        self.rdap_real = self.d._rdap_org
        self.d._rdap_org = lambda ip: self.rdap(ip)
        self.ptr = lambda ip: (_ for _ in ()).throw(socket.herror("sin PTR"))

    def _ptr(self, ip):
        self.ptr_llamadas.append(ip)
        return self.ptr(ip)

    def colgado(self, ip):
        self.para.wait(60)
        raise socket.herror("sin respuesta")

    def test_ptr_colgado_pasa_a_rdap_y_queda_en_disco(self):
        """Un PTR que no contesta no se espera mas de PTR_S: se pregunta a RDAP y el resultado
        queda en la cache EN DISCO (antes esas IP no llegaban nunca y salian «-» siempre)."""
        self.d.PTR_S = 0.3
        self.ptr = self.colgado
        self.rdap = lambda ip: ("Operador Ejemplo", "EC")
        t = time.monotonic()
        r = self.d.resolver([IPS[0]], espera=3)
        self.assertLess(time.monotonic() - t, 1.5)
        self.assertEqual(r[IPS[0]]["org"], "Operador Ejemplo · EC")
        self.assertEqual(r[IPS[0]]["via"], "rdap")
        with open(self.d.CACHE, encoding="utf-8") as f:
            self.assertEqual(json.load(f)[IPS[0]]["via"], "rdap")

    def test_en_paralelo(self):
        """10 IP que tardan 0,5 s cada una: en serie serian 5 s; aqui, poco mas de 0,5 s x 2
        tandas (8 a la vez)."""
        def lento(ip):
            time.sleep(0.5)
            return ("srv.google.com", [], [ip])
        self.ptr = lento
        t = time.monotonic()
        r = self.d.resolver(IPS[:10], espera=5)
        self.assertLess(time.monotonic() - t, 2.0)
        self.assertEqual({e["org"] for e in r.values()}, {"Google"})
        self.assertEqual(len(r), 10)

    def test_la_espera_tiene_tope_y_lo_tardio_queda_para_despues(self):
        """Con todo colgado se vuelve a los `espera` s sin esas IP; cuando por fin contestan
        quedan en la cache y la siguiente peticion las da sin ir a la red."""
        def tarde(ip):
            time.sleep(0.6)
            return ("x.google.com", [], [ip])
        self.ptr = tarde
        t = time.monotonic()
        self.assertEqual(self.d.resolver(IPS[:3], espera=0.1), {})
        self.assertLess(time.monotonic() - t, 0.5)
        time.sleep(1.0)
        n = len(self.ptr_llamadas)
        self.assertEqual(len(self.d.resolver(IPS[:3], espera=0.1)), 3)
        self.assertEqual(len(self.ptr_llamadas), n)       # salio de la cache

    def test_no_consulta_privadas_ni_de_documentacion(self):
        """Solo IPv4 publicas: ni 10.x, ni RFC 5737, ni basura van a la red."""
        r = self.d.resolver(["10.0.0.5", "192.0.2.10", "no-es-ip", "203.0.113.9"], espera=0.5)
        self.assertEqual(r, {})
        self.assertEqual(self.ptr_llamadas, [])

    def test_la_misma_ip_pedida_dos_veces_se_consulta_una(self):
        """Dos pestanas abiertas piden lo mismo a la vez: una sola consulta a la red."""
        def lento(ip):
            time.sleep(0.4)
            return ("srv.google.com", [], [ip])
        self.ptr = lento
        hs = [threading.Thread(target=self.d.resolver, args=([IPS[0]],), kwargs={"espera": 2})
              for _ in range(3)]
        [h.start() for h in hs]
        [h.join() for h in hs]
        self.assertEqual(self.ptr_llamadas, [IPS[0]])

    def test_rdap_que_falla_no_se_guarda_7_dias_como_sin_ptr(self):
        """Correccion de defecto: con rafagas rdap.org fallaba (18 de 32) y el fallo quedaba 7 dias
        como «sin PTR». Ahora es «?» (via=error) y caduca a los TTL_ERROR s para reintentarse."""
        def falla(ip):
            raise self.d.ErrorRdap("429")
        self.rdap = falla
        self.d.PTR_S = 0.1
        r = self.d.resolver([IPS[0]], espera=3)
        self.assertEqual((r[IPS[0]]["org"], r[IPS[0]]["via"]), ("?", "error"))
        ent = r[IPS[0]]
        self.assertTrue(self.d.vigente(ent))
        self.assertFalse(self.d.vigente(ent, ahora=ent["ts"] + self.d.TTL_ERROR + 1))
        self.assertTrue(self.d.vigente(dict(ent, via="rdap"), ahora=ent["ts"] + self.d.TTL_ERROR + 1))

    def test_cada_ip_va_a_su_registro_regional(self):
        """Correccion de defecto: rdap.org (solo redirige) corta con 429 a las ~10 consultas; se
        pregunta directo al registro de la tabla de IANA (el prefijo mas largo, por https) y a
        rdap.org solo si no hay tabla."""
        self.assertEqual(self.d.url_rdap("192.88.99.7"), "https://rdap.ejemplo-b.test/rdap/ip/192.88.99.7")
        self.assertEqual(self.d.url_rdap("192.10.0.1"), "https://rdap.ejemplo-a.test/ip/192.10.0.1")
        self.assertEqual(self.d.url_rdap("8.8.8.8"), "https://rdap.org/ip/8.8.8.8")

    def test_rdap_reintenta_una_vez_si_le_limitan(self):
        """Un 429 (limite del registro) se reintenta una vez; un 404 es «sin dueño», no error."""
        import io
        import urllib.error
        r = self.d
        rdap_org = self.rdap_real                 # la de verdad (setUp puso un falso)
        llamadas = []
        def urlopen(req, timeout=None):
            llamadas.append(req.full_url)
            if len(llamadas) == 1:
                raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, None)
            return io.BytesIO(json.dumps({"name": "RED-EJEMPLO", "country": "EC"}).encode())
        r.urllib.request.urlopen, original = urlopen, r.urllib.request.urlopen
        self.addCleanup(setattr, r.urllib.request, "urlopen", original)
        t = time.monotonic()
        self.assertEqual(rdap_org(IPS[0]), ("RED-EJEMPLO", "EC"))
        self.assertGreaterEqual(time.monotonic() - t, 0.9)
        self.assertEqual(len(llamadas), 2)
        def no_hay(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
        r.urllib.request.urlopen = no_hay
        self.assertEqual(rdap_org(IPS[1]), ("", ""))


class GeneradorSinRed(unittest.TestCase):
    def test_el_generador_no_importa_red_y_deja_huecos(self):
        """El generador ya no puede consultar la red (ni socket ni urllib) y, para una IP publica
        sin dueño en cache, deja el hueco que rellena la pestana; las no publicas, «-»."""
        fuente = open(os.path.join(LIB, "html_report.py"), encoding="utf-8").read()
        arbol = ast.parse(fuente)
        importados = {a.name for n in ast.walk(arbol) if isinstance(n, ast.Import) for a in n.names}
        self.assertFalse({"socket", "urllib.request"} & importados, importados)
        self.assertNotIn("gethostbyaddr", fuente)
        f = next(n for n in arbol.body if isinstance(n, ast.FunctionDef) and n.name == "_pend_dueno")
        ns = {"esc": lambda x: x,
              "duenos": type("D", (), {"consultable": staticmethod(lambda ip: ip.startswith("192.88.99."))})}
        exec(compile(ast.Module(body=[f], type_ignores=[]), "html_report.py", "exec"), ns)
        self.assertIn("data-dueno='192.88.99.7'", ns["_pend_dueno"]("192.88.99.7"))
        self.assertNotIn("data-dueno", ns["_pend_dueno"]("10.0.0.5"))


class RutaDuenos(unittest.TestCase):
    """GET /duenos del panel y la pestana Top origenes (fixture del panel, sin red)."""
    def setUp(self):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from fixtures.panel2._dash_p import PanelP
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.p.cuarentena("_todos", [])
        d = os.path.join(self.p.tmp.name, "panel", "nodos", "_todos")
        with open(os.path.join(d, "report-20261013-1200.html"), "w", encoding="utf-8") as f:
            f.write("<html><head><style></style></head><body><main><!--TOP_INI--><section class=\"card\">"
                    "<td class='org'><span class='obadge pend' data-dueno='192.88.99.7'>&hellip;</span></td>"
                    "</section><!--TOP_FIN--></main></body></html>")
        self.pedidas = []
        self.p.d.duenos.resolver = lambda ips, espera=8: (
            self.pedidas.append(list(ips)) or
            {ip: {"org": "Google", "legit": True, "via": "ptr", "ts": time.time()} for ip in ips})
        self.ana = self.p.entrar("ana")

    def test_solo_resuelve_lo_que_el_top_tiene_pendiente(self):
        """Capacidad nueva: /duenos da el dueño de las IP pendientes del Top y NO consulta IPs
        que el Top no pide (el panel no hace de resolvedor para nadie)."""
        r = self.p.pedir("GET", "/duenos?nodo=_todos&ip=192.88.99.7&ip=192.88.99.8", cookie=self.ana)
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.texto), {"192.88.99.7": {"org": "Google", "legit": True, "via": "ptr"}})
        self.assertEqual(self.pedidas, [["192.88.99.7"]])

    def test_la_pestana_top_pide_los_que_faltan(self):
        """La pestana lleva el codigo que rellena los huecos pidiendolos a /duenos."""
        h = self.p.pedir("GET", "/top?nodo=_todos", cookie=self.ana).texto
        self.assertIn("data-dueno='192.88.99.7'", h)
        self.assertIn("fetch('/duenos?'", h)
        self.assertEqual(self.pedidas, [])            # abrir la pagina no consulta nada por si solo


if __name__ == "__main__":
    unittest.main()
