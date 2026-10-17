"""Histórico -> «Cortar a los que te atacan desde internet»: cada IP con su detalle.

El user (2026-10-16), viendo la columna Feed con «cins» a secas: «debemos dar mas detalles». La
tabla da ahora, de cada atacante, el dueño de la IP, qué hizo (tipo de ataque y puertos), cuándo
fue su última alerta y TODOS los feeds en los que está, y debajo explica qué es cada feed.

Sin red: el dueño sale de la cache de duenos.py o queda el hueco que la pagina pide a /duenos, y
/duenos se prueba con el resolvedor falso. Las IP «de internet» son resolutores publicos conocidos
usados como relleno: los rangos de documentacion (RFC 5737) no son globales y la tabla los
descarta a proposito.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, "fixtures", "panel2"))
sys.path.insert(0, AQUI)
import _dash  # noqa: E402

EN_DOS = "1.1.1.1"       # en CINS y en ET Compromised, dueño en la cache
SIN_FEED = "8.8.8.8"     # en ningun feed: entra por lo que hizo
VIEJA = "9.9.9.9"        # entrantes.json sin puertos ni ultima (archivo de antes)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = _dash.Arbol(self.tmp.name)
        self.d = _dash.cargar(self.a)
        self.n = self.d.nodos
        self.n.asegurar_dirs()
        ahora = int(time.time())
        self.a.salida("p001", "entrantes.json", {"origenes": {
            EN_DOS: {"alertas": 900, "destinos": 40, "pais": "CN", "ultima": ahora - 300,
                     "firma": "ET SCAN Suspicious inbound to Telnet port 23",
                     "puertos": [23, 2323, 22, 80, 8080, 7547, 81]},
            SIN_FEED: {"alertas": 50, "destinos": 5, "pais": "US", "ultima": ahora - 3 * 86400,
                       "firma": "ET SCAN Potential SSH Scan", "puertos": [22]},
            VIEJA: {"alertas": 30, "destinos": 4, "pais": "RU", "firma": "x"},
        }})
        feeds = os.path.dirname(self.d.FEEDS_META)
        os.makedirs(feeds, exist_ok=True)
        with open(os.path.join(feeds, "reputation.lst"), "w", encoding="utf-8", newline="\n") as f:
            f.write("%s\tcins\n%s\tet-compromised\n" % (EN_DOS, EN_DOS))
        with open(self.d.FEEDS_META, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"sources": {
                "cins": {"categoria": "atacante-observado", "count": 15000, "fetched_valid": ahora - 7200},
                "et-compromised": {"categoria": "atacante-observado", "count": 900}}}, f)
        cache = os.path.join(self.tmp.name, "ipinfo-cache.json")
        with open(cache, "w", encoding="utf-8", newline="\n") as f:
            json.dump({EN_DOS: {"org": "EJEMPLO-NET · CN", "legit": False, "ts": time.time(),
                                "via": "rdap", "v": self.d.duenos.VERSION}}, f)
        p = mock.patch.object(self.d.duenos, "CACHE", cache)
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        self.n.quitar_nodo()
        _dash.restaurar()
        self.tmp.cleanup()

    def pagina(self):
        with self.n.contexto("p001"):
            return self.d.historico_page(7)

    def fila(self, h, ip):
        i = h.index("<td class=mono>%s</td>" % ip)
        return h[i:h.index("</tr>", i)]


class Datos(Base):
    def test_todos_los_feeds_de_la_ip(self):
        """Capacidad nueva: una IP en dos feeds lleva los dos, no solo el ultimo del archivo."""
        with self.n.contexto("p001"):
            bl = {x["ip"]: x for x in self.d.blocklist_borde()}
        self.assertEqual(bl[EN_DOS]["fuentes"], ["cins", "et-compromised"])
        self.assertEqual(bl[EN_DOS]["fuente"], "et-compromised")      # rep_fuente no cambia
        self.assertEqual(bl[SIN_FEED]["fuentes"], [])

    def test_puertos_y_ultima_del_generador(self):
        """Capacidad nueva: los puertos y la ultima alerta de entrantes.json llegan a la tabla; un
        archivo sin ellos da [] y 0 (sin fallar)."""
        with self.n.contexto("p001"):
            bl = {x["ip"]: x for x in self.d.blocklist_borde()}
        self.assertEqual(bl[EN_DOS]["puertos"][:2], ["23", "2323"])
        self.assertGreater(bl[EN_DOS]["ultima"], 0)
        self.assertEqual((bl[VIEJA]["puertos"], bl[VIEJA]["ultima"]), ([], 0))


class Tabla(Base):
    def test_columnas_nuevas(self):
        """Capacidad nueva: la tabla tiene Dueño, Qué hizo y Última vez ademas de lo de antes."""
        h = self.pagina()
        self.assertIn("<th>IP</th><th>Dueño</th><th>País</th><th>Qué hizo</th>", h)
        self.assertIn("<th>Última vez</th><th>Feed</th>", h)

    def test_feed_con_nombre_y_los_dos(self):
        """Correccion de defecto: «cins» a secas no decia nada; sale el nombre de cada feed."""
        f = self.fila(self.pagina(), EN_DOS)
        self.assertIn(">CINS Army</span>", f)
        self.assertIn(">ET Compromised</span>", f)
        self.assertNotIn(">cins<", f)

    def test_que_hizo_y_puertos(self):
        """Capacidad nueva: el tipo de ataque traducido y los puertos (5 y «+N»)."""
        f = self.fila(self.pagina(), EN_DOS)
        self.assertIn("Escaneo Telnet", f)
        self.assertIn("puertos 23, 2323, 22, 80, 8080 +2", f)
        self.assertIn("title='ET SCAN Suspicious inbound to Telnet port 23'", f)

    def test_ultima_vez(self):
        """Capacidad nueva: cuando fue la ultima alerta, en «hace…»."""
        h = self.pagina()
        self.assertIn(">hace 5 min</td>", self.fila(h, EN_DOS))
        self.assertIn(">hace 3 días</td>", self.fila(h, SIN_FEED))
        self.assertIn("<td>-</td>", self.fila(h, VIEJA))

    def test_dueno_de_la_cache_y_hueco_para_el_resto(self):
        """Capacidad nueva: el dueño sale de la cache; el que falta queda pendiente y la pagina
        lleva el codigo que lo pide a /duenos (abrirla no consulta la red)."""
        h = self.pagina()
        self.assertIn("EJEMPLO-NET · CN</span>", self.fila(h, EN_DOS))
        self.assertIn("data-dueno='%s'" % SIN_FEED, self.fila(h, SIN_FEED))
        self.assertIn("fetch('/duenos?'", h)

    def test_sin_feed_dice_por_que_entra(self):
        """Capacidad nueva: la que no esta en ningun feed lo dice, y la leyenda explica por que
        esta en la lista."""
        h = self.pagina()
        self.assertIn(">ninguno</span>", self.fila(h, SIN_FEED))
        self.assertIn("entra en la lista por lo que hizo, 20 alertas o más contra 3 equipos", h)

    def test_leyenda_de_los_feeds(self):
        """Capacidad nueva: debajo, que es cada feed de la tabla, con su tamaño, cuando se bajo y
        su web; solo los que aparecen."""
        h = self.pagina()
        self.assertIn("Qué es cada feed de la tabla:", h)
        self.assertIn("<b>CINS Army</b>: IPs que la red de sensores de CINS", h)
        self.assertIn("15,000 IPs en su lista; bajada hace 2 h", h)
        self.assertIn("href='https://cinsscore.com/'", h)
        self.assertNotIn("<b>Feodo Tracker</b>", h)


class RutaDuenos(unittest.TestCase):
    """GET /duenos contesta tambien las IPs de la tabla de Histórico, y solo esas."""
    def setUp(self):
        sys.path.insert(0, AQUI)
        from fixtures.panel2._dash_p import PanelP
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        d = os.path.join(self.p.tmp.name, "panel", "nodos", "p001")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "entrantes.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump({"origenes": {EN_DOS: {"alertas": 900, "destinos": 40, "pais": "CN"}}}, f)
        self.pedidas = []
        falso = mock.patch.object(self.p.d.duenos, "resolver", lambda ips, espera=8: (
            self.pedidas.append(list(ips)) or
            {ip: {"org": "EJEMPLO-NET", "legit": False, "via": "rdap", "ts": time.time()} for ip in ips}))
        falso.start()
        self.addCleanup(falso.stop)
        self.ana = self.p.entrar("ana")

    def test_resuelve_las_de_la_tabla_y_no_otras(self):
        """Capacidad nueva: el hueco del dueño en Histórico se rellena; una IP que no esta en la
        tabla no se consulta (el panel no hace de resolvedor para nadie)."""
        r = self.p.pedir("GET", "/duenos?nodo=p001&ip=%s&ip=%s" % (EN_DOS, SIN_FEED), cookie=self.ana)
        self.assertEqual(r.status, 200)
        self.assertEqual(list(json.loads(r.texto)), [EN_DOS])
        self.assertEqual(self.pedidas, [[EN_DOS]])


if __name__ == "__main__":
    unittest.main()
