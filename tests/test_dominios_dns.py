"""El dominio de las consultas DNS y la reputacion de los destinos (el user, 2026-10-15).

Tipo de cada prueba en su docstring. Datos RFC 5737 / 10.x y dominios .example.

- Conducta («Dominios sospechosos que consultó») decia «Nada que destacar» para todos los
  abonados: el panel buscaba el dominio de la alerta en `dns.rrname` y Suricata 7 lo escribe en
  `dns.query[0].rrname` (en produccion, todas las alertas DNS). Igual en el historial y el PDF.
- La ficha de evidencia, en «Reputación del destino», solo ensenaba las IPs que coincidian con
  una lista: sin coincidencias decia «Ningún destino aparece» aunque la tabla de alertas
  mostraba los destinos, y en las consultas DNS miraba el resolutor y no el dominio.
"""
import json
import os
import re
import sys
import tempfile
import time
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
sys.path.insert(0, os.path.join(AQUI, "fixtures", "panel2"))
import _dash  # noqa: E402
import test_hrep_nodos as H  # noqa: E402
from fixtures.panel2._dash_p import PanelP  # noqa: E402

INFECTADO = "10.0.0.21"
FEEDS = "LOCAL DNS a dominio fichado en feeds de reputacion"


def con_dns(ev, dominio, formato):
    """El evento con su dominio donde lo pone cada version: v2 (eventos dns de dns.json),
    s7 (lo DNS de una alerta en Suricata 7) y s8 (Suricata 8, version 3)."""
    ev["dns"] = {
        "v2": {"version": 2, "type": "query", "id": 1, "rrname": dominio, "rrtype": "A"},
        "s7": {"version": 2, "query": [{"type": "query", "id": 1, "rrname": dominio, "rrtype": "A",
                                        "tx_id": 0, "opcode": 0}]},
        "s8": {"version": 3, "type": "request", "id": 1, "queries": [{"rrname": dominio, "rrtype": "A"}]},
    }[formato]
    return ev


def alerta_dns(src, dominio, formato, firma=FEEDS, sid=9000050, hace=30):
    ev = json.loads(_dash.alerta(src=src, dst="192.0.2.53", dport=53, firma=firma, sid=sid, hace=hace))
    return json.dumps(con_dns(ev, dominio, formato), separators=(",", ":"))


def consulta(src, dominio, formato, hace=30):
    ev = {"timestamp": _dash.marca(hace), "event_type": "dns", "src_ip": src, "src_port": 53000,
          "dest_ip": "192.0.2.53", "dest_port": 53, "proto": "UDP"}
    return json.dumps(con_dns(ev, dominio, formato), separators=(",", ":"))


class Conducta(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = _dash.Arbol(self.tmp.name, puntos={"p001": _dash.punto("norte", 1)})
        lineas = [_dash.alerta(src=INFECTADO, hace=60 + i) for i in range(3)]      # botnet real
        for i, f in enumerate(("v2", "s7", "s8")):
            lineas.append(alerta_dns(INFECTADO, "malo-%s.example" % f, f, hace=50 + i))
            lineas.append(consulta(INFECTADO, "visto-%s.example" % f, f, hace=40 + i))
        # el dominio de una alerta de ruido (ET INFO) no es sospechoso, en ningun formato
        lineas.append(alerta_dns(INFECTADO, "fotos.example.cloud", "s7", hace=45,
                                 firma="ET INFO Observed DNS Query to .cloud TLD", sid=2027757))
        self.a.eve("p001", lineas)
        self.d = _dash.cargar(self.a)
        self.n = self.d.nodos
        self.n.asegurar_dirs()

    def tearDown(self):
        self.n.quitar_nodo()
        _dash.restaurar()
        self.tmp.cleanup()

    def informes(self):
        with self.n.contexto("p001"):
            self.d.hist_ingerir()
            return {"base": self.d.hist_conducta(), "eve": self.d.conducta_recolectar()}

    def test_dominio_de_en_los_tres_formatos(self):
        """Correccion de defecto: `dominio_de` saca el dominio de un evento dns (v2), de una alerta
        de Suricata 7 (`dns.query[]`) y de Suricata 8 (`dns.queries[]`); sin dominio, ''."""
        for f in ("v2", "s7", "s8"):
            with self.subTest(formato=f):
                self.assertEqual(self.d.dominio_de(con_dns({}, "x.example", f)), "x.example")
        for ev in ({}, {"dns": None}, {"dns": "x"}, {"dns": {"query": []}}, {"dns": {"queries": [{}]}},
                   {"dns": {"query": "x.example"}}, {"dns": {"rrname": 7}}):
            with self.subTest(ev=ev):
                self.assertEqual(self.d.dominio_de(ev), "")

    def test_dominios_sospechosos_con_la_alerta_de_suricata_7(self):
        """Correccion de defecto (el user, 2026-10-15: «Dominios sospechosos que consultó: Nada
        que destacar»): el dominio de cada alerta DNS sale en «malos», en el historial (base) y
        en la lectura directa de los eve, venga en el formato que venga."""
        for via, rep in self.informes().items():
            with self.subTest(via=via):
                f = next(x for x in rep["filas"] if x["ip"] == INFECTADO)
                malos = sorted(d for d, _n in f["malos"])
                self.assertEqual(malos, ["malo-s7.example", "malo-s8.example", "malo-v2.example"])

    def test_el_ruido_sigue_sin_ser_sospechoso(self):
        """Conservacion: ahora que el dominio de una alerta de Suricata 7 se lee, el de una ET
        INFO sigue fuera de «malos»."""
        for via, rep in self.informes().items():
            with self.subTest(via=via):
                f = next(x for x in rep["filas"] if x["ip"] == INFECTADO)
                self.assertNotIn("fotos.example.cloud", [d for d, _n in f["malos"]])

    def test_dominios_consultados_tambien_en_la_version_3(self):
        """Correccion de defecto: las consultas de dns.json con el formato de Suricata 8
        (`dns.queries[]`) cuentan en «dominios consultados» como las de la version 2."""
        for via, rep in self.informes().items():
            with self.subTest(via=via):
                f = next(x for x in rep["filas"] if x["ip"] == INFECTADO)
                doms = {d for d, _n in f["dominios"]}
                self.assertTrue({"visto-v2.example", "visto-s8.example"} <= doms, doms)


IP = "10.0.0.5"
LIMPIA, FICHADA, RESOLUTOR = "203.0.113.9", "198.51.100.7", "192.0.2.53"


class Ficha(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")
        ahora = int(time.time())
        c = PanelP.candidato(IP, "p001", confianza="sospechoso")
        c["destinos"] = 3
        c["pruebas"] = [
            {"tipo": "dns", "sid": "9000050", "sig": FEEDS, "dst": RESOLUTOR, "dport": 53,
             "rrname": "malo.example", "ts": ahora - 100},
            {"tipo": "cnc", "sid": "2000001", "sig": "ET MALWARE prueba", "dst": LIMPIA, "dport": 443,
             "rrname": "", "ts": ahora - 90},
            {"tipo": "cnc", "sid": "2000001", "sig": "ET MALWARE prueba", "dst": FICHADA, "dport": 8080,
             "rrname": "", "ts": ahora - 80}]
        c["reputacion"] = [{"ip": FICHADA, "cidr": "198.51.100.0/24", "fuente": "spamhaus-drop",
                            "categoria": "infra-delictiva", "vigente": True,
                            "fetched_valid": ahora - 3600, "expira": ahora + 86400,
                            "puerto_c2": False, "contexto": False}]
        c["dominios_feeds"] = [["malo.example", 3], ["otro-malo.example", 1]]
        self.c = c

    def ficha(self, listas):
        self.p.cuarentena("p001", [self.c])
        ruta = os.path.join(self.p.tmp.name, "panel", "nodos", "p001", "cuarentena.json")
        with open(ruta, encoding="utf-8") as f:
            d = json.load(f)
        if listas is not None:
            d["reputacion_listas"] = listas
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(d, f)
        r = self.p.pedir("GET", "/cuarentena/ficha?embed=1&nodo=p001&ip=p001%7C" + IP, cookie=self.ana)
        self.assertEqual(r.status, 200, r.texto[:300])
        m = re.search(r"<tr><th>Reputación del destino</th><td>(.*?)</td></tr><tr><th>Corroboración</th>",
                      r.texto, re.S)
        self.assertIsNotNone(m, r.texto[-2000:])
        return m.group(1)

    @staticmethod
    def fila(celda, destino):
        """La fila de la tabla de reputacion cuyo destino es `destino` (texto de la fila)."""
        for tr in re.findall(r"<tr><td>(.*?)</td></tr>", celda, re.S):
            if re.match(r"<span class=mono>%s</span>" % re.escape(destino), tr):
                return tr
        return None

    def test_cada_destino_con_lo_que_dicen_las_listas(self):
        """Correccion de defecto (el user, 2026-10-15: «no salen los destinos si en Destino los
        saca»): una fila por destino de las alertas. La IP fichada con su lista y vigencia, la
        limpia con «No está en las listas», y de la consulta DNS el DOMINIO (fichado por la regla
        de los feeds) con el resolutor como canal, no como destino."""
        celda = self.ficha({"ok": True, "info": "16.723 IOCs (cins, feodo, spamhaus-drop)"})
        self.assertNotIn("Ningún destino aparece", celda)
        fichada = self.fila(celda, FICHADA)
        self.assertIsNotNone(fichada, celda)
        self.assertIn("spamhaus-drop", fichada)
        self.assertIn("en 198.51.100.0/24", fichada)
        self.assertIn("vigente", fichada)
        self.assertIn("No está en las listas", self.fila(celda, LIMPIA) or "")
        dom = self.fila(celda, "malo.example") or ""
        self.assertIn("<b>Fichado</b>", dom)
        self.assertIn("consultado vía " + RESOLUTOR, dom)
        self.assertIn("<b>Fichado</b>", self.fila(celda, "otro-malo.example") or "")
        self.assertIsNone(self.fila(celda, RESOLUTOR))      # el resolutor no es un destino
        self.assertIn("los 3 destinos distintos del abonado: 16.723 IOCs", celda)

    def test_sin_listas_cargadas_no_dice_que_no_esta(self):
        """Correccion de defecto: si las listas no estaban cargadas al generar el informe, la ficha
        lo dice y no afirma que un destino «no está en las listas»."""
        celda = self.ficha({"ok": False, "info": "feeds sin refrescar (>3d; el actualizador no corre?)"})
        self.assertNotIn("No está en las listas", celda)
        self.assertIn("Sin comprobar", self.fila(celda, LIMPIA) or "")
        self.assertIn("Las listas de reputación no estaban cargadas", celda)
        self.assertIn("feeds sin refrescar", celda)

    def test_cuarentena_json_de_antes(self):
        """Conservacion: un cuarentena.json sin `reputacion_listas` ni `dominios_feeds` (anterior a
        este cambio) sigue dando la ficha, con los destinos de sus alertas."""
        del self.c["dominios_feeds"]
        celda = self.ficha(None)
        self.assertIn("No está en las listas", self.fila(celda, LIMPIA) or "")
        self.assertIn("Lo marcó la firma", self.fila(celda, "malo.example") or "")


class Generador(H.Entorno):
    def test_dominios_de_la_regla_de_los_feeds_y_estado_de_las_listas(self):
        """Capacidad nueva: cuarentena.json guarda, por candidato, los dominios que encontro la
        regla de los feeds (sid 9000050) y, arriba, si las listas de reputacion estaban cargadas
        al cruzar los destinos."""
        self.tres_cnc("p001")
        self.eventos("p001", "eve.json", [H.alerta("10.0.0.5", "192.0.2.53", sig=FEEDS, sid=9000050,
                                                   dport=53, rrname="Malo.Example.", hace_s=30 + i)
                                          for i in range(2)])
        self.ok("60", "--nodo", "p001")
        cuar = self.salida("p001", "cuarentena.json")
        self.assertEqual(cuar["candidatos"][0]["dominios_feeds"], [["malo.example", 2]])
        self.assertEqual(cuar["reputacion_listas"], {"ok": False, "info": "feeds no instalados"})

        self.global_("feeds/reputation.meta", {"generated": time.time(), "sources": {
            "spamhaus-drop": {"vigente": True, "categoria": "infra-delictiva"}}})
        self.global_("feeds/reputation.lst", "198.51.100.0/24\tspamhaus-drop\n")
        self.ok("60", "--nodo", "p001")
        listas = self.salida("p001", "cuarentena.json")["reputacion_listas"]
        self.assertTrue(listas["ok"])
        self.assertIn("spamhaus-drop", listas["info"])


if __name__ == "__main__":
    unittest.main()
