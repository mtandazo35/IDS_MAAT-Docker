"""Informe y Reporte: en qué categoría cae cada abonado (el user, 2026-10-15, informe PDF del lab).

Tipo: corrección de defecto; cada prueba falla sin su arreglo.
- 1: escaneo, fuerza bruta y spam van ANTES que el DNS de malware. Un CPE que escaneaba y mandaba
  spam salía «DNS de malware: no hace falta dejarlo sin internet» y no contaba en «para cortar».
- 2: la regla propia de los feeds (sid 9000050, «LOCAL DNS a dominio fichado en feeds de
  reputacion») no tenía categoría: su firma salía cortada como categoría y el abonado que solo
  tenía esa alerta caía en «Otros».
- 3: esa regla no tenía límite: un solo CPE dio 48.257 de las 48.918 alertas del informe.
Datos RFC 1918 de prueba (10.0.0.x), sin red.
"""
import os
import re
import sys
import tempfile
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, "fixtures", "panel2"))
import _dash  # noqa: E402

FEEDS = "LOCAL DNS a dominio fichado en feeds de reputacion"
ADB = "LOCAL CPE escanea ADB/router saliente"
SMTP = "LOCAL SMTP directo saliente desde cliente (posible spambot)"
CC = "ET DNS Query for .cc TLD"
TODO, SPAM_DNS, SOLO_FEEDS = "10.0.0.31", "10.0.0.32", "10.0.0.33"
TMPL = os.path.join(AQUI, "..", "images", "suricata", "rootfs", "usr", "share", "ids-maat", "local.rules.tmpl")


def lineas():
    out = []
    for i in range(3):
        # el caso del informe: escanea, manda spam y además consulta dominios fichados
        out.append(_dash.alerta(src=TODO, dst="10.0.0.1", dport=53, firma=FEEDS, sid=9000050, hace=60 + i))
        out.append(_dash.alerta(src=TODO, dport=5555, firma=ADB, sid=9000012, hace=60 + i))
        out.append(_dash.alerta(src=TODO, dport=25, firma=SMTP, sid=9000020, hace=60 + i))
        # spam y DNS de malware
        out.append(_dash.alerta(src=SPAM_DNS, dst="10.0.0.1", dport=53, firma=CC, sid=2027758, hace=60 + i))
        out.append(_dash.alerta(src=SPAM_DNS, dport=25, firma=SMTP, sid=9000020, hace=60 + i))
        # solo la regla propia de los feeds
        out.append(_dash.alerta(src=SOLO_FEEDS, dst="10.0.0.1", dport=53, firma=FEEDS, sid=9000050, hace=60 + i))
    return out


class Categorias(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = _dash.Arbol(self.tmp.name, puntos={"p001": _dash.punto("norte", 1)})
        self.a.eve("p001", lineas())
        self.d = _dash.cargar(self.a)
        self.n = self.d.nodos
        self.n.asegurar_dirs()

    def tearDown(self):
        self.n.quitar_nodo()
        _dash.restaurar()
        self.tmp.cleanup()

    def informe(self):
        with self.n.contexto("p001"):
            self.d.hist_ingerir()
            return self.d.informe_datos(3, "ana")

    def test_escaneo_y_spam_ganan_al_dns_de_malware(self):
        d = self.informe()
        quien = {c["clave"]: [a["ip"] for a in c["abonados"]] for c in d["categorias"]}
        self.assertEqual(quien["escaneo"], [TODO])
        self.assertEqual(quien["spam"], [SPAM_DNS])
        self.assertEqual(quien["dns"], [SOLO_FEEDS])
        self.assertEqual(quien["otros"], [])
        self.assertEqual(d["totales"]["cortar"], 1)            # el que escanea cuenta para cortar
        orden = [c["clave"] for c in d["categorias"]]
        self.assertLess(orden.index("escaneo"), orden.index("dns"))
        self.assertLess(orden.index("spam"), orden.index("dns"))
        self.assertTrue(any("(botnet, escaneo, fuerza bruta, spam, DNS de malware, minado, P2P)" in x
                            for x in d["metodologia"]), d["metodologia"])

    def test_la_lista_del_mikrotik_sigue_el_mismo_orden(self):
        """La misma tabla decide la address-list de Cuarentena: el que escanea va a la de escaneo."""
        self.assertEqual(self.d.categoria_de_cats({"DNS sospechoso": 9, "Escaneo saliente": 1}), "escaneo")
        self.assertEqual(self.d.categoria_de_cats({"DNS sospechoso": 9, "Spam": 1}), "spam")
        self.assertEqual(self.d.categoria_de_cats({"DNS sospechoso": 9}), "dns")
        doc = self.d.documentacion_page(pagina="todo")
        self.assertRegex(doc, r"botnet, escaneo, fuerza bruta,\s+spam, DNS de malware, criptominado y P2P")

    def test_la_regla_de_los_feeds_es_dns_de_malware(self):
        self.assertEqual(self.d.traducir(FEEDS), "DNS sospechoso")
        d = self.informe()
        dns = next(c for c in d["categorias"] if c["clave"] == "dns")["abonados"]
        self.assertEqual([(a["ip"], a["repetido"]) for a in dns], [(SOLO_FEEDS, "DNS sospechoso")])
        self.assertEqual({f[0] for f in dns[0]["firmas"]}, {"DNS sospechoso"})


class LimiteDeLaRegla(unittest.TestCase):
    def test_una_alerta_por_abonado_y_minuto(self):
        with open(TMPL, encoding="utf-8") as f:
            regla = [x for x in f if "sid:9000050;" in x]
        self.assertEqual(len(regla), 1, regla)
        self.assertIn("threshold:type limit, track by_src, count 1, seconds 60;", regla[0])
        self.assertTrue(re.search(r"\brev:2;", regla[0]), regla[0])


if __name__ == "__main__":
    unittest.main()
