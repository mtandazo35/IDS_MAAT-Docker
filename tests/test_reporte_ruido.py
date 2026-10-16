"""Reporte (/conducta): el ruido no cuenta ni clasifica, y no salen abonados sin alertas reales.

Tipo: correccion de defecto (visto en local, 2026-10-13). Un abonado limpio salia «DNS de malware —
GRAVE», confianza «Probable», con «Consultas a dominios de malware: Si» y a la vez «Dominios
sospechosos: nada que destacar»: el reporte contaba las firmas ET INFO (una consulta a un dominio
.cloud se traduce «DNS sospechoso») y lo que no es abuso (videollamadas, anomalias de protocolo), y
le bastaba UNA alerta de una categoria para ponersela. Ademas «Otros — revisar a mano» se llenaba
de abonados con 0 alertas (30 de 36 en un punto). Se prueba por las dos vias: la base del
historial (hist_conducta) y la lectura directa de los eve (conducta_recolectar).
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
import _dash  # noqa: E402

LIMPIO, INFECTADO, NAVEGA = "10.0.0.20", "10.0.0.21", "10.0.0.22"


def dns(src, nombre, hace=30):
    return json.dumps({"timestamp": _dash.marca(hace), "event_type": "dns", "src_ip": src,
                       "src_port": 53000, "dest_ip": "10.0.0.1", "dest_port": 53, "proto": "UDP",
                       "dns": {"type": "query", "rrname": nombre}}, separators=(",", ":"))


def alerta_dns(src, firma, dominio, hace=30):
    """Alerta de una consulta DNS como la escribe Suricata 7: el dominio en `dns.query[0].rrname`.
    Antes aqui iba `dns.rrname`, que Suricata no usa en las alertas: el panel no veia ningun
    dominio y la prueba de abajo pasaba sin mirar nada (tests/test_dominios_dns.py)."""
    ev = json.loads(_dash.alerta(src=src, dst="10.0.0.1", dport=53, firma=firma, hace=hace))
    ev["dns"] = {"version": 2, "query": [{"type": "query", "id": 1, "rrname": dominio, "rrtype": "A"}]}
    return json.dumps(ev, separators=(",", ":"))


def lineas():
    out = []
    # limpio: solo ruido (consultas .cloud por ET INFO, videollamadas, anomalias TCP)
    for i in range(20):
        out.append(alerta_dns(LIMPIO, "ET INFO Observed DNS Query to .cloud TLD", "fotos.example.cloud", 40 + i))
        out.append(_dash.alerta(src=LIMPIO, dport=3478, hace=40 + i,
                                firma="ET INFO Session Traversal Utilities for NAT (STUN Binding Request)"))
        out.append(_dash.alerta(src=LIMPIO, hace=40 + i, firma="SURICATA STREAM Packet with invalid ack"))
    # infectado: botnet de verdad, mezclada con el mismo ruido
    for i in range(5):
        out.append(_dash.alerta(src=INFECTADO, dport=8080, hace=60 + i, firma="ET MALWARE Mirai Botnet CnC Checkin"))
        out.append(alerta_dns(INFECTADO, "ET INFO Observed DNS Query to .cloud TLD", "cdn.example.cloud", 60 + i))
    # navega: trafico sin ninguna alerta
    out.append(dns(NAVEGA, "www.example.com"))
    return out


class ReporteSinRuido(unittest.TestCase):
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

    def informes(self):
        with self.n.contexto("p001"):
            self.d.hist_ingerir()
            return {"base": self.d.hist_conducta(), "eve": self.d.conducta_recolectar()}

    def test_el_limpio_y_el_que_solo_navega_no_salen(self):
        for via, rep in self.informes().items():
            with self.subTest(via=via):
                ips = {f["ip"] for f in rep["filas"]}
                self.assertNotIn(LIMPIO, ips)       # antes: «DNS de malware — GRAVE»
                self.assertNotIn(NAVEGA, ips)       # antes: «Otros», 0 alertas
                self.assertIn(INFECTADO, ips)

    def test_el_infectado_cuenta_solo_lo_real_y_es_botnet(self):
        for via, rep in self.informes().items():
            with self.subTest(via=via):
                f = next(x for x in rep["filas"] if x["ip"] == INFECTADO)
                self.assertEqual(f["alertas"], 5)   # las 5 de Mirai, no las 5 de ET INFO
                self.assertTrue(all(not k.startswith("ET INFO") for k, _n in f["firmas"]), f["firmas"])
                self.assertEqual(self.d.conducta_categoria(f), "botnet")

    def test_el_dominio_de_una_alerta_de_ruido_no_es_sospechoso(self):
        """El dominio que trae una alerta ET INFO no se apunta como «dominio sospechoso»."""
        for via, rep in self.informes().items():
            with self.subTest(via=via):
                f = next(x for x in rep["filas"] if x["ip"] == INFECTADO)
                self.assertNotIn("cdn.example.cloud", [d for d, _n in f["malos"]])

    def test_lo_que_no_cuenta_es_lo_no_abusivo_del_generador_menos_el_p2p(self):
        """Una sola idea de «ruido» en todo el panel: CD_NO_CUENTA = CATS_NO_ABUSO del generador
        de reportes sin el P2P (que en el Reporte tiene su propia categoria)."""
        import ast
        fuente = open(os.path.join(_dash.LIB, "html_report.py"), encoding="utf-8").read()
        nodo = next(n for n in ast.parse(fuente).body
                    if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "CATS_NO_ABUSO")
        no_abuso = ast.literal_eval(nodo.value)
        self.assertEqual(set(self.d.CD_NO_CUENTA), no_abuso - {"BitTorrent / P2P"})


class CuandoCayo(ReporteSinRuido):
    """Capacidad nueva (el user, 2026-10-13): el informe dice CUANDO cayo cada cliente en su
    categoria: la primera y la ultima alerta real de esa categoria en el periodo."""

    def test_desde_la_primera_alerta_de_su_categoria(self):
        import time
        ahora = time.time()
        for via, rep in self.informes().items():
            with self.subTest(via=via):
                f = next(x for x in rep["filas"] if x["ip"] == INFECTADO)
                desde, hasta, aprox = self.d.conducta_cuando(f)
                # las Mirai van de hace 64 s a hace 60 s; el ruido (ET INFO) no mueve la fecha
                self.assertFalse(aprox)
                self.assertAlmostEqual(desde, ahora - 64, delta=3)
                self.assertAlmostEqual(hasta, ahora - 60, delta=3)

    def test_datos_viejos_sin_hora_dan_el_dia_aproximado(self):
        """Lo ingerido antes de existir firma_ts solo tiene el dia: sale ese dia, marcado."""
        import time
        with self.n.contexto("p001"):
            self.d.hist_ingerir()
            c = self.d._hist_con("p001")
            try:
                c.execute("DELETE FROM firma_ts")
                c.commit()
            finally:
                c.close()
            f = next(x for x in self.d.hist_conducta()["filas"] if x["ip"] == INFECTADO)
        desde, hasta, aprox = self.d.conducta_cuando(f)
        self.assertTrue(aprox)
        self.assertIsNone(hasta)
        self.assertEqual(time.strftime("%Y-%m-%d", time.localtime(desde)),
                         time.strftime("%Y-%m-%d", time.localtime(time.time() - 64)))


if __name__ == "__main__":
    unittest.main()
