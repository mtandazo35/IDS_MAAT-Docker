"""html_report.py: la regla propia de los feeds cuenta como DNS sospechoso (el user, 2026-10-15).

Tipo: corrección de defecto; cada prueba falla sin su arreglo.
- La regla sid 9000050 («LOCAL DNS a dominio fichado en feeds de reputacion») no casaba con
  ninguna palabra de DNS_MAL: sus alertas no sumaban dns_hits. Con los feeds de dominios sin clave
  en el panel (sin domains.lst, sin Camino B), quien solo consultaba dominios fichados no salía
  nunca en «DNS sospechoso» de Cuarentena.
- Conservación: si el panel sí tiene el dominio en domains.lst, esa consulta ya la cuenta el
  Camino B desde dns.json; la alerta de la regla no la suma otra vez (sería la misma prueba
  contada dos veces y bastaría una consulta para ser candidato).
Reusa el entorno de test_hrep_nodos (generador como subproceso, sin red). Datos RFC 5737 / 10.x.
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_hrep_nodos import Entorno, alerta, consulta_dns  # noqa: E402

FEEDS = "LOCAL DNS a dominio fichado en feeds de reputacion"


def feeds(src, dom, n, desde=0):
    """`n` alertas de la regla de los feeds de `src` por `dom`, una por minuto (su threshold)."""
    return [alerta(src, "192.0.2.53", sig=FEEDS, sid=9000050, dport=53, rrname=dom,
                   hace_s=60 * (i + 1), flow_id=desde + i) for i in range(n)]


class SinListaDeDominios(Entorno):
    def test_la_regla_de_los_feeds_hace_candidato(self):
        self.eventos("p001", "eve.json",
                     feeds("10.0.0.5", "malo.example", 3, 100)               # 3 consultas
                     + feeds("10.0.0.6", "uno.example", 1, 200)              # 2 dominios distintos
                     + feeds("10.0.0.6", "dos.example", 1, 300)
                     + feeds("10.0.0.7", "malo.example", 1, 400))            # una sola: no basta
        self.ok("60", "--nodo", "p001")
        cuar = self.salida("p001", "cuarentena.json")
        self.assertEqual(self.cpes(cuar, "dns_candidatos"), [("p001", "10.0.0.5"), ("p001", "10.0.0.6")])
        c = {x["ip"]: x for x in cuar["dns_candidatos"]}
        self.assertEqual((c["10.0.0.5"]["alertas_dns"], c["10.0.0.5"]["firmas_dns"]), (3, 1))
        self.assertEqual((c["10.0.0.6"]["alertas_dns"], c["10.0.0.6"]["firmas_dns"]), (2, 2))
        self.assertEqual(c["10.0.0.5"]["firma"], "DNS a dominio malo: malo.example")
        dom = {d["dominio"]: d["ips"] for d in self.salida("p001", "dominios-malos.json")["dominios"]}
        self.assertEqual(dom["malo.example"], [["10.0.0.5", 3], ["10.0.0.7", 1]])


class ConListaDeDominios(Entorno):
    def test_la_misma_consulta_no_cuenta_dos_veces(self):
        self.global_("feeds/reputation.meta", {"generated": time.time(), "sources": {}})
        self.global_("feeds/domains.lst", "malo.example\turlhaus\n")
        # cada consulta sale en dns.json (Camino B) y además como alerta de la regla
        self.eventos("p001", "dns.json", [consulta_dns("10.0.0.5", "malo.example", hace_s=60 * (i + 1))
                                          for i in range(3)])
        self.eventos("p001", "eve.json", feeds("10.0.0.5", "malo.example", 3, 100)
                     # un dominio que el panel no tiene en su lista: solo lo ve la regla
                     + feeds("10.0.0.6", "otro.example", 3, 200))
        self.ok("60", "--nodo", "p001")
        cuar = self.salida("p001", "cuarentena.json")
        c = {x["ip"]: x for x in cuar["dns_candidatos"]}
        self.assertEqual(sorted(c), ["10.0.0.5", "10.0.0.6"])
        self.assertEqual((c["10.0.0.5"]["alertas_dns"], c["10.0.0.5"]["firmas_dns"]), (3, 1))
        self.assertEqual((c["10.0.0.6"]["alertas_dns"], c["10.0.0.6"]["firmas_dns"]), (3, 1))
        dom = {d["dominio"]: d["ips"] for d in self.salida("p001", "dominios-malos.json")["dominios"]}
        self.assertEqual(dom["malo.example"], [["10.0.0.5", 3]])
        self.assertEqual(dom["otro.example"], [["10.0.0.6", 3]])


if __name__ == "__main__":
    unittest.main()
