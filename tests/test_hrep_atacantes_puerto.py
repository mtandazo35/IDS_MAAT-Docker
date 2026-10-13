"""html_report.py: grafica «Atacantes por puerto» y etiquetas legibles de las graficas de barras.

Reusa el entorno de test_hrep_nodos (generador como subproceso, sin red). Datos RFC 5737 / 10.x.
El tipo de cada prueba va en su docstring.
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_hrep_nodos import Entorno, alerta  # noqa: E402


def tarjeta(doc, titulo):
    """El <section> de la grafica de barras con ese titulo."""
    m = re.search(r'<section class="card"><h2>%s<.*?</section>' % re.escape(titulo), doc, re.S)
    assert m, titulo
    return m.group(0)


def filas_cols(t):
    """Filas de una grafica en columnas: [(ip, nodo o None, puerto)] y las x de cada columna."""
    filas, xs = [], {"ip": set(), "flecha": set(), "pto": set()}
    for g in re.findall(r"<g><title>.*?</g>", t, re.S):
        ip = re.search(r'<text x="([\d.]+)" y="\d+" class="lbl">([^<]+)</text>', g)
        nodo = re.search(r'class="lbl lnodo">([^<]+)</text>', g)
        flecha = re.search(r'<text x="([\d.]+)" y="\d+" class="lbl lflecha">→</text>', g)
        pto = re.search(r'<text x="([\d.]+)" y="\d+" class="lbl lpto">([^<]+)</text>', g)
        xs["ip"].add(ip.group(1)); xs["flecha"].add(flecha.group(1)); xs["pto"].add(pto.group(1))
        filas.append((ip.group(2), nodo.group(1) if nodo else None, pto.group(2)))
    return filas, xs


class AtacantesPorPuerto(Entorno):
    def test_pares_ip_puerto_con_su_nodo(self):
        """Capacidad nueva: la grafica dice QUIEN ataca QUE puerto (par IP -> puerto), ordenada
        por alertas; en «Todos» cada IP lleva el nombre de su nodo, nunca la clave pid|ip."""
        self.eventos("p001", "eve.json",
                     [alerta("10.0.0.5", "192.0.2.10", dport=23, flow_id=10 + i) for i in range(5)]
                     + [alerta("10.0.0.5", "192.0.2.10", dport=445, flow_id=20 + i) for i in range(2)])
        self.eventos("p002", "eve.json",
                     [alerta("10.0.0.5", "192.0.2.11", dport=443, flow_id=30 + i) for i in range(3)])
        self.ok("60", "--todos")
        doc = self.html("_todos")
        self.assertNotIn("Puertos de destino mas atacados</h2>", doc)
        t = tarjeta(doc, "Atacantes por puerto")
        filas, xs = filas_cols(t)
        self.assertEqual(filas, [("10.0.0.5", "Nodo A", "23/TCP"),
                                 ("10.0.0.5", "Nodo B", "443/TCP"),
                                 ("10.0.0.5", "Nodo A", "445/TCP")])
        # IP, nodo, flecha y puerto en columnas: cada una empieza en la misma x en todas las
        # filas, sin escalera por el largo del puerto (el user, 2026-10-13)
        self.assertEqual(len(xs["ip"]), 1, xs)
        self.assertEqual(len(xs["flecha"]), 1, xs)
        self.assertEqual(len(xs["pto"]), 1, xs)
        self.assertIn("<title>10.0.0.5 · Nodo A → 23/TCP</title>", t)
        origen = tarjeta(doc, "IPs origen (atacantes)")
        self.assertNotIn("p001|", origen)
        self.assertIn("10.0.0.5 · Nodo A", origen)

    def test_ips_destino_con_su_puerto(self):
        """Capacidad nueva: cada IP destino lleva el puerto por el que la atacan (el mas usado) y
        «+N» si la atacan por mas puertos."""
        self.eventos("p001", "eve.json",
                     [alerta("10.0.0.5", "192.0.2.10", dport=23, flow_id=50 + i) for i in range(4)]
                     + [alerta("10.0.0.6", "192.0.2.10", dport=2323, flow_id=60)]
                     + [alerta("10.0.0.5", "192.0.2.11", dport=443, flow_id=70 + i) for i in range(2)])
        self.ok("60", "--nodo", "p001")
        t = tarjeta(self.html("p001"), "IPs destino (objetivos)")
        self.assertEqual(re.findall(r'class="lbl">([^<]+)</text>', t),
                         ["192.0.2.10 · 23/TCP +1", "192.0.2.11 · 443/TCP"])

    def test_un_solo_nodo_sin_nombre_y_una_fila_no_empata(self):
        """Correccion de defecto: con una sola fila no sale «los 1 van empatados», sino «solo 1
        ...»; con un solo nodo la etiqueta es la IP sola (el nombre del nodo seria ruido)."""
        self.eventos("p001", "eve.json",
                     [alerta("10.0.0.5", "192.0.2.10", dport=23, flow_id=40 + i) for i in range(3)])
        self.ok("60", "--nodo", "p001")
        doc = self.html("p001")
        t = tarjeta(doc, "Atacantes por puerto")
        self.assertEqual(filas_cols(t)[0], [("10.0.0.5", None, "23/TCP")])
        self.assertIn("<b>solo 1 atacante</b> en 3 alertas (muestra pequeña)", t)
        self.assertNotIn("van empatados", doc)


if __name__ == "__main__":
    unittest.main()
