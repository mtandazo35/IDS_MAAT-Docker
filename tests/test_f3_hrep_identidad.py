"""html_report.py no mezcla identidades (auditoría A-14).

- Un CPE propio (`pid|ip`) nunca sale como «ataque entrante desde internet»: antes
  `es_mi_cpe('p001|10.0.0.5')` daba siempre False y el CPE salía con botón «Denunciar».
- En «Todos», cada evento se juzga con las redes de abonados de SU punto, no con la unión: antes
  una IP de la red de p002 vista en el espejo de p001 era candidata de p001 (y el envío masivo de
  «Todos» la mandaba al router de p001).

Mismo arnés que tests/test_hrep_nodos.py (el generador como subproceso, sin red, datos RFC 5737 /
10.x). Tipo de cada prueba en su docstring (CONTRATO-F2 §10.5).
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_hrep_nodos import Entorno, alerta  # noqa: E402


def seccion(doc, titulo):
    i = doc.find(titulo)
    if i < 0:
        return ""
    j = doc.find("</section>", i)
    return doc[i:j]


class Entrantes(Entorno):
    def test_cpe_propio_no_es_ataque_entrante(self):
        """Corrección de defecto (A-14): una alerta de un CPE de p001 hacia otro CPE de p001 no pone
        al CPE como atacante «desde internet»; el atacante de verdad (198.51.100.7) sí sale."""
        self.eventos("p001", "eve.json", [
            alerta("10.0.0.5", "10.0.0.9", sig="ET SCAN Test interno", sid=2000020, dport=22,
                   cat="Attempted Information Leak", hace_s=60 + i) for i in range(2)])
        self.eventos("p001", "eve.json", [
            alerta("198.51.100.7", "10.0.0.5", sig="ET SCAN Test entrante", sid=2000021, dport=23,
                   cat="Attempted Information Leak", hace_s=80 + i) for i in range(2)])
        for args, nodo in ((("60", "--nodo", "p001"), "p001"), (("60", "--todos"), "_todos")):
            self.ok(*args)
            sec = seccion(self.html(nodo), "Ataques entrantes desde internet")
            atacantes = re.findall(r"<span class='ipx mono'>([^<]+)</span>", sec)
            self.assertNotIn("10.0.0.5", atacantes, nodo)
            self.assertIn("198.51.100.7", atacantes, nodo)
            self.assertEqual(list(self.salida(nodo, "entrantes.json")["origenes"]), ["198.51.100.7"])


class RedesPorPunto(Entorno):
    PUNTOS = {"p001": {"nombre": "Nodo A", "redes": ["10.0.0.0/24"]},
              "p002": {"nombre": "Nodo B", "redes": ["172.16.0.0/24"]}}

    def test_todos_juzga_cada_evento_con_las_redes_de_su_punto(self):
        """Corrección de defecto (A-14): p001 (10.0.0.0/24) ve 172.16.0.9, que es de la red de p002.
        En «Todos» no es candidato de p001 (igual que en el informe de p001); un CPE de verdad de
        cada punto sí lo es."""
        self.tres_cnc("p001", src="172.16.0.9")
        self.tres_cnc("p001", src="10.0.0.5")
        self.tres_cnc("p002", src="172.16.0.7")
        self.ok("60", "--nodo", "p001")
        self.ok("60", "--todos")
        self.assertEqual(self.cpes(self.salida("p001", "cuarentena.json")), [("p001", "10.0.0.5")])
        self.assertEqual(self.cpes(self.salida("_todos", "cuarentena.json")),
                         [("p001", "10.0.0.5"), ("p002", "172.16.0.7")])

    def test_mis_redes_global_sigue_valiendo_para_todos(self):
        """Conservación: con MIS_REDES en conf/panel.conf, esas redes valen para todos los puntos."""
        self.global_("conf/panel.conf", "MIS_REDES=172.16.0.0/12,10.0.0.0/8\n")
        self.tres_cnc("p001", src="172.16.0.9")
        self.ok("60", "--todos")
        self.assertEqual(self.cpes(self.salida("_todos", "cuarentena.json")), [("p001", "172.16.0.9")])


if __name__ == "__main__":
    unittest.main()
