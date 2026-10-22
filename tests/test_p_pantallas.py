"""Pantallas del dashboard (P): selector de nodo, vista «Todos», permisos en el servidor y destino
de las acciones (CONTRATO-F2 §1, §3, §10.1, §10.2).

Cada prueba dice su tipo (CONTRATO-F2 §10.5) en su docstring. Datos: 10.0.0.0/24 en los dos puntos.
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
from _dash_p import PanelP  # noqa: E402

IP = "10.0.0.5"


class Pantallas(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        c = PanelP.candidato
        self.p.cuarentena("_todos", [c(IP, "p001"), c(IP, "p002")])
        self.p.cuarentena("p001", [c(IP, "p001")])
        self.p.cuarentena("p002", [c(IP, "p002")])
        self.ana = self.p.entrar("ana")

    def test_todos_dos_filas_misma_ip(self):
        """Capacidad nueva: en «Todos» la misma IP de dos nodos son dos filas, cada una con su nodo
        (su identidad nodo|IP); con ?nodo=p002 sale una sola, la de p002."""
        r = self.p.pedir("GET", "/cuarentena?nodo=_todos", cookie=self.ana)
        self.assertEqual(r.status, 200, r.texto[:500])
        self.assertEqual(r.texto.count("verFicha('p001|%s')" % IP), 1)
        self.assertEqual(r.texto.count("verFicha('p002|%s')" % IP), 1)
        self.assertIn(">norte</span>", r.texto)
        self.assertIn(">sur</span>", r.texto)
        r = self.p.pedir("GET", "/cuarentena?nodo=p002", cookie=self.ana)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.texto.count("verFicha('p002|%s')" % IP), 1)
        self.assertNotIn("verFicha('p001|", r.texto)

    def test_selector_lista_los_puntos(self):
        """Capacidad nueva: el selector (GET name=nodo) trae «Todos» y cada punto con su salud, marca
        el elegido y no sale en Ajustes ni en Puntos."""
        r = self.p.pedir("GET", "/cuarentena?nodo=p001", cookie=self.ana)
        sel = re.search(r"<form method=get action=\"/cuarentena\" class=nodosel>.*?</form>", r.texto, re.S)
        self.assertIsNotNone(sel)
        ops = re.findall(r'<option value="([^"]+)"( selected)?>', sel.group(0))
        self.assertEqual([o for o, _s in ops], ["_todos", "p001", "p002"])
        self.assertEqual([o for o, s in ops if s], ["p001"])
        self.assertIn("norte (p001)", sel.group(0))
        for ruta in ("/ajustes", "/puntos"):
            self.assertNotIn("class=nodosel", self.p.pedir("GET", ruta, cookie=self.ana).texto, ruta)

    def test_nodo_invalido_400_inexistente_404(self):
        """Correccion de defecto: un nodo mal escrito o que no existe no se cambia por «Todos»."""
        self.assertEqual(self.p.pedir("GET", "/cuarentena?nodo=..%2Fp001", cookie=self.ana).status, 400)
        self.assertEqual(self.p.pedir("GET", "/cuarentena?nodo=todos", cookie=self.ana).status, 400)
        self.assertEqual(self.p.pedir("GET", "/cuarentena?nodo=p009", cookie=self.ana).status, 404)

    def test_enlaces_compartibles_llevan_nodo(self):
        """Capacidad nueva: un reporte se sirve con su nodo y no desde otro (inv_B §2). La lista de
        reportes guardados del Historico se quito (el user, 2026-10-12)."""
        d = os.path.join(self.p.tmp.name, "panel", "nodos", "p002")
        with open(os.path.join(d, "report-20261001-1000.html"), "w", encoding="utf-8") as f:
            f.write("<html><body>reporte p002</body></html>")
        r = self.p.pedir("GET", "/historico?nodo=p002", cookie=self.ana)
        self.assertEqual(r.status, 200, r.texto[:300])
        self.assertNotIn("Reportes guardados", r.texto)
        r = self.p.pedir("GET", "/r/report-20261001-1000.html?nodo=p002", cookie=self.ana)
        self.assertIn("reporte p002", r.texto)
        self.assertEqual(self.p.pedir("GET", "/r/report-20261001-1000.html?nodo=p001", cookie=self.ana).status, 404)


class Permisos(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)

    def test_lectura_no_puede_cuarentenar(self):
        """Correccion de defecto: el rol se comprueba en el servidor (403), no solo ocultando botones."""
        luis = self.p.entrar("luis")
        for ruta in ("/cuarentena/enviar", "/cuarentena/quitar", "/cuarentena/enviar-todos", "/cuarentena/graduada"):
            r = self.p.pedir("POST", ruta, {"ip": "p001|" + IP, "nodo": "p001"}, cookie=luis)
            self.assertEqual(r.status, 403, ruta)
        self.assertEqual(self.p.mk, [])
        # ver si puede
        self.assertEqual(self.p.pedir("GET", "/cuarentena?nodo=p001", cookie=luis).status, 200)

    def test_operador_no_toca_puntos_ni_espejo(self):
        """Correccion de defecto: alta, baja, espejo y MikroTik global son solo de admin (403). Desde
        2026-10-22 el operador entra en la ficha de sus puntos (tests/test_panel_alcance.py)."""
        olga = self.p.entrar("olga")
        self.assertEqual(self.p.pedir("GET", "/puntos/nuevo", cookie=olga).status, 403)
        for ruta in ("/puntos", "/puntos/p001", "/puntos/p001/logs"):
            self.assertEqual(self.p.pedir("GET", ruta, cookie=olga).status, 200, ruta)
        for ruta, form in (("/puntos/p001/espejo", {"accion": "aplicar"}), ("/puntos/p001/espejo", {"accion": "plan"})):
            self.assertIn(self.p.pedir("POST", ruta, form, cookie=olga).status, (403, 404), ruta)
        for ruta, form in (("/puntos/nuevo", {"nombre": "este", "redes": "10.1.0.0/24"}),
                           ("/puntos/p001/borrar", {"confirmar": "norte"}), ("/mikrotik", {"nodo": "p001"})):
            self.assertEqual(self.p.pedir("POST", ruta, form, cookie=olga).status, 403, ruta)
        self.assertEqual(self.p.espejo, [])
        self.assertEqual(self.p.orq.ordenes("punto.crear") + self.p.orq.ordenes("punto.borrar"), [])
        # el operador si opera la cuarentena
        # sin reporte de p001 no hay evidencia que fechar: el envio manual va confirmado (§10.4)
        r = self.p.pedir("POST", "/cuarentena/enviar?nodo=p001", {"ip": "p001|" + IP, "confirmar_vieja": "1"},
                         cookie=olga)
        self.assertEqual(r.status, 303)
        self.assertEqual(self.p.mk, [("add", IP, "p001")])


class Destino(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        c = PanelP.candidato
        self.p.cuarentena("_todos", [c(IP, "p001"), c(IP, "p002"), c("10.0.0.9", "p002", "sospechoso")])
        self.p.cuarentena("p001", [c(IP, "p001")])
        self.ana = self.p.entrar("ana")

    def test_destino_sale_de_la_operacion_no_del_selector(self):
        """Correccion de defecto: mirando p001, una accion sobre p002|IP va SOLO al router de p002;
        sin nodo o con un nodo inexistente no se toca ningun router."""
        self.p.pedir("GET", "/cuarentena?nodo=p001", cookie=self.ana)
        r = self.p.pedir("POST", "/cuarentena/enviar?nodo=p001", {"ip": "p002|" + IP}, cookie=self.ana)
        self.assertEqual(r.status, 303)
        self.assertEqual(self.p.mk, [("add", IP, "p002")])
        for malo in (IP, "p009|" + IP, "_todos|" + IP, "../p001|" + IP):
            self.p.pedir("POST", "/cuarentena/enviar?nodo=p001", {"ip": malo}, cookie=self.ana)
            self.p.pedir("POST", "/cuarentena/quitar?nodo=p001", {"ip": malo}, cookie=self.ana)
        self.assertEqual(self.p.mk, [("add", IP, "p002")])

    def test_masiva_desde_todos_por_nodo(self):
        """Capacidad nueva: «Enviar confirmados» desde «Todos» se reparte por nodo: cada CPE a su
        router, solo los confirmados, y el resultado se da por nodo."""
        r = self.p.pedir("POST", "/cuarentena/enviar-todos?nodo=_todos", {"nodo": "_todos"}, cookie=self.ana)
        self.assertEqual(r.status, 303)
        self.assertEqual(sorted(self.p.mk), [("add", IP, "p001"), ("add", IP, "p002")])
        r = self.p.pedir("GET", r.cab("Location"), cookie=self.ana)
        self.assertIn("norte: 1 enviado", r.texto)
        self.assertIn("sur: 1 enviado", r.texto)

    def test_masiva_de_un_nodo_no_toca_el_otro(self):
        """Capacidad nueva: con la lista de p001, la masiva no envia nada a p002."""
        self.p.pedir("POST", "/cuarentena/enviar-todos", {"nodo": "p001"}, cookie=self.ana)
        self.assertEqual(self.p.mk, [("add", IP, "p001")])


class Eventos(unittest.TestCase):
    def test_pestana_y_rutas_de_eventos(self):
        """Capacidad nueva (§9): /eventos con la barra del panel (pestana y selector), sin
        autorrecarga, para el rol lectura; el nodo de la URL se valida (404 si no existe)."""
        p = PanelP()
        self.addCleanup(p.cerrar)
        if not os.path.exists(os.path.join(os.path.dirname(p.d.__file__), "eventos_web.py")):
            self.skipTest("eventos_web.py (zona E) no esta en este arbol")
        with open(os.path.join(p.tmp.name, "datos", "p001", "eve.json"), "w", encoding="utf-8") as f:
            f.write('{"timestamp":"2026-10-11T10:00:00.000000+0000","event_type":"alert","src_ip":"10.0.0.5",'
                    '"dest_ip":"192.0.2.10","proto":"TCP","alert":{"signature":"ET PRUEBA","signature_id":1,'
                    '"severity":2}}\n')
        luis = p.entrar("luis")
        r = p.pedir("GET", "/eventos?nodo=p001", cookie=luis)
        self.assertEqual(r.status, 200, r.texto[:300])
        # todo enlace lleva el nodo de la pagina (CONTRATO-F2 §10.1, auditoria A-11)
        self.assertIn('href="/eventos?nodo=p001" class="tab on"', r.texto)
        self.assertIn("class=nodosel", r.texto)
        self.assertNotIn('http-equiv="refresh"', r.texto)
        self.assertEqual(p.pedir("GET", "/eventos?nodo=p009", cookie=luis).status, 404)


class Origen(unittest.TestCase):
    def test_x_forwarded_host_solo_de_un_proxy_de_confianza(self):
        """Correccion de defecto (§7): X-Forwarded-Host/Forwarded no validan un Origin ajeno si
        el par TCP no es un proxy de confianza."""
        p = PanelP()
        self.addCleanup(p.cerrar)
        h = {"Origin": "https://ajeno.example", "Host": "panel.example", "X-Forwarded-Host": "ajeno.example"}
        self.assertNotEqual(p.d.origen_ajeno(h, "", proxy_confiable=False), "")
        self.assertEqual(p.d.origen_ajeno(h, "", proxy_confiable=True), "")
        self.assertEqual(p.d.origen_ajeno({"Origin": "https://panel.example", "Host": "panel.example"}, "",
                                          proxy_confiable=False), "")


class SinDialogosDelNavegador(unittest.TestCase):
    def test_ninguna_pagina_usa_alert_ni_confirm(self):
        """Conservacion: confirmaciones y avisos van en los modales del panel (nunca alert/confirm)."""
        p = PanelP()
        self.addCleanup(p.cerrar)
        p.cuarentena("_todos", [PanelP.candidato(IP, "p001")])
        ana = p.entrar("ana")
        for ruta in ("/cuarentena?nodo=_todos", "/ajustes", "/puntos", "/puntos/nuevo", "/puntos/p001",
                     "/documentacion", "/exclusiones", "/historico?nodo=p001", "/reputacion?nodo=p001"):
            r = p.pedir("GET", ruta, cookie=ana)
            self.assertEqual(r.status, 200, (ruta, r.texto[:300]))
            self.assertIsNone(re.search(r"\b(alert|confirm|prompt)\(", r.texto), ruta)


if __name__ == "__main__":
    unittest.main()
