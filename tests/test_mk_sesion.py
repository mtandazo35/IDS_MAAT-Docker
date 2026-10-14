"""mk_sesion + _mk_add_en: una conexion al router para una tanda de operaciones.

Tipo: capacidad nueva (base comun de la tanda MikroTik del 2026-10-14). Hasta ahora cada IP
enviada abria su propia conexion TLS + login (politicas, barrido, envio masivo). mk_add sigue
igual por fuera; por dentro usa _mk_add_en, que es lo que reutilizan las tandas.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_f1_cuarentena import Panel  # noqa: E402

IPS = ["10.0.0.%d" % i for i in (21, 22, 23)]


class MkSesion(unittest.TestCase):
    def setUp(self):
        self.p = Panel()
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d
        self.conexiones = []
        conectar = self.d.mk_conectar
        self.d.mk_conectar = lambda dd, timeout=6: (self.conexiones.append(dd.get("ROUTER_ID"))
                                                     or conectar(dd, timeout))

    def test_una_conexion_para_toda_la_tanda(self):
        r = self.d.router_por_id("p001")
        with self.d.mk_sesion(r) as (s, dd):
            for ip in IPS:
                self.assertEqual(self.d._mk_add_en(s, ip, "lista-x", dd.get("TTL"), "prueba")[0], True)
            self.assertEqual(self.d._mk_add_en(s, IPS[0], "lista-x")[0], True)   # ya estaba: exito
        self.assertEqual(self.conexiones, ["p001"])
        self.assertEqual(self.p.lista("p001", "lista-x"), sorted(IPS))
        self.assertEqual(self.p.lista("p002", "lista-x"), [])

    def test_mk_add_sigue_igual_por_fuera(self):
        r = self.d.router_por_id("p002")
        self.assertEqual(self.d.mk_add(IPS[0], comment="c", lista="lista-y", router=r)[0], True)
        self.assertEqual(self.d.mk_add(IPS[0], comment="c", lista="lista-y", router=r),
                         (True, "ya estaba en la lista"))
        self.assertEqual(self.p.lista("p002", "lista-y"), [IPS[0]])

    def test_punto_en_baja_no_abre_nada(self):
        self.d._BAJAS.add("p001")
        self.addCleanup(self.d._BAJAS.discard, "p001")
        with self.assertRaises(self.d.PuntoEnBaja):
            with self.d.mk_sesion(self.d.router_por_id("p001")):
                pass
        self.assertEqual(self.conexiones, [])

    def test_router_caido_lanza_y_no_deja_nada_abierto(self):
        self.p.caidos.add("p001")
        with self.assertRaises(OSError):
            with self.d.mk_sesion(self.d.router_por_id("p001")):
                self.fail("no deberia entrar")


if __name__ == "__main__":
    unittest.main()
