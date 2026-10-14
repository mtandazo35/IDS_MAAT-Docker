"""Ajustes > MikroTik: solo lo comun a todos los nodos; la conexion, en la ficha del punto.

Tipo: correccion de defecto (el user, 2026-10-14: «aqui por que esta si ya tenemos en puntos»).
Ajustes tenia un formulario de conexion (nodo, usuario y clave de la API, permitir enviar) con los
mismos campos que Puntos > ficha > API, y al guardar copiaba al router elegido la lista y el TTL
globales: la lista LIST del router volvia al defecto aunque el formulario no la enseñara, el TTL
que se veia era siempre 1h/1d (no el del router) y «vacio = permanente» no se cumplia.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_f1_cuarentena import Panel  # noqa: E402


class AjustesMikrotik(unittest.TestCase):
    def setUp(self):
        self.p = Panel(http=True)
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d

    def _routers(self):
        return {r["id"]: r for r in self.d.cargar_routers()}

    def _guardar(self, **campos):
        st, _c, txt = self.p.pedir("POST", "/mikrotik", campos)
        return st, txt

    def test_ajustes_ya_no_tiene_el_formulario_de_conexion(self):
        """Ni usuario ni clave ni «Probar conexion» en Ajustes: una tabla con el estado de la API
        de cada nodo y el enlace a su ficha (apartado API)."""
        st, _c, h = self.p.pedir("GET", "/ajustes")
        self.assertEqual(st, 200)
        ini = h.index("MikroTik &mdash; cuarentena")
        card = h[ini:h.index("</section>", ini)]
        for fuera in ("name=user", "name=pass", "name=enabled", "name=nodo", "mktest", "Probar conexion"):
            self.assertNotIn(fuera, card)
        for pid in ("p001", "p002"):
            self.assertIn("href='/puntos/%s#api'" % pid, card)
        self.assertIn("configurada</span> <span class=mkcx-u>(u)</span>", card)   # p001: usuario u
        self.assertIn("id=mkwait", card)        # la ventana de las acciones de reglas sigue

    def test_guardar_no_toca_la_conexion_ni_la_lista_del_router(self):
        """Un formulario viejo que aun mande nodo/user/pass/enabled no cambia nada de la conexion,
        y la lista LIST propia del router no vuelve al defecto."""
        rs = self.d.cargar_routers()
        for r in rs:
            r["LIST"] = "lista-propia"
        self.d.guardar_routers(rs)
        antes = self._routers()
        st, txt = self._guardar(nodo="p001", user="otro", **{"pass": "clave-nueva"}, list="otra")
        self.assertEqual(st, 200)
        self.assertIn("Ajustes de MikroTik guardados", txt)
        despues = self._routers()
        for pid in ("p001", "p002"):
            for k in ("USER", "PASS", "ENABLED", "LIST", "LIST_DNS"):
                self.assertEqual(despues[pid].get(k), antes[pid].get(k), (pid, k))
        self.assertEqual(despues["p001"]["ENABLED"], "1")   # sin «enabled» en el form: sigue activo

    def test_el_ttl_va_a_todos_los_nodos_y_vacio_es_permanente(self):
        st, _txt = self._guardar(ttl="2h", ttl_dns="")
        self.assertEqual(st, 200)
        rs = self._routers()
        self.assertEqual({rs[p]["TTL"] for p in rs}, {"2h"})
        self.assertEqual({rs[p]["TTL_DNS"] for p in rs}, {""})
        self.assertEqual(self.d.cargar_mk_de(rs["p002"])["TTL_DNS"], "")    # sin timeout
        # y se enseña el que tienen, no el defecto 1h
        _s, _c, h = self.p.pedir("GET", "/ajustes")
        self.assertRegex(h, r"name=ttl value=\"2h\"")
        self.assertRegex(h, r"name=ttl_dns value=\"\"")

    def test_ttl_invalido_no_guarda_nada(self):
        mk_antes = os.path.exists(self.d.MK_CONF) and open(self.d.MK_CONF, encoding="utf-8").read()
        antes = self._routers()
        st, txt = self._guardar(ttl="2 horas", ttl_dns="1d", auto="1")
        self.assertEqual(st, 400)
        self.assertIn("no es un tiempo de RouterOS", txt)
        self.assertEqual(self._routers(), antes)
        self.assertEqual(os.path.exists(self.d.MK_CONF) and open(self.d.MK_CONF, encoding="utf-8").read(), mk_antes)
        for bueno in ("30m", "1h", "1d12h", "1w", "00:30:00", "1d00:30:00"):
            self.assertTrue(self.d.RE_TTL_ROS.match(bueno), bueno)
        for malo in ("2 horas", "1x", "h", "-1h", "1h;", "99:9"):
            self.assertFalse(self.d.RE_TTL_ROS.match(malo), malo)

    def test_avisa_si_el_ttl_es_distinto_entre_nodos(self):
        rs = self.d.cargar_routers()
        rs[0]["TTL"], rs[1]["TTL"] = "1h", "3h"
        self.d.guardar_routers(rs)
        _s, _c, h = self.p.pedir("GET", "/ajustes")
        self.assertIn("Ahora no es igual en todos los nodos (p001: 1h · p002: 3h)", h)

    def test_probar_conexion_de_ajustes_ya_no_existe(self):
        """La prueba de conexion es la de la ficha del punto, que no guarda a escondidas."""
        st, _c, _txt = self.p.pedir("POST", "/mikrotik/test", {"nodo": "p001", "ajax": "1"})
        self.assertNotEqual(st, 200)


if __name__ == "__main__":
    unittest.main()
