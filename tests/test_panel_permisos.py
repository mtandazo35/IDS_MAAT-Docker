"""Permisos del panel, fase 1 (el dueño, 2026-10-22: «mejoremos los roles para personalizar más,
hasta para los administradores poder filtrar los puntos»).

- permisos.py: el catálogo por secciones y las plantillas de los roles de siempre; un usuario sin
  lista `permisos` tiene los de su rol y, si está limitado a unos puntos, pierde los globales.
- Un administrador también se limita a unos puntos: ve solo esos, sin «Todos», y no toca lo global
  (Ajustes, usuarios, exclusiones).
- Salvaguarda: siempre queda un administrador activo con todos los puntos (no se le quita el rol,
  ni se le limitan los puntos, ni se borra, ni se desactiva si es el único).
Con el panel real de _dash_p (montaje de test_panel_alcance)."""

import importlib
import os
import sys
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
A = importlib.import_module("test_panel_alcance")
PANEL = os.path.join(os.path.dirname(AQUI), "images", "panel", "rootfs", "usr", "local", "lib", "ids-panel")
sys.path.insert(0, PANEL)
permisos = importlib.import_module("permisos")


class Catalogo(unittest.TestCase):
    def test_claves_unicas_y_grupos(self):
        """Cada permiso sale una vez y pertenece a un grupo; activos() cuenta por grupo."""
        self.assertEqual(len(permisos.TODOS), len(set(permisos.TODOS)))
        grupos = [g for g, _t, _ps in permisos.CATALOGO]
        self.assertEqual(grupos, ["resumen", "cuarentena", "reputacion", "puntos", "usuarios", "ajustes"])
        for g, _t, ps in permisos.CATALOGO:
            for p, _e, _gl in ps:
                self.assertTrue(p.startswith(g + "."), p)
        self.assertEqual(permisos.activos(permisos.TODOS, "ajustes"), (12, 12))
        self.assertEqual(permisos.activos(permisos.PLANTILLAS["lectura"], "puntos"), (0, 10))
        self.assertTrue(all(p.startswith("ajustes.") for p in permisos.GLOBALES if p.startswith("ajustes")))

    def test_plantillas_reproducen_los_roles(self):
        """Conservación: lectura solo ve; operador además opera cuarentenas y la ficha (sin crear,
        borrar ni desbanear, ni usuarios ni ajustes); admin, todo."""
        lec, ope, adm = (permisos.PLANTILLAS[k] for k in ("lectura", "operador", "admin"))
        self.assertTrue(lec < ope < adm)
        self.assertEqual(adm, frozenset(permisos.TODOS))
        for p in ("puntos.crear", "puntos.borrar", "puntos.desbanear", "usuarios.ver", "usuarios.editar",
                  "ajustes.empresa", "ajustes.actualizar"):
            self.assertNotIn(p, ope, p)
        for p in ("cuarentena.enviar", "puntos.api", "puntos.vpn_regenerar", "puntos.arrancar"):
            self.assertIn(p, ope, p)
            self.assertNotIn(p, lec, p)

    def test_de_usuario(self):
        """Sin lista: la plantilla del rol; con lista: solo claves del catálogo; mal formada o rol
        desconocido: ninguno; limitado a unos puntos: sin los globales."""
        de = permisos.de_usuario
        self.assertEqual(de({"role": "operador"}), permisos.PLANTILLAS["operador"])
        self.assertEqual(de({"role": "admin", "permisos": ["puntos.ver", "inventado", "ajustes.dns"]}),
                         frozenset({"puntos.ver", "ajustes.dns"}))
        self.assertEqual(de({"role": "admin", "permisos": "puntos.ver"}), frozenset())
        self.assertEqual(de({"role": "jefe"}), frozenset())
        self.assertEqual(de(None), frozenset())
        lim = de({"role": "admin", "puntos": ["p001"]})
        self.assertFalse(lim & permisos.GLOBALES)
        self.assertIn("puntos.borrar", lim)
        self.assertIn("usuarios.editar", lim)


class AdminLimitado(A.Base):
    """adela es admin con puntos=["p001"] (montaje de test_panel_alcance)."""

    def test_ve_solo_sus_puntos(self):
        """Capacidad nueva: un admin con lista ve solo sus puntos, sin «Todos» ni datos ajenos."""
        self.assertEqual(self.get("/?nodo=p002", "adela").status, 404)
        self.assertEqual(self.get("/?nodo=_todos", "adela").status, 404)
        r = self.get("/", "adela")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.sin_ajenos(r.texto, "/ adela")
        self.esta(A.RES_PROPIO, r.texto)

    def test_no_toca_lo_global(self):
        """Capacidad nueva: sin las tarjetas de admin en Ajustes, sin usuarios ni exclusiones (403) y
        sin crear puntos; usuarios.json intacto."""
        antes = self.d.cargar_usuarios()
        h = self.get("/ajustes", "adela").texto
        self.assertNotIn("value=add_user", h)
        self.assertEqual(self.get("/exclusiones", "adela").status, 403)
        self.assertEqual(self.get("/puntos/nuevo", "adela").status, 403)
        r = self.post("/perfil", {"accion": "add_user", "nuser": "intruso", "npass": "clave-larga-de-prueba",
                                  "nrole": "admin", "puntos_modo": "todos"}, "adela")
        self.assertEqual(r.status, 403)
        r = self.post("/perfil", {"accion": "edit_user", "user": "adela", "nombre": "", "correo": "",
                                  "role": "admin", "puntos_modo": "todos"}, "adela")
        self.assertEqual(r.status, 403)
        self.assertEqual(self.d.cargar_usuarios(), antes)

    def test_gestiona_la_ficha_de_su_punto(self):
        """Capacidad nueva: como un operador en sus puntos: su ficha sí, la ajena 404."""
        self.assertEqual(self.get("/puntos/p001", "adela").status, 200)
        self.assertEqual(self.get("/puntos/p002", "adela").status, 404)


class Salvaguarda(A.Base):
    def editar(self, objetivo, rol, modo, puntos=(), quien="ana"):
        form = {"accion": "edit_user", "user": objetivo, "nombre": "", "correo": "", "role": rol,
                "puntos_modo": modo}
        if puntos:
            form["puntos"] = list(puntos)
        return self.post("/perfil", form, quien)

    def test_el_unico_admin_total_no_se_pierde(self):
        """Capacidad nueva: con ana como único admin con todos los puntos (adela está limitada), no se
        le pueden limitar los puntos, quitar el rol, borrar ni desactivar."""
        self.editar("ana", "admin", "solo", ["p001"], quien="ana")
        self.assertNotIn("puntos", self.usuario("ana"))
        self.editar("ana", "operador", "todos", quien="ana")
        self.assertEqual(self.usuario("ana")["role"], "admin")
        self._cookies.clear()
        self.post("/perfil", {"accion": "rol_user", "user": "ana", "role": "lectura"}, "ana")
        self.assertEqual(self.usuario("ana")["role"], "admin")
        # otro admin limitado no cuenta: tampoco se puede desactivar ni borrar a ana desde otro admin total
        self.d.guardar_usuarios(self.d.cargar_usuarios() + [dict(self.usuario("ana"), user="beto")])
        self.post("/perfil", {"accion": "toggle_user", "user": "beto"}, "ana")
        self.assertFalse(self.usuario("beto")["activo"])
        self._cookies.clear()
        self.post("/perfil", {"accion": "del_user", "user": "ana"}, "ana")
        self.assertIsNotNone(self.usuario("ana"))

    def test_con_otro_admin_total_si_se_limita(self):
        """Con otro admin activo con todos los puntos, sí se puede limitar a uno de los dos."""
        self.d.guardar_usuarios(self.d.cargar_usuarios() + [dict(self.usuario("ana"), user="beto")])
        r = self.editar("beto", "admin", "solo", ["p001", "p003"])
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.assertEqual(self.usuario("beto").get("puntos"), ["p001", "p003"])
        self.assertEqual(self.get("/?nodo=p002", "beto").status, 404)


if __name__ == "__main__":
    unittest.main()
