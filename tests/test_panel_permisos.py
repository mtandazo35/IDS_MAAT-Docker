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
        self.assertNotIn("puntos.borrar", lim)          # borrar puntos es global
        self.assertIn("puntos.api", lim)
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


# --------------------------------------------------------------------------------------------
# Fase 2: la sección Puntos decide por permiso; el acordeón de Usuarios
# --------------------------------------------------------------------------------------------
PUNTOS_TODOS = frozenset(x for x in permisos.TODOS if x.startswith("puntos."))


class DelFormulario(unittest.TestCase):
    def test_grupos_editables_y_plantilla(self):
        """Lo que se guarda: en Puntos, lo marcado (válido); el resto, la plantilla del rol; sin
        grupos editables, None (formulario de antes: no se toca)."""
        f = permisos.del_formulario
        self.assertIsNone(f([""], ["puntos.ver"], "operador"))
        self.assertIsNone(f(["ajustes"], ["ajustes.dns"], "admin"))
        r = set(f(["puntos"], ["puntos.ver", "inventado", "ajustes.dns"], "operador"))
        self.assertEqual(r & PUNTOS_TODOS, {"puntos.ver"})
        self.assertNotIn("ajustes.dns", r)
        self.assertTrue(permisos.PLANTILLAS["operador"] - PUNTOS_TODOS <= r)
        self.assertEqual(set(f(["puntos"], [], "lectura")), permisos.PLANTILLAS["lectura"])


class PuntosPorPermiso(A.Base):
    def poner_permisos(self, quien, lista):
        us = self.d.cargar_usuarios()
        for r in us:
            if r["user"] == quien:
                r["permisos"] = list(lista)
        self.d.guardar_usuarios(us)

    def test_solo_ver_la_ficha(self):
        """Capacidad nueva: un operador sin lista de puntos y solo con «Ver la lista y la ficha» entra
        en la ficha, pero no arranca, no toca la API, ni prefijos, ni la VPN, ni logs (403 sin
        efectos) y la ficha no le ofrece esos botones ni le enseña los comandos de la VPN."""
        self.poner_permisos("pepe", sorted((permisos.PLANTILLAS["operador"] - PUNTOS_TODOS) | {"puntos.ver"}))
        r = self.get("/puntos/p001", "pepe")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        for no in ("value=guardar", "Regenerar la clave VPN", "Guardar prefijos", "/puntos/p001/arrancar",
                   "/puntos/p001/logs", "id=baja"):
            self.no_esta(no, r.texto, "ficha pepe")
        self.esta("no tiene permiso para ver los comandos", r.texto, "ficha pepe")
        for ruta, form in (("/puntos/p001/arrancar", {}), ("/puntos/p001/regenerar", {}),
                           ("/puntos/p001/ajustar", {"redes": ""}), ("/puntos/p001/api", {"accion": "guardar"})):
            with self.subTest(ruta=ruta):
                self.assertEqual(self.post(ruta, form, "pepe").status, 403)
        self.assertEqual(self.get("/puntos/p001/logs", "pepe").status, 403)
        self.assertEqual(self.get("/puntos/p001/huella", "pepe").status, 403)
        self.assertEqual(self.p.orq.ordenes("punto.arrancar"), [])

    def test_lectura_con_permiso_entra(self):
        """Capacidad nueva: un usuario de lectura con «Ver la lista y la ficha» entra en Puntos."""
        self.poner_permisos("luis", sorted(permisos.PLANTILLAS["lectura"] | {"puntos.ver"}))
        self.assertEqual(self.get("/puntos", "luis").status, 200)
        self.assertEqual(self.get("/puntos/p001", "luis").status, 200)
        self.assertEqual(self.post("/puntos/p001/arrancar", {}, "luis").status, 403)

    def test_borrar_es_global(self):
        """Borrar puntos es global: con lista de puntos no vale aunque esté marcado (403); sin lista,
        la ficha ofrece la baja."""
        con_borrar = sorted(permisos.PLANTILLAS["operador"] | {"puntos.borrar"})
        self.poner_permisos("olga", con_borrar)          # olga ve solo p001
        self.assertEqual(self.post("/puntos/p001/borrar", {"confirmar": "x"}, "olga").status, 403)
        self.no_esta("id=baja", self.get("/puntos/p001", "olga").texto, "ficha olga")
        self.poner_permisos("pepe", con_borrar)          # pepe ve todos
        self.esta("id=baja", self.get("/puntos/p001", "pepe").texto, "ficha pepe")

    def test_sin_lista_como_antes(self):
        """Conservación: sin `permisos`, cada rol tiene los de su plantilla (operador arranca, lectura no
        entra en Puntos)."""
        r = self.post("/puntos/p001/arrancar", {}, "olga")
        self.assertEqual(r.status, 303, A.plano(r.texto))
        self.assertEqual(self.get("/puntos", "luis").status, 403)


# --------------------------------------------------------------------------------------------
# Fase 3: Cuarentena y Reputación deciden por permiso
# --------------------------------------------------------------------------------------------
class CuarentenaPorPermiso(A.Base):
    poner_permisos = PuntosPorPermiso.poner_permisos

    def sin(self, quien, *quitar):
        r = self.usuario(quien)
        self.poner_permisos(quien, sorted(permisos.PLANTILLAS[r["role"]] - set(quitar)))

    def test_sin_enviar_no_envia(self):
        """Capacidad nueva: un operador sin «Enviar y quitar» recibe 403 y nada llega al router; con
        el resto de su plantilla, la graduada sí."""
        self.sin("olga", "cuarentena.enviar")
        r = self.post("/cuarentena/enviar", {"ip": "p001|" + A.IP_PROPIA_CAND, "score": "80"}, "olga")
        self.assertEqual(r.status, 403)
        self.assertEqual(self.post("/cuarentena/quitar", {"ip": "p001|" + A.IP_PROPIA}, "olga").status, 403)
        self.assertEqual(self.p.mk, [])

    def test_lectura_con_enviar_si_envia(self):
        """Capacidad nueva: un usuario de lectura (luis, p001) con «Enviar y quitar» manda a cuarentena
        en su punto."""
        self.poner_permisos("luis", sorted(permisos.PLANTILLAS["lectura"] | {"cuarentena.enviar"}))
        r = self.post("/cuarentena/enviar", {"ip": "p001|" + A.IP_PROPIA_CAND, "score": "80"}, "luis")
        self.assertEqual(r.status, 303, A.plano(r.texto))
        self.assertIn(("add", A.IP_PROPIA_CAND, "p001"), self.p.mk)

    def test_sin_ver_no_ve(self):
        """Capacidad nueva: sin «Ver candidatos...», ni la página ni la ficha del abonado (403)."""
        self.sin("pepe", "cuarentena.ver")
        self.assertEqual(self.get("/cuarentena", "pepe").status, 403)
        self.assertEqual(self.get("/cuarentena/ficha?ip=p001%7C" + A.IP_PROPIA, "pepe").status, 403)

    def test_cada_accion_su_permiso(self):
        """Capacidad nueva: graduada, DNS, envío masivo y destinos, cada uno con el suyo (403 sin él)."""
        casos = (("cuarentena.graduada", "/cuarentena/graduada", {"ip": "p001|" + A.IP_PROPIA_CAND}),
                 ("cuarentena.dns", "/cuarentena/dns/enviar", {"ip": "p001|" + A.IP_PROPIA_CAND}),
                 ("cuarentena.masivo", "/cuarentena/enviar-todos", {"nodo": "p001"}),
                 ("cuarentena.destinos", "/cuarentena/destino/bloquear", {"ip": "203.0.113.60"}))
        for perm, ruta, form in casos:
            with self.subTest(perm=perm):
                self.sin("pepe", perm)
                self.assertEqual(self.post(ruta, form, "pepe").status, 403)
        self.assertEqual(self.p.mk, [])

    def test_confianza_global_y_denunciar(self):
        """Destinos de confianza y denunciar son globales: un limitado con ellos marcados sigue con
        403; uno sin lista de puntos y sin ellos, también."""
        llamadas = []
        self.d.excluir_destino = lambda dd: (llamadas.append(dd) or (1, "excluido"))
        self.d.aidb_denunciar = lambda ip, **k: (llamadas.append(ip) or (True, "denunciada"))
        self.poner_permisos("olga", sorted(permisos.PLANTILLAS["operador"]))
        self.sin("pepe", "cuarentena.confianza", "reputacion.denunciar")
        for quien in ("olga", "pepe"):
            with self.subTest(quien=quien):
                self.assertEqual(self.post("/cuarentena/excluir-destino", {"destino": "203.0.113.50"},
                                           quien).status, 403)
                self.assertEqual(self.post("/reputacion/denunciar", {"ip": "203.0.113.52", "firma": "ET x",
                                                                     "dport": "443", "proto": "TCP", "n": "3"},
                                           quien).status, 403)
        self.assertEqual(llamadas, [])

    def test_reputacion(self):
        """Capacidad nueva: sin «Ver las IPs públicas» no hay página; sin «Consultar AbuseIPDB», ni
        consulta ni ficha (403)."""
        self.sin("luis", "reputacion.ver")
        self.assertEqual(self.get("/reputacion", "luis").status, 403)
        self.sin("pepe", "reputacion.consultar")
        self.assertEqual(self.get("/reputacion", "pepe").status, 200)
        self.assertEqual(self.get("/reputacion?ips=203.0.113.9", "pepe").status, 403)
        self.assertEqual(self.get("/reputacion/ficha?ip=203.0.113.9", "pepe").status, 403)
        self.assertEqual(self.post("/reputacion", {"ips": "203.0.113.9"}, "pepe").status, 403)


class AcordeonUsuarios(A.Base):
    def editar(self, objetivo, rol, perm=None, grupos="puntos"):
        form = {"accion": "edit_user", "user": objetivo, "nombre": "", "correo": "", "role": rol}
        if grupos is not None:
            form["perm_grupos"] = grupos
        if perm:
            form["perm"] = list(perm)
        return self.post("/perfil", form, "ana")

    def test_el_formulario_trae_el_acordeon(self):
        """Capacidad nueva: Ajustes › Usuarios trae el acordeón «Permisos» con la sección Puntos, su
        «Activos X/Y» y una casilla por permiso; la fila lleva los permisos del usuario."""
        h = self.get("/ajustes", "ana").texto
        self.esta("name=perm_grupos value='cuarentena,reputacion,puntos'", h, "ajustes")
        self.esta("class=pgrp data-g='cuarentena'", h, "ajustes")
        self.esta("class=pgrp data-g='reputacion'", h, "ajustes")
        self.esta("class=pgrp data-g='puntos'", h, "ajustes")
        self.esta("Activos <b class=pgn>0</b>/10", h, "ajustes")
        for p in sorted(PUNTOS_TODOS):
            self.esta("name=perm value='%s'" % p, h, "ajustes")
        self.esta("data-permisos='", h, "ajustes")

    def test_el_javascript_de_ajustes_compila(self):
        """El JS de Ajustes (con el del acordeón) no tiene errores de sintaxis (node --check); sin
        node, se salta."""
        import re
        import shutil
        import subprocess
        import tempfile
        node = shutil.which("node")
        if not node:
            self.skipTest("sin node")
        h = self.get("/ajustes", "ana").texto
        js = "\n;\n".join(re.findall(r"<script>(.*?)</script>", h, re.S))
        self.assertIn("function permPlantilla", js)
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8",
                                         dir=os.environ.get("TMPDIR", "/tmp")) as f:
            f.write(js)
        self.addCleanup(os.unlink, f.name)
        r = subprocess.run([node, "--check", f.name], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr[-800:])

    def test_guardar_y_volver_a_la_plantilla(self):
        """Capacidad nueva: editar con el acordeón guarda la lista si difiere de la plantilla y la
        borra si es igual; sin perm_grupos (formulario de antes) no se toca; cambiar el rol la borra.
        Y vale en la siguiente petición."""
        self.editar("olga", "operador", ["puntos.ver"])
        r = self.usuario("olga")
        self.assertIn("puntos.ver", r["permisos"])
        self.assertNotIn("puntos.arrancar", r["permisos"])
        self.assertEqual(self.post("/puntos/p001/arrancar", {}, "olga").status, 403)
        self.editar("olga", "operador", None, grupos=None)
        self.assertIn("permisos", self.usuario("olga"))
        self.editar("olga", "operador", sorted(permisos.PLANTILLAS["operador"] & PUNTOS_TODOS))
        self.assertNotIn("permisos", self.usuario("olga"))
        self.editar("olga", "operador", ["puntos.ver"])
        self.post("/perfil", {"accion": "rol_user", "user": "olga", "role": "lectura"}, "ana")
        self.assertNotIn("permisos", self.usuario("olga"))

    def test_alta_con_permisos(self):
        """Capacidad nueva: al crear, lo marcado; si coincide con la plantilla no se guarda lista."""
        base = {"accion": "add_user", "npass": "clave-larga-de-prueba", "nrole": "operador",
                "puntos_modo": "todos", "perm_grupos": "puntos"}
        self.post("/perfil", dict(base, nuser="np1", perm=["puntos.ver", "puntos.logs"]), "ana")
        self.assertEqual(set(self.usuario("np1")["permisos"]) & PUNTOS_TODOS, {"puntos.ver", "puntos.logs"})
        self.post("/perfil", dict(base, nuser="np2", perm=sorted(permisos.PLANTILLAS["operador"] & PUNTOS_TODOS)),
                  "ana")
        self.assertNotIn("permisos", self.usuario("np2"))


if __name__ == "__main__":
    unittest.main()
