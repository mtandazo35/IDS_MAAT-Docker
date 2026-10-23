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
        # (fase 5) gestiona usuarios de sus puntos, pero no ve a quien tiene más que ella
        self.assertNotIn("data-user='ana'", h)
        self.assertNotIn("data-user='pepe'", h)
        self.assertEqual(self.get("/exclusiones", "adela").status, 403)
        self.assertEqual(self.get("/puntos/nuevo", "adela").status, 403)
        r = self.post("/perfil", {"accion": "add_user", "nuser": "intruso", "npass": "clave-larga-de-prueba",
                                  "nrole": "admin", "puntos_modo": "todos"}, "adela")
        self.assertEqual(r.status, 403)
        r = self.post("/perfil", {"accion": "edit_user", "user": "adela", "nombre": "", "correo": "",
                                  "role": "admin", "puntos_modo": "todos"}, "adela")
        self.assertIn(r.status, (403, 200))
        self.assertIn("puntos", self.usuario("adela"))     # no se amplía a todos los puntos
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
        self.assertIsNone(f(["inventado"], ["ajustes.dns"], "admin"))
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


# --------------------------------------------------------------------------------------------
# Fase 4: Resumen, Histórico, Conducta, Informe, Eventos y la vista «Todos» por permiso
# --------------------------------------------------------------------------------------------
class ResumenPorPermiso(A.Base):
    poner_permisos = PuntosPorPermiso.poner_permisos
    sin = CuarentenaPorPermiso.sin

    def test_sin_todos_ve_los_puntos_uno_a_uno(self):
        """Capacidad nueva: un usuario sin lista de puntos pero sin «Vista Todos» los ve todos, de uno
        en uno: «Todos» es 404, su vista por defecto es el primer punto y el selector no la ofrece."""
        self.sin("pepe", "resumen.todos")
        self.assertEqual(self.get("/?nodo=_todos", "pepe").status, 404)
        r = self.get("/", "pepe")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        vals, elegida, _sel = A.selector(r.texto)
        self.assertEqual(elegida, "p001")
        self.assertNotIn("_todos", vals or [])
        self.assertEqual(self.get("/?nodo=p002", "pepe").status, 200)

    def test_cada_pagina_su_permiso(self):
        """Capacidad nueva: sin el permiso de una página, 403 y sin su pestaña en el menú."""
        casos = (("resumen.historico", "/historico", "/historico"),
                 ("resumen.conducta", "/conducta", "/conducta"),
                 ("resumen.conducta", "/conducta.csv", None),
                 ("resumen.informe", "/informe.pdf?dias=1", None),
                 ("resumen.eventos", "/eventos", "/eventos"),
                 ("resumen.ver", "/top", "/top"),
                 ("resumen.ver", "/detalle", "/detalle"))
        for perm, ruta, tab in casos:
            with self.subTest(perm=perm, ruta=ruta):
                self.sin("pepe", perm)
                self.assertEqual(self.get(ruta, "pepe").status, 403)
                if tab:
                    h = self.get("/cuarentena", "pepe").texto
                    self.no_esta('href="%s" class="tab' % tab, h, "menú sin " + perm)

    def test_generar_conducta_su_permiso(self):
        """Generar el reporte de Conducta tiene su permiso: lectura no lo trae (403), con él marcado sí
        (303); un operador sin él, tampoco."""
        self.assertEqual(self.post("/conducta/refrescar", {}, "luis").status, 403)
        self.poner_permisos("luis", sorted(permisos.PLANTILLAS["lectura"] | {"resumen.conducta_generar"}))
        self.assertEqual(self.post("/conducta/refrescar", {}, "luis").status, 303)
        self.sin("pepe", "resumen.conducta_generar")
        self.assertEqual(self.post("/conducta/refrescar", {}, "pepe").status, 403)
        self.assertNotIn("<button class='b pri'>Generar ahora</button>", self.get("/conducta", "pepe").texto)

    def test_sin_en_vivo_va_a_lo_primero_que_puede(self):
        """Capacidad nueva: sin «En vivo» la portada lleva a la primera página que sí puede ver."""
        self.sin("pepe", "resumen.ver")
        r = self.get("/", "pepe")
        self.assertEqual(r.status, 303)
        self.assertTrue((r.cab("Location") or "").startswith("/cuarentena"), r.cab("Location"))

    def test_sin_nada_va_a_ajustes(self):
        """Sin ninguna página de datos, la portada lleva a Ajustes (su clave y su foto)."""
        self.poner_permisos("luis", [])
        r = self.get("/", "luis")
        self.assertEqual(r.status, 303)
        self.assertTrue((r.cab("Location") or "").startswith("/ajustes"), r.cab("Location"))


# --------------------------------------------------------------------------------------------
# Fase 5: un cliente administra a su gente sin dar más de lo que tiene
# --------------------------------------------------------------------------------------------
GESTOR = sorted(permisos.PLANTILLAS["operador"] | {"usuarios.ver", "usuarios.editar", "usuarios.borrar"})


class UsuariosDelegados(A.Base):
    poner_permisos = PuntosPorPermiso.poner_permisos

    def setUp(self):
        super().setUp()
        self.poner_permisos("olga", GESTOR)            # olga: operador, solo p001, gestiona usuarios

    def alta(self, nombre, rol="lectura", modo="solo", puntos=("p001",), perm=None, quien="olga"):
        form = {"accion": "add_user", "nuser": nombre, "npass": "clave-larga-de-prueba", "nrole": rol,
                "puntos_modo": modo, "perm_grupos": "resumen,cuarentena,reputacion,puntos,usuarios"}
        if puntos:
            form["puntos"] = list(puntos)
        if perm is not None:
            form["perm"] = list(perm)
        return self.post("/perfil", form, quien)

    def test_ve_solo_a_quien_puede_gestionar(self):
        """Capacidad nueva: en su lista sale ella y luis (lectura, p001); no pepe (todos los puntos),
        ni dora (p003), ni los administradores."""
        h = self.get("/ajustes", "olga").texto
        self.esta("value=add_user", h, "ajustes olga")
        for u in ("luis",):
            self.esta("data-user='%s'" % u, h, "ajustes olga")
        for u in ("pepe", "dora", "ana", "adela"):
            self.no_esta("data-user='%s'" % u, h, "ajustes olga")
        self.no_esta("data-user='olga'", h, "ajustes olga (no se edita a sí misma)")

    def test_alta_dentro_de_lo_suyo(self):
        """Capacidad nueva: crea usuarios solo con sus puntos y sus permisos: un punto ajeno o un
        permiso que no tiene se quedan fuera."""
        r = self.alta("nuevo1", puntos=("p001", "p002"),
                      perm=["resumen.ver", "cuarentena.enviar", "puntos.borrar", "usuarios.editar"])
        self.assertEqual(r.status, 200, A.plano(r.texto))
        u = self.usuario("nuevo1")
        self.assertEqual(u.get("puntos"), ["p001"])
        self.assertIn("cuarentena.enviar", u["permisos"])
        self.assertNotIn("puntos.borrar", u["permisos"])
        self.assertTrue(set(u["permisos"]) <= set(GESTOR))

    def test_no_da_mas_que_lo_suyo(self):
        """Capacidad nueva: ni rol administrador, ni «todos los puntos» (403, sin usuario nuevo)."""
        self.assertEqual(self.alta("nuevo2", rol="admin").status, 403)
        self.assertEqual(self.alta("nuevo3", modo="todos", puntos=()).status, 403)
        self.assertIsNone(self.usuario("nuevo2"))
        self.assertIsNone(self.usuario("nuevo3"))

    def test_no_toca_a_quien_tiene_mas(self):
        """Capacidad nueva: editar, cambiar el rol, borrar o desactivar a pepe, dora, ana o a sí misma
        responde «no existe» y no cambia nada."""
        antes = self.d.cargar_usuarios()
        for u in ("pepe", "dora", "ana", "olga"):
            for form in ({"accion": "edit_user", "user": u, "nombre": "x", "correo": "", "role": "lectura",
                          "puntos_modo": "solo", "puntos": ["p001"]},
                         {"accion": "rol_user", "user": u, "role": "lectura"},
                         {"accion": "del_user", "user": u}, {"accion": "toggle_user", "user": u}):
                with self.subTest(u=u, accion=form["accion"]):
                    r = self.post("/perfil", form, "olga")
                    self.assertIn("Ese usuario no existe", r.texto)
        self.assertEqual(self.d.cargar_usuarios(), antes)

    def test_edita_a_los_suyos(self):
        """Capacidad nueva: a luis (lectura, p001) lo edita y lo desactiva."""
        r = self.post("/perfil", {"accion": "edit_user", "user": "luis", "nombre": "Luis", "correo": "",
                                  "role": "operador", "puntos_modo": "solo", "puntos": ["p001"],
                                  "perm_grupos": "cuarentena", "perm": ["cuarentena.ver", "cuarentena.enviar"]},
                      "olga")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        u = self.usuario("luis")
        self.assertEqual((u["role"], u["nombre"]), ("operador", "Luis"))
        self.assertTrue(set(u["permisos"]) <= set(GESTOR))
        self.post("/perfil", {"accion": "toggle_user", "user": "luis"}, "olga")
        self.assertFalse(self.usuario("luis")["activo"])

    def test_admin_recortado_no_se_devuelve_todo(self):
        """Verificador final, H1: un admin con todos los puntos pero permisos recortados no se da
        todos los permisos a sí mismo ni toca la cuenta de un admin con todo."""
        us = self.d.cargar_usuarios()
        x = dict(self.usuario("ana"), user="xavi", permisos=["resumen.ver", "usuarios.ver", "usuarios.editar"])
        self.d.guardar_usuarios(us + [x])
        todo = sorted(permisos.TODOS)
        r = self.post("/perfil", {"accion": "edit_user", "user": "xavi", "nombre": "", "correo": "", "role": "admin",
                                  "puntos_modo": "todos", "perm_grupos": ",".join(permisos.EDITABLES), "perm": todo},
                      "xavi")
        self.assertIn("Ese usuario no existe", r.texto)
        self.assertEqual(self.usuario("xavi")["permisos"], x["permisos"])
        hash_ana = self.usuario("ana")["hash"]
        r = self.post("/perfil", {"accion": "edit_user", "user": "ana", "nombre": "", "correo": "", "role": "admin",
                                  "npass": "clave-nueva-de-xavi"}, "xavi")
        self.assertIn("Ese usuario no existe", r.texto)
        self.assertEqual(self.usuario("ana")["hash"], hash_ana)

    def test_cambiar_rol_no_reparte_de_mas(self):
        """Verificador final, H2: cambiar el rol desde la tabla, delegado, da la plantilla del rol
        nuevo dentro de lo que tiene quien la cambia."""
        self.poner_permisos("olga", sorted(set(GESTOR) - {"puntos.vpn_regenerar"}))
        self.post("/perfil", {"accion": "rol_user", "user": "luis", "role": "operador"}, "olga")
        u = self.usuario("luis")
        self.assertEqual(u["role"], "operador")
        self.assertNotIn("puntos.vpn_regenerar", u.get("permisos", permisos.PLANTILLAS["operador"]))

    def test_a_un_par_no(self):
        """Verificador final, M1: a otro con su mismo rol y sus mismos permisos no lo ve ni lo toca
        (le cambiaría la clave)."""
        self.d.guardar_usuarios(self.d.cargar_usuarios() + [dict(self.usuario("olga"), user="olivia")])
        self.no_esta("data-user='olivia'", self.get("/ajustes", "olga").texto, "par")
        r = self.post("/perfil", {"accion": "edit_user", "user": "olivia", "nombre": "", "correo": "",
                                  "role": "operador", "npass": "clave-nueva-de-olga"}, "olga")
        self.assertIn("Ese usuario no existe", r.texto)

    def test_cada_accion_su_permiso(self):
        """Sin «Crear y editar», ni alta (403); sin «Borrar y desactivar», ni borrar (403); sin «Ver
        los usuarios», sin la lista."""
        self.poner_permisos("olga", sorted(set(GESTOR) - {"usuarios.editar"}))
        self.assertEqual(self.alta("nuevo4").status, 403)
        self.poner_permisos("olga", sorted(set(GESTOR) - {"usuarios.borrar"}))
        self.assertEqual(self.post("/perfil", {"accion": "del_user", "user": "luis"}, "olga").status, 403)
        self.assertIsNotNone(self.usuario("luis"))
        self.poner_permisos("olga", sorted(set(GESTOR) - {"usuarios.ver"}))
        self.no_esta("data-user='luis'", self.get("/ajustes", "olga").texto, "sin ver")


# --------------------------------------------------------------------------------------------
# Fase 6: Ajustes por permiso, botones finos en Cuarentena y salvaguarda de permisos
# --------------------------------------------------------------------------------------------
class AjustesPorPermiso(A.Base):
    poner_permisos = PuntosPorPermiso.poner_permisos

    def test_un_ajuste_suelto(self):
        """Capacidad nueva: un operador con todos los puntos y solo «Resolutores DNS» de Ajustes entra
        en DNS (su tarjeta y su POST) y no en Empresa, Exclusiones, Registro ni Actualizar (403)."""
        self.poner_permisos("pepe", sorted(permisos.PLANTILLAS["operador"] | {"ajustes.dns"}))
        self.d.guardar_resolutores = lambda texto: 1
        self.assertNotEqual(self.post("/dns", {"resolutores": "192.0.2.53"}, "pepe").status, 403)
        for ruta in ("/exclusiones", "/registro", "/bitacora", "/actualizacion.json"):
            with self.subTest(ruta=ruta):
                self.assertEqual(self.get(ruta, "pepe").status, 403)
        self.assertEqual(self.post("/empresa", {"nombre": "x"}, "pepe").status, 403)
        h = self.get("/ajustes", "pepe").texto
        self.esta("openm('dns')", h, "tarjeta DNS")
        self.no_esta("openm('empresa')", h, "tarjeta Empresa")

    def test_ajustes_son_globales(self):
        """Con lista de puntos, un permiso de Ajustes no vale aunque esté marcado (403)."""
        self.poner_permisos("olga", sorted(permisos.PLANTILLAS["operador"] | {"ajustes.dns", "ajustes.exclusiones"}))
        self.assertEqual(self.post("/dns", {"resolutores": "192.0.2.53"}, "olga").status, 403)
        self.assertEqual(self.get("/exclusiones", "olga").status, 403)

    def test_exclusiones_con_su_permiso(self):
        """Capacidad nueva: la pestaña y la página de Exclusiones salen con su permiso."""
        self.poner_permisos("pepe", sorted(permisos.PLANTILLAS["operador"] | {"ajustes.exclusiones"}))
        self.assertEqual(self.get("/exclusiones", "pepe").status, 200)
        self.esta(">Exclusiones</a>", self.get("/cuarentena", "pepe").texto, "pestaña")
        self.poner_permisos("pepe", sorted(permisos.PLANTILLAS["operador"]))
        self.no_esta(">Exclusiones</a>", self.get("/cuarentena", "pepe").texto, "sin pestaña")

    def test_botones_finos_en_cuarentena(self):
        """Capacidad nueva: la página de Cuarentena enseña cada bloque según su permiso: sin «Destinos
        de confianza», no sale el formulario de excluir destinos (el admin, sí)."""
        self.esta("Excluir y liberar", self.get("/cuarentena?nodo=p001", "ana").texto, "admin")
        self.poner_permisos("pepe", sorted(permisos.PLANTILLAS["operador"] - {"cuarentena.confianza"}))
        h = self.get("/cuarentena?nodo=p001", "pepe").texto
        self.no_esta("Excluir y liberar", h, "sin confianza")

    def test_siempre_queda_un_admin_con_todo(self):
        """Capacidad nueva: al único administrador con todos los puntos no se le pueden quitar
        permisos (no se guarda); con otro igual, sí."""
        form = {"accion": "edit_user", "user": "ana", "nombre": "", "correo": "", "role": "admin",
                "perm_grupos": "ajustes"}
        r = self.post("/perfil", form, "ana")
        self.assertIn("tiene que quedar al menos un administrador", r.texto)
        self.assertNotIn("permisos", self.usuario("ana"))
        self.d.guardar_usuarios(self.d.cargar_usuarios() + [dict(self.usuario("ana"), user="beto")])
        self.post("/perfil", form, "ana")
        self.assertNotIn("ajustes.dns", self.usuario("ana").get("permisos", permisos.TODOS))


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
        self.esta("name=perm_grupos value='resumen,cuarentena,reputacion,puntos,usuarios,ajustes'", h, "ajustes")
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


# --------------------------------------------------------------------------------------------
# Roles en su apartado (2026-10-23, opción 1): los permisos se editan por rol, no por usuario
# --------------------------------------------------------------------------------------------
class RolesEditables(A.Base):
    def guardar_rol(self, rol, perm, quien="ana"):
        return self.post("/perfil", {"accion": "rol_permisos", "role": rol, "perm": list(perm)}, quien)

    def test_la_ventana_del_usuario_no_trae_permisos(self):
        """Capacidad nueva: la ventana de editar usuario ya no lleva el acordeón (está en Roles); la
        tarjeta Roles lista los tres con su recuento y solo operador y lectura se editan."""
        h = self.get("/ajustes", "ana").texto
        i, j = h.index("id=ovlEdit"), h.index("id=ovlRol")
        self.assertNotIn("name=perm ", h[i:j] if i < j else h[i:])
        self.esta("Roles y permisos", h, "tile")
        self.esta("data-rol='operador'", h, "roles")
        self.esta("data-rol='lectura'", h, "roles")
        self.no_esta("data-rol='admin'", h, "roles")
        self.esta("name=accion value=rol_permisos", h, "roles")

    def test_cambiar_un_rol_cambia_a_sus_usuarios(self):
        """Capacidad nueva: quitar «Arrancar» al rol Operador se lo quita a todos sus operadores sin
        lista propia en su siguiente petición; volver a los de fábrica lo devuelve."""
        sin = sorted(permisos.PLANTILLAS["operador"] - {"puntos.arrancar"})
        r = self.guardar_rol("operador", sin)
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.assertEqual(self.post("/puntos/p001/arrancar", {}, "olga").status, 403)
        self.assertEqual(self.post("/puntos/p001/arrancar", {}, "pepe").status, 403)
        self.guardar_rol("operador", sorted(permisos.PLANTILLAS["operador"]))
        self.assertEqual(self.post("/puntos/p001/arrancar", {}, "olga").status, 303)

    def test_dar_a_lectura_un_permiso(self):
        """Capacidad nueva: marcar «Ver la ficha» en el rol Lectura deja entrar en Puntos a sus usuarios."""
        self.assertEqual(self.get("/puntos", "luis").status, 403)
        self.guardar_rol("lectura", sorted(permisos.PLANTILLAS["lectura"] | {"puntos.ver"}))
        self.assertEqual(self.get("/puntos", "luis").status, 200)

    def test_admin_no_se_edita_y_solo_el_admin_con_todo(self):
        """El rol administrador no se edita; los roles solo los cambia un administrador con todo (un
        admin limitado o un operador: 403) y nada cambia."""
        r = self.guardar_rol("admin", ["resumen.ver"])
        self.esta("no se edita", r.texto, "rol admin")
        self.assertEqual(self.post("/puntos/p001/arrancar", {}, "ana").status, 303)
        for quien in ("adela", "olga", "pepe"):
            with self.subTest(quien=quien):
                self.assertEqual(self.guardar_rol("lectura", sorted(permisos.TODOS), quien).status, 403)
        self.assertEqual(self.get("/puntos", "luis").status, 403)

    def test_quitar_permisos_propios(self):
        """Capacidad nueva: quien tiene permisos propios sale marcado en la tabla y «Usar los permisos
        de su rol» se los quita."""
        self.poner_permisos("olga", ["puntos.ver", "resumen.ver"])
        h = self.get("/ajustes", "ana").texto
        self.esta(">propios</span>", h, "tabla")
        self.esta("data-propios='1'", h, "tabla")
        self.post("/perfil", {"accion": "edit_user", "user": "olga", "nombre": "", "correo": "",
                              "role": "operador", "usar_rol": "1"}, "ana")
        self.assertNotIn("permisos", self.usuario("olga"))
        self.assertEqual(self.post("/puntos/p001/arrancar", {}, "olga").status, 303)

    def test_bajar_de_rol_quita_los_propios(self):
        """Auditoría H1: pasar a otro rol desde la ventana de editar quita los permisos propios (como el
        cambio de rol de la tabla): olga, operador con propios, pasa a lectura y ya no arranca."""
        self.poner_permisos("olga", sorted(permisos.PLANTILLAS["operador"]))
        self.post("/perfil", {"accion": "edit_user", "user": "olga", "nombre": "", "correo": "",
                              "role": "lectura"}, "ana")
        r = self.usuario("olga")
        self.assertEqual(r["role"], "lectura")
        self.assertNotIn("permisos", r)
        self.assertEqual(self.post("/puntos/p001/arrancar", {}, "olga").status, 403)

    def test_roles_json_ilegible_no_vuelve_a_fabrica(self):
        """Auditoría H3: un roles.json corrupto conserva los roles cargados (no vuelve en silencio a los
        de fábrica, que pueden ser más permisos)."""
        self.guardar_rol("operador", sorted(permisos.PLANTILLAS["operador"] - {"puntos.arrancar"}))
        self.assertEqual(self.post("/puntos/p001/arrancar", {}, "olga").status, 403)
        with open(self.d.ROLES_FILE, "w", encoding="utf-8") as f:
            f.write("{ roto")
        self.assertEqual(self.post("/puntos/p001/arrancar", {}, "olga").status, 403)

    poner_permisos = PuntosPorPermiso.poner_permisos


if __name__ == "__main__":
    unittest.main()
