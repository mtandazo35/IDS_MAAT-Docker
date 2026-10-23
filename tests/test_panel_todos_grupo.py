"""«Todos mis puntos» (bloque C, 2026-10-23): un usuario limitado con 2 o mas puntos tiene su vista
acumulada, que es el acumulado de SUS puntos en su propia carpeta (nodos/_g<12 hex>, nodos.grupo_id),
nunca el «Todos» real (nodos/_todos, que mezcla los puntos de todos).

Pruebas de COMPORTAMIENTO, sin red:
- Nucleo (nodos.py): grupo_id, poner_todos_grupo, grupo_actual, todos_visible y dir_salida(TODOS).
- Servidor HTTP real (montaje de test_panel_alcance: p001/p002/p003, p002 es el punto AJENO con
  marcas propias): dora (operador [p003, p001]) ve su acumulado (RES_GRUPO) y nunca RES_TODOS ni
  nada de p002; olga y luis (un punto) siguen sin «Todos»; sin el permiso resumen.todos, tampoco
  dora; ana y pepe siguen con el «Todos» real.
- Generador (html_report.py como subproceso, montaje de test_hrep_nodos): --grupo p001,p003
  escribe solo en la carpeta del grupo y sin nada de p002; un --grupo malo sale con error.
- Refrescador del panel: los grupos que nadie usa se borran; lo que no es un grupo, nunca.

Tipo: capacidad nueva (todas). Datos RFC 5737 / 10.x.
"""
import glob
import importlib
import json
import os
import sys
import threading
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
A = importlib.import_module("test_panel_alcance")
H = importlib.import_module("test_hrep_nodos")
if A._dash.LIB not in sys.path:
    sys.path.insert(0, A._dash.LIB)
permisos = importlib.import_module("permisos")

DORA = ["p001", "p003"]


# ============================================================================================
# Nucleo: nodos.py
# ============================================================================================
class NucleoGrupo(A.NucleoBase):
    def grupos_en_disco(self):
        if not os.path.isdir(self.n.NODOS):
            return []
        return sorted(x for x in os.listdir(self.n.NODOS) if x.startswith("_g"))

    def test_grupo_id_estable_e_independiente_del_orden(self):
        """Capacidad nueva: el id del grupo solo depende del conjunto de puntos (ni del orden ni de
        repetidos), casa con RE_GRUPO y dos conjuntos distintos dan carpetas distintas."""
        n = self.n
        g = n.grupo_id(["p001", "p003"])
        self.assertEqual(g, n.grupo_id(["p003", "p001"]))
        self.assertEqual(g, n.grupo_id(("p001", "p003", "p001")))
        self.assertEqual(g, n.grupo_id(["p001", "p003"]))          # estable entre llamadas
        self.assertRegex(g, n.RE_GRUPO)
        self.assertNotEqual(g, n.grupo_id(["p001", "p002"]))
        self.assertNotEqual(g, n.grupo_id(["p001", "p002", "p003"]))
        self.assertNotEqual(g, n.TODOS)

    def test_dos_puntos_en_modo_grupo_ven_su_acumulado(self):
        """Capacidad nueva: con alcance de 2 puntos y el modo grupo, «Todos» se puede mirar, abarca
        solo esos puntos y sus salidas van a la carpeta del grupo; nodos/_todos ni se crea."""
        n = self.n
        n.poner_alcance(["p003", "p001"])
        n.poner_todos_grupo(True)
        g = n.grupo_id(DORA)
        self.assertEqual(n.grupo_actual(), g)
        self.assertTrue(n.todos_visible())
        self.assertEqual(n.validar_nodo(n.TODOS), n.TODOS)
        self.assertEqual(n.nodos_de(n.TODOS), DORA)
        self.assertEqual(sorted({pid for pid, _f in n.ficheros_eventos(n.TODOS)}), DORA)
        self.assertEqual(n.dir_salida(n.TODOS), os.path.join(n.NODOS, g))
        self.assertTrue(os.path.isdir(os.path.join(n.NODOS, g)))
        self.assertEqual(n.salida("cuarentena.json", n.TODOS), os.path.join(n.NODOS, g, "cuarentena.json"))
        self.assertFalse(os.path.exists(os.path.join(n.NODOS, n.TODOS)))
        with n.contexto(n.TODOS):
            self.assertEqual(n.dir_salida(), os.path.join(n.NODOS, g))

    def test_un_solo_punto_no_tiene_grupo(self):
        """Capacidad nueva: con un solo punto (tambien si los demas de su lista no existen o se
        purgaron) no hay grupo: «Todos» no existe y no se crea ninguna carpeta."""
        n = self.n
        n.poner_todos_grupo(True)
        for lista in (["p001"], ["p001", "p009"], ["p001", "../p003", "p003\n"]):
            with self.subTest(lista=lista):
                n.poner_alcance(lista)
                self.assertIsNone(n.grupo_actual())
                self.assertFalse(n.todos_visible())
                for fn in (n.validar_nodo, n.dir_salida, n.nodos_de):
                    with self.assertRaises(n.NodoInexistente):
                        fn(n.TODOS)
        os.makedirs(n.ESTADO, exist_ok=True)
        with open(os.path.join(n.ESTADO, "bajas-purgadas.json"), "w", encoding="utf-8") as f:
            json.dump({"p003": {"cuando": 1}}, f)
        n.poner_alcance(DORA)
        self.assertIsNone(n.grupo_actual())
        self.assertFalse(n.todos_visible())
        with self.assertRaises(n.NodoInexistente):
            n.dir_salida(n.TODOS)
        self.assertEqual(self.grupos_en_disco(), [])
        self.assertFalse(os.path.exists(os.path.join(n.NODOS, n.TODOS)))

    def test_sin_modo_grupo_no_hay_todos(self):
        """Capacidad nueva: con 2 puntos pero sin el modo grupo (lo pone el panel en cada peticion)
        un limitado sigue sin «Todos»: nunca cae a nodos/_todos."""
        n = self.n
        n.poner_alcance(DORA)
        self.assertIsNone(n.grupo_actual())
        self.assertFalse(n.todos_visible())
        with self.assertRaises(n.NodoInexistente):
            n.dir_salida(n.TODOS)
        n.poner_todos_grupo(True)
        n.poner_todos_grupo(False)
        self.assertFalse(n.todos_visible())
        self.assertEqual(self.grupos_en_disco(), [])

    def test_sin_el_permiso_no_hay_todos(self):
        """Capacidad nueva: sin el permiso de la vista (poner_sin_todos), ni el grupo."""
        n = self.n
        n.poner_alcance(DORA)
        n.poner_todos_grupo(True)
        n.poner_sin_todos(True)
        self.assertFalse(n.todos_visible())
        for fn in (n.validar_nodo, n.dir_salida):
            with self.assertRaises(n.NodoInexistente):
                fn(n.TODOS)
        self.assertEqual(self.grupos_en_disco(), [])

    def test_sin_alcance_es_el_todos_de_siempre(self):
        """Conservacion: sin alcance (admin, usuario sin lista, hilo de fondo), el modo grupo no
        cambia nada: «Todos» es nodos/_todos con todos los puntos."""
        n = self.n
        n.poner_todos_grupo(True)
        self.assertIsNone(n.grupo_actual())
        self.assertTrue(n.todos_visible())
        self.assertEqual(n.nodos_de(n.TODOS), A.TODOS_LOS_PIDS)
        self.assertEqual(n.dir_salida(n.TODOS), os.path.join(n.NODOS, n.TODOS))
        self.assertEqual(self.grupos_en_disco(), [])

    def test_quitar_alcance_resetea_el_modo(self):
        """Capacidad nueva: quitar_alcance (fin de la peticion) quita tambien el modo grupo y el
        «sin todos»: la siguiente peticion de un limitado no hereda su «Todos»."""
        n = self.n
        n.poner_alcance(DORA)
        n.poner_todos_grupo(True)
        n.poner_sin_todos(True)
        n.quitar_alcance()
        self.assertTrue(n.todos_visible())                         # sin alcance ni «sin todos»
        n.poner_alcance(DORA)
        self.assertIsNone(n.grupo_actual())
        self.assertFalse(n.todos_visible())

    def test_un_hilo_no_hereda_el_modo(self):
        """Capacidad nueva: el modo grupo es del hilo: otro hilo con el mismo alcance y sin el modo
        no tiene «Todos»."""
        n = self.n
        n.poner_alcance(DORA)
        n.poner_todos_grupo(True)
        visto, errores = {}, []

        def otro():
            try:
                n.poner_alcance(DORA)
                visto["grupo"] = n.grupo_actual()
                visto["todos"] = n.todos_visible()
            except Exception as ex:             # noqa: BLE001 (se informa abajo)
                errores.append(repr(ex))
            finally:
                n.quitar_alcance()
        t = threading.Thread(target=otro)
        t.start()
        t.join(15)
        self.assertEqual(errores, [])
        self.assertEqual(visto, {"grupo": None, "todos": False})
        self.assertEqual(n.grupo_actual(), n.grupo_id(DORA))


# ============================================================================================
# Servidor HTTP real
# ============================================================================================
class TodosMisPuntos(A.Base):
    EXTRA = (A.IP_AJENA, A.IP_AJENA_CAND)

    def test_dora_abre_su_acumulado(self):
        """Capacidad nueva: dora sin ?nodo= y con ?nodo=_todos ve SU acumulado (RES_GRUPO), nunca el
        «Todos» real ni nada de p002; el selector trae «Todos mis puntos» elegido y sus dos puntos."""
        for ruta in ("/", "/?nodo=_todos"):
            with self.subTest(ruta=ruta):
                r = self.get(ruta, "dora")
                self.assertEqual(r.status, 200, A.plano(r.texto))
                self.esta(A.RES_GRUPO, r.texto, ruta)
                self.sin_ajenos(r.texto, ruta, extra=self.EXTRA)
                vals, elegida, sel = A.selector(r.texto)
                self.assertEqual(elegida, "_todos")
                self.assertEqual(sorted(vals or []), ["_todos", "p001", "p003"])
                self.esta("Todos mis puntos", sel, ruta)
                self.no_esta("Todos los nodos", sel, ruta)

    def test_paginas_del_acumulado_sin_ajenos(self):
        """Capacidad nueva: las paginas de su acumulado responden 200 con lo de SUS puntos y sin
        nada de p002 ni de nodos/_todos."""
        for ruta in ("/top", "/detalle", "/cuarentena", "/historico", "/eventos"):
            with self.subTest(ruta=ruta):
                r = self.get(ruta + "?nodo=_todos", "dora")
                self.assertEqual(r.status, 200, A.plano(r.texto))
                self.sin_ajenos(r.texto, ruta, extra=self.EXTRA)
        self.esta("TOP " + A.RES_GRUPO, self.get("/top?nodo=_todos", "dora").texto, "/top")
        t = self.get("/cuarentena?nodo=_todos", "dora").texto
        self.esta(A.IP_PROPIA_CAND, t, "/cuarentena")
        self.esta(A.IP_ESTE, t, "/cuarentena")
        t = self.get("/eventos?nodo=_todos", "dora").texto
        self.esta(A.IP_ESTE, t, "/eventos")

    def test_enviar_todos_de_su_acumulado_solo_a_sus_routers(self):
        """Capacidad nueva: «Enviar todos» en su acumulado va a los routers de SUS puntos y nada a
        p002."""
        self.d.destino_bloqueable = lambda ip, propias=None: (True, "")
        r = self.post("/cuarentena/enviar-todos", {"nodo": "_todos"}, "dora")
        self.assertNotEqual(r.status, 500, A.plano(r.texto))
        self.assertEqual(self.mk_a("p002"), [])
        self.assertEqual([x for x in self.p.mk if x[2] not in DORA], [])
        self.assertIn(("add", A.IP_PROPIA_CAND, "p001"), self.p.mk)
        self.assertNotIn("p002|" + A.IP_AJENA_CAND, self.d.cargar_enviados(self.d.MK_SENT))

    def test_un_solo_punto_sigue_sin_todos(self):
        """Conservacion: olga y luis (un punto) no tienen vista acumulada: ?nodo=_todos es 404 y no
        se les ofrece ninguna opcion «Todos»."""
        for quien in ("olga", "luis"):
            with self.subTest(quien=quien):
                r = self.get("/?nodo=_todos", quien)
                self.assertEqual(r.status, 404, A.plano(r.texto))
                self.sin_ajenos(r.texto, quien, extra=self.EXTRA + (A.RES_GRUPO,))
                r = self.get("/", quien)
                self.assertEqual(r.status, 200, A.plano(r.texto))
                vals, _elegida, sel = A.selector(r.texto)
                self.assertNotIn("_todos", vals or [])
                self.no_esta("Todos", sel, quien)
                self.no_esta(A.RES_GRUPO, r.texto, quien)

    def test_sin_el_permiso_dora_no_tiene_acumulado(self):
        """Capacidad nueva: dora sin «resumen.todos» en su lista de permisos: ?nodo=_todos es 404,
        sin datos de su grupo ni ajenos; abre su primer punto y el selector no ofrece «Todos»."""
        self.assertIn("resumen.todos", permisos.PLANTILLAS["operador"])
        us = self.d.cargar_usuarios()
        for r in us:
            if r["user"] == "dora":
                r["permisos"] = sorted(permisos.PLANTILLAS["operador"] - {"resumen.todos"})
        self.d.guardar_usuarios(us)
        r = self.get("/?nodo=_todos", "dora")
        self.assertEqual(r.status, 404, A.plano(r.texto))
        self.sin_ajenos(r.texto, "_todos", extra=self.EXTRA + (A.RES_GRUPO,))
        r = self.get("/", "dora")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.no_esta(A.RES_GRUPO, r.texto, "/")
        self.sin_ajenos(r.texto, "/", extra=self.EXTRA)
        vals, elegida, _sel = A.selector(r.texto)
        self.assertEqual(elegida, "p001")
        self.assertNotIn("_todos", vals or [])

    def test_admin_y_sin_lista_ven_el_todos_real(self):
        """Conservacion: ana (admin) y pepe (sin lista) siguen viendo el «Todos» real, con su
        etiqueta de siempre, y nunca la carpeta del grupo de dora."""
        for quien in ("ana", "pepe"):
            for ruta in ("/", "/?nodo=_todos"):
                with self.subTest(quien=quien, ruta=ruta):
                    r = self.get(ruta, quien)
                    self.assertEqual(r.status, 200, A.plano(r.texto))
                    self.esta(A.RES_TODOS, r.texto, ruta)
                    self.no_esta(A.RES_GRUPO, r.texto, ruta)
                    _vals, elegida, sel = A.selector(r.texto)
                    self.assertEqual(elegida, "_todos")
                    self.esta("Todos los nodos", sel, ruta)
                    self.no_esta("Todos mis puntos", sel, ruta)

    def test_una_lista_que_cambia_cambia_de_grupo(self):
        """Capacidad nueva: si el admin le cambia los puntos a dora, su «Todos» es la carpeta del
        nuevo conjunto (sin informe aun: nunca el del grupo viejo ni el real)."""
        self.poner_puntos("dora", ["p001", "p002", "p003"])
        nuevo = self.n.grupo_id(A.TODOS_LOS_PIDS)
        self.assertNotEqual(nuevo, self.grupo_dora)
        r = self.get("/?nodo=_todos", "dora")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.no_esta(A.RES_GRUPO, r.texto, "grupo viejo")
        self.no_esta(A.RES_TODOS, r.texto, "todos real")

    def test_ficha_ip_sola_no_lee_enviados_sin_punto(self):
        """Auditoría C (BAJO-1): en su acumulado, la ficha con la IP sola de un CPE que no está en sus
        puntos no enseña una entrada vieja del registro de enviados sin pid (que puede ser de otro)."""
        d = self.d
        env = d.cargar_enviados(d.MK_SENT)
        env["10.0.0.99"] = {"cuando": 1, "score": "80", "por": "ana", "lista": "clientes-botnet",
                            "motivo": {"tipo": "infeccion", "firma": "FIRMA-VIEJA-SIN-PID-KQ", "score": 80}}
        d.guardar_enviados(env, d.MK_SENT)
        r = self.get("/cuarentena/ficha?ip=10.0.0.99&nodo=_todos", "dora")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.no_esta("FIRMA-VIEJA-SIN-PID-KQ", r.texto, "ficha dora")
        self.no_esta("En cuarentena", r.texto, "ficha dora")


# ============================================================================================
# Generador: html_report.py --grupo
# ============================================================================================
FIRMA_AJENA = "ET MALWARE " + A.FIRMA_AJENA
NOMBRE_AJENO = "Nodo OMEGASUR-KQ"
SRC_AJENA = "10.0.0.88"
DST_AJENO = "198.51.100.201"


class GeneradorGrupo(H.Entorno):
    PUNTOS = {"p001": {"nombre": "Nodo A", "redes": ["10.0.0.0/24"]},
              "p002": {"nombre": NOMBRE_AJENO, "redes": ["10.0.0.0/24"]},
              "p003": {"nombre": "Nodo C", "redes": ["10.0.0.0/24"]}}
    MARCAS = (NOMBRE_AJENO, A.FIRMA_AJENA, SRC_AJENA, DST_AJENO)

    def setUp(self):
        super().setUp()
        os.makedirs(os.path.join(self.datos, "p003"), exist_ok=True)
        self.eventos("p001", "eve.json", [H.alerta("10.0.0.5", "192.0.2.10", hace_s=60 + i, flow_id=100 + i)
                                          for i in range(3)])
        self.eventos("p002", "eve.json", [H.alerta(SRC_AJENA, DST_AJENO, sig=FIRMA_AJENA, sid=2009901,
                                                   hace_s=60 + i, flow_id=200 + i) for i in range(3)])
        self.eventos("p003", "eve.json", [H.alerta("10.0.0.7", "192.0.2.12", hace_s=60 + i, flow_id=300 + i)
                                          for i in range(3)])

    @staticmethod
    def gid(pids_):
        return importlib.import_module("nodos").grupo_id(pids_)

    def carpetas(self):
        d = os.path.join(self.panel, "nodos")
        return sorted(os.listdir(d)) if os.path.isdir(d) else []

    def sin_marcas(self, texto, donde):
        for m in self.MARCAS:
            self.assertNotIn(m, texto, "%s: dato de p002 %r" % (donde, m))

    def test_grupo_escribe_solo_en_su_carpeta_y_sin_ajenos(self):
        """Capacidad nueva: --grupo p001,p003 escribe el acumulado de esos dos puntos en su carpeta
        (nodos/<grupo_id>), no toca nodos/_todos ni la de p002 y no lleva nada de p002."""
        g = self.gid(["p001", "p003"])
        self.ok("60", "--grupo", "p001,p003")
        self.assertEqual(self.carpetas(), [g])
        doc = self.html(g)
        self.sin_marcas(doc, "informe")
        self.assertIn("Todos mis puntos", doc)
        self.assertIn("10.0.0.5", doc)
        self.assertIn("10.0.0.7", doc)
        for f in glob.glob(os.path.join(self.panel, "nodos", g, "*")):
            if os.path.isfile(f):
                with open(f, encoding="utf-8", errors="replace") as fh:
                    self.sin_marcas(fh.read(), os.path.basename(f))
        cuar = self.salida(g, "cuarentena.json")
        self.assertTrue({c["router"] for c in cuar["candidatos"]} <= {"p001", "p003"}, cuar["candidatos"])
        self.assertFalse(os.path.exists(os.path.join(self.panel, "nodos", "_todos")))

    def test_orden_de_la_lista_no_cambia_la_carpeta(self):
        """Capacidad nueva: --grupo p003,p001 es la misma carpeta que p001,p003 (la que mira el
        panel con nodos.grupo_id), sin crear otra."""
        self.ok("60", "--grupo", "p003,p001")
        self.ok("60", "--grupo", "p001,p003")
        self.assertEqual(self.carpetas(), [self.gid(["p001", "p003"])])

    def test_grupo_malo_sale_con_error_sin_escribir(self):
        """Capacidad nueva: un pid mal formado, vacio o menos de 2 puntos distintos sale con 2; si
        de los pedidos existen menos de 2, con 3. En ningun caso se escribe nada (ni nodos/_todos)."""
        casos = (("p001,p0x", 2), ("p001,../p002", 2), ("p001,", 2), ("p001", 2), ("p001,p001", 2),
                 ("p001,p009", 3))
        for lista, codigo in casos:
            with self.subTest(lista=lista):
                r = self.generar("60", "--grupo", lista)
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertEqual(r.returncode, codigo, r.stderr)
                self.assertEqual(self.carpetas(), [])

    def test_grupo_excluye_nodo_y_todos(self):
        """Capacidad nueva: --grupo con --todos o con --nodo es un error (no se elige uno)."""
        for extra in (("--todos",), ("--nodo", "p001")):
            with self.subTest(extra=extra):
                r = self.generar("60", "--grupo", "p001,p003", *extra)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(self.carpetas(), [])


# ============================================================================================
# Refrescador: generacion y limpieza de los grupos (dashboard.py, Agente 2)
# ============================================================================================
class LimpiezaDeGrupos(A.Base):
    def funcion(self, nombre):
        fn = getattr(self.d, nombre, None)
        # (auditoria C) un renombrado debe fallar, no saltarse en silencio
        self.assertTrue(callable(fn), "falta dashboard.%s" % nombre)
        return fn

    def test_grupos_en_uso(self):
        """Capacidad nueva: grupos_en_uso() da {grupo_id: pids} de los limitados con 2 o mas puntos
        existentes y el permiso de la vista (dora); ni el de un limitado con un punto, ni el de una
        lista con puntos que no existen, ni nada para quien ve todo. Dos usuarios con los mismos
        puntos comparten grupo; sin resumen.todos no hay grupo."""
        fn = self.funcion("grupos_en_uso")
        self.assertEqual(fn(), {self.grupo_dora: ["p001", "p003"]})
        us = self.d.cargar_usuarios()
        clon = dict(next(r for r in us if r["user"] == "dora"), user="dorita", puntos=["p001", "p003"])
        self.d.guardar_usuarios(us + [clon])
        self.assertEqual(fn(), {self.grupo_dora: ["p001", "p003"]})
        us = self.d.cargar_usuarios()
        for r in us:
            if r["user"] in ("dora", "dorita"):
                r["permisos"] = sorted(permisos.PLANTILLAS["operador"] - {"resumen.todos"})
        self.d.guardar_usuarios(us)
        self.assertEqual(fn(), {})

    def test_limpiar_con_los_grupos_en_uso(self):
        """Capacidad nueva: limpiar_grupos(grupos_en_uso()) conserva el grupo de dora y borra el de
        un grupo que ya nadie usa (dora pasa a un solo punto)."""
        limpiar, en_uso = self.funcion("limpiar_grupos"), self.funcion("grupos_en_uso")
        base = self.n.NODOS
        limpiar(en_uso())
        self.assertTrue(os.path.isfile(os.path.join(base, self.grupo_dora, "report-20261022-000000.html")))
        self.poner_puntos("dora", ["p003"])
        limpiar(en_uso())
        self.assertFalse(os.path.exists(os.path.join(base, self.grupo_dora)))
        for c in (self.n.TODOS, "p001", "p002", "p003"):
            self.assertTrue(os.path.isdir(os.path.join(base, c)), c)

    def test_un_grupo_sin_uso_se_borra_y_lo_demas_nunca(self):
        """Capacidad nueva: la limpieza borra la carpeta de un grupo que nadie usa y conserva la del
        grupo de dora, la de cada punto, nodos/_todos y cualquier carpeta que no case con RE_GRUPO
        (aunque tampoco este en uso)."""
        fn = self.funcion("limpiar_grupos")
        base = self.n.NODOS
        huerfano = self.n.grupo_id(["p002", "p003"])          # nadie tiene exactamente esos dos
        no_grupos = ("_gZZZZZZZZZZZZ", "_g0123", "_g0123456789abc0", "_G0123456789ab", "_grupo-manual",
                     "otra-cosa")
        for c in (huerfano,) + no_grupos:
            os.makedirs(os.path.join(base, c), exist_ok=True)
            with open(os.path.join(base, c, "report-20261022-000000.html"), "w", encoding="utf-8") as f:
                f.write("x")
        fn({self.grupo_dora: ["p001", "p003"]})
        self.assertFalse(os.path.exists(os.path.join(base, huerfano)))
        for c in (self.grupo_dora, self.n.TODOS, "p001", "p002", "p003") + no_grupos:
            with self.subTest(carpeta=c):
                self.assertTrue(os.path.isdir(os.path.join(base, c)), c)
        self.assertTrue(os.path.isfile(os.path.join(base, self.grupo_dora, "report-20261022-000000.html")))


if __name__ == "__main__":
    unittest.main()
