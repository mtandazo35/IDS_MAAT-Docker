"""Multi-usuario por punto (decision del dueño, 2026-10-22): el admin asigna a cada usuario los
puntos que ve; cada usuario ve SOLO los suyos, como un panel independiente, y el admin lo ve todo.

Pruebas de COMPORTAMIENTO, sin red:
- Nucleo (nodos.py): con alcance, un punto ajeno no existe por ninguna via (listas, rutas de datos
  y de salidas, la vista «Todos»); el alcance es de cada hilo y un hilo sin alcance (los de fondo)
  lo ve todo.
- Sesion (dashboard.py): puntos_de_usuario / sesion_de, releidos en cada peticion; la baja de un
  punto lo quita de las listas de los usuarios sin ampliar a nadie.
- Servidor HTTP real (fixtures/panel2/_dash_p.py) con tres puntos que comparten la red
  10.0.0.0/24: p001 «kappanorte», p002 «omegasur» y p003 «sigmaeste». p002 es el punto AJENO: sus
  datos llevan marcas propias (nombre, firma, evidencia, abonado, destino, resumen, publica) que un
  usuario limitado no puede ver en ninguna respuesta. Routers, espejo y orquestador son falsos y
  apuntan lo que se les pide: «no se toco el router» se comprueba con su registro, y cada rechazo
  tiene su control (el admin, con el mismo formulario, si llega).

Usuarios: ana admin; adela admin con lista (se ignora); olga operador [p001]; dora operador
[p003, p001]; pepe operador sin lista (todos); luis lectura [p001]; vera operador [] (ninguno);
tito operador con lista mal formada; fede operador [p009] (no existe).

Tipo: capacidad nueva (todas). Datos RFC 5737 / 10.x.
"""
import html
import http.client
import importlib
import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import uuid

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, "fixtures", "panel2"))
import _dash  # noqa: E402
from _dash_p import PanelP  # noqa: E402

NOMBRES = {"p001": "kappanorte", "p002": "omegasur", "p003": "sigmaeste"}
TODOS_LOS_PIDS = sorted(NOMBRES)
AJENO = NOMBRES["p002"]
FIRMA_AJENA = "FIRMA-SOLO-AJENA-KQ"
EVID_AJENA = "EVIDENCIA-AJENA-KQ"
ABON_AJENO = "ABONADO-AJENO-KQ"
RES_AJENO = "RESUMEN-AJENO-KQ"
RES_TODOS = "RESUMEN-TODOS-KQ"
RES_PROPIO = "RESUMEN-PROPIO-KQ"
RES_ESTE = "RESUMEN-ESTE-KQ"
RES_GRUPO = "RESUMEN-GRUPO-KQ"   # (bloque C 2026-10-23) «Todos mis puntos» de dora: nodos/<grupo_id(p001,p003)>
DST_AJENO = "198.51.100.201"     # destino que solo aparece en los eventos de p002
PUB_AJENA = "192.0.2.201"        # publica declarada de p002
IP_PROPIA = "10.0.0.5"           # p001, ya en cuarentena
IP_PROPIA_CAND = "10.0.0.6"      # p001, candidata sin enviar
IP_ESTE = "10.0.0.7"             # p003, candidata sin enviar
IP_AJENA = "10.0.0.88"           # p002, enviada (cuarentena, graduada y DNS)
IP_AJENA_CAND = "10.0.0.90"      # p002, candidata sin enviar
MARCAS_AJENAS = (AJENO, FIRMA_AJENA, EVID_AJENA, ABON_AJENO, RES_AJENO, RES_TODOS, DST_AJENO, PUB_AJENA)
LIMITADOS = ("olga", "luis", "dora")


def plano(texto, n=260):
    """El texto visible de una respuesta, corto (para los mensajes de fallo)."""
    t = re.sub(r"<script.*?</script>|<style.*?</style>", " ", texto or "", flags=re.S)
    t = html.unescape(re.sub(r"<[^>]+>", " ", t))
    return " ".join(t.split())[:n]


def selector(texto):
    """(valores de las opciones, opcion elegida, html interior) del selector de nodo, o
    (None, None, "") si la pagina no lo trae."""
    m = re.search(r"<select[^>]*\bname=['\"]?nodo\b[^>]*>(.*?)</select>", texto, re.S)
    if not m:
        return None, None, ""
    sel = m.group(1)
    vals = re.findall(r"<option[^>]*\bvalue=['\"]?([^'\" >]*)", sel)
    elegida = re.findall(r"<option[^>]*\bvalue=['\"]?([^'\" >]*)['\"]?[^>]*\bselected", sel)
    return vals, (elegida[0] if elegida else None), sel


# ============================================================================================
# Nucleo: nodos.py
# ============================================================================================
def cargar_nodos(raiz):
    os.environ.update({"IDS_PANEL_DIR": os.path.join(raiz, "panel"),
                       "IDS_DATOS": os.path.join(raiz, "datos"),
                       "IDS_RUN": os.path.join(raiz, "run")})
    if _dash.LIB not in sys.path:
        sys.path.insert(0, _dash.LIB)
    return importlib.reload(importlib.import_module("nodos"))


class NucleoBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        r = self.tmp.name
        for d in ("run", "panel", "datos/p001", "datos/p002", "datos/p003"):
            os.makedirs(os.path.join(r, d))
        with open(os.path.join(r, "run", "estado.json"), "w", encoding="utf-8") as f:
            json.dump({"puntos": {pid: {"nombre": nom, "redes": ["10.0.0.0/24"]}
                                  for pid, nom in NOMBRES.items()}}, f)
        for pid in NOMBRES:
            with open(os.path.join(r, "datos", pid, "eve.json"), "w", encoding="utf-8") as f:
                f.write(_dash.alerta() + "\n")
        self.n = cargar_nodos(r)
        self.n.quitar_nodo()
        self.n.quitar_alcance()

    def tearDown(self):
        self.n.quitar_nodo()
        self.n.quitar_alcance()
        _dash.restaurar()
        self.tmp.cleanup()


class NucleoAlcance(NucleoBase):
    def test_sin_alcance_lo_ve_todo(self):
        """Capacidad nueva (conservacion): sin alcance (admin, usuario sin lista, fondo) se ve todo,
        incluida la vista «Todos», como antes."""
        n = self.n
        self.assertIsNone(n.alcance())
        self.assertFalse(n.limitado())
        self.assertEqual(n.pids(), TODOS_LOS_PIDS)
        self.assertTrue(all(n.puede_ver(p) for p in NOMBRES))
        self.assertEqual(n.validar_nodo(n.TODOS), n.TODOS)
        self.assertEqual(n.nodos_de(n.TODOS), TODOS_LOS_PIDS)
        self.assertTrue(os.path.isdir(n.dir_salida(n.TODOS)))
        self.assertIsNone(n.poner_alcance(None))
        self.assertFalse(n.limitado())

    def test_un_punto_ajeno_no_existe(self):
        """Capacidad nueva: con alcance [p003, p001], p002 no sale en ninguna lista, no existe para
        validar ni para mirar (NodoInexistente = 404) y ni siquiera se averigua su nombre."""
        n = self.n
        self.assertEqual(n.poner_alcance(["p003", "p001"]), frozenset({"p001", "p003"}))
        self.assertTrue(n.limitado())
        self.assertEqual(n.pids(), ["p001", "p003"])
        self.assertEqual([p["nombre"] for p in n.puntos()], [NOMBRES["p001"], NOMBRES["p003"]])
        self.assertFalse(n.existe("p002"))
        self.assertFalse(n.puede_ver("p002"))
        self.assertIsNone(n.punto("p002"))
        self.assertEqual(n.nombre("p002"), "p002")
        for fn in (n.exigir_pid, n.validar_nodo, n.poner_nodo, n.nodos_de):
            with self.subTest(fn=fn.__name__):
                with self.assertRaises(n.NodoInexistente):
                    fn("p002")
        self.assertFalse(n.hay_nodo())
        with self.assertRaises(n.NodoInexistente):
            with n.contexto("p002"):
                pass
        self.assertEqual(n.poner_nodo("p003"), "p003")
        self.assertEqual(n.nodos_de(), ["p003"])

    def test_la_vista_todos_no_se_puede_pedir(self):
        """Capacidad nueva: un limitado no mira «Todos» (sus ficheros mezclan los puntos de todos):
        ni validarla, ni ponerla, ni sus eventos, ni sus salidas; y no se crea nodos/_todos."""
        n = self.n
        n.poner_alcance(["p001"])
        for fn in (n.validar_nodo, n.poner_nodo, n.nodos_de, n.dir_salida, n.ficheros_eventos):
            with self.subTest(fn=fn.__name__):
                with self.assertRaises(n.NodoInexistente):
                    fn(n.TODOS)
        with self.assertRaises(n.NodoInexistente):
            n.salida("cuarentena.json", n.TODOS)
        with self.assertRaises(n.NodoInexistente):
            with n.contexto(n.TODOS):
                pass
        self.assertFalse(n.hay_nodo())
        self.assertFalse(os.path.exists(os.path.join(n.NODOS, n.TODOS)))

    def test_rutas_de_datos_de_un_punto_ajeno(self):
        """Capacidad nueva: ninguna ruta lleva a los datos de un punto ajeno (eventos, eve vivo,
        tzsp, salidas, relés de la API) y su carpeta de salidas no se crea; las del suyo, si."""
        n = self.n
        n.poner_alcance(["p001"])
        for fn in (n.dir_eventos, n.eve_vivo, n.tzsp_json, n.dir_salida, n.api_sock, n.api_sock_claro,
                   n.ficheros_eventos):
            with self.subTest(fn=fn.__name__):
                with self.assertRaises(n.NodoInexistente):
                    fn("p002")
        with self.assertRaises(n.NodoInexistente):
            n.salida("cuarentena.json", "p002")
        self.assertFalse(os.path.exists(os.path.join(n.NODOS, "p002")))
        self.assertEqual(n.ficheros_eventos("p001"), [("p001", os.path.join(n.DATOS, "p001", "eve.json"))])
        self.assertEqual(n.eve_vivo("p001"), os.path.join(n.DATOS, "p001", "eve.json"))
        self.assertTrue(os.path.isdir(n.dir_salida("p001")))

    def test_mal_formado_sigue_siendo_invalido(self):
        """Conservacion: con alcance, un id mal formado sigue siendo NodoInvalido (400), no 404."""
        n = self.n
        n.poner_alcance(["p001"])
        for malo in ("p0x", "../p002", "p002\n", ""):
            with self.subTest(malo=malo):
                with self.assertRaises(n.NodoInvalido):
                    n.validar_nodo(malo)
                with self.assertRaises(n.NodoInvalido):
                    n.dir_eventos(malo)

    def test_lista_vacia_o_con_basura_nunca_amplia(self):
        """Capacidad nueva: una lista vacia no ve NINGUN punto (nunca «todos»); de una lista con
        basura solo quedan los pids bien formados, y uno que no existe no aparece."""
        n = self.n
        self.assertEqual(n.poner_alcance([]), frozenset())
        self.assertTrue(n.limitado())
        self.assertEqual(n.pids(), [])
        self.assertEqual(n.puntos(), [])
        for pid in NOMBRES:
            self.assertFalse(n.puede_ver(pid))
            with self.assertRaises(n.NodoInexistente):
                n.dir_eventos(pid)
        with self.assertRaises(n.NodoInexistente):
            n.validar_nodo(n.TODOS)
        self.assertEqual(n.poner_alcance(["../p002", "p002\n", 5, None, "P002", "p001"]), frozenset({"p001"}))
        self.assertEqual(n.pids(), ["p001"])
        n.poner_alcance(["p009", "p001"])
        self.assertEqual(n.pids(), ["p001"])
        with self.assertRaises(n.NodoInexistente):
            n.exigir_pid("p009")

    def test_quitar_alcance_vuelve_a_todo(self):
        """Capacidad nueva: quitar_alcance (fin de la peticion) deja el hilo sin limite."""
        n = self.n
        n.poner_alcance(["p001"])
        n.quitar_alcance()
        self.assertIsNone(n.alcance())
        self.assertEqual(n.pids(), TODOS_LOS_PIDS)
        self.assertEqual(n.validar_nodo(n.TODOS), n.TODOS)

    def test_sin_alcance_y_pids_todos_para_escribir(self):
        """Capacidad nueva: sin_alcance() quita el limite solo durante el bloque (tambien si el bloque
        falla) y pids_todos() da todos los puntos aunque la peticion este limitada: es lo que usa
        quien ESCRIBE datos de todos los puntos para no podar los ajenos."""
        n = self.n
        n.poner_alcance(["p001"])
        self.assertEqual(n.pids_todos(), TODOS_LOS_PIDS)
        self.assertEqual(n.pids(), ["p001"])
        with n.sin_alcance():
            self.assertIsNone(n.alcance())
            self.assertEqual(n.pids(), TODOS_LOS_PIDS)
        self.assertEqual(n.alcance(), frozenset({"p001"}))
        with self.assertRaises(KeyError):
            with n.sin_alcance():
                raise KeyError("fallo dentro del bloque")
        self.assertEqual(n.pids(), ["p001"])
        n.poner_alcance([])
        self.assertEqual(n.pids_todos(), TODOS_LOS_PIDS)
        self.assertEqual(n.pids(), [])

    def test_un_punto_purgado_no_vuelve_por_el_alcance(self):
        """Conservacion: un punto ya purgado no reaparece porque siga en la lista de un usuario."""
        n = self.n
        os.makedirs(n.ESTADO, exist_ok=True)
        with open(os.path.join(n.ESTADO, "bajas-purgadas.json"), "w", encoding="utf-8") as f:
            json.dump({"p001": {"cuando": 1}}, f)
        n.poner_alcance(["p001", "p003"])
        self.assertEqual(n.pids(), ["p003"])
        n.poner_alcance(["p001"])
        self.assertEqual(n.pids(), [])


class NucleoHilos(NucleoBase):
    def test_dos_peticiones_a_la_vez_no_se_mezclan(self):
        """Capacidad nueva: el alcance es del hilo: dos peticiones simultaneas de usuarios distintos
        ven cada una lo suyo, y el hilo que no puso alcance lo sigue viendo todo."""
        n = self.n
        barrera = threading.Barrier(2, timeout=10)
        visto, errores = {}, []

        def peticion(nombre, alcance_):
            try:
                n.poner_alcance(alcance_)
                n.poner_nodo(alcance_[0])
                barrera.wait()                  # los dos con su alcance puesto a la vez
                visto[nombre] = (n.pids(), n.nodo_actual(), n.puede_ver("p002"))
                barrera.wait()
            except Exception as ex:             # noqa: BLE001 (se informa abajo)
                errores.append(repr(ex))
                barrera.abort()
            finally:
                n.quitar_alcance()
                n.quitar_nodo()
        hs = [threading.Thread(target=peticion, args=("a", ["p001"])),
              threading.Thread(target=peticion, args=("b", ["p002", "p003"]))]
        for h in hs:
            h.start()
        for h in hs:
            h.join(15)
        self.assertEqual(errores, [])
        self.assertEqual(visto["a"], (["p001"], "p001", False))
        self.assertEqual(visto["b"], (["p002", "p003"], "p002", True))
        self.assertIsNone(n.alcance())
        self.assertEqual(n.pids(), TODOS_LOS_PIDS)

    def test_un_hilo_de_fondo_no_hereda_el_alcance(self):
        """Capacidad nueva: un hilo lanzado desde una peticion limitada (como los de fondo) no tiene
        alcance: ve todos los puntos y «Todos»; la peticion sigue limitada."""
        n = self.n
        n.poner_alcance(["p001"])
        visto, errores = {}, []

        def fondo():
            try:
                visto["alcance"] = n.alcance()
                visto["pids"] = n.pids()
                with n.contexto(n.TODOS):
                    visto["todos"] = n.nodos_de()
                visto["dir"] = n.dir_salida("p002")
                visto["eve"] = n.eve_vivo("p002")
            except Exception as ex:             # noqa: BLE001 (se informa abajo)
                errores.append(repr(ex))
        t = threading.Thread(target=fondo)
        t.start()
        t.join(15)
        self.assertEqual(errores, [])
        self.assertIsNone(visto["alcance"])
        self.assertEqual(visto["pids"], TODOS_LOS_PIDS)
        self.assertEqual(visto["todos"], TODOS_LOS_PIDS)
        self.assertTrue(os.path.isdir(visto["dir"]))
        self.assertEqual(visto["eve"], os.path.join(n.DATOS, "p002", "eve.json"))
        self.assertEqual(n.pids(), ["p001"])
        with self.assertRaises(n.NodoInexistente):
            n.dir_salida("p002")


# ============================================================================================
# Sesion y usuarios (dashboard.py, sin servidor)
# ============================================================================================
class DashBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = _dash.Arbol(self.tmp.name)
        self.d = _dash.cargar(self.a)
        self.d.nodos.asegurar_dirs()

    def tearDown(self):
        self.d.nodos.quitar_nodo()
        self.d.nodos.quitar_alcance()
        _dash.restaurar()
        self.tmp.cleanup()

    @staticmethod
    def u(nombre, rol, **extra):
        r = {"user": nombre, "salt": "00", "hash": "h-" + nombre, "role": rol, "activo": True}
        r.update(extra)
        return r

    def usuarios(self):
        return {r["user"]: r for r in self.d.cargar_usuarios()}


class SesionYPuntos(DashBase):
    def test_puntos_de_usuario(self):
        """Capacidad nueva: None = todos (sin la clave `puntos`, tambien el admin); una lista = esos
        pids bien formados (desde la fase 1 de permisos, tambien para el admin); vacia o mal formada
        (no lista) = ninguno, nunca todos."""
        f = self.d.puntos_de_usuario
        casos = [
            (None, None),
            (self.u("a", "admin"), None),
            (self.u("a", "admin", puntos=["p001"]), ["p001"]),
            (self.u("a", "admin", puntos=[]), []),
            (self.u("o", "operador"), None),
            (self.u("l", "lectura"), None),
            (self.u("o", "operador", puntos=["p002", "p001"]), ["p001", "p002"]),
            (self.u("o", "operador", puntos=[]), []),
            (self.u("l", "lectura", puntos="p001"), []),
            (self.u("l", "lectura", puntos={"p001": True}), []),
            (self.u("o", "operador", puntos=["p001", "../p002", 5, "p002\n", "P002"]), ["p001"]),
        ]
        for r, esperado in casos:
            with self.subTest(r=r):
                res = f(r)
                self.assertEqual(None if res is None else sorted(res), esperado)

    def test_sesion_trae_los_puntos_y_se_relee(self):
        """Capacidad nueva: sesion_de devuelve los puntos del usuario releidos en cada peticion: un
        cambio del admin vale en la siguiente, sin volver a entrar (el admin con lista, desde la
        fase 1 de permisos, tambien se limita)."""
        d = self.d
        d.guardar_usuarios([self.u("ana", "admin", puntos=["p001"]), self.u("olga", "operador", puntos=["p001"]),
                            self.u("pepe", "operador")])
        t = {n: d.sesion_abrir(n, r) for n, r in (("ana", "admin"), ("olga", "operador"), ("pepe", "operador"))}
        self.assertEqual(d.sesion_de(t["ana"])["puntos"], ["p001"])
        self.assertEqual(d.sesion_de(t["olga"])["puntos"], ["p001"])
        self.assertIsNone(d.sesion_de(t["pepe"])["puntos"])
        us = d.cargar_usuarios()
        us[1]["puntos"] = ["p001", "p002"]
        us[2]["puntos"] = []
        d.guardar_usuarios(us)
        self.assertEqual(sorted(d.sesion_de(t["olga"])["puntos"]), ["p001", "p002"])
        self.assertEqual(d.sesion_de(t["pepe"])["puntos"], [])


class BajaDelPunto(DashBase):
    def poblar(self):
        self.d.guardar_usuarios([self.u("ana", "admin"), self.u("a", "operador", puntos=["p001", "p002"]),
                                 self.u("b", "lectura", puntos=["p002"]), self.u("c", "operador"),
                                 self.u("e", "operador", puntos=["p001"])])

    def comprobar(self):
        us = self.usuarios()
        self.assertEqual(us["a"]["puntos"], ["p001"])
        self.assertIn("puntos", us["b"])               # se queda sin ninguno: NO pasa a verlos todos
        self.assertEqual(us["b"]["puntos"], [])
        self.assertEqual(self.d.puntos_de_usuario(us["b"]), [])
        self.assertNotIn("puntos", us["c"])
        self.assertNotIn("puntos", us["ana"])
        self.assertEqual(us["e"]["puntos"], ["p001"])

    def test_quitar_punto_de_usuarios(self):
        """Capacidad nueva: quitar_punto_de_usuarios(pid) lo quita de cada lista y dice cuantos
        usuarios cambio; quien se queda sin puntos no ve ninguno. Repetirlo no cambia nada."""
        d = self.d
        self.assertTrue(hasattr(d, "quitar_punto_de_usuarios"),
                        "contrato pendiente: falta dashboard.quitar_punto_de_usuarios")
        self.poblar()
        self.assertEqual(d.quitar_punto_de_usuarios("p002"), 2)
        self.comprobar()
        self.assertEqual(d.quitar_punto_de_usuarios("p002"), 0)

    def test_purgar_un_punto_lo_quita_de_los_usuarios(self):
        """Capacidad nueva: la baja de un punto (purgar_punto) lo quita de las listas: un pid no se
        reutiliza, pero una lista no debe arrastrar puntos muertos."""
        self.poblar()
        self.d.purgar_punto("p002", "ana")
        self.comprobar()


class RoutersSinPoda(DashBase):
    """routers.json lleva la conexion (y la clave cifrada) del router de CADA punto."""

    def setUp(self):
        super().setUp()
        self.d.guardar_routers([{"id": "p001", "USER": "u-p001", "PASS": "clave-p001", "ENABLED": "1"},
                                {"id": "p002", "USER": "u-p002", "PASS": "clave-p002", "ENABLED": "1"}])

    def routers(self):
        with self.d.nodos.sin_alcance():
            return {r["id"]: r for r in self.d.cargar_routers()}

    def test_guardar_con_alcance_no_borra_los_routers_ajenos(self):
        """Correccion de defecto (2026-10-22, critico): guardar_routers podaba routers.json con
        nodos.pids(); desde la peticion de un limitado borraba la API (clave incluida) de los puntos
        que no ve y el mapa del generador se quedaba solo con los suyos. Ahora conserva todo, no
        escribe un punto ajeno aunque venga en la lista y devuelve solo lo que ve quien guarda."""
        d, n = self.d, self.d.nodos
        n.poner_alcance(["p001"])
        vuelta = d.guardar_routers([{"id": "p001", "USER": "u-nueva", "PASS": "clave-nueva-1", "ENABLED": "1"},
                                    {"id": "p002", "USER": "intruso", "PASS": "clave-intrusa", "ENABLED": "0"}])
        self.assertEqual([r["id"] for r in vuelta], ["p001"])
        n.quitar_alcance()
        rs = self.routers()
        self.assertEqual((rs["p001"]["USER"], rs["p001"]["PASS"]), ("u-nueva", "clave-nueva-1"))
        self.assertEqual((rs["p002"]["USER"], rs["p002"]["PASS"], rs["p002"]["ENABLED"]),
                         ("u-p002", "clave-p002", "1"))
        self.assertEqual(sorted(d._routers_guardados()), ["p001", "p002"])
        with open(d.ROUTERS_MAP, encoding="utf-8") as f:
            self.assertEqual(sorted(x["id"] for x in json.load(f)), ["p001", "p002"])

    def test_lista_vacia_tampoco_poda(self):
        """Correccion de defecto (misma causa): un usuario sin puntos que llegara a guardar no deja
        routers.json vacio."""
        d, n = self.d, self.d.nodos
        n.poner_alcance([])
        self.assertEqual(d.guardar_routers([]), [])
        n.quitar_alcance()
        self.assertEqual(sorted(d._routers_guardados()), ["p001", "p002"])
        self.assertEqual(self.routers()["p002"]["PASS"], "clave-p002")


# ============================================================================================
# Servidor HTTP real
# ============================================================================================
class Base(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.d, self.n = self.p.d, self.p.nodos
        self.raiz = self.p.tmp.name
        self.d.mk_lista_en_uso = lambda *a, **k: True
        self._cookies = {}
        self._estado()
        self._datos()
        self._usuarios()

    # ---- arbol --------------------------------------------------------------------------
    def _estado(self):
        """p001/p002 de _dash_p renombrados y un p003, los tres con la misma red."""
        ruta = os.path.join(self.raiz, "run", "estado.json")
        with open(ruta, encoding="utf-8") as f:
            est = json.load(f)
        pts = est["puntos"]
        p3 = json.loads(json.dumps(pts["p001"]))
        p3.update({"n": 3, "sensor": "100.64.3.1", "mk": "100.64.3.2"})
        pts["p003"] = p3
        for pid, nom in NOMBRES.items():
            pts[pid]["nombre"] = nom
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(est, f)
        t = time.time() + 5                     # leer_estado cachea por (mtime, tamano)
        os.utime(ruta, (t, t))
        for d in ("datos/p003", "run/p003"):
            os.makedirs(os.path.join(self.raiz, d), exist_ok=True)

    def _datos(self):
        d, p = self.d, self.p
        self.lineas_ajenas = [
            _dash.alerta(src=IP_AJENA, dst=DST_AJENO, firma="ET MALWARE " + FIRMA_AJENA, sid=2009901, hace=40),
            _dash.alerta(src=IP_AJENA_CAND, dst=DST_AJENO, firma="ET MALWARE " + FIRMA_AJENA, sid=2009901, hace=20)]
        eves = {"p001": [_dash.alerta(src=IP_PROPIA, hace=40), _dash.alerta(src=IP_PROPIA_CAND, hace=20)],
                "p002": self.lineas_ajenas,
                "p003": [_dash.alerta(src=IP_ESTE, hace=30)]}
        for pid, lineas in eves.items():
            with open(os.path.join(self.raiz, "datos", pid, "eve.json"), "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(lineas) + "\n")

        def cand(ip, pid, firma, evid):
            c = PanelP.candidato(ip, pid)
            c.update(firma="ET MALWARE " + firma, evidencias=[evid])
            return c
        propios = [cand(IP_PROPIA, "p001", "FIRMA-PROPIA-KQ", "EVIDENCIA-PROPIA-KQ"),
                   cand(IP_PROPIA_CAND, "p001", "FIRMA-PROPIA-KQ", "EVIDENCIA-PROPIA-KQ")]
        ajenos = [cand(IP_AJENA, "p002", FIRMA_AJENA, EVID_AJENA), cand(IP_AJENA_CAND, "p002", FIRMA_AJENA, EVID_AJENA)]
        este = [cand(IP_ESTE, "p003", "FIRMA-ESTE-KQ", "EVIDENCIA-ESTE-KQ")]
        p.cuarentena("p001", propios)
        p.cuarentena("p002", ajenos)
        p.cuarentena("p003", este)
        p.cuarentena(self.n.TODOS, propios + ajenos + este)
        # (bloque C 2026-10-23) el acumulado de los puntos de dora (p001+p003), como lo deja el
        # generador con --grupo: solo lo de sus puntos, en su propia carpeta
        self.grupo_dora = self.n.grupo_id(["p001", "p003"])
        p.cuarentena(self.grupo_dora, propios + este)
        ahora = int(time.time())

        def env(pid, lista, firma):
            return {"cuando": ahora - 600, "score": "80", "por": "ana", "router": pid, "lista": lista,
                    "motivo": {"tipo": "infeccion", "firma": firma, "score": 80, "banda": "ALTO"}}
        d.guardar_enviados({"p001|" + IP_PROPIA: env("p001", "clientes-botnet", "FIRMA-PROPIA-KQ"),
                            "p002|" + IP_AJENA: env("p002", "clientes-botnet", FIRMA_AJENA)}, d.MK_SENT)
        d.guardar_enviados({"p002|" + IP_AJENA: env("p002", "suricata-graduada", FIRMA_AJENA)}, d.MK_SENT_GRAD)
        d.guardar_enviados({"p002|" + IP_AJENA: env("p002", "suricata-dns-sospechoso", FIRMA_AJENA)}, d.MK_SENT_DNS)
        mapa = {"p001|" + IP_PROPIA: {"nombre": "ABONADO-PROPIO-KQ", "mac": "02:00:00:00:00:01", "tipo": "PPPoE",
                                      "router": "p001"},
                "p002|" + IP_AJENA: {"nombre": ABON_AJENO, "mac": "02:00:00:00:00:02", "tipo": "PPPoE",
                                     "router": "p002"}}
        with open(d.ABONADOS_FILE, "w", encoding="utf-8") as f:
            json.dump({"ts": ahora, "mapa": mapa}, f)
        with open(d.ABON_HIST_FILE, "w", encoding="utf-8") as f:
            for k, v in mapa.items():
                f.write(json.dumps({"ts": ahora - 3600, "ip": k, "nombre": v["nombre"], "mac": v["mac"],
                                    "tipo": "PPPoE"}) + "\n")
        d.guardar_publicas({"p001": ["192.0.2.101"], "p002": [PUB_AJENA]})
        d.mk_log("ENVIADO", IP_AJENA, "ana", "lista=clientes-botnet nodo=p002")
        for nodo, marca in (("p001", RES_PROPIO), ("p002", RES_AJENO + " " + FIRMA_AJENA), ("p003", RES_ESTE),
                            (self.n.TODOS, RES_TODOS + " " + FIRMA_AJENA), (self.grupo_dora, RES_GRUPO)):
            dd = os.path.join(self.raiz, "panel", "nodos", nodo)
            os.makedirs(dd, exist_ok=True)
            with open(os.path.join(dd, "report-20261022-000000.html"), "w", encoding="utf-8") as f:
                f.write("<!doctype html><html><head><style>.rq{color:#000}</style></head><body><main>"
                        "<section class=card><p>%s</p></section><!--TOP_INI--><section class=card><p>TOP %s</p>"
                        "</section><!--TOP_FIN--></main></body></html>" % (marca, marca))

    def _usuarios(self):
        us = self.d.cargar_usuarios()
        clave = {"salt": us[0]["salt"], "hash": us[0]["hash"]}   # la de _dash_p

        def u(nombre, rol, **extra):
            r = dict(clave, user=nombre, role=rol, activo=True)
            r.update(extra)
            return r
        self.d.guardar_usuarios([
            u("ana", "admin"), u("adela", "admin", puntos=["p001"]), u("olga", "operador", puntos=["p001"]),
            u("dora", "operador", puntos=["p003", "p001"]), u("pepe", "operador"),
            u("luis", "lectura", puntos=["p001"]), u("vera", "operador", puntos=[]),
            u("tito", "operador", puntos="p001"), u("fede", "operador", puntos=["p009"])])

    # ---- ayudas -------------------------------------------------------------------------
    def ck(self, quien):
        if quien not in self._cookies:
            rol = next(r["role"] for r in self.d.cargar_usuarios() if r["user"] == quien)
            self._cookies[quien] = "sid=" + self.d.sesion_abrir(quien, rol)
        return self._cookies[quien]

    def get(self, ruta, quien):
        return self.p.pedir("GET", ruta, cookie=self.ck(quien))

    def post(self, ruta, form, quien):
        return self.p.pedir("POST", ruta, form, cookie=self.ck(quien))

    def poner_puntos(self, quien, puntos):
        us = self.d.cargar_usuarios()
        for r in us:
            if r["user"] == quien:
                if puntos is None:
                    r.pop("puntos", None)
                else:
                    r["puntos"] = puntos
        self.d.guardar_usuarios(us)

    def usuario(self, nombre):
        return next((r for r in self.d.cargar_usuarios() if r["user"] == nombre), None)

    def mk_a(self, pid):
        return [x for x in self.p.mk if x[2] == pid]

    def esta(self, sub, texto, donde=""):
        if sub not in (texto or ""):
            self.fail("%s: falta %r en la respuesta: %s" % (donde, sub, plano(texto)))

    def no_esta(self, sub, texto, donde=""):
        i = (texto or "").find(sub)
        if i >= 0:
            self.fail("%s: sobra %r en la respuesta: ...%s..." % (donde, sub, texto[max(0, i - 160):i + 80]))

    def sin_ajenos(self, texto, donde="", extra=()):
        for m in MARCAS_AJENAS + tuple(extra):
            i = (texto or "").find(m)
            if i >= 0:
                self.fail("%s: dato del punto ajeno %r en la respuesta: ...%s..."
                          % (donde, m, texto[max(0, i - 160):i + 80]))


class VistasLimitado(Base):
    RUTAS = ("/", "/top", "/detalle", "/cuarentena", "/conducta", "/historico", "/eventos", "/reputacion")

    def test_nodo_ajeno_o_todos_es_404(self):
        """Capacidad nueva: un limitado (operador o lectura) que pide un punto ajeno por la URL recibe
        404, sin nada de ese punto en la respuesta; con un solo punto, «Todos» tambien es 404.
        (bloque C 2026-10-23) dora (2 puntos) si abre «Todos»: es SU acumulado (nodos/<grupo>),
        200 y sin nada del punto ajeno ni de nodos/_todos (RES_TODOS esta en MARCAS_AJENAS)."""
        for quien in LIMITADOS:
            for ruta in self.RUTAS:
                for nodo in ("p002", "_todos"):
                    with self.subTest(quien=quien, ruta=ruta, nodo=nodo):
                        r = self.get("%s?nodo=%s" % (ruta, nodo), quien)
                        self.assertEqual(r.status, 200 if (quien, nodo) == ("dora", "_todos") else 404,
                                         plano(r.texto))
                        self.sin_ajenos(r.texto, ruta, extra=(IP_AJENA, IP_AJENA_CAND))

    def test_sin_nodo_abre_su_primer_punto(self):
        """Capacidad nueva: sin ?nodo= un limitado con un punto abre ese punto, nunca «Todos»; y si
        elige otro de los suyos, la sesion lo recuerda. (bloque C 2026-10-23) con 2 o mas puntos
        abre su acumulado «Todos mis puntos» (nodos/<grupo>), nunca el «Todos» real."""
        r = self.get("/", "olga")
        self.assertEqual(r.status, 200, plano(r.texto))
        self.esta(RES_PROPIO, r.texto)
        self.sin_ajenos(r.texto, "/ olga")
        self.assertEqual(selector(r.texto)[1] or "p001", "p001")
        r = self.get("/", "dora")                     # su lista dice [p003, p001]: su acumulado
        self.assertEqual(r.status, 200, plano(r.texto))
        self.esta(RES_GRUPO, r.texto)
        self.sin_ajenos(r.texto, "/ dora (acumulado)")
        self.assertEqual(selector(r.texto)[1], "_todos")
        self.esta(RES_ESTE, self.get("/?nodo=p003", "dora").texto)
        r = self.get("/", "dora")
        self.esta(RES_ESTE, r.texto)
        self.sin_ajenos(r.texto, "/ dora")

    def test_punto_recordado_que_ya_no_es_suyo(self):
        """Capacidad nueva: si la sesion recordaba un punto que ya no es suyo (el admin le limito
        despues), la siguiente pagina abre el primero de los suyos, sin datos del otro."""
        self.poner_puntos("olga", None)
        r = self.get("/?nodo=p002", "olga")
        self.assertEqual(r.status, 200, plano(r.texto))
        self.esta(RES_AJENO, r.texto)
        self.poner_puntos("olga", ["p001"])
        for ruta in ("/", "/cuarentena"):
            with self.subTest(ruta=ruta):
                r = self.get(ruta, "olga")
                self.assertEqual(r.status, 200, plano(r.texto))
                self.sin_ajenos(r.texto, ruta)
        r = self.get("/", "olga")
        self.esta(RES_PROPIO, r.texto)
        self.assertEqual(selector(r.texto)[1] or "p001", "p001")

    def test_selector_solo_con_sus_puntos(self):
        """Capacidad nueva: el selector de nodo de un limitado no trae los puntos ajenos (ni su
        nombre) ni el «Todos los nodos» real; con un punto, ninguna vista acumulada. (bloque C
        2026-10-23) con dos puntos trae los dos y «Todos mis puntos (acumulado)»."""
        for quien, suyos in (("olga", ["p001"]), ("luis", ["p001"]), ("dora", ["p001", "p003"])):
            for ruta in ("/", "/cuarentena", "/eventos"):
                with self.subTest(quien=quien, ruta=ruta):
                    r = self.get(ruta, quien)
                    self.assertEqual(r.status, 200, plano(r.texto))
                    vals, _elegida, sel = selector(r.texto)
                    self.assertNotIn("p002", vals or [])
                    self.no_esta("Todos los nodos", sel)
                    self.no_esta(AJENO, r.texto)
                    if len(suyos) > 1:
                        self.assertEqual(sorted(vals or []), ["_todos"] + suyos)
                        self.esta("Todos mis puntos", sel)
                    else:
                        self.assertNotIn("_todos", vals or [])
                        self.no_esta("Todos", sel)

    def test_ninguna_pagina_ensena_datos_ajenos(self):
        """Capacidad nueva: en ninguna pagina de un limitado aparece nada del punto ajeno ni de la
        vista acumulada: nombre, firma, evidencia, abonado, destino, resumen, publica ni sus IPs.
        Las paginas responden 200 (tambien las que consulta la propia pagina, como /ventana-estado)."""
        rutas = self.RUTAS + ("/conducta.csv", "/ventana-estado", "/ajustes", "/documentacion",
                              "/cuarentena/ficha?ip=p001%7C" + IP_PROPIA)
        for quien in LIMITADOS:
            for ruta in rutas:
                with self.subTest(quien=quien, ruta=ruta):
                    r = self.get(ruta, quien)
                    self.assertEqual(r.status, 200, plano(r.texto))
                    self.sin_ajenos(r.texto, ruta, extra=(IP_AJENA, IP_AJENA_CAND))

    def test_ficha_de_un_cpe_ajeno(self):
        """Capacidad nueva: la ficha de evidencia de un CPE de otro punto (pid|ip) es 404 para un
        limitado; con la IP sola es la de SU punto (sin evidencia). El admin si la ve (control)."""
        ruta = "/cuarentena/ficha?ip=p002%7C" + IP_AJENA
        r = self.get(ruta, "ana")
        self.assertEqual(r.status, 200)
        self.esta("En cuarentena", r.texto)
        self.esta(ABON_AJENO, r.texto)
        for quien in LIMITADOS:
            for q in (ruta, ruta + "&embed=1"):
                with self.subTest(quien=quien, ruta=q):
                    r = self.get(q, quien)
                    self.assertEqual(r.status, 404, plano(r.texto))
                    self.no_esta("En cuarentena", r.texto)
                    self.sin_ajenos(r.texto, q)
            with self.subTest(quien=quien, ruta="ip sola"):
                r = self.get("/cuarentena/ficha?ip=" + IP_AJENA, quien)
                self.assertEqual(r.status, 200, plano(r.texto))
                self.no_esta("En cuarentena", r.texto)
                self.no_esta("p002%7C", r.texto)    # ni la ofrece para elegir
                self.sin_ajenos(r.texto, "ip sola")
        r = self.get("/cuarentena/ficha?ip=p001%7C" + IP_PROPIA, "olga")
        self.assertEqual(r.status, 200)
        self.esta("En cuarentena", r.texto)
        self.esta("ABONADO-PROPIO-KQ", r.texto)

    def test_detalle_de_un_evento_ajeno(self):
        """Capacidad nueva: una referencia de evento (firmada y valida) de un punto ajeno no ensena
        el evento a un limitado, ni desde su nodo ni pidiendo el otro. El admin si lo ve (control)."""
        ew = self.d.eventos_web
        ln = self.lineas_ajenas[0].encode("utf-8")
        qs = urllib.parse.urlencode(sorted(ew.ref("p002", "eve.json", 0, ew.huella(ln)).items()))
        r = self.get("/eventos/detalle?nodo=p002&" + qs, "ana")
        self.assertEqual(r.status, 200)
        self.esta("<pre class='evjson'>", r.texto)
        self.esta(FIRMA_AJENA, r.texto)
        for quien in LIMITADOS:
            for q, esperado in (("/eventos/detalle?" + qs, None), ("/eventos/detalle?nodo=p001&" + qs, None),
                                ("/eventos/detalle?nodo=p002&" + qs, 404)):
                with self.subTest(quien=quien, ruta=q[:40]):
                    r = self.get(q, quien)
                    if esperado:
                        self.assertEqual(r.status, esperado, plano(r.texto))
                    self.no_esta("<pre class='evjson'>", r.texto)
                    self.sin_ajenos(r.texto, q[:40])

    def test_conexion_reutilizada_no_arrastra_el_alcance(self):
        """Capacidad nueva: en una conexion keep-alive (el mismo hilo del servidor) el alcance de
        una peticion no pasa a la siguiente: el admin ve todo tras un limitado, y al reves."""
        c = http.client.HTTPConnection("127.0.0.1", self.p.puerto, timeout=30)
        self.addCleanup(c.close)

        def pedir(ruta, quien):
            c.request("GET", ruta, headers={"Cookie": self.ck(quien)})
            r = c.getresponse()
            return r.status, r.read().decode("utf-8", "replace")
        st, _t = pedir("/?nodo=p001", "olga")
        self.assertEqual(st, 200)
        sock = c.sock
        self.assertIsNotNone(sock)
        st, t = pedir("/?nodo=p002", "ana")
        self.assertEqual(st, 200, plano(t))
        self.esta(RES_AJENO, t)
        st, t = pedir("/?nodo=_todos", "ana")
        self.assertEqual(st, 200, plano(t))
        self.esta(RES_TODOS, t)
        self.assertIs(c.sock, sock)                 # la misma conexion: el mismo hilo
        st, t = pedir("/?nodo=p002", "olga")
        self.assertEqual(st, 404)
        self.sin_ajenos(t, "keep-alive")


class AccionesLimitado(Base):
    def setUp(self):
        super().setUp()
        self.d.destino_bloqueable = lambda ip, propias=None: (True, "")   # RFC 5737: aqui da igual

    def registros(self):
        d = self.d
        return {os.path.basename(p): d.cargar_enviados(p) for p in (d.MK_SENT, d.MK_SENT_GRAD, d.MK_SENT_DNS)}

    def test_cpe_de_otro_punto_no_se_toca(self):
        """Capacidad nueva: enviar, cortar, quitar o liberar un CPE `pid|ip` de un punto ajeno se
        rechaza sin hablar con su router y sin tocar los registros (aunque se confirme la evidencia).
        Control: el admin, con los mismos formularios, si llega al router de p002."""
        k_env, k_cand = "p002|" + IP_AJENA, "p002|" + IP_AJENA_CAND
        enviar = {"ip": k_cand, "score": "80", "confirmar_vieja": "1"}
        intentos = (
            ("/cuarentena/enviar", enviar),
            ("/cuarentena/enviar", dict(enviar, ajax="1")),
            ("/cuarentena/enviar?nodo=p002", enviar),
            ("/cuarentena/graduada", enviar),
            ("/cuarentena/dns/enviar", enviar),
            ("/cuarentena/quitar", {"ip": k_env}),
            ("/cuarentena/graduada/quitar", {"ip": k_env}),
            ("/cuarentena/dns/quitar", {"ip": k_env}),
            ("/cuarentena/quitar-uno", {"sel": "cuar|" + k_env}),
            ("/cuarentena/quitar-uno", {"sel": "dns|" + k_env}),
            ("/cuarentena/quitar-varios", {"sel": ["cuar|" + k_env, "dns|" + k_env]}),
        )
        antes = self.registros()
        for quien in ("olga", "dora"):
            for ruta, form in intentos:
                with self.subTest(quien=quien, ruta=ruta, form=form):
                    r = self.post(ruta, form, quien)
                    self.assertNotEqual(r.status, 500, plano(r.texto))
                    self.assertEqual(self.mk_a("p002"), [])
                    self.sin_ajenos(r.texto, ruta)
        self.assertEqual(self.registros(), antes)
        self.assertEqual(self.p.mk, [])
        for ruta, form in (intentos[0], intentos[3], intentos[4], intentos[8], intentos[6], intentos[7]):
            n0 = len(self.mk_a("p002"))
            r = self.post(ruta, form, "ana")
            with self.subTest(control=ruta, form=form):
                self.assertEqual(len(self.mk_a("p002")), n0 + 1, plano(r.texto))

    def test_envio_masivo_de_otro_punto_o_de_todos(self):
        """Capacidad nueva: «Enviar todos» (CnC y DNS) con el nodo de la lista de un punto ajeno o de
        «Todos» no manda nada. Control: el admin, con el mismo formulario, si.
        (bloque C 2026-10-23) el «Todos» de dora es SU acumulado: puede mandar a SUS routers (p001,
        p003), pero nunca nada a p002 ni lo de nodos/_todos."""
        for quien in ("olga", "dora"):
            for ruta in ("/cuarentena/enviar-todos", "/cuarentena/dns/enviar-todos"):
                for nodo in ("p002", "_todos"):
                    with self.subTest(quien=quien, ruta=ruta, nodo=nodo):
                        n0 = len(self.p.mk)
                        r = self.post(ruta, {"nodo": nodo}, quien)
                        self.assertNotEqual(r.status, 500, plano(r.texto))
                        self.assertEqual(self.mk_a("p002"), [])
                        if (quien, nodo) != ("dora", "_todos"):
                            self.assertEqual(self.p.mk[n0:], [])
                        self.assertEqual([x for x in self.p.mk if x[2] not in ("p001", "p003")], [])
        self.assertNotIn("p002|" + IP_AJENA_CAND, self.d.cargar_enviados(self.d.MK_SENT))
        self.p.mk.clear()
        self.post("/cuarentena/enviar-todos", {"nodo": "p002"}, "ana")
        self.assertIn(("add", IP_AJENA_CAND, "p002"), self.p.mk)

    def test_sus_propios_cpes_si(self):
        """Capacidad nueva (conservacion para el limitado): con SU punto trabaja como siempre: enviar
        (sin confirmar: su evidencia es reciente) y quitar van al router de su punto."""
        r = self.post("/cuarentena/enviar", {"ip": "p001|" + IP_PROPIA_CAND, "score": "80"}, "olga")
        self.assertEqual(r.status, 303, plano(r.texto))
        self.assertIn(("add", IP_PROPIA_CAND, "p001"), self.p.mk)
        self.assertIn("p001|" + IP_PROPIA_CAND, self.d.cargar_enviados(self.d.MK_SENT))
        r = self.post("/cuarentena/quitar", {"ip": "p001|" + IP_PROPIA}, "olga")
        self.assertEqual(r.status, 303, plano(r.texto))
        self.assertIn(("remove", IP_PROPIA, "p001"), self.p.mk)
        self.assertNotIn("p001|" + IP_PROPIA, self.d.cargar_enviados(self.d.MK_SENT))
        self.assertEqual(self.mk_a("p002"), [])

    def test_envio_masivo_de_su_punto(self):
        """Capacidad nueva (conservacion para el limitado): «Enviar todos» con la lista de SU punto
        manda sus confirmados a su router y nada a los demas."""
        r = self.post("/cuarentena/enviar-todos", {"nodo": "p001"}, "olga")
        self.assertEqual(r.status, 303, plano(r.texto))
        self.assertIn(("add", IP_PROPIA_CAND, "p001"), self.p.mk)
        self.assertEqual([x for x in self.p.mk if x[2] != "p001"], [])

    def test_destino_malo_solo_en_sus_routers(self):
        """Capacidad nueva: bloquear o desbloquear un destino (operacion multipunto) desde un
        limitado va solo a SUS routers y el registro lo dice; el admin lo pone en todos."""
        dst = "192.0.2.77"

        def routers(accion):
            return sorted(x[2] for x in self.p.mk if x[1] == dst and x[0] == accion)
        r = self.post("/cuarentena/destino/bloquear", {"ip": dst}, "olga")
        self.assertEqual(routers("add"), ["p001"])
        self.assertEqual(self.d.cargar_enviados(self.d.MK_SENT_DST)[dst]["puntos"], ["p001"])
        aviso = self.get(r.cab("Location") or "/cuarentena", "olga")
        self.sin_ajenos(aviso.texto, "aviso del bloqueo")
        self.p.mk.clear()
        self.post("/cuarentena/destino/bloquear", {"ip": dst}, "ana")
        self.assertEqual(routers("add"), TODOS_LOS_PIDS)
        self.assertEqual(self.d.cargar_enviados(self.d.MK_SENT_DST)[dst]["puntos"], TODOS_LOS_PIDS)
        self.p.mk.clear()
        self.post("/cuarentena/destino/quitar", {"ip": dst}, "dora")
        self.assertEqual(routers("remove"), ["p001", "p003"])
        self.assertEqual(self.d.cargar_enviados(self.d.MK_SENT_DST)[dst]["puntos"], ["p002"])

    def test_acciones_globales_prohibidas_al_limitado(self):
        """Capacidad nueva: lo que afecta a todos los puntos (excluir un destino, quitar un destino
        confiable, denunciar en AbuseIPDB) es 403 para un limitado y no se ejecuta. Control: un
        operador sin lista si puede."""
        llamadas = []
        d = self.d
        d.excluir_destino = lambda dd: (llamadas.append(("excluir", dd)) or (1, "excluido"))
        d.modificar_dest_ok = lambda **k: llamadas.append(("quitar-destino", k))
        d.aidb_denunciar = lambda ip, **k: (llamadas.append(("denunciar", ip)) or (True, "denunciada"))
        intentos = (("/cuarentena/excluir-destino", {"destino": "203.0.113.50"}),
                    ("/cuarentena/quitar-destino", {"destino": "203.0.113.51"}),
                    ("/reputacion/denunciar", {"ip": "203.0.113.52", "firma": "ET prueba", "dport": "443",
                                               "proto": "TCP", "n": "3"}))
        for quien in ("olga", "dora"):
            for ruta, form in intentos:
                with self.subTest(quien=quien, ruta=ruta):
                    self.assertEqual(self.post(ruta, form, quien).status, 403)
        self.assertEqual(llamadas, [])
        for ruta, form in intentos:
            self.assertNotEqual(self.post(ruta, form, "pepe").status, 403)
        self.assertEqual([x[0] for x in llamadas], ["excluir", "quitar-destino", "denunciar"])


class FichaPuntoPorRol(Base):
    def setUp(self):
        super().setUp()
        self.bajas = []
        self.d.baja_limpiar_router = lambda pid, usuario=None, op=None: (
            self.bajas.append(pid) or {"ok": True, "mensaje": "limpio"})

    def ordenes_de(self, pid):
        return [o for o in self.p.orq.pedidas if (o.get("params") or {}).get("pid") == pid]

    def test_operador_limitado_ve_la_lista_y_la_ficha_de_sus_puntos(self):
        """Capacidad nueva: un operador limitado ve en /puntos solo sus puntos y abre la ficha, los
        logs y la huella de los suyos (200); los de uno ajeno son 404, sin su nombre. Su ficha no
        trae la baja ni «Desbanear» (son del admin, que si los tiene: control)."""
        a = self.get("/puntos/p001", "ana").texto
        self.esta("/puntos/p001/borrar", a)
        self.esta("/puntos/p001/desbanear", a)
        for quien, suyos in (("olga", ["p001"]), ("dora", ["p001", "p003"])):
            with self.subTest(quien=quien, ruta="/puntos"):
                r = self.get("/puntos", quien)
                self.assertEqual(r.status, 200, plano(r.texto))
                for pid in suyos:
                    self.esta(NOMBRES[pid], r.texto)
                for pid in set(TODOS_LOS_PIDS) - set(suyos):
                    self.no_esta(NOMBRES[pid], r.texto)
                self.sin_ajenos(r.texto, "/puntos")
            for suyo in suyos:
                with self.subTest(quien=quien, ruta="/puntos/" + suyo):
                    r = self.get("/puntos/" + suyo, quien)
                    self.assertEqual(r.status, 200, plano(r.texto))
                    self.esta(NOMBRES[suyo], r.texto)
                    self.no_esta("/puntos/%s/borrar" % suyo, r.texto)
                    self.no_esta("/puntos/%s/desbanear" % suyo, r.texto)
                    self.sin_ajenos(r.texto, "/puntos/" + suyo)
                    for sub in ("logs", "huella"):
                        r = self.get("/puntos/%s/%s" % (suyo, sub), quien)
                        self.assertEqual(r.status, 200, plano(r.texto))
                        self.sin_ajenos(r.texto, sub)
            for ruta in ("/puntos/p002", "/puntos/p002/logs", "/puntos/p002/huella"):
                with self.subTest(quien=quien, ruta=ruta):
                    r = self.get(ruta, quien)
                    self.assertEqual(r.status, 404, plano(r.texto))
                    self.sin_ajenos(r.texto, ruta)
        self.assertEqual(self.ordenes_de("p002"), [])

    def test_operador_limitado_gestiona_su_punto(self):
        """Capacidad nueva: con SU punto el operador limitado arranca, para, reinicia, regenera y
        ajusta (cada boton su orden de cola con su pid). Guardar la API de su router no borra de
        routers.json los routers de los demas puntos (fallo critico de guardar_routers, 2026-10-22)."""
        with self.n.sin_alcance():
            self.d.guardar_routers([{"id": pid, "USER": "u-" + pid, "PASS": "clave-" + pid, "ENABLED": "1"}
                                    for pid in TODOS_LOS_PIDS])
        for acc, orden in (("arrancar", "punto.arrancar"), ("parar", "punto.parar"),
                           ("reiniciar", "punto.reiniciar"), ("regenerar", "punto.vpn.regenerar")):
            with self.subTest(acc=acc):
                r = self.post("/puntos/p001/" + acc, {}, "olga")
                self.assertEqual(r.status, 303, plano(r.texto))
                self.assertEqual(self.p.orq.ordenes(orden)[-1]["params"], {"pid": "p001"})
        r = self.post("/puntos/p001/ajustar", {"redes": "10.0.0.0/24"}, "olga")
        self.assertIn(r.status, (200, 303), plano(r.texto))
        self.assertEqual(self.p.orq.ordenes("punto.ajustar")[-1]["params"]["pid"], "p001")
        r = self.post("/puntos/p001/api", {"accion": "guardar", "user": "ids-nueva", "pass": "clave-nueva-1",
                                           "enabled": "1"}, "olga")
        self.assertNotEqual(r.status, 500, plano(r.texto))
        r = self.post("/puntos/p003/api", {"accion": "guardar", "user": "ids-este", "pass": "clave-este-1",
                                           "enabled": "1"}, "dora")
        self.assertNotEqual(r.status, 500, plano(r.texto))
        with self.n.sin_alcance():
            rs = {r["id"]: r for r in self.d.cargar_routers()}
        self.assertEqual((rs["p001"]["USER"], rs["p001"]["PASS"]), ("ids-nueva", "clave-nueva-1"))
        self.assertEqual((rs["p003"]["USER"], rs["p003"]["PASS"]), ("ids-este", "clave-este-1"))
        self.assertEqual((rs["p002"]["USER"], rs["p002"]["PASS"], rs["p002"]["ENABLED"]), ("u-p002", "clave-p002", "1"))
        self.assertEqual(sorted(self.d._routers_guardados()), TODOS_LOS_PIDS)
        with open(self.d.ROUTERS_MAP, encoding="utf-8") as f:
            self.assertEqual(sorted(x["id"] for x in json.load(f)), TODOS_LOS_PIDS)
        self.assertEqual(self.ordenes_de("p002"), [])

    def test_operaciones_solo_las_suyas_y_de_puntos_visibles(self):
        """Capacidad nueva: /operaciones/<op> de un operador solo abre las suyas y de puntos que ve:
        la de otro usuario, o la suya de un punto que ya no ve, es 404."""
        r = self.post("/puntos/p002/arrancar", {}, "ana")
        op_ana = r.cab("Location")
        r = self.post("/puntos/p001/arrancar", {}, "olga")
        op_olga = r.cab("Location")
        self.assertTrue((op_ana or "").startswith("/operaciones/"), op_ana)
        self.assertTrue((op_olga or "").startswith("/operaciones/"), op_olga)
        op_ana, op_olga = op_ana.split("?", 1)[0], op_olga.split("?", 1)[0]
        self.assertEqual(self.get(op_ana, "ana").status, 200)
        self.assertEqual(self.get(op_olga, "olga").status, 200)
        for ruta, quien in ((op_ana, "olga"), (op_ana, "dora"), (op_olga, "dora")):
            with self.subTest(ruta=ruta, quien=quien):
                r = self.get(ruta, quien)
                self.assertEqual(r.status, 404, plano(r.texto))
                self.sin_ajenos(r.texto, ruta)
                self.assertEqual(self.get(ruta + "?json=1", quien).status, 404)
        self.poner_puntos("olga", ["p003"])
        self.assertEqual(self.get(op_olga, "olga").status, 404)

    def test_operador_limitado_no_da_de_alta_ni_de_baja(self):
        """Capacidad nueva: un operador limitado no crea puntos ni da de baja (ni limpia el router)
        ni desbanea el suyo: 403 y nada al orquestador. Control: el admin si pide la baja."""
        self.assertEqual(self.get("/puntos/nuevo", "olga").status, 403)
        intentos = (("/puntos/nuevo", {"op": str(uuid.uuid4()), "nombre": "nuevoq"}),
                    ("/puntos/p001/borrar", {"confirmar": NOMBRES["p001"], "limpiar_router": "1"}),
                    ("/puntos/p001/borrar", {"confirmar": NOMBRES["p001"], "limpiar_router": "1", "ajax": "1"}),
                    ("/puntos/p001/desbanear", {}),
                    ("/puntos/p001/desbanear", {"ajax": "1"}))
        for ruta, form in intentos:
            with self.subTest(ruta=ruta, form=form):
                self.assertEqual(self.post(ruta, form, "olga").status, 403)
        self.assertEqual(self.p.orq.ordenes("punto.crear"), [])
        self.assertEqual(self.p.orq.ordenes("punto.borrar"), [])
        self.assertEqual(self.bajas, [])
        self.post("/puntos/p001/borrar", {"confirmar": NOMBRES["p001"]}, "ana")
        self.assertEqual(len(self.p.orq.ordenes("punto.borrar")), 1)

    def test_operador_limitado_no_toca_un_punto_ajeno(self):
        """Capacidad nueva: las acciones de un punto ajeno son 404 (como uno que no existe: sin
        enumeracion), baja y desbaneo 403 (del admin, antes de mirar el pid); nada llega al
        orquestador ni a routers.json para ese punto."""
        with self.n.sin_alcance():
            self.d.guardar_routers([{"id": "p002", "USER": "u-p002", "PASS": "clave-p002", "ENABLED": "1"}])
        form = {"confirmar": AJENO, "redes": "10.9.0.0/24", "accion": "guardar", "user": "intruso",
                "pass": "clave-intrusa", "op": str(uuid.uuid4())}
        for acc, esperado in (("arrancar", 404), ("parar", 404), ("reiniciar", 404), ("regenerar", 404),
                              ("ajustar", 404), ("api", 404), ("desbanear", 403), ("borrar", 403)):
            for quien in ("olga", "dora"):
                with self.subTest(acc=acc, quien=quien):
                    r = self.post("/puntos/p002/" + acc, form, quien)
                    self.assertEqual(r.status, esperado, plano(r.texto))
                    self.sin_ajenos(r.texto, acc)
        self.assertEqual(self.ordenes_de("p002"), [])
        self.assertEqual(self.bajas, [])
        with self.n.sin_alcance():
            rs = {r["id"]: r for r in self.d.cargar_routers()}
        self.assertEqual((rs["p002"]["USER"], rs["p002"]["PASS"]), ("u-p002", "clave-p002"))

    def test_lectura_no_entra_en_puntos(self):
        """Capacidad nueva (rol): un usuario de lectura, limitado o no, no entra en el apartado
        Puntos (403), ni siquiera en su propio punto."""
        for ruta in ("/puntos", "/puntos/p001", "/puntos/nuevo", "/puntos/p001/logs", "/puntos/p002"):
            with self.subTest(ruta=ruta):
                r = self.get(ruta, "luis")
                self.assertEqual(r.status, 403, plano(r.texto))
                self.sin_ajenos(r.texto, ruta)
        self.assertEqual(self.post("/puntos/p001/arrancar", {}, "luis").status, 403)
        self.assertEqual(self.p.orq.pedidas, [])

    def test_admin_ve_y_gestiona_cualquier_punto(self):
        """Conservacion: el admin sigue viendo la lista entera, cualquier ficha y actuando en todos."""
        r = self.get("/puntos", "ana")
        self.assertEqual(r.status, 200)
        for nom in NOMBRES.values():
            self.esta(nom, r.texto)
        r = self.get("/puntos/p002", "ana")
        self.assertEqual(r.status, 200)
        self.esta(AJENO, r.texto)
        r = self.post("/puntos/p002/arrancar", {}, "ana")
        self.assertEqual(r.status, 303, plano(r.texto))
        self.assertEqual(self.p.orq.ordenes("punto.arrancar")[-1]["params"], {"pid": "p002"})


class UsuariosEnAjustes(Base):
    def alta(self, nombre, rol, modo, puntos=()):
        form = {"accion": "add_user", "nuser": nombre, "npass": "clave-larga-de-prueba", "nrole": rol,
                "puntos_modo": modo}
        if puntos:
            form["puntos"] = list(puntos)
        return self.post("/perfil", form, "ana")

    def editar(self, objetivo, rol, modo, puntos=(), quien="ana"):
        form = {"accion": "edit_user", "user": objetivo, "nombre": "", "correo": "", "role": rol,
                "puntos_modo": modo}
        if puntos:
            form["puntos"] = list(puntos)
        return self.post("/perfil", form, quien)

    def test_alta_con_sus_puntos(self):
        """Capacidad nueva: al crear un usuario, «solo» guarda la lista ordenada y sin repetidos de
        los puntos existentes (los inexistentes o mal formados se ignoran); «todos» no guarda lista
        (desde la fase 1 de permisos tambien el admin se limita); «solo» sin ninguno guarda []. Y el
        usuario entra viendo solo lo suyo."""
        self.alta("nuevo1", "operador", "solo", ["p003", "p001", "p001", "p999", "../p002", "p0002", ""])
        self.alta("nuevo2", "lectura", "todos", ["p001"])
        self.alta("nuevo3", "admin", "solo", ["p001"])
        self.alta("nuevo4", "operador", "solo")
        us = {n: self.usuario(n) for n in ("nuevo1", "nuevo2", "nuevo3", "nuevo4")}
        for n, r in us.items():
            self.assertIsNotNone(r, n)
        self.assertEqual(us["nuevo1"].get("puntos"), ["p001", "p003"])
        self.assertNotIn("puntos", us["nuevo2"])
        self.assertEqual(us["nuevo3"].get("puntos"), ["p001"])
        self.assertEqual(us["nuevo4"].get("puntos"), [])
        self.assertEqual(self.get("/?nodo=p002", "nuevo1").status, 404)
        self.assertEqual(self.get("/?nodo=p003", "nuevo1").status, 200)
        self.assertEqual(self.get("/?nodo=p002", "nuevo2").status, 200)
        self.assertEqual(self.get("/eventos", "nuevo4").status, 403)

    def test_edicion_cambia_sus_puntos(self):
        """Capacidad nueva: editar un usuario cambia su lista: «todos» la borra, «solo» la fija
        (ordenada, sin repetidos ni inexistentes), «solo» sin ninguno deja [] y, desde la fase 1 de
        permisos, el rol admin tambien la conserva."""
        pasos = ((("operador", "todos", ["p001"]), None),
                 (("operador", "solo", ["p002"]), ["p002"]),
                 (("operador", "solo", ["p003", "p002", "p003", "p777"]), ["p002", "p003"]),
                 (("operador", "solo", []), []),
                 (("admin", "solo", ["p001"]), ["p001"]))
        for (rol, modo, pts), esperado in pasos:
            with self.subTest(rol=rol, modo=modo, puntos=pts):
                self.editar("olga", rol, modo, pts)
                r = self.usuario("olga")
                self.assertEqual(r["role"], rol)
                if esperado is None:
                    self.assertNotIn("puntos", r)
                else:
                    self.assertEqual(r.get("puntos"), esperado)

    def test_solo_el_admin_asigna_puntos(self):
        """Capacidad nueva (rol): ni un operador limitado ni uno sin lista puede asignar puntos, ni
        a otro ni a si mismo (para ampliarse): 403 y usuarios.json intacto."""
        antes = self.d.cargar_usuarios()
        for quien in ("olga", "dora", "pepe"):
            with self.subTest(quien=quien):
                self.assertEqual(self.editar("pepe", "operador", "solo", ["p001"], quien=quien).status, 403)
                self.assertEqual(self.editar(quien, "operador", "todos", quien=quien).status, 403)
                r = self.post("/perfil", {"accion": "add_user", "nuser": "intruso", "npass": "clave-larga-de-prueba",
                                          "nrole": "operador", "puntos_modo": "todos"}, quien)
                self.assertEqual(r.status, 403)
        self.assertEqual(self.d.cargar_usuarios(), antes)

    def test_el_cambio_vale_en_la_siguiente_peticion(self):
        """Capacidad nueva: el admin limita a un usuario con la sesion abierta y su siguiente
        peticion ya va limitada (sin volver a entrar); al quitarle el limite vuelve a verlo todo."""
        self.assertEqual(self.get("/?nodo=p002", "pepe").status, 200)
        self.editar("pepe", "operador", "solo", ["p001"])
        r = self.get("/?nodo=p002", "pepe")
        self.assertEqual(r.status, 404)
        r = self.get("/", "pepe")
        self.assertEqual(r.status, 200, plano(r.texto))
        self.sin_ajenos(r.texto, "/ pepe limitado")
        self.editar("pepe", "operador", "todos")
        self.assertEqual(self.get("/?nodo=p002", "pepe").status, 200)

    def test_el_formulario_ofrece_cada_punto(self):
        """Capacidad nueva: Ajustes > Usuarios (admin) ofrece el modo (puntos_modo) y una casilla
        `puntos` por cada punto existente, con el pid como valor."""
        h = self.get("/ajustes", "ana").texto
        self.assertRegex(h, r"name=['\"]?puntos_modo\b")
        vals = set()
        for tag in re.findall(r"<input\b[^>]*>", h):
            if re.search(r"\bname=['\"]?puntos(?:['\"\s/>]|$)", tag):
                m = re.search(r"\bvalue=['\"]?([^'\"\s>]+)", tag)
                if m:
                    vals.add(m.group(1))
        self.assertTrue(set(TODOS_LOS_PIDS) <= vals, vals)


class AdminSinCambios(Base):
    def test_admin_y_usuarios_sin_lista_lo_ven_todo(self):
        """Conservacion: el admin sin lista y el usuario sin lista ven todos los puntos y la vista
        acumulada, que es su vista por defecto; el selector trae «Todos» y los tres. (Un admin con
        lista, desde la fase 1 de permisos, se limita: test_panel_permisos.)"""
        for quien in ("ana", "pepe"):
            with self.subTest(quien=quien):
                r = self.get("/", quien)
                self.assertEqual(r.status, 200, plano(r.texto))
                self.esta(RES_TODOS, r.texto)
                vals, elegida, _sel = selector(r.texto)
                self.assertEqual(elegida, "_todos")
                self.assertEqual(set(vals or []), {"_todos"} | set(TODOS_LOS_PIDS))
                r = self.get("/?nodo=p002", quien)
                self.assertEqual(r.status, 200, plano(r.texto))
                self.esta(RES_AJENO, r.texto)
                self.esta(AJENO, r.texto)
                r = self.get("/cuarentena?nodo=_todos", quien)
                self.assertEqual(r.status, 200, plano(r.texto))
                self.esta(IP_AJENA_CAND, r.texto)
                self.esta(IP_PROPIA_CAND, r.texto)
                r = self.get("/reputacion?nodo=_todos", quien)
                self.esta(PUB_AJENA, r.texto)
                self.esta("TOP " + RES_AJENO, self.get("/top?nodo=p002", quien).texto)
                self.esta(FIRMA_AJENA, self.get("/eventos?nodo=p002", quien).texto)
                r = self.get("/cuarentena/ficha?ip=p002%7C" + IP_AJENA, quien)
                self.assertEqual(r.status, 200)
                self.esta("En cuarentena", r.texto)

    def test_admin_actua_en_cualquier_punto(self):
        """Conservacion: el admin y el operador sin lista envian a cualquier punto, y «Enviar todos»
        en la vista acumulada reparte cada CPE a su router."""
        r = self.post("/cuarentena/enviar", {"ip": "p002|" + IP_AJENA_CAND, "score": "80"}, "ana")
        self.assertEqual(r.status, 303, plano(r.texto))
        self.assertIn(("add", IP_AJENA_CAND, "p002"), self.p.mk)
        r = self.post("/cuarentena/enviar", {"ip": "p003|" + IP_ESTE, "score": "80"}, "pepe")
        self.assertEqual(r.status, 303, plano(r.texto))
        self.assertIn(("add", IP_ESTE, "p003"), self.p.mk)
        self.p.mk.clear()
        self.post("/cuarentena/enviar-todos", {"nodo": "_todos"}, "ana")
        self.assertIn(("add", IP_PROPIA_CAND, "p001"), self.p.mk)


class SinPuntos(Base):
    def test_sin_ningun_punto_es_403(self):
        """Capacidad nueva: con lista vacia, mal formada o solo de puntos que no existen no se ve
        nada: 403 «Sin puntos asignados» en cualquier pagina y ninguna accion llega al router."""
        for quien in ("vera", "tito", "fede"):
            for ruta in ("/cuarentena?nodo=p001", "/eventos", "/top"):
                with self.subTest(quien=quien, ruta=ruta):
                    r = self.get(ruta, quien)
                    self.assertEqual(r.status, 403, plano(r.texto))
                    self.sin_ajenos(r.texto, ruta, extra=(RES_PROPIO, NOMBRES["p001"]))
            r = self.get("/eventos", quien)
            self.esta("Sin puntos asignados", r.texto)
            # (bloque B) la portada lleva a su cuenta
            for ruta in ("/", "/?nodo=_todos"):
                r = self.get(ruta, quien)
                self.assertEqual(r.status, 303, plano(r.texto))
                self.assertTrue((r.cab("Location") or "").startswith("/ajustes"), r.cab("Location"))
            r = self.post("/cuarentena/enviar", {"ip": "p001|" + IP_PROPIA_CAND, "score": "80",
                                                 "confirmar_vieja": "1"}, quien)
            self.assertEqual(r.status, 403)
        self.assertEqual(self.p.mk, [])

    def test_puede_salir(self):
        """Capacidad nueva: sin puntos, salir del panel sigue funcionando."""
        self.assertEqual(self.get("/logout", "vera").status, 303)

    def test_su_unico_punto_dado_de_baja(self):
        """Capacidad nueva: si se purga el unico punto de un usuario, queda sin puntos (403), no pasa
        a ver todo; quien conserva otro abre ese, y el admin sigue viendo los demas."""
        with open(os.path.join(self.n.ESTADO, "bajas-purgadas.json"), "w", encoding="utf-8") as f:
            json.dump({"p001": {"cuando": int(time.time())}}, f)
        r = self.get("/eventos", "olga")
        self.assertEqual(r.status, 403, plano(r.texto))
        r = self.get("/", "dora")
        self.assertEqual(r.status, 200, plano(r.texto))
        self.esta(RES_ESTE, r.texto)
        self.assertEqual(self.get("/?nodo=p002", "ana").status, 200)


if __name__ == "__main__":
    unittest.main()
