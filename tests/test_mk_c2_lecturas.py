"""C2: lecturas del router para las reglas por clase (plan, aplicar, estado).

Tipo: correccion de defecto + rendimiento (tanda MikroTik del 2026-10-14).

a) _mk_print se traga los fallos (transporte, timeout, !trap) y devuelve []: el plan lo leia
   como «el router no tiene nuestras reglas», proponia add y aplicar las DUPLICABA. Ahora
   _reglas_nuestras lee con _mk_print_estricto, que lanza ErrorLecturaMK: ni se propone ni se
   aplica nada, y el estado dice «error» en vez de «pendientes».
b) estado_reglas releia las cinco tablas por cada una de las ocho clases (~40 prints por la
   VPN al abrir Ajustes). Ahora lee cada tabla UNA vez y da el mismo resultado.

Panel real (dashboard.py) con el MikroTik simulado de tests/_mikrotik_simulado.py; al router
se le anaden aqui las tablas que el simulador no trae (raw, nat, queue tree, interface list),
sin tocar el simulador.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_f1_cuarentena import Panel  # noqa: E402

RAW = "/ip/firewall/raw"


def con_tablas_de_reglas(router):
    """Las tablas que tocan las reglas por clase, vacias, y la interface-list WAN (la usan las
    plantillas por defecto: sin ella el verificador bloquea el aplicar)."""
    for t in (RAW, "/ip/firewall/nat", "/queue/tree", "/interface/list"):
        router.tablas.setdefault(t, [])
    router.tablas["/interface/list"].append({".id": "*FF01", "name": "WAN"})
    # una regla ajena con un comentario parecido: nunca es nuestra
    router.cargar(RAW, [{"chain": "prerouting", "action": "accept", "comment": "Suricata cuarentena"}])
    return router


def contar_prints(router):
    """Lista que se llena con cada orden print que recibe el router."""
    vistos = []
    original = router.ejecutar

    def ejecutar(palabras):
        if palabras[0].endswith("/print"):
            vistos.append(palabras[0])
        return original(palabras)
    router.ejecutar = ejecutar
    return vistos


def estado_de(plan):
    """La misma regla de estado_reglas, aplicada a un plan calculado por separado."""
    quedan = sum(1 for a in plan["acciones"] if a[0] in ("add", "set", "igual"))
    if plan["cambios"]:
        return {"estado": "pendientes", "cambios": plan["cambios"]}
    return {"estado": "aplicadas" if quedan else "ninguna", "cambios": 0}


class Base(unittest.TestCase):
    def setUp(self):
        self.p = Panel()
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d
        self.rt = con_tablas_de_reglas(self.p.routers["p001"])
        self.r = self.d.router_por_id("p001")
        self.m = self.d._mk_globales()

    def nuestras(self, cat):
        return [f for t in self.d._PROPS_TABLA for f in self.rt.tablas[t]
                if (f.get("comment") or "").startswith("Suricata:%s:" % cat)]

    def aplicar(self, cat):
        ok, msg, _p = self.d.aplicar_reglas(self.r, cat, quien="prueba")
        self.assertTrue(ok, msg)


class LecturaFallidaNoDuplica(Base):
    def setUp(self):
        super().setUp()
        self.aplicar("botnet")
        self.reglas = len(self.nuestras("botnet"))
        self.assertGreater(self.reglas, 0)
        self.escrituras = len(self.rt.escrituras)

    def test_trap_en_el_print_no_es_tabla_vacia(self):
        self.rt.fallar_print = RAW + "/print"
        with self.d.mk_sesion(self.r) as (s, _dd):
            # el tolerante sigue igual (lo usa el diagnostico): [] ...
            self.assertEqual(self.d._mk_print(s, RAW + "/print", [".id"]), [])
            # ... y el estricto dice que no pudo leer
            with self.assertRaises(self.d.ErrorLecturaMK) as cm:
                self.d._reglas_nuestras(s, "botnet")
            self.assertIn("no se pudo leer el router", str(cm.exception))
            with self.assertRaises(self.d.ErrorLecturaMK):
                self.d._plan_en(s, "botnet", None, self.m)
        with self.assertRaises(self.d.ErrorLecturaMK):
            self.d.plan_reglas(self.r, "botnet")
        # aplicar no propone ni manda nada: ni altas duplicadas ni ninguna otra orden
        with self.assertRaises(self.d.ErrorLecturaMK):
            self.d.aplicar_reglas(self.r, "botnet", quien="prueba")
        with self.assertRaises(self.d.ErrorLecturaMK):
            self.d.quitar_reglas(self.r, "botnet", quien="prueba")
        self.assertEqual(len(self.rt.escrituras), self.escrituras)
        self.rt.fallar_print = None
        self.assertEqual(len(self.nuestras("botnet")), self.reglas)
        # con el router leyendo otra vez, el plan ve lo que hay: nada que hacer
        self.assertEqual(self.d.plan_reglas(self.r, "botnet")["cambios"], 0)

    def test_estado_dice_error_en_todas_y_no_pendientes(self):
        self.rt.fallar_print = RAW + "/print"
        vistos = contar_prints(self.rt)
        e = self.d.estado_reglas(self.r, self.m)
        self.assertEqual(set(e), set(self.d.ACCIONES_POR_CAT))
        for cat, v in e.items():
            self.assertEqual(v["estado"], "error", (cat, v))
            self.assertIn("no se pudo leer el router", v["msg"])
        # tras el fallo no se le pregunta nada mas a esa conexion
        self.assertEqual(vistos.count(RAW + "/print"), 1)

    def test_trap_sin_mensaje_tambien_es_fallo(self):
        original = self.rt.ejecutar
        self.rt.ejecutar = lambda pal: ([["!trap"], ["!done"]] if pal[0] == RAW + "/print"
                                        else original(pal))
        with self.d.mk_sesion(self.r) as (s, _dd):
            with self.assertRaises(self.d.ErrorLecturaMK):
                self.d._mk_print_estricto(s, RAW + "/print", [".id"])

    def test_router_mudo_en_la_lectura(self):
        # el router no contesta al print (timeout): antes era «tabla vacia» y se planificaba
        original = self.rt.ejecutar
        self.rt.ejecutar = lambda pal: None if pal[0] == RAW + "/print" else original(pal)
        with self.assertRaises(self.d.ErrorLecturaMK):
            self.d.aplicar_reglas(self.r, "botnet", quien="prueba")
        e = self.d.estado_reglas(self.r, self.m)
        self.assertTrue(all(v["estado"] == "error" for v in e.values()), e)
        self.assertEqual(len(self.rt.escrituras), self.escrituras)
        self.assertEqual(len(self.nuestras("botnet")), self.reglas)


class EstadoUnaLecturaPorTabla(Base):
    def setUp(self):
        super().setUp()
        self.aplicar("botnet")                        # aplicadas
        self.aplicar("spam")
        fila = self.nuestras("spam")[0]               # y una corregida a mano: pendientes
        fila["action"] = "accept" if fila.get("action") != "accept" else "drop"

    def test_mismo_resultado_con_cinco_lecturas_en_vez_de_cuarenta(self):
        vistos = contar_prints(self.rt)
        # ANTES: cada clase lee sus tablas por separado (lo que hacia estado_reglas)
        antes = {}
        with self.d.mk_sesion(self.r) as (s, _dd):
            for cat in self.d.ACCIONES_POR_CAT:
                antes[cat] = estado_de(self.d._plan_en(s, cat, None, self.m, verificar=False))
        n_antes = len(vistos)
        del vistos[:]
        # DESPUES: estado_reglas, una lectura por tabla
        despues = self.d.estado_reglas(self.r, self.m)
        n_tablas = len(self.d._PROPS_TABLA)
        self.assertGreaterEqual(n_antes, n_tablas * len(self.d.ACCIONES_POR_CAT))   # ~40
        self.assertEqual(len(vistos), n_tablas)                                      # 5
        self.assertEqual(sorted(vistos), sorted(t + "/print" for t in self.d._PROPS_TABLA))
        self.assertEqual(despues, antes)
        # y el resultado es el que toca, no solo el mismo
        self.assertEqual(despues["botnet"], {"estado": "aplicadas", "cambios": 0})
        self.assertEqual(despues["spam"]["estado"], "pendientes")
        self.assertGreaterEqual(despues["spam"]["cambios"], 1)
        self.assertEqual(despues["fuerza"]["estado"], "pendientes")
        self.assertEqual(despues["p2p"], {"estado": "ninguna", "cambios": 0})

    def test_lectura_compartida_ve_las_propiedades_de_cada_clase(self):
        # las propias pueden usar cualquier campo (aqui in-interface-list y comment de
        # otra forma): con la lectura compartida se comparan igual que con la propia
        leidas = {}
        with self.d.mk_sesion(self.r) as (s, _dd):
            for cat in self.d.ACCIONES_POR_CAT:
                solo = self.d._plan_en(s, cat, None, self.m, verificar=False)
                junto = self.d._plan_en(s, cat, None, self.m, verificar=False, leidas=leidas)
                self.assertEqual([a[0] for a in junto["acciones"]], [a[0] for a in solo["acciones"]], cat)
                self.assertEqual(junto["cambios"], solo["cambios"], cat)
                self.assertEqual(junto["diferencias"], solo["diferencias"], cat)


if __name__ == "__main__":
    unittest.main()
