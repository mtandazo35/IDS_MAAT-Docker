"""Núcleo del panel (N): lo que el apartado Puntos (P) usa de N: espejo por mikrotik_init,
baja (purgar_punto), redirecciones con nodo e historial de abonados por punto
(CONTRATO-F2 §4, §5, §10.1).
"""
import json
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
import _dash  # noqa: E402

K1 = "p001|" + _dash.IP
K2 = "p002|" + _dash.IP


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = _dash.Arbol(self.tmp.name)
        self.d = _dash.cargar(self.a)
        self.n = self.d.nodos
        self.n.asegurar_dirs()
        self.registro = []
        self.d.mk_conectar = _dash.conectar_falso(self.registro)
        self.d.guardar_routers([{"id": "p001", "USER": "u", "PASS": "c1", "ENABLED": "1"},
                                {"id": "p002", "USER": "u", "PASS": "c2", "ENABLED": "1"}])

    def tearDown(self):
        self.n.quitar_nodo()
        sys.modules.pop("mikrotik_init", None)
        _dash.restaurar()
        self.tmp.cleanup()


class Espejo(Base):
    def setUp(self):
        super().setUp()
        self.llamadas = []
        mi = types.ModuleType("mikrotik_init")

        def plan(con, pid, sensor, puerto, redes, lista):
            # la forma REAL de mikrotik_init.plan(): `terminal` + `cambios` (no `lineas`: F1, A-01)
            self.llamadas.append(("plan", con.router_id, pid, sensor, puerto, tuple(redes), lista))
            return {"pid": pid, "sensor": sensor, "puerto": puerto, "lista": lista, "redes": list(redes),
                    "terminal": ["/ip firewall mangle add action=sniff-tzsp sniff-target=%s" % sensor],
                    "cambios": [{"que": "espejo", "orden": "/ip/firewall/mangle/add",
                                 "args": ["=action=sniff-tzsp", "=sniff-target=%s" % sensor]}],
                    "avisos": [], "bloqueos": [], "fasttrack": []}

        def aplicar(con, p, respaldo_dir):
            self.llamadas.append(("aplicar", con.router_id, os.path.isdir(respaldo_dir)))
            return {"ok": True, "mensaje": "aplicado"}

        def pausar(con, pid, respaldo_dir):
            self.llamadas.append(("pausar", con.router_id, pid))
            return (True, "pausado")
        mi.plan, mi.aplicar, mi.pausar = plan, aplicar, pausar
        mi.retirar = lambda con, pid, r: (_ for _ in ()).throw(RuntimeError("el router no contesto"))
        sys.modules["mikrotik_init"] = mi

    def test_plan_y_aplicar_con_los_datos_del_punto(self):
        """Tipo: capacidad nueva (§4). El espejo de p002 se planifica y aplica por el router
        de p002, con su sensor, su puerto TZSP y sus prefijos; el resultado tiene la forma
        {ok, mensaje, lineas, avisos}."""
        r = self.d.espejo_plan("p002")
        self.assertEqual((r["ok"], r["lineas"][0][-10:]), (True, "100.64.2.1"))
        self.assertEqual(self.llamadas[0], ("plan", "p002", "p002", "100.64.2.1", 37008,
                                            ("10.0.0.0/24",), "ids-vigilados"))
        r = self.d.espejo_aplicar("p002", "admin", huella=r["huella"])   # la del plan mostrado
        self.assertEqual((r["ok"], r["mensaje"]), (True, "aplicado"))
        self.assertEqual([c[:2] for c in self.llamadas[1:]], [("plan", "p002"), ("aplicar", "p002")])
        self.assertTrue(self.llamadas[-1][2])                    # hay directorio de respaldos
        self.assertEqual(self.d.espejo_pausar("p002")["mensaje"], "pausado")
        self.assertNotIn("p001", {c[1] for c in self.llamadas})

    def test_fallo_y_destino_invalido(self):
        """Tipo: capacidad nueva. Un fallo del router vuelve como ok=False con el motivo;
        un pid mal formado o inexistente lanza (400/404) sin tocar ningun router."""
        r = self.d.espejo_retirar("p001", "admin")
        self.assertEqual((r["ok"], r["mensaje"]), (False, "el router no contesto"))
        with self.assertRaises(self.n.NodoInvalido):
            self.d.espejo_plan("_todos")
        with self.assertRaises(self.n.NodoInexistente):
            self.d.espejo_aplicar("p009")
        self.assertEqual([c for c in self.llamadas if c[0] != "retirar"], [])


class Baja(Base):
    def test_purgar_punto_no_toca_el_otro(self):
        """Tipo: capacidad nueva (§5, caso «baja»). La baja borra lo de p001 (claves p001|...,
        su router, sus exclusiones, sus publicas, nodos/p001/) y deja intacto p002."""
        for path in (self.d.MK_SENT, self.d.MK_SENT_DNS):
            with open(path, "w", encoding="utf-8") as f:
                json.dump({K1: {"cuando": 1}, K2: {"cuando": 1}}, f)
        with open(self.d.ABONADOS_FILE, "w", encoding="utf-8") as f:
            json.dump({"ts": 1, "mapa": {K1: {"nombre": "a"}, K2: {"nombre": "b"}}}, f)
        self.d.guardar_publicas({"p001": ["192.0.2.0/29"], "p002": ["198.51.100.0/29"]})
        self.d.ORQ_TRANSPORTE = lambda pet: {"op_id": pet["op_id"], "ok": True, "codigo": "ACEPTADA"}
        self.d.guardar_exclusiones([{"tipo": "src", "ip": _dash.IP, "motivo": "x", "nodo": "p001"},
                                    {"tipo": "src", "ip": _dash.IP, "motivo": "y", "nodo": "p002"}])
        self.a.salida("p001", "cuarentena.json", {})
        self.a.salida("p002", "cuarentena.json", {})
        h = self.d.purgar_punto("p001")
        self.assertEqual(h["cuarentena-enviados.json"], 1)
        for path in (self.d.MK_SENT, self.d.MK_SENT_DNS):
            self.assertEqual(sorted(self.d.cargar_enviados(path)), [K2])
        self.assertEqual(sorted(self.d.cargar_abonados()["mapa"]), [K2])
        self.assertEqual(sorted(self.d.cargar_publicas()), ["p002"])
        self.assertEqual([r["nodo"] for r in self.d.cargar_exclusiones()], ["p002"])
        g = json.load(open(self.d.ROUTERS_CONF, encoding="utf-8"))["routers"]
        self.assertEqual(sorted(g), ["p002"])
        self.assertFalse(os.path.exists(os.path.join(self.a.panel, "nodos", "p001")))
        self.assertTrue(os.path.exists(os.path.join(self.a.panel, "nodos", "p002", "cuarentena.json")))
        with self.assertRaises(self.n.NodoInvalido):
            self.d.purgar_punto("../p002")


class Redirecciones(Base):
    def test_aviso_conserva_el_nodo(self):
        """Tipo: capacidad nueva. La redireccion tras una accion vuelve al nodo que se miraba."""
        with self.n.contexto("p002"):
            url = self.d.cuar_aviso_url("hecho")
        self.assertTrue(url.startswith("/cuarentena?msg="))
        self.assertTrue(url.endswith("&nodo=p002"))
        with self.n.contexto(self.n.TODOS):
            self.assertTrue(self.d.rep_aviso_url("hecho").endswith("&nodo=_todos"))

    def test_historial_de_abonado_por_punto(self):
        """Tipo: corrección de defecto. Quien tenia 10.0.0.5 se busca en SU punto: con la
        misma IP en dos puntos son dos abonados distintos."""
        self.d._registrar_hist_abonados({K1: {"nombre": "abonado-norte"}, K2: {"nombre": "abonado-sur"}})
        import time
        t = time.time() + 5
        self.assertEqual(self.d.historial_abonado(_dash.IP, t, "p002")["nombre"], "abonado-sur")
        with self.n.contexto("p001"):
            self.assertEqual(self.d.historial_abonado(_dash.IP, t)["nombre"], "abonado-norte")
        with self.n.contexto(self.n.TODOS):
            self.assertEqual(self.d.historial_abonado(_dash.IP, t), {})
        self.assertEqual(self.d.abonado_de(_dash.IP, "p002", {K1: {"n": 1}, K2: {"n": 2}}), {"n": 2})


if __name__ == "__main__":
    unittest.main()
