"""mikrotik_init: fallos, respaldos, plan desactualizado y validacion de datos.

Cada prueba dice su tipo (CONTRATO-F2 §10.5). MikroTik simulado (tests/_mikrotik_simulado.py),
sin red; datos RFC 5737 / 10.x.
"""
import os
import sys
import tempfile
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(os.path.dirname(AQUI), "images", "panel", "rootfs", "usr", "local", "lib",
                   "ids-panel")
for _p in (AQUI, LIB):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import mikrotik_init as mk  # noqa: E402
import _mikrotik_simulado as sim  # noqa: E402

PID = "p003"
COM = "IDS ids-maat:p003"
FI, MG, AL = sim.TABLAS


def mios(router):
    return {t: [f for f in router.tablas[t] if f.get("comment") == COM] for t in sim.TABLAS}


def forma(router):
    """Las tablas sin los .id (que dependen del orden de las escrituras)."""
    return {t: [{k: v for k, v in f.items() if k != ".id"} for f in router.tablas[t]]
            for t in sim.TABLAS}


class Fallos(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.resp = os.path.join(self.tmp.name, "respaldos-mk")

    def plan(self, r, redes=None):
        return mk.plan(r.conexion(), PID, sim.SENSOR, sim.PUERTO, redes or sim.REDES)

    def referencia(self):
        r = sim.router_isp()
        self.assertTrue(mk.aplicar(r.conexion(), self.plan(r), self.resp)["ok"])
        return forma(r)

    def test_fallo_a_mitad_para_y_lo_dice(self):
        """Conservacion (heredado: para en el PRIMER fallo): con un !trap inyectado en la 3.a
        orden se aplican solo las dos primeras, se dice cual fallo y que queda; el plan
        siguiente completa lo que falta sin duplicar."""
        r = sim.router_isp()
        p = self.plan(r)
        r.fallar_en = 3
        res = mk.aplicar(r.conexion(), p, self.resp)
        self.assertFalse(res["ok"])
        self.assertEqual(res["hechos"], [c["que"] for c in p["cambios"][:2]])
        self.assertIn(p["cambios"][2]["que"], res["fallo"])
        self.assertEqual(res["sin_aplicar"], [c["que"] for c in p["cambios"][2:]])
        self.assertEqual(len(r.escrituras), 2)
        r.fallar_en = None
        p2 = self.plan(r)
        self.assertEqual(len(p2["cambios"]), len(p["cambios"]) - 2)
        self.assertTrue(mk.aplicar(r.conexion(), p2, self.resp)["ok"])
        self.assertEqual(forma(r), self.referencia())

    def test_timeout_tras_enviar_se_relee(self):
        """Capacidad nueva (§10.5 timeout de la API tras enviar una orden): la 4.a orden se
        aplica pero el router no contesta; aplicar para y no la da por hecha; con otra
        conexion el plan relee el router, no la repite y el resultado no tiene duplicados."""
        r = sim.router_isp()
        p = self.plan(r)
        r.colgar_en = 4
        res = mk.aplicar(r.conexion(), p, self.resp)
        self.assertFalse(res["ok"])
        self.assertEqual(len(res["hechos"]), 3)
        self.assertIn("sin respuesta", res["fallo"])
        self.assertEqual(len(r.escrituras), 4)
        r.colgar_en = None
        p2 = self.plan(r)
        self.assertEqual(len(p2["cambios"]), len(p["cambios"]) - 4)
        self.assertTrue(mk.aplicar(r.conexion(), p2, self.resp)["ok"])
        self.assertEqual(forma(r), self.referencia())
        self.assertEqual(len(mios(r)[MG]), 2)

    def test_sin_export_no_se_toca_nada(self):
        """Conservacion (heredado: sin respaldo no se toca nada): si el /export del router falla,
        no hay ninguna escritura."""
        r = sim.router_isp()
        antes = r.instantanea()
        p = self.plan(r)
        r.fallar_export = True
        res = mk.aplicar(r.conexion(), p, self.resp)
        self.assertFalse(res["ok"])
        self.assertIn("/export", res["fallo"])
        self.assertEqual((r.escrituras, res["hechos"], res["export"]), ([], [], None))
        self.assertEqual(r.instantanea(), antes)

    def test_sin_respaldo_local_no_se_toca_nada(self):
        """Capacidad nueva: si no se puede escribir el JSON local, ni siquiera se hace el
        /export y el router queda igual."""
        r = sim.router_isp()
        antes = r.instantanea()
        p = self.plan(r)
        no_dir = os.path.join(self.tmp.name, "un-fichero")
        with open(no_dir, "w") as fh:
            fh.write("x")
        res = mk.aplicar(r.conexion(), p, no_dir)
        self.assertFalse(res["ok"])
        self.assertEqual((r.escrituras, r.exports, res["respaldo"]), ([], [], None))
        self.assertEqual(r.instantanea(), antes)

    def test_pausar_y_retirar_sin_export_no_tocan(self):
        """Capacidad nueva: pausar y retirar tambien exigen el /export antes de escribir."""
        r = sim.router_isp()
        res = mk.aplicar(r.conexion(), self.plan(r), self.resp)
        tras = r.instantanea()
        n = len(r.escrituras)
        r.fallar_export = True
        self.assertFalse(mk.pausar(r.conexion(), PID)["ok"])
        self.assertFalse(mk.retirar(r.conexion(), PID, res["respaldo"])["ok"])
        self.assertEqual(len(r.escrituras), n)
        self.assertEqual(r.instantanea(), tras)

    def test_plan_desactualizado_no_se_aplica(self):
        """Capacidad nueva: si el router cambio entre la vista previa y aplicar (otra lista de
        cambios), no se escribe nada y se devuelve el plan nuevo."""
        r = sim.router_isp()
        p = self.plan(r)
        r.cargar(FI, [{"chain": "forward", "action": "fasttrack-connection",
                       "connection-state": "established", "comment": "otro fasttrack"}])
        res = mk.aplicar(r.conexion(), p, self.resp)
        self.assertFalse(res["ok"])
        self.assertEqual((r.escrituras, r.exports, res["respaldo"]), ([], [], None))
        self.assertGreater(len(res["plan"]["cambios"]), len(p["cambios"]))
        self.assertTrue(mk.aplicar(r.conexion(), res["plan"], self.resp)["ok"])

    def test_print_fallido_no_es_tabla_vacia(self):
        """Correccion de defecto: el _mk_print del panel devuelve [] si el router rechaza el print,
        y con eso el plan volveria a crear los espejos (dos a la vez llenando el enlace). Aqui
        un print fallido es ErrorRouter y aplicar no escribe nada."""
        r = sim.router_isp()
        self.assertTrue(mk.aplicar(r.conexion(), self.plan(r), self.resp)["ok"])
        n = len(r.escrituras)
        r.fallar_print = MG + "/print"
        with self.assertRaises(mk.ErrorRouter):
            self.plan(r)
        p = {"pid": PID, "sensor": sim.SENSOR, "puerto": sim.PUERTO, "redes": sim.REDES,
             "lista": "ids-vigilados", "cambios": []}
        res = mk.aplicar(r.conexion(), p, self.resp)
        self.assertFalse(res["ok"])
        self.assertEqual(len(r.escrituras), n)
        self.assertEqual(len(mios(r)[MG]), 2)

    def test_datos_invalidos(self):
        """Capacidad nueva: pid (nodos.pid_valido), sensor, puerto, lista y redes se validan
        antes de leer el router; IPv6 es un error claro (fuera de esta version)."""
        r = sim.router_isp()
        malos = [
            dict(pid="p03"), dict(pid="../p003"), dict(pid=None),
            dict(sensor="192.0.2.300"), dict(sensor="2001:db8::1"),
            dict(puerto=0), dict(puerto="x"),
            dict(redes=["10.0.0.0/33"]), dict(redes=["2001:db8::/32"]),
            dict(lista="mi lista"), dict(lista="!ids"),
        ]
        for m in malos:
            kw = dict(pid=PID, sensor=sim.SENSOR, puerto=sim.PUERTO, redes=sim.REDES)
            kw.update(m)
            lista = kw.pop("lista", "ids-vigilados")
            with self.assertRaises(mk.DatosInvalidos, msg=m) as cm:
                mk.plan(r.conexion(), kw["pid"], kw["sensor"], kw["puerto"], kw["redes"], lista)
            if "2001" in str(m):
                self.assertIn("IPv6", str(cm.exception))
        self.assertEqual(r.escrituras, [])
        with self.assertRaises(mk.DatosInvalidos):
            mk.pausar(r.conexion(), "p3")
        self.assertFalse(mk.retirar(r.conexion(), "todos", None)["ok"])
        # redes como texto, sin estricto y sin duplicar
        p = mk.plan(r.conexion(), PID, sim.SENSOR, "37008", " 10.0.0.7/24, 10.0.0.0/24,10.0.3.4/32 ")
        self.assertEqual(p["redes"], ["10.0.0.0/24", "10.0.3.4"])

    def test_respaldo_de_otro_punto(self):
        """Capacidad nueva: retirar con el respaldo de otro punto no toca nada."""
        r = sim.router_isp()
        res = mk.aplicar(r.conexion(), self.plan(r), self.resp)
        n = len(r.escrituras)
        ret = mk.retirar(r.conexion(), "p004", res["respaldo"])
        self.assertFalse(ret["ok"])
        self.assertEqual(len(r.escrituras), n)

    def test_lista_usada_por_regla_ajena_bloquea(self):
        """Capacidad nueva (OPERACION §2 manda): si una regla filter ajena usa la lista, anadir
        redes cambiaria lo que deja pasar; el plan lo bloquea y aplicar no escribe nada."""
        r = sim.router_isp(extra_filter=[{"chain": "forward", "action": "accept",
                                          "src-address-list": "ids-vigilados",
                                          "comment": "accept vigilados"}])
        p = self.plan(r)
        self.assertEqual(len(p["bloqueos"]), 1)
        res = mk.aplicar(r.conexion(), p, self.resp)
        self.assertFalse(res["ok"])
        self.assertEqual((r.escrituras, r.exports), ([], []))

    def test_accept_viejo_del_punto_se_quita(self):
        """Correccion de defecto: la version anterior de OPERACION anadia un `accept` de los
        vigilados (connection-bytes=0-10000) ANTES del fasttrack, que se saltaba la cuarentena:
        un vigilado en cuarentena abria conexiones nuevas. Aplicar el espejo lo quita y la
        cuarentena vuelve a cortar."""
        r = sim.router_isp()
        ft = next(f[".id"] for f in r.tablas[FI] if f["action"] == "fasttrack-connection")
        r._anadir(FI, {"chain": "forward", "action": "accept", "src-address-list": "ids-vigilados",
                       "connection-bytes": "0-10000", "comment": COM}, antes=ft)
        r.cargar(AL, [{"list": "ids-vigilados", "address": "10.0.0.0/24", "comment": COM}])
        nueva = dict(src="10.0.0.66", dst=sim.REMOTO, in_if=sim.LAN, out_if=sim.WAN,
                     proto="tcp", dport=443, estado="new", bytes=0)
        self.assertEqual(r.paquete("c1", **nueva)["veredicto"], "accept")      # el defecto
        p = self.plan(r)
        self.assertTrue([c for c in p["cambios"] if c["orden"] == FI + "/remove"])
        self.assertTrue(mk.aplicar(r.conexion(), p, self.resp)["ok"])
        r.aceleradas = set()
        self.assertEqual(r.paquete("c2", **nueva)["veredicto"], "drop")
        self.assertFalse([f for t in sim.TABLAS for f in r.tablas[t] if f.get("comment") == COM
                          and f.get("action") == "accept"])

    def test_mangle_que_termina_la_cadena_se_avisa(self):
        """Capacidad nueva: un mangle forward que termina la cadena (accept) antes de los
        nuestros deja el espejo ciego para lo que case; el plan lo avisa y el simulador
        confirma que esos paquetes no llegan al sensor."""
        r = sim.router_isp(extra_mangle=[{"chain": "forward", "action": "accept",
                                          "src-address": "10.0.0.5", "comment": "no marcar"}])
        p = self.plan(r)
        aceptar = r.tablas[MG][-1][".id"]
        self.assertTrue([a for a in p["avisos"] if aceptar in a])
        self.assertTrue(mk.aplicar(r.conexion(), p, self.resp)["ok"])
        res = sim.recorrer(r, sim.bateria())
        ciego = [x for x in res[("vigilado:tcp-saliente", 0)]["espejo"] if x[0] == sim.SENSOR]
        visto = [x for x in res[("vigilado-2:tcp-saliente", 0)]["espejo"] if x[0] == sim.SENSOR]
        self.assertEqual((ciego, len(visto)), ([], 1))


if __name__ == "__main__":
    unittest.main()
