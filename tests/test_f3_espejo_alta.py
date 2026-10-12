"""El espejo nunca toca lo que el alta deja en el router (auditoria A-02).

El alta del punto pega en el MikroTik una regla `chain=input ... action=accept` para la API-SSL
desde el sensor, con el comentario del alta `IDS ids-maat:<pid>` (OPERACION §1.2/§1.3). Antes,
el espejo usaba ese MISMO comentario y aplicar/retirar la quitaban como «regla filter del punto
que ya no corresponde»: con la cadena input en drop, el panel se quedaba sin API en ese router.

Ahora el espejo usa su comentario propio `IDS ids-maat:<pid>:espejo` y, de lo que lleva el del
alta (espejos de versiones anteriores), solo reconoce lo que tiene forma de espejo (sniff-tzsp,
filter forward con la lista). Tipo de cada prueba en su docstring (CONTRATO-F2 §10.5). Todo
contra tests/_mikrotik_simulado.py; datos RFC 5737 / 10.x.
"""
import os
import re
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
ALTA = "IDS ids-maat:p003"
ESPEJO = "IDS ids-maat:p003:espejo"
FI, MG, AL = sim.TABLAS


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.resp = os.path.join(self.tmp.name, "respaldos-mk")

    def plan(self, r):
        return mk.plan(r.conexion(), PID, sim.SENSOR, sim.PUERTO, sim.REDES)

    def aplicar(self, r):
        res = mk.aplicar(r.conexion(), self.plan(r), self.resp)
        self.assertTrue(res["ok"], res)
        return res

    def tocados(self, r):
        """Los .id sobre los que el router recibio alguna escritura."""
        out = set()
        for _o, args in r.escrituras:
            for a in args:
                if a.startswith("=.id=") or a.startswith("=numbers="):
                    out.add(a.split("=", 2)[2])
        return out


class ReglaApiDelAlta(Base):
    def test_aplicar_pausar_retirar_no_tocan_la_regla_api(self):
        """Correccion de defecto (A-02): con la regla input de la API-SSL del alta en la tabla,
        el plan no la nombra, y aplicar, pausar y retirar la dejan exactamente igual. Antes:
        plan `/ip firewall filter remove <id>` y la regla desaparecia al aplicar."""
        r = sim.router_isp()
        api = sim.con_alta(r, PID)
        original = dict(r.fila(FI, api))
        antes = r.instantanea()
        p = self.plan(r)
        self.assertFalse([t for t in p["terminal"] if api in t.split()], p["terminal"])
        res = self.aplicar(r)
        self.assertEqual(r.fila(FI, api), original)
        self.assertEqual(r.tablas[FI][0][".id"], api, "sigue la primera de la tabla")
        self.assertTrue(mk.pausar(r.conexion(), PID, self.resp)["ok"])
        self.assertEqual(r.fila(FI, api), original)
        ret = mk.retirar(r.conexion(), PID, res["respaldo"])
        self.assertTrue(ret["ok"], ret)
        self.assertEqual(r.fila(FI, api), original)
        self.assertNotIn(api, self.tocados(r))
        # retirar devuelve el router a como estaba antes del espejo, regla del alta incluida
        self.assertEqual(r.instantanea(), antes)

    def test_lo_que_crea_el_espejo_lleva_su_comentario_propio(self):
        """Capacidad nueva: todo lo que crea el espejo lleva `IDS ids-maat:<pid>:espejo`; con el
        comentario del alta solo queda la regla de la API."""
        r = sim.router_isp()
        api = sim.con_alta(r, PID)
        self.aplicar(r)
        con_alta = [(t, f[".id"]) for t in sim.TABLAS for f in r.tablas[t] if f.get("comment") == ALTA]
        self.assertEqual(con_alta, [(FI, api)])
        espejo = {t: len([f for f in r.tablas[t] if f.get("comment") == ESPEJO]) for t in sim.TABLAS}
        self.assertEqual(espejo, {FI: 2, MG: 2, AL: 2})
        self.assertEqual(self.plan(r)["cambios"], [], "idempotente")

    def test_baja_manual_de_operacion_quita_espejo_y_alta(self):
        """Conservacion: la expresion de la baja manual (OPERACION §2.1) casa el comentario del
        espejo y el del alta, y no casa otro punto (`p0031`)."""
        rx = re.compile(r"ids-maat:p003(:|$)")
        self.assertTrue(rx.search(ESPEJO))
        self.assertTrue(rx.search(ALTA))
        self.assertFalse(rx.search("IDS ids-maat:p0031"))
        self.assertFalse(rx.search("IDS ids-maat:p0031:espejo"))


class RespaldoCorrupto(Base):
    def test_respaldo_corrupto_no_bloquea_retirar(self):
        """Corrección de defecto (A-21): si el último JSON de respaldo del punto está corrupto (corte
        a mitad), retirar usa el anterior válido y devuelve el fasttrack a su valor original."""
        r = sim.router_isp()
        antes = r.instantanea()
        res = self.aplicar(r)
        d = os.path.dirname(res["respaldo"])
        with open(os.path.join(d, "espejo-29991231-235959.json"), "w", encoding="utf-8") as f:
            f.write('{"pid": "p003", "fasttrack": {')          # el más reciente, a medias
        ret = mk.retirar(r.conexion(), PID, self.resp)
        self.assertTrue(ret["ok"], ret)
        self.assertEqual(r.instantanea(), antes)


class EspejoDeVersionAnterior(Base):
    def heredado(self):
        """Un router con el espejo montado por la version anterior (todo con el comentario del
        alta) y la regla de la API del alta."""
        r = sim.router_isp()
        api = sim.con_alta(r, PID)
        self.aplicar(r)
        for t in sim.TABLAS:
            for f in r.tablas[t]:
                if f.get("comment") == ESPEJO:
                    f["comment"] = ALTA
        r.escrituras = []
        return r, api

    def test_se_reconoce_y_pasa_al_comentario_propio(self):
        """Correccion de defecto / migracion: el espejo anterior se reconoce por su forma (no se
        duplica) y solo cambia de comentario; la regla de la API no se toca."""
        r, api = self.heredado()
        original = dict(r.fila(FI, api))
        p = self.plan(r)
        self.assertTrue(p["cambios"])
        self.assertEqual({c["orden"].rsplit("/", 1)[1] for c in p["cambios"]}, {"set"}, p["terminal"])
        self.aplicar(r)
        self.assertEqual(r.fila(FI, api), original)
        self.assertEqual([(t, f[".id"]) for t in sim.TABLAS for f in r.tablas[t] if f.get("comment") == ALTA],
                         [(FI, api)])
        self.assertEqual(self.plan(r)["cambios"], [])

    def test_pausar_y_retirar_el_anterior_sin_tocar_la_api(self):
        """Correccion de defecto: pausar apaga los sniff-tzsp anteriores y retirar los quita con
        sus fasttrack y su lista; la regla input de la API sigue igual."""
        r, api = self.heredado()
        original = dict(r.fila(FI, api))
        pa = mk.pausar(r.conexion(), PID, self.resp)
        self.assertTrue(pa["ok"], pa)
        self.assertEqual(sorted(f["disabled"] for f in r.tablas[MG] if f.get("comment") == ALTA),
                         ["true", "true"])
        ret = mk.retirar(r.conexion(), PID, self.resp)
        self.assertTrue(ret["ok"], ret)
        self.assertEqual(r.fila(FI, api), original)
        self.assertEqual([(t, f[".id"]) for t in sim.TABLAS for f in r.tablas[t] if f.get("comment") == ALTA],
                         [(FI, api)])
        self.assertNotIn(api, self.tocados(r))


if __name__ == "__main__":
    unittest.main()
