"""mikrotik_init como modulo: el espejo de OPERACION.md §2 sobre un MikroTik simulado.

Cada prueba dice su tipo (CONTRATO-F2 §10.5): conservacion, correccion de defecto o
capacidad nueva. Todo contra tests/_mikrotik_simulado.py (protocolo binario real de la API,
sin red); datos RFC 5737 / 10.x.
"""
import json
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


def mios(router, tabla):
    return [f for f in router.tablas[tabla] if f.get("comment") == COM]


def espejados(res):
    return [r for r in res["espejo"] if r == (sim.SENSOR, str(sim.PUERTO))]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.resp = os.path.join(self.tmp.name, "respaldos-mk")

    def plan(self, router, redes=None, **kw):
        return mk.plan(router.conexion(), PID, sim.SENSOR, sim.PUERTO,
                       sim.REDES if redes is None else redes, **kw)

    def aplicar(self, router, redes=None):
        p = self.plan(router, redes)
        return mk.aplicar(router.conexion(), p, self.resp)


class Montar(Base):
    def test_reglas_exactas_de_operacion(self):
        """Capacidad nueva: lo creado es exactamente OPERACION §2 (lista, dos mangle con
        connection-bytes=0-10000, fasttrack excluido + dos fasttrack de vigilados pasados 10 KB
        justo detras), todo con el comentario del punto y ninguna regla accept."""
        r = sim.router_isp()
        ft = next(f[".id"] for f in r.tablas[FI] if f["action"] == "fasttrack-connection")
        res = self.aplicar(r)
        self.assertTrue(res["ok"], res)
        al = sorted(f["address"] for f in mios(r, AL))
        self.assertEqual(al, ["10.0.0.0/24", "10.0.1.0/24"])
        mg = mios(r, MG)
        self.assertEqual(len(mg), 2)
        for f in mg:
            self.assertEqual((f["chain"], f["action"], f["sniff-target"], f["sniff-target-port"],
                              f["connection-bytes"], f["passthrough"], f["disabled"]),
                             ("forward", "sniff-tzsp", sim.SENSOR, "37008", "0-10000", "true", "false"))
        self.assertEqual(sorted((f.get("src-address-list", ""), f.get("dst-address-list", ""))
                                for f in mg), [("", "ids-vigilados"), ("ids-vigilados", "")])
        regla = r.fila(FI, ft)
        self.assertEqual((regla["src-address-list"], regla["dst-address-list"]),
                         ("!ids-vigilados", "!ids-vigilados"))
        orden = [f[".id"] for f in r.tablas[FI]]
        i = orden.index(ft)
        nuevas = r.tablas[FI][i + 1:i + 3]
        for f, campo in zip(nuevas, ("src-address-list", "dst-address-list")):
            self.assertEqual(f["comment"], COM)
            self.assertEqual(f["action"], "fasttrack-connection")
            self.assertEqual(f[campo], "ids-vigilados")
            self.assertEqual(f["connection-bytes"], "10000-0")
            # las MISMAS condiciones que la fasttrack original
            self.assertEqual((f["connection-state"], f["hw-offload"]), ("established,related", "true"))
        self.assertEqual(r.tablas[FI][i + 3]["comment"], "defconf: accept established,related")
        for t in sim.TABLAS:
            self.assertFalse([f for f in mios(r, t) if f.get("action") == "accept"])
        self.assertEqual(r.exports, [res["export"]])
        self.assertRegex(res["export"], r"^ids-maat-p003-\d{8}-\d{6}$")

    def test_vista_previa_es_lo_que_se_aplica(self):
        """Capacidad nueva: plan() no escribe nada y aplicar() ejecuta exactamente sus cambios,
        en su orden; `terminal` es la misma lista en sintaxis de terminal."""
        r = sim.router_isp()
        antes = r.instantanea()
        p = self.plan(r)
        self.assertEqual(r.instantanea(), antes)
        self.assertEqual(r.escrituras, [])
        self.assertEqual(len(p["terminal"]), len(p["cambios"]))
        self.assertEqual(p["identidad"], "router-lab")
        res = mk.aplicar(r.conexion(), p, self.resp)
        self.assertTrue(res["ok"], res)
        self.assertEqual([(o, a) for o, a in r.escrituras],
                         [(c["orden"], c["args"]) for c in p["cambios"]])
        self.assertEqual(res["hechos"], [c["que"] for c in p["cambios"]])
        ft = p["fasttrack"]
        self.assertEqual(len(ft), 1)
        self.assertEqual((ft[0]["accion"], ft[0]["src-address-list"], ft[0]["dst-address-list"]),
                         ("excluir", "", ""))

    def test_respaldo_json_local(self):
        """Capacidad nueva: aplicar deja el JSON del respaldo (0600 en POSIX) con las tablas
        leidas y los valores originales del fasttrack."""
        r = sim.router_isp()
        ft = next(f[".id"] for f in r.tablas[FI] if f["action"] == "fasttrack-connection")
        antes = r.instantanea()
        res = self.aplicar(r)
        ruta = res["respaldo"]
        self.assertEqual(os.path.dirname(ruta), os.path.join(self.resp, PID))
        self.assertRegex(os.path.basename(ruta), r"^espejo-\d{8}-\d{6}\.json$")
        with open(ruta, encoding="utf-8") as fh:
            d = json.load(fh)
        self.assertEqual(d["filter"], antes[FI])
        self.assertEqual(d["mangle"], antes[MG])
        self.assertEqual(d["fasttrack"], {ft: {"src-address-list": "", "dst-address-list": ""}})
        self.assertEqual(d["export"], res["export"])
        if os.name == "posix":
            self.assertEqual(os.stat(ruta).st_mode & 0o777, 0o600)
        self.assertEqual(mk.ultimo_respaldo(self.resp, PID), ruta)

    def test_idempotente(self):
        """Capacidad nueva (§10.5 doble clic): aplicar dos veces no duplica nada; la segunda
        no tiene cambios, no hace respaldos y las tablas quedan identicas."""
        r = sim.router_isp()
        self.assertTrue(self.aplicar(r)["ok"])
        tras1 = r.instantanea()
        n_exp = len(r.exports)
        p2 = self.plan(r)
        self.assertEqual(p2["cambios"], [])
        self.assertEqual(p2["fasttrack"][0]["accion"], "ya-excluida")
        res2 = mk.aplicar(r.conexion(), p2, self.resp)
        self.assertTrue(res2["ok"])
        self.assertEqual((res2["hechos"], res2["respaldo"], res2["export"]), ([], None, None))
        self.assertEqual(r.instantanea(), tras1)
        self.assertEqual(len(r.exports), n_exp)

    def test_espejo_dos_direcciones_hasta_10k(self):
        """Capacidad nueva: tras aplicar, el espejo ve las dos direcciones de los vigilados por
        debajo de 10 KB, deja de verlos al acelerarse pasados 10 KB, y nunca ve a los demas."""
        r = sim.router_isp()
        bat = sim.bateria()
        antes = sim.recorrer(r, bat)
        self.assertFalse([k for k, v in antes.items() if espejados(v)])
        self.assertTrue(self.aplicar(r)["ok"])
        desp = sim.recorrer(r, bat)
        sale = "vigilado:tcp-saliente"
        vistos = [n for n in range(7) if espejados(desp[(sale, n)])]
        self.assertEqual(vistos, [0, 1, 2, 3])          # ida y vuelta, todo lo de <=10 KB
        self.assertTrue(desp[(sale, 5)]["acelerada"])     # acelerada desde el de 12 KB
        self.assertTrue(desp[(sale, 6)]["acelerada"])
        self.assertEqual([n for n in range(7) if espejados(desp[("vigilado-2:tcp-saliente", n)])],
                         [0, 1, 2, 3])
        # antes, el vigilado se aceleraba en el primer paquete establecido
        self.assertTrue(antes[(sale, 2)]["acelerada"])
        for k, v in desp.items():
            if k[0].startswith("no-vigilado"):
                self.assertEqual(espejados(v), [], k)
        # los no vigilados se siguen acelerando igual que antes
        for k in antes:
            if k[0].startswith("no-vigilado"):
                self.assertEqual(antes[k]["acelerada"], desp[k]["acelerada"], k)

    def test_pausar(self):
        """Capacidad nueva: pausar deshabilita solo nuestros dos mangle (tras un /export) y deja
        el fasttrack como esta; el espejo deja de ver nada; volver a aplicar los habilita."""
        r = sim.router_isp()
        self.assertTrue(self.aplicar(r)["ok"])
        filtro = r.instantanea()[FI]
        res = mk.pausar(r.conexion(), PID)
        self.assertTrue(res["ok"], res)
        self.assertEqual(r.exports[-1], res["export"])
        self.assertEqual([f["disabled"] for f in mios(r, MG)], ["true", "true"])
        self.assertEqual(r.tablas[FI], filtro)
        ajeno = next(f for f in r.tablas[MG] if f.get("comment") == "IDS ids-maat:p004")
        self.assertEqual(ajeno["disabled"], "false")
        self.assertFalse([k for k, v in sim.recorrer(r, sim.bateria()).items() if espejados(v)])
        self.assertEqual(mk.pausar(r.conexion(), PID)["hechos"], [])     # ya pausado
        p = self.plan(r)
        self.assertEqual([c["orden"] for c in p["cambios"]], [MG + "/set", MG + "/set"])
        self.assertTrue(mk.aplicar(r.conexion(), p, self.resp)["ok"])
        self.assertEqual([f["disabled"] for f in mios(r, MG)], ["false", "false"])

    def test_retirar_deja_las_tablas_como_estaban(self):
        """Capacidad nueva: retirar (con el respaldo de aplicar) deja filter, mangle y
        address-list identicas a las originales, haciendo antes un /export."""
        r = sim.router_isp()
        antes = r.instantanea()
        res = self.aplicar(r)
        n_exp = len(r.exports)
        ret = mk.retirar(r.conexion(), PID, res["respaldo"])
        self.assertTrue(ret["ok"], ret)
        self.assertEqual(len(r.exports), n_exp + 1)
        self.assertEqual(r.exports[-1], ret["export"])
        self.assertEqual(r.instantanea(), antes)
        self.assertEqual(mk.retirar(r.conexion(), PID, res["respaldo"])["cambios"], [])

    def test_retirar_nunca_toca_ajenas(self):
        """Capacidad nueva: reglas y entradas ajenas con comentarios parecidos
        (`ids-maat:p0031`, `IDS ids-maat:p004`, `IDS ids-maat:p003 manual`) sobreviven a
        aplicar y retirar sin cambiar; una red que ya estaba en la lista sin nuestro
        comentario no se duplica ni se borra."""
        r = sim.router_isp(
            extra_filter=[{"chain": "forward", "action": "passthrough",
                           "comment": "IDS ids-maat:p003 manual"}],
            extra_mangle=[{"chain": "prerouting", "action": "passthrough", "comment": "ids-maat:p0031"}],
            extra_al=[{"list": "ids-vigilados", "address": "10.0.1.0/24", "comment": "puesta a mano"}])
        antes = r.instantanea()
        res = self.aplicar(r)
        self.assertTrue(res["ok"], res)
        self.assertEqual([f["address"] for f in r.tablas[AL] if f["list"] == "ids-vigilados"
                          and f["address"] == "10.0.1.0/24"], ["10.0.1.0/24"])
        self.assertTrue(mk.retirar(r.conexion(), PID, res["respaldo"])["ok"])
        self.assertEqual(r.instantanea(), antes)
        quitadas = [a for o, a in r.escrituras if o.endswith("/remove")]
        ids_ajenos = {f[".id"] for t in sim.TABLAS for f in antes[t]}
        self.assertFalse([a for a in quitadas if a[0][len("=.id="):] in ids_ajenos])

    def test_prefijos_editables(self):
        """Capacidad nueva (§9): cambiar las redes del punto quita las nuestras que sobran y anade
        las nuevas, sin tocar el resto."""
        r = sim.router_isp()
        self.assertTrue(self.aplicar(r)["ok"])
        p = self.plan(r, ["10.0.0.0/24", "10.0.2.9/32"])
        self.assertEqual([c["orden"] for c in p["cambios"]], [AL + "/add", AL + "/remove"])
        self.assertTrue(mk.aplicar(r.conexion(), p, self.resp)["ok"])
        self.assertEqual(sorted(f["address"] for f in mios(r, AL)), ["10.0.0.0/24", "10.0.2.9"])
        self.assertEqual(self.plan(r, ["10.0.0.0/24", "10.0.2.9"])["cambios"], [])

    def test_espejo_viejo_hacia_el_sensor_se_apaga(self):
        """Conservacion (heredado): un espejo ajeno hacia el mismo sensor se apaga (no se borra)
        antes de crear los nuestros; uno hacia otro sensor no se toca. Retirar no lo
        vuelve a encender (queda documentado: se apago a proposito)."""
        r = sim.router_isp(extra_mangle=[
            {"chain": "forward", "action": "sniff-tzsp", "sniff-target": sim.SENSOR,
             "sniff-target-port": "37008", "src-address-list": "ids-vigilados",
             "comment": "espejo IDS (ida)"}])
        viejo = r.tablas[MG][-1][".id"]
        antes = r.instantanea()
        p = self.plan(r)
        apagar = [i for i, c in enumerate(p["cambios"]) if c["args"] == ["=.id=" + viejo, "=disabled=yes"]]
        crear = [i for i, c in enumerate(p["cambios"]) if c["orden"] == MG + "/add"]
        self.assertEqual(len(apagar), 1)
        self.assertLess(apagar[0], min(crear))
        res = mk.aplicar(r.conexion(), p, self.resp)
        self.assertTrue(res["ok"])
        self.assertEqual(r.fila(MG, viejo)["disabled"], "true")
        otro = next(f for f in r.tablas[MG] if f.get("sniff-target") == "203.0.113.9")
        self.assertEqual(otro["disabled"], "false")
        # cada paquete vigilado llega UNA vez al sensor, no dos
        res_p = sim.recorrer(r, sim.bateria())
        self.assertEqual(len(espejados(res_p[("vigilado:tcp-saliente", 0)])), 1)
        self.assertTrue(mk.retirar(r.conexion(), PID, res["respaldo"])["ok"])
        despues = r.instantanea()
        self.assertEqual(despues[MG][-1]["disabled"], "true")
        despues[MG][-1]["disabled"] = "false"
        self.assertEqual(despues, antes)


class Fasttrack(Base):
    def test_fasttrack_con_address_list_no_se_toca(self):
        """Capacidad nueva: una fasttrack que ya usa address-lists no se modifica, no lleva
        fasttrack de vigilados y el plan lo avisa con su .id."""
        r = sim.router_isp(con_fasttrack=False)
        r.tablas[FI].insert(1, {".id": "*F1", "chain": "forward", "action": "fasttrack-connection",
                                "connection-state": "established,related",
                                "src-address-list": "clientes-vip", "disabled": "false"})
        antes = dict(r.fila(FI, "*F1"))
        p = self.plan(r)
        ft = p["fasttrack"][0]
        self.assertEqual((ft[".id"], ft["accion"], ft["src-address-list"]), ("*F1", "no-se-toca", "clientes-vip"))
        self.assertTrue([a for a in p["avisos"] if "*F1" in a])
        self.assertTrue(mk.aplicar(r.conexion(), p, self.resp)["ok"])
        self.assertEqual(r.fila(FI, "*F1"), antes)
        self.assertEqual(mios(r, FI), [])

    def test_fasttrack_deshabilitada_no_se_toca(self):
        """Capacidad nueva (decision): una fasttrack deshabilitada no acelera nada: no se
        modifica ni lleva fasttrack de vigilados; el plan avisa de volver a aplicar si se
        habilita."""
        r = sim.router_isp()
        ft = next(f for f in r.tablas[FI] if f["action"] == "fasttrack-connection")
        ft["disabled"] = "true"
        antes = dict(ft)
        p = self.plan(r)
        self.assertEqual(p["fasttrack"][0]["accion"], "no-se-toca")
        self.assertTrue(mk.aplicar(r.conexion(), p, self.resp)["ok"])
        self.assertEqual(r.fila(FI, antes[".id"]), antes)
        self.assertEqual(mios(r, FI), [])

    def test_sin_fasttrack_solo_lista_y_mangle(self):
        """Capacidad nueva: sin fasttrack solo van la address-list y los dos mangle."""
        r = sim.router_isp(con_fasttrack=False)
        filtro = r.instantanea()[FI]
        p = self.plan(r)
        self.assertEqual(p["fasttrack"], [])
        self.assertEqual(sorted({c["orden"] for c in p["cambios"]}), [AL + "/add", MG + "/add"])
        self.assertTrue(mk.aplicar(r.conexion(), p, self.resp)["ok"])
        self.assertEqual(r.tablas[FI], filtro)

    def test_varias_fasttrack_y_condiciones_copiadas(self):
        """Capacidad nueva: con varias fasttrack se tratan todas igual; las nuevas copian todas
        las condiciones (interfaces, protocolo, connection-mark, hw-offload) y no los
        contadores, el comentario ni el estado; la ultima regla de la tabla va sin place-before."""
        r = sim.router_isp()
        r.cargar(FI, [{"chain": "forward", "action": "fasttrack-connection",
                       "connection-state": "established", "connection-mark": "no-mark",
                       "in-interface": "ether3", "protocol": "udp", "hw-offload": "no",
                       "log-prefix": "ft2", "comment": "fasttrack udp", "bytes": "123456",
                       "packets": "99"}])
        ft2 = r.tablas[FI][-1][".id"]
        p = self.plan(r)
        self.assertEqual([f["accion"] for f in p["fasttrack"]], ["excluir", "excluir"])
        adds = [c["args"] for c in p["cambios"] if c["orden"] == FI + "/add"]
        self.assertEqual(len(adds), 4)
        ult = [a for a in adds if "=in-interface=ether3" in a]
        self.assertEqual(len(ult), 2)
        for a in ult:
            self.assertFalse([x for x in a if x.startswith("=place-before=")])
            for x in ("=connection-state=established", "=connection-mark=no-mark",
                      "=protocol=udp", "=hw-offload=false", "=connection-bytes=10000-0",
                      "=comment=" + COM):
                self.assertIn(x, a)
            for x in a:
                self.assertFalse(x.split("=")[1] in ("bytes", "packets", "disabled", "log-prefix",
                                                     ".id"), x)
        self.assertTrue(mk.aplicar(r.conexion(), p, self.resp)["ok"])
        self.assertEqual(r.fila(FI, ft2)["src-address-list"], "!ids-vigilados")
        self.assertEqual([f["comment"] for f in r.tablas[FI][-2:]], [COM, COM])
        self.assertEqual(self.plan(r)["cambios"], [])

    def test_estado_del_instalador_anterior(self):
        """Conservacion/migracion: el mkinit heredado dejaba `src-address-list=!ids-vigilados`
        solo en src. Se completa con dst, el respaldo guarda el valor de entonces y retirar lo
        devuelve tal cual."""
        r = sim.router_isp()
        ft = next(f for f in r.tablas[FI] if f["action"] == "fasttrack-connection")
        ft["src-address-list"] = "!ids-vigilados"
        antes = r.instantanea()
        p = self.plan(r)
        self.assertEqual(p["fasttrack"][0]["accion"], "excluir")
        res = mk.aplicar(r.conexion(), p, self.resp)
        self.assertEqual(r.fila(FI, ft[".id"])["dst-address-list"], "!ids-vigilados")
        self.assertTrue(mk.retirar(r.conexion(), PID, res["respaldo"])["ok"])
        self.assertEqual(r.instantanea(), antes)

    def test_ya_excluida_sin_respaldo(self):
        """Capacidad nueva: una fasttrack con `!<lista>` en los dos campos cuenta como hecha
        (solo se anaden las de vigilados); retirar sin respaldo le quita esos dos valores."""
        r = sim.router_isp()
        ft = next(f for f in r.tablas[FI] if f["action"] == "fasttrack-connection")
        original = dict(ft)
        ft["src-address-list"] = ft["dst-address-list"] = "!ids-vigilados"
        p = self.plan(r)
        self.assertEqual(p["fasttrack"][0]["accion"], "ya-excluida")
        self.assertFalse([c for c in p["cambios"] if c["orden"] == FI + "/set"])
        self.assertTrue(mk.aplicar(r.conexion(), p, self.resp)["ok"])
        ret = mk.retirar(r.conexion(), PID, None)
        self.assertTrue(ret["ok"], ret)
        self.assertEqual(r.fila(FI, ft[".id"]), original)

    def test_originales_pasan_de_un_respaldo_al_siguiente(self):
        """Correccion de defecto: tras un segundo aplicar (p. ej. al cambiar las redes) el
        fasttrack ya esta excluido; su respaldo arrastra los valores originales del primero,
        asi que retirar con el ULTIMO respaldo devuelve la fasttrack a como estaba de verdad."""
        r = sim.router_isp()
        ft = next(f for f in r.tablas[FI] if f["action"] == "fasttrack-connection")
        ft["src-address-list"] = "!ids-vigilados"     # valor original que se debe recuperar
        antes = r.instantanea()
        self.assertTrue(self.aplicar(r)["ok"])
        res2 = self.aplicar(r, ["10.0.0.0/24"])
        self.assertTrue(res2["ok"], res2)
        self.assertNotEqual(res2["respaldo"], None)
        ultimo = mk.ultimo_respaldo(self.resp, PID)
        self.assertEqual(ultimo, res2["respaldo"])
        with open(ultimo, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["fasttrack"][ft[".id"]],
                             {"src-address-list": "!ids-vigilados", "dst-address-list": ""})
        self.assertTrue(mk.retirar(r.conexion(), PID, ultimo)["ok"])
        self.assertEqual(r.instantanea(), antes)

    def test_retirar_no_pisa_un_cambio_posterior(self):
        """Capacidad nueva: si alguien cambio a mano el fasttrack despues de aplicar, retirar no
        pisa ese campo (lo avisa) y si quita lo nuestro."""
        r = sim.router_isp()
        ft = next(f for f in r.tablas[FI] if f["action"] == "fasttrack-connection")
        res = self.aplicar(r)
        ft["src-address-list"] = "clientes-vip"
        ret = mk.retirar(r.conexion(), PID, res["respaldo"])
        self.assertTrue(ret["ok"], ret)
        self.assertEqual(r.fila(FI, ft[".id"])["src-address-list"], "clientes-vip")
        self.assertNotIn("dst-address-list", r.fila(FI, ft[".id"]))
        self.assertTrue([a for a in ret["avisos"] if ft[".id"] in a])
        for t in sim.TABLAS:
            self.assertEqual(mios(r, t), [])


if __name__ == "__main__":
    unittest.main()
