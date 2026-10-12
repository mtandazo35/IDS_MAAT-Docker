"""mikrotik_init: el espejo no autoriza nada que la politica del router rechazaba (OPERACION §2).

Se evalua trafico con el evaluador de paquetes del MikroTik simulado (orden de reglas,
fasttrack que acelera y no termina, conexiones aceleradas que se saltan filter y mangle)
antes de aplicar, despues de aplicar, de pausar y de retirar. Cada prueba dice su tipo
(CONTRATO-F2 §10.5); datos RFC 5737 / 10.x, sin red.
"""
import os
import random
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
FI = sim.TABLAS[0]


def veredictos(router, conexiones):
    return {k: v["veredicto"] for k, v in sim.recorrer(router, conexiones).items()}


def accepts(router):
    return sorted(str(sorted(f.items())) for t in sim.TABLAS for f in router.tablas[t]
                  if f.get("action") == "accept")


class Politica(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.resp = os.path.join(self.tmp.name, "respaldos-mk")

    def ciclo(self, r):
        """[(estado, veredictos)] antes, aplicado, pausado y retirado; con las tablas."""
        bat = sim.bateria()
        out = [("antes", veredictos(r, bat), accepts(r))]
        p = mk.plan(r.conexion(), PID, sim.SENSOR, sim.PUERTO, sim.REDES)
        res = mk.aplicar(r.conexion(), p, self.resp)
        self.assertTrue(res["ok"], res)
        out.append(("aplicado", veredictos(r, bat), accepts(r)))
        self.assertTrue(mk.pausar(r.conexion(), PID)["ok"])
        out.append(("pausado", veredictos(r, bat), accepts(r)))
        self.assertTrue(mk.retirar(r.conexion(), PID, res["respaldo"])["ok"])
        out.append(("retirado", veredictos(r, bat), accepts(r)))
        return out

    def test_mismo_veredicto_en_todo_el_ciclo(self):
        """Capacidad nueva (requisito que manda): con la tabla realista (fasttrack, accept
        established, drop invalid, drop de cuarentena detras del fasttrack, accept LAN, drop
        final) la bateria de paquetes (vigilados y no, cuarentena, nueva/establecida/invalida,
        por debajo y por encima de 10 KB, en las dos direcciones) da el MISMO veredicto antes,
        aplicado, pausado y retirado; y no aparece ninguna regla accept."""
        r = sim.router_isp()
        ciclo = self.ciclo(r)
        base = ciclo[0][1]
        # la bateria no es trivial: hay de las dos cosas, y la cuarentena corta
        self.assertIn("drop", base.values())
        self.assertIn("accept", base.values())
        self.assertEqual(base[("vigilado-cuarentena:tcp-saliente", 0)], "drop")
        self.assertEqual(base[("vigilado:tcp-saliente", 0)], "accept")
        self.assertEqual(base[("vigilado:entrante", 0)], "drop")
        for estado, v, acc in ciclo[1:]:
            self.assertEqual(v, base, estado)
            self.assertEqual(acc, ciclo[0][2], estado)

    def test_mismo_veredicto_con_varias_fasttrack(self):
        """Capacidad nueva: igual con dos fasttrack (una con interfaz y protocolo) y una
        fasttrack ajena con address-list que no se toca."""
        r = sim.router_isp()
        ft = next(f[".id"] for f in r.tablas[FI] if f["action"] == "fasttrack-connection")
        r._anadir(FI, {"chain": "forward", "action": "fasttrack-connection",
                       "connection-state": "established", "protocol": "udp",
                       "in-interface": sim.WAN, "comment": "ft udp"}, antes=ft)
        r._anadir(FI, {"chain": "forward", "action": "fasttrack-connection",
                       "connection-state": "established", "src-address-list": "cuarentena",
                       "comment": "ft raro"})
        ciclo = self.ciclo(r)
        for estado, v, acc in ciclo[1:]:
            self.assertEqual(v, ciclo[0][1], estado)
            self.assertEqual(acc, ciclo[0][2], estado)

    def test_propiedad_nada_descartado_pasa_a_aceptarse(self):
        """Capacidad nueva (prueba de propiedad): en 300 tablas aleatorias (reglas de un ISP en
        orden aleatorio, con 1-2 fasttrack de condiciones variadas, la cuarentena antes o
        despues del accept established) y secuencias aleatorias por conexion con aceleracion,
        ningun paquete que antes se descartaba se acepta tras aplicar, pausar o retirar; y
        tras retirar las tablas son las originales."""
        rnd = random.Random(20261011)
        plantillas = [
            {"action": "accept", "connection-state": "established,related"},
            {"action": "drop", "connection-state": "invalid"},
            {"action": "drop", "src-address-list": "cuarentena"},
            {"action": "drop", "dst-address-list": "cuarentena"},
            {"action": "accept", "src-address": "10.0.0.0/16"},
            {"action": "accept", "protocol": "udp", "dst-port": "53"},
            {"action": "drop", "protocol": "tcp", "dst-port": "25"},
            {"action": "reject", "src-address": "10.0.1.0/24", "protocol": "udp"},
            {"action": "drop", "in-interface": sim.WAN, "connection-state": "new"},
            {"action": "accept", "connection-bytes": "0-5000"},
            {"action": "passthrough", "comment": "IDS ids-maat:p0031"},
        ]
        fasttracks = [
            {"connection-state": "established,related", "hw-offload": "yes"},
            {"connection-state": "established", "connection-mark": "no-mark"},
            {"connection-state": "established,related", "in-interface": sim.LAN},
            {"connection-state": "established", "protocol": "tcp"},
            {"connection-state": "established,related", "src-address-list": "cuarentena"},
        ]
        ips = list(sim.CLIENTES.values()) + ["10.0.9.3"]
        comparados = 0
        for n in range(300):
            resp = os.path.join(self.resp, str(n))
            r = sim.RouterSimulado()
            r.cargar(sim.TABLAS[2], [
                {"list": "cuarentena", "address": "10.0.0.66"},
                {"list": "cuarentena", "address": "10.0.5.66"}])
            reglas = [dict(x) for x in rnd.sample(plantillas, rnd.randint(2, len(plantillas)))]
            for _f in range(rnd.randint(1, 2)):
                reglas.insert(rnd.randint(0, len(reglas)),
                              dict(rnd.choice(fasttracks), action="fasttrack-connection"))
            if rnd.random() < 0.7:
                reglas.append({"action": "drop", "comment": "drop final"})
            r.cargar(FI, [dict(x, chain="forward") for x in reglas])
            original = r.instantanea()
            conexiones = []
            for c in range(12):
                ip = rnd.choice(ips)
                proto = rnd.choice(["tcp", "udp"])
                dport = rnd.choice([443, 53, 25, 22])
                bytes_, paquetes = 0, []
                estado = "new"
                for _p in range(rnd.randint(1, 8)):
                    sube = rnd.random() < 0.5 or not paquetes
                    lado = (dict(src=ip, dst=sim.REMOTO, in_if=sim.LAN, out_if=sim.WAN) if sube
                            else dict(src=sim.REMOTO, dst=ip, in_if=sim.WAN, out_if=sim.LAN))
                    if rnd.random() < 0.15 and paquetes:
                        lado = dict(src=sim.REMOTO, dst=ip, in_if=sim.WAN, out_if=sim.LAN)
                    paquetes.append(dict(lado, proto=proto, dport=dport, estado=estado, bytes=bytes_,
                                         marca=rnd.choice(["no-mark", "no-mark", "cli"])))
                    bytes_ += rnd.choice([100, 1500, 4000, 9000, 20000])
                    estado = rnd.choice(["established", "established", "related", "invalid"])
                conexiones.append(("c%d" % c, ip, paquetes))
            antes = veredictos(r, conexiones)
            acc0 = accepts(r)
            p = mk.plan(r.conexion(), PID, sim.SENSOR, sim.PUERTO, sim.REDES)
            res = mk.aplicar(r.conexion(), p, resp)
            self.assertTrue(res["ok"], res)
            estados = [("aplicado", veredictos(r, conexiones), accepts(r))]
            self.assertTrue(mk.pausar(r.conexion(), PID)["ok"])
            estados.append(("pausado", veredictos(r, conexiones), accepts(r)))
            self.assertTrue(mk.retirar(r.conexion(), PID, res["respaldo"])["ok"])
            estados.append(("retirado", veredictos(r, conexiones), accepts(r)))
            for estado, v, acc in estados:
                self.assertEqual(acc, acc0, estado)
                for k, ver in antes.items():
                    if ver == "drop":
                        self.assertEqual(v[k], "drop", (estado, k, reglas))
                        comparados += 1
            self.assertEqual(r.instantanea(), original)
        self.assertGreater(comparados, 1000)


if __name__ == "__main__":
    unittest.main()
