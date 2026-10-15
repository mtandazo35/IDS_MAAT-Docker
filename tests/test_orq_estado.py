"""estado.json (§5.10): esquema, escritura atómica, lecturas de status/tzsp/eve, netns por inodo y
supervisión (unhealthy con espera creciente, netns distinto -> reinicio de suricata)."""

import json
import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

STATUS = """TITLE,OpenVPN 2.6.14 x86_64-pc-linux-gnu
TIME,2026-10-10 08:15:00,1760084100
HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher
CLIENT_LIST,vpn3a9f2c,203.0.113.45:51234,100.64.1.2,,1000,2000,2026-10-10 06:15:00,1760077000,vpn3a9f2c,0,0,AES-256-GCM
END
"""


def tipo_ok(v, tipos):
    return v is None or isinstance(v, tipos)


class Estado(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()
        r = A.crear(self, self.orq, {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]})
        self.assertEqual(r["codigo"], "OK")

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_esquema(self):
        t = int(time.time())
        self.e.ruta("/srv/ids/run/p001/openvpn-status.log").write_text(STATUS, encoding="utf-8")
        self.e.ruta("/srv/ids/run/p001/tzsp.json").write_text(json.dumps(
            {"v": 1, "punto": "p001", "ts": t - 12, "inicio": t - 1000, "rx": 1200, "tx": 1180, "rechazados": 20}),
            encoding="utf-8")
        ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(t - 14))
        stats = {"timestamp": ts, "event_type": "stats", "stats": {
            "capture": {"kernel_packets": 98765, "kernel_drops": 0},
            "detect": {"engines": [{"id": 0, "rules_loaded": 18234, "rules_failed": 0}]}}}
        self.e.ruta("/srv/ids/datos/p001/eve.json").write_text(
            '{"event_type":"alert"}\n' + json.dumps(stats, separators=(",", ":")) + "\n", encoding="utf-8")
        est = self.orq.escribir_estado()
        disco = json.loads(self.e.ruta("/srv/ids/run/estado.json").read_text(encoding="utf-8"))
        self.assertEqual(disco["v"], 1)
        self.assertEqual(disco["puntos"].keys(), est["puntos"].keys())
        self.assertEqual(set(disco), {"v", "ts", "orq_version", "version", "dev", "tun_base", "cola", "capacidad",
                                      "reglas", "disco", "puntos"})
        self.assertEqual(set(disco["cola"]), {"en_curso", "pendientes"})
        self.assertEqual(set(disco["capacidad"]), {"mem_total_mb", "mem_comprometida_mb", "mem_disponible_mb",
                                                   "caben"})
        self.assertEqual(disco["capacidad"]["mem_total_mb"], 7962)
        self.assertEqual(set(disco["capacidad"]["caben"]), {"reducido", "completo-low", "completo"})
        self.assertEqual(set(disco["reglas"]), {"current", "releases"})
        self.assertEqual(disco["reglas"]["releases"], ["20261010T081500Z"])
        self.assertTrue(tipo_ok(disco["disco"]["srv_ids_libre_pct"], int))
        self.assertEqual((disco["tun_base"], disco["dev"], disco["version"]), ("100.64", False, "0.1.0"))
        p = disco["puntos"]["p001"]
        self.assertEqual(set(p), {"nombre", "n", "puerto", "tun_net", "perfil", "hilos", "ros_version", "compat_v6",
                                  "deseado", "estado", "contenedores", "netns", "vpn_cliente", "tzsp", "suricata",
                                  "avisos", "redes", "api_puerto", "sensor", "mk", "tzsp_puerto", "retencion",
                                  "paso_error", "error_desde"})
        self.assertEqual((p["paso_error"], p["error_desde"]), (None, None))
        # CONTRATO-F2 §9: retención efectiva (desde el primer evento que queda)
        self.assertEqual(set(p["retencion"]), {"objetivo_dias", "desde", "dias", "anticipado",
                                               "ultimo_anticipado"})
        self.assertEqual((p["retencion"]["objetivo_dias"], p["retencion"]["anticipado"]), (30, False))
        self.assertEqual(p["retencion"]["desde"], t - 14)
        self.assertEqual((p["nombre"], p["n"], p["puerto"], p["tun_net"], p["estado"], p["deseado"]),
                         ("norte", 1, 1194, "100.64.1.0/24", "activo", "activo"))
        # lo que usa el panel para hablar con el MikroTik y montar el espejo del punto
        self.assertEqual((p["sensor"], p["mk"], p["tzsp_puerto"]), ("100.64.1.1", "100.64.1.2", 37008))
        self.assertTrue(p["redes"] and isinstance(p["api_puerto"], int))
        for parte in ("vpn", "suricata"):
            c = p["contenedores"][parte]
            self.assertEqual(set(c), {"estado", "salud", "inicio", "reinicios_1h", "imagen"})
            self.assertEqual((c["estado"], c["salud"]), ("running", "healthy"))
            self.assertIsInstance(c["inicio"], int)
        self.assertEqual(p["vpn_cliente"], {"conectado": True, "desde": 1760077000, "ip_real": "203.0.113.45",
                                            "usuario": "vpn3a9f2c", "viejo": False})
        self.assertEqual(p["tzsp"], {"edad_s": 12, "rx": 1200, "tx": 1180, "rechazados": 20})
        self.assertEqual(p["suricata"]["reglas_cargadas"], 18234)
        self.assertEqual(p["suricata"]["kernel_packets"], 98765)
        self.assertEqual(p["suricata"]["stats_edad_s"], 14)
        self.assertEqual(set(p["netns"]), {"coherente", "vpn", "suricata"})
        self.assertIsInstance(p["avisos"], list)

    def test_escritura_atomica(self):
        ruta = self.e.ruta("/srv/ids/run/estado.json")
        reemplazos = []
        original = self.mod.os.replace

        def espia(a, b):
            reemplazos.append((Path(a).name, Path(b).name))
            self.assertTrue(Path(a).exists())
            json.loads(Path(a).read_text(encoding="utf-8"))   # el temporal ya está completo
            return original(a, b)

        self.mod.os.replace = espia
        try:
            self.orq.escribir_estado()
        finally:
            self.mod.os.replace = original
        self.assertIn("estado.json", [b for _, b in reemplazos])
        self.assertEqual([a for a, b in reemplazos if b == "estado.json"][0][:12], ".estado.json")
        self.assertEqual(sorted(x.name for x in ruta.parent.iterdir() if x.is_file()), ["estado.json"])

    def test_avisos(self):
        t = int(time.time())
        tz = self.e.ruta("/srv/ids/run/p001/tzsp.json")
        tz.write_text(json.dumps({"ts": t, "rx": 0, "tx": 0, "rechazados": 0}), encoding="utf-8")
        p = self.orq.punto("p001")
        su = {"kernel_packets": 10}
        tzd = {"tx": 0}
        self.assertEqual(self.orq._avisos_espejo(p, tzd, su, t), [])
        self.assertEqual(self.orq._avisos_espejo(p, tzd, su, t + 601), ["SIN-ESPEJO"])
        # el espejo entra (tx sube) pero kernel_packets no se mueve en 2 min
        self.assertEqual(self.orq._avisos_espejo(p, {"tx": 50}, su, t + 700), [])
        self.assertEqual(self.orq._avisos_espejo(p, {"tx": 70}, su, t + 760), [])
        self.assertEqual(self.orq._avisos_espejo(p, {"tx": 90}, su, t + 830), ["ESPEJO-NO-LLEGA"])
        self.assertEqual(self.orq._avisos_espejo(p, {"tx": 99}, {"kernel_packets": 40}, t + 840), [])
        self.assertEqual(self.orq._avisos_espejo(p, {"tx": 120}, {"kernel_packets": 80}, t + 990), [])
        # disco y reinicios
        self.orq.x("INSERT INTO reinicio VALUES ('p001','vpn',?),('p001','vpn',?),('p001','vpn',?)", (t, t, t))
        self.mod.disco_libre_pct = lambda: 10
        est = self.orq.construir_estado()
        self.assertIn("REINICIOS", est["puntos"]["p001"]["avisos"])
        self.assertIn("DISCO", est["puntos"]["p001"]["avisos"])


class Netns(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()
        A.crear(self, self.orq, {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]})

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def ns(self, pid_proc, origen=None):
        d = self.e.kdir / "proc" / str(pid_proc) / "ns"
        d.mkdir(parents=True, exist_ok=True)
        if origen is None:
            (d / "net").write_text("netns %d" % pid_proc, encoding="utf-8")
        else:
            os.link(origen, d / "net")      # mismo inodo = mismo netns
        return d / "net"

    def test_mismo_inodo_coherente(self):
        vpn = self.s.contenedores["ids-p001-vpn"]["pid"]
        sur = self.s.contenedores["ids-p001-suricata"]["pid"]
        f = self.ns(vpn)
        self.ns(sur, origen=f)
        r = self.orq.comprobar_netns("p001")
        self.assertTrue(r["coherente"])
        self.assertEqual(r["vpn"], r["suricata"])
        self.assertEqual(self.orq.q1("SELECT COUNT(*) FROM op WHERE estado='pendiente'")[0], 0)

    def test_inodos_distintos_reinicia_suricata(self):
        vpn = self.s.contenedores["ids-p001-vpn"]["pid"]
        sur = self.s.contenedores["ids-p001-suricata"]["pid"]
        self.ns(vpn)
        self.ns(sur)
        r = self.orq.comprobar_netns("p001")
        self.assertFalse(r["coherente"])
        self.assertNotEqual(r["vpn"], r["suricata"])
        # se encola UNA orden de reinicio de suricata (no se duplica)
        self.orq.comprobar_netns("p001")
        f = self.orq.q("SELECT orden, quien FROM op WHERE estado='pendiente'")
        self.assertEqual([(x[0], x[1]) for x in f], [("punto.reiniciar", "orq:netns")])
        est = self.orq.construir_estado()
        self.assertIn("NETNS-DISTINTO", est["puntos"]["p001"]["avisos"])
        self.s.llamadas.clear()
        while self.orq.procesar_una():
            pass
        self.assertTrue(self.s.ordenes("docker restart --time 30 ids-p001-suricata"))
        self.assertFalse(self.s.ordenes("docker restart --time 30 ids-p001-vpn"))

    def test_evento_start_del_vpn_compara(self):
        vpn = self.s.contenedores["ids-p001-vpn"]["pid"]
        sur = self.s.contenedores["ids-p001-suricata"]["pid"]
        self.ns(vpn)
        self.ns(sur)
        self.orq.evento({"Type": "container", "Action": "start", "Actor": {"Attributes": {
            "name": "ids-p001-vpn", "ids-maat.punto": "p001", "ids-maat.parte": "vpn"}}})
        self.assertEqual(self.orq.q1("SELECT COUNT(*) FROM op WHERE estado='pendiente' AND orden='punto.reiniciar'")[0], 1)

    def test_contenedor_parado_sin_conclusion(self):
        self.s.contenedores["ids-p001-suricata"]["estado"] = "exited"
        self.assertIsNone(self.orq.comprobar_netns("p001")["coherente"])


class Supervision(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()
        A.crear(self, self.orq, {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]})

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_unhealthy_espera_creciente_y_error_a_las_3(self):
        t = time.time()
        self.s.contenedores["ids-p001-suricata"]["salud"] = "unhealthy"
        ev = {"Action": "health_status: unhealthy", "Actor": {"Attributes": {
            "ids-maat.punto": "p001", "ids-maat.parte": "suricata"}}}
        esperas = []
        for _ in range(3):
            self.orq.programar_reinicio("p001", "suricata", t)
            cuando = self.orq._programados[("p001", "suricata")]
            esperas.append(round(cuando - t))
            self.orq.tick(t=cuando + 0.1)
            self.assertFalse(("p001", "suricata") in self.orq._programados and
                             self.orq._programados[("p001", "suricata")] <= cuando)
            while self.orq.procesar_una():
                pass
            self.s.contenedores["ids-p001-suricata"]["salud"] = "unhealthy"
            t = cuando + 1
            self.orq._programados.clear()
        self.assertEqual(esperas, [30, 120, 600])
        self.orq.evento(ev)
        self.assertEqual(self.orq.punto("p001")["estado"], "error")
        self.assertNotIn(("p001", "suricata"), self.orq._programados)

    def test_reinicio_de_supervision_no_sano_no_pasa_a_error(self):
        self.s.salud_inicial = "unhealthy"
        self.orq.encolar_interno("punto.reiniciar", {"pid": "p001", "parte": "suricata"}, "orq:salud")
        while self.orq.procesar_una():
            pass
        self.assertEqual(self.orq.punto("p001")["estado"], "activo")
        r = A.ejecutar_orden(self.orq, "punto.reiniciar", {"pid": "p001", "parte": "suricata"})
        self.assertEqual(r["codigo"], "FALLO")
        self.assertEqual(self.orq.punto("p001")["estado"], "error")      # pedido por una persona

    def test_punto_parado_no_se_reinicia(self):
        r = A.ejecutar_orden(self.orq, "punto.parar", {"pid": "p001", "parte": "todo"})
        self.assertEqual(r["codigo"], "OK")
        self.orq.programar_reinicio("p001", "vpn")
        self.assertEqual(self.orq._programados, {})


if __name__ == "__main__":
    unittest.main()
