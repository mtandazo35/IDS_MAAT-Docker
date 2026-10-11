"""tzsp-decap: parser TZSP, filtro de origen fail-closed, recorte por flujo, latido y tzsp.json."""
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_vpn as ay  # noqa: E402

td = ay.cargar(ay.BIN / "tzsp-decap", "ids_vpn_tzsp_decap")
MK = "100.64.3.2"


def receptor(recorte=0, estado=None, allow=MK + "/32", ahora=1000.0):
    return td.Receptor(td.leer_allow(allow), recorte, estado, "p003", ahora=ahora)


class Parser(unittest.TestCase):
    def test_trama_con_solo_end(self):
        f = ay.trama_tcp()
        self.assertEqual(td.decap(ay.tzsp(f)), f)

    def test_tags_padding_y_con_longitud(self):
        f = ay.trama_tcp()
        tags = b"\x00\x00" + b"\x0a\x04ABCD" + b"\x00" + b"\x01"
        self.assertEqual(td.decap(ay.tzsp(f, tags=tags)), f)

    def test_tipo_tx_aceptado(self):
        f = ay.trama_tcp()
        self.assertEqual(td.decap(ay.tzsp(f, tipo=1)), f)

    def test_invalidos(self):
        f = ay.trama_tcp()
        casos = {
            "version 2": ay.tzsp(f, version=2),
            "tipo 5": ay.tzsp(f, tipo=5),
            "encapsulado no Ethernet": ay.tzsp(f, encap=18),
            "corto": b"\x01\x00\x00",
            "vacío": b"",
            "sin END": ay.tzsp(b"", tags=b"\x0a\x02AB"),
            "tag con longitud truncada": ay.tzsp(b"", tags=b"\x0a"),
            "longitud de tag que se sale": ay.tzsp(b"", tags=b"\x0a\xffAB"),
            "END sin trama": ay.tzsp(b""),
        }
        for nombre, d in casos.items():
            with self.subTest(nombre):
                self.assertIsNone(td.decap(d))


class FiltroOrigen(unittest.TestCase):
    def test_solo_el_mikrotik(self):
        r = receptor()
        self.assertTrue(r.permitido(MK))
        for ip in ("100.64.3.1", "100.64.3.3", "192.0.2.9", "0.0.0.0", "x", "", "::1"):
            with self.subTest(ip=ip):
                self.assertFalse(r.permitido(ip))

    def test_lista_vacia_no_acepta_nada(self):
        r = td.Receptor([], 0, None, "p003")
        self.assertFalse(r.permitido(MK))

    def test_config_fail_closed(self):
        base = {"TZSP_PORT": "37008", "TZSP_BYTES": "10000", "TZSP_OUT_IF": "ids-in",
                "TZSP_ESTADO": "/run/ids/tzsp.json", "PUNTO": "p003"}
        for allow in ("", "/32", " ", "100.64.3.2/33", "nada", MK + "/32,basura"):
            with self.subTest(allow=allow):
                with self.assertRaises(td.ErrorConfig):
                    td.config_desde_entorno({**base, "TZSP_ALLOW": allow})
        with self.assertRaises(td.ErrorConfig):
            td.config_desde_entorno({k: v for k, v in base.items()})
        cfg = td.config_desde_entorno({**base, "TZSP_ALLOW": MK + "/32"})
        self.assertEqual([str(r) for r in cfg["allow"]], [MK + "/32"])
        self.assertEqual(cfg["recorte"], 10000)

    def test_otros_valores_malos(self):
        base = {"TZSP_ALLOW": MK + "/32", "TZSP_PORT": "37008", "TZSP_BYTES": "0"}
        for cambio in ({"TZSP_PORT": "0"}, {"TZSP_PORT": "70000"}, {"TZSP_PORT": "x"},
                       {"TZSP_BYTES": "-1"}, {"TZSP_BYTES": "mucho"}):
            with self.subTest(cambio=cambio):
                with self.assertRaises(td.ErrorConfig):
                    td.config_desde_entorno({**base, **cambio})

    def test_main_sin_allow_sale_con_error_y_sin_abrir_sockets(self):
        env = {**os.environ, "PYTHONUTF8": "1", "TZSP_ALLOW": "", "TZSP_PORT": "37008", "TZSP_BYTES": "0"}
        p = subprocess.run([sys.executable, str(ay.BIN / "tzsp-decap")], env=env,
                           capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertEqual(p.returncode, 2)
        self.assertTrue(p.stderr.startswith("tzsp-decap: "))
        self.assertIn("TZSP_ALLOW", p.stderr)

    def test_origen_no_autorizado_no_se_inyecta(self):
        r = receptor()
        enviadas = []
        self.assertEqual(r.procesar(ay.tzsp(ay.trama_tcp()), "192.0.2.9", 1000, enviadas.append),
                         "rechazado")
        self.assertEqual(enviadas, [])
        self.assertEqual((r.rx, r.tx, r.rechazados), (1, 0, 1))
        self.assertEqual(r.procesar(ay.tzsp(ay.trama_tcp()), MK, 1000, enviadas.append), "enviado")
        self.assertEqual(len(enviadas), 1)
        self.assertEqual((r.rx, r.tx, r.rechazados), (2, 1, 1))

    def test_basura_del_mikrotik_se_descarta(self):
        r = receptor()
        enviadas = []
        self.assertEqual(r.procesar(b"\x02\x00\x00\x01\x01abc", MK, 1000, enviadas.append),
                         "descartado")
        self.assertEqual(r.procesar(ay.tzsp(b"\x00" * 10), MK, 1000, enviadas.append), "descartado")
        self.assertEqual(enviadas, [])
        self.assertEqual(r.descartados, 2)

    def test_error_de_envio_cuenta_como_muy_grande(self):
        r = receptor()

        def falla(_):
            raise OSError(90, "Message too long")
        self.assertEqual(r.procesar(ay.tzsp(ay.trama_tcp()), MK, 1000, falla), "muy_grande")
        self.assertEqual((r.tx, r.muy_grandes), (0, 1))


class Recorte(unittest.TestCase):
    def test_primeros_bytes_pasan_y_el_resto_no(self):
        r = receptor(recorte=1000)
        f = ay.trama_tcp(datos=b"x" * 300)          # 354 bytes por trama
        res = [r.recortar(f, 1000 + i) for i in range(6)]
        # 354, 708, 1062 (>= 1000): la 4.ª y siguientes sobran
        self.assertEqual(res, [False, False, False, True, True, True])

    def test_los_dos_sentidos_son_el_mismo_flujo(self):
        r = receptor(recorte=500)
        ida = ay.trama_tcp("10.0.0.5", "192.0.2.80", 40000, 443, b"x" * 400)
        vuelta = ay.trama_tcp("192.0.2.80", "10.0.0.5", 443, 40000, b"y" * 400)
        self.assertFalse(r.recortar(ida, 1000))
        self.assertFalse(r.recortar(vuelta, 1000))
        self.assertTrue(r.recortar(ida, 1000))
        self.assertTrue(r.recortar(vuelta, 1000))

    def test_flujos_distintos_no_se_mezclan(self):
        r = receptor(recorte=100)
        a = ay.trama_tcp(sp=40000, datos=b"x" * 200)
        b = ay.trama_tcp(sp=40001, datos=b"x" * 200)
        self.assertFalse(r.recortar(a, 1000))
        self.assertTrue(r.recortar(a, 1000))
        self.assertFalse(r.recortar(b, 1000))

    def test_sin_recorte_no_se_recorta_nada(self):
        r = receptor(recorte=0)
        f = ay.trama_tcp(datos=b"x" * 1400)
        self.assertFalse(any(r.recortar(f, 1000) for _ in range(50)))

    def test_lo_que_no_se_entiende_no_se_recorta(self):
        r = receptor(recorte=10)
        dns = ay.ethernet(ay.ipv4("10.0.0.5", "192.0.2.53", 17, ay.udp(5353, 53, b"q" * 100)))
        icmp = ay.ethernet(ay.ipv4("10.0.0.5", "192.0.2.1", 1, b"\x08\x00" + b"p" * 100))
        arp = ay.ethernet(b"\x00" * 60, tipo=0x0806)
        frag = ay.ethernet(ay.ipv4("10.0.0.5", "192.0.2.80", 6, b"z" * 200, frag=0x0010))
        mf = ay.ethernet(ay.ipv4("10.0.0.5", "192.0.2.80", 17, ay.udp(1, 2, b"z" * 200), frag=0x2000))
        for nombre, f in (("dns", dns), ("icmp", icmp), ("arp", arp), ("fragmento", frag),
                          ("primer fragmento", mf)):
            with self.subTest(nombre):
                self.assertIsNone(td.clave_flujo(f))
                self.assertFalse(any(r.recortar(f, 1000) for _ in range(5)))

    def test_vlan(self):
        r = receptor(recorte=100)
        f = ay.ethernet(ay.ipv4("10.0.0.5", "192.0.2.80", 6, ay.tcp(1, 2, b"x" * 200)), vlan=10)
        self.assertIsNotNone(td.clave_flujo(f))
        self.assertFalse(r.recortar(f, 1000))
        self.assertTrue(r.recortar(f, 1000))

    def test_flujo_callado_se_olvida(self):
        r = receptor(recorte=100, ahora=1000.0)
        f = ay.trama_tcp(datos=b"x" * 200)
        self.assertFalse(r.recortar(f, 1000))
        self.assertTrue(r.recortar(f, 1001))
        # 200 s después (TTL 120) el flujo se olvidó y vuelve a pasar el principio
        self.assertFalse(r.recortar(f, 1201))

    def test_procesar_cuenta_recortados(self):
        r = receptor(recorte=100)
        enviadas = []
        d = ay.tzsp(ay.trama_tcp(datos=b"x" * 200))
        estados = [r.procesar(d, MK, 1000, enviadas.append) for _ in range(3)]
        self.assertEqual(estados, ["enviado", "recortado", "recortado"])
        self.assertEqual((r.tx, r.recortados, len(enviadas)), (1, 2, 1))


class SocketFalso:
    """Socket UDP falso: entrega los datagramas de `cola` y si no, `socket.timeout`.

    Cada `recvfrom` hace avanzar el reloj: `paso` si entrega algo, el timeout pedido si no."""

    def __init__(self, reloj, cola=(), paso=1.0):
        self.reloj = reloj
        self.cola = list(cola)
        self.paso = paso
        self.timeouts = []

    def settimeout(self, t):
        self.timeouts.append(t)

    def recvfrom(self, n):
        if self.cola:
            self.reloj.t += self.paso
            return self.cola.pop(0)
        self.reloj.t += self.timeouts[-1]
        raise socket.timeout("timed out")


class Reloj:
    def __init__(self, t=1760080000.0):
        self.t = t

    def __call__(self):
        return self.t


class Latido(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.ruta = os.path.join(self.dir.name, "tzsp.json")

    def tearDown(self):
        self.dir.cleanup()

    def leer(self):
        with open(self.ruta, encoding="utf-8") as fh:
            return json.load(fh)

    def test_escribe_al_arrancar_y_cada_30s_sin_trafico(self):
        reloj = Reloj()
        r = td.Receptor(td.leer_allow(MK + "/32"), 10000, self.ruta, "p003", ahora=reloj())
        rx = SocketFalso(reloj)
        escrituras = []
        original = r.escribir_estado

        def espia(ahora):
            escrituras.append(ahora)
            return original(ahora)
        r.escribir_estado = espia
        salida = io.StringIO()
        r.bucle(rx, lambda f: None, reloj=reloj, salida=salida, max_vueltas=5)
        inicio = 1760080000.0
        self.assertEqual(escrituras, [inicio + 30 * i for i in range(6)])
        self.assertTrue(all(t <= 30 for t in rx.timeouts))
        e = self.leer()
        self.assertEqual(e["ts"], int(inicio + 150))
        self.assertEqual(e["ventana"]["segundos"], 30)
        self.assertEqual((e["rx"], e["tx"]), (0, 0))
        # el resumen sale cada 60 s aunque no haya tráfico, y nunca empieza por una IP
        lineas = salida.getvalue().splitlines()
        self.assertEqual(len(lineas), 2)
        for l in lineas:
            self.assertTrue(l.startswith("tzsp-decap: rx=0 tx=0 "), l)
            self.assertTrue(l.endswith("ultimo_origen=-"), l)

    def test_con_trafico_continuo_tambien_escribe_cada_30s(self):
        reloj = Reloj()
        r = td.Receptor(td.leer_allow(MK + "/32"), 0, self.ruta, "p003", ahora=reloj())
        d = ay.tzsp(ay.trama_tcp())
        rx = SocketFalso(reloj, [(d, (MK, 37008))] * 100, paso=1.0)
        escrituras = []
        original = r.escribir_estado
        r.escribir_estado = lambda a: (escrituras.append(a), original(a))[1]
        r.bucle(rx, lambda f: None, reloj=reloj, salida=io.StringIO(), max_vueltas=100)
        huecos = [b - a for a, b in zip(escrituras, escrituras[1:])]
        self.assertTrue(huecos and all(h == 30 for h in huecos), huecos)

    def test_esquema_de_tzsp_json(self):
        reloj = Reloj(1760089970.0)
        r = td.Receptor(td.leer_allow(MK + "/32"), 10000, self.ruta, "p003", ahora=1760080000.0)
        r.escribir_estado(reloj())
        d = ay.tzsp(ay.trama_tcp())
        for _ in range(40):
            r.procesar(d, MK, 1760089990.0, lambda f: None)
        for _ in range(2):
            r.procesar(d, "192.0.2.9", 1760089995.0, lambda f: None)
        r.escribir_estado(1760090000.0)
        e = self.leer()
        self.assertEqual(set(e), {"v", "punto", "ts", "inicio", "rx", "tx", "descartados",
                                  "muy_grandes", "rechazados", "recortados", "recorte_bytes",
                                  "ventana", "ultimo_visto", "esperados"})
        self.assertEqual(e["v"], 1)
        self.assertEqual(e["punto"], "p003")
        self.assertEqual(e["ts"], 1760090000)
        self.assertEqual(e["inicio"], 1760080000)
        self.assertEqual(e["rx"], 42)
        self.assertEqual(e["rechazados"], 2)
        self.assertEqual(e["recorte_bytes"], 10000)
        self.assertEqual(e["ventana"], {"segundos": 30, "aceptados": {MK: 40},
                                        "rechazados": {"192.0.2.9": 2}})
        self.assertEqual(e["ultimo_visto"], {MK: 1760089990})
        self.assertEqual(e["esperados"], [MK + "/32"])
        self.assertEqual(e["tx"] + e["recortados"] + e["descartados"] + e["muy_grandes"], 40)
        for k in ("ts", "inicio", "rx", "tx", "descartados", "muy_grandes", "rechazados",
                  "recortados", "recorte_bytes"):
            self.assertIsInstance(e[k], int, k)
        self.assertFalse(os.path.exists(self.ruta + ".tmp"))
        # la ventana empieza de cero tras cada escritura; los contadores siguen acumulando
        r.escribir_estado(1760090030.0)
        e2 = self.leer()
        self.assertEqual(e2["ventana"], {"segundos": 30, "aceptados": {}, "rechazados": {}})
        self.assertEqual(e2["rx"], 42)
        self.assertEqual(e2["ultimo_visto"], {MK: 1760089990})

    def test_error_de_escritura_no_tumba_el_receptor(self):
        r = td.Receptor(td.leer_allow(MK + "/32"), 0,
                        os.path.join(self.dir.name, "no", "existe", "tzsp.json"), "p003")
        viejo = sys.stderr
        sys.stderr = io.StringIO()
        try:
            datos = r.escribir_estado(1760090000.0)
        finally:
            sys.stderr = viejo
        self.assertEqual(datos["v"], 1)


if __name__ == "__main__":
    unittest.main()
