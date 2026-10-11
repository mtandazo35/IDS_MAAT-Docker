"""Ciclo de vida de un punto con el código real del orquestador y el sistema simulado:
asignación (pid/N/puerto/subred/cluster), pid nunca reutilizado, enfriamiento de N, borrado total,
deshacer ante fallo, idempotencia de crear."""

import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

NORTE = {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]}


class Asignacion(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def crear(self, nombre, codigo="OK", **extra):
        params = {"nombre": nombre, "redes_abonados": ["10.0.0.0/24"]}
        params.update(extra)
        return A.crear(self, self.orq, params, codigo)

    def test_derivar_ejemplos_del_contrato(self):
        d = self.mod.derivar(3, "100.64")
        self.assertEqual((d["puerto"], d["tun_net"], d["sensor"], d["mk"], d["subred"], d["cluster_id"]),
                         (1196, "100.64.3.0/24", "100.64.3.1", "100.64.3.2", "10.210.0.48/28", 103))
        d = self.mod.derivar(12, "198.18")
        self.assertEqual((d["puerto"], d["tun_net"], d["sensor"], d["mk"], d["subred"], d["cluster_id"]),
                         (1205, "198.18.12.0/24", "198.18.12.1", "198.18.12.2", "10.210.0.192/28", 112))

    def test_crear_asigna_valores_correctos(self):
        r1 = self.crear("norte")
        r2 = self.crear("sur")
        r3 = self.crear("este")
        self.assertEqual([r["codigo"] for r in (r1, r2, r3)], ["OK", "OK", "OK"])
        d = r3["resultado"]
        self.assertEqual((d["pid"], d["n"], d["puerto"], d["tun_net"]), ("p003", 3, 1196, "100.64.3.0/24"))
        p = self.orq.punto("p003")
        self.assertEqual((p["subred"], p["cluster_id"]), ("10.210.0.48/28", 103))
        compose = self.e.ruta("/srv/ids/puntos/p003/compose.yml").read_text(encoding="utf-8")
        self.assertIn('ports: ["1196:1194/tcp"]', compose)
        self.assertIn("subnet: 10.210.0.48/28", compose)
        self.assertIn('TUN_MK: "100.64.3.2"', compose)
        yaml = self.e.ruta("/srv/ids/puntos/p003/suricata/suricata.yaml").read_text(encoding="utf-8")
        self.assertIn("cluster-id: 103", yaml)
        self.assertIn("sensor-name: p003", yaml)

    def test_pid_no_se_reutiliza_y_n_se_enfria(self):
        self.crear("norte")
        self.crear("sur")
        r = A.ejecutar_orden(self.orq, "punto.borrar", {"pid": "p001", "confirmar": "norte"})
        self.assertEqual(r["codigo"], "OK")
        r = self.crear("oeste")
        # p001 nunca vuelve; N=1 está en enfriamiento: toma el 3
        self.assertEqual((r["resultado"]["pid"], r["resultado"]["n"]), ("p003", 3))
        # pasado el enfriamiento, N=1 vuelve a estar libre (el pid sigue sin volver)
        self.orq.x("UPDATE enfriamiento SET hasta=?", (int(time.time()) - 1,))
        r = self.crear("centro")
        self.assertEqual((r["resultado"]["pid"], r["resultado"]["n"]), ("p004", 1))
        # pedir un pid ya usado es CONFLICTO
        r = self.crear("viejo", "CONFLICTO", pid="p001")
        self.assertEqual(r["codigo"], "CONFLICTO")

    def test_n_mas_bajo_libre_y_n_pedido(self):
        r = self.crear("norte", n=5)
        self.assertEqual(r["resultado"]["n"], 5)
        r = self.crear("sur")
        self.assertEqual(r["resultado"]["n"], 1)
        r = self.crear("dup", "CONFLICTO", n=5)
        self.assertEqual(r["codigo"], "CONFLICTO")

    def test_base_198_18(self):
        A.cerrar(self.orq, self.e)
        self.mod, self.e, self.s, self.orq = A.preparar(tun_base="198.18")
        r = self.crear("norte", n=12)
        self.assertEqual(r["resultado"]["tun_net"], "198.18.12.0/24")
        self.assertEqual(r["resultado"]["puerto"], 1205)
        server = self.e.ruta("/srv/ids/puntos/p001/vpn/server.conf").read_text(encoding="utf-8")
        self.assertIn("server 198.18.12.0 255.255.255.0", server)
        ccd = self.e.ruta("/srv/ids/puntos/p001/vpn/ccd").iterdir().__next__()
        self.assertEqual(ccd.read_text(encoding="utf-8"), "ifconfig-push 198.18.12.2 255.255.255.0\n")

    def test_puerto_ocupado_conflicto_puerto(self):
        self.s.puertos_ocupados.add(1194)
        r = self.crear("norte", "CONFLICTO_PUERTO")
        self.assertEqual(r["codigo"], "CONFLICTO_PUERTO")
        self.assertIsNone(self.orq.punto("p001"))


class Borrado(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_borrar_elimina_todo_lo_del_punto(self):
        r = A.crear(self, self.orq, NORTE)
        self.assertEqual(r["codigo"], "OK")
        # el contenedor suricata escribiría su eve; el vpn su tzsp.json
        self.e.ruta("/srv/ids/datos/p001/eve.json").write_text("{}\n", encoding="utf-8")
        self.e.ruta("/srv/ids/run/p001/tzsp.json").write_text("{}", encoding="utf-8")
        self.assertTrue(self.e.ruta("/srv/ids/pki/servidores/p001.key").exists())
        r = A.ejecutar_orden(self.orq, "punto.borrar", {"pid": "p001", "confirmar": "otro"})
        self.assertEqual(r["codigo"], "INVALIDO")
        r = A.ejecutar_orden(self.orq, "punto.borrar", {"pid": "p001", "confirmar": "norte"})
        self.assertEqual(r["codigo"], "OK", r)
        for d in ("puntos", "datos", "run", "ctl"):
            self.assertFalse(self.e.ruta("/srv/ids/%s/p001" % d).exists(), d)
        self.assertFalse(list(self.e.ruta("/srv/ids/pki/servidores").glob("p001.*")))
        self.assertIsNone(self.orq.punto("p001"))
        self.assertNotIn("ids-p001-vpn", self.s.contenedores)
        self.assertTrue(self.s.ordenes("docker compose -p ids-p001"))
        self.assertTrue(self.s.ordenes("docker network rm ids-p001"))
        # el puerto sale de @puertos_vpn y no quedan órdenes del punto salvo la propia baja
        nft = self.e.ruta("/srv/ids/fw/ids_host.nft").read_text(encoding="utf-8")
        self.assertIn("set puertos_vpn { type inet_service; }", nft)
        ops = self.orq.q("SELECT orden FROM op WHERE pid='p001'")
        self.assertEqual([o[0] for o in ops], ["punto.borrar"])
        # solo queda el enfriamiento de N
        self.assertEqual(self.orq.q1("SELECT n FROM enfriamiento")[0], 1)
        # en orq.jsonl no hay parámetros en claro
        diario = self.e.ruta("/srv/ids/estado/orq.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("10.0.0.0", diario)
        self.assertNotIn("norte", diario)
        for linea in diario.splitlines():
            self.assertEqual(set(json.loads(linea)), {"ts", "op_id", "quien", "orden", "pid", "params_sha256",
                                                      "pasos", "codigo", "mensaje"})

    def test_borrar_inexistente_es_ok(self):
        r = A.ejecutar_orden(self.orq, "punto.borrar", {"pid": "p042", "confirmar": "x"})
        self.assertEqual((r["codigo"], r["mensaje"]), ("OK", "no existía"))


class Deshacer(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def assert_sin_rastro(self, pid):
        for d in ("puntos", "datos", "run", "ctl"):
            self.assertFalse(self.e.ruta("/srv/ids/%s/%s" % (d, pid)).exists(), d)
        self.assertIsNone(self.orq.punto(pid))
        self.assertFalse(list(self.e.ruta("/srv/ids/pki/servidores").glob("%s.*" % pid)))

    def test_fallo_en_compose_up_deshace_todo(self):
        self.s.fallar["compose -p ids-p001 -f"] = 1
        r = A.crear(self, self.orq, NORTE, "REVERTIDA")
        self.assertEqual(r["codigo"], "REVERTIDA")
        self.assertIn("compose up", r["mensaje"])
        self.assert_sin_rastro("p001")
        self.assertIsNone(r["resultado"].get("clave"))
        # el siguiente alta no reutiliza el pid; N=1 sí (nunca se publicó)
        del self.s.fallar["compose -p ids-p001 -f"]
        r = A.crear(self, self.orq, NORTE)
        self.assertEqual((r["codigo"], r["resultado"]["pid"], r["resultado"]["n"]), ("OK", "p002", 1))

    def test_fallo_en_suricata_T_deshace(self):
        self.s.fallar["-T -c /etc/ids/suricata/suricata.yaml"] = 1
        r = A.crear(self, self.orq, NORTE, "REVERTIDA")
        self.assertEqual(r["codigo"], "REVERTIDA")
        self.assertEqual([p["estado"] for p in r["pasos"]][-1], "fallo")
        self.assert_sin_rastro("p001")

    def test_no_sano_deshace(self):
        self.s.salud_inicial = "starting"
        r = A.crear(self, self.orq, NORTE, "REVERTIDA")
        self.assertEqual(r["codigo"], "REVERTIDA")
        self.assertIn("esperar salud", r["mensaje"])
        self.assert_sin_rastro("p001")
        self.assertEqual(self.s.contenedores, {})

    def test_alta_interrumpida_se_deshace_al_arrancar(self):
        r = A.crear(self, self.orq, NORTE)
        self.assertEqual(r["codigo"], "OK")
        self.orq.x("UPDATE punto SET estado='creando'")
        self.orq.x("UPDATE op SET estado='en_curso'")
        self.orq.arrancar()
        self.assert_sin_rastro("p001")
        f = self.orq.q1("SELECT codigo, mensaje FROM op WHERE orden='punto.crear'")
        self.assertEqual((f[0], f[1]), ("FALLO", "error: interrumpida"))


class Idempotencia(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_crear_lo_que_ya_existe(self):
        r = A.crear(self, self.orq, NORTE)
        self.assertIn("clave", r["resultado"])
        r2 = A.crear(self, self.orq, NORTE)
        self.assertEqual((r2["codigo"], r2["mensaje"]), ("OK", "ya existe"))
        self.assertNotIn("clave", r2["resultado"])
        self.assertIn("<CLAVE-VPN>", r2["resultado"]["comandos"])
        r3 = A.crear(self, self.orq, {"nombre": "norte", "redes_abonados": ["10.9.0.0/24"]}, "CONFLICTO")
        self.assertEqual(r3["codigo"], "CONFLICTO")

    def test_redes_invalidas(self):
        for redes in (["0.0.0.0/0"], ["100.64.0.0/10"], ["10.210.5.0/24"], ["192.0.2.0/24"],
                      ["no-es-red"], [], ["10.%d.0.0/24" % i for i in range(65)]):
            r = self.orq.atender(A.peticion("punto.crear", {"nombre": "x1", "redes_abonados": redes}))
            self.assertEqual(r["codigo"], "INVALIDO", redes)


if __name__ == "__main__":
    unittest.main()
