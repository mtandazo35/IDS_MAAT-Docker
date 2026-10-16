"""Protocolo del socket (ORQUESTADOR §3, CONTRATO §5.11), idempotencia por op_id y cola en serie."""

import sys
import threading
import time
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402


class Protocolo(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_ordenes_desconocidas_reservadas_y_token(self):
        r = self.orq.atender(A.peticion("ejecutar", {"cmd": "id"}))
        self.assertEqual((r["codigo"], r["ok"]), ("INVALIDO", False))
        # punto.threshold dejó de estar reservada en F2 (test_orq_threshold.py) y sistema.actualizar
        # con el botón «Actualizar» del panel (test_orq_actualizar.py)
        for orden in ("acceso.aplicar", "sistema.revertir", "bitacora.anclar"):
            r = self.orq.atender(A.peticion(orden, {}))
            self.assertEqual((r["codigo"], r["mensaje"]), ("INVALIDO", "no disponible en F1a"), orden)
        r = self.orq.atender(A.peticion("sistema.estado", {}, token="0" * 64))
        self.assertEqual((r["codigo"], r["mensaje"]), ("INVALIDO", "token inválido"))
        r = self.orq.atender({"v": 2})
        self.assertEqual(r["codigo"], "INVALIDO")
        r = self.orq.atender("no es un objeto")
        self.assertEqual(r["codigo"], "INVALIDO")
        self.assertEqual(self.s.llamadas, [])

    def test_parametros_fuera_de_rango_o_no_admitidos(self):
        malos = [
            ("punto.crear", {"nombre": "Norte", "redes_abonados": ["10.0.0.0/24"]}),
            ("punto.crear", {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"], "hilos": 3}),
            ("punto.crear", {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"], "ros_version": 5}),
            ("punto.crear", {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"], "api_puerto": 22}),
            ("punto.crear", {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"], "imagen": "x"}),
            ("punto.crear", {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"], "perfil": "todo"}),
            ("punto.crear", {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"], "n": 251}),
            ("punto.crear", {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"], "origen_ip": "1.2.3"}),
            ("punto.borrar", {"pid": "p1"}),
            ("punto.reiniciar", {"pid": "p001", "parte": "host"}),
            ("punto.logs", {"pid": "p001", "lineas": 501}),
            ("punto.ajustar", {"pid": "p001", "compat_v6": "si"}),
            ("reglas.actualizar", {"sin_descarga": "si"}),
            ("op.estado", {"op_id": "; rm -rf /"}),
        ]
        for orden, params in malos:
            r = self.orq.atender(A.peticion(orden, params))
            self.assertEqual(r["codigo"], "INVALIDO", (orden, params, r))
        self.assertEqual(self.orq.q1("SELECT COUNT(*) FROM op")[0], 0)

    def test_mismo_op_id_una_sola_ejecucion(self):
        op_id = str(uuid.uuid4())
        params = {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]}
        r1 = self.orq.atender(A.peticion("punto.crear", params, op_id=op_id))
        r2 = self.orq.atender(A.peticion("punto.crear", params, op_id=op_id))
        self.assertEqual((r1["codigo"], r2["codigo"]), ("ACEPTADA", "ACEPTADA"))
        while self.orq.procesar_una():
            pass
        self.assertEqual(len(self.s.ordenes("docker compose -p ids-p001 -f")), 1)
        self.assertEqual(self.orq.q1("SELECT COUNT(*) FROM punto")[0], 1)
        # repetida tras terminar: el resultado guardado, sin la clave
        r3 = self.orq.atender(A.peticion("punto.crear", params, op_id=op_id))
        self.assertEqual(r3["codigo"], "OK")
        self.assertEqual(r3["datos"]["pid"], "p001")
        self.assertNotIn("clave", r3["datos"])
        # el mismo op_id con otros parámetros: CONFLICTO
        r4 = self.orq.atender(A.peticion("punto.crear", dict(params, nombre="sur"), op_id=op_id))
        self.assertEqual(r4["codigo"], "CONFLICTO")
        self.assertEqual(self.orq.q1("SELECT COUNT(*) FROM punto")[0], 1)

    def test_clave_se_entrega_una_sola_vez(self):
        r = self.orq.atender(A.peticion("punto.crear", {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]}))
        while self.orq.procesar_una():
            pass
        e1 = self.orq.atender(A.peticion("op.estado", {"op_id": r["op_id"]}))["datos"]
        e2 = self.orq.atender(A.peticion("op.estado", {"op_id": r["op_id"]}))["datos"]
        clave = e1["resultado"]["clave"]
        self.assertRegex(clave, r"^[A-Za-z0-9]{24}$")
        self.assertIn("password=%s " % clave, e1["resultado"]["comandos"])
        self.assertNotIn("clave", e2["resultado"])
        self.assertNotIn(clave, e2["resultado"]["comandos"])
        # nada del secreto en disco: ni orq.db ni orq.jsonl
        for f in ("orq.db", "orq.jsonl"):
            datos = self.e.ruta("/srv/ids/estado/" + f).read_bytes()
            self.assertNotIn(clave.encode(), datos, f)
        usuarios = self.e.ruta("/srv/ids/puntos/p001/vpn/usuarios").read_text(encoding="utf-8")
        self.assertNotIn(clave, usuarios)

    def test_lecturas_no_se_encolan(self):
        A.crear(self, self.orq, {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]})
        antes = self.orq.q1("SELECT COUNT(*) FROM op")[0]
        for orden, params in (("punto.estado", {"pid": "*"}), ("punto.comandos", {"pid": "p001"}),
                              ("sistema.estado", {}), ("sistema.capacidad", {}),
                              ("punto.logs", {"pid": "p001", "parte": "vpn", "lineas": 10})):
            r = self.orq.atender(A.peticion(orden, params))
            self.assertEqual(r["codigo"], "OK", (orden, r))
        self.assertEqual(self.orq.q1("SELECT COUNT(*) FROM op")[0], antes)
        r = self.orq.atender(A.peticion("punto.estado", {"pid": "p009"}))
        self.assertEqual(r["codigo"], "NO_EXISTE")

    def test_logs_sin_password_ni_key(self):
        A.crear(self, self.orq, {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]})
        r = self.orq.atender(A.peticion("punto.logs", {"pid": "p001", "parte": "vpn", "lineas": 50}))
        self.assertEqual(r["datos"]["lineas"], ["linea normal", "otra linea"])


class ColaEnSerie(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()

    def tearDown(self):
        self.orq.parar()
        A.cerrar(self.orq, self.e)

    def test_dos_ordenes_a_la_vez_se_ejecutan_una_tras_otra(self):
        tramos = []
        cerrojo = threading.Lock()

        def lenta(ctx, params):
            t0 = time.monotonic()
            with ctx.paso("trabajo"):
                time.sleep(0.25)
            with cerrojo:
                tramos.append((ctx.op_id, t0, time.monotonic()))
            return {"levantados": [], "huerfanos": []}

        self.orq.o_reconciliar = lenta
        hilo = threading.Thread(target=self.orq.trabajador, daemon=True)
        hilo.start()
        ids = [str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())]
        respuestas = {}

        def pedir(op_id):
            respuestas[op_id] = self.orq.atender(A.peticion("sistema.reconciliar", {}, op_id=op_id))

        hilos = [threading.Thread(target=pedir, args=(i,)) for i in ids]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join()
        self.assertTrue(all(r["codigo"] == "ACEPTADA" for r in respuestas.values()))
        fin = time.monotonic() + 10
        while len(tramos) < 3 and time.monotonic() < fin:
            time.sleep(0.05)
        self.assertEqual(len(tramos), 3)
        tramos.sort(key=lambda t: t[1])
        for (_, _, fin_a), (_, ini_b, _) in zip(tramos, tramos[1:]):
            self.assertLessEqual(fin_a, ini_b, "dos órdenes se solaparon")
        # el orden de ejecución es el de llegada (seq)
        orden_seq = [f[0] for f in self.orq.q("SELECT op_id FROM op ORDER BY seq")]
        self.assertEqual([t[0] for t in tramos], orden_seq)
        for op_id in ids:
            d = self.orq.op_estado(op_id)
            self.assertEqual((d["estado"], d["codigo"]), ("terminada", "OK"))


if __name__ == "__main__":
    unittest.main()
