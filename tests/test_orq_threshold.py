"""punto.threshold (CONTRATO-F2 §6): validación línea a línea, escritura atómica, recarga por el socket
de control, reinicio si falla, vuelta al threshold anterior si tampoco queda sano, y bajas con órdenes
pendientes (CONTRATO-F2 §10.5). Todo con el sistema simulado de _ayuda_orq."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

NORTE = {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]}
BUENO = ("# exclusiones del panel\n"
         "suppress gen_id 1, sig_id 2010935, track by_src, ip 10.0.0.5\n"
         "suppress gen_id 1, sig_id 2013028, track by_dst, ip [192.0.2.0/24,198.51.100.7]\n"
         "threshold gen_id 1, sig_id 2402000, type limit, track by_src, count 1, seconds 60\n"
         "event_filter gen_id 1, sig_id 2210000, type limit, track by_src, count 1, seconds 300\n")


class Base(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(ncpu=8)
        A.crear(self, self.orq, NORTE)
        self.s.llamadas.clear()
        self.socket = []                     # órdenes que recibió el «socket de control»
        self.socket_falla = False

        def suricata_comando(pid, comando):
            self.socket.append((pid, comando))
            if self.socket_falla:
                raise self.mod.ErrorOrden("FALLO", "suricata: NOK")
            return {"return": "OK"}
        self.mod.suricata_comando = suricata_comando
        self.th = self.e.ruta("/srv/ids/puntos/p001/suricata/threshold.config")
        self.inicial = self.th.read_text(encoding="utf-8")

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def threshold(self, contenido, pid="p001"):
        return A.ejecutar_orden(self.orq, "punto.threshold", {"pid": pid, "contenido": contenido})


class Validacion(Base):
    def test_rechaza_lo_que_no_es_suppress_threshold_event_filter(self):
        """Capacidad nueva: solo suppress/threshold/event_filter y comentarios; nada llega al disco."""
        malos = ["include /etc/passwd\n", "rate_filter gen_id 1, sig_id 1, track by_src, count 1, seconds 1, "
                 "new_action drop, timeout 10\n", "suppress gen_id 1, sig_id 1, track by_src, ip 10.0.0.1; rm\n",
                 "suppress gen_id x, sig_id 1\n", "suppress gen_id 1, sig_id 1, ip 10.0.0.1\n",
                 "threshold gen_id 1, sig_id 1, type limit, track by_src, count 1\n",
                 "suppress gen_id 1, sig_id 1, track by_src, track by_dst, ip 10.0.0.1\n",
                 "suppress gen_id 1, sig_id 1\x00\n", "x" * (300 * 1024)]
        for malo in malos:
            r = self.orq.atender(A.peticion("punto.threshold", {"pid": "p001", "contenido": malo}))
            self.assertEqual(r["codigo"], "INVALIDO", repr(malo[:60]))
        self.assertEqual(self.th.read_text(encoding="utf-8"), self.inicial)
        self.assertEqual(self.socket, [])
        self.assertFalse(self.s.llamadas)

    def test_punto_inexistente_rechazado_al_encolar(self):
        """Capacidad nueva: un pid que no existe no entra en la cola (NO_EXISTE inmediato)."""
        r = self.orq.atender(A.peticion("punto.threshold", {"pid": "p009", "contenido": BUENO}))
        self.assertEqual(r["codigo"], "NO_EXISTE")
        self.assertIsNone(self.orq.q1("SELECT 1 FROM op WHERE orden='punto.threshold'"))


class Aplicar(Base):
    def test_recarga_sin_reiniciar(self):
        """Capacidad nueva: escribe el fichero y recarga por el socket sin reiniciar el contenedor
        (el espejo no se corta); queda en orq.jsonl sin el contenido en claro."""
        r = self.threshold(BUENO)
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertEqual(r["resultado"]["recarga"], "reload-rules")
        self.assertEqual(self.th.read_text(encoding="utf-8"), BUENO)
        self.assertEqual(self.socket, [("p001", "reload-rules")])
        self.assertFalse([a for a in self.s.llamadas if a[:2] == ["docker", "restart"]])
        diario = self.e.ruta("/srv/ids/estado/orq.jsonl").read_text(encoding="utf-8")
        linea = [json.loads(x) for x in diario.splitlines() if '"punto.threshold"' in x][-1]
        self.assertEqual((linea["orden"], linea["pid"], linea["codigo"]), ("punto.threshold", "p001", "OK"))
        self.assertNotIn("2010935", diario)

    def test_si_la_recarga_falla_reinicia(self):
        """Capacidad nueva: reload-rules falla -> reinicio de suricata y espera a sano."""
        self.socket_falla = True
        r = self.threshold(BUENO)
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertEqual(r["resultado"]["recarga"], "reinicio")
        self.assertEqual([a[-1] for a in self.s.llamadas if a[:2] == ["docker", "restart"]], ["ids-p001-suricata"])
        self.assertEqual(self.th.read_text(encoding="utf-8"), BUENO)

    def test_si_tampoco_queda_sano_vuelve_al_anterior_y_avisa(self):
        """Caso obligatorio §10.5 «recarga de threshold fallida»: se recupera la configuración válida
        anterior, el punto no queda en error y estado.json avisa THRESHOLD-FALLIDO."""
        self.socket_falla = True
        self.s.salud_inicial = "unhealthy"
        reinicios = []

        def reiniciar(pid):
            reinicios.append(self.th.read_text(encoding="utf-8"))
            # con el threshold anterior Suricata vuelve a estar sano
            self.s.salud_inicial = "healthy" if len(reinicios) > 1 else "unhealthy"
            c = self.s.contenedores["ids-%s-suricata" % pid]
            c.update(estado="running", salud=self.s.salud_inicial)
        self.orq._reiniciar_suricata = reiniciar
        r = self.threshold(BUENO)
        self.assertEqual(r["codigo"], "REVERTIDA", A.explicar(r))
        self.assertEqual(self.th.read_text(encoding="utf-8"), self.inicial)
        self.assertEqual(reinicios, [BUENO, self.inicial])
        self.assertEqual(self.orq.punto("p001")["estado"], "activo")
        est = self.orq.escribir_estado()
        self.assertIn("THRESHOLD-FALLIDO", est["puntos"]["p001"]["avisos"])
        # el siguiente que va bien quita el aviso
        self.socket_falla = False
        self.orq._reiniciar_suricata = lambda pid: None
        self.assertEqual(self.threshold(BUENO)["codigo"], "OK")
        self.assertNotIn("THRESHOLD-FALLIDO", self.orq.escribir_estado()["puntos"]["p001"]["avisos"])

    def test_varias_seguidas_solo_cuenta_la_ultima(self):
        """Capacidad nueva: dos exclusiones seguidas en cola -> una sola recarga con la última."""
        otro = BUENO + "suppress gen_id 1, sig_id 2999999, track by_src, ip 10.0.0.9\n"
        r1 = self.orq.atender(A.peticion("punto.threshold", {"pid": "p001", "contenido": BUENO}))
        r2 = self.orq.atender(A.peticion("punto.threshold", {"pid": "p001", "contenido": otro}))
        while self.orq.procesar_una():
            pass
        e1 = self.orq.op_estado(r1["op_id"])
        e2 = self.orq.op_estado(r2["op_id"])
        self.assertEqual((e1["codigo"], e1["resultado"]["aplicado"]), ("OK", False))
        self.assertEqual((e2["codigo"], e2["resultado"]["aplicado"]), ("OK", True))
        self.assertEqual(self.socket, [("p001", "reload-rules")])
        self.assertEqual(self.th.read_text(encoding="utf-8"), otro)

    def test_punto_parado_no_se_levanta(self):
        """Corrección de defecto evitado: con el punto parado, reiniciar suricata para aplicar el
        threshold lo levantaría; se escribe y se aplicará al arrancar."""
        self.assertEqual(A.ejecutar_orden(self.orq, "punto.parar", {"pid": "p001"})["codigo"], "OK")
        self.s.llamadas.clear()
        r = self.threshold(BUENO)
        self.assertEqual((r["codigo"], r["resultado"]["recarga"]), ("OK", "al arrancar"))
        self.assertEqual(self.socket, [])
        self.assertFalse([a for a in self.s.llamadas if a[:2] in (["docker", "restart"], ["docker", "compose"])])
        self.assertEqual(self.s.contenedores["ids-p001-suricata"]["estado"], "exited")

    def test_doble_envio_mismo_op_id_no_repite(self):
        """Caso obligatorio §10.5 «doble clic o reintento»: el mismo op_id no recarga dos veces."""
        op = "11111111-2222-3333-4444-555555555555"
        A.ejecutar_orden(self.orq, "punto.threshold", {"pid": "p001", "contenido": BUENO}, op_id=op)
        r = self.orq.atender(A.peticion("punto.threshold", {"pid": "p001", "contenido": BUENO}, op_id=op))
        self.assertEqual(r["codigo"], "OK")
        while self.orq.procesar_una():
            pass
        self.assertEqual(self.socket, [("p001", "reload-rules")])


class Baja(Base):
    def test_baja_cancela_lo_pendiente_del_punto(self):
        """Caso obligatorio §10.5 «baja con trabajos pendientes»: las órdenes del punto que esperaban
        detrás de la baja se cancelan (op.estado lo dice), nunca se ejecutan, y un threshold nuevo
        para ese pid se rechaza; el pid no se reutiliza, así que nada alcanza a otro punto."""
        baja = self.orq.atender(A.peticion("punto.borrar", {"pid": "p001", "confirmar": "norte"}))
        detras = self.orq.atender(A.peticion("punto.reiniciar", {"pid": "p001", "parte": "suricata"}))
        self.assertEqual(detras["codigo"], "ACEPTADA")
        while self.orq.procesar_una():
            pass
        self.assertEqual(self.orq.op_estado(baja["op_id"])["codigo"], "OK")
        e = self.orq.op_estado(detras["op_id"])
        self.assertEqual((e["estado"], e["codigo"]), ("terminada", "CANCELADA"))
        self.assertFalse([a for a in self.s.llamadas if a[:2] == ["docker", "restart"]])
        r = self.orq.atender(A.peticion("punto.threshold", {"pid": "p001", "contenido": BUENO}))
        self.assertEqual(r["codigo"], "NO_EXISTE")
        diario = [json.loads(x) for x in self.e.ruta("/srv/ids/estado/orq.jsonl").read_text(
            encoding="utf-8").splitlines()]
        self.assertIn(("punto.reiniciar", "CANCELADA"), [(x.get("orden"), x.get("codigo")) for x in diario])
        nuevo = A.crear(self, self.orq, {"nombre": "sur", "redes_abonados": ["10.0.0.0/24"]})
        self.assertEqual(nuevo["resultado"]["pid"], "p002")


if __name__ == "__main__":
    unittest.main()
