"""Validación del orquestador: threshold (A-13), órdenes a pids que no existen (A-22) y entradas
mal formadas (A-23). Sistema simulado de _ayuda_orq; tipo de cada prueba en su docstring."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402


class Threshold(unittest.TestCase):
    def setUp(self):
        self.mod = A.cargar_orq()

    def test_comentario_en_linea_propia_se_admite(self):
        """Corrección de defecto (A-13): el motivo de una exclusión en una línea `#` propia, encima
        de la regla (como lo escribe el panel), es válido y se conserva tal cual."""
        txt = ("# generado por el panel\n"
               "# falso positivo: impresora de la oficina\n"
               "suppress gen_id 1, sig_id 2100498, track by_src, ip 10.0.0.5\n")
        self.assertEqual(self.mod.validar_threshold(txt), txt)

    def test_comentario_al_final_de_una_regla_da_error_claro(self):
        """Corrección de defecto (A-13): un comentario al final de la regla (lo que generaba el panel
        antes) da un error con el número de línea y la forma correcta, no «parámetro no válido»."""
        txt = ("# generado por el panel\n"
               "suppress gen_id 1, sig_id 2100498, track by_src, ip 10.0.0.5   # falso positivo\n")
        with self.assertRaises(self.mod.ErrorOrden) as cm:
            self.mod.validar_threshold(txt)
        self.assertEqual(cm.exception.codigo, "INVALIDO")
        self.assertIn("línea 2", cm.exception.mensaje)
        self.assertIn("línea propia", cm.exception.mensaje)

    def test_linea_demasiado_larga(self):
        """Corrección de defecto (A-23): una línea de más de 4096 bytes se rechaza (Suricata la
        partiría a 8191 y el resto podría ser otra orden)."""
        txt = "# " + "x" * 5000 + "\n"
        with self.assertRaises(self.mod.ErrorOrden) as cm:
            self.mod.validar_threshold(txt)
        self.assertIn("línea 1", cm.exception.mensaje)

    def test_mensaje_admite_el_threshold_maximo(self):
        """Corrección de defecto (A-23): el tope del mensaje del socket deja pasar un threshold del
        tamaño máximo con su escapado JSON (antes 64 KiB < 256 KiB)."""
        self.assertGreaterEqual(self.mod.MAX_MENSAJE, 2 * self.mod.MAX_THRESHOLD + 4096)


class Pids(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(ncpu=8)

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_orden_a_un_pid_que_no_existe_se_rechaza_al_encolar(self):
        """Corrección de defecto (A-22): `parar p005` sin p005 ya no se acepta para ejecutarse sobre
        el punto que se cree después; da NO_EXISTE y no deja nada en la cola."""
        r = self.orq.atender(A.peticion("punto.parar", {"pid": "p005"}))
        self.assertEqual(r["codigo"], "NO_EXISTE", r)
        self.assertIsNone(self.orq.q1("SELECT 1 FROM op WHERE pid='p005'"))

    def test_pid_explicito_solo_desde_root(self):
        """Corrección de defecto (A-22): el panel (uid 10500) no puede pedir `crear pid=p999` (agotaría
        la secuencia); la CLI root sí (reconstruir)."""
        pet = A.peticion("punto.crear", {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"],
                                         "pid": "p999"})
        r = self.orq.atender(pet, uid=self.mod.UID_PANEL)
        self.assertEqual(r["codigo"], "INVALIDO", r)

    def test_sin_fila_de_secuencia_no_vuelve_a_p001(self):
        """Corrección de defecto (A-22): sin la fila `secuencia` (orq.db restaurada o perdida) el
        siguiente pid no reutiliza uno que ya se ve en los puntos o en el historial de órdenes."""
        A.crear(self, self.orq, {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]})
        A.crear(self, self.orq, {"nombre": "sur", "redes_abonados": ["10.0.1.0/24"]})
        self.orq.x("DELETE FROM secuencia")
        r = A.crear(self, self.orq, {"nombre": "este", "redes_abonados": ["10.0.2.0/24"]})
        self.assertEqual(r["resultado"]["pid"], "p003", r)


class Entradas(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(ncpu=8)

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_salto_de_linea_y_digitos_unicode(self):
        """Corrección de defecto (A-23): `p001\\n`, `p٠٠١` y un nombre con salto de línea final no
        son válidos; `_int('²')` es INVALIDO y no una excepción que cierra la conexión."""
        for pid in ("p001\n", "p١٢٣"):
            self.assertFalse(self.mod.RE_PID.match(pid), repr(pid))
        self.assertFalse(self.mod.RE_NOMBRE.match("norte\n"))
        with self.assertRaises(self.mod.ErrorOrden):
            self.mod._int("²", "hilos", rango=(1, 2))

    def test_redes_de_mas_de_un_8_no(self):
        """Corrección de defecto (A-28): redes de abonados /1 a /7 se rechazan (el panel ya lo hacía
        en su formulario; el orquestador solo rechazaba /0). Un /8 sigue valiendo."""
        cfg = self.mod.config()
        with self.assertRaises(self.mod.ErrorOrden):
            self.mod.validar_redes(["172.0.0.0/7"], cfg)
        self.assertEqual(self.mod.validar_redes(["172.0.0.0/8"], cfg), ["172.0.0.0/8"])

    def test_token_con_surrogate_responde(self):
        """Corrección de defecto (A-23): un token con un surrogate suelto da «token inválido» en vez
        de una excepción sin respuesta."""
        r = self.orq.atender(A.peticion("sistema.estado", token="\udc80" * 64))
        self.assertEqual(r["codigo"], "INVALIDO")

    def test_token_vacio_no_vale(self):
        """Corrección de defecto (A-23): con un orq_token vacío el orquestador no acepta peticiones
        con token vacío (FALLO: no hay token válido)."""
        self.e.ruta("/etc/ids-maat/orq_token").write_text("\n", encoding="utf-8")
        r = self.orq.atender(A.peticion("sistema.estado", token=""))
        self.assertFalse(r["ok"])
        self.assertEqual(r["codigo"], "FALLO")


if __name__ == "__main__":
    unittest.main()
