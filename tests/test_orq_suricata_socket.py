"""Socket de control de Suricata: cada orden JSON termina en salto de línea.

Tipo: corrección de defecto. Visto en el laboratorio (2026-10-12): Suricata 7.0.10 cierra la
conexión si `{"command": ...}` llega sin «\n». `reopen-log-files` fallaba tras cada rotación, el
eve.json nuevo se quedaba sin eventos `stats`, el healthcheck lo daba por enfermo y el orquestador
reiniciaba el contenedor cada ~90 min. La misma orden la usa `punto.threshold` (`reload-rules`).
El doble reproduce lo observado: sin «\n» la orden no recibe respuesta (conexión cerrada).
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402


class SocketSuricata7:
    """Doble del socket de control de Suricata 7.0.x tal como se comportó en el laboratorio."""

    def __init__(self):
        self.recibido = []
        self.salida = b""
        self.cerrado = False

    def sendall(self, datos):
        self.recibido.append(datos)
        msg = json.loads(datos.decode("utf-8"))
        if "version" in msg:
            self.salida += b'{"return":"OK"}\n'          # la versión la acepta con o sin «\n»
        elif datos.endswith(b"\n"):
            self.salida += b'{"message":"done","return":"OK"}\n'
        else:
            self.cerrado = True                          # orden sin «\n»: cierra sin responder

    def recv(self, n):
        trozo, self.salida = self.salida[:n], self.salida[n:]
        return trozo

    def close(self):
        pass


class Comando(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(ncpu=8)
        self.sock = SocketSuricata7()
        self.mod._unix = lambda path, timeout=10: self.sock

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_reopen_log_files_llega_y_responde(self):
        r = self.mod.suricata_comando("p001", "reopen-log-files")
        self.assertEqual(r.get("return"), "OK")
        self.assertFalse(self.sock.cerrado)
        self.assertTrue(all(m.endswith(b"\n") for m in self.sock.recibido), self.sock.recibido)

    def test_reload_rules_igual(self):
        self.assertEqual(self.mod.suricata_comando("p001", "reload-rules").get("return"), "OK")


if __name__ == "__main__":
    unittest.main()
