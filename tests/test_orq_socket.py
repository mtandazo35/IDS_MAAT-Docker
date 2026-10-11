"""Socket del servicio con SO_PEERCRED (solo Linux: AF_UNIX + SO_PEERCRED)."""

import os
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

LINUX = sys.platform.startswith("linux")


@unittest.skipUnless(LINUX, "AF_UNIX/SO_PEERCRED: solo Linux (en Windows se omite)")
class SocketPeercred(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()
        self.sock = Path(tempfile.mkdtemp(prefix="ids-sock-")) / "orq.sock"

    def tearDown(self):
        self.orq.parar()
        A.cerrar(self.orq, self.e)

    def servir(self, uids):
        detener = threading.Event()
        listo = threading.Event()
        h = threading.Thread(target=self.mod.servir, args=(self.orq,),
                             kwargs={"ruta_sock": str(self.sock), "uids": uids, "detener": detener,
                                     "listo": listo}, daemon=True)
        h.start()
        self.assertTrue(listo.wait(5))
        self.addCleanup(lambda: (detener.set(), h.join(5)))

    def test_uid_autorizado(self):
        self.servir({os.getuid()})
        self.assertEqual(oct(self.sock.stat().st_mode & 0o777), "0o660")
        r = self.mod.llamar(A.peticion("sistema.capacidad"), ruta_sock=str(self.sock))
        self.assertEqual(r["codigo"], "OK")
        self.assertEqual(r["datos"]["mem_total_mb"], 7962)
        r = self.mod.llamar(A.peticion("sistema.capacidad", token="1" * 64), ruta_sock=str(self.sock))
        self.assertEqual(r["codigo"], "INVALIDO")

    def test_uid_no_autorizado_se_cierra_sin_respuesta(self):
        if os.getuid() in (0, 10500):
            self.skipTest("la prueba necesita un uid distinto de 0 y 10500")
        self.servir({0, 10500})
        with self.assertRaises(self.mod.SinServicio):
            self.mod.llamar(A.peticion("sistema.capacidad"), ruta_sock=str(self.sock))
        self.assertEqual(self.orq.q1("SELECT COUNT(*) FROM op")[0], 0)

    def test_mensaje_demasiado_grande(self):
        import socket
        self.servir({os.getuid()})
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(str(self.sock))
        s.sendall(b"{" + b" " * (self.mod.MAX_MENSAJE + 10))
        s.shutdown(socket.SHUT_WR)
        datos = s.recv(65536)
        s.close()
        self.assertIn(b"demasiado grande", datos)

    def test_cli_por_el_socket(self):
        self.servir({os.getuid()})
        tr = lambda pet: self.mod.llamar(pet, ruta_sock=str(self.sock))  # noqa: E731
        import io
        out = io.StringIO()
        c = self.mod.Cliente(transporte=tr, dormir=lambda s: self.orq.procesar_una(), salida=out)
        rc = self.mod.main(["reconciliar"], cliente=c)
        self.assertEqual(rc, 0, out.getvalue())
        self.assertIn("en cola: op", out.getvalue())
        self.assertEqual(self.orq.q1("SELECT quien FROM op")[0], "cli:%s" % (os.environ.get("SUDO_USER") or "root"))
        uuid.UUID(self.orq.q1("SELECT op_id FROM op")[0])


if __name__ == "__main__":
    unittest.main()
