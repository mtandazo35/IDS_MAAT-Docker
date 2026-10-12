"""El orquestador (root en el host) en directorios que escriben los contenedores (auditoría A-04).

`datos/<pid>` lo escribe el contenedor suricata y `run/<pid>`/`ctl/<pid>` el vpn, root dentro y sin
userns. Antes, la compresión de rotados abría el temporal `.<rotado>.gz.tmp` con `open(tmp, "wb")`
(sigue enlaces) y le hacía chmod/chown/utime por nombre: un enlace plantado por el contenedor
reescribía un fichero del host (reproducción `auditoria_A\\infra\\i5_comprimir_enlace.py`). Los
lectores (tzsp.json, openvpn-status.log, eve.json) leían sin tope y siguiendo enlaces.

Ahora: sin seguir enlaces, solo ficheros regulares con un nombre, temporal O_EXCL|O_NOFOLLOW con
modo/dueño/fechas sobre el descriptor, y lecturas con tope. En Windows no se pueden crear symlinks
(WinError 1314): ahí se usa un enlace DURO, que recorre el mismo camino de código; las variantes con
symlink y FIFO corren en Linux (CI). Tipo de cada prueba en su docstring (CONTRATO-F2 §10.5).
"""
import gzip
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402


def _symlinks():
    d = tempfile.mkdtemp(prefix="ids-sl-")
    try:
        os.symlink(os.path.join(d, "x"), os.path.join(d, "y"))
        return True
    except (OSError, NotImplementedError, AttributeError):
        return False
    finally:
        import shutil
        shutil.rmtree(d, True)


HAY_SYMLINKS = _symlinks()
HAY_FIFO = hasattr(os, "mkfifo")


def enlazar(destino, nombre):
    """El enlace que plantaría el contenedor: symlink si se puede; si no, enlace duro."""
    try:
        os.symlink(str(destino), str(nombre))
        return "symlink"
    except (OSError, NotImplementedError):
        os.link(str(destino), str(nombre))
        return "duro"


class Base(unittest.TestCase):
    def setUp(self):
        self.mod = A.cargar_orq()
        self.e = A.Entorno()
        self.addCleanup(self.e.cerrar)
        self.datos = self.e.ruta("/srv/ids/datos/p001")
        self.datos.mkdir(parents=True)
        self.run = self.e.ruta("/srv/ids/run/p001")
        self.run.mkdir(parents=True)
        fw = self.e.ruta("/srv/ids/fw")
        fw.mkdir(parents=True)
        self.victima = fw / "ids_host.nft"           # fichero del host fuera de lo montado
        self.victima.write_text("table inet ids_host { reglas del host }\n", encoding="utf-8")
        os.chmod(self.victima, 0o600)
        self.contenido_victima = self.victima.read_bytes()

    def rotado(self, nombre="eve.json-20260101-000000", texto=b'{"elegido":"por el contenedor"}\n'):
        f = self.datos / nombre
        f.write_bytes(texto)
        viejo = time.time() - 3 * 86400
        os.utime(f, (viejo, viejo))
        return f


class Compresion(Base):
    def test_temporal_plantado_no_escribe_en_el_host(self):
        """Corrección de defecto (A-04, repro i5): con `.<rotado>.gz.tmp` plantado como enlace a un
        fichero del host, comprimir no lo toca (contenido y modo iguales); el rotado se comprime
        igual en un temporal nuevo. Antes: el fichero del host acababa siendo el gzip."""
        rot = self.rotado()
        tmp = self.datos / ".eve.json-20260101-000000.gz.tmp"
        enlazar(self.victima, tmp)
        hechos = self.mod.comprimir_rotados(["p001"], time.time())
        self.assertEqual(self.victima.read_bytes(), self.contenido_victima)
        if sys.platform != "win32":
            self.assertEqual(self.victima.stat().st_mode & 0o777, 0o600)
        self.assertEqual([h.name for h in hechos], ["eve.json-20260101-000000.gz"])
        with gzip.open(self.datos / "eve.json-20260101-000000.gz", "rb") as g:
            self.assertEqual(g.read(), b'{"elegido":"por el contenedor"}\n')
        self.assertFalse(rot.exists())
        self.assertFalse(os.path.lexists(tmp))

    def test_rotado_que_es_enlace_a_un_fichero_del_host_no_se_toca(self):
        """Corrección de defecto (A-04): un «rotado» que es un enlace (duro o simbólico) a un
        fichero del host no se comprime: ni se copia su contenido a datos/<pid> (lo leería el
        contenedor) ni se borra un nombre del host."""
        f = self.datos / "eve.json-20260101-000000"
        tipo = enlazar(self.victima, f)
        viejo = time.time() - 3 * 86400
        os.utime(f, (viejo, viejo), follow_symlinks=(tipo == "duro"))
        self.assertEqual(self.mod.comprimir_rotados(["p001"], time.time()), [])
        self.assertIsNone(self.mod.comprimir_rotado(f))
        self.assertFalse((self.datos / "eve.json-20260101-000000.gz").exists())
        self.assertEqual(self.victima.read_bytes(), self.contenido_victima)
        self.assertNotIn(f.name, [x.name for _c, x in self.mod.rotados("p001")])

    def test_temporal_viejo_que_es_enlace_se_borra_sin_seguirlo(self):
        """Corrección de defecto (A-04): un `.gz.tmp` viejo que es un enlace se quita (el nombre),
        no se salta ni se sigue; el fichero del host queda igual."""
        tmp = self.datos / ".dns.json-20260101-000000.gz.tmp"
        enlazar(self.victima, tmp)
        viejo = time.time() - 7200
        try:
            os.utime(tmp, (viejo, viejo), follow_symlinks=False)
        except (NotImplementedError, OSError):
            os.utime(tmp, (viejo, viejo))
        self.mod.comprimir_rotados(["p001"], time.time())
        self.assertFalse(os.path.lexists(tmp))
        self.assertTrue(self.victima.exists())
        self.assertEqual(self.victima.read_bytes(), self.contenido_victima)

    def test_compresion_normal_se_conserva(self):
        """Conservación: un rotado normal se comprime con su mtime y su contenido."""
        rot = self.rotado(texto=b"linea\n" * 1000)
        mt = rot.stat().st_mtime_ns
        g = self.mod.comprimir_rotado(rot)
        self.assertEqual(g.name, rot.name + ".gz")
        self.assertEqual(g.stat().st_mtime_ns // 10**9, mt // 10**9)
        with gzip.open(g, "rb") as h:
            self.assertEqual(h.read(), b"linea\n" * 1000)
        self.assertEqual(sorted(x.name for x in self.datos.iterdir()), [g.name])


class Lectores(Base):
    def test_tzsp_con_tope(self):
        """Corrección de defecto (A-04): tzsp.json se lee con tope (64 KiB). Un fichero de 8 MiB con
        el JSON al final ya no se lee entero (antes sí: memoria y tiempo sin límite)."""
        tz = self.run / "tzsp.json"
        tz.write_bytes(b" " * (8 * 1024 * 1024) + b'{"ts":1,"rx":5,"tx":7,"rechazados":0}')
        self.assertIsNone(self.mod.leer_tzsp(tz, 2)["tx"])
        tz.write_bytes(b'{"ts":1,"rx":5,"tx":7,"rechazados":0}')
        self.assertEqual(self.mod.leer_tzsp(tz, 2)["tx"], 7)          # conservación

    def test_lectores_no_siguen_enlaces(self):
        """Corrección de defecto (A-04): tzsp.json, openvpn-status.log y eve.json que son enlaces a
        ficheros del host no se leen (se toman como ausentes)."""
        secreto = self.e.ruta("/srv/ids/fw/secreto")
        secreto.write_text('{"ts":1,"rx":1,"tx":99}\nCLIENT_LIST,TOKEN-DEL-HOST,192.0.2.5:5,x,x,x,x,x,0,root\n'
                           '{"timestamp":"2026-01-01T00:00:00+0000","event_type":"stats","stats":'
                           '{"capture":{"kernel_packets":5}}}\n', encoding="utf-8")
        enlazar(secreto, self.run / "tzsp.json")
        enlazar(secreto, self.run / "openvpn-status.log")
        enlazar(secreto, self.datos / "eve.json")
        self.assertIsNone(self.mod.leer_tzsp(self.run / "tzsp.json", 2)["tx"])
        self.assertFalse(self.mod.leer_status_openvpn(self.run / "openvpn-status.log")["conectado"])
        self.assertIsNone(self.mod.leer_stats_eve(self.datos / "eve.json", 2)["kernel_packets"])
        self.assertIsNone(self.mod.primer_ts(self.datos / "eve.json"))

    def test_stats_eve_lee_solo_la_cola(self):
        """Conservación: leer_stats_eve sigue sacando el último `stats` de la cola del eve.json."""
        ev = {"timestamp": "2026-01-01T00:00:00.000000+0000", "event_type": "stats",
              "stats": {"capture": {"kernel_packets": 42, "kernel_drops": 1},
                        "detect": {"engines": [{"rules_loaded": 10, "rules_failed": 0}]}}}
        (self.datos / "eve.json").write_text("x" * 2_000_000 + "\n" + json.dumps(ev, separators=(",", ":")) + "\n",
                                             encoding="utf-8")
        st = self.mod.leer_stats_eve(self.datos / "eve.json", 1767225600 + 5)
        self.assertEqual((st["kernel_packets"], st["reglas_cargadas"]), (42, 10))

    def test_primer_ts_de_gz_acotado(self):
        """Corrección de defecto (A-04/B-08): un .gz de miles de miembros vacíos no se descomprime
        sin fin; uno normal sigue dando su primer evento (conservación)."""
        bomba = self.datos / "eve.json-20260101-000000.gz"
        vacio = gzip.compress(b"")
        bomba.write_bytes(vacio * 200_000)              # ~4 MB comprimido, 0 bytes de datos
        t0 = time.time()
        self.assertIsNone(self.mod.primer_ts(bomba))
        self.assertLess(time.time() - t0, 5)
        bueno = self.datos / "dns.json-20260101-000000.gz"
        bueno.write_bytes(vacio + gzip.compress(
            b'{"timestamp":"2026-01-01T00:00:00.000000+0000","event_type":"dns"}\n'))
        self.assertEqual(self.mod.primer_ts(bueno), 1767225600)

    @unittest.skipUnless(HAY_FIFO, "mkfifo: solo POSIX")
    def test_fifo_no_cuelga(self):
        """Corrección de defecto (A-04): una FIFO en lugar de tzsp.json / eve.json no cuelga la
        supervisión (antes, open() bloqueaba tick() de todos los puntos)."""
        os.mkfifo(self.run / "tzsp.json")
        os.mkfifo(self.datos / "eve.json")
        res = {}

        def leer():
            res["tz"] = self.mod.leer_tzsp(self.run / "tzsp.json", 2)
            res["su"] = self.mod.leer_stats_eve(self.datos / "eve.json", 2)
        h = threading.Thread(target=leer, daemon=True)
        h.start()
        h.join(5)
        self.assertFalse(h.is_alive(), "la lectura de una FIFO se ha quedado colgada")
        self.assertIsNone(res["tz"]["tx"])
        self.assertIsNone(res["su"]["kernel_packets"])

    @unittest.skipUnless(HAY_SYMLINKS, "este sistema no deja crear enlaces simbolicos")
    def test_dev_zero_por_symlink_no_se_lee(self):
        """Corrección de defecto (A-04): tzsp.json -> /dev/zero (o cualquier dispositivo) no se lee."""
        os.symlink(os.devnull, self.run / "tzsp.json")
        self.assertIsNone(self.mod.leer_tzsp(self.run / "tzsp.json", 2)["tx"])


class Sockets(Base):
    def test_socket_de_control_que_no_es_socket_no_se_usa(self):
        """Corrección de defecto (A-04): si en el sitio del socket de control hay otra cosa (un
        fichero o un enlace al socket de otro punto), el orquestador no conecta."""
        import socket
        if not hasattr(socket, "AF_UNIX"):
            self.skipTest("AF_UNIX no existe en esta plataforma")
        ctl = self.e.ruta("/srv/ids/ctl/p001/suricata")
        ctl.mkdir(parents=True)
        (ctl / "suricata-command.socket").write_text("no soy un socket", encoding="utf-8")
        with self.assertRaises(self.mod.ErrorOrden) as cm:
            self.mod.suricata_comando("p001", "reload-rules")
        self.assertIn("no es un socket", cm.exception.mensaje)


class Escritura(Base):
    def test_escribir_atomico_no_sigue_un_temporal_plantado(self):
        """Corrección de defecto (A-04): el temporal de escribir_atomico es nuevo cada vez
        (O_EXCL, nombre único): un `.x.tmp<pid>` plantado no se sigue."""
        dest = self.datos / "x"
        plantado = self.datos / (".x.tmp%d" % os.getpid())
        enlazar(self.victima, plantado)
        self.mod.escribir_atomico(dest, "nuevo\n", modo=0o640)
        self.assertEqual(dest.read_text(encoding="utf-8"), "nuevo\n")
        self.assertEqual(self.victima.read_bytes(), self.contenido_victima)


if __name__ == "__main__":
    unittest.main()
