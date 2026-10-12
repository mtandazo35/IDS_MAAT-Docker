"""feeds_update.py en el contenedor del panel (CONTRATO-F2 §8 y §10.3): rutas bajo IDS_PANEL_DIR, claves
cifradas con la clave maestra, sin dataset ni recarga de Suricata. Las fuentes se sirven desde un HTTP
local en 127.0.0.1 (feeds.conf permite cambiar cada URL): nada sale a internet."""

import http.server
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "images" / "panel" / "rootfs" / "usr" / "local" / "lib" / "ids-panel"
SCRIPT = LIB / "feeds_update.py"
CLAVE_MAESTRA = "00112233445566778899aabbccddeeff" * 2
AIDB = "clave-aidb-de-prueba-7f3a"
ABUSECH = "clave-abusech-de-prueba-91c2"

HAY_CRYPTO = importlib.util.find_spec("cryptography") is not None


def cargar_secretos(ruta_clave):
    spec = importlib.util.spec_from_file_location("secretos_prueba_feeds", LIB / "secretos.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.ruta_clave = lambda: str(ruta_clave)      # secretos lee la ruta en cada uso
    return mod


class Servidor(http.server.BaseHTTPRequestHandler):
    """Fuentes falsas: cada ruta devuelve una lista; guarda las cabeceras recibidas."""
    vistas = []
    caidas = set()

    def log_message(self, *a):
        pass

    def _responder(self):
        Servidor.vistas.append((self.path, dict(self.headers)))
        if self.path in Servidor.caidas:
            self.send_response(500)
            self.end_headers()
            return
        cuerpos = {
            "/feodo": "# feodo\n192.0.2.10\n",
            "/cins": "198.51.100.20\n",
            "/drop": "203.0.113.0/24 ; SBL1\n",
            "/aidb": "192.0.2.30\n",
            "/et": "192.0.2.40\n",
            "/tor": "192.0.2.50\n",
            "/tfx-api": json.dumps({"data": [{"ioc_type": "ip:port", "ioc": "192.0.2.60:4444",
                                              "confidence_level": 90}]}),
            "/urlhaus": "127.0.0.1 malo.example.com\n",
            "/threatfox": "127.0.0.1 c2.example.net\n",
        }
        cuerpo = cuerpos.get(self.path.split("?")[0], "").encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json" if self.path.startswith("/tfx") else "text/plain")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    do_GET = _responder

    def do_POST(self):
        largo = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(largo)
        self._responder()


@unittest.skipUnless(HAY_CRYPTO, "falta cryptography (python3-cryptography en la imagen)")
class Feeds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Servidor)
        cls.hilo = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.hilo.start()
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        Servidor.vistas = []
        Servidor.caidas = set()
        self.dir = Path(tempfile.mkdtemp(prefix="ids-feeds-"))
        self.panel = self.dir / "panel"
        (self.panel / "conf").mkdir(parents=True)
        self.clave = self.dir / "master_key"
        self.clave.write_text(CLAVE_MAESTRA + "\n", encoding="ascii")
        sec = cargar_secretos(self.clave)
        b = self.base
        conf = ["FEODO_URL=%s/feodo" % b, "CINS_URL=%s/cins" % b, "SPAMHAUS_DROP_URL=%s/drop" % b,
                "ABUSEIPDB_URL=%s/aidb" % b, "ET_COMPROMISED_URL=%s/et" % b, "TOR_EXIT_URL=%s/tor" % b,
                "THREATFOX_API_URL=%s/tfx-api" % b, "URLHAUS_URL=%s/urlhaus" % b,
                "THREATFOX_URL=%s/threatfox" % b,
                "ABUSEIPDB_KEY=" + sec.cifrar(AIDB, "feeds:ABUSEIPDB_KEY"),
                "ABUSE_CH_AUTH_KEY=" + sec.cifrar(ABUSECH, "feeds:ABUSE_CH_AUTH_KEY")]
        (self.panel / "conf" / "feeds.conf").write_text("\n".join(conf) + "\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def correr(self, clave=True):
        env = dict(os.environ, IDS_PANEL_DIR=str(self.panel), IDS_DATOS=str(self.dir / "datos"),
                   IDS_RUN=str(self.dir / "run"), PYTHONDONTWRITEBYTECODE="1",
                   IDS_MASTER_KEY=str(self.clave if clave else self.dir / "no-existe"))
        env.pop("HTTP_PROXY", None)
        env.pop("http_proxy", None)
        env["NO_PROXY"] = "127.0.0.1"
        return subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, env=env, timeout=120)

    def meta(self):
        return json.loads((self.panel / "feeds" / "reputation.meta").read_text(encoding="utf-8"))

    def test_escribe_en_feeds_del_panel_sin_dataset(self):
        """Adaptada (conservación + quitar lo del servidor viejo): reputation.lst, domains.lst y
        c2ports.lst con su fuente, en IDS_PANEL_DIR/feeds; no hay domains.dataset ni nada fuera
        del directorio del panel."""
        r = self.correr()
        self.assertEqual(r.returncode, 0, r.stderr)
        feeds = self.panel / "feeds"
        rep = (feeds / "reputation.lst").read_text(encoding="utf-8").splitlines()
        self.assertIn("192.0.2.10\tfeodo", rep)
        self.assertIn("203.0.113.0/24\tspamhaus-drop", rep)
        self.assertIn("192.0.2.60\tthreatfox-c2", rep)
        self.assertEqual((feeds / "c2ports.lst").read_text(encoding="utf-8"), "192.0.2.60:4444\tthreatfox-c2\n")
        dom = (feeds / "domains.lst").read_text(encoding="utf-8").splitlines()
        self.assertEqual(sorted(dom), ["c2.example.net\tthreatfox", "malo.example.com\turlhaus"])
        self.assertFalse((feeds / "domains.dataset").exists())
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["master_key", "panel"])
        self.assertEqual(self.meta()["sources"]["abuseipdb"]["estado"], "valido")

    def test_claves_cifradas_se_descifran_y_no_salen(self):
        """Capacidad nueva (§10.3): la clave guardada cifrada llega en claro solo en la cabecera de
        su fuente (Key para AbuseIPDB, Auth-Key para abuse.ch); nunca en la salida ni en meta."""
        r = self.correr()
        self.assertEqual(r.returncode, 0, r.stderr)
        cab = {ruta.split("?")[0]: h for ruta, h in Servidor.vistas}
        self.assertEqual(cab["/aidb"].get("Key"), AIDB)
        self.assertEqual(cab["/urlhaus"].get("Auth-Key"), ABUSECH)
        self.assertNotIn("Key", cab["/feodo"])
        texto = r.stdout + r.stderr + (self.panel / "feeds" / "reputation.meta").read_text(encoding="utf-8")
        for secreto in (AIDB, ABUSECH):
            self.assertNotIn(secreto, texto)

    def test_sin_clave_maestra_sigue_sin_esas_fuentes(self):
        """Capacidad nueva (§10.3): sin la clave maestra no se rompe ni se borra nada: las fuentes
        con clave quedan sin-clave, las abiertas se bajan y se avisa por stderr."""
        r = self.correr(clave=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no se puede descifrar", r.stderr)
        src = self.meta()["sources"]
        self.assertEqual(src["abuseipdb"]["estado"], "sin-clave")
        self.assertEqual(src["urlhaus"]["estado"], "sin-clave")
        self.assertEqual(src["feodo"]["estado"], "valido")
        self.assertNotIn("/aidb", [x[0].split("?")[0] for x in Servidor.vistas])
        self.assertIn("ABUSEIPDB_KEY=enc1:", (self.panel / "conf" / "feeds.conf").read_text(encoding="utf-8"))

    def test_fuente_caida_conserva_la_ultima_valida(self):
        """Conservación: si una fuente falla, se conserva su última versión válida y sigue vigente."""
        self.assertEqual(self.correr().returncode, 0)
        meta = self.panel / "feeds" / "reputation.meta"
        m = json.loads(meta.read_text(encoding="utf-8"))
        m["sources"]["cins"]["fetched_valid"] -= 13 * 3600       # fuera del intervalo mínimo (12 h)
        meta.write_text(json.dumps(m), encoding="utf-8")
        Servidor.caidas = {"/cins"}
        r = self.correr()
        self.assertEqual(r.returncode, 0, r.stderr)
        s = self.meta()["sources"]["cins"]
        self.assertEqual((s["estado"], s["vigente"]), ("error", True))
        self.assertIn("198.51.100.20\tcins",
                      (self.panel / "feeds" / "reputation.lst").read_text(encoding="utf-8").splitlines())


if __name__ == "__main__":
    unittest.main()
