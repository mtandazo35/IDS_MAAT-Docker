"""salud-suricata (Puntos, apartado A, D6): el `stats` que da por sano a Suricata tiene que ser
posterior al arranque del proceso actual. Un eve.json se escribe en modo añadir: tras un
reinicio, su cola trae el último stats de la instancia ANTERIOR y el contenedor nuevo salía
sano antes de cargar las reglas."""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_suricata as A  # noqa: E402

S = A.cargar("salud-suricata")
AHORA = 1760090000
CMD = b"/usr/bin/suricata\x00-c\x00/etc/ids/suricata/suricata.yaml\x00--af-packet\x00"


def stats(epoch):
    ts = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
    return json.dumps({"timestamp": ts, "event_type": "stats", "stats": {"uptime": 60}},
                      separators=(",", ":"))


class StatsDelArranqueActual(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.eve = os.path.join(self.tmp.name, "eve.json")
        with open(self.eve, "w", encoding="utf-8", newline="\n") as f:
            f.write(stats(AHORA - 30) + "\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_stats_de_la_instancia_anterior_no_vale(self):
        sano, motivo = S.comprobar(self.eve, AHORA, CMD, inicio=AHORA - 10)
        self.assertFalse(sano)
        self.assertIn("anterior al arranque", motivo)

    def test_stats_posterior_al_arranque_vale(self):
        self.assertEqual(S.comprobar(self.eve, AHORA, CMD, inicio=AHORA - 60)[0], True)

    def test_sin_inicio_conocido_no_se_exige(self):
        self.assertEqual(S.comprobar(self.eve, AHORA, CMD, inicio=None)[0], True)

    def test_main_pasa_el_inicio(self):
        with redirect_stdout(io.StringIO()) as out:
            rc = S.main({"IDS_EVE": self.eve, "IDS_AHORA": str(AHORA)}, cmdline=CMD, inicio=AHORA - 10)
        self.assertEqual(rc, 1, out.getvalue())

    def test_inicio_del_proceso_desde_proc(self):
        d = Path(self.tmp.name)
        # comm con espacios y paréntesis: se corta por el ÚLTIMO «)»
        campos = ["S", "0", "1", "1", "0", "-1", "4194560"] + ["0"] * 12 + ["12345"]
        (d / "stat").write_text("1 (Suricata (Main)) " + " ".join(campos) + " 0 0\n", encoding="utf-8")
        (d / "proc_stat").write_text("cpu  1 2 3 4\nintr 5\nbtime 1760000000\nprocesses 9\n",
                                     encoding="utf-8")
        self.assertAlmostEqual(S.inicio_proceso(d / "stat", d / "proc_stat", tics=100), 1760000123.45)
        self.assertIsNone(S.inicio_proceso(d / "no-existe", d / "proc_stat", tics=100))
        (d / "proc_stat").write_text("cpu  1 2 3 4\n", encoding="utf-8")
        self.assertIsNone(S.inicio_proceso(d / "stat", d / "proc_stat", tics=100))


if __name__ == "__main__":
    unittest.main()
