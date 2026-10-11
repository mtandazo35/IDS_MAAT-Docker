"""salud-suricata (CONTRATO-F1a §5.7): stats reciente -> 0; viejo, ausente o sin eve -> 1."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_suricata as A  # noqa: E402

S = A.cargar("salud-suricata")
AHORA = 1760090000
CMD_SURICATA = b"/usr/bin/suricata\x00-c\x00/etc/ids/suricata/suricata.yaml\x00--af-packet\x00"


def ts_eve(epoch, tz_horas=0):
    tz = timezone(timedelta(hours=tz_horas))
    d = datetime.fromtimestamp(epoch, tz)
    return d.strftime("%Y-%m-%dT%H:%M:%S.%f") + d.strftime("%z")


def stats(epoch, tz_horas=0):
    return json.dumps({"timestamp": ts_eve(epoch, tz_horas), "event_type": "stats",
                       "stats": {"uptime": 60, "capture": {"kernel_packets": 0, "kernel_drops": 0}}},
                      separators=(",", ":"))


def alerta(epoch, relleno=""):
    return json.dumps({"timestamp": ts_eve(epoch), "event_type": "alert", "host": "p003",
                       "alert": {"signature_id": 2100498, "signature": "GPL ATTACK_RESPONSE " + relleno}},
                      separators=(",", ":"))


class Salud(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.eve = os.path.join(self.tmp.name, "eve.json")

    def tearDown(self):
        self.tmp.cleanup()

    def escribir(self, *lineas):
        with open(self.eve, "w", encoding="utf-8", newline="\n") as f:
            for l in lineas:
                f.write(l + "\n")

    def codigo(self, cmdline=CMD_SURICATA, ahora=AHORA):
        env = {"IDS_EVE": self.eve, "IDS_AHORA": str(ahora)}
        with redirect_stdout(io.StringIO()) as out:
            rc = S.main(env, cmdline=cmdline)
        self.salida = out.getvalue()
        return rc

    def test_stats_de_hace_30_s_sano(self):
        self.escribir(alerta(AHORA - 100), stats(AHORA - 30), alerta(AHORA - 5))
        self.assertEqual(self.codigo(), 0, self.salida)

    def test_stats_de_hace_200_s_mal(self):
        self.escribir(stats(AHORA - 200), alerta(AHORA - 5))
        self.assertEqual(self.codigo(), 1)
        self.assertIn("200", self.salida)

    def test_limite_120_s(self):
        self.escribir(stats(AHORA - 119))
        self.assertEqual(self.codigo(), 0)
        self.escribir(stats(AHORA - 120))
        self.assertEqual(self.codigo(), 1)

    def test_vale_el_stats_mas_reciente(self):
        self.escribir(stats(AHORA - 30), stats(AHORA - 400))
        self.assertEqual(self.codigo(), 0)

    def test_sin_eve_mal(self):
        self.assertEqual(self.codigo(), 1)

    def test_eve_sin_stats_mal(self):
        self.escribir(alerta(AHORA - 1), alerta(AHORA - 2))
        self.assertEqual(self.codigo(), 1)

    def test_pid1_que_no_es_suricata_mal(self):
        self.escribir(stats(AHORA - 30))
        self.assertEqual(self.codigo(cmdline=b"/bin/sh\x00-c\x00sleep 99\x00"), 1)

    def test_solo_mira_los_ultimos_512_kib(self):
        relleno = "x" * 900
        lineas = [stats(AHORA - 30)] + [alerta(AHORA - 10, relleno) for _ in range(600)]
        self.escribir(*lineas)
        self.assertGreater(os.path.getsize(self.eve), 512 * 1024)
        self.assertEqual(self.codigo(), 1)
        lineas.append(stats(AHORA - 20))
        self.escribir(*lineas)
        self.assertEqual(self.codigo(), 0)

    def test_linea_cortada_o_basura(self):
        self.escribir('{"timestamp":"roto","event_type":"stats"}', "no es json",
                      stats(AHORA - 30)[:40])
        self.assertEqual(self.codigo(), 1)

    def test_zona_horaria_del_timestamp(self):
        # el mismo instante escrito con -05:00 sigue teniendo 30 s
        self.escribir(stats(AHORA - 30, tz_horas=-5))
        self.assertEqual(self.codigo(), 0)
        self.assertEqual(S.ts_epoch(ts_eve(AHORA, -5)), AHORA)

    def test_ids_ahora_invalido(self):
        self.escribir(stats(AHORA - 30))
        with redirect_stdout(io.StringIO()):
            self.assertEqual(S.main({"IDS_EVE": self.eve, "IDS_AHORA": "ayer"}, cmdline=CMD_SURICATA), 1)

    def test_programa_real_sin_eve_sale_con_1(self):
        env = dict(os.environ, IDS_EVE=self.eve, IDS_AHORA=str(AHORA))
        r = subprocess.run([sys.executable, str(A.BIN / "salud-suricata")], env=env,
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("salud-suricata", r.stdout)


if __name__ == "__main__":
    unittest.main()
