"""Los contadores del Suricata salen de stats.json, no de la cola del eve (lab .152, 2026-10-15).

Con espejo real, entre dos `stats` del eve.json caben ~1,6 MB de eventos (2 300 en 30 s). El
orquestador y salud-suricata buscaban el último en los últimos 512 KiB del eve y casi nunca lo
encontraban: estado.json con `kernel_packets: null`, el punto «sin datos» en el panel y el
healthcheck sano solo de casualidad (corre ~5 s después de cada stats). Ahora la plantilla saca
los stats también a stats.json (~8 KB cada 30 s); logrotate lo corta con copytruncate y deja
stats.json.1. Sin ninguno de los dos (punto con el yaml de antes) se mira el eve como antes.
Tipo de cada prueba en su docstring (CONTRATO-F2 §10.5).
"""
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
import _ayuda_orq as AO  # noqa: E402
import _ayuda_suricata as AS  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
AHORA = 1792098047
CMD = b"/usr/bin/suricata\x00-c\x00/etc/ids/suricata/suricata.yaml\x00--af-packet\x00"


def stats(epoch, kp=0):
    ts = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
    return json.dumps({"timestamp": ts, "event_type": "stats",
                       "stats": {"uptime": 60, "capture": {"kernel_packets": kp, "kernel_drops": 3},
                                 "detect": {"engines": [{"rules_loaded": 46915, "rules_failed": 0}]}}},
                      separators=(",", ":"))


def tls(relleno=900):
    return json.dumps({"timestamp": "2026-10-15T21:00:13.000000+0000", "event_type": "tls",
                       "tls": {"sni": "x" * relleno}}, separators=(",", ":"))


def escribir(ruta, *lineas):
    with open(ruta, "w", encoding="utf-8", newline="\n") as f:
        for l in lineas:
            f.write(l + "\n")


def eve_real(ruta, t_stats):
    """Un eve como el del lab: un stats y detrás ~1,9 MB de eventos sin ningún otro."""
    escribir(ruta, stats(t_stats, 5), *([tls()] * 2000))


class Orquestador(unittest.TestCase):
    def setUp(self):
        self.mod = AO.cargar_orq()
        self.e = AO.Entorno()
        self.addCleanup(self.e.cerrar)
        self.datos = self.e.ruta("/srv/ids/datos/p001")
        self.datos.mkdir(parents=True)

    def test_eve_con_espejo_real_no_da_contadores(self):
        """Regresión (lab .152): la cola de 512 KiB del eve no tiene ningún stats."""
        eve_real(self.datos / "eve.json", AHORA - 20)
        self.assertGreater(os.path.getsize(self.datos / "eve.json"), 1024 * 1024)
        self.assertIsNone(self.mod.leer_stats_eve(self.datos / "eve.json", AHORA)["kernel_packets"])
        self.assertIsNone(self.mod.leer_stats_punto(self.datos, AHORA)["kernel_packets"])

    def test_stats_json_da_los_contadores(self):
        """Corrección: con stats.json salen los contadores, sea cual sea el tamaño del eve."""
        eve_real(self.datos / "eve.json", AHORA - 20)
        escribir(self.datos / "stats.json", stats(AHORA - 40, 100), stats(AHORA - 10, 3816801))
        st = self.mod.leer_stats_punto(self.datos, AHORA)
        self.assertEqual((st["kernel_packets"], st["kernel_drops"], st["reglas_cargadas"],
                          st["reglas_fallidas"], st["stats_edad_s"]), (3816801, 3, 46915, 0, 10))

    def test_recien_rotado_vale_stats_json_1(self):
        """Corrección: copytruncate deja stats.json vacío; el último está en stats.json.1."""
        escribir(self.datos / "stats.json")
        escribir(self.datos / "stats.json.1", stats(AHORA - 70, 1), stats(AHORA - 25, 7))
        self.assertEqual(self.mod.leer_stats_punto(self.datos, AHORA)["kernel_packets"], 7)

    def test_gana_el_mas_reciente(self):
        """Corrección: entre stats.json y stats.json.1, el de timestamp más nuevo."""
        escribir(self.datos / "stats.json", stats(AHORA - 5, 9))
        escribir(self.datos / "stats.json.1", stats(AHORA - 35, 8))
        self.assertEqual(self.mod.leer_stats_punto(self.datos, AHORA)["kernel_packets"], 9)

    def test_stats_json_vacio_no_vuelve_al_eve(self):
        """Corrección: si stats.json existe manda él; un stats viejo del eve no se toma por actual."""
        escribir(self.datos / "stats.json")
        escribir(self.datos / "eve.json", stats(AHORA - 5, 42))
        self.assertIsNone(self.mod.leer_stats_punto(self.datos, AHORA)["kernel_packets"])

    def test_sin_stats_json_se_mira_el_eve(self):
        """Conservación: punto con el yaml de antes (sin stats.json) hasta punto.reconfigurar."""
        escribir(self.datos / "eve.json", tls(), stats(AHORA - 5, 42), tls())
        self.assertEqual(self.mod.leer_stats_punto(self.datos, AHORA)["kernel_packets"], 42)
        self.assertEqual(self.mod.leer_stats_punto(self.datos, AHORA)["stats_edad_s"], 5)

    def test_stats_json_enlazado_no_se_lee(self):
        """Corrección de defecto (A-04) en el lector nuevo: un stats.json que es enlace no se sigue."""
        secreto = self.e.ruta("/srv/ids/fw/secreto")
        secreto.parent.mkdir(parents=True)
        escribir(secreto, stats(AHORA - 5, 99))
        if os.name == "nt":
            os.link(str(secreto), str(self.datos / "stats.json"))
        else:
            os.symlink(str(secreto), str(self.datos / "stats.json"))
        self.assertIsNone(self.mod.leer_stats_punto(self.datos, AHORA)["kernel_packets"])

    def test_estado_del_punto_usa_stats_json(self):
        """Corrección: _estado_punto (estado.json) y la medida del punto leen stats.json."""
        fuente = (RAIZ / "orquestador" / "ids_orq.py").read_text(encoding="utf-8")
        self.assertNotIn('leer_stats_eve(ruta("/srv/ids/datos/', fuente)
        self.assertEqual(fuente.count('leer_stats_punto(ruta("/srv/ids/datos/%s" % '), 2)


class Salud(unittest.TestCase):
    S = AS.cargar("salud-suricata")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.eve = os.path.join(self.tmp.name, "eve.json")
        self.st = os.path.join(self.tmp.name, "stats.json")

    def comprobar(self):
        return self.S.comprobar(self.eve, AHORA, CMD, inicio=AHORA - 600)

    def test_eve_con_espejo_real_sin_stats_json_mal(self):
        """Regresión (lab .152): sin stats.json y con espejo real, la cola del eve no tiene stats."""
        eve_real(self.eve, AHORA - 20)
        sano, motivo = self.comprobar()
        self.assertFalse(sano, motivo)
        self.assertIn("512 KiB", motivo)

    def test_stats_json_reciente_sano(self):
        """Corrección: con stats.json reciente sale sano aunque la cola del eve no tenga stats."""
        eve_real(self.eve, AHORA - 20)
        escribir(self.st, stats(AHORA - 20))
        sano, motivo = self.comprobar()
        self.assertTrue(sano, motivo)

    def test_recien_rotado_sano(self):
        """Corrección: stats.json vacío tras copytruncate; vale el de stats.json.1."""
        escribir(self.st)
        escribir(self.st + ".1", stats(AHORA - 15))
        sano, motivo = self.comprobar()
        self.assertTrue(sano, motivo)

    def test_stats_json_viejo_mal(self):
        """Conservación: el límite de 120 s sigue valiendo con stats.json."""
        escribir(self.st, stats(AHORA - 200))
        escribir(self.eve, stats(AHORA - 5))
        sano, motivo = self.comprobar()
        self.assertFalse(sano, motivo)
        self.assertIn("200", motivo)

    def test_stats_json_vacio_mal(self):
        """Corrección: stats.json sin ningún stats (y sin .1) no da sano."""
        escribir(self.st)
        sano, motivo = self.comprobar()
        self.assertFalse(sano, motivo)
        self.assertIn("stats.json", motivo)

    def test_anterior_al_arranque_mal(self):
        """Conservación: el stats de stats.json tiene que ser de la instancia actual."""
        escribir(self.st, stats(AHORA - 30))
        sano, motivo = self.S.comprobar(self.eve, AHORA, CMD, inicio=AHORA - 10)
        self.assertFalse(sano, motivo)

    def test_main_con_ids_eve(self):
        """Conservación: con IDS_EVE, stats.json se busca a su lado."""
        escribir(self.st, stats(AHORA - 20))
        with redirect_stdout(io.StringIO()) as out:
            rc = self.S.main({"IDS_EVE": self.eve, "IDS_AHORA": str(AHORA)}, cmdline=CMD, inicio=AHORA - 600)
        self.assertEqual(rc, 0, out.getvalue())


class Plantilla(unittest.TestCase):
    def test_eve_solo_de_stats(self):
        """Corrección: la plantilla saca los stats a stats.json (y siguen en el eve, para Eventos)."""
        tmpl = (RAIZ / "images" / "suricata" / "rootfs" / "usr" / "share" / "ids-maat"
                / "suricata.yaml.tmpl").read_text(encoding="utf-8")
        bloques = tmpl.split("  - eve-log:")
        de_stats = [b for b in bloques if "filename: stats.json" in b]
        self.assertEqual(len(de_stats), 1)
        cuerpo = de_stats[0].split("\n\n")[0]
        self.assertIn("- stats:", cuerpo)
        self.assertIn("threads: no", cuerpo)
        for otro in ("- alert", "- http", "- tls", "- dns"):
            self.assertNotIn(otro, cuerpo)
        principal = [b for b in bloques if "filename: eve.json" in b][0]
        self.assertIn("- stats:", principal)

    def test_logrotate_copytruncate(self):
        """Corrección: stats.json se rota aparte, con copytruncate y un solo anterior."""
        conf = (RAIZ / "host" / "logrotate" / "ids-maat.conf").read_text(encoding="utf-8")
        bloque = conf.split("/srv/ids/datos/*/stats.json {", 1)[1].split("}", 1)[0]
        for d in ("copytruncate", "rotate 1", "size 5M"):
            self.assertIn(d, bloque)
        cabecera_eve = conf.split("{", 1)[0]
        self.assertNotIn("stats.json", cabecera_eve)


if __name__ == "__main__":
    unittest.main()
