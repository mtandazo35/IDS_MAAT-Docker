"""Un Suricata sano sin su eve.json o su dns.json sigue escribiendo en el rotado: el postrotate de
logrotate no pudo pedir `reopen-log-files` (el orquestador se reiniciaba en ese segundo). Así el punto
no vuelve a rotar y el rotado crece sin tope hasta llenar el disco. La supervisión lo detecta y se lo
pide, como mucho una vez por minuto y punto. Pasó el 2026-10-13 en el laboratorio, cuando una carga
coincidió con la rotación de las :30. Desde 2026-10-15 el timer de logrotate corre cada 5 min y ya no
hay una hora que evitar al cargar.

Docker simulado de _ayuda_orq; nada real."""
import json
import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

NORTE = {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]}


class ReabrirLogsPerdidos(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(ncpu=8)
        A.crear(self, self.orq, NORTE)
        self.pedidas = []
        self.fallar = None

        def suricata_comando(pid, comando):
            self.pedidas.append((pid, comando))
            if self.fallar:
                raise self.mod.ErrorOrden("FALLO", self.fallar)
            return {"return": "OK"}
        self.mod.suricata_comando = suricata_comando
        self.datos = self.e.ruta("/srv/ids/datos/p001")
        self.datos.mkdir(parents=True, exist_ok=True)
        for n in ("eve.json", "dns.json"):
            (self.datos / n).write_text("", encoding="utf-8")
        self.t = time.time() + 1000

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def rotar(self, nombre="eve.json"):
        """Lo que hace logrotate (nocreate): renombra el vivo y Suricata sigue con él abierto."""
        os.replace(self.datos / nombre, self.datos / ("%s-20261015-193000" % nombre))

    def diario(self):
        lineas = self.e.ruta("/srv/ids/estado/orq.jsonl").read_text(encoding="utf-8").splitlines()
        return [x for x in map(json.loads, lineas) if x.get("evento") == "supervision.reabrir_logs"]

    def test_con_sus_logs_no_pide_nada(self):
        self.orq.tick(self.t)
        self.assertEqual(self.pedidas, [])

    def test_sin_eve_pide_reabrir_como_mucho_una_vez_por_minuto(self):
        self.rotar()
        self.orq.tick(self.t)
        self.assertEqual(self.pedidas, [("p001", "reopen-log-files")])
        self.orq.tick(self.t + 15)
        self.orq.tick(self.t + 45)
        self.assertEqual(len(self.pedidas), 1)
        self.orq.tick(self.t + 61)                    # sigue faltando: lo vuelve a pedir
        self.assertEqual(len(self.pedidas), 2)
        (self.datos / "eve.json").write_text("", encoding="utf-8")   # Suricata ya lo reabrió
        self.orq.tick(self.t + 200)
        self.assertEqual(len(self.pedidas), 2)
        self.assertEqual([(x["pid"], x["faltan"], x["resultado"]) for x in self.diario()],
                         [("p001", ["eve.json"], "ok")] * 2)

    def test_sin_dns_tambien(self):
        self.rotar("dns.json")
        self.orq.tick(self.t)
        self.assertEqual(self.pedidas, [("p001", "reopen-log-files")])
        self.assertEqual(self.diario()[-1]["faltan"], ["dns.json"])

    def test_mientras_arranca_no_es_un_rotado_perdido(self):
        """Un Suricata que todavía carga reglas no ha abierto sus logs: no se le pide nada."""
        self.rotar()
        self.s.contenedores["ids-p001-suricata"]["salud"] = "starting"
        self.orq.tick(self.t)
        self.assertEqual(self.pedidas, [])

    def test_un_fallo_no_para_la_supervision_y_queda_anotado(self):
        self.rotar()
        self.fallar = "sin socket"
        est = self.orq.tick(self.t)
        self.assertEqual(est["puntos"]["p001"]["estado"], "activo")
        self.assertEqual(self.pedidas, [("p001", "reopen-log-files")])
        self.assertEqual(self.diario()[-1]["resultado"], "fallo: sin socket")


if __name__ == "__main__":
    unittest.main()
