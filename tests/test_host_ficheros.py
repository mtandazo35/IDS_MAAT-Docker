"""Ficheros del host: daemon.json, logrotate (con logrotate real si existe), módulos, sysctl, sshd y
`ids-orq fw-render` (lo que usa install.sh para el firewall)."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
H = REPO / "host"

LOGROTATE_CONTRATO = """# eve/dns rotan al pasar de 100 MB (ids-logrotate.timer mira cada 5 min): un rotado tiene que caber
# en lo que Eventos descomprime por fichero (TOPE_GZ, 150 MB); con 1 GB la búsqueda se saltaba las
# horas anteriores. `size` y no `maxsize`: sin `size`, logrotate rota en cada pasada todo lo que
# pase de 1 MB (su umbral por defecto).
/srv/ids/datos/*/eve.json /srv/ids/datos/*/dns.json {
    size 100M
    rotate -1
    dateext
    dateformat -%Y%m%d-%H%M%S
    nocompress
    missingok
    notifempty
    nocreate
    sharedscripts
    postrotate
        /usr/local/bin/ids-orq reabrir-logs >/dev/null 2>&1 || true
    endscript
}
# Solo las estadísticas de Suricata (~8 KB cada 30 s): se guarda el anterior y nada más.
# copytruncate porque Suricata lo abre en modo añadir; el lector mira también stats.json.1
# para no quedarse sin dato justo después del corte.
/srv/ids/datos/*/stats.json {
    size 5M
    rotate 1
    copytruncate
    nocompress
    missingok
    notifempty
}
/srv/ids/estado/orq.jsonl {
    monthly
    rotate 24
    compress
    missingok
    notifempty
    nocreate
}
"""


class Ficheros(unittest.TestCase):
    def test_daemon_json(self):
        d = json.loads((H / "docker" / "daemon.json").read_text(encoding="utf-8"))
        self.assertEqual(d, {"userland-proxy": False, "live-restore": True, "no-new-privileges": True,
                             "log-driver": "local", "log-opts": {"max-size": "10m", "max-file": "3"},
                             "default-address-pools": [{"base": "10.210.0.0/16", "size": 28}],
                             "bip": "10.210.254.1/24"})

    def test_logrotate_exacto(self):
        txt = (H / "logrotate" / "ids-maat.conf").read_text(encoding="utf-8")
        self.assertEqual(txt, LOGROTATE_CONTRATO)
        # eve/dns sin copytruncate (se reabren con reopen-log-files); solo stats.json lo lleva
        eve_dns = txt.split("}", 1)[0]
        self.assertNotIn("copytruncate", eve_dns)
        self.assertEqual(txt.count("copytruncate"), 2)       # el comentario + el de stats.json

    def test_un_rotado_cabe_en_lo_que_lee_eventos(self):
        """Corrección de defecto (2026-10-15): con `maxsize 1G` y sin `size`, logrotate rotaba en cada
        pasada todo lo que pasara de 1 MB, y 1 GB de verdad habría dejado cada rotado por encima de
        lo que Eventos descomprime por fichero (TOPE_GZ): la búsqueda se saltaba las horas
        anteriores. El umbral deja sitio a lo que entra entre dos pasadas del timer (5 min)."""
        eve_dns = LOGROTATE_CONTRATO.split("}", 1)[0]
        self.assertIsNone(re.search(r"^\s*maxsize\b", eve_dns, re.M))
        m = re.search(r"^\s*size (\d+)M$", eve_dns, re.M)
        self.assertIsNotNone(m, eve_dns)
        sys.path.insert(0, str(REPO / "images" / "panel" / "rootfs" / "usr" / "local" / "lib" / "ids-panel"))
        import eventos_web
        self.assertLessEqual(int(m.group(1)) * 1024 * 1024, eventos_web.TOPE_GZ * 2 // 3)

    def test_modulos_sysctl_ssh(self):
        mods = [x for x in (H / "modules" / "ids.conf").read_text(encoding="utf-8").splitlines()
                if x and not x.startswith("#")]
        self.assertEqual(mods, ["tun", "veth", "nft_ct"])
        sysctl = [x for x in (H / "sysctl" / "90-ids.conf").read_text(encoding="utf-8").splitlines()
                  if x and not x.startswith("#")]
        self.assertEqual(sysctl, ["net.core.rmem_max=33554432"])
        ssh = {x.split()[0].lower(): x.split()[1] for x in (H / "ssh" / "10-ids.conf").read_text(encoding="utf-8")
               .splitlines() if x and not x.startswith("#")}
        self.assertEqual(ssh["passwordauthentication"], "no")
        self.assertEqual(ssh["kbdinteractiveauthentication"], "no")

    def test_journald(self):
        """VPN-15: todos los contenedores escriben en journald por docker.service y comparten su
        límite de ritmo: tiene que caber una avalancha contra la VPN sin perder las líneas que lee
        fail2ban, y el tamaño queda acotado."""
        import configparser
        cp = configparser.RawConfigParser(strict=True)
        cp.optionxform = str
        cp.read_string((H / "journald" / "90-ids.conf").read_text(encoding="utf-8"))
        j = cp["Journal"]
        self.assertEqual(j["RateLimitIntervalSec"], "30s")
        self.assertGreaterEqual(int(j["RateLimitBurst"]), 50000)      # Debian: 10000
        self.assertRegex(j["SystemMaxUse"], r"^[0-9]+[MG]$")
        self.assertEqual(set(cp.sections()), {"Journal"})


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("logrotate"), "sin logrotate")
class LogrotateReal(unittest.TestCase):
    def test_rota_y_pide_reabrir(self):
        d = Path(tempfile.mkdtemp(prefix="lr-"))
        try:
            marca = d / "reabierto"
            orq = d / "ids-orq"
            orq.write_text("#!/bin/sh\necho \"$@\" > %s\n" % marca, encoding="utf-8")
            orq.chmod(0o755)
            conf = LOGROTATE_CONTRATO.replace("/srv/ids", str(d / "srv/ids")).replace("/usr/local/bin/ids-orq", str(orq))
            (d / "lr.conf").write_text(conf, encoding="utf-8")
            eve = d / "srv/ids/datos/p001/eve.json"
            eve.parent.mkdir(parents=True)
            eve.write_text("x" * 100 + "\n", encoding="utf-8")
            r = subprocess.run(["logrotate", "-f", "-s", str(d / "estado"), str(d / "lr.conf")],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            # CONTRATO-F2 §9: rotado con fecha y hora (la poda por fecha es del orquestador)
            rotados = [f.name for f in (d / "srv/ids/datos/p001").iterdir()]
            self.assertEqual(len(rotados), 1, rotados)
            self.assertRegex(rotados[0], r"^eve\.json-\d{8}-\d{6}$")
            self.assertFalse(eve.exists())                          # nocreate: lo reabre Suricata
            self.assertEqual(marca.read_text().strip(), "reabrir-logs")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_rota_por_tamano_y_no_antes(self):
        """Corrección de defecto (2026-10-15, en producción): con `maxsize 1G` y sin `size`,
        logrotate rotaba eve/dns en cada pasada del timer (cada 30 min) en cuanto pasaban de 1 MB.
        Sin -f, como lo lanza el timer: con 99 MB no rota; con 101 MB rota una vez y pide reabrir."""
        d = Path(tempfile.mkdtemp(prefix="lr-"))
        try:
            marca = d / "reabierto"
            orq = d / "ids-orq"
            orq.write_text("#!/bin/sh\necho \"$@\" > %s\n" % marca, encoding="utf-8")
            orq.chmod(0o755)
            conf = LOGROTATE_CONTRATO.replace("/srv/ids", str(d / "srv/ids")).replace("/usr/local/bin/ids-orq", str(orq))
            (d / "lr.conf").write_text(conf, encoding="utf-8")
            eve = d / "srv/ids/datos/p001/eve.json"
            eve.parent.mkdir(parents=True)

            def pasada(mb):
                with open(eve, "ab") as f:
                    f.truncate(mb * 1024 * 1024)        # disperso: no ocupa disco
                r = subprocess.run(["logrotate", "-s", str(d / "estado"), str(d / "lr.conf")],
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
                return sorted(f.name for f in eve.parent.iterdir())

            self.assertEqual(pasada(2), ["eve.json"])          # el umbral por defecto (1 MB) ya no manda
            self.assertEqual(pasada(99), ["eve.json"])
            self.assertFalse(marca.exists())
            rotados = pasada(101)
            self.assertEqual(len(rotados), 1, rotados)
            self.assertRegex(rotados[0], r"^eve\.json-\d{8}-\d{6}$")
            self.assertEqual(marca.read_text().strip(), "reabrir-logs")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_stats_json_copytruncate(self):
        """stats.json: se corta en su sitio (mismo inodo, Suricata sigue escribiendo en modo
        añadir) y queda un solo anterior, stats.json.1; no pide reabrir los logs."""
        d = Path(tempfile.mkdtemp(prefix="lr-"))
        try:
            marca = d / "reabierto"
            orq = d / "ids-orq"
            orq.write_text("#!/bin/sh\necho \"$@\" > %s\n" % marca, encoding="utf-8")
            orq.chmod(0o755)
            conf = LOGROTATE_CONTRATO.replace("/srv/ids", str(d / "srv/ids")).replace("/usr/local/bin/ids-orq", str(orq))
            (d / "lr.conf").write_text(conf, encoding="utf-8")
            st = d / "srv/ids/datos/p001/stats.json"
            st.parent.mkdir(parents=True)
            for vuelta in ("primero", "segundo"):
                st.write_text('{"event_type":"stats","v":"%s"}\n' % vuelta, encoding="utf-8")
                ino = st.stat().st_ino
                r = subprocess.run(["logrotate", "-f", "-s", str(d / "estado"), str(d / "lr.conf")],
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(st.stat().st_ino, ino)
                self.assertEqual(st.stat().st_size, 0)
            self.assertEqual(sorted(f.name for f in st.parent.iterdir()), ["stats.json", "stats.json.1"])
            self.assertIn("segundo", (st.parent / "stats.json.1").read_text(encoding="utf-8"))
            self.assertFalse(marca.exists())
        finally:
            shutil.rmtree(d, ignore_errors=True)


class FwRender(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_sin_puntos(self):
        self.orq.db.close()
        os.remove(self.e.ruta("/srv/ids/estado/orq.db"))
        self.assertEqual(self.mod.main(["fw-render", "--aplicar"]), 0)
        txt = self.e.ruta("/srv/ids/fw/ids_host.nft").read_text(encoding="utf-8")
        self.assertIn("set puertos_vpn { type inet_service; }", txt)
        self.assertEqual([a[:2] for a in self.s.llamadas], [["nft", "-c"], ["nft", "-f"]])
        self.assertFalse(self.e.ruta("/srv/ids/fw/ids_host.nuevo.nft").exists())

    def test_con_puntos_conserva_puertos(self):
        A.crear(self, self.orq, {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]})
        conf = self.e.ruta("/etc/ids-maat/ids.conf")
        conf.write_text(conf.read_text(encoding="utf-8").replace("REDES_GESTION=192.0.2.0/25,198.51.100.0/26",
                                                                  "REDES_GESTION=192.0.2.0/24"), encoding="utf-8")
        self.assertEqual(self.mod.main(["fw-render", "--aplicar"]), 0)
        txt = self.e.ruta("/srv/ids/fw/ids_host.nft").read_text(encoding="utf-8")
        self.assertIn("elements = { 192.0.2.0/24 }", txt)
        self.assertIn("set puertos_vpn { type inet_service; elements = { 1194 } }", txt)
        # respaldo del firewall anterior antes de cambiarlo
        self.assertTrue(list(self.e.ruta("/root/backups").glob("ids-maat-fw-*.nft")))

    def test_nft_rechaza_no_se_instala(self):
        self.orq.db.close()
        os.remove(self.e.ruta("/srv/ids/estado/orq.db"))
        self.s.fallar["nft -c"] = 1
        self.assertEqual(self.mod.main(["fw-render", "--aplicar"]), 1)
        self.assertFalse(self.e.ruta("/srv/ids/fw/ids_host.nft").exists())
        self.assertEqual([a[:2] for a in self.s.llamadas], [["nft", "-c"]])


if __name__ == "__main__":
    unittest.main()
