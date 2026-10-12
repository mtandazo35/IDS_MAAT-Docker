"""Unidades systemd del host: orden de arranque ids-host-fw -> docker -> ids-orq, encierro del
orquestador (ORQUESTADOR §1.1), timers de reglas y logrotate (§5.14, §5.15)."""

import configparser
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SD = REPO / "host" / "systemd"
UNIDADES = ["ids-host-fw.service", "ids-orq.service", "ids-reglas.service", "ids-reglas.timer",
            "ids-logrotate.service", "ids-logrotate.timer"]


def unidad(nombre):
    cp = configparser.RawConfigParser(strict=True, delimiters=("=",), comment_prefixes=("#", ";"))
    cp.optionxform = str
    cp.read_string((SD / nombre).read_text(encoding="utf-8"))
    return cp


def lista(cp, sec, clave):
    return cp[sec].get(clave, "").split()


class Unidades(unittest.TestCase):
    def test_estan_todas(self):
        self.assertEqual(sorted(p.name for p in SD.iterdir()), sorted(UNIDADES))

    def test_orden_de_arranque(self):
        """Ordena las tres unidades con sus Before/After: tiene que salir fw -> docker -> orq."""
        fw, orq = unidad("ids-host-fw.service"), unidad("ids-orq.service")
        antes = {("ids-host-fw.service", x) for x in lista(fw, "Unit", "Before")}
        antes |= {(x, "ids-orq.service") for x in lista(orq, "Unit", "After")}
        nodos = ["docker.service", "ids-orq.service", "ids-host-fw.service"]
        orden = []
        pendientes = set(nodos)
        while pendientes:
            libres = sorted(n for n in pendientes if not any((m, n) in antes for m in pendientes if m != n))
            self.assertTrue(libres, "ciclo en el orden de arranque")
            orden.append(libres[0])
            pendientes.remove(libres[0])
        self.assertEqual(orden, ["ids-host-fw.service", "docker.service", "ids-orq.service"])
        self.assertIn("docker.service", lista(orq, "Unit", "Requires"))

    def test_firewall(self):
        fw = unidad("ids-host-fw.service")
        s = fw["Service"]
        self.assertEqual((s["Type"], s["RemainAfterExit"]), ("oneshot", "yes"))
        self.assertEqual(s["ExecStart"], "/usr/sbin/nft -f /srv/ids/fw/ids_host.nft")
        self.assertNotIn("ExecStop", s)            # parar la unidad no abre el host
        self.assertEqual(fw["Install"]["WantedBy"], "multi-user.target")

    def test_orquestador_encerrado(self):
        s = unidad("ids-orq.service")["Service"]
        self.assertEqual(s["ExecStart"], "/usr/local/bin/ids-orq servicio")
        self.assertEqual((s["Restart"], s["RuntimeDirectory"]), ("always", "ids-orq"))
        # el panel monta /run/ids-orq: si systemd lo borrara al reiniciar el servicio, el montaje
        # del contenedor se quedaría con el directorio viejo y sin socket
        self.assertEqual(s["RuntimeDirectoryPreserve"], "yes")
        self.assertEqual(s["ProtectSystem"], "strict")
        self.assertEqual(s["ReadWritePaths"].split(), ["/srv/ids", "/root/backups", "/run/ids-orq"])
        self.assertEqual((s["PrivateTmp"], s["ProtectHome"], s["NoNewPrivileges"]), ("yes", "read-only", "yes"))
        # el CLI de docker necesita un directorio escribible para su configuración
        self.assertTrue(s["Environment"].startswith("DOCKER_CONFIG=/srv/ids/"))
        # tope de memoria (A-04): un fallo del orquestador no se come la RAM de los puntos
        self.assertEqual(s["MemoryMax"], "1G")

    def test_timers(self):
        r = unidad("ids-reglas.timer")["Timer"]
        self.assertEqual((r["OnCalendar"], r["RandomizedDelaySec"], r["Persistent"]),
                         ("*-*-* 08:15:00 UTC", "10m", "true"))
        self.assertEqual(unidad("ids-reglas.service")["Service"]["ExecStart"], "/usr/local/bin/ids-orq reglas actualizar")
        lr = unidad("ids-logrotate.timer")["Timer"]
        self.assertEqual(lr["OnCalendar"], "*:0/30")
        self.assertEqual(unidad("ids-logrotate.service")["Service"]["ExecStart"],
                         "/usr/sbin/logrotate --state /var/lib/logrotate/ids-maat.status /etc/ids-maat/logrotate.conf")

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("systemd-analyze"), "sin systemd-analyze")
    def test_calendarios_validos(self):
        for expr in ("*-*-* 08:15:00 UTC", "*:0/30"):
            r = subprocess.run(["systemd-analyze", "calendar", expr], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
