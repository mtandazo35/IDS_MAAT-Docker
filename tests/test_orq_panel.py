"""Núcleo del panel (F1b, CONTRATO-F1b «Integración»): compose de ids-core, `ids-orq panel aplicar`,
`crear-admin`/`restablecer` con un contenedor de un solo uso y la reconciliación tras un reinicio.
Todo con el sistema simulado de _ayuda_orq (docker, nft): nada se ejecuta de verdad."""

import contextlib
import io
import ipaddress
import json
import os
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

try:
    import yaml  # solo para leer el compose como lo leería Docker; si no está, esa prueba se omite
except ImportError:  # pragma: no cover
    yaml = None

ENTORNO_INTERFAZ = {"IDS_PROXY", "IDS_EMPRESA", "IDS_PUERTO", "IDS_TZ", "IDS_ORQ_SOCK", "IDS_ORQ_TOKEN",
                    "IDS_PANEL_DIR", "IDS_DATOS", "IDS_RUN", "IDS_MASTER_KEY"}


class Base(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()
        self.mod.ESPERA_PANEL_S = 0.2

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def conf(self, **cambios):
        p = self.e.ruta("/etc/ids-maat/ids.conf")
        kv = self.mod.leer_kv(p)
        kv.update(cambios)
        p.write_text("".join("%s=%s\n" % x for x in kv.items()), encoding="utf-8")
        return self.mod.config()

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = self.mod.main(["panel"] + list(args))
            except SystemExit as e:          # argparse
                rc = e.code
        return rc, out.getvalue(), err.getvalue()


class ComposeCore(Base):
    def render(self, cfg=None):
        return self.mod.render_core(cfg or self.mod.config(), A.IMG_PANEL, "0.1.0")

    def test_sin_marcadores_y_lo_esencial(self):
        txt = self.render()
        self.assertTrue(A.sin_marcadores(txt))
        for linea in ("name: ids-core", "    image: %s" % A.IMG_PANEL, "    container_name: ids-core-panel",
                      "    restart: unless-stopped", '    user: "10500:10500"', "    cap_drop: [ALL]",
                      '    security_opt: ["no-new-privileges:true"]', "    read_only: true",
                      '    ports: ["5637:5637/tcp"]', "      core: { ipv4_address: 10.210.255.2 }",
                      "    logging: { driver: journald, options: { tag: ids-panel } }",
                      '      test: ["CMD", "ids-panel", "salud"]',
                      "    ipam: { config: [ { subnet: 10.210.255.0/24, gateway: 10.210.255.1 } ] }",
                      "    driver_opts: { com.docker.network.bridge.name: ids-core }"):
            self.assertIn(linea + "\n", txt)
        self.assertNotIn("cap_add", txt)
        self.assertNotIn("ids-maat.punto", txt)      # no es un punto: ni huérfano ni supervisado como tal
        self.assertNotIn(A.TOKEN, txt)               # el token va por fichero, nunca en el compose

    def test_memoria_igual_a_la_reserva_de_la_admision(self):
        txt = self.render()
        mem = "%dm" % self.mod.RESERVA_PANEL_MB
        self.assertIn("    mem_limit: %s\n" % mem, txt)
        self.assertIn("    memswap_limit: %s\n" % mem, txt)
        self.assertEqual(self.mod.RESERVA_PANEL_MB, 1536)           # CONTRATO-F2 §6
        # la admisión de un punto ya descuenta esa reserva aunque no haya panel
        self.assertEqual(self.mod.memoria_comprometida([]), self.mod.RESERVA_HOST_MB + self.mod.RESERVA_PANEL_MB)

    def test_montajes_del_contrato(self):
        vols = re.findall(r"(?m)^      - (\S+)$", self.render())
        self.assertEqual(vols, ["/srv/ids/panel:/srv/ids/panel", "/srv/ids/datos:/srv/ids/datos:ro",
                                "/srv/ids/run:/srv/ids/run:ro", "/run/ids-orq:/run/ids-orq:ro",
                                "/etc/ids-maat/orq_token:/run/secrets/orq_token:ro",
                                "/etc/ids-maat/master.key:/run/secrets/master_key:ro"])

    def test_raiz_de_pruebas_en_los_montajes(self):
        txt = self.mod.render_core(self.mod.config(), A.IMG_PANEL, "0.1.0", raiz_host="/tmp/raiz")
        for v in re.findall(r"(?m)^      - (\S+)$", txt):
            self.assertTrue(v.startswith("/tmp/raiz/"), v)

    def test_entorno_de_la_interfaz(self):
        env = dict(re.findall(r'(?m)^      (IDS_[A-Z_]+|TZ): "([^"]*)"$', self.render()))
        self.assertEqual(set(env) - {"TZ"}, ENTORNO_INTERFAZ)
        self.assertEqual(env["IDS_PROXY"], "203.0.113.50")
        self.assertEqual(env["IDS_EMPRESA"], "ids.empresa.example")
        self.assertEqual(env["IDS_PUERTO"], "5637")
        self.assertEqual((env["IDS_TZ"], env["TZ"]), ("UTC", "UTC"))
        self.assertEqual(env["IDS_ORQ_SOCK"], "/run/ids-orq/orq.sock")
        self.assertEqual(env["IDS_ORQ_TOKEN"], "/run/secrets/orq_token")
        self.assertEqual((env["IDS_PANEL_DIR"], env["IDS_DATOS"], env["IDS_RUN"]),
                         ("/srv/ids/panel", "/srv/ids/datos", "/srv/ids/run"))
        self.assertEqual(env["IDS_MASTER_KEY"], "/run/secrets/master_key")     # CONTRATO-F2 §10.3

    def test_proxy_varios_y_zona(self):
        cfg = self.conf(IPS_PROXY="203.0.113.48/28,198.51.100.70", ZONA_HORARIA="America/Guayaquil")
        env = dict(re.findall(r'(?m)^      (IDS_[A-Z_]+|TZ): "([^"]*)"$', self.render(cfg)))
        self.assertEqual(env["IDS_PROXY"], "203.0.113.48/28,198.51.100.70")
        self.assertEqual(env["IDS_TZ"], "America/Guayaquil")
        self.assertEqual(env["TZ"], "UTC")           # el contenedor en UTC; la zona solo al mostrar

    def test_zona_invalida(self):
        for mala in ("../etc", "Hora local", '"', "America/Guayaquil: x"):
            with self.assertRaises(self.mod.ErrorOrden, msg=repr(mala)):
                self.conf(ZONA_HORARIA=mala)

    def test_puerto_publicado_coherente_con_el_firewall(self):
        """El 5637 publicado es el que el firewall del host solo deja pasar desde @proxy: el DNAT
        de Docker conserva el puerto original y la regla de forward casa con ct original proto-dst."""
        for puerto in (5637, 8443):
            cfg = self.conf(PUERTO_PANEL=str(puerto))
            self.assertIn('    ports: ["%d:5637/tcp"]\n' % puerto, self.render(cfg))
            nft = self.mod.render_nft(cfg, [], [])
            self.assertIn("ct original proto-dst %d ip saddr != @proxy counter drop" % puerto, nft)
            self.assertIn("ct original proto-dst != @puertos_vpn ct original proto-dst != %d counter drop" % puerto, nft)
            self.assertNotRegex(nft, r"dport %d" % puerto)   # el panel nunca se abre en input

    def test_red_core_fuera_de_los_puntos_y_de_docker0(self):
        core = ipaddress.IPv4Network(self.mod.PANEL_RED)
        self.assertTrue(core.subnet_of(ipaddress.IPv4Network("10.210.0.0/16")))
        self.assertFalse(core.overlaps(ipaddress.IPv4Network("10.210.254.0/24")))     # bip
        for n in range(1, self.mod.N_MAX + 1):
            self.assertFalse(core.overlaps(ipaddress.IPv4Network(self.mod.derivar(n, "100.64")["subred"])), n)
        self.assertIn(ipaddress.IPv4Address(self.mod.PANEL_IP), core)

    @unittest.skipUnless(yaml, "sin PyYAML")
    def test_compose_como_lo_lee_docker(self):
        d = yaml.safe_load(self.render())
        self.assertEqual(d["name"], "ids-core")
        self.assertEqual(list(d["services"]), ["panel"])
        p = d["services"]["panel"]
        self.assertEqual(p["networks"], {"core": {"ipv4_address": "10.210.255.2"}})
        self.assertEqual(p["ports"], ["5637:5637/tcp"])
        self.assertEqual(set(p["environment"]) - {"TZ"}, ENTORNO_INTERFAZ)
        self.assertTrue(all(isinstance(v, str) for v in p["environment"].values()))
        self.assertEqual(p["healthcheck"]["test"], ["CMD", "ids-panel", "salud"])
        self.assertEqual(d["networks"]["core"]["name"], "ids-core")
        self.assertEqual(d["networks"]["core"]["ipam"]["config"], [{"subnet": "10.210.255.0/24",
                                                                    "gateway": "10.210.255.1"}])


class Aplicar(Base):
    def test_levanta_y_espera_sano(self):
        rc, out, err = self.cli("aplicar")
        self.assertEqual(rc, 0, err)
        self.assertIn("OK panel ids-core-panel", out)
        compose = self.e.ruta("/srv/ids/core/compose.yml")
        self.assertEqual(compose.read_text(encoding="utf-8"),
                         self.mod.render_core(self.mod.config(), A.IMG_PANEL, "0.1.0", raiz_host=str(self.e.dir)))
        up = self.s.ordenes("docker compose -p ids-core")
        self.assertEqual(len(up), 1)
        self.assertEqual(up[0][5:], [str(compose), "up", "-d", "--pull", "never", "--remove-orphans"])
        self.assertEqual(self.s.contenedores["ids-core-panel"]["estado"], "running")
        self.assertTrue(self.e.ruta("/srv/ids/panel").is_dir())
        if sys.platform.startswith("linux"):
            self.assertEqual(oct(compose.stat().st_mode & 0o7777), "0o600")
            self.assertEqual(oct(self.e.ruta("/srv/ids/panel").stat().st_mode & 0o7777), "0o2770")
            self.assertEqual(oct(self.e.ruta("/srv/ids/core").stat().st_mode & 0o7777), "0o700")

    def test_sin_master_key_no_levanta(self):
        """Corrección de defecto: sin /etc/ids-maat/master.key, Docker crearía un DIRECTORIO con
        ese nombre en el host al montarla; aplicar se niega antes de tocar Docker."""
        self.e.ruta("/etc/ids-maat/master.key").unlink()
        rc, _, err = self.cli("aplicar")
        self.assertEqual(rc, 1)
        self.assertIn("master.key", err)
        self.assertFalse(self.s.ordenes("docker compose -p ids-core"))
        self.assertFalse(self.e.ruta("/etc/ids-maat/master.key").exists())

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0,
                         "permisos de dueño: solo como root en Linux")
    def test_master_key_legible_por_el_grupo_del_panel(self):
        """Capacidad nueva: el panel (10500, sin capacidades) lee la clave maestra por grupo."""
        k = self.e.ruta("/etc/ids-maat/master.key")
        os.chmod(k, 0o400)
        self.assertEqual(self.cli("aplicar")[0], 0)
        st = k.stat()
        self.assertEqual((oct(st.st_mode & 0o7777), st.st_uid, st.st_gid), ("0o440", 0, 10500))

    def test_no_sano_falla(self):
        self.s.salud_inicial = "starting"
        rc, out, err = self.cli("aplicar")
        self.assertEqual(rc, 1)
        self.assertIn("no sanos", err)

    def test_sin_esperar(self):
        self.s.salud_inicial = "starting"
        rc, _, err = self.cli("aplicar", "--sin-esperar")
        self.assertEqual(rc, 0, err)

    def test_imagenes_sin_panel(self):
        p = self.e.ruta("/etc/ids-maat/imagenes.json")
        d = json.loads(p.read_text(encoding="utf-8"))
        del d["imagenes"]["panel"]
        p.write_text(json.dumps(d), encoding="utf-8")
        self.assertIsNone(self.mod.imagenes()["panel"])      # los puntos siguen funcionando
        rc, _, err = self.cli("aplicar")
        self.assertEqual(rc, 1)
        self.assertIn("no trae la imagen del panel", err)
        self.assertFalse(self.s.ordenes("docker compose -p ids-core"))

    def test_produccion_exige_digest_del_panel(self):
        p = self.e.ruta("/etc/ids-maat/imagenes.json")
        for mala in ("ghcr.io/mtandazo35/ids-maat-panel:0.2.0", A.IMG_PANEL.replace("panel@", "vpn@"),
                     "ids-maat-panel:ci"):
            d = json.loads(p.read_text(encoding="utf-8"))
            d["imagenes"]["panel"] = mala
            p.write_text(json.dumps(d), encoding="utf-8")
            with self.assertRaises(self.mod.ErrorOrden, msg=mala):
                self.mod.imagenes()

    def test_laboratorio_acepta_referencia_local(self):
        p = self.e.ruta("/etc/ids-maat/imagenes.json")
        d = json.loads(p.read_text(encoding="utf-8"))
        d["dev"] = True
        d["imagenes"]["panel"] = "ids-maat-panel:ci"
        p.write_text(json.dumps(d), encoding="utf-8")
        self.assertEqual(self.mod.imagenes()["panel"], "ids-maat-panel:ci")
        rc, _, err = self.cli("aplicar")
        self.assertEqual(rc, 0, err)
        self.assertIn("    image: ids-maat-panel:ci\n", self.e.ruta("/srv/ids/core/compose.yml").read_text(encoding="utf-8"))


class Admin(Base):
    def test_crear_admin_imprime_solo_la_clave(self):
        rc, out, err = self.cli("crear-admin")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "CLAVE=%s\n" % self.s.claves_panel[-1])
        self.assertNotIn(self.s.claves_panel[-1], err)
        self.assertIn("admin", json.loads(self.e.ruta("/srv/ids/panel/conf/usuarios.json").read_text(encoding="utf-8")))

    def test_contenedor_de_un_solo_uso_encerrado(self):
        self.cli("crear-admin", "--usuario", "admin")
        run = [a for a in self.s.llamadas if a[:2] == ["docker", "run"]][-1]
        linea = " ".join(run)
        for trozo in ("--rm", "--network none", "--log-driver none", "--read-only", "--cap-drop ALL",
                      "--security-opt no-new-privileges:true", "--user 10500:10500",
                      "--entrypoint ids-panel %s crear-admin --usuario admin" % A.IMG_PANEL):
            self.assertIn(trozo, linea)
        vols = [run[i + 1] for i, x in enumerate(run) if x == "-v"]
        self.assertEqual(vols, ["%s/srv/ids/panel:/srv/ids/panel" % str(self.e.dir).replace("\\", "/")])
        env = dict(run[i + 1].split("=", 1) for i, x in enumerate(run) if x == "-e")
        self.assertEqual(set(env) - {"TZ"}, ENTORNO_INTERFAZ)
        self.assertNotIn(A.TOKEN, linea)

    def test_reinstalacion_no_regenera(self):
        rc, out, _ = self.cli("crear-admin")
        self.assertEqual(rc, 0)
        antes = self.e.ruta("/srv/ids/panel/conf/usuarios.json").read_text(encoding="utf-8")
        rc, out, err = self.cli("crear-admin")
        self.assertEqual(rc, 3)
        self.assertEqual(out, "")
        self.assertIn("se conserva", err)
        self.assertEqual(self.e.ruta("/srv/ids/panel/conf/usuarios.json").read_text(encoding="utf-8"), antes)
        self.assertEqual(len(self.s.claves_panel), 1)

    def test_restablecer(self):
        self.cli("crear-admin")
        rc, out, err = self.cli("restablecer", "admin")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "CLAVE=%s\n" % self.s.claves_panel[-1])
        self.assertEqual(len(self.s.claves_panel), 2)
        self.assertNotEqual(self.s.claves_panel[0], self.s.claves_panel[1])
        rc, out, err = self.cli("restablecer", "nadie")
        self.assertEqual((rc, out), (1, ""))
        self.assertIn("FALLO", err)

    def test_usuario_invalido(self):
        for malo in ("Admin", "admin;rm", "-v", "", "a" * 33, ".admin"):
            rc, out, _ = self.cli("restablecer", malo)
            self.assertEqual((rc, out), (2, ""), malo)
        self.assertFalse([a for a in self.s.llamadas if a[:2] == ["docker", "run"]])

    def test_salida_rara_no_se_da_por_buena(self):
        for salida in ("", "CLAVE=\n", "CLAVE=a\nCLAVE=b\n", "clave: x\n"):
            self.assertIsNone(self.mod.linea_clave(salida), repr(salida))
        self.assertEqual(self.mod.linea_clave("aviso\nCLAVE=abc123\n"), "CLAVE=abc123")


class Reconciliar(Base):
    def reconciliar(self):
        r = A.ejecutar_orden(self.orq, "sistema.reconciliar", {})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        return r["resultado"]

    def test_tras_reiniciar_levanta_el_panel(self):
        self.assertEqual(self.cli("aplicar")[0], 0)
        del self.s.contenedores["ids-core-panel"]          # el VPS arrancó y el panel no está
        self.s.llamadas.clear()
        res = self.reconciliar()
        self.assertIn("panel", res["levantados"])
        self.assertEqual(res["huerfanos"], [])
        up = self.s.ordenes("docker compose -p ids-core")
        self.assertEqual(up[0][-4:], ["up", "-d", "--pull", "never"])
        self.assertEqual(self.s.contenedores["ids-core-panel"]["estado"], "running")

    def test_panel_en_marcha_no_se_toca(self):
        self.cli("aplicar")
        self.s.llamadas.clear()
        self.assertEqual(self.reconciliar()["levantados"], [])
        self.assertFalse(self.s.ordenes("docker compose -p ids-core"))

    def test_sin_panel_instalado_nada(self):
        self.assertEqual(self.reconciliar()["levantados"], [])
        self.assertFalse(self.s.ordenes("docker compose -p ids-core"))


if __name__ == "__main__":
    unittest.main()
