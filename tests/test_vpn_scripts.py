"""Scripts sh de la imagen vpn: sintaxis, árbol s6 (orden de §5.1), `run` y salud-vpn (§5.7).

Los `run` y salud-vpn se ejecutan de verdad con bash y comandos falsos en el PATH
(python3, socat, openvpn, nft, s6-svstat), que apuntan lo que reciben."""
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_vpn as ay  # noqa: E402

BASH = ay.bash()
S6RC = ay.S6 / "s6-rc.d"
ONESHOTS = ["init-env", "init-nft", "init-veth", "init-mon"]
LONGRUNS = ["openvpn", "tzsp-decap", "rele-api"]


def scripts_sh():
    lista = [ay.BIN / "salud-vpn"]
    lista += sorted((ay.S6 / "scripts").iterdir())
    lista += [S6RC / s / "run" for s in LONGRUNS]
    lista += sorted((ay.RAIZ / "tests" / "imagen").glob("test_vpn_*.sh"))
    return lista


def ruta_bash(p):
    return str(p).replace("\\", "/")


class ArbolS6(unittest.TestCase):
    def test_tipos(self):
        for s in ONESHOTS:
            self.assertEqual((S6RC / s / "type").read_text(encoding="utf-8").strip(), "oneshot", s)
        for s in LONGRUNS:
            self.assertEqual((S6RC / s / "type").read_text(encoding="utf-8").strip(), "longrun", s)

    def test_bundle_user_tiene_todo(self):
        self.assertEqual(sorted(p.name for p in (S6RC / "user" / "contents.d").iterdir()),
                         sorted(ONESHOTS + LONGRUNS))

    def test_orden_de_arranque(self):
        """Orden topológico de dependencies.d: env -> nft -> veth -> mon -> servicios."""
        deps = {s: {p.name for p in (S6RC / s / "dependencies.d").iterdir()}
                for s in ONESHOTS + LONGRUNS}
        hecho, orden = {"base"}, []
        while not set(deps) <= hecho:
            listos = sorted(s for s in deps if s not in hecho and deps[s] <= hecho)
            self.assertTrue(listos, f"ciclo o dependencia desconocida: {deps}")
            orden.append(listos)
            hecho.update(listos)
        self.assertEqual(orden, [["init-env"], ["init-nft"], ["init-veth"], ["init-mon"],
                                 sorted(LONGRUNS)])

    def test_up_apunta_a_un_script_que_existe(self):
        for s in ONESHOTS:
            up = (S6RC / s / "up").read_text(encoding="utf-8").strip()
            self.assertTrue(up.startswith("/etc/s6-overlay/scripts/"), up)
            self.assertTrue((ay.ROOTFS / up.lstrip("/")).is_file(), up)

    def test_dockerfile_da_permisos_a_todo_lo_ejecutable(self):
        docker = (ay.RAIZ / "images" / "vpn" / "Dockerfile").read_text(encoding="utf-8")
        ejecutables = [ay.BIN / n for n in ("tzsp-decap", "ovpn-auth", "salud-vpn")]
        ejecutables += [ay.RENDER] + sorted((ay.S6 / "scripts").iterdir())
        ejecutables += [S6RC / s / "run" for s in LONGRUNS]
        for f in ejecutables:
            ruta = "/" + f.relative_to(ay.ROOTFS).as_posix()
            self.assertIn(ruta, docker, f"falta chmod 0755 de {ruta}")


class Sintaxis(unittest.TestCase):
    def test_shebang_y_finales_lf(self):
        for f in list(ay.ROOTFS.rglob("*")) + [ay.RAIZ / "images" / "vpn" / "Dockerfile"]:
            if f.is_file() and "__pycache__" not in f.parts:
                b = f.read_bytes()
                self.assertNotIn(b"\r", b, f)
                self.assertFalse(b.startswith(b"\xef\xbb\xbf"), f)
        for f in scripts_sh():
            shebang = b"#!/usr/bin/env bash\n" if f.parent.name == "imagen" else b"#!/bin/sh\n"
            self.assertTrue(f.read_bytes().startswith(shebang), f)
        for f in (ay.BIN / "tzsp-decap", ay.BIN / "ovpn-auth", ay.RENDER):
            self.assertTrue(f.read_bytes().startswith(b"#!/usr/bin/env python3\n"), f)

    @unittest.skipUnless(BASH, "sin bash")
    def test_bash_n(self):
        for f in scripts_sh():
            with self.subTest(f.name):
                p = subprocess.run([BASH, "-n", ruta_bash(f)], capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)


@unittest.skipUnless(BASH, "sin bash")
class ConFalsos(unittest.TestCase):
    """Ejecuta scripts reales con bash y comandos falsos delante en el PATH."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.falsos = Path(self.dir.name) / "bin"
        self.falsos.mkdir()
        self.registro = Path(self.dir.name) / "registro"

    def tearDown(self):
        self.dir.cleanup()

    def falso(self, nombre, cuerpo):
        f = self.falsos / nombre
        f.write_bytes(("#!/bin/sh\n" + cuerpo + "\n").encode())
        f.chmod(f.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return f

    def falso_que_apunta(self, nombre):
        """Comando falso que apunta su umask, sus argumentos y su entorno TZSP/TUN."""
        reg = ruta_bash(self.registro)
        return self.falso(nombre, f'''{{
  echo "umask=$(umask)"
  for a in "$@"; do echo "arg=$a"; done
  env | grep -E '^(TZSP_|TUN_|API_)' | sort | sed 's/^/env=/'
}} > "{reg}"''')

    def ejecutar(self, script, env=None, extra_env=None, quitar=()):
        e = dict(os.environ)
        e.update(ay.ENTORNO_BUENO)
        e["PATH"] = str(self.falsos) + os.pathsep + e.get("PATH", "")
        e.pop("TZSP_MAP", None)
        e.update(env or {})
        e.update(extra_env or {})
        for k in quitar:
            e.pop(k, None)
        return subprocess.run([BASH, ruta_bash(script)], env=e, capture_output=True, text=True,
                              timeout=30)

    def leido(self):
        return self.registro.read_text(encoding="utf-8").splitlines()

    # --- run de los longrun ---------------------------------------------------------------
    def test_run_openvpn(self):
        self.falso_que_apunta("openvpn")
        p = self.ejecutar(S6RC / "openvpn" / "run")
        self.assertEqual(p.returncode, 0, p.stderr)
        r = self.leido()
        self.assertEqual(r[0], "umask=0027")
        self.assertEqual([l for l in r if l.startswith("arg=")],
                         ["arg=--config", "arg=/etc/ids/vpn/server.conf"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "modos de fichero POSIX")
    def test_run_openvpn_prepara_el_status_0640(self):
        """El `status` de OpenVPN se crea antes con 0640 (OpenVPN lo crearía 0600)."""
        run = Path(self.dir.name) / "run"
        txt = (S6RC / "openvpn" / "run").read_text(encoding="utf-8")
        run.write_text(txt.replace("/run/ids/", str(Path(self.dir.name)) + "/"), encoding="utf-8")
        estado = Path(self.dir.name) / "openvpn-status.log"
        estado.write_text("viejo")
        estado.chmod(0o600)
        self.falso_que_apunta("openvpn")
        p = self.ejecutar(run)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(stat.S_IMODE(estado.stat().st_mode), 0o640)
        self.assertEqual(estado.read_text(), "viejo")     # no lo trunca: eso lo hace OpenVPN

    def test_run_tzsp_decap(self):
        self.falso_que_apunta("python3")
        p = self.ejecutar(S6RC / "tzsp-decap" / "run", {"TZSP_MAP": "10.0.0.1=eth0"})
        self.assertEqual(p.returncode, 0, p.stderr)
        r = self.leido()
        self.assertEqual(r[0], "umask=0027")
        self.assertIn("arg=/usr/local/bin/tzsp-decap", r)
        env = [l for l in r if l.startswith("env=TZSP_")]
        self.assertEqual(env, ["env=TZSP_ALLOW=100.64.3.2/32", "env=TZSP_BYTES=10000",
                               "env=TZSP_ESTADO=/run/ids/tzsp.json", "env=TZSP_OUT_IF=ids-in",
                               "env=TZSP_PORT=37008", "env=TZSP_PUERTO=37008"])

    def test_run_tzsp_decap_sin_tun_mk_deja_allow_invalido(self):
        """Sin TUN_MK, TZSP_ALLOW queda "/32": el receptor real lo rechaza (fail-closed)."""
        self.falso_que_apunta("python3")
        p = self.ejecutar(S6RC / "tzsp-decap" / "run", quitar=("TUN_MK",))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("env=TZSP_ALLOW=/32", self.leido())
        td = ay.cargar(ay.BIN / "tzsp-decap", "ids_vpn_tzsp_decap_run")
        with self.assertRaises(td.ErrorConfig):
            td.config_desde_entorno({"TZSP_ALLOW": "/32", "TZSP_PORT": "37008"})

    def test_run_rele_api(self):
        self.falso_que_apunta("socat")
        p = self.ejecutar(S6RC / "rele-api" / "run", {"API_PUERTO": "8728"})
        self.assertEqual(p.returncode, 0, p.stderr)
        r = self.leido()
        self.assertEqual(r[0], "umask=0007")
        self.assertEqual([l for l in r if l.startswith("arg=")], [
            "arg=UNIX-LISTEN:/run/ids/api.sock,fork,unlink-early,mode=660,max-children=4",
            "arg=TCP:100.64.3.2:8728,connect-timeout=5"])

    # --- punto directo (sin VPN, solo LAN; el user, 2026-10-18) ---------------------------------
    DIRECTO = {"MODO": "directo", "MK_IP": "192.168.88.1"}

    def test_run_openvpn_directo_no_arranca_openvpn(self):
        """En directo el servicio se queda quieto (sleep) y openvpn ni se llama."""
        marca = Path(self.dir.name) / "openvpn-llamado"
        self.falso("openvpn", 'touch "%s"' % ruta_bash(marca))
        self.falso_que_apunta("sleep")
        p = self.ejecutar(S6RC / "openvpn" / "run", self.DIRECTO)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual([l for l in self.leido() if l.startswith("arg=")], ["arg=infinity"])
        self.assertFalse(marca.exists())
        self.assertIn("punto directo", p.stdout)

    def test_run_tzsp_decap_directo_desde_cualquier_ip(self):
        """2026-10-20 («necesito que escuche cualquier IP»): el espejo directo no se filtra por origen."""
        self.falso_que_apunta("python3")
        p = self.ejecutar(S6RC / "tzsp-decap" / "run", self.DIRECTO)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("env=TZSP_ALLOW=0.0.0.0/0", self.leido())
        self.assertNotIn("env=TZSP_ALLOW=192.168.88.1/32", self.leido())

    def test_run_tzsp_decap_directo_no_depende_de_mk_ip(self):
        self.falso_que_apunta("python3")
        p = self.ejecutar(S6RC / "tzsp-decap" / "run", {"MODO": "directo"}, quitar=("MK_IP",))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("env=TZSP_ALLOW=0.0.0.0/0", self.leido())

    def test_run_rele_api_directo(self):
        self.falso_que_apunta("socat")
        p = self.ejecutar(S6RC / "rele-api" / "run", self.DIRECTO)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("arg=TCP:192.168.88.1:8729,connect-timeout=5", self.leido())

    def test_salud_directo_sin_openvpn_ni_listen(self):
        """Sin OpenVPN (servicio quieto) y sin nada en el 1194: sano en directo."""
        extra = self.preparar_salud(caido="openvpn", tcp=self.TCP_SIN_ESCUCHA, arriba="1")
        extra["MODO"] = "directo"
        p = self.salud(extra, 1760090010)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_salud_directo_sigue_exigiendo_el_resto(self):
        for s in ("tzsp-decap", "rele-api"):
            with self.subTest(s):
                extra = self.preparar_salud(caido=s)
                extra["MODO"] = "directo"
                p = self.salud(extra, 1760090010)
                self.assertEqual(p.returncode, 1)
                self.assertIn(s, p.stdout)
        extra = self.preparar_salud(nft_ok=False)
        extra["MODO"] = "directo"
        self.assertEqual(self.salud(extra, 1760090010).returncode, 1)
        extra = self.preparar_salud()
        extra["MODO"] = "directo"
        self.assertEqual(self.salud(extra, 1760090090).returncode, 1)     # latido viejo

    # --- salud-vpn --------------------------------------------------------------------------
    # /proc/net/tcp de un netns con OpenVPN escuchando en 0.0.0.0:1194 (04AA) y un cliente
    # conectado (ESTABLISHED, 01); y el de uno sin nada en LISTEN en ese puerto
    TCP_ESCUCHA = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:04AA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1\n"
        "   1: 020140C8:04AA 2D7100CB:C822 01 00000000:00000000 02:00000A6B 00000000     0        0 4243 2\n")
    TCP_SIN_ESCUCHA = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 020140C8:04AA 2D7100CB:C822 01 00000000:00000000 02:00000A6B 00000000     0        0 4243 2\n"
        "   1: 00000000:04AB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4244 1\n")

    def preparar_salud(self, caido=None, nft_ok=True, mtime=1760090000, tcp=None, arriba="300",
                       server_conf="port 1194\nproto tcp4-server\n"):
        svc = Path(self.dir.name) / "service"
        for s in LONGRUNS:
            (svc / s).mkdir(parents=True, exist_ok=True)
        caido = caido or ""
        # `-o up` como antes; `-o updownfor` (segundos desde el último up/down) solo si se da
        # (arriba=None imita un s6-svstat que no conoce ese campo: sale con error)
        updown = ("echo %s" % arriba if arriba is not None
                  else 'echo "s6-svstat: fatal: unknown field" >&2; exit 100')
        self.falso("s6-svstat", f'''[ "$1" = "-o" ] || exit 9
if [ "$2" = "updownfor" ]; then {updown}; exit 0; fi
[ "$2" = "up" ] || exit 9
case "$3" in */{caido or "nada-caido"}) echo false ;; *) echo true ;; esac''')
        self.falso("nft", 'exit 0' if nft_ok else 'echo "Error: No such file or directory" >&2; exit 1')
        tzsp = Path(self.dir.name) / "tzsp.json"
        tzsp.write_text("{}", encoding="utf-8")
        os.utime(tzsp, (mtime, mtime))
        ftcp = Path(self.dir.name) / "tcp"
        ftcp.write_bytes((self.TCP_ESCUCHA if tcp is None else tcp).encode())
        conf = Path(self.dir.name) / "server.conf"
        conf.write_bytes(server_conf.encode())
        # tcp6 no existe: se salta (en el contenedor IPv6 está desactivado)
        return {"IDS_SVSTAT": ruta_bash(self.falsos / "s6-svstat"), "IDS_SERVICIOS": ruta_bash(svc),
                "IDS_TZSP": ruta_bash(tzsp), "IDS_PROC_TCP": ruta_bash(ftcp) + " " + ruta_bash(ftcp) + "6",
                "IDS_SERVERCONF": ruta_bash(conf)}

    def salud(self, extra, ahora):
        return self.ejecutar(ay.BIN / "salud-vpn", extra_env={**extra, "IDS_AHORA": str(ahora)})

    def test_salud_sana_sin_trafico(self):
        p = self.salud(self.preparar_salud(), 1760090089)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_salud_latido_viejo(self):
        p = self.salud(self.preparar_salud(), 1760090090)
        self.assertEqual(p.returncode, 1)
        self.assertIn("latido", p.stdout)

    def test_salud_sin_tzsp_json(self):
        extra = self.preparar_salud()
        extra["IDS_TZSP"] = ruta_bash(Path(self.dir.name) / "no-existe.json")
        self.assertEqual(self.salud(extra, 1760090010).returncode, 1)

    def test_salud_servicio_caido(self):
        for s in LONGRUNS:
            with self.subTest(s):
                p = self.salud(self.preparar_salud(caido=s), 1760090010)
                self.assertEqual(p.returncode, 1)
                self.assertIn(s, p.stdout)

    def test_salud_sin_tabla_nft(self):
        p = self.salud(self.preparar_salud(nft_ok=False), 1760090010)
        self.assertEqual(p.returncode, 1)
        self.assertIn("ids_punto", p.stdout)

    def test_salud_sin_listen_en_el_puerto(self):
        """Corrección de defecto (D6): openvpn «up» en s6 sin servidor escuchando salía sano."""
        p = self.salud(self.preparar_salud(tcp=self.TCP_SIN_ESCUCHA), 1760090010)
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("nadie escucha en 1194/tcp", p.stdout)

    def test_salud_puerto_de_server_conf(self):
        conf = "port 1195\nproto tcp4-server\n"
        p = self.salud(self.preparar_salud(server_conf=conf), 1760090010)
        self.assertEqual(p.returncode, 1)
        self.assertIn("1195/tcp", p.stdout)
        tcp = self.TCP_ESCUCHA.replace("00000000:04AA 00000000:0000 0A", "00000000:04AB 00000000:0000 0A")
        p = self.salud(self.preparar_salud(server_conf=conf, tcp=tcp), 1760090010)
        self.assertEqual(p.returncode, 0, p.stdout)
        # sin línea `port`: el 1194 de OpenVPN
        p = self.salud(self.preparar_salud(server_conf="proto tcp4-server\n"), 1760090010)
        self.assertEqual(p.returncode, 0, p.stdout)

    def test_salud_sano_con_mikrotik_desconectado(self):
        """El LISTEN no depende del cliente: sin ninguna conexión establecida sigue sano."""
        solo_listen = "".join(self.TCP_ESCUCHA.splitlines(True)[:2])
        p = self.salud(self.preparar_salud(tcp=solo_listen), 1760090010)
        self.assertEqual(p.returncode, 0, p.stdout)

    def test_salud_openvpn_recien_arrancado(self):
        """Un openvpn que s6 relanza en bucle está «up» unos segundos en cada vuelta."""
        p = self.salud(self.preparar_salud(arriba="3"), 1760090010)
        self.assertEqual(p.returncode, 1)
        self.assertIn("openvpn lleva 3 s arriba", p.stdout)
        self.assertEqual(self.salud(self.preparar_salud(arriba="6"), 1760090010).returncode, 0)

    def test_salud_s6_sin_updownfor_no_se_exige(self):
        p = self.salud(self.preparar_salud(arriba=None), 1760090010)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
