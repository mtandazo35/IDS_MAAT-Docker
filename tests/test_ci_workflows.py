"""CI y release: scripts de apoyo ejecutados de verdad (release.json, render de .nft, build.sh y la lista
de lint) y reglas de los workflows (acciones por SHA, matriz vpn/suricata, cosign coherente con
install.sh)."""

import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WF = REPO / ".github" / "workflows"
SCRIPTS = REPO / ".github" / "scripts"


def cargar(nombre):
    spec = importlib.util.spec_from_file_location("ci_" + nombre, SCRIPTS / (nombre + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def bash():
    for c in ("bash",):
        p = shutil.which(c)
        if p and "system32" not in p.lower():
            return p
    return None


class ReleaseJson(unittest.TestCase):
    def setUp(self):
        self.mod = cargar("release_json")
        self.d = Path(tempfile.mkdtemp(prefix="rel-"))
        self.tar = self.d / "ids-maat-host-0.1.0.tar.gz"
        self.tar.write_bytes(b"contenido del tar")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_formato_del_contrato(self):
        vpn = "ghcr.io/mtandazo35/ids-maat-vpn@sha256:" + "1" * 64
        sur = "ghcr.io/mtandazo35/ids-maat-suricata@sha256:" + "2" * 64
        d = self.mod.construir("0.1.0", vpn, sur, self.tar)
        self.assertEqual(d, {"v": 1, "version": "0.1.0", "imagenes": {"vpn": vpn, "suricata": sur},
                             "host_tar": {"nombre": "ids-maat-host-0.1.0.tar.gz",
                                          "sha256": hashlib.sha256(b"contenido del tar").hexdigest()},
                             "min_orq": "0.1.0", "migraciones": []})

    def test_version_exacta_de_suricata(self):
        vpn = "ghcr.io/mtandazo35/ids-maat-vpn@sha256:" + "1" * 64
        sur = "ghcr.io/mtandazo35/ids-maat-suricata@sha256:" + "2" * 64
        d = self.mod.construir("0.1.0", vpn, sur, self.tar, suricata_version="7.0.10")
        self.assertEqual(d["suricata_version"], "7.0.10")
        import io
        import contextlib
        import json
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = self.mod.main(["--version", "0.1.0", "--vpn", vpn, "--suricata", sur, "--tar", str(self.tar),
                                "--suricata-version", "7.0.10"])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue())["suricata_version"], "7.0.10")
        for mala in ("7.0", "", "7.0.10\n", "7.0.x"):
            with self.assertRaises(ValueError, msg=repr(mala)):
                self.mod.construir("0.1.0", vpn, sur, self.tar, suricata_version=mala)

    def test_rechaza_referencias_malas(self):
        buena = "ghcr.io/mtandazo35/ids-maat-vpn@sha256:" + "1" * 64
        for vpn, sur, ver in ((buena.replace("vpn@", "suricata@"), buena, "0.1.0"),
                              ("ghcr.io/otro/ids-maat-vpn@sha256:" + "1" * 64, buena, "0.1.0"),
                              ("ghcr.io/mtandazo35/ids-maat-vpn:latest", buena, "0.1.0"),
                              (buena, "ghcr.io/mtandazo35/ids-maat-suricata@sha256:" + "2" * 64, "v0.1.0")):
            with self.assertRaises(ValueError):
                self.mod.construir(ver, vpn, sur, self.tar)


class RenderNft(unittest.TestCase):
    def test_renderiza(self):
        d = Path(tempfile.mkdtemp(prefix="nft-"))
        try:
            antes = os.environ.get("IDS_RAIZ")
            import io
            import contextlib
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cargar("render_nft").main([str(d)]), 0)
            self.assertIn("ids_host-vacio.nft", out.getvalue())
            self.assertEqual(os.environ.get("IDS_RAIZ"), antes)
            vacio = (d / "ids_host-vacio.nft").read_text(encoding="utf-8")
            puntos = (d / "ids_host-puntos.nft").read_text(encoding="utf-8")
            self.assertIn("set puertos_vpn { type inet_service; }", vacio)
            self.assertIn("elements = { 1194, 1196 }", puntos)
            self.assertIn('comment "origen fijo p003"', puntos)
            self.assertNotRegex(vacio + puntos, r"@@[A-Z_]+@@")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class Lint(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git"), "sin git")
    def test_listas(self):
        mod = cargar("lint")
        import io
        import contextlib
        for tipo, esperados in (("python", ["orquestador/ids_orq.py", ".github/scripts/lint.py"]),
                                ("shell", ["install.sh", "images/build.sh", "tests/run.sh"])):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(mod.main([tipo]), 0)
            lista = out.getvalue().split()
            for e in esperados:
                self.assertIn(e, lista)
        self.assertEqual(mod.main(["otro"]), 2)


@unittest.skipUnless(bash(), "sin bash")
class BuildSh(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="build-"))
        self.reg = self.d / "args"
        falso = self.d / "docker"
        falso.write_text('#!/bin/sh\nfor a in "$@"; do echo "$a"; done > "%s"\n' % self.reg.as_posix(),
                         encoding="utf-8", newline="\n")
        falso.chmod(0o755)
        self.docker = falso.as_posix()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def correr(self, *args):
        env = dict(os.environ, DOCKER=self.docker)
        env.pop("VERSION", None)
        return subprocess.run([bash(), "images/build.sh"] + list(args), cwd=REPO, env=env, capture_output=True,
                              text=True)

    @unittest.skipUnless((REPO / "images" / "vpn" / "Dockerfile").exists(), "falta images/vpn/Dockerfile (A)")
    def test_build_con_base_fijada(self):
        r = self.correr("vpn", "ci")
        self.assertEqual(r.returncode, 0, r.stderr)
        args = self.reg.read_text(encoding="utf-8").split("\n")
        base = (REPO / "images" / "base.env").read_text(encoding="utf-8").strip()
        self.assertRegex(base, r"^BASE_IMAGE=debian:trixie-slim@sha256:[0-9a-f]{64}$")
        self.assertEqual(args[:8], ["build", "--build-arg", base, "--build-arg", "VERSION=dev", "-t",
                                    "ids-maat-vpn:ci", "vpn"])
        r = self.correr("vpn")
        self.assertIn("ids-maat-vpn:dev", self.reg.read_text(encoding="utf-8"))

    @unittest.skipUnless((REPO / "images" / "suricata" / "Dockerfile").exists(), "falta images/suricata/Dockerfile (B)")
    def test_suricata_pasa_la_serie(self):
        r = self.correr("suricata", "ci")
        self.assertEqual(r.returncode, 0, r.stderr)
        args = self.reg.read_text(encoding="utf-8").split("\n")
        serie = re.search(r"^ARG SURICATA_VERSION=(\S+)$",
                          (REPO / "images" / "suricata" / "Dockerfile").read_text(encoding="utf-8"), re.M).group(1)
        self.assertRegex(serie, r"^\d+\.\d+$")
        i = args.index("SURICATA_VERSION=%s" % serie)
        self.assertEqual(args[i - 1], "--build-arg")
        self.assertEqual([x for x in args if x][-3:], ["-t", "ids-maat-suricata:ci", "suricata"])
        self.correr("vpn", "ci")
        self.assertNotIn("SURICATA_VERSION", self.reg.read_text(encoding="utf-8"))

    def test_argumentos_malos(self):
        self.assertEqual(self.correr("panel").returncode, 2)
        self.assertEqual(self.correr().returncode, 2)
        self.assertEqual(self.correr("vpn", "x;rm").returncode, 2)


class Workflows(unittest.TestCase):
    def leer(self, nombre):
        return (WF / nombre).read_text(encoding="utf-8")

    def test_acciones_fijadas_por_sha(self):
        for nombre in ("ci.yml", "release.yml"):
            for uso in re.findall(r"^\s*-?\s*uses:\s*(\S+)", self.leer(nombre), re.M):
                if uso.startswith("./"):
                    continue
                self.assertRegex(uso, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$", "%s: %s" % (nombre, uso))

    def test_jobs_de_ci(self):
        ci = self.leer("ci.yml")
        for job in ("lint", "pruebas", "pruebas-windows", "imagenes"):
            self.assertRegex(ci, r"(?m)^  %s:\n" % re.escape(job))
        self.assertIn("workflow_call:", ci)
        self.assertIn("runs-on: windows-latest", ci)
        self.assertIn("bash tests/run.sh --imagenes --integracion", ci)

    def test_release(self):
        rel = self.leer("release.yml")
        self.assertRegex(rel, r'tags: \["v\*"\]')
        self.assertIn("img: [vpn, suricata]", rel)
        self.assertNotIn("panel", rel.split("img:")[1].split("\n")[0])
        self.assertIn("uses: ./.github/workflows/ci.yml", rel)
        self.assertIn("id-token: write", rel)
        self.assertIn("sign-blob --yes --bundle release.json.bundle release.json", rel)
        self.assertIn("git archive --format=tar.gz", rel)

    def test_release_publica_la_version_exacta_de_suricata(self):
        rel = self.leer("release.yml")
        # imagen: la etiqueta lleva la serie del ARG del Dockerfile, solo en la imagen suricata
        self.assertIn("sed -n 's/^ARG SURICATA_VERSION=//p' images/suricata/Dockerfile", rel)
        self.assertIn("matrix.img == 'suricata' && format('SURICATA_VERSION={0}', "
                      "steps.base.outputs.suricata_serie)", rel)
        # release: la versión exacta sale de la imagen publicada y va a release.json
        self.assertRegex(rel, r'--entrypoint cat "\$ref_suricata" \\\n\s+/usr/share/ids-maat/suricata-version')
        self.assertIn('--suricata-version "$suricata_version"', rel)

    def test_cosign_igual_que_install(self):
        rel = self.leer("release.yml")
        inst = (REPO / "install.sh").read_text(encoding="utf-8")
        for var in ("COSIGN_VERSION", "COSIGN_SHA256"):
            v_rel = re.search(r"%s: (\S+)" % var, rel).group(1)
            v_inst = re.search(r"^%s=(\S+)$" % var, inst, re.M).group(1)
            self.assertEqual(v_rel, v_inst, var)


if __name__ == "__main__":
    unittest.main()
