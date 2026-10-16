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

    VPN = "ghcr.io/mtandazo35/ids-maat-vpn@sha256:" + "1" * 64
    SUR = "ghcr.io/mtandazo35/ids-maat-suricata@sha256:" + "2" * 64
    PANEL = "ghcr.io/mtandazo35/ids-maat-panel@sha256:" + "3" * 64

    def test_formato_del_contrato_con_panel(self):
        d = self.mod.construir("0.1.0", self.VPN, self.SUR, self.PANEL, self.tar)
        self.assertEqual(d, {"v": 1, "version": "0.1.0",
                             "imagenes": {"vpn": self.VPN, "suricata": self.SUR, "panel": self.PANEL},
                             "host_tar": {"nombre": "ids-maat-host-0.1.0.tar.gz",
                                          "sha256": hashlib.sha256(b"contenido del tar").hexdigest()},
                             "min_orq": "0.1.0", "migraciones": []})

    def test_version_exacta_de_suricata(self):
        d = self.mod.construir("0.1.0", self.VPN, self.SUR, self.PANEL, self.tar, suricata_version="7.0.10")
        self.assertEqual(d["suricata_version"], "7.0.10")
        import io
        import contextlib
        import json
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = self.mod.main(["--version", "0.1.0", "--vpn", self.VPN, "--suricata", self.SUR, "--panel", self.PANEL,
                                "--tar", str(self.tar), "--suricata-version", "7.0.10"])
        self.assertEqual(rc, 0)
        d = json.loads(out.getvalue())
        self.assertEqual(d["suricata_version"], "7.0.10")
        self.assertEqual(d["imagenes"]["panel"], self.PANEL)
        for mala in ("7.0", "", "7.0.10\n", "7.0.x"):
            with self.assertRaises(ValueError, msg=repr(mala)):
                self.mod.construir("0.1.0", self.VPN, self.SUR, self.PANEL, self.tar, suricata_version=mala)

    def test_sin_panel_no_hay_release(self):
        import io
        import contextlib
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.mod.main(["--version", "0.1.0", "--vpn", self.VPN, "--suricata", self.SUR, "--tar", str(self.tar)])

    def test_rechaza_referencias_malas(self):
        buena, sur, panel = self.VPN, self.SUR, self.PANEL
        for vpn, s, pn, ver in ((buena.replace("vpn@", "suricata@"), sur, panel, "0.1.0"),
                                ("ghcr.io/otro/ids-maat-vpn@sha256:" + "1" * 64, sur, panel, "0.1.0"),
                                ("ghcr.io/mtandazo35/ids-maat-vpn:latest", sur, panel, "0.1.0"),
                                (buena, sur, panel, "v0.1.0"),
                                (buena, sur, "ghcr.io/mtandazo35/ids-maat-panel:0.1.0", "0.1.0"),
                                (buena, sur, panel.replace("panel@", "vpn@"), "0.1.0"),
                                (buena, sur, "", "0.1.0")):
            with self.assertRaises(ValueError, msg=(vpn, s, pn, ver)):
                self.mod.construir(ver, vpn, s, pn, self.tar)


class GhcrPublico(unittest.TestCase):
    """ghcr_publico.py con un registro falso: anónimo obtiene token; el manifiesto da 200 si el
    paquete es público y 401/403 si es privado."""

    def setUp(self):
        self.mod = cargar("ghcr_publico")
        self.publicos = {"vpn", "suricata"}
        self.pedidas = []

    def abrir(self, req, timeout=None):
        import io
        import json
        import urllib.error
        url = req.full_url
        self.pedidas.append((req.get_method(), url, dict(req.header_items())))
        if "/token?" in url:
            cuerpo = io.BytesIO(json.dumps({"token": "anonimo"}).encode())
            cuerpo.status = 200
            return cuerpo
        nombre = re.search(r"/ids-maat-([a-z]+)/manifests/", url).group(1)
        if nombre in self.publicos:
            r = io.BytesIO(b"")
            r.status = 200
            return r
        raise urllib.error.HTTPError(url, 401, "unauthorized", {}, None)

    def correr(self, *args):
        import io
        out = io.StringIO()
        self.resumen = Path(tempfile.mkdtemp(prefix="ghcr-")) / "resumen.md"
        antes = os.environ.get("GITHUB_STEP_SUMMARY")
        os.environ["GITHUB_STEP_SUMMARY"] = str(self.resumen)
        try:
            rc = self.mod.main(list(args), abrir=self.abrir, salida=out)
        finally:
            if antes is None:
                os.environ.pop("GITHUB_STEP_SUMMARY", None)
            else:
                os.environ["GITHUB_STEP_SUMMARY"] = antes
        return rc, out.getvalue()

    def test_privado_avisa_con_el_enlace_y_falla_en_estricto(self):
        rc, out = self.correr("--estricto", "0.2.0", "panel", "vpn", "suricata")
        self.assertEqual(rc, 1)
        self.assertIn("::warning title=GHCR privado::ids-maat-panel es privado", out)
        self.assertIn("https://github.com/users/mtandazo35/packages/container/ids-maat-panel/settings", out)
        self.assertIn("ids-maat-vpn:0.2.0 es público", out)
        self.assertNotIn("ids-maat-vpn es privado", out)
        self.assertIn("ids-maat-panel", self.resumen.read_text(encoding="utf-8"))
        # sin credenciales: solo el token anónimo y el manifiesto por etiqueta
        for metodo, url, cab in self.pedidas:
            self.assertTrue(url.startswith("https://ghcr.io/"), url)
            if "/manifests/" in url:
                self.assertEqual(metodo, "HEAD")
                self.assertEqual(cab.get("Authorization"), "Bearer anonimo")
                self.assertTrue(url.endswith("/manifests/0.2.0"), url)

    def test_todo_publico(self):
        self.publicos = {"panel", "vpn", "suricata"}
        rc, out = self.correr("--estricto", "0.2.0", "panel", "vpn", "suricata")
        self.assertEqual(rc, 0)
        self.assertNotIn("::warning", out)
        self.assertFalse(self.resumen.exists())

    def test_sin_estricto_solo_avisa(self):
        rc, out = self.correr("0.2.0", "panel")
        self.assertEqual(rc, 0)
        self.assertIn("::warning", out)


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

    @unittest.skipUnless((REPO / "images" / "panel" / "Dockerfile").exists(), "falta images/panel/Dockerfile (P)")
    def test_panel_con_base_fijada(self):
        r = self.correr("panel", "ci")
        self.assertEqual(r.returncode, 0, r.stderr)
        args = self.reg.read_text(encoding="utf-8").split("\n")
        base = (REPO / "images" / "base.env").read_text(encoding="utf-8").strip()
        self.assertEqual(args[:8], ["build", "--build-arg", base, "--build-arg", "VERSION=dev", "-t",
                                    "ids-maat-panel:ci", "panel"])
        self.assertNotIn("SURICATA_VERSION", "\n".join(args))

    def test_argumentos_malos(self):
        self.assertEqual(self.correr("otro").returncode, 2)
        self.assertEqual(self.correr("panel;x").returncode, 2)
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
        for job in ("lint", "pruebas", "imagenes"):
            self.assertRegex(ci, r"(?m)^  %s:\n" % re.escape(job))
        self.assertNotIn("windows-latest", ci)          # sin job de Windows (dueño, 2026-10-15)
        # imagenes arranca a la vez que pruebas (no las espera): el CI acaba ~8 min antes
        self.assertNotRegex(ci.split("\n  imagenes:\n", 1)[1], r"(?m)^    needs:")
        self.assertIn("bash tests/run.sh --imagenes --integracion", ci)

    def test_ci_construye_y_prueba_las_tres_imagenes(self):
        ci = self.leer("ci.yml")
        for img in ("vpn", "suricata", "panel"):
            self.assertIn("bash images/build.sh %s ci" % img, ci)
            self.assertIn("IDS_IMG_%s: ids-maat-%s:ci" % ("SURICATA" if img == "suricata" else img.upper(), img), ci)

    def test_release(self):
        rel = self.leer("release.yml")
        self.assertRegex(rel, r'tags: \["v\*"\]')
        matriz = re.search(r"(?m)^\s+img: \[([^\]]*)\]$", rel).group(1)
        self.assertEqual([x.strip() for x in matriz.split(",")], ["panel", "vpn", "suricata"])
        # no repite el CI: exige que ci.yml esté en verde para el commit etiquetado
        self.assertNotIn("uses: ./.github/workflows/ci.yml", rel)
        self.assertIn("actions/workflows/ci.yml/runs?head_sha=${GITHUB_SHA}&status=success", rel)
        self.assertIn("needs: ci-verde", rel.split("\n  imagen:\n", 1)[1])
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

    def test_cada_imagen_de_la_matriz_llega_a_release_json_e_install(self):
        """Lo que publica la matriz es lo que release.json lleva por digest, lo que verifica la
        visibilidad, lo que install.sh exige en release.json y lo que build.sh acepta."""
        rel = self.leer("release.yml")
        inst = (REPO / "install.sh").read_text(encoding="utf-8")
        build = (REPO / "images" / "build.sh").read_text(encoding="utf-8")
        matriz = [x.strip() for x in re.search(r"(?m)^\s+img: \[([^\]]*)\]$", rel).group(1).split(",")]
        visib = re.search(r"ghcr_publico\.py --estricto \S+ (.+)$", rel, re.M).group(1).split()
        self.assertEqual(sorted(visib), sorted(matriz))
        self.assertIn("needs: release", rel.split("visibilidad:")[1])
        exigidas = re.search(r'for parte in \(([^)]*)\):\n\s+ref = d\["imagenes"\]\[parte\]', inst).group(1)
        for img in matriz:
            self.assertIn('ref_%s="ghcr.io/mtandazo35/ids-maat-%s@$(digest %s)"' % (img, img, img), rel)
            self.assertIn('--%s "$ref_%s"' % (img, img), rel)
            self.assertIn('"%s"' % img, exigidas)
            self.assertIn(img, re.search(r"^  ([a-z|]+)\) ;;$", build, re.M).group(1).split("|"))

    def test_cosign_igual_que_install(self):
        rel = self.leer("release.yml")
        inst = (REPO / "install.sh").read_text(encoding="utf-8")
        for var in ("COSIGN_VERSION", "COSIGN_SHA256"):
            v_rel = re.search(r"%s: (\S+)" % var, rel).group(1)
            v_inst = re.search(r"^%s=(\S+)$" % var, inst, re.M).group(1)
            self.assertEqual(v_rel, v_inst, var)


if __name__ == "__main__":
    unittest.main()
