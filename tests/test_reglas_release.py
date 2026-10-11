"""ids-reglas descargar (CONTRATO-F1a §5.9): release completa con un suricata-update simulado
sobre reglas de prueba; LISTO el último, MANIFEST.json, una sola descarga, current intacto y
nada a medias si algo falla."""
import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_suricata as A  # noqa: E402

R = A.cargar("ids-reglas")
TS = "20261010T081500Z"
AHORA = 1760090000.0
HOSTS = b"127.0.0.1 malo.example.com\n127.0.0.1 otro.example.net\n127.0.0.1 192.0.2.1\n"
CLAVES_MANIFEST = {"v", "ts", "suricata_version", "imagen", "fuentes", "reglas", "dominios"}


def bajar_todo(datos=HOSTS):
    return lambda url: datos


def bajar_nada(url):
    raise R.ErrorReglas("HTTP 403")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.raiz = self.base / "reglas"
        self.raiz.mkdir()
        self.share = A.SHARE
        self.falso = A.FalsoSuricata(R)
        self.escritos = []
        original = R.escribir

        def espia(ruta, datos, modo=0o644):
            self.escritos.append(os.path.relpath(ruta, self.raiz).replace(os.sep, "/"))
            return original(ruta, datos, modo)

        self._original = original
        R.escribir = espia

    def tearDown(self):
        R.escribir = self._original
        self.tmp.cleanup()

    def share_copia(self):
        destino = self.base / "share"
        shutil.copytree(A.SHARE, destino)
        self.share = destino
        return destino

    def descargar(self, ts=TS, bajar=None, ahora=AHORA):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = R.descargar(ts, raiz=str(self.raiz), share=str(self.share), ejecutar=self.falso,
                             bajar=bajar or bajar_todo(), ahora=lambda: ahora,
                             imagen="ghcr.io/mtandazo35/ids-maat-suricata@sha256:" + "0" * 64,
                             salida=out)
        self.err = err.getvalue()
        lineas = out.getvalue().splitlines()
        self.ultima = json.loads(lineas[-1]) if lineas else None
        self.ultima_texto = lineas[-1] if lineas else ""
        return rc

    def rel(self, ts=TS):
        return self.raiz / "releases" / ts


class ReleaseBuena(Base):
    def test_arbol_completo(self):
        self.assertEqual(self.descargar(), 0, self.err)
        rel = self.rel()
        for p in ("completo/suricata.rules", "completo/local.rules", "completo/classification.config",
                  "reducido/suricata.rules", "reducido/local.rules", "reducido/classification.config",
                  "feeds/domains.dataset", "feeds/domains.lst", "MANIFEST.json", "LISTO"):
            self.assertTrue((rel / p).is_file(), p)
        sobrantes = [p for p in rel.rglob("*.tmp")]
        self.assertEqual(sobrantes, [])

    def test_listo_es_lo_ultimo_y_es_el_resumen(self):
        self.assertEqual(self.descargar(), 0, self.err)
        rel_listo = "releases/%s/LISTO" % TS
        self.assertEqual(self.escritos[-1], rel_listo)
        self.assertIn("releases/%s/MANIFEST.json" % TS, self.escritos[:-1])
        listo = (self.rel() / "LISTO").read_text(encoding="utf-8").strip()
        self.assertEqual(listo, self.ultima_texto)
        self.assertIs(self.ultima["ok"], True)

    def test_manifest(self):
        self.assertEqual(self.descargar(), 0, self.err)
        m = json.loads((self.rel() / "MANIFEST.json").read_text(encoding="utf-8"))
        self.assertEqual(set(m), CLAVES_MANIFEST)
        self.assertEqual((m["v"], m["ts"], m["suricata_version"]), (1, TS, "7.0.10"))
        self.assertTrue(m["imagen"].startswith("ghcr.io/mtandazo35/ids-maat-suricata@sha256:"))
        self.assertEqual(m["dominios"], 2)
        et = m["fuentes"][0]
        self.assertEqual(et["nombre"], "et-open")
        self.assertEqual(et["url"], self.falso.url)
        tar = self.falso.ruta_tar(self.raiz / "cache" / "suricata-update")
        self.assertEqual(et["sha256"], hashlib.sha256(tar.read_bytes()).hexdigest())
        for f in m["fuentes"]:
            self.assertEqual(set(f), {"nombre", "url", "sha256"})
        for perfil in ("completo", "reducido"):
            d = self.rel() / perfil
            activas = sum(len(R.reglas_activas((d / f).read_text(encoding="utf-8")))
                          for f in ("suricata.rules", "local.rules"))
            self.assertEqual(m["reglas"][perfil], activas)
        self.assertLess(m["reglas"]["reducido"], m["reglas"]["completo"])
        resumen = dict(m, ok=True)
        self.assertEqual(self.ultima, resumen)

    def test_sid_e2e_en_los_dos_perfiles(self):
        self.assertEqual(self.descargar(), 0, self.err)
        for perfil in ("completo", "reducido"):
            texto = (self.rel() / perfil / "suricata.rules").read_text(encoding="utf-8")
            self.assertTrue(R.sid_activo(texto, 2100498), perfil)
        reducido = (self.rel() / "reducido" / "suricata.rules").read_text(encoding="utf-8")
        self.assertFalse(R.sid_activo(reducido, 2900020))          # ET POLICY fuera
        self.assertNotIn("sid:2900090;", reducido)                  # *deleted.rules ignorado

    def test_una_sola_descarga_y_reducido_offline(self):
        self.assertEqual(self.descargar(), 0, self.err)
        upd = [a for a in self.falso.llamadas if a[0] == "suricata-update"]
        self.assertEqual(len(upd), 2)
        self.assertEqual([("--offline" in a) for a in upd], [False, True])
        datos = str(self.raiz / "cache" / "suricata-update")
        for a in upd:
            self.assertEqual(a[a.index("--data-dir") + 1], datos)
            self.assertIn("--no-test", a)
            self.assertNotIn("-T", a)
            self.assertFalse([x for x in a if x.startswith("--reload")])
        salidas = [Path(a[a.index("-o") + 1]).name for a in upd]
        self.assertEqual(salidas, ["completo", "reducido"])

    def test_local_rules_apunta_al_dataset_de_la_misma_release(self):
        self.assertEqual(self.descargar(), 0, self.err)
        dataset = "%s/releases/%s/feeds/domains.dataset" % (str(self.raiz).rstrip("/"), TS)
        for perfil in ("completo", "reducido"):
            local = (self.rel() / perfil / "local.rules").read_text(encoding="utf-8")
            self.assertNotIn("@@", local)
            self.assertIn("load %s;" % dataset, local)
            self.assertNotIn("save", local.split("dataset:", 1)[1].split(";", 1)[0])

    def test_dataset_presente_aunque_fallen_los_feeds(self):
        self.assertEqual(self.descargar(bajar=bajar_nada), 0, self.err)
        ds = self.rel() / "feeds" / "domains.dataset"
        self.assertTrue(ds.is_file())
        self.assertEqual(ds.read_bytes(), b"")
        self.assertEqual(self.ultima["dominios"], 0)
        self.assertTrue(all(f["sha256"] is None for f in self.ultima["fuentes"][1:]))

    def test_classification_del_sistema_si_suricata_update_no_la_deja(self):
        self.falso.clasificacion = False
        sistema = self.base / "classification.config"
        sistema.write_text("config classification: bad-unknown,Potentially Bad Traffic,2\n")
        viejo = R.CLASIFICACION_SISTEMA
        R.CLASIFICACION_SISTEMA = str(sistema)
        try:
            self.assertEqual(self.descargar(), 0, self.err)
        finally:
            R.CLASIFICACION_SISTEMA = viejo
        for perfil in ("completo", "reducido"):
            self.assertEqual((self.rel() / perfil / "classification.config").read_text(),
                             sistema.read_text())

    @unittest.skipUnless(sys.platform.startswith("linux"), "modos POSIX")
    def test_modos(self):
        self.assertEqual(self.descargar(), 0, self.err)
        for p in self.rel().rglob("*"):
            modo = p.stat().st_mode & 0o777
            self.assertEqual(modo, 0o755 if p.is_dir() else 0o644, str(p))

    def test_current_no_se_toca(self):
        actual = self.raiz / "current"
        try:
            os.symlink("releases/20261009T081500Z", actual)
            antes = os.readlink(actual)
        except (OSError, NotImplementedError):
            actual.write_text("releases/20261009T081500Z")   # Windows sin permiso de enlaces
            antes = actual.read_text()
        self.assertEqual(self.descargar(), 0, self.err)
        despues = os.readlink(actual) if actual.is_symlink() else actual.read_text()
        self.assertEqual(antes, despues)
        # bajo /reglas solo escribe en releases/<ts>/ y cache/ (lo de fuera es su /tmp)
        en_reglas = [e for e in self.escritos if not e.startswith("..")]
        self.assertTrue(en_reglas)
        self.assertFalse([e for e in en_reglas if not e.startswith(("releases/%s/" % TS, "cache/"))])
        self.assertEqual(sorted(p.name for p in self.raiz.iterdir()), ["cache", "current", "releases"])


class ReleaseMala(Base):
    def assertNadaAMedias(self, rc):
        self.assertEqual(rc, 1)
        self.assertFalse(self.rel().exists(), "la release a medias tiene que desaparecer")
        self.assertIs(self.ultima["ok"], False)
        self.assertNotIn("releases/%s/LISTO" % TS, self.escritos)

    def test_falla_el_perfil_reducido(self):
        self.falso.fallar_en = "reducido"
        self.assertNadaAMedias(self.descargar())
        self.assertIn("suricata-update", self.err)

    def test_falla_la_descarga_de_et(self):
        self.falso.fallar_en = "completo"
        self.assertNadaAMedias(self.descargar())

    def test_offline_sin_cache_no_inventa_reglas(self):
        """Si la descarga no deja nada en la caché, reducido no puede salir de la nada."""
        original = self.falso._update

        def sin_cache(args):
            r = original(args)
            if "--offline" not in args:
                self.falso.ruta_tar(args[args.index("--data-dir") + 1]).unlink()
            return r
        self.falso._update = sin_cache
        self.assertNadaAMedias(self.descargar())

    def test_un_disable_que_quita_el_sid_e2e_tumba_la_release(self):
        share = self.share_copia()
        with open(share / "disable-reducido.conf", "a", encoding="utf-8") as f:
            f.write("2100498\n")
        self.assertNadaAMedias(self.descargar())
        self.assertIn("2100498", self.err)

    def test_marcador_sin_sustituir_en_local_rules(self):
        share = self.share_copia()
        with open(share / "local.rules.tmpl", "a", encoding="utf-8") as f:
            f.write("# @@OTRO@@\n")
        self.assertNadaAMedias(self.descargar())

    def test_ts_invalido(self):
        for ts in ("", "2026-10-10", "20261010T081500", "../../etc", "20261310T081500Z", TS + "\n"):
            self.assertEqual(self.descargar(ts=ts), 1, ts)
            self.assertIs(self.ultima["ok"], False)
        self.assertFalse((self.raiz / "releases").exists() and any((self.raiz / "releases").iterdir()))

    def test_release_existente_no_se_pisa(self):
        self.assertEqual(self.descargar(), 0, self.err)
        listo = (self.rel() / "LISTO").read_bytes()
        self.escritos.clear()
        self.assertEqual(self.descargar(), 1)
        self.assertEqual((self.rel() / "LISTO").read_bytes(), listo, "la release buena sigue intacta")
        self.assertEqual(self.escritos, [])

    def test_la_cache_sobrevive_a_un_fallo(self):
        self.falso.fallar_en = "reducido"
        self.descargar()
        self.assertTrue(self.falso.ruta_tar(self.raiz / "cache" / "suricata-update").is_file())


class Programa(unittest.TestCase):
    def test_argumentos(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                R.main([])
        self.assertEqual(cm.exception.code, 2)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                R.main(["descargar"])


if __name__ == "__main__":
    unittest.main()
