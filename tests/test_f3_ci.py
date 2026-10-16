"""CI y pruebas obligatorias (auditoría B-01, B-03).

- B-01: la integración F2 entró sin CI porque `ci.yml` tenía YAML inválido y las pruebas de los
  workflows solo buscaban texto. Aquí se PARSEAN con PyYAML (los workflows y el compose
  renderizado). Es obligatoria en todas las plataformas: en local avisa antes de subir (una prueba
  dentro del CI no puede avisar de que el CI no arranca) y el CI la corre con PyYAML fijado.
- B-03: `tests/correr.py` no veía un módulo obligatorio omitido al importarse ni un patrón
  obligatorio que ya no casaba con nada.
Tipo de cada prueba en su docstring (CONTRATO-F2 §10.5).
"""
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

AQUI = Path(__file__).resolve().parent
REPO = AQUI.parent
WF = REPO / ".github" / "workflows"
sys.path.insert(0, str(AQUI))
import _ayuda_orq as A  # noqa: E402
import correr  # noqa: E402

try:
    import yaml
except ImportError:          # en el CI está (PYYAML_CI); sin él, estas pruebas se omiten y fallan como obligatorias
    yaml = None


@unittest.skipUnless(yaml, "sin PyYAML (pip install pyyaml; el CI lo instala con versión fijada)")
class YamlReal(unittest.TestCase):
    def test_workflows_son_yaml_valido(self):
        """Corrección de defecto (B-01): cada workflow se parsea como lo haría GitHub (YAML 1.1); un
        `run:` de una línea con «: » sin comillas (lo que dejó el CI sin arrancar) falla aquí."""
        ficheros = sorted(WF.glob("*.yml"))
        self.assertTrue(ficheros)
        for f in ficheros:
            with self.subTest(f.name):
                d = yaml.safe_load(f.read_text(encoding="utf-8"))
                self.assertIsInstance(d, dict)
                self.assertIsInstance(d.get("jobs"), dict, f.name)
                for nombre, job in d["jobs"].items():
                    for paso in job.get("steps") or []:
                        if "run" in paso:
                            self.assertIsInstance(paso["run"], str, "%s/%s: run no es texto" % (f.name, nombre))

    def test_detecta_el_fallo_que_dejo_el_ci_sin_arrancar(self):
        """Corrección de defecto (B-01): el `run:` sin comillas de bloque de antes de 48e3c2a no es
        YAML válido; la prueba de arriba lo habría parado."""
        roto = ('jobs:\n  a:\n    steps:\n      - name: x\n'
                '        run: python -m pip install --quiet --only-binary=:all: "cryptography==1"\n')
        with self.assertRaises(yaml.YAMLError):
            yaml.safe_load(roto)

    def test_compose_renderizado_es_yaml_valido(self):
        """Corrección de defecto (B-01): el compose.yml de un punto, como lo escribe el orquestador,
        se lee con PyYAML y tiene sus dos servicios."""
        mod, e, _s, orq = A.preparar(ncpu=8)
        try:
            A.crear(self, orq, {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]})
            d = yaml.safe_load(e.ruta("/srv/ids/puntos/p001/compose.yml").read_text(encoding="utf-8"))
            self.assertEqual(set(d["services"]), {"vpn", "suricata"})
            self.assertEqual(d["name"], "ids-p001")
        finally:
            A.cerrar(orq, e)


class CiInstala(unittest.TestCase):
    def setUp(self):
        self.ci = (WF / "ci.yml").read_text(encoding="utf-8")

    def test_pyyaml_fijado_en_el_lint(self):
        """Corrección de defecto (B-01/B-03): PyYAML con versión fijada para la sintaxis YAML de los
        workflows y del compose. Desde 2026-10-15 el CI solo hace lint; las obligatorias se
        comprueban en la VPS (`IDS_OBLIGATORIAS=linux|root bash tests/run.sh`)."""
        self.assertRegex(self.ci, r'PYYAML_CI: "\d+\.\d+\.\d+"')
        self.assertEqual(len(re.findall(r'"pyyaml==\$\{PYYAML_CI\}"', self.ci)), 1)
        self.assertIn("test_f3_ci.YamlReal", self.ci)


class Obligatorias(unittest.TestCase):
    def test_modulo_omitido_al_importar_cuenta_como_obligatoria_omitida(self):
        """Corrección de defecto (B-03): un módulo obligatorio que se omite entero al importarse
        (`raise unittest.SkipTest`) ya no pasa desapercibido."""
        d = tempfile.mkdtemp(prefix="ids-oblig-")
        self.addCleanup(shutil.rmtree, d, True)
        Path(d, "test_modulo_omitido.py").write_text(
            "import unittest\nraise unittest.SkipTest('falta cryptography')\n", encoding="utf-8")
        suite = unittest.defaultTestLoader.discover(d, pattern="test_*.py", top_level_dir=d)
        descubiertas = correr.ids_de(suite)
        r = unittest.TestResult()
        suite.run(r)
        omitidas = [(t.id(), str(m)) for t, m in r.skipped]
        sys.modules.pop("test_modulo_omitido", None)
        om, sin, cuenta = correr.comprobar_obligatorias(
            [("test_modulo_omitido.*", "exige cryptography")], descubiertas, omitidas)
        self.assertEqual(len(om), 1, (descubiertas, omitidas))
        self.assertIn("falta cryptography", om[0][1])
        self.assertEqual((sin, cuenta), ([], {"test_modulo_omitido.*": 0}))

    def test_patron_sin_ninguna_prueba_falla(self):
        """Corrección de defecto (B-03): un patrón obligatorio que no casa con ninguna prueba
        (fichero borrado o renombrado) se informa como «sin prueba»."""
        om, sin, cuenta = correr.comprobar_obligatorias(
            [("test_existe.*", ""), ("test_borrado.*", "motivo")],
            ["test_existe.A.test_x", "test_existe.A.test_y"], [])
        self.assertEqual(om, [])
        self.assertEqual(sin, [("test_borrado.*", "motivo")])
        self.assertEqual(cuenta, {"test_existe.*": 2, "test_borrado.*": 0})

    def test_obligatorias_txt_casan_todas_con_alguna_prueba(self):
        """Corrección de defecto (B-03): todos los patrones de tests/obligatorias.txt (de todas las
        plataformas) casan con alguna prueba del repositorio."""
        suite = unittest.defaultTestLoader.discover(str(AQUI), pattern="test_*.py", top_level_dir=str(AQUI))
        descubiertas = correr.ids_de(suite)
        for plataforma in correr.PLATAFORMAS:
            _om, sin, _c = correr.comprobar_obligatorias(correr.leer_obligatorias(plataforma), descubiertas, [])
            self.assertEqual(sin, [], plataforma)

    def test_root_incluye_las_de_linux(self):
        """Capacidad nueva: `--obligatorias root` (como root en la VPS) aplica las de linux y las de root."""
        root = {p for p, _m in correr.leer_obligatorias("root")}
        linux = {p for p, _m in correr.leer_obligatorias("linux")}
        self.assertTrue(linux <= root)
        self.assertIn("test_orq_panel.Aplicar.test_master_key_legible_por_el_grupo_del_panel", root)
        self.assertNotIn("test_orq_panel.Aplicar.test_master_key_legible_por_el_grupo_del_panel", linux)


if __name__ == "__main__":
    unittest.main()
