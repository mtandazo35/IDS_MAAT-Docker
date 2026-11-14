"""Importar exclusiones no puede dejar el sensor sin ellas sin avisar (QA U-01, 2026-11-14).

Importar REEMPLAZA todas las exclusiones propias. Antes se hacía sin preguntar, y el servidor
guardaba la lista limpia aunque quedara vacía: un archivo equivocado dejaba el sensor sin
exclusiones («Importadas 0»), volvían los falsos positivos y, con ellos, las cuarentenas
automáticas de clientes legítimos. Ahora:
  - el servidor no cambia nada si el archivo no trae ninguna exclusión válida;
  - si descarta alguna, lo dice (y lo anota en la bitácora);
  - el navegador pide confirmar (modal rojo) con cuántas se borran y cuántas entran.
Datos RFC 5737.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixtures.panel2._dash_p import PanelP  # noqa: E402

ACTUALES = [{"tipo": "dst", "ip": "192.0.2.10", "motivo": "monitoreo", "puertos": [161],
             "sid": "", "hasta": 0, "nodo": "", "autor": "ana", "creado": 0},
            {"tipo": "src", "ip": "192.0.2.11", "motivo": "backup", "puertos": [],
             "sid": "", "hasta": 0, "nodo": "", "autor": "ana", "creado": 0}]


class ImportarExclusiones(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")
        self.d = self.p.d
        self.d.guardar_exclusiones([dict(r) for r in ACTUALES])

    def ips(self):
        return sorted(r["ip"] for r in self.d.cargar_exclusiones(incluir_vencidas=True)
                      if r.get("motivo") != "(conf)")

    def importar(self, data):
        txt = data if isinstance(data, str) else json.dumps(data)
        return self.p.pedir("POST", "/exclusiones", {"accion": "import", "json": txt}, cookie=self.ana)

    def test_sin_ninguna_valida_no_cambia_nada(self):
        """Corrección de defecto: un archivo sin ninguna exclusión válida no borra las actuales."""
        for data in ([], [{"ip": "no-es-ip"}, {"ip": "300.1.1.1"}], ["texto", 3]):
            r = self.importar(data)
            self.assertEqual(r.status, 200)
            self.assertIn("no se cambió nada", r.texto, data)
            self.assertEqual(self.ips(), ["192.0.2.10", "192.0.2.11"], data)

    def test_con_descartes_lo_dice(self):
        """Corrección de defecto: si descarta alguna, importa las válidas y dice cuántas descartó."""
        r = self.importar([{"ip": "198.51.100.7", "tipo": "src"}, {"ip": "mal"}])
        self.assertIn("Importadas 1 exclusiones", r.texto)
        self.assertIn("1 descartada(s)", r.texto)
        self.assertEqual(self.ips(), ["198.51.100.7"])

    def test_todas_validas_reemplaza(self):
        """Conservación: un archivo bueno reemplaza las actuales como siempre."""
        r = self.importar([{"ip": "203.0.113.5"}, {"ip": "203.0.113.6", "puertos": [53]}])
        self.assertIn("Importadas 2 exclusiones (reemplazaron las anteriores).", r.texto)
        self.assertNotIn("descartada", r.texto)
        self.assertEqual(self.ips(), ["203.0.113.5", "203.0.113.6"])

    def test_json_roto_no_cambia_nada(self):
        """Conservación: un JSON roto se rechaza sin tocar nada."""
        r = self.importar("{no es json")
        self.assertIn("no es JSON válido", r.texto)
        self.assertEqual(self.ips(), ["192.0.2.10", "192.0.2.11"])

    # ---- navegador -----------------------------------------------------------------------
    def pagina(self):
        h = self.p.pedir("GET", "/exclusiones", cookie=self.ana).texto
        self.assertIn('onsubmit="var m=excImportar(this);if(!m)return false;'
                      "return ask(this,'Reemplazar las exclusiones',m,'Reemplazar','danger')\"", h)
        self.assertIn('data-n="2"', h)      # las propias que borraría importar
        return h

    def test_el_formulario_pide_confirmar(self):
        """Capacidad nueva: importar pasa por excImportar, que confirma con el modal en rojo; sin
        archivo, vacío o no-lista avisa y no envía. Con node (si no hay, se salta)."""
        node = shutil.which("node")
        if not node:
            self.skipTest("sin node")
        h = self.pagina()
        m = re.search(r"function excImportar\(f\)\{.*?respaldo\.';\}", h, re.S)
        self.assertTrue(m, "no está excImportar")
        js = """
var llamadas = [], valor = '';
var document = {getElementById: function(){ return {value: valor}; }};
function aviso(t, x){ llamadas.push(['aviso', t]); }
var form = {getAttribute: function(){ return '2'; }};
%s
var res = {};
valor = '';           res.vacio = [excImportar(form), llamadas.pop()];
valor = '{"a":1}';    res.noLista = [excImportar(form), llamadas.pop()];
valor = '[]';         res.cero = [excImportar(form), llamadas.pop()];
valor = '[{"ip":"203.0.113.5"},{"ip":"203.0.113.6"},{"ip":"203.0.113.7"}]';
res.bueno = [excImportar(form), llamadas.pop() || null];
console.log(JSON.stringify(res));
""" % m.group(0)
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8",
                                         dir=os.environ.get("TMPDIR", "/tmp")) as f:
            f.write(js)
        self.addCleanup(os.unlink, f.name)
        r = subprocess.run([node, f.name], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        res = json.loads(r.stdout.strip().splitlines()[-1])
        self.assertEqual(res["vacio"], [False, ["aviso", "Falta el archivo"]])
        self.assertEqual(res["noLista"], [False, ["aviso", "Archivo no válido"]])
        self.assertEqual(res["cero"], [False, ["aviso", "Archivo vacío"]])
        texto, llamada = res["bueno"]
        self.assertIsNone(llamada)            # sin aviso: el onsubmit pasa el texto a ask(this,...,'danger')
        self.assertIn("Se borrarán las 2 exclusión(es) actuales", texto)
        self.assertIn("se cargarán las 3 del archivo", texto)


if __name__ == "__main__":
    unittest.main()
