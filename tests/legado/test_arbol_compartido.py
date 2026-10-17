# -*- coding: utf-8 -*-
"""Un solo arbol ast por fichero del panel, compartido por todas las pruebas (extraer.arbol).

Tipo: correccion de defecto (memoria de la suite). Cada modulo de legado guardaba su propio
`ARBOL = ast.parse(DASH)`: 46 arboles de dashboard.py (40-80 MB cada uno) al descubrir la
suite, ~1,85 GB en el proceso padre. Con el corredor en paralelo cada proceso acababa con su
copia: el 2026-10-16 agoto la memoria del VPS de produccion y el kernel mato a Suricata; el
2026-10-17, ya con el tope del cgroup, el tope mato la corrida.
"""
import ast
import os
import subprocess
import sys
import textwrap
import unittest

try:
    import resource
except ImportError:                          # sin Linux no hay ru_maxrss: no se mide la memoria
    resource = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extraer  # noqa: E402

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOPE_DESCUBRIR_MB = 800     # con un arbol por modulo eran ~1.850


def _llama_ast_parse(nodo):
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
               and n.func.attr == "parse" and getattr(n.func.value, "id", "") == "ast"
               for n in ast.walk(nodo))


class ArbolCompartido(unittest.TestCase):
    def test_un_arbol_por_fichero(self):
        # el marcador viejo y el fichero nuevo son el mismo fichero: el mismo objeto
        self.assertIs(extraer.arbol("DASH"), extraer.arbol("suricata-dashboard"))
        self.assertIs(extraer.arbol("HREP"), extraer.arbol("html_report.py"))
        self.assertIsNot(extraer.arbol("DASH"), extraer.arbol("HREP"))

    def test_es_el_arbol_de_su_fuente(self):
        # las pruebas sacan el codigo con get_source_segment(fuente, nodo): tiene que casar
        src = extraer.fuente("DASH")
        arbol = extraer.arbol("DASH")
        self.assertIsInstance(arbol, ast.Module)
        defs = [n for n in arbol.body if isinstance(n, ast.FunctionDef)]
        self.assertGreater(len(defs), 100)
        for f in (defs[0], defs[len(defs) // 2], defs[-1]):
            self.assertTrue(ast.get_source_segment(src, f).startswith("def %s(" % f.name), f.name)

    def test_descubrir_la_suite_no_dispara_la_memoria(self):
        # lo que hace correr.py antes de repartir: importar TODOS los modulos de prueba
        codigo = textwrap.dedent("""
            import resource, sys, unittest
            t = sys.argv[1]
            sys.path.insert(0, t)
            n = unittest.TestLoader().discover(t, pattern="test_*.py", top_level_dir=t).countTestCases()
            print(n, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024)
        """)
        if resource is None:
            self.skipTest("sin el modulo resource (no es Linux) no se mide la memoria")
        r = subprocess.run([sys.executable, "-c", codigo, TESTS], capture_output=True, text=True,
                           timeout=600)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        pruebas, mb = (int(x) for x in r.stdout.split()[-2:])
        self.assertGreater(pruebas, 1000)
        self.assertLess(mb, TOPE_DESCUBRIR_MB,
                        "descubrir %d pruebas pide %d MB: ¿algun modulo vuelve a guardar su "
                        "propio arbol? usar extraer.arbol()" % (pruebas, mb))

    def test_ningun_modulo_parsea_al_importarse(self):
        # `ARBOL = ast.parse(DASH)` (o un for sobre ast.parse) a nivel de modulo es un arbol mas
        # por modulo al descubrir la suite; dentro de una funcion se libera al acabar
        mal = []
        for d in (TESTS, os.path.join(TESTS, "legado")):
            for f in sorted(os.listdir(d)):
                if not (f.startswith("test_") and f.endswith(".py")):
                    continue
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    cuerpo = ast.parse(fh.read()).body
                mal += ["%s:%d" % (f, n.lineno) for n in cuerpo
                        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                        and _llama_ast_parse(n)]
        self.assertEqual(mal, [], "usar extraer.arbol(nombre) en vez de ast.parse")


if __name__ == "__main__":
    unittest.main()
