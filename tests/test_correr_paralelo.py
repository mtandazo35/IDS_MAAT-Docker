"""tests/correr.py reparte los módulos de prueba entre varios procesos (el user, 2026-10-16: la
suite tardaba 16 min en un solo núcleo de los 8 del VPS: «usa todos los 8 núcleos»).
Tipo: cambio de comportamiento pedido.

Con una suite de juguete en una carpeta temporal se comprueba que de verdad corre en más de un
proceso, que cada módulo entero va a un mismo proceso, que cuenta lo mismo que en serie (pasadas,
fallos, errores, omitidas, módulos que no importan u omitidos enteros) y que un proceso que muere
no se lleva por delante el resto de la corrida.
"""
import contextlib
import io
import os
import re
import shutil
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import correr  # noqa: E402

# cada prueba deja un fichero <marca>.<pid> en ZZPAR_DIR: así se ve en qué proceso corrió
ANOTAR = '''
import os, time, unittest
def anotar(marca, espera=0):
    time.sleep(espera)
    open(os.path.join(os.environ["ZZPAR_DIR"], "%s.%d" % (marca, os.getpid())), "w").close()
'''

JUGUETE = {
    # 4 pruebas en 2 clases: 2 pasan, 1 falla, 1 se omite. La espera hace que el otro módulo
    # lo coja otro proceso (el primero sigue ocupado con este).
    "test_zzpar_a.py": ANOTAR + '''
class A(unittest.TestCase):
    def test_1(self): anotar("a1", 1)
    def test_falla(self): anotar("af"); self.assertEqual(1, 2)
class A2(unittest.TestCase):
    def test_3(self): anotar("a3")
    @unittest.skip("omitida a proposito")
    def test_omitida(self): pass
''',
    "test_zzpar_b.py": ANOTAR + '''
class B(unittest.TestCase):
    def test_1(self): anotar("b1", 1)
    def test_error(self): anotar("be"); raise RuntimeError("error a proposito")
''',
    "test_zzpar_c.py": 'import unittest\nraise unittest.SkipTest("modulo omitido entero")\n',
    "test_zzpar_d.py": 'import zzpar_no_existe  # noqa: F401\n',
}

MUERE = {
    # en un proceso hijo se mata (como una señal o un os._exit dentro de una prueba); repetido en
    # serie, en el proceso padre, pasa
    "test_zzmuere_a.py": ANOTAR + '''
class M(unittest.TestCase):
    def test_muere(self):
        anotar("m")
        if os.getpid() != int(os.environ["ZZPAR_PADRE"]):
            os._exit(3)
''',
    "test_zzmuere_b.py": ANOTAR + '''
class N(unittest.TestCase):
    def test_1(self): anotar("n1")
    def test_2(self): anotar("n2")
''',
}


class Paralelo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="zzpar-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(self._limpiar_modulos)
        self.addCleanup(os.environ.pop, "ZZPAR_DIR", None)
        self.addCleanup(os.environ.pop, "ZZPAR_PADRE", None)
        os.environ["ZZPAR_PADRE"] = str(os.getpid())

    def _limpiar_modulos(self):
        for m in [m for m in sys.modules if m.startswith(("test_zzpar_", "test_zzmuere_"))]:
            del sys.modules[m]
        while self.raiz_en_path():
            sys.path.remove(self.raiz)

    def raiz_en_path(self):
        return getattr(self, "raiz", None) in sys.path

    def juguete(self, ficheros):
        self.raiz = os.path.join(self.tmp, "suite")
        os.makedirs(self.raiz)
        for nombre, codigo in ficheros.items():
            with open(os.path.join(self.raiz, nombre), "w", encoding="utf-8", newline="\n") as f:
                f.write(textwrap.dedent(codigo))

    def correr(self, procesos):
        """(código de salida, stdout+stderr, {marca: {pids}}) de correr.main sobre la suite de juguete
        (procesos=None: sin --procesos, el número por defecto)."""
        marcas = tempfile.mkdtemp(prefix="marcas-", dir=self.tmp)
        os.environ["ZZPAR_DIR"] = marcas
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            codigo = correr.main([] if procesos is None else ["--procesos", str(procesos)],
                                 raiz=self.raiz)
        pid = {}
        for f in os.listdir(marcas):
            marca, _, p = f.rpartition(".")
            pid.setdefault(marca, set()).add(int(p))
        return codigo, out.getvalue() + err.getvalue(), pid

    @staticmethod
    def cuentas(texto):
        """(«Ran N», línea OK/FAILED, nº de omitidas) tal como los imprime la corrida."""
        return (re.search(r"^Ran (\d+) tests?", texto, re.M).group(1),
                re.search(r"^(OK|FAILED).*$", texto, re.M).group(0),
                re.search(r"^== omitidas: (\d+)", texto, re.M).group(1))

    def test_en_paralelo_cuenta_lo_mismo_que_en_serie(self):
        self.juguete(JUGUETE)
        c1, serie, _ = self.correr(1)
        c3, paralelo, _ = self.correr(3)
        self.assertEqual((c1, c3), (1, 1))                        # hay un fallo y errores
        self.assertEqual(self.cuentas(serie), ("8", "FAILED (failures=1, errors=2, skipped=2)", "2"))
        self.assertEqual(self.cuentas(paralelo), self.cuentas(serie))
        for x in ("FAIL: test_falla", "ERROR: test_error", "zzpar_no_existe",
                  "OMITIDA test_zzpar_c.(modulo omitido): modulo omitido entero",
                  "OMITIDA test_zzpar_a.A2.test_omitida: omitida a proposito"):
            self.assertIn(x, paralelo)
        self.assertIn("(3 procesos)", paralelo)
        self.assertIn("== los 10 módulos más lentos (segundos)", paralelo)

    def test_varios_procesos_y_cada_modulo_entero_en_uno(self):
        self.juguete(JUGUETE)
        _c, _t, pid = self.correr(3)
        self.assertEqual(sorted(pid), ["a1", "a3", "af", "b1", "be"])
        a = pid["a1"] | pid["a3"] | pid["af"]
        b = pid["b1"] | pid["be"]
        self.assertEqual((len(a), len(b)), (1, 1))                 # un módulo, un proceso
        self.assertNotEqual(a, b)                                  # y de verdad en paralelo
        self.assertNotIn(os.getpid(), a | b)                       # en hijos, no en el padre

    def test_en_serie_corre_en_el_propio_proceso(self):
        self.juguete(JUGUETE)
        _c, texto, pid = self.correr(1)
        self.assertEqual(set().union(*pid.values()), {os.getpid()})
        self.assertNotIn("procesos)", texto)

    def test_un_proceso_que_muere_no_tumba_la_corrida(self):
        self.juguete(MUERE)
        codigo, texto, pid = self.correr(2)
        self.assertEqual(codigo, 1)                                # la corrida falla...
        self.assertIn("un proceso de pruebas murió", texto)
        self.assertIn("se repitieron en serie: test_zzmuere_a", texto)
        self.assertEqual(sorted(pid), ["m", "n1", "n2"])           # ...pero corre todo
        self.assertEqual(len(pid["m"]), 2)                         # murió en un hijo...
        self.assertIn(os.getpid(), pid["m"])                       # ...y se repitió aquí
        self.assertEqual(re.search(r"^Ran (\d+)", texto, re.M).group(1), "3")

    def test_por_defecto_los_nucleos_hasta_4(self):
        # medido en el .152 (2026-10-17): cada proceso acaba en ~600 MB; con 8 no cabe en el tope
        self.juguete(JUGUETE)
        for nucleos, procesos in ((16, 4), (2, 2)):
            with mock.patch.object(os, "cpu_count", return_value=nucleos):
                _c, texto, _pid = self.correr(None)
            self.assertIn("(%d procesos)" % procesos, texto)


if __name__ == "__main__":
    unittest.main()
