"""Corre las pruebas unittest de tests/ y publica el resultado con cada omisión y su motivo.

  python tests/correr.py [--procesos N] [--obligatorias linux|root] [--resumen FICHERO]

- Descubre `tests/test_*.py` y `tests/legado/test_*.py` (paquete `legado`).
- `--procesos N`: reparte los MÓDULOS de prueba entre N procesos; por defecto, todos los núcleos (el
  user, 2026-10-16: la suite tardaba 16 min en un solo núcleo de los 8 del VPS). Un módulo entero va
  a un mismo proceso y sus pruebas corren en el orden de siempre, así que setUpClass y los TMP que
  algunos módulos de legado crean al importarse no se comparten entre procesos. Si un proceso muere,
  lo que quedaba se repite en serie y la corrida falla diciéndolo. `--procesos 1` = en serie.
- Imprime al final: pasadas, fallos, errores y la lista de OMITIDAS con su motivo.
- `--obligatorias <plataforma>`: las pruebas que casan con `tests/obligatorias.txt` para esa
  plataforma tienen que ejecutarse; si alguna se omite, no cuenta como verificada y la corrida
  falla (sale con 1) diciendo cuál y por qué se omitió. También falla (auditoría B-03):
    - si un MÓDULO obligatorio se omite entero al importarse (`raise unittest.SkipTest`: unittest
      lo llama `unittest.loader.ModuleSkipped.<módulo>`, que antes no casaba con ningún patrón);
    - si un patrón obligatorio no casa con NINGUNA prueba descubierta (fichero borrado o
      renombrado: lo obligatorio no puede desaparecer en silencio).
  Imprime cuántas pruebas se ejecutaron por patrón. `root` (como root, con --imagenes
  --integracion en la VPS) aplica los patrones de `todas`, `linux` y `root`.
- `--resumen`: añade el resumen en Markdown a ese fichero (en GitHub Actions, $GITHUB_STEP_SUMMARY).

Sale con 0 solo si no hay fallos, ni errores, ni obligatorias omitidas o sin prueba.
"""

import argparse
import concurrent.futures
import fnmatch
import io
import multiprocessing
import os
import sys
import time
import traceback
import unittest
import warnings

TESTS = os.path.dirname(os.path.abspath(__file__))
PLATAFORMAS = ("linux", "root")       # sin Windows desde 2026-10-15 (decisión del dueño)
# qué columnas de obligatorias.txt aplica cada plataforma («todas» siempre)
INCLUYE = {"linux": ("linux",), "root": ("linux", "root")}
MODULO_OMITIDO = "unittest.loader.ModuleSkipped."


class Resultado(unittest.TextTestResult):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.pasadas = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.pasadas.append(test.id())


class _Flujo(io.StringIO):
    """Lo que TextTestResult espera de su stream (write + writeln), en memoria: cada proceso
    devuelve los puntos de su módulo y el padre los imprime de una vez."""

    def writeln(self, arg=None):
        if arg:
            self.write(arg)
        self.write("\n")


class _Hecha:
    """Una prueba que ya corrió en otro proceso: los TestCase no viajan entre procesos, solo su id
    y su descripción (lo único que leen main() y resumen_md())."""

    def __init__(self, tid, desc=None):
        self._id, self._desc = tid, desc or tid

    def id(self):
        return self._id

    def __str__(self):
        return self._desc


class Total:
    """Las cuentas de todos los procesos, con los nombres que lee main() de un TestResult."""

    def __init__(self):
        self.pasadas, self.failures, self.errors, self.skipped = [], [], [], []
        self.unexpectedSuccesses, self.esperados, self.testsRun = [], 0, 0

    def sumar(self, d):
        self.testsRun += d["corridas"]
        self.pasadas += d["pasadas"]
        self.failures += [(_Hecha(i, desc), txt) for i, desc, txt in d["fallos"]]
        self.errors += [(_Hecha(i, desc), txt) for i, desc, txt in d["errores"]]
        self.skipped += [(_Hecha(i), m) for i, m in d["omitidas"]]
        self.esperados += d["esperados"]
        self.unexpectedSuccesses += [_Hecha(i) for i in d["inesperados"]]

    def wasSuccessful(self):
        return not (self.failures or self.errors or self.unexpectedSuccesses)


def modulos(suite):
    """[(nombre, TestSuite)]: las pruebas agrupadas por módulo, en el orden descubierto. Lo que
    unittest fabrica cuando un módulo no se puede importar o se omite entero (_FailedTest,
    ModuleSkipped, del módulo unittest.loader) va aparte, cada uno con su id."""
    grupos = {}

    def hojas(s):
        for t in s:
            if isinstance(t, unittest.TestSuite):
                yield from hojas(t)
            else:
                yield t
    for t in hojas(suite):
        mod = type(t).__module__
        grupos.setdefault(t.id() if mod.startswith("unittest.") else mod, []).append(t)
    return [(k, unittest.TestSuite(v)) for k, v in grupos.items()]


# [(nombre, TestSuite)] del reparto en curso. Se rellena ANTES de crear los procesos: con fork cada
# hijo la hereda tal cual y al hijo solo viaja el índice (las pruebas no se pueden mandar por pickle).
_MODULOS = []


def _correr_modulo(i, verbosidad=1):
    """Corre el módulo i en este proceso. Devuelve solo lo que se puede mandar al padre."""
    nombre, s = _MODULOS[i]
    flujo = _Flujo()
    r = Resultado(flujo, True, verbosidad)
    t0 = time.monotonic()
    with warnings.catch_warnings():
        if not sys.warnoptions:              # lo mismo que hace TextTestRunner
            warnings.simplefilter("default")
        r.startTestRun()
        try:
            s.run(r)
        finally:
            r.stopTestRun()
    return {"nombre": nombre, "seg": time.monotonic() - t0, "salida": flujo.getvalue(),
            "corridas": r.testsRun, "pasadas": r.pasadas,
            "fallos": [(t.id(), r.getDescription(t), txt) for t, txt in r.failures],
            "errores": [(t.id(), r.getDescription(t), txt) for t, txt in r.errors],
            "omitidas": [(t.id(), str(m)) for t, m in r.skipped],
            "esperados": len(r.expectedFailures),
            "inesperados": [t.id() for t in r.unexpectedSuccesses]}


def _anotar(total, tiempos, d, salida):
    total.sumar(d)
    tiempos.append((d["seg"], d["nombre"]))
    salida.write(d["salida"])
    salida.flush()


def correr_en_paralelo(suite, procesos, verbosidad=1, salida=None):
    """Reparte los módulos de `suite` entre `procesos` procesos (fork) y devuelve un Total.
    Imprime, como TextTestRunner y en su mismo canal (stderr), los puntos de cada módulo al
    acabar, las trazas de fallos y errores, «Ran N tests» y OK / FAILED (...); y además los 10
    módulos más lentos."""
    global _MODULOS
    salida = salida or sys.stderr
    previos, _MODULOS = _MODULOS, modulos(suite)
    try:
        # los grandes primero: si uno largo sale el último, los demás procesos esperan por él
        orden = sorted(range(len(_MODULOS)), key=lambda i: -_MODULOS[i][1].countTestCases())
        total, tiempos, rotos = Total(), [], []
        t0 = time.monotonic()
        ctx = multiprocessing.get_context("fork")
        with concurrent.futures.ProcessPoolExecutor(procesos, mp_context=ctx) as ex:
            futuros = {ex.submit(_correr_modulo, i, verbosidad): i for i in orden}
            for f in concurrent.futures.as_completed(futuros):
                i = futuros[f]
                try:
                    d = f.result()
                except concurrent.futures.process.BrokenProcessPool:
                    rotos.append(i)
                    continue
                except Exception:            # fallo del reparto (no de una prueba): cuenta como error
                    total.errors.append((_Hecha(_MODULOS[i][0]), traceback.format_exc()))
                    continue
                _anotar(total, tiempos, d, salida)
        if rotos:
            # Un proceso murió sin devolver nada (os._exit, una señal, sin memoria) y con él cae el
            # pool entero: lo que quedaba se corre aquí, en serie, para no perder resultados; y la
            # corrida falla igual, porque algo mató un proceso de pruebas.
            total.errors.append((_Hecha("correr.proceso_muerto", "un proceso de pruebas murió"),
                                 "Murió un proceso de pruebas; se repitieron en serie: %s"
                                 % ", ".join(sorted(_MODULOS[i][0] for i in rotos))))
            for i in sorted(rotos):
                _anotar(total, tiempos, _correr_modulo(i, verbosidad), salida)
        _informe(total, tiempos, time.monotonic() - t0, procesos, salida)
        return total
    finally:
        _MODULOS = previos


def _informe(total, tiempos, seg, procesos, salida):
    """Lo que imprime TextTestRunner al acabar, más los módulos más lentos."""
    w = salida.write
    w("\n")
    for tipo, lista in (("ERROR", total.errors), ("FAIL", total.failures)):
        for t, txt in lista:
            w("=" * 70 + "\n%s: %s\n" % (tipo, t) + "-" * 70 + "\n%s\n" % txt)
    w("-" * 70 + "\nRan %d test%s in %.3fs (%d procesos)\n\n"
      % (total.testsRun, "" if total.testsRun == 1 else "s", seg, procesos))
    info = (("failures", len(total.failures)), ("errors", len(total.errors)),
            ("skipped", len(total.skipped)), ("expected failures", total.esperados),
            ("unexpected successes", len(total.unexpectedSuccesses)))
    info = ", ".join("%s=%d" % (k, n) for k, n in info if n)
    w(("OK" if total.wasSuccessful() else "FAILED") + (" (%s)" % info if info else "") + "\n")
    w("== los 10 módulos más lentos (segundos)\n")
    for s, nombre in sorted(tiempos, reverse=True)[:10]:
        w("   %7.1f  %s\n" % (s, nombre))
    salida.flush()


def leer_obligatorias(plataforma, ruta=None):
    """[(patrón, motivo)] de tests/obligatorias.txt para la plataforma pedida."""
    salida = []
    try:
        with open(ruta or os.path.join(TESTS, "obligatorias.txt"), encoding="utf-8") as f:
            lineas = f.read().splitlines()
    except OSError:
        return salida
    aplica = INCLUYE.get(plataforma, (plataforma,))
    for linea in lineas:
        texto, _, motivo = linea.partition("#")
        partes = texto.split()
        if not partes:
            continue
        patron, plataformas = partes[0], (partes[1] if len(partes) > 1 else "todas").split(",")
        if "todas" in plataformas or any(p in plataformas for p in aplica):
            salida.append((patron, motivo.strip()))
    return salida


def normalizar(tid):
    """Id comparable con los patrones: un módulo omitido entero al importar se llama
    `unittest.loader.ModuleSkipped.<módulo>` y pasa a `<módulo>.(modulo omitido)`."""
    if tid.startswith(MODULO_OMITIDO):
        return tid[len(MODULO_OMITIDO):] + ".(modulo omitido)"
    return tid


def ids_de(suite):
    """Todos los ids de prueba de una suite (recursivo), normalizados."""
    out = []
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            out.extend(ids_de(t))
        else:
            out.append(normalizar(t.id()))
    return out


def comprobar_obligatorias(patrones, descubiertas, omitidas):
    """(obligatorias omitidas [(id, motivo)], patrones sin prueba [(patrón, motivo)], cuenta por
    patrón {patrón: ejecutadas}). `descubiertas`: ids normalizados; `omitidas`: [(id, motivo)]."""
    omit = {normalizar(t): m for t, m in omitidas}
    obligatorias_omitidas, sin_prueba, cuenta = [], [], {}
    for patron, por_que in patrones:
        casan = [t for t in descubiertas if fnmatch.fnmatchcase(t, patron)]
        if not casan:
            sin_prueba.append((patron, por_que))
        cuenta[patron] = len([t for t in casan if t not in omit])
    for tid, motivo in sorted(omit.items()):
        for patron, por_que in patrones:
            if fnmatch.fnmatchcase(tid, patron):
                obligatorias_omitidas.append((tid, "%s (obligatoria: %s)" % (motivo, por_que or patron)))
                break
    return obligatorias_omitidas, sin_prueba, cuenta


def resumen_md(r, omitidas, obligatorias_omitidas, sin_prueba=()):
    L = ["### Pruebas unittest", "",
         "| resultado | número |", "|---|---|",
         "| pasadas | %d |" % len(r.pasadas), "| fallos | %d |" % len(r.failures),
         "| errores | %d |" % len(r.errors), "| omitidas | %d |" % len(omitidas),
         "| obligatorias omitidas (NO verificadas) | %d |" % len(obligatorias_omitidas),
         "| patrones obligatorios sin ninguna prueba | %d |" % len(sin_prueba), ""]
    if obligatorias_omitidas:
        L += ["#### Obligatorias omitidas: no cuentan como verificadas", ""]
        L += ["- `%s`: %s" % (t, m) for t, m in obligatorias_omitidas] + [""]
    if sin_prueba:
        L += ["#### Patrones obligatorios que no casan con ninguna prueba", ""]
        L += ["- `%s`: %s" % (p, m) for p, m in sin_prueba] + [""]
    if omitidas:
        L += ["#### Omitidas y motivo", "", "| prueba | motivo |", "|---|---|"]
        L += ["| `%s` | %s |" % (t, m.replace("|", "\\|")) for t, m in omitidas] + [""]
    for titulo, lista in (("Fallos", r.failures), ("Errores", r.errors)):
        if lista:
            L += ["#### " + titulo, ""] + ["- `%s`" % t.id() for t, _ in lista] + [""]
    return "\n".join(L) + "\n"


def main(argv=None, raiz=TESTS):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--obligatorias", choices=PLATAFORMAS)
    p.add_argument("--resumen")
    p.add_argument("--procesos", type=int, default=os.cpu_count() or 1,
                   help="procesos en paralelo (por defecto, todos los núcleos; 1 = en serie)")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    if raiz not in sys.path:
        sys.path.insert(0, raiz)
    suite = unittest.TestLoader().discover(raiz, pattern="test_*.py", top_level_dir=raiz)
    descubiertas = ids_de(suite)
    verbosidad = 2 if a.verbose else 1
    if a.procesos > 1 and "fork" in multiprocessing.get_all_start_methods():
        r = correr_en_paralelo(suite, a.procesos, verbosidad)
    else:
        r = unittest.TextTestRunner(verbosity=verbosidad, resultclass=Resultado).run(suite)
    omitidas = sorted((normalizar(t.id()), str(m)) for t, m in r.skipped)
    obligatorias_omitidas, sin_prueba, cuenta = [], [], {}
    if a.obligatorias:
        obligatorias_omitidas, sin_prueba, cuenta = comprobar_obligatorias(
            leer_obligatorias(a.obligatorias), descubiertas, omitidas)
    print()
    print("== omitidas: %d" % len(omitidas))
    for tid, motivo in omitidas:
        print("   OMITIDA %s: %s" % (tid, motivo))
    if a.obligatorias:
        print("== obligatorias (%s): pruebas ejecutadas por patrón" % a.obligatorias)
        for patron, n in cuenta.items():
            print("   %5d  %s" % (n, patron))
    if obligatorias_omitidas:
        print("== OBLIGATORIAS omitidas (no verificadas): %d" % len(obligatorias_omitidas))
        for tid, motivo in obligatorias_omitidas:
            print("   NO VERIFICADA %s: %s" % (tid, motivo))
    if sin_prueba:
        print("== patrones OBLIGATORIOS sin ninguna prueba: %d" % len(sin_prueba))
        for patron, motivo in sin_prueba:
            print("   SIN PRUEBA %s: %s" % (patron, motivo))
    if a.resumen:
        try:
            with open(a.resumen, "a", encoding="utf-8") as f:
                f.write(resumen_md(r, omitidas, obligatorias_omitidas, sin_prueba))
        except OSError as e:
            print("no se pudo escribir el resumen: %s" % e, file=sys.stderr)
    ok = r.wasSuccessful() and not obligatorias_omitidas and not sin_prueba
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
