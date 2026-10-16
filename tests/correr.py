"""Corre las pruebas unittest de tests/ y publica el resultado con cada omisión y su motivo.

  python tests/correr.py [--obligatorias linux|root] [--resumen FICHERO]

- Descubre `tests/test_*.py` y `tests/legado/test_*.py` (paquete `legado`).
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
import fnmatch
import os
import sys
import unittest

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


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--obligatorias", choices=PLATAFORMAS)
    p.add_argument("--resumen")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    if TESTS not in sys.path:
        sys.path.insert(0, TESTS)
    suite = unittest.defaultTestLoader.discover(TESTS, pattern="test_*.py", top_level_dir=TESTS)
    descubiertas = ids_de(suite)
    runner = unittest.TextTestRunner(verbosity=2 if a.verbose else 1, resultclass=Resultado)
    r = runner.run(suite)
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
