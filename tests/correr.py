"""Corre las pruebas unittest de tests/ y publica el resultado con cada omisión y su motivo.

  python tests/correr.py [--obligatorias linux|windows] [--resumen FICHERO]

- Descubre `tests/test_*.py` y `tests/legado/test_*.py` (paquete `legado`).
- Imprime al final: pasadas, fallos, errores y la lista de OMITIDAS con su motivo.
- `--obligatorias <plataforma>`: las pruebas que casan con `tests/obligatorias.txt` para esa
  plataforma tienen que ejecutarse; si alguna se omite, no cuenta como verificada y la corrida
  falla (sale con 1) diciendo cuál y por qué se omitió.
- `--resumen`: añade el resumen en Markdown a ese fichero (en GitHub Actions, $GITHUB_STEP_SUMMARY).

Sale con 0 solo si no hay fallos, ni errores, ni obligatorias omitidas.
"""

import argparse
import fnmatch
import os
import sys
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))


class Resultado(unittest.TextTestResult):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.pasadas = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.pasadas.append(test.id())


def leer_obligatorias(plataforma):
    """[(patrón, motivo)] de tests/obligatorias.txt para la plataforma pedida."""
    salida = []
    try:
        lineas = open(os.path.join(TESTS, "obligatorias.txt"), encoding="utf-8").read().splitlines()
    except OSError:
        return salida
    for linea in lineas:
        texto, _, motivo = linea.partition("#")
        partes = texto.split()
        if not partes:
            continue
        patron, plataformas = partes[0], (partes[1] if len(partes) > 1 else "todas").split(",")
        if "todas" in plataformas or plataforma in plataformas:
            salida.append((patron, motivo.strip()))
    return salida


def resumen_md(r, omitidas, obligatorias_omitidas):
    L = ["### Pruebas unittest", "",
         "| resultado | número |", "|---|---|",
         "| pasadas | %d |" % len(r.pasadas), "| fallos | %d |" % len(r.failures),
         "| errores | %d |" % len(r.errors), "| omitidas | %d |" % len(omitidas),
         "| obligatorias omitidas (NO verificadas) | %d |" % len(obligatorias_omitidas), ""]
    if obligatorias_omitidas:
        L += ["#### Obligatorias omitidas: no cuentan como verificadas", ""]
        L += ["- `%s`: %s" % (t, m) for t, m in obligatorias_omitidas] + [""]
    if omitidas:
        L += ["#### Omitidas y motivo", "", "| prueba | motivo |", "|---|---|"]
        L += ["| `%s` | %s |" % (t, m.replace("|", "\\|")) for t, m in omitidas] + [""]
    for titulo, lista in (("Fallos", r.failures), ("Errores", r.errors)):
        if lista:
            L += ["#### " + titulo, ""] + ["- `%s`" % t.id() for t, _ in lista] + [""]
    return "\n".join(L) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--obligatorias", choices=("linux", "windows"))
    p.add_argument("--resumen")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    if TESTS not in sys.path:
        sys.path.insert(0, TESTS)
    suite = unittest.defaultTestLoader.discover(TESTS, pattern="test_*.py", top_level_dir=TESTS)
    runner = unittest.TextTestRunner(verbosity=2 if a.verbose else 1, resultclass=Resultado)
    r = runner.run(suite)
    omitidas = sorted((t.id(), str(m)) for t, m in r.skipped)
    obligatorias_omitidas = []
    if a.obligatorias:
        patrones = leer_obligatorias(a.obligatorias)
        for tid, motivo in omitidas:
            for patron, por_que in patrones:
                if fnmatch.fnmatchcase(tid, patron):
                    obligatorias_omitidas.append((tid, "%s (obligatoria: %s)" % (motivo, por_que or patron)))
                    break
    print()
    print("== omitidas: %d" % len(omitidas))
    for tid, motivo in omitidas:
        print("   OMITIDA %s: %s" % (tid, motivo))
    if obligatorias_omitidas:
        print("== OBLIGATORIAS omitidas (no verificadas): %d" % len(obligatorias_omitidas))
        for tid, motivo in obligatorias_omitidas:
            print("   NO VERIFICADA %s: %s" % (tid, motivo))
    if a.resumen:
        try:
            with open(a.resumen, "a", encoding="utf-8") as f:
                f.write(resumen_md(r, omitidas, obligatorias_omitidas))
        except OSError as e:
            print("no se pudo escribir el resumen: %s" % e, file=sys.stderr)
    ok = r.wasSuccessful() and not obligatorias_omitidas
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
