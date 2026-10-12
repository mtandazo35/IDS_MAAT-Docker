# -*- coding: utf-8 -*-
"""Lo comun de las pruebas heredadas de suricata-ids-lab (tests/legado/).

Las pruebas viejas eran guiones: cada `check()` imprimia "OK"/"FALLA" y al final
"TODO OK" o "N fallo(s)" con el codigo de salida. Aqui se conservan tal cual (su logica
no cambia) y unittest las lanza con `correr_main`, que convierte cualquier FALLA en un
fallo de la prueba con las lineas que fallaron. Las de navegador (.js) se lanzan con node
(`correr_node`) y se omiten, con el motivo, si node no esta instalado.
"""
import atexit
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
if AQUI not in sys.path:
    sys.path.insert(0, AQUI)

import extraer  # noqa: E402

_ARTEFACTOS = []


def artefactos():
    """Directorio (temporal, uno por proceso) con lo que deja extraer.extraer()."""
    if not _ARTEFACTOS:
        d = tempfile.mkdtemp(prefix="legado-")
        atexit.register(shutil.rmtree, d, True)
        extraer.extraer(d)
        _ARTEFACTOS.append(d)
    return _ARTEFACTOS[0]


def _veredicto(caso, salida, rc):
    fallas = [l for l in salida.splitlines() if "FALLA" in l]
    if rc not in (0, None) or "TODO OK" not in salida:
        caso.fail("la prueba heredada fallo (rc=%r):\n%s" % (
            rc, "\n".join(fallas[:40]) or salida[-3000:]))


def correr_main(caso, main, *args):
    """Ejecuta el main() de una prueba heredada y falla con sus lineas FALLA."""
    out = io.StringIO()
    rc = None
    with contextlib.redirect_stdout(out):
        try:
            rc = main(*args)
        except SystemExit as e:
            rc = e.code
    _veredicto(caso, out.getvalue(), rc)


def cargar_nodos(raiz, puntos=None):
    """nodos.py con sus raices bajo `raiz` (panel/, datos/, run/) y, si se da, un
    run/estado.json con esos puntos ({pid: {nombre, redes...}}). Devuelve el modulo recargado."""
    import importlib
    import json
    nuevas = {"IDS_PANEL_DIR": os.path.join(raiz, "panel"),
              "IDS_DATOS": os.path.join(raiz, "datos"),
              "IDS_RUN": os.path.join(raiz, "run")}
    for d in ("panel", "datos", "run"):
        os.makedirs(os.path.join(raiz, d), exist_ok=True)
    if puntos is not None:
        with open(os.path.join(raiz, "run", "estado.json"), "w", encoding="utf-8") as f:
            json.dump({"puntos": puntos}, f)
    if extraer.LIB not in sys.path:
        sys.path.insert(0, extraer.LIB)
    # nodos.py lee el entorno al cargarse: se pone, se recarga y se deja el entorno como
    # estaba, para no cambiarle las raices a otras pruebas del mismo proceso
    antes = {k: os.environ.get(k) for k in nuevas}
    os.environ.update(nuevas)
    try:
        import nodos
        return importlib.reload(nodos)
    finally:
        for k, v in antes.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def node():
    return shutil.which("node")


def correr_node(caso, script, artefacto):
    """Lanza `node <script> <artefacto>`; se omite si no hay node."""
    exe = node()
    if not exe:
        caso.skipTest("node no disponible")
    p = subprocess.run([exe, os.path.join(AQUI, script), os.path.join(artefactos(), artefacto)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=120)
    _veredicto(caso, p.stdout + p.stderr, p.returncode)
