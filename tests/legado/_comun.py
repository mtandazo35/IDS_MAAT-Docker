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
    """Ejecuta el main() de una prueba heredada y falla con sus lineas FALLA.

    Al acabar (tambien con excepcion) deja el entorno como estaba si la prueba uso
    `panel()`: la clave maestra temporal y el nodo del hilo no pasan a la siguiente."""
    out = io.StringIO()
    rc = None
    try:
        with contextlib.redirect_stdout(out):
            try:
                rc = main(*args)
            except SystemExit as e:
                rc = e.code
    finally:
        restaurar_panel()
    _veredicto(caso, out.getvalue(), rc)


# Dos puntos de prueba (CONTRATO-F2 §1: un punto = un router del multi-nodo viejo, id = pid).
# Redes de abonados 10.x; nada real.
PUNTOS = {"p001": {"nombre": "MikroTik", "redes": ["10.0.0.0/8", "100.64.0.0/10"],
                   "api_puerto": 8729, "sensor": "100.64.1.1", "mk": "100.64.1.2",
                   "tzsp_puerto": 37008},
          "p002": {"nombre": "Sucursal", "redes": ["10.0.0.0/8"],
                   "api_puerto": 8729, "sensor": "100.64.2.1", "mk": "100.64.2.2",
                   "tzsp_puerto": 37008}}

_PANEL_ENV = {}
_PANEL_MOD = []


def panel(raiz, puntos=None, nodo=None):
    """`nodos` y `secretos` REALES del panel portado sobre un arbol temporal `raiz`:
    panel/, datos/, run/estado.json con `puntos` (por defecto PUNTOS) y una clave maestra
    de prueba en raiz/secretos/master_key (IDS_MASTER_KEY queda apuntando ahi hasta que
    `correr_main` llama a `restaurar_panel()`). Con `nodo`, se pone como nodo del hilo
    (nodos.poner_nodo). Devuelve (nodos, secretos), para meterlos en el espacio de nombres
    de lo que se extrae del dashboard: `ns["nodos"], ns["secretos"] = _comun.panel(tmp)`."""
    import importlib
    nod = cargar_nodos(raiz, PUNTOS if puntos is None else puntos)
    clave = os.path.join(raiz, "secretos", "master_key")
    os.makedirs(os.path.dirname(clave), exist_ok=True)
    with open(clave, "w", encoding="ascii") as f:
        f.write("5a" * 32 + "\n")
    if "IDS_MASTER_KEY" not in _PANEL_ENV:
        _PANEL_ENV["IDS_MASTER_KEY"] = os.environ.get("IDS_MASTER_KEY")
    os.environ["IDS_MASTER_KEY"] = clave
    import secretos
    sec = importlib.reload(secretos)
    nod.quitar_nodo()
    if nodo is not None:
        nod.poner_nodo(nodo)
    _PANEL_MOD[:] = [nod]
    return nod, sec


def piezas(ns, nombres, fichero="DASH"):
    """Ejecuta en `ns` las definiciones de nivel de modulo (funciones, clases y asignaciones)
    de `fichero` cuyo nombre esta en `nombres`: el codigo REAL del panel portado, no una
    copia. Devuelve `ns`."""
    import ast
    src = extraer.fuente(fichero)
    for n in ast.parse(src).body:
        nombre = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nombre in nombres:
            exec(ast.get_source_segment(src, n) or "", ns)
    return ns


def restaurar_panel():
    """Quita el nodo del hilo y devuelve IDS_MASTER_KEY a su valor de antes de `panel()`."""
    for nod in _PANEL_MOD:
        try:
            nod.quitar_nodo()
        except Exception:
            pass
    del _PANEL_MOD[:]
    for k, v in _PANEL_ENV.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    _PANEL_ENV.clear()


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
