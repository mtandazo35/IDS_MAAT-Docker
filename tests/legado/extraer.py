#!/usr/bin/env python3
"""Saca de los ficheros del panel las piezas que se pueden probar sueltas.

Adaptacion del `tests/extraer.py` de suricata-ids-lab. Alli todo el proyecto era un unico
script con programas en Python y JavaScript metidos en heredocs; aqui esos heredocs son ya
ficheros reales en images/panel/rootfs/usr/local/lib/ids-panel/, asi que se leen directamente.
Las firmas son las del original para que las pruebas cambien lo minimo:

  heredoc(src, nombre)   el codigo de un programa (src se ignora; nombre = el binario viejo
                         "suricata-dashboard", el marcador "DASH" o el fichero nuevo)
  literal / asignacion / funcion / cuerpo_ruta   igual que antes

y deja en un directorio los mismos artefactos:

  sort.js         ordenamiento de tablas (_SORT_JS)
  pos.js          posicion de la pagina al recargar (_POS_JS)
  ask.js          modal de confirmacion y aviso (_ASK)
  masivo.js       script de la pagina de Cuarentena (seleccion y quitado masivo)
  mapa.js         mapa del reporte (mapa_ataques_section)
  ruta_uno.py     cuerpo de la ruta /cuarentena/quitar-uno
  ruta_masivo.py  cuerpo de la ruta /cuarentena/quitar-varios

Uso:  python tests/legado/extraer.py <directorio_destino>
"""
import ast
import os
import re
import sys
import textwrap

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LIB = os.path.join(RAIZ, "images", "panel", "rootfs", "usr", "local", "lib", "ids-panel")
SHARE = os.path.join(RAIZ, "images", "panel", "rootfs", "usr", "local", "share", "ids-panel")
MAPA = os.path.join(SHARE, "mapa")
DATOS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "datos")

# binario viejo / marcador del heredoc -> fichero nuevo
FICHEROS = {
    "suricata-dashboard": "dashboard.py", "DASH": "dashboard.py",
    "suricata-html-report": "html_report.py", "HREP": "html_report.py",
    "suricata-feeds-update": "feeds_update.py", "FEEDS": "feeds_update.py",
    "suricata-mikrotik-init": "mikrotik_init.py", "MKINIT": "mikrotik_init.py",
    "suricata-report": "informe_diario.py", "REP": "informe_diario.py",
}


def ruta(nombre):
    """Ruta del fichero del panel que sustituye al heredoc `nombre`."""
    return os.path.join(LIB, FICHEROS.get(nombre, nombre))


def fuente(nombre):
    """Texto del programa `nombre` (binario viejo, marcador del heredoc o fichero nuevo)."""
    with open(ruta(nombre), encoding="utf-8") as f:
        return f.read()


def heredoc(src, nombre):
    """Compatibilidad con el extraer.py viejo: devuelve el codigo de /usr/local/bin/<nombre>,
    que ahora es un fichero del panel. `src` (el instalador) ya no existe y se ignora."""
    return fuente(nombre)


def literal(nodo, sustituciones=None):
    """Evalua una concatenacion de literales de texto. Lo que no sea literal (datos
    embebidos con json.dumps, tablas) se sustituye por un marcador: a las pruebas les
    interesa el codigo, no los datos."""
    sustituciones = sustituciones or {}
    if isinstance(nodo, ast.Constant) and isinstance(nodo.value, str):
        return nodo.value
    if isinstance(nodo, ast.BinOp) and isinstance(nodo.op, ast.Add):
        return literal(nodo.left, sustituciones) + literal(nodo.right, sustituciones)
    if isinstance(nodo, ast.Name):
        return sustituciones.get(nodo.id, "")
    if isinstance(nodo, ast.Call) and getattr(nodo.func, "id", "") == "str":
        return "0"
    if isinstance(nodo, ast.IfExp):
        # trozo opcional (p. ej. el `&nodo=` del selector, que solo se pone con un nodo
        # elegido): se toma la rama del `else`, la de la pagina sin ese anadido. Un marcador
        # "{}" en medio de una expresion JS la rompia (SyntaxError en node).
        return literal(nodo.orelse, sustituciones)
    return "{}"


def asignacion(arbol, nombre):
    for n in ast.walk(arbol):
        if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == nombre for t in n.targets):
            return n
    raise LookupError("no se encontro la variable %s" % nombre)


def funcion(arbol, nombre):
    for n in ast.walk(arbol):
        if isinstance(n, ast.FunctionDef) and n.name == nombre:
            return n
    raise LookupError("no se encontro la funcion %s" % nombre)


def cuerpo_ruta(fuente_, arbol, ruta_):
    """Devuelve el cuerpo del `if ruta == "<ruta>":` sin indentar, para ejecutarlo suelto."""
    for n in ast.walk(arbol):
        if (isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
                and getattr(n.test.left, "id", "") == "ruta" and n.test.comparators
                and getattr(n.test.comparators[0], "value", "") == ruta_):
            lineas = fuente_.split("\n")[n.body[0].lineno - 1:n.body[-1].end_lineno]
            return textwrap.dedent("\n".join(lineas))
    raise LookupError("no se encontro la ruta %s" % ruta_)


def extraer(destino):
    """Escribe los artefactos en `destino` y devuelve la lista de lo escrito."""
    os.makedirs(destino, exist_ok=True)
    dash = fuente("DASH")
    arbol = ast.parse(dash)
    escritos = []

    def escribir(nombre, texto):
        with open(os.path.join(destino, nombre), "w", encoding="utf-8") as f:
            f.write(texto)
        escritos.append("%s (%d bytes)" % (nombre, len(texto)))

    for var, archivo in (("_SORT_JS", "sort.js"), ("_POS_JS", "pos.js")):
        js = literal(asignacion(arbol, var).value)
        escribir(archivo, js.replace("<script>", "").replace("</script>", ""))

    # el modal de confirmacion: aqui sale solo el JS; el markup lo comprueba aparte
    ask = literal(asignacion(arbol, "_ASK").value)
    escribir("ask.js", re.findall(r"<script>(.*?)</script>", ask, re.S)[0])

    pag = funcion(arbol, "cuarentena_page")
    cuerpo = [x for x in ast.walk(pag) if isinstance(x, ast.Assign)
              and any(getattr(t, "id", "") == "body" for t in x.targets)][-1]
    scripts = re.findall(r"<script>(.*?)</script>", literal(cuerpo.value), re.S)
    escribir("masivo.js", scripts[0])

    for r, archivo in (("/cuarentena/quitar-uno", "ruta_uno.py"),
                       ("/cuarentena/quitar-varios", "ruta_masivo.py")):
        escribir(archivo, cuerpo_ruta(dash, arbol, r))

    rep = ast.parse(fuente("HREP"))
    fn = funcion(rep, "mapa_ataques_section")
    ret = [n for n in ast.walk(fn) if isinstance(n, ast.Return)][-1]
    # tablas de paises reducidas: las pruebas solo necesitan unos pocos
    html = literal(ret.value, {"_MAP_NUM2ISO": "{840:'US',528:'NL',466:'ML'}",
                               "_MAP_NAMES": "{US:'Estados Unidos',NL:'Paises Bajos'}"})
    js = [s for s in re.findall(r"<script>(.*?)</script>", html, re.S) if "(function(){" in s]
    if not js:
        raise LookupError("no se encontro el script del mapa")
    escribir("mapa.js", js[0])
    return escritos


def main():
    destino = sys.argv[1] if len(sys.argv) > 1 else "."
    try:
        escritos = extraer(destino)
    except LookupError as e:
        raise SystemExit(str(e))
    print("extraidos en %s:" % destino)
    for e in escritos:
        print("  " + e)


if __name__ == "__main__":
    main()
