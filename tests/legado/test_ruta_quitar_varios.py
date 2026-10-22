# -*- coding: utf-8 -*-
"""/cuarentena/quitar-varios (respaldo sin JS) con dobles.

Adaptada al panel portado (CONTRATO-F2 §1, §3, §10.1): la identidad del CPE es SIEMPRE
`pid|ip` y el destino sale del pid de la propia clave (`_destino_ok`/`_router_de_pid` REALES,
con `nodos.py` real sobre un arbol temporal). Sin permiso la ruta responde con
`self._prohibido()` (403 por rol en el servidor, CONTRATO-F2 §10.2) en vez de `self._deny()`. Las
comprobaciones son las mismas, mas el subcaso del contrato «sin pid no hay destino».
"""
import ast, ipaddress, os, secrets, sys, tempfile, time, urllib, urllib.parse as _up, textwrap
import unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
CODIGO = open(os.path.join(_comun.artefactos(), "ruta_masivo.py"), encoding="utf-8").read()
TMP = tempfile.TemporaryDirectory()

# el aviso viaja como CODIGO de un solo uso (/cuarentena?msg=<codigo>): se usan las
# funciones reales del panel para guardarlo y para leerlo
_DASH = extraer.fuente("DASH")
AV = {"time": time, "secrets": secrets, "urllib": urllib}
for _n in extraer.arbol("DASH").body:
    _nom = getattr(_n, "name", None) or (getattr(_n.targets[0], "id", "")
                                         if isinstance(_n, ast.Assign) and _n.targets else "")
    if _nom in ("_REP_AVISOS", "_REP_AVISOS_TTL", "rep_aviso_guardar", "rep_aviso_tomar",
                "rep_aviso_url", "cuar_aviso_url"):
        exec(ast.get_source_segment(_DASH, _n), AV)

def correr(sels, operador=True, fallan=(), caido=False, estado=None, intentos=None,
           tras_quitar=None):
    estado = estado if estado is not None else {
        "cuar": {"p001|10.6.1.89": {}, "p001|10.6.2.82": {}, "p001|10.6.0.208": {}},
        "dns":  {"p001|198.51.100.5": {}}}
    class Self:
        def _operador(self): return operador
        # (adaptada, permisos 2026-10-22) el operador del doble tiene los de su plantilla
        def _puede(self, permiso): return operador
        def _deny(self): return ("DENY", 403)
        def _prohibido(self): return ("DENY", 403)   # CONTRATO-F2 §10.2: 403 por rol
        def _redirect(self, url): return ("REDIR", url)
    def remove(ip, lista=None, router=None):
        if intentos is not None: intentos.append(ip)
        if caido: return (False, "no hay conexion con el router")
        return (False, "el router rechazo") if ip in fallan else (True, "")
    def quitar(ips, path="cuar"):
        # simula que MIENTRAS se hablaba con el router, el hilo de fondo anoto un CPE nuevo
        if tras_quitar: tras_quitar()
        return [i for i in ips if estado[path].pop(i, None) is not None]
    nod, sec = _comun.panel(TMP.name)
    AV["nodos"] = nod          # rep_aviso_url mira el nodo del hilo (?nodo=)
    ns = {"self": Self(), "q": {"sel": sels}, "_up": _up, "ipaddress": ipaddress,
          "MK_SENT": "cuar", "MK_SENT_DNS": "dns",
          "cargar_mk": lambda: {"LIST_DNS": "lista-dns"},
          "cargar_enviados": lambda path="cuar": estado[path],
          "quitar_enviados": quitar,
          "mk_remove": remove, "mk_log": lambda *a: None,
          "ip_de": lambda k: k.split("|", 1)[1] if "|" in k else k,
          "rid_de": lambda k: k.split("|", 1)[0] if "|" in k else "",
          "nodos": nod,
          "cargar_routers": lambda: [{"id": p} for p in nod.pids()],
          "cargar_mk_de": lambda r: {"LIST_DNS": "lista-dns"},
          "_suf_nodo": lambda k: "",
          "CTX": type("C", (), {"user": "ana"})(),
          "cuar_aviso_url": AV.get("cuar_aviso_url")}
    _comun.piezas(ns, ("_router_de_pid", "_destino_ok"))
    exec(compile("def _f():\n" + textwrap.indent(CODIGO, "    "), "<r>", "exec"), ns)
    return ns["_f"](), estado

_LEIDOS = {}
def msg(r):
    """El texto que vera el usuario: la URL lleva un codigo y el panel lo traduce. El
    codigo es de un solo uso: se recuerda lo leido para poder mirarlo varias veces."""
    assert r[1].startswith("/cuarentena?msg="), r
    cod = _up.unquote(r[1].split("msg=", 1)[1])
    if cod not in _LEIDOS:
        _LEIDOS[cod] = AV["rep_aviso_tomar"](cod)[0]
    return _LEIDOS[cod]

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c: fallos += 1

def main():
    global fallos
    fallos = 0
    r, estado = correr(["cuar|p001|10.6.1.89", "dns|p001|198.51.100.5", "cuar|p001|10.6.2.82"])
    check("la URL del redirect no lleva el texto, solo un codigo",
          "entrada" not in _up.unquote(r[1]) and " " not in _up.unquote(r[1]), r[1])
    check("quita de ambas listas y lo resume", msg(r) == "3 entrada(s) quitada(s)", msg(r))
    check("cada una sale de SU registro",
          estado["cuar"] == {"p001|10.6.0.208": {}} and estado["dns"] == {}, estado)

    r, estado = correr(["cuar|p001|10.6.1.89", "cuar|p001|10.6.2.82"], fallan={"10.6.2.82"})
    check("informa cual fallo y por que", "10.6.2.82 (el router rechazo)" in msg(r), msg(r))
    check("la que fallo sigue en el registro", "p001|10.6.2.82" in estado["cuar"], estado["cuar"])

    # HALLAZGO: con el router caido no debe esperar el timeout de las 500
    intentos = []
    r, _ = correr(["cuar|p001|10.6.1.89", "cuar|p001|10.6.2.82", "cuar|p001|10.6.0.208"], caido=True,
                  intentos=intentos)
    check("router caido: corta en la primera y no intenta las demas", len(intentos) == 1, intentos)
    check("y lo dice claramente", "no responde" in msg(r), msg(r))

    # HALLAZGO: el tope de 500 no debe descartar en silencio
    r, _ = correr(["cuar|p001|10.6.1.89"] * 600)
    check("avisa cuantas quedaron fuera del tope", "Quedan 100 sin procesar" in msg(r), msg(r))

    # HALLAZGO: no dar por quitada una IP que no estaba en esa lista
    intentos = []
    r, estado = correr(["cuar|p001|198.51.100.5"], intentos=intentos)   # esa vive en la lista DNS
    check("no da falso exito por la lista equivocada",
          msg(r).startswith("0 entrada(s)") and "no está en esa lista" in msg(r), msg(r))
    check("ni siquiera llama al router", not intentos, intentos)

    # HALLAZGO: no pisar lo que otro hilo escribio mientras hablabamos con el router
    estado = {"cuar": {"p001|10.6.1.89": {}}, "dns": {}}
    def intruso():
        estado["cuar"]["p001|10.7.7.7"] = {"por": "politica-rapida"}   # el barrido rapido, a mitad
    r, estado = correr(["cuar|p001|10.6.1.89"], estado=estado, tras_quitar=intruso)
    check("conserva el CPE que el hilo de fondo anoto mientras tanto",
          "p001|10.7.7.7" in estado["cuar"] and "p001|10.6.1.89" not in estado["cuar"], estado["cuar"])

    r, _ = correr(["cuar|p001|10.6.1.89"], operador=False)
    check("sin permiso no hace nada", r == ("DENY", 403), r)
    r, estado = correr([])
    check("sin seleccion avisa y no toca nada", msg(r) == "No seleccionaste ninguna IP", msg(r))

    # CONTRATO-F2 §1/§10.1: sin pid (IP pelada) o con un punto que no existe no hay destino:
    # error por entrada, sin hablar con ningun router y sin tocar el registro
    intentos = []
    estado = {"cuar": {"10.6.1.89": {}, "p009|10.6.1.89": {}}, "dns": {}}
    r, estado = correr(["cuar|10.6.1.89", "cuar|p009|10.6.1.89"], estado=estado, intentos=intentos)
    check("sin destino inequivoco: 0 quitadas, 'destino no valido' y no se toca nada",
          msg(r).startswith("0 entrada(s)") and "destino no válido" in msg(r)
          and not intentos and len(estado["cuar"]) == 2, (msg(r), intentos, estado))

    print("\n" + ("TODO OK" if not fallos else f"{fallos} fallo(s)"))
    return 1 if fallos else 0


class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada a claves pid|ip (CONTRATO-F2 §1, §10.1) y 403 por rol (§10.2). /cuarentena/quitar-varios (respaldo sin JS) con dobles."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
