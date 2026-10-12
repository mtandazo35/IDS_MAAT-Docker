# -*- coding: utf-8 -*-
"""/cuarentena/quitar-uno con dobles (sin MikroTik ni disco).

Adaptada al panel portado (CONTRATO-F2 §1, §3, §10.1): la identidad del CPE es SIEMPRE
`pid|ip` y el destino sale del pid de la propia clave (`_destino_ok`/`_router_de_pid` REALES,
con `nodos.py` real sobre un arbol temporal); los routers r2/r3 del multi-nodo viejo son los
puntos p001/p002. Las comprobaciones son las mismas.
"""
import ipaddress, os, sys, tempfile, textwrap
import unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
CODIGO = open(os.path.join(_comun.artefactos(), "ruta_uno.py"), encoding="utf-8").read()
TMP = tempfile.TemporaryDirectory()

def correr(sel, operador=True, fallan=(), estado=None, logs=None, hablado=None):
    estado = estado if estado is not None else {"cuar": {"p001|10.6.1.89": {}}, "dns": {"p001|10.6.0.144": {}}}
    resp = {}
    hablado = hablado if hablado is not None else []
    class Self:
        def _operador(self): return operador
        def _json(self, obj, code=200):
            resp.update(obj); resp["_code"] = code; return obj
    def _remove(ip, lista=None, router=None):
        hablado.append((ip, (router or {}).get("id", ""), lista))
        return (False, "sin respuesta del router") if ip in fallan else (True, "")
    nod, sec = _comun.panel(TMP.name)

    def quitar(ips, path="cuar"):
        hechas = [i for i in ips if estado[path].pop(i, None) is not None]
        return hechas
    ns = {"self": Self(), "q": {"sel": [sel]}, "ipaddress": ipaddress,
          "MK_SENT": "cuar", "MK_SENT_DNS": "dns",
          "cargar_mk": lambda: {"LIST_DNS": "lista-dns"},
          "cargar_enviados": lambda path="cuar": estado[path],
          "quitar_enviados": quitar,
          "mk_remove": _remove,
          "ip_de": lambda k: k.split("|", 1)[1] if "|" in k else k,
          "rid_de": lambda k: k.split("|", 1)[0] if "|" in k else "",
          "nodos": nod,
          "cargar_routers": lambda: [{"id": p} for p in nod.pids()],
          "cargar_mk_de": lambda r: {"LIST_DNS": "lista-dns-" + r.get("id", "")},
          "_suf_nodo": lambda k: (" nodo=" + k.split("|", 1)[0]) if "|" in k else "",
          "mk_log": (lambda *a: logs.append(a)) if logs is not None else (lambda *a: None),
          "CTX": type("C", (), {"user": "ana"})()}
    _comun.piezas(ns, ("_router_de_pid", "_destino_ok"))
    exec(compile("def _f():\n" + textwrap.indent(CODIGO, "    "), "<r>", "exec"), ns)
    return ns["_f"](), resp, estado

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c: fallos += 1

def main():
    global fallos
    fallos = 0
    _, resp, estado = correr("cuar|p001|10.6.1.89")
    check("quita y responde ok", resp.get("ok") is True and "p001|10.6.1.89" not in estado["cuar"], (resp, estado))

    _, resp, estado = correr("dns|p001|10.6.0.144")
    check("una de DNS sale de SU registro", resp["ok"] and "p001|10.6.0.144" not in estado["dns"], (resp, estado))

    logs = []
    _, resp, estado = correr("cuar|p001|10.6.1.89", fallan={"10.6.1.89"}, logs=logs)
    check("router caido: ok=false con el motivo", resp["ok"] is False and "sin respuesta" in resp["err"], resp)
    check("la IP SIGUE en el registro para reintentar", "p001|10.6.1.89" in estado["cuar"], estado["cuar"])
    check("queda registrado como error", any("ERROR-QUITAR" in str(l) for l in logs), logs)

    _, resp, _ = correr("cuar|p001|no-es-ip")
    check("IP manipulada: error claro", resp["ok"] is False and resp["err"] == "IP invalida", resp)

    # HALLAZGO de la auditoria: pedir una IP por la lista equivocada daba un visto bueno falso
    logs = []
    _, resp, estado = correr("cuar|p001|10.6.0.144", logs=logs)   # esa IP vive en la lista DNS
    check("pedirla por la lista equivocada NO da falso exito",
          resp["ok"] is False and "no esta en esa lista" in resp["err"], resp)
    check("y no se toca el router ni el registro",
          "p001|10.6.0.144" in estado["dns"] and not logs, (estado, logs))

    # --- multi-nodo: el bloqueo debe salir al router de ESE CPE ---
    hablado = []
    estado = {"cuar": {"p001|10.0.0.5": {}, "p002|10.0.0.5": {}}, "dns": {}}
    _, resp, estado = correr("cuar|p001|10.0.0.5", estado=estado, hablado=hablado)
    check("la misma IP en otro nodo: se libera la del nodo pedido",
          resp["ok"] and "p001|10.0.0.5" not in estado["cuar"], (resp, estado))
    check("y NO se toca la del otro nodo", "p002|10.0.0.5" in estado["cuar"], estado["cuar"])
    check("se le hablo al router correcto", hablado and hablado[0][1] == "p001", hablado)

    _, resp, estado = correr("cuar|p001|10.6.1.89", operador=False)
    check("sin permiso: 403 y sin tocar nada", resp.get("_code") == 403 and "p001|10.6.1.89" in estado["cuar"], resp)

    # CONTRATO-F2 §1/§10.1: sin pid (IP pelada) o con un punto que no existe no hay destino
    hablado = []
    estado = {"cuar": {"10.6.1.89": {}, "p009|10.6.1.89": {}}, "dns": {}}
    for sel in ("cuar|10.6.1.89", "cuar|p009|10.6.1.89"):
        _, resp, estado = correr(sel, estado=estado, hablado=hablado)
        check("sin destino inequivoco (%s): 400 y no se toca nada" % sel,
              resp.get("_code") == 400 and resp["ok"] is False and not hablado
              and len(estado["cuar"]) == 2, (resp, hablado, estado))

    print("\n" + ("TODO OK" if not fallos else f"{fallos} fallo(s)"))
    return 1 if fallos else 0


class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada a claves pid|ip (CONTRATO-F2 §1, §10.1). /cuarentena/quitar-uno con dobles (sin MikroTik ni disco)."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
