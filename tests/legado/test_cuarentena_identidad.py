# -*- coding: utf-8 -*-
"""Enviar y quitar de cuarentena respetando la identidad (router, IP).

El registro de enviados, los candidatos del reporte y el Top usan la IDENTIDAD del
CPE, que con varios MikroTik es "router|IP". Las rutas de ENVIO guardaban en cambio la
IP pelada, asi que:

  - el Top y la pestana Cuarentena mostraban "sin enviar" un CPE ya bloqueado
    (la marca se busca por identidad y estaba guardada por IP);
  - el bloqueo salia siempre hacia el router por defecto, no hacia el del abonado;
  - y al querer liberarlo, "router|IP" se rechazaba como "IP invalida".

Este archivo ejecuta las rutas reales contra un MikroTik de mentira.

Adaptada al panel portado (CONTRATO-F2 §1, §3, §4, §10.1, §10.3):
  - los routers r1/r2 del multi-nodo viejo son los puntos p001/p002 (`cargar_routers()` sale
    de `nodos.puntos()`, §4) y lo del usuario se guarda con `guardar_routers()` REAL, con la
    clave cifrada (§10.3);
  - la identidad es SIEMPRE `pid|ip`, tambien con un solo punto (§1): el subcaso «con un
    solo nodo la clave sigue siendo la IP pelada» pasa a `p001|ip`, y se anade que la IP
    pelada ya no tiene destino (§10.1, sin `router_defecto`, §3);
  - `cuarentena.json` es por nodo, en `nodos.dir_salida(pid)` (§3);
  - sin permiso la ruta responde con `self._prohibido()` (403 por rol, §10.2).
"""
import ast
import json
import os
import sys
import unittest
import tempfile
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ

DASH = extraer.fuente("DASH")
ARBOL = extraer.arbol("DASH")

# router_defecto e IFACE_BASE desaparecen en el panel portado (CONTRATO-F2 §3, §4); los
# routers salen de los puntos y routers.json guarda lo del usuario por pid, con la clave
# cifrada (CAMPOS_USUARIO, _routers_guardados, guardar_routers, _asoc_router...)
PIEZAS = ("MK_CONF", "MK_SENT", "MK_SENT_DNS", "MK_LOG", "ROUTERS_CONF", "ROUTERS_MAP",
          "CAMPOS_ROUTER", "CAMPOS_USUARIO", "SECRETOS_AVISO", "_ROUTERS_LOCK", "_MK_CONEXION",
          "_ENV_LOCK",
          "_router_vacio", "_mk_globales", "_routers_guardados", "_asoc_router",
          "cargar_routers", "guardar_routers", "_CAMPOS_HUELLA", "publicar_routers_map",
          "router_por_id", "cargar_mk", "cargar_mk_de",
          "mk_configurado", "mk_listo", "_ttl_efectivo",
          "clave_cpe", "ip_de", "rid_de", "router_de_clave", "_suf_nodo",
          "_router_de_pid", "_destino_ok", "cuarentena_json", "_cargar_cuarentena",
          "_motivo_bloqueo", "cargar_enviados", "guardar_enviados", "quitar_enviados",
          "_REP_AVISOS", "_REP_AVISOS_TTL", "rep_aviso_guardar", "rep_aviso_tomar",
          "rep_aviso_url", "cuar_aviso_url",
          # F1 (auditoria A-03): las rutas anotan el registro releyendolo bajo el cerrojo
          "_registrar_enviados", "_marcar_quitada", "_QUITADAS_TS")

# dos puntos: el «Nodo Sur» y el «Nodo Norte» del multi-nodo viejo (r1, r2)
PUNTOS2 = {"p001": dict(_comun.PUNTOS["p001"], nombre="Nodo Sur"),
           "p002": dict(_comun.PUNTOS["p002"], nombre="Nodo Norte")}
PUNTOS1 = {"p001": dict(_comun.PUNTOS["p001"])}

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def cuerpo_ruta(ruta):
    for n in ast.walk(ARBOL):
        if (isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
                and getattr(n.test.left, "id", "") == "ruta" and n.test.comparators
                and getattr(n.test.comparators[0], "value", "") == ruta):
            ls = DASH.split("\n")[n.body[0].lineno - 1:n.body[-1].end_lineno]
            return textwrap.dedent("\n".join(ls))
    raise SystemExit("no se encontro la ruta " + ruta)


def entorno(tmp, puntos):
    """Las piezas reales del panel, con `nodos`/`secretos` reales sobre un arbol de prueba:
    las rutas de archivo (nodos.ruta, nodos.salida) ya caen dentro de `tmp`."""
    nod, sec = _comun.panel(tmp, puntos)
    for d in ("conf", "estado", "log"):
        os.makedirs(nod.ruta(d), exist_ok=True)
    ns = {"json": json, "os": os, "html": __import__("html"), "time": __import__("time"),
          "threading": __import__("threading"), "ipaddress": __import__("ipaddress"),
          "secrets": __import__("secrets"), "urllib": __import__("urllib.parse"),
          "_up": __import__("urllib.parse", fromlist=["parse"]),
          "nodos": nod, "secretos": sec}
    piezas = [(getattr(n, "name", None) or (getattr(n.targets[0], "id", "")
               if isinstance(n, ast.Assign) and n.targets else ""), n)
              for n in ARBOL.body]
    piezas = [(nom, n) for nom, n in piezas if nom in PIEZAS]
    # 1) constantes, 2) funciones: asi los argumentos por defecto (path=MK_SENT) quedan
    #    apuntando al arbol de prueba (en el original se reescribian a mano las rutas)
    for nom, n in piezas:
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            exec(ast.get_source_segment(DASH, n) or "", ns)
    for nom, n in piezas:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["pedir_regen"] = lambda *a, **k: None
    return ns


def guardar_cuar(ns, pid, datos):
    """cuarentena.json de ESE nodo (CONTRATO-F2 §3: dir_salida(pid))."""
    with open(ns["nodos"].salida("cuarentena.json", pid), "w", encoding="utf-8") as f:
        json.dump(datos, f)


class Mikrotik:
    """MikroTik de mentira: apunta a que router y a que lista fue cada orden."""
    def __init__(self):
        self.add = []      # (ip, lista, router_id)
        self.rem = []

    def add_fn(self, ip, comment="", lista=None, ttl=None, router=None):
        self.add.append((ip, lista, (router or {}).get("id", "")))
        return True, ""

    def rem_fn(self, ip, lista=None, router=None):
        self.rem.append((ip, lista, (router or {}).get("id", "")))
        return True, "quitado"


def llamar(ns, mk, ruta, campos, operador=True):
    """Ejecuta el cuerpo de una ruta y devuelve lo que se le respondio al usuario."""
    visto = {}
    class Self:
        def _operador(self): return operador
        # (adaptada, permisos 2026-10-22) el operador del doble tiene los de su plantilla
        def _puede(self, permiso): return operador
        def _deny(self): return visto.update({"deny": True})
        def _prohibido(self): return visto.update({"deny": True})   # CONTRATO-F2 §10.2
        def _redirect(self, u): return visto.update({"redirect": u})
        def _json(self, d, code=200): return visto.update({"json": d})
        def send_response(self, *a): pass
        def send_header(self, *a): pass
        def end_headers(self, *a): pass
        wfile = type("W", (), {"write": lambda self, b: visto.update({"texto": b.decode("utf-8")})})()
    class Ctx:
        user = "operador1"
        ip = "192.0.2.9"
    # los dobles van en el MISMO espacio de nombres donde se definieron las piezas del
    # panel: guardar_enviados() y compania resuelven ahi sus propias dependencias
    ns2 = ns
    ns2.update({"self": Self(), "q": {k: [v] for k, v in campos.items()}, "CTX": Ctx(),
                "mk_add": mk.add_fn, "mk_remove": mk.rem_fn,
                "mk_log": lambda *a, **k: None, "bitacora": lambda *a, **k: None,
                "notificar_cuarentena": lambda *a, **k: None,
                "enviar_telegram": lambda *a, **k: None,
                "pedir_regen": lambda *a, **k: None,
                "es_mi_cpe": lambda ip: ip.startswith("10."),
                "es_publica_declarada": lambda ip: "",
                "publica_ajena": lambda ip: False,     # (adaptada, bloque A 2026-10-23)
                "categoria_cpe": lambda k: "botnet",
                "lista_de_categoria": lambda c: "clientes-botnet",
                "nombre_categoria": lambda c: "Botnet / CnC",
                "nunca_bloquear": lambda ip: False,
                # la evidencia reciente (§10.4) tiene su prueba en tests/test_f1_*: aqui se
                # mira el destino y la identidad, como antes
                "evidencia_sin_confirmar": lambda clave, q: ""})
    exec(compile("def _f():\n" + textwrap.indent(cuerpo_ruta(ruta), "    "), "<r>", "exec"), ns2)
    ns2["_f"]()
    return visto


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp, PUNTOS2)
    with open(ns["MK_CONF"], "w", encoding="utf-8") as f:
        f.write("ENABLED=1\nAUTO_MANTENER=0\n")
    # lo del usuario por punto (la clave queda cifrada en routers.json, §10.3); HOST/PORT/TLS
    # ya no se guardan: salen del punto (unix:<api.sock>, §4)
    ns["guardar_routers"]([
        {"id": "p001", "USER": "api", "PASS": "x", "LIST": "cuar-sur", "TTL": "1h", "ENABLED": "1"},
        {"id": "p002", "USER": "api", "PASS": "x", "LIST": "cuar-norte", "TTL": "1h", "ENABLED": "1"},
    ])
    # dos CPEs DISTINTOS con la misma IP, uno en cada nodo: el caso que rompia todo. Cada
    # nodo tiene SU cuarentena.json (§3) y la vista «Todos» los dos
    sur = {"ip": "10.6.1.165", "router": "p001", "riesgo": 73, "banda": "ALTO",
           "confianza": "alta", "alertas_cnc": 8, "firmas_cnc": 2, "firma": "Mirai del sur",
           "destinos_ip": ["198.51.100.7"]}
    norte = {"ip": "10.6.1.165", "router": "p002", "riesgo": 91, "banda": "ALTO",
             "confianza": "alta", "alertas_cnc": 40, "firmas_cnc": 3, "firma": "Cobalt del norte",
             "destinos_ip": ["203.0.113.9"]}
    guardar_cuar(ns, "p001", {"candidatos": [sur], "dns_candidatos": [], "top_riesgo": []})
    guardar_cuar(ns, "p002", {"candidatos": [norte], "dns_candidatos": [], "top_riesgo": []})
    guardar_cuar(ns, ns["nodos"].TODOS, {"candidatos": [sur, norte], "dns_candidatos": [],
                                         "top_riesgo": []})

    mk = Mikrotik()

    # --- 1) enviar el CPE del nodo Norte ---
    v = llamar(ns, mk, "/cuarentena/enviar", {"ajax": "1", "ip": "p002|10.6.1.165", "score": "91"})
    check("se acepta la identidad 'router|IP' (antes: 'IP invalida')",
          v.get("texto", "").startswith("OK"), v)
    check("el bloqueo sale hacia SU router, a la lista de su CATEGORIA",
          mk.add[-1:] == [("10.6.1.165", "clientes-botnet", "p002")], mk.add)

    reg = ns["cargar_enviados"](ns["MK_SENT"])
    check("queda registrado por identidad, no por IP pelada",
          list(reg.keys()) == ["p002|10.6.1.165"], list(reg.keys()))
    check("y por eso el Top lo marca 'En cuarentena'",
          ns["clave_cpe"]("10.6.1.165", "p002") in reg, list(reg.keys()))
    check("el CPE del OTRO nodo con la misma IP sigue sin bloquear",
          ns["clave_cpe"]("10.6.1.165", "p001") not in reg, list(reg.keys()))
    e = reg.get("p002|10.6.1.165") or {}
    check("se guarda el motivo del CPE correcto, no el del vecino",
          (e.get("motivo") or {}).get("firma") == "Cobalt del norte", e.get("motivo"))
    check("no se rotula como manual: era candidato del reporte",
          e.get("manual") is False, e)

    # --- 2) el mismo CPE del nodo Sur es otro abonado ---
    llamar(ns, mk, "/cuarentena/enviar", {"ajax": "1", "ip": "p001|10.6.1.165", "score": "73"})
    reg = ns["cargar_enviados"](ns["MK_SENT"])
    check("el del sur va a SU router, no al del norte",
          mk.add[-1:] == [("10.6.1.165", "clientes-botnet", "p001")], mk.add)
    check("y conviven los dos en el registro", len(reg) == 2, list(reg.keys()))

    # --- 3) liberar uno no libera al otro ---
    v = llamar(ns, mk, "/cuarentena/quitar", {"ip": "p002|10.6.1.165"})
    # el aviso viaja como codigo (/cuarentena?msg=<codigo>): se lee como lo haria el GET
    _cod = v.get("redirect", "").split("msg=", 1)[-1].split("&", 1)[0]
    _txt = ns["rep_aviso_tomar"](_cod)[0]
    check("quitar acepta la identidad (antes: 'IP invalida')",
          _txt.startswith("10.6.1.165") and "invalida" not in _txt, (v, _txt))
    check("se quita del router correcto y de la lista DONDE ESTA",
          mk.rem[-1:] == [("10.6.1.165", "clientes-botnet", "p002")], mk.rem)
    # importa: la lista se guarda al enviar. Si manana cambia la categoria del CPE o se
    # renombra la lista, hay que sacarlo de donde esta, no de donde tocaria hoy
    check("la lista usada queda guardada en el registro",
          (ns["cargar_enviados"](ns["MK_SENT"]).get("p001|10.6.1.165") or {}).get("lista")
          == "clientes-botnet",
          ns["cargar_enviados"](ns["MK_SENT"]).get("p001|10.6.1.165"))
    check("y tambien la categoria, para poder explicarlo despues",
          (ns["cargar_enviados"](ns["MK_SENT"]).get("p001|10.6.1.165") or {}).get("categoria")
          == "botnet")
    reg = ns["cargar_enviados"](ns["MK_SENT"])
    check("sale del registro el del norte", "p002|10.6.1.165" not in reg, list(reg.keys()))
    check("y el del sur sigue bloqueado", "p001|10.6.1.165" in reg, list(reg.keys()))

    # --- 4) una instalacion de un solo nodo funciona igual (con la clave pid|ip) ---
    tmp1 = tempfile.mkdtemp()
    ns1 = entorno(tmp1, PUNTOS1)
    with open(ns1["MK_CONF"], "w", encoding="utf-8") as f:
        f.write("ENABLED=1\nAUTO_MANTENER=0\n")
    ns1["guardar_routers"]([{"id": "p001", "USER": "api", "PASS": "x",
                             "LIST": "suricata-cuarentena", "TTL": "1h", "ENABLED": "1"}])
    guardar_cuar(ns1, "p001", {"candidatos": [{"ip": "10.6.4.61", "router": "p001", "riesgo": 73,
                                               "confianza": "alta", "firma": "unica"}],
                               "dns_candidatos": [], "top_riesgo": []})
    mk1 = Mikrotik()
    # CONTRATO-F2 §1: la identidad es SIEMPRE pid|ip, tambien con un solo punto (antes: la
    # IP pelada). §10.1/§3: la IP pelada ya no tiene destino (no hay router por defecto)
    v = llamar(ns1, mk1, "/cuarentena/enviar", {"ajax": "1", "ip": "10.6.4.61", "score": "73"})
    check("con un solo nodo la IP pelada ya no tiene destino: no se envia (§1, §10.1)",
          "destino no válido" in v.get("texto", "") and mk1.add == []
          and ns1["cargar_enviados"](ns1["MK_SENT"]) == {}, (v, mk1.add))
    v = llamar(ns1, mk1, "/cuarentena/enviar", {"ajax": "1", "ip": "p001|10.6.4.61", "score": "73"})
    reg1 = ns1["cargar_enviados"](ns1["MK_SENT"])
    check("con un solo nodo la clave es p001|IP (CONTRATO-F2 §1)",
          list(reg1.keys()) == ["p001|10.6.4.61"], list(reg1.keys()))
    check("y se envia igual que siempre",
          mk1.add == [("10.6.4.61", "clientes-botnet", "p001")], mk1.add)
    llamar(ns1, mk1, "/cuarentena/quitar", {"ip": "p001|10.6.4.61"})
    check("y se quita igual que siempre",
          ns1["cargar_enviados"](ns1["MK_SENT"]) == {}, ns1["cargar_enviados"](ns1["MK_SENT"]))

    # --- 5) un nodo en dry-run no recibe nada ---
    # (el arbol del paso 4 recargo `nodos`; se vuelve al de dos puntos)
    ns = entorno(tmp, PUNTOS2)
    ns["guardar_routers"]([{"id": "p002", "ENABLED": "0"}])
    n_antes = len(mk.add)
    v = llamar(ns, mk, "/cuarentena/enviar", {"ajax": "1", "ip": "p002|10.6.1.165", "score": "91"})
    check("a un nodo deshabilitado no se le manda nada", len(mk.add) == n_antes, mk.add)
    check("y se dice por que", "HABILITA" in v.get("texto", ""), v)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada a pid|ip siempre (CONTRATO-F2 §1, §10.1), routers por punto con clave cifrada (§4, §10.3) y cuarentena.json por nodo (§3). Enviar y quitar de cuarentena respetando la identidad (router, IP)."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
