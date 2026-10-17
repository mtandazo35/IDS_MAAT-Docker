# -*- coding: utf-8 -*-
"""Las IPs en cuarentena, entre el panel y las address-lists del MikroTik.

De donde sale:
  - el user pidio un boton para volver a cargar en el router las IPs del panel si las
    listas se vacian ("si estan, perfecto, lo omite");
  - al mirarlo salio un fallo: la sincronizacion de cada 5 minutos comparaba TODO con la
    lista vieja unica (LIST). Un CPE en clientes-botnet no estaba ahi, asi que se soltaba
    del registro aunque siguiera bloqueado: el panel lo olvidaba, el liberador ya no podia
    sacarlo y la politica lo volvia a mandar en el ciclo siguiente.

Lo que se protege:
  - sync: cada entrada contra SU lista; lo que esta, se marca en el router;
  - sync: una entrada permanente que falta en el router NO se olvida, queda "falta en el
    router"; una con TTL que falta se suelta (caduco); lo desconocido se registra con su
    lista; un router que no responde no toca lo suyo;
  - recargar: carga SOLO las que faltan, omite las que estan y las de "nunca bloquear",
    con una conexion, respetando la permanencia (politica sin TTL), y las marca en el router.

Adaptada al panel portado (CONTRATO-F2 §1, §3, §4, §10.1): el router r1 es el punto p001
(`nodos.py` real), las claves del registro son SIEMPRE `pid|ip` (`clave_cpe` REAL: lo que se
registra desde el router entra como `p001|ip`), la sync corre por nodo y solo toca las
claves de ese nodo, y una entrada sin pid (registro de antes) ya no se atribuye a ningun
router «por defecto» (`_rid_entrada`): se anade que ni la sync ni recargar la tocan.
`recargar_listas` exige un router de destino que exista (`_router_destino`, §10.1): se anade
que sin el no conecta. Las comprobaciones originales son las mismas.
"""
import ast
import json
import os
import sys
import unittest
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ
import test_acciones_router as base          # RouterFalso: la API de RouterOS de mentira

DASH = extraer.fuente("DASH")
ARBOL = extraer.arbol("DASH")

PIEZAS = ("_mk_ips_listas_en", "_mk_ips_listas", "_rid_entrada", "mk_sync_enviados", "recargar_listas",
          "cargar_enviados", "_ttl_efectivo", "ACCIONES_POR_CAT",
          # panel portado: identidad pid|ip real y destino validado (CONTRATO-F2 §1, §10.1)
          "clave_cpe", "_router_destino",
          # F1 (auditoria A-15): mk_sync_enviados no resucita lo liberado despues de leer el router
          "_QUITADAS_TS", "_marcar_quitada")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(cfg=None, nunca=()):
    rt = base.RouterFalso()
    td = tempfile.mkdtemp()
    nod, _sec = _comun.panel(td)          # puntos p001 y p002, nodos.py real
    conex = []
    bit = []
    m = {"HOST": "192.0.2.1", "USER": "u", "PASS": "p", "ENABLED": "1", "LIST": "suricata-cuarentena",
         "TTL": "", "AUTO_MANTENER": "1"}
    m.update(cfg or {})

    def guardar(d, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(d, f)

    ns = {"json": json, "os": os, "time": time, "_ENV_LOCK": threading.RLock(), "nodos": nod,
          "MK_SENT": os.path.join(td, "env.json"), "MK_SENT_DNS": os.path.join(td, "envd.json"),
          "cargar_routers": lambda: [dict(m, id="p001")], "cargar_mk_de": lambda r: dict(m),
          "mk_conectar": lambda d, timeout=6: (conex.append(1), rt)[1],
          "_mk_send": lambda s_, words: s_.enviar(words), "_mk_reply": lambda s_: s_.responder(),
          "lista_de_categoria": lambda c: "clientes-" + c,
          "rid_de": lambda k: k.split("|")[0] if "|" in k else "", "ip_de": lambda k: k.split("|")[-1],
          "nunca_bloquear": lambda ip, pid=None: ip in nunca, "bitacora": lambda a, d="", quien=None, ip=None: bit.append((a, d)),
          "guardar_enviados": lambda d, path=None: guardar(d, path)}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n), ns)
    return ns, rt, conex, bit


def al(rt, lista, ip):
    rt.t["/ip/firewall/address-list"].append({".id": rt._id(), "list": lista, "address": ip})


def escribir(path, d):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(d, f)


def leer(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    # ===================== sync =====================
    ns, rt, conex, _b = entorno()
    al(rt, "clientes-botnet", "10.0.0.5")
    al(rt, "clientes-spam", "10.0.0.77")                      # puesta a mano en el router
    # CONTRATO-F2 §1: claves pid|ip; y una vieja sin pid que nadie debe tocar (§3, §10.1)
    escribir(ns["MK_SENT"], {
        "p001|10.0.0.5": {"lista": "clientes-botnet", "router": "p001", "categoria": "botnet", "pol": True},
        "p001|10.0.0.6": {"lista": "clientes-botnet", "router": "p001", "categoria": "botnet", "pol": True},
        "p001|10.0.0.9": {"lista": "clientes-escaneo", "router": "p001", "categoria": "escaneo"},
        "10.0.0.4": {"lista": "clientes-botnet", "router": "r1", "categoria": "botnet"}})
    ns["mk_sync_enviados"]()
    env = leer(ns["MK_SENT"])
    check("sync: el CPE que esta en clientes-botnet NO se suelta (antes se comparaba con LIST)",
          "p001|10.0.0.5" in env and env["p001|10.0.0.5"]["en_router"] is True, env.get("p001|10.0.0.5"))
    check("sync: una entrada permanente que falta en el router se queda, marcada 'falta'",
          env.get("p001|10.0.0.6", {}).get("en_router") is False and env["p001|10.0.0.6"].get("falta_desde"),
          env.get("p001|10.0.0.6"))
    check("  y sin TTL configurado (auto-mantener), la manual que falta tambien se queda",
          env.get("p001|10.0.0.9", {}).get("en_router") is False, env.get("p001|10.0.0.9"))
    check("sync: lo que esta en una lista del panel y el panel no conoce, se registra con su lista",
          env.get("p001|10.0.0.77", {}).get("lista") == "clientes-spam" and env["p001|10.0.0.77"]["manual"] is True,
          env.get("p001|10.0.0.77"))
    check("sync: una conexion por router (no una por lista)", len(conex) <= 2, len(conex))   # LIST y LIST_DNS
    check("sync: una entrada sin pid no se atribuye a ningun router y no se toca (CONTRATO-F2 §3, §10.1)",
          env.get("10.0.0.4") == {"lista": "clientes-botnet", "router": "r1", "categoria": "botnet"},
          env.get("10.0.0.4"))

    # (adaptada, 2026-10-14) la cuarentena de abonados ya no caduca: aunque el .conf traiga un TTL
    # y AUTO_MANTENER=0 de antes, la que falta en el router NO se da por caducada (alguien la quito
    # a mano): se queda marcada como que falta, para recargarla
    ns2, rt2, _c2, _b2 = entorno({"TTL": "1d", "AUTO_MANTENER": "0"})
    escribir(ns2["MK_SENT"], {"p001|10.0.0.9": {"lista": "clientes-escaneo", "router": "p001"},
                              "p001|10.0.0.6": {"lista": "clientes-botnet", "router": "p001", "pol": True}})
    ns2["mk_sync_enviados"]()
    env2 = leer(ns2["MK_SENT"])
    check("sync: la que falta ya no se da por caducada: se queda marcada como que falta",
          env2.get("p001|10.0.0.9", {}).get("en_router") is False, env2)
    check("  pero la de politica (va sin TTL) se queda aunque haya TTL",
          env2.get("p001|10.0.0.6", {}).get("en_router") is False, env2)

    # router caido: no se toca nada
    ns3, rt3, _c3, _b3 = entorno()
    escribir(ns3["MK_SENT"], {"p001|10.0.0.6": {"lista": "clientes-botnet", "router": "p001", "pol": True}})
    def _caido(d, timeout=6):
        raise IOError("sin respuesta")
    ns3["mk_conectar"] = _caido
    ns3["mk_sync_enviados"]()
    check("sync: si el router no responde no se toca su registro",
          leer(ns3["MK_SENT"]) == {"p001|10.0.0.6": {"lista": "clientes-botnet", "router": "p001", "pol": True}}, "")

    # ===================== recargar =====================
    ns, rt, conex, bit = entorno({"TTL": "1d", "AUTO_MANTENER": "0"}, nunca=("10.0.0.8",))
    al(rt, "clientes-botnet", "10.0.0.5")
    escribir(ns["MK_SENT"], {
        "p001|10.0.0.5": {"lista": "clientes-botnet", "router": "p001", "categoria": "botnet", "pol": True},
        "p001|10.0.0.6": {"lista": "clientes-botnet", "router": "p001", "categoria": "botnet", "pol": True,
                          "en_router": False, "falta_desde": 1},
        "p001|10.0.0.7": {"lista": "clientes-spam", "router": "p001", "categoria": "spam"},
        "p001|10.0.0.8": {"lista": "clientes-spam", "router": "p001", "categoria": "spam"},
        # registro viejo sin pid: no es de ningun router (CONTRATO-F2 §3, §10.1)
        "10.0.0.4": {"lista": "clientes-spam", "router": "r1", "categoria": "spam"}})
    ok, msg = ns["recargar_listas"]({"id": "p001"}, quien="admin")
    ips = {(f["list"], f["address"]): f for f in rt.t["/ip/firewall/address-list"]}
    check("recargar: carga las que faltan", ("clientes-botnet", "10.0.0.6") in ips and ("clientes-spam", "10.0.0.7") in ips, list(ips))
    check("  la que ya estaba se omite (no se duplica)",
          sum(1 for f in rt.t["/ip/firewall/address-list"] if f["address"] == "10.0.0.5") == 1, "")
    check("  la que ahora esta en 'nunca bloquear' no se carga", ("clientes-spam", "10.0.0.8") not in ips, "")
    # (adaptada, 2026-10-14) antes la manual iba con el TTL configurado; ya no hay caducidad
    check("  la de politica y la manual van permanentes (la cuarentena no caduca)",
          "timeout" not in ips[("clientes-botnet", "10.0.0.6")] and not ips[("clientes-spam", "10.0.0.7")].get("timeout"),
          (ips[("clientes-botnet", "10.0.0.6")], ips[("clientes-spam", "10.0.0.7")]))
    check("  con UNA conexion", len(conex) == 1, len(conex))
    env = leer(ns["MK_SENT"])
    check("  y quedan marcadas en el router",
          env["p001|10.0.0.6"]["en_router"] is True and "falta_desde" not in env["p001|10.0.0.6"]
          and env["p001|10.0.0.7"]["en_router"] is True, (env["p001|10.0.0.6"], env["p001|10.0.0.7"]))
    check("  el mensaje dice cuantas se cargaron y cuantas ya estaban, por lista",
          ok and "2 IP(s) cargadas" in msg and "1 ya estaban" in msg and "clientes-spam: 1 cargada(s)" in msg
          and "nunca bloquear" in msg, msg)
    check("  y queda en la bitacora", bit and bit[-1][0] == "LISTAS-RECARGADAS", bit)
    check("  la entrada sin pid no se carga en este router (CONTRATO-F2 §3, §10.1)",
          ("clientes-spam", "10.0.0.4") not in ips, list(ips))
    ok2, msg2 = ns["recargar_listas"]({"id": "p001"}, quien="admin")
    check("recargar otra vez: no falta nada, no carga nada", ok2 and msg2.startswith("No faltaba nada")
          and len(rt.t["/ip/firewall/address-list"]) == 3, msg2)
    ns_v, _rt, _c, _bb = entorno()
    okv, msgv = ns_v["recargar_listas"]({"id": "p001"})
    check("sin IPs en cuarentena lo dice y no conecta", okv and "no hay nada que cargar" in msgv and not _c, msgv)
    # CONTRATO-F2 §10.1: sin destino inequivoco (sin router o un punto que no existe) no se ejecuta
    for r in ({}, {"id": "p009"}):
        try:
            ns_v["recargar_listas"](r)
            lanzo = False
        except (ValueError, LookupError):
            lanzo = True
        check("recargar sin destino valido (%r) no se ejecuta ni conecta" % (r,), lanzo and not _c, _c)

    # ===================== lo que se ve =====================
    check("el boton esta en Ajustes > MikroTik, con confirmacion propia (no confirm())",
          "listasRecargar()" in DASH and "Recargar las listas en el router" in DASH
          and "_accResultado('/mikrotik/listas/recargar'" in DASH, "")
    i = DASH.index('if ruta == "/mikrotik/listas/recargar":')
    check("la ruta es solo de admin", "self._admin()" in DASH[i:i + 300], "")
    check("en el desplegable de listas y en Cuarentena se ve 'falta en el router'",
          "falta en el router</span>" in DASH and "FALTA en el router" in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada a pid|ip y sin router por defecto (CONTRATO-F2 §1, §3, §10.1). Las IPs en cuarentena, entre el panel y las address-lists del MikroTik."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
