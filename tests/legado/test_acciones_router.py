# -*- coding: utf-8 -*-
"""Politicas de accion por categoria: las reglas se ponen en el router por la API.

Contra un RouterOS de mentira que habla el protocolo de la API (print con proplist y
filtros, add, set, remove, .id). Lo que se protege:
  - las plantillas generan lo que dicen (cortar, solo-web con su cadena y jump, sin correo,
    redirigir con y sin IP, limitar solo con limite, nada vacio);
  - aplicar respalda las tablas ANTES del primer cambio y el archivo queda en 600;
  - aplicar dos veces: la segunda no hace nada (ni respaldo ni ordenes);
  - una regla ajena (otro comment) no se toca nunca, ni al quitar;
  - cambiar de plantilla corrige (set) y quita lo que sobra; el jump va delante de la
    primera regla de prerouting (place-before);
  - quitar deja solo lo ajeno; la vista previa dice exactamente lo que se hara;
  - si el router rechaza una orden se para y lo dice; sin respaldo no se toca nada;
  - guardar_mk conserva ACCION_*.
"""
import ast
import json
import os
import re
import stat
import sys
import unittest
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ
DASH = extraer.fuente("DASH")
ARBOL = extraer.arbol("DASH")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


PIEZAS = ("ACCIONES", "ACCIONES_POR_CAT", "ACCION_DEFECTO", "T_RAW", "T_NAT", "T_MANGLE", "T_QUEUE", "T_FILTER",
          "_RSC_TABLA", "REGLAS_DIR", "_RE_KV", "_CADENAS_BASE", "_ACCIONES_TABLA", "_TERMINALES", "_NO_CRITERIO",
          "_PROTO_CON_PUERTO", "_LISTAS_IF_SISTEMA", "verificar_reglas", "_mk_contar", "verificar_en_router", "lineas_verificacion", "_RE_FIND_COMMENT", "_RE_FIND_CHAIN", "DNS_PROTEGIDO_DEFECTO", "PUERTOS_MINERIA", "reglas_desde_rsc", "cargar_reglas_propias", "guardar_reglas_propias",
          "_TABLA_RSC", "_PROPS_TABLA", "RESPALDOS_MK", "_MK_CONEXION", "accion_de_clase", "reglas_de_accion",
          "_com_regla", "_cod_regla", "_prefijo_regla", "_rsc_val", "rsc_de", "_reglas_nuestras", "_params_accion",
          "_plan", "_aviso_fasttrack", "_plan_en", "plan_reglas", "_mk_print_todo", "_mk_print", "respaldar_firewall", "aplicar_reglas",
          "quitar_reglas", "_aplicar_en", "guardar_mk", "_mk_globales", "estado_reglas",
          "ErrorLecturaMK", "_mk_print_estricto")


class RouterFalso(object):
    """Lo justo de la API de RouterOS: tablas con .id, print/add/set/remove."""
    def __init__(self):
        self.t = {"/ip/firewall/raw": [], "/ip/firewall/nat": [], "/ip/firewall/filter": [],
                  "/ip/firewall/mangle": [], "/queue/tree": [],
                  "/interface/list": [{".id": "*L1", "name": "WAN"}], "/ip/firewall/address-list": []}
        self.n = 0; self.ordenes = []; self.fallar = None; self.pend = None

    def _id(self):
        self.n += 1; return "*%X" % self.n

    def enviar(self, words):
        self.pend = words

    def responder(self):
        w = self.pend; self.pend = None
        cmd = w[0]; args = w[1:]
        tabla, op = cmd.rsplit("/", 1)
        self.ordenes.append((op, tabla, tuple(args)))
        if self.fallar and self.fallar(op, tabla, args):
            return (False, [["!trap", "=message=rechazado por el router"], ["!done"]], "rechazado por el router")
        filas = self.t[tabla]
        if op == "print":
            props = None; filtros = {}
            for a in args:
                if a.startswith("=.proplist="):
                    props = a[len("=.proplist="):].split(",")
                elif a.startswith("?"):
                    k, v = a[1:].split("=", 1); filtros[k] = v
            out = []
            for f in filas:
                if all(f.get(k) == v for k, v in filtros.items()):
                    campos = props or list(f.keys())
                    out.append(["!re"] + ["=%s=%s" % (k, f[k]) for k in campos if k in f])
            return (True, out + [["!done"]], "")
        kv = {}
        for a in args:
            if a.startswith("="):
                k, v = a[1:].split("=", 1); kv[k] = v
        if op == "add":
            fila = {".id": self._id()}; pb = kv.pop("place-before", None); fila.update(kv)
            if pb:
                i = next((i for i, f in enumerate(filas) if f[".id"] == pb), len(filas))
                filas.insert(i, fila)
            else:
                filas.append(fila)
            return (True, [["!done", "=ret=" + fila[".id"]]], "")
        if op == "set":
            rid = kv.pop(".id"); f = next(f for f in filas if f[".id"] == rid); f.update(kv)
            return (True, [["!done"]], "")
        if op == "remove":
            rid = kv[".id"]; filas[:] = [f for f in filas if f[".id"] != rid]
            return (True, [["!done"]], "")
        raise AssertionError(cmd)

    def reglas(self, tabla, pref="Suricata:"):
        return [f for f in self.t[tabla] if (f.get("comment") or "").startswith(pref)]


def entorno():
    rt = RouterFalso()
    logs = []
    m = {"HOST": "192.0.2.1", "USER": "u", "PASS": "p", "ENABLED": "1"}
    # panel portado: nodos.py real sobre un arbol temporal (RESPALDOS_MK sale de
    # nodos.RESPALDOS y REGLAS_DIR de nodos.ruta; CONTRATO-F2 §2); el router de la accion
    # es un punto (id = pid, §1/§4)
    td = tempfile.mkdtemp()
    nod, _sec = _comun.panel(td)
    ns = {"re": re, "os": os, "json": json, "time": time, "threading": threading, "nodos": nod,
          "mk_conectar": lambda d, timeout=6: rt,
          "_mk_send": lambda s_, words: s_.enviar(),
          "_mk_reply": lambda s_: s_.responder(),
          "cargar_mk_de": lambda r: dict(m), "lista_de_categoria": lambda c: "clientes-" + c,
          "mk_log": lambda a, ip, q, det="": logs.append((a, det)), "MK_CONF": None}
    # _mk_send recibe las palabras: el doble necesita verlas
    ns["_mk_send"] = lambda s_, words: s_.enviar(words)
    for n in ARBOL.body:
        noms = set()
        if getattr(n, "name", None):
            noms.add(n.name)
        elif isinstance(n, ast.Assign):
            for tg in n.targets:          # tambien 'A, B, C = ...' (las tablas van asi)
                for el in (tg.elts if isinstance(tg, ast.Tuple) else [tg]):
                    if isinstance(el, ast.Name):
                        noms.add(el.id)
        if noms & set(PIEZAS):
            exec(ast.get_source_segment(DASH, n) or "", ns)
    ns["_mk_globales"] = lambda: m
    # RESPALDOS_MK es el REAL del panel portado (bajo nodos.RESPALDOS del arbol temporal)
    return ns, rt, m, logs, td


def estado_por_clase():
    """La etiqueta de Ajustes: "Reglas aplicadas" en verde cuando el router ya tiene lo que
    toca. Con UN login para todas las clases (abrir MikroTik no puede costar ocho)."""
    ns, rt, m, logs, td = entorno()
    rt.t["/interface/list"] = [{".id": "*1", "name": "WAN"}]
    conexiones = []
    ns["mk_conectar"] = lambda d, timeout=6: (conexiones.append(1), rt)[1]
    e = ns["estado_reglas"]({"id": "p001"})
    check("estado: una sola conexion para todas las clases", len(conexiones) == 1, len(conexiones))
    check("  router vacio: las clases con accion salen pendientes, con cuantos cambios",
          # 7: solo navegación con QUIC y la hora (2026-10-18)
          e["botnet"]["estado"] == "pendientes" and e["botnet"]["cambios"] == 7, e["botnet"])
    check("  las que no tienen accion (p2p/minado/otros) no dicen nada",
          all(e[c]["estado"] == "ninguna" for c in ("p2p", "minado", "otros")), e)
    ok, msg, _p = ns["aplicar_reglas"]({"id": "p001"}, "botnet", quien="admin")
    e2 = ns["estado_reglas"]({"id": "p001"})
    check("  tras aplicar botnet: 'aplicadas' (0 cambios)", ok and e2["botnet"] == {"estado": "aplicadas", "cambios": 0}, (msg, e2["botnet"]))
    check("  y las demas siguen pendientes", e2["fuerza"]["estado"] == "pendientes", e2["fuerza"])
    m["ACCION_BOTNET"] = "nada"
    e3 = ns["estado_reglas"]({"id": "p001"})
    check("  si la clase pasa a 'nada' y quedan reglas en el router: pendientes (hay que quitarlas)",
          e3["botnet"]["estado"] == "pendientes" and e3["botnet"]["cambios"] == 7, e3["botnet"])
    ns["quitar_reglas"]({"id": "p001"}, "botnet", quien="admin")
    check("  y quitadas: ninguna", ns["estado_reglas"]({"id": "p001"})["botnet"]["estado"] == "ninguna", "")


def main():
    ns, rt, m, logs, td = entorno()
    R = ns["reglas_de_accion"]
    T_RAW, T_NAT, T_MANGLE, T_QUEUE = ns["T_RAW"], ns["T_NAT"], ns["T_MANGLE"], ns["T_QUEUE"]

    # ---------- plantillas ----------
    c = R("botnet", "cortar", "clientes-botnet")
    check("cortar = un drop en raw prerouting por la lista, arriba del todo",
          c == [(T_RAW, {"chain": "prerouting", "action": "drop", "src-address-list": "clientes-botnet", "_arriba": "1",
                         "_desc": "Cortar todo"})], c)
    w = R("botnet", "solo-web", "clientes-botnet")
    check("solo-web = cadena propia (DNS udp/tcp, 80/443 tcp, 443 udp, 123 udp) + drop + jump desde prerouting",
          len(w) == 7 and [x[1]["action"] for x in w] == ["return"] * 5 + ["drop", "jump"]
          and w[6][1]["jump-target"] == "SURICATA-BOTNET" and w[2][1]["dst-port"] == "80,443", w)
    # el user (2026-10-18): QUIC (443 UDP) y la hora (123 UDP) tambien pasan; y solo entra en la
    # cadena lo que sale de la lista
    check("  solo-web deja pasar QUIC (443 UDP) y la hora (123 UDP)",
          {(x[1].get("protocol"), x[1].get("dst-port")) for x in w if x[1]["action"] == "return"}
          == {("udp", "53"), ("tcp", "53"), ("tcp", "80,443"), ("udp", "443"), ("udp", "123")}, w)
    check("  y a la cadena solo se entra desde la lista (el jump es la unica regla con la lista)",
          [x[1].get("src-address-list") for x in w] == [None] * 6 + ["clientes-botnet"], w)
    check("  cada regla lleva su descripcion para el comentario",
          [x[1]["_desc"] for x in w] == ["DNS UDP", "DNS TCP", "HTTP HTTPS", "HTTP3 QUIC", "Hora NTP",
                                         "Bloquear resto", "Revisar clientes"], w)
    check("  y el comentario es «Suricata:<clase>:NN <descripcion>»",
          ns["_com_regla"]("botnet", 4, "HTTP3 QUIC") == "Suricata:botnet:04 HTTP3 QUIC"
          and ns["_com_regla"]("botnet", 4) == "Suricata:botnet:04"
          and ns["_cod_regla"]("Suricata:botnet:04 HTTP3 QUIC") == ns["_cod_regla"]("Suricata:botnet:04")
          == "Suricata:botnet:04", "")
    for _acc, _cat, _par in (("cortar", "fuerza", {}), ("sin-correo", "spam", {}), ("frenar-escaneo", "escaneo", {"wan": "WAN"}),
                             ("dns-protegido", "dns", {"wan": "WAN"}), ("redirigir-dns", "dns", {}),
                             ("limitar", "p2p", {"limite": "2M"})):
        _rs = R(_cat, _acc, "l", _par)
        check("  todas las reglas de «%s» llevan descripcion" % _acc,
              _rs and all(x[1].get("_desc") for x in _rs), _rs)
    sc = R("spam", "sin-correo", "clientes-spam")
    check("sin-correo = drop tcp 25,465,587,2525 (como la del ISP)", sc[0][1]["dst-port"] == "25,465,587,2525" and sc[0][1]["protocol"] == "tcp", sc)
    rd = R("dns", "redirigir-dns", "clientes-dns-malware", {"dns_ip": ""})
    check("redirigir sin IP = redirect al propio router, udp y tcp",
          [x[1]["action"] for x in rd[:2]] == ["redirect", "redirect"] and {x[1]["protocol"] for x in rd[:2]} == {"udp", "tcp"}, rd)
    # 2026-10-18: igualada a DNS protegido (arriba, !WAN y sin DoT/DoQ)
    rdw = R("dns", "redirigir-dns", "clientes-dns-malware", {"dns_ip": "", "wan": "WAN"})
    check("  y como DNS protegido: arriba, solo desde la LAN, y corta DoT/DoQ por TCP y UDP",
          len(rdw) == 4 and all(x[1].get("_arriba") == "1" and x[1].get("in-interface-list") == "!WAN" for x in rdw)
          and [(x[0], x[1]["action"], x[1].get("protocol")) for x in rdw[2:]]
          == [(T_RAW, "drop", "tcp"), (T_RAW, "drop", "udp")]
          and "853" in rdw[2][1]["dst-port"].split(",") and "853" in rdw[3][1]["dst-port"].split(","), rdw)
    rd2 = R("dns", "redirigir-dns", "l", {"dns_ip": "192.0.2.53"})
    check("redirigir con IP = dst-nat a esa IP", rd2[0][1]["action"] == "dst-nat" and rd2[0][1]["to-addresses"] == "192.0.2.53", rd2)
    check("limitar sin limite no genera nada", R("p2p", "limitar", "l", {"limite": ""}) == [], "")
    li = R("p2p", "limitar", "clientes-p2p", {"limite": "2M"})
    check("limitar con limite = marca de conexion + marca de paquete + cola", [x[0] for x in li] == [T_MANGLE, T_MANGLE, T_QUEUE]
          and li[2][1]["max-limit"] == "2M" and li[1][1]["new-packet-mark"] == "suricata-p2p", li)
    check("  la conexion se marca una vez (connection-mark=no-mark), no en cada paquete",
          li[0][1].get("connection-mark") == "no-mark", li[0])
    # 2026-10-18: plantilla nueva para criptominado, solo para su lista
    mi = R("minado", "cortar-mineria", "clientes-minado")
    check("cortar mineria = un drop tcp a los puertos stratum, solo de la lista de minado, arriba",
          mi == [(T_RAW, {"chain": "prerouting", "action": "drop", "src-address-list": "clientes-minado",
                          "protocol": "tcp", "dst-port": ns["PUERTOS_MINERIA"], "_arriba": "1",
                          "_desc": "Bloquear puertos de mineria"})]
          and "3333" in ns["PUERTOS_MINERIA"].split(","), mi)
    check("  se elige solo en criptominado y su defecto sigue siendo 'nada'",
          "cortar-mineria" in ns["ACCIONES_POR_CAT"]["minado"] and ns["accion_de_clase"]("minado", {}) == "nada"
          and all("cortar-mineria" not in v for k, v in ns["ACCIONES_POR_CAT"].items() if k != "minado")
          and ns["accion_de_clase"]("minado", {"ACCION_MINADO": "cortar-mineria"}) == "cortar-mineria", "")
    # revision 2026-10-15, Q16: «2M/2M» es de queue simple; en la max-limit de una queue tree
    # RouterOS lo rechaza. Un valor guardado asi sale como «2M».
    li2 = R("p2p", "limitar", "clientes-p2p", {"limite": "2M/2M"})
    check("un limite guardado como 2M/2M va a la cola como 2M", li2[2][1]["max-limit"] == "2M", li2)
    check("nada = vacio", R("otros", "nada", "l") == [], "")
    check("los defectos son las reglas probadas del ISP: botnet solo-web, dns protegido, escaneo frenado",
          ns["accion_de_clase"]("botnet", {}) == "solo-web" and ns["accion_de_clase"]("dns", {}) == "dns-protegido"
          and ns["accion_de_clase"]("escaneo", {}) == "frenar-escaneo" and ns["accion_de_clase"]("p2p", {}) == "nada"
          and ns["accion_de_clase"]("spam", {}) == "sin-correo", "")

    # ---------- las plantillas que salen de las reglas del ISP ----------
    dp = R("dns", "dns-protegido", "clientes-dns-malware", {"dns_ip": "", "wan": "WAN"})
    check("DNS protegido: 8 reglas (2 nat, 2 drop DoT, cadena de tope de 2 y su jump UDP y TCP)", len(dp) == 8
          and [x[0] for x in dp] == [T_NAT, T_NAT, T_RAW, T_RAW, T_RAW, T_RAW, T_RAW, T_RAW], [x[0] for x in dp])
    check("  el tope de consultas vale para el 53 UDP y TCP (2026-10-18)",
          [(x[1].get("protocol"), x[1].get("dst-port")) for x in dp if x[1].get("action") == "jump"]
          == [("udp", "53"), ("tcp", "53")], dp[6:])
    check("  el 53 va a Quad9 por defecto, con !WAN", dp[0][1]["to-addresses"] == "9.9.9.9"
          and dp[0][1]["in-interface-list"] == "!WAN" and dp[0][1]["action"] == "dst-nat", dp[0])
    check("  corta DoT/DoQ y puertos alternativos como la del ISP",
          dp[2][1]["dst-port"] == "853,8853,9953" and dp[3][1]["dst-port"] == "784,853,8853,9953", (dp[2], dp[3]))
    check("  tope de 50/s por cliente con rafaga 100", dp[4][1]["dst-limit"] == "50,100,src-address/10s", dp[4])
    dp2 = R("dns", "dns-protegido", "l", {"dns_ip": "192.0.2.53", "wan": ""})
    check("  con IP propia y sin lista WAN: a esa IP y sin la condicion",
          dp2[0][1]["to-addresses"] == "192.0.2.53" and all("in-interface-list" not in x[1] for x in dp2), dp2[0])
    fe = R("escaneo", "frenar-escaneo", "clientes-escaneo", {"wan": "WAN"})
    check("frenar escaneo: tope de 30 SYN/s (rafaga 60) y jump con syn,!ack y !WAN",
          fe[0][1]["dst-limit"] == "30,60,src-address/10s" and fe[2][1]["tcp-flags"] == "syn,!ack"
          and fe[2][1]["in-interface-list"] == "!WAN" and fe[2][1]["jump-target"] == "SURICATA-ESCANEO-TOPE", fe)
    check("  y el escaneo de puertos TCP y UDP con psd (sin protocolo: vale para los dos), arriba y con !WAN",
          len(fe) == 4 and fe[3][1].get("psd") == "21,3s,3,1" and fe[3][1]["action"] == "drop"
          and "protocol" not in fe[3][1] and fe[3][1]["src-address-list"] == "clientes-escaneo"
          and fe[3][1]["in-interface-list"] == "!WAN" and fe[3][1]["_arriba"] == "1", fe)
    pa = ns["_params_accion"]("dns", {})
    check("la lista WAN por defecto es 'WAN'; 'ninguna' la quita",
          pa["wan"] == "WAN" and ns["_params_accion"]("dns", {"ACCION_WAN_LIST": "ninguna"})["wan"] == "", pa)
    check("una accion que no es de esa clase cae al defecto", ns["accion_de_clase"]("otros", {"ACCION_OTROS": "limitar"}) == "nada", "")
    check("rsc entrecomilla lo que lo necesita", 'src-address-list="Cliente Virus"' in ns["rsc_de"](T_RAW, {"src-address-list": "Cliente Virus"})
          and "src-address-list=clientes-botnet" in ns["rsc_de"](T_RAW, {"src-address-list": "clientes-botnet"}, "Suricata:botnet:01"), "")

    # ---------- aplicar: respaldo antes, idempotente, lo ajeno intacto ----------
    rt.t[T_RAW].append({".id": rt._id(), "chain": "prerouting", "action": "accept", "comment": "mio: gestion"})
    router = {"id": "p001"}
    m["ACCION_BOTNET"] = "cortar"          # el defecto ya es solo-web: aqui se prueba cortar
    ok, msg, plan = ns["aplicar_reglas"](router, "botnet", quien="admin")
    check("aplicar 'cortar' en botnet: ok", ok is True, msg)
    nuestras = rt.reglas(T_RAW, "Suricata:botnet:")
    check("queda UNA regla nuestra con su comentario numerado y su descripcion",
          len(nuestras) == 1 and nuestras[0]["comment"] == "Suricata:botnet:01 Cortar todo", nuestras)
    check("y se puso DELANTE de la regla ajena (place-before)", rt.t[T_RAW][0]["comment"] == "Suricata:botnet:01 Cortar todo", [f.get("comment") for f in rt.t[T_RAW]])
    resp = os.listdir(ns["RESPALDOS_MK"])
    check("hay respaldo del firewall", len(resp) == 1 and resp[0].startswith("mikrotik-p001-"), resp)
    # CONTRATO-F2 §2/§4: los respaldos del firewall van al RESPALDOS del panel (antes /root/backups/panel)
    check("  y queda bajo nodos.RESPALDOS del panel",
          os.path.dirname(ns["RESPALDOS_MK"]) == ns["nodos"].RESPALDOS, ns["RESPALDOS_MK"])
    j = json.load(open(os.path.join(ns["RESPALDOS_MK"], resp[0]), encoding="utf-8"))
    check("el respaldo trae las tablas de ANTES (solo la regla ajena)", [f.get("comment") for f in j["tablas"][T_RAW]] == ["mio: gestion"], j["tablas"][T_RAW])
    if os.name != "nt":
        check("respaldo en 600", stat.S_IMODE(os.stat(os.path.join(ns["RESPALDOS_MK"], resp[0])).st_mode) == 0o600, "")
    i_resp = next(i for i, o in enumerate(rt.ordenes) if o[0] == "print" and "=.proplist" not in "".join(o[2]))
    i_add = next(i for i, o in enumerate(rt.ordenes) if o[0] == "add")
    check("el respaldo se leyo ANTES del primer add", i_resp < i_add, (i_resp, i_add))
    check("queda en la bitacora", any(a == "REGLAS-APLICADAS" and "clase=botnet" in d for a, d in logs), logs)

    n_ord = len(rt.ordenes)
    ok2, msg2, plan2 = ns["aplicar_reglas"](router, "botnet", quien="admin")
    check("aplicar otra vez: sin cambios", ok2 and "sin cambios" in msg2 and plan2["cambios"] == 0, msg2)
    check("y sin ordenes de escritura ni respaldo nuevo",
          all(o[0] == "print" for o in rt.ordenes[n_ord:]) and len(os.listdir(ns["RESPALDOS_MK"])) == 1, rt.ordenes[n_ord:])

    # ---------- cambiar de plantilla: set + add + remove ----------
    m["ACCION_BOTNET"] = "solo-web"
    plan3 = ns["plan_reglas"](router, "botnet")
    ops = [a[0] for a in plan3["acciones"]]
    check("vista previa de cortar->solo-web: 1 set (la :01) y 6 add", ops.count("set") == 1 and ops.count("add") == 6 and "remove" not in ops, ops)
    check("la vista previa lleva el comentario con la descripcion",
          any('comment="Suricata:botnet:04 HTTP3 QUIC"' in l for l in plan3["rsc"]), plan3["rsc"])
    check("la vista previa es RSC legible", any("jump-target=SURICATA-BOTNET" in l for l in plan3["rsc"]), plan3["rsc"])
    ok3, msg3, _ = ns["aplicar_reglas"](router, "botnet", quien="admin")
    nuestras = rt.reglas(T_RAW, "Suricata:botnet:")
    cadena = [f["action"] for f in nuestras if f.get("chain") == "SURICATA-BOTNET"]
    pre = [f.get("comment") for f in rt.t[T_RAW] if f.get("chain") == "prerouting"]
    check("ahora hay 7 reglas nuestras: la cadena en orden (5 return + drop)", len(nuestras) == 7
          and cadena == ["return"] * 5 + ["drop"], [f["action"] for f in nuestras])
    check("y el jump va el PRIMERO de prerouting, delante de la regla ajena",
          pre and pre[0] == "Suricata:botnet:07 Revisar clientes" and "mio: gestion" in pre, pre)
    check("la ajena sigue intacta", any(f.get("comment") == "mio: gestion" and f["action"] == "accept" for f in rt.t[T_RAW]), "")
    m["ACCION_BOTNET"] = "cortar"
    ok4, msg4, plan4 = ns["aplicar_reglas"](router, "botnet", quien="admin")
    check("volver a cortar: corrige la :01 y quita las otras 6", "6 quitada" in msg4 and len(rt.reglas(T_RAW, "Suricata:botnet:")) == 1
          and rt.reglas(T_RAW, "Suricata:botnet:")[0]["action"] == "drop", msg4)

    # ---------- reglas de antes, sin descripcion (2026-10-18): se les pone, no se rehacen ----------
    rt.t[T_RAW][:] = [f for f in rt.t[T_RAW] if not (f.get("comment") or "").startswith("Suricata:")]
    rt.t[T_RAW].insert(0, {".id": rt._id(), "chain": "prerouting", "action": "drop",
                           "src-address-list": "clientes-botnet", "comment": "Suricata:botnet:01"})
    plan_v = ns["plan_reglas"](router, "botnet")
    ops_v = [a[0] for a in plan_v["acciones"]]
    check("una regla vieja sin descripcion es la misma regla: un set, ni add ni remove",
          ops_v == ["set"], ops_v)
    ok_v, msg_v, _ = ns["aplicar_reglas"](router, "botnet", quien="admin")
    check("  y al aplicar queda con la descripcion",
          ok_v and [f.get("comment") for f in rt.reglas(T_RAW, "Suricata:botnet:")] == ["Suricata:botnet:01 Cortar todo"],
          (msg_v, rt.reglas(T_RAW, "Suricata:botnet:")))
    check("  la segunda vez: sin cambios", ns["plan_reglas"](router, "botnet")["cambios"] == 0, "")

    # ---------- quitar: solo lo nuestro ----------
    ok5, msg5, _ = ns["quitar_reglas"](router, "botnet", quien="admin")
    check("quitar deja solo lo ajeno", ok5 and rt.reglas(T_RAW) == [] and len(rt.t[T_RAW]) == 1, rt.t[T_RAW])

    # ---------- limitar sin limite: no se aplica y se dice ----------
    m["ACCION_P2P"] = "limitar"
    ok6, msg6, plan6 = ns["aplicar_reglas"](router, "p2p", quien="admin")
    check("limitar sin limite no toca nada y avisa", ok6 is False and "Falta el límite" in msg6 and rt.t[T_MANGLE] == [], msg6)
    m["ACCION_LIMITE_P2P"] = "2M"
    ok7, msg7, _ = ns["aplicar_reglas"](router, "p2p", quien="admin")
    check("con limite, marcas y cola", ok7 and len(rt.t[T_MANGLE]) == 2 and rt.t[T_QUEUE][0]["max-limit"] == "2M", msg7)
    # 2026-10-18: con fasttrack las conexiones aceleradas se saltan mangle y cola. Aviso SOLO si
    # el router lo usa sin connection-mark=no-mark (no todos lo usan); la regla no se toca
    check("  sin fasttrack en el router: sin aviso", "fasttrack" not in ns["plan_reglas"](router, "p2p")["aviso"], "")
    rt.t[ns["T_FILTER"]].append({".id": rt._id(), "chain": "forward", "action": "fasttrack-connection",
                           "connection-state": "established,related", "comment": "mio: fasttrack"})
    av = ns["plan_reglas"](router, "p2p")["aviso"]
    check("  con fasttrack: la vista previa avisa que el limite no vale y da la orden",
          "fasttrack" in av and "connection-mark=no-mark" in av, av)
    rt.t[ns["T_FILTER"]][-1]["connection-mark"] = "no-mark"
    check("  con fasttrack que ya deja fuera las marcadas: sin aviso",
          "fasttrack" not in ns["plan_reglas"](router, "p2p")["aviso"], "")
    rt.t[ns["T_FILTER"]][-1].pop("connection-mark"); rt.t[ns["T_FILTER"]][-1]["disabled"] = "true"
    check("  con fasttrack desactivado: sin aviso", "fasttrack" not in ns["plan_reglas"](router, "p2p")["aviso"], "")
    check("  y la regla de fasttrack sigue como estaba (el panel no la toca)",
          rt.t[ns["T_FILTER"]][-1]["comment"] == "mio: fasttrack" and rt.t[ns["T_FILTER"]][-1]["action"] == "fasttrack-connection", "")
    rt.t[ns["T_FILTER"]].pop()

    # ---------- el router rechaza: se para y se dice ----------
    m["ACCION_SPAM"] = "sin-correo"
    rt.fallar = lambda op, tabla, args: op == "add"
    ok8, msg8, _ = ns["aplicar_reglas"](router, "spam", quien="admin")
    check("si el router rechaza, falla con el motivo y el respaldo", ok8 is False and "rechazado" in msg8 and "respaldo" in msg8.lower(), msg8)
    check("y queda en la bitacora como error", any(a == "REGLAS-ERROR" for a, _d in logs), "")
    rt.fallar = None

    # ---------- sin respaldo no se toca ----------
    ns["RESPALDOS_MK"] = os.path.join(td, "noexiste", "x" * 300)   # ruta imposible
    antes = len(rt.t[T_RAW])
    ok9, msg9, _ = ns["aplicar_reglas"](router, "spam", quien="admin")
    check("si el respaldo falla, no se toca nada", ok9 is False and "respaldar" in msg9 and len(rt.t[T_RAW]) == antes, msg9)

    # ---------- reglas PROPIAS: el bloque que pega el usuario ----------
    PEGADO = """/ip firewall raw
add action=return chain=BOTNET-CUARENTENA comment="Permite consultas DNS UDP 53" dst-port=53 protocol=udp
add action=return chain=BOTNET-CUARENTENA comment="Permite consultas DNS TCP 53" dst-port=53 protocol=tcp
add action=return chain=BOTNET-CUARENTENA comment="Permite navegacion" dst-port=80,443 protocol=tcp
add action=drop chain=BOTNET-CUARENTENA comment="Bloquea el resto"
add action=jump chain=prerouting comment="Restringe clientes botnet" jump-target=BOTNET-CUARENTENA place-before=0 src-address-list={LISTA}
"""
    pr = ns["reglas_desde_rsc"](PEGADO, "clientes-botnet")
    check("el bloque pegado parsea en 5 reglas raw", len(pr) == 5 and all(tb == T_RAW for tb, _p in pr), pr)
    check("el comment pegado se descarta (lo pone el panel) y {LISTA} se sustituye",
          all("comment" not in p for _t, p in pr) and pr[4][1]["src-address-list"] == "clientes-botnet", pr[4])
    check("place-before=0 pasa a 'la primera de su cadena'", pr[4][1].get("_arriba") == "1" and "place-before" not in pr[4][1], pr[4])
    check("los valores entrecomillados y las listas de puertos se respetan", pr[2][1]["dst-port"] == "80,443", pr[2])
    try:
        ns["reglas_desde_rsc"]("/ip route\nadd dst-address=0.0.0.0/0", "l"); mal = ""
    except ValueError as ex:
        mal = str(ex)
    check("una tabla que no se maneja es un error con la linea", "línea 1" in mal and "no soportada" in mal, mal)
    try:
        ns["reglas_desde_rsc"]("add chain=prerouting action=drop", "l"); mal2 = ""
    except ValueError as ex:
        mal2 = str(ex)
    check("un add sin tabla delante es un error", "falta la tabla" in mal2, mal2)
    check("la marca interna no sale en el RSC de la vista previa, place-before si",
          "_arriba" not in ns["rsc_de"](T_RAW, pr[4][1], "Suricata:botnet:05") and "place-before=0" in ns["rsc_de"](T_RAW, pr[4][1]), "")

    ns["REGLAS_DIR"] = os.path.join(td, "reglas")
    n_g = ns["guardar_reglas_propias"]("botnet", PEGADO)
    check("guardar valida y cuenta las reglas", n_g == 5 and ns["cargar_reglas_propias"]("botnet").startswith("/ip firewall raw"), n_g)
    try:
        ns["guardar_reglas_propias"]("botnet", "/ip route\nadd x=1"); g_mal = ""
    except ValueError as ex:
        g_mal = str(ex)
    check("un bloque invalido NO se guarda", "no soportada" in g_mal and "/ip route" not in ns["cargar_reglas_propias"]("botnet"), g_mal)

    rt2 = RouterFalso(); rt2.t[T_RAW].append({".id": rt2._id(), "chain": "prerouting", "action": "accept", "comment": "mio"})
    ns["mk_conectar"] = lambda d, timeout=6: rt2
    ns["RESPALDOS_MK"] = os.path.join(td, "backups2")
    m["ACCION_BOTNET"] = "propias"
    okp, msgp, planp = ns["aplicar_reglas"](router, "botnet", quien="admin")
    check("aplicar las reglas propias: ok, 5 nuevas", okp and "5 nueva" in msgp, msgp)
    pre2 = [f.get("comment") for f in rt2.t[T_RAW] if f.get("chain") == "prerouting"]
    check("el jump pegado con place-before=0 queda el primero de prerouting", pre2[0] == "Suricata:botnet:05" and "mio" in pre2, pre2)
    okp2, msgp2, planp2 = ns["aplicar_reglas"](router, "botnet", quien="admin")
    check("segunda vez: sin cambios (los campos propios tambien se comparan)", okp2 and planp2["cambios"] == 0, (msgp2, [a[0] for a in planp2["acciones"]]))
    m["ACCION_ESCANEO"] = "propias"
    oke, msge, plane = ns["aplicar_reglas"](router, "escaneo", quien="admin")
    check("propias sin bloque pegado: no toca nada y lo dice", oke is False and "No hay reglas propias" in msge, msge)

    # ---------- las reglas REALES del ISP (2026-10-09), pegadas tal cual ----------
    DNS_ISP = """/ip firewall nat
add action=dst-nat chain=dstnat comment="Fuerza DNS UDP" dst-port=53 in-interface-list=!WAN protocol=udp src-address-list={LISTA} to-addresses=9.9.9.9 to-ports=53 place-before=0
add action=dst-nat chain=dstnat comment="Fuerza DNS TCP" dst-port=53 in-interface-list=!WAN protocol=tcp src-address-list={LISTA} to-addresses=9.9.9.9 to-ports=53 place-before=0

/ip firewall raw
add action=drop chain=prerouting comment="DoT TCP" dst-port=853,8853,9953 in-interface-list=!WAN protocol=tcp src-address-list={LISTA}
add action=drop chain=prerouting comment="DoT UDP" dst-port=784,853,8853,9953 in-interface-list=!WAN protocol=udp src-address-list={LISTA}

/ip firewall raw
add action=return chain=DNS-MALWARE-LIMIT comment="hasta 50/s" dst-limit=50,100,src-address/10s
add action=drop chain=DNS-MALWARE-LIMIT comment="exceso"
add action=jump chain=prerouting comment="tope" dst-port=53 in-interface-list=!WAN jump-target=DNS-MALWARE-LIMIT place-before=0 protocol=udp src-address-list={LISTA}
"""
    rd_isp = ns["reglas_desde_rsc"](DNS_ISP, "clientes-dns-malware")
    check("el bloque DNS del ISP parsea entero (7 reglas, nat y raw)", len(rd_isp) == 7
          and [x[0] for x in rd_isp].count(T_NAT) == 2, [x[0] for x in rd_isp])
    check("  !WAN y dst-limit llegan tal cual", rd_isp[0][1]["in-interface-list"] == "!WAN"
          and rd_isp[4][1]["dst-limit"] == "50,100,src-address/10s", (rd_isp[0], rd_isp[4]))
    ESC_ISP = """/ip firewall raw
add action=return chain=ESCANEO-CONTROL comment="30/s" dst-limit=30,60,src-address/10s
add action=drop chain=ESCANEO-CONTROL comment="exceso"
add action=jump chain=prerouting comment="Controla SYN" in-interface-list=!WAN jump-target=ESCANEO-CONTROL place-before=[find where chain=prerouting comment="Drop Malware"] protocol=tcp src-address-list={LISTA} tcp-flags=syn,!ack
"""
    re_isp = ns["reglas_desde_rsc"](ESC_ISP, "clientes-escaneo")
    j = re_isp[2][1]
    check("place-before=[find ...] NO se parte: la cadena sigue siendo prerouting y no se cuela 'where'",
          j["chain"] == "prerouting" and "where" not in j and j.get("_antes_de") == "Drop Malware"
          and j.get("_antes_cadena") == "prerouting" and j["tcp-flags"] == "syn,!ack", j)
    check("y la vista previa lo escribe como en la consola",
          'place-before=[find where chain=prerouting comment="Drop Malware"]' in ns["rsc_de"](T_RAW, j), ns["rsc_de"](T_RAW, j))
    try:
        ns["reglas_desde_rsc"]("/ip firewall raw\nadd chain=prerouting action=drop place-before=[find where dynamic=yes]", "l"); m_pb = ""
    except ValueError as ex:
        m_pb = str(ex)
    check("un place-before que no se sabe resolver es un error con su linea", "línea 2" in m_pb and "place-before" in m_pb, m_pb)

    # aplicar el de escaneo en un router CON la regla 'Drop Malware'
    rt3 = RouterFalso()
    for c_ in ("mio: gestion", "Drop Malware", "mio: final"):
        rt3.t[T_RAW].append({".id": rt3._id(), "chain": "prerouting", "action": "accept" if c_ != "Drop Malware" else "drop", "comment": c_})
    ns["mk_conectar"] = lambda d, timeout=6: rt3
    ns["RESPALDOS_MK"] = os.path.join(td, "backups3")
    ns["REGLAS_DIR"] = os.path.join(td, "reglas3")
    ns["guardar_reglas_propias"]("escaneo", ESC_ISP)
    m["ACCION_ESCANEO"] = "propias"
    p3 = ns["plan_reglas"](router, "escaneo")
    check("con 'Drop Malware' en el router, la vista previa no avisa", "Drop Malware" not in p3["aviso"], p3["aviso"])
    ok_e, msg_e, _ = ns["aplicar_reglas"](router, "escaneo", quien="admin")
    pre3 = [f.get("comment") for f in rt3.t[T_RAW] if f.get("chain") == "prerouting"]
    check("el jump queda justo DELANTE de 'Drop Malware', no arriba del todo",
          ok_e and pre3 == ["mio: gestion", "Suricata:escaneo:03", "Drop Malware", "mio: final"], pre3)

    # ... y en un router SIN esa regla: aviso en la vista previa y va la primera
    rt4 = RouterFalso(); rt4.t[T_RAW].append({".id": rt4._id(), "chain": "prerouting", "action": "accept", "comment": "mio"})
    ns["mk_conectar"] = lambda d, timeout=6: rt4
    p4 = ns["plan_reglas"](router, "escaneo")
    check("sin 'Drop Malware', la vista previa lo avisa ANTES de aplicar", "no hay ninguna regla 'Drop Malware'" in p4["aviso"], p4["aviso"])
    ok4b, _m4, _ = ns["aplicar_reglas"](router, "escaneo", quien="admin")
    pre4 = [f.get("comment") for f in rt4.t[T_RAW] if f.get("chain") == "prerouting"]
    check("  y el jump va el primero de prerouting", ok4b and pre4[0] == "Suricata:escaneo:03", pre4)

    # orden: varias 'arriba' conservan su orden (antes salian al reves)
    ORDEN = """/ip firewall raw
add chain=prerouting action=accept protocol=tcp dst-port=587 src-address-list={LISTA} place-before=0
add chain=prerouting action=drop protocol=tcp dst-port=587 place-before=0
add chain=prerouting action=drop protocol=tcp dst-port=25
"""
    rt5 = RouterFalso(); rt5.t[T_RAW].append({".id": rt5._id(), "chain": "prerouting", "action": "accept", "comment": "mio"})
    ns["mk_conectar"] = lambda d, timeout=6: rt5
    ns["guardar_reglas_propias"]("spam", ORDEN)
    m["ACCION_SPAM"] = "propias"
    ns["aplicar_reglas"](router, "spam", quien="admin")
    pre5 = [f.get("comment") for f in rt5.t[T_RAW] if f.get("chain") == "prerouting"]
    check("dos reglas 'arriba' conservan su orden (accept antes que drop) y lo que no dice posicion va al final",
          pre5 == ["Suricata:spam:01", "Suricata:spam:02", "mio", "Suricata:spam:03"], pre5)

    # ---------- guardar_mk conserva ACCION_* ----------
    ns["MK_CONF"] = os.path.join(td, "mk.conf")
    ns["guardar_mk"]({"HOST": "h", "ACCION_BOTNET": "solo-web", "ACCION_DNS_IP": "192.0.2.53", "ACCION_LIMITE_P2P": "2M"})
    # _mk_globales real, no el doble
    for n in ARBOL.body:
        if getattr(n, "name", None) == "_mk_globales":
            exec(ast.get_source_segment(DASH, n), ns)
    g = ns["_mk_globales"]()
    check("guardar_mk conserva ACCION_*", g.get("ACCION_BOTNET") == "solo-web" and g.get("ACCION_DNS_IP") == "192.0.2.53" and g.get("ACCION_LIMITE_P2P") == "2M", g)

    estado_por_clase()
    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion (prueba heredada de suricata-ids-lab), solo cambia la carga: nodos.py real (RESPALDOS_MK = nodos.RESPALDOS/mikrotik, REGLAS_DIR = nodos.ruta, CONTRATO-F2 §2) y router = punto p001 (§1, §4). Politicas de accion por categoria: las reglas se ponen en el router por la API."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
