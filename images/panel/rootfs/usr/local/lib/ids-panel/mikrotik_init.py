#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Espejo del IDS en el MikroTik de un punto: plan, aplicar, pausar y retirar.

Modulo del panel (pantalla Puntos, ficha del punto > Espejo). Lo que hace en el router es
EXACTAMENTE docs/OPERACION.md §2, y si algo de aqui choca con ese documento, manda el
documento. Requisito que manda sobre todo:

    Instalar, actualizar, pausar o retirar el espejo no autoriza trafico que la politica
    original del router rechazaba. Por eso aqui NO SE CREA NINGUNA REGLA `accept`.

Lo que se monta, todo con el comentario PROPIO del espejo `IDS ids-maat:<pid>:espejo`
(auditoria A-02): el alta del punto pone con `IDS ids-maat:<pid>` la regla `chain=input` que
deja entrar a la API-SSL desde el tunel y el blackhole del tunel, y el espejo NO los toca nunca
(sin esa regla, con la cadena input en drop, el panel se queda sin API en ese router). La baja
manual de OPERACION §2.1 (`comment~"ids-maat:<pid>(:|$)"`) sigue quitandolo todo:

  - address-list `<lista>` con cada red del punto (prefijos editables: una red con nuestro
    comentario que ya no esta en `redes` se quita; una direccion que ya estaba en la lista sin
    nuestro comentario no se duplica ni se borra nunca);
  - dos mangle `chain=forward action=sniff-tzsp` (ida `src-address-list=<lista>`, vuelta
    `dst-address-list=<lista>`) con `connection-bytes=0-10000` y `passthrough=yes`;
  - los espejos sniff-tzsp viejos hacia el mismo sensor que no son nuestros se APAGAN (no se
    borran): dos espejos a la vez llenan el enlace y el TZSP, que es UDP, desaparece;
  - fasttrack: a cada `fasttrack-connection` habilitada que no usa address-lists se le pone
    `src-address-list=!<lista> dst-address-list=!<lista>` (su valor original va al respaldo) y,
    justo detras, dos `fasttrack-connection` nuevas con sus MISMAS condiciones y
    `src-address-list=<lista>` / `dst-address-list=<lista>` y `connection-bytes=10000-0`.
    Solo cambian condiciones de reglas que deciden que se ACELERA, nunca que pasa: un paquete
    no acelerado sigue recorriendo el filtro entero.

No hay regla de DNS aparte ni nada de IPv6 (fuera de esta version).

Interfaz (la usa la pantalla Puntos; `conexion` es el socket ya logueado de `mk_conectar`):

plan(conexion, pid, sensor, puerto, redes, lista="ids-vigilados") -> dict   (solo lectura)
    {"pid": "p003", "sensor": "192.0.2.10", "puerto": 37008, "lista": "ids-vigilados",
     "redes": ["10.0.0.0/24", "10.0.9.7"],        # normalizadas; un /32 sin "/32", como el router
     "comentario": "IDS ids-maat:p003:espejo",
     "identidad": "nombre del router",             # /system/identity/print
     "cambios": [{"que": "texto para el operador", "orden": "/ip/firewall/mangle/add",
                  "args": ["=chain=forward", ...]}, ...],   # en el orden en que se aplican
     "terminal": ["/ip firewall mangle add chain=forward ...", ...],  # 1 por cambio, mismo orden
     "avisos": ["texto", ...],                     # informativos: no impiden aplicar
     "bloqueos": ["texto", ...],                   # si hay alguno, aplicar() se niega
     "fasttrack": [{".id": "*2", "src-address-list": "", "dst-address-list": "",
                    "disabled": False,
                    "accion": "excluir" | "ya-excluida" | "no-se-toca",
                    "que": "texto"}, ...]}         # una por regla fasttrack-connection ajena,
                                                   # con los valores que tiene AHORA (los originales)
    `redes` es una lista o un texto separado por comas. Lanza DatosInvalidos (pid, sensor,
    puerto, lista o red mal formados; IPv6) o ErrorRouter (el router no responde o rechaza
    una lectura: un print fallido NUNCA se toma por tabla vacia).

aplicar(conexion, plan, respaldo_dir) -> dict
    {"ok": bool, "hechos": ["que", ...], "fallo": None | "texto", "sin_aplicar": ["que", ...],
     "respaldo": None | "<respaldo_dir>/<pid>/espejo-AAAAMMDD-HHMMSS.json",
     "export": None | "ids-maat-<pid>-AAAAMMDD-HHMMSS",       # fichero .rsc en el router
     "plan": None | <plan recalculado>}                       # solo si el router cambio
    Recalcula el plan; si los cambios no son los de la vista previa, no aplica y lo dice (y
    devuelve el plan nuevo). Sin cambios: ok y nada mas. Si no: JSON local (0600) y
    `/export` en el router; sin los dos respaldos no se toca nada. Despues aplica en orden y
    para en el PRIMER fallo. Una orden sin respuesta (timeout) cuenta como fallo: puede
    haberse aplicado o no, y el plan siguiente relee el router antes de repetir nada.

aplicar(), pausar() y retirar() devuelven ademas "mensaje" (una linea: el fallo, o lo hecho) y
"lineas" (["hecho: ...", "SIN APLICAR: ..."]) y "avisos" (lista, vacia si no hay).

pausar(conexion, pid, respaldo_dir=None) -> {"ok", "hechos", "fallo", "sin_aplicar", "export",
    "respaldo"}
    `disabled=yes` en los mangle con el comentario del punto (antes, `/export` en el router y,
    con `respaldo_dir`, la copia local de esos mangle en <respaldo_dir>/<pid>/pausa-*.json).
    El fasttrack queda como esta. Volver a aplicar el plan los habilita otra vez.

plan_retirar(conexion, pid, respaldo=None, lista=None) -> {"pid", "lista", "cambios",
    "terminal", "avisos"}   (solo lectura; misma forma de `cambios` que plan())
retirar(conexion, pid, respaldo, lista=None) -> {"ok", "hechos", "fallo", "sin_aplicar",
    "export", "avisos", "cambios"}
    `respaldo`: el dict o la ruta del JSON que guardo aplicar() (vale el ultimo: lleva los
    valores originales del fasttrack de los anteriores; ver ultimo_respaldo()), el DIRECTORIO
    de respaldos del panel (se usa el ultimo JSON de ese punto), o None.
    Antes, `/export` en el router. Borra de mangle, filter y address-list SOLO lo del espejo
    (comentario exacto `IDS ids-maat:<pid>:espejo`, o el `IDS ids-maat:<pid>` de versiones
    anteriores en reglas con forma de espejo: ver es_del_espejo()), y devuelve a cada fasttrack sus valores
    originales de src/dst-address-list segun el respaldo (solo los campos que siguen siendo
    `!<lista>`: si alguien los cambio despues, no se tocan y se avisa). Una fasttrack que no
    esta en el respaldo y tiene `!<lista>` en los dos campos los pierde (unset). Nunca borra
    ni cambia reglas ajenas.

ultimo_respaldo(respaldo_dir, pid) -> ruta del JSON mas reciente de ese punto, o None.

JSON de respaldo: {"pid", "fecha", "export", "identidad", "lista", "sensor", "puerto",
"redes", "comentario", "filter": [filas], "mangle": [filas], "address-list": [filas de la
lista y de las entradas con nuestro comentario], "fasttrack": {".id": {"src-address-list",
"dst-address-list"}} (valores originales), "cambios": [...]}.
"""
import glob
import ipaddress
import json
import os
import re
import time

import nodos

LISTA = "ids-vigilados"
CB_ESPEJO = "0-10000"       # el espejo: los primeros 10 KB de cada conexion
CB_ACELERAR = "10000-0"     # el fasttrack de los vigilados: a partir de los 10 KB
FT = "fasttrack-connection"
RE_LISTA = re.compile(r"^[A-Za-z0-9._-]{1,63}$")

AL = "/ip/firewall/address-list/"
MG = "/ip/firewall/mangle/"
FI = "/ip/firewall/filter/"

# Lo que NO es condicion de una regla y no se copia del fasttrack original a las nuevas.
# Tambien todo lo que empieza por "." (.id, .nextid, .about...).
_NO_CONDICION = {"comment", "disabled", "dynamic", "invalid", "bytes", "packets", "chain",
                 "action", "src-address-list", "dst-address-list", "connection-bytes",
                 "place-before", "log", "log-prefix"}


class ErrorEspejo(Exception):
    """Algo impide calcular o aplicar el espejo."""


class DatosInvalidos(ErrorEspejo, ValueError):
    """pid, sensor, puerto, lista, redes o respaldo mal formados."""


class ErrorRouter(ErrorEspejo):
    """El router no responde o rechaza una lectura."""


# --- cliente minimo de la API de RouterOS: copia del de dashboard.py, sin importarlo ---
def _mk_len(n):
    if n < 0x80: return bytes([n])
    if n < 0x4000: return (n | 0x8000).to_bytes(2, "big")
    if n < 0x200000: return (n | 0xC00000).to_bytes(3, "big")
    if n < 0x10000000: return (n | 0xE0000000).to_bytes(4, "big")
    return b"\xF0" + n.to_bytes(4, "big")

def _mk_word(sock, w):
    b = w.encode("utf-8")
    sock.sendall(_mk_len(len(b)) + b)

def _mk_send(sock, words):
    for w in words:
        _mk_word(sock, w)
    sock.sendall(b"\x00")

def _mk_rlen(sock):
    c = sock.recv(1)
    if not c: raise IOError("conexion cerrada")
    c = c[0]
    if c & 0x80 == 0: return c
    if c & 0xC0 == 0x80: return ((c & 0x3F) << 8) + sock.recv(1)[0]
    if c & 0xE0 == 0xC0:
        b = sock.recv(2); return ((c & 0x1F) << 16) + (b[0] << 8) + b[1]
    if c & 0xF0 == 0xE0:
        b = sock.recv(3); return ((c & 0x0F) << 24) + (b[0] << 16) + (b[1] << 8) + b[2]
    b = sock.recv(4); return int.from_bytes(b, "big")

def _mk_read(sock):
    """Lee una sentencia (lista de palabras hasta la palabra vacia)."""
    words = []
    while True:
        n = _mk_rlen(sock)
        if n == 0:
            return words
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk: raise IOError("conexion cerrada")
            data += chunk
        words.append(data.decode("utf-8", "replace"))

def _mk_reply(sock):
    """Junta sentencias hasta !done/!fatal. Devuelve (ok, sentencias, mensaje_error)."""
    frases, err = [], ""
    while True:
        w = _mk_read(sock)
        if not w:
            continue
        frases.append(w)
        tipo = w[0]
        if tipo == "!trap" or tipo == "!fatal":
            for a in w[1:]:
                if a.startswith("=message="):
                    err = a[len("=message="):]
        if tipo == "!done":
            return (err == "", frases, err)
        if tipo == "!fatal":
            return (False, frases, err or "conexion terminada")

# Errores de un socket que se corta o se queda callado a mitad de respuesta.
_FALLOS_RED = (OSError, IndexError, ValueError)

def _mk_print(s_, cmd, props=None, consulta=()):
    """Un print de la API como lista de diccionarios, en el orden del router.

    A diferencia del _mk_print del panel, un print que falla LANZA ErrorRouter: tomarlo por
    una tabla vacia haria que el plan volviera a crear todo (reglas duplicadas, dos espejos)."""
    palabras = [cmd]
    if props:
        palabras.append("=.proplist=" + ",".join(props))
    palabras.extend(consulta)
    try:
        _mk_send(s_, palabras)
        ok, frases, err = _mk_reply(s_)
    except _FALLOS_RED as e:
        raise ErrorRouter("sin respuesta del router en %s: %s" % (cmd, e))
    if not ok:
        raise ErrorRouter("el router rechazo %s: %s" % (cmd, err))
    filas = []
    for f in frases:
        if not (f and f[0] == "!re"):
            continue
        d = {}
        for a in f:
            if a.startswith("=") and "=" in a[1:]:
                k, v = a[1:].split("=", 1)
                d[k] = v
        filas.append(d)
    return filas


def en_terminal(orden, args):
    """La orden de la API escrita como en la terminal del router, para la vista previa:
    /ip/firewall/mangle/add =chain=forward  ->  /ip firewall mangle add chain=forward.
    Asi el operador lee lo que conoce, no el protocolo de la API."""
    partes = orden.strip("/").split("/")
    txt = "/" + " ".join(partes[:-1]) + " " + partes[-1]
    for x in args:
        k, v = x[1:].split("=", 1)
        if k in (".id", "numbers"):
            txt += " " + v          # set *1A ...: el id interno, como lo admite la terminal
            continue
        if v == "" or any(c in v for c in ' \t";\\$[]{}'):
            v = '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
        txt += " %s=%s" % (k, v)
    return txt


# --- utilidades -------------------------------------------------------------------------
def comentario(pid):
    """El comentario de todo lo que el espejo del punto crea en el router. Es PROPIO del espejo:
    lo que el alta pone con `comentario_alta(pid)` (la regla input de la API-SSL, el blackhole)
    no es del espejo y el espejo no lo toca (auditoria A-02)."""
    return "IDS ids-maat:%s:espejo" % pid


def comentario_alta(pid):
    """El comentario del alta del punto (OPERACION §1.2/§1.3). Las versiones anteriores del
    espejo tambien lo usaban: por eso solo cuenta como del espejo con forma de espejo."""
    return "IDS ids-maat:%s" % pid


def es_del_espejo(f, tabla, pid, lista=LISTA):
    """¿Es esta fila del espejo del punto? Con el comentario propio, si. Con el comentario del
    alta (espejos montados por versiones anteriores), solo si tiene forma de espejo:
      - mangle: `action=sniff-tzsp`;
      - filter: `chain=forward` y usa la lista del espejo (las fasttrack de vigilados y el
        `accept` de vigilados de una version anterior); NUNCA `chain=input` (la API-SSL);
      - address-list: entradas de la lista del espejo.
    Nada mas: una regla del alta o ajena con un comentario parecido no se toca."""
    com = f.get("comment")
    if com == comentario(pid):
        return True
    if com != comentario_alta(pid):
        return False
    if tabla == "mangle":
        return f.get("action") == "sniff-tzsp"
    if tabla == "filter":
        return (f.get("chain") == "forward"
                and lista in (f.get("src-address-list", ""), f.get("dst-address-list", "")))
    if tabla == "address-list":
        return f.get("list") == lista
    return False

def _si(v):
    return str(v).strip().lower() in ("true", "yes")

def _val(v):
    """Valor comparable: el router devuelve true/false donde se le manda yes/no."""
    v = str(v)
    return {"yes": "true", "no": "false"}.get(v.lower(), v)

def _txt_red(net):
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)

def _norm_dir(txt):
    """Direccion de una address-list como la escribe el router (sin /32)."""
    try:
        return _txt_red(ipaddress.ip_network(txt.strip(), strict=False))
    except ValueError:
        return txt.strip()

def _validar_pid(pid):
    if not nodos.pid_valido(pid):
        raise DatosInvalidos("punto invalido: %r" % (pid,))
    return pid

def _validar_lista(lista):
    if not isinstance(lista, str) or not RE_LISTA.match(lista):
        raise DatosInvalidos("nombre de address-list invalido: %r" % (lista,))
    return lista

def _validar(pid, sensor, puerto, redes, lista):
    _validar_pid(pid)
    try:
        ip = ipaddress.ip_address(str(sensor).strip())
    except ValueError:
        raise DatosInvalidos("IP del sensor invalida: %r" % (sensor,))
    if ip.version != 4:
        raise DatosInvalidos("IPv6 queda fuera de esta version: sensor %s" % ip)
    try:
        puerto = int(puerto)
    except (TypeError, ValueError):
        raise DatosInvalidos("puerto TZSP invalido: %r" % (puerto,))
    if not 1 <= puerto <= 65535:
        raise DatosInvalidos("puerto TZSP fuera de rango: %d" % puerto)
    _validar_lista(lista)
    if isinstance(redes, str):
        redes = redes.split(",")
    norm = []
    for r in redes or []:
        r = str(r).strip()
        if not r:
            continue
        try:
            net = ipaddress.ip_network(r, strict=False)
        except ValueError:
            raise DatosInvalidos("red invalida: %r" % r)
        if net.version != 4:
            raise DatosInvalidos("IPv6 queda fuera de esta version: %s" % r)
        t = _txt_red(net)
        if t not in norm:
            norm.append(t)
    return pid, str(ip), puerto, norm, lista

def _condiciones(f):
    """Las condiciones de una regla (para copiar las de un fasttrack), en su orden."""
    return [(k, v) for k, v in f.items()
            if not k.startswith(".") and k not in _NO_CONDICION and v != ""]

def _clave_cond(f):
    return tuple(sorted((k, _val(v)) for k, v in _condiciones(f)))

def _rol_compania(f, lista):
    """'ida'/'vuelta' si f es una de nuestras fasttrack de los vigilados, si no None."""
    if f.get("action") != FT or f.get("connection-bytes") != CB_ACELERAR:
        return None
    s, d = f.get("src-address-list", ""), f.get("dst-address-list", "")
    if s == lista and not d:
        return "ida"
    if d == lista and not s:
        return "vuelta"
    return None


def _leer_router(s, lista, com):
    """Lo que el plan necesita del router. La address-list puede tener cientos de miles de
    entradas (listas de bloqueo): solo se leen la lista del espejo y lo nuestro."""
    ident = ""
    for f in _mk_print(s, "/system/identity/print"):
        ident = f.get("name", ident)
    al = _mk_print(s, AL + "print", consulta=["?list=" + lista])
    vistos = {f.get(".id") for f in al}
    al += [f for f in _mk_print(s, AL + "print", consulta=["?comment=" + com])
           if f.get(".id") not in vistos]
    return {"identidad": ident,
            "filter": _mk_print(s, FI + "print"),
            "mangle": _mk_print(s, MG + "print"),
            "address-list": al}


# --- el plan ----------------------------------------------------------------------------
def _calcular(s, pid, sensor, puerto, redes, lista):
    """(plan, tablas leidas). Primero se calcula TODO y despues se hace: la vista previa y
    la ejecucion salen de la MISMA lista de cambios."""
    pid, sensor, puerto, redes, lista = _validar(pid, sensor, puerto, redes, lista)
    com = comentario(pid)
    t = _leer_router(s, lista, com)

    def mio(f, tabla):
        return es_del_espejo(f, tabla, pid, lista)
    cambios, avisos, bloqueos, fasttrack = [], [], [], []

    def cambio(que, orden, args):
        cambios.append({"que": que, "orden": orden, "args": args})

    # 1) la lista de a quien se vigila
    en_lista = {}
    for f in t["address-list"]:
        if f.get("list") == lista:
            en_lista.setdefault(_norm_dir(f.get("address", "")), []).append(f)
    for r in redes:
        if r not in en_lista:
            cambio("anadir %s a la lista %s" % (r, lista), AL + "add",
                   ["=list=" + lista, "=address=" + r, "=comment=" + com])
    for f in t["address-list"]:
        dire = _norm_dir(f.get("address", ""))
        if mio(f, "address-list"):
            if f.get("list") == lista and dire in redes:
                if f.get("comment") != com:     # de una version anterior: pasa al comentario propio
                    cambio("poner el comentario del espejo a %s en la lista %s" % (dire, lista),
                           AL + "set", ["=.id=" + f[".id"], "=comment=" + com])
                continue
            cambio("quitar %s de la lista %s (ya no es una red del punto)" % (dire, f.get("list")),
                   AL + "remove", ["=.id=" + f[".id"]])
        elif f.get("list") == lista and dire not in redes:
            avisos.append("%s esta en la lista %s sin el comentario del punto: se vigila aunque no "
                          "sea una red del punto, y no se toca" % (dire, lista))
    if not redes and not any(not mio(f, "address-list") for f in t["address-list"]
                             if f.get("list") == lista):
        avisos.append("la lista %s queda VACIA: no se espejara nada hasta que el punto tenga redes"
                      % lista)

    # 2) el espejo: dos mangle, sin duplicar; antes se apagan los espejos viejos al sensor.
    # Se apagan ANTES de crear los nuevos: si el router rechaza algo a mitad, lo peor que queda
    # es un espejo de menos (se ve en el panel), nunca dos a la vez llenando el enlace.
    base = [("chain", "forward"), ("action", "sniff-tzsp"), ("sniff-target", sensor),
            ("sniff-target-port", str(puerto)), ("connection-bytes", CB_ESPEJO),
            ("passthrough", "yes")]
    quiero = [("ida", base + [("src-address-list", lista)]),
              ("vuelta", base + [("dst-address-list", lista)])]
    mias = [f for f in t["mangle"] if mio(f, "mangle")]
    for f in t["mangle"]:
        if mio(f, "mangle") or _si(f.get("disabled", "false")):
            continue
        if f.get("action") == "sniff-tzsp" and f.get("sniff-target", "").strip() == sensor:
            cambio("apagar un espejo viejo hacia este sensor (%s, comment=%r)"
                   % (f[".id"], f.get("comment", "")), MG + "set",
                   ["=.id=" + f[".id"], "=disabled=yes"])
        elif (f.get("chain") == "forward"
              and (f.get("action") == "accept"
                   or (f.get("action") != "sniff-tzsp" and not _si(f.get("passthrough", "true"))))):
            avisos.append("la regla mangle %s (forward, action=%s, passthrough=%s) termina la cadena: "
                          "lo que case no llegara al espejo" % (f[".id"], f.get("action"),
                                                               f.get("passthrough", "")))
    usadas = []
    pendientes = []
    for rol, campos in quiero:
        otro = "dst-address-list" if rol == "ida" else "src-address-list"
        quiero_f = dict(campos)
        cand = [f for f in mias if f not in usadas
                and f.get(campos[-1][0]) == lista and not f.get(otro)]
        args = ["=%s=%s" % kv for kv in campos] + ["=comment=" + com]
        if not cand:
            pendientes.append(("espejo de %s: crear" % rol, MG + "add", args))
            continue
        f = cand[0]
        usadas.append(f)
        if (all(_val(f.get(k, "")) == _val(v) for k, v in quiero_f.items())
                and not _si(f.get("disabled")) and f.get("comment") == com):
            continue
        pendientes.append(("espejo de %s: actualizar (%s)" % (rol, f[".id"]), MG + "set",
                           ["=.id=" + f[".id"]] + args + ["=disabled=no"]))
    for f in mias:
        if f not in usadas:
            cambio("quitar una regla mangle sobrante del punto (%s, action=%s)"
                   % (f[".id"], f.get("action")), MG + "remove", ["=.id=" + f[".id"]])
    for p in pendientes:
        cambio(*p)

    # 3) el fasttrack: sin excluir la lista, mangle solo ve el primer paquete
    reglas = t["filter"]
    excl = "!" + lista
    pool = []           # nuestras fasttrack de vigilados que ya estan: (clave, regla)
    sobran = []         # el resto de lo nuestro en filter
    for f in reglas:
        if not mio(f, "filter"):
            continue
        rol = _rol_compania(f, lista)
        if rol:
            pool.append(((rol, f.get("chain", ""), _clave_cond(f)), f))
        else:
            sobran.append(f)
    for i, f in enumerate(reglas):
        if mio(f, "filter"):
            continue
        src, dst = f.get("src-address-list", ""), f.get("dst-address-list", "")
        apagada = _si(f.get("disabled", "false"))
        if f.get("action") != FT:
            if lista in (src, dst) or excl in (src, dst):
                txt = ("la regla filter %s (action=%s) usa la lista %s: anadir o quitar redes cambiaria "
                       "lo que deja pasar" % (f[".id"], f.get("action"), lista))
                if apagada:
                    avisos.append(txt + " si se habilita (esta deshabilitada)")
                else:
                    bloqueos.append(txt + ". Resuelvelo a mano (otra lista) antes de montar el espejo")
            continue
        ft = {".id": f[".id"], "src-address-list": src, "dst-address-list": dst,
              "disabled": apagada}
        fasttrack.append(ft)
        if apagada:
            ft["accion"], ft["que"] = "no-se-toca", "deshabilitada: no acelera nada"
            avisos.append("la regla fasttrack %s esta deshabilitada y no se toca: si la habilitas, "
                          "vuelve a aplicar el espejo" % f[".id"])
            continue
        if src not in ("", excl) or dst not in ("", excl):
            ft["accion"], ft["que"] = "no-se-toca", "ya usa address-lists"
            avisos.append("la regla fasttrack %s ya usa address-lists (src=%r dst=%r): no se modifica; "
                          "los vigilados que acelere no se espejaran. Resuelvelo a mano"
                          % (f[".id"], src, dst))
            continue
        if f.get("connection-bytes"):
            ft["accion"], ft["que"] = "no-se-toca", "ya usa connection-bytes"
            avisos.append("la regla fasttrack %s ya usa connection-bytes=%s: no se modifica; "
                          "resuelvelo a mano" % (f[".id"], f["connection-bytes"]))
            continue
        hecha = src == excl and dst == excl
        ft["accion"] = "ya-excluida" if hecha else "excluir"
        ft["que"] = ("ya excluye a %s" % lista) if hecha else (
            "excluir %s (sus valores de ahora van al respaldo)" % lista)
        sig = next((g[".id"] for g in reglas[i + 1:] if not mio(g, "filter")), None)
        cond = _condiciones(f)
        for rol, campo in (("ida", "src-address-list"), ("vuelta", "dst-address-list")):
            clave = (rol, f.get("chain", ""), _clave_cond(f))
            ya = next((x for x in pool if x[0] == clave), None)
            if ya:
                pool.remove(ya)
                arreglo = []
                if _si(ya[1].get("disabled")):
                    arreglo.append("=disabled=no")
                if ya[1].get("comment") != com:  # de una version anterior: comentario propio
                    arreglo.append("=comment=" + com)
                if arreglo:
                    cambio("habilitar o marcar como del espejo el fasttrack de vigilados (%s) de %s"
                           % (rol, f[".id"]), FI + "set", ["=.id=" + ya[1][".id"]] + arreglo)
                continue
            args = ["=chain=" + f.get("chain", "forward"), "=action=" + FT]
            args += ["=%s=%s" % kv for kv in cond]
            args += ["=%s=%s" % (campo, lista), "=connection-bytes=" + CB_ACELERAR, "=comment=" + com]
            if sig:
                args.append("=place-before=" + sig)
            cambio("acelerar a los vigilados (%s) pasados 10 KB, detras de %s" % (rol, f[".id"]),
                   FI + "add", args)
        if not hecha:
            cambio("excluir %s del fasttrack %s (sin esto mangle solo ve el primer paquete)"
                   % (lista, f[".id"]), FI + "set",
                   ["=.id=" + f[".id"], "=src-address-list=" + excl, "=dst-address-list=" + excl])
    for f in [x[1] for x in pool] + sobran:
        cambio("quitar una regla filter del punto que ya no corresponde (%s, action=%s)"
               % (f[".id"], f.get("action")), FI + "remove", ["=.id=" + f[".id"]])

    p = {"pid": pid, "sensor": sensor, "puerto": puerto, "lista": lista, "redes": redes,
         "comentario": com, "identidad": t["identidad"], "cambios": cambios,
         "terminal": [en_terminal(c["orden"], c["args"]) for c in cambios],
         "avisos": avisos, "bloqueos": bloqueos, "fasttrack": fasttrack}
    return p, t


def plan(conexion, pid, sensor, puerto, redes, lista=LISTA):
    """Vista previa: que cambiaria en el router. No toca nada."""
    return _calcular(conexion, pid, sensor, puerto, redes, lista)[0]


# --- ejecutar ---------------------------------------------------------------------------
def _orden(s, orden, args):
    """(ok, error). Una orden sin respuesta es un fallo que no se sabe si se aplico."""
    try:
        _mk_send(s, [orden] + list(args))
        ok, _f, err = _mk_reply(s)
    except _FALLOS_RED as e:
        return False, ("sin respuesta del router (%s): puede haberse aplicado o no; vuelve a pedir "
                       "el plan, que relee el router antes de repetir nada" % e)
    return ok, err

def _marca():
    return time.strftime("%Y%m%d-%H%M%S")

def _avisar(avance, etapa, **extra):
    """Cuenta al panel por donde va (`avance(etapa=..., avance="i/N")`). Opcional: un fallo
    del que escucha no para nada en el router."""
    if avance is None:
        return
    try:
        avance(etapa=etapa, **extra)
    except Exception:
        pass

def _correr(s, cambios, res, avance=None):
    """Aplica en orden y para en el PRIMER fallo: seguir podia dejar, por ejemplo, el espejo
    nuevo creado y el viejo sin apagar. Lo hecho hasta ahi queda dicho en res."""
    for n, c in enumerate(cambios):
        _avisar(avance, "orden %d/%d" % (n + 1, len(cambios)), avance_n="%d/%d" % (n, len(cambios)))
        ok, err = _orden(s, c["orden"], c["args"])
        if not ok:
            res["fallo"] = "%s: %s" % (c["que"], err or "rechazado")
            res["sin_aplicar"] = [x["que"] for x in cambios[n:]]
            return res
        res["hechos"].append(c["que"])
    res["ok"] = True
    return res

def _exportar(s, pid, res, avance=None):
    """Respaldo en el router (/export file=...). Sin el, no se toca nada."""
    _avisar(avance, "export")
    nombre = "ids-maat-%s-%s" % (pid, _marca())
    ok, err = _orden(s, "/export", ["=file=" + nombre])
    if not ok:
        res["fallo"] = "fallo el respaldo /export en el router (%s): no se ha tocado nada" % (err or "?")
        return False
    res["export"] = nombre
    return True

def _orden_respaldo(ruta):
    """Clave para ordenar espejo-AAAAMMDD-HHMMSS[-n].json por fecha y numero."""
    b = os.path.basename(ruta)[len("espejo-"):-len(".json")]
    ts, _, n = b[:15], b[15:16], b[16:]
    return (ts, int(n) if n.isdigit() else 0)

def ultimo_respaldo(respaldo_dir, pid):
    """La ruta del JSON de respaldo mas reciente del punto, o None."""
    _validar_pid(pid)
    rs = glob.glob(os.path.join(respaldo_dir, pid, "espejo-*.json"))
    return max(rs, key=_orden_respaldo) if rs else None

def _originales_previos(d, ftid):
    """Valores originales de un fasttrack que ya estaba excluido, de un respaldo anterior."""
    for ruta in sorted(glob.glob(os.path.join(d, "espejo-*.json")), key=_orden_respaldo, reverse=True):
        try:
            with open(ruta, encoding="utf-8") as fh:
                v = (json.load(fh).get("fasttrack") or {}).get(ftid)
        except (OSError, ValueError, AttributeError):
            continue
        if isinstance(v, dict):
            return v
    return None

def _guardar_respaldo(respaldo_dir, p, t, nombre, fecha):
    d = os.path.join(respaldo_dir, p["pid"])
    os.makedirs(d, mode=0o700, exist_ok=True)
    originales = {}
    for ft in p["fasttrack"]:
        if ft["accion"] == "excluir":
            originales[ft[".id"]] = {"src-address-list": ft["src-address-list"],
                                     "dst-address-list": ft["dst-address-list"]}
        elif ft["accion"] == "ya-excluida":
            # aplicado antes: su original de verdad esta en el respaldo de entonces. Sin el,
            # no se inventa (retirar() quita los dos !<lista>).
            v = _originales_previos(d, ft[".id"])
            if v is not None:
                originales[ft[".id"]] = v
    datos = {"pid": p["pid"], "fecha": fecha,
             "export": nombre, "identidad": p["identidad"], "lista": p["lista"],
             "sensor": p["sensor"], "puerto": p["puerto"], "redes": p["redes"],
             "comentario": p["comentario"], "filter": t["filter"], "mangle": t["mangle"],
             "address-list": t["address-list"], "fasttrack": originales, "cambios": p["cambios"]}
    texto = json.dumps(datos, indent=1, ensure_ascii=False)
    base = os.path.join(d, "espejo-" + fecha)
    for n in range(100):
        ruta = base + (("-%d" % n) if n else "") + ".json"
        try:
            fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(texto)
            fh.flush()
            os.fsync(fh.fileno())
        return ruta
    raise OSError("no hay nombre libre para el respaldo en %s" % d)


def _firma(p):
    return [(c["orden"], list(c["args"])) for c in (p.get("cambios") or [])]


def _con_mensaje(fn):
    """Las tres que tocan el router devuelven ademas `mensaje` (una linea para la pantalla) y
    `lineas` (lo hecho y lo que quedo sin aplicar), como espera el panel."""
    import functools

    @functools.wraps(fn)
    def envuelta(*a, **k):
        res = fn(*a, **k)
        lineas = ["hecho: %s" % x for x in res.get("hechos") or []]
        lineas += ["SIN APLICAR: %s" % x for x in res.get("sin_aplicar") or []]
        if res.get("fallo"):
            res["mensaje"] = res["fallo"]
        elif res.get("hechos"):
            res["mensaje"] = "hecho: %d cambio(s) en el router" % len(res["hechos"])
        else:
            res["mensaje"] = "nada que cambiar: el router ya estaba como debe"
        res["lineas"] = lineas
        res.setdefault("avisos", [])
        return res
    return envuelta


@_con_mensaje
def aplicar(conexion, plan, respaldo_dir, avance=None):
    """Aplica el plan si el router sigue como en la vista previa (ver el docstring del modulo).
    `avance` (opcional) recibe las etapas: verificar, respaldo, export y orden i/N."""
    res = {"ok": False, "hechos": [], "fallo": None, "sin_aplicar": [], "respaldo": None,
           "export": None, "plan": None}
    _avisar(avance, "verificar")
    try:
        actual, t = _calcular(conexion, plan["pid"], plan["sensor"], plan["puerto"],
                              plan["redes"], plan.get("lista", LISTA))
    except (KeyError, TypeError, AttributeError):
        res["fallo"] = "plan incompleto: vuelve a pedir la vista previa"
        return res
    except ErrorEspejo as e:
        res["fallo"] = str(e)
        return res
    if _firma(actual) != _firma(plan):
        res["fallo"] = ("el router cambio desde la vista previa: no se ha tocado nada. Revisa el "
                        "plan nuevo y vuelve a aplicar")
        res["plan"] = actual
        return res
    if actual["bloqueos"]:
        res["fallo"] = "no se aplica: " + "; ".join(actual["bloqueos"])
        return res
    if not actual["cambios"]:
        res["ok"] = True
        return res
    fecha = _marca()
    nombre = "ids-maat-%s-%s" % (actual["pid"], fecha)
    _avisar(avance, "respaldo")
    try:
        res["respaldo"] = _guardar_respaldo(respaldo_dir, actual, t, nombre, fecha)
    except (OSError, TypeError, ValueError) as e:
        res["fallo"] = "no se pudo guardar el respaldo local (%s): no se ha tocado nada" % e
        return res
    _avisar(avance, "export")
    ok, err = _orden(conexion, "/export", ["=file=" + nombre])
    if not ok:
        res["fallo"] = "fallo el respaldo /export en el router (%s): no se ha tocado nada" % (err or "?")
        return res
    res["export"] = nombre
    return _correr(conexion, actual["cambios"], res, avance)


@_con_mensaje
def pausar(conexion, pid, respaldo_dir=None, avance=None):
    """Deshabilita los dos mangle del punto. El fasttrack queda como esta. Con `respaldo_dir`,
    antes guarda tambien la copia local de esos mangle (`<respaldo_dir>/<pid>/pausa-*.json`)."""
    res = {"ok": False, "hechos": [], "fallo": None, "sin_aplicar": [], "export": None,
           "respaldo": None}
    _validar_pid(pid)
    try:
        mg = _mangle_del_espejo(conexion, pid)
    except ErrorRouter as e:
        res["fallo"] = str(e)
        return res
    cambios = [{"que": "pausar el espejo %s" % f[".id"], "orden": MG + "set",
                "args": ["=.id=" + f[".id"], "=disabled=yes"]}
               for f in mg if not _si(f.get("disabled", "false"))]
    if not cambios:
        res["ok"] = True
        return res
    if respaldo_dir:
        try:
            res["respaldo"] = _guardar_pausa(respaldo_dir, pid, mg)
        except (OSError, TypeError, ValueError) as e:
            res["fallo"] = "no se pudo guardar el respaldo local (%s): no se ha tocado nada" % e
            return res
    if not _exportar(conexion, pid, res, avance):
        return res
    return _correr(conexion, cambios, res, avance)


def _mangle_del_espejo(conexion, pid):
    """Los mangle del espejo del punto (comentario propio, o el del alta con sniff-tzsp)."""
    vistos, out = set(), []
    for com in (comentario(pid), comentario_alta(pid)):
        for f in _mk_print(conexion, MG + "print", consulta=["?comment=" + com]):
            if f.get(".id") not in vistos and es_del_espejo(f, "mangle", pid):
                vistos.add(f.get(".id"))
                out.append(f)
    return out


def _guardar_pausa(respaldo_dir, pid, mangle):
    d = os.path.join(respaldo_dir, pid)
    os.makedirs(d, mode=0o700, exist_ok=True)
    ruta = os.path.join(d, "pausa-%s.json" % _marca())
    fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"pid": pid, "mangle": mangle}, fh, indent=1, ensure_ascii=False)
    return ruta


def _cargar_respaldo(respaldo, pid=None):
    if respaldo is None:
        return {}
    if isinstance(respaldo, str) and os.path.isdir(respaldo):
        # el directorio de respaldos del panel: vale el ultimo JSON del espejo de ese punto QUE SE
        # PUEDA LEER; uno corrupto (corte a mitad, disco lleno) no bloquea retirar (A-21): se usa
        # el anterior valido
        if not pid:
            return {}
        _validar_pid(pid)
        rutas = sorted(glob.glob(os.path.join(respaldo, pid, "espejo-*.json")),
                       key=_orden_respaldo, reverse=True)
        for ruta in rutas:
            try:
                with open(ruta, encoding="utf-8") as fh:
                    d = json.load(fh)
            except (OSError, ValueError):
                continue
            if isinstance(d, dict) and isinstance(d.get("fasttrack", {}), dict):
                return d
        return {}
    if isinstance(respaldo, dict):
        return respaldo
    try:
        with open(respaldo, encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError, TypeError) as e:
        raise DatosInvalidos("no se puede leer el respaldo %r: %s" % (respaldo, e))
    if not isinstance(d, dict):
        raise DatosInvalidos("el respaldo %r no es un respaldo del espejo" % (respaldo,))
    return d


def plan_retirar(conexion, pid, respaldo=None, lista=None):
    """Que haria retirar(). No toca nada."""
    _validar_pid(pid)
    resp = _cargar_respaldo(respaldo, pid)
    if resp.get("pid") not in (None, pid):
        raise DatosInvalidos("el respaldo es del punto %s, no de %s" % (resp.get("pid"), pid))
    lista = _validar_lista(lista or resp.get("lista") or LISTA)
    originales = resp.get("fasttrack") or {}
    if not isinstance(originales, dict):
        raise DatosInvalidos("el respaldo no trae los valores del fasttrack")
    com = comentario(pid)
    excl = "!" + lista
    reglas = _mk_print(conexion, FI + "print")
    mg = _mangle_del_espejo(conexion, pid)
    al = _mk_print(conexion, AL + "print", consulta=["?comment=" + com])
    vistos = {f.get(".id") for f in al}
    al += [f for f in _mk_print(conexion, AL + "print", consulta=["?comment=" + comentario_alta(pid)])
           if f.get(".id") not in vistos and es_del_espejo(f, "address-list", pid, lista)]
    cambios, avisos = [], []

    def cambio(que, orden, args):
        cambios.append({"que": que, "orden": orden, "args": args})

    for f in mg:
        cambio("quitar el espejo %s" % f[".id"], MG + "remove", ["=.id=" + f[".id"]])
    ids = {f.get(".id") for f in reglas}
    for f in reglas:
        if es_del_espejo(f, "filter", pid, lista) or f.get("action") != FT:
            continue
        orig = originales.get(f[".id"])
        campos = ("src-address-list", "dst-address-list")
        if isinstance(orig, dict):
            for campo in campos:
                ahora, antes = f.get(campo, ""), orig.get(campo, "") or ""
                if ahora == antes:
                    continue
                if ahora != excl:
                    avisos.append("el fasttrack %s tiene %s=%r, que no puso el espejo: no se toca"
                                  % (f[".id"], campo, ahora))
                    continue
                if antes:
                    cambio("devolver %s=%s al fasttrack %s" % (campo, antes, f[".id"]), FI + "set",
                           ["=.id=" + f[".id"], "=%s=%s" % (campo, antes)])
                else:
                    cambio("quitar %s del fasttrack %s (no tenia)" % (campo, f[".id"]), FI + "unset",
                           ["=numbers=" + f[".id"], "=value-name=" + campo])
        elif all(f.get(c, "") == excl for c in campos):
            for campo in campos:
                cambio("quitar %s=%s del fasttrack %s" % (campo, excl, f[".id"]), FI + "unset",
                       ["=numbers=" + f[".id"], "=value-name=" + campo])
        elif excl in (f.get(c, "") for c in campos):
            avisos.append("el fasttrack %s tiene %s solo en un campo y no esta en el respaldo "
                          "(quiza del instalador anterior): no se toca" % (f[".id"], excl))
    for ftid in originales:
        if ftid not in ids:
            avisos.append("el fasttrack %s del respaldo ya no existe en el router" % ftid)
    for f in reglas:
        if es_del_espejo(f, "filter", pid, lista):
            cambio("quitar la regla filter %s del espejo" % f[".id"], FI + "remove", ["=.id=" + f[".id"]])
    for f in al:
        if es_del_espejo(f, "address-list", pid, lista):
            cambio("quitar %s de la lista %s" % (f.get("address"), f.get("list")), AL + "remove",
                   ["=.id=" + f[".id"]])
    return {"pid": pid, "lista": lista, "cambios": cambios,
            "terminal": [en_terminal(c["orden"], c["args"]) for c in cambios], "avisos": avisos}


@_con_mensaje
def retirar(conexion, pid, respaldo=None, lista=None, avance=None):
    """Quita todo lo del espejo del punto y devuelve el fasttrack a como estaba."""
    res = {"ok": False, "hechos": [], "fallo": None, "sin_aplicar": [], "export": None,
           "avisos": [], "cambios": []}
    try:
        p = plan_retirar(conexion, pid, respaldo, lista)
    except ErrorEspejo as e:
        res["fallo"] = str(e)
        return res
    res["avisos"], res["cambios"] = p["avisos"], p["cambios"]
    if not p["cambios"]:
        res["ok"] = True
        return res
    if not _exportar(conexion, pid, res, avance):
        return res
    return _correr(conexion, p["cambios"], res, avance)
