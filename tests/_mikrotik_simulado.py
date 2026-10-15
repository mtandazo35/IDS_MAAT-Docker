"""MikroTik de mentira para las pruebas del espejo (tests/test_mkinit_*.py).

Habla el protocolo binario real de la API de RouterOS por un socket falso (sendall/recv/
close/settimeout), con una implementacion propia (no la del modulo que se prueba), y guarda
las tablas /ip/firewall/filter, /mangle y /address-list con `.id` `*1`, `*2`... en hexadecimal
como el router. Soporta print (con `=.proplist=` y consultas `?campo=valor`, `?campo`,
`?-campo`), add (con place-before), set, unset, remove, /export y /system/identity/print, y
contesta !trap a lo que el router rechaza (duplicado en address-list, `.id` inexistente).

Fallos a proposito: `fallar_en = N` (la N-esima escritura desde que se pone contesta !trap),
`colgar_en = N` (la N-esima escritura SE APLICA y la conexion se queda callada: recv lanza
socket.timeout), `fallar_export`, `fallar_print = "<ruta>/print"`.

EVALUADOR de paquetes (paquete()): mangle forward decide si se espeja (sniff-tzsp) y despues
la cadena forward de filter en orden; `fasttrack-connection` marca la conexion como acelerada
y NO termina; accept/drop/reject terminan; al final, accept. Los paquetes de una conexion ya
acelerada se saltan filter y mangle (veredicto accept, sin espejo). connection-bytes `a-b` es
inclusivo y `b=0` es sin tope; `!` niega. Una condicion que no sabe evaluar es un error (para
que una prueba no pase por accidente).
"""
import copy
import ipaddress
import socket

TABLAS = ("/ip/firewall/filter", "/ip/firewall/mangle", "/ip/firewall/address-list")
_BOOLEANOS = {"disabled", "passthrough", "hw-offload", "log", "dynamic", "invalid"}
_NO_COND = {".id", "chain", "action", "comment", "disabled", "dynamic", "invalid", "bytes",
            "packets", "log", "log-prefix", "hw-offload", "passthrough", "sniff-target",
            "sniff-target-port", "new-connection-mark"}


def _codificar(palabra):
    b = palabra.encode("utf-8")
    n = len(b)
    if n < 0x80:
        pre = bytes([n])
    elif n < 0x4000:
        pre = (n | 0x8000).to_bytes(2, "big")
    elif n < 0x200000:
        pre = (n | 0xC00000).to_bytes(3, "big")
    else:
        pre = (n | 0xE0000000).to_bytes(4, "big")
    return pre + b


def _decodificar(buf):
    """(palabras de UNA sentencia, bytes consumidos) o (None, 0) si aun no esta entera."""
    i, palabras = 0, []
    while True:
        if i >= len(buf):
            return None, 0
        c = buf[i]
        if c & 0x80 == 0:
            n, k = c, 1
        elif c & 0xC0 == 0x80:
            k = 2
        elif c & 0xE0 == 0xC0:
            k = 3
        elif c & 0xF0 == 0xE0:
            k = 4
        else:
            k = 5
        if i + k > len(buf):
            return None, 0
        if k > 1:
            raw = int.from_bytes(buf[i:i + k], "big")
            n = raw & {2: 0x3FFF, 3: 0x1FFFFF, 4: 0x0FFFFFFF}.get(k, 0xFFFFFFFF)
            if k == 5:
                n = int.from_bytes(buf[i + 1:i + 5], "big")
        i += k
        if n == 0:
            return palabras, i
        if i + n > len(buf):
            return None, 0
        palabras.append(buf[i:i + n].decode("utf-8"))
        i += n


def _bool(v):
    return {"yes": "true", "no": "false"}.get(str(v).lower(), str(v).lower())


def _dir(txt):
    try:
        net = ipaddress.ip_network(txt.strip(), strict=False)
    except ValueError:
        return txt
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)


class _Trap(Exception):
    pass


class RouterSimulado:
    def __init__(self, identidad="router-lab"):
        self.identidad = identidad
        self.tablas = {t: [] for t in TABLAS}
        self._sig = 1
        self.exports = []
        self.escrituras = []        # (orden, palabras) aceptadas (add/set/unset/remove)
        self.fallar_en = None
        self.colgar_en = None
        self.fallar_export = False
        self.fallar_print = None
        self._n = 0
        self.colgado = False
        self.aceleradas = set()

    # --- estado ------------------------------------------------------------------------
    def cargar(self, tabla, filas):
        """Mete filas (dicts) al final de la tabla, como hechas a mano. Devuelve sus .id."""
        return [self._anadir(tabla, dict(f)) for f in filas]

    def _anadir(self, tabla, campos, antes=None):
        fila = {".id": "*%X" % self._sig}
        self._sig += 1
        if tabla == "/ip/firewall/address-list":
            fila.update({"list": "", "address": "", "disabled": "false", "dynamic": "false"})
        else:
            fila.update({"chain": "", "action": "", "disabled": "false", "dynamic": "false",
                         "invalid": "false", "log": "false", "log-prefix": "",
                         "bytes": "0", "packets": "0"})
        for k, v in campos.items():
            fila[k] = _bool(v) if k in _BOOLEANOS else v
        if tabla == "/ip/firewall/address-list":
            fila["address"] = _dir(fila["address"])
        filas = self.tablas[tabla]
        if antes is None:
            filas.append(fila)
        else:
            pos = [f[".id"] for f in filas].index(antes)
            filas.insert(pos, fila)
        return fila[".id"]

    def instantanea(self):
        return copy.deepcopy(self.tablas)

    def fila(self, tabla, rid):
        return next((f for f in self.tablas[tabla] if f[".id"] == rid), None)

    def conexion(self):
        self.colgado = False
        return ConexionSimulada(self)

    # --- la API ------------------------------------------------------------------------
    def ejecutar(self, palabras):
        """Lista de sentencias de respuesta, o None si el router se queda callado."""
        orden, args = palabras[0], palabras[1:]
        try:
            return self._ejecutar(orden, args)
        except _Trap as e:
            return [["!trap", "=message=" + str(e)], ["!done"]]

    def _ejecutar(self, orden, args):
        attrs, consultas = {}, []
        for a in args:
            if a.startswith("="):
                k, _, v = a[1:].partition("=")
                attrs[k] = v
            elif a.startswith("?"):
                consultas.append(a[1:])
        if orden == "/system/identity/print":
            return [["!re", "=name=" + self.identidad], ["!done"]]
        if orden == "/export":
            if self.fallar_export:
                raise _Trap("failure: not enough space")
            self.exports.append(attrs.get("file", ""))
            return [["!done"]]
        tabla, _, verbo = orden.rpartition("/")
        if tabla not in self.tablas:
            raise _Trap("no such command prefix")
        if verbo == "print":
            if self.fallar_print == orden:
                raise _Trap("failure: print rechazado a proposito")
            return self._print(tabla, attrs, consultas)
        if verbo not in ("add", "set", "unset", "remove"):
            raise _Trap("no such command")
        self._n += 1
        if self.fallar_en is not None and self._n == self.fallar_en:
            raise _Trap("failure: fallo inyectado en la escritura %d" % self._n)
        resp = getattr(self, "_" + verbo)(tabla, attrs)
        self.escrituras.append((orden, list(args)))
        if self.colgar_en is not None and self._n == self.colgar_en:
            self.colgado = True
            return None
        return resp

    def _print(self, tabla, attrs, consultas):
        props = [p for p in attrs.get(".proplist", "").split(",") if p and p != "*"]
        out = []
        for f in self.tablas[tabla]:
            ok = True
            for q in consultas:
                if q.startswith("-"):
                    ok = ok and q[1:] not in f
                elif "=" in q:
                    k, v = q.split("=", 1)
                    ok = ok and f.get(k) == v
                else:
                    ok = ok and q in f
            if not ok:
                continue
            claves = props or list(f)
            out.append(["!re"] + ["=%s=%s" % (k, f[k]) for k in claves if k in f])
        return out + [["!done"]]

    def _buscar(self, tabla, attrs):
        rid = attrs.get(".id") or attrs.get("numbers")
        f = self.fila(tabla, rid) if rid else None
        if f is None:
            raise _Trap("no such item")
        return f

    def _add(self, tabla, attrs):
        antes = attrs.pop("place-before", None)
        if antes is not None and self.fila(tabla, antes) is None:
            raise _Trap("no such item (place-before)")
        if tabla == "/ip/firewall/address-list":
            if any(f["list"] == attrs.get("list") and f["address"] == _dir(attrs.get("address", ""))
                   for f in self.tablas[tabla]):
                raise _Trap("failure: already have such entry")
        elif not attrs.get("chain") or not attrs.get("action"):
            raise _Trap("failure: chain/action not set")
        rid = self._anadir(tabla, attrs, antes)
        return [["!done", "=ret=" + rid]]

    def _set(self, tabla, attrs):
        f = self._buscar(tabla, attrs)
        for k, v in attrs.items():
            if k in (".id", "numbers"):
                continue
            f[k] = _bool(v) if k in _BOOLEANOS else v
        return [["!done"]]

    def _unset(self, tabla, attrs):
        f = self._buscar(tabla, attrs)
        f.pop(attrs.get("value-name", ""), None)
        return [["!done"]]

    def _remove(self, tabla, attrs):
        f = self._buscar(tabla, attrs)
        self.tablas[tabla].remove(f)
        return [["!done"]]

    # --- el evaluador de paquetes ------------------------------------------------------
    def _en_lista(self, ip, lista):
        a = ipaddress.ip_address(ip)
        for f in self.tablas["/ip/firewall/address-list"]:
            if f["list"] == lista and f.get("disabled") != "true":
                try:
                    if a in ipaddress.ip_network(f["address"], strict=False):
                        return True
                except ValueError:
                    pass
        return False

    def _casa(self, regla, p):
        for k, v in regla.items():
            if k in _NO_COND or v == "":
                continue
            neg = v.startswith("!")
            val = v[1:] if neg else v
            if k == "src-address":
                r = ipaddress.ip_address(p["src"]) in ipaddress.ip_network(val, strict=False)
            elif k == "dst-address":
                r = ipaddress.ip_address(p["dst"]) in ipaddress.ip_network(val, strict=False)
            elif k == "src-address-list":
                r = self._en_lista(p["src"], val)
            elif k == "dst-address-list":
                r = self._en_lista(p["dst"], val)
            elif k == "protocol":
                r = p.get("proto", "tcp") == val
            elif k == "dst-port":
                r = str(p.get("dport", 0)) in val.split(",")
            elif k == "connection-state":
                r = p.get("estado", "new") in val.split(",")
            elif k == "connection-bytes":
                a, b = (int(x) for x in val.split("-"))
                r = a <= p.get("bytes", 0) and (b == 0 or p.get("bytes", 0) <= b)
            elif k == "in-interface":
                r = p.get("in_if", "") == val
            elif k == "out-interface":
                r = p.get("out_if", "") == val
            elif k == "connection-mark":
                r = p.get("marca", "no-mark") == val
            else:
                raise NotImplementedError("condicion no simulada: %s" % k)
            if neg:
                r = not r
            if not r:
                return False
        return True

    def paquete(self, conn, **p):
        """Veredicto de un paquete de la conexion `conn` que atraviesa el router (forward).
        p: src, dst, proto, dport, estado, bytes (de la conexion hasta ahora), in_if, out_if,
        marca. Devuelve {"veredicto": "accept"|"drop", "espejo": [(sensor, puerto)...],
        "acelerada": bool (si ya iba acelerada antes de este paquete)}."""
        if conn in self.aceleradas:
            return {"veredicto": "accept", "espejo": [], "acelerada": True}
        espejo = []
        for r in self.tablas["/ip/firewall/mangle"]:
            if r.get("chain") != "forward" or r.get("disabled") == "true" or not self._casa(r, p):
                continue
            if r.get("action") == "sniff-tzsp":
                espejo.append((r.get("sniff-target"), r.get("sniff-target-port")))
                if r.get("passthrough", "true") == "false":
                    break
            elif r.get("action") == "accept" or r.get("passthrough", "true") == "false":
                break
        veredicto = "accept"
        for r in self.tablas["/ip/firewall/filter"]:
            if r.get("chain") != "forward" or r.get("disabled") == "true" or not self._casa(r, p):
                continue
            a = r.get("action")
            if a == "fasttrack-connection":
                self.aceleradas.add(conn)
            elif a == "accept":
                break
            elif a in ("drop", "reject", "tarpit"):
                veredicto = "drop"
                break
        return {"veredicto": veredicto, "espejo": espejo, "acelerada": False}


class ConexionSimulada:
    """El socket que recibe mikrotik_init: bytes de la API en los dos sentidos."""

    def __init__(self, router):
        self.router = router
        self._entrada = b""
        self._salida = b""
        self.cerrada = False
        self.timeout = None

    def settimeout(self, t):
        self.timeout = t

    def sendall(self, datos):
        if self.cerrada:
            raise OSError("socket cerrado")
        self._entrada += datos
        while True:
            palabras, n = _decodificar(self._entrada)
            if palabras is None:
                return
            self._entrada = self._entrada[n:]
            if not palabras:
                continue
            resp = self.router.ejecutar(palabras)
            if resp is None:
                continue
            for frase in resp:
                self._salida += b"".join(_codificar(w) for w in frase) + b"\x00"

    def recv(self, n):
        if self.cerrada:
            raise OSError("socket cerrado")
        if not self._salida:
            if self.router.colgado:
                raise socket.timeout("timed out")
            raise socket.timeout("timed out (nada que leer)")
        out, self._salida = self._salida[:n], self._salida[n:]
        return out

    def close(self):
        self.cerrada = True


# --- tabla y trafico de las pruebas (RFC 5737 / 10.x) -----------------------------------
SENSOR = "192.0.2.10"
PUERTO = 37008
REDES = ["10.0.0.0/24", "10.0.1.0/24"]
LAN, WAN = "ether2", "ether1"
REMOTO = "198.51.100.20"


def router_isp(con_fasttrack=True, extra_filter=(), extra_mangle=(), extra_al=()):
    """Un router de ISP realista: fasttrack established,related; accept established,related;
    drop invalid; drop de la cuarentena DETRAS del fasttrack; accept de la LAN; drop final.
    Mas reglas ajenas con comentarios parecidos a los del espejo."""
    r = RouterSimulado()
    r.cargar("/ip/firewall/address-list", [
        {"list": "cuarentena", "address": "10.0.0.66", "comment": "cuarentena manual"},
        {"list": "cuarentena", "address": "10.0.5.66", "comment": "cuarentena manual"},
        {"list": "otros", "address": "10.0.7.0/24", "comment": "IDS ids-maat:p0031"},
        {"list": "ids-vigilados", "address": "10.0.9.0/24", "comment": "IDS ids-maat:p004"},
    ] + list(extra_al))
    r.cargar("/ip/firewall/filter", [
        {"chain": "input", "action": "accept", "connection-state": "established,related",
         "comment": "defconf: accept established"},
    ])
    if con_fasttrack:
        r.cargar("/ip/firewall/filter", [
            {"chain": "forward", "action": "fasttrack-connection",
             "connection-state": "established,related", "hw-offload": "yes",
             "comment": "defconf: fasttrack"}])
    r.cargar("/ip/firewall/filter", [
        {"chain": "forward", "action": "accept", "connection-state": "established,related",
         "comment": "defconf: accept established,related"},
        {"chain": "forward", "action": "drop", "connection-state": "invalid",
         "comment": "defconf: drop invalid"},
        {"chain": "forward", "action": "drop", "src-address-list": "cuarentena",
         "comment": "Suricata cuarentena"},
        {"chain": "forward", "action": "passthrough", "comment": "IDS ids-maat:p0031"},
        {"chain": "forward", "action": "passthrough", "comment": "IDS ids-maat:p004"},
        {"chain": "forward", "action": "accept", "src-address": "10.0.0.0/16", "comment": "LAN"},
    ] + list(extra_filter) + [
        {"chain": "forward", "action": "drop", "comment": "drop final"},
    ])
    r.cargar("/ip/firewall/mangle", [
        {"chain": "forward", "action": "mark-connection", "new-connection-mark": "cli",
         "passthrough": "yes", "connection-state": "new", "comment": "ids-maat:p0031"},
        {"chain": "forward", "action": "sniff-tzsp", "sniff-target": "203.0.113.9",
         "sniff-target-port": "37008", "comment": "IDS ids-maat:p004"},
    ] + list(extra_mangle))
    return r


def con_alta(router, pid="p003", sensor=SENSOR, api_puerto=8729):
    """Lo que un alta de versiones anteriores dejaba en el router (el script de hoy ya no lleva
    firewall, 2026-10-15, pero esos routers la conservan): la regla `chain=input` que acepta la
    API-SSL desde el sensor por el tunel, PRIMERA de la tabla, con el comentario del alta
    `IDS ids-maat:<pid>`. No es del espejo: aplicar, pausar y retirar el espejo no la tocan
    (auditoria A-02). Devuelve su .id."""
    primera = router.tablas["/ip/firewall/filter"][0][".id"] if router.tablas["/ip/firewall/filter"] else None
    return router._anadir("/ip/firewall/filter", {
        "chain": "input", "in-interface": "ids-vpn", "src-address": sensor, "protocol": "tcp",
        "dst-port": str(api_puerto), "action": "accept", "comment": "IDS ids-maat:%s" % pid},
        antes=primera)


CLIENTES = {
    "vigilado": "10.0.0.5",
    "vigilado-2": "10.0.1.7",
    "vigilado-cuarentena": "10.0.0.66",
    "no-vigilado": "10.0.5.9",
    "no-vigilado-cuarentena": "10.0.5.66",
}


def bateria():
    """Conexiones (nombre, cliente, [paquetes]) en las dos direcciones, por debajo y por
    encima de 10 KB, nuevas, establecidas e invalidas. Cada paquete es un dict de paquete()."""
    out = []
    for nombre, ip in CLIENTES.items():
        sube = dict(src=ip, dst=REMOTO, in_if=LAN, out_if=WAN, proto="tcp", dport=443)
        baja = dict(src=REMOTO, dst=ip, in_if=WAN, out_if=LAN, proto="tcp", dport=443)
        out.append(("%s:tcp-saliente" % nombre, ip, [
            dict(sube, estado="new", bytes=0),
            dict(baja, estado="established", bytes=300),
            dict(sube, estado="established", bytes=4000),
            dict(baja, estado="established", bytes=9000),
            dict(sube, estado="established", bytes=12000),
            dict(baja, estado="established", bytes=30000),
            dict(sube, estado="established", bytes=60000),
        ]))
        out.append(("%s:entrante" % nombre, ip, [
            dict(baja, estado="new", bytes=0, dport=22),
            dict(baja, estado="invalid", bytes=100, dport=22),
        ]))
        out.append(("%s:udp" % nombre, ip, [
            dict(sube, proto="udp", dport=53, estado="new", bytes=0),
            dict(baja, proto="udp", dport=53, estado="established", bytes=200),
            dict(sube, proto="udp", dport=53, estado="established", bytes=15000),
        ]))
    return out


def recorrer(router, conexiones):
    """{(conexion, n): resultado de paquete()} con las aceleraciones a cero."""
    router.aceleradas = set()
    res = {}
    for nombre, _ip, paquetes in conexiones:
        for n, p in enumerate(paquetes):
            res[(nombre, n)] = router.paquete(nombre, **p)
    return res
