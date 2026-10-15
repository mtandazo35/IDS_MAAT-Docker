"""Ayudante de las pruebas del núcleo del panel (constructor N): dashboard.py con nodos.

`Arbol(raiz)` monta un árbol temporal completo y aislado:
  run/estado.json      p001 «norte» y p002 «sur», los dos activos, con la MISMA red 10.0.0.0/24
  datos/p00X/eve.json  la MISMA IP 10.0.0.5 con el MISMO flujo (alertas recientes) en los dos
  panel/               vacío (lo crea nodos.asegurar_dirs)
  secrets/master_key   clave maestra de prueba (32 bytes en hex)

`cargar(arbol)` pone el entorno (IDS_PANEL_DIR, IDS_DATOS, IDS_RUN, IDS_MASTER_KEY, IDS_TZ,
IDS_ORQ_*) y vuelve a importar nodos, secretos y dashboard desde cero, de forma que todas las
rutas del módulo caen dentro del árbol. El módulo queda en sys.modules["dashboard"] (el CLI lo
importa por ese nombre). `restaurar()` deja el entorno como estaba.

Solo stdlib (+ `cryptography`, que ya exige secretos.py). Datos RFC 5737 / 10.x.
"""

import importlib
import importlib.util
import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
LIB = os.path.join(REPO, "images", "panel", "rootfs", "usr", "local", "lib", "ids-panel")
if LIB not in sys.path:
    sys.path.insert(0, LIB)

IP = "10.0.0.5"
DESTINO = "203.0.113.9"
VARS = ("IDS_PANEL_DIR", "IDS_DATOS", "IDS_RUN", "IDS_SHARE", "IDS_MASTER_KEY", "IDS_TZ",
        "IDS_ORQ_SOCK", "IDS_ORQ_TOKEN", "IDS_PROXY", "IDS_PUERTO", "IDS_EMPRESA", "TZ")
_ENV0 = {k: os.environ.get(k) for k in VARS}


def marca(segundos_atras=0):
    t = datetime.now(timezone.utc) - timedelta(seconds=segundos_atras)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"


def alerta(src=IP, dst=DESTINO, dport=443, firma="ET MALWARE Botnet CnC Checkin", sid=2000001,
           hace=30):
    return json.dumps({"timestamp": marca(hace), "event_type": "alert", "src_ip": src,
                       "src_port": 51000, "dest_ip": dst, "dest_port": dport, "proto": "TCP",
                       "in_iface": "ids-in",
                       "alert": {"signature": firma, "signature_id": sid, "severity": 1}},
                      separators=(",", ":"))


def punto(nombre, n):
    return {"nombre": nombre, "n": n, "deseado": "activo", "estado": "activo",
            "redes": ["10.0.0.0/24"], "api_puerto": 8729, "sensor": "100.64.%d.1" % n,
            "mk": "100.64.%d.2" % n, "tzsp_puerto": 37008,
            "contenedores": {"vpn": {"estado": "running", "salud": "healthy"},
                             "suricata": {"estado": "running", "salud": "healthy"}},
            "vpn_cliente": {"conectado": True, "desde": int(time.time()) - 600,
                            "ip_real": "198.51.100.%d" % (10 + n), "usuario": "ids-vpn"},
            "tzsp": {"edad_s": 5, "rx": 1200, "tx": 1100, "rechazados": 0},
            "suricata": {"stats_edad_s": 5, "reglas_cargadas": 40000, "reglas_fallidas": 0,
                         "kernel_packets": 100000, "kernel_drops": 10},
            "avisos": []}


class Arbol:
    def __init__(self, raiz, puntos=None):
        self.raiz = raiz
        self.run = os.path.join(raiz, "run")
        self.datos = os.path.join(raiz, "datos")
        self.panel = os.path.join(raiz, "panel")
        self.share = os.path.join(raiz, "share")
        self.clave = os.path.join(raiz, "secrets", "master_key")
        for d in (self.run, self.datos, self.panel, self.share, os.path.dirname(self.clave)):
            os.makedirs(d, exist_ok=True)
        with open(self.clave, "w", encoding="ascii") as f:
            f.write("5a" * 32 + "\n")
        with open(os.path.join(raiz, "secrets", "orq_token"), "w", encoding="ascii") as f:
            f.write("f" * 64 + "\n")
        self.puntos = puntos if puntos is not None else {"p001": punto("norte", 1), "p002": punto("sur", 2)}
        self.escribir_estado()
        for pid in self.puntos:
            self.eve(pid, [alerta(), alerta(hace=20), alerta(hace=10)])

    def escribir_estado(self, ts=None):
        est = {"v": 1, "ts": int(ts if ts is not None else time.time()), "version": "prueba",
               "disco": {"srv_ids_libre_pct": 70.0}, "puntos": self.puntos}
        p = os.path.join(self.run, "estado.json")
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(est, f)
        os.replace(tmp, p)
        # nodos.leer_estado cachea por (mtime_ns, tamano): dos escrituras seguidas del mismo
        # tamano en el mismo tick se verian iguales
        t = time.time() + (getattr(self, "_tick", 0) + 1)
        self._tick = getattr(self, "_tick", 0) + 1
        os.utime(p, (t, t))

    def eve(self, pid, lineas, nombre="eve.json"):
        d = os.path.join(self.datos, pid)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, nombre), "w", encoding="utf-8") as f:
            f.write("\n".join(lineas) + "\n")

    def salida(self, pid, nombre, datos):
        d = os.path.join(self.panel, "nodos", pid)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, nombre), "w", encoding="utf-8") as f:
            json.dump(datos, f)

    def foto(self):
        """{ruta relativa: (tamano, mtime_ns)} de todo el arbol (para ver que se escribio)."""
        out = {}
        for base, _ds, fs in os.walk(self.raiz):
            for n in fs:
                p = os.path.join(base, n)
                st = os.stat(p)
                out[os.path.relpath(p, self.raiz)] = (st.st_size, st.st_mtime_ns)
        return out


def entorno(arbol, **extra):
    os.environ.update({
        "IDS_PANEL_DIR": arbol.panel, "IDS_DATOS": arbol.datos, "IDS_RUN": arbol.run,
        "IDS_SHARE": arbol.share, "IDS_MASTER_KEY": arbol.clave, "IDS_TZ": "UTC",
        "IDS_ORQ_SOCK": os.path.join(arbol.raiz, "orq.sock"),
        "IDS_ORQ_TOKEN": os.path.join(arbol.raiz, "secrets", "orq_token"),
        "IDS_PROXY": "", "IDS_PUERTO": "5637", "IDS_EMPRESA": "Empresa de prueba"})
    os.environ.update({k: str(v) for k, v in extra.items()})


def cargar(arbol, **extra):
    """Importa nodos, secretos y dashboard desde cero sobre el arbol. Devuelve el modulo."""
    entorno(arbol, **extra)
    import nodos
    import secretos
    importlib.reload(nodos)
    importlib.reload(secretos)
    sys.modules.pop("dashboard", None)
    spec = importlib.util.spec_from_file_location("dashboard", os.path.join(LIB, "dashboard.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dashboard"] = mod
    spec.loader.exec_module(mod)
    nodos.quitar_nodo()
    return mod


def restaurar():
    for k, v in _ENV0.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    # la CLI (`ids-panel`, llamada aqui en el mismo proceso) pone IDS_TZ en TZ con tzset, como el
    # panel al arrancar: con TZ ya devuelta, que la libc tambien vuelva a la hora de antes
    if hasattr(time, "tzset"):
        time.tzset()
    sys.modules.pop("dashboard", None)


class SockFalso:
    """Socket de la API de RouterOS que contesta !done a cada sentencia (y apunta cuales)."""

    def __init__(self, router_id, registro):
        self.router_id = router_id
        self.registro = registro
        self.palabras = []
        self.pend = b""
        self.cerrado = False

    def sendall(self, b):
        if b == b"\x00":
            self.registro.append((self.router_id, list(self.palabras)))
            self.palabras = []
            self.pend += b"\x05!done\x00"
            return
        # una palabra: longitud codificada (1 a 3 bytes) + texto
        c = b[0]
        n = 1 if c & 0x80 == 0 else (2 if c & 0xC0 == 0x80 else (3 if c & 0xE0 == 0xC0 else 4))
        self.palabras.append(b[n:].decode("utf-8", "replace"))

    def recv(self, n):
        if not self.pend:
            return b""
        out, self.pend = self.pend[:n], self.pend[n:]
        return out

    def settimeout(self, t):
        pass

    def close(self):
        self.cerrado = True


def conectar_falso(registro):
    """Sustituto de dashboard.mk_conectar: devuelve un SockFalso del router de `d`."""
    def _con(d, timeout=6):
        return SockFalso(d.get("ROUTER_ID"), registro)
    return _con
