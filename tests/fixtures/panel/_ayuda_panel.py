"""Ayudas de las pruebas del panel (constructor P). Solo stdlib; funciona en Windows y Linux.

- Pone images/panel/rootfs/usr/local/lib/ids-panel en sys.path (paquete `idspanel`).
- `cargar_orq()` importa orquestador/ids_orq.py SOLO para leer: el orquestador falso valida cada
  petición con el `validar_params` real y genera los comandos con el `comandos_mikrotik` real, así
  que si el panel manda un parámetro que el orquestador no acepta, las pruebas fallan.
- `OrqFalso`: transporte inyectable que simula punto.crear / op.estado / punto.comandos /
  punto.borrar / punto.vpn.regenerar como el servicio real (la clave sale una sola vez).
- `PanelPrueba`: servidor HTTP real del panel en 127.0.0.1:<puerto libre> con directorios temporales.
"""

import contextlib
import datetime as dt
import http.client
import importlib.util
import ipaddress
import json
import shutil
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
LIB = REPO / "images" / "panel" / "rootfs" / "usr" / "local" / "lib" / "ids-panel"
SCRIPT = REPO / "images" / "panel" / "rootfs" / "usr" / "local" / "bin" / "ids-panel"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from idspanel import usuarios as U  # noqa: E402
from idspanel.app import Panel, crear_servidor  # noqa: E402
from idspanel.config import Config, redes_proxy  # noqa: E402
from idspanel.orq import ErrorTransporte  # noqa: E402
from idspanel.sesiones import token_csrf  # noqa: E402

TOKEN = "f" * 64
DNS = "ids.empresa.example"
_ORQ = None


def cargar_orq():
    global _ORQ
    if _ORQ is None:
        nombre = "ids_orq_panel_%s" % uuid.uuid4().hex[:8]
        spec = importlib.util.spec_from_file_location(nombre, REPO / "orquestador" / "ids_orq.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[nombre] = mod
        spec.loader.exec_module(mod)
        _ORQ = mod
    return _ORQ


class CfgOrq:
    """Lo mínimo de ids_orq.Config que usa validar_params (valores de documentación)."""
    red_tuneles = ipaddress.IPv4Network("100.64.0.0/16")
    pool = ipaddress.IPv4Network("10.210.0.0/16")
    redes_gestion = [ipaddress.IPv4Network("192.0.2.0/25"), ipaddress.IPv4Network("198.51.100.0/26")]


@contextlib.contextmanager
def iteraciones_rapidas(n=1000):
    """PBKDF2 barato para las pruebas HTTP (las de crear-admin usan las 600 000 reales)."""
    antes = U.ITERACIONES
    U.ITERACIONES = n
    try:
        yield
    finally:
        U.ITERACIONES = antes


# --------------------------------------------------------------------------------------------
# Orquestador falso
# --------------------------------------------------------------------------------------------

class OrqFalso:
    CAMPOS = {"v", "op_id", "token", "orden", "params", "quien", "ip", "ts"}

    def __init__(self, llamadas_hasta_fin=3, token=TOKEN):
        self.orq = cargar_orq()
        self.token = token
        self.llamadas_hasta_fin = llamadas_hasta_fin
        self.peticiones = []
        self.ops = {}
        self.puntos = {}
        self.secretos = {}
        self.caido = False
        self.forzar = {}
        self._lock = threading.Lock()

    def ordenes(self, orden=None):
        return [p for p in self.peticiones if orden is None or p["orden"] == orden]

    def anadir_punto(self, nombre="norte", n=3, ros=7):
        pid = "p%03d" % n
        d = self.orq.derivar(n, "100.64")
        self.puntos[pid] = {"pid": pid, "nombre": nombre, "n": n, "puerto": 1194 + n - 1,
                            "tun_net": d["tun_net"], "sensor": d["sensor"], "ros_version": ros,
                            "api_puerto": 8729, "usuario": "vpn3a9f2c"}
        return pid

    def _r(self, op_id, codigo, mensaje="ok", datos=None):
        return {"op_id": op_id, "ok": codigo in ("OK", "ACEPTADA"), "codigo": codigo, "mensaje": mensaje,
                "datos": datos or {}}

    def __call__(self, pet):
        with self._lock:
            return self._atender(pet)

    def _atender(self, pet):
        if self.caido:
            raise ErrorTransporte("[Errno 2] No such file or directory")
        pet = json.loads(json.dumps(pet))          # lo que viajaría por el socket
        self.peticiones.append(pet)
        assert set(pet) == self.CAMPOS, "campos de la petición: %s" % sorted(pet)
        assert pet["v"] == 1
        op_id = pet["op_id"]
        if pet["token"] != self.token:
            return self._r(op_id, "INVALIDO", "token inválido")
        if not self.orq.RE_OPID.match(op_id or ""):
            return self._r(op_id, "INVALIDO", "op_id inválido")
        orden = pet["orden"]
        if orden not in self.orq.ORDENES_COLA and orden not in self.orq.ORDENES_LECTURA:
            return self._r(op_id, "INVALIDO", "orden desconocida")
        try:
            params = self.orq.validar_params(orden, pet["params"], lambda: CfgOrq)
        except self.orq.ErrorOrden as e:
            return self._r(op_id, e.codigo, e.mensaje, e.datos)
        if orden in self.forzar:
            codigo, mensaje, datos = self.forzar[orden]
            return self._r(op_id, codigo, mensaje, datos)
        if orden in self.orq.ORDENES_COLA:
            if op_id in self.ops:
                return self._r(op_id, "ACEPTADA", "ya en cola", {"op_id": op_id, "delante": 0})
            self.ops[op_id] = {"orden": orden, "params": params, "llamadas": 0, "fin": None}
            return self._r(op_id, "ACEPTADA", "en cola", {"op_id": op_id, "delante": 0})
        if orden == "op.estado":
            return self._op_estado(op_id, params["op_id"])
        if orden == "punto.comandos":
            p = self.puntos.get(params["pid"])
            if p is None:
                return self._r(op_id, "NO_EXISTE", "no existe %s" % params["pid"])
            return self._r(op_id, "OK", "ok", {"comandos": self.orq.comandos_mikrotik(p, DNS)})
        return self._r(op_id, "INVALIDO", "no simulada")

    def _ejecutar(self, op):
        orden, prm = op["orden"], op["params"]
        if orden == "punto.crear":
            n = len(self.puntos) + 3
            pid = self.anadir_punto(prm["nombre"], n, prm["ros_version"])
            p = self.puntos[pid]
            p["usuario"] = "vpn%06x" % (0xa00000 + n)
            clave = self.orq.nueva_clave()
            datos = {"pid": pid, "n": n, "puerto": p["puerto"], "tun_net": p["tun_net"], "usuario": p["usuario"],
                     "nombre": p["nombre"], "perfil": prm["perfil"], "hilos": prm["hilos"], "cpuset": "2",
                     "mem_limit": "900m", "comandos": self.orq.comandos_mikrotik(p, DNS)}
            return "OK", "punto %s creado" % pid, datos, {"clave": clave,
                                                          "comandos": self.orq.comandos_mikrotik(p, DNS, clave)}
        if orden == "punto.borrar":
            p = self.puntos.get(prm["pid"])
            if p is None:
                return "OK", "no existía", {}, None
            if prm["confirmar"] != p["nombre"]:
                return "INVALIDO", "confirmar no coincide con el nombre del punto", {}, None
            del self.puntos[prm["pid"]]
            return "OK", "punto %s eliminado" % prm["pid"], {}, None
        if orden == "punto.vpn.regenerar":
            p = self.puntos.get(prm["pid"])
            if p is None:
                return "NO_EXISTE", "no existe %s" % prm["pid"], {}, None
            clave = self.orq.nueva_clave()
            datos = {"pid": p["pid"], "usuario": p["usuario"], "nombre": p["nombre"],
                     "comandos": self.orq.comandos_mikrotik(p, DNS)}
            return "OK", "credencial regenerada", datos, {"clave": clave,
                                                          "comandos": self.orq.comandos_mikrotik(p, DNS, clave)}
        return "OK", "ok", {}, None

    def _op_estado(self, op_id, buscado):
        op = self.ops.get(buscado)
        if op is None:
            return self._r(op_id, "NO_EXISTE", "op desconocida")
        op["llamadas"] += 1
        nombres = self.orq.PASOS_CREAR if op["orden"] == "punto.crear" else ["paso 1", "paso 2"]
        total = len(nombres)
        if op["fin"] is None and op["llamadas"] < self.llamadas_hasta_fin:
            hechos = min(op["llamadas"], total - 1)
            pasos = [{"n": i + 1, "nombre": nombres[i], "estado": "ok", "dur_s": 0.1} for i in range(hechos)]
            return self._r(op_id, "OK", "ok", {"estado": "en_curso", "orden": op["orden"], "paso": nombres[hechos],
                                                "avance": "%d/%d" % (hechos, total), "pasos": pasos,
                                                "log_tail": []})
        if op["fin"] is None:
            codigo, mensaje, datos, secreto = self._ejecutar(op)
            op["fin"] = (codigo, mensaje, datos)
            if secreto:
                self.secretos[buscado] = secreto
        codigo, mensaje, datos = op["fin"]
        pasos = [{"n": i + 1, "nombre": nombres[i], "estado": "ok", "dur_s": 0.1} for i in range(total)]
        if codigo != "OK":
            pasos[-1] = dict(pasos[-1], estado="fallo", detalle=mensaje)
        res = dict(datos)
        sec = self.secretos.pop(buscado, None)          # como Orquestador.op_estado: una sola vez
        if sec:
            res.update(sec)
        return self._r(op_id, "OK", "ok", {"estado": "terminada", "orden": op["orden"], "paso": nombres[-1],
                                            "avance": "%d/%d" % (total, total), "pasos": pasos, "log_tail": [],
                                            "codigo": codigo, "mensaje": mensaje, "resultado": res})


# --------------------------------------------------------------------------------------------
# estado.json y eve.json de ejemplo
# --------------------------------------------------------------------------------------------

def punto_estado(nombre, n, conectado=True, estado="activo", avisos=(), ros=7, ahora=None):
    t = int(ahora or time.time())
    return {
        "nombre": nombre, "n": n, "puerto": 1194 + n - 1, "tun_net": "100.64.%d.0/24" % n,
        "perfil": "reducido", "hilos": 1, "ros_version": ros, "compat_v6": "no",
        "deseado": "activo", "estado": estado,
        "contenedores": {
            "vpn": {"estado": "running", "salud": "healthy", "inicio": t - 9000, "reinicios_1h": 0, "imagen": "sha256:a"},
            "suricata": {"estado": "running", "salud": "healthy", "inicio": t - 8990, "reinicios_1h": 0,
                         "imagen": "sha256:b"}},
        "netns": {"coherente": True, "vpn": 4026532871, "suricata": 4026532871},
        "vpn_cliente": ({"conectado": True, "desde": t - 7200, "ip_real": "203.0.113.45", "usuario": "vpn3a9f2c"}
                        if conectado else {"conectado": False, "desde": None, "ip_real": None, "usuario": None}),
        "tzsp": {"edad_s": 12, "rx": 1200, "tx": 1180, "rechazados": 20},
        "suricata": {"stats_edad_s": 14, "reglas_cargadas": 18234, "reglas_fallidas": 0,
                     "kernel_packets": 98765, "kernel_drops": 0},
        "avisos": list(avisos),
    }


def escribir_estado(run_dir, puntos, ahora=None):
    t = int(ahora or time.time())
    est = {"v": 1, "ts": t, "orq_version": "0.1.0", "version": "0.1.0", "dev": False, "tun_base": "100.64",
           "cola": {"en_curso": None, "pendientes": 0},
           "capacidad": {"mem_total_mb": 7962, "mem_comprometida_mb": 4180, "mem_disponible_mb": 3100,
                         "caben": {"reducido": 3, "completo-low": 2, "completo": 1}},
           "reglas": {"current": "20261010T081500Z", "releases": ["20261010T081500Z"]},
           "disco": {"srv_ids_libre_pct": 71}, "puntos": puntos}
    Path(run_dir).mkdir(parents=True, exist_ok=True)
    (Path(run_dir) / "estado.json").write_text(json.dumps(est), encoding="utf-8")


def ts_eve(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def linea_alerta(epoch, pid, src, dst, firma="ET SCAN prueba", sid=2000001, sev=2, sport=51000, dport=443):
    return json.dumps({"timestamp": ts_eve(epoch), "flow_id": 1, "in_iface": "ids-mon", "event_type": "alert",
                       "src_ip": src, "src_port": sport, "dest_ip": dst, "dest_port": dport, "proto": "TCP",
                       "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 1, "signature": firma,
                                 "category": "Attempted Information Leak", "severity": sev},
                       "host": pid}, separators=(",", ":"))


def linea_stats(epoch):
    return json.dumps({"timestamp": ts_eve(epoch), "event_type": "stats",
                       "stats": {"uptime": 10, "capture": {"kernel_packets": 10, "kernel_drops": 0},
                                 "relleno": "x" * 3000}}, separators=(",", ":"))


def escribir_eve(datos_dir, pid, lineas, nombre="eve.json", modo="w"):
    d = Path(datos_dir) / pid
    d.mkdir(parents=True, exist_ok=True)
    with open(d / nombre, modo, encoding="utf-8", newline="\n") as f:
        for linea in lineas:
            f.write(linea + "\n")
    return d / nombre


# --------------------------------------------------------------------------------------------
# Servidor del panel
# --------------------------------------------------------------------------------------------

class Resp:
    def __init__(self, status, cabeceras, texto):
        self.status = status
        self.cabeceras = cabeceras
        self.texto = texto

    def cab(self, nombre):
        return self.cabeceras.get(nombre.lower(), "")

    def cookies(self):
        return [v for k, v in self.cabeceras_lista if k.lower() == "set-cookie"]


class PanelPrueba:
    def __init__(self, proxies="", orq=None, empresa="Empresa <b>Norte</b> & Cía", tz="UTC"):
        self.dir = Path(tempfile.mkdtemp(prefix="ids-panel-"))
        for d in ("panel", "datos", "run", "secretos"):
            (self.dir / d).mkdir()
        (self.dir / "secretos" / "orq_token").write_text(TOKEN + "\n", encoding="utf-8")
        self.cfg = Config(panel_dir=self.dir / "panel", datos_dir=self.dir / "datos", run_dir=self.dir / "run",
                          orq_sock=str(self.dir / "orq.sock"), orq_token=str(self.dir / "secretos" / "orq_token"),
                          puerto=0, escucha="127.0.0.1", empresa=empresa, tz=tz, proxies=redes_proxy(proxies))
        self.orq = orq if orq is not None else OrqFalso()
        self.panel = Panel(self.cfg, transporte=self.orq)
        self.srv = crear_servidor(self.panel, "127.0.0.1", 0)
        self.srv.silencioso = True
        self.puerto = self.srv.server_address[1]
        self.origen = "http://127.0.0.1:%d" % self.puerto
        self._hilo = threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._hilo.start()

    def cerrar(self):
        self.srv.shutdown()
        self.srv.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def pedir(self, metodo, ruta, form=None, cabeceras=None, cookie=None, origen=True):
        c = http.client.HTTPConnection("127.0.0.1", self.puerto, timeout=15)
        cab = dict(cabeceras or {})
        cuerpo = None
        if form is not None:
            cuerpo = urllib.parse.urlencode(form).encode("utf-8")
            cab.setdefault("Content-Type", "application/x-www-form-urlencoded")
            if origen:
                cab.setdefault("Origin", self.origen)
        if cookie:
            cab["Cookie"] = cookie
        c.request(metodo, ruta, body=cuerpo, headers=cab)
        r = c.getresponse()
        lista = r.getheaders()
        texto = r.read().decode("utf-8", "replace")
        c.close()
        resp = Resp(r.status, {k.lower(): v for k, v in lista}, texto)
        resp.cabeceras_lista = lista
        return resp

    def usuario(self, nombre="admin", clave="clave-de-prueba-123"):
        U.Usuarios(str(self.cfg.usuarios_json)).crear(nombre, clave)
        return clave

    def entrar(self, nombre="admin", clave="clave-de-prueba-123", cabeceras=None):
        r = self.pedir("POST", "/entrar", {"usuario": nombre, "clave": clave}, cabeceras=cabeceras)
        assert r.status == 303, (r.status, r.texto[:300])
        galleta = [v for v in r.cookies() if v.split("=", 1)[1].split(";", 1)[0]][0]
        return galleta.split(";", 1)[0]

    def csrf(self, cookie):
        return token_csrf(cookie.split("=", 1)[1])

    def post(self, ruta, form, cookie, **kw):
        form = dict(form)
        form.setdefault("csrf", self.csrf(cookie))
        return self.pedir("POST", ruta, form, cookie=cookie, **kw)

    def bitacora(self):
        p = self.cfg.bitacora_jsonl
        return p.read_text(encoding="utf-8") if p.exists() else ""
