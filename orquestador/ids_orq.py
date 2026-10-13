#!/usr/bin/env python3
"""ids-orq: orquestador de IDS_MAAT-Docker (servicio systemd + CLI). Solo stdlib.

F1a, según docs/CONTRATO-F1a.md (§3, §4, §5.9-§5.12). Un solo módulo:

- `ids-orq servicio` abre /run/ids-orq/orq.sock (SO_PEERCRED uid 0 o 10500 + token), ejecuta
  la cola global en serie (persistida en orq.db), supervisa (docker events, netns por inodo,
  reinicios con espera creciente) y escribe /srv/ids/run/estado.json cada 15 s.
- El resto de subórdenes son la CLI, que habla con el servicio por el socket.
- F1b: `ids-orq panel aplicar|crear-admin|restablecer` (locales, de root, como `fw-render`)
  renderizan y levantan el núcleo `ids-core` (el panel) y crean o restablecen sus usuarios
  (docs/CONTRATO-F1b.md «Integración»).

Importable en Windows (pruebas): nada de fcntl/pwd/grp/AF_UNIX a nivel de módulo.
`IDS_RAIZ` antepone un prefijo a las rutas del host; `IDS_KERNEL_RAIZ` (interno de C, pruebas)
hace lo mismo con /proc y /sys.
"""

import argparse
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import string
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

ORQ_VERSION = "0.1.0"
UID_PANEL = 10500
GID_PANEL = 10500
REGISTRO = "ghcr.io/mtandazo35"
# `\Z` y `[0-9]`, no `$` ni `\d` (auditoría A-23): `$` deja pasar un «\n» final (un nombre con
# salto de línea rompía el bloque RouterOS) y `\d` acepta dígitos Unicode.
RE_IMAGEN_PROD = re.compile(r"^ghcr\.io/mtandazo35/ids-maat-(vpn|suricata|panel)@sha256:[0-9a-f]{64}\Z")
RE_IMAGEN_DEV = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}\Z")
RE_PID = re.compile(r"^p[0-9]{3}\Z")
RE_NOMBRE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}\Z")
RE_USUARIO = re.compile(r"^vpn[0-9a-f]{6}\Z")
RE_OPID = re.compile(r"^[0-9A-Za-z-]{8,64}\Z")
RE_TS = re.compile(r"^[0-9]{8}T[0-9]{6}Z\Z")
RE_MARCADOR = re.compile(r"@@([A-Z0-9_]+)@@")

# Perfiles (§4.6.2). La tabla vive SOLO aquí.
PERFILES = {
    "reducido": {"reglas": "reducido", "detect": "medium", "sgh": "auto",
                 "flow": "64mb", "stream": "64mb", "reassembly": "256mb", "defrag": "32mb",
                 "mem_limit": 900},
    "completo-low": {"reglas": "completo", "detect": "low", "sgh": "single",
                     "flow": "64mb", "stream": "64mb", "reassembly": "256mb", "defrag": "32mb",
                     "mem_limit": 1300},
    "completo": {"reglas": "completo", "detect": "medium", "sgh": "auto",
                 "flow": "64mb", "stream": "64mb", "reassembly": "256mb", "defrag": "32mb",
                 "mem_limit": 1700},
}
PERFIL_DEFECTO = "reducido"
MEM_VPN_MB = 192
RESERVA_HOST_MB = 1024
RESERVA_PANEL_MB = 1536            # CONTRATO-F2 §6: panel heredado + generador por nodo (RLIMIT_AS 1 GiB)
MARGEN_DISPONIBLE_MB = 512
ANILLO_MB_POR_HILO = 32          # 1024 frames x 32 KiB (INSTANCIA §10.1)
TZSP_PUERTO = 37008
TZSP_BYTES = 10000
IDS_ESPERA_MON_S = 60
ENFRIAMIENTO_S = 7 * 86400
RETENCION_OPS_S = 30 * 86400
N_MAX = 250
ESPERA_SALUD_S = 180
INTERVALO_SONDEO_S = 2.0
INTERVALO_ESTADO_S = 15
INTERVALO_NETNS_S = 30
ESPERAS_REINICIO_S = (30, 120, 600)
MAX_REINICIOS_HORA = 3
MAX_MENSAJE = 1024 * 1024          # cabe un threshold de MAX_THRESHOLD con el escapado JSON (A-23)
MAX_PETICIONES_MIN = 240
RELEASES_A_CONSERVAR = 3
MAX_RESPALDOS_FW = 20
RETENCION_DIAS = 30                  # CONTRATO-F2 §9: objetivo de días de eve.json/dns.json por punto
DISCO_MIN_LIBRE_PCT = 15             # por debajo, se borran antes de tiempo los rotados más viejos
INTERVALO_PODA_S = 86400             # poda por fecha: una vez al día (y al arrancar)
MAX_THRESHOLD = 256 * 1024
MAX_LINEAS_THRESHOLD = 5000
MAX_LINEA_THRESHOLD = 4096           # Suricata lee el threshold.config con líneas de 8191 bytes (A-23)
MIN_TOKEN = 32
MIN_PREFIJO_REDES = 8                # redes de abonados: como mucho /8 (A-28)

# Núcleo (F1b, CONTRATO-F1b «Integración»): el panel en la red ids-core reservada en F1a
CORE_PROYECTO = "ids-core"
CORE_COMPOSE = "/srv/ids/core/compose.yml"
PANEL_CONTENEDOR = "ids-core-panel"
PANEL_RED = "10.210.255.0/24"
PANEL_PUERTA = "10.210.255.1"
PANEL_IP = "10.210.255.2"
PANEL_PUERTO = 5637                  # el del contenedor; el publicado es PUERTO_PANEL de ids.conf
PANEL_DIR = "/srv/ids/panel"
PANEL_USUARIOS = PANEL_DIR + "/conf/usuarios.json"     # CONTRATO-F2 §7 (lo escribe ids-panel)
MASTER_KEY = "/etc/ids-maat/master.key"               # en el panel: /run/secrets/master_key (ro)
ESPERA_PANEL_S = 120
RE_USUARIO_PANEL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}\Z")     # el mismo que ids-panel
RE_ZONA = re.compile(r"^(UTC|[A-Za-z]+(/[A-Za-z0-9_+-]+){1,2})\Z")
SALIDA_PANEL_YA_EXISTE = 3

PASOS_CREAR = ["validar", "asignar", "admisión de RAM", "directorios", "certificado",
               "usuario VPN", "server.conf", "suricata.yaml", "suricata -T", "threshold.config",
               "compose.yml", "firewall", "compose up", "esperar salud"]

ORDENES_COLA = {"punto.crear", "punto.borrar", "punto.arrancar", "punto.parar",
                "punto.reiniciar", "punto.ajustar", "punto.vpn.regenerar", "punto.threshold",
                "reglas.actualizar", "sistema.reconciliar"}
ORDENES_LECTURA = {"punto.estado", "punto.logs", "punto.comandos", "punto.api.huella",
                   "punto.medir", "logs.reabrir", "sistema.estado", "sistema.capacidad",
                   "op.estado"}
ORDENES_RESERVADAS = {"acceso.aplicar", "acceso.confirmar",
                      "sistema.buscar_actualizacion", "sistema.actualizar", "sistema.revertir",
                      "sistema.respaldar", "bitacora.anclar"}

CODIGOS_SALIDA = {"OK": 0, "ACEPTADA": 0, "FALLO": 1, "REVERTIDA": 1, "INVALIDO": 2,
                  "CONFLICTO": 3, "CONFLICTO_PUERTO": 3, "NO_EXISTE": 4, "CANCELADA": 1}
SALIDA_SIN_SERVICIO = 5


# --------------------------------------------------------------------------------------------
# Rutas, registro y utilidades
# --------------------------------------------------------------------------------------------

def raiz():
    return os.environ.get("IDS_RAIZ", "/") or "/"


def _prefijar(base, p):
    if base in ("/", ""):
        return Path(p)
    return Path(base) / p.lstrip("/")


def ruta(p):
    """Ruta del host con el prefijo IDS_RAIZ."""
    return _prefijar(raiz(), p)


def kruta(p):
    """Ruta del kernel (/proc, /sys) con el prefijo IDS_KERNEL_RAIZ (solo pruebas)."""
    return _prefijar(os.environ.get("IDS_KERNEL_RAIZ", "/") or "/", p)


def host_str(p):
    """Ruta del host como texto POSIX (para compose.yml), con el prefijo IDS_RAIZ."""
    r = raiz()
    if r in ("/", ""):
        return p
    return r.replace("\\", "/").rstrip("/") + p


def dir_plantillas():
    return Path(__file__).resolve().parent / "plantillas"


def log(msg):
    try:
        print("ids-orq: " + msg, file=sys.stderr, flush=True)
    except Exception:
        pass


def ahora():
    return int(time.time())


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_txt(txt):
    return hashlib.sha256(txt.encode("utf-8")).hexdigest()


def es_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _chown(path, uid, gid):
    if hasattr(os, "chown") and es_root():
        os.chown(path, uid, gid)


def _chmod(path, modo):
    try:
        os.chmod(path, modo)
    except OSError:
        pass


def asegurar_dir(path, modo, uid=0, gid=0):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    _chmod(path, modo)
    _chown(path, uid, gid)
    return path


def escribir_atomico(path, contenido, modo=0o644, uid=0, gid=0):
    """Escribe con fichero temporal en el mismo directorio y os.replace (rename atómico)."""
    path = Path(path)
    # temporal NUEVO (O_EXCL|O_NOFOLLOW, nombre único): nunca se escribe a través de un enlace o
    # de un fichero que ya estuviera ahí, y modo y dueño van sobre el descriptor (A-04)
    tmp = path.with_name(".%s.tmp%d.%s" % (path.name, os.getpid(), secrets.token_hex(4)))
    datos = contenido.encode("utf-8") if isinstance(contenido, str) else contenido
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as f:
            f.write(datos)
            f.flush()
            try:
                os.fsync(fd)
            except OSError:
                pass
        if hasattr(os, "fchmod"):
            try:
                os.fchmod(fd, modo)
            except OSError:
                pass
        if hasattr(os, "fchown") and es_root():
            os.fchown(fd, uid, gid)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise
    os.close(fd)
    if not hasattr(os, "fchmod"):
        _chmod(tmp, modo)                  # solo Windows (pruebas): el nombre es nuestro (O_EXCL)
    try:
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise
    return path


def borrar_arbol(path):
    path = Path(path)
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def podar_releases(releases, actual):
    """Conserva las RELEASES_A_CONSERVAR releases completas (con LISTO) más recientes y `actual`
    (la que se acaba de crear o revalidar); borra las demás, también las huérfanas sin LISTO que
    dejó una descarga interrumpida. Devuelve los nombres borrados."""
    releases = Path(releases)
    rel = sorted(d.name for d in releases.iterdir() if d.is_dir() and RE_TS.match(d.name))
    listas = [x for x in rel if (releases / x / "LISTO").is_file()]
    conservar = set(listas[-RELEASES_A_CONSERVAR:]) | {actual}
    borradas = []
    for x in rel:
        if x not in conservar:
            borrar_arbol(releases / x)
            borradas.append(x)
    return borradas


class ErrorOrden(Exception):
    def __init__(self, codigo, mensaje, datos=None):
        super().__init__(mensaje)
        self.codigo = codigo
        self.mensaje = mensaje
        self.datos = datos or {}


class FalloCmd(ErrorOrden):
    def __init__(self, args, rc, out, err):
        corto = (err or out or "").strip().splitlines()
        detalle = corto[-1] if corto else ""
        super().__init__("FALLO", "%s salió con %s: %s" % (args[0] if args else "?", rc, detalle))
        self.rc = rc
        self.out = out
        self.err = err


class Resultado:
    def __init__(self, rc, out="", err=""):
        self.rc = rc
        self.out = out or ""
        self.err = err or ""


def ejecutar(args, entrada=None, timeout=600):
    """Único punto de ejecución de órdenes del sistema (shell=False). Las pruebas lo sustituyen."""
    try:
        p = subprocess.run([str(a) for a in args], input=entrada, capture_output=True, text=True,
                           timeout=timeout, shell=False)
        return Resultado(p.returncode, p.stdout, p.stderr)
    except subprocess.TimeoutExpired:
        return Resultado(124, "", "tiempo agotado")
    except FileNotFoundError:
        return Resultado(127, "", "no existe la orden %s" % args[0])


def ejecutar_ok(args, entrada=None, timeout=600):
    r = ejecutar(args, entrada=entrada, timeout=timeout)
    if r.rc != 0:
        raise FalloCmd(list(args), r.rc, r.out, r.err)
    return r


def ncpu():
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


# --------------------------------------------------------------------------------------------
# Configuración del VPS
# --------------------------------------------------------------------------------------------

def leer_kv(path):
    datos = {}
    for linea in Path(path).read_text(encoding="utf-8").splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#") or "=" not in linea:
            continue
        k, v = linea.split("=", 1)
        datos[k.strip()] = v.strip()
    return datos


def _redes(txt, campo):
    out = []
    for parte in [x for x in (txt or "").split(",") if x]:
        try:
            out.append(ipaddress.IPv4Network(parte, strict=False))
        except ValueError:
            raise ErrorOrden("FALLO", "ids.conf: %s tiene un valor inválido" % campo)
    return out


class Config:
    def __init__(self, kv):
        faltan = [k for k in ("VERSION", "NOMBRE_DNS", "TUN_BASE", "REDES_GESTION", "IPS_PROXY",
                              "PUERTO_PANEL", "POOL_DOCKER") if not kv.get(k)]
        if faltan:
            raise ErrorOrden("FALLO", "ids.conf: faltan " + ", ".join(faltan))
        self.version = kv["VERSION"]
        self.nombre_dns = kv["NOMBRE_DNS"]
        if kv["TUN_BASE"] not in ("100.64", "198.18"):
            raise ErrorOrden("FALLO", "ids.conf: TUN_BASE debe ser 100.64 o 198.18")
        self.tun_base = kv["TUN_BASE"]
        self.redes_gestion = _redes(kv["REDES_GESTION"], "REDES_GESTION")
        self.ips_proxy = _redes(kv["IPS_PROXY"], "IPS_PROXY")
        self.ignoreip = kv.get("IGNOREIP_DUENO", "")
        self.puerto_panel = int(kv["PUERTO_PANEL"])
        self.pool = ipaddress.IPv4Network(kv["POOL_DOCKER"], strict=False)
        if not self.redes_gestion or not self.ips_proxy:
            raise ErrorOrden("FALLO", "ids.conf: REDES_GESTION e IPS_PROXY no pueden estar vacías")
        # F1b: zona horaria con la que el panel muestra las fechas (opcional; por defecto la de
        # Ecuador: los clientes son ISP de Ecuador y todo se lee en su hora)
        self.zona = kv.get("ZONA_HORARIA") or "America/Guayaquil"
        if not RE_ZONA.match(self.zona):
            raise ErrorOrden("FALLO", "ids.conf: ZONA_HORARIA inválida")

    @property
    def red_tuneles(self):
        return ipaddress.IPv4Network(self.tun_base + ".0.0/16")


def config():
    p = ruta("/etc/ids-maat/ids.conf")
    if not p.exists():
        raise ErrorOrden("FALLO", "no existe %s (¿se ejecutó install.sh?)" % p)
    return Config(leer_kv(p))


def imagenes():
    p = ruta("/etc/ids-maat/imagenes.json")
    if not p.exists():
        raise ErrorOrden("FALLO", "no existe %s" % p)
    d = json.loads(p.read_text(encoding="utf-8"))
    dev = bool(d.get("dev", False))
    imgs = d.get("imagenes") or {}
    # el panel es opcional aquí (un imagenes.json de F1a no lo trae); `panel aplicar` lo exige
    for parte in ("vpn", "suricata") + (("panel",) if "panel" in imgs else ()):
        ref = imgs.get(parte, "")
        if dev:
            if not RE_IMAGEN_DEV.match(ref or ""):
                raise ErrorOrden("FALLO", "imagenes.json: referencia de %s inválida" % parte)
        else:
            m = RE_IMAGEN_PROD.match(ref or "")
            if not m or m.group(1) != parte:
                raise ErrorOrden("FALLO", "imagenes.json: %s no es ghcr.io/mtandazo35/ids-maat-%s@sha256:…"
                                 % (parte, parte))
    return {"dev": dev, "version": d.get("version", ""), "vpn": imgs["vpn"],
            "suricata": imgs["suricata"], "panel": imgs.get("panel")}


def leer_token():
    """El token del socket. Uno vacío o corto no vale (A-23): con él cualquier token vacío entraría."""
    t = ruta("/etc/ids-maat/orq_token").read_text(encoding="utf-8").strip()
    if len(t) < MIN_TOKEN:
        raise OSError("orq_token vacío o demasiado corto (mín. %d caracteres)" % MIN_TOKEN)
    return t


def meminfo():
    datos = {}
    for linea in kruta("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        partes = linea.split()
        if len(partes) >= 2 and partes[0].endswith(":"):
            try:
                datos[partes[0][:-1]] = int(partes[1]) // 1024
            except ValueError:
                pass
    return {"total": datos.get("MemTotal", 0), "disponible": datos.get("MemAvailable", 0)}


# --------------------------------------------------------------------------------------------
# Identificadores y asignación (§3)
# --------------------------------------------------------------------------------------------

def derivar(n, tun_base, pool=None):
    pool = pool or ipaddress.IPv4Network("10.210.0.0/16")
    base = "%s.%d" % (tun_base, n)
    subred = ipaddress.IPv4Network((int(pool.network_address) + 16 * n, 28))
    return {"n": n, "puerto": 1194 + n - 1, "tun_net": base + ".0/24", "tun_red": base + ".0",
            "sensor": base + ".1", "mk": base + ".2", "subred": str(subred),
            "cluster_id": 100 + n}


def formato_cpus(cpus):
    cpus = sorted(set(cpus))
    trozos = []
    i = 0
    while i < len(cpus):
        j = i
        while j + 1 < len(cpus) and cpus[j + 1] == cpus[j] + 1:
            j += 1
        trozos.append(str(cpus[i]) if i == j else "%d-%d" % (cpus[i], cpus[j]))
        i = j + 1
    return ",".join(trozos)


def leer_cpus(txt):
    out = set()
    for trozo in [x for x in (txt or "").split(",") if x]:
        if "-" in trozo:
            a, b = trozo.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(trozo))
    return out


def cpuset_vpn(nc):
    return "0-1" if nc >= 4 else None


def cpuset_suricata(nc, hilos, ocupadas):
    """Las `hilos` CPU libres más bajas a partir de la 2; si no quedan, 2-<nc-1> compartido."""
    if nc <= 2:
        return None
    libres = [c for c in range(2, nc) if c not in ocupadas]
    if len(libres) >= hilos:
        return formato_cpus(libres[:hilos])
    return formato_cpus(range(2, nc))


def coste_punto(perfil, hilos):
    return PERFILES[perfil]["mem_limit"] + MEM_VPN_MB + ANILLO_MB_POR_HILO * hilos


def memoria_comprometida(puntos):
    """puntos: lista de (perfil, hilos). Fórmula de INSTANCIA §10.3."""
    total = sum(coste_punto(pf, h) for pf, h in puntos)
    reserva_t = max([PERFILES[pf]["mem_limit"] for pf, _ in puntos] or [0])
    return total + reserva_t + RESERVA_HOST_MB + RESERVA_PANEL_MB


def cabe(puntos, nuevo, mem):
    pf, h = nuevo
    if memoria_comprometida(puntos + [nuevo]) > mem["total"]:
        return False
    return mem["disponible"] >= PERFILES[pf]["mem_limit"] + MARGEN_DISPONIBLE_MB


def caben(puntos, mem):
    out = {}
    for pf in PERFILES:
        k = 0
        lista = list(puntos)
        while k < N_MAX:
            nuevo = (pf, 1)
            if memoria_comprometida(lista + [nuevo]) > mem["total"]:
                break
            if mem["disponible"] - k * coste_punto(pf, 1) < PERFILES[pf]["mem_limit"] + MARGEN_DISPONIBLE_MB:
                break
            lista.append(nuevo)
            k += 1
        out[pf] = k
    return out


def hash_clave(clave, sal=None):
    sal = sal if sal is not None else secrets.token_bytes(16)
    h = hashlib.scrypt(clave.encode("utf-8"), salt=sal, n=16384, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$%s$%s" % (sal.hex(), h.hex())


def nueva_clave():
    alfabeto = string.ascii_letters + string.digits
    return "".join(secrets.choice(alfabeto) for _ in range(24))


def nuevo_usuario():
    return "vpn" + secrets.token_hex(3)


# --------------------------------------------------------------------------------------------
# Plantillas (render con str.replace de @@X@@)
# --------------------------------------------------------------------------------------------

def renderizar(texto, valores, lineas=None):
    """Sustituye @@X@@; una línea que es solo @@L@@ (con `lineas`) se cambia por su texto o se quita.
    Falla si queda algún marcador."""
    lineas = lineas or {}
    out = []
    for linea in texto.split("\n"):
        m = re.fullmatch(r"\s*@@([A-Z0-9_]+)@@\s*", linea)
        if m and m.group(1) in lineas:
            valor = lineas[m.group(1)]
            if valor:
                out.append(valor)
            continue
        out.append(linea)
    texto = "\n".join(out)
    for k, v in valores.items():
        texto = texto.replace("@@%s@@" % k, str(v))
    sobran = sorted(set(RE_MARCADOR.findall(texto)))
    if sobran:
        raise ErrorOrden("FALLO", "plantilla: marcadores sin valor: " + ", ".join(sobran))
    return texto


def leer_plantilla(nombre):
    return (dir_plantillas() / nombre).read_text(encoding="utf-8")


def render_compose(p, imgs, version, nc, raiz_host="/"):
    """p: dict del punto (pid, n, puerto, tun_net, sensor, mk, api_puerto, perfil, hilos,
    cpuset_suricata, subred)."""
    prefijo = "" if raiz_host in ("/", "") else raiz_host.replace("\\", "/").rstrip("/")
    vpn_cpu = cpuset_vpn(nc)
    sur_cpu = p.get("cpuset_suricata")
    valores = {
        "PID": p["pid"], "N": p["n"], "PUERTO": p["puerto"], "TUN_NET": p["tun_net"],
        "TUN_SENSOR": p["sensor"], "TUN_MK": p["mk"], "API_PUERTO": p["api_puerto"],
        "TZSP_PUERTO": TZSP_PUERTO, "TZSP_BYTES": TZSP_BYTES, "ESPERA_MON": IDS_ESPERA_MON_S,
        "IMAGEN_VPN": imgs["vpn"], "IMAGEN_SURICATA": imgs["suricata"], "VERSION": version,
        "RAIZ": prefijo, "HILOS": p["hilos"],
        "MEM_SURICATA": "%dm" % PERFILES[p["perfil"]]["mem_limit"], "MEM_VPN": "%dm" % MEM_VPN_MB,
        "SUBRED": p["subred"],
    }
    lineas = {
        "LINEA_CPUSET_VPN": '    cpuset: "%s"' % vpn_cpu if vpn_cpu else None,
        "LINEA_CPUSET_SURICATA": '    cpuset: "%s"' % sur_cpu if sur_cpu else None,
    }
    return renderizar(leer_plantilla("compose.yml.tmpl"), valores, lineas)


def render_server_conf(pid, tun_red, ros_version, compat_v6):
    lineas = {
        "LINEA_TLS_CIPHER": 'tls-cipher "DEFAULT:@SECLEVEL=0"' if compat_v6 in ("seclevel0", "legacy") else None,
        "LINEA_TLS_CERT_PROFILE": "tls-cert-profile legacy" if compat_v6 == "legacy" else None,
    }
    valores = {"PID": pid, "TUN_RED": tun_red,
               "FALLBACK": "AES-256-CBC" if int(ros_version) == 6 else "AES-256-GCM"}
    return renderizar(leer_plantilla("server.conf.tmpl"), valores, lineas)


def render_ccd(mk):
    return "ifconfig-push %s 255.255.255.0\n" % mk


def render_usuarios(pid, usuario, hash_txt):
    return "# ids-maat %s — generado por ids-orq; no editar\n%s:%s\n" % (pid, usuario, hash_txt)


def render_threshold(pid):
    return "# ids-maat %s — generado por ids-orq; no editar\n" % pid


def _elems_ip(redes):
    return ", ".join(str(r.network_address) if r.prefixlen == 32 else str(r) for r in redes)


def render_nft(cfg, puertos, origenes):
    """puertos: lista de int; origenes: lista de (pid, puerto, ip)."""
    puertos = sorted(set(int(x) for x in puertos))
    elementos = "elements = { %s } " % ", ".join(str(x) for x in puertos) if puertos else ""
    lineas_origen = "\n".join(
        '    meta l4proto tcp ct direction original ct status dnat ct original proto-dst %d '
        'ip saddr != %s counter drop comment "origen fijo %s"' % (puerto, ip, pid)
        for pid, puerto, ip in sorted(origenes))
    valores = {"GESTION": _elems_ip(cfg.redes_gestion), "PROXY": _elems_ip(cfg.ips_proxy),
               "PUERTOS_VPN": elementos, "PUERTO_PANEL": cfg.puerto_panel}
    return renderizar(leer_plantilla("ids_host.nft.tmpl"), valores,
                      {"LINEAS_ORIGEN_FIJO": lineas_origen or None})


def entorno_panel(cfg):
    """Entorno del panel (CONTRATO-F1b, interfaz fija). El mismo para el servicio y para las
    órdenes de un solo uso (crear-admin, restablecer). El token va por fichero, nunca en claro."""
    return {
        "IDS_PROXY": ",".join(str(r.network_address) if r.prefixlen == 32 else str(r) for r in cfg.ips_proxy),
        "IDS_EMPRESA": cfg.nombre_dns,
        "IDS_PUERTO": str(PANEL_PUERTO),
        "IDS_TZ": cfg.zona,
        "TZ": "UTC",
        "IDS_ORQ_SOCK": "/run/ids-orq/orq.sock",
        "IDS_ORQ_TOKEN": "/run/secrets/orq_token",
        "IDS_PANEL_DIR": PANEL_DIR,
        "IDS_DATOS": "/srv/ids/datos",
        "IDS_RUN": "/srv/ids/run",
        # CONTRATO-F2 §10.3: secretos del panel cifrados con la clave maestra (montada ro)
        "IDS_MASTER_KEY": "/run/secrets/master_key",
    }


def render_core(cfg, imagen_panel, version, raiz_host="/"):
    """compose.yml del núcleo (proyecto ids-core): el panel en 10.210.255.2."""
    prefijo = "" if raiz_host in ("/", "") else raiz_host.replace("\\", "/").rstrip("/")
    entorno = "\n".join('      %s: "%s"' % kv for kv in entorno_panel(cfg).items())
    valores = {"IMAGEN_PANEL": imagen_panel, "VERSION": version, "RAIZ": prefijo,
               "PUERTO_PANEL": cfg.puerto_panel, "PUERTO_CONTENEDOR": PANEL_PUERTO,
               "UID": UID_PANEL, "GID": GID_PANEL, "MEM_PANEL": "%dm" % RESERVA_PANEL_MB,
               "PANEL_IP": PANEL_IP, "PANEL_RED": PANEL_RED, "PANEL_PUERTA": PANEL_PUERTA,
               "CONTENEDOR": PANEL_CONTENEDOR, "PROYECTO": CORE_PROYECTO}
    return renderizar(leer_plantilla("core.yml.tmpl"), valores, {"LINEAS_ENTORNO": entorno})


def valores_suricata(sensor, home_net, rule_path, n, hilos, perfil, hs):
    pf = PERFILES[perfil]
    return {
        "SENSOR_NAME": sensor, "HOME_NET": home_net, "RULE_PATH": rule_path,
        "CLUSTER_ID": str(100 + int(n)), "HILOS": str(hilos), "RING_SIZE": "1024",
        "BLOCK_SIZE": "131072", "SNAPLEN": "32768", "DETECT_PROFILE": pf["detect"],
        "SGH_MPM_CONTEXT": pf["sgh"], "MPM_ALGO": "hs" if hs else "ac-ks",
        "SPM_ALGO": "hs" if hs else "bm", "FLOW_MEMCAP": pf["flow"],
        "STREAM_MEMCAP": pf["stream"], "REASSEMBLY_MEMCAP": pf["reassembly"],
        "DEFRAG_MEMCAP": pf["defrag"],
    }


def render_suricata(tmpl, manifiesto, valores):
    """Sustituye cada @@X@@ de la plantilla de la imagen; falla si sobra o falta alguno."""
    if not isinstance(manifiesto, dict) or manifiesto.get("v") != 1:
        raise ErrorOrden("FALLO", "plantilla.json: versión no soportada")
    marc = set(manifiesto.get("marcadores") or [])
    en_tmpl = set(RE_MARCADOR.findall(tmpl))
    if en_tmpl - marc:
        raise ErrorOrden("FALLO", "suricata.yaml.tmpl: marcadores no declarados: " + ", ".join(sorted(en_tmpl - marc)))
    if marc - en_tmpl:
        raise ErrorOrden("FALLO", "suricata.yaml.tmpl: faltan marcadores: " + ", ".join(sorted(marc - en_tmpl)))
    if set(valores) != marc:
        raise ErrorOrden("FALLO", "plantilla.json: marcadores distintos de los que conoce ids-orq: "
                         + ", ".join(sorted(set(valores) ^ marc)))
    for k, v in valores.items():
        tmpl = tmpl.replace("@@%s@@" % k, str(v))
    if RE_MARCADOR.search(tmpl):
        raise ErrorOrden("FALLO", "suricata.yaml: quedan marcadores sin sustituir")
    return tmpl


def home_net(redes):
    return "[" + ",".join(redes) + "]"


CERT_IDS_PROMAX = """# --- Certificado API-SSL ids-promax (6.49 y v7; si ya existe, solo la última línea) ---
/certificate
add name=ids-promax common-name=ids-promax \\
    key-usage=key-cert-sign,crl-sign,digital-signature,tls-server,tls-client,data-encipherment,key-encipherment \\
    days-valid=4576 trusted=yes
/certificate sign ids-promax
/certificate set ids-promax trusted=yes
/ip service set api-ssl certificate=ids-promax
"""


def comandos_mikrotik(p, nombre_dns, clave=None):
    """Bloque de `ids-orq punto ovpn-client` (§5.12). p: pid, nombre, n, puerto, tun_net, sensor,
    ros_version, api_puerto. Sin clave se imprime <CLAVE-VPN>."""
    pid = p["pid"]
    ros = int(p["ros_version"])
    pw = clave if clave else "<CLAVE-VPN>"
    otro = 7 if ros == 6 else 6
    cifrado_v7 = "aes256-cbc" if ros == 6 else "aes256-gcm"
    api = p["api_puerto"]
    sensor = p["sensor"]
    comun = (
        "/user group add name=ids-api policy=read,write,api\n"
        "/user add name=ids-api group=ids-api address=%s/32 password=<CLAVE-API>\n"
        "/ip firewall filter add chain=input in-interface=ids-vpn src-address=%s protocol=tcp \\\n"
        "    dst-port=%s action=accept place-before=0 comment=\"IDS ids-maat:%s\"\n"
        % (sensor, sensor, api, pid))
    return (
        "# ids-maat %s (%s) · N=%s · puerto %s · túnel %s · declarado RouterOS v%d\n"
        "# El bloque v%d solo conecta tras: ids-orq punto ajustar %s --ros %d\n"
        "#\n"
        "%s"
        "#\n"
        "# --- RouterOS v7 ---\n"
        "/interface ovpn-client add name=ids-vpn connect-to=%s port=%s protocol=tcp mode=ip \\\n"
        "    user=%s password=%s cipher=%s auth=sha1 \\\n"
        "    add-default-route=no use-peer-dns=no disabled=no\n"
        "/ip route add dst-address=%s blackhole distance=250 comment=\"IDS ids-maat:%s\"\n"
        "%s"
        "#\n"
        "# --- RouterOS v6 (6.49 o superior) ---\n"
        "/interface ovpn-client add name=ids-vpn connect-to=%s port=%s mode=ip \\\n"
        "    user=%s password=%s cipher=aes256 auth=sha1 \\\n"
        "    add-default-route=no disabled=no\n"
        "/ip route add dst-address=%s type=blackhole distance=250 comment=\"IDS ids-maat:%s\"\n"
        "%s"
        % (pid, p["nombre"], p["n"], p["puerto"], p["tun_net"], ros,
           otro, pid, otro,
           CERT_IDS_PROMAX,
           nombre_dns, p["puerto"], p["usuario"], pw, cifrado_v7,
           p["tun_net"], pid, comun,
           nombre_dns, p["puerto"], p["usuario"], pw,
           p["tun_net"], pid, comun))


# --------------------------------------------------------------------------------------------
# Docker
# --------------------------------------------------------------------------------------------

def nombres_contenedores(pid):
    return {"vpn": "ids-%s-vpn" % pid, "suricata": "ids-%s-suricata" % pid}


def _epoch_rfc3339(txt):
    if not txt or txt.startswith("0001-"):
        return None
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})?$", txt)
    if not m:
        return None
    base = dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    zona = m.group(2) or "Z"
    off = 0
    if zona != "Z":
        signo = 1 if zona[0] == "+" else -1
        off = signo * (int(zona[1:3]) * 3600 + int(zona[4:6]) * 60)
    return int(base.replace(tzinfo=dt.timezone.utc).timestamp()) - off


def docker_inspect(nombres):
    """{nombre: {estado, salud, inicio, imagen, pid, id}}; los que no existen no aparecen."""
    if not nombres:
        return {}
    r = ejecutar(["docker", "inspect", "--type", "container"] + list(nombres), timeout=60)
    try:
        lista = json.loads(r.out or "[]")
    except ValueError:
        lista = []
    out = {}
    for obj in lista or []:
        nombre = (obj.get("Name") or "").lstrip("/")
        st = obj.get("State") or {}
        salud = ((st.get("Health") or {}).get("Status")) or "none"
        out[nombre] = {"estado": st.get("Status", "?"), "salud": salud,
                       "inicio": _epoch_rfc3339(st.get("StartedAt")), "imagen": obj.get("Image", ""),
                       "pid": st.get("Pid") or 0, "id": obj.get("Id", "")}
    return out


def compose_args(pid, *resto):
    return ["docker", "compose", "-p", "ids-%s" % pid, "-f",
            str(ruta("/srv/ids/puntos/%s/compose.yml" % pid))] + list(resto)


def core_compose_args(*resto):
    return ["docker", "compose", "-p", CORE_PROYECTO, "-f", str(ruta(CORE_COMPOSE))] + list(resto)


def esperar_salud(nombres, limite=None):
    """Espera a que todos estén `healthy`; falla enseguida si alguno sale (exited/dead)."""
    limite = ESPERA_SALUD_S if limite is None else limite
    fin = time.monotonic() + limite
    while True:
        info = docker_inspect(nombres)
        if all(info.get(n, {}).get("salud") == "healthy" for n in nombres):
            return info
        muertos = [n for n in nombres if info.get(n, {}).get("estado") in ("exited", "dead")]
        if muertos or time.monotonic() >= fin:
            malos = ", ".join("%s=%s/%s" % (n, info.get(n, {}).get("estado", "ausente"),
                                            info.get(n, {}).get("salud", "-")) for n in nombres)
            raise ErrorOrden("FALLO", "no sanos en %d s: %s" % (limite, malos))
        time.sleep(INTERVALO_SONDEO_S)


def digest12(imagen):
    m = re.search(r"@sha256:([0-9a-f]{64})$", imagen)
    if m:
        return m.group(1)[:12]
    r = ejecutar_ok(["docker", "image", "inspect", "--format", "{{.Id}}", imagen], timeout=60)
    m = re.search(r"([0-9a-f]{64})", r.out)
    if not m:
        raise ErrorOrden("FALLO", "no se pudo obtener el id de la imagen %s" % imagen)
    return m.group(1)[:12]


def plantilla_suricata(imagen):
    """Extrae (una vez por digest) suricata.yaml.tmpl, plantilla.json y --build-info de la imagen."""
    d12 = digest12(imagen)
    destino = ruta("/srv/ids/estado/plantillas/%s" % d12)
    ficheros = ("suricata.yaml.tmpl", "plantilla.json", "build-info.txt")
    if not all((destino / f).exists() for f in ficheros):
        tmp = ruta("/srv/ids/estado/plantillas/.%s.%s" % (d12, secrets.token_hex(3)))
        asegurar_dir(tmp, 0o700)
        nombre = "ids-orq-plantilla-%s-%s" % (d12, secrets.token_hex(3))
        try:
            ejecutar_ok(["docker", "create", "--name", nombre, imagen], timeout=120)
            try:
                for f in ("suricata.yaml.tmpl", "plantilla.json"):
                    ejecutar_ok(["docker", "cp", "%s:/usr/share/ids-maat/%s" % (nombre, f), str(tmp / f)],
                                timeout=120)
            finally:
                ejecutar(["docker", "rm", "-f", nombre], timeout=60)
            r = ejecutar_ok(["docker", "run", "--rm", "--network", "none", "--entrypoint",
                             "/usr/bin/suricata", imagen, "--build-info"], timeout=120)
            (tmp / "build-info.txt").write_text(r.out, encoding="utf-8")
            if destino.exists():
                borrar_arbol(destino)
            os.replace(tmp, destino)
        finally:
            if tmp.exists():
                borrar_arbol(tmp)
    tmpl = (destino / "suricata.yaml.tmpl").read_text(encoding="utf-8")
    manifiesto = json.loads((destino / "plantilla.json").read_text(encoding="utf-8"))
    info = (destino / "build-info.txt").read_text(encoding="utf-8")
    hs = bool(re.search(r"Hyperscan support:\s*yes", info, re.I))
    return tmpl, manifiesto, hs


# --------------------------------------------------------------------------------------------
# Ficheros en directorios que escriben los contenedores (auditoría A-04)
# --------------------------------------------------------------------------------------------
# datos/<pid> lo escribe suricata y run/<pid> y ctl/<pid> los escribe vpn: root dentro del
# contenedor, sin userns. El orquestador es root en el host, así que ahí NUNCA sigue un enlace
# ni escribe por nombre en algo que el contenedor pueda haber plantado:
#   - abre sin seguir enlaces (O_NOFOLLOW) ni bloquearse (O_NONBLOCK: una FIFO no cuelga tick());
#   - solo ficheros regulares (lstat antes y fstat después, mismo inodo) con UN solo nombre
#     (st_nlink == 1: un enlace duro a un fichero ajeno no cuela);
#   - lee con tope de bytes;
#   - los temporales se crean con O_CREAT|O_EXCL|O_NOFOLLOW y el modo, dueño y fechas se ponen
#     sobre el descriptor (fchmod/fchown/futimens), nunca por nombre.
# Los directorios padre (datos/, run/, ctl/) son del host y el contenedor no puede cambiarlos.

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_EXTRA = getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
TOPE_STATUS_OVPN = 1024 * 1024        # openvpn-status.log: un cliente, unas pocas líneas
TOPE_TZSP = 64 * 1024                  # tzsp.json: un objeto pequeño
TOPE_STATS_EVE = 512 * 1024            # cola de eve.json donde buscar el último «stats»
TOPE_PRIMER_TS = 64 * 1024             # principio de un eve/dns (descomprimido)
TOPE_PRIMER_TS_GZ = 1024 * 1024        # comprimido que se lee como mucho para sacar ese principio


class FicheroNoSeguro(OSError):
    """Un fichero de un directorio de contenedor que no se toca: enlace, FIFO, dispositivo,
    directorio, varios nombres o cambiado entre la comprobación y la apertura."""


def es_regular_suelto(path):
    """lstat: fichero regular (no enlace, no FIFO) con un solo nombre. Nunca sigue enlaces."""
    try:
        st = os.lstat(str(path))
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_nlink == 1


def abrir_de_contenedor(path):
    """(fd de solo lectura, fstat) de un fichero de un directorio de contenedor, o FicheroNoSeguro
    / OSError. Quien llama cierra el fd."""
    path = str(path)
    lst = os.lstat(path)
    if not stat.S_ISREG(lst.st_mode):
        raise FicheroNoSeguro("%s: no es un fichero regular" % path)
    fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_EXTRA)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (lst.st_dev, lst.st_ino):
            raise FicheroNoSeguro("%s: cambió entre la comprobación y la apertura" % path)
        if st.st_nlink != 1:
            raise FicheroNoSeguro("%s: tiene %d nombres (enlace duro)" % (path, st.st_nlink))
    except BaseException:
        os.close(fd)
        raise
    return fd, st


def _leer_fd(fd, tope):
    trozos, n = [], 0
    while n < tope:
        b = os.read(fd, min(1024 * 1024, tope - n))
        if not b:
            break
        trozos.append(b)
        n += len(b)
    return b"".join(trozos)


def leer_de_contenedor(path, tope, desde_el_final=False):
    """Como mucho `tope` bytes de un fichero de un directorio de contenedor (del principio o, con
    `desde_el_final`, de la cola). Lanza OSError (FicheroNoSeguro incluido)."""
    fd, st = abrir_de_contenedor(path)
    try:
        if desde_el_final and st.st_size > tope:
            os.lseek(fd, st.st_size - tope, os.SEEK_SET)
        return _leer_fd(fd, tope)
    finally:
        os.close(fd)


def mismo_inodo(path, st):
    """¿El nombre sigue apuntando (sin seguir enlaces) al inodo `st`, con un solo nombre?"""
    try:
        l = os.lstat(str(path))
    except OSError:
        return False
    return (stat.S_ISREG(l.st_mode) and (l.st_dev, l.st_ino) == (st.st_dev, st.st_ino)
            and l.st_nlink == 1)


# --------------------------------------------------------------------------------------------
# Lecturas de estado (estado.json §5.10)
# --------------------------------------------------------------------------------------------

def leer_status_openvpn(path):
    try:
        txt = leer_de_contenedor(path, TOPE_STATUS_OVPN).decode("utf-8", errors="replace")
    except OSError:
        return {"conectado": False, "desde": None, "ip_real": None, "usuario": None}
    for linea in txt.splitlines():
        if not linea.startswith("CLIENT_LIST,"):
            continue
        c = linea.split(",")
        if len(c) < 10:
            continue
        real = c[2]
        ip = real.rsplit(":", 1)[0] if ":" in real else real
        try:
            desde = int(c[8])
        except ValueError:
            desde = None
        usuario = c[9] if c[9] and c[9] != "UNDEF" else c[1]
        return {"conectado": True, "desde": desde, "ip_real": ip, "usuario": usuario}
    return {"conectado": False, "desde": None, "ip_real": None, "usuario": None}


def leer_tzsp(path, t):
    try:
        d = json.loads(leer_de_contenedor(path, TOPE_TZSP).decode("utf-8"))
        return {"edad_s": max(0, t - int(d.get("ts", 0))), "rx": int(d.get("rx", 0)),
                "tx": int(d.get("tx", 0)), "rechazados": int(d.get("rechazados", 0))}
    except (OSError, ValueError, TypeError, AttributeError):
        return {"edad_s": None, "rx": None, "tx": None, "rechazados": None}


def _ts_suricata(txt):
    try:
        return int(dt.datetime.strptime(txt, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp())
    except (ValueError, TypeError):
        try:
            return int(dt.datetime.strptime(txt, "%Y-%m-%dT%H:%M:%S%z").timestamp())
        except (ValueError, TypeError):
            return None


def leer_stats_eve(path, t):
    vacio = {"stats_edad_s": None, "reglas_cargadas": None, "reglas_fallidas": None,
             "kernel_packets": None, "kernel_drops": None}
    try:
        bloque = leer_de_contenedor(path, TOPE_STATS_EVE, desde_el_final=True).decode(
            "utf-8", errors="replace")
    except OSError:
        return vacio
    for linea in reversed(bloque.splitlines()):
        if '"event_type":"stats"' not in linea:
            continue
        try:
            ev = json.loads(linea)
        except ValueError:
            continue
        st = ev.get("stats") or {}
        motores = ((st.get("detect") or {}).get("engines")) or []
        cap = st.get("capture") or {}
        ts = _ts_suricata(ev.get("timestamp"))
        return {"stats_edad_s": max(0, t - ts) if ts else None,
                "reglas_cargadas": sum(int(m.get("rules_loaded", 0)) for m in motores) if motores else None,
                "reglas_fallidas": sum(int(m.get("rules_failed", 0)) for m in motores) if motores else None,
                "kernel_packets": cap.get("kernel_packets"), "kernel_drops": cap.get("kernel_drops")}
    return vacio


def leer_reglas():
    base = ruta("/srv/ids/reglas")
    rel = base / "releases"
    releases = sorted(d.name for d in rel.iterdir() if d.is_dir() and RE_TS.match(d.name)
                      and (d / "LISTO").exists()) if rel.exists() else []
    actual = None
    cur = base / "current"
    if cur.is_symlink():
        actual = Path(os.readlink(cur)).name
    elif cur.exists():
        actual = cur.resolve().name
    return {"current": actual, "releases": releases}


def disco_libre_pct():
    p = ruta("/srv/ids")
    try:
        u = shutil.disk_usage(p if p.exists() else ruta("/"))
        return int(round(100.0 * u.free / u.total)) if u.total else None
    except OSError:
        return None



# --------------------------------------------------------------------------------------------
# threshold.config (punto.threshold, CONTRATO-F2 §6)
# --------------------------------------------------------------------------------------------

# Solo `suppress`, `threshold` y `event_filter` con pares «clave valor» de la sintaxis de
# Suricata, y comentarios. Nada de `rate_filter`, `include` ni caracteres fuera de la lista.
RE_TH_LINEA = re.compile(r"^(suppress|threshold|event_filter)\s+(.+)$")
RE_TH_PAR = re.compile(r"^(gen_id|sig_id|track|ip|type|count|seconds)\s+([A-Za-z0-9_.:/,\[\]!$ -]{1,512})$")
TH_TRACK = {"by_src", "by_dst", "by_rule", "by_both", "by_either"}
TH_TIPO = {"limit", "threshold", "both", "backoff"}


def _partir_pares(txt):
    """Separa por comas que no están dentro de corchetes (ip [10.0.0.0/8,192.0.2.1])."""
    trozos, actual, nivel = [], "", 0
    for c in txt:
        if c == "[":
            nivel += 1
        elif c == "]":
            nivel -= 1
        if c == "," and nivel == 0:
            trozos.append(actual)
            actual = ""
        else:
            actual += c
    trozos.append(actual)
    return trozos


def validar_threshold(contenido):
    """Comprueba línea a línea el threshold.config que manda el panel. Devuelve el texto
    normalizado (LF y terminado en salto de línea) o lanza ErrorOrden INVALIDO con la línea."""
    if not isinstance(contenido, str):
        raise _inv("contenido debe ser texto")
    if len(contenido.encode("utf-8")) > MAX_THRESHOLD:
        raise _inv("threshold demasiado grande (máx. %d KiB)" % (MAX_THRESHOLD // 1024))
    lineas = contenido.replace("\r\n", "\n").split("\n")
    if len(lineas) > MAX_LINEAS_THRESHOLD:
        raise _inv("threshold con demasiadas líneas (máx. %d)" % MAX_LINEAS_THRESHOLD)
    for i, linea in enumerate(lineas, 1):
        if any(ord(c) < 32 and c != "\t" for c in linea):
            raise _inv("línea %d: caracteres de control" % i)
        if len(linea.encode("utf-8")) > MAX_LINEA_THRESHOLD:
            raise _inv("línea %d: demasiado larga (máx. %d bytes)" % (i, MAX_LINEA_THRESHOLD))
        x = linea.strip()
        if not x or x.startswith("#"):
            continue                      # comentario en línea propia: se admite tal cual
        if "#" in x:
            # Suricata no admite comentarios al final de una regla del threshold (A-13): el motivo
            # de una exclusión va en una línea propia que empiece por «#», encima de la regla
            raise _inv("línea %d: comentario al final de una regla; ponlo en una línea propia que "
                       "empiece por # (encima de la regla)" % i)
        m = RE_TH_LINEA.match(x)
        if not m:
            raise _inv("línea %d: solo se admiten suppress, threshold, event_filter y comentarios" % i)
        pares = {}
        for trozo in _partir_pares(m.group(2)):
            pm = RE_TH_PAR.match(trozo.strip())
            if not pm or pm.group(1) in pares:
                raise _inv("línea %d: parámetro no válido: %s" % (i, trozo.strip()[:60]))
            pares[pm.group(1)] = pm.group(2).strip()
        if not pares.get("gen_id", "").isdigit() or not pares.get("sig_id", "").isdigit():
            raise _inv("línea %d: gen_id y sig_id numéricos son obligatorios" % i)
        if "track" in pares and pares["track"] not in TH_TRACK:
            raise _inv("línea %d: track no válido" % i)
        if m.group(1) == "suppress":
            if set(pares) - {"gen_id", "sig_id", "track", "ip"}:
                raise _inv("línea %d: suppress solo admite gen_id, sig_id, track e ip" % i)
            if "ip" in pares and "track" not in pares:
                raise _inv("línea %d: suppress con ip necesita track" % i)
        else:
            if set(pares) - {"gen_id", "sig_id", "track", "type", "count", "seconds"}:
                raise _inv("línea %d: %s solo admite gen_id, sig_id, type, track, count y seconds"
                           % (i, m.group(1)))
            if (pares.get("type") not in TH_TIPO or not pares.get("count", "").isdigit()
                    or not pares.get("seconds", "").isdigit() or "track" not in pares):
                raise _inv("línea %d: %s necesita type, track, count y seconds" % (i, m.group(1)))
    texto = "\n".join(lineas).rstrip("\n")
    return texto + "\n" if texto else ""


# --------------------------------------------------------------------------------------------
# Retención de los eventos por fecha (CONTRATO-F2 §9)
# --------------------------------------------------------------------------------------------
# logrotate rota por tamaño con nombre fechado (eve.json-AAAAMMDD-HHMMSS[.gz]) y sin tope de
# número; la poda es del orquestador: por fecha (más de RETENCION_DIAS) y, si el disco baja de
# DISCO_MIN_LIBRE_PCT, antes de tiempo, empezando por los rotados más viejos de cualquier punto.

RE_ROTADO = re.compile(r"^(eve|dns)\.json[-.].+$")
RE_FECHA_ROTADO = re.compile(r"^(?:eve|dns)\.json-(\d{8})-(\d{6})(?:\.gz)?$")


def fecha_rotado(path):
    """Cota superior de la marca de tiempo de los eventos de un rotado: la más tardía entre la
    fecha de rotación del nombre (hora local del host, la de logrotate) y el mtime. Un rotado
    no recibe eventos posteriores a esa fecha, así que podar por ella nunca borra un evento más
    reciente que el límite."""
    p = Path(path)
    try:
        mtime = int(os.lstat(str(p)).st_mtime)     # sin seguir enlaces (A-04)
    except OSError:
        return None
    m = RE_FECHA_ROTADO.match(p.name)
    if not m:
        return mtime
    try:
        nombre = int(time.mktime(time.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")))
    except (ValueError, OverflowError):
        return mtime
    return max(nombre, mtime)


def rotados(pid):
    """[(cota, path)] de los eve/dns rotados de un punto (nunca los vivos), el más viejo primero."""
    d = ruta("/srv/ids/datos/%s" % pid)
    salida = []
    try:
        hijos = list(d.iterdir())
    except OSError:
        return salida
    for f in hijos:
        if not RE_ROTADO.match(f.name) or f.name.endswith(".tmp") or not es_regular_suelto(f):
            continue
        cota = fecha_rotado(f)
        if cota is not None:
            salida.append((cota, f))
    salida.sort(key=lambda x: (x[0], x[1].name))
    return salida


RE_ROTADO_SIN_COMPRIMIR = re.compile(r"^(?:eve|dns)\.json-\d{8}-\d{6}$")
ESPERA_COMPRIMIR_S = 120             # Suricata ya reabrió (postrotate) y no escribe más en el rotado
INTERVALO_COMPRIMIR_S = 60


def comprimir_rotado(f):
    """gzip de un rotado conservando su mtime (= su último evento), dueño y modo: Eventos del
    panel salta ficheros por mtime y logrotate/gzip no lo conservan. Atómico (.tmp + rename);
    el original solo se borra cuando el .gz está completo. Devuelve la ruta del .gz o None.

    datos/<pid> lo escribe el contenedor suricata (A-04): el origen se abre sin seguir enlaces y
    solo si es un fichero regular con un nombre; el temporal se crea nuevo (O_EXCL|O_NOFOLLOW,
    tras borrar el NOMBRE que hubiera, que nunca sigue un enlace) y su modo, dueño y fechas se
    ponen sobre el descriptor. Antes de renombrar y de borrar se comprueba que cada nombre sigue
    siendo el inodo que se ha escrito o leído."""
    import gzip
    f = Path(f)
    try:
        fd_src, st = abrir_de_contenedor(f)
    except OSError as e:
        log("comprimir %s: no se toca (%s)" % (f, e))
        return None
    destino = f.with_name(f.name + ".gz")
    # con punto delante: el glob `eve.json*` del panel (Eventos, generador) no lo ve a medias
    tmp = f.with_name("." + f.name + ".gz.tmp")
    fd_tmp = None
    escrito = False
    try:
        try:
            os.unlink(str(tmp))            # resto o algo plantado: se quita el NOMBRE, sin seguirlo
        except FileNotFoundError:
            pass
        fd_tmp = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_EXTRA,
                         0o600)
        st_tmp = os.fstat(fd_tmp)
        with os.fdopen(fd_src, "rb", closefd=False) as src, \
                os.fdopen(fd_tmp, "wb", closefd=False) as raw:
            with gzip.GzipFile(filename=f.name, mode="wb", fileobj=raw, compresslevel=6,
                               mtime=int(st.st_mtime)) as gz:
                shutil.copyfileobj(src, gz, 1024 * 1024)
            raw.flush()
            os.fsync(fd_tmp)
        if hasattr(os, "fchmod"):
            os.fchmod(fd_tmp, st.st_mode & 0o777)
        else:                              # solo Windows (pruebas): el nombre es el nuestro (O_EXCL)
            os.chmod(str(tmp), st.st_mode & 0o777)
        if es_root() and hasattr(os, "fchown"):
            os.fchown(fd_tmp, st.st_uid, st.st_gid)
        if os.utime in os.supports_fd:
            os.utime(fd_tmp, ns=(st.st_atime_ns, st.st_mtime_ns))
        else:
            os.utime(str(tmp), ns=(st.st_atime_ns, st.st_mtime_ns))
        escrito = True
        if not mismo_inodo(tmp, st_tmp):
            raise FicheroNoSeguro("%s cambió mientras se escribía" % tmp)
        if not mismo_inodo(f, st):
            raise FicheroNoSeguro("%s cambió mientras se comprimía" % f)
        os.close(fd_tmp)
        fd_tmp = None
        os.close(fd_src)
        fd_src = None
        os.replace(str(tmp), str(destino))
        if mismo_inodo(f, st):
            os.unlink(str(f))
        return destino
    except OSError as e:
        log("comprimir %s: %s" % (f, e))
        if escrito or fd_tmp is not None:
            try:
                os.unlink(str(tmp))        # el nombre: nunca sigue un enlace
            except OSError:
                pass
        return None
    finally:
        for fd in (fd_tmp, fd_src):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def comprimir_rotados(pids, t, espera=ESPERA_COMPRIMIR_S):
    """Comprime los rotados fechados sin comprimir con más de `espera` s sin escribirse."""
    hechos = []
    for pid in pids:
        d = ruta("/srv/ids/datos/%s" % pid)
        try:
            hijos = sorted(d.iterdir())
        except OSError:
            continue
        for f in hijos:
            if f.name.startswith(".") and f.name.endswith(".gz.tmp"):
                try:
                    # resto de una compresión interrumpida (o algo plantado): se borra el NOMBRE
                    if t - os.lstat(str(f)).st_mtime > 3600:
                        os.unlink(str(f))
                except OSError:
                    pass
                continue
            if not RE_ROTADO_SIN_COMPRIMIR.match(f.name) or not es_regular_suelto(f):
                continue
            try:
                if t - os.lstat(str(f)).st_mtime < espera:
                    continue
            except OSError:
                continue
            g = comprimir_rotado(f)
            if g is not None:
                hechos.append(g)
    return hechos


_PRIMER_TS = {}


def _principio_gz(comprimido, tope):
    """Hasta `tope` bytes descomprimidos del principio de un gzip (varios miembros), sin pasar de
    lo que ya se ha leído comprimido: un .gz de miembros vacíos no gasta más que eso."""
    import zlib
    salida = b""
    resto = comprimido
    while resto and len(salida) < tope:
        d = zlib.decompressobj(31)
        salida += d.decompress(resto, tope - len(salida))
        if not d.eof:
            break
        resto = d.unused_data
    return salida[:tope]


def primer_ts(path):
    """Marca de tiempo del primer evento de un fichero (vivo o .gz), con caché por tamaño y
    mtime. Solo lee el principio: como mucho 64 KiB descomprimidos."""
    import zlib
    p = Path(path)
    try:
        st = os.lstat(str(p))              # sin seguir enlaces (A-04)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    clave = (str(p), st.st_size, st.st_mtime_ns)
    if clave in _PRIMER_TS:
        return _PRIMER_TS[clave]
    ts = None
    try:
        if p.name.endswith(".gz"):
            bloque = _principio_gz(leer_de_contenedor(p, TOPE_PRIMER_TS_GZ), TOPE_PRIMER_TS)
        else:
            bloque = leer_de_contenedor(p, TOPE_PRIMER_TS)
        for linea in bloque.decode("utf-8", errors="replace").splitlines()[:50]:
            m = re.search(r'"timestamp"\s*:\s*"([^"]+)"', linea)
            if m:
                ts = _ts_suricata(m.group(1))
                if ts:
                    break
    except (OSError, EOFError, ValueError, zlib.error):
        ts = None
    if len(_PRIMER_TS) > 4096:
        _PRIMER_TS.clear()
    _PRIMER_TS[clave] = ts
    return ts


def datos_mas_viejos(pid):
    """Fecha del dato más viejo disponible del punto (primer evento del fichero más viejo). Si no
    se puede leer, la cota del fichero: así nunca se anuncia más retención de la que hay."""
    candidatos = rotados(pid)
    for nombre in ("eve.json", "dns.json"):
        f = ruta("/srv/ids/datos/%s/%s" % (pid, nombre))
        try:
            st = os.lstat(str(f))           # sin seguir enlaces (A-04)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode):
            candidatos.append((int(st.st_mtime), f))
    mejor = None
    for cota, f in candidatos:
        ts = primer_ts(f)
        valor = ts if ts is not None else cota
        if valor is not None and (mejor is None or valor < mejor):
            mejor = valor
    return mejor


# --------------------------------------------------------------------------------------------
# PKI (CA común por VPS, certificado de servidor por punto)
# --------------------------------------------------------------------------------------------

def asegurar_ca(nombre_dns):
    pki = asegurar_dir(ruta("/srv/ids/pki"), 0o700)
    asegurar_dir(pki / "servidores", 0o700)
    if not (pki / "ca.crt").exists() or not (pki / "ca.key").exists():
        ejecutar_ok(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "7300",
                     "-nodes", "-keyout", str(pki / "ca.key"), "-out", str(pki / "ca.crt"),
                     "-subj", "/CN=ids-maat-ca %s" % nombre_dns,
                     "-addext", "basicConstraints=critical,CA:TRUE",
                     "-addext", "keyUsage=critical,keyCertSign,cRLSign"], timeout=120)
        _chmod(pki / "ca.key", 0o600)
        _chmod(pki / "ca.crt", 0o644)
    if not (pki / "dh.pem").exists():
        ejecutar_ok(["openssl", "genpkey", "-genparam", "-algorithm", "DH", "-pkeyopt",
                     "dh_param:ffdhe2048", "-out", str(pki / "dh.pem")], timeout=120)
        _chmod(pki / "dh.pem", 0o644)
    return pki


EXT_SERVIDOR = """basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"""


def cert_servidor(pid, nombre_dns):
    pki = asegurar_ca(nombre_dns)
    srv = pki / "servidores"
    key, crt, csr, ext = (srv / ("%s.key" % pid), srv / ("%s.crt" % pid), srv / ("%s.csr" % pid),
                          srv / ("%s.ext" % pid))
    try:
        ext.write_text(EXT_SERVIDOR, encoding="utf-8")
        ejecutar_ok(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
                     "-keyout", str(key), "-subj", "/CN=server-%s" % pid, "-out", str(csr)], timeout=120)
        ejecutar_ok(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(pki / "ca.crt"),
                     "-CAkey", str(pki / "ca.key"), "-set_serial", "0x" + secrets.token_hex(16),
                     "-days", "3650", "-sha256", "-extfile", str(ext), "-out", str(crt)], timeout=120)
    finally:
        for f in (csr, ext):
            if f.exists():
                f.unlink()
    _chmod(key, 0o600)
    _chmod(crt, 0o644)
    return key, crt


def borrar_cert(pid):
    srv = ruta("/srv/ids/pki/servidores")
    for ext in ("key", "crt", "csr", "ext"):
        f = srv / ("%s.%s" % (pid, ext))
        if f.exists():
            f.unlink()


# --------------------------------------------------------------------------------------------
# Base de datos (orq.db)
# --------------------------------------------------------------------------------------------

ESQUEMA = """
CREATE TABLE IF NOT EXISTS secuencia (nombre TEXT PRIMARY KEY, valor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS punto (
  pid TEXT PRIMARY KEY, nombre TEXT NOT NULL, n INTEGER NOT NULL UNIQUE, puerto INTEGER NOT NULL,
  subred TEXT NOT NULL, cluster_id INTEGER NOT NULL, perfil TEXT NOT NULL, hilos INTEGER NOT NULL,
  ros_version INTEGER NOT NULL, compat_v6 TEXT NOT NULL, api_puerto INTEGER NOT NULL,
  origen_ip TEXT, redes TEXT NOT NULL, usuario TEXT, cpuset_suricata TEXT,
  imagen_vpn TEXT, imagen_suricata TEXT, deseado TEXT NOT NULL, estado TEXT NOT NULL,
  paso_error TEXT, creado INTEGER NOT NULL, actualizado INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS enfriamiento (n INTEGER PRIMARY KEY, hasta INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS op (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, op_id TEXT NOT NULL UNIQUE, orden TEXT NOT NULL,
  params_sha256 TEXT NOT NULL, params TEXT, pid TEXT, quien TEXT, estado TEXT NOT NULL,
  codigo TEXT, mensaje TEXT, datos TEXT, paso TEXT, pasos TEXT, total INTEGER, log TEXT,
  creado INTEGER NOT NULL, inicio INTEGER, fin INTEGER);
CREATE TABLE IF NOT EXISTS reinicio (pid TEXT NOT NULL, parte TEXT NOT NULL, ts INTEGER NOT NULL);
"""


def abrir_db():
    d = asegurar_dir(ruta("/srv/ids/estado"), 0o700)
    db = sqlite3.connect(str(d / "orq.db"), isolation_level=None, check_same_thread=False,
                         timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute("PRAGMA busy_timeout=5000")
    db.executescript(ESQUEMA)
    return db


def fila_a_punto(f, cfg_base=None):
    if f is None:
        return None
    p = dict(f)
    p["redes"] = json.loads(p["redes"])
    base = cfg_base or "100.64"
    p.update({k: v for k, v in derivar(p["n"], base).items() if k in ("tun_net", "tun_red", "sensor", "mk")})
    return p


# --------------------------------------------------------------------------------------------
# Contexto de una orden en curso
# --------------------------------------------------------------------------------------------

class Contexto:
    def __init__(self, orq, op_id, orden, total=None):
        self.orq = orq
        self.op_id = op_id
        self.orden = orden
        self.total = total
        self.pasos = []
        self.log = []
        self.paso_actual = None
        self.deshacer = None
        self.mensaje = None
        self.pid = None
        self.quien = ""

    def registrar(self, linea):
        self.log.append(str(linea)[:500])
        del self.log[:-50]

    @contextmanager
    def paso(self, nombre):
        t0 = time.monotonic()
        self.paso_actual = nombre
        self.orq._progreso(self)
        try:
            yield
        except Exception as e:
            self.pasos.append({"n": len(self.pasos) + 1, "nombre": nombre, "estado": "fallo",
                               "dur_s": round(time.monotonic() - t0, 1),
                               "detalle": getattr(e, "mensaje", str(e))[:300]})
            self.orq._progreso(self)
            raise
        self.pasos.append({"n": len(self.pasos) + 1, "nombre": nombre, "estado": "ok",
                           "dur_s": round(time.monotonic() - t0, 1)})
        self.orq._progreso(self)


# --------------------------------------------------------------------------------------------
# Validación de parámetros (lista blanca)
# --------------------------------------------------------------------------------------------

def _inv(msg):
    return ErrorOrden("INVALIDO", msg)


def _solo(params, permitidos, requeridos=()):
    if not isinstance(params, dict):
        raise _inv("params debe ser un objeto")
    sobran = set(params) - set(permitidos)
    if sobran:
        raise _inv("parámetros no admitidos: " + ", ".join(sorted(sobran)))
    for r in requeridos:
        if r not in params:
            raise _inv("falta el parámetro %s" % r)


def _int(v, nombre, validos=None, rango=None):
    if isinstance(v, bool) or not isinstance(v, int):
        if isinstance(v, str) and v.isascii() and v.isdigit() and len(v) <= 9:   # '²' no (A-23)
            v = int(v)
        else:
            raise _inv("%s debe ser un entero" % nombre)
    if validos is not None and v not in validos:
        raise _inv("%s debe ser uno de %s" % (nombre, ", ".join(str(x) for x in validos)))
    if rango is not None and not (rango[0] <= v <= rango[1]):
        raise _inv("%s fuera de rango (%d-%d)" % (nombre, rango[0], rango[1]))
    return v


def _pid(v):
    if not isinstance(v, str) or not RE_PID.match(v):
        raise _inv("pid inválido (pNNN)")
    return v


def _parte(v):
    if v not in ("vpn", "suricata", "todo"):
        raise _inv("parte debe ser vpn, suricata o todo")
    return v


def _ipv4(v, nombre):
    try:
        return str(ipaddress.IPv4Address(v))
    except (ValueError, TypeError):
        raise _inv("%s no es una IPv4" % nombre)


def validar_redes(redes, cfg):
    if not isinstance(redes, list) or not redes:
        raise _inv("redes_abonados debe ser una lista no vacía")
    if len(redes) > 64:
        raise _inv("redes_abonados admite como mucho 64 redes")
    out = []
    prohibidas = [(cfg.red_tuneles, "la base de túneles"), (cfg.pool, "el pool de Docker")]
    prohibidas += [(g, "las redes de gestión") for g in cfg.redes_gestion]
    for r in redes:
        if not isinstance(r, str):
            raise _inv("redes_abonados: cada red es un CIDR IPv4 en texto")
        try:
            net = ipaddress.IPv4Network(r.strip(), strict=False)
        except ValueError:
            raise _inv("redes_abonados: %r no es un CIDR IPv4" % r)
        if net.prefixlen == 0:
            raise _inv("redes_abonados: 0.0.0.0/0 no está permitido")
        if net.prefixlen < MIN_PREFIJO_REDES:
            # /1 a /7 sería medio internet en la address-list del espejo (A-28; el panel usa el
            # mismo tope en _redes_validas)
            raise _inv("redes_abonados: %s es demasiado grande (como mucho /%d)" % (net, MIN_PREFIJO_REDES))
        for p, desc in prohibidas:
            if net.overlaps(p):
                raise _inv("redes_abonados: %s se solapa con %s" % (net, desc))
        if str(net) not in out:
            out.append(str(net))
    return out


def validar_crear(params, cfg):
    _solo(params, {"nombre", "redes_abonados", "perfil", "hilos", "ros_version", "compat_v6",
                   "api_puerto", "origen_ip", "pid", "n"}, ("nombre", "redes_abonados"))
    nombre = params["nombre"]
    if not isinstance(nombre, str) or not RE_NOMBRE.match(nombre):
        raise _inv("nombre inválido (^[a-z0-9][a-z0-9-]{1,30}$)")
    perfil = params.get("perfil") or PERFIL_DEFECTO
    if perfil not in PERFILES:
        raise _inv("perfil debe ser " + ", ".join(PERFILES))
    compat = params.get("compat_v6") or "no"
    if compat not in ("no", "seclevel0", "legacy"):
        raise _inv("compat_v6 debe ser no, seclevel0 o legacy")
    out = {"nombre": nombre, "redes_abonados": validar_redes(params["redes_abonados"], cfg),
           "perfil": perfil, "hilos": _int(params.get("hilos", 1), "hilos", rango=(1, 2)),
           "ros_version": _int(params.get("ros_version", 7), "ros_version", validos=(6, 7)),
           "compat_v6": compat,
           "api_puerto": _int(params.get("api_puerto", 8729), "api_puerto", validos=(8729, 8728)),
           "origen_ip": _ipv4(params["origen_ip"], "origen_ip") if params.get("origen_ip") else None,
           "pid": _pid(params["pid"]) if params.get("pid") else None,
           "n": _int(params["n"], "n", rango=(1, N_MAX)) if params.get("n") is not None else None}
    return out


def validar_ajustar(params, cfg):
    _solo(params, {"pid", "perfil", "hilos", "redes_abonados", "compat_v6", "ros_version",
                   "origen_ip"}, ("pid",))
    out = {"pid": _pid(params["pid"])}
    if params.get("perfil") is not None:
        if params["perfil"] not in PERFILES:
            raise _inv("perfil debe ser " + ", ".join(PERFILES))
        out["perfil"] = params["perfil"]
    if params.get("hilos") is not None:
        out["hilos"] = _int(params["hilos"], "hilos", rango=(1, 2))
    if params.get("redes_abonados") is not None:
        out["redes_abonados"] = validar_redes(params["redes_abonados"], cfg)
    if params.get("compat_v6") is not None:
        if params["compat_v6"] not in ("no", "seclevel0", "legacy"):
            raise _inv("compat_v6 debe ser no, seclevel0 o legacy")
        out["compat_v6"] = params["compat_v6"]
    if params.get("ros_version") is not None:
        out["ros_version"] = _int(params["ros_version"], "ros_version", validos=(6, 7))
    if "origen_ip" in params:
        out["origen_ip"] = _ipv4(params["origen_ip"], "origen_ip") if params["origen_ip"] else None
    return out


def validar_params(orden, params, cfg_fn):
    params = params if params is not None else {}
    if orden == "punto.crear":
        return validar_crear(params, cfg_fn())
    if orden == "punto.borrar":
        _solo(params, {"pid", "confirmar"}, ("pid", "confirmar"))
        if not isinstance(params["confirmar"], str):
            raise _inv("confirmar debe ser el nombre del punto")
        return {"pid": _pid(params["pid"]), "confirmar": params["confirmar"]}
    if orden in ("punto.arrancar", "punto.parar", "punto.reiniciar"):
        _solo(params, {"pid", "parte"}, ("pid",))
        return {"pid": _pid(params["pid"]), "parte": _parte(params.get("parte", "todo"))}
    if orden == "punto.ajustar":
        return validar_ajustar(params, cfg_fn())
    if orden == "punto.threshold":
        _solo(params, {"pid", "contenido"}, ("pid", "contenido"))
        return {"pid": _pid(params["pid"]), "contenido": validar_threshold(params["contenido"])}
    if orden in ("punto.vpn.regenerar", "punto.comandos", "punto.api.huella", "punto.medir"):
        _solo(params, {"pid"}, ("pid",))
        return {"pid": _pid(params["pid"])}
    if orden == "punto.estado":
        _solo(params, {"pid"})
        pid = params.get("pid", "*")
        return {"pid": pid if pid == "*" else _pid(pid)}
    if orden == "punto.logs":
        _solo(params, {"pid", "parte", "lineas"}, ("pid",))
        parte = params.get("parte", "vpn")
        if parte not in ("vpn", "suricata"):
            raise _inv("parte debe ser vpn o suricata")
        return {"pid": _pid(params["pid"]), "parte": parte,
                "lineas": _int(params.get("lineas", 100), "lineas", rango=(1, 500))}
    if orden == "reglas.actualizar":
        _solo(params, {"sin_descarga"})
        v = params.get("sin_descarga", False)
        if not isinstance(v, bool):
            raise _inv("sin_descarga debe ser booleano")
        return {"sin_descarga": v}
    if orden == "logs.reabrir":
        _solo(params, {"pid"})
        return {"pid": _pid(params["pid"])} if params.get("pid") else {}
    if orden in ("sistema.reconciliar", "sistema.estado", "sistema.capacidad"):
        _solo(params, set())
        return {}
    if orden == "op.estado":
        _solo(params, {"op_id"}, ("op_id",))
        if not isinstance(params["op_id"], str) or not RE_OPID.match(params["op_id"]):
            raise _inv("op_id inválido")
        return {"op_id": params["op_id"]}
    raise _inv("orden desconocida")


# --------------------------------------------------------------------------------------------
# Sockets de control (unix-command de Suricata, management de OpenVPN, relé de la API)
# --------------------------------------------------------------------------------------------

def _unix(path, timeout=10):
    """Conecta a un socket de control de un contenedor (ctl/<pid>, run/<pid>). El contenedor
    puede cambiar lo que hay en ese nombre (A-04): solo se conecta si es un socket y no un
    enlace (que podría llevar al socket de otro punto o del host)."""
    import socket
    if not hasattr(socket, "AF_UNIX"):
        raise ErrorOrden("FALLO", "AF_UNIX no disponible en esta plataforma")
    try:
        st = os.lstat(str(path))
    except OSError as e:
        raise ErrorOrden("FALLO", "sin socket %s: %s" % (path, e.strerror or e))
    if not stat.S_ISSOCK(st.st_mode):
        raise ErrorOrden("FALLO", "%s no es un socket (¿enlace?): no se usa" % path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(path))
    return s


def _leer_json(s):
    buf = b""
    while len(buf) < MAX_MENSAJE:
        trozo = s.recv(4096)
        if not trozo:
            break
        buf += trozo
        try:
            return json.loads(buf.decode("utf-8"))
        except ValueError:
            continue
    return json.loads(buf.decode("utf-8") or "{}")


def suricata_comando(pid, comando):
    """Una orden por el socket de control de Suricata. Cada mensaje JSON va terminado en salto
    de línea: Suricata 7 cierra la conexión si la orden llega sin él (visto en el laboratorio:
    `reopen-log-files` fallaba tras cada rotación, el eve nuevo se quedaba sin `stats` y el
    contenedor acababa reiniciado por «unhealthy»)."""
    path = ruta("/srv/ids/ctl/%s/suricata/suricata-command.socket" % pid)
    s = _unix(path)
    try:
        s.sendall((json.dumps({"version": "0.2"}) + "\n").encode())
        r = _leer_json(s)
        if r.get("return") != "OK":
            raise ErrorOrden("FALLO", "suricata rechazó la versión del protocolo")
        s.sendall((json.dumps({"command": comando}) + "\n").encode())
        r = _leer_json(s)
        if r.get("return") != "OK":
            raise ErrorOrden("FALLO", "suricata: %s" % r.get("message", "error"))
        return r
    finally:
        s.close()


def openvpn_kill(pid, usuario):
    path = ruta("/srv/ids/ctl/%s/vpn/ovpn-mgmt.sock" % pid)
    s = _unix(path)
    try:
        s.recv(4096)
        s.sendall(("kill %s\n" % usuario).encode())
        return s.recv(4096).decode("utf-8", errors="replace").strip()
    finally:
        s.close()


def huella_api(pid):
    import ssl
    s = _unix(ruta("/srv/ids/run/%s/api.sock" % pid), timeout=15)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except (AttributeError, ValueError):
        pass
    try:
        t = ctx.wrap_socket(s, server_hostname=None)
        der = t.getpeercert(binary_form=True)
        t.close()
    finally:
        s.close()
    if not der:
        raise ErrorOrden("FALLO", "el router no presentó certificado (¿API-SSL sin ids-promax?)")
    return hashlib.sha256(der).hexdigest()


# --------------------------------------------------------------------------------------------
# Orquestador
# --------------------------------------------------------------------------------------------

class Orquestador:
    def __init__(self):
        self.db = abrir_db()
        self._db_lock = threading.RLock()
        self._cola_cv = threading.Condition()
        self._secretos = {}
        self._netns = {}
        self._programados = {}
        self._espejo = {}
        self._peticiones = {}
        self._parar = threading.Event()
        self._ultimo_netns = 0.0
        self._en_curso = None
        self._ultima_poda = 0.0
        self._threshold_fallido = {}     # pid -> {"ts", "mensaje"} hasta el siguiente que vaya bien

    # ---- base de datos -----------------------------------------------------------------------
    def q(self, sql, args=()):
        with self._db_lock:
            return self.db.execute(sql, args).fetchall()

    def q1(self, sql, args=()):
        with self._db_lock:
            return self.db.execute(sql, args).fetchone()

    def x(self, sql, args=()):
        with self._db_lock:
            return self.db.execute(sql, args)

    @contextmanager
    def tx(self):
        with self._db_lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
            self.db.execute("COMMIT")

    def _base(self):
        try:
            return config().tun_base
        except ErrorOrden:
            return "100.64"

    def punto(self, pid):
        return fila_a_punto(self.q1("SELECT * FROM punto WHERE pid=?", (pid,)), self._base())

    def puntos(self):
        base = self._base()
        return [fila_a_punto(f, base) for f in self.q("SELECT * FROM punto ORDER BY n")]

    # ---- protocolo ---------------------------------------------------------------------------
    def atender(self, pet, uid=0):
        op_id = pet.get("op_id") if isinstance(pet, dict) else None

        def resp(codigo, mensaje, datos=None):
            return {"op_id": op_id, "ok": codigo in ("OK", "ACEPTADA"), "codigo": codigo,
                    "mensaje": mensaje, "datos": datos or {}}

        if not isinstance(pet, dict) or pet.get("v") != 1:
            return resp("INVALIDO", "petición inválida (v=1)")
        try:
            token = leer_token()
        except OSError:
            return resp("FALLO", "no se puede leer el token del orquestador")
        try:
            token_ok = isinstance(pet.get("token"), str) and hmac.compare_digest(
                pet["token"].encode("utf-8"), token.encode("utf-8"))
        except (UnicodeError, TypeError):       # p. ej. un surrogate suelto (A-23)
            token_ok = False
        if not token_ok:
            log("petición con token inválido (uid %s)" % uid)
            return resp("INVALIDO", "token inválido")
        if not isinstance(op_id, str) or not RE_OPID.match(op_id):
            return resp("INVALIDO", "op_id inválido")
        orden = pet.get("orden")
        quien = pet.get("quien") if isinstance(pet.get("quien"), str) else ""
        quien = re.sub(r"[^\w:.@-]", "_", quien)[:64] or "desconocido"
        if orden in ORDENES_RESERVADAS:
            return resp("INVALIDO", "no disponible en F1a")
        if orden not in ORDENES_COLA and orden not in ORDENES_LECTURA:
            return resp("INVALIDO", "orden desconocida")
        try:
            params = validar_params(orden, pet.get("params"), config)
        except ErrorOrden as e:
            return resp(e.codigo, e.mensaje, e.datos)
        if orden == "punto.crear" and params.get("pid") and uid != 0:
            # el pid explícito es solo de la CLI root (reconstruir): desde el panel agotaría la
            # secuencia con p999 (A-22)
            return resp("INVALIDO", "pid explícito: solo desde la CLI del servidor")
        # punto.borrar sí se encola: de un pid inexistente limpia restos («no existía») y solo
        # alcanzaría a un punto posterior con el MISMO nombre (exige confirmar = nombre)
        if (orden in ORDENES_COLA and orden not in ("punto.crear", "punto.borrar") and params.get("pid")
                and self.punto(params["pid"]) is None
                and self.q1("SELECT 1 FROM op WHERE op_id=?", (op_id,)) is None):
            # una orden para un punto que no existe se rechaza al encolar: si no, se ejecutaría
            # sobre el punto que se cree después con ese pid (A-22). Un reintento de una orden ya
            # encolada (mismo op_id) sigue dando su estado.
            return resp("NO_EXISTE", "no existe %s" % params["pid"])
        if orden == "punto.threshold":
            # se rechaza ya al encolar: un punto inexistente o dándose de baja no recibe nada
            p = self.punto(params["pid"])
            if p is None:
                return resp("NO_EXISTE", "no existe %s" % params["pid"])
            if p["estado"] == "borrando":
                return resp("CONFLICTO", "%s se está dando de baja" % params["pid"])
        if orden in ORDENES_COLA:
            try:
                return self.encolar(op_id, orden, params, quien)
            except sqlite3.Error as e:
                log("encolar: %r" % e)
                return resp("FALLO", "no se pudo encolar: %s" % e)
        try:
            datos = self.leer(orden, params)
            return resp("OK", "ok", datos)
        except ErrorOrden as e:
            return resp(e.codigo, e.mensaje, e.datos)
        except Exception as e:  # noqa: BLE001 - una lectura nunca tumba el servicio
            log("fallo en %s: %r" % (orden, e))
            return resp("FALLO", str(e))

    def encolar(self, op_id, orden, params, quien):
        sha = sha256_txt(canon({"orden": orden, "params": params}))
        with self.tx() as db:
            f = db.execute("SELECT * FROM op WHERE op_id=?", (op_id,)).fetchone()
            if f is not None:
                if f["orden"] != orden or f["params_sha256"] != sha:
                    return {"op_id": op_id, "ok": False, "codigo": "CONFLICTO",
                            "mensaje": "op_id ya usado con otra orden u otros parámetros", "datos": {}}
                if f["estado"] == "terminada":
                    return {"op_id": op_id, "ok": f["codigo"] == "OK", "codigo": f["codigo"],
                            "mensaje": f["mensaje"], "datos": json.loads(f["datos"] or "{}")}
                delante = db.execute("SELECT COUNT(*) FROM op WHERE estado IN ('pendiente','en_curso') "
                                     "AND seq<?", (f["seq"],)).fetchone()[0]
                return {"op_id": op_id, "ok": True, "codigo": "ACEPTADA", "mensaje": "ya en cola",
                        "datos": {"op_id": op_id, "delante": delante}}
            delante = db.execute("SELECT COUNT(*) FROM op WHERE estado IN ('pendiente','en_curso')").fetchone()[0]
            db.execute("INSERT INTO op (op_id, orden, params_sha256, params, pid, quien, estado, creado) "
                       "VALUES (?,?,?,?,?,?,'pendiente',?)",
                       (op_id, orden, sha, canon(params), params.get("pid"), quien, ahora()))
        with self._cola_cv:
            self._cola_cv.notify_all()
        return {"op_id": op_id, "ok": True, "codigo": "ACEPTADA", "mensaje": "en cola",
                "datos": {"op_id": op_id, "delante": delante}}

    def encolar_interno(self, orden, params, quien):
        """Encola una orden del propio orquestador si no hay otra igual pendiente."""
        sha = sha256_txt(canon({"orden": orden, "params": params}))
        if self.q1("SELECT 1 FROM op WHERE estado='pendiente' AND params_sha256=?", (sha,)):
            return None
        op_id = str(uuid.uuid4())
        self.encolar(op_id, orden, params, quien)
        return op_id

    # ---- cola en serie ------------------------------------------------------------------------
    def _progreso(self, ctx):
        self.x("UPDATE op SET paso=?, pasos=?, total=?, log=? WHERE op_id=?",
               (ctx.paso_actual, json.dumps(ctx.pasos, ensure_ascii=False), ctx.total,
                json.dumps(ctx.log[-20:], ensure_ascii=False), ctx.op_id))

    def procesar_una(self):
        """Ejecuta la siguiente orden pendiente. Devuelve False si la cola está vacía."""
        with self.tx() as db:
            f = db.execute("SELECT * FROM op WHERE estado='pendiente' ORDER BY seq LIMIT 1").fetchone()
            if f is None:
                return False
            db.execute("UPDATE op SET estado='en_curso', inicio=? WHERE op_id=?", (ahora(), f["op_id"]))
        params = json.loads(f["params"] or "{}")
        ctx = Contexto(self, f["op_id"], f["orden"])
        ctx.pid = params.get("pid")
        ctx.quien = f["quien"] or ""
        self._en_curso = {"op_id": f["op_id"], "orden": f["orden"], "pid": params.get("pid"),
                          "desde": ahora()}
        secretos = None
        try:
            datos, secretos = self.ejecutar_orden(ctx, f["orden"], params)
            codigo, mensaje = "OK", ctx.mensaje or "ok"
        except ErrorOrden as e:
            codigo, mensaje, datos = e.codigo, e.mensaje, e.datos
            if ctx.deshacer and self._deshacer(ctx) and codigo not in (
                    "INVALIDO", "CONFLICTO", "CONFLICTO_PUERTO", "NO_EXISTE"):
                codigo = "REVERTIDA"
                mensaje = "falló «%s»: %s; deshecho" % (ctx.paso_actual, e.mensaje)
        except Exception as e:  # noqa: BLE001
            log("fallo inesperado en %s: %r" % (f["orden"], e))
            codigo, mensaje, datos = "FALLO", "error interno: %s" % e, {}
            if ctx.deshacer and self._deshacer(ctx):
                codigo = "REVERTIDA"
                mensaje = "falló «%s»: %s; deshecho" % (ctx.paso_actual, e)
        finally:
            self._en_curso = None
        if secretos:
            self._secretos[f["op_id"]] = secretos
        self.x("UPDATE op SET estado='terminada', codigo=?, mensaje=?, datos=?, pasos=?, total=?, "
               "log=?, fin=?, params=NULL, pid=COALESCE(?, pid) WHERE op_id=?",
               (codigo, mensaje, json.dumps(datos or {}, ensure_ascii=False),
                json.dumps(ctx.pasos, ensure_ascii=False), ctx.total,
                json.dumps(ctx.log[-20:], ensure_ascii=False), ahora(), ctx.pid, f["op_id"]))
        self._diario(f, ctx, codigo)
        # estado.json al momento: si no, el panel sigue viendo hasta 15 s el punto recien dado de
        # baja (o parado, o creado) como estaba antes de la orden
        try:
            self.escribir_estado()
        except Exception as e:  # noqa: BLE001 - el ciclo de supervision lo reescribe igual
            log("estado tras %s: %r" % (f["orden"], e))
        with self._cola_cv:
            self._cola_cv.notify_all()
        return True

    def _deshacer(self, ctx):
        try:
            ctx.deshacer()
            return True
        except Exception as e:  # noqa: BLE001
            log("deshacer falló: %r" % e)
            ctx.registrar("deshacer falló: %s" % e)
            return False

    def _diario(self, f, ctx, codigo):
        """orq.jsonl: una línea por orden terminada, sin secretos ni parámetros en claro."""
        linea = {"ts": ahora(), "op_id": f["op_id"], "quien": f["quien"], "orden": f["orden"],
                 "pid": ctx.pid or f["pid"], "params_sha256": f["params_sha256"],
                 "pasos": ["%s:%s" % (p["nombre"], p["estado"]) for p in ctx.pasos],
                 "codigo": codigo,
                 "mensaje": "ok" if codigo == "OK" else "%s en «%s»" % (codigo, ctx.paso_actual or "-")}
        self._diario_linea(linea)

    def _diario_linea(self, linea):
        try:
            with open(ruta("/srv/ids/estado/orq.jsonl"), "a", encoding="utf-8") as fh:
                fh.write(json.dumps(linea, ensure_ascii=False) + "\n")
        except OSError as e:
            log("no se pudo escribir orq.jsonl: %s" % e)

    def trabajador(self):
        while not self._parar.is_set():
            try:
                hubo = self.procesar_una()
            except Exception as e:  # noqa: BLE001
                log("trabajador: %r" % e)
                hubo = False
            if not hubo:
                with self._cola_cv:
                    self._cola_cv.wait(timeout=1.0)

    def ejecutar_orden(self, ctx, orden, params):
        manejadores = {
            "punto.crear": self.o_crear, "punto.borrar": self.o_borrar,
            "punto.arrancar": self.o_arrancar, "punto.parar": self.o_parar,
            "punto.reiniciar": self.o_reiniciar, "punto.ajustar": self.o_ajustar,
            "punto.vpn.regenerar": self.o_regenerar, "punto.threshold": self.o_threshold,
            "reglas.actualizar": self.o_reglas,
            "sistema.reconciliar": self.o_reconciliar,
        }
        r = manejadores[orden](ctx, params)
        if isinstance(r, tuple):
            return r
        return r, None

    # ---- lecturas -----------------------------------------------------------------------------
    def leer(self, orden, params):
        if orden == "op.estado":
            return self.op_estado(params["op_id"])
        if orden == "punto.estado":
            est = self.construir_estado(con_puntos=True)
            if params["pid"] == "*":
                return {"puntos": est["puntos"]}
            if params["pid"] not in est["puntos"]:
                raise ErrorOrden("NO_EXISTE", "no existe %s" % params["pid"])
            return est["puntos"][params["pid"]]
        if orden == "sistema.estado":
            est = self.construir_estado(con_puntos=False)
            est.pop("puntos", None)
            return est
        if orden == "sistema.capacidad":
            return self.capacidad()
        p = None
        if params.get("pid"):
            p = self.punto(params["pid"])
            if p is None:
                raise ErrorOrden("NO_EXISTE", "no existe %s" % params["pid"])
        if orden == "punto.comandos":
            return {"comandos": comandos_mikrotik(p, config().nombre_dns)}
        if orden == "punto.logs":
            return self.logs(p, params["parte"], params["lineas"])
        if orden == "punto.api.huella":
            return {"sha256": huella_api(p["pid"])}
        if orden == "punto.medir":
            return self.medir(p)
        if orden == "logs.reabrir":
            objetivo = [p] if p else [x for x in self.puntos() if x["estado"] in ("activo", "error")]
            out = {}
            for x in objetivo:
                try:
                    suricata_comando(x["pid"], "reopen-log-files")
                    out[x["pid"]] = "OK"
                except Exception as e:  # noqa: BLE001
                    out[x["pid"]] = "fallo: %s" % e
            return {"puntos": out}
        raise ErrorOrden("INVALIDO", "orden desconocida")

    def op_estado(self, op_id):
        f = self.q1("SELECT * FROM op WHERE op_id=?", (op_id,))
        if f is None:
            raise ErrorOrden("NO_EXISTE", "op desconocida")
        pasos = json.loads(f["pasos"] or "[]")
        total = f["total"]
        out = {"estado": f["estado"], "orden": f["orden"], "paso": f["paso"],
               "avance": "%d/%s" % (len(pasos), total if total else "?"), "pasos": pasos,
               "log_tail": json.loads(f["log"] or "[]")}
        if f["estado"] == "pendiente":
            out["delante"] = self.q1("SELECT COUNT(*) FROM op WHERE estado IN ('pendiente','en_curso') "
                                     "AND seq<?", (f["seq"],))[0]
        if f["estado"] == "terminada":
            out["codigo"] = f["codigo"]
            out["mensaje"] = f["mensaje"]
            datos = json.loads(f["datos"] or "{}")
            secreto = self._secretos.pop(op_id, None)
            if secreto:
                datos = dict(datos, **secreto)
            out["resultado"] = datos
        return out

    def logs(self, p, parte, lineas):
        nombre = nombres_contenedores(p["pid"])[parte]
        r = ejecutar(["docker", "logs", "--tail", str(lineas), nombre], timeout=60)
        filtro = re.compile(r"password|key", re.I)
        todas = (r.out + r.err).splitlines()
        return {"lineas": [x for x in todas if not filtro.search(x)][-lineas:]}

    def medir(self, p):
        nombres = nombres_contenedores(p["pid"])
        info = docker_inspect(list(nombres.values()))
        sur = info.get(nombres["suricata"]) or {}
        actual = pico = None
        cid = sur.get("id")
        if cid:
            for base in ("/sys/fs/cgroup/system.slice/docker-%s.scope" % cid,
                         "/sys/fs/cgroup/docker/%s" % cid):
                d = kruta(base)
                if (d / "memory.current").exists():
                    actual = int((d / "memory.current").read_text().strip()) // (1024 * 1024)
                    if (d / "memory.peak").exists():
                        pico = int((d / "memory.peak").read_text().strip()) // (1024 * 1024)
                    break
        t = ahora()
        st = leer_stats_eve(ruta("/srv/ids/datos/%s/eve.json" % p["pid"]), t)
        return {"memoria_actual_mb": actual, "memoria_pico_mb": pico,
                "kernel_packets": st["kernel_packets"], "kernel_drops": st["kernel_drops"],
                "reglas_cargadas": st["reglas_cargadas"],
                "tzsp": leer_tzsp(ruta("/srv/ids/run/%s/tzsp.json" % p["pid"]), t)}

    def capacidad(self):
        mem = meminfo()
        vivos = [(p["perfil"], p["hilos"]) for p in self.puntos()]
        return {"mem_total_mb": mem["total"], "mem_comprometida_mb": memoria_comprometida(vivos),
                "mem_disponible_mb": mem["disponible"], "caben": caben(vivos, mem)}

    # ---- estado.json --------------------------------------------------------------------------
    def construir_estado(self, con_puntos=True):
        t = ahora()
        try:
            imgs = imagenes()
        except (ErrorOrden, OSError, ValueError):
            imgs = {"dev": False, "version": ""}
        try:
            cfg = config()
            version, base = cfg.version, cfg.tun_base
        except (ErrorOrden, OSError):
            version, base = "", None
        pend = self.q1("SELECT COUNT(*) FROM op WHERE estado='pendiente'")[0]
        en_curso = None
        f = self.q1("SELECT op_id, orden, pid, paso, inicio FROM op WHERE estado='en_curso' LIMIT 1")
        if f is not None:
            en_curso = {"op_id": f["op_id"], "orden": f["orden"], "pid": f["pid"],
                        "paso": f["paso"], "desde": f["inicio"]}
        try:
            cap = self.capacidad()
        except OSError:
            cap = {"mem_total_mb": None, "mem_comprometida_mb": None, "mem_disponible_mb": None,
                   "caben": {}}
        libre = disco_libre_pct()
        est = {"v": 1, "ts": t, "orq_version": ORQ_VERSION, "version": version,
               "dev": bool(imgs.get("dev")), "tun_base": base,
               "cola": {"en_curso": en_curso, "pendientes": pend}, "capacidad": cap,
               "reglas": leer_reglas(), "disco": {"srv_ids_libre_pct": libre}, "puntos": {}}
        if not con_puntos:
            return est
        puntos = self.puntos()
        nombres = []
        for p in puntos:
            nombres += list(nombres_contenedores(p["pid"]).values())
        info = docker_inspect(nombres)
        for p in puntos:
            est["puntos"][p["pid"]] = self._estado_punto(p, info, t, libre)
        return est

    def _reinicios_1h(self, pid, parte, t):
        return self.q1("SELECT COUNT(*) FROM reinicio WHERE pid=? AND parte=? AND ts>?",
                       (pid, parte, t - 3600))[0]

    def _estado_punto(self, p, info, t, libre):
        pid = p["pid"]
        cont = {}
        for parte, nombre in nombres_contenedores(pid).items():
            i = info.get(nombre)
            cont[parte] = {"estado": i["estado"] if i else "ausente",
                           "salud": i["salud"] if i else "none",
                           "inicio": i["inicio"] if i else None,
                           "reinicios_1h": self._reinicios_1h(pid, parte, t),
                           "imagen": i["imagen"] if i else None}
        ns = self._netns.get(pid) or {"coherente": None, "vpn": None, "suricata": None}
        tz = leer_tzsp(ruta("/srv/ids/run/%s/tzsp.json" % pid), t)
        su = leer_stats_eve(ruta("/srv/ids/datos/%s/eve.json" % pid), t)
        avisos = self._avisos_espejo(p, tz, su, t)
        if ns.get("coherente") is False:
            avisos.append("NETNS-DISTINTO")
        if any(c["reinicios_1h"] >= MAX_REINICIOS_HORA for c in cont.values()):
            avisos.append("REINICIOS")
        if libre is not None and libre < DISCO_MIN_LIBRE_PCT:
            avisos.append("DISCO")
        retencion = self.retencion_punto(pid, t)
        if retencion["anticipado"]:
            avisos.append("RETENCION-REDUCIDA")
        if pid in self._threshold_fallido:
            avisos.append("THRESHOLD-FALLIDO")
        return {
            "nombre": p["nombre"], "n": p["n"], "puerto": p["puerto"], "tun_net": p["tun_net"],
            "perfil": p["perfil"], "hilos": p["hilos"], "ros_version": p["ros_version"],
            "compat_v6": p["compat_v6"], "deseado": p["deseado"], "estado": p["estado"],
            # lo que necesita el panel para hablar con el MikroTik y montar su espejo
            "redes": list(p["redes"]), "api_puerto": p["api_puerto"], "sensor": p["sensor"],
            "mk": p["mk"], "tzsp_puerto": TZSP_PUERTO,
            "contenedores": cont, "netns": ns,
            "vpn_cliente": leer_status_openvpn(ruta("/srv/ids/run/%s/openvpn-status.log" % pid)),
            "tzsp": tz, "suricata": su, "avisos": avisos,
            # CONTRATO-F2 §9: desde qué fecha hay eventos y si hubo borrado antes de tiempo
            "retencion": retencion,
        }

    def _avisos_espejo(self, p, tz, su, t):
        """SIN-ESPEJO: activo y sin subir tzsp.tx en 10 min. ESPEJO-NO-LLEGA: tzsp.tx sube en los
        últimos 2 min y capture.kernel_packets lleva 2 min sin subir."""
        avisos = []
        if tz["tx"] is None:
            return avisos
        kp = su["kernel_packets"]
        st = self._espejo.get(p["pid"])
        if st is None or tz["tx"] < st["tx"]:          # primera vez o tzsp-decap reiniciado
            st = {"tx": tz["tx"], "kp": kp, "desde": t, "ultimo_tx": None, "tx_sin_kp": None}
        else:
            if kp is not None and (st["kp"] is None or kp > st["kp"]):
                st["tx_sin_kp"] = None                   # Suricata ve paquetes: todo bien
            elif tz["tx"] > st["tx"] and st["tx_sin_kp"] is None:
                st["tx_sin_kp"] = t                      # entra espejo y kernel_packets no sube
            if tz["tx"] > st["tx"]:
                st["ultimo_tx"] = t
            st["tx"], st["kp"] = tz["tx"], kp
        self._espejo[p["pid"]] = st
        if p["deseado"] != "activo":
            return avisos
        if t - (st["ultimo_tx"] or st["desde"]) >= 600:
            avisos.append("SIN-ESPEJO")
        elif (st["tx_sin_kp"] is not None and t - st["tx_sin_kp"] >= 120
              and t - st["ultimo_tx"] < 120):
            avisos.append("ESPEJO-NO-LLEGA")
        return avisos

    def escribir_estado(self):
        est = self.construir_estado(con_puntos=True)
        d = asegurar_dir(ruta("/srv/ids/run"), 0o750, 0, GID_PANEL)
        escribir_atomico(d / "estado.json", json.dumps(est, ensure_ascii=False, indent=1) + "\n",
                         modo=0o640, uid=0, gid=GID_PANEL)
        return est

    # ---- retención de eventos (CONTRATO-F2 §9) ------------------------------------------------
    def _retencion(self):
        """{pid: {"ultimo_anticipado": ts, "cota": ts}} en /srv/ids/estado/retencion.json."""
        if getattr(self, "_ret_cache", None) is None:
            try:
                d = json.loads(ruta("/srv/ids/estado/retencion.json").read_text(encoding="utf-8"))
                self._ret_cache = d if isinstance(d, dict) else {}
            except (OSError, ValueError):
                self._ret_cache = {}
        return self._ret_cache

    def _retencion_guardar(self):
        asegurar_dir(ruta("/srv/ids/estado"), 0o700)
        escribir_atomico(ruta("/srv/ids/estado/retencion.json"),
                         json.dumps(self._retencion(), ensure_ascii=False, sort_keys=True) + "\n", modo=0o600)

    def retencion_punto(self, pid, t):
        """Retención efectiva publicada en estado.json: fecha del dato más viejo que queda y si
        hubo borrado anticipado por disco en los últimos RETENCION_DIAS (mientras tanto no se
        puede prometer el objetivo)."""
        desde = datos_mas_viejos(pid)
        ult = (self._retencion().get(pid) or {}).get("ultimo_anticipado")
        anticipado = bool(ult and t - ult < RETENCION_DIAS * 86400)
        return {"objetivo_dias": RETENCION_DIAS, "desde": desde,
                "dias": round(max(0, t - desde) / 86400.0, 1) if desde else None,
                "anticipado": anticipado,
                "ultimo_anticipado": ult if anticipado else None}

    def _pids_datos(self):
        d = ruta("/srv/ids/datos")
        try:
            return sorted(x.name for x in d.iterdir() if x.is_dir() and RE_PID.match(x.name))
        except OSError:
            return []

    def podar_por_fecha(self, t):
        """Borra los rotados cuyo último evento posible tiene más de RETENCION_DIAS."""
        limite = int(t) - RETENCION_DIAS * 86400
        total = 0
        for pid in self._pids_datos():
            borrados = 0
            for cota, f in rotados(pid):
                if cota >= limite:
                    break
                try:
                    f.unlink()
                    borrados += 1
                except OSError as e:
                    log("poda por fecha: %s: %s" % (f, e))
            if borrados:
                total += borrados
                self._diario_linea({"ts": int(t), "evento": "poda.fecha", "pid": pid,
                                    "ficheros": borrados, "limite": limite})
        return total

    def podar_por_disco(self, t, libre_fn=None):
        """Con /srv/ids por debajo de DISCO_MIN_LIBRE_PCT, borra los rotados más viejos (de
        cualquier punto) hasta recuperar el umbral. Cada borrado anticipado queda en orq.jsonl y
        marca el punto (retención efectiva menor que el objetivo). Nunca toca los vivos."""
        libre_fn = libre_fn or disco_libre_pct
        libre = libre_fn()
        if libre is None or libre >= DISCO_MIN_LIBRE_PCT:
            return []
        candidatos = sorted((cota, pid, f) for pid in self._pids_datos() for cota, f in rotados(pid))
        borrados = []
        for cota, pid, f in candidatos:
            if libre is not None and libre >= DISCO_MIN_LIBRE_PCT:
                break
            try:
                f.unlink()
            except OSError as e:
                log("poda por disco: %s: %s" % (f, e))
                continue
            borrados.append((pid, f.name, cota))
            self._diario_linea({"ts": int(t), "evento": "poda.disco", "pid": pid, "fichero": f.name,
                                "cota": cota, "libre_pct": libre})
            self._retencion()[pid] = {"ultimo_anticipado": int(t), "cota": cota}
            libre = libre_fn()
        if borrados:
            self._retencion_guardar()
            log("disco: %d rotado(s) borrado(s) antes de tiempo (libre %s %%)" % (len(borrados), libre))
        if libre is not None and libre < DISCO_MIN_LIBRE_PCT:
            log("disco: sigue por debajo del %d %% libre y no quedan rotados que borrar" % DISCO_MIN_LIBRE_PCT)
        return borrados

    # ---- supervisión --------------------------------------------------------------------------
    def comprobar_netns(self, pid):
        n = nombres_contenedores(pid)
        r = ejecutar(["docker", "inspect", "--type", "container", "-f", "{{.State.Pid}}",
                      n["vpn"], n["suricata"]], timeout=30)
        pids = [int(x) for x in r.out.split() if x.strip().isdigit()]
        res = {"coherente": None, "vpn": None, "suricata": None}
        if r.rc != 0 or len(pids) != 2 or 0 in pids:
            self._netns[pid] = res
            return res
        try:
            ino = [os.stat(kruta("/proc/%d/ns/net" % x)).st_ino for x in pids]
        except OSError:
            self._netns[pid] = res
            return res
        res = {"coherente": ino[0] == ino[1], "vpn": ino[0], "suricata": ino[1]}
        self._netns[pid] = res
        if not res["coherente"]:
            log("%s: netns distintos (vpn %s, suricata %s): se reinicia suricata" % (pid, ino[0], ino[1]))
            self.encolar_interno("punto.reiniciar", {"pid": pid, "parte": "suricata"}, "orq:netns")
        return res

    def evento(self, ev):
        """Un evento de `docker events` filtrado por la etiqueta ids-maat.punto."""
        attrs = ((ev.get("Actor") or {}).get("Attributes")) or {}
        pid = attrs.get("ids-maat.punto")
        parte = attrs.get("ids-maat.parte")
        accion = ev.get("Action") or ev.get("status") or ""
        if not pid or not RE_PID.match(pid) or parte not in ("vpn", "suricata"):
            return
        p = self.punto(pid)
        if p is None:
            return
        if accion == "start" and parte == "vpn":
            self.comprobar_netns(pid)
        elif accion == "die" and p["deseado"] == "activo" and (self._en_curso or {}).get("pid") != pid:
            self.x("INSERT INTO reinicio (pid, parte, ts) VALUES (?,?,?)", (pid, parte, ahora()))
        elif accion.startswith("health_status") and accion.endswith("unhealthy"):
            self.programar_reinicio(pid, parte)

    def programar_reinicio(self, pid, parte, t=None):
        t = t if t is not None else time.time()
        p = self.punto(pid)
        if p is None or p["deseado"] != "activo" or p["estado"] == "error":
            return
        if (pid, parte) in self._programados:
            return
        hechos = self._reinicios_1h(pid, parte, int(t))
        if hechos >= MAX_REINICIOS_HORA:
            self.x("UPDATE punto SET estado='error', paso_error=?, actualizado=? WHERE pid=?",
                   ("%s unhealthy tras %d reinicios en 1 h" % (parte, hechos), ahora(), pid))
            log("%s: %s sigue unhealthy tras %d reinicios en 1 h: punto en error" % (pid, parte, hechos))
            return
        self._programados[(pid, parte)] = t + ESPERAS_REINICIO_S[min(hechos, len(ESPERAS_REINICIO_S) - 1)]

    def tick(self, t=None):
        t = t if t is not None else time.time()
        for (pid, parte), cuando in list(self._programados.items()):
            if cuando <= t:
                del self._programados[(pid, parte)]
                info = docker_inspect([nombres_contenedores(pid)[parte]])
                i = info.get(nombres_contenedores(pid)[parte])
                if i and i["salud"] == "unhealthy":
                    self.x("INSERT INTO reinicio (pid, parte, ts) VALUES (?,?,?)", (pid, parte, int(t)))
                    self.encolar_interno("punto.reiniciar", {"pid": pid, "parte": parte}, "orq:salud")
        if t - self._ultimo_netns >= INTERVALO_NETNS_S:
            self._ultimo_netns = t
            for p in self.puntos():
                if p["deseado"] == "activo" and p["estado"] in ("activo", "error"):
                    self.comprobar_netns(p["pid"])
        try:
            if t - self._ultima_poda >= INTERVALO_PODA_S:
                self._ultima_poda = t
                self.podar_por_fecha(t)
            self.podar_por_disco(t)
        except Exception as e:  # noqa: BLE001 - la poda nunca para la supervisión
            log("poda: %r" % e)
        est = self.escribir_estado()
        for pid, e in est["puntos"].items():
            for parte, c in e["contenedores"].items():
                if c["salud"] == "unhealthy":
                    self.programar_reinicio(pid, parte, t)
        return est

    def bucle_supervision(self):
        while not self._parar.is_set():
            try:
                self.tick()
            except Exception as e:  # noqa: BLE001
                log("supervisión: %r" % e)
            self._parar.wait(INTERVALO_ESTADO_S)

    def bucle_compresion(self):
        """Hilo aparte: comprimir un rotado de 1 GB tarda y no puede retrasar estado.json."""
        while not self._parar.is_set():
            try:
                comprimir_rotados(self._pids_datos(), time.time())
            except Exception as e:  # noqa: BLE001
                log("compresión: %r" % e)
            self._parar.wait(INTERVALO_COMPRIMIR_S)

    def bucle_eventos(self):
        espera = 1
        while not self._parar.is_set():
            try:
                proc = subprocess.Popen(["docker", "events", "--format", "{{json .}}", "--filter",
                                         "label=ids-maat.punto"], stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True)
                espera = 1
                for linea in proc.stdout:
                    if self._parar.is_set():
                        break
                    try:
                        self.evento(json.loads(linea))
                    except Exception as e:  # noqa: BLE001
                        log("evento: %r" % e)
                proc.kill()
            except OSError as e:
                log("docker events: %s" % e)
            self._parar.wait(espera)
            espera = min(espera * 2, 30)

    def arrancar(self):
        """Libera la cola tras un reinicio del servicio y encola la reconciliación."""
        for f in self.q("SELECT * FROM op WHERE estado='en_curso'"):
            self.x("UPDATE op SET estado='terminada', codigo='FALLO', mensaje='error: interrumpida', "
                   "fin=?, params=NULL WHERE op_id=?", (ahora(), f["op_id"]))
        for p in [x for x in self.puntos() if x["estado"] == "creando"]:
            log("%s: alta interrumpida; se deshace" % p["pid"])
            try:
                self.limpiar_punto(p, enfriar=False)
            except Exception as e:  # noqa: BLE001
                log("%s: no se pudo deshacer: %r" % (p["pid"], e))
        self.x("DELETE FROM op WHERE estado='terminada' AND fin<?", (ahora() - RETENCION_OPS_S,))
        self.encolar_interno("sistema.reconciliar", {}, "orq:arranque")

    # ---- piezas comunes -----------------------------------------------------------------------
    def regenerar_fw(self, excluir=None):
        cfg = config()
        puertos, origenes = [], []
        for p in self.puntos():
            if p["pid"] == excluir or p["estado"] == "borrando":
                continue
            if not ruta("/srv/ids/puntos/%s" % p["pid"]).is_dir():
                continue
            puertos.append(p["puerto"])
            if p.get("origen_ip"):
                origenes.append((p["pid"], p["puerto"], p["origen_ip"]))
        texto = render_nft(cfg, puertos, origenes)
        d = asegurar_dir(ruta("/srv/ids/fw"), 0o700)
        actual = d / "ids_host.nft"
        nuevo = d / "ids_host.nuevo.nft"
        escribir_atomico(nuevo, texto, modo=0o600)
        try:
            ejecutar_ok(["nft", "-c", "-f", str(nuevo)], timeout=60)
            if actual.exists():
                self._respaldo_fw(actual)
            ejecutar_ok(["nft", "-f", str(nuevo)], timeout=60)
            os.replace(nuevo, actual)
        finally:
            if nuevo.exists():
                nuevo.unlink()
        return texto

    def _respaldo_fw(self, actual):
        d = asegurar_dir(ruta("/root/backups"), 0o700)
        destino = d / ("ids-maat-fw-%s.nft" % time.strftime("%Y%m%dT%H%M%S", time.gmtime()))
        shutil.copyfile(actual, destino)
        _chmod(destino, 0o600)
        viejos = sorted(d.glob("ids-maat-fw-*.nft"))
        for v in viejos[:-MAX_RESPALDOS_FW]:
            v.unlink()

    def puerto_ocupado(self, puerto):
        r = ejecutar(["ss", "-Hltn"], timeout=30)
        for linea in r.out.splitlines():
            c = linea.split()
            if len(c) >= 4 and c[3].rsplit(":", 1)[-1] == str(puerto):
                return True
        return False

    def esperar_salud(self, nombres, limite=None):
        return esperar_salud(nombres, limite)

    def validar_T(self, imagen, rule_path, perfil, hs_tmpl, reserva, etiqueta):
        """`suricata -T` efímero (§5.9) con un yaml de validación."""
        tmpl, manifiesto, hs = hs_tmpl
        yaml = render_suricata(tmpl, manifiesto, valores_suricata(
            "validacion", "[10.0.0.0/8]", rule_path, 1, 1, perfil, hs))
        base = asegurar_dir(ruta("/srv/ids/estado/validacion"), 0o700)
        d = base / ("%s-%s" % (etiqueta, secrets.token_hex(3)))
        asegurar_dir(d, 0o755)
        try:
            escribir_atomico(d / "suricata.yaml", yaml, modo=0o644)
            escribir_atomico(d / "threshold.config", "", modo=0o644)
            ejecutar_ok(["docker", "run", "--rm", "--network", "none", "--read-only",
                         "--tmpfs", "/tmp:size=64m", "--tmpfs", "/run:size=8m", "--cap-drop", "ALL",
                         "--security-opt", "no-new-privileges:true", "--memory", "%dm" % reserva,
                         "--memory-swap", "%dm" % reserva,
                         "-v", "%s:/reglas:ro" % host_str("/srv/ids/reglas"),
                         "-v", "%s:/etc/ids/suricata:ro" % str(d).replace("\\", "/"),
                         "--entrypoint", "/usr/bin/suricata", imagen,
                         "-T", "-c", "/etc/ids/suricata/suricata.yaml", "-l", "/tmp"], timeout=900)
        finally:
            borrar_arbol(d)

    def crear_dirs(self, pid):
        asegurar_dir(ruta("/srv/ids/puntos/%s" % pid), 0o700)
        asegurar_dir(ruta("/srv/ids/puntos/%s/vpn" % pid), 0o700)
        asegurar_dir(ruta("/srv/ids/puntos/%s/vpn/ccd" % pid), 0o700)
        asegurar_dir(ruta("/srv/ids/puntos/%s/suricata" % pid), 0o755)
        asegurar_dir(ruta("/srv/ids/datos"), 0o750, 0, GID_PANEL)
        asegurar_dir(ruta("/srv/ids/datos/%s" % pid), 0o2750, 0, GID_PANEL)
        asegurar_dir(ruta("/srv/ids/run"), 0o750, 0, GID_PANEL)
        asegurar_dir(ruta("/srv/ids/run/%s" % pid), 0o2770, 0, GID_PANEL)
        asegurar_dir(ruta("/srv/ids/ctl"), 0o700)
        asegurar_dir(ruta("/srv/ids/ctl/%s/vpn" % pid), 0o700)
        asegurar_dir(ruta("/srv/ids/ctl/%s/suricata" % pid), 0o700)

    def limpiar_punto(self, p, enfriar=True, op_actual=None):
        """Borrado total del lado del host (DATOS §8). Idempotente."""
        pid = p["pid"]
        compose = ruta("/srv/ids/puntos/%s/compose.yml" % pid)
        if compose.exists():
            ejecutar(compose_args(pid, "down", "--remove-orphans", "--timeout", "30"), timeout=300)
        n = nombres_contenedores(pid)
        ejecutar(["docker", "rm", "-f", n["suricata"], n["vpn"]], timeout=120)
        ejecutar(["docker", "network", "rm", "ids-%s" % pid], timeout=60)
        for d in ("puntos", "datos", "run", "ctl"):
            borrar_arbol(ruta("/srv/ids/%s/%s" % (d, pid)))
        borrar_cert(pid)
        with self.tx() as db:
            db.execute("DELETE FROM punto WHERE pid=?", (pid,))
            db.execute("DELETE FROM reinicio WHERE pid=?", (pid,))
            cancelar = []
            if enfriar:
                db.execute("INSERT OR REPLACE INTO enfriamiento (n, hasta) VALUES (?,?)",
                           (p["n"], ahora() + ENFRIAMIENTO_S))
                # órdenes de este punto que esperaban en la cola: se cancelan (op.estado lo dice)
                # y no se ejecutan nunca; los pid no se reutilizan, así que no alcanzan a otro
                cancelar = db.execute("SELECT * FROM op WHERE pid=? AND estado='pendiente' AND op_id IS NOT ?",
                                      (pid, op_actual)).fetchall()
                for f in cancelar:
                    db.execute("UPDATE op SET estado='terminada', codigo='CANCELADA', mensaje=?, params=NULL, "
                               "fin=? WHERE op_id=?", ("cancelada: %s se dio de baja" % pid, ahora(), f["op_id"]))
                db.execute("DELETE FROM op WHERE pid=? AND op_id IS NOT ? AND estado='terminada' "
                           "AND codigo IS NOT 'CANCELADA'", (pid, op_actual))
        for f in cancelar:
            self._diario_linea({"ts": ahora(), "op_id": f["op_id"], "quien": f["quien"], "orden": f["orden"],
                                "pid": pid, "params_sha256": f["params_sha256"], "pasos": [],
                                "codigo": "CANCELADA", "mensaje": "cancelada por la baja del punto"})
        if self._retencion().pop(pid, None) is not None:
            self._retencion_guardar()
        self._threshold_fallido.pop(pid, None)
        self._netns.pop(pid, None)
        self._espejo.pop(pid, None)
        for k in [k for k in self._programados if k[0] == pid]:
            del self._programados[k]
        try:
            self.regenerar_fw(excluir=pid)
        except ErrorOrden as e:
            log("%s: firewall no regenerado tras la limpieza: %s" % (pid, e.mensaje))
            raise

    def _ocupadas(self, excluir=None):
        nc = ncpu()
        out = set()
        for p in self.puntos():
            if p["pid"] == excluir or not p.get("cpuset_suricata"):
                continue
            cpus = leer_cpus(p["cpuset_suricata"])
            if len(cpus) == p["hilos"] and max(cpus) < nc:      # exclusivas (no el 2-<nc-1> compartido)
                out |= cpus
        return out

    def asignar_n(self, pedido=None):
        t = ahora()
        usados = {f[0] for f in self.q("SELECT n FROM punto")}
        frios = {f[0] for f in self.q("SELECT n FROM enfriamiento WHERE hasta>?", (t,))}
        if pedido is not None:
            if pedido in usados:
                raise ErrorOrden("CONFLICTO", "N=%d está en uso" % pedido)
            if pedido in frios:
                raise ErrorOrden("CONFLICTO", "N=%d está en enfriamiento" % pedido)
            return pedido
        for n in range(1, N_MAX + 1):
            if n not in usados and n not in frios:
                return n
        raise ErrorOrden("CONFLICTO", "no quedan N libres (1-%d)" % N_MAX)

    def asignar_pid(self, db, pedido=None):
        f = db.execute("SELECT valor FROM secuencia WHERE nombre='pid'").fetchone()
        siguiente = f[0] if f else 1
        # sin la fila (orq.db perdida o restaurada vieja) no se vuelve a p001: nunca por debajo de
        # un pid que ya se ve en los puntos o en el historial de órdenes (A-22)
        vistos = [r[0] for r in db.execute("SELECT pid FROM punto UNION SELECT pid FROM op "
                                           "WHERE pid IS NOT NULL").fetchall()]
        maximo = max((int(x[1:]) for x in vistos if isinstance(x, str) and RE_PID.match(x)), default=0)
        siguiente = max(siguiente, maximo + 1)
        if pedido is not None:
            num = int(pedido[1:])
            if num < siguiente or num < 1:
                raise ErrorOrden("CONFLICTO", "%s ya se usó: los pid no se reutilizan" % pedido)
            siguiente = num
        if siguiente > 999:
            raise ErrorOrden("CONFLICTO", "se agotaron los pid (p999)")
        db.execute("INSERT OR REPLACE INTO secuencia (nombre, valor) VALUES ('pid', ?)", (siguiente + 1,))
        return "p%03d" % siguiente

    def escribir_compose(self, p, imgs, version):
        texto = render_compose(p, imgs, version, ncpu(), raiz_host=raiz())
        escribir_atomico(ruta("/srv/ids/puntos/%s/compose.yml" % p["pid"]), texto, modo=0o600)

    def escribir_yaml(self, p, imagen, tmpl_info=None):
        tmpl, manifiesto, hs = tmpl_info or plantilla_suricata(imagen)
        yaml = render_suricata(tmpl, manifiesto, valores_suricata(
            p["pid"], home_net(p["redes"]), "/reglas/current/%s" % PERFILES[p["perfil"]]["reglas"],
            p["n"], p["hilos"], p["perfil"], hs))
        escribir_atomico(ruta("/srv/ids/puntos/%s/suricata/suricata.yaml" % p["pid"]), yaml, modo=0o644)

    def escribir_usuarios(self, p, usuario, clave):
        escribir_atomico(ruta("/srv/ids/puntos/%s/vpn/usuarios" % p["pid"]),
                         render_usuarios(p["pid"], usuario, hash_clave(clave)), modo=0o600)

    def reserva_T(self, perfiles_extra=()):
        usados = [p["perfil"] for p in self.puntos()] + list(perfiles_extra)
        return max([PERFILES[x]["mem_limit"] for x in usados] or [PERFILES[PERFIL_DEFECTO]["mem_limit"]])

    def _datos_punto(self, p, clave=None, ya=False):
        cfg = config()
        d = {"pid": p["pid"], "n": p["n"], "puerto": p["puerto"], "tun_net": p["tun_net"],
             "usuario": p["usuario"], "nombre": p["nombre"], "perfil": p["perfil"],
             "hilos": p["hilos"], "cpuset": p.get("cpuset_suricata"),
             "mem_limit": "%dm" % PERFILES[p["perfil"]]["mem_limit"],
             "comandos": comandos_mikrotik(p, cfg.nombre_dns)}
        if ya:
            d["ya_entregada"] = True
        sec = None
        if clave:
            sec = {"clave": clave, "comandos": comandos_mikrotik(p, cfg.nombre_dns, clave)}
        return d, sec

    # ---- órdenes que encolan ------------------------------------------------------------------
    def o_crear(self, ctx, prm):
        ctx.total = len(PASOS_CREAR)
        with ctx.paso("validar"):
            cfg = config()
            imgs = imagenes()
            existente = self.q1("SELECT * FROM punto WHERE nombre=?", (prm["nombre"],))
            if existente is not None:
                p = fila_a_punto(existente, cfg.tun_base)
                igual = (p["redes"] == prm["redes_abonados"] and p["perfil"] == prm["perfil"]
                         and p["hilos"] == prm["hilos"] and p["ros_version"] == prm["ros_version"]
                         and p["compat_v6"] == prm["compat_v6"] and p["api_puerto"] == prm["api_puerto"]
                         and (p["origen_ip"] or None) == prm["origen_ip"]
                         and prm["pid"] in (None, p["pid"]) and prm["n"] in (None, p["n"]))
                if not igual or p["estado"] == "creando":
                    raise ErrorOrden("CONFLICTO", "ya existe un punto %s con otros datos (%s)"
                                     % (prm["nombre"], p["pid"]))
                ctx.pid = p["pid"]
                ctx.mensaje = "ya existe"
                return self._datos_punto(p, ya=True)
            cur = ruta("/srv/ids/reglas/current")
            if not cur.exists():
                raise ErrorOrden("FALLO", "no hay reglas (reglas/current): ejecuta «ids-orq reglas actualizar»")
            if prm["pid"] and self.q1("SELECT 1 FROM punto WHERE pid=?", (prm["pid"],)):
                raise ErrorOrden("CONFLICTO", "%s ya existe" % prm["pid"])
        with ctx.paso("asignar"):
            n = self.asignar_n(prm["n"])
            der = derivar(n, cfg.tun_base, cfg.pool)
            if self.puerto_ocupado(der["puerto"]):
                raise ErrorOrden("CONFLICTO_PUERTO", "el puerto %d/tcp está ocupado en el host" % der["puerto"],
                                 {"n": n, "puerto": der["puerto"]})
            nc = ncpu()
            cpuset = cpuset_suricata(nc, prm["hilos"], self._ocupadas())
            t = ahora()
            with self.tx() as db:
                pid = self.asignar_pid(db, prm["pid"])
                db.execute(
                    "INSERT INTO punto (pid, nombre, n, puerto, subred, cluster_id, perfil, hilos, "
                    "ros_version, compat_v6, api_puerto, origen_ip, redes, usuario, cpuset_suricata, "
                    "imagen_vpn, imagen_suricata, deseado, estado, creado, actualizado) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'activo','creando',?,?)",
                    (pid, prm["nombre"], n, der["puerto"], der["subred"], der["cluster_id"],
                     prm["perfil"], prm["hilos"], prm["ros_version"], prm["compat_v6"],
                     prm["api_puerto"], prm["origen_ip"], json.dumps(prm["redes_abonados"]), None,
                     cpuset, imgs["vpn"], imgs["suricata"], t, t))
            ctx.pid = pid
            p = self.punto(pid)
            ctx.deshacer = lambda: self.limpiar_punto(self.punto(pid) or p, enfriar=False)
            ctx.registrar("%s N=%d puerto %d subred %s" % (pid, n, der["puerto"], der["subred"]))
        with ctx.paso("admisión de RAM"):
            mem = meminfo()
            otros = [(x["perfil"], x["hilos"]) for x in self.puntos() if x["pid"] != pid]
            if not cabe(otros, (prm["perfil"], prm["hilos"]), mem):
                raise ErrorOrden("CONFLICTO", "no cabe un punto %s con %d hilo(s)" % (prm["perfil"], prm["hilos"]),
                                 {"caben": caben(otros, mem)})
        with ctx.paso("directorios"):
            self.crear_dirs(pid)
        with ctx.paso("certificado"):
            key, crt = cert_servidor(pid, cfg.nombre_dns)
            vpn = ruta("/srv/ids/puntos/%s/vpn" % pid)
            pki = ruta("/srv/ids/pki")
            for origen, destino, modo in ((pki / "ca.crt", "ca.crt", 0o644), (crt, "server.crt", 0o644),
                                          (key, "server.key", 0o600), (pki / "dh.pem", "dh.pem", 0o644)):
                escribir_atomico(vpn / destino, Path(origen).read_bytes(), modo=modo)
        with ctx.paso("usuario VPN"):
            usuario = nuevo_usuario()
            clave = nueva_clave()
            self.escribir_usuarios(p, usuario, clave)
            escribir_atomico(ruta("/srv/ids/puntos/%s/vpn/ccd/%s" % (pid, usuario)), render_ccd(der["mk"]),
                             modo=0o644)
            self.x("UPDATE punto SET usuario=? WHERE pid=?", (usuario, pid))
            p = self.punto(pid)
        with ctx.paso("server.conf"):
            escribir_atomico(ruta("/srv/ids/puntos/%s/vpn/server.conf" % pid),
                             render_server_conf(pid, der["tun_red"], prm["ros_version"], prm["compat_v6"]),
                             modo=0o644)
        with ctx.paso("suricata.yaml"):
            info_tmpl = plantilla_suricata(imgs["suricata"])
            self.escribir_yaml(p, imgs["suricata"], info_tmpl)
        with ctx.paso("suricata -T"):
            regla = PERFILES[prm["perfil"]]["reglas"]
            self.validar_T(imgs["suricata"], "/reglas/current/%s" % regla, prm["perfil"], info_tmpl,
                           self.reserva_T([prm["perfil"]]), pid)
        with ctx.paso("threshold.config"):
            escribir_atomico(ruta("/srv/ids/puntos/%s/suricata/threshold.config" % pid), render_threshold(pid),
                             modo=0o644)
        with ctx.paso("compose.yml"):
            self.escribir_compose(p, imgs, cfg.version)
        with ctx.paso("firewall"):
            self.regenerar_fw()
        with ctx.paso("compose up"):
            ejecutar_ok(compose_args(pid, "up", "-d", "--pull", "never"), timeout=600)
        with ctx.paso("esperar salud"):
            self.esperar_salud(list(nombres_contenedores(pid).values()))
        self.x("UPDATE punto SET estado='activo', paso_error=NULL, actualizado=? WHERE pid=?", (ahora(), pid))
        ctx.deshacer = None
        ctx.mensaje = "punto %s creado" % pid
        return self._datos_punto(self.punto(pid), clave=clave)

    def o_borrar(self, ctx, prm):
        p = self.punto(prm["pid"])
        if p is None:
            with ctx.paso("comprobar"):
                for d in ("puntos", "datos", "run", "ctl"):
                    borrar_arbol(ruta("/srv/ids/%s/%s" % (d, prm["pid"])))
            ctx.mensaje = "no existía"
            return {}
        if prm["confirmar"] != p["nombre"]:
            raise ErrorOrden("INVALIDO", "confirmar no coincide con el nombre del punto")
        ctx.total = 2
        with ctx.paso("marcar borrando"):
            self.x("UPDATE punto SET estado='borrando', actualizado=? WHERE pid=?", (ahora(), p["pid"]))
        with ctx.paso("borrado total"):
            self.limpiar_punto(p, enfriar=True, op_actual=ctx.op_id)
        ctx.mensaje = "punto %s eliminado" % p["pid"]
        return {}

    def _p_o_noexiste(self, pid):
        p = self.punto(pid)
        if p is None:
            raise ErrorOrden("NO_EXISTE", "no existe %s" % pid)
        return p

    def _observado(self, pid):
        info = docker_inspect(list(nombres_contenedores(pid).values()))
        return {parte: {"estado": (info.get(n) or {}).get("estado", "ausente"),
                        "salud": (info.get(n) or {}).get("salud", "none")}
                for parte, n in nombres_contenedores(pid).items()}

    def _reiniciar_suricata(self, pid):
        n = nombres_contenedores(pid)["suricata"]
        r = ejecutar(["docker", "restart", "--time", "30", n], timeout=180)
        if r.rc != 0:
            ejecutar_ok(compose_args(pid, "up", "-d", "--pull", "never", "--no-deps", "--force-recreate",
                                     "suricata"), timeout=600)

    def _salud_o_error(self, ctx, pid, nombres):
        try:
            self.esperar_salud(nombres)
        except ErrorOrden as e:
            for n in nombres:
                r = ejecutar(["docker", "logs", "--tail", "50", n], timeout=60)
                for linea in (r.out + r.err).splitlines()[-50:]:
                    if not re.search(r"password|key", linea, re.I):
                        ctx.registrar(linea)
            # un reinicio de la supervisión no pasa el punto a error: eso lo decide la regla de
            # 3 reinicios en 1 h (programar_reinicio); uno pedido por una persona, sí
            if not ctx.quien.startswith("orq:"):
                self.x("UPDATE punto SET estado='error', paso_error=?, actualizado=? WHERE pid=?",
                       (e.mensaje[:200], ahora(), pid))
            raise

    def o_arrancar(self, ctx, prm):
        p = self._p_o_noexiste(prm["pid"])
        pid, parte = p["pid"], prm["parte"]
        with ctx.paso("arrancar"):
            servicios = [] if parte == "todo" else [parte]
            ejecutar_ok(compose_args(pid, "up", "-d", "--pull", "never", *servicios), timeout=600)
            if parte == "todo":
                self.x("UPDATE punto SET deseado='activo', actualizado=? WHERE pid=?", (ahora(), pid))
        with ctx.paso("esperar salud"):
            nombres = list(nombres_contenedores(pid).values())
            self._salud_o_error(ctx, pid, nombres)
            self.x("UPDATE punto SET estado='activo', paso_error=NULL, actualizado=? WHERE pid=?", (ahora(), pid))
        self.comprobar_netns(pid)
        return {"observado": self._observado(pid)}

    def o_parar(self, ctx, prm):
        p = self._p_o_noexiste(prm["pid"])
        pid, parte = p["pid"], prm["parte"]
        with ctx.paso("parar"):
            if parte == "todo":
                ejecutar_ok(compose_args(pid, "stop"), timeout=300)
                self.x("UPDATE punto SET deseado='parado', estado='parado', actualizado=? WHERE pid=?",
                       (ahora(), pid))
            else:
                ejecutar(["docker", "stop", "--time", "30", nombres_contenedores(pid)[parte]], timeout=120)
        for k in [k for k in self._programados if k[0] == pid]:
            del self._programados[k]
        return {"observado": self._observado(pid)}

    def o_reiniciar(self, ctx, prm):
        p = self._p_o_noexiste(prm["pid"])
        pid, parte = p["pid"], prm["parte"]
        n = nombres_contenedores(pid)
        if parte in ("vpn", "todo"):
            with ctx.paso("reiniciar vpn"):
                ejecutar_ok(["docker", "restart", "--time", "30", n["vpn"]], timeout=180)
            with ctx.paso("esperar vpn"):
                self._salud_o_error(ctx, pid, [n["vpn"]])
        with ctx.paso("reiniciar suricata"):
            self._reiniciar_suricata(pid)
        with ctx.paso("esperar salud"):
            self._salud_o_error(ctx, pid, [n["vpn"], n["suricata"]])
        if p["deseado"] == "activo":
            self.x("UPDATE punto SET estado='activo', paso_error=NULL, actualizado=? WHERE pid=?", (ahora(), pid))
        self.comprobar_netns(pid)
        return {"observado": self._observado(pid)}

    def o_ajustar(self, ctx, prm):
        p = self._p_o_noexiste(prm["pid"])
        pid = p["pid"]
        cfg = config()
        nuevo = dict(p)
        if "redes_abonados" in prm:
            nuevo["redes"] = prm["redes_abonados"]
        for k in ("perfil", "hilos", "compat_v6", "ros_version"):
            if k in prm:
                nuevo[k] = prm[k]
        if "origen_ip" in prm:
            nuevo["origen_ip"] = prm["origen_ip"]
        cambia_sur = any(nuevo[k] != p[k] for k in ("perfil", "hilos", "redes"))
        cambia_vpn = any(nuevo[k] != p[k] for k in ("compat_v6", "ros_version"))
        cambia_fw = (nuevo.get("origen_ip") or None) != (p.get("origen_ip") or None)
        recreado = []
        if not (cambia_sur or cambia_vpn or cambia_fw):
            ctx.mensaje = "sin cambios"
            return {"recreado": []}
        imgs = imagenes()
        sube = (PERFILES[nuevo["perfil"]]["mem_limit"] > PERFILES[p["perfil"]]["mem_limit"]
                or nuevo["hilos"] > p["hilos"])
        if sube:
            with ctx.paso("admisión de RAM"):
                mem = meminfo()
                otros = [(x["perfil"], x["hilos"]) for x in self.puntos() if x["pid"] != pid]
                if not cabe(otros, (nuevo["perfil"], nuevo["hilos"]), mem):
                    raise ErrorOrden("CONFLICTO", "no cabe el perfil %s" % nuevo["perfil"],
                                     {"caben": caben(otros, mem)})
        if nuevo["hilos"] != p["hilos"]:
            nuevo["cpuset_suricata"] = cpuset_suricata(ncpu(), nuevo["hilos"], self._ocupadas(excluir=pid))
        if cambia_sur:
            imagen = p.get("imagen_suricata") or imgs["suricata"]
            with ctx.paso("suricata.yaml + -T"):
                info_tmpl = plantilla_suricata(imagen)
                self.validar_T(imagen, "/reglas/current/%s" % PERFILES[nuevo["perfil"]]["reglas"],
                               nuevo["perfil"], info_tmpl, self.reserva_T([nuevo["perfil"]]), pid)
                self.escribir_yaml(nuevo, imagen, info_tmpl)
            with ctx.paso("compose.yml"):
                self.escribir_compose(nuevo, {"vpn": p.get("imagen_vpn") or imgs["vpn"], "suricata": imagen},
                                      cfg.version)
        with self.tx() as db:
            db.execute("UPDATE punto SET perfil=?, hilos=?, redes=?, compat_v6=?, ros_version=?, origen_ip=?, "
                       "cpuset_suricata=?, actualizado=? WHERE pid=?",
                       (nuevo["perfil"], nuevo["hilos"], json.dumps(nuevo["redes"]), nuevo["compat_v6"],
                        nuevo["ros_version"], nuevo.get("origen_ip"), nuevo.get("cpuset_suricata"),
                        ahora(), pid))
        if cambia_vpn:
            with ctx.paso("server.conf"):
                escribir_atomico(ruta("/srv/ids/puntos/%s/vpn/server.conf" % pid),
                                 render_server_conf(pid, p["tun_red"], nuevo["ros_version"], nuevo["compat_v6"]),
                                 modo=0o644)
            with ctx.paso("reiniciar openvpn"):
                if p["deseado"] == "activo":
                    ejecutar_ok(["docker", "exec", nombres_contenedores(pid)["vpn"], "/command/s6-svc", "-r",
                                 "/run/service/openvpn"], timeout=60)
            recreado.append("openvpn")
        if cambia_fw:
            with ctx.paso("firewall"):
                self.regenerar_fw()
            recreado.append("firewall")
        if cambia_sur and p["deseado"] == "activo":
            with ctx.paso("recrear suricata"):
                ejecutar_ok(compose_args(pid, "up", "-d", "--pull", "never"), timeout=600)
            with ctx.paso("esperar salud"):
                self._salud_o_error(ctx, pid, list(nombres_contenedores(pid).values()))
            recreado.append("suricata")
        datos = {"recreado": recreado}
        if cambia_vpn:
            datos["comandos"] = comandos_mikrotik(self.punto(pid), cfg.nombre_dns)
        ctx.mensaje = "ajustado: " + (", ".join(recreado) or "solo configuración")
        return datos

    def o_regenerar(self, ctx, prm):
        p = self._p_o_noexiste(prm["pid"])
        pid = p["pid"]
        clave = nueva_clave()
        with ctx.paso("usuarios"):
            usuario = p["usuario"] or nuevo_usuario()
            self.escribir_usuarios(p, usuario, clave)
            ccd = ruta("/srv/ids/puntos/%s/vpn/ccd/%s" % (pid, usuario))
            if not ccd.exists():
                escribir_atomico(ccd, render_ccd(p["mk"]), modo=0o644)
            self.x("UPDATE punto SET usuario=?, actualizado=? WHERE pid=?", (usuario, ahora(), pid))
        with ctx.paso("desconectar sesión"):
            try:
                ctx.registrar(openvpn_kill(pid, usuario))
            except Exception as e:  # noqa: BLE001 - sin sesión o sin socket: no es un fallo
                ctx.registrar("management: %s" % e)
        p = self.punto(pid)
        ctx.mensaje = "credencial regenerada"
        return self._datos_punto(p, clave=clave)

    def o_threshold(self, ctx, prm):
        """punto.threshold (CONTRATO-F2 §6): escribe el threshold.config del punto (ya validado
        línea a línea) y recarga Suricata sin cortar el espejo (`reload-rules` por el socket de
        control); si la recarga falla, reinicia el contenedor `suricata`. Si tampoco queda sano,
        se vuelve al threshold anterior (que estaba en marcha), se reinicia otra vez y la orden
        acaba REVERTIDA con el aviso THRESHOLD-FALLIDO en estado.json."""
        p = self._p_o_noexiste(prm["pid"])
        pid = p["pid"]
        if p["estado"] == "borrando":
            raise ErrorOrden("CONFLICTO", "%s se está dando de baja" % pid)
        # varias exclusiones seguidas: solo cuenta la última (las anteriores no recargan nada)
        siguiente = self.q1("SELECT op_id FROM op WHERE estado='pendiente' AND orden='punto.threshold' "
                            "AND pid=? ORDER BY seq LIMIT 1", (pid,))
        if siguiente is not None:
            ctx.mensaje = "sustituida por una orden posterior (%s)" % siguiente["op_id"]
            return {"aplicado": False, "sustituida_por": siguiente["op_id"]}
        dest = ruta("/srv/ids/puntos/%s/suricata/threshold.config" % pid)
        guardado = ruta("/srv/ids/puntos/%s/threshold.anterior" % pid)
        contenido = prm["contenido"]
        ctx.total = 3
        with ctx.paso("escribir threshold.config"):
            try:
                previo = dest.read_text(encoding="utf-8")
            except OSError:
                previo = render_threshold(pid)
            if previo == contenido:
                ctx.mensaje = "sin cambios"
                return {"aplicado": False, "sha256": sha256_txt(contenido)}
            escribir_atomico(guardado, previo, modo=0o600)
            escribir_atomico(dest, contenido, modo=0o644)
        sur = nombres_contenedores(pid)["suricata"]
        if p["deseado"] != "activo" or (docker_inspect([sur]).get(sur) or {}).get("estado") != "running":
            # parado o pausado: no se levanta por esto; Suricata lo leerá al arrancar
            ctx.mensaje = "escrito; se aplicará cuando arranque suricata"
            self._threshold_fallido.pop(pid, None)
            return {"aplicado": True, "recarga": "al arrancar", "sha256": sha256_txt(contenido)}

        def deshacer():
            escribir_atomico(dest, previo, modo=0o644)
            self._threshold_fallido[pid] = {"ts": ahora(), "mensaje": "threshold rechazado: sigue el anterior"}
            self._reiniciar_suricata(pid)
            self.esperar_salud([sur])
            if p["deseado"] == "activo":
                self.x("UPDATE punto SET estado='activo', paso_error=NULL, actualizado=? WHERE pid=?",
                       (ahora(), pid))
        ctx.deshacer = deshacer
        recarga = "reload-rules"
        with ctx.paso("recargar reglas"):
            try:
                suricata_comando(pid, "reload-rules")
            except Exception as e:  # noqa: BLE001 - socket ausente, NOK o timeout: se reinicia
                ctx.registrar("reload-rules falló: %s; se reinicia suricata" % getattr(e, "mensaje", e))
                recarga = "reinicio"
        if recarga == "reinicio":
            with ctx.paso("reiniciar suricata"):
                self._reiniciar_suricata(pid)
            with ctx.paso("esperar salud"):
                self._salud_o_error(ctx, pid, [sur])
        ctx.deshacer = None
        self._threshold_fallido.pop(pid, None)
        ctx.mensaje = "threshold aplicado (%s)" % recarga
        return {"aplicado": True, "recarga": recarga, "sha256": sha256_txt(contenido)}

    def o_reglas(self, ctx, prm):
        imgs = imagenes()
        imagen = imgs["suricata"]
        base = ruta("/srv/ids/reglas")
        asegurar_dir(base, 0o755)
        asegurar_dir(base / "releases", 0o755)
        asegurar_dir(base / "cache", 0o755)
        creada = None
        if prm.get("sin_descarga"):
            ts = leer_reglas()["current"]
            if not ts:
                raise ErrorOrden("FALLO", "no hay release actual que revalidar")
        else:
            ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            with ctx.paso("descargar"):
                creada = base / "releases" / ts
                contenedor = "ids-reglas-%s" % ts
                # --imagen: la referencia por digest de imagenes.json queda en el MANIFEST.json
                r = ejecutar(["docker", "run", "--rm", "--name", contenedor,
                              "--network", "bridge", "--read-only", "--tmpfs", "/tmp:size=512m",
                              "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                              "--memory", "1g", "--memory-swap", "1g",
                              "-v", "%s:/reglas" % host_str("/srv/ids/reglas"),
                              "--entrypoint", "/usr/local/bin/ids-reglas", imagen,
                              "descargar", "--ts", ts, "--imagen", imagen], timeout=3600)
                if r.rc == 124:
                    # El timeout mata el cliente docker, no el contenedor: seguiría escribiendo
                    # en la release mientras se borra.
                    ctx.registrar("tiempo agotado: docker rm -f %s" % contenedor)
                    ejecutar(["docker", "rm", "-f", contenedor], timeout=60)
                ultima = (r.out.strip().splitlines() or [""])[-1]
                try:
                    resumen = json.loads(ultima)
                except ValueError:
                    resumen = {}
                if r.rc != 0 or resumen.get("ok") is not True or not (creada / "LISTO").exists():
                    if creada.exists():
                        borrar_arbol(creada)
                    raise FalloCmd(["ids-reglas"], r.rc, r.out, r.err)
                ctx.registrar("release %s" % ts)
        info_tmpl = None
        perfiles = sorted({x["perfil"] for x in self.puntos()} | {"reducido", "completo"})
        reserva = max(PERFILES[x]["mem_limit"] for x in perfiles)
        try:
            with ctx.paso("plantilla"):
                info_tmpl = plantilla_suricata(imagen)
            for pf in perfiles:
                with ctx.paso("suricata -T %s" % pf):
                    self.validar_T(imagen, "/reglas/releases/%s/%s" % (ts, PERFILES[pf]["reglas"]), pf,
                                   info_tmpl, reserva, "reglas-%s" % pf)
        except ErrorOrden:
            if creada is not None and creada.exists():
                borrar_arbol(creada)
            raise
        with ctx.paso("cambiar current"):
            tmp = base / "current.tmp"
            if tmp.is_symlink() or tmp.exists():
                tmp.unlink()
            os.symlink("releases/%s" % ts, tmp)
            os.replace(tmp, base / "current")
        fallos = []
        for p in self.puntos():
            if p["deseado"] != "activo" or p["estado"] not in ("activo", "error"):
                continue
            try:
                with ctx.paso("reiniciar %s" % p["pid"]):
                    self._reiniciar_suricata(p["pid"])
                    self.esperar_salud(list(nombres_contenedores(p["pid"]).values()))
            except ErrorOrden as e:
                fallos.append(p["pid"])
                ctx.registrar("%s: %s" % (p["pid"], e.mensaje))
        with ctx.paso("podar releases"):
            for viejo in podar_releases(base / "releases", ts):
                ctx.registrar("podada %s" % viejo)
        conteos = {}
        try:
            conteos = json.loads((base / "releases" / ts / "MANIFEST.json").read_text(encoding="utf-8")).get("reglas", {})
        except (OSError, ValueError):
            pass
        if fallos:
            raise ErrorOrden("FALLO", "reglas %s activas, pero no quedaron sanos: %s" % (ts, ", ".join(fallos)),
                             {"ts": ts, "reglas": conteos})
        ctx.mensaje = "reglas %s" % ts
        return {"ts": ts, "reglas": conteos}

    def o_reconciliar(self, ctx, prm):
        levantados, huerfanos = [], []
        for p in self.puntos():
            if p["deseado"] != "activo" or p["estado"] in ("error", "creando", "borrando"):
                continue
            info = docker_inspect(list(nombres_contenedores(p["pid"]).values()))
            if all((info.get(n) or {}).get("estado") == "running" for n in nombres_contenedores(p["pid"]).values()):
                self.comprobar_netns(p["pid"])
                continue
            try:
                with ctx.paso("levantar %s" % p["pid"]):
                    ejecutar_ok(compose_args(p["pid"], "up", "-d", "--pull", "never"), timeout=600)
                levantados.append(p["pid"])
            except ErrorOrden as e:
                ctx.registrar("%s: %s" % (p["pid"], e.mensaje))
        # el panel: Docker ya lo relanza al arrancar (unless-stopped); esto cubre un `docker stop`
        # o `docker rm` y un dockerd que no lo levantó. No se re-renderiza: eso es `panel aplicar`.
        if ruta(CORE_COMPOSE).exists():
            if (docker_inspect([PANEL_CONTENEDOR]).get(PANEL_CONTENEDOR) or {}).get("estado") != "running":
                try:
                    with ctx.paso("levantar panel"):
                        ejecutar_ok(core_compose_args("up", "-d", "--pull", "never"), timeout=300)
                    levantados.append("panel")
                except ErrorOrden as e:
                    ctx.registrar("panel: %s" % e.mensaje)
        conocidos = {p["pid"] for p in self.puntos()}
        r = ejecutar(["docker", "ps", "-a", "--filter", "label=ids-maat.punto", "--format",
                      '{{.Names}}\t{{.Label "ids-maat.punto"}}'], timeout=60)
        for linea in r.out.splitlines():
            c = linea.split("\t")
            if len(c) == 2 and c[1] not in conocidos:
                huerfanos.append(c[0])
        d = ruta("/srv/ids/puntos")
        if d.exists():
            for x in sorted(d.iterdir()):
                if x.is_dir() and RE_PID.match(x.name) and x.name not in conocidos:
                    huerfanos.append(str(x))
        ctx.mensaje = "levantados %d, huérfanos %d" % (len(levantados), len(huerfanos))
        return {"levantados": levantados, "huerfanos": huerfanos}

    def parar(self):
        self._parar.set()
        with self._cola_cv:
            self._cola_cv.notify_all()


# --------------------------------------------------------------------------------------------
# Socket del servicio
# --------------------------------------------------------------------------------------------

def uid_par(conn):
    import socket
    import struct
    cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _, uid, _ = struct.unpack("3i", cred)
    return uid


def manejar_conexion(orq, conn, uids):
    try:
        try:
            uid = uid_par(conn)
        except OSError:
            uid = -1
        if uid not in uids:
            log("conexión rechazada: uid %s no autorizado" % uid)
            return
        ventana = int(time.time() // 60)
        clave = (uid, ventana)
        orq._peticiones = {k: v for k, v in orq._peticiones.items() if k[1] == ventana}
        orq._peticiones[clave] = orq._peticiones.get(clave, 0) + 1
        conn.settimeout(10)
        buf = b""
        while b"\n" not in buf and len(buf) <= MAX_MENSAJE:
            trozo = conn.recv(4096)
            if not trozo:
                break
            buf += trozo
        if orq._peticiones[clave] > MAX_PETICIONES_MIN:
            resp = {"op_id": None, "ok": False, "codigo": "INVALIDO", "mensaje": "demasiadas peticiones",
                    "datos": {}}
        elif len(buf) > MAX_MENSAJE:
            resp = {"op_id": None, "ok": False, "codigo": "INVALIDO", "mensaje": "mensaje demasiado grande",
                    "datos": {}}
        else:
            try:
                pet = json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
            except ValueError:
                pet = None
            try:
                resp = orq.atender(pet, uid)
            except Exception as e:  # noqa: BLE001 - siempre hay respuesta; nunca se cierra mudo (A-23)
                log("atender: %r" % e)
                resp = {"op_id": None, "ok": False, "codigo": "INVALIDO",
                        "mensaje": "petición no válida", "datos": {}}
        conn.sendall((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
    except OSError as e:
        log("conexión: %s" % e)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def servir(orq, ruta_sock=None, uids=(0, UID_PANEL), detener=None, listo=None):
    import socket
    detener = detener or orq._parar
    path = Path(ruta_sock) if ruta_sock else ruta("/run/ids-orq/orq.sock")
    if not ruta_sock:
        asegurar_dir(path.parent, 0o750, 0, GID_PANEL)
    if path.exists() or path.is_symlink():
        path.unlink()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(path))
    _chmod(path, 0o660)
    _chown(path, 0, GID_PANEL)
    s.listen(16)
    s.settimeout(0.5)
    if listo is not None:
        listo.set()
    try:
        while not detener.is_set():
            try:
                conn, _ = s.accept()
            except socket.timeout:
                continue
            threading.Thread(target=manejar_conexion, args=(orq, conn, set(uids)), daemon=True).start()
    finally:
        s.close()
        try:
            path.unlink()
        except OSError:
            pass


class SinServicio(Exception):
    pass


def llamar(pet, ruta_sock=None, timeout=60):
    import socket
    if not hasattr(socket, "AF_UNIX"):
        raise SinServicio("AF_UNIX no disponible")
    path = Path(ruta_sock) if ruta_sock else ruta("/run/ids-orq/orq.sock")
    if not path.exists():
        raise SinServicio("no existe %s" % path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(str(path))
        s.sendall((json.dumps(pet) + "\n").encode("utf-8"))
        buf = b""
        while b"\n" not in buf:
            trozo = s.recv(65536)
            if not trozo:
                break
            buf += trozo
    except OSError as e:
        raise SinServicio(str(e))
    finally:
        s.close()
    if not buf.strip():
        raise SinServicio("el servicio cerró la conexión (¿uid no autorizado?)")
    return json.loads(buf.decode("utf-8"))


def servicio():
    import signal
    orq = Orquestador()
    for d, modo, gid in (("/srv/ids/estado", 0o700, 0), ("/srv/ids/run", 0o750, GID_PANEL),
                         ("/srv/ids/fw", 0o700, 0), ("/srv/ids/ctl", 0o700, 0),
                         ("/srv/ids/puntos", 0o700, 0), ("/srv/ids/datos", 0o750, GID_PANEL)):
        asegurar_dir(ruta(d), modo, 0, gid)
    orq.arrancar()

    def _fin(*_):
        orq.parar()
    signal.signal(signal.SIGTERM, _fin)
    signal.signal(signal.SIGINT, _fin)
    for fn in (orq.trabajador, orq.bucle_supervision, orq.bucle_eventos, orq.bucle_compresion):
        threading.Thread(target=fn, daemon=True).start()
    log("servicio %s listo" % ORQ_VERSION)
    servir(orq)
    return 0


# --------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------

def _linea_paso(paso, total):
    izq = "  [%d/%s] %s " % (paso["n"], total or "?", paso["nombre"])
    res = "ok" if paso["estado"] == "ok" else "FALLO"
    extra = " (%d s)" % paso["dur_s"] if paso.get("dur_s", 0) >= 10 else ""
    det = " — %s" % paso["detalle"] if paso.get("detalle") else ""
    return izq.ljust(46, ".") + " " + res + extra + det


def _aplanar(d, prefijo=""):
    out = []
    for k, v in d.items():
        clave = "%s.%s" % (prefijo, k) if prefijo else k
        if isinstance(v, dict) and v:
            out += _aplanar(v, clave)
        elif isinstance(v, list):
            out.append((clave, ",".join(str(x) for x in v) if v else "-"))
        else:
            out.append((clave, "-" if v is None else v))
    return out


def _edad(segundos):
    if segundos is None:
        return "-"
    if segundos < 120:
        return "%d s" % segundos
    if segundos < 7200:
        return "%d min" % (segundos // 60)
    if segundos < 172800:
        return "%d h" % (segundos // 3600)
    return "%d d" % (segundos // 86400)


def formato_estado(sis, puntos, t=None):
    t = t if t is not None else ahora()
    reg = sis.get("reglas") or {}
    cap = sis.get("capacidad") or {}
    cola = sis.get("cola") or {}
    en = cola.get("en_curso")
    lineas = ["ids-orq %s · versión %s · base de túneles %s · reglas %s (%d releases)%s" % (
        sis.get("orq_version"), sis.get("version"), sis.get("tun_base"), reg.get("current") or "-",
        len(reg.get("releases") or []), " · DEV (sin firmas)" if sis.get("dev") else ""),
        "cola: %s · %d pendientes" % ("%s %s (%s)" % (en["orden"], en.get("pid") or "", en.get("paso") or "")
                                       if en else "libre", cola.get("pendientes", 0)),
        "memoria: total %s MB · comprometida %s MB · caben: %s" % (
            cap.get("mem_total_mb"), cap.get("mem_comprometida_mb"),
            ", ".join("%s %s" % (k, v) for k, v in (cap.get("caben") or {}).items()))]
    filas = [("PID", "NOMBRE", "N", "PUERTO", "PERFIL", "DESEADO", "ESTADO", "VPN", "ESPEJO", "NETNS", "AVISOS")]
    for pid, e in sorted(puntos.items()):
        vc = e.get("vpn_cliente") or {}
        vpn = "%s (%s)" % (vc.get("ip_real"), _edad(t - vc["desde"]) if vc.get("desde") else "-") \
            if vc.get("conectado") else "-"
        ns = (e.get("netns") or {}).get("coherente")
        filas.append((pid, e["nombre"], str(e["n"]), str(e["puerto"]), e["perfil"], e["deseado"], e["estado"],
                      vpn, _edad((e.get("tzsp") or {}).get("edad_s")),
                      "ok" if ns else ("DISTINTO" if ns is False else "-"),
                      ",".join(e.get("avisos") or []) or "-"))
    anchos = [max(len(f[i]) for f in filas) for i in range(len(filas[0]))]
    for f in filas:
        lineas.append("  ".join(c.ljust(anchos[i]) for i, c in enumerate(f)).rstrip())
    return "\n".join(lineas)


def formato_creado(d):
    return "\n".join([
        ("OK punto %s ya existía" if d.get("ya_entregada") else "OK punto %s creado") % d["pid"],
        "  nombre       %s" % d["nombre"],
        "  N            %s" % d["n"],
        "  puerto       %s/tcp" % d["puerto"],
        "  túnel        %s (sensor %s, MikroTik %s)" % (d["tun_net"], d["tun_net"].rsplit(".", 1)[0] + ".1",
                                                       d["tun_net"].rsplit(".", 1)[0] + ".2"),
        "  perfil       %s · hilos %s · cpuset %s · mem_limit %s" % (d["perfil"], d["hilos"],
                                                                    d.get("cpuset") or "-", d["mem_limit"]),
        "  usuario VPN  %s" % d["usuario"],
        ("  clave VPN    %s      ← se muestra UNA sola vez" % d["clave"]) if d.get("clave")
        else "  clave VPN    (ya entregada; para una nueva: ids-orq punto vpn-regenerar %s)" % d["pid"],
        d["comandos"].rstrip("\n")])


def _redes_arg(txt):
    return [x.strip() for x in txt.split(",") if x.strip()]


def construir_parser():
    comun = argparse.ArgumentParser(add_help=False)
    comun.add_argument("--json", action="store_true", help="imprime la respuesta tal cual")
    comun.add_argument("--no-esperar", action="store_true", help="imprime el op_id y sale")
    ap = argparse.ArgumentParser(prog="ids-orq", description="Orquestador de IDS_MAAT-Docker (F1a)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("servicio", help="arranca el servicio (lo usa ids-orq.service)")
    pu = sub.add_parser("punto", help="órdenes de un punto")
    ps = pu.add_subparsers(dest="sub", required=True)
    c = ps.add_parser("crear", parents=[comun])
    c.add_argument("--nombre", required=True)
    c.add_argument("--redes", required=True, type=_redes_arg)
    c.add_argument("--perfil", choices=list(PERFILES))
    c.add_argument("--hilos", type=int, choices=(1, 2))
    c.add_argument("--ros", type=int, choices=(6, 7))
    c.add_argument("--compat-v6", nargs="?", const="seclevel0", choices=("seclevel0", "legacy"))
    c.add_argument("--api-puerto", type=int, choices=(8729, 8728))
    c.add_argument("--origen-ip")
    b = ps.add_parser("borrar", parents=[comun])
    b.add_argument("pid")
    b.add_argument("--confirmar", required=True)
    e = ps.add_parser("estado", parents=[comun])
    e.add_argument("pid", nargs="?", default="*")
    for nombre in ("arrancar", "parar", "reiniciar"):
        x = ps.add_parser(nombre, parents=[comun])
        x.add_argument("pid")
        x.add_argument("--parte", choices=("vpn", "suricata", "todo"), default="todo")
    a = ps.add_parser("ajustar", parents=[comun])
    a.add_argument("pid")
    a.add_argument("--perfil", choices=list(PERFILES))
    a.add_argument("--hilos", type=int, choices=(1, 2))
    a.add_argument("--redes", type=_redes_arg)
    g = a.add_mutually_exclusive_group()
    g.add_argument("--compat-v6", nargs="?", const="seclevel0", choices=("seclevel0", "legacy"))
    g.add_argument("--sin-compat-v6", action="store_true")
    a.add_argument("--ros", type=int, choices=(6, 7))
    g2 = a.add_mutually_exclusive_group()
    g2.add_argument("--origen-ip")
    g2.add_argument("--sin-origen-ip", action="store_true")
    for nombre in ("ovpn-client", "vpn-regenerar", "api-huella", "medir"):
        x = ps.add_parser(nombre, parents=[comun])
        x.add_argument("pid")
    lg = ps.add_parser("logs", parents=[comun])
    lg.add_argument("pid")
    lg.add_argument("--parte", choices=("vpn", "suricata"), default="vpn")
    lg.add_argument("--lineas", type=int, default=100)
    rg = sub.add_parser("reglas", help="reglas ET y feeds")
    rs = rg.add_subparsers(dest="sub", required=True)
    ra = rs.add_parser("actualizar", parents=[comun])
    ra.add_argument("--sin-descarga", action="store_true")
    rl = sub.add_parser("reabrir-logs", parents=[comun])
    rl.add_argument("pid", nargs="?")
    sub.add_parser("reconciliar", parents=[comun])
    sub.add_parser("estado", parents=[comun])
    op = sub.add_parser("op", parents=[comun])
    op.add_argument("op_id")
    fw = sub.add_parser("fw-render", help="(instalador) genera /srv/ids/fw/ids_host.nft desde ids.conf")
    fw.add_argument("--aplicar", action="store_true", help="nft -c y nft -f del resultado")
    pn = sub.add_parser("panel", help="núcleo: el panel (local, como root)")
    pns = pn.add_subparsers(dest="sub", required=True)
    pa = pns.add_parser("aplicar", help="renderiza /srv/ids/core/compose.yml, lo levanta y espera a sano")
    pa.add_argument("--sin-esperar", action="store_true")
    pc = pns.add_parser("crear-admin", help="crea el primer usuario e imprime CLAVE=<clave> (3 si ya existe)")
    pc.add_argument("--usuario", default="admin")
    pr = pns.add_parser("restablecer", help="clave nueva para un usuario; imprime CLAVE=<clave>")
    pr.add_argument("usuario")
    return ap


def orden_desde_args(a):
    """(orden, params) del socket para los argumentos de la CLI."""
    if a.cmd == "punto":
        s = a.sub
        if s == "crear":
            p = {"nombre": a.nombre, "redes_abonados": a.redes}
            for k, v in (("perfil", a.perfil), ("hilos", a.hilos), ("ros_version", a.ros),
                         ("compat_v6", a.compat_v6), ("api_puerto", a.api_puerto), ("origen_ip", a.origen_ip)):
                if v is not None:
                    p[k] = v
            return "punto.crear", p
        if s == "borrar":
            return "punto.borrar", {"pid": a.pid, "confirmar": a.confirmar}
        if s == "estado":
            return "punto.estado", {"pid": a.pid}
        if s in ("arrancar", "parar", "reiniciar"):
            return "punto." + s, {"pid": a.pid, "parte": a.parte}
        if s == "ajustar":
            p = {"pid": a.pid}
            for k, v in (("perfil", a.perfil), ("hilos", a.hilos), ("redes_abonados", a.redes),
                         ("compat_v6", a.compat_v6), ("ros_version", a.ros), ("origen_ip", a.origen_ip)):
                if v is not None:
                    p[k] = v
            if a.sin_compat_v6:
                p["compat_v6"] = "no"
            if a.sin_origen_ip:
                p["origen_ip"] = None
            return "punto.ajustar", p
        if s == "ovpn-client":
            return "punto.comandos", {"pid": a.pid}
        if s == "vpn-regenerar":
            return "punto.vpn.regenerar", {"pid": a.pid}
        if s == "api-huella":
            return "punto.api.huella", {"pid": a.pid}
        if s == "medir":
            return "punto.medir", {"pid": a.pid}
        if s == "logs":
            return "punto.logs", {"pid": a.pid, "parte": a.parte, "lineas": a.lineas}
    if a.cmd == "reglas":
        return "reglas.actualizar", ({"sin_descarga": True} if a.sin_descarga else {})
    if a.cmd == "reabrir-logs":
        return "logs.reabrir", ({"pid": a.pid} if a.pid else {})
    if a.cmd == "reconciliar":
        return "sistema.reconciliar", {}
    if a.cmd == "estado":
        return "sistema.estado", {}
    if a.cmd == "op":
        return "op.estado", {"op_id": a.op_id}
    raise ValueError("orden no reconocida")


class Cliente:
    """Transporte de la CLI hacia el servicio (las pruebas lo sustituyen)."""

    def __init__(self, transporte=None, dormir=time.sleep, salida=None):
        self.transporte = transporte or llamar
        self.dormir = dormir
        self.salida = salida or sys.stdout
        self.token = None
        self.quien = "cli:%s" % (os.environ.get("SUDO_USER") or "root")

    def p(self, txt=""):
        print(txt, file=self.salida)

    def pedir(self, orden, params, op_id=None):
        if self.token is None:
            self.token = leer_token()
        pet = {"v": 1, "op_id": op_id or str(uuid.uuid4()), "token": self.token, "orden": orden,
               "params": params, "quien": self.quien, "ip": "", "ts": ahora()}
        return self.transporte(pet)

    def seguir(self, op_id, delante=0):
        self.p("en cola: op %s (%d delante)" % (op_id, delante))
        vistos = 0
        while True:
            r = self.pedir("op.estado", {"op_id": op_id})
            if r.get("codigo") != "OK":
                return r.get("codigo"), r.get("mensaje"), {}
            d = r["datos"]
            for paso in d.get("pasos", [])[vistos:]:
                self.p(_linea_paso(paso, (d.get("avance") or "?/?").split("/")[1]))
            vistos = len(d.get("pasos", []))
            if d["estado"] == "terminada":
                return d.get("codigo"), d.get("mensaje"), d.get("resultado") or {}
            self.dormir(1)

    def ejecutar(self, a):
        orden, params = orden_desde_args(a)
        if a.cmd == "estado":
            r1 = self.pedir("sistema.estado", {})
            if r1.get("codigo") != "OK":
                return self.final(r1.get("codigo"), r1.get("mensaje"), {}, orden, a)
            r2 = self.pedir("punto.estado", {"pid": "*"})
            if a.json:
                self.p(json.dumps({"sistema": r1, "puntos": r2}, ensure_ascii=False, indent=1))
                return CODIGOS_SALIDA.get(r2.get("codigo"), 1)
            self.p(formato_estado(r1["datos"], (r2.get("datos") or {}).get("puntos", {})))
            return 0
        r = self.pedir(orden, params)
        if a.json:
            self.p(json.dumps(r, ensure_ascii=False, indent=1))
            if r.get("codigo") == "ACEPTADA" and not a.no_esperar:
                codigo, mensaje, datos = self.seguir(r["op_id"], (r.get("datos") or {}).get("delante", 0))
                self.p(json.dumps({"codigo": codigo, "mensaje": mensaje, "datos": datos}, ensure_ascii=False,
                                  indent=1))
                return CODIGOS_SALIDA.get(codigo, 1)
            return CODIGOS_SALIDA.get(r.get("codigo"), 1)
        if r.get("codigo") == "ACEPTADA":
            if a.no_esperar:
                self.p(r["op_id"])
                return 0
            codigo, mensaje, datos = self.seguir(r["op_id"], (r.get("datos") or {}).get("delante", 0))
            return self.final(codigo, mensaje, datos, orden, a)
        return self.final(r.get("codigo"), r.get("mensaje"), r.get("datos") or {}, orden, a)

    def final(self, codigo, mensaje, datos, orden, a):
        if codigo != "OK":
            self.p("%s %s" % (codigo, mensaje))
            if datos.get("caben"):
                self.p("  caben: " + ", ".join("%s %s" % kv for kv in datos["caben"].items()))
            return CODIGOS_SALIDA.get(codigo, 1)
        if orden == "punto.crear":
            self.p(formato_creado(datos))
        elif orden in ("punto.comandos",):
            self.p(datos["comandos"].rstrip("\n"))
        elif orden == "punto.vpn.regenerar":
            self.p("OK %s" % mensaje)
            self.p("  usuario VPN  %s" % datos.get("usuario"))
            if datos.get("clave"):
                self.p("  clave VPN    %s      ← se muestra UNA sola vez" % datos["clave"])
            self.p(datos.get("comandos", "").rstrip("\n"))
        elif orden in ("punto.estado", "punto.medir", "sistema.capacidad"):
            for k, v in _aplanar(datos):
                self.p("%s: %s" % (k, v))
        elif orden == "punto.logs":
            for linea in datos.get("lineas", []):
                self.p(linea)
        elif orden == "punto.api.huella":
            self.p(datos["sha256"])
        elif orden == "op.estado":
            for paso in datos.get("pasos", []):
                self.p(_linea_paso(paso, (datos.get("avance") or "?/?").split("/")[1]))
            self.p("%s %s" % (datos.get("codigo") or datos.get("estado"), datos.get("mensaje") or ""))
            res = datos.get("resultado") or {}
            if res.get("clave"):
                self.p("  clave VPN    %s      ← se muestra UNA sola vez" % res["clave"])
            if res.get("comandos"):
                self.p(res["comandos"].rstrip("\n"))
            return CODIGOS_SALIDA.get(datos.get("codigo") or "OK", 1)
        else:
            self.p("OK %s" % (mensaje or ""))
            for k, v in _aplanar(datos):
                self.p("  %s: %s" % (k, v))
        return 0


def fw_render(aplicar=False):
    """Genera ids_host.nft con los puntos que haya (lo usa install.sh antes de que corra el servicio)."""
    cfg = config()
    puertos, origenes = [], []
    dbp = ruta("/srv/ids/estado/orq.db")
    if dbp.exists():
        orq = Orquestador()
        if aplicar:
            orq.regenerar_fw()
            return 0
        for p in orq.puntos():
            if ruta("/srv/ids/puntos/%s" % p["pid"]).is_dir():
                puertos.append(p["puerto"])
                if p.get("origen_ip"):
                    origenes.append((p["pid"], p["puerto"], p["origen_ip"]))
    texto = render_nft(cfg, puertos, origenes)
    d = asegurar_dir(ruta("/srv/ids/fw"), 0o700)
    if aplicar:
        nuevo = d / "ids_host.nuevo.nft"
        escribir_atomico(nuevo, texto, modo=0o600)
        try:
            ejecutar_ok(["nft", "-c", "-f", str(nuevo)], timeout=60)
            ejecutar_ok(["nft", "-f", str(nuevo)], timeout=60)
            os.replace(nuevo, d / "ids_host.nft")
        finally:
            if nuevo.exists():
                nuevo.unlink()
    else:
        escribir_atomico(d / "ids_host.nft", texto, modo=0o600)
    return 0


# --------------------------------------------------------------------------------------------
# Núcleo: el panel (F1b). Órdenes locales de root, como fw-render: no pasan por la cola (el panel
# no comparte nada con los puntos) y las usa install.sh antes de dar la URL y la clave.
# --------------------------------------------------------------------------------------------

def imagenes_con_panel():
    imgs = imagenes()
    if not imgs.get("panel"):
        raise ErrorOrden("FALLO", "imagenes.json no trae la imagen del panel (vuelve a ejecutar install.sh)")
    return imgs


def dirs_panel():
    asegurar_dir(ruta("/srv/ids/core"), 0o700)
    asegurar_dir(ruta(PANEL_DIR), 0o2770, 0, GID_PANEL)


def asegurar_master_key():
    """La clave maestra se monta en el panel (/run/secrets/master_key, ro). Si faltara, Docker
    crearía un DIRECTORIO con ese nombre en el host: se exige que exista como fichero. El panel
    corre como 10500 sin capacidades, así que la lee por grupo: 0440 root:ids-panel."""
    k = ruta(MASTER_KEY)
    if not k.is_file():
        raise ErrorOrden("FALLO", "falta %s (la crea install.sh; sin ella el panel no puede descifrar "
                                  "sus secretos)" % MASTER_KEY)
    _chown(k, 0, GID_PANEL)
    _chmod(k, 0o440)
    return k


def panel_aplicar(esperar=True):
    """Renderiza /srv/ids/core/compose.yml, `compose up -d` y espera a `healthy`. Idempotente:
    con la misma imagen y el mismo ids.conf, compose no recrea el contenedor."""
    cfg = config()
    imgs = imagenes_con_panel()
    dirs_panel()
    for d in ("/srv/ids/datos", "/srv/ids/run", "/run/ids-orq"):
        asegurar_dir(ruta(d), 0o750, 0, GID_PANEL)
    asegurar_master_key()
    texto = render_core(cfg, imgs["panel"], cfg.version, raiz_host=raiz())
    escribir_atomico(ruta(CORE_COMPOSE), texto, modo=0o600)
    ejecutar_ok(core_compose_args("up", "-d", "--pull", "never", "--remove-orphans"), timeout=300)
    if esperar:
        esperar_salud([PANEL_CONTENEDOR], ESPERA_PANEL_S)
    return texto


def panel_un_uso(orden, usuario):
    """`ids-panel crear-admin|restablecer --usuario X` en un contenedor de un solo uso con la
    imagen del panel: uid 10500, solo /srv/ids/panel montado, sin red y sin driver de logs (la
    clave sale una vez por stdout y no queda en ningún log). Devuelve el Resultado tal cual."""
    if orden not in ("crear-admin", "restablecer"):
        raise ErrorOrden("INVALIDO", "orden del panel desconocida")
    if not RE_USUARIO_PANEL.match(usuario or ""):
        raise ErrorOrden("INVALIDO", "usuario inválido: minúsculas, números, . _ - (máx. 32)")
    cfg = config()
    imgs = imagenes_con_panel()
    dirs_panel()
    args = ["docker", "run", "--rm", "--network", "none", "--log-driver", "none", "--read-only",
            "--tmpfs", "/tmp:size=16m", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--user", "%d:%d" % (UID_PANEL, GID_PANEL), "--memory", "256m", "--memory-swap", "256m",
            "--pids-limit", "64"]
    for k, v in entorno_panel(cfg).items():
        args += ["-e", "%s=%s" % (k, v)]
    args += ["-v", "%s:%s" % (host_str(PANEL_DIR), PANEL_DIR), "--entrypoint", "ids-panel", imgs["panel"],
             orden, "--usuario", usuario]
    return ejecutar(args, timeout=180)


def linea_clave(salida):
    """La única línea `CLAVE=<clave>` de la salida del panel, o None."""
    lineas = [x.strip() for x in (salida or "").splitlines() if re.fullmatch(r"\s*CLAVE=\S+\s*", x)]
    return lineas[0] if len(lineas) == 1 else None


def cli_panel(a, salida=None, error=None):
    salida = salida or sys.stdout
    error = error or sys.stderr
    try:
        if a.sub == "aplicar":
            panel_aplicar(esperar=not a.sin_esperar)
            cfg = config()
            print("OK panel %s en %s (http://%s:%d, solo desde %s)" % (
                PANEL_CONTENEDOR, PANEL_IP, cfg.nombre_dns, cfg.puerto_panel,
                ",".join(str(r) for r in cfg.ips_proxy)), file=salida)
            return 0
        usuario = a.usuario
        r = panel_un_uso("crear-admin" if a.sub == "crear-admin" else "restablecer", usuario)
    except ErrorOrden as e:
        print("%s %s" % (e.codigo, e.mensaje), file=error)
        return CODIGOS_SALIDA.get(e.codigo, 1)
    if a.sub == "crear-admin" and r.rc == SALIDA_PANEL_YA_EXISTE:
        print("CONFLICTO ya existe el usuario %s: se conserva su clave (ids-orq panel restablecer %s)"
              % (usuario, usuario), file=error)
        return SALIDA_PANEL_YA_EXISTE
    clave = linea_clave(r.out) if r.rc == 0 else None
    if clave is None:
        detalle = (r.err or "").strip().splitlines()
        print("FALLO ids-panel %s salió con %s%s" % (a.sub, r.rc, (": " + detalle[-1]) if detalle else ""),
              file=error)
        return 1
    print(clave, file=salida)
    print("clave del usuario %s del panel: se muestra UNA sola vez y no se guarda en claro" % usuario,
          file=error)
    return 0


def main(argv=None, cliente=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    a = construir_parser().parse_args(argv)
    if a.cmd == "servicio":
        return servicio()
    if a.cmd == "fw-render":
        try:
            return fw_render(a.aplicar)
        except ErrorOrden as e:
            print("FALLO %s" % e.mensaje, file=sys.stderr)
            return 1
    if a.cmd == "panel":
        return cli_panel(a)
    cli = cliente or Cliente()
    try:
        return cli.ejecutar(a)
    except SinServicio as e:
        print("sin servicio: %s (¿systemctl status ids-orq?)" % e, file=sys.stderr)
        return SALIDA_SIN_SERVICIO
    except OSError as e:
        print("sin servicio: no se puede leer el token (%s)" % e, file=sys.stderr)
        return SALIDA_SIN_SERVICIO


if __name__ == "__main__":
    sys.exit(main())
