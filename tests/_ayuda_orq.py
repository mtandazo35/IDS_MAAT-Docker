"""Ayudas de las pruebas del orquestador (constructor C).

- `cargar_orq()` importa orquestador/ids_orq.py como módulo nuevo.
- `Entorno` crea un IDS_RAIZ temporal con ids.conf, imagenes.json, token, meminfo y reglas.
- `SistemaFalso` sustituye a `ids_orq.ejecutar`: simula docker, nft, ss y openssl y registra
  cada llamada. Nada se ejecuta de verdad (salvo openssl si se pide `openssl_real=True`).
"""

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIX = REPO / "tests" / "fixtures" / "orq"
DIGEST_VPN = "a" * 64
DIGEST_SUR = "b" * 64
IMG_VPN = "ghcr.io/mtandazo35/ids-maat-vpn@sha256:" + DIGEST_VPN
IMG_SUR = "ghcr.io/mtandazo35/ids-maat-suricata@sha256:" + DIGEST_SUR
IMG_PANEL = "ghcr.io/mtandazo35/ids-maat-panel@sha256:" + "e" * 64
TOKEN = "f" * 64

IDS_CONF = """VERSION=0.1.0
NOMBRE_DNS=ids.empresa.example
TUN_BASE=@@BASE@@
REDES_GESTION=192.0.2.0/25,198.51.100.0/26
IPS_PROXY=203.0.113.50
IGNOREIP_DUENO=203.0.113.20
PUERTO_PANEL=5637
POOL_DOCKER=10.210.0.0/16
"""


def cargar_orq():
    nombre = "ids_orq_prueba_%s" % uuid.uuid4().hex[:8]
    spec = importlib.util.spec_from_file_location(nombre, REPO / "orquestador" / "ids_orq.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[nombre] = mod
    spec.loader.exec_module(mod)
    return mod


def symlinks_posibles():
    """¿Funciona aquí el enlace que crea producción (`os.symlink("releases/<ts>", current)`)?

    No basta con poder crearlo: en Windows con privilegio de enlaces (runner de GitHub, que es
    administrador) el enlace relativo con «/» se crea, pero Windows no lo resuelve (el «/» no es
    separador para el kernel) y `current.exists()` da False. Producción corre en Linux; en ese
    caso las pruebas que dependen de que producción cree `current` se omiten."""
    d = Path(tempfile.mkdtemp(prefix="ids-sl-"))
    try:
        (d / "releases" / "x").mkdir(parents=True)
        os.symlink("releases/x", d / "current")
        return (d / "current").is_dir()
    except (OSError, NotImplementedError):
        return False
    finally:
        shutil.rmtree(d, ignore_errors=True)


def enlazar_current(reglas, ts):
    """Crea reglas/current -> releases/<ts> para las pruebas (no es código de producción).

    Usa el separador del sistema (en Windows «\\», que sí resuelve) y comprueba que el enlace
    lleve a un directorio; si no se puede crear o no resuelve (Windows sin privilegio de enlaces,
    WinError 1314), deja un directorio `current` en su lugar."""
    cur = reglas / "current"
    try:
        os.symlink(os.path.join("releases", ts), cur, target_is_directory=True)
        if cur.is_dir():
            return
        cur.unlink()
    except (OSError, NotImplementedError):
        pass
    cur.mkdir()


class Entorno:
    def __init__(self, tun_base="100.64", ncpu=4, meminfo=None, dev=False, panel=True):
        self.dir = Path(tempfile.mkdtemp(prefix="ids-orq-"))
        self.kdir = self.dir / "_kernel"
        self._env = {k: os.environ.get(k) for k in ("IDS_RAIZ", "IDS_KERNEL_RAIZ")}
        os.environ["IDS_RAIZ"] = str(self.dir)
        os.environ["IDS_KERNEL_RAIZ"] = str(self.kdir)
        etc = self.dir / "etc" / "ids-maat"
        etc.mkdir(parents=True)
        (etc / "ids.conf").write_text(IDS_CONF.replace("@@BASE@@", tun_base), encoding="utf-8")
        img = {"v": 1, "version": "0.1.0", "dev": dev,
               "imagenes": {"vpn": IMG_VPN, "suricata": IMG_SUR}}
        if panel:
            img["imagenes"]["panel"] = IMG_PANEL
        (etc / "imagenes.json").write_text(json.dumps(img), encoding="utf-8")
        (etc / "orq_token").write_text(TOKEN + "\n", encoding="utf-8")
        (etc / "master.key").write_text("0123456789abcdef" * 4 + "\n", encoding="utf-8")
        (self.kdir / "proc").mkdir(parents=True)
        shutil.copyfile(meminfo or (FIX / "meminfo"), self.kdir / "proc" / "meminfo")
        reglas = self.dir / "srv" / "ids" / "reglas"
        rel = reglas / "releases" / "20261010T081500Z"
        for perfil in ("completo", "reducido"):
            (rel / perfil).mkdir(parents=True)
        (rel / "LISTO").write_text("", encoding="utf-8")
        enlazar_current(reglas, "20261010T081500Z")
        self.ncpu = ncpu

    def ruta(self, p):
        return self.dir / p.lstrip("/")

    def escribir_meminfo(self, total_mb, disponible_mb):
        (self.kdir / "proc" / "meminfo").write_text(
            "MemTotal: %d kB\nMemAvailable: %d kB\n" % (total_mb * 1024, disponible_mb * 1024),
            encoding="utf-8")

    def cerrar(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.dir, ignore_errors=True)


class SistemaFalso:
    """Simula las órdenes del sistema que usa ids_orq."""

    def __init__(self, entorno, openssl_real=False):
        self.e = entorno
        self.llamadas = []
        self.contenedores = {}
        self.siguiente_pid = 1000
        self.puertos_ocupados = set()
        self.fallar = {}          # subcadena de la orden -> rc
        self.salud_inicial = "healthy"
        self.openssl_real = openssl_real and shutil.which("openssl") is not None
        self.nft_aplicado = []
        self.release_ts = None
        self.claves_panel = []    # claves que «imprimió» el ids-panel simulado
        self.forzar_parte = {}    # parte -> {"estado", "salud"} al crearla o arrancarla
        self.imagenes_faltan = set()   # referencias que `docker image inspect` no encuentra
        self.modos_vpn = "vpn,directo"  # etiqueta ids-maat.modos de la imagen vpn ("" = anterior)
        self.api_puerto_vpn = "libre"   # etiqueta ids-maat.api-puerto de la imagen vpn ("" = anterior)
        self.baneadas = set()          # IPs baneadas en la jaula ids-vpn (fail2ban-client simulado)

    def __call__(self, args, entrada=None, timeout=600):
        mod = sys.modules[self.mod_name]
        args = [str(a) for a in args]
        self.llamadas.append(args)
        linea = " ".join(args)
        for sub, rc in self.fallar.items():
            if sub in linea:
                return mod.Resultado(rc, "", "fallo simulado: %s" % sub)
        h = getattr(self, "_" + args[0].replace("-", "_"), None)
        if h is None:
            return mod.Resultado(127, "", "orden no simulada: %s" % args[0])
        rc, out, err = h(args)
        return mod.Resultado(rc, out, err)

    def instalar(self, mod):
        self.mod_name = mod.__name__
        mod.ejecutar = self
        mod.ncpu = lambda: self.e.ncpu
        mod.INTERVALO_SONDEO_S = 0.01
        mod.ESPERA_SALUD_S = 0.2
        mod.ESPERA_SALUD_MARGEN_S = 0
        return self

    def ordenes(self, prefijo):
        return [a for a in self.llamadas if " ".join(a).startswith(prefijo)]

    # ---- simulaciones -------------------------------------------------------------------------
    def _nuevo(self, nombre, pid_punto, parte, compose=None):
        self.siguiente_pid += 1
        self.contenedores[nombre] = {"estado": "running", "salud": self.salud_inicial,
                                     "pid": self.siguiente_pid, "punto": pid_punto, "parte": parte,
                                     "id": uuid.uuid4().hex * 2, "compose": compose}
        self.contenedores[nombre].update(self.forzar_parte.get(parte, {}))

    def _arrancar(self, c):
        """Arranca un contenedor que ya existe: proceso nuevo (pid nuevo), mismo contenedor."""
        self.siguiente_pid += 1
        c.update(estado="running", salud=self.salud_inicial, pid=self.siguiente_pid)
        c.update(self.forzar_parte.get(c.get("parte"), {}))

    @staticmethod
    def _bloques_compose(fichero):
        """{servicio: texto de su bloque} del compose.yml (lo que Docker compara para decidir si
        recrea); {} si no se puede leer."""
        try:
            lineas = Path(fichero).read_text(encoding="utf-8").splitlines()
        except OSError:
            return {}
        bloques, actual, dentro = {}, None, False
        for linea in lineas:
            if not linea.startswith(" "):
                dentro = linea.rstrip() == "services:"
                actual = None
                continue
            m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", linea)
            if dentro and m:
                actual = m.group(1)
                bloques[actual] = []
            elif dentro and actual:
                bloques[actual].append(linea)
        return {k: "\n".join(v) for k, v in bloques.items()}

    def _docker(self, a):
        sub = a[1]
        if sub == "compose":
            proyecto = a[a.index("-p") + 1]
            pid = proyecto.split("-", 1)[1]
            resto = a[a.index("-f") + 2:]
            accion = resto[0]
            servicios = [x for x in resto[1:] if not x.startswith("-") and x not in ("never",)]
            if proyecto == "ids-core":
                nombres = {"panel": "ids-core-panel"}
                pid = None
            else:
                nombres = {"vpn": "ids-%s-vpn" % pid, "suricata": "ids-%s-suricata" % pid}
            if accion == "up":
                # como Docker: recrea si no existe, si se pide --force-recreate o si cambió el
                # bloque del servicio en el compose (o se recreó la vpn, de la que suricata toma la
                # red); arranca el que está parado; y NO toca el que está en marcha y sin cambios
                # (el suricata.yaml va montado: cambiarlo no recrea nada)
                bloques = self._bloques_compose(a[a.index("-f") + 1])
                recreados = set()
                for parte in (servicios or list(nombres)):
                    c = self.contenedores.get(nombres[parte])
                    h = bloques.get(parte)
                    if (c is None or "--force-recreate" in resto
                            or (h is not None and c.get("compose") not in (None, h))
                            or (parte == "suricata" and "vpn" in recreados)):
                        self._nuevo(nombres[parte], pid, parte, h)
                        recreados.add(parte)
                    elif c["estado"] != "running":
                        self._arrancar(c)
                return 0, "", ""
            if accion == "down":
                for n in nombres.values():
                    self.contenedores.pop(n, None)
                return 0, "", ""
            if accion == "stop":
                for n in nombres.values():
                    if n in self.contenedores:
                        self.contenedores[n]["estado"] = "exited"
                return 0, "", ""
            return 0, "", ""
        if sub == "inspect":
            nombres = [x for x in a[2:] if not x.startswith("-") and x not in ("container",)
                       and not x.startswith("{{")]
            if "-f" in a:
                fmt = a[a.index("-f") + 1]
                nombres = [x for x in nombres if x != fmt]
                out = [str(self.contenedores[n]["pid"]) if self.contenedores[n]["estado"] == "running" else "0"
                       for n in nombres if n in self.contenedores]
                rc = 0 if len(out) == len(nombres) else 1
                return rc, "\n".join(out) + "\n", ""
            lista = []
            for n in nombres:
                c = self.contenedores.get(n)
                if c:
                    lista.append({"Name": "/" + n, "Id": c["id"], "Image": "sha256:" + "c" * 64,
                                  "State": {"Status": c["estado"], "Pid": c["pid"] if c["estado"] == "running" else 0,
                                            "StartedAt": "2026-10-10T08:15:00.123456789Z",
                                            "Health": {"Status": c["salud"]}}})
            return (0 if len(lista) == len(nombres) else 1), json.dumps(lista), ""
        if sub == "rm":
            for n in a[2:]:
                self.contenedores.pop(n, None)
            return 0, "", ""
        if sub == "network":
            return 0, "", ""
        if sub in ("restart", "start"):
            n = a[-1]
            if n not in self.contenedores:
                return 1, "", "No such container: %s" % n
            self._arrancar(self.contenedores[n])
            return 0, "", ""
        if sub == "stop":
            n = a[-1]
            if n in self.contenedores:
                self.contenedores[n]["estado"] = "exited"
            return 0, "", ""
        if sub == "image":
            if a[2:3] == ["inspect"] and a[-1] in self.imagenes_faltan:
                return 1, "", "Error response from daemon: No such image: %s\n" % a[-1]
            if any("ids-maat.modos" in x for x in a):        # etiqueta de la imagen vpn
                return 0, self.modos_vpn + "\n", ""
            if any("ids-maat.api-puerto" in x for x in a):   # cualquier puerto para la API (2026-10-20)
                return 0, self.api_puerto_vpn + "\n", ""
            return 0, "sha256:" + "d" * 64 + "\n", ""
        if sub == "create":
            return 0, "id\n", ""
        if sub == "cp":
            origen, destino = a[2], a[3]
            nombre = origen.rsplit("/", 1)[1]
            shutil.copyfile(FIX / nombre, destino)
            return 0, "", ""
        if sub == "run":
            if "crear-admin" in a or "restablecer" in a:
                return self._panel_un_uso(a)
            if "confianza" in a:
                return self._panel_confianza(a)
            if "--build-info" in a:
                return 0, "This is Suricata version 7.0.10 RELEASE\nHyperscan support:       yes\n", ""
            if "-T" in a:
                return 0, "Configuration provided was successfully loaded. Exiting.\n", ""
            if "descargar" in a:
                ts = a[a.index("--ts") + 1]
                rel = self.e.ruta("/srv/ids/reglas/releases/%s" % ts)
                for perfil in ("completo", "reducido"):
                    (rel / perfil).mkdir(parents=True, exist_ok=True)
                    (rel / perfil / "suricata.rules").write_text("", encoding="utf-8")
                (rel / "feeds").mkdir(exist_ok=True)
                (rel / "feeds" / "domains.dataset").write_text("", encoding="utf-8")
                man = {"v": 1, "ts": ts, "reglas": {"completo": 50000, "reducido": 18000}, "dominios": 0}
                (rel / "MANIFEST.json").write_text(json.dumps(man), encoding="utf-8")
                (rel / "LISTO").write_text("", encoding="utf-8")
                self.release_ts = ts
                return 0, "descargando…\n" + json.dumps(dict(man, ok=True)) + "\n", ""
            return 0, "", ""
        if sub == "logs":
            return 0, "linea normal\nAuth password=secreto\nprivate key cargada\notra linea\n", ""
        if sub == "ps":
            return 0, "", ""
        if sub == "exec":
            return 0, "", ""
        return 0, "", ""

    def _panel_un_uso(self, a):
        """ids-panel crear-admin|restablecer --usuario X: conf/usuarios.json (CONTRATO-F2 §7) en el
        /srv/ids/panel montado."""
        montaje = a[a.index("-v") + 1]
        origen = montaje.rsplit(":", 1)[0]
        usuarios = Path(origen) / "conf" / "usuarios.json"
        usuarios.parent.mkdir(parents=True, exist_ok=True)
        usuario = a[a.index("--usuario") + 1]
        datos = json.loads(usuarios.read_text(encoding="utf-8")) if usuarios.exists() else {}
        if "crear-admin" in a and datos:
            return 3, "", "ya existe\n"
        if "restablecer" in a and usuario not in datos:
            return 4, "", "no existe el usuario\n"
        clave = uuid.uuid4().hex[:20]
        datos[usuario] = "pbkdf2$falso$" + uuid.uuid4().hex
        usuarios.write_text(json.dumps(datos), encoding="utf-8")
        self.claves_panel.append(clave)
        return 0, "CLAVE=%s\n" % clave, ""

    def _panel_confianza(self, a):
        """ids-panel confianza ver|agregar|vaciar sobre conf/confianza.json del /srv/ids/panel
        montado (el panel real normaliza y valida; aqui solo se guarda lo que llega)."""
        montaje = a[a.index("-v") + 1]
        fichero = Path(montaje.rsplit(":", 1)[0]) / "conf" / "confianza.json"
        fichero.parent.mkdir(parents=True, exist_ok=True)
        lista = json.loads(fichero.read_text(encoding="utf-8")) if fichero.exists() else []
        resto = a[a.index("confianza") + 1:]
        self.confianza_args = resto
        if resto[0] == "ver":
            return 0, "".join("%s\n" % e["red"] for e in lista), ""
        if resto[0] == "vaciar":
            fichero.write_text("[]", encoding="utf-8")
            return 0, "OK lista vaciada (%d entradas)\n" % len(lista), ""
        nota = next((x.split("=", 1)[1] for x in resto if x.startswith("--nota=")), "")
        lista.append({"red": resto[1], "nota": nota})
        fichero.write_text(json.dumps(lista), encoding="utf-8")
        return 0, "OK agregada %s\n" % resto[1], ""

    def _nft(self, a):
        fichero = a[-1]
        txt = Path(fichero).read_text(encoding="utf-8")
        if "-c" not in a:
            self.nft_aplicado.append(txt)
        return 0, "", ""

    def _ss(self, a):
        lineas = ["LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*"]
        lineas += ["LISTEN 0 128 0.0.0.0:%d 0.0.0.0:*" % p for p in sorted(self.puertos_ocupados)]
        return 0, "\n".join(lineas) + "\n", ""

    def _openssl(self, a):
        if self.openssl_real:
            p = subprocess.run(a, capture_output=True, text=True)
            return p.returncode, p.stdout, p.stderr
        if "-ext" in a and "-in" in a:
            # `x509 -in crt -noout -ext subjectAltName`: el SAN que dejó aquí el `-extfile` del firmado
            try:
                txt = Path(a[a.index("-in") + 1]).read_text(encoding="utf-8")
            except OSError:
                return 1, "", "Could not open file\n"
            m = re.search(r"^subjectAltName=(.+)$", txt, re.M)
            if not m:
                return 0, "", ""
            return 0, "X509v3 Subject Alternative Name: \n    %s\n" % m.group(1).replace("IP:", "IP Address:"), ""
        for opcion in ("-keyout", "-out"):
            if opcion in a:
                Path(a[a.index(opcion) + 1]).write_text("-----BEGIN FALSO-----\n%s\n" % opcion, encoding="utf-8")
        if "-extfile" in a and "-out" in a and "-selfsign" not in a:
            # (la CA autofirmada no: su ca.crt tiene que seguir pareciendo un PEM para leer_ca_pem)
            # el certificado «firmado» lleva las extensiones pedidas (para `-ext subjectAltName`)
            ext = Path(a[a.index("-extfile") + 1]).read_text(encoding="utf-8")
            with open(a[a.index("-out") + 1], "a", encoding="utf-8") as fh:
                fh.write(ext)
        return 0, "", ""

    def _fail2ban_client(self, a):
        """`fail2ban-client set ids-vpn unbanip <ip>`: «1» si estaba en `baneadas`, «0» si no."""
        if a[1:4] != ["set", "ids-vpn", "unbanip"] or len(a) != 5:
            return 255, "", "orden de fail2ban-client no simulada: %s\n" % " ".join(a)
        ip = a[4]
        if ip in self.baneadas:
            self.baneadas.discard(ip)
            return 0, "1\n", ""
        return 0, "0\n", ""


def preparar(tun_base="100.64", ncpu=4, meminfo=None, openssl_real=False, dev=False):
    """Devuelve (mod, entorno, sistema, orquestador)."""
    e = Entorno(tun_base=tun_base, ncpu=ncpu, meminfo=meminfo, dev=dev)
    mod = cargar_orq()
    s = SistemaFalso(e, openssl_real=openssl_real).instalar(mod)
    orq = mod.Orquestador()
    return mod, e, s, orq


def peticion(orden, params=None, op_id=None, token=TOKEN):
    return {"v": 1, "op_id": op_id or str(uuid.uuid4()), "token": token, "orden": orden,
            "params": params if params is not None else {}, "quien": "prueba", "ip": "", "ts": 0}


def ejecutar_orden(orq, orden, params=None, op_id=None):
    """Encola, procesa la cola y devuelve op.estado de la orden."""
    r = orq.atender(peticion(orden, params, op_id))
    if r["codigo"] != "ACEPTADA":
        return r
    while orq.procesar_una():
        pass
    return orq.atender(peticion("op.estado", {"op_id": r["op_id"]}))["datos"]


def explicar(r):
    """Texto de diagnóstico de un resultado: código, mensaje y el paso que falló."""
    pasos = [p for p in r.get("pasos", []) if p.get("estado") != "ok"]
    return "%s: %s%s" % (r.get("codigo"), r.get("mensaje"),
                         "" if not pasos else " (paso %s)" % ", ".join(
                             "%s=%s %s" % (p.get("nombre"), p.get("estado"), p.get("detalle", ""))
                             for p in pasos))


def crear(test, orq, params, codigo="OK"):
    """punto.crear que hace fallar la prueba con el código y el mensaje del orquestador si el
    resultado no es el esperado (en lugar de un KeyError más adelante)."""
    r = ejecutar_orden(orq, "punto.crear", params)
    if r.get("codigo") != codigo:
        test.fail("punto.crear %s esperaba %s; dio %s" % (params.get("nombre"), codigo, explicar(r)))
    return r


def cerrar(orq, e):
    try:
        orq.db.close()
    except Exception:
        pass
    e.cerrar()


def sin_marcadores(txt):
    return not re.search(r"@@[A-Z0-9_]+@@", txt)
