"""Alertas de /srv/ids/datos/<pid>/eve.json leyendo solo el FINAL del fichero.

- `ultimas_alertas`: lee hacia atrás por bloques (eve.json y, si no basta, eve.json.1, el rotado
  sin comprimir por delaycompress) hasta reunir `limite` alertas o leer `max_bytes`.
- `Contador24h`: alertas de las últimas 24 h por punto; la primera vez lee hacia atrás hasta
  pasar las 24 h y después solo lo nuevo (por inodo y posición).

Cada alerta lleva su punto: la misma IP en dos puntos son dos filas distintas.
"""

import json
import os
import re
import threading
import time

from . import util

BLOQUE = 256 * 1024
MAX_BYTES_LISTA = 32 * 1024 * 1024
MAX_BYTES_CONTEO = 256 * 1024 * 1024
DIA_S = 86400
HOLGURA_S = 300
MARCA_ALERTA = b'"event_type":"alert"'
RE_TS = re.compile(rb'^\{"timestamp":"([^"]+)"')
RE_PID = re.compile(r"^p\d{3}$")


def ficheros_eve(datos_dir, pid):
    base = os.path.join(str(datos_dir), pid)
    return [os.path.join(base, "eve.json"), os.path.join(base, "eve.json.1")]


def lineas_hacia_atras(path, fin=None, max_bytes=MAX_BYTES_LISTA):
    """Líneas completas de `path` desde el final hacia el principio (bytes, sin el \\n).

    Se para al leer `max_bytes`. Una última línea sin \\n (Suricata escribiendo) se descarta."""
    try:
        f = open(path, "rb")
    except OSError:
        return
    with f:
        if fin is None:
            f.seek(0, 2)
            fin = f.tell()
        pos = fin
        resto = b""
        leidos = 0
        a_medias = True                         # hasta ver el último salto: línea a medias
        while pos > 0 and leidos < max_bytes:
            n = min(BLOQUE, pos)
            pos -= n
            f.seek(pos)
            trozo = f.read(n)
            leidos += n
            partes = (trozo + resto).split(b"\n")
            if a_medias:
                if len(partes) == 1:
                    resto = b""
                    continue
                partes = partes[:-1]
                a_medias = False
            resto = partes[0]
            for linea in reversed(partes[1:]):
                if linea:
                    yield linea
        if pos == 0 and resto:
            yield resto


def ts_linea(linea):
    m = RE_TS.match(linea)
    return util.ts_suricata(m.group(1).decode("ascii", "replace")) if m else None


def alerta(ev, pid):
    a = ev.get("alert") if isinstance(ev.get("alert"), dict) else {}
    return {
        "punto": pid,
        "ts": util.ts_suricata(ev.get("timestamp")),
        "src_ip": str(ev.get("src_ip") or ""), "src_port": ev.get("src_port"),
        "dest_ip": str(ev.get("dest_ip") or ""), "dest_port": ev.get("dest_port"),
        "proto": str(ev.get("proto") or ""),
        "firma": str(a.get("signature") or ""), "sid": a.get("signature_id"),
        "severidad": a.get("severity"), "categoria": str(a.get("category") or ""),
        "accion": str(a.get("action") or ""),
    }


def ultimas_alertas(datos_dir, pid, limite=100, ip=None, max_bytes=MAX_BYTES_LISTA):
    """Las `limite` alertas más recientes del punto (la más nueva primero), opcionalmente solo
    las que tienen `ip` como origen o destino."""
    if not RE_PID.match(pid or ""):
        return []
    ip_b = ip.encode("ascii") if ip else None
    out = []
    presupuesto = max_bytes
    for path in ficheros_eve(datos_dir, pid):
        if not os.path.exists(path) or presupuesto <= 0:
            continue
        try:
            tam = os.path.getsize(path)
        except OSError:
            continue
        for linea in lineas_hacia_atras(path, max_bytes=presupuesto):
            if MARCA_ALERTA not in linea:
                continue
            if ip_b and ip_b not in linea:
                continue
            try:
                ev = json.loads(linea)
            except ValueError:
                continue
            if not isinstance(ev, dict) or ev.get("event_type") != "alert":
                continue
            if ip and ip not in (ev.get("src_ip"), ev.get("dest_ip")):
                continue
            out.append(alerta(ev, pid))
            if len(out) >= limite:
                return out
        presupuesto -= tam
    return out


def alertas_empresa(datos_dir, pids, limite=200, ip=None):
    """Alertas de varios puntos mezcladas por hora (la más nueva primero); cada fila con su punto."""
    todas = []
    for pid in pids:
        todas += ultimas_alertas(datos_dir, pid, limite=limite, ip=ip)
    todas.sort(key=lambda a: (a["ts"] or 0), reverse=True)
    return todas[:limite]


class Contador24h:
    def __init__(self, datos_dir, reloj=time.time):
        self.datos_dir = datos_dir
        self.reloj = reloj
        self._st = {}
        self._lock = threading.Lock()

    def _reconstruir(self, pid, ino, tam, t):
        corte = t - DIA_S
        tss = []
        completo = True
        presupuesto = MAX_BYTES_CONTEO
        principal, rotado = ficheros_eve(self.datos_dir, pid)
        try:
            tam_rotado = os.path.getsize(rotado)
        except OSError:
            tam_rotado = None
        for path, fin in ((principal, tam), (rotado, tam_rotado)):
            if fin is None:
                continue
            if presupuesto <= 0:
                completo = False
                break
            parar = False
            for linea in lineas_hacia_atras(path, fin=fin, max_bytes=presupuesto):
                ts = ts_linea(linea)
                if ts is not None and ts < corte - HOLGURA_S:
                    parar = True                 # ya pasamos las 24 h (con holgura)
                    break
                if MARCA_ALERTA in linea and ts is not None and ts >= corte:
                    tss.append(ts)
            if parar:
                break
            if fin > presupuesto:
                completo = False
                break
            presupuesto -= fin
        tss.sort()
        self._st[pid] = {"ino": ino, "pos": tam, "ts": tss, "completo": completo}

    def _avanzar(self, pid, path, st, tam):
        if tam - st["pos"] > MAX_BYTES_CONTEO:
            return False
        try:
            with open(path, "rb") as f:
                f.seek(st["pos"])
                datos = f.read(tam - st["pos"])
        except OSError:
            return False
        corte = datos.rfind(b"\n")
        if corte < 0:
            return True
        for linea in datos[:corte].split(b"\n"):
            if MARCA_ALERTA in linea:
                ts = ts_linea(linea)
                if ts is not None:
                    st["ts"].append(ts)
        st["pos"] += corte + 1
        return True

    def contar(self, pid):
        """(alertas en las últimas 24 h, completo). completo=False si se cortó por tamaño."""
        if not RE_PID.match(pid or ""):
            return 0, True
        t = self.reloj()
        path = ficheros_eve(self.datos_dir, pid)[0]
        with self._lock:
            try:
                s = os.stat(path)
            except OSError:
                self._st.pop(pid, None)
                return 0, True
            ino = getattr(s, "st_ino", 0)
            st = self._st.get(pid)
            if st is None or st["ino"] != ino or s.st_size < st["pos"] or not self._avanzar(pid, path, st, s.st_size):
                self._reconstruir(pid, ino, s.st_size, t)
                st = self._st[pid]
            corte = t - DIA_S
            if st["ts"] and st["ts"][0] < corte:
                st["ts"] = [x for x in st["ts"] if x >= corte]
            return len(st["ts"]), st["completo"]
