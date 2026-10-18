"""Lectura de /srv/ids/run/estado.json (CONTRATO-F1a §5.10) y de run/<pid>/tzsp.json (§5.4).

El panel no llama al orquestador en cada carga: lee lo que el orquestador escribe cada 15 s.
"""

import os
import re
import threading
import time

from . import util

RE_PID = re.compile(r"^p\d{3}$")
VIEJO_S = 60

AVISOS = {
    "SIN-ESPEJO": "No llega el espejo del MikroTik desde hace 10 min o más",
    "ESPEJO-NO-LLEGA": "El espejo llega a la VPN pero Suricata no ve paquetes",
    "NETNS-DISTINTO": "VPN y Suricata quedaron en redes distintas (el orquestador lo corrige)",
    "REINICIOS": "3 o más reinicios en la última hora",
    "DISCO": "Queda poco disco libre en el servidor (< 15 %)",
}

ESTADOS = {
    "creando": "creando", "activo": "activo", "parado": "parado", "error": "con error",
    "borrando": "borrando",
}


def pid_valido(pid):
    return isinstance(pid, str) and bool(RE_PID.match(pid))


class LectorEstado:
    def __init__(self, run_dir, reloj=time.time):
        self.run_dir = run_dir
        self.reloj = reloj
        self._lock = threading.Lock()
        self._cache = None
        self._marca = None

    def estado(self):
        path = os.path.join(str(self.run_dir), "estado.json")
        try:
            st = os.stat(path)
            marca = (st.st_mtime_ns, st.st_size)
        except OSError:
            return None
        with self._lock:
            if self._cache is None or marca != self._marca:
                d = util.leer_json(path)
                if not isinstance(d, dict) or d.get("v") != 1:
                    return None
                if not isinstance(d.get("puntos"), dict):
                    d["puntos"] = {}
                d["puntos"] = {k: v for k, v in d["puntos"].items() if pid_valido(k) and isinstance(v, dict)}
                self._cache, self._marca = d, marca
            return self._cache

    def edad(self):
        e = self.estado()
        if not e:
            return None
        try:
            return max(0, int(self.reloj() - float(e.get("ts", 0))))
        except (TypeError, ValueError):
            return None

    def puntos(self):
        e = self.estado() or {}
        pts = e.get("puntos") or {}
        return sorted(pts.items(), key=lambda kv: (kv[1].get("n") or 0, kv[0]))

    def punto(self, pid):
        if not pid_valido(pid):
            return None
        return ((self.estado() or {}).get("puntos") or {}).get(pid)

    def ultimo_espejo(self, pid):
        """Epoch del último paquete TZSP aceptado (ultimo_visto de tzsp.json), o None."""
        if not pid_valido(pid):
            return None
        d = util.leer_json(os.path.join(str(self.run_dir), pid, "tzsp.json"))
        if not isinstance(d, dict):
            return None
        uv = d.get("ultimo_visto")
        if not isinstance(uv, dict):
            return None
        vals = [v for v in uv.values() if isinstance(v, (int, float))]
        return max(vals) if vals else None


def semaforo(p):
    """verde / ambar / rojo / gris para un punto de estado.json (PLAN-PANEL §7)."""
    estado = p.get("estado")
    cont = p.get("contenedores") or {}
    avisos = p.get("avisos") or []
    if p.get("deseado") == "parado" or estado == "parado":
        return "gris"
    if estado == "error" or any(a in avisos for a in ("NETNS-DISTINTO", "REINICIOS")):
        return "rojo"
    for parte in ("vpn", "suricata"):
        c = cont.get(parte) or {}
        if c.get("estado") not in (None, "running") or c.get("salud") == "unhealthy":
            return "rojo"
    if p.get("modo") == "directo":
        # sin VPN (punto directo): conectado = llega el espejo de su MikroTik (hace menos de 2 min)
        visto = (p.get("tzsp") or {}).get("visto_s")
        conectado = isinstance(visto, (int, float)) and not isinstance(visto, bool) and visto < 120
    else:
        conectado = bool((p.get("vpn_cliente") or {}).get("conectado"))
    if avisos or estado in ("creando", "borrando") or not conectado:
        return "ambar"
    return "verde"


def texto_contenedor(c):
    c = c or {}
    est, salud = c.get("estado"), c.get("salud")
    if est in (None, "ausente"):
        return "no existe"
    if est != "running":
        return est
    return {"healthy": "sano", "unhealthy": "enfermo", "starting": "arrancando"}.get(salud, "en marcha")
