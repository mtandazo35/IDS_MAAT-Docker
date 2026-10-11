"""Bitácora del panel: /srv/ids/panel/bitacora.jsonl, una línea por acción (quién hizo qué).

Nunca lleva claves, tokens ni cookies: solo usuario, IP real, acción, punto y resultado.
"""

import json
import os
import re
import threading
import time

_PROHIBIDAS = re.compile(r"clave|password|token|cookie|secret", re.I)
_lock = threading.Lock()


class Bitacora:
    def __init__(self, path, reloj=time.time):
        self.path = path
        self.reloj = reloj

    def registrar(self, accion, usuario="", ip="", punto=None, resultado="ok", detalle=None):
        linea = {"ts": int(self.reloj()), "usuario": usuario or "-", "ip": ip or "-", "accion": accion,
                 "resultado": resultado}
        if punto:
            linea["punto"] = punto
        if detalle:
            linea["detalle"] = {k: v for k, v in detalle.items() if not _PROHIBIDAS.search(k)}
        txt = json.dumps(linea, ensure_ascii=False, sort_keys=True) + "\n"
        with _lock:
            try:
                fd = os.open(str(self.path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(txt)
            except OSError:
                pass

    def ultimas(self, n=50):
        try:
            with open(self.path, "rb") as f:
                f.seek(0, 2)
                tam = f.tell()
                f.seek(max(0, tam - 256 * 1024))
                lineas = f.read().decode("utf-8", "replace").splitlines()
        except OSError:
            return []
        out = []
        for linea in reversed(lineas):
            try:
                out.append(json.loads(linea))
            except ValueError:
                continue
            if len(out) >= n:
                break
        return out
