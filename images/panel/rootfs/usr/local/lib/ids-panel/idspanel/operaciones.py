"""Operaciones que el panel pidió al orquestador (/srv/ids/panel/operaciones.json, 0600).

El panel genera el op_id ANTES de llamar y lo guarda aquí (ORQUESTADOR §6): así sigue el avance
aunque se reinicie, y solo quien la pidió puede ver su resultado. Nunca se guardan claves.
"""

import re
import threading
import time

from . import util

RE_OPID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
MAX_OPS = 300
RETENCION_S = 7 * 86400
CAMPOS = ("usuario", "orden", "pid", "nombre", "ros_version", "creada", "terminada", "codigo", "mensaje",
          "pasos", "total", "ya_existia",
          # trabajos del panel (ordenes «panel.*», que no van al orquestador): de que proceso son,
          # la IP de quien lo pidio y su resultado (nunca claves)
          "proceso", "ip", "resultado", "etapa", "avance")
# lo que se apunta despues de terminar: que paso con la clave de la VPN (nunca la clave) y si la
# persona ya vio el resultado (la ficha lo enseña UNA vez si se cerro la pestaña a mitad)
ANOTABLES = ("entrega_clave", "vista")
# el avance de un trabajo del panel: cambia a cada paso y solo vive en memoria (si el proceso se
# reinicia, el trabajo tambien murio y se cierra como interrumpido)
AVANCE = ("etapa", "avance", "pasos")


class Operaciones:
    def __init__(self, path, reloj=time.time):
        self.path = path
        self.reloj = reloj
        self._lock = threading.Lock()
        d = util.leer_json(path, {})
        self._ops = d.get("ops", {}) if isinstance(d, dict) and isinstance(d.get("ops"), dict) else {}

    def _guardar(self):
        t = self.reloj()
        vivas = sorted(((v.get("creada", 0), k) for k, v in self._ops.items()
                        if t - v.get("creada", 0) < RETENCION_S), reverse=True)[:MAX_OPS]
        self._ops = {k: self._ops[k] for _, k in vivas}
        try:
            util.escribir_json(self.path, {"v": 1, "ops": self._ops}, modo=0o600)
        except OSError:
            pass

    def registrar(self, op_id, usuario, orden, pid=None, nombre=None, ros_version=None, extra=None):
        with self._lock:
            self._ops[op_id] = {"usuario": usuario, "orden": orden, "pid": pid, "nombre": nombre,
                                "ros_version": ros_version, "creada": int(self.reloj()), "terminada": False}
            self._ops[op_id].update({k: v for k, v in (extra or {}).items() if k in CAMPOS})
            self._guardar()

    def avanzar(self, op_id, **campos):
        """Avance de un trabajo del panel aun abierto (campos de AVANCE), solo en memoria."""
        with self._lock:
            o = self._ops.get(op_id)
            if o is None or o.get("terminada"):
                return False
            o.update({k: v for k, v in campos.items() if k in AVANCE})
            return True

    def quitar(self, op_id):
        with self._lock:
            if self._ops.pop(op_id, None) is not None:
                self._guardar()

    def listar(self):
        """Copia de todas las operaciones guardadas {op_id: dict} (lectura con el cerrojo)."""
        with self._lock:
            return {k: dict(v) for k, v in self._ops.items()}

    def obtener(self, op_id):
        with self._lock:
            o = self._ops.get(op_id)
            return dict(o) if o else None

    def terminar(self, op_id, **campos):
        """Marca la operación como terminada. Devuelve False si ya lo estaba (para registrar una vez)."""
        with self._lock:
            o = self._ops.get(op_id)
            if o is None or o.get("terminada"):
                return False
            o.update({k: v for k, v in campos.items() if k in CAMPOS})
            o["terminada"] = True
            self._guardar()
            return True

    def anotar(self, op_id, sobrescribir=True, **campos):
        """Apunta campos de ANOTABLES en una operacion ya registrada. Con sobrescribir=False no
        pisa lo que ya este (la peticion que gano `terminar` manda). False si no existe."""
        with self._lock:
            o = self._ops.get(op_id)
            if o is None:
                return False
            # solo lo que cambia: `vista=True` se anota en cada visita a la pagina y reescribir el
            # fichero entero sin cambios no aporta nada (revision 2026-10-15, B6)
            nuevos = {k: v for k, v in campos.items()
                      if k in ANOTABLES and (sobrescribir or k not in o) and o.get(k) != v}
            if nuevos:
                o.update(nuevos)
                self._guardar()
            return True
