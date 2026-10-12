"""Cliente del orquestador (ORQUESTADOR §3, CONTRATO-F1a §5.11).

Socket /run/ids-orq/orq.sock, JSON por líneas, UNA petición y UNA respuesta por conexión:

  {"v":1, "op_id":"<uuid4>", "token":"…", "orden":"…", "params":{…}, "quien":"panel:<login>",
   "ip":"<ip real>", "ts":<epoch>}
  -> {"op_id":"…", "ok":bool, "codigo":"OK|ACEPTADA|CONFLICTO|CONFLICTO_PUERTO|NO_EXISTE|INVALIDO|
       FALLO|REVERTIDA", "mensaje":"…", "datos":{…}}

El transporte se puede inyectar (pruebas). AF_UNIX se importa dentro de la función: el módulo
se importa en Windows.
"""

import json
import time
import uuid

MAX_RESPUESTA = 4 * 1024 * 1024

# códigos propios del panel (no los manda el orquestador)
SIN_SERVICIO = "SIN_SERVICIO"
SIN_TOKEN = "SIN_TOKEN"


class ErrorTransporte(Exception):
    pass


def transporte_unix(ruta_sock, timeout=30):
    def enviar(pet):
        import socket
        if not hasattr(socket, "AF_UNIX"):
            raise ErrorTransporte("AF_UNIX no disponible en esta plataforma")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(str(ruta_sock))
            s.sendall((json.dumps(pet, ensure_ascii=False) + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf and len(buf) < MAX_RESPUESTA:
                trozo = s.recv(65536)
                if not trozo:
                    break
                buf += trozo
        except OSError as e:
            raise ErrorTransporte(str(e))
        finally:
            s.close()
        if not buf.strip():
            raise ErrorTransporte("el orquestador cerró la conexión sin responder")
        try:
            return json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
        except ValueError:
            raise ErrorTransporte("respuesta ilegible del orquestador")
    return enviar


class ClienteOrq:
    def __init__(self, ruta_sock, ruta_token, transporte=None, reloj=time.time):
        self.ruta_sock = ruta_sock
        self.ruta_token = ruta_token
        self.transporte = transporte or transporte_unix(ruta_sock)
        self.reloj = reloj

    def _token(self):
        with open(self.ruta_token, "r", encoding="utf-8") as f:
            return f.read().strip()

    def pedir(self, orden, params, quien="panel", ip="", op_id=None):
        """Respuesta del orquestador como dict. Nunca lanza: los fallos del canal vuelven con
        codigo SIN_SERVICIO o SIN_TOKEN."""
        op_id = op_id or str(uuid.uuid4())
        try:
            token = self._token()
        except (OSError, ValueError):            # ilegible o no UTF-8: «nunca lanza» (auditoria ap2 H1)
            return {"op_id": op_id, "ok": False, "codigo": SIN_TOKEN,
                    "mensaje": "no se puede leer el token del orquestador", "datos": {}}
        pet = {"v": 1, "op_id": op_id, "token": token, "orden": orden, "params": params or {},
               "quien": quien, "ip": ip or "", "ts": int(self.reloj())}
        try:
            r = self.transporte(pet)
        except (ErrorTransporte, OSError) as e:
            return {"op_id": op_id, "ok": False, "codigo": SIN_SERVICIO, "mensaje": str(e)[:200], "datos": {}}
        if not isinstance(r, dict):
            return {"op_id": op_id, "ok": False, "codigo": SIN_SERVICIO,
                    "mensaje": "respuesta ilegible del orquestador", "datos": {}}
        r.setdefault("datos", {})
        if not isinstance(r["datos"], dict):
            r["datos"] = {}
        r.setdefault("mensaje", "")
        r.setdefault("codigo", "FALLO")
        return r


def _caben(datos):
    caben = (datos or {}).get("caben")
    if isinstance(caben, dict) and caben:
        return " Caben ahora: " + ", ".join("%s %s" % (k, v) for k, v in caben.items()) + "."
    return ""


def traducir(codigo, mensaje, datos=None):
    """Texto claro para un técnico a partir de la respuesta del orquestador."""
    mensaje = (mensaje or "").strip()
    if codigo in ("OK", "ACEPTADA"):
        return mensaje or "Hecho."
    if codigo == SIN_SERVICIO:
        return ("No se puede hablar con el orquestador: el servicio ids-orq del servidor está parado "
                "o el panel no tiene montado su socket. Prueba de nuevo en un minuto y, si sigue, "
                "revisa «systemctl status ids-orq» en el servidor.")
    if codigo == SIN_TOKEN:
        return "El panel no puede leer el token del orquestador (secreto orq_token no montado)."
    if mensaje == "token inválido":
        return "El orquestador rechazó al panel: el token no coincide (revisa el secreto orq_token)."
    if mensaje == "demasiadas peticiones":
        return "El orquestador está recibiendo demasiadas peticiones. Espera un minuto y repite."
    if codigo == "INVALIDO":
        return "Los datos no son válidos: %s." % mensaje.rstrip(".")
    if codigo == "CONFLICTO":
        return "No se puede hacer ahora: %s.%s" % (mensaje.rstrip("."), _caben(datos))
    if codigo == "CONFLICTO_PUERTO":
        return ("El puerto del túnel que le toca a este punto está ocupado en el servidor (%s). "
                "Libéralo o avisa al administrador del servidor." % mensaje.rstrip("."))
    if codigo == "NO_EXISTE":
        return "Ese punto ya no existe (quizá alguien lo borró)."
    if codigo == "REVERTIDA":
        return "La operación falló y se deshizo todo lo hecho. Detalle: %s." % mensaje.rstrip(".")
    return "El orquestador no pudo completar la orden. Detalle: %s." % (mensaje.rstrip(".") or codigo)


MARCAS = (("certificado", "# --- Certificado API-SSL"), ("v7", "# --- RouterOS v7"),
          ("v6", "# --- RouterOS v6"))


def partir_comandos(texto):
    """Separa el bloque de `punto.comandos` en cabecera, certificado, v7 y v6.

    Si el formato no es el esperado, devuelve {"todo": texto} y el panel lo muestra entero."""
    texto = texto or ""
    out = {"cabecera": []}
    actual = "cabecera"
    vistos = set()
    for linea in texto.splitlines():
        for nombre, marca in MARCAS:
            if linea.startswith(marca):
                actual = nombre
                vistos.add(nombre)
                out[actual] = []
                break
        out.setdefault(actual, []).append(linea)
    if not {"v6", "v7"} <= vistos:
        return {"todo": texto.rstrip("\n")}
    res = {}
    for k, lineas in out.items():
        while lineas and lineas[-1].strip() in ("#", ""):
            lineas.pop()
        res[k] = "\n".join(lineas)
    return res
