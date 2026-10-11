"""Secretos del panel cifrados con la clave maestra (CONTRATO-F2 §10.3).

Las claves de la API de los routers, de AbuseIPDB/abuse.ch/Groq y el token de Telegram se guardan en
la configuración como `enc1:<base64(nonce12 + texto_cifrado + etiqueta)>` (AES-256-GCM). La clave sale
de `/run/secrets/master_key` (32 bytes en hex, ro; en el host `/etc/ids-maat/master.key`).

- `cifrar(texto)` -> valor para guardar. Vacío se guarda vacío.
- `descifrar(valor)` -> texto. Un valor sin prefijo es texto en claro (configuración vieja o importada):
  se devuelve tal cual y `necesita_cifrar(valor)` dice que hay que volver a guardarlo cifrado.
- Sin clave maestra o con un valor manipulado: `SecretoNoDisponible`. Nunca se borra nada por eso.
- `asociado` liga el texto cifrado a su sitio (p. ej. "router:p001:PASS"): copiar el valor cifrado a
  otro campo o a otro router no lo hace válido allí.
"""

import base64
import os
import threading

PREFIJO = "enc1:"
RUTA_CLAVE = os.environ.get("IDS_MASTER_KEY", "/run/secrets/master_key")

_lock = threading.Lock()
_cache = {"ruta": None, "clave": None}


class SecretoNoDisponible(Exception):
    pass


def _clave():
    with _lock:
        if _cache["ruta"] == RUTA_CLAVE and _cache["clave"] is not None:
            return _cache["clave"]
        try:
            with open(RUTA_CLAVE, encoding="ascii") as f:
                txt = f.read().strip()
            clave = bytes.fromhex(txt)
        except (OSError, ValueError, UnicodeDecodeError):
            raise SecretoNoDisponible("no se puede leer la clave maestra") from None
        if len(clave) != 32:
            raise SecretoNoDisponible("la clave maestra no tiene 32 bytes")
        _cache.update(ruta=RUTA_CLAVE, clave=clave)
        return clave


def disponible():
    try:
        _clave()
        return True
    except SecretoNoDisponible:
        return False


def _aead():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(_clave())


def cifrar(texto, asociado=""):
    if texto is None or texto == "":
        return ""
    nonce = os.urandom(12)
    ct = _aead().encrypt(nonce, str(texto).encode("utf-8"), asociado.encode("utf-8") or None)
    return PREFIJO + base64.b64encode(nonce + ct).decode("ascii")


def descifrar(valor, asociado=""):
    if valor is None or valor == "":
        return ""
    valor = str(valor)
    if not valor.startswith(PREFIJO):
        return valor
    try:
        bruto = base64.b64decode(valor[len(PREFIJO):], validate=True)
    except ValueError:
        raise SecretoNoDisponible("valor cifrado ilegible") from None
    if len(bruto) < 12 + 16:
        raise SecretoNoDisponible("valor cifrado ilegible")
    from cryptography.exceptions import InvalidTag
    try:
        return _aead().decrypt(bruto[:12], bruto[12:], asociado.encode("utf-8") or None).decode("utf-8")
    except InvalidTag:
        raise SecretoNoDisponible("valor cifrado manipulado o de otro sitio") from None


def necesita_cifrar(valor):
    return bool(valor) and not str(valor).startswith(PREFIJO)
