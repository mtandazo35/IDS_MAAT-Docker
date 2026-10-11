"""Utilidades comunes: escritura atómica, JSON, fechas y escape HTML."""

import datetime as dt
import html
import json
import os
import secrets
from pathlib import Path


def esc(v):
    """Escape HTML de cualquier dato (también comillas: vale dentro de atributos)."""
    if v is None:
        return ""
    return html.escape(str(v), quote=True)


def escribir_atomico(path, texto, modo=0o600):
    """Escribe con un temporal del mismo directorio (creado ya con `modo`) y os.replace."""
    path = Path(path)
    tmp = path.with_name(".%s.%s.tmp" % (path.name, secrets.token_hex(4)))
    datos = texto.encode("utf-8") if isinstance(texto, str) else texto
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), modo)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(datos)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        try:
            os.chmod(str(tmp), modo)
        except OSError:
            pass
        os.replace(str(tmp), str(path))
    except BaseException:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise


def leer_json(path, defecto=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return defecto


def escribir_json(path, obj, modo=0o600):
    escribir_atomico(path, json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=True) + "\n", modo)


_ZONAS = {}


def zona(nombre):
    if nombre in _ZONAS:
        return _ZONAS[nombre]
    z = dt.timezone.utc
    if nombre and nombre.upper() != "UTC":
        try:
            from zoneinfo import ZoneInfo
            z = ZoneInfo(nombre)
        except Exception:  # noqa: BLE001 - zona desconocida o sin tzdata: UTC
            z = dt.timezone.utc
    _ZONAS[nombre] = z
    return z


def fecha(ts, tz="UTC", segundos=True):
    """epoch -> texto en la zona de la empresa ('' si no hay)."""
    if ts is None:
        return ""
    try:
        d = dt.datetime.fromtimestamp(float(ts), zona(tz))
    except (ValueError, OverflowError, OSError, TypeError):
        return ""
    return d.strftime("%Y-%m-%d %H:%M:%S" if segundos else "%Y-%m-%d %H:%M")


def ts_suricata(txt):
    """'2026-10-10T08:15:00.123456+0000' -> epoch float (None si no se entiende)."""
    if not isinstance(txt, str):
        return None
    for formato in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return dt.datetime.strptime(txt, formato).timestamp()
        except ValueError:
            continue
    return None


def edad(segundos):
    if segundos is None:
        return "-"
    segundos = max(0, int(segundos))
    if segundos < 120:
        return "%d s" % segundos
    if segundos < 7200:
        return "%d min" % (segundos // 60)
    if segundos < 172800:
        return "%d h" % (segundos // 3600)
    return "%d d" % (segundos // 86400)
