"""Ayudas compartidas de las pruebas de la imagen `vpn` (constructor A)."""
import importlib.machinery
import importlib.util
import shutil
import socket
import struct
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
ROOTFS = RAIZ / "images" / "vpn" / "rootfs"
BIN = ROOTFS / "usr" / "local" / "bin"
RENDER = ROOTFS / "usr" / "local" / "lib" / "ids-vpn" / "render.py"
S6 = ROOTFS / "etc" / "s6-overlay"
FIXTURES = RAIZ / "tests" / "fixtures" / "vpn"

ENTORNO_BUENO = {
    "PUNTO": "p003",
    "N": "3",
    "TUN_NET": "100.64.3.0/24",
    "TUN_SENSOR": "100.64.3.1",
    "TUN_MK": "100.64.3.2",
    "API_PUERTO": "8729",
    "TZSP_PUERTO": "37008",
    "TZSP_BYTES": "10000",
    "TZ": "UTC",
}


def cargar(ruta, nombre):
    """Carga un script (con o sin .py) como módulo nuevo, sin ejecutar su __main__."""
    ruta = str(ruta)
    cargador = importlib.machinery.SourceFileLoader(nombre, ruta)
    spec = importlib.util.spec_from_loader(nombre, cargador)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.pop(nombre, None)
    # sin __pycache__ dentro de images/vpn/rootfs: acabaría copiado en la imagen
    antes = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        cargador.exec_module(mod)
    finally:
        sys.dont_write_bytecode = antes
    return mod


def bash():
    """Ruta de bash, o None. En Windows evita el `bash.exe` de WSL de System32."""
    if sys.platform.startswith("win"):
        for c in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"):
            if Path(c).exists():
                return c
    b = shutil.which("bash")
    if b and "system32" in b.lower():
        return None
    return b


# --- construcción de paquetes --------------------------------------------------------------

def _suma(datos):
    if len(datos) % 2:
        datos += b"\0"
    s = sum(struct.unpack(f"!{len(datos) // 2}H", datos))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4(src, dst, proto, carga, frag=0):
    """Cabecera IPv4 de 20 bytes + carga. `frag` = campo flags+desplazamiento."""
    total = 20 + len(carga)
    cab = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, frag, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    cab = cab[:10] + struct.pack("!H", _suma(cab)) + cab[12:]
    return cab + carga


def tcp(sp, dp, datos=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, 1, 0, 0x50, 0x18, 65535, 0, 0) + datos


def udp(sp, dp, datos=b""):
    return struct.pack("!HHHH", sp, dp, 8 + len(datos), 0) + datos


def ethernet(carga, tipo=0x0800, vlan=None):
    dst = b"\x02\x00\x00\x00\x00\x01"
    src = b"\x02\x00\x00\x00\x00\x02"
    if vlan is not None:
        return dst + src + struct.pack("!HHH", 0x8100, vlan, tipo) + carga
    return dst + src + struct.pack("!H", tipo) + carga


def tzsp(trama, tipo=0, encap=1, tags=b"\x01", version=1):
    """Datagrama TZSP: version | tipo | encapsulado | tags (por defecto solo END) | trama."""
    return struct.pack("!BBH", version, tipo, encap) + tags + trama


def trama_tcp(src="10.0.0.5", dst="192.0.2.80", sp=40000, dp=443, datos=b"x" * 100):
    return ethernet(ipv4(src, dst, 6, tcp(sp, dp, datos)))
