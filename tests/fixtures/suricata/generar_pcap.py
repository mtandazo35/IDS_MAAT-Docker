#!/usr/bin/env python3
"""Genera alerta-2100498.pcap: una captura sintética y determinista que dispara el sid
2100498 de ET Open (GPL ATTACK_RESPONSE id check returned root, content "uid=0|28|root|29|").

Una sesión TCP completa (handshake, petición, respuesta, cierre) entre un abonado
10.0.0.10 (dentro de la LAN de ejemplo 10.0.0.0/24) y 203.0.113.80:8080. La respuesta del
servidor lleva "uid=0(root) gid=0(root) groups=0(root)". Checksums IP y TCP correctos.

Restricciones: el fichero no puede contener ningún byte CR (0x0d) ni empezar por un BOM (la
prueba de finales de línea del repo mira todos los ficheros), así que la carga útil usa
solo LF y el generador ajusta los números de secuencia hasta que no aparezca ninguno.

Uso:  python3 generar_pcap.py [salida]   (por defecto, junto a este fichero)
"""
import os
import struct
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
NOMBRE = "alerta-2100498.pcap"

MAC_CLIENTE = b"\x02\x00\x00\x00\x00\x0a"
MAC_SERVIDOR = b"\x02\x00\x00\x00\x00\x50"
CLIENTE = "10.0.0.10"
SERVIDOR = "203.0.113.80"
PUERTO_CLIENTE = 40100
PUERTO_SERVIDOR = 8080
PETICION = b"id\n"
RESPUESTA = b"uid=0(root) gid=0(root) groups=0(root)\n"
TS_BASE = 1760090000

SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def ip4(txt):
    return bytes(int(x) for x in txt.split("."))


def suma(datos):
    if len(datos) % 2:
        datos += b"\x00"
    t = 0
    for i in range(0, len(datos), 2):
        t += (datos[i] << 8) + datos[i + 1]
    while t >> 16:
        t = (t & 0xFFFF) + (t >> 16)
    return (~t) & 0xFFFF


def tcp(src, dst, sp, dp, seq, ack, flags, carga=b""):
    cab = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 0x50, flags, 64240, 0, 0)
    pseudo = ip4(src) + ip4(dst) + struct.pack("!BBH", 0, 6, len(cab) + len(carga))
    cs = suma(pseudo + cab + carga)
    return cab[:16] + struct.pack("!H", cs) + cab[18:] + carga


def ipv4(src, dst, carga, ident):
    cab = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(carga), ident, 0x4000, 64, 6, 0)
    cab += ip4(src) + ip4(dst)
    return cab[:10] + struct.pack("!H", suma(cab)) + cab[12:] + carga


def trama(src_mac, dst_mac, paquete_ip):
    return dst_mac + src_mac + b"\x08\x00" + paquete_ip


def paquetes(isn_c, isn_s, ident):
    """La sesión entera: del cliente (c) y del servidor (s)."""
    c, s = isn_c, isn_s
    out = []

    def de_cliente(seq, ack, flags, carga=b""):
        nonlocal ident
        ident += 1
        out.append(trama(MAC_CLIENTE, MAC_SERVIDOR, ipv4(
            CLIENTE, SERVIDOR,
            tcp(CLIENTE, SERVIDOR, PUERTO_CLIENTE, PUERTO_SERVIDOR, seq, ack, flags, carga),
            ident)))

    def de_servidor(seq, ack, flags, carga=b""):
        nonlocal ident
        ident += 1
        out.append(trama(MAC_SERVIDOR, MAC_CLIENTE, ipv4(
            SERVIDOR, CLIENTE,
            tcp(SERVIDOR, CLIENTE, PUERTO_SERVIDOR, PUERTO_CLIENTE, seq, ack, flags, carga),
            ident)))

    de_cliente(c, 0, SYN)
    de_servidor(s, c + 1, SYN | ACK)
    de_cliente(c + 1, s + 1, ACK)
    de_cliente(c + 1, s + 1, PSH | ACK, PETICION)
    c2 = c + 1 + len(PETICION)
    de_servidor(s + 1, c2, ACK)
    de_servidor(s + 1, c2, PSH | ACK, RESPUESTA)
    s2 = s + 1 + len(RESPUESTA)
    de_cliente(c2, s2, ACK)
    de_cliente(c2, s2, FIN | ACK)
    de_servidor(s2, c2 + 1, FIN | ACK)
    de_cliente(c2 + 1, s2 + 1, ACK)
    return out


def pcap(lista):
    """libpcap clásico, Ethernet, microsegundos, little endian."""
    datos = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, p in enumerate(lista):
        datos += struct.pack("<IIII", TS_BASE + i // 4, (i % 4) * 250000, len(p), len(p)) + p
    return datos


def generar():
    """Bytes del pcap. Determinista: siempre el mismo resultado."""
    for k in range(1000):
        datos = pcap(paquetes(0x10000000 + k * 7919, 0x20000000 + k * 104729, 100 + k))
        if b"\r" not in datos and not datos.startswith(b"\xef\xbb\xbf"):
            return datos
    raise RuntimeError("no se encontró una variante sin CR")


def main(argv):
    salida = argv[1] if len(argv) > 1 else os.path.join(AQUI, NOMBRE)
    with open(salida, "wb") as f:
        f.write(generar())
    print(salida)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
