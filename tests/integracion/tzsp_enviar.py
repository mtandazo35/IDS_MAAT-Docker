#!/usr/bin/env python3
"""Reenvía las tramas Ethernet de un pcap como TZSP (lo que hace un MikroTik con sniff-tzsp).

    tzsp_enviar.py <fichero.pcap> <ip destino> [puerto=37008] [repeticiones=3]

Cabecera TZSP: versión 1, tipo 0 (recibido), encapsulación 1 (Ethernet), etiqueta END."""

import socket
import struct
import sys
import time

CABECERA = b"\x01\x00\x00\x01\x01"


def tramas(path):
    datos = open(path, "rb").read()
    magia = datos[:4]
    if magia == b"\xd4\xc3\xb2\xa1":
        orden = "<"
    elif magia == b"\xa1\xb2\xc3\xd4":
        orden = ">"
    else:
        raise SystemExit("no es un pcap clásico")
    if struct.unpack(orden + "I", datos[20:24])[0] != 1:
        raise SystemExit("el pcap no es Ethernet (linktype 1)")
    i = 24
    while i + 16 <= len(datos):
        _, _, incl, _ = struct.unpack(orden + "IIII", datos[i:i + 16])
        i += 16
        yield datos[i:i + incl]
        i += incl


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    destino = (argv[1], int(argv[2]) if len(argv) > 2 else 37008)
    veces = int(argv[3]) if len(argv) > 3 else 3
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    n = 0
    for _ in range(veces):
        for t in tramas(argv[0]):
            s.sendto(CABECERA + t, destino)
            n += 1
            time.sleep(0.01)
        time.sleep(0.5)
    print("tzsp_enviar: %d tramas a %s:%d" % (n, destino[0], destino[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
