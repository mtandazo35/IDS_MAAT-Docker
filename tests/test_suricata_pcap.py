"""Captura de la prueba de extremo a extremo (fixtures/suricata/alerta-2100498.pcap).

La alerta real con Suricata la comprueba tests/imagen/test_suricata_pcap.sh; aquí se
comprueba que el fichero del repo es el que sale del generador, que es un pcap válido con
checksums correctos y que su carga casa con el content del sid 2100498."""
import importlib.util
import re
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_suricata as A  # noqa: E402

PCAP = A.FIXTURES / "alerta-2100498.pcap"
REGLA = (A.FIXTURES / "et" / "rules" / "emerging-attack_response.rules").read_text(encoding="utf-8")


def cargar_generador():
    spec = importlib.util.spec_from_file_location("generar_pcap_b", A.FIXTURES / "generar_pcap.py")
    mod = importlib.util.module_from_spec(spec)
    antes, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = antes
    return mod


def content_a_bytes(texto):
    """content de Suricata ("uid=0|28|root|29|") a bytes."""
    out = b""
    for i, trozo in enumerate(texto.split("|")):
        out += bytes.fromhex(trozo) if i % 2 else trozo.encode("ascii")
    return out


def suma(datos):
    if len(datos) % 2:
        datos += b"\x00"
    t = sum((datos[i] << 8) + datos[i + 1] for i in range(0, len(datos), 2))
    while t >> 16:
        t = (t & 0xFFFF) + (t >> 16)
    return t


def leer_pcap(datos):
    magia, vmay, vmen, _tz, _sig, snap, enlace = struct.unpack("<IHHiIII", datos[:24])
    assert (magia, vmay, vmen, enlace) == (0xA1B2C3D4, 2, 4, 1)
    off, paquetes = 24, []
    while off < len(datos):
        _s, _us, incl, orig = struct.unpack("<IIII", datos[off:off + 16])
        assert incl == orig <= snap
        paquetes.append(datos[off + 16:off + 16 + incl])
        off += 16 + incl
    assert off == len(datos)
    return paquetes


class Pcap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.datos = PCAP.read_bytes()
        cls.paquetes = leer_pcap(cls.datos)

    def test_es_lo_que_genera_el_generador(self):
        self.assertEqual(cargar_generador().generar(), self.datos)

    def test_sin_cr_ni_bom(self):
        self.assertNotIn(b"\r", self.datos)
        self.assertFalse(self.datos.startswith(b"\xef\xbb\xbf"))

    def test_checksums_ip_y_tcp_correctos(self):
        for p in self.paquetes:
            self.assertEqual(p[12:14], b"\x08\x00")
            ip = p[14:]
            ihl = (ip[0] & 0x0F) * 4
            self.assertEqual(suma(ip[:ihl]), 0xFFFF)
            total = struct.unpack("!H", ip[2:4])[0]
            seg = ip[ihl:total]
            pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(seg))
            self.assertEqual(ip[9], 6)
            self.assertEqual(suma(pseudo + seg), 0xFFFF)

    def test_sesion_tcp_completa_con_la_respuesta_root(self):
        banderas, cargas = [], []
        for p in self.paquetes:
            ip = p[14:]
            ihl = (ip[0] & 0x0F) * 4
            tcp = ip[ihl:]
            off = (tcp[12] >> 4) * 4
            banderas.append(tcp[13])
            if tcp[off:]:
                cargas.append(tcp[off:])
        self.assertEqual(banderas[:3], [0x02, 0x12, 0x10])   # SYN, SYN-ACK, ACK
        self.assertIn(0x11, banderas)                          # FIN-ACK
        regla = next(l for l in REGLA.splitlines() if "sid:2100498;" in l)
        content = re.search(r'content:"([^"]+)"', regla).group(1)
        self.assertTrue(any(content_a_bytes(content) in c for c in cargas))

    def test_el_abonado_esta_en_la_lan_de_ejemplo(self):
        ip = self.paquetes[0][14:]
        self.assertEqual(ip[12:16], bytes([10, 0, 0, 10]))


if __name__ == "__main__":
    unittest.main()
