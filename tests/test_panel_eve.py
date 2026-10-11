"""Panel: lectura del final de eve.json por punto (alertas, filtro por IP, conteo de 24 h)."""

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures" / "panel"))
import _ayuda_panel as A  # noqa: E402
from idspanel import eve  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="ids-eve-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        self.t = 1791700000.0


class Lectura(Base):
    def test_lineas_hacia_atras_con_bloques_pequenos(self):
        lineas = ["linea-%04d-%s" % (i, "x" * (i % 37)) for i in range(400)]
        p = self.d / "f.json"
        p.write_bytes(("\n".join(lineas) + "\n" + '{"a medias').encode())     # última sin \n
        for bloque in (7, 64, 1000, 1 << 20):
            with mock.patch.object(eve, "BLOQUE", bloque):
                leidas = [x.decode() for x in eve.lineas_hacia_atras(str(p))]
            self.assertEqual(leidas, list(reversed(lineas)), bloque)

    def test_solo_alertas_del_punto_mas_nuevas_primero(self):
        t = self.t
        A.escribir_eve(self.d, "p003", [A.linea_alerta(t - 30, "p003", "10.0.0.1", "192.0.2.1", firma="A"),
                                        A.linea_stats(t - 20),
                                        '{"timestamp":"x","event_type":"dns","dns":{}}',
                                        "basura no json",
                                        A.linea_alerta(t - 10, "p003", "10.0.0.2", "192.0.2.2", firma="B")])
        a = eve.ultimas_alertas(self.d, "p003")
        self.assertEqual([x["firma"] for x in a], ["B", "A"])
        self.assertEqual(a[0]["punto"], "p003")
        self.assertEqual((a[0]["src_ip"], a[0]["src_port"], a[0]["dest_ip"], a[0]["dest_port"]),
                         ("10.0.0.2", 51000, "192.0.2.2", 443))
        self.assertEqual((a[0]["sid"], a[0]["severidad"]), (2000001, 2))
        self.assertAlmostEqual(a[0]["ts"], t - 10, delta=1)
        self.assertEqual(eve.ultimas_alertas(self.d, "p003", limite=1)[0]["firma"], "B")
        self.assertEqual(eve.ultimas_alertas(self.d, "p999"), [])
        self.assertEqual(eve.ultimas_alertas(self.d, "../p003"), [])

    def test_filtro_por_ip_exacto(self):
        t = self.t
        A.escribir_eve(self.d, "p003", [A.linea_alerta(t - 3, "p003", "10.0.0.1", "192.0.2.1", firma="uno"),
                                        A.linea_alerta(t - 2, "p003", "10.0.0.11", "192.0.2.1", firma="once"),
                                        A.linea_alerta(t - 1, "p003", "192.0.2.9", "10.0.0.1", firma="destino")])
        self.assertEqual([x["firma"] for x in eve.ultimas_alertas(self.d, "p003", ip="10.0.0.1")],
                         ["destino", "uno"])                        # 10.0.0.11 no es 10.0.0.1

    def test_ip_repetida_en_dos_puntos_no_se_mezcla(self):
        t = self.t
        A.escribir_eve(self.d, "p003", [A.linea_alerta(t - 5, "p003", "10.0.0.5", "192.0.2.1", firma="norte")])
        A.escribir_eve(self.d, "p004", [A.linea_alerta(t - 4, "p004", "10.0.0.5", "192.0.2.1", firma="sur")])
        filas = eve.alertas_empresa(self.d, ["p003", "p004"], ip="10.0.0.5")
        self.assertEqual([(x["punto"], x["firma"]) for x in filas], [("p004", "sur"), ("p003", "norte")])
        self.assertEqual([x["punto"] for x in eve.ultimas_alertas(self.d, "p003", ip="10.0.0.5")], ["p003"])

    def test_sigue_en_el_rotado(self):
        t = self.t
        A.escribir_eve(self.d, "p003", [A.linea_alerta(t - 100, "p003", "10.0.0.1", "192.0.2.1", firma="rotada")],
                       nombre="eve.json.1")
        A.escribir_eve(self.d, "p003", [A.linea_alerta(t - 1, "p003", "10.0.0.1", "192.0.2.1", firma="nueva")])
        self.assertEqual([x["firma"] for x in eve.ultimas_alertas(self.d, "p003")], ["nueva", "rotada"])

    def test_tope_de_bytes(self):
        t = self.t
        lineas = [A.linea_alerta(t - 1000, "p003", "10.0.0.1", "192.0.2.1", firma="lejana")]
        lineas += [A.linea_stats(t - 900 + i) for i in range(200)]          # ~600 KB de stats
        A.escribir_eve(self.d, "p003", lineas)
        self.assertEqual(eve.ultimas_alertas(self.d, "p003", max_bytes=64 * 1024), [])
        self.assertEqual(len(eve.ultimas_alertas(self.d, "p003")), 1)


class Conteo24h(Base):
    def test_cuenta_solo_las_24_h_y_luego_lee_solo_lo_nuevo(self):
        t = self.t
        reloj = [t]
        c = eve.Contador24h(self.d, reloj=lambda: reloj[0])
        self.assertEqual(c.contar("p003"), (0, True))                        # sin eve
        p = A.escribir_eve(self.d, "p003", [
            A.linea_alerta(t - 90000, "p003", "10.0.0.1", "192.0.2.1"),
            A.linea_alerta(t - 3600, "p003", "10.0.0.1", "192.0.2.1"),
            A.linea_stats(t - 60),
            A.linea_alerta(t - 30, "p003", "10.0.0.2", "192.0.2.1")])
        self.assertEqual(c.contar("p003"), (2, True))
        A.escribir_eve(self.d, "p003", [A.linea_alerta(t - 5, "p003", "10.0.0.3", "192.0.2.1")], modo="a")
        with mock.patch.object(eve, "lineas_hacia_atras", side_effect=AssertionError("no debe releer")):
            self.assertEqual(c.contar("p003"), (3, True))                     # incremental
        # línea a medias: no cuenta hasta que se complete
        with open(p, "a", encoding="utf-8", newline="\n") as f:
            f.write(A.linea_alerta(t - 1, "p003", "10.0.0.4", "192.0.2.1")[:40])
        self.assertEqual(c.contar("p003")[0], 3)
        with open(p, "a", encoding="utf-8", newline="\n") as f:
            f.write(A.linea_alerta(t - 1, "p003", "10.0.0.4", "192.0.2.1")[40:] + "\n")
        self.assertEqual(c.contar("p003")[0], 4)
        reloj[0] = t + 86400 - 100                                            # pasa el día
        self.assertEqual(c.contar("p003")[0], 3)

    def test_rotacion_recuenta(self):
        t = self.t
        c = eve.Contador24h(self.d, reloj=lambda: t)
        p = A.escribir_eve(self.d, "p003", [A.linea_alerta(t - 10 - i, "p003", "10.0.0.1", "192.0.2.1")
                                            for i in range(5)])
        self.assertEqual(c.contar("p003")[0], 5)
        os.replace(p, p.with_name("eve.json.1"))                              # logrotate (sin copytruncate)
        A.escribir_eve(self.d, "p003", [A.linea_alerta(t - 1, "p003", "10.0.0.1", "192.0.2.1")])
        self.assertEqual(c.contar("p003")[0], 6)                              # nuevo + rotado
        A.escribir_eve(self.d, "p003", [])                                    # truncado
        self.assertEqual(c.contar("p003")[0], 5)

    def test_se_para_al_pasar_las_24_h(self):
        t = self.t
        lineas = [A.linea_alerta(t - 200000 + i, "p003", "10.0.0.1", "192.0.2.1") for i in range(2000)]
        lineas += [A.linea_alerta(t - 10, "p003", "10.0.0.1", "192.0.2.1")]
        A.escribir_eve(self.d, "p003", lineas)
        vistas = []
        original = eve.ts_linea

        def contar_lecturas(linea):
            vistas.append(1)
            return original(linea)
        with mock.patch.object(eve, "ts_linea", side_effect=contar_lecturas):
            self.assertEqual(eve.Contador24h(self.d, reloj=lambda: t).contar("p003"), (1, True))
        self.assertLess(len(vistas), 10)                                      # no recorre todo el fichero


class Alias(unittest.TestCase):
    def test_marca_de_alerta_es_la_de_suricata(self):
        linea = A.linea_alerta(time.time(), "p003", "10.0.0.1", "192.0.2.1").encode()
        self.assertIn(eve.MARCA_ALERTA, linea)
        self.assertIsNotNone(eve.ts_linea(linea))


if __name__ == "__main__":
    unittest.main()
