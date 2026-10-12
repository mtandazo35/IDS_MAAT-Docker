"""Correcciones F2 de la pagina Eventos (eventos_web.py), auditoria B (B-07, B-08, B-14, B-16)
y auditoria A (A-25, parte de Eventos). Todas son de tipo «correccion de defecto»
(CONTRATO-F2 §10.5): cada una reproduce el defecto (falla en b9dcd02) y prueba la correccion.
"""
import gzip
import os
import struct
import time
import tracemalloc
import unittest
import zlib
from unittest import mock

from test_eventos_busqueda import T0, Base, alerta, iso, linea

MiB = 1024 * 1024


def miembros_vacios(n):
    """Un .gz hecho de `n` miembros gzip vacios: 0 bytes descomprimidos, ~20 bytes cada uno."""
    return gzip.compress(b"", mtime=0) * n


def gz_fname(tam_nombre, datos=b""):
    """Un miembro gzip con la cabecera FNAME de `tam_nombre` bytes (gzip la lee byte a byte)."""
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    cuerpo = co.compress(datos) + co.flush()
    cab = b"\x1f\x8b\x08\x08" + struct.pack("<I", 0) + b"\x00\xff" + b"n" * tam_nombre + b"\x00"
    return cab + cuerpo + struct.pack("<II", zlib.crc32(datos) & 0xffffffff, len(datos) & 0xffffffff)


class LineaLargaHaciaAtras(Base):
    def test_b07_memoria_acotada_con_linea_larga_terminada_en_salto(self):
        """Correccion de defecto (B-07/EP-01): una linea de 24 MiB terminada en \\n se salta y
        cuenta como incompleta sin acumularla entera en memoria (antes: pico de 2x la linea)."""
        larga = linea({"timestamp": iso(T0 - 20), "event_type": "alert", "x": "A" * (24 * MiB)})
        p = self.ruta("p001", "eve.json")
        with open(p, "w", encoding="ascii") as f:
            f.write(alerta(T0 - 30, sid=2000031) + "\n" + larga + "\n" + alerta(T0 - 10, sid=2000032) + "\n")
        os.utime(p, (T0, T0))
        del larga
        tracemalloc.start()
        try:
            res = self.buscar("p001")
            _, pico = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(pico, 8 * MiB, "pico de memoria %.1f MiB" % (pico / MiB))
        self.assertEqual([x["ev"]["alert"]["signature_id"] for x in res["filas"]], [2000032, 2000031])
        self.assertGreaterEqual(res["incompletas"], 1)


class GzPatologicos(Base):
    def setUp(self):
        super().setUp()
        self.escribir("p001", "eve.json", [alerta(T0 - 10)], mtime=T0)

    def _gz(self, nombre, datos, mtime):
        p = self.ruta("p001", nombre)
        with open(p, "wb") as f:
            f.write(datos)
        os.utime(p, (mtime, mtime))
        return p

    def test_b08_miembros_vacios_se_cortan_y_es_parcial(self):
        """Correccion de defecto (B-08/EP-02): un .gz de 300 000 miembros vacios (6 MB en disco)
        no se recorre entero sin tope: se omite con aviso (parcial) y la consulta es rapida."""
        self._gz("eve.json.1.gz", miembros_vacios(300000), T0 - 100)
        t = time.monotonic()
        res = self.buscar("p001")
        dur = time.monotonic() - t
        self.assertLess(dur, 1.5)
        self.assertTrue(res["parcial"])
        self.assertTrue(any("miembros" in x[3] for x in res["omitidos"]), res["omitidos"])
        self.assertEqual(len(res["filas"]), 1)

    def test_b08_cabecera_fname_enorme_cuenta_bytes(self):
        """Correccion de defecto (B-08/EP-02): los bytes comprimidos consumidos (aqui una cabecera
        FNAME de 16 MiB que no produce nada) cuentan para el tope: la busqueda dice que es parcial."""
        self._gz("eve.json.1.gz", gz_fname(16 * MiB), T0 - 100)
        with mock.patch.object(self.ev, "TOPE_BYTES", 4 * MiB):
            res = self.buscar("p001")
        self.assertTrue(res["parcial"])
        self.assertTrue(res["motivo"])
        self.assertGreater(res["bytes"], 4 * MiB)

    def test_b08_gz_normal_sigue_leyendose(self):
        """Conservacion: un .gz rotado normal (y uno con varios miembros y relleno de ceros) se lee
        entero como antes."""
        datos = (alerta(T0 - 50, sid=2000050) + "\n").encode()
        dos = gzip.compress(datos) + gzip.compress((alerta(T0 - 40, sid=2000040) + "\n").encode()) + b"\x00" * 64
        self._gz("eve.json.2.gz", dos, T0 - 30)
        res = self.buscar("p001")
        self.assertFalse(res["parcial"], res["omitidos"])
        self.assertEqual(sorted(x["ev"]["alert"]["signature_id"] for x in res["filas"]),
                         [2000001, 2000040, 2000050])

    def test_b08_disponible_desde_acotada(self):
        """Correccion de defecto (B-08/EP-02): disponible_desde() no recorre un .gz de miembros
        vacios en cada carga de la pagina: pasa al siguiente fichero con tope de bytes y tiempo."""
        self._gz("eve.json.3.gz", miembros_vacios(400000), T0 - 7200)
        self._gz("eve.json.2.gz", gzip.compress((alerta(T0 - 5000) + "\n").encode()), T0 - 3600)
        t = time.monotonic()
        desde = self.ev.disponible_desde("p001")
        self.assertLess(time.monotonic() - t, 1.0)
        self.assertEqual(desde // 1000000, T0 - 5000)

    def test_b08_detalle_de_un_gz_patologico_no_cuelga(self):
        """Correccion de defecto (B-08): la referencia del detalle sobre un .gz de miembros vacios
        se rechaza con tope (no recorre los miembros sin limite)."""
        self._gz("eve.json.1.gz", miembros_vacios(300000), T0 - 100)
        t = time.monotonic()
        with self.assertRaises(self.ev.RefInvalida):
            self.ev._linea_en("p001", "eve.json.1.gz", 10, time.monotonic())
        self.assertLess(time.monotonic() - t, 1.5)


class FicheroIlegible(Base):
    def test_a25_fichero_que_no_se_puede_abrir_marca_parcial(self):
        """Correccion de defecto (A-25, §10.5 «consulta que llega a su limite»): un fichero de la
        ventana que no se puede abrir no deja la busqueda como completa ni «Sin coincidencias»."""
        self.escribir("p001", "eve.json", [alerta(T0 - 10)], mtime=T0)
        self.escribir("p001", "eve.json.1", [alerta(T0 - 900)], mtime=T0 - 600)
        real = self.ev._abrir

        def abrir(ruta, st):
            if ruta.endswith("eve.json.1"):
                raise PermissionError(13, "permiso denegado")
            return real(ruta, st)
        with mock.patch.object(self.ev, "_abrir", abrir):
            res = self.buscar("p001")
            html_ = self.ev.pagina(self.q(), "p001")
        self.assertTrue(res["parcial"])
        self.assertTrue(any(x[1] == "eve.json.1" for x in res["omitidos"]), res["omitidos"])
        self.assertIn("eve.json.1", html_)
        self.assertIn("parcial", html_)


class Concurrencia(Base):
    def test_b14_consultas_simultaneas_limitadas(self):
        """Correccion de defecto (B-14/EP-08): con todas las plazas de busqueda ocupadas, una
        consulta mas no lee nada y dice que reintente (cada consulta puede leer 200 MB y 8 s)."""
        self.escribir("p001", "eve.json", [alerta(T0 - 10)], mtime=T0)
        tomadas = 0
        for _ in range(self.ev.CONCURRENCIA):
            self.assertTrue(self.ev._CONSULTAS.acquire(timeout=1))
            tomadas += 1
        try:
            with mock.patch.object(self.ev, "ESPERA_OCUPADO", 0.05), \
                    mock.patch.object(self.ev, "buscar", side_effect=AssertionError("no debia buscar")):
                html_ = self.ev.pagina(self.q(), "p001")
        finally:
            for _ in range(tomadas):
                self.ev._CONSULTAS.release()
        self.assertIn("ocupad", html_)
        # con plazas libres vuelve a buscar
        self.assertIn("2000001", self.ev.pagina(self.q(), "p001"))

    def test_b14_las_plazas_se_devuelven_con_excepcion(self):
        """La plaza se devuelve aunque la busqueda falle."""
        with mock.patch.object(self.ev, "buscar", side_effect=RuntimeError("x")):
            for _ in range(self.ev.CONCURRENCIA + 1):
                with self.assertRaises(RuntimeError):
                    self.ev.pagina(self.q(), "p001")
        self.escribir("p001", "eve.json", [alerta(T0 - 10)], mtime=T0)
        self.assertIn("2000001", self.ev.pagina(self.q(), "p001"))


class AbrirSinBloquear(Base):
    def test_b16_abre_con_o_nonblock(self):
        """Correccion de defecto (B-16/EP-09): `_abrir` abre con O_NONBLOCK (un FIFO cambiado por
        el fichero entre la validacion y el open no deja el hilo colgado). En Windows no existe la
        constante: se simula para ver que se pasa."""
        visto = {}

        def abrir(ruta, flags, *a):
            visto["flags"] = flags
            raise OSError("parada de la prueba")
        with mock.patch.object(os, "O_NONBLOCK", 0x800, create=True), \
                mock.patch.object(self.ev.os, "open", abrir):
            with self.assertRaises(OSError):
                self.ev._abrir("x", os.stat(self.tmp))
        self.assertTrue(visto["flags"] & 0x800)


if __name__ == "__main__":
    unittest.main()
