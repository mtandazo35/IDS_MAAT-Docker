"""Base GeoIP del mapa: viene en la imagen y el panel la renueva (lab .152, 2026-10-15).

La imagen del panel no traía ca-certificates: la descarga HTTPS de la base fallaba siempre
(CERTIFICATE_VERIFY_FAILED), `_provisionar_geo` se callaba el error con `except: pass` y solo se
intentaba una vez al arrancar. Resultado: /srv/ids/panel/geo vacío, `window.__ATTACK_GEO={}` en
todos los reportes y el mapa de En vivo en blanco aunque el punto tuviera miles de alertas a
destinos públicos. Ahora la imagen trae su base (geo_base.py imagen: CSV fijado por commit y
SHA256), el panel baja la última cada 30 días y lo dice en el log si no puede, y el generador usa
la renovada si está y la de la imagen si no. Tipo de cada prueba en su docstring (CONTRATO-F2 §10.5).
"""
import array
import ast
import bisect
import hashlib
import importlib.util
import io
import ipaddress
import os
import re
import struct
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
import _dash  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
LIB = RAIZ / "images" / "panel" / "rootfs" / "usr" / "local" / "lib" / "ids-panel"


def cargar_geo_base():
    spec = importlib.util.spec_from_file_location("geo_base_prueba", str(LIB / "geo_base.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


G = cargar_geo_base()


class Respuesta:
    def __init__(self, crudo):
        self.crudo = crudo if isinstance(crudo, bytes) else crudo.encode("utf-8")
        self.cerrada = False

    def read(self):
        return self.crudo

    def close(self):
        self.cerrada = True


def csv_geo(n=1200, pais=None):
    """n rangos /24 consecutivos desde 1.0.0.0, como el CSV de dbip-country."""
    filas = []
    for i in range(n):
        a, b = divmod(i, 256)
        cc = pais or ("US" if i % 2 else "JP")
        filas.append("1.%d.%d.0,1.%d.%d.255,%s" % (a, b, a, b, cc))
    return "\n".join(filas) + "\n"


class ParadaFalsa:
    """_PARAR de mentira: apunta cada espera y para en la espera número `parar_en`."""

    def __init__(self, parar_en=1):
        self.esperas = []
        self.parar_en = parar_en

    def wait(self, t=None):
        self.esperas.append(t)
        return len(self.esperas) >= self.parar_en


class GeoBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_construir_formato_del_lector(self):
        """Capacidad nueva: el binario es el que lee html_report (N, inicios, finales, ISO2)."""
        n, datos = G.construir("basura\n,,\n" + csv_geo() + "1.2.3.4,1.2.3.0,US\nx,y,ZZ\n")
        self.assertEqual(n, 1200)
        self.assertEqual(struct.unpack("<I", datos[:4])[0], 1200)
        self.assertEqual(len(datos), 4 + 1200 * 4 * 2 + 1200 * 2)
        self.assertEqual(datos[-2:], b"US")

    def test_construir_corto_no_vale(self):
        """Corrección de defecto: una descarga cortada (pocos rangos) se rechaza con motivo."""
        with self.assertRaisesRegex(ValueError, "solo 10 rangos"):
            G.construir(csv_geo(10))

    def test_escribir_atomico(self):
        """Capacidad nueva: escribe por .tmp + rename y no deja el temporal."""
        destino = os.path.join(self.tmp.name, "geo", "ipv4.bin")
        G.escribir(b"abc", destino)
        self.assertEqual(Path(destino).read_bytes(), b"abc")
        self.assertEqual(os.listdir(os.path.dirname(destino)), ["ipv4.bin"])

    def test_bajar_comprueba_sha256(self):
        """Capacidad nueva: con sha256 solo se acepta el contenido fijado."""
        crudo = csv_geo().encode()
        bueno = hashlib.sha256(crudo).hexdigest()
        r = Respuesta(crudo)
        with mock.patch("urllib.request.urlopen", return_value=r):
            self.assertEqual(G.bajar("https://x/csv", bueno), crudo.decode())
        self.assertTrue(r.cerrada)
        with mock.patch("urllib.request.urlopen", return_value=Respuesta(crudo + b"1.9.9.0,1.9.9.255,FR\n")):
            with self.assertRaisesRegex(ValueError, "SHA256"):
                G.bajar("https://x/csv", bueno)

    def test_imagen_fijada_por_commit_y_sha256(self):
        """Capacidad nueva: la imagen usa un commit fijo (no main) y un SHA256 completo."""
        self.assertRegex(G.COMMIT_IMAGEN, r"^[0-9a-f]{40}$")
        self.assertRegex(G.SHA256_IMAGEN, r"^[0-9a-f]{64}$")
        self.assertIn(G.COMMIT_IMAGEN, G.URL_PLANTILLA % G.COMMIT_IMAGEN)
        self.assertTrue(G.URL_ULTIMA.endswith("/main/dbip-country/dbip-country-ipv4.csv"))
        self.assertEqual(G.REFRESCO_S, 30 * 86400)

    def test_main_imagen(self):
        """Capacidad nueva: `geo_base.py imagen <salida>` baja el CSV fijado, lo comprueba y escribe."""
        crudo = csv_geo().encode()
        destino = os.path.join(self.tmp.name, "share", "geo", "ipv4.bin")
        pedidas = []

        def urlopen(url, timeout=None):
            pedidas.append(url)
            return Respuesta(crudo)
        with mock.patch.object(G, "SHA256_IMAGEN", hashlib.sha256(crudo).hexdigest()), \
                mock.patch("urllib.request.urlopen", side_effect=urlopen), redirect_stdout(io.StringIO()):
            self.assertEqual(G.main(["imagen", destino]), 0)
        self.assertEqual(pedidas, [G.URL_PLANTILLA % G.COMMIT_IMAGEN])
        self.assertGreater(os.path.getsize(destino), 1200 * 10)

    def test_main_imagen_con_otro_contenido_falla(self):
        """Capacidad nueva: si el CSV no es el fijado, el build de la imagen falla (no sale sin mapa)."""
        destino = os.path.join(self.tmp.name, "ipv4.bin")
        with mock.patch("urllib.request.urlopen", return_value=Respuesta(csv_geo())):
            with self.assertRaisesRegex(ValueError, "SHA256"):
                G.main(["imagen", destino])
        self.assertFalse(os.path.exists(destino))

    def test_main_fijar_y_uso(self):
        """Capacidad nueva: `fijar <commit>` imprime las constantes; sin argumentos válidos, uso y 2."""
        crudo = csv_geo().encode()
        out = io.StringIO()
        with mock.patch("urllib.request.urlopen", return_value=Respuesta(crudo)), redirect_stdout(out):
            self.assertEqual(G.main(["fijar", "a" * 40]), 0)
        self.assertIn('COMMIT_IMAGEN = "%s"' % ("a" * 40), out.getvalue())
        self.assertIn('SHA256_IMAGEN = "%s"' % hashlib.sha256(crudo).hexdigest(), out.getvalue())
        with redirect_stderr(io.StringIO()):
            self.assertEqual(G.main([]), 2)


class Lector(unittest.TestCase):
    """html_report._geo_load/pais extraídos del fuente: la renovada manda; si no, la de la imagen."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ejec = os.path.join(self.tmp.name, "panel", "geo", "ipv4.bin")
        self.imagen = os.path.join(self.tmp.name, "share", "geo", "ipv4.bin")

    def pais(self, ip):
        fuente = (LIB / "html_report.py").read_text(encoding="utf-8")
        ns = {"os": os, "struct": struct, "array": array, "bisect": bisect, "_ipm": ipaddress,
              "GEOIP_BIN": self.ejec, "GEOIP_BIN_IMAGEN": self.imagen, "_G_S": None, "_G_E": None,
              "_G_C": None, "_G_loaded": False, "_G_ok": False, "_geo_cache": {}}
        for nodo in ast.parse(fuente).body:
            if isinstance(nodo, ast.FunctionDef) and nodo.name in ("_geo_load", "pais"):
                exec(ast.get_source_segment(fuente, nodo), ns)
        return ns["pais"](ip)

    def test_solo_la_de_la_imagen(self):
        """Corrección de defecto: sin base renovada, el mapa usa la de la imagen (antes, vacío)."""
        G.escribir(G.construir(csv_geo(pais="JP"))[1], self.imagen)
        self.assertEqual(self.pais("1.0.0.5"), "JP")

    def test_la_renovada_manda(self):
        """Capacidad nueva: con las dos, gana la que renueva el panel."""
        G.escribir(G.construir(csv_geo(pais="JP"))[1], self.imagen)
        G.escribir(G.construir(csv_geo(pais="DE"))[1], self.ejec)
        self.assertEqual(self.pais("1.0.0.5"), "DE")

    def test_renovada_rota_vuelve_a_la_imagen(self):
        """Corrección de defecto: una renovada ilegible no deja el mapa vacío."""
        G.escribir(G.construir(csv_geo(pais="JP"))[1], self.imagen)
        G.escribir(b"\x05\x00", self.ejec)
        self.assertEqual(self.pais("1.0.0.5"), "JP")

    def test_sin_ninguna(self):
        """Conservación: sin base, país vacío (y las privadas nunca tienen país)."""
        self.assertEqual(self.pais("1.0.0.5"), "")
        G.escribir(G.construir(csv_geo(pais="JP"))[1], self.imagen)
        self.assertEqual(self.pais("10.0.0.5"), "")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = _dash.Arbol(self.tmp.name)
        self.d = _dash.cargar(self.a)
        self.d.nodos.asegurar_dirs()

    def tearDown(self):
        self.d.nodos.quitar_nodo()
        _dash.restaurar()
        self.tmp.cleanup()

    def poner(self, ruta, pais="JP", hace_s=0):
        self.d.geo_base.escribir(self.d.geo_base.construir(csv_geo(pais=pais))[1], ruta)
        if hace_s:
            t = time.time() - hace_s
            os.utime(ruta, (t, t))


class Provisionar(Base):
    def test_rutas_de_las_dos_bases(self):
        """Capacidad nueva: la renovada en PANEL/geo y la de la imagen en SHARE/geo."""
        self.assertEqual(self.d._GEOIP_BIN2, os.path.join(self.a.panel, "geo", "ipv4.bin"))
        self.assertEqual(self.d._GEOIP_IMAGEN, os.path.join(self.a.share, "geo", "ipv4.bin"))

    def test_al_dia_no_baja_nada(self):
        """Conservación: con la renovada de menos de 30 días no hay descarga."""
        self.poner(self.d._GEOIP_BIN2, hace_s=86400)
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("no debe bajar")):
            self.assertIs(self.d._provisionar_geo(), True)

    def test_vieja_se_renueva(self):
        """Capacidad nueva: con más de 30 días se baja la última, se pide regenerar y queda en el log."""
        self.poner(self.d._GEOIP_BIN2, pais="DE", hace_s=31 * 86400)
        err = io.StringIO()
        with mock.patch("urllib.request.urlopen", return_value=Respuesta(csv_geo(pais="FR"))), redirect_stderr(err):
            self.assertIs(self.d._provisionar_geo(), True)
        self.assertTrue(self.d.FORCE_REGEN)
        self.assertIn("GeoIP: base renovada (1200 rangos)", err.getvalue())
        self.assertLess(time.time() - os.path.getmtime(self.d._GEOIP_BIN2), 60)
        self.assertEqual(Path(self.d._GEOIP_BIN2).read_bytes()[-2:], b"FR")

    def test_sin_red_con_la_de_la_imagen(self):
        """Corrección de defecto: si falla, lo dice en el log (antes `except: pass`) y el mapa sigue
        con la de la imagen."""
        self.poner(self.d._GEOIP_IMAGEN)
        err = io.StringIO()
        fallo = OSError("CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate")
        with mock.patch("urllib.request.urlopen", side_effect=fallo), redirect_stderr(err):
            self.assertIs(self.d._provisionar_geo(), False)
        self.assertIn("GeoIP: no se pudo renovar la base", err.getvalue())
        self.assertIn("CERTIFICATE_VERIFY_FAILED", err.getvalue())
        self.assertIn("sigue con la de la imagen", err.getvalue())
        self.assertFalse(os.path.exists(self.d._GEOIP_BIN2))

    def test_sin_red_y_sin_ninguna(self):
        """Corrección de defecto: sin ninguna base, el log dice que el mapa sale vacío."""
        err = io.StringIO()
        with mock.patch("urllib.request.urlopen", side_effect=OSError("sin red")), redirect_stderr(err):
            self.assertIs(self.d._provisionar_geo(), False)
        self.assertIn("sin base: el mapa sale vacio", err.getvalue())

    def test_vieja_y_sin_red_sigue_con_la_anterior(self):
        """Capacidad nueva: una renovada vieja no se borra si no se puede bajar otra."""
        self.poner(self.d._GEOIP_BIN2, hace_s=40 * 86400)
        err = io.StringIO()
        with mock.patch("urllib.request.urlopen", side_effect=OSError("sin red")), redirect_stderr(err):
            self.assertIs(self.d._provisionar_geo(), False)
        self.assertIn("sigue con la base anterior", err.getvalue())
        self.assertTrue(os.path.getsize(self.d._GEOIP_BIN2) > 0)

    def test_descarga_cortada_no_se_instala(self):
        """Corrección de defecto: una descarga truncada no pisa nada y lo dice."""
        err = io.StringIO()
        with mock.patch("urllib.request.urlopen", return_value=Respuesta(csv_geo(10))), redirect_stderr(err):
            self.assertIs(self.d._provisionar_geo(), False)
        self.assertIn("solo 10 rangos", err.getvalue())
        self.assertFalse(os.path.exists(self.d._GEOIP_BIN2))


class Hilo(Base):
    def esperas(self, resultados, parar_en):
        it = iter(resultados)
        parada = ParadaFalsa(parar_en)
        with mock.patch.object(self.d, "_provisionar_geo", side_effect=lambda: next(it)), \
                mock.patch.object(self.d, "_PARAR", parada):
            self.d._geo_hilo()
        return parada.esperas

    def test_sin_ninguna_base_reintenta_cada_hora(self):
        """Corrección de defecto: sin base y sin red, otro intento cada hora (antes, uno solo)."""
        self.assertEqual(self.esperas([False, False, True], 3), [3600, 3600, 86400])

    def test_con_la_de_la_imagen_no_insiste(self):
        """Capacidad nueva: si falla pero hay base que usar, se vuelve a mirar al día siguiente."""
        self.poner(self.d._GEOIP_IMAGEN)
        self.assertEqual(self.esperas([False, False], 2), [86400, 86400])

    def test_al_dia_se_revisa_cada_dia_y_para_con_el_panel(self):
        """Capacidad nueva: una revisión al día; al parar el panel (SIGTERM) el hilo sale."""
        self.assertEqual(self.esperas([True], 1), [86400])

    def test_lo_arranca_el_refrescador(self):
        """Corrección de defecto: el refrescador arranca el hilo que renueva, no un solo intento."""
        fuente = Path(self.d.__file__).read_text(encoding="utf-8")
        self.assertIn("threading.Thread(target=_geo_hilo, daemon=True).start()", fuente)
        self.assertNotIn("threading.Thread(target=_provisionar_geo", fuente)


class Imagen(unittest.TestCase):
    def setUp(self):
        self.docker = (RAIZ / "images" / "panel" / "Dockerfile").read_text(encoding="utf-8")

    def test_panel_con_ca_certificates(self):
        """Corrección de defecto: sin ca-certificates ninguna llamada HTTPS del panel verifica el
        certificado (GeoIP, feeds de reputación, dueño de la IP por RDAP, Telegram, IA)."""
        apt = re.search(r"apt-get install[^\n]*", self.docker).group(0)
        self.assertIn("ca-certificates", re.split(r"[\s;\\]+", apt))

    def test_base_geoip_en_la_imagen(self):
        """Capacidad nueva: el build construye la base de la imagen antes de COPY rootfs (capa
        aparte) y comprueba que está."""
        paso = "python3 /usr/local/lib/ids-panel/geo_base.py imagen /usr/local/share/ids-panel/geo/ipv4.bin"
        self.assertIn(paso, self.docker)
        self.assertLess(self.docker.index(paso), self.docker.index("COPY rootfs/ /"))
        self.assertIn("COPY rootfs/usr/local/lib/ids-panel/geo_base.py /usr/local/lib/ids-panel/geo_base.py",
                      self.docker)
        self.assertEqual(self.docker.count("test -s /usr/local/share/ids-panel/geo/ipv4.bin"), 2)


if __name__ == "__main__":
    unittest.main()
