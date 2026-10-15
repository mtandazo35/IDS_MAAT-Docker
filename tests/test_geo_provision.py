"""Base GeoIP del mapa: se instala, deja rastro si no puede y reintenta (lab .152, 2026-10-15).

La imagen del panel no traía ca-certificates: la descarga HTTPS de la base fallaba siempre
(CERTIFICATE_VERIFY_FAILED), `_provisionar_geo` se callaba el error con `except: pass` y solo se
intentaba una vez al arrancar. Resultado: /srv/ids/panel/geo vacío, `window.__ATTACK_GEO={}` en
todos los reportes y el mapa de En vivo en blanco aunque el punto tuviera miles de alertas a
destinos públicos. Tipo de cada prueba en su docstring (CONTRATO-F2 §10.5).
"""
import io
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
import _dash  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent


class Respuesta:
    def __init__(self, texto):
        self.texto = texto.encode("utf-8")

    def read(self):
        return self.texto


def csv_geo(n=1200):
    """n rangos /24 consecutivos desde 1.0.0.0, como el CSV de dbip-country."""
    filas = []
    for i in range(n):
        a, b = divmod(i, 256)
        filas.append("1.%d.%d.0,1.%d.%d.255,%s" % (a, b, a, b, "US" if i % 2 else "JP"))
    return "\n".join(filas) + "\n"


class ParadaFalsa:
    """_PARAR de mentira: apunta cada espera y nunca para (salvo que se pida)."""

    def __init__(self, parar_en=None):
        self.esperas = []
        self.parar_en = parar_en

    def wait(self, t=None):
        self.esperas.append(t)
        return self.parar_en is not None and len(self.esperas) >= self.parar_en


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


class Provisionar(Base):
    def test_sin_red_deja_rastro_y_dice_false(self):
        """Corrección de defecto: si la descarga falla, False y una línea «GeoIP: …» con el motivo
        (antes `except: pass`: el mapa vacío sin rastro en el log)."""
        err = io.StringIO()
        fallo = OSError("CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate")
        with mock.patch("urllib.request.urlopen", side_effect=fallo), redirect_stderr(err):
            self.assertIs(self.d._provisionar_geo(), False)
        self.assertIn("GeoIP: no se pudo bajar la base", err.getvalue())
        self.assertIn("CERTIFICATE_VERIFY_FAILED", err.getvalue())
        self.assertFalse(os.path.exists(self.d._GEOIP_BIN2))

    def test_base_bajada_se_instala(self):
        """Conservación: con la descarga bien, escribe ipv4.bin, pide regenerar el reporte y dice True."""
        err = io.StringIO()
        with mock.patch("urllib.request.urlopen", return_value=Respuesta(csv_geo())), redirect_stderr(err):
            self.assertIs(self.d._provisionar_geo(), True)
        self.assertGreater(os.path.getsize(self.d._GEOIP_BIN2), 1200 * 10)
        self.assertTrue(self.d.FORCE_REGEN)
        self.assertIn("GeoIP: base instalada (1200 rangos)", err.getvalue())

    def test_base_corta_no_se_usa(self):
        """Corrección de defecto: una descarga truncada (pocos rangos) no se instala y lo dice."""
        err = io.StringIO()
        with mock.patch("urllib.request.urlopen", return_value=Respuesta(csv_geo(10))), redirect_stderr(err):
            self.assertIs(self.d._provisionar_geo(), False)
        self.assertIn("solo trae 10 rangos", err.getvalue())
        self.assertFalse(os.path.exists(self.d._GEOIP_BIN2))

    def test_ya_instalada_no_baja_nada(self):
        """Conservación: con ipv4.bin presente no hay descarga."""
        os.makedirs(os.path.dirname(self.d._GEOIP_BIN2), exist_ok=True)
        with open(self.d._GEOIP_BIN2, "wb") as f:
            f.write(b"\x01\x00\x00\x00" + b"\x00" * 10)
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("no debe bajar")):
            self.assertIs(self.d._provisionar_geo(), True)


class Hilo(Base):
    def test_reintenta_cada_hora_hasta_tenerla(self):
        """Corrección de defecto: mientras falte la base, otro intento cada GEO_REINTENTO_S (antes
        una sola vez al arrancar: sin internet en ese momento, sin mapa hasta reiniciar)."""
        intentos = iter([False, False, True])
        parada = ParadaFalsa()
        with mock.patch.object(self.d, "_provisionar_geo", side_effect=lambda: next(intentos)), \
                mock.patch.object(self.d, "_PARAR", parada):
            self.d._geo_hilo()
        self.assertEqual(parada.esperas, [3600, 3600])
        self.assertEqual(self.d.GEO_REINTENTO_S, 3600)

    def test_para_con_el_panel(self):
        """Capacidad nueva: al parar el panel (SIGTERM) el hilo deja de reintentar."""
        parada = ParadaFalsa(parar_en=1)
        llamadas = []
        with mock.patch.object(self.d, "_provisionar_geo", side_effect=lambda: llamadas.append(1) or False), \
                mock.patch.object(self.d, "_PARAR", parada):
            self.d._geo_hilo()
        self.assertEqual(len(llamadas), 1)

    def test_lo_arranca_el_refrescador(self):
        """Corrección de defecto: el refrescador arranca el hilo que reintenta, no un solo intento."""
        fuente = Path(self.d.__file__).read_text(encoding="utf-8")
        self.assertIn("threading.Thread(target=_geo_hilo, daemon=True).start()", fuente)
        self.assertNotIn("threading.Thread(target=_provisionar_geo", fuente)


class Imagen(unittest.TestCase):
    def test_panel_con_ca_certificates(self):
        """Corrección de defecto: sin ca-certificates ninguna llamada HTTPS del panel verifica el
        certificado (GeoIP, dueño de la IP por RDAP, Telegram, IA)."""
        docker = (RAIZ / "images" / "panel" / "Dockerfile").read_text(encoding="utf-8")
        apt = re.search(r"apt-get install[^\n]*", docker).group(0)
        self.assertIn("ca-certificates", re.split(r"[\s;\\]+", apt))


if __name__ == "__main__":
    unittest.main()
