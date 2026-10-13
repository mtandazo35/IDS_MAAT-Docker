"""Todo en hora de Ecuador por defecto (el user, 2026-10-12).

Tipo: correccion de defecto. Sin --zona al instalar, el orquestador pasaba IDS_TZ=UTC y el panel
(y Eventos) mostraban la hora UTC (5 h por delante); el generador ya usaba America/Guayaquil.
Ahora la zona por defecto es America/Guayaquil en todas las piezas; sin tzdata, Ecuador es UTC-5
fijo (no tiene horario de verano) en vez de caer en UTC.
"""
import importlib
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(REPO, "images", "panel", "rootfs", "usr", "local", "lib", "ids-panel")
if LIB not in sys.path:
    sys.path.insert(0, LIB)

UTC_MEDIODIA = datetime(2026, 10, 12, 17, 0, tzinfo=timezone.utc)   # 12:00 en Ecuador


class ZonaPorDefecto(unittest.TestCase):
    def setUp(self):
        self.viejo = os.environ.pop("IDS_TZ", None)
        self.addCleanup(self.restaurar)

    def restaurar(self):
        if self.viejo is not None:
            os.environ["IDS_TZ"] = self.viejo
        else:
            os.environ.pop("IDS_TZ", None)

    def test_eventos_sin_ids_tz_muestra_hora_de_ecuador(self):
        import eventos_web
        eventos_web._ZONAS.clear()
        z = eventos_web._zona()
        self.assertEqual(UTC_MEDIODIA.astimezone(z).strftime("%H:%M"), "12:00")

    def test_config_del_panel_por_defecto_ecuador(self):
        from idspanel import config
        importlib.reload(config)
        src = open(config.__file__, encoding="utf-8").read()
        self.assertIn('env.get("IDS_TZ") or "America/Guayaquil"', src)

    def test_dashboard_sin_tzdata_ecuador_es_utc_menos_5(self):
        """Sin la base de zonas (Windows sin tzdata, imagen rota) no se cae en UTC: Ecuador es
        UTC-5 fijo. Una zona desconocida distinta si cae en UTC, como antes."""
        src = open(os.path.join(LIB, "dashboard.py"), encoding="utf-8").read()
        ini = src.index("def _zona(nombre):")
        ns = {"timezone": timezone, "timedelta": timedelta}
        exec(src[ini:src.index("TZ_EC = _zona(IDS_TZ)")], ns)
        import builtins
        real = builtins.__import__

        def sin_zoneinfo(nombre, *a, **k):
            if nombre == "zoneinfo":
                raise ImportError("sin tzdata")
            return real(nombre, *a, **k)
        builtins.__import__ = sin_zoneinfo
        try:
            z = ns["_zona"]("America/Guayaquil")
            otra = ns["_zona"]("Europe/Madrid")
        finally:
            builtins.__import__ = real
        self.assertEqual(UTC_MEDIODIA.astimezone(z).strftime("%H:%M"), "12:00")
        self.assertEqual(otra, timezone.utc)
        self.assertIn('os.environ.get("IDS_TZ") or "America/Guayaquil"', src)


class MarcasDeSuricata(unittest.TestCase):
    def test_historial_respeta_la_zona_de_la_marca(self):
        """Correccion de defecto: el historial (y con el la conducta y «ultima vez») leia la
        marca de Suricata como hora local e ignoraba su zona: con Suricata en UTC y el panel en
        Ecuador, todo salia 5 h adelantado."""
        import time
        src = open(os.path.join(LIB, "dashboard.py"), encoding="utf-8").read()
        ini = src.index("def _cd_ts(s):")
        ns = {"time": time, "datetime": datetime, "_CD_TS": {}}
        exec(src[ini:src.index("def _cd_top(")], ns)
        cd_ts = ns["_cd_ts"]
        self.assertEqual(cd_ts("2026-10-12T17:00:00.123456+0000"), UTC_MEDIODIA.timestamp())
        self.assertEqual(cd_ts("2026-10-12T12:00:00.123456-0500"), UTC_MEDIODIA.timestamp())
        self.assertEqual(cd_ts("2026-10-12T17:00:00Z"), UTC_MEDIODIA.timestamp())
        # el mismo segundo en otra zona no reutiliza la memoria del anterior
        self.assertEqual(cd_ts("2026-10-12T17:00:00.000001-0500"), UTC_MEDIODIA.timestamp() + 5 * 3600)
        # sin zona: hora local, como antes
        self.assertEqual(cd_ts("2026-10-12T12:00:00"), time.mktime(time.strptime("2026-10-12T12:00:00",
                                                                             "%Y-%m-%dT%H:%M:%S")))


class Orquestador(unittest.TestCase):
    def test_sin_zona_en_ids_conf_es_ecuador(self):
        src = open(os.path.join(REPO, "orquestador", "ids_orq.py"), encoding="utf-8").read()
        self.assertIn('self.zona = kv.get("ZONA_HORARIA") or "America/Guayaquil"', src)


if __name__ == "__main__":
    unittest.main()
