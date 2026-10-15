"""Todo en hora de Ecuador por defecto (el user, 2026-10-12).

Tipo: correccion de defecto. Sin --zona al instalar, el orquestador pasaba IDS_TZ=UTC y el panel
(y Eventos) mostraban la hora UTC (5 h por delante); el generador ya usaba America/Guayaquil.
Ahora la zona por defecto es America/Guayaquil en todas las piezas; sin tzdata, Ecuador es UTC-5
fijo (no tiene horario de verano) en vez de caer en UTC.

2026-10-15 (auditoria): «UTC dentro, Ecuador fuera» tambien en las fechas de AbuseIPDB (venian en
UTC y se ensenaban como locales) y en la CLI `ids-panel` (no ponia la zona: su bitacora y sus
copias salian en UTC).
"""
import ast
import html
import importlib
import json
import os
import subprocess
import sys
import tempfile
import time
import types
import unittest
from datetime import datetime, timedelta, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(REPO, "images", "panel", "rootfs", "usr", "local", "lib", "ids-panel")
LANZADOR = os.path.join(REPO, "images", "panel", "rootfs", "usr", "local", "bin", "ids-panel")
if LIB not in sys.path:
    sys.path.insert(0, LIB)

UTC_MEDIODIA = datetime(2026, 10, 12, 17, 0, tzinfo=timezone.utc)   # 12:00 en Ecuador
ECUADOR = timezone(timedelta(hours=-5))                             # sin horario de verano


def _piezas(ns, nombres):
    """Ejecuta en `ns` las definiciones de nivel de modulo de dashboard.py cuyo nombre esta en
    `nombres`: el codigo REAL del panel, no una copia. Devuelve `ns`."""
    with open(os.path.join(LIB, "dashboard.py"), encoding="utf-8") as f:
        src = f.read()
    for n in ast.parse(src).body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in nombres:
            exec(ast.get_source_segment(src, n) or "", ns)
    return ns


def _sin_zoneinfo(funcion, *args):
    """Llama a `funcion` como si no hubiera tzdata (el import de zoneinfo falla)."""
    import builtins
    real = builtins.__import__

    def falso(nombre, *a, **k):
        if nombre == "zoneinfo":
            raise ImportError("sin tzdata")
        return real(nombre, *a, **k)
    builtins.__import__ = falso
    try:
        return funcion(*args)
    finally:
        builtins.__import__ = real


def _devolver_tz(tz):
    if tz is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = tz
    if hasattr(time, "tzset"):
        time.tzset()


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


class FechasDeAbuseIPDB(unittest.TestCase):
    """Correccion de defecto (auditoria, 2026-10-15): las fechas de AbuseIPDB (`lastReportedAt` en
    la ficha de una IP, `mostRecentReport` en cada direccion de una red) se cortaban del texto de
    la API, que va en UTC, y se ensenaban como hora local: 5 h adelantadas y, con la fecha cortada
    a 10, del dia siguiente de 19:00 a 24:00. Ahora la cache las guarda en UTC con su zona y se
    pasan a IDS_TZ al mostrarlas (`fecha_ec`)."""

    @classmethod
    def setUpClass(cls):
        ns = {"os": os, "html": html, "json": json, "time": time, "datetime": datetime,
              "timezone": timezone, "timedelta": timedelta,
              # el cruce con los CPEs de la ficha tiene su propia prueba (test_culpables_ficha)
              "culpables_ficha_html": lambda ip, cats, esc=None, tope=6, ejemplos=None: ""}
        _piezas(ns, ("_zona", "fecha_ec", "AIDB_CATS", "AIDB_REMEDIO", "js_attr", "RANGO_TOPE",
                     "_RANGO_JS", "rango_detalle_html", "ficha_ip_html", "_aidb_resumen",
                     "_aidb_resumen_red"))
        ns["TZ_EC"] = ns["_zona"]("America/Guayaquil")     # la zona de la empresa: aqui, Ecuador
        cls.ns = ns

    def test_utc_pasa_a_hora_de_ecuador_con_su_dia(self):
        f = self.ns["fecha_ec"]
        # las 03:00 UTC del 16 son las 22:00 del 15 en Ecuador (cortada a 10 salia el 16)
        self.assertEqual(f("2026-10-16T03:00:00+00:00"), "15/10/2026 22:00")
        self.assertEqual(f("2026-10-16T03:00:00Z"), "15/10/2026 22:00")
        self.assertEqual(f("2026-10-16T03:00:00.123456+00:00"), "15/10/2026 22:00")
        self.assertEqual(f("2026-09-20T10:00:00+00:00"), "20/09/2026 05:00")
        # la cache vieja la guardaba cortada a 19, sin el «+00:00»: era UTC igual
        self.assertEqual(f("2026-10-16T03:00:00"), "15/10/2026 22:00")
        # una marca que ya trae otra zona se respeta
        self.assertEqual(f("2026-10-15T22:00:00-05:00"), "15/10/2026 22:00")

    def test_lo_que_no_se_entiende_sale_como_antes(self):
        f = self.ns["fecha_ec"]
        # una fecha sin hora (cache vieja de una red) no se puede pasar de zona: tal cual
        self.assertEqual(f("2026-09-19"), "2026-09-19")
        # el ultimo: año 1 en UTC, fuera de rango al pasarlo a UTC-5 (OverflowError)
        for raro in ("ayer", "2026-10-16Tbasura", "2026-13-45T99:00:00+00:00",
                     "0001-01-01T00:00:00+00:00"):
            self.assertEqual(f(raro), raro)
        self.assertEqual(f(None), "")
        self.assertEqual(f(""), "")

    def test_la_cache_las_guarda_en_utc_con_su_zona(self):
        r = self.ns["_aidb_resumen"]({"ipAddress": "203.0.113.6", "abuseConfidenceScore": 35,
                                      "lastReportedAt": "2026-10-16T03:00:00+00:00"})
        self.assertEqual(r["ultimo"], "2026-10-16T03:00:00+00:00")
        red = self.ns["_aidb_resumen_red"]("203.0.113.0/28", {"numPossibleHosts": 16, "reportedAddress": [
            {"ipAddress": "203.0.113.9", "abuseConfidenceScore": 21, "numReports": 3,
             "mostRecentReport": "2026-10-16T03:00:00+00:00", "countryCode": "EC"}]})
        self.assertEqual(red["denunciadas"][0][3], "2026-10-16T03:00:00+00:00")

    def test_la_ficha_y_el_rango_las_muestran_en_hora_de_ecuador(self):
        ficha = self.ns["ficha_ip_html"]({"ip": "203.0.113.6", "score": 35, "reportes": 14,
                                          "denunciantes": 7, "ultimo": "2026-10-16T03:00:00+00:00",
                                          "cats": [[4, 12]], "ts": 0})
        self.assertIn("&middot; última 15/10/2026 22:00</div>", ficha)
        self.assertNotIn("2026-10-16", ficha)
        rango = self.ns["rango_detalle_html"]({"tipo": "red", "red": "203.0.113.0/28", "hosts": 16,
                                               "denunciadas": [
                                                   ["203.0.113.9", 21, 3, "2026-10-16T03:00:00+00:00", "EC"],
                                                   ["203.0.113.6", 35, 10, "2026-09-19", "EC"]]})
        self.assertIn("<td class=mono>15/10/2026 22:00</td>", rango)
        self.assertIn("<td class=mono>2026-09-19</td>", rango)      # cache vieja: tal cual
        self.assertNotIn("2026-10-16", rango)


class ZonaDelProceso(unittest.TestCase):
    """Correccion de defecto (auditoria, 2026-10-15): sin tzdata, `_aplicar_tz` ponia en TZ el
    nombre IANA, la libc no lo encontraba y el proceso (la bitacora del panel y de la CLI) caia en
    UTC mientras las pantallas (TZ_EC) iban en UTC-5. Ahora el proceso usa la misma zona fija que
    TZ_EC, en formato POSIX. Con tzdata, el nombre, como siempre."""

    @classmethod
    def setUpClass(cls):
        cls.ns = _piezas({"timezone": timezone, "timedelta": timedelta, "os": os, "time": time},
                         ("_zona", "_tz_proceso", "_aplicar_tz"))

    def poner(self, nombre, sin_tzdata=False):
        self.ns["IDS_TZ"] = nombre
        self.ns["TZ_EC"] = (_sin_zoneinfo(self.ns["_zona"], nombre) if sin_tzdata
                            else self.ns["_zona"](nombre))

    def test_sin_tzdata_ecuador_es_utc_menos_5_tambien_en_el_proceso(self):
        self.poner("America/Guayaquil", sin_tzdata=True)
        self.assertEqual(self.ns["_tz_proceso"](), "<-05>5")
        # una zona que no se conoce cae en UTC, como TZ_EC: va el nombre (la libc tambien da UTC)
        self.poner("Europe/Madrid", sin_tzdata=True)
        self.assertEqual(self.ns["_tz_proceso"](), "Europe/Madrid")
        self.poner("UTC")
        self.assertEqual(self.ns["_tz_proceso"](), "UTC")

    @unittest.skipUnless(hasattr(time, "tzset"), "sin time.tzset (Windows) el proceso no cambia de "
                         "zona; _aplicar_tz no hace nada ahi")
    def test_aplicar_tz_sin_tzdata_deja_el_proceso_en_hora_de_ecuador(self):
        self.addCleanup(_devolver_tz, os.environ.get("TZ"))
        self.poner("America/Guayaquil", sin_tzdata=True)
        self.ns["_aplicar_tz"]()
        self.assertEqual(os.environ["TZ"], "<-05>5")
        self.assertEqual(time.strftime("%H:%M", time.localtime(UTC_MEDIODIA.timestamp())), "12:00")


class CLIEnHoraDeLaEmpresa(unittest.TestCase):
    """Correccion de defecto (auditoria, 2026-10-15): `ids-panel` (crear-admin, restablecer,
    confianza) no ponia la zona de la empresa como el panel. El contenedor corre en UTC: la
    bitacora y el nombre de la copia de `confianza vaciar` salian en UTC, mezclados con las lineas
    del panel en hora local (5 h por delante)."""

    def test_al_cargar_el_panel_pone_su_zona_con_la_funcion_del_panel(self):
        from idspanel import cli
        llamadas = []
        falso = types.ModuleType("dashboard")
        falso._aplicar_tz = lambda: llamadas.append("tz")
        antes = sys.modules.get("dashboard")
        sys.modules["dashboard"] = falso
        try:
            self.assertIs(cli._dash(), falso)
        finally:
            if antes is None:
                sys.modules.pop("dashboard", None)
            else:
                sys.modules["dashboard"] = antes
        self.assertEqual(llamadas, ["tz"])

    @unittest.skipUnless(hasattr(time, "tzset"), "sin time.tzset (Windows) un proceso no cambia de "
                         "zona: el panel tampoco (ver _aplicar_tz)")
    def test_bitacora_y_copia_en_hora_de_ecuador_con_el_contenedor_en_utc(self):
        """La CLI de verdad (el lanzador de la imagen) en otro proceso, con TZ=UTC como en el
        contenedor e IDS_TZ=America/Guayaquil."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        r = tmp.name
        for d in ("panel", "datos", "run"):
            os.makedirs(os.path.join(r, d))
        env = dict(os.environ, IDS_PANEL_DIR=os.path.join(r, "panel"), IDS_DATOS=os.path.join(r, "datos"),
                   IDS_RUN=os.path.join(r, "run"), IDS_MASTER_KEY=os.path.join(r, "master_key"),
                   IDS_ORQ_SOCK=os.path.join(r, "orq.sock"), IDS_ORQ_TOKEN=os.path.join(r, "orq_token"),
                   IDS_PUERTO="5637", IDS_TZ="America/Guayaquil", TZ="UTC",
                   PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1")
        for args in (["confianza", "agregar", "198.51.100.7", "--nota", "prueba"], ["confianza", "vaciar"]):
            p = subprocess.run([sys.executable, LANZADOR] + args, env=env, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=300)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        with open(os.path.join(r, "panel", "log", "bitacora.log"), encoding="utf-8") as f:
            lineas = [ln.split("\t") for ln in f.read().splitlines()]
        self.assertEqual([c[3] for c in lineas], ["CONFIANZA-AGREGADA", "CONFIANZA-VACIADA"], lineas)
        marcas = [datetime.strptime(c[0], "%Y-%m-%d %H:%M:%S") for c in lineas]
        copias = [n for n in os.listdir(os.path.join(r, "panel", "conf")) if n.endswith(".antes-de-vaciar")]
        self.assertEqual(len(copias), 1, copias)
        # confianza.json.AAAAMMDDTHHMMSS.antes-de-vaciar
        marcas.append(datetime.strptime(copias[0].split(".")[2], "%Y%m%dT%H%M%S"))
        ahora_ec = datetime.now(timezone.utc).astimezone(ECUADOR).replace(tzinfo=None)
        for m in marcas:
            # en UTC estarian 5 h por delante; el margen es lo que tarda la prueba
            self.assertLess(abs((m - ahora_ec).total_seconds()), 600, (m, ahora_ec))


class Orquestador(unittest.TestCase):
    def test_sin_zona_en_ids_conf_es_ecuador(self):
        src = open(os.path.join(REPO, "orquestador", "ids_orq.py"), encoding="utf-8").read()
        self.assertIn('self.zona = kv.get("ZONA_HORARIA") or "America/Guayaquil"', src)


if __name__ == "__main__":
    unittest.main()
