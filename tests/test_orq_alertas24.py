"""`alertas_24h` en estado.json (§5.10): recuento real de las alertas de las últimas 24 h de cada
punto, que el orquestador saca del contador acumulado de Suricata (`stats.detect.alert`, vuelve a 0
al reiniciarlo) en cubos de 5 min guardados en /srv/ids/estado/alertas.json.

El panel contaba solo las alertas de los últimos 8 MB del eve.json vivo (3-5 min de tráfico con
espejo real) y daba «0+». Sistema simulado de _ayuda_orq; nada real. Tipo de cada prueba en su
docstring (CONTRATO-F2 §10.5).
"""

import copy
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

DIA = 86400
CUBO = 300
T0 = 1792098000                     # múltiplo de 300: el cubo de T0 empieza en T0
VIEJO = T0 - 2 * DIA                # un Suricata que lleva más de 24 h en marcha
_FALTA = object()


def stats(epoch, alertas=_FALTA, kp=10):
    """Línea «stats» de Suricata 7 (como la de stats.json) con `detect.alert` si se da."""
    det = {"engines": [{"id": 0, "rules_loaded": 18234, "rules_failed": 0}]}
    if alertas is not _FALTA:
        det["alert"] = alertas
    ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(epoch))
    return json.dumps({"timestamp": ts, "event_type": "stats",
                       "stats": {"capture": {"kernel_packets": kp, "kernel_drops": 0}, "detect": det}},
                      separators=(",", ":"))


def escribir(ruta, *lineas):
    with open(ruta, "w", encoding="utf-8", newline="\n") as f:
        for linea in lineas:
            f.write(linea + "\n")


class Calculo(unittest.TestCase):
    """_alertas_24h a mano, con instantes fijos (sin puntos ni stats)."""

    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def a24(self, cum, inicio, t, pid="p001"):
        return self.orq._alertas_24h(pid, cum, inicio, t)

    def cubos(self, pid="p001"):
        return {int(k): v for k, v in self.orq._alertas()[pid]["cubos"].items()}

    def test_primera_muestra_con_inicio_reciente_reparte(self):
        """Capacidad nueva: un Suricata arrancado hace 1 h con 135 alertas -> las 135 son de las
        últimas 24 h; se reparten a partes iguales entre los 13 cubos de 5 min desde su arranque
        (el resto, al último) y `desde` es el arranque."""
        inicio = T0 - 3600
        self.assertEqual(self.a24(135, inicio, T0 + 10), {"n": 135, "desde": inicio, "completo": False})
        c = self.cubos()
        self.assertEqual(sorted(c), list(range(T0 - 3600, T0 + 1, CUBO)))
        self.assertEqual((c[T0 - 3600], c[T0 - 300], c[T0]), (10, 10, 15))
        self.assertEqual(sum(c.values()), 135)

    def test_primera_muestra_con_inicio_viejo_solo_toma_la_base(self):
        """Capacidad nueva: un Suricata que lleva más de 24 h en marcha no dice cuándo fueron sus
        alertas: se toma la base sin contar nada (`desde` = ahora, incompleto) y desde ahí se
        cuenta lo que sube. Lo mismo sin `inicio`."""
        self.assertEqual(self.a24(5000, VIEJO, T0), {"n": 0, "desde": T0, "completo": False})
        self.assertEqual(self.a24(5012, VIEJO, T0 + 15)["n"], 12)
        self.assertEqual(self.a24(70, None, T0, pid="p002"), {"n": 0, "desde": T0, "completo": False})

    def test_incrementos_van_al_cubo_de_su_muestra(self):
        """Capacidad nueva: lo que sube el contador entre dos muestras va al cubo de 5 min de la
        muestra; sin alertas nuevas no cambia nada."""
        self.a24(100, VIEJO, T0)
        self.assertEqual(self.a24(103, VIEJO, T0 + 15)["n"], 3)
        self.assertEqual(self.a24(103, VIEJO, T0 + 30)["n"], 3)
        self.assertEqual(self.a24(110, VIEJO, T0 + 400)["n"], 10)
        self.assertEqual(self.cubos(), {T0: 3, T0 + 300: 7})

    def test_reinicio_cuenta_la_instancia_nueva(self):
        """Capacidad nueva: al reiniciarse Suricata el contador vuelve a 0; lo de la instancia nueva
        se suma a lo ya contado (ni se resta ni se pierde)."""
        self.a24(1000, VIEJO, T0)
        self.a24(1004, VIEJO, T0 + 15)
        nuevo = T0 + 20
        self.assertEqual(self.a24(6, nuevo, T0 + 30)["n"], 10)      # `inicio` distinto y `cum` menor
        self.assertEqual(self.a24(9, nuevo, T0 + 45)["n"], 13)
        # sin `inicio` con que comparar, un contador que baja también es un reinicio
        self.assertEqual(self.a24(2, None, T0 + 60)["n"], 15)
        # la instancia nueva ya pasó del contador de la vieja: cuenta entero, no la diferencia
        self.a24(5, VIEJO, T0, pid="p002")
        self.assertEqual(self.a24(8, T0 + 5, T0 + 15, pid="p002")["n"], 8)

    def test_lectura_atrasada_no_cuenta_dos_veces(self):
        """Corrección de defecto evitado: estado.json se arma desde varios hilos (supervisión,
        trabajador, punto.estado) y uno puede llegar con una lectura anterior a la última ya
        contada. Con el mismo `inicio` el contador de un Suricata no baja: una muestra menor, o de
        un instante anterior, se ignora en lugar de tomarse por un reinicio y sumar todo otra vez."""
        self.a24(1000, VIEJO, T0)
        self.a24(1010, VIEJO, T0 + 15)
        self.assertEqual(self.a24(1005, VIEJO, T0 + 15)["n"], 10)          # misma instancia, menor
        self.assertEqual(self.a24(1008, T0 - 5, T0 + 10)["n"], 10)         # anterior a la última
        self.assertEqual(self.orq._alertas()["p001"]["ult"], 1010)
        self.assertEqual(self.a24(1020, VIEJO, T0 + 30)["n"], 20)

    def test_inicio_desconocido_no_es_reinicio(self):
        """Corrección de defecto evitado: si docker inspect no da el arranque (contenedor quitado o
        fallo puntual), `inicio` None no se toma por un reinicio: con el mismo contador no suma
        nada y, al volver el `inicio` de siempre, sigue contando solo lo que subió."""
        self.a24(500, VIEJO, T0)
        self.assertEqual(self.a24(500, None, T0 + 15)["n"], 0)
        self.assertEqual(self.orq._alertas()["p001"]["inicio"], VIEJO)
        self.assertEqual(self.a24(507, VIEJO, T0 + 30)["n"], 7)

    def test_hueco_de_mas_de_24_h_vuelve_a_empezar(self):
        """Capacidad nueva: con el orquestador parado más de un día no se sabe cuándo fue lo que
        subió el contador: se descarta, se vacían los cubos y se cuenta desde ese momento."""
        self.a24(100, VIEJO, T0)
        self.a24(110, VIEJO, T0 + 15)
        t = T0 + 15 + DIA + 1
        self.assertEqual(self.a24(500, VIEJO, t), {"n": 0, "desde": t, "completo": False})
        self.assertEqual(self.cubos(), {})
        self.assertEqual(self.a24(505, VIEJO, t + 15)["n"], 5)

    def test_lo_de_hace_mas_de_24_h_sale_del_recuento(self):
        """Capacidad nueva: la ventana corre. A las 24 h el recuento pasa a completo; 5 min después
        el primer cubo sale de `n` y, pasado su margen, se poda del estado."""
        inicio = T0 - 3600
        self.a24(130, inicio, T0)                                          # 13 cubos de 10
        self.assertEqual(self.a24(130, inicio, inicio + DIA - 1),
                         {"n": 130, "desde": inicio, "completo": False})
        self.assertEqual(self.a24(130, inicio, inicio + DIA),
                         {"n": 130, "desde": inicio, "completo": True})
        self.assertEqual(self.a24(130, inicio, inicio + DIA + CUBO)["n"], 120)
        self.assertIn(inicio, self.cubos())
        # un segundo después también el cubo siguiente empieza antes del corte (aprox. de 5 min)
        self.assertEqual(self.a24(130, inicio, inicio + DIA + CUBO + 1)["n"], 110)
        self.assertNotIn(inicio, self.cubos())

    def test_sin_stats_no_toca_nada(self):
        """Conservación: sin stats (`cum` None) no se inventa nada: sin estado, n = None; con estado
        se da lo que hay y la base no se mueve."""
        self.assertEqual(self.a24(None, T0 - 60, T0), {"n": None, "desde": None, "completo": False})
        self.assertNotIn("p001", self.orq._alertas())
        self.a24(100, VIEJO, T0)
        self.a24(104, VIEJO, T0 + 15)
        antes = copy.deepcopy(self.orq._alertas()["p001"])
        self.assertEqual(self.a24(None, None, T0 + 30), {"n": 4, "desde": T0, "completo": False})
        self.assertEqual(self.orq._alertas()["p001"], antes)


class Persistencia(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()
        self.fichero = self.e.ruta("/srv/ids/estado/alertas.json")

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def leer(self):
        return json.loads(self.fichero.read_text(encoding="utf-8"))

    def test_otro_orquestador_lo_relee(self):
        """Capacidad nueva: alertas.json (0600) sobrevive a un reinicio del servicio: otro
        Orquestador sigue desde la misma base y no reparte otra vez lo ya contado."""
        inicio = T0 - 3600
        self.orq._alertas_24h("p001", 130, inicio, T0)
        self.assertTrue(self.fichero.exists())
        if sys.platform.startswith("linux"):
            self.assertEqual(self.fichero.stat().st_mode & 0o777, 0o600)
        otro = self.mod.Orquestador()
        try:
            self.assertEqual(otro._alertas_24h("p001", None, inicio, T0 + 15),
                             {"n": 130, "desde": inicio, "completo": False})
            self.assertEqual(otro._alertas_24h("p001", 135, inicio, T0 + 30)["n"], 135)
        finally:
            otro.db.close()

    def test_se_guarda_como_mucho_cada_minuto(self):
        """Capacidad nueva: con estado.json cada 15 s, alertas.json se reescribe como mucho una vez
        por minuto (la primera muestra, al momento)."""
        self.orq._alertas_24h("p001", 100, VIEJO, T0)
        self.assertEqual(self.leer()["p001"]["ult"], 100)
        self.orq._alertas_24h("p001", 105, VIEJO, T0 + 15)
        self.orq._alertas_24h("p001", 108, VIEJO, T0 + 45)
        self.assertEqual(self.leer()["p001"]["ult"], 100)
        self.orq._alertas_24h("p001", 110, VIEJO, T0 + 60)
        self.assertEqual(self.leer(), {"p001": {"inicio": VIEJO, "ult": 110, "ts": T0 + 60, "desde": T0,
                                                "cubos": {str(T0): 10}}})

    def test_fichero_corrupto_vuelve_a_empezar(self):
        """Corrección de defecto evitado: un alertas.json roto, o con entradas de otra forma, no
        tumba estado.json: esos puntos vuelven a empezar como en su primera muestra y el fichero
        se rehace."""
        self.fichero.parent.mkdir(parents=True, exist_ok=True)
        self.fichero.write_text("{no es json", encoding="utf-8")
        self.assertEqual(self.orq._alertas_24h("p001", 50, VIEJO, T0), {"n": 0, "desde": T0, "completo": False})
        self.assertEqual(self.leer()["p001"]["ult"], 50)
        bueno = {"inicio": None, "ult": 7, "ts": T0, "desde": T0, "cubos": {str(T0): 3}}
        self.fichero.write_text(json.dumps({"p001": {"ult": "x"}, "p002": [1], "p003": bueno,
                                            "../x": bueno, "p004": dict(bueno, cubos={"a": 1})}),
                                encoding="utf-8")
        otro = self.mod.Orquestador()
        try:
            self.assertEqual(set(otro._alertas()), {"p003"})
            self.assertEqual(otro._alertas_24h("p003", None, None, T0 + 15)["n"], 3)
        finally:
            otro.db.close()
        self.fichero.write_text("[1, 2]", encoding="utf-8")
        otro = self.mod.Orquestador()
        try:
            self.assertEqual(otro._alertas(), {})
        finally:
            otro.db.close()


class EstadoJson(unittest.TestCase):
    """De stats.json a estado.json, con un punto del sistema simulado."""

    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()
        A.crear(self, self.orq, {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]})
        self.inicio = self.mod.docker_inspect(["ids-p001-suricata"])["ids-p001-suricata"]["inicio"]
        self.assertIsInstance(self.inicio, int)
        self.datos = self.e.ruta("/srv/ids/datos/p001")
        self.datos.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def estado(self, t):
        self.mod.ahora = lambda: t
        return self.orq.escribir_estado()["puntos"]["p001"]

    def test_estado_json_lleva_el_recuento(self):
        """Capacidad nueva: estado.json publica `suricata.alertas` (contador del Suricata vivo) y
        `alertas_24h`; con el Suricata arrancado hace 1 h, todo su contador cae en las 24 h."""
        t = self.inicio + 3600
        escribir(self.datos / "stats.json", stats(t - 40, 100), stats(t - 10, 120))
        p = self.estado(t)
        self.assertEqual(p["suricata"]["alertas"], 120)
        self.assertEqual(p["alertas_24h"], {"n": 120, "desde": self.inicio, "completo": False})
        escribir(self.datos / "stats.json", stats(t + 20, 131))
        self.assertEqual(self.estado(t + 30)["alertas_24h"]["n"], 131)
        disco = json.loads(self.e.ruta("/srv/ids/run/estado.json").read_text(encoding="utf-8"))
        self.assertEqual(disco["puntos"]["p001"]["alertas_24h"], {"n": 131, "desde": self.inicio,
                                                                  "completo": False})

    def test_stats_del_suricata_anterior_no_cuentan(self):
        """Corrección de defecto evitado: tras un reinicio, stats.json guarda unos minutos el último
        stats del Suricata anterior (hasta el primero del nuevo, que carga reglas). Ese contador no
        es de la instancia viva: no se cuenta; si no, todo lo de la vieja se sumaría otra vez como
        si fuera de la nueva."""
        t = self.inicio + 600
        escribir(self.datos / "stats.json", stats(self.inicio - 30, 999))
        p = self.estado(t)
        self.assertEqual(p["suricata"]["alertas"], 999)
        self.assertEqual(p["alertas_24h"], {"n": None, "desde": None, "completo": False})
        escribir(self.datos / "stats.json", stats(self.inicio - 30, 999), stats(t + 5, 4))
        self.assertEqual(self.estado(t + 15)["alertas_24h"], {"n": 4, "desde": self.inicio, "completo": False})

    def test_error_al_guardar_no_rompe_estado_json(self):
        """Corrección de defecto evitado: si alertas.json no se puede escribir (disco lleno),
        estado.json se escribe igual con el recuento en memoria y el fallo queda en el registro."""
        original = self.mod.escribir_atomico
        mensajes = []

        def falla(path, *a, **k):
            if Path(path).name == "alertas.json":
                raise OSError(28, "No space left on device")
            return original(path, *a, **k)

        self.mod.escribir_atomico = falla
        self.mod.log = mensajes.append
        t = self.inicio + 3600
        escribir(self.datos / "stats.json", stats(t - 10, 120))
        self.assertEqual(self.estado(t)["alertas_24h"]["n"], 120)
        self.assertFalse(self.e.ruta("/srv/ids/estado/alertas.json").exists())
        disco = json.loads(self.e.ruta("/srv/ids/run/estado.json").read_text(encoding="utf-8"))
        self.assertEqual(disco["puntos"]["p001"]["alertas_24h"]["n"], 120)
        self.assertTrue([m for m in mensajes if "alertas.json" in m], mensajes)

    def test_baja_quita_su_entrada(self):
        """Conservación de la baja total (DATOS §8): alertas.json no guarda puntos que ya no
        existen; al dar de baja un punto su entrada desaparece del fichero."""
        fichero = self.e.ruta("/srv/ids/estado/alertas.json")
        self.orq._alertas_24h("p001", 10, None, T0)
        self.orq._alertas_24h("p007", 10, None, T0)          # punto que ya no existe
        self.orq.construir_estado()
        self.assertEqual(set(json.loads(fichero.read_text(encoding="utf-8"))), {"p001"})
        r = A.ejecutar_orden(self.orq, "punto.borrar", {"pid": "p001", "confirmar": "norte"})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertEqual(json.loads(fichero.read_text(encoding="utf-8")), {})


class Lectura(unittest.TestCase):
    def setUp(self):
        self.mod = A.cargar_orq()
        self.e = A.Entorno()
        self.addCleanup(self.e.cerrar)
        self.datos = self.e.ruta("/srv/ids/datos/p001")
        self.datos.mkdir(parents=True)

    def test_ultimo_stats_lee_detect_alert(self):
        """Capacidad nueva: el stats de Suricata 7 trae `detect.alert` (alertas desde que arrancó
        ese Suricata) y sale como `alertas`; si falta o no es un número no negativo, None."""
        self.assertIsNone(self.mod.STATS_VACIO["alertas"])
        self.assertIsNone(self.mod.leer_stats_punto(self.datos, T0)["alertas"])
        escribir(self.datos / "stats.json", stats(T0 - 40, 40), stats(T0 - 10, 42))
        st = self.mod.leer_stats_punto(self.datos, T0)
        self.assertEqual((st["alertas"], st["kernel_packets"], st["reglas_cargadas"]), (42, 10, 18234))
        for raro in (_FALTA, None, "42", True, -1, float("nan"), float("inf"), {"n": 1}):
            escribir(self.datos / "stats.json", stats(T0 - 10, raro))
            self.assertIsNone(self.mod.leer_stats_punto(self.datos, T0)["alertas"], repr(raro))

    def test_cola_del_eve_tambien(self):
        """Conservación: un punto con el yaml de antes (sin stats.json) también da `alertas` desde
        la cola del eve."""
        escribir(self.datos / "eve.json", '{"event_type":"alert"}', stats(T0 - 5, 17))
        self.assertEqual(self.mod.leer_stats_punto(self.datos, T0)["alertas"], 17)


if __name__ == "__main__":
    unittest.main()
