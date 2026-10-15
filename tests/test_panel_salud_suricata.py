"""Salud del punto con el Suricata caído y avisos de Telegram de un punto que «espera» al MikroTik.

- A2 (MEDIA, revisión final, regresión): con la VPN sana y sin MikroTik, un Suricata `exited`,
  `unhealthy` o `restarting` daba el estado global «esperando» (ámbar), como si fuera lo normal
  tras un alta. Ahora es rojo («con error») con el detalle del contenedor, esté o no el MikroTik.
- B2 (MEDIA): `mk_visto` salía solo del sensor.json anterior; uno de formato viejo (sin la clave),
  ilegible o perdido con el router caído en el primer ciclo dejaba el punto «esperando al
  MikroTik» para siempre y Telegram no volvía a avisar. Formato viejo o ilegible = ya visto; sin
  fichero vale la evidencia del tráfico.

Panel real de `fixtures/panel2/_dash_p.py` (p001 sano y con espejo, p002 con la VPN sana y el
MikroTik sin conectar). Datos RFC 5737 / 10.x.
"""
import json
import os
import sys
import time
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, "fixtures", "panel2"))
from _dash_p import PanelP  # noqa: E402


class _Base(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d
        self._tick = 0

    def suricata(self, pid, estado, salud):
        """Cambia el contenedor suricata de `pid` en estado.json (y su mtime, que es la cache)."""
        ruta = os.path.join(self.p.tmp.name, "run", "estado.json")
        with open(ruta, encoding="utf-8") as f:
            est = json.load(f)
        est["puntos"][pid]["contenedores"] = dict(est["puntos"][pid]["contenedores"],
                                                  suricata={"estado": estado, "salud": salud})
        est["ts"] = int(time.time())
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(est, f)
        self._tick += 1
        t = time.time() + self._tick
        os.utime(ruta, (t, t))


class SuricataCaidoEsRojo(_Base):
    def test_sin_mikrotik_y_suricata_caido_es_rojo(self):
        """Corrección de defecto (A2): p002 con la VPN sana esperando al MikroTik y el Suricata
        exited / unhealthy / restarting: antes «esperando» (ámbar); ahora «error» (rojo) con el
        estado del contenedor en el motivo y la etapa Suricata en fallo."""
        self.assertEqual(self.d.salud_punto("p002")["estado"], "esperando")      # el punto de partida
        for estado, salud in (("exited", "none"), ("running", "unhealthy"), ("restarting", "starting")):
            with self.subTest(estado=estado, salud=salud):
                self.suricata("p002", estado, salud)
                s = self.d.salud_punto("p002")
                self.assertEqual(s["estado"], "error", s["motivo"])
                self.assertIn("Suricata", s["motivo"])
                self.assertIn(estado, s["motivo"])
                self.assertEqual(s["etapas_por_id"]["suricata"]["estado"], "fallo")
                self.assertEqual(self.p.pw.SALUD_COLOR[s["estado"]], "#c0392b")

    def test_con_mikrotik_y_suricata_caido_es_rojo(self):
        """Corrección de defecto (A2): con el MikroTik conectado y los últimos contadores aún >0, un
        Suricata parado salía «degradada» (naranja). Ahora también rojo."""
        self.suricata("p001", "exited", "none")
        s = self.d.salud_punto("p001")
        self.assertEqual(s["estado"], "error", s["motivo"])
        self.assertIn("exited", s["motivo"])

    def test_suricata_arrancando_sigue_esperando(self):
        """Regresión (A2): un Suricata en marcha con el healthcheck en `starting` no es un fallo:
        p002 sigue «esperando» al MikroTik."""
        self.suricata("p002", "running", "starting")
        self.assertEqual(self.d.salud_punto("p002")["estado"], "esperando")


class TelegramMkVisto(_Base):
    def setUp(self):
        super().setUp()
        self.avisos = []
        self.d.enviar_telegram = lambda t: self.avisos.append(t) or True
        self.sen = self.p.nodos.salida("sensor.json", "p002")
        os.makedirs(os.path.dirname(self.sen), exist_ok=True)

    def _de_sur(self):
        return [x for x in self.avisos if "sur" in x]

    def test_sensor_json_de_formato_viejo_avisa(self):
        """Corrección de defecto (B2): un sensor.json de antes de la marca (sin `mk_visto`) y el
        router sin conectar: antes «esperando al MikroTik» para siempre, sin aviso. Ahora cuenta
        como ya visto y avisa."""
        with open(self.sen, "w", encoding="utf-8") as f:
            json.dump({"ts": int(time.time()) - 300, "pid": "p002", "nivel": "ok", "alert_estado": "ok"}, f)
        o = self.d.medir_sensor("p002")
        self.assertTrue(o["mk_visto"])
        self.assertFalse(o.get("esperando_mk"))
        self.assertTrue(self._de_sur(), o.get("titulo"))

    def test_sensor_json_ilegible_avisa(self):
        """Corrección de defecto (B2): un sensor.json que no se puede leer (cortado) tampoco
        silencia los avisos."""
        with open(self.sen, "w", encoding="utf-8") as f:
            f.write('{"ts": 17')
        o = self.d.medir_sensor("p002")
        self.assertTrue(o["mk_visto"])
        time.sleep(0.05)
        o = self.d.medir_sensor("p002")         # la tasa sale de dos medidas: ahora «sin tráfico»
        self.assertTrue(o["mk_visto"])
        self.assertTrue(self._de_sur(), o.get("titulo"))

    def test_sin_fichero_el_trafico_que_hubo_cuenta(self):
        """Corrección de defecto (B2): sin sensor.json (perdido) pero con paquetes contados por el
        Suricata del punto (solo llegan por el espejo del MikroTik), el MikroTik ya se vio."""
        ruta = os.path.join(self.p.tmp.name, "run", "estado.json")
        with open(ruta, encoding="utf-8") as f:
            est = json.load(f)
        est["puntos"]["p002"]["suricata"]["kernel_packets"] = 5000
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(est, f)
        t = time.time() + 5
        os.utime(ruta, (t, t))
        o = self.d.medir_sensor("p002")
        self.assertTrue(o["mk_visto"])

    def test_punto_nuevo_sin_trafico_sigue_sin_avisar(self):
        """Regresión (B2): un punto recién creado (sin fichero ni tráfico) sigue esperando al
        MikroTik sin avisar por Telegram."""
        o = self.d.medir_sensor("p002")
        self.assertFalse(o["mk_visto"])
        self.assertTrue(o.get("esperando_mk"))
        self.assertEqual(self._de_sur(), [])

    def test_suricata_caido_avisa_aunque_espere_al_mikrotik(self):
        """Capacidad nueva (A2/B2): con el Suricata del punto parado no se calla el aviso aunque el
        MikroTik no haya conectado nunca (la salud lo da en rojo)."""
        self.suricata("p002", "exited", "none")
        o = self.d.medir_sensor("p002")
        self.assertFalse(o.get("esperando_mk"))
        self.assertTrue(self._de_sur(), o.get("titulo"))


if __name__ == "__main__":
    unittest.main()
