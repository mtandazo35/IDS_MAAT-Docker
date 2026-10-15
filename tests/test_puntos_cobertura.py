"""Ficha y lista de Puntos con espejo real (lab, p001, 2026-10-15):

- Cobertura de prefijos: el MikroTik espejaba 192.168.116-117.x y 172.16.32.x y los prefijos del
  punto eran otras redes 10.x. Suricata solo trata como abonados ($HOME_NET) los prefijos, asi
  que el punto salia sano y con 0 alertas para siempre, sin ningun aviso. Ahora la ficha dice que
  redes llegan fuera de los prefijos y ofrece añadirlas al cuadro de Prefijos (sin guardar).
- «Alertas 24 h»: el panel contaba los ultimos 8 MB del eve vivo (minutos con espejo real) y
  salia «0+». Manda el recuento del orquestador (`alertas_24h` en estado.json); sin el, el de
  antes con «+».

Tipo «corrección de defecto»: cada prueba falla sin el cambio, salvo las marcadas «conservación».
Panel de verdad sobre un directorio temporal y orquestador falso (fixtures/panel2/_dash_p.py).
"""
import json
import os
import re
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
from _dash_p import PanelP  # noqa: E402


def _ev(src, dst, tipo="tls"):
    return json.dumps({"timestamp": "2026-10-15T17:00:00.000000-0500", "event_type": tipo,
                       "src_ip": src, "dest_ip": dst, "dest_port": 443}, separators=(",", ":"))


class _Base(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")

    def cambiar(self, pid, **campos):
        ruta = os.path.join(self.p.tmp.name, "run", "estado.json")
        with open(ruta, encoding="utf-8") as f:
            est = json.load(f)
        est["puntos"][pid].update(campos)
        est["ts"] = int(time.time())
        with open(ruta, "w", encoding="utf-8", newline="\n") as f:
            json.dump(est, f)
        t = time.time() + len(json.dumps(campos))          # otra marca: nodos.leer_estado relee
        os.utime(ruta, (t, t))

    def eve(self, pid, lineas):
        with open(os.path.join(self.p.tmp.name, "datos", pid, "eve.json"), "w", encoding="utf-8",
                  newline="\n") as f:
            f.write("".join(l + "\n" for l in lineas))

    def get(self, ruta):
        r = self.p.pedir("GET", ruta, cookie=self.ana)
        self.assertEqual(r.status, 200, r.texto[:400])
        return r.texto

    def fila(self, texto, pid):
        m = re.search(r"<tr><td><a href='/puntos/%s'>.*?</tr>" % pid, texto, re.S)
        self.assertIsNotNone(m, pid)
        return m.group(0)


class Cobertura(_Base):
    def test_todo_fuera_de_los_prefijos(self):
        """Prefijos 10.0.0.0/24 y espejo de 192.168.117.x: 100 % fuera, se sugiere la /24. Lo
        publico (destinos) no cuenta y la red del tunel tampoco."""
        self.cambiar("p001", tun_net="100.64.1.0/24")
        lineas = [_ev("192.168.117.%d" % (i % 50 + 2), "203.0.113.%d" % (i % 9 + 1)) for i in range(300)]
        lineas += [_ev("100.64.1.2", "100.64.1.1")] * 100            # el MikroTik por el tunel
        self.eve("p001", lineas)
        c = self.p.pw.cobertura_prefijos("p001")
        self.assertEqual(c["muestra"], 300)
        self.assertEqual(c["dentro"], 0)
        self.assertEqual(c["pct_fuera"], 100.0)
        self.assertEqual(c["fuera"], [("192.168.117.0/24", 300)])
        self.assertEqual(c["sugeridas"], ["192.168.117.0/24"])
        self.assertEqual(self.p.pw.fuera_de_prefijos(c), "100 % del tráfico espejado fuera de los prefijos")

    def test_mezcla_sugiere_solo_las_redes_con_peso(self):
        """70 % dentro, 30 % en 172.16.33.x y una IP suelta de 10.20.60.x (menos del 1 %): aviso,
        172.16.33.0/24 sugerida; 10.20.60.0/24 se lista pero no se sugiere. CGNAT cuenta."""
        lineas = [_ev("10.0.0.%d" % (i % 200 + 1), "198.51.100.4") for i in range(700)]
        lineas += [_ev("172.16.33.%d" % (i % 90 + 2), "198.51.100.4") for i in range(250)]
        lineas += [_ev("100.70.0.9", "198.51.100.4")] * 47
        lineas += [_ev("10.20.60.5", "198.51.100.4")] * 3
        self.eve("p001", lineas)
        c = self.p.pw.cobertura_prefijos("p001")
        self.assertEqual(c["muestra"], 1000)
        self.assertEqual(c["dentro"], 700)
        self.assertEqual(c["pct_fuera"], 30.0)
        self.assertEqual(c["sugeridas"], ["172.16.33.0/24", "100.70.0.0/24"])
        self.assertIn(("10.20.60.0/24", 3), c["fuera"])
        # en el aviso, la red suelta no sale como «1 %»: va junta con las demás de menos del 1 %
        h = self.p.pw.cobertura_html(c)
        self.assertIn("<b>172.16.33.0/24</b> (25 %), <b>100.70.0.0/24</b> (5 %) y 1 red con menos del 1 % "
                      "cada una. El Suricata", h)
        self.assertNotIn("10.20.60.0/24", h)

    def test_poco_fuera_o_poca_muestra_no_avisa(self):
        """Conservación: 10 % fuera no avisa; menos de COB_MIN_MUESTRA IPs, None."""
        self.eve("p001", [_ev("10.0.0.5", "198.51.100.4")] * 270 + [_ev("192.168.1.5", "198.51.100.4")] * 30)
        c = self.p.pw.cobertura_prefijos("p001")
        self.assertEqual(c["pct_fuera"], 10.0)
        self.assertEqual(self.p.pw.cobertura_html(c), "")
        self.assertEqual(self.p.pw.fuera_de_prefijos(c), "")
        self.eve("p002", [_ev("192.168.1.5", "198.51.100.4")] * 50)
        self.assertIsNone(self.p.pw.cobertura_prefijos("p002"))

    def test_sin_eve_none(self):
        """Conservación: sin eve.json no se opina."""
        self.assertIsNone(self.p.pw.cobertura_prefijos("p002"))

    def test_ficha_avisa_y_ofrece_añadir(self):
        """La ficha de p001 lleva el aviso ámbar con la red y el boton que la añade al cuadro de
        Prefijos (data-redes; no guarda nada por si solo)."""
        self.eve("p001", [_ev("192.168.116.%d" % (i % 40 + 2), "203.0.113.5") for i in range(250)])
        t = self.get("/puntos/p001")
        m = re.search(r"<div class='aviso amb'><b>Nada del tráfico que llega por el espejo.*?</div></div>", t, re.S)
        self.assertIsNotNone(m, "falta el aviso de cobertura")
        self.assertIn("<b>192.168.116.0/24</b> (100 %)", m.group(0))
        self.assertIn("data-redes='192.168.116.0/24'", m.group(0))
        self.assertIn("Añadir estas redes a los prefijos", m.group(0))
        self.assertIn("textarea[name=redes]", m.group(0))
        # el aviso va dentro del Resumen, antes de la salud por etapas
        self.assertLess(t.index("Nada del tráfico"), t.index("Salud por etapas"))
        self.assertGreater(t.index("Nada del tráfico"), t.index("id=resumen"))

    def test_ficha_sin_aviso_si_todo_dentro(self):
        """Conservación: todo el espejo dentro de los prefijos, ningun aviso de cobertura."""
        self.eve("p001", [_ev("10.0.0.%d" % (i % 200 + 1), "203.0.113.5") for i in range(250)])
        t = self.get("/puntos/p001")
        self.assertNotIn("Añadir estas redes", t)
        self.assertNotIn("fuera de los prefijos", t)

    def test_salud_degradada_con_el_espejo_fuera(self):
        """p001 con todas las etapas bien pero el espejo de otras redes: antes «operativa» (y 0
        alertas); ahora «degradada» con el motivo, en la ficha y en la lista."""
        self.eve("p001", [_ev("192.168.117.%d" % (i % 40 + 2), "203.0.113.5") for i in range(250)])
        s = self.p.d.salud_punto("p001")
        self.assertTrue(all(e["ok"] for e in s["etapas"]), s["etapas"])
        self.assertEqual(s["estado"], "degradada")
        self.assertEqual(s["motivo"], "100 % del tráfico espejado fuera de los prefijos")
        self.assertIn("100 % del tráfico espejado fuera de los prefijos", self.fila(self.get("/puntos"), "p001"))

    def test_salud_operativa_con_el_espejo_dentro(self):
        """Conservación: espejo dentro de los prefijos y todo bien, «operativa»."""
        self.eve("p001", [_ev("10.0.0.%d" % (i % 200 + 1), "203.0.113.5") for i in range(250)])
        s = self.p.d.salud_punto("p001")
        self.assertEqual((s["estado"], s["motivo"]), ("operativa", "todas las etapas al día"))


class Alertas24h(_Base):
    def test_recuento_del_orquestador_completo(self):
        """Con `alertas_24h` completo en estado.json, la ficha y la lista dicen ese numero, sin
        «+», y el total de arriba lo suma."""
        self.cambiar("p001", alertas_24h={"n": 12345, "desde": int(time.time()) - 90000, "completo": True})
        ficha = self.get("/puntos/p001")
        self.assertIn("<a href='/eventos?nodo=p001'>12.345</a>", ficha)
        lista = self.get("/puntos")
        self.assertIn("<td class=num>12.345</td>", self.fila(lista, "p001"))
        self.assertRegex(lista, r"Alertas 24 h</div><div[^>]*>12\.345</div>")

    def test_recuento_sin_24h_dice_desde_cuando(self):
        """El orquestador lleva una hora contando: «N desde las HH:MM», sin «+»."""
        desde = int(time.time()) - 3600
        self.cambiar("p001", alertas_24h={"n": 7, "desde": desde, "completo": False})
        hhmm = time.strftime("%H:%M", time.localtime(desde))
        if time.strftime("%Y-%m-%d", time.localtime(desde)) == time.strftime("%Y-%m-%d"):
            esperado = "7 <span class=hint>desde las %s</span>" % hhmm
        else:
            esperado = "7 <span class=hint>desde el %s %s</span>" % (time.strftime("%d/%m", time.localtime(desde)), hhmm)
        self.assertIn("<a href='/eventos?nodo=p001'>%s</a>" % esperado, self.get("/puntos/p001"))
        self.assertIn("<td class=num>%s</td>" % esperado, self.fila(self.get("/puntos"), "p001"))

    def test_sin_recuento_del_orquestador_el_de_antes(self):
        """Conservación: orquestador de antes (sin `alertas_24h`) o con un valor que no es un
        entero >= 0: el recuento de la cola del eve, como siempre."""
        ahora = time.strftime("%Y-%m-%dT%H:%M:%S.000000%z")
        self.eve("p001", [json.dumps({"timestamp": ahora, "event_type": "alert", "src_ip": "10.0.0.5",
                                      "dest_ip": "203.0.113.5"}, separators=(",", ":"))] * 3)
        self.assertEqual(self.p.pw.alertas_24h("p001"), (3, True))
        for malo in ({"n": True}, {"n": -1}, {"n": "9"}, "9", None):
            self.p.pw._ALERTAS.clear()
            self.cambiar("p001", alertas_24h=malo)
            self.assertIsNone(self.p.pw.alertas_24h_orq(self.p.nodos.punto("p001")), malo)
            self.assertEqual(self.p.pw.alertas_24h_html("p001")[1], 3, malo)


if __name__ == "__main__":
    unittest.main()
