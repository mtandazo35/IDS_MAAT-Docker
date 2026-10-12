"""Retención de eventos por fecha (CONTRATO-F2 §9): poda diaria de lo que tiene más de 30 días, poda por
disco (< 15 % libre) de los rotados más viejos de cualquier punto con registro en orq.jsonl, y retención
efectiva publicada por punto en estado.json. Sistema simulado de _ayuda_orq; nada real."""

import gzip
import json
import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

DIA = 86400


def ts_suricata(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(epoch))


class Base(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(ncpu=8)
        A.crear(self, self.orq, {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]})
        A.crear(self, self.orq, {"nombre": "sur", "redes_abonados": ["10.0.0.0/24"]})
        self.t = int(time.time())

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def rotado(self, pid, nombre_base, rotado_hace_dias, primer_evento_hace_dias, gz=True):
        """Rotado con nombre fechado de logrotate (dateext) y su primer evento."""
        cuando = self.t - int(rotado_hace_dias * DIA)
        nombre = "%s-%s%s" % (nombre_base, time.strftime("%Y%m%d-%H%M%S", time.localtime(cuando)),
                              ".gz" if gz else "")
        f = self.e.ruta("/srv/ids/datos/%s/%s" % (pid, nombre))
        linea = json.dumps({"timestamp": ts_suricata(self.t - int(primer_evento_hace_dias * DIA)),
                            "event_type": "alert"}) + "\n"
        if gz:
            with gzip.open(f, "wb") as g:
                g.write((linea * 3).encode())
        else:
            f.write_text(linea * 3, encoding="utf-8")
        os.utime(f, (cuando, cuando))
        return f

    def vivo(self, pid, primer_evento_hace_dias):
        f = self.e.ruta("/srv/ids/datos/%s/eve.json" % pid)
        f.write_text(json.dumps({"timestamp": ts_suricata(self.t - int(primer_evento_hace_dias * DIA)),
                                 "event_type": "alert"}) + "\n", encoding="utf-8")
        return f

    def diario(self):
        p = self.e.ruta("/srv/ids/estado/orq.jsonl")
        if not p.exists():
            return []
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()]


class PorFecha(Base):
    def test_borra_solo_lo_de_mas_de_30_dias(self):
        """Capacidad nueva: un rotado se borra cuando hasta su último evento posible (la fecha de
        rotación) tiene más de 30 días; uno rotado hace 29 días con eventos de hace 40 se queda."""
        viejo = self.rotado("p001", "eve.json", 31, 32)
        limite = self.rotado("p001", "dns.json", 29, 40)
        nuevo = self.rotado("p002", "eve.json", 2, 3, gz=False)
        vivo = self.vivo("p001", 1)
        self.assertEqual(self.orq.podar_por_fecha(self.t), 1)
        self.assertFalse(viejo.exists())
        for f in (limite, nuevo, vivo):
            self.assertTrue(f.exists(), f.name)
        ev = [x for x in self.diario() if x.get("evento") == "poda.fecha"]
        self.assertEqual([(x["pid"], x["ficheros"]) for x in ev], [("p001", 1)])

    def test_rotacion_por_tamano_no_corta_dias(self):
        """Corrección de defecto: con `rotate 4` y rotación por tamaño, un punto con mucho tráfico
        perdía días a las pocas horas; ahora 40 rotados del mismo día se conservan todos."""
        for i in range(40):
            self.rotado("p001", "eve.json", 1 + i / 1000.0, 1 + i / 1000.0)
        self.assertEqual(self.orq.podar_por_fecha(self.t), 0)
        self.assertEqual(len(self.mod.rotados("p001")), 40)

    def test_logrotate_sin_tope_de_numero(self):
        """Capacidad nueva: el logrotate del host rota con nombre fechado (fecha y hora), sin
        `maxage` ni tope de número que corte días: la poda por fecha es del orquestador."""
        txt = (A.REPO / "host" / "logrotate" / "ids-maat.conf").read_text(encoding="utf-8")
        bloque = txt.split("}")[0]
        self.assertIn("    rotate -1\n", bloque)
        self.assertIn("    dateext\n", bloque)
        self.assertIn("    dateformat -%Y%m%d-%H%M%S\n", bloque)
        self.assertNotIn("maxage", bloque)
        # comprime el orquestador (conserva el mtime); logrotate no
        self.assertIn("    nocompress\n", bloque)
        self.assertNotIn("delaycompress", bloque)
        self.assertTrue(self.mod.RE_FECHA_ROTADO.match("eve.json-20261011-143000.gz"))


class PorDisco(Base):
    def test_borra_los_mas_viejos_de_cualquier_punto_y_lo_registra(self):
        """Capacidad nueva: por debajo del 15 % libre se borran primero los rotados más viejos de
        todos los puntos, uno a uno hasta recuperar el umbral; cada borrado queda en orq.jsonl y el
        punto afectado publica anticipado; el vivo nunca se toca."""
        a = self.rotado("p002", "eve.json", 10, 11)       # el más viejo de todos
        b = self.rotado("p001", "eve.json", 8, 9)
        c = self.rotado("p001", "eve.json", 3, 4)
        vivo = self.vivo("p001", 1)
        libres = iter([10, 12, 16])                        # 10 % -> borra a -> 12 % -> borra b -> 16 %
        borrados = self.orq.podar_por_disco(self.t, libre_fn=lambda: next(libres))
        self.assertEqual([(p, n) for p, n, _ in borrados], [("p002", a.name), ("p001", b.name)])
        self.assertFalse(a.exists() or b.exists())
        self.assertTrue(c.exists() and vivo.exists())
        ev = [x for x in self.diario() if x.get("evento") == "poda.disco"]
        self.assertEqual([(x["pid"], x["fichero"], x["libre_pct"]) for x in ev],
                         [("p002", a.name, 10), ("p001", b.name, 12)])
        est = self.orq.escribir_estado()
        for pid in ("p001", "p002"):
            r = est["puntos"][pid]["retencion"]
            self.assertTrue(r["anticipado"], pid)
            self.assertEqual(r["ultimo_anticipado"], self.t)
            self.assertIn("RETENCION-REDUCIDA", est["puntos"][pid]["avisos"])

    def test_con_disco_suficiente_no_borra(self):
        """Conservación: con el disco por encima del umbral no se borra nada antes de tiempo."""
        a = self.rotado("p001", "eve.json", 10, 11)
        self.assertEqual(self.orq.podar_por_disco(self.t, libre_fn=lambda: 40), [])
        self.assertTrue(a.exists())
        self.assertFalse(self.orq.escribir_estado()["puntos"]["p001"]["retencion"]["anticipado"])

    def test_la_marca_persiste_tras_reiniciar_el_orquestador(self):
        """Capacidad nueva: tras un reinicio del servicio se sigue sin prometer 30 días."""
        self.rotado("p001", "eve.json", 10, 11)
        libres = iter([10, 20])
        self.orq.podar_por_disco(self.t, libre_fn=lambda: next(libres))
        otro = self.mod.Orquestador()
        try:
            self.assertTrue(otro.retencion_punto("p001", self.t)["anticipado"])
            self.assertFalse(otro.retencion_punto("p001", self.t + 31 * DIA)["anticipado"])
        finally:
            otro.db.close()


class Compresion(Base):
    def test_gz_conserva_mtime_contenido_y_modo(self):
        """Capacidad nueva (pedida por Eventos): el .gz de un rotado conserva el mtime del rotado
        (= su último evento), el contenido y el modo; el original desaparece y el vivo no se toca.
        logrotate/gzip ponían la hora de compresión, que rompía el salto de ficheros por fecha."""
        f = self.rotado("p001", "eve.json", 3, 4, gz=False)
        os.chmod(f, 0o640)
        antes = f.stat()
        contenido = f.read_bytes()
        vivo = self.vivo("p001", 1)
        mvivo = vivo.stat().st_mtime_ns
        hechos = self.mod.comprimir_rotados(["p001"], time.time())
        self.assertEqual([g.name for g in hechos], [f.name + ".gz"])
        g = hechos[0]
        self.assertFalse(f.exists())
        self.assertEqual(g.stat().st_mtime_ns, antes.st_mtime_ns)
        if sys.platform.startswith("linux"):
            self.assertEqual(g.stat().st_mode & 0o777, 0o640)
        with gzip.open(g, "rb") as h:
            self.assertEqual(h.read(), contenido)
        self.assertEqual(vivo.stat().st_mtime_ns, mvivo)
        self.assertEqual(self.mod.comprimir_rotados(["p001"], time.time()), [])    # idempotente

    def test_no_comprime_lo_que_aun_se_escribe(self):
        """Corrección de defecto evitado: un rotado escrito hace menos de 2 min (Suricata aún no
        reabrió) no se comprime; un .gz.tmp a medias no cuenta como dato ni se poda como tal."""
        f = self.rotado("p001", "dns.json", 0, 1, gz=False)
        os.utime(f, None)                                      # escrito ahora mismo
        self.assertEqual(self.mod.comprimir_rotados(["p001"], time.time()), [])
        self.assertTrue(f.exists())
        resto = self.e.ruta("/srv/ids/datos/p001/.eve.json-20261001-000000.gz.tmp")
        resto.write_bytes(b"\x1f\x8b a medias")
        self.assertNotIn(resto.name, [x.name for _, x in self.mod.rotados("p001")])
        # el glob del panel (nodos.ficheros_eventos: «eve.json*») no ve el temporal
        import glob
        vistos = glob.glob(str(self.e.ruta("/srv/ids/datos/p001")) + "/eve.json*")
        self.assertFalse([v for v in vistos if v.endswith(".tmp")], vistos)
        os.utime(resto, (time.time() - 7200, time.time() - 7200))
        self.mod.comprimir_rotados(["p001"], time.time())
        self.assertFalse(resto.exists())                       # resto viejo de una interrupción


class Efectiva(Base):
    def test_desde_el_primer_evento_que_queda(self):
        """Capacidad nueva: `desde` es el primer evento del fichero más viejo (también .gz), no la
        fecha de rotación; sin rotados, el primer evento del vivo."""
        self.vivo("p002", 2)
        self.assertEqual(self.orq.retencion_punto("p002", self.t)["desde"], self.t - 2 * DIA)
        self.rotado("p001", "dns.json", 5, 25)            # dns rota poco: guarda lo más viejo
        self.rotado("p001", "eve.json", 6, 7)
        r = self.orq.retencion_punto("p001", self.t)
        self.assertEqual((r["desde"], r["dias"], r["objetivo_dias"]), (self.t - 25 * DIA, 25.0, 30))

    def test_fichero_ilegible_no_promete_mas(self):
        """Corrección de defecto evitado: un .gz roto no se toma como «sin fecha = todo»; se usa la
        fecha del fichero, que nunca es anterior a sus eventos."""
        f = self.e.ruta("/srv/ids/datos/p001/eve.json-20261001-000000.gz")
        f.write_bytes(b"no es gzip")
        cuando = self.t - 4 * DIA
        os.utime(f, (cuando, cuando))
        self.assertGreaterEqual(self.orq.retencion_punto("p001", self.t)["desde"], cuando)

    def test_baja_borra_su_marca(self):
        """Conservación de la baja total (DATOS §8): la marca de retención del punto se borra."""
        self.rotado("p001", "eve.json", 10, 11)
        libres = iter([10, 20])
        self.orq.podar_por_disco(self.t, libre_fn=lambda: next(libres))
        r = A.ejecutar_orden(self.orq, "punto.borrar", {"pid": "p001", "confirmar": "norte"})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        guardado = json.loads(self.e.ruta("/srv/ids/estado/retencion.json").read_text(encoding="utf-8"))
        self.assertNotIn("p001", guardado)


if __name__ == "__main__":
    unittest.main()
