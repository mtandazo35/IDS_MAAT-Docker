"""El orquestador nunca pisa un rotado comprimido que ya existe (CONTRATO-F2 §9 y §10.5).

logrotate (`dateext`, `dateformat -%Y%m%d-%H%M%S`) pone a los rotados la hora LOCAL del host. Si el
reloj de pared retrocede (el instalador pasa el host de UTC a America/Guayaquil: 5 h atrás), durante
ese rato se repiten nombres de rotados. `comprimir_rotado` terminaba con `os.replace(tmp, destino)`:
con un `eve.json-AAAAMMDD-HHMMSS.gz` ya existente lo sobrescribía y se perdían sus eventos (unos
30 min: logrotate rota en cada pasada del timer). Ahora el nuevo va al primer nombre libre (`-2.gz`,
`-3.gz`…) con `os.link`, que falla si el nombre existe; la poda, la retención y Eventos del panel
reconocen ese nombre.

Sistema simulado de _ayuda_orq; nada real. En Windows no se pueden crear symlinks: el enlace
plantado es un enlace duro (como en test_f3_orq_contenedor) y la carrera con symlink corre en Linux.
"""
import gzip
import json
import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402
from test_eventos_busqueda import T0, alerta  # noqa: E402
from test_eventos_busqueda import Base as BaseEventos  # noqa: E402
from test_f3_orq_contenedor import HAY_SYMLINKS, enlazar  # noqa: E402

DIA = 86400
NOMBRE = "eve.json-20261015-120023"            # el nombre de rotado que logrotate repite


def ts_suricata(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(epoch))


def nombre_fechado(base, epoch):
    """El nombre que pone logrotate (dateext, hora local del host) a un rotado de ese instante."""
    return "%s-%s" % (base, time.strftime("%Y%m%d-%H%M%S", time.localtime(epoch)))


def leer_gz(f):
    with gzip.open(f, "rb") as g:
        return g.read()


class Base(unittest.TestCase):
    def setUp(self):
        self.mod = A.cargar_orq()
        self.e = A.Entorno()
        self.addCleanup(self.e.cerrar)
        self.datos = self.e.ruta("/srv/ids/datos/p001")
        self.datos.mkdir(parents=True)

    def rotado(self, texto, nombre=NOMBRE, hace_s=3 * 3600):
        """Lo que deja logrotate: el rotado sin comprimir, sin escribirse desde hace `hace_s`."""
        f = self.datos / nombre
        f.write_bytes(texto)
        t = int(time.time()) - hace_s
        os.utime(f, (t, t))
        return f

    def gz(self, nombre, texto, hace_s):
        """Un .gz que ya estaba en datos/p001 (comprimido en una pasada anterior)."""
        f = self.datos / nombre
        f.write_bytes(gzip.compress(texto))
        t = int(time.time()) - hace_s
        os.utime(f, (t, t))
        return f

    def victima(self):
        """Un fichero del host fuera de lo que monta el contenedor."""
        fw = self.e.ruta("/srv/ids/fw")
        fw.mkdir(parents=True)
        v = fw / "ids_host.nft"
        v.write_text("table inet ids_host { reglas del host }\n", encoding="utf-8")
        return v

    def nombres(self):
        return sorted(x.name for x in self.datos.iterdir())


class NoPisa(Base):
    def test_gz_existente_se_conserva_y_el_nuevo_lleva_sufijo(self):
        """Tipo: corrección de defecto. Ya hay `eve.json-…-120023.gz` (eventos de antes del cambio
        de hora) y logrotate deja otro rotado con el mismo nombre: el nuevo se guarda como
        `…-120023-2.gz` y el de antes queda intacto (mismos bytes y mismo mtime). Antes: os.replace
        lo sobrescribía y sus eventos se perdían."""
        viejo = self.gz(NOMBRE + ".gz", b'{"de":"antes del cambio de hora"}\n', 5 * 3600)
        antes = (viejo.read_bytes(), viejo.stat().st_mtime_ns)
        rot = self.rotado(b'{"de":"despues del cambio de hora"}\n')
        mt = rot.stat().st_mtime_ns
        hechos = self.mod.comprimir_rotados(["p001"], time.time())
        self.assertEqual([h.name for h in hechos], [NOMBRE + "-2.gz"])
        self.assertEqual((viejo.read_bytes(), viejo.stat().st_mtime_ns), antes)
        self.assertEqual(leer_gz(hechos[0]), b'{"de":"despues del cambio de hora"}\n')
        self.assertEqual(hechos[0].stat().st_mtime_ns, mt)           # su mtime, como siempre
        self.assertEqual(self.nombres(), [NOMBRE + "-2.gz", NOMBRE + ".gz"])   # sin rotado ni .tmp
        self.assertEqual(self.mod.comprimir_rotados(["p001"], time.time()), [])  # no se recomprime

    def test_mismo_nombre_tres_veces_no_se_pierde_ninguno(self):
        """Tipo: corrección de defecto. El mismo nombre de rotado tres veces (el reloj retrocede
        más de una vez): quedan `.gz`, `-2.gz` y `-3.gz`, cada uno con sus eventos."""
        esperado = {}
        for i, sufijo in enumerate((".gz", "-2.gz", "-3.gz")):
            texto = ('{"tanda":%d}\n' % i).encode()
            self.rotado(texto)
            hechos = self.mod.comprimir_rotados(["p001"], time.time())
            self.assertEqual([h.name for h in hechos], [NOMBRE + sufijo])
            esperado[NOMBRE + sufijo] = texto
        self.assertEqual(self.nombres(), sorted(esperado))
        for nombre, texto in esperado.items():
            self.assertEqual(leer_gz(self.datos / nombre), texto, nombre)

    def test_sin_nombre_libre_no_se_pisa_ni_se_borra_el_rotado(self):
        """Tipo: corrección de defecto. Si ya existen todos los nombres posibles (aquí el tope
        MAX_SUFIJO_GZ baja a 3), no se pisa ninguno y el rotado sigue sin comprimir, sin temporal
        a medias: se reintenta en la siguiente pasada y no se pierde nada."""
        self.mod.MAX_SUFIJO_GZ = 3
        previos = {}
        for sufijo in (".gz", "-2.gz", "-3.gz"):
            g = self.gz(NOMBRE + sufijo, sufijo.encode(), 3600)
            previos[g.name] = g.read_bytes()
        rot = self.rotado(b"lo nuevo\n")
        self.assertEqual(self.mod.comprimir_rotados(["p001"], time.time()), [])
        self.assertEqual(rot.read_bytes(), b"lo nuevo\n")
        for nombre, datos in previos.items():
            self.assertEqual((self.datos / nombre).read_bytes(), datos, nombre)
        self.assertEqual(self.nombres(), sorted(list(previos) + [rot.name]))

    def test_gz_existente_que_es_enlace_no_se_sigue(self):
        """Tipo: conservación (A-04). En el nombre del .gz hay un enlace plantado por el contenedor
        a un fichero del host: no se sigue, el fichero del host queda igual y lo comprimido va a
        un .gz regular propio (con esta corrección, `-2.gz`: el nombre ocupado no se toca)."""
        victima = self.victima()
        contenido = victima.read_bytes()
        enlazar(victima, self.datos / (NOMBRE + ".gz"))
        rot = self.rotado(b'{"de":"el contenedor"}\n')
        hechos = self.mod.comprimir_rotados(["p001"], time.time())
        self.assertEqual(len(hechos), 1)
        self.assertTrue(self.mod.es_regular_suelto(hechos[0]), hechos[0].name)
        self.assertEqual(leer_gz(hechos[0]), b'{"de":"el contenedor"}\n')
        self.assertEqual(victima.read_bytes(), contenido)
        self.assertFalse(rot.exists())

    @unittest.skipUnless(HAY_SYMLINKS and os.name != "nt", "symlinks con semántica POSIX: solo Linux (CI)")
    def test_temporal_cambiado_por_symlink_antes_de_enlazar(self):
        """Tipo: conservación (A-04). El contenedor cambia el temporal por un symlink a un fichero
        del host justo después de la última comprobación: el enlace al nombre final no lo sigue
        (linkat sin AT_SYMLINK_FOLLOW), así que en datos/<pid> no aparece un enlace duro al
        fichero del host y este queda igual."""
        victima = self.victima()
        contenido = victima.read_bytes()
        rot = self.rotado(b'{"x":1}\n')
        tmp = self.datos / (".%s.gz.tmp" % rot.name)
        real = self.mod.mismo_inodo

        def con_carrera(path, st):
            ok = real(path, st)
            if ok and Path(path) == tmp:
                os.unlink(str(tmp))
                os.symlink(str(victima), str(tmp))
            return ok
        self.mod.mismo_inodo = con_carrera
        self.mod.comprimir_rotado(rot)
        self.assertEqual(victima.read_bytes(), contenido)
        self.assertEqual(os.stat(str(victima)).st_nlink, 1)
        self.assertFalse(os.path.lexists(str(tmp)))

    def test_sin_gz_previo_el_nombre_es_el_de_siempre(self):
        """Tipo: conservación. Sin .gz previo el nombre es `<rotado>.gz`, sin sufijo, con el
        contenido y el mtime del rotado; el rotado y el temporal desaparecen."""
        rot = self.rotado(b"linea\n" * 1000)
        mt = rot.stat().st_mtime_ns
        g = self.mod.comprimir_rotado(rot)
        self.assertEqual(g.name, NOMBRE + ".gz")
        self.assertEqual(g.stat().st_mtime_ns, mt)
        self.assertEqual(leer_gz(g), b"linea\n" * 1000)
        self.assertEqual(self.nombres(), [NOMBRE + ".gz"])


class PodaYRetencion(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(ncpu=8)
        self.addCleanup(A.cerrar, self.orq, self.e)
        self.t = int(time.time())
        self.datos = self.e.ruta("/srv/ids/datos/p001")
        self.datos.mkdir(parents=True)

    def gz(self, base, rotado_hace_dias, sufijo="", primer_evento_hace_dias=None, mtime_hace_dias=None):
        """.gz con el nombre de logrotate de hace `rotado_hace_dias` (más el sufijo de un nombre
        repetido), su primer evento y su mtime (por defecto, la hora del nombre)."""
        cuando = self.t - int(rotado_hace_dias * DIA)
        f = self.datos / (nombre_fechado(base, cuando) + sufijo + ".gz")
        primer = self.t - int((primer_evento_hace_dias or rotado_hace_dias + 1) * DIA)
        linea = json.dumps({"timestamp": ts_suricata(primer), "event_type": "alert"}) + "\n"
        f.write_bytes(gzip.compress((linea * 3).encode()))
        mt = cuando if mtime_hace_dias is None else self.t - int(mtime_hace_dias * DIA)
        os.utime(f, (mt, mt))
        return f

    def diario(self, evento):
        p = self.e.ruta("/srv/ids/estado/orq.jsonl")
        if not p.exists():
            return []
        return [x for x in map(json.loads, p.read_text(encoding="utf-8").splitlines())
                if x.get("evento") == evento]

    def test_regex_y_fecha_del_nombre_con_sufijo(self):
        """Tipo: corrección de defecto. RE_ROTADO y RE_FECHA_ROTADO aceptan `…-HHMMSS-2.gz` (hasta
        el tope MAX_SUFIJO_GZ) con la fecha del nombre, y RE_ROTADO_SIN_COMPRIMIR no (no se vuelve
        a comprimir). La cota de un .gz con sufijo es, como la de los demás, la más tardía entre la
        fecha del nombre y el mtime; sin ampliar RE_FECHA_ROTADO solo contaba el mtime."""
        f = self.gz("eve.json", 29, sufijo="-2", mtime_hace_dias=31)
        self.assertEqual(self.mod.fecha_rotado(f), self.t - 29 * DIA)
        for n in (2, 3):
            nombre = "%s-%d.gz" % (NOMBRE, n)
            self.assertTrue(self.mod.RE_ROTADO.match(nombre), nombre)
            m = self.mod.RE_FECHA_ROTADO.match(nombre)
            self.assertEqual(m.groups() if m else None, ("20261015", "120023"), nombre)
            self.assertIsNone(self.mod.RE_ROTADO_SIN_COMPRIMIR.match(nombre), nombre)
        tope = "%s-%d.gz" % (NOMBRE, self.mod.MAX_SUFIJO_GZ)
        self.assertTrue(self.mod.RE_ROTADO.match(tope) and self.mod.RE_FECHA_ROTADO.match(tope), tope)
        for nombre in (NOMBRE, NOMBRE + ".gz", "dns.json-20261015-120023.gz"):     # conservación
            self.assertTrue(self.mod.RE_FECHA_ROTADO.match(nombre), nombre)
        self.assertIsNone(self.mod.RE_FECHA_ROTADO.match(NOMBRE + "-2"))     # sin .gz no existe

    def test_poda_por_fecha_cuenta_los_de_sufijo(self):
        """Tipo: conservación. La poda por fecha trata el .gz con sufijo como cualquier rotado:
        borra el que pasó de 30 días, igual que su par sin sufijo, y conserva los recientes con y
        sin sufijo."""
        viejos = [self.gz("eve.json", 40), self.gz("eve.json", 40, sufijo="-2")]
        recientes = [self.gz("eve.json", 2), self.gz("eve.json", 2, sufijo="-2"),
                     self.gz("dns.json", 2, sufijo="-3")]
        self.assertEqual(self.orq.podar_por_fecha(self.t), 2)
        for f in viejos:
            self.assertFalse(f.exists(), f.name)
        for f in recientes:
            self.assertTrue(f.exists(), f.name)
        self.assertEqual([(x["pid"], x["ficheros"]) for x in self.diario("poda.fecha")], [("p001", 2)])

    def test_poda_por_disco_cuenta_los_de_sufijo(self):
        """Tipo: conservación. Con el disco bajo el umbral, un .gz con sufijo entra en la cola
        de los más viejos como cualquier rotado: se borra en su turno y queda en orq.jsonl con su
        nombre."""
        a = self.gz("eve.json", 10, sufijo="-2")        # el más viejo
        b = self.gz("dns.json", 8)
        c = self.gz("eve.json", 3, sufijo="-2")
        libres = iter([10, 12, 16])                     # 10 % -> borra a -> 12 % -> borra b -> 16 %
        borrados = self.orq.podar_por_disco(self.t, libre_fn=lambda: next(libres))
        self.assertEqual([(p, n) for p, n, _ in borrados], [("p001", a.name), ("p001", b.name)])
        self.assertTrue(c.exists())
        self.assertEqual([x["fichero"] for x in self.diario("poda.disco")], [a.name, b.name])

    def test_retencion_lee_el_gz_con_sufijo(self):
        """Tipo: conservación. La retención efectiva (datos_mas_viejos/primer_ts) lee el primer
        evento de un .gz con sufijo: si es el dato más viejo, `desde` es ese evento."""
        self.gz("eve.json", 5, sufijo="-2", primer_evento_hace_dias=6)
        self.gz("eve.json", 4, primer_evento_hace_dias=5)
        (self.datos / "eve.json").write_text(
            json.dumps({"timestamp": ts_suricata(self.t - DIA), "event_type": "alert"}) + "\n",
            encoding="utf-8")
        self.assertEqual(self.orq.retencion_punto("p001", self.t)["desde"], self.t - 6 * DIA)


class Panel(BaseEventos):
    def test_eventos_lee_el_gz_de_antes_y_el_de_sufijo(self):
        """Tipo: conservación. Eventos del panel (glob «eve.json*» de nodos.ficheros_eventos y
        RE_FICHERO) lee los dos .gz de un nombre repetido, el de antes y el `-2.gz`, sin rechazar
        ninguno; también admite el nombre del tope (`-999.gz`, MAX_SUFIJO_GZ)."""
        n = "eve.json-20261011-120000"
        self.escribir("p001", n + ".gz", [alerta(T0 - 3000, sid=1)], mtime=T0 - 3000)
        self.escribir("p001", n + "-2.gz", [alerta(T0 - 300, sid=2)], mtime=T0 - 300)
        self.escribir("p001", "eve.json", [alerta(T0 - 100, sid=3)], mtime=T0 - 100)
        r = self.buscar("p001")
        self.assertFalse(r["parcial"], r["omitidos"])
        self.assertEqual(r["rechazados"], [])
        self.assertEqual([(x["ev"]["alert"]["signature_id"], x["fichero"]) for x in r["filas"]],
                         [(3, "eve.json"), (2, n + "-2.gz"), (1, n + ".gz")])
        self.assertTrue(self.ev.nombre_valido(n + "-999.gz"))


if __name__ == "__main__":
    unittest.main()
