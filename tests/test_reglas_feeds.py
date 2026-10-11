"""Feeds de dominios de ids-reglas (CONTRATO-F1a §5.9): validación, domains.lst,
domains.dataset en base64, dataset vacío si los feeds fallan, caché con caducidad y tope."""
import base64
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_suricata as A  # noqa: E402

R = A.cargar("ids-reglas")
AHORA = 1760090000.0

HOSTS = b"""# URLhaus hostfile de prueba
127.0.0.1\tlocalhost
127.0.0.1\tmalo.example.com
0.0.0.0 OTRO-MALO.example.net.   # comentario
127.0.0.1\t192.0.2.7
127.0.0.1\tsin_guion_bajo.example.com
127.0.0.1\t-empieza.example.com
127.0.0.1\txn--bcher-kva.example
127.0.0.1\t%s.example.com
127.0.0.1
""" % (b"a" * 64)

DOMINIOS = b"""! comentario estilo adblock
# comentario
c2.example.org
c2.example.org
*.comodin.example.org
sinpunto
dominio con espacio.example
""" + (b"x" * 250) + b".example\n"


def cfg(*fuentes, tope=100000):
    return {"v": 1, "max_dominios": tope, "fuentes": list(fuentes)}


def fuente(nombre, url, tipo="hosts", ttl=48):
    return {"nombre": nombre, "url": url, "tipo": tipo, "licencia": "CC0-1.0", "ttl_horas": ttl}


class Bajar:
    def __init__(self, respuestas):
        self.respuestas = respuestas
        self.urls = []

    def __call__(self, url):
        self.urls.append(url)
        r = self.respuestas.get(url)
        if isinstance(r, Exception):
            raise r
        if r is None:
            raise R.ErrorReglas("HTTP 404")
        return r


class Validacion(unittest.TestCase):
    def test_dominios(self):
        buenos = {"Malo.Example.COM.": "malo.example.com", "*.x.example": "x.example",
                  "xn--bcher-kva.example": "xn--bcher-kva.example", "a-b.c-d.example": "a-b.c-d.example"}
        for entrada, esperado in buenos.items():
            self.assertEqual(R.dominio_valido(entrada), esperado, entrada)
        for malo in ("", "localhost", "sinpunto", "192.0.2.7", "a..example", "-a.example",
                     "a-.example", "a_b.example", "a.example.123", "x" * 64 + ".example",
                     ("a" * 60 + ".") * 5 + "example", "dominio con espacio.example", "ñandú.example"):
            self.assertIsNone(R.dominio_valido(malo), malo)

    def test_formato_hosts(self):
        doms = R.parsear_feed(HOSTS.decode(), "hosts")
        self.assertEqual(doms, {"malo.example.com", "otro-malo.example.net", "xn--bcher-kva.example"})

    def test_formato_dominios(self):
        doms = R.parsear_feed(DOMINIOS.decode(), "dominios")
        self.assertEqual(doms, {"c2.example.org", "comodin.example.org"})

    def test_tipo_desconocido(self):
        with self.assertRaises(R.ErrorReglas):
            R.parsear_feed("a.example\n", "urls")

    def test_html_no_es_una_lista(self):
        self.assertTrue(R.es_html(b"  <!DOCTYPE html><html>login</html>"))
        self.assertTrue(R.es_html(b"<html><head><title>x</title>"))
        self.assertFalse(R.es_html(HOSTS))


class Generar(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.feeds = base / "rel" / "feeds"
        self.feeds.mkdir(parents=True)
        self.cache = base / "cache" / "feeds"

    def tearDown(self):
        self.tmp.cleanup()

    def leer(self):
        lst = (self.feeds / "domains.lst").read_text(encoding="utf-8").splitlines()
        ds = (self.feeds / "domains.dataset").read_text(encoding="ascii").splitlines()
        return lst, ds

    def test_lst_y_dataset_en_base64(self):
        c = cfg(fuente("urlhaus", "https://a.example/hosts"),
                fuente("lista", "https://b.example/dom", "dominios"))
        bajar = Bajar({"https://a.example/hosts": HOSTS, "https://b.example/dom": DOMINIOS})
        fuentes, n = R.generar_feeds(c, str(self.feeds), str(self.cache), bajar, AHORA)
        lst, ds = self.leer()
        self.assertEqual(lst, sorted({"malo.example.com", "otro-malo.example.net", "xn--bcher-kva.example",
                                      "c2.example.org", "comodin.example.org"}))
        self.assertEqual(n, 5)
        self.assertEqual([base64.b64decode(l).decode() for l in ds], lst)
        self.assertEqual([f["nombre"] for f in fuentes], ["urlhaus", "lista"])
        import hashlib
        self.assertEqual(fuentes[0]["sha256"], hashlib.sha256(HOSTS).hexdigest())
        self.assertEqual(set(fuentes[0]), {"nombre", "url", "sha256"})

    def test_si_todo_falla_el_dataset_existe_vacio(self):
        c = cfg(fuente("urlhaus", "https://a.example/hosts"), fuente("otra", "https://b.example/x"))
        bajar = Bajar({"https://a.example/hosts": R.ErrorReglas("HTTP 403"),
                       "https://b.example/x": OSError("sin red")})
        fuentes, n = R.generar_feeds(c, str(self.feeds), str(self.cache), bajar, AHORA)
        self.assertTrue((self.feeds / "domains.dataset").is_file())
        self.assertEqual((self.feeds / "domains.dataset").read_bytes(), b"")
        self.assertEqual((self.feeds / "domains.lst").read_bytes(), b"")
        self.assertEqual(n, 0)
        self.assertEqual([f["sha256"] for f in fuentes], [None, None])

    def test_respuesta_html_cuenta_como_fallo(self):
        c = cfg(fuente("urlhaus", "https://a.example/hosts"))
        bajar = Bajar({"https://a.example/hosts": b"<!doctype html><title>Login</title>"})
        _f, n = R.generar_feeds(c, str(self.feeds), str(self.cache), bajar, AHORA)
        self.assertEqual(n, 0)
        self.assertFalse((self.cache / "urlhaus.txt").exists())

    def test_cache_vigente_y_caducada(self):
        c = cfg(fuente("urlhaus", "https://a.example/hosts", ttl=48))
        R.generar_feeds(c, str(self.feeds), str(self.cache), Bajar({"https://a.example/hosts": HOSTS}), AHORA)
        os.utime(self.cache / "urlhaus.txt", (AHORA - 3600, AHORA - 3600))
        falla = Bajar({})
        _f, n = R.generar_feeds(c, str(self.feeds), str(self.cache), falla, AHORA)
        self.assertEqual(n, 3, "con la caché de hace 1 h se usan sus dominios")
        os.utime(self.cache / "urlhaus.txt", (AHORA - 49 * 3600, AHORA - 49 * 3600))
        _f, n = R.generar_feeds(c, str(self.feeds), str(self.cache), falla, AHORA)
        self.assertEqual(n, 0, "la caché de hace 49 h ha caducado")
        self.assertEqual((self.feeds / "domains.dataset").read_bytes(), b"")

    def test_tope_de_dominios_por_orden_de_fuente(self):
        c = cfg(fuente("primera", "https://a.example/1", "dominios"),
                fuente("segunda", "https://a.example/2", "dominios"), tope=3)
        bajar = Bajar({"https://a.example/1": b"b.example\na.example\n",
                       "https://a.example/2": b"z.example\ny.example\nx.example\n"})
        _f, n = R.generar_feeds(c, str(self.feeds), str(self.cache), bajar, AHORA)
        lst, _ds = self.leer()
        self.assertEqual(n, 3)
        self.assertEqual(lst, ["a.example", "b.example", "x.example"])


class FeedsJson(unittest.TestCase):
    def test_el_de_la_imagen_es_valido(self):
        c = R.cargar_feeds_json(str(A.SHARE / "feeds.json"))
        self.assertGreaterEqual(len(c["fuentes"]), 1)
        for f in c["fuentes"]:
            self.assertTrue(f["url"].startswith("https://"))
            self.assertTrue(f.get("licencia"), f["nombre"])

    def test_rechaza_esquemas_malos(self):
        tmp = tempfile.mkdtemp()
        try:
            ruta = os.path.join(tmp, "feeds.json")
            for malo in ({"v": 2, "fuentes": []},
                         cfg(fuente("../x", "https://a.example/")),
                         cfg(fuente("a", "http://a.example/")),
                         cfg(fuente("a", "https://a.example/", "rpz")),
                         cfg(fuente("a", "https://a.example/"), fuente("a", "https://b.example/"))):
                with open(ruta, "w", encoding="utf-8") as fh:
                    json.dump(malo, fh)
                with self.assertRaises(R.ErrorReglas, msg=repr(malo)):
                    R.cargar_feeds_json(ruta)
        finally:
            shutil.rmtree(tmp)

    def test_solo_https_en_la_descarga_real(self):
        with self.assertRaises(R.ErrorReglas):
            R.bajar_url("http://a.example/x")


if __name__ == "__main__":
    unittest.main()
