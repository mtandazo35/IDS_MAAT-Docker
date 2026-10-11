"""Detalle de un evento (eventos_web.detalle): referencia pid+fichero+desplazamiento firmada
con HMAC; cualquier manipulacion se rechaza SIN leer nada (CONTRATO-F2 §9 y §10.5).
"""
import html
import json
import os
import re
import stat
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from test_eventos_busqueda import T0, Base, alerta, form, iso, linea


def _symlinks():
    d = tempfile.mkdtemp(prefix="ids-ln-")
    try:
        os.symlink(os.path.join(d, "x"), os.path.join(d, "y"))
        return True
    except (OSError, NotImplementedError, AttributeError):
        return False
    finally:
        for n in ("y",):
            try:
                os.remove(os.path.join(d, n))
            except OSError:
                pass
        os.rmdir(d)


HAY_SYMLINKS = _symlinks()


class Detalle(Base):
    def setUp(self):
        super().setUp()
        self.l1 = alerta(T0 - 20, sid=2000010, firma="ET <script>alert(1)</script> prueba")
        self.l2 = alerta(T0 - 10, sid=2000011, src="10.0.0.5")
        self.escribir("p001", "eve.json", [self.l1, self.l2], mtime=T0)
        self.escribir("p002", "eve.json", [alerta(T0 - 5, sid=2000099)], mtime=T0)

    def refs(self, nodo="p001", **kw):
        """Consultas de detalle tal como salen en los enlaces de la pagina."""
        pag = self.ev.pagina(self.q(**kw), nodo)
        return [{k: v[0] for k, v in parse_qs(urlsplit(html.unescape(h)).query).items()}
                for h in re.findall(r"href='(/eventos/detalle\?[^']+)'", pag)]

    def sin_leer(self):
        """Ninguna lectura de ficheros de eventos: ni abrirlos ni descomprimirlos."""
        return mock.patch.object(self.ev, "_abrir", side_effect=AssertionError("leyo un fichero"))

    def rechazada(self, q, nodo="p001"):
        with self.sin_leer():
            out = self.ev.detalle(q, nodo)
        self.assertIn("Referencia de evento no valida", out)
        self.assertNotIn("<pre", out)
        return out

    def test_detalle_con_json_completo_escapado_y_volver(self):
        """Capacidad nueva (§9): el detalle enseña el JSON completo, formateado y escapado, y el
        enlace de vuelta conserva nodo, filtros y cursor."""
        q = self.refs(ip="10.0.0.5", firma="2000010")[0]
        out = self.ev.detalle(q, "p001")
        pre = re.search(r"<pre class='evjson'>(.*?)</pre>", out, re.S).group(1)
        self.assertEqual(json.loads(html.unescape(pre)), json.loads(self.l1))
        self.assertIn("\n  \"alert\": {", html.unescape(pre))                 # formateado
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)
        volver = html.unescape(re.search(r"<a href='(/eventos\?[^']+)'>&laquo; Volver", out).group(1))
        vq = parse_qs(urlsplit(volver).query)
        self.assertEqual((vq["nodo"], vq["ip"], vq["firma"]), (["p001"], ["10.0.0.5"], ["2000010"]))
        self.assertNotIn("s", vq)                                             # la firma no vuelve

    def test_detalle_en_todos_y_desde_gz(self):
        """Capacidad nueva: el detalle funciona en «Todos» y con eventos de un .gz rotado."""
        self.escribir("p002", "eve.json.1.gz", [alerta(T0 - 400, sid=2000077), alerta(T0 - 300, sid=2000078)],
                      mtime=T0 - 300)
        qs = self.refs(self.n.TODOS)
        gz = [q for q in qs if q["f"] == "eve.json.1.gz"]
        self.assertEqual(len(gz), 2)
        for q in gz:
            out = self.ev.detalle(q, self.n.TODOS)
            pre = re.search(r"<pre class='evjson'>(.*?)</pre>", out, re.S).group(1)
            self.assertIn(json.loads(html.unescape(pre))["alert"]["signature_id"], (2000077, 2000078))

    def test_firma_mala_o_campos_cambiados(self):
        """Correccion de defecto (§10.5 «rutas manipuladas»): cambiar cualquier campo de la
        referencia invalida la firma, y se rechaza sin abrir ningun fichero."""
        q = self.refs()[0]
        for k, v in (("s", ("0" if q["s"][0] != "0" else "1") + q["s"][1:]), ("o", str(int(q["o"]) + 1)),
                     ("h", "0" * 16), ("f", "eve.json.1"), ("s", ""), ("s", q["s"].upper())):
            self.rechazada(dict(q, **{k: v}))

    def test_otro_pid(self):
        """Correccion de defecto (§10.1/§10.5): otro pid en la referencia, un pid que no existe o
        un evento de p002 mirando p001 se rechazan, aunque la firma sea buena."""
        q = self.refs()[0]
        self.rechazada(dict(q, p="p002"))                                # firma de p001
        bueno = self.refs("p002")[0]
        self.rechazada(bueno, nodo="p001")                               # firma valida, otro nodo
        self.assertIn("<pre", self.ev.detalle(bueno, "p002"))
        f3 = dict(q, p="p003", s=self.ev.firmar("p003", q["f"], int(q["o"]), q["h"]))
        self.rechazada(f3, nodo=self.n.TODOS)                            # no existe
        self.rechazada(dict(q, p="../p001"))

    def test_rutas_manipuladas_aunque_esten_firmadas(self):
        """Correccion de defecto (§10.5): nombres con `..`, separadores, rutas absolutas o que
        no son eve.json*/dns.json* se rechazan antes de mirar la firma (aqui van firmados con la
        clave buena para demostrar que el filtro de nombre no depende de ella)."""
        q = self.refs()[0]
        fuera = os.path.join(self.tmp, "fuera", "eve.json")
        with open(fuera, "w") as f:
            f.write(alerta(T0) + "\n")
        for nombre in ("../p002/eve.json", "eve.json/../../p002/eve.json", "..\\p002\\eve.json", fuera,
                       "eve.json..gz", "eve.json\x00", "suricata.yaml", "eve.json\n", "eve.json/", ".eve.json",
                       "dns.json.1/../../../fuera/eve.json"):
            firmada = dict(q, f=nombre, s=self.ev.firmar("p001", nombre, int(q["o"]), q["h"]))
            self.rechazada(firmada)

    def test_desplazamiento_fuera_de_rango_o_a_media_linea(self):
        """Correccion de defecto: con firma valida, un desplazamiento fuera del fichero o que no
        es inicio de linea es un error, no una lectura a medias."""
        q = self.refs()[0]
        tam = os.path.getsize(self.ruta("p001", "eve.json"))
        for off in (tam, tam + 10 ** 9, 5, 10 ** 14):
            firmada = dict(q, o=str(off), s=self.ev.firmar("p001", "eve.json", off, q["h"]))
            out = self.ev.detalle(firmada, "p001")
            self.assertIn("Referencia de evento no valida", out)
            self.assertNotIn("<pre", out)
        for malo in ("-1", "1e3", "0x10", "", "9" * 16):
            self.rechazada(dict(q, o=malo))

    @unittest.skipUnless(HAY_SYMLINKS, "este sistema no deja crear enlaces simbolicos")
    def test_enlace_simbolico_fuera_del_punto(self):
        """Correccion de defecto (§10.5 «enlaces simbolicos»): un eve.json.N que apunta fuera de
        DATOS/<pid> no se lista ni se lee por el detalle, aunque la referencia este firmada."""
        secreto = os.path.join(self.tmp, "fuera", "secreto.json")
        with open(secreto, "w") as f:
            f.write(alerta(T0 - 1, sid=6666666, firma="NO DEBE SALIR") + "\n")
        os.symlink(secreto, self.ruta("p001", "eve.json.9"))
        r = self.buscar("p001")
        self.assertNotIn(6666666, [x["ev"]["alert"]["signature_id"] for x in r["filas"]])
        self.assertIn(("p001", "eve.json.9"), r["rechazados"])
        with open(secreto, "rb") as f:
            h = self.ev.huella(f.readline())
        q = {"p": "p001", "f": "eve.json.9", "o": "0", "h": h, "s": self.ev.firmar("p001", "eve.json.9", 0, h)}
        out = self.ev.detalle(q, "p001")
        self.assertNotIn("NO DEBE SALIR", out)
        self.assertIn("Referencia de evento no valida", out)

    def test_enlace_simbolico_simulado(self):
        """Correccion de defecto (§10.5), tambien donde no se pueden crear enlaces: si la ruta
        real de un fichero del punto sale de DATOS/<pid>, no se abre."""
        real = os.path.realpath
        fuera = os.path.join(self.tmp, "fuera", "eve.json.9")

        def realpath(p, *a, **k):
            if os.path.basename(p) == "eve.json.9":
                return real(fuera)
            return real(p, *a, **k)
        self.escribir("p001", "eve.json.9", [alerta(T0 - 1, sid=6666666)], mtime=T0)
        h = self.ev.huella((alerta(T0 - 1, sid=6666666) + "\n").encode())
        q = {"p": "p001", "f": "eve.json.9", "o": "0", "h": h, "s": self.ev.firmar("p001", "eve.json.9", 0, h)}
        with mock.patch("os.path.realpath", side_effect=realpath):
            r = self.buscar("p001")
            self.assertIn(("p001", "eve.json.9"), r["rechazados"])
            self.assertNotIn(6666666, [x["ev"]["alert"]["signature_id"] for x in r["filas"]])
            with mock.patch.object(self.ev, "_abrir", side_effect=AssertionError("leyo el enlace")):
                # (el detalle busca la huella en los demas ficheros del punto, que son legitimos)
                with mock.patch.object(self.ev.nodos, "ficheros_eventos",
                                       return_value=[("p001", self.ruta("p001", "eve.json.9"))]):
                    out = self.ev.detalle(q, "p001")
        self.assertIn("Referencia de evento no valida", out)

    def test_evento_rotado_se_encuentra(self):
        """Correccion de defecto (§10.5 «rotacion»): si el vivo rota despues de pintar la lista,
        el enlace sigue llevando a ESE evento (misma huella) y no a otro que ocupe su sitio."""
        q = self.refs()[0]
        os.replace(self.ruta("p001", "eve.json"), self.ruta("p001", "eve.json.1"))
        self.escribir("p001", "eve.json", [alerta(T0 + 1, sid=7777777), alerta(T0 + 2, sid=7777778)], mtime=T0 + 2)
        out = self.ev.detalle(q, "p001")
        pre = json.loads(html.unescape(re.search(r"<pre class='evjson'>(.*?)</pre>", out, re.S).group(1)))
        self.assertIn(pre["alert"]["signature_id"], (2000010, 2000011))
        self.assertIn("eve.json.1", out)
        os.remove(self.ruta("p001", "eve.json.1"))
        out = self.ev.detalle(q, "p001")
        self.assertIn("ya no esta", out)
        self.assertNotIn("7777777", out)

    def test_linea_que_no_es_json(self):
        """Correccion de defecto: un evento cuya linea no es JSON valido no rompe el detalle."""
        p = self.ruta("p001", "eve.json")
        roto = ('{"timestamp":"%s","event_type":"alert",' % iso(T0 - 3)).encode()
        with open(p, "ab") as f:
            off = f.tell()
            f.write(roto + b"\n")
        h = self.ev.huella(roto)
        out = self.ev.detalle({"p": "p001", "f": "eve.json", "o": str(off), "h": h,
                               "s": self.ev.firmar("p001", "eve.json", off, h)}, "p001")
        self.assertIn("no es JSON valido", out)


class Clave(Base):
    def test_secreto_0600_persistente(self):
        """Capacidad nueva: el secreto HMAC se crea una vez en CONF (0600 en POSIX) y sirve para
        las firmas de otro proceso (aqui, tras recargar el modulo)."""
        p = os.path.join(self.n.CONF, self.ev.CLAVE_HMAC)
        self.assertFalse(os.path.exists(p))
        s1 = self.ev.firmar("p001", "eve.json", 0, "0" * 16)
        self.assertTrue(os.path.isfile(p))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        import importlib
        ev2 = importlib.reload(self.ev)
        self.assertEqual(ev2.firmar("p001", "eve.json", 0, "0" * 16), s1)
        self.assertEqual([n for n in os.listdir(self.n.CONF) if n.endswith(".tmp")], [])

    def test_secreto_danado_se_regenera(self):
        """Correccion de defecto: un fichero de clave vacio o con basura no deja firmar con
        una clave vacia; se sustituye por una nueva."""
        p = os.path.join(self.n.CONF, self.ev.CLAVE_HMAC)
        with open(p, "w") as f:
            f.write("\n")
        self.ev.firmar("p001", "eve.json", 0, "0" * 16)
        with open(p) as f:
            self.assertRegex(f.read().strip(), r"^[0-9a-f]{64}$")


class Dns(Base):
    def test_dns_de_dns_json(self):
        """Capacidad nueva (§9): el tipo DNS lee dns.json* (el eve del contenedor no lleva dns)."""
        self.escribir("p001", "dns.json", [linea({"timestamp": iso(T0 - 5), "event_type": "dns",
                                                  "src_ip": "10.0.0.5", "dest_ip": "192.0.2.53", "proto": "UDP",
                                                  "dns": {"version": 3, "type": "request",
                                                          "queries": [{"rrname": "ejemplo.test", "rrtype": "A"}]}})],
                      mtime=T0)
        self.escribir("p001", "eve.json", [alerta(T0 - 4)], mtime=T0)
        r = self.buscar("p001", tipo="dns", desde=form(T0 - 60))
        self.assertEqual([x["fichero"] for x in r["filas"]], ["dns.json"])
        self.assertIn("ejemplo.test", self.ev.pagina(self.q(tipo="dns"), "p001"))


if __name__ == "__main__":
    unittest.main()
