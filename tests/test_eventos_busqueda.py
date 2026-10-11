"""Pagina Eventos (eventos_web.py): busqueda por nodo y en «Todos», filtros, .gz rotados,
paginacion por cursor, topes y escapado (CONTRATO-F2 §9 y §10.5).

Cada prueba dice su tipo en el docstring: capacidad nueva (el buscador sustituye a EveBox, no
existia en el panel heredado) o correccion de defecto (casos obligatorios de §10.5).
"""
import gzip
import html
import importlib
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock
from urllib.parse import parse_qs, urlsplit

LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "images", "panel", "rootfs", "usr", "local", "lib", "ids-panel")

T0 = 1791700000          # 2026-10-11 en UTC; todas las marcas de las pruebas cuelgan de aqui


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def form(t):
    """Fecha del formulario (hora local = UTC en las pruebas)."""
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def linea(d):
    return json.dumps(d, separators=(",", ":"))


def alerta(t, src="10.0.0.5", dst="192.0.2.10", sid=2000001, firma="ET PRUEBA uno", sev=2,
           sport=51000, dport=443, proto="TCP", flow=111):
    return linea({"timestamp": iso(t), "flow_id": flow, "event_type": "alert", "src_ip": src,
                  "src_port": sport, "dest_ip": dst, "dest_port": dport, "proto": proto,
                  "alert": {"action": "allowed", "signature_id": sid, "signature": firma,
                            "severity": sev, "category": "Prueba"}})


def consulta_dns(t, src="10.0.0.5", rrname="ejemplo.test"):
    return linea({"timestamp": iso(t), "event_type": "dns", "src_ip": src, "src_port": 40000,
                  "dest_ip": "192.0.2.53", "dest_port": 53, "proto": "UDP",
                  "dns": {"type": "query", "rrname": rrname, "rrtype": "A"}})


def stats(t):
    return linea({"timestamp": iso(t), "event_type": "stats",
                  "stats": {"uptime": 10, "capture": {"kernel_packets": 5, "kernel_drops": 0}}})


class Base(unittest.TestCase):
    """Arbol temporal: IDS_DATOS, IDS_RUN (estado.json con p001 «norte» y p002 «sur») e
    IDS_PANEL_DIR. Sin pruebas propias (la importan los otros ficheros)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ids-eventos-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        r = self.tmp
        for d in ("run", "datos/p001", "datos/p002", "panel/conf", "fuera"):
            os.makedirs(os.path.join(r, d))
        with open(os.path.join(r, "run", "estado.json"), "w", encoding="utf-8") as f:
            json.dump({"puntos": {"p001": {"nombre": "norte", "redes": ["10.0.0.0/24"]},
                                  "p002": {"nombre": "sur", "redes": ["10.0.0.0/24"]}}}, f)
        viejo = {k: os.environ.get(k) for k in ("IDS_PANEL_DIR", "IDS_DATOS", "IDS_RUN", "IDS_TZ")}
        self.addCleanup(self._restaurar_env, viejo)
        os.environ.update({"IDS_PANEL_DIR": os.path.join(r, "panel"), "IDS_DATOS": os.path.join(r, "datos"),
                           "IDS_RUN": os.path.join(r, "run"), "IDS_TZ": "UTC"})
        if LIB not in sys.path:
            sys.path.insert(0, LIB)
        import nodos
        self.n = importlib.reload(nodos)
        import eventos_web
        self.ev = importlib.reload(eventos_web)

    @staticmethod
    def _restaurar_env(viejo):
        for k, v in viejo.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def ruta(self, pid, nombre):
        return os.path.join(self.tmp, "datos", pid, nombre)

    def escribir(self, pid, nombre, lineas, mtime=None, final=True):
        """Escribe el fichero (gz si acaba en .gz) y le pone de mtime la ultima marca."""
        datos = ("\n".join(lineas) + ("\n" if final and lineas else "")).encode()
        p = self.ruta(pid, nombre)
        if nombre.endswith(".gz"):
            with gzip.open(p, "wb") as f:
                f.write(datos)
        else:
            with open(p, "wb") as f:
                f.write(datos)
        if mtime is not None:
            os.utime(p, (mtime, mtime))
        return p

    def q(self, **kw):
        d = {"desde": form(T0 - 3600), "hasta": form(T0 + 3600)}
        d.update({k: str(v) for k, v in kw.items()})
        return d

    def buscar(self, nodo, **kw):
        return self.ev.buscar(self.ev.filtros(self.q(**kw)), nodo)

    def todas_las_paginas(self, nodo, maximo=200, **kw):
        """Recorre la busqueda siguiendo el cursor; devuelve [(clave, fila)] y las respuestas."""
        filas, resps, cur = [], [], None
        for _ in range(maximo):
            extra = dict(kw)
            if cur:
                extra["cursor"] = self.ev.cursor_txt(cur)
            r = self.buscar(nodo, **extra)
            resps.append(r)
            filas += [((x["ts_us"], x["pid"], x["huella"]), x) for x in r["filas"]]
            cur = r["siguiente"]
            if not cur:
                break
        else:
            self.fail("la paginacion no termina")
        return filas, resps


def filas_html(pagina):
    return re.findall(r"<tr data-pid='(p\d{3})'>", pagina)


class DosNodos(Base):
    def test_misma_ip_mismo_flujo_en_dos_nodos_son_dos_filas(self):
        """Capacidad nueva (§9, caso «misma IP y mismo flujo en dos puntos»): la misma linea
        exacta en p001 y p002 sale dos veces en «Todos», cada una con su nodo, y una sola con
        el nodo elegido."""
        l = alerta(T0, src="10.0.0.5", flow=777)
        self.escribir("p001", "eve.json", [l], mtime=T0)
        self.escribir("p002", "eve.json", [l], mtime=T0)
        r = self.buscar(self.n.TODOS)
        self.assertEqual(sorted(x["pid"] for x in r["filas"]), ["p001", "p002"])
        self.assertEqual({x["ev"]["src_ip"] for x in r["filas"]}, {"10.0.0.5"})
        pag = self.ev.pagina(self.q(), self.n.TODOS)
        self.assertEqual(sorted(filas_html(pag)), ["p001", "p002"])
        fila2 = re.search(r"<tr data-pid='p002'>.*?</tr>", pag, re.S).group(0)
        self.assertIn("<span class='nodochip' title='p002'>sur</span>", fila2)
        self.assertIn("<th>Nodo</th>", pag)

        r2 = self.buscar("p002")
        self.assertEqual([x["pid"] for x in r2["filas"]], ["p002"])
        pag2 = self.ev.pagina(self.q(), "p002")
        self.assertEqual(filas_html(pag2), ["p002"])
        self.assertNotIn("<th>Nodo</th>", pag2)

    def test_nodo_inexistente_no_amplia(self):
        """Correccion de defecto (§10.1): un nodo que no existe es un error, nunca «Todos»."""
        self.escribir("p001", "eve.json", [alerta(T0)], mtime=T0)
        with self.assertRaises(self.n.NodoInexistente):
            self.ev.pagina(self.q(), "p003")
        with self.assertRaises(self.n.NodoInvalido):
            self.ev.pagina(self.q(), "../p001")


class Filtros(Base):
    def setUp(self):
        super().setUp()
        self.escribir("p001", "eve.json", [
            alerta(T0 - 7200, src="10.0.0.5", sid=1, firma="VIEJA fuera de ventana"),
            alerta(T0 - 30, src="10.0.0.5", dst="192.0.2.10", sid=2010935, firma="ET SCAN Puerto raro", sev=1,
                   sport=51000, dport=3389),
            alerta(T0 - 20, src="10.0.0.55", dst="192.0.2.11", sid=2010936, firma="ET POLICY otra", sev=3,
                   sport=3389, dport=80, proto="UDP"),
            alerta(T0 - 10, src="192.0.2.12", dst="10.0.0.5", sid=2010935, firma="ET SCAN Puerto raro", sev=1,
                   sport=443, dport=52000),
            consulta_dns(T0 - 5, src="10.0.0.5"),
            stats(T0 - 1),
        ], mtime=T0)

    def sids(self, **kw):
        return [x["ev"].get("alert", {}).get("signature_id") for x in self.buscar("p001", **kw)["filas"]]

    def test_filtros(self):
        """Capacidad nueva (§9): SID, firma, severidad, IP (cualquiera/origen/destino), puerto
        (origen/destino), protocolo, fecha y tipo de evento, con resultados concretos."""
        self.assertEqual(self.sids(), [2010935, 2010936, 2010935])           # alert por defecto, ventana
        self.assertEqual(self.sids(firma="2010935"), [2010935, 2010935])     # SID
        self.assertEqual(self.sids(firma="scan puerto"), [2010935, 2010935]) # texto, sin mayusculas
        self.assertEqual(self.sids(sev="3"), [2010936])
        self.assertEqual(self.sids(ip="10.0.0.5"), [2010935, 2010935])       # 10.0.0.55 no es 10.0.0.5
        self.assertEqual(len(self.buscar("p001", ip="10.0.0.5", ipdir="src")["filas"]), 1)
        self.assertEqual(self.buscar("p001", ip="10.0.0.5", ipdir="dst")["filas"][0]["ev"]["src_ip"], "192.0.2.12")
        self.assertEqual(self.sids(puerto="3389"), [2010936, 2010935])
        self.assertEqual(self.sids(puerto="3389", pdir="dst"), [2010935])
        self.assertEqual(self.sids(puerto="3389", pdir="src"), [2010936])
        self.assertEqual(self.sids(proto="udp"), [2010936])
        self.assertEqual(self.sids(desde=form(T0 - 25), hasta=form(T0 - 15)), [2010936])
        self.assertEqual(self.sids(desde=form(T0 - 8000), hasta=form(T0 - 7000)), [1])
        tipos = [x["ev"]["event_type"] for x in self.buscar("p001", tipo="todos")["filas"]]
        self.assertEqual(tipos, ["stats", "dns", "alert", "alert", "alert"])  # mas recientes primero
        self.assertEqual([x["ev"]["event_type"] for x in self.buscar("p001", tipo="stats")["filas"]], ["stats"])

    def test_filtro_invalido_no_busca(self):
        """Capacidad nueva: un filtro malo se dice y no se busca (ni se ensancha la busqueda)."""
        with mock.patch.object(self.ev, "buscar", side_effect=AssertionError("no debia buscar")):
            for malo in ({"ip": "10.0.0.999"}, {"puerto": "70000"}, {"desde": form(T0), "hasta": form(T0 - 60)},
                         {"tipo": "flow<x>"}, {"cursor": "abc"}, {"sev": "0"}, {"desde": "ayer"}):
                pag = self.ev.pagina(self.q(**malo), "p001")
                self.assertIn("banner err", pag, malo)
                self.assertEqual(filas_html(pag), [])

    def test_ventana_por_defecto_es_la_ultima_hora(self):
        """Capacidad nueva: sin fechas se mira la ultima hora (y los enlaces llevan las fechas
        fijadas, para que la pagina siguiente no se mueva con el reloj)."""
        f = self.ev.filtros({}, ahora=T0)
        self.assertEqual(f["hasta_us"], (T0 + 1) * 1000000 - 1)
        self.assertEqual(f["desde_us"], (T0 + 1 - 3600) * 1000000)
        self.assertEqual(f["tipo"], "alert")


class Rotados(Base):
    def test_gz_rotado_y_salto_por_mtime(self):
        """Capacidad nueva (§9): lee los .gz rotados; un rotado que se cerro antes de la ventana
        no se abre (aqui esta danado: si se leyera, la busqueda saldria parcial)."""
        self.escribir("p001", "eve.json.2.gz", [alerta(T0 - 9000, sid=9)], mtime=T0 - 9000)
        with open(self.ruta("p001", "eve.json.2.gz"), "r+b") as f:
            f.seek(12)
            f.write(b"\x00" * 8)                                   # gz roto
        os.utime(self.ruta("p001", "eve.json.2.gz"), (T0 - 9000, T0 - 9000))
        self.escribir("p001", "eve.json.1.gz", [alerta(T0 - 300, sid=1), alerta(T0 - 200, sid=2)], mtime=T0 - 200)
        self.escribir("p001", "eve.json", [alerta(T0 - 100, sid=3), alerta(T0 - 50, sid=4)], mtime=T0 - 50)
        r = self.buscar("p001")
        self.assertFalse(r["parcial"], r["omitidos"])
        self.assertEqual([x["ev"]["alert"]["signature_id"] for x in r["filas"]], [4, 3, 2, 1])
        self.assertEqual([x["fichero"] for x in r["filas"]], ["eve.json", "eve.json", "eve.json.1.gz", "eve.json.1.gz"])
        self.assertEqual(r["ficheros"], 2)

    def test_misma_linea_en_rotado_plano_y_gz_sale_una_vez(self):
        """Correccion de defecto (§10.5 «rotacion mientras se lee»): mientras logrotate comprime,
        eve.json.1 y eve.json.1.gz tienen las mismas lineas: no salen duplicadas."""
        ls = [alerta(T0 - 300, sid=1), alerta(T0 - 200, sid=2)]
        self.escribir("p001", "eve.json.1", ls, mtime=T0 - 200)
        self.escribir("p001", "eve.json.1.gz", ls, mtime=T0 - 200)
        self.escribir("p001", "eve.json", [alerta(T0 - 100, sid=3)], mtime=T0 - 100)
        r = self.buscar("p001")
        self.assertEqual([x["ev"]["alert"]["signature_id"] for x in r["filas"]], [3, 2, 1])


class Paginacion(Base):
    def preparar(self):
        """~260 alertas en dos nodos, con marcas repetidas (mismo paquete, varias firmas),
        repartidas entre un .gz rotado, un rotado plano y el vivo."""
        esperado = set()
        for pid in ("p001", "p002"):
            vivo, rot, gz = [], [], []
            for i in range(130):
                t = T0 - 3000 + (i // 3) * 7 + (i % 3) * 0.000001 * (i % 2)   # empates de marca
                l = alerta(t, src="10.0.0.%d" % (i % 9), sid=3000000 + i, flow=i)
                (gz if i < 40 else rot if i < 80 else vivo).append(l)
                esperado.add((pid, 3000000 + i))
            self.escribir(pid, "eve.json.2.gz", gz, mtime=T0 - 3000 + 13 * 7 + 1)
            self.escribir(pid, "eve.json.1", rot, mtime=T0 - 3000 + 26 * 7 + 1)
            self.escribir(pid, "eve.json", vivo, mtime=T0)
        return esperado

    def comprobar(self, filas, esperado):
        claves = [c for c, _ in filas]
        self.assertEqual(len(claves), len(set(claves)), "eventos repetidos entre paginas")
        self.assertEqual(claves, sorted(claves, reverse=True), "no van de mas reciente a mas viejo")
        vistos = {(x["pid"], x["ev"]["alert"]["signature_id"]) for _, x in filas}
        self.assertEqual(vistos, esperado, "faltan o sobran eventos")

    def test_paginas_sin_huecos_ni_repetidos(self):
        """Capacidad nueva (§9): paginacion por cursor en «Todos», con bloques y paginas
        pequenos para forzar cortes de bloque, biseccion y empates de marca."""
        esperado = self.preparar()
        for por_pagina, bloque in ((7, 256), (100, 1 << 20), (13, 1500)):
            with mock.patch.object(self.ev, "POR_PAGINA", por_pagina), mock.patch.object(self.ev, "BLOQUE", bloque):
                filas, resps = self.todas_las_paginas(self.n.TODOS)
            self.comprobar(filas, esperado)
            self.assertTrue(all(len(r["filas"]) == por_pagina for r in resps[:-1]))
            self.assertFalse(any(r["parcial"] for r in resps))

    def test_lineas_nuevas_y_rotacion_entre_paginas(self):
        """Correccion de defecto (§10.5): si entre pagina y pagina el vivo crece o rota, las
        paginas siguientes no repiten ni pierden nada de la busqueda original."""
        esperado = self.preparar()
        with mock.patch.object(self.ev, "POR_PAGINA", 20), mock.patch.object(self.ev, "BLOQUE", 512):
            r = self.buscar(self.n.TODOS)
            filas = [((x["ts_us"], x["pid"], x["huella"]), x) for x in r["filas"]]
            # llegan eventos nuevos al vivo (dentro de la ventana) ...
            with open(self.ruta("p001", "eve.json"), "ab") as f:
                f.write((alerta(T0 + 5, sid=4000001) + "\n").encode())
            # ... y p002 rota: eve.json -> eve.json.0, vivo nuevo vacio con una linea nueva
            os.replace(self.ruta("p002", "eve.json"), self.ruta("p002", "eve.json.0"))
            os.utime(self.ruta("p002", "eve.json.0"), (T0, T0))
            self.escribir("p002", "eve.json", [alerta(T0 + 6, sid=4000002)], mtime=T0 + 6)
            cur = r["siguiente"]
            while cur:
                r = self.buscar(self.n.TODOS, cursor=self.ev.cursor_txt(cur))
                filas += [((x["ts_us"], x["pid"], x["huella"]), x) for x in r["filas"]]
                cur = r["siguiente"]
        self.comprobar(filas, esperado)

    def test_enlace_siguiente_de_la_pagina(self):
        """Capacidad nueva: el enlace «Siguientes» de la pagina HTML lleva nodo, filtros y
        cursor, y siguiendolo se llega al final sin repetir filas."""
        self.preparar()
        vistas = []
        with mock.patch.object(self.ev, "POR_PAGINA", 50):
            q = self.q()
            for _ in range(20):
                pag = self.ev.pagina(q, self.n.TODOS)
                vistas += re.findall(r"href='(/eventos/detalle\?[^']+)'", pag)
                m = re.search(r"<a href='(/eventos\?[^']+)'>Siguientes", pag)
                if not m:
                    break
                qs = parse_qs(urlsplit(html.unescape(m.group(1))).query)
                self.assertEqual(qs["nodo"], [self.n.TODOS])
                q = {k: v[0] for k, v in qs.items()}
        refs = [parse_qs(urlsplit(html.unescape(v)).query)["h"][0] + parse_qs(urlsplit(html.unescape(v)).query)["p"][0]
                for v in vistas]
        self.assertEqual(len(refs), 260)
        self.assertEqual(len(set(refs)), 260)


class Incompletos(Base):
    def test_json_incompleto_se_salta_y_cuenta(self):
        """Correccion de defecto (§10.5 «JSON incompleto»): una linea cortada, basura y la linea
        que Suricata esta escribiendo se saltan y se cuentan; la pagina sale con lo valido."""
        buena1, buena2 = alerta(T0 - 20, sid=1), alerta(T0 - 10, sid=2)
        cortada = alerta(T0 - 15, sid=3)[:160]                      # trae marca y "alert", sin cerrar
        p = self.ruta("p001", "eve.json")
        with open(p, "wb") as f:
            f.write((buena1 + "\n" + cortada + "\n" + '{"timestamp":"' + iso(T0 - 12) + '","event_type":"alert",}'
                     + "\n" + buena2 + "\n" + alerta(T0 - 5, sid=4)[:90]).encode())
        os.utime(p, (T0, T0))
        r = self.buscar("p001")
        self.assertEqual([x["ev"]["alert"]["signature_id"] for x in r["filas"]], [2, 1])
        self.assertGreaterEqual(r["incompletas"], 3)
        pag = self.ev.pagina(self.q(), "p001")
        self.assertEqual(filas_html(pag), ["p001", "p001"])
        self.assertIn("incompletas o con JSON no valido saltadas", pag)


class Topes(Base):
    def test_gz_que_descomprime_mucho_corta_con_aviso(self):
        """Correccion de defecto (§10.5 «.gz que descomprime mucho»): el tope va por bytes
        DEScomprimidos; el fichero se omite, la pagina dice que es parcial y hasta donde, y
        nunca dice «sin coincidencias»."""
        relleno = [alerta(T0 - 500 + i * 0.001, sid=7) for i in range(3000)]   # ~600 KB, comprime mucho
        p = self.escribir("p001", "eve.json.1.gz", relleno, mtime=T0 - 400)
        self.assertLess(os.path.getsize(p), 64 * 1024)
        self.escribir("p001", "eve.json", [stats(T0 - 1)], mtime=T0)
        with mock.patch.object(self.ev, "TOPE_GZ", 128 * 1024):
            r = self.buscar("p001")
            pag = self.ev.pagina(self.q(), "p001")
        self.assertTrue(r["parcial"])
        self.assertEqual([(o[0], o[1]) for o in r["omitidos"]], [("p001", "eve.json.1.gz")])
        self.assertEqual(r["filas"], [])
        self.assertIn("<b>parcial</b>", pag)
        self.assertIn("eve.json.1.gz", pag)
        self.assertNotIn("Sin coincidencias", pag)

    def test_tope_de_bytes_parcial_y_continuar_sin_perder(self):
        """Correccion de defecto (§10.5 «consulta que llega a su limite»): con el tope de bytes
        la pagina es parcial, dice hasta que fecha y fichero llego, solo enseña lo garantizado,
        y siguiendo «continuar» se recorre todo sin repetir ni perder."""
        ls = [alerta(T0 - 3000 + i, sid=5000000 + i) if i % 10 == 0 else stats(T0 - 3000 + i) for i in range(3000)]
        self.escribir("p001", "eve.json", ls, mtime=T0)
        esperado = {5000000 + i for i in range(0, 3000, 10)}
        with mock.patch.object(self.ev, "TOPE_BYTES", 20000), mock.patch.object(self.ev, "BLOQUE", 4096),                 mock.patch.object(self.ev, "DESORDEN_US", 5000000):
            r = self.buscar("p001")
            self.assertTrue(r["parcial"])
            self.assertFalse(r["sin_garantia"])
            self.assertEqual(r["fichero_corte"], ("p001", "eve.json"))
            self.assertIsNotNone(r["hasta_us"])
            self.assertTrue(all(x["ts_us"] > r["hasta_us"] for x in r["filas"]))
            pag = self.ev.pagina(self.q(), "p001")
            self.assertIn("<b>parcial</b>", pag)
            self.assertIn("Continuar la busqueda", pag)
            self.assertNotIn("Sin coincidencias", pag)
            filas, resps = self.todas_las_paginas("p001", maximo=500)
        claves = [c for c, _ in filas]
        self.assertEqual(len(claves), len(set(claves)))
        self.assertEqual({x["ev"]["alert"]["signature_id"] for _, x in filas}, esperado)
        self.assertTrue(any(r["parcial"] for r in resps))
        self.assertFalse(any(r["sin_garantia"] for r in resps if r["parcial"]))

    def test_tope_menor_que_el_margen_de_desorden_avanza_y_avisa(self):
        """Correccion de defecto (encontrado al probar): si el tope no cubre ni el margen de
        desorden (60 s de eventos), la cota estricta no avanzaba y «continuar» repetia la misma
        pagina sin fin. Ahora avanza, lo dice, y con eventos ordenados no se pierde nada."""
        ls = [alerta(T0 - 3000 + i, sid=5000000 + i) if i % 10 == 0 else stats(T0 - 3000 + i) for i in range(3000)]
        self.escribir("p001", "eve.json", ls, mtime=T0)
        with mock.patch.object(self.ev, "TOPE_BYTES", 20000), mock.patch.object(self.ev, "BLOQUE", 4096):
            r = self.buscar("p001")
            self.assertTrue(r["parcial"])
            pag2 = self.ev.pagina(self.q(cursor=self.ev.cursor_txt(r["siguiente"])), "p001")
            self.assertIn("fuera de orden", pag2)
            filas, resps = self.todas_las_paginas("p001", maximo=500)
        self.assertTrue(any(x.get("sin_garantia") for x in resps))
        claves = [c for c, _ in filas]
        self.assertEqual(len(claves), len(set(claves)))
        self.assertEqual({x["ev"]["alert"]["signature_id"] for _, x in filas},
                         {5000000 + i for i in range(0, 3000, 10)})

    def test_tope_de_tiempo_es_parcial(self):
        """Correccion de defecto (§10.5): agotado el tiempo no se dice «sin coincidencias»."""
        self.escribir("p001", "eve.json", [alerta(T0 - 10)], mtime=T0)
        with mock.patch.object(self.ev, "TOPE_SEGUNDOS", -1):
            r = self.buscar("p001")
            pag = self.ev.pagina(self.q(), "p001")
        self.assertTrue(r["parcial"])
        self.assertIn("s de busqueda", r["motivo"])
        self.assertNotIn("Sin coincidencias", pag)
        self.assertIn("No hay coincidencias en lo que se llego a revisar", pag)


class Escapado(Base):
    def test_html_y_js_de_los_eventos_sale_escapado(self):
        """Correccion de defecto (§10.5 «HTML/JS en campos capturados»): firmas, rrname,
        user-agent... son datos del trafico y salen escapados en la lista."""
        malo = "<script>alert(1)</script>"
        self.escribir("p001", "eve.json", [
            alerta(T0 - 30, firma="ET " + malo),
            consulta_dns(T0 - 20, rrname="\"><img src=x onerror=alert(2)>.test"),
            linea({"timestamp": iso(T0 - 10), "event_type": "http", "src_ip": "10.0.0.5", "dest_ip": "192.0.2.80",
                   "proto": "TCP", "http": {"hostname": "<b>h</b>", "url": "/'onmouseover='x",
                                            "http_user_agent": malo}}),
        ], mtime=T0)
        pag = self.ev.pagina(self.q(tipo="todos"), "p001")
        self.assertEqual(len(filas_html(pag)), 3)
        self.assertNotIn("<script>alert", pag)
        self.assertNotIn("<img src=x", pag)
        self.assertNotIn("<b>h</b>", pag)
        self.assertNotIn("'onmouseover='", pag)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", pag)
        self.assertNotRegex(pag, r"\b(alert|confirm|prompt)\(\s*['\"]")   # nada de dialogos del navegador


class Retencion(Base):
    def test_disponible_desde_por_nodo(self):
        """Capacidad nueva (§9 «retencion efectiva visible en Eventos»): desde que fecha hay
        eventos en cada nodo, leyendo el rotado mas viejo (tambien .gz)."""
        self.escribir("p001", "eve.json.1.gz", [alerta(T0 - 86400 * 3)], mtime=T0 - 86400 * 2)
        self.escribir("p001", "eve.json", [alerta(T0 - 10)], mtime=T0)
        self.escribir("p002", "eve.json", [alerta(T0 - 20)], mtime=T0)
        self.assertEqual(self.ev.disponible_desde("p001") // 1000000, T0 - 86400 * 3)
        self.assertEqual(self.ev.disponible_desde("p002") // 1000000, T0 - 20)
        pag = self.ev.pagina(self.q(), self.n.TODOS)
        self.assertIn(form(T0 - 86400 * 3)[:16].replace("T", " "), pag)


if __name__ == "__main__":
    unittest.main()
