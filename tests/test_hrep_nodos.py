"""html_report.py por nodo y en «Todos» (CONTRATO-F2 §3, §10.1, §10.5; inv_C §1).

Cada prueba ejecuta el generador como SUBPROCESO (es un script, no un modulo) con PANEL, DATOS
y RUN en un directorio temporal, eventos sinteticos con el formato compacto de eve.json de
Suricata y sin red (IDS_HREP_SIN_RED=1: ni PTR ni RDAP). Datos RFC 5737 / 10.x.
El tipo de cada prueba va en su docstring.
"""
import glob
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "images", "panel", "rootfs", "usr", "local", "lib", "ids-panel")
HREP = os.path.join(LIB, "html_report.py")

try:
    import fcntl
except ImportError:
    fcntl = None

SIG_CNC = "ET MALWARE Test CnC Checkin"
SIG_DNS = "ET DNS Query to a known malware domain"


def marca(hace_s=60):
    """Marca de tiempo como la escribe Suricata (offset -0500), `hace_s` segundos atras."""
    t = datetime.now(timezone(timedelta(hours=-5))) - timedelta(seconds=hace_s)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f%z")


def alerta(src, dst, sig=SIG_CNC, sid=2000001, dport=443, in_iface="eth0", rrname=None,
           cat="A Network Trojan was detected", hace_s=60, flow_id=1001):
    ev = {"timestamp": marca(hace_s), "flow_id": flow_id, "in_iface": in_iface,
          "event_type": "alert", "src_ip": src, "src_port": 40000, "dest_ip": dst,
          "dest_port": dport, "proto": "TCP",
          "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 1,
                    "signature": sig, "category": cat, "severity": 1}}
    if rrname:
        ev["dns"] = {"query": [{"type": "query", "id": 1, "rrname": rrname, "rrtype": "A"}]}
    return ev


def consulta_dns(src, rrname, dst="192.0.2.53", hace_s=60):
    return {"timestamp": marca(hace_s), "flow_id": 2002, "in_iface": "eth0",
            "event_type": "dns", "src_ip": src, "src_port": 5353, "dest_ip": dst,
            "dest_port": 53, "proto": "UDP",
            "dns": {"type": "query", "id": 7, "rrname": rrname, "rrtype": "A", "tx_id": 0}}


def lineas(eventos):
    return "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in eventos)


class Entorno(unittest.TestCase):
    PUNTOS = {"p001": {"nombre": "Nodo A", "redes": ["10.0.0.0/24"]},
              "p002": {"nombre": "Nodo B", "redes": ["10.0.0.0/24"]}}

    def setUp(self):
        self.raiz = tempfile.mkdtemp(prefix="hrep-")
        self.addCleanup(shutil.rmtree, self.raiz, True)
        self.panel = os.path.join(self.raiz, "panel")
        self.datos = os.path.join(self.raiz, "datos")
        self.run_d = os.path.join(self.raiz, "run")
        self.lockd = os.path.join(self.raiz, "lock")
        for d in (self.panel, self.run_d, self.lockd,
                  os.path.join(self.datos, "p001"), os.path.join(self.datos, "p002")):
            os.makedirs(d)
        self.estado(self.PUNTOS)

    # --- ayudas ---------------------------------------------------------------------------
    def estado(self, puntos):
        with open(os.path.join(self.run_d, "estado.json"), "w", encoding="utf-8") as f:
            json.dump({"puntos": puntos}, f)

    def eventos(self, pid, fichero, evs):
        p = os.path.join(self.datos, pid, fichero)
        if fichero.endswith(".gz"):
            with gzip.open(p, "wt", encoding="utf-8") as f:
                f.write(lineas(evs))
        else:
            with open(p, "a", encoding="utf-8") as f:
                f.write(lineas(evs))
        return p

    def global_(self, rel, contenido):
        p = os.path.join(self.panel, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(contenido if isinstance(contenido, str) else json.dumps(contenido))

    def generar(self, *args, env_extra=None):
        env = dict(os.environ)
        env.update({"IDS_PANEL_DIR": self.panel, "IDS_DATOS": self.datos, "IDS_RUN": self.run_d,
                    "IDS_HREP_SIN_RED": "1",
                    "IDS_HREP_LOCK": os.path.join(self.lockd, "ids-hrep.lock")})
        env.update(env_extra or {})
        return subprocess.run([sys.executable, HREP] + list(args), env=env, cwd=self.raiz,
                              capture_output=True, text=True, timeout=180)

    def ok(self, *args, **kw):
        r = self.generar(*args, **kw)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r

    def salida(self, nodo, fichero):
        with open(os.path.join(self.panel, "nodos", nodo, fichero), encoding="utf-8") as f:
            return json.load(f) if fichero.endswith(".json") else f.read()

    def html(self, nodo):
        hs = glob.glob(os.path.join(self.panel, "nodos", nodo, "report-*.html"))
        self.assertEqual(len(hs), 1, hs)
        with open(hs[0], encoding="utf-8") as f:
            return f.read()

    @staticmethod
    def cpes(cuar, lista="candidatos"):
        return sorted((c["router"], c["ip"]) for c in cuar[lista])

    def arbol(self):
        """{ruta relativa: (tamano, mtime_ns)} de todo lo que hay bajo la raiz temporal."""
        r = {}
        for base, _dirs, fs in os.walk(self.raiz):
            for f in fs:
                p = os.path.join(base, f)
                st = os.stat(p)
                r[os.path.relpath(p, self.raiz)] = (st.st_size, st.st_mtime_ns)
        return r

    def tres_cnc(self, pid, src="10.0.0.5", dst="192.0.2.10", **kw):
        self.eventos(pid, "eve.json", [alerta(src, dst, hace_s=60 + i, **kw) for i in range(3)])


class PorNodo(Entorno):
    def test_misma_ip_y_flujo_en_dos_nodos_son_dos_cpe(self):
        """Capacidad nueva (§10.5 caso «misma IP y mismo flujo en dos puntos»): en --todos salen
        dos CPE p001|10.0.0.5 y p002|10.0.0.5, cada uno con SUS alertas (no se suman) y la
        etiqueta de su nodo; --nodo p001 solo ve el suyo."""
        self.tres_cnc("p001")
        self.tres_cnc("p002")
        self.ok("60", "--todos")
        cuar = self.salida("_todos", "cuarentena.json")
        self.assertEqual(self.cpes(cuar), [("p001", "10.0.0.5"), ("p002", "10.0.0.5")])
        self.assertEqual([c["alertas_cnc"] for c in cuar["candidatos"]], [3, 3])
        doc = self.html("_todos")
        self.assertIn("title='Espejo de este MikroTik'>Nodo A</span>", doc)
        self.assertIn("title='Espejo de este MikroTik'>Nodo B</span>", doc)

        self.ok("60", "--nodo", "p001")
        cuar1 = self.salida("p001", "cuarentena.json")
        self.assertEqual(self.cpes(cuar1), [("p001", "10.0.0.5")])
        self.assertEqual(cuar1["candidatos"][0]["alertas_cnc"], 3)
        self.assertEqual(self.cpes(cuar1, "top_riesgo"), [("p001", "10.0.0.5")])
        # con un solo nodo no hay chip (seria ruido), pero la identidad sigue siendo pid|ip
        self.assertNotIn("class='nodochip'", self.html("p001"))
        self.assertFalse(os.path.exists(os.path.join(self.panel, "nodos", "p002")))

    def test_ultima_alerta_por_clave(self):
        """Capacidad nueva (§10.4, pedida por N): cada entrada de candidatos y top_riesgo lleva
        `ultima`, el epoch de la última alerta de ESA clave pid|ip (no la de la misma IP en otro
        nodo), para comprobar que la evidencia es reciente antes de una cuarentena."""
        ahora = int(time.time())
        self.eventos("p001", "eve.json", [alerta("10.0.0.5", "192.0.2.10", hace_s=s) for s in (900, 600, 300)])
        self.eventos("p002", "eve.json", [alerta("10.0.0.5", "192.0.2.10", hace_s=s) for s in (3000, 2900, 2800)])
        self.ok("120", "--todos")
        cuar = self.salida("_todos", "cuarentena.json")
        for lista in ("candidatos", "top_riesgo"):
            ult = {c["router"]: c["ultima"] for c in cuar[lista]}
            self.assertEqual(set(ult), {"p001", "p002"}, lista)
            self.assertLessEqual(abs(ult["p001"] - (ahora - 300)), 5, lista)
            self.assertLessEqual(abs(ult["p002"] - (ahora - 2800)), 5, lista)

    def test_in_iface_no_decide_el_nodo(self):
        """Correccion de defecto (inv_C §1.3): el nodo sale del fichero (DATOS/p001), no de
        in_iface; un in_iface «p002» dentro de los eventos de p001 no lo cambia."""
        self.tres_cnc("p001", in_iface="p002")
        self.ok("60", "--todos")
        self.assertEqual(self.cpes(self.salida("_todos", "cuarentena.json")), [("p001", "10.0.0.5")])

    def test_cuarentena_ya_enviada_casa_por_pid_ip(self):
        """Conservacion: el boton del Top marca «En cuarentena» si la clave pid|ip esta en
        estado/cuarentena-enviados.json, y solo para ese nodo (la misma IP en otro no)."""
        self.tres_cnc("p001")
        self.tres_cnc("p002")
        self.global_("estado/cuarentena-enviados.json", {"p001|10.0.0.5": {"ts": 1}})
        self.ok("60", "--todos")
        doc = self.html("_todos")
        self.assertEqual(doc.count("&#10003; En cuarentena</span>"), 1)
        self.assertIn("qcuar(this,'p002|10.0.0.5'", doc)
        self.assertNotIn("qcuar(this,'p001|10.0.0.5'", doc)


class Cli(Entorno):
    def test_nodo_malo_o_inexistente_no_genera_nada(self):
        """Correccion de defecto / capacidad nueva (§10.1): un nodo mal formado, inexistente,
        o una linea de ordenes sin exactamente uno de --nodo/--todos sale con error y no
        escribe nada (ni amplia a «Todos»)."""
        self.tres_cnc("p001")
        casos = (["60", "--nodo", "../p001"], ["60", "--nodo", "p1"], ["60", "--nodo", "_todos"],
                 ["60", "--nodo", "p009"], ["60"], ["60", "--nodo", "p001", "--todos"])
        for args in casos:
            antes = self.arbol()
            r = self.generar(*args)
            self.assertNotEqual(r.returncode, 0, args)
            self.assertTrue(r.stderr.strip(), args)
            self.assertEqual(r.stdout.strip(), "", args)
            self.assertEqual(self.arbol(), antes, args)
        r = self.generar("60", "--nodo", "p009")
        self.assertIn("inexistente", r.stderr)

    def test_salidas_en_su_nodo_y_nada_fuera_del_panel(self):
        """Capacidad nueva (inv_C §1.2): todo lo que escribe va a PANEL/nodos/<pid>/ (o
        nodos/_todos/); DATOS queda intacto; imprime la ruta del HTML."""
        self.tres_cnc("p001")
        self.tres_cnc("p002", src="10.0.0.6")
        antes = self.arbol()
        r = self.ok("60", "--nodo", "p001")
        despues = self.arbol()
        nuevos = {k for k in despues if despues[k] != antes.get(k)}
        fuera = {k for k in nuevos
                 if not k.startswith(os.path.join("panel", "nodos", "p001") + os.sep)
                 and not k.startswith("lock" + os.sep)}
        self.assertEqual(fuera, set())
        nombres = {os.path.basename(k) for k in nuevos if not k.startswith("lock" + os.sep)}
        for f in ("cuarentena.json", "metricas.json", "destinos-malos.json", "entrantes.json"):
            self.assertIn(f, nombres)
        self.assertEqual(len([n for n in nombres if n.startswith("report-")]), 1)
        out = r.stdout.strip().splitlines()[-1]
        self.assertEqual(os.path.dirname(out), os.path.join(self.panel, "nodos", "p001"))
        self.assertTrue(os.path.isfile(out))
        m = self.salida("p001", "metricas.json")
        dia = next(iter(m["dias"].values()))
        self.assertEqual(dia["nodos"], {"p001": 3})           # solo los eventos de p001
        self.assertEqual(dia["cpes"], ["p001|10.0.0.5"])

        self.ok("60", "--todos")
        self.assertTrue(glob.glob(os.path.join(self.panel, "nodos", "_todos", "report-*.html")))
        self.assertFalse(os.path.exists(os.path.join(self.panel, "nodos", "p002")))


class Exclusiones(Entorno):
    def test_exclusion_con_nodo_solo_filtra_ese_nodo(self):
        """Correccion de defecto (inv_C §1.4 b): con claves pid|ip la exclusion de origen no
        filtraba nada; ahora compara la IP y respeta el campo `nodo` (vacio = todos)."""
        self.tres_cnc("p001")
        self.tres_cnc("p002")
        self.global_("conf/exclusiones.json", [{"tipo": "src", "ip": "10.0.0.5", "nodo": "p001"}])
        self.ok("60", "--todos")
        self.assertEqual(self.cpes(self.salida("_todos", "cuarentena.json")), [("p002", "10.0.0.5")])

        self.global_("conf/exclusiones.json", [{"tipo": "src", "ip": "10.0.0.5"}])
        self.ok("60", "--todos")
        cuar = self.salida("_todos", "cuarentena.json")
        self.assertEqual(cuar["candidatos"], [])
        self.assertEqual(cuar["top_riesgo"], [])

    def test_exclusion_de_destino_con_nodo(self):
        """Capacidad nueva (§3): una exclusion de destino con `nodo: p002` solo quita las
        alertas de p002 hacia ese destino."""
        self.tres_cnc("p001")
        self.tres_cnc("p002")
        self.global_("conf/exclusiones.json", [{"tipo": "dst", "ip": "192.0.2.10", "nodo": "p002"}])
        self.ok("60", "--todos")
        self.assertEqual(self.cpes(self.salida("_todos", "cuarentena.json")), [("p001", "10.0.0.5")])


class Dns(Entorno):
    def test_contadores_dns_casan_con_la_clave_del_cpe(self):
        """Correccion de defecto (inv_C §1.4 b): las consultas de dns.json a un dominio de los
        feeds (Camino B) se cuentan con la misma clave pid|ip que las alertas DNS (Camino A):
        1 alerta + 2 consultas = un solo CPE con 3 (antes: 2 en la IP pelada y 1 en la clave)."""
        self.global_("feeds/reputation.meta", {"generated": time.time(), "sources": {}})
        self.global_("feeds/domains.lst", "malo.example\turlhaus\n")
        self.eventos("p001", "eve.json", [alerta("10.0.0.5", "192.0.2.53", sig=SIG_DNS, sid=2000002,
                                                 dport=53, rrname="malo.example",
                                                 cat="Potentially Bad Traffic")])
        self.eventos("p001", "dns.json", [consulta_dns("10.0.0.5", "malo.example", hace_s=30 + i)
                                          for i in range(2)])
        self.ok("60", "--nodo", "p001")
        cuar = self.salida("p001", "cuarentena.json")
        self.assertEqual(self.cpes(cuar, "dns_candidatos"), [("p001", "10.0.0.5")])
        self.assertEqual(cuar["dns_candidatos"][0]["alertas_dns"], 3)
        dom = self.salida("p001", "dominios-malos.json")["dominios"]
        self.assertEqual([(d["dominio"], d["cpes"], d["ips"]) for d in dom],
                         [("malo.example", 1, [["10.0.0.5", 3]])])


class Lectura(Entorno):
    def test_lee_rotados_gz_y_salta_los_viejos(self):
        """Conservacion (inv_C §1.4 e): los rotados .gz se leen; un .gz cuyo mtime cae antes
        de la ventana se salta entero."""
        open(os.path.join(self.datos, "p001", "eve.json"), "w").close()
        self.eventos("p001", "eve.json.1.gz", [alerta("10.0.0.5", "192.0.2.10", hace_s=60 + i)
                                               for i in range(3)])
        viejo = self.eventos("p001", "eve.json.2.gz", [alerta("10.0.0.7", "192.0.2.10", hace_s=60 + i)
                                                       for i in range(3)])
        t = time.time() - 3 * 86400
        os.utime(viejo, (t, t))
        self.ok("60", "--nodo", "p001")
        self.assertEqual(self.cpes(self.salida("p001", "cuarentena.json")), [("p001", "10.0.0.5")])

    def test_mis_redes_salen_del_punto(self):
        """Capacidad nueva: sin MIS_REDES en conf/panel.conf, los abonados son las `redes`
        del punto (172.16.5.5 no es de p001 y no entra en cuarentena); con MIS_REDES manda
        el .conf."""
        self.tres_cnc("p001", src="172.16.5.5")
        self.ok("60", "--nodo", "p001")
        self.assertEqual(self.salida("p001", "cuarentena.json")["candidatos"], [])
        self.global_("conf/panel.conf", "MIS_REDES=172.16.0.0/12\n")
        self.ok("60", "--nodo", "p001")
        self.assertEqual(self.cpes(self.salida("p001", "cuarentena.json")), [("p001", "172.16.5.5")])

    def test_campos_capturados_con_html_se_escapan(self):
        """Correccion de defecto / caso §10.5 «HTML/JS en campos capturados»: una firma, un
        rrname y el nombre del punto con <script>/<img> salen escapados en el informe."""
        puntos = dict(self.PUNTOS)
        puntos["p002"] = {"nombre": "<img src=x onerror=alert(3)>", "redes": ["10.0.0.0/24"]}
        self.estado(puntos)
        self.tres_cnc("p001", sig="ET MALWARE <script>alert(1)</script> CnC")
        self.tres_cnc("p002")
        self.eventos("p001", "eve.json", [alerta("10.0.0.5", "192.0.2.53", sig=SIG_DNS, sid=2000002,
                                                 dport=53, rrname="<script>alert(2)</script>.example",
                                                 cat="Potentially Bad Traffic")])
        self.ok("60", "--todos")
        doc = self.html("_todos")
        for crudo in ("<script>alert(1)", "<script>alert(2)", "<img src=x"):
            self.assertNotIn(crudo, doc)
        self.assertIn("&lt;script&gt;alert(1)", doc)
        self.assertIn("&lt;script&gt;alert(2)", doc)
        self.assertIn("&lt;img src=x onerror=alert(3)&gt;", doc)


class Candado(Entorno):
    def test_candado_que_no_se_puede_abrir_no_sale_en_silencio(self):
        """Correccion de defecto (inv_C §1.4 a): si el candado no se puede abrir (antes /run de
        solo lectura) el generador avisa en stderr y sale con error, no con 0 en silencio."""
        self.tres_cnc("p001")
        r = self.generar("60", "--nodo", "p001",
                         env_extra={"IDS_HREP_LOCK": os.path.join(self.raiz, "no-existe", "x.lock")})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("candado", r.stderr)
        self.assertEqual(glob.glob(os.path.join(self.panel, "nodos", "*", "*")), [])

    @unittest.skipIf(fcntl is None, "flock solo en POSIX")
    def test_candado_ocupado_avisa_y_no_genera(self):
        """Capacidad nueva: con otra generacion en curso (candado tomado) no se genera y se
        avisa con un codigo propio (75), nunca 0."""
        self.tres_cnc("p001")
        lock = os.path.join(self.lockd, "ids-hrep.lock")
        with open(lock, "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            r = self.generar("60", "--nodo", "p001")
        self.assertEqual(r.returncode, 75)
        self.assertIn("en curso", r.stderr)
        self.assertEqual(glob.glob(os.path.join(self.panel, "nodos", "p001", "report-*.html")), [])


if __name__ == "__main__":
    unittest.main()
