"""Correcciones F2 del apartado Puntos (puntos_web.py): auditoria A (A-01, A-08, A-09, A-28) y
auditoria B (B-09, B-10, B-11, B-12, B-13). Tipo «correccion de defecto» (CONTRATO-F2 §10.5):
cada prueba falla en b9dcd02 y pasa con la correccion. Panel de verdad sobre un directorio
temporal (fixtures/panel2/_dash_p.py); A-01 tambien con mikrotik_init real y el MikroTik simulado.
"""
import gzip
import hashlib
import json
import os
import re
import sys
import threading
import time
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(TESTS, "fixtures", "panel2"))
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)
from _dash_p import CLAVE, PanelP  # noqa: E402

PLAN_RE = re.compile(r"<pre class=cmd id=plan-p001>(.*?)</pre>", re.S)
HUELLA_RE = re.compile(r"name=plan value='([0-9a-f]{16,64})'")


def token(texto, accion, pid="p001", valor=None):
    """Token (name=op) del formulario de la ficha que va a /puntos/<pid>/<accion>."""
    patron = r"action='/puntos/%s/%s'[^>]*>(?:(?!</form>).)*?" % (pid, accion)
    if valor:
        patron += r"name=accion value=%s>(?:(?!</form>).)*?" % valor
    m = re.search(patron + r"name=op value='([0-9a-f-]{36})'", texto, re.S)
    return m.group(1) if m else None


class _Base(unittest.TestCase):
    Panel = PanelP

    def setUp(self):
        self.p = self.Panel()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")

    def admin(self, nombre):
        d = self.p.d
        lst = d.cargar_usuarios()
        salt, h = d._hash_pw(CLAVE)
        lst.append({"user": nombre, "salt": salt, "hash": h, "role": "admin", "activo": True})
        d.guardar_usuarios(lst)
        return self.p.entrar(nombre)

    def ficha(self, pid="p001"):
        r = self.p.pedir("GET", "/puntos/%s" % pid, cookie=self.ana)
        self.assertEqual(r.status, 200)
        return r.texto


# --------------------------------------------------------------------------------------------
# A-01: la vista previa del espejo muestra el plan real
# --------------------------------------------------------------------------------------------
class _PanelEspejoReal(PanelP):
    """Con espejo_plan/espejo_aplicar REALES del nucleo, mikrotik_init real y un router simulado."""

    def _sustitutos(self):
        reales = {k: getattr(self.d, k) for k in ("espejo_plan", "espejo_aplicar", "espejo_pausar",
                                                  "espejo_retirar")}
        super()._sustitutos()
        for k, v in reales.items():
            setattr(self.d, k, v)
        import _mikrotik_simulado as sim
        self.router = sim.router_isp()
        self.d.mk_conectar = lambda dd, timeout=6: self.router.conexion()


class EspejoReal(_Base):
    Panel = _PanelEspejoReal

    def setUp(self):
        super().setUp()
        self.p.d.guardar_routers([{"id": "p001", "USER": "ids-api", "PASS": "clave-api", "ENABLED": "1"}])

    def test_a01_vista_previa_con_ordenes_y_aplica_lo_visto(self):
        """A-01: la vista previa enseña las ordenes reales (`terminal` de mikrotik_init), el boton
        Aplicar aparece, la huella de un plan vacio no aplica nada y la del plan visto aplica
        exactamente esas ordenes."""
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "plan"}, cookie=self.ana)
        self.assertEqual(r.status, 200)
        pre = PLAN_RE.search(r.texto)
        self.assertIsNotNone(pre, "la vista previa no lleva las ordenes")
        ordenes = [x for x in pre.group(1).splitlines() if x.strip()]
        self.assertEqual(len(ordenes), 6)
        self.assertTrue(any("sniff-tzsp" in x for x in ordenes))
        self.assertNotIn("accept", pre.group(1).replace("fasttrack-connection", ""))
        self.assertIn("Aplicar este plan", r.texto)
        huella = HUELLA_RE.search(r.texto).group(1)
        n0 = len(self.p.router.escrituras)
        vacia = hashlib.sha256(b"").hexdigest()[:32]
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "aplicar", "plan": vacia}, cookie=self.ana)
        self.assertEqual(r.status, 409)
        self.assertEqual(len(self.p.router.escrituras), n0)
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "aplicar", "plan": huella}, cookie=self.ana)
        self.assertEqual(r.status, 200, r.texto[-600:])
        self.assertEqual(len(self.p.router.escrituras) - n0, 6)
        # ya aplicado: el plan siguiente esta vacio y no ofrece Aplicar
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "plan"}, cookie=self.ana)
        self.assertNotIn("Aplicar este plan", r.texto)


class EspejoPlanes(_Base):
    def poner_plan(self, res):
        self.p.d.espejo_plan = lambda pid: (self.p.espejo.append(("plan", pid)) or dict(res))

    def test_a01_bloqueos_impiden_aplicar(self):
        """A-01: con `bloqueos` el plan se enseña con los bloqueos, sin boton, y aplicar no se hace."""
        self.poner_plan({"ok": True, "mensaje": "vista previa", "lineas": [],
                         "terminal": ["/ip firewall mangle add chain=forward action=sniff-tzsp"],
                         "avisos": [], "bloqueos": ["la lista ids-vigilados ya existe con otras entradas"]})
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "plan"}, cookie=self.ana)
        self.assertIn("ya existe con otras entradas", r.texto)
        self.assertIn("sniff-tzsp", r.texto)
        self.assertNotIn("Aplicar este plan", r.texto)
        h = hashlib.sha256(b"/ip firewall mangle add chain=forward action=sniff-tzsp").hexdigest()[:32]
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "aplicar", "plan": h}, cookie=self.ana)
        self.assertEqual(r.status, 409)
        self.assertNotIn(("aplicar", "p001"), self.p.espejo)

    def test_a01_fasttrack_y_avisos_visibles(self):
        """A-01: los cambios del fasttrack y los avisos del plan se ven en la vista previa."""
        self.poner_plan({"ok": True, "terminal": ["/ip firewall filter set *6 src-address-list=!ids-vigilados"],
                         "avisos": ["hay otra regla sniff-tzsp ajena"],
                         "fasttrack": [{".id": "*6", "accion": "excluir", "que": "excluir ids-vigilados del fasttrack *6"}]})
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "plan"}, cookie=self.ana)
        self.assertIn("excluir ids-vigilados del fasttrack *6", r.texto)
        self.assertIn("hay otra regla sniff-tzsp ajena", r.texto)
        self.assertIn("Aplicar este plan", r.texto)

    def test_a01_accept_en_los_cambios_se_rechaza(self):
        """A-01: un `accept` en los cambios estructurados (no solo en el texto) tambien se rechaza."""
        self.poner_plan({"ok": True, "terminal": ["/ip firewall filter add chain=forward"],
                         "cambios": [{"orden": "/ip/firewall/filter/add", "args": ["=chain=forward", "=action=accept"]}]})
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "plan"}, cookie=self.ana)
        self.assertEqual(r.status, 500)
        self.assertNotIn("Aplicar este plan", r.texto)

    def test_a01_huella_del_nucleo_va_a_aplicar(self):
        """A-01 + A-21(1): si el nucleo da la huella de su plan, el formulario la lleva y se le pasa a
        espejo_aplicar(pid, huella=...) para que aplique ese plan y no otro."""
        self.poner_plan({"ok": True, "terminal": ["/ip firewall mangle add x"], "huella": "c0ffee" * 6})
        visto = []
        self.p.d.espejo_aplicar = lambda pid, usuario=None, huella=None: (
            visto.append((pid, huella)) or {"ok": True, "mensaje": "aplicado", "lineas": ["hecho: x"]})
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "plan"}, cookie=self.ana)
        self.assertEqual(HUELLA_RE.search(r.texto).group(1), "c0ffee" * 6)
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "aplicar", "plan": "c0ffee" * 6}, cookie=self.ana)
        self.assertEqual(r.status, 200)
        self.assertEqual(visto, [("p001", "c0ffee" * 6)])


# --------------------------------------------------------------------------------------------
# A-08: token de un solo uso en todas las ordenes de la ficha
# --------------------------------------------------------------------------------------------
class TokensFicha(_Base):
    def test_a08_ordenes_de_cola_no_se_repiten(self):
        """A-08: arrancar/parar/reiniciar/regenerar/ajustar/borrar llevan token; el mismo formulario
        enviado dos veces es UNA orden en el orquestador y lleva a la misma operacion."""
        texto = self.ficha()
        casos = (("arrancar", {}, "punto.arrancar"), ("parar", {}, "punto.parar"),
                 ("reiniciar", {}, "punto.reiniciar"), ("regenerar", {}, "punto.vpn.regenerar"),
                 ("ajustar", {"redes": "10.7.0.0/24"}, "punto.ajustar"),
                 ("borrar", {"confirmar": "norte"}, "punto.borrar"))
        vistos = set()
        for acc, form, orden in casos:
            tok = token(texto, acc)
            self.assertIsNotNone(tok, "el formulario %s no lleva token" % acc)
            vistos.add(tok)
            form = dict(form, op=tok)
            r1 = self.p.pedir("POST", "/puntos/p001/" + acc, form, cookie=self.ana)
            r2 = self.p.pedir("POST", "/puntos/p001/" + acc, form, cookie=self.ana)
            self.assertEqual((r1.status, r2.status), (303, 303), acc)
            self.assertEqual(r1.cab("Location"), "/operaciones/%s" % tok)
            self.assertEqual(r2.cab("Location"), r1.cab("Location"))
            self.assertEqual(len(self.p.orq.ordenes(orden)), 1, acc)
            self.assertEqual(self.p.orq.ordenes(orden)[0]["op_id"], tok)
        self.assertEqual(len(vistos), len(casos), "cada formulario lleva su propio token")

    def test_a08_token_de_otra_orden_no_vale(self):
        """A-08: el token de un formulario no sirve para otra orden u otro punto (409, nada se pide)."""
        tok = token(self.ficha(), "reiniciar")
        self.assertEqual(self.p.pedir("POST", "/puntos/p001/reiniciar", {"op": tok}, cookie=self.ana).status, 303)
        r = self.p.pedir("POST", "/puntos/p002/parar", {"op": tok}, cookie=self.ana)
        self.assertEqual(r.status, 409)
        self.assertEqual(self.p.orq.ordenes("punto.parar"), [])

    def test_a08_espejo_y_api_un_solo_uso(self):
        """A-08: aplicar, pausar y retirar el espejo y guardar la API con el mismo token se hacen
        una sola vez; el reintento da el resultado de la primera."""
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "plan"}, cookie=self.ana)
        huella = HUELLA_RE.search(r.texto).group(1)
        tok = token(r.texto, "espejo", valor="aplicar")
        self.assertIsNotNone(tok)
        for _ in range(2):
            r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "aplicar", "plan": huella, "op": tok},
                             cookie=self.ana)
            self.assertEqual(r.status, 200)
        self.assertEqual(self.p.espejo.count(("aplicar", "p001")), 1)
        texto = self.ficha()
        for acc in ("pausar", "retirar"):
            tok = token(texto, "espejo", valor=acc)
            self.assertIsNotNone(tok, acc)
            for _ in range(2):
                self.p.pedir("POST", "/puntos/p001/espejo", {"accion": acc, "op": tok}, cookie=self.ana)
            self.assertEqual(self.p.espejo.count((acc, "p001")), 1, acc)
        tok = token(texto, "api", valor="guardar")
        self.assertIsNotNone(tok)
        guardados = []
        real = self.p.d.guardar_routers
        self.p.d.guardar_routers = lambda lst: guardados.append(1) or real(lst)
        for _ in range(2):
            r = self.p.pedir("POST", "/puntos/p001/api", {"accion": "guardar", "user": "ids-api", "op": tok},
                             cookie=self.ana)
            self.assertEqual(r.status, 200)
        self.assertEqual(len(guardados), 1)

    def test_a08_doble_clic_simultaneo_en_aplicar(self):
        """A-08 (§10.5 «doble clic»): dos POST a la vez con el mismo formulario aplican una vez."""
        lento = threading.Event()

        def aplicar(pid):
            self.p.espejo.append(("aplicar", pid))
            lento.wait(0.5)
            return {"ok": True, "mensaje": "aplicado"}
        self.p.d.espejo_aplicar = aplicar
        r = self.p.pedir("POST", "/puntos/p001/espejo", {"accion": "plan"}, cookie=self.ana)
        form = {"accion": "aplicar", "plan": HUELLA_RE.search(r.texto).group(1),
                "op": token(r.texto, "espejo", valor="aplicar")}
        st = []
        hilos = [threading.Thread(target=lambda: st.append(
            self.p.pedir("POST", "/puntos/p001/espejo", form, cookie=self.ana).status)) for _ in range(2)]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join(10)
        lento.set()
        self.assertEqual(self.p.espejo.count(("aplicar", "p001")), 1)
        self.assertEqual(sorted(st), [200, 409])


# --------------------------------------------------------------------------------------------
# A-09: la limpieza de la baja no depende de quien abra la operacion
# --------------------------------------------------------------------------------------------
class BajaSinVista(_Base):
    def setUp(self):
        super().setUp()
        d = self.p.d
        d.guardar_routers([{"id": "p001", "USER": "ids-api", "PASS": "secreta-1", "ENABLED": "1"},
                           {"id": "p002", "USER": "ids-api", "PASS": "secreta-2", "ENABLED": "1"}])
        d.guardar_enviados({"p001|10.0.0.5": {"cuando": 1}, "p002|10.0.0.5": {"cuando": 1}}, d.MK_SENT)
        for pid in ("p001", "p002"):
            self.p.cuarentena(pid, [])

    def quitar_del_estado(self, pid, ts=None):
        ruta = os.path.join(self.p.tmp.name, "run", "estado.json")
        with open(ruta, encoding="utf-8") as f:
            est = json.load(f)
        est["puntos"].pop(pid, None)
        est["ts"] = int(ts if ts is not None else time.time())
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(est, f)
        t = time.time() + 5 + (0 if ts is None else ts - time.time())
        os.utime(ruta, (t, t))

    def restos(self, pid):
        d = self.p.d
        with open(d.ROUTERS_CONF, encoding="utf-8") as f:
            g = json.load(f)["routers"]
        return {"nodos": os.path.isdir(os.path.join(self.p.nodos.NODOS, pid)), "router": pid in g,
                "enviados": any(k.startswith(pid + "|") for k in d.cargar_enviados(d.MK_SENT))}

    NADA = {"nodos": False, "router": False, "enviados": False}
    TODO = {"nodos": True, "router": True, "enviados": True}

    def pedir_baja(self):
        tok = token(self.ficha(), "borrar")
        r = self.p.pedir("POST", "/puntos/p001/borrar", {"confirmar": "norte", "op": tok}, cookie=self.ana)
        self.assertEqual(r.status, 303)
        return tok

    def test_a09_a_quien_pidio_no_vuelve(self):
        """A-09 caso A: quien pidio la baja no vuelve; otro admin mira Puntos y el panel se limpia."""
        self.pedir_baja()
        self.quitar_del_estado("p001")
        bea = self.admin("bea")
        self.assertEqual(self.p.pedir("GET", "/puntos", cookie=bea).status, 200)
        self.assertEqual(self.restos("p001"), self.NADA)
        self.assertEqual(self.restos("p002"), self.TODO)

    def test_a09_b_otro_admin_abre_la_operacion(self):
        """A-09 caso B: otro admin abre la operacion (404, no es suya) y aun asi se limpia."""
        op = self.pedir_baja()
        self.quitar_del_estado("p001")
        bea = self.admin("bea")
        self.assertEqual(self.p.pedir("GET", "/operaciones/" + op, cookie=bea).status, 404)
        self.assertEqual(self.restos("p001"), self.NADA)
        self.assertEqual(self.restos("p002"), self.TODO)

    def test_a09_c_orquestador_reiniciado(self):
        """A-09 caso C: el orquestador se reinicio y no conoce la operacion (NO_EXISTE); el punto ya
        no esta en estado.json: se limpia igual."""
        op = self.pedir_baja()
        self.p.orq.ops.clear()
        self.quitar_del_estado("p001")
        r = self.p.pedir("GET", "/operaciones/" + op, cookie=self.ana)
        self.assertIn("no conoce", r.texto)
        self.assertEqual(self.restos("p001"), self.NADA)
        self.assertEqual(self.restos("p002"), self.TODO)

    def test_a09_baja_por_la_cli(self):
        """A-09, baja por la CLI (sin operacion del panel): se limpia cuando el punto falta de
        estado.json en dos lecturas separadas (no por un estado suelto)."""
        pw = self.p.pw
        ahora = time.time()
        self.quitar_del_estado("p002", ts=ahora)
        pw.barrer_bajas(self.p.d, ahora=ahora)
        self.assertEqual(self.restos("p002"), self.TODO, "una sola lectura no basta")
        self.quitar_del_estado("p002", ts=ahora + 90)
        pw.barrer_bajas(self.p.d, ahora=ahora + 90)
        self.assertEqual(self.restos("p002"), self.NADA)
        self.assertEqual(self.restos("p001"), self.TODO)

    def test_a09_estado_viejo_no_borra(self):
        """A-09: sin confirmacion del orquestador (no conoce la operacion) y con estado.json viejo
        (orquestador parado) no se borra nada aunque falte el punto."""
        self.pedir_baja()
        self.p.orq.ops.clear()
        self.quitar_del_estado("p001", ts=time.time() - 3600)
        self.p.pw.barrer_bajas(self.p.d)
        self.assertEqual(self.restos("p001")["router"], True)


# --------------------------------------------------------------------------------------------
# B-09 / B-10: lectura de ficheros de eventos en Puntos
# --------------------------------------------------------------------------------------------
class FicherosDeEventos(_Base):
    def eve(self, pid, texto, nombre="eve.json", mtime=None):
        p = os.path.join(self.p.tmp.name, "datos", pid, nombre)
        modo = "wb" if isinstance(texto, bytes) else "w"
        with open(p, modo) as f:
            f.write(texto)
        if mtime:
            os.utime(p, (mtime, mtime))
        return p

    @staticmethod
    def alerta(t):
        iso = time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(t))
        return '{"timestamp":"%s","event_type":"alert","src_ip":"10.0.0.5"}\n' % iso

    def test_b10_linea_json_que_no_es_objeto(self):
        """B-10/EP-04: una linea JSON que no es objeto (o tzsp.json que no es objeto) no da 500."""
        ahora = time.time()
        self.eve("p001", self.alerta(ahora - 60) + '[{"event_type":"alert","timestamp":"x"}]\n'
                 + "[" * 5000 + '"event_type":"alert"' + "]" * 5000 + "\n")
        with open(os.path.join(self.p.tmp.name, "run", "p001", "tzsp.json"), "w", encoding="utf-8") as f:
            f.write("[1, 2]")
        r = self.p.pedir("GET", "/puntos", cookie=self.ana)
        self.assertEqual(r.status, 200)
        self.assertIn("/puntos/p002", r.texto)
        self.assertEqual(self.p.pedir("GET", "/puntos/p001", cookie=self.ana).status, 200)
        self.assertEqual(self.p.pw.alertas_24h("p001"), (1, True))

    def test_b09_eve_cuya_ruta_real_sale_del_punto(self):
        """B-09/EP-03: un eve.json cuya ruta real esta fuera de datos/<pid> no se lee (0, True).
        (En Windows no hay enlaces sin privilegio: se simula la resolucion con realpath.)"""
        ahora = time.time()
        ruta = self.eve("p001", self.alerta(ahora - 60) * 3)
        fuera = os.path.join(self.p.tmp.name, "fuera-eve.json")
        real = os.path.realpath

        def rp(x, *a, **k):
            return fuera if os.path.normcase(os.path.abspath(x)) == os.path.normcase(ruta) else real(x, *a, **k)
        with mock.patch("os.path.realpath", rp):
            self.assertEqual(self.p.pw.alertas_24h("p001", ahora + 1), (0, True))
        self.assertEqual(self.p.pw.alertas_24h("p001", ahora + 2), (3, True))

    def test_b09_tope_real_de_bytes(self):
        """B-09/EP-03: la lectura de alertas_24h se para en TOPE_ALERTAS_BYTES aunque el fichero
        no termine (lo que daria un enlace a /dev/zero) y dice que no es completa."""
        ahora = time.time()
        self.eve("p001", self.alerta(ahora - 60))
        linea = self.alerta(ahora - 30).encode()

        class SinFin:
            leido = 0

            def __init__(self, *a):
                pass

            def fileno(self):
                raise OSError("sin descriptor")

            def seek(self, *a):
                return 0

            def readline(self, n=-1):
                SinFin.leido += len(linea)
                if SinFin.leido > 64 * 1024 * 1024:
                    raise AssertionError("lectura sin tope")
                return linea

            def read(self, n=-1):
                return self.readline()

            def __iter__(self):
                return self

            def __next__(self):
                return self.readline()

            def close(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        with mock.patch.object(self.p.pw, "TOPE_ALERTAS_BYTES", 256 * 1024), \
                mock.patch.object(self.p.pw.eventos_web, "_abrir", lambda real, st: SinFin()):
            n, completo = self.p.pw.alertas_24h("p001", ahora)
        self.assertFalse(completo)
        self.assertLess(SinFin.leido, 2 * 1024 * 1024)
        self.assertGreater(n, 0)

    def test_b09_retencion_no_sigue_enlaces(self):
        """B-09/EP-03: la retencion por ficheros no toma la marca de un fichero cuya ruta real
        esta fuera del punto (simulado con realpath)."""
        ahora = time.time()
        self.eve("p001", self.alerta(ahora - 60), mtime=ahora)
        viejo = self.eve("p001", '{"timestamp":"2001-01-01T00:00:00.000000+0000","event_type":"alert"}\n',
                         nombre="eve.json.1", mtime=ahora - 86400)
        fuera = os.path.join(self.p.tmp.name, "fuera.json")
        real = os.path.realpath

        def rp(x, *a, **k):
            return fuera if os.path.normcase(os.path.abspath(x)) == os.path.normcase(viejo) else real(x, *a, **k)
        self.p.pw._RET.clear()
        with mock.patch("os.path.realpath", rp):
            ret = self.p.pw.retencion("p001", {})
        self.assertGreater(ret["desde"], ahora - 2 * 86400)

    def test_b09_retencion_con_gz_de_miembros_vacios(self):
        """B-09/EP-03: un .gz de miembros vacios como fichero mas viejo no cuesta segundos."""
        ahora = time.time()
        self.eve("p001", self.alerta(ahora - 60), mtime=ahora)
        self.eve("p001", gzip.compress(b"", mtime=0) * 300000, nombre="eve.json.1.gz", mtime=ahora - 86400)
        self.p.pw._RET.clear()
        t = time.monotonic()
        ret = self.p.pw.retencion("p001", {})
        self.assertLess(time.monotonic() - t, 1.0)
        self.assertTrue(ret["desde"])


# --------------------------------------------------------------------------------------------
# B-11 / B-12: la pagina con la clave VPN de una sola vez
# --------------------------------------------------------------------------------------------
class ClaveUnaVez(_Base):
    def crear(self):
        r = self.p.pedir("GET", "/puntos/nuevo", cookie=self.ana)
        tok = re.search(r"name=op value='([0-9a-f-]{36})'", r.texto).group(1)
        self.p.pedir("POST", "/puntos/nuevo", {"op": tok, "nombre": "este", "redes": "10.1.0.0/24"}, cookie=self.ana)
        return tok

    def test_b11_no_store(self):
        """B-11/EP-05: la pagina de la operacion (con la clave VPN) no se guarda en caches."""
        tok = self.crear()
        r = self.p.pedir("GET", "/operaciones/" + tok, cookie=self.ana)
        self.assertIn("CLAVE-VPN-UNICA-7Q2", r.texto)
        self.assertEqual(r.cab("Cache-Control"), "no-store")
        self.assertEqual(r.cab("X-Frame-Options"), "DENY")
        self.assertEqual(r.cab("X-Content-Type-Options"), "nosniff")

    def test_b12_quien_recibe_la_clave_la_ensena(self):
        """B-12/EP-06: si la peticion que recibio la clave pierde la carrera de `terminar` contra
        otra (autorrecarga + F5), la ensena igualmente (el orquestador ya la entrego solo a ella)."""
        tok = self.crear()
        ops = self.p.pw.ops()
        real = ops.terminar

        def terminar_perdida(op_id, **k):
            real(op_id, codigo=k.get("codigo"), mensaje=k.get("mensaje"))   # la otra peticion la cerro
            return False
        with mock.patch.object(ops, "terminar", terminar_perdida):
            r = self.p.pedir("GET", "/operaciones/" + tok, cookie=self.ana)
        self.assertIn("CLAVE-VPN-UNICA-7Q2", r.texto)


# --------------------------------------------------------------------------------------------
# A-28 / B-13: validaciones
# --------------------------------------------------------------------------------------------
class Validaciones(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)

    def test_a28_prefijos_demasiado_anchos(self):
        """A-28: /1 a /7 no son redes de abonados (como el minimo /8 del panel)."""
        pw = self.p.pw
        for r in ("10.0.0.0/7", "0.0.0.0/1", "128.0.0.0/4"):
            self.assertIsNone(pw.validar_redes(r)[0], r)
        self.assertEqual(pw.validar_redes("10.0.0.0/8")[0], ["10.0.0.0/8"])

    def test_b13_ruta_con_digitos_raros(self):
        """B-13/EP-07 (lado Puntos): la ruta solo admite p y tres digitos ASCII, sin salto final."""
        pw = self.p.pw
        self.assertIsNone(pw.RE_RUTA_PID.match("/puntos/p١٢٣"))
        self.assertIsNone(pw.RE_RUTA_PID.match("/puntos/p001\n"))
        self.assertIsNone(pw.RE_RUTA_OP.match("/operaciones/%s\n" % ("0" * 8 + "-0000-0000-0000-" + "0" * 12)))
        self.assertEqual(pw.RE_RUTA_PID.match("/puntos/p001/espejo").groups(), ("p001", "espejo"))


if __name__ == "__main__":
    unittest.main()
