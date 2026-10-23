"""Telegram por punto (bloque D, 2026-10-23): cada punto puede tener su chat propio (el del cliente)
con el MISMO bot del panel; lo de ese punto le llega a su chat ademas de al chat global (el del
administrador), que sigue recibiendo todo.

Pruebas de COMPORTAMIENTO, sin red: `urllib.request.urlopen` se sustituye por un doble que apunta
(chat, texto) de cada sendMessage (en informe_diario.py, dentro del subproceso, igual).
- Nucleo (dashboard.py): chat_valido, guardar/quitar, fichero roto, chat de un pid sin chat.
- Aislamiento: el aviso de cuarentena, el del sensor y el envio masivo de un punto llegan al global
  y al chat de ESE punto, nunca al de otro, y el texto del chat de un punto no lleva nada de otro
  (MARCAS_AJENAS de tests/test_panel_alcance.py). Sin token no sale nada.
- Ficha (puntos_web.py): seccion «Avisos por Telegram» y POST /puntos/<pid>/telegram con el
  permiso puntos.telegram, solo en sus puntos.
- Informe diario: cada chat de punto recibe solo su seccion; el global, el completo.

Montaje de tests/test_panel_alcance.py (A.Base: p001 «kappanorte», p002 «omegasur» = el punto
AJENO, p003 «sigmaeste»; olga operador [p001], luis lectura [p001]) y de tests/test_informe_diario.py.

Tipo: capacidad nueva (todas). Datos RFC 5737 / 10.x.
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from unittest import mock

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
import test_panel_alcance as A  # noqa: E402  (pone fixtures/panel2 en sys.path)
import test_informe_diario as INF  # noqa: E402
import _dash  # noqa: E402

# Contrato de la ficha (Agente 2): si cambia un nombre, se cuadra aqui
RUTA_TG = "/puntos/%s/telegram"      # POST con accion=guardar|probar|quitar
CAMPO_CHAT = "chat"                  # campo del formulario con el Chat ID
SECCION_TG = "id=telegram"           # la seccion «Avisos por Telegram» de la ficha

TOKEN = INF.TOKEN
CHAT_GLOBAL = "-1009000000001"       # el del administrador (report.conf)
CHAT_P1 = "-1001111111111"           # el del cliente de p001
CHAT_P2 = "@canal_omegasur"          # el del cliente de p002 (el ajeno)
CHAT_P3 = "-1003333333333"


class Telegrama:
    """Doble de urllib.request.urlopen: apunta (chat, texto) de cada sendMessage; nada sale a la red."""

    def __init__(self):
        self.enviados = []
        self.lock = threading.Lock()

    def __call__(self, url, data=None, timeout=None, **_kw):
        u = url if isinstance(url, str) else getattr(url, "full_url", "")
        if "api.telegram.org" not in u:
            raise OSError("red cortada en la prueba")
        q = urllib.parse.parse_qs((data or b"").decode("utf-8"))
        with self.lock:
            self.enviados.append((q.get("chat_id", [""])[0], q.get("text", [""])[0]))
        return io.BytesIO(b'{"ok": true, "result": {}}')

    def a(self, chat):
        with self.lock:
            return [t for c, t in self.enviados if c == chat]

    def chats(self):
        with self.lock:
            return {c for c, _t in self.enviados}

    def limpiar(self):
        with self.lock:
            self.enviados.clear()


def sin_marcas(caso, textos, marcas, donde):
    for t in textos:
        for m in marcas:
            if m in t:
                caso.fail("%s: %r en un texto que no es de ese punto: %r" % (donde, m, t[:300]))


# ============================================================================================
# Nucleo (dashboard.py, sin servidor)
# ============================================================================================
class _Arbol(unittest.TestCase):
    """dashboard.py sobre un arbol temporal con p001/p002/p003 (los nombres de A) y urlopen falso."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        pts = {pid: _dash.punto(nom, i) for i, (pid, nom) in enumerate(sorted(A.NOMBRES.items()), 1)}
        self.a = _dash.Arbol(self.tmp.name, puntos=pts)
        self.d = _dash.cargar(self.a)
        self.n = self.d.nodos
        self.n.asegurar_dirs()
        self.tg = Telegrama()
        p = mock.patch.object(urllib.request, "urlopen", self.tg)
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        self.n.quitar_nodo()
        self.n.quitar_alcance()
        _dash.restaurar()
        self.tmp.cleanup()

    def fichero(self):
        try:
            with open(self.d.TELEGRAM_PUNTOS_FILE, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    def crudo(self):
        try:
            with open(self.d.TELEGRAM_PUNTOS_FILE, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None


class Nucleo(_Arbol):
    def test_chat_valido(self):
        """Capacidad nueva: un Chat ID es un numero (los grupos con -), o @canal; nada mas."""
        buenos = ("123456789", "-1001234567890", "-42", "@canal_cliente", "@Abcde", "1" * 20)
        malos = ("", " ", " 123", "123 ", "12 34", "123\n", "-", "--100", "+100", "-100abc", "1" * 21,
                 "@", "@abc", "@1canal", "@_canal", "@canal-cliente", "@" + "a" * 33, "canal",
                 "123;rm -rf /", "123&text=hola", "<script>", "@canal\n", "123\x00", "-100 123",
                 None, 123, -100, b"123", ["123"])
        for c in buenos:
            with self.subTest(chat=c):
                self.assertTrue(self.d.chat_valido(c))
        for c in malos:
            with self.subTest(chat=c):
                self.assertFalse(self.d.chat_valido(c))

    def test_chat_valido_solo_digitos_ascii(self):
        """Capacidad nueva: los digitos de otros alfabetos (\\d de Python los acepta sin re.ASCII)
        no son un Chat ID: Telegram los rechaza y el fichero guardaria basura."""
        for c in ("１２３", "-100١٢٣", "१२"):
            with self.subTest(chat=c):
                self.assertFalse(self.d.chat_valido(c))

    def test_guardar_y_quitar(self):
        """Capacidad nueva: guardar pone el chat de ESE punto sin tocar los demas; quitar (chat
        vacio o None) lo borra; repetir el quitar no cambia nada. Fichero 0600."""
        d = self.d
        self.assertIsNone(self.fichero())
        self.assertEqual(d.guardar_telegram_punto("p001", CHAT_P1), CHAT_P1)
        self.assertEqual(d.guardar_telegram_punto("p002", CHAT_P2), CHAT_P2)
        self.assertEqual(self.fichero(), {"p001": CHAT_P1, "p002": CHAT_P2})
        if os.name == "posix":
            self.assertEqual(os.stat(d.TELEGRAM_PUNTOS_FILE).st_mode & 0o777, 0o600)
        self.assertEqual(d.guardar_telegram_punto("p001", CHAT_P3), CHAT_P3)
        self.assertEqual(self.fichero(), {"p001": CHAT_P3, "p002": CHAT_P2})
        self.assertEqual(d.guardar_telegram_punto("p001", ""), "")
        self.assertEqual(self.fichero(), {"p002": CHAT_P2})
        self.assertEqual(d.guardar_telegram_punto("p001", None), "")
        self.assertEqual(self.fichero(), {"p002": CHAT_P2})
        self.assertEqual(d.telegram_chat_de("p002"), CHAT_P2)
        self.assertEqual(d.telegram_chat_de("p001"), "")

    def test_guardar_rechaza_chat_o_pid_malos(self):
        """Capacidad nueva: un chat no valido es ValueError y no se escribe; un pid mal formado,
        inexistente o fuera del alcance de la peticion tampoco escribe."""
        d, n = self.d, self.n
        d.guardar_telegram_punto("p001", CHAT_P1)
        antes = self.crudo()
        for malo in ("123;rm -rf /", "@abc", "12 34", "<b>x</b>"):
            with self.subTest(chat=malo):
                with self.assertRaises(ValueError):
                    d.guardar_telegram_punto("p001", malo)
        with self.assertRaises(n.NodoInvalido):
            d.guardar_telegram_punto("../p001", CHAT_P2)
        with self.assertRaises(n.NodoInexistente):
            d.guardar_telegram_punto("p009", CHAT_P2)
        n.poner_alcance(["p001"])
        try:
            with self.assertRaises(n.NodoInexistente):
                d.guardar_telegram_punto("p002", CHAT_P2)
        finally:
            n.quitar_alcance()
        self.assertEqual(self.crudo(), antes)

    def test_fichero_roto_es_vacio(self):
        """Capacidad nueva: un fichero ilegible o que no es un objeto = ningun chat (y nada sale);
        de uno con basura solo quedan las entradas bien formadas. Guardar sobre uno roto no lo pisa."""
        d = self.d
        os.makedirs(os.path.dirname(d.TELEGRAM_PUNTOS_FILE), exist_ok=True)
        for crudo in ('{"p001": "-100', "[1, 2]", '"-100123"', "", "null"):
            with self.subTest(crudo=crudo):
                with open(d.TELEGRAM_PUNTOS_FILE, "w", encoding="utf-8") as f:
                    f.write(crudo)
                self.assertEqual(d.cargar_telegram_puntos(), {})
                self.assertEqual(d.telegram_chat_de("p001"), "")
                self.assertFalse(d.enviar_telegram_punto("p001", "hola"))
        with open(d.TELEGRAM_PUNTOS_FILE, "w", encoding="utf-8") as f:
            json.dump({"p001": "@canal_bueno", "p002": "basura x", "../p003": "123", "p003": 5,
                       "P003": "123"}, f)
        self.assertEqual(d.cargar_telegram_puntos(), {"p001": "@canal_bueno"})
        # (auditoría D, B4) guardar sobre un fichero roto NO lo pisa: se perderían los chats de los
        # demás puntos; se niega y el fichero queda como estaba
        with open(d.TELEGRAM_PUNTOS_FILE, "w", encoding="utf-8") as f:
            f.write("{roto")
        with self.assertRaises(OSError):
            d.guardar_telegram_punto("p003", CHAT_P3)
        with open(d.TELEGRAM_PUNTOS_FILE, encoding="utf-8") as f:
            self.assertEqual(f.read(), "{roto")
        self.assertEqual(self.tg.enviados, [])

    def test_chat_de_un_pid_sin_chat_es_de_nadie(self):
        """Capacidad nueva: el chat de p001 no lo hereda ningun otro pid (ni uno mal formado, ni en
        mayusculas, ni uno que no existe): telegram_chat_de da "" y enviar_telegram_punto no manda."""
        d = self.d
        d.telegram_set(chat=CHAT_GLOBAL)
        d.guardar_telegram_punto("p001", CHAT_P1)
        self.assertEqual(d.telegram_chat_de("p001"), CHAT_P1)
        for pid in ("p002", "p003", "p009", "", None, "P001", "../p001", "p001\n", "p001 ", "_todos"):
            with self.subTest(pid=pid):
                self.assertEqual(d.telegram_chat_de(pid), "")
                self.assertFalse(d.enviar_telegram_punto(pid, "hola"))
        self.assertEqual(self.tg.enviados, [])


@unittest.skipUnless(INF.HAY_CRYPTO, "falta cryptography (python3-cryptography en la imagen)")
class AvisoCuarentena(_Arbol):
    """notificar_cuarentena real (no el doble de PanelP), con el token cifrado de verdad."""

    def setUp(self):
        super().setUp()
        d, ahora = self.d, int(time.time())
        mapa = {"p001|" + A.IP_PROPIA: {"nombre": "ABONADO-PROPIO-KQ", "mac": "02:00:00:00:00:01",
                                        "tipo": "PPPoE", "router": "p001"},
                "p002|" + A.IP_AJENA: {"nombre": A.ABON_AJENO, "mac": "02:00:00:00:00:02",
                                       "tipo": "PPPoE", "router": "p002"}}
        with open(d.ABONADOS_FILE, "w", encoding="utf-8") as f:
            json.dump({"ts": ahora, "mapa": mapa}, f)

        def cand(ip, pid, firma, evid):
            return {"ip": ip, "router": pid, "riesgo": 80, "banda": "ALTO", "confianza": "alta",
                    "ultima": ahora - 60, "firma": "ET MALWARE " + firma, "evidencias": [evid]}
        self.a.salida("p001", "cuarentena.json", {"ventana_min": 1440, "dns_candidatos": [], "candidatos": [
            cand(A.IP_PROPIA, "p001", "FIRMA-PROPIA-KQ", "EVIDENCIA-PROPIA-KQ")]})
        self.a.salida("p002", "cuarentena.json", {"ventana_min": 1440, "dns_candidatos": [], "candidatos": [
            cand(A.IP_AJENA, "p002", A.FIRMA_AJENA, A.EVID_AJENA)]})
        d.telegram_set(token=TOKEN, chat=CHAT_GLOBAL)
        d.guardar_telegram_punto("p001", CHAT_P1)
        d.guardar_telegram_punto("p002", CHAT_P2)

    def test_aviso_va_al_global_y_a_su_chat_nunca_al_ajeno(self):
        """Capacidad nueva: la cuarentena de un CPE de p001 llega al global y al chat de p001, y
        NUNCA al de p002; lo de p002, al reves. Ningun texto del chat de p001 lleva datos de p002."""
        d = self.d
        d.notificar_cuarentena("p001|" + A.IP_PROPIA, "Infección CnC", "clientes-botnet", quien="olga")
        self.assertEqual(len(self.tg.a(CHAT_GLOBAL)), 1, self.tg.enviados)
        self.assertEqual(len(self.tg.a(CHAT_P1)), 1, self.tg.enviados)
        self.assertEqual(self.tg.a(CHAT_P2), [])
        self.assertIn("ABONADO-PROPIO-KQ", self.tg.a(CHAT_P1)[0])
        d.notificar_cuarentena("p002|" + A.IP_AJENA, "Infección CnC", "clientes-botnet", quien="ana")
        self.assertEqual(len(self.tg.a(CHAT_GLOBAL)), 2)
        self.assertEqual(len(self.tg.a(CHAT_P1)), 1, "el aviso de p002 llego al chat de p001")
        self.assertEqual(len(self.tg.a(CHAT_P2)), 1)
        # el del ajeno SI lleva sus marcas: si se hubiera colado en el chat de p001, se veria
        self.assertIn(A.ABON_AJENO, self.tg.a(CHAT_P2)[0])
        self.assertIn(A.EVID_AJENA, self.tg.a(CHAT_P2)[0])
        sin_marcas(self, self.tg.a(CHAT_P1), A.MARCAS_AJENAS + (A.IP_AJENA,), "chat de p001")
        sin_marcas(self, self.tg.a(CHAT_P2), (A.NOMBRES["p001"], "ABONADO-PROPIO-KQ", "EVIDENCIA-PROPIA-KQ"),
                   "chat de p002")
        self.assertEqual(self.tg.chats(), {CHAT_GLOBAL, CHAT_P1, CHAT_P2})

    def test_punto_sin_chat_solo_global(self):
        """Capacidad nueva (conservacion): un punto sin chat propio solo avisa al global, como antes."""
        self.d.guardar_telegram_punto("p001", "")
        self.d.notificar_cuarentena("p001|" + A.IP_PROPIA, "Infección CnC", "clientes-botnet")
        self.assertEqual(self.tg.chats(), {CHAT_GLOBAL})

    def test_sin_token_no_sale_nada(self):
        """Capacidad nueva: sin token (o borrado) no sale nada, ni al global ni a los chats de punto."""
        d = self.d
        d.telegram_set(token="")
        self.assertEqual(d.telegram_token(), "")
        d.notificar_cuarentena("p001|" + A.IP_PROPIA, "Infección CnC", "clientes-botnet")
        self.assertFalse(d.enviar_telegram_punto("p001", "hola"))
        self.assertFalse(d.enviar_telegram_chat(CHAT_P1, "hola"))
        self.assertEqual(self.tg.enviados, [])

    def test_chat_no_valido_no_se_usa(self):
        """Capacidad nueva: enviar_telegram_chat no habla con Telegram con un chat mal formado."""
        for malo in ("", "123&chat_id=-100999", "@abc", None):
            with self.subTest(chat=malo):
                self.assertFalse(self.d.enviar_telegram_chat(malo, "hola"))
        self.assertEqual(self.tg.enviados, [])


# ============================================================================================
# Servidor HTTP real (montaje de test_panel_alcance)
# ============================================================================================
@unittest.skipUnless(INF.HAY_CRYPTO, "falta cryptography (python3-cryptography en la imagen)")
class _BaseTG(A.Base):
    def setUp(self):
        super().setUp()
        self.tg = Telegrama()
        p = mock.patch.object(urllib.request, "urlopen", self.tg)
        p.start()
        self.addCleanup(p.stop)
        d = self.d
        d.telegram_set(token=TOKEN, chat=CHAT_GLOBAL)
        # PanelP sustituye enviar_telegram por un doble mudo: el global se manda por el mismo camino
        # que los chats de punto (enviar_telegram_chat real, con el token real) para poder contarlo
        d.enviar_telegram = lambda texto: d.enviar_telegram_chat(CHAT_GLOBAL, texto)
        d.destino_bloqueable = lambda ip, propias=None: (True, "")   # RFC 5737: aqui da igual

    def fichero(self):
        try:
            with open(self.d.TELEGRAM_PUNTOS_FILE, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def chats_guardados(self):
        with self.n.sin_alcance():
            return self.d.cargar_telegram_puntos()


class AislamientoPanel(_BaseTG):
    def setUp(self):
        super().setUp()
        self.d.guardar_telegram_punto("p001", CHAT_P1)
        self.d.guardar_telegram_punto("p002", CHAT_P2)

    def suricata(self, pids, estado="exited", salud="none"):
        ruta = os.path.join(self.raiz, "run", "estado.json")
        with open(ruta, encoding="utf-8") as f:
            est = json.load(f)
        for pid in pids:
            est["puntos"][pid]["contenedores"] = dict(est["puntos"][pid]["contenedores"],
                                                      suricata={"estado": estado, "salud": salud})
        est["ts"] = int(time.time())
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(est, f)
        t = time.time() + 60                    # leer_estado cachea por (mtime, tamano)
        os.utime(ruta, (t, t))

    def test_aviso_del_sensor_solo_a_su_chat(self):
        """Capacidad nueva: con el Suricata de p001 y de p002 parados, el aviso de cada uno llega al
        global y a SU chat; el chat de p001 no recibe nada de p002 (ni su nombre) y al reves."""
        self.suricata(["p001", "p002"])
        self.d.medir_sensor("p001")
        self.assertTrue(self.tg.a(CHAT_P1), self.tg.enviados)
        self.assertEqual(self.tg.a(CHAT_P2), [])
        self.d.medir_sensor("p002")
        self.assertTrue(self.tg.a(CHAT_P2), self.tg.enviados)
        self.assertGreaterEqual(len(self.tg.a(CHAT_GLOBAL)), 2)
        self.assertTrue(any(A.AJENO in t for t in self.tg.a(CHAT_P2)))
        sin_marcas(self, self.tg.a(CHAT_P1), A.MARCAS_AJENAS, "chat de p001")
        sin_marcas(self, self.tg.a(CHAT_P2), (A.NOMBRES["p001"], A.NOMBRES["p003"]), "chat de p002")
        self.assertEqual(self.tg.chats(), {CHAT_GLOBAL, CHAT_P1, CHAT_P2})

    def test_masivo_de_todos_a_cada_chat_solo_lo_suyo(self):
        """Capacidad nueva: «Enviar todos» del admin con CPE de los tres puntos manda al global el
        resumen y a cada chat de punto solo sus CPE; p003 (sin chat) no manda a ningun otro chat."""
        r = self.post("/cuarentena/enviar-todos", {"nodo": "_todos"}, "ana")
        esperar_masivo()   # (auditoría D) los avisos por punto salen en un hilo
        self.assertNotEqual(r.status, 500, A.plano(r.texto))
        for pid in A.TODOS_LOS_PIDS:                # el punto de partida: hubo envios en los tres
            self.assertTrue(self.mk_a(pid), (pid, self.p.mk))
        self.assertTrue(self.tg.a(CHAT_GLOBAL), self.tg.enviados)
        self.assertTrue(self.tg.a(CHAT_P1), self.tg.enviados)
        self.assertTrue(self.tg.a(CHAT_P2), self.tg.enviados)
        self.assertTrue(any(A.IP_PROPIA_CAND in t for t in self.tg.a(CHAT_P1)), self.tg.a(CHAT_P1))
        self.assertTrue(any(A.IP_AJENA_CAND in t for t in self.tg.a(CHAT_P2)), self.tg.a(CHAT_P2))
        sin_marcas(self, self.tg.a(CHAT_P1), A.MARCAS_AJENAS + (A.IP_AJENA_CAND, A.IP_AJENA, A.NOMBRES["p003"],
                                                                 A.IP_ESTE), "chat de p001")
        sin_marcas(self, self.tg.a(CHAT_P2), (A.NOMBRES["p001"], A.NOMBRES["p003"], A.IP_PROPIA_CAND, A.IP_ESTE),
                   "chat de p002")
        self.assertEqual(self.tg.chats(), {CHAT_GLOBAL, CHAT_P1, CHAT_P2})

    def test_masivo_del_limitado_no_llega_al_chat_ajeno(self):
        """Capacidad nueva: el «Enviar todos» de olga con la lista de SU punto avisa a su chat y al
        global; el chat de p002 no recibe nada."""
        r = self.post("/cuarentena/enviar-todos", {"nodo": "p001"}, "olga")
        esperar_masivo()   # (auditoría D) los avisos por punto salen en un hilo
        self.assertEqual(r.status, 303, A.plano(r.texto))
        self.assertTrue(self.tg.a(CHAT_P1), self.tg.enviados)
        self.assertEqual(self.tg.a(CHAT_P2), [])
        sin_marcas(self, self.tg.a(CHAT_P1), A.MARCAS_AJENAS, "chat de p001")

    def test_sin_token_nada_sale(self):
        """Capacidad nueva: sin token, ni el sensor ni el masivo mandan nada a ningun chat."""
        self.d.telegram_set(token="")
        self.suricata(["p001", "p002"])
        self.d.medir_sensor("p001")
        self.d.medir_sensor("p002")
        self.post("/cuarentena/enviar-todos", {"nodo": "_todos"}, "ana")
        esperar_masivo()   # (auditoría D) los avisos por punto salen en un hilo
        self.assertEqual(self.tg.enviados, [])


def esperar_masivo():
    """Espera a los hilos que mandan el masivo a cada chat de punto (_avisar_masivo_puntos_fondo)."""
    import threading
    for t in threading.enumerate():
        if t.name == "tg-masivo":
            t.join(30)


class FichaTelegram(_BaseTG):
    def pedir_tg(self, pid, accion, quien, chat=None):
        form = {"accion": accion, "ajax": "1"}
        if chat is not None:
            form[CAMPO_CHAT] = chat
        return self.post(RUTA_TG % pid, form, quien)

    def test_operador_ve_la_seccion_de_su_punto(self):
        """Capacidad nueva: olga (operador, puntos.telegram) ve la seccion en la ficha de p001, sin
        datos de otro punto."""
        r = self.get("/puntos/p001", "olga")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.esta(SECCION_TG, r.texto, "ficha p001")
        self.esta(RUTA_TG % "p001", r.texto, "ficha p001")
        self.sin_ajenos(r.texto, "ficha p001")

    def test_operador_guarda_prueba_y_quita_su_chat(self):
        """Capacidad nueva: olga guarda el chat de p001 (el fichero lo dice), lo prueba (un mensaje
        a ese chat con el nombre del punto y nada mas) y lo quita (el fichero ya no lo tiene)."""
        self.d.guardar_telegram_punto("p002", CHAT_P2)
        r = self.pedir_tg("p001", "guardar", "olga", CHAT_P1)
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.assertEqual(self.chats_guardados(), {"p001": CHAT_P1, "p002": CHAT_P2})
        self.assertEqual(self.d.telegram_chat_de("p001"), CHAT_P1)
        self.esta(CHAT_P1, self.get("/puntos/p001", "olga").texto, "ficha con el chat")
        r = self.pedir_tg("p001", "probar", "olga", CHAT_P1)
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.assertEqual(len(self.tg.a(CHAT_P1)), 1, self.tg.enviados)
        self.assertIn(A.NOMBRES["p001"], self.tg.a(CHAT_P1)[0])
        sin_marcas(self, self.tg.a(CHAT_P1), A.MARCAS_AJENAS, "prueba de p001")
        self.assertEqual(self.tg.chats(), {CHAT_P1})
        r = self.pedir_tg("p001", "quitar", "olga")
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.assertEqual(self.chats_guardados(), {"p002": CHAT_P2})

    def test_punto_ajeno_es_404_y_no_toca_nada(self):
        """Capacidad nueva: olga con el punto ajeno (p002) recibe 404 para guardar, probar y quitar;
        el fichero queda igual byte a byte y no sale nada. Control: el admin si puede."""
        self.d.guardar_telegram_punto("p002", CHAT_P2)
        antes = self.fichero()
        for acc, chat in (("guardar", CHAT_P1), ("probar", CHAT_P1), ("quitar", None)):
            with self.subTest(accion=acc):
                r = self.pedir_tg("p002", acc, "olga", chat)
                self.assertEqual(r.status, 404, A.plano(r.texto))
                self.sin_ajenos(r.texto, "POST p002 " + acc, extra=(CHAT_P2,))
        self.assertEqual(self.fichero(), antes)
        self.assertEqual(self.tg.enviados, [])
        r = self.pedir_tg("p002", "guardar", "ana", CHAT_P3)
        self.assertEqual(r.status, 200, A.plano(r.texto))
        self.assertEqual(self.chats_guardados(), {"p002": CHAT_P3})

    def test_sin_permiso_no_ve_la_seccion_y_403(self):
        """Capacidad nueva: luis (lectura, con «Ver la lista y la ficha» pero sin puntos.telegram)
        no ve la seccion y su POST es 403; el fichero no cambia."""
        us = self.d.cargar_usuarios()
        for u in us:
            if u["user"] == "luis":
                u["permisos"] = sorted(set(self.d.permisos.PLANTILLAS["lectura"]) | {"puntos.ver"})
        self.d.guardar_usuarios(us)
        self.d.guardar_telegram_punto("p001", CHAT_P1)
        antes = self.fichero()
        r = self.get("/puntos/p001", "luis")
        if r.status == 200:
            self.no_esta(SECCION_TG, r.texto, "ficha de luis")
            self.no_esta(RUTA_TG % "p001", r.texto, "ficha de luis")
        else:
            self.assertEqual(r.status, 403, A.plano(r.texto))
        for acc, chat in (("guardar", CHAT_P3), ("probar", CHAT_P3), ("quitar", None)):
            with self.subTest(accion=acc):
                r = self.pedir_tg("p001", acc, "luis", chat)
                self.assertEqual(r.status, 403, A.plano(r.texto))
        self.assertEqual(self.fichero(), antes)
        self.assertEqual(self.tg.enviados, [])

    def test_chat_no_valido_no_se_guarda(self):
        """Capacidad nueva: un Chat ID no valido (o vacio al guardar) es 400 y no se guarda; probar
        con uno no valido no manda nada."""
        self.d.guardar_telegram_punto("p001", CHAT_P1)
        antes = self.fichero()
        for malo in ("123;rm -rf /", "@abc", "12 34", "<script>x</script>", "-100abc", ""):
            with self.subTest(chat=malo):
                r = self.pedir_tg("p001", "guardar", "olga", malo)
                self.assertEqual(r.status, 400, A.plano(r.texto))
                self.assertNotIn("<script>x", r.texto)
                r = self.pedir_tg("p001", "probar", "olga", malo or "@abc")
                self.assertEqual(r.status, 400, A.plano(r.texto))
        self.assertEqual(self.fichero(), antes)
        self.assertEqual(self.tg.enviados, [])

    def test_probar_sin_bot(self):
        """Capacidad nueva: sin token no hay con que probar: no sale nada y no se guarda."""
        self.d.telegram_set(token="")
        r = self.pedir_tg("p001", "probar", "olga", CHAT_P1)
        self.assertIn(r.status, (400, 409), A.plano(r.texto))
        self.assertEqual(self.tg.enviados, [])
        self.assertEqual(self.chats_guardados(), {})


# ============================================================================================
# Informe diario (subproceso, montaje de test_informe_diario)
# ============================================================================================
ARNES_INF = ("import sys, json, urllib.request, urllib.parse; sys.path.insert(0, %r); import informe_diario as I\n"
             "vistos = []\n"
             "def falso(url, data=None, timeout=None):\n"
             "    q = urllib.parse.parse_qs(data.decode())\n"
             "    vistos.append([q['chat_id'][0], q['text'][0]])\n"
             "urllib.request.urlopen = falso\n"
             "rc = I.main(sys.argv[1:])\n"
             "print('@@' + json.dumps({'rc': rc, 'vistos': vistos}))\n")
NORTE = ("10.0.0.5", "(p001)", "Nodo Norte")
SUR = ("10.0.0.9", "(p002)", "Nodo Sur")


@unittest.skipUnless(INF.HAY_CRYPTO, "falta cryptography (python3-cryptography en la imagen)")
class InformePorPunto(INF.Base):
    def setUp(self):
        super().setUp()
        self.eve("p001", [INF.alerta("10.0.0.5", "ET MALWARE Botnet CnC Checkin", 1)] * 4)
        self.eve("p002", [INF.alerta("10.0.0.9", "ET SCAN Nmap Scripting Engine", 2)] * 2)

    def conf(self, con_token=True):
        lineas = ["TELEGRAM_CHAT_ID=%s" % CHAT_GLOBAL]
        if con_token:
            cod = ("import sys; sys.path.insert(0, %r); import secretos; "
                   "print(secretos.cifrar(%r, 'report:TELEGRAM_TOKEN'))" % (str(INF.LIB), TOKEN))
            valor = subprocess.run([sys.executable, "-c", cod], capture_output=True, text=True, env=self.env(),
                                   timeout=60).stdout.strip()
            self.assertTrue(valor.startswith("enc1:"), valor)
            lineas.insert(0, "TELEGRAM_TOKEN=%s" % valor)
        (self.panel / "conf" / "report.conf").write_text("\n".join(lineas) + "\n", encoding="utf-8")

    def chats(self, d):
        (self.panel / "conf" / "telegram-puntos.json").write_text(json.dumps(d), encoding="utf-8")

    def correr_inf(self, *args):
        r = subprocess.run([sys.executable, "-c", ARNES_INF % str(INF.LIB)] + list(args), capture_output=True,
                           text=True, env=self.env(), timeout=120)
        lin = [x for x in r.stdout.splitlines() if x.startswith("@@")]
        self.assertTrue(lin, r.stderr)
        res = json.loads(lin[-1][2:])
        por_chat = {}
        for chat, texto in res["vistos"]:
            por_chat.setdefault(chat, []).append(texto)
        return res["rc"], por_chat, r

    def test_cada_chat_de_punto_solo_su_seccion(self):
        """Capacidad nueva: con chats en p001 y p002, el global recibe el informe completo y cada
        chat de punto SOLO su seccion, sin nada del otro punto."""
        self.conf()
        self.chats({"p001": CHAT_P1, "p002": CHAT_P2})
        rc, por_chat, r = self.correr_inf()
        self.assertEqual(rc, 0, r.stderr)
        self.assertEqual(set(por_chat), {CHAT_GLOBAL, CHAT_P1, CHAT_P2})
        glob = "\n".join(por_chat[CHAT_GLOBAL])
        for m in NORTE + SUR:
            self.assertIn(m, glob)
        self.assertTrue(any("10.0.0.5" in t for t in por_chat[CHAT_P1]), por_chat[CHAT_P1])
        self.assertTrue(any("10.0.0.9" in t for t in por_chat[CHAT_P2]), por_chat[CHAT_P2])
        sin_marcas(self, por_chat[CHAT_P1], SUR, "informe al chat de p001")
        sin_marcas(self, por_chat[CHAT_P2], NORTE, "informe al chat de p002")
        self.assertNotIn(TOKEN, r.stdout + r.stderr)

    def test_solo_los_puntos_con_chat_valido(self):
        """Capacidad nueva: un punto sin chat, con chat mal formado o que no existe no recibe nada
        (ni hace que otro reciba de mas)."""
        self.conf()
        self.chats({"p001": "basura x", "p009": "-1009999999999", "p002": CHAT_P2, "../p001": CHAT_P1})
        rc, por_chat, r = self.correr_inf()
        self.assertEqual(rc, 0, r.stderr)
        self.assertEqual(set(por_chat), {CHAT_GLOBAL, CHAT_P2})
        sin_marcas(self, por_chat[CHAT_P2], NORTE, "informe al chat de p002")

    def test_informe_de_un_punto_no_llega_al_chat_del_otro(self):
        """Capacidad nueva: `--nodo p001` solo manda a su chat (y al global); el de p002, nada."""
        self.conf()
        self.chats({"p001": CHAT_P1, "p002": CHAT_P2})
        rc, por_chat, r = self.correr_inf("--nodo", "p001")
        self.assertEqual(rc, 0, r.stderr)
        self.assertEqual(set(por_chat), {CHAT_GLOBAL, CHAT_P1})
        sin_marcas(self, por_chat[CHAT_GLOBAL] + por_chat[CHAT_P1], SUR, "informe de p001")

    def test_sin_token_no_sale_nada(self):
        """Capacidad nueva: sin token no se manda nada, ni al global ni a los chats de punto (rc 0)."""
        self.conf(con_token=False)
        self.chats({"p001": CHAT_P1, "p002": CHAT_P2})
        rc, por_chat, r = self.correr_inf()
        self.assertEqual(rc, 0, r.stderr)
        self.assertEqual(por_chat, {})


if __name__ == "__main__":
    unittest.main()
