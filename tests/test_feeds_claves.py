"""Ajustes > Reputacion: como sacar cada clave (enlaces comprobados) y validacion de cada una.

Tipo: correccion de defecto + capacidad nueva (el user, 2026-10-14: «no manda los link donde se
deben crear las api», «que valide bien los link para crear cuentas y api y que valide los token»).
  - Cada servicio tiene su bloque con pasos y botones a la pagina exacta; el panel solo enlaza las
    direcciones de FEEDS_ENLACES (la de AbuseIPDB que habia, /account/api, daba 404).
  - Telegram: antes solo se miraba la FORMA del token; ahora getMe (token) y getChat (chat) antes
    de guardar, y «Detectar Chat ID» (getUpdates) para no leer JSON a mano.
  - Una clave pegada en el campo de otro servicio se rechaza con un mensaje que lo dice.
Sin red: la Bot API y las validaciones se simulan. Con IDS_PRUEBAS_RED=1 se comprueba ademas que
cada enlace responde 200 de verdad.
"""
import json
import os
import re
import sys
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_f1_cuarentena import Panel  # noqa: E402

TOK = "123456789:" + "B" * 35
CHAT = "-1001234567890"


class Bloques(unittest.TestCase):
    def setUp(self):
        self.p = Panel(http=True)
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d
        _s, _c, h = self.p.pedir("GET", "/ajustes")
        i = h.index("<h2>Reputacion / feeds</h2>")
        self.card = h[i:h.index("</section>", i)]

    def test_solo_enlaces_comprobados_y_todos_presentes(self):
        enlaces = set(re.findall(r"href='(https?://[^']+)' target=_blank", self.card))
        self.assertEqual(enlaces, set(self.d.FEEDS_ENLACES.values()))
        self.assertNotIn("abuseipdb.com/account/api", self.card)       # la que daba 404
        for url in enlaces:
            self.assertIn("href='%s' target=_blank rel='noopener noreferrer'" % url, self.card)

    def test_un_bloque_por_servicio_con_sus_pasos(self):
        for ident in ("feed-abusech", "feed-aidb", "feed-groq", "feed-telegram"):
            self.assertIn("<div class=fsrv id=%s>" % ident, self.card)
        self.assertEqual(self.card.count("<div class=fcomo>Como sacar la clave</div>"), 4)
        # la casilla de denunciar va en el bloque de AbuseIPDB, no debajo de Telegram
        aidb = self.card[self.card.index("id=feed-aidb"):self.card.index("id=feed-groq")]
        self.assertIn("name=reportar", aidb)
        self.assertIn("Detectar Chat ID", self.card[self.card.index("id=feed-telegram"):])

    def test_configurar_en_las_fuentes_sin_clave(self):
        """Cada fuente sin clave (tambien las variantes como threatfox-c2) lleva a su bloque."""
        self.d.cargar_feeds_meta = lambda: {"sources": {
            n: {"estado": "sin-clave"} for n in ("urlhaus", "threatfox-c2", "abuseipdb", "cins")}}
        _s, _c, h = self.p.pedir("GET", "/ajustes")
        filas = dict(re.findall(r"<tr><td class=mono>([a-z0-9-]+)</td><td>(.*?)</td>", h))
        self.assertIn("feed-abusech", filas["urlhaus"])
        self.assertIn("feed-abusech", filas["threatfox-c2"])
        self.assertIn("feed-aidb", filas["abuseipdb"])
        self.assertNotIn("Configurar", filas["cins"])       # no pide clave


class Telegram(unittest.TestCase):
    def setUp(self):
        self.p = Panel(http=True)
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d
        self.llamadas = []
        self.resp = {}

        def falso(tok, metodo, params=None, timeout=12):
            self.llamadas.append(metodo)
            return self.resp.get(metodo, (False, "sin respuesta de Telegram", 0))
        self.d._tg_api = falso

    def guardar(self, **campos):
        return self.p.pedir("POST", "/telegram", campos)[2]

    def test_token_rechazado_no_se_guarda(self):
        self.resp["getMe"] = (False, "Unauthorized", 401)
        txt = self.guardar(tgtoken=TOK, tgchat=CHAT)
        self.assertIn("No se guardo", txt)
        self.assertIn("Telegram rechazo el token", txt)
        self.assertFalse(self.d.telegram_configurado())

    def test_chat_donde_el_bot_no_esta_no_se_guarda(self):
        self.resp["getMe"] = (True, {"username": "avisos_bot"}, 200)
        self.resp["getChat"] = (False, "Bad Request: chat not found", 400)
        txt = self.guardar(tgtoken=TOK, tgchat=CHAT)
        self.assertIn("el bot no tiene acceso a ese chat", txt)
        self.assertFalse(self.d.telegram_configurado())

    def test_token_y_chat_buenos_se_guardan_y_lo_dice(self):
        self.resp["getMe"] = (True, {"username": "avisos_bot"}, 200)
        self.resp["getChat"] = (True, {"id": int(CHAT), "title": "NOC", "type": "supergroup"}, 200)
        txt = self.guardar(tgtoken=TOK, tgchat=CHAT)
        self.assertIn("Telegram guardado", txt)
        self.assertIn("@avisos_bot", txt)
        self.assertIn("NOC", txt)
        self.assertEqual(self.d.telegram_token(), TOK)
        self.assertEqual(self.d.telegram_chat(), CHAT)

    def test_sin_red_se_guarda_y_avisa_que_no_se_comprobo(self):
        txt = self.guardar(tgtoken=TOK, tgchat=CHAT)
        self.assertIn("Telegram guardado", txt)
        self.assertIn("no se pudo comprobar", txt)

    def test_forma_mala_ni_pregunta(self):
        txt = self.guardar(tgtoken="no-es-un-token")
        self.assertIn("no parece un token de bot", txt)
        self.assertEqual(self.llamadas, [])

    def test_detectar_chat_id(self):
        self.resp["getUpdates"] = (True, [
            {"message": {"chat": {"id": 5551234, "first_name": "Ana", "type": "private"}}},
            {"message": {"chat": {"id": int(CHAT), "title": "NOC", "type": "supergroup"}}},
            {"message": {"chat": {"id": 5551234, "first_name": "Ana", "type": "private"}}}], 200)
        st, _c, txt = self.p.pedir("POST", "/telegram/detectar", {"tgtoken": TOK})
        j = json.loads(txt)
        self.assertTrue(j["ok"])
        self.assertEqual(sorted(c["id"] for c in j["chats"]), sorted(["5551234", CHAT]))
        self.resp["getUpdates"] = (True, [], 200)
        j = json.loads(self.p.pedir("POST", "/telegram/detectar", {"tgtoken": TOK})[2])
        self.assertFalse(j["ok"])
        self.assertIn("mandale un mensaje", j["msg"])
        self.resp["getUpdates"] = (False, "Conflict: webhook is active", 409)
        j = json.loads(self.p.pedir("POST", "/telegram/detectar", {"tgtoken": TOK})[2])
        self.assertIn("webhook", j["msg"])
        # solo administradores
        self.assertEqual(self.p.pedir("POST", "/telegram/detectar", {"tgtoken": TOK}, "olga")[0], 403)


class CampoEquivocado(unittest.TestCase):
    def setUp(self):
        self.p = Panel(http=True)
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d
        no = lambda *a, **k: self.fail("no deberia preguntar al servicio")   # noqa: E731
        self.d.feeds_auth_probar = no
        self.d.aidb_probar = no
        self.d.groq_probar = no

    def test_clave_de_otro_servicio_se_rechaza_explicandolo(self):
        txt = self.p.pedir("POST", "/feeds", {"authkey": "gsk_" + "x" * 40})[2]
        self.assertIn("parece la clave de Groq", txt)
        txt = self.p.pedir("POST", "/feeds/aidb", {"aidbkey": TOK})[2]
        self.assertIn("parece la clave de un bot de Telegram", txt)
        txt = self.p.pedir("POST", "/feeds/groq", {"groqkey": "a" * 80})[2]
        self.assertIn("las claves de Groq empiezan por gsk_", txt)


@unittest.skipUnless(os.environ.get("IDS_PRUEBAS_RED") == "1", "sin red: IDS_PRUEBAS_RED=1 para comprobar los enlaces")
class EnlacesVivos(unittest.TestCase):
    def test_cada_enlace_responde(self):
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
        p = Panel()
        self.addCleanup(p.cerrar)
        for nombre, url in p.d.FEEDS_ENLACES.items():
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                self.assertEqual(r.status, 200, "%s %s" % (nombre, url))


if __name__ == "__main__":
    unittest.main()
