"""Botón «Actualizar» del panel (ACTUALIZACIONES.md §4), como el del panel original:

- idspanel/actualizaciones.py: qué hay instalado, qué hay nuevo en main (API de GitHub simulada) y
  el avance que deja ids-actualizar.sh;
- el panel de verdad (fixtures/panel2/_dash_p.py): el botón de la barra y su ventana solo para el
  admin, la tarjeta Ajustes → Versión, POST /actualizar-panel (pide sistema.actualizar al
  orquestador), /actualizacion.json y la página «Actualizando…».

Tipo «capacidad nueva»: el panel no tenía botón de actualizar (se quitó con el actualizador por git).
"""
import io
import json
import os
import re
import sys
import time
import unittest
import urllib.error

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, "fixtures", "panel2"))
from _dash_p import LIB, PanelP  # noqa: E402

if LIB not in sys.path:
    sys.path.insert(0, LIB)
from idspanel import actualizaciones as A  # noqa: E402

VIEJO = "1" * 40
NUEVO1 = "2" * 40
NUEVO2 = "3" * 40
MERGE = "4" * 40


def commit(sha, asunto, fecha="2026-10-15T20:00:00Z", padres=1):
    return {"sha": sha, "parents": [{"sha": "0" * 40}] * padres,
            "commit": {"message": asunto + "\n\ncuerpo", "committer": {"date": fecha}}}


LISTA = [commit(NUEVO2, "Panel: botón Actualizar"), commit(MERGE, "Merge branch x", padres=2),
         commit(NUEVO1, "Orquestador: sistema.actualizar"), commit(VIEJO, "Lo instalado")]
COMPARA = {"status": "ahead", "ahead_by": 3, "base_commit": {"sha": VIEJO},
           "commits": [commit(NUEVO1, "Orquestador: sistema.actualizar"),
                       commit(MERGE, "Merge branch x", padres=2), commit(NUEVO2, "Panel: botón Actualizar")]}


def github(respuestas):
    """pedir() falso: {fragmento de URL: respuesta o excepción}; apunta las URL pedidas."""
    pedidas = []

    def pedir(url):
        pedidas.append(url)
        for frag, r in respuestas.items():
            if frag in url:
                if isinstance(r, Exception):
                    raise r
                return r
        raise AssertionError("URL no prevista: " + url)
    pedir.pedidas = pedidas
    return pedir


def http_error(codigo):
    return urllib.error.HTTPError("https://api.github.com/x", codigo, "x", {}, io.BytesIO(b""))


class Modulo(unittest.TestCase):
    def test_instalada(self):
        self.assertEqual(A.instalada({"commit": VIEJO}, "main-2222222"), (VIEJO, VIEJO[:7]))
        self.assertEqual(A.instalada({}, "main-abc1234"), ("abc1234", "abc1234"))
        self.assertEqual(A.instalada({}, "lab-87cc7b5"), ("87cc7b5", "87cc7b5"))
        self.assertEqual(A.instalada({"version": "0.1.3"}, "dev"), ("v0.1.3", "v0.1.3"))
        self.assertEqual(A.instalada({}, "v0.1.2"), ("v0.1.2", "v0.1.2"))
        self.assertEqual(A.instalada({"commit": "no-es-sha"}, "dev"), ("", "dev"))

    def test_al_dia(self):
        p = github({"/commits?": [commit(VIEJO, "Lo instalado")]})
        d = A.buscar({"commit": VIEJO}, pedir=p, ahora=100)
        self.assertFalse(d["disponible"])
        self.assertEqual((d["objetivo"], d["ultimo"], d["error"], d["checked"]), (VIEJO, "Lo instalado", "", 100))
        self.assertEqual(len(p.pedidas), 1)                 # sin comparación: ya está al día
        self.assertFalse(d["historial"][0]["nuevo"])

    def test_novedades_sin_merges_y_de_la_mas_nueva_a_la_mas_vieja(self):
        p = github({"/commits?": LISTA, "/compare/": COMPARA})
        d = A.buscar({"commit": VIEJO}, pedir=p)
        self.assertTrue(d["disponible"])
        self.assertEqual(d["objetivo"], NUEVO2)
        self.assertEqual(d["n"], 3)
        self.assertEqual(d["mejoras"], ["Panel: botón Actualizar", "Orquestador: sistema.actualizar"])
        self.assertIn("/compare/%s...%s" % (VIEJO, NUEVO2), p.pedidas[1])
        self.assertEqual([(h["sha"], h["nuevo"]) for h in d["historial"]],
                         [(NUEVO2[:7], True), (NUEVO1[:7], True), (VIEJO[:7], False)])
        self.assertEqual(d["historial"][0]["fecha"], "2026-10-15T20:00:00Z")    # el panel la pasa a su hora

    def test_release_se_compara_por_su_etiqueta(self):
        p = github({"/commits?": LISTA, "/compare/": dict(COMPARA, base_commit={"sha": VIEJO})})
        d = A.buscar({"version": "0.1.3"}, "0.1.3", pedir=p)
        self.assertIn("/compare/v0.1.3...", p.pedidas[1])
        self.assertTrue(d["disponible"])
        self.assertEqual(d["instalada_sha"], VIEJO)

    def test_github_limita_o_no_contesta(self):
        for exc, texto in ((http_error(403), "60 por hora"), (urllib.error.URLError("timed out"), "sin conexión"),
                           (ValueError("x"), "no se entiende")):
            with self.subTest(texto=texto):
                d = A.buscar({"commit": VIEJO}, pedir=github({"/commits?": exc}))
                self.assertFalse(d["disponible"])
                self.assertEqual(d["objetivo"], "")
                self.assertIn(texto, d["error"])

    def test_no_se_encuentra_lo_instalado_pero_se_puede_actualizar(self):
        d = A.buscar({"commit": VIEJO}, pedir=github({"/commits?": LISTA, "/compare/": http_error(404)}))
        self.assertTrue(d["disponible"])
        self.assertEqual(d["objetivo"], NUEVO2)
        self.assertIn("no se pudo comparar", d["error"])
        d = A.buscar({}, "dev", pedir=github({"/commits?": LISTA}))
        self.assertTrue(d["disponible"])
        self.assertIn("no se sabe qué versión", d["error"])

    def test_avance(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(A.avance(td), {})
            with open(os.path.join(td, A.FICHERO_AVANCE), "w", encoding="utf-8") as f:
                json.dump({"estado": "en_curso", "ts": 1000}, f)
            self.assertEqual(A.avance(td, ahora=1000 + 60)["estado"], "en_curso")
            self.assertTrue(A.en_curso(A.avance(td, ahora=1060)))
            self.assertEqual(A.avance(td, ahora=1000 + A.AVANCE_COLGADO_S + 1)["estado"], "colgada")
        self.assertTrue(A.toca_buscar({}))
        self.assertFalse(A.toca_buscar({"checked": 1000}, ahora=1000 + A.BUSCAR_CADA_S - 1))
        self.assertTrue(A.toca_buscar({"checked": 1000}, ahora=1000 + A.BUSCAR_CADA_S))


class Panel(unittest.TestCase):
    def setUp(self):
        self.p = PanelP()
        self.addCleanup(self.p.cerrar)
        self.ana = self.p.entrar("ana")        # admin
        self.olga = self.p.entrar("olga")      # operador
        self.instalado(VIEJO)                  # la busqueda de las pruebas se hizo con VIEJO instalado

    def instalado(self, commit):
        """El commit que publica el orquestador en estado.json (lo instalado)."""
        est = os.path.join(self.p.tmp.name, "run", "estado.json")
        with open(est, encoding="utf-8") as f:
            e = json.load(f)
        e["commit"] = commit
        with open(est, "w", encoding="utf-8", newline="\n") as f:
            json.dump(e, f)
        t = time.time() + int(commit[:6], 16) % 1000 + 5        # otra marca: nodos.leer_estado relee
        os.utime(est, (t, t))

    def busqueda(self, **cambios):
        d = {"v": 1, "checked": int(time.time()), "instalada": VIEJO[:7], "ref": VIEJO, "disponible": True,
             "objetivo": NUEVO2, "ultimo": "Panel: botón Actualizar", "fecha": "15/10/2026", "n": 3,
             "mejoras": ["Panel: botón <b>Actualizar</b>", "Orquestador: sistema.actualizar"],
             "historial": [{"sha": NUEVO2[:7], "asunto": "Panel: botón Actualizar", "fecha": "15/10/2026", "nuevo": True}],
             "error": ""}
        d.update(cambios)
        A.guardar_busqueda(self.p.nodos.ESTADO, d)

    def avance(self, **campos):
        d = {"v": 1, "id": "11111111-2222-4333-8444-555555555555", "estado": "en_curso", "ts": int(time.time()),
             "inicio": int(time.time()) - 60, "desde": VIEJO, "a": NUEVO2, "quien": "panel:ana",
             "pasos": [{"nombre": "descargar el commit", "estado": "ok"},
                       {"nombre": "construir la imagen del panel", "estado": "en_curso"}]}
        d.update(campos)
        with open(os.path.join(self.p.tmp.name, "run", "actualizacion.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(d, f)

    def seguir(self, r):
        """La pagina a la que redirige `r` (sin el #)."""
        return self.get(r.cab("Location").split("#", 1)[0])

    def get(self, ruta, cookie=None):
        r = self.p.pedir("GET", ruta, cookie=cookie or self.ana)
        self.assertEqual(r.status, 200, r.texto[:300])
        return r.texto

    def test_aviso_en_el_menu_y_ventana_solo_para_el_admin_con_novedades(self):
        """Como la notificacion de una app: dentro del menu del usuario, con el punto sobre su foto
        (en la barra se montaba encima del resto, el user 2026-10-15), y abre la ventana de mejoras."""
        self.busqueda()
        t = self.get("/ajustes")
        menu = t[t.index('id="umenu"'):]
        menu = menu[:menu.index("Cerrar sesi")]
        self.assertIn("class=unotif", menu)
        self.assertIn("Actualizaci&oacute;n disponible", menu)
        self.assertIn("3 cambio(s) nuevo(s): pulsa para ver las mejoras.", menu)
        self.assertIn("getElementById('updov').style.display='flex'", menu)
        self.assertIn('class="unotifdot"', t[t.index('id="ubtn"') - 200:t.index('id="umenu"')])
        self.assertNotIn("class=updbtn", t)                     # ya no hay boton suelto en la barra
        self.assertIn("id=updov", t)
        self.assertIn("<li>Panel: botón &lt;b&gt;Actualizar&lt;/b&gt;</li>", t)    # escapado
        self.assertIn("<li>y 1 cambio(s) más.</li>", t)
        self.assertRegex(t, r"action='/actualizar-panel'.*?name=commit value='%s'" % NUEVO2)
        self.assertIn("return ask(this,'Actualizar el panel y el orquestador'", t)
        o = self.get("/ajustes", self.olga)
        self.assertNotIn("class=unotif", o)
        self.assertNotIn('class="unotifdot"', o)
        self.assertNotIn("id=updov", o)

    def test_al_dia_sin_boton_en_la_barra(self):
        self.busqueda(disponible=False, objetivo=VIEJO, mejoras=[], n=0)
        t = self.get("/ajustes")
        self.assertNotIn("class=unotif", t)
        self.assertNotIn('class="unotifdot"', t)
        self.assertIn("Estás en la última versión", t)
        self.assertIn("Actualizar de todos modos", t)      # como en el original: siempre se puede forzar

    def test_tarjeta_con_novedades_e_historial(self):
        self.busqueda()
        t = self.get("/ajustes")
        self.assertIn("Versión y actualizaciones", t)
        self.assertIn("Hay actualizaciones disponibles (3 cambio(s) en main)", t)
        self.assertIn("Buscar actualizaciones", t)
        self.assertIn("Historial de cambios", t)
        self.assertIn("<span class=vnew>Nuevo</span>", t)
        self.assertIn("ids-orq punto reconfigurar", t)

    def test_sin_buscar_todavia(self):
        t = self.get("/ajustes")
        self.assertIn("Aún no se ha buscado", t)
        self.assertNotIn("class=unotif", t)

    def test_ultima_actualizacion_y_fallos(self):
        self.busqueda(disponible=False, objetivo=NUEVO2)
        self.avance(estado="ok", fin=int(time.time()))
        t = self.get("/ajustes")
        self.assertIn("Actualizado de <b>%s</b> a <b>%s</b> por ana" % (VIEJO[:7], NUEVO2[:7]), t)
        self.avance(estado="revertida", mensaje="Falló «recrear el panel»: el panel nuevo no quedó sano.")
        self.assertIn("se volvió a la versión anterior", self.get("/ajustes"))
        self.avance(estado="en_curso", ts=int(time.time()) - A.AVANCE_COLGADO_S - 5)
        self.assertIn("journalctl -u ids-actualizar", self.get("/ajustes"))

    def test_pedir_la_actualizacion(self):
        self.busqueda()
        r = self.p.pedir("POST", "/actualizar-panel", {"commit": NUEVO2}, cookie=self.ana)
        self.assertEqual(r.status, 303, r.texto[:300])
        m = re.search(r"/actualizando\?op=([0-9a-f-]{36})", r.cab("Location") or "")
        self.assertIsNotNone(m, r.cab("Location"))
        ped = self.p.orq.ordenes("sistema.actualizar")
        self.assertEqual(len(ped), 1)
        self.assertEqual((ped[0]["params"], ped[0]["op_id"], ped[0]["quien"]),
                         ({"commit": NUEVO2}, m.group(1), "panel:ana"))
        with open(self.p.d.BITACORA_LOG, encoding="utf-8") as f:
            self.assertIn("ACTUALIZAR-PANEL\ta=%s resultado=ACEPTADA op=%s" % (NUEVO2[:7], m.group(1)), f.read())

    def test_solo_admin_y_commit_valido(self):
        r = self.p.pedir("POST", "/actualizar-panel", {"commit": NUEVO2}, cookie=self.olga)
        self.assertEqual(r.status, 403)
        for malo in ("", "main", "ABCDEF1", NUEVO2 + "0", "abc; rm -rf /"):
            with self.subTest(malo=malo):
                r = self.p.pedir("POST", "/actualizar-panel", {"commit": malo}, cookie=self.ana)
                self.assertEqual(r.status, 303)
                self.assertIn("La versión pedida no es válida", self.seguir(r))
        self.assertEqual(self.p.orq.ordenes("sistema.actualizar"), [])
        for ruta in ("/actualizando", "/actualizacion.json"):
            self.assertEqual(self.p.pedir("GET", ruta, cookie=self.olga).status, 403, ruta)

    def test_con_una_en_curso_no_se_pide_otra(self):
        self.avance()
        r = self.p.pedir("POST", "/actualizar-panel", {"commit": NUEVO2}, cookie=self.ana)
        self.assertEqual(r.status, 303)
        self.assertIn("/actualizando", r.cab("Location"))
        self.assertEqual(self.p.orq.ordenes("sistema.actualizar"), [])
        t = self.get("/ajustes")
        self.assertIn("<a role=menuitem class=unotif href='/actualizando'>", t)   # el aviso lleva al avance
        self.assertIn("Actualizando el panel&hellip;", t)

    def test_avance_en_json_y_pagina(self):
        self.avance()
        op = "11111111-2222-4333-8444-555555555555"
        d = json.loads(self.get("/actualizacion.json?op=" + op))
        self.assertEqual(d["avance"]["estado"], "en_curso")
        self.assertEqual(d["op"], {"estado": "sin_respuesta"})       # el orquestador falso no la conoce
        self.assertNotIn("op", json.loads(self.get("/actualizacion.json?op=no-vale")))
        t = self.get("/actualizando?op=" + op)
        self.assertIn("Actualizando el panel", t)
        self.assertIn('var OP="%s"' % op, t)
        self.assertIn('var OP=""', self.get("/actualizando?op=%3Cscript%3E"))
        # si acaba bien lleva a En vivo (el user: «cuando termine, mandar al En vivo»), no a Ajustes
        # (el panel le pone a cada ruta interna el nodo que se mira: «/?nodo=_todos»)
        self.assertRegex(t, r"setTimeout\(function\(\)\{location\.href='/(\?nodo=[^']*)?';\},3000\)")
        self.assertRegex(t, r"l\.href='/(\?nodo=[^']*)?';l\.textContent='Ir a En vivo'")
        self.assertNotIn("location.href='/ajustes", t)

    def test_tras_actualizar_la_busqueda_vieja_no_vale(self):
        """La busqueda guardada se hizo con VIEJO; actualizado a NUEVO2 (por el boton o por consola),
        la tarjeta decia aun «instalada VIEJO, 3 cambios» (el user, captura del .159). Ahora no vale:
        sin aviso y «Aún no se ha buscado» hasta que el hilo busque otra vez."""
        self.busqueda()
        self.assertIn("class=unotif", self.get("/ajustes"))
        self.instalado(NUEVO2)
        t = self.get("/ajustes")
        self.assertNotIn("class=unotif", t)
        self.assertNotIn('class="unotifdot"', t)
        self.assertIn("Aún no se ha buscado", t)
        self.assertIn("<div class=versha>%s</div>" % NUEVO2[:7], t)
        self.assertNotIn("Hay actualizaciones disponibles", t)
        self.assertEqual(A.vigente({"ref": VIEJO}, {"commit": VIEJO}), {"ref": VIEJO})
        self.assertEqual(A.vigente({"ref": VIEJO}, {"commit": NUEVO2}), {})
        self.assertEqual(A.vigente({}, {"commit": VIEJO}), {})

    def test_buscar_ahora(self):
        original = self.p.d.actualizaciones.pedir_github
        self.addCleanup(setattr, self.p.d.actualizaciones, "pedir_github", original)
        self.p.d.actualizaciones.pedir_github = github({"/commits?": LISTA, "/compare/": COMPARA})
        r = self.p.pedir("POST", "/buscar-actualizacion", {}, cookie=self.ana)
        # vuelve a Ajustes → Versión con el aviso (recargar ya no repite la busqueda: el user)
        self.assertEqual(r.status, 303, r.texto[:300])
        self.assertRegex(r.cab("Location"), r"^/ajustes\?msg=[A-Za-z0-9_-]+#update$")
        self.assertIn("Hay una versión nueva disponible", self.seguir(r))
        self.assertNotIn("Hay una versión nueva disponible", self.get(r.cab("Location").split("#")[0]))   # un solo uso
        self.assertEqual(A.leer_busqueda(self.p.nodos.ESTADO)["objetivo"], NUEVO2)
        self.assertEqual(self.p.pedir("POST", "/buscar-actualizacion", {}, cookie=self.olga).status, 403)


if __name__ == "__main__":
    unittest.main()
