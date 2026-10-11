"""Panel: páginas renderizadas con un estado.json de ejemplo, alertas por punto y escape HTML."""

import re
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures" / "panel"))
import _ayuda_panel as A  # noqa: E402
from idspanel import vistas  # noqa: E402
from idspanel.util import esc  # noqa: E402

XSS = '<script>alert("x")</script>'


def filas(html_):
    return re.findall(r"<tr[^>]*>(.*?)</tr>", html_, re.S)


class Paginas(unittest.TestCase):
    def setUp(self):
        self._it = A.iteraciones_rapidas()
        self._it.__enter__()
        self.addCleanup(self._it.__exit__, None, None, None)
        self.p = A.PanelPrueba()
        self.addCleanup(self.p.cerrar)
        self.p.usuario()
        self.ck = self.p.entrar()
        self.t = time.time()
        A.escribir_estado(self.p.cfg.run_dir, {
            "p003": A.punto_estado("norte", 3, ahora=self.t),
            "p004": A.punto_estado("sur", 4, conectado=False, avisos=["SIN-ESPEJO"], ahora=self.t),
        }, ahora=self.t)
        self.p.orq.anadir_punto("norte", 3)
        self.p.orq.anadir_punto("sur", 4, ros=6)
        t = self.t
        # la MISMA IP privada en dos puntos: dos abonados distintos
        A.escribir_eve(self.p.cfg.datos_dir, "p003", [
            A.linea_alerta(t - 90000, "p003", "10.0.0.5", "198.51.100.7", firma="vieja"),     # > 24 h
            A.linea_alerta(t - 300, "p003", "10.0.0.5", "198.51.100.7", firma="FIRMA-NORTE-1"),
            A.linea_stats(t - 200),
            A.linea_alerta(t - 100, "p003", "10.0.0.9", "198.51.100.8", firma=XSS),
        ])
        A.escribir_eve(self.p.cfg.datos_dir, "p004", [
            A.linea_alerta(t - 50, "p004", "10.0.0.5", "203.0.113.99", firma="FIRMA-SUR-1", sev=1),
        ])
        (self.p.cfg.run_dir / "p003").mkdir()
        (self.p.cfg.run_dir / "p003" / "tzsp.json").write_text(
            '{"v":1,"ultimo_visto":{"100.64.3.2":%d}}' % int(t - 30), encoding="utf-8")

    def get(self, ruta):
        r = self.p.pedir("GET", ruta, cookie=self.ck)
        self.assertEqual(r.status, 200, (ruta, r.texto[:500]))
        return r.texto

    def test_puntos(self):
        html_ = self.get("/puntos")
        self.assertIn("Toda la empresa", html_)
        fs = filas(self.get("/puntos/tabla"))
        empresa = [f for f in fs if "Toda la empresa" in f][0]
        norte = [f for f in fs if "/puntos/p003" in f][0]
        sur = [f for f in fs if "/puntos/p004" in f][0]
        self.assertIn("norte", norte)
        self.assertIn("1196/tcp", norte)
        self.assertIn("100.64.3.0/24", norte)
        self.assertIn("conectado", norte)
        self.assertIn("203.0.113.45", norte)
        self.assertIn("hace 30 s", norte)                       # último espejo (tzsp.json)
        self.assertIn('class="dot verde"', norte)
        self.assertRegex(norte, r'/alertas\?punto=p003">2<')   # 24 h: la de hace 25 h no cuenta
        self.assertIn("desconectado", sur)
        self.assertIn("No llega el espejo", sur)
        self.assertIn('class="dot ambar"', sur)
        self.assertRegex(sur, r'/alertas\?punto=p004">1<')
        self.assertRegex(empresa, r'/alertas">3<')
        self.assertIn("2 puntos", empresa)
        self.assertIn("1 conectados", empresa)

    def test_puntos_sin_estado_json_avisa(self):
        (self.p.cfg.run_dir / "estado.json").unlink()
        html_ = self.get("/puntos")
        self.assertIn("No se puede leer el estado del orquestador", html_)
        self.assertIn("Todavía no hay puntos", html_)

    def test_estado_viejo_avisa(self):
        A.escribir_estado(self.p.cfg.run_dir, {"p003": A.punto_estado("norte", 3)}, ahora=time.time() - 600)
        self.assertIn("no lo está actualizando", self.get("/puntos/tabla"))

    def test_ficha_alertas_del_punto_y_filtro_por_ip(self):
        html_ = self.get("/puntos/p003")
        self.assertIn("FIRMA-NORTE-1", html_)
        self.assertNotIn("FIRMA-SUR-1", html_)                    # no se mezcla con p004
        self.assertLess(html_.index("FIRMA-NORTE-1"), html_.index(">vieja<"))   # la más nueva primero
        html_ = self.get("/puntos/p003?ip=10.0.0.9")
        self.assertNotIn("FIRMA-NORTE-1", html_)
        self.assertIn(esc(XSS), html_)
        html_ = self.get("/puntos/p003?ip=no-es-ip")
        self.assertIn("no es una dirección IP", html_)
        # comandos SIN clave y opción de regenerar
        self.assertIn("&lt;CLAVE-VPN&gt;", html_)
        self.assertIn("/interface ovpn-client add name=ids-vpn", html_)
        self.assertIn("/puntos/p003/regenerar", html_)

    def test_ficha_de_punto_inexistente(self):
        self.assertEqual(self.p.pedir("GET", "/puntos/p099", cookie=self.ck).status, 404)
        self.assertEqual(self.p.pedir("GET", "/puntos/../etc", cookie=self.ck).status, 404)

    def test_alertas_empresa_no_mezcla_ips_repetidas(self):
        html_ = self.get("/alertas?ip=10.0.0.5")
        fs = [f for f in filas(html_) if "FIRMA-" in f]
        self.assertEqual(len(fs), 2)
        sur = [f for f in fs if "FIRMA-SUR-1" in f][0]
        norte = [f for f in fs if "FIRMA-NORTE-1" in f][0]
        self.assertIn("/puntos/p004", sur)
        self.assertNotIn("/puntos/p003", sur)
        self.assertIn("/puntos/p003", norte)
        self.assertNotIn("/puntos/p004", norte)
        # filtro por punto
        html_ = self.get("/alertas?punto=p004&ip=10.0.0.5")
        self.assertIn("FIRMA-SUR-1", html_)
        self.assertNotIn("FIRMA-NORTE-1", html_)
        # orden: la más nueva primero
        html_ = self.get("/alertas")
        self.assertLess(html_.index("FIRMA-SUR-1"), html_.index("FIRMA-NORTE-1"))

    def test_escape_html(self):
        for ruta in ("/puntos", "/alertas", "/puntos/p003", "/documentacion"):
            html_ = self.get(ruta)
            self.assertNotIn(XSS, html_, ruta)
            self.assertNotIn("<b>Norte</b>", html_, ruta)          # IDS_EMPRESA también se escapa
            self.assertIn("Empresa &lt;b&gt;Norte&lt;/b&gt; &amp; Cía", html_, ruta)
        self.assertIn(esc(XSS), self.get("/alertas"))
        html_ = self.p.pedir("POST", "/entrar", {"usuario": '"><img src=x>', "clave": "x"}).texto
        self.assertNotIn('"><img src=x>', html_)
        self.assertIn("&quot;&gt;&lt;img src=x&gt;", html_)

    def test_documentacion(self):
        html_ = self.get("/documentacion")
        for t in ("Qué es un punto", "Crear un punto", "Borrar un punto", "Comandos del MikroTik",
                  "La VPN solo trae el espejo", "proxy inverso"):
            self.assertIn(t, html_)


class Vistas(unittest.TestCase):
    def test_esc(self):
        self.assertEqual(esc('<a href="x">&\''), "&lt;a href=&quot;x&quot;&gt;&amp;&#x27;")
        self.assertEqual(esc(None), "")

    def test_semaforo(self):
        from idspanel.estado import semaforo
        p = A.punto_estado("norte", 3)
        self.assertEqual(semaforo(p), "verde")
        self.assertEqual(semaforo(dict(p, avisos=["SIN-ESPEJO"])), "ambar")
        self.assertEqual(semaforo(dict(p, estado="error")), "rojo")
        self.assertEqual(semaforo(dict(p, deseado="parado", estado="parado")), "gris")
        cont = {"vpn": {"estado": "exited", "salud": "none"}, "suricata": p["contenedores"]["suricata"]}
        self.assertEqual(semaforo(dict(p, contenedores=cont)), "rojo")

    def test_tabla_escapa_datos_del_estado(self):
        p = A.punto_estado("norte", 3)
        p["tun_net"] = XSS
        p["avisos"] = [XSS]
        emp = {"puntos": 1, "activos": 1, "vpn_sana": 1, "conectados": 1, "con_espejo": 0, "suricata_sana": 1,
               "alertas": 0, "completo": True}
        html_ = vistas.tabla_puntos([("p003", p, None, (0, True))], emp, 5, time.time(), "UTC")
        self.assertNotIn(XSS, html_)
        self.assertIn(esc(XSS), html_)


if __name__ == "__main__":
    unittest.main()
