"""REDES_PANEL aparte de IPS_PROXY (el dueño, 2026-10-15: entra al panel desde sus /25 y /26).

Tipo: corrección de defecto; cada prueba falla sin su arreglo en el orquestador.
- Antes, la única lista era IPS_PROXY: abría el 5637 en el firewall y además era la de proxies de
  confianza del panel. Con una /25 ahí, el panel se fiaba del X-Forwarded-For de toda la red, y el
  instalador (proxy hasta /28) ya no se podía volver a ejecutar.
- Ahora el firewall deja llegar a REDES_PANEL y a IPS_PROXY, y el panel solo se fía de IPS_PROXY.
Datos de documentación (RFC 5737).
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

ENTORNO = r'(?m)^      (IDS_[A-Z_]+|TZ): "([^"]*)"$'


class RedesPanel(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def conf(self, **cambios):
        p = self.e.ruta("/etc/ids-maat/ids.conf")
        kv = self.mod.leer_kv(p)
        kv.update(cambios)
        p.write_text("".join("%s=%s\n" % x for x in kv.items()), encoding="utf-8")
        return self.mod.config()

    def entorno(self, cfg):
        return dict(re.findall(ENTORNO, self.mod.render_core(cfg, A.IMG_PANEL, "0.1.0")))

    def test_redes_del_panel_sin_proxy(self):
        cfg = self.conf(IPS_PROXY="", REDES_PANEL="198.51.100.0/25,192.0.2.128/26")
        nft = self.mod.render_nft(cfg, [1194], [])
        self.assertIn("set proxy       { type ipv4_addr; flags interval; elements = { 192.0.2.128/26, 198.51.100.0/25 } }", nft)
        self.assertEqual(self.entorno(cfg)["IDS_PROXY"], "")          # no se fía de nadie

    def test_redes_del_panel_y_un_proxy(self):
        cfg = self.conf(IPS_PROXY="203.0.113.50", REDES_PANEL="198.51.100.0/25")
        nft = self.mod.render_nft(cfg, [], [])
        self.assertIn("elements = { 198.51.100.0/25, 203.0.113.50 }", nft)
        self.assertEqual(self.entorno(cfg)["IDS_PROXY"], "203.0.113.50")   # solo del proxy

    def test_redes_del_panel_que_tapan_al_proxy(self):
        """nft rechaza intervalos solapados: la unión se agrupa."""
        cfg = self.conf(IPS_PROXY="198.51.100.70", REDES_PANEL="198.51.100.0/25")
        self.assertIn("elements = { 198.51.100.0/25 }", self.mod.render_nft(cfg, [], []))
        cfg = self.conf(IPS_PROXY="203.0.113.50", REDES_PANEL="0.0.0.0/0")
        self.assertIn("elements = { 0.0.0.0/0 }", self.mod.render_nft(cfg, [], []))
        self.assertEqual(self.entorno(cfg)["IDS_PROXY"], "203.0.113.50")

    def test_sin_redes_del_panel_igual_que_antes(self):
        cfg = self.conf(IPS_PROXY="203.0.113.48/28,203.0.113.70")
        self.assertIn("elements = { 203.0.113.48/28, 203.0.113.70 }", self.mod.render_nft(cfg, [], []))
        self.assertEqual(self.entorno(cfg)["IDS_PROXY"], "203.0.113.48/28,203.0.113.70")

    def test_sin_proxy_ni_redes_del_panel_falla(self):
        with self.assertRaises(self.mod.ErrorOrden) as e:
            self.conf(IPS_PROXY="", REDES_PANEL="")
        self.assertIn("IPS_PROXY o REDES_PANEL", str(e.exception))


if __name__ == "__main__":
    unittest.main()
