"""Instalación sin --gestion ni --proxy (el dueño, 2026-10-15: «debe ser libre, luego yo pongo
seguridad»): ids.conf lleva REDES_GESTION=0.0.0.0/0 e IPS_PROXY=0.0.0.0/0.

Tipo: corrección de defecto; cada prueba falla sin su arreglo en el orquestador.
- La gestión abierta no es una red reservada: sin el arreglo, 0.0.0.0/0 se solapa con todo y
  ningún punto se puede crear (validar_redes) ni sale con prefijos por defecto.
- El proxy abierto deja entrar a cualquiera al panel, pero el panel no se fía del X-Forwarded-For
  de nadie: sin el arreglo IDS_PROXY=0.0.0.0/0 y cualquiera falsea su IP (bloqueos, registro).
Datos de documentación (RFC 5737) y RFC 1918.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

ABIERTO = "0.0.0.0/0"


class AccesoAbierto(unittest.TestCase):
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

    def test_gestion_abierta_no_quita_redes_a_los_abonados(self):
        cerrada = self.conf(REDES_GESTION="192.0.2.0/25")
        esperado = self.mod.redes_por_defecto(cerrada)
        abierta = self.conf(REDES_GESTION=ABIERTO)
        self.assertEqual(self.mod.redes_por_defecto(abierta), esperado)
        self.assertIn("192.168.0.0/16", esperado)
        self.assertEqual(self.mod.validar_redes(["10.0.0.0/24", "203.0.113.0/24"], abierta),
                         ["10.0.0.0/24", "203.0.113.0/24"])
        # la base de túneles y el pool siguen reservados
        with self.assertRaises(self.mod.ErrorOrden):
            self.mod.validar_redes(["10.210.1.0/24"], abierta)

    def test_proxy_abierto_sin_proxy_de_confianza(self):
        cfg = self.conf(IPS_PROXY=ABIERTO)
        txt = self.mod.render_core(cfg, A.IMG_PANEL, "0.1.0")
        env = dict(re.findall(r'(?m)^      (IDS_[A-Z_]+|TZ): "([^"]*)"$', txt))
        self.assertEqual(env["IDS_PROXY"], "")
        # con un proxy de verdad, se sigue pasando
        cfg = self.conf(IPS_PROXY="203.0.113.50")
        env = dict(re.findall(r'(?m)^      (IDS_[A-Z_]+|TZ): "([^"]*)"$',
                              self.mod.render_core(cfg, A.IMG_PANEL, "0.1.0")))
        self.assertEqual(env["IDS_PROXY"], "203.0.113.50")

    def test_firewall_abierto(self):
        cfg = self.conf(REDES_GESTION=ABIERTO, IPS_PROXY=ABIERTO)
        nft = self.mod.render_nft(cfg, [1194], [])
        self.assertIn("set gestion     { type ipv4_addr; flags interval; elements = { 0.0.0.0/0 } }", nft)
        self.assertIn("set proxy       { type ipv4_addr; flags interval; elements = { 0.0.0.0/0 } }", nft)
        self.assertIn("ip saddr @gestion tcp dport 22 accept", nft)


if __name__ == "__main__":
    unittest.main()
