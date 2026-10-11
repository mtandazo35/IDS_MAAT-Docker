"""Perfiles de reglas (CONTRATO-F1a §5.9): qué quitan disable-comun.conf y
disable-reducido.conf sobre un conjunto de reglas de prueba con los grupos de ET Open, y
que el sid 2100498 sigue activo en los dos perfiles."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_suricata as A  # noqa: E402

R = A.cargar("ids-reglas")
ET = A.FIXTURES / "et" / "rules"


def conjunto_prueba():
    grupos = {}
    for f in sorted(ET.glob("*.rules")):
        if f.name == "emerging-deleted.rules":
            continue
        grupos[f.name] = [l for l in f.read_text(encoding="utf-8").splitlines()
                          if l.strip() and not l.startswith("#")]
    return grupos


def sids(reglas):
    return {R._sid_gid(r)[0] for r in reglas}


def conf(nombre):
    return R.leer_conf_disable((A.SHARE / nombre).read_text(encoding="utf-8"))


class Semantica(unittest.TestCase):
    REGLA = 'alert ip any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"x"; sid:2100498; rev:7;)'

    def test_sid_y_gid_sid(self):
        self.assertTrue(R.casa_disable("2100498", self.REGLA, "g.rules"))
        self.assertTrue(R.casa_disable("1:2100498", self.REGLA, "g.rules"))
        self.assertFalse(R.casa_disable("3:2100498", self.REGLA, "g.rules"))
        self.assertFalse(R.casa_disable("210049", self.REGLA, "g.rules"))
        self.assertFalse(R.casa_disable("21004981", self.REGLA, "g.rules"))

    def test_grupo_con_comodin(self):
        self.assertTrue(R.casa_disable("group:emerging-attack_*", self.REGLA, "rules/emerging-attack_response.rules"))
        self.assertFalse(R.casa_disable("group:emerging-policy.rules", self.REGLA, "emerging-attack_response.rules"))

    def test_regex_sin_mayusculas(self):
        self.assertTrue(R.casa_disable('re:msg:"gpl attack_response', self.REGLA, None))
        self.assertFalse(R.casa_disable('re:msg:"SURICATA\\s', self.REGLA, None))

    def test_comentarios_y_vacias_fuera(self):
        self.assertEqual(R.leer_conf_disable("# x\n\n  2100498 \n#2\n"), ["2100498"])

    def test_sid_activo_ignora_comentadas(self):
        self.assertTrue(R.sid_activo(self.REGLA + "\n", 2100498))
        self.assertFalse(R.sid_activo("# " + self.REGLA + "\n", 2100498))
        self.assertFalse(R.sid_activo(self.REGLA.replace("2100498", "21004980") + "\n", 2100498))


class PerfilesReales(unittest.TestCase):
    """Los .conf de la imagen aplicados al conjunto de prueba."""

    @classmethod
    def setUpClass(cls):
        cls.grupos = conjunto_prueba()
        cls.comun = conf("disable-comun.conf")
        cls.reducido = cls.comun + conf("disable-reducido.conf")
        cls.completo_sids = sids(R.filtrar(cls.grupos, cls.comun))
        cls.reducido_sids = sids(R.filtrar(cls.grupos, cls.reducido))

    def test_sid_e2e_en_los_dos_perfiles(self):
        self.assertIn(2100498, self.completo_sids)
        self.assertIn(2100498, self.reducido_sids)

    def test_ninguna_entrada_quita_el_sid_e2e(self):
        """Ni por su grupo real de ET ni por sid o regex (que valen en cualquier grupo)."""
        regla = next(r for r in self.grupos["emerging-attack_response.rules"] if "sid:2100498;" in r)
        for e in self.reducido:
            self.assertFalse(R.casa_disable(e, regla, "emerging-attack_response.rules"),
                             "%s quita el 2100498" % e)
            if not e.startswith(("group:", "filename:")):
                self.assertFalse(R.casa_disable(e, regla, None), "%s quita el 2100498" % e)

    def test_comun_quita_el_ruido_del_espejo(self):
        self.assertNotIn(2210029, self.completo_sids)       # SURICATA STREAM (group:)
        self.assertNotIn(2200000, self.completo_sids)       # SURICATA decoder (re:msg)
        self.assertNotIn(2016149, self.completo_sids)       # STUN por sid
        self.assertNotIn(2033078, self.completo_sids)

    def test_completo_conserva_lo_de_et(self):
        for sid in (2900001, 2900010, 2900011, 2900020, 2900030, 2900040, 2900050, 2900060, 2900070):
            self.assertIn(sid, self.completo_sids)

    def test_reducido_quita_politica_inventario_y_caza(self):
        for sid in (2900020, 2900030, 2900040, 2900050, 2900060, 2900070):
            self.assertNotIn(sid, self.reducido_sids)

    def test_reducido_conserva_malware_y_attack_response(self):
        for sid in (2100498, 2900001, 2900010, 2900011):
            self.assertIn(sid, self.reducido_sids)

    def test_reducido_es_subconjunto_de_completo(self):
        self.assertLess(self.reducido_sids, self.completo_sids)


if __name__ == "__main__":
    unittest.main()
