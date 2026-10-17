"""La clave VPN de cada punto la guarda el orquestador CIFRADA y los comandos del MikroTik salen
siempre completos (el user, 2026-10-16: «no le pones la clave a la vpn y toca generar la clave para
que funcione, eso está mal»; «el plan es que las vpn se carguen ya todo»).

- El alta y «Regenerar» la guardan cifrada (AES-256-GCM con la clave maestra, el formato `enc1:` y el
  dato asociado `vpn:<pid>` del panel) y `punto.comandos` da el script con la clave puesta, aunque la
  entrega al panel se haya perdido (orquestador reiniciado).
- Nunca una clave que no es la vigente: se comprueba con el hash que usa ovpn-auth.
- Los puntos de antes la toman de la copia del panel, solo si es la vigente y es de ese punto.
- Nunca en claro: ni en orq.db, ni en orq.jsonl, ni en estado.json, ni en ningún otro fichero.
- Sin clave maestra, como antes: <CLAVE-VPN> y la clave entregada una vez.
- La baja la borra; el alta repetida da los comandos completos.

Tipo «corrección de defecto»: fallan sin el arreglo.
"""

import importlib
import json
import os
import sys
import unittest
from pathlib import Path

AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(AQUI))
import _ayuda_orq as A  # noqa: E402

LIB_PANEL = AQUI.parent / "images" / "panel" / "rootfs" / "usr" / "local" / "lib" / "ids-panel"
NORTE = {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]}
PLACEHOLDER = "<CLAVE-VPN>"


class Base(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()
        r = A.crear(self, self.orq, NORTE)
        self.clave = r["resultado"]["clave"]
        self.usuario = r["resultado"]["usuario"]

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def comandos(self):
        r = self.orq.atender(A.peticion("punto.comandos", {"pid": "p001"}))
        self.assertEqual(r["codigo"], "OK", r)
        return r["datos"]

    def guardada(self):
        f = self.orq.q1("SELECT cifrada FROM clave_vpn WHERE pid='p001'")
        return f[0] if f else None

    def copia_del_panel(self, valor, usuario=None):
        p = self.e.ruta(self.mod.PANEL_VPN_CLAVES)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"v": 1, "puntos": {"p001": {
            "usuario": usuario or self.usuario, "clave": valor, "clave_id": "", "ts": 1}}}), encoding="utf-8")


class ComandosCompletos(Base):
    def test_tras_el_alta_salen_con_la_clave(self):
        d = self.comandos()
        self.assertNotIn(PLACEHOLDER, d["comandos"])
        self.assertEqual(d["comandos"].count("user=%s password=%s " % (self.usuario, self.clave)), 2)   # v7 y v6
        self.assertEqual(d["clave"], self.clave)

    def test_aunque_la_entrega_al_panel_se_pierda(self):
        """Antes: el orquestador se reiniciaba antes de entregar la clave y la ficha salía con
        <CLAVE-VPN> («toca generar la clave para que funcione»). Ahora la tiene guardada."""
        self.orq.db.close()
        self.orq = self.mod.Orquestador()           # reinicio: lo que tenía en memoria se pierde
        d = self.comandos()
        self.assertNotIn(PLACEHOLDER, d["comandos"])
        self.assertIn("password=%s " % self.clave, d["comandos"])

    def test_regenerar_la_sustituye(self):
        r = A.ejecutar_orden(self.orq, "punto.vpn.regenerar", {"pid": "p001"})
        self.assertEqual(r["codigo"], "OK", r)
        nueva = r["resultado"]["clave"]
        self.assertNotEqual(nueva, self.clave)
        d = self.comandos()
        self.assertIn("password=%s " % nueva, d["comandos"])
        self.assertNotIn(self.clave, d["comandos"])

    def test_el_alta_repetida_da_los_comandos_completos(self):
        r = A.crear(self, self.orq, NORTE)
        self.assertEqual(r["mensaje"], "ya existe")
        self.assertEqual(r["resultado"]["clave"], self.clave)
        self.assertNotIn(PLACEHOLDER, r["resultado"]["comandos"])

    def test_la_consola_imprime_el_script_completo(self):
        p = self.orq.punto("p001")
        cmds = self.orq.comandos(p, self.mod.config().nombre_dns, self.orq.clave_vpn_vigente(p))
        self.assertEqual(cmds.count("password=%s " % self.clave), 2)


class NuncaUnaClaveVieja(Base):
    def test_si_el_hash_cambio_por_otro_lado_no_la_da(self):
        """El fichero de usuarios (lo que comprueba ovpn-auth) cambió sin pasar por aquí: la
        guardada ya no es la vigente y no se da por buena."""
        self.orq.escribir_usuarios(self.orq.punto("p001"), self.usuario, "OtraClaveDistinta123456")
        d = self.comandos()
        self.assertIn(PLACEHOLDER, d["comandos"])
        self.assertNotIn(self.clave, d["comandos"])
        self.assertNotIn("clave", d)

    def test_un_valor_manipulado_o_de_otro_punto_no_vale(self):
        v = self.guardada()
        otro = self.mod.cifrar_clave_vpn("p002", self.clave)        # la misma clave, ligada a otro punto
        for malo in (v[:-4] + ("AAAA" if not v.endswith("AAAA") else "BBBB"), otro, self.clave):
            self.orq.x("UPDATE clave_vpn SET cifrada=? WHERE pid='p001'", (malo,))
            d = self.comandos()
            self.assertIn(PLACEHOLDER, d["comandos"], malo[:12])


class PuntosDeAntes(Base):
    def setUp(self):
        super().setUp()
        self.orq.x("DELETE FROM clave_vpn WHERE pid='p001'")        # como un punto de antes del cambio

    def test_toma_la_del_panel_si_es_la_vigente(self):
        self.copia_del_panel(self.mod.cifrar_clave_vpn("p001", self.clave))
        d = self.comandos()
        self.assertIn("password=%s " % self.clave, d["comandos"])
        self.assertTrue(self.guardada().startswith("enc1:"))            # adoptada: ya no depende del panel
        self.e.ruta(self.mod.PANEL_VPN_CLAVES).unlink()
        self.assertIn("password=%s " % self.clave, self.comandos()["comandos"])

    def test_no_toma_una_del_panel_que_no_vale(self):
        for valor, usuario in ((self.mod.cifrar_clave_vpn("p001", "ClaveViejaDelPanel000000"), None),
                               (self.mod.cifrar_clave_vpn("p002", self.clave), None),
                               (self.mod.cifrar_clave_vpn("p001", self.clave), "vpn000000"),
                               (self.clave, None)):                        # en claro: nunca
            self.copia_del_panel(valor, usuario)
            d = self.comandos()
            self.assertIn(PLACEHOLDER, d["comandos"])
            self.assertIsNone(self.guardada())

    def test_sin_ninguna_salen_como_antes(self):
        d = self.comandos()
        self.assertEqual(d["comandos"].count("password=%s " % PLACEHOLDER), 2)
        self.assertNotIn("clave", d)


class NuncaEnClaro(Base):
    def test_ningun_fichero_la_lleva_en_claro(self):
        self.comandos()
        A.ejecutar_orden(self.orq, "punto.estado", {"pid": "p001"})
        self.orq.escribir_estado()
        self.assertTrue(self.guardada().startswith("enc1:"))
        self.assertEqual(self.mod.descifrar_clave_vpn("p001", self.guardada()), self.clave)
        crudo = self.clave.encode("ascii")
        for raiz, _dirs, ficheros in os.walk(self.e.dir):
            for f in ficheros:
                ruta = os.path.join(raiz, f)
                with open(ruta, "rb") as fh:
                    self.assertNotIn(crudo, fh.read(), ruta)

    def test_mismo_formato_que_el_panel(self):
        """La copia del panel (secretos.py) y la del orquestador se leen la una a la otra."""
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("sin python3-cryptography")
        antes = os.environ.get("IDS_MASTER_KEY")
        os.environ["IDS_MASTER_KEY"] = str(self.e.ruta(self.mod.MASTER_KEY))
        self.addCleanup(lambda: os.environ.pop("IDS_MASTER_KEY", None) if antes is None
                        else os.environ.__setitem__("IDS_MASTER_KEY", antes))
        sys.path.insert(0, str(LIB_PANEL))
        self.addCleanup(sys.path.remove, str(LIB_PANEL))
        secretos = importlib.import_module("secretos")
        secretos._cache.update(ruta=None, clave=None)
        self.assertEqual(secretos.descifrar(self.mod.cifrar_clave_vpn("p001", "abc123"), "vpn:p001"), "abc123")
        self.assertEqual(self.mod.descifrar_clave_vpn("p001", secretos.cifrar("abc123", "vpn:p001")), "abc123")
        secretos._cache.update(ruta=None, clave=None)


class BajaYSinClaveMaestra(Base):
    def test_la_baja_la_borra(self):
        r = A.ejecutar_orden(self.orq, "punto.borrar", {"pid": "p001", "confirmar": "norte"})
        self.assertEqual(r["codigo"], "OK", r)
        self.assertIsNone(self.guardada())

    def test_sin_clave_maestra_como_antes(self):
        self.e.ruta(self.mod.MASTER_KEY).unlink()
        r = A.crear(self, self.orq, {"nombre": "sur", "redes_abonados": ["10.1.0.0/24"]})
        self.assertTrue(r["resultado"]["clave"])                         # se entrega igual, una vez
        self.assertIsNone(self.orq.q1("SELECT cifrada FROM clave_vpn WHERE pid='p002'"))
        d = self.orq.atender(A.peticion("punto.comandos", {"pid": "p002"}))["datos"]
        self.assertIn(PLACEHOLDER, d["comandos"])
        self.assertNotIn("clave", d)


if __name__ == "__main__":
    unittest.main()
