"""Plantilla suricata.yaml.tmpl y plantilla.json (CONTRATO-F1a §4.6): marcadores, render
por instancia y estructura del yaml resultante."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_suricata as A  # noqa: E402

try:
    import yaml as pyyaml
except ImportError:  # el CI usa solo la stdlib
    pyyaml = None

FUERA_DEL_EVE = {"flow", "dns", "quic", "anomaly", "ike", "bittorrent-dht"}


def nombres_tipos(tipos):
    out = []
    for t in tipos:
        out.append(next(iter(t)) if isinstance(t, dict) else t)
    return out


def salida(cfg, clave, **filtro):
    """Las entradas de outputs de un tipo, filtradas por sus campos."""
    res = []
    for o in cfg["outputs"]:
        if clave in o and all(o[clave].get(k) == v for k, v in filtro.items()):
            res.append(o[clave])
    return res


class Marcadores(unittest.TestCase):
    def setUp(self):
        self.tmpl = A.PLANTILLA.read_text(encoding="utf-8")
        self.man = json.loads(A.MANIFIESTO.read_text(encoding="utf-8"))

    def test_manifiesto_igual_al_contrato(self):
        contrato = json.loads((A.FIXTURES / "marcadores-contrato.json").read_text(encoding="utf-8"))
        self.assertEqual(self.man["v"], 1)
        self.assertEqual(self.man["plantilla_version"], 1)
        self.assertEqual(self.man["marcadores"], contrato["marcadores"])

    def test_plantilla_tiene_exactamente_los_marcadores(self):
        self.assertEqual(A.marcadores_de(self.tmpl), set(self.man["marcadores"]))
        self.assertEqual(len(self.man["marcadores"]), len(set(self.man["marcadores"])))

    def test_render_no_deja_marcadores(self):
        out = A.render(self.tmpl, self.man["marcadores"], A.VALORES_PRUEBA)
        self.assertNotIn("@@", out)

    def test_render_falla_si_falta_un_valor(self):
        valores = dict(A.VALORES_PRUEBA)
        del valores["CLUSTER_ID"]
        with self.assertRaises(A.ErrorRender):
            A.render(self.tmpl, self.man["marcadores"], valores)

    def test_render_falla_si_sobra_un_valor(self):
        with self.assertRaises(A.ErrorRender):
            A.render(self.tmpl, self.man["marcadores"], dict(A.VALORES_PRUEBA, OTRO="x"))

    def test_render_falla_si_la_plantilla_trae_un_marcador_de_mas(self):
        with self.assertRaises(A.ErrorRender):
            A.render(self.tmpl + "\n# @@NUEVO@@\n", self.man["marcadores"], A.VALORES_PRUEBA)

    def test_render_falla_si_a_la_plantilla_le_falta_un_marcador(self):
        recortada = self.tmpl.replace("@@SNAPLEN@@", "32768")
        with self.assertRaises(A.ErrorRender):
            A.render(recortada, self.man["marcadores"], A.VALORES_PRUEBA)

    def test_texto_utf8_sin_bom_ni_crlf_ni_tabuladores(self):
        datos = A.PLANTILLA.read_bytes()
        self.assertFalse(datos.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", datos)
        self.assertNotIn(b"\t", datos)
        self.assertTrue(datos.startswith(b"%YAML 1.1\n---\n"))


class Estructura(unittest.TestCase):
    """El yaml renderizado dice lo que el contrato fija (§4.6 y INSTANCIA §5-6)."""

    @classmethod
    def setUpClass(cls):
        cls.texto = A.render_imagen()
        cls.cfg = A.yaml_subconjunto(cls.texto)

    def test_identidad_y_rutas(self):
        c = self.cfg
        self.assertEqual(c["sensor-name"], "p003")
        self.assertEqual(c["vars"]["address-groups"]["HOME_NET"], "[10.0.0.0/24,192.168.88.0/24]")
        self.assertEqual(c["vars"]["address-groups"]["EXTERNAL_NET"], "!$HOME_NET")
        self.assertEqual(c["default-log-dir"], "/var/log/suricata")
        self.assertEqual(c["default-rule-path"], "/reglas/current/reducido")
        self.assertEqual(c["rule-files"], ["suricata.rules", "local.rules"])
        self.assertEqual(c["classification-file"], "/reglas/current/reducido/classification.config")
        self.assertEqual(c["threshold-file"], "/etc/ids/suricata/threshold.config")
        self.assertEqual(c["unix-command"], {"enabled": "yes",
                                             "filename": "/run/suricata/suricata-command.socket"})

    def test_variables_que_usan_las_reglas_de_et(self):
        grupos = self.cfg["vars"]["address-groups"]
        puertos = self.cfg["vars"]["port-groups"]
        for v in ("HTTP_SERVERS", "SMTP_SERVERS", "SQL_SERVERS", "DNS_SERVERS", "TELNET_SERVERS",
                  "AIM_SERVERS", "DC_SERVERS", "DNP3_SERVER", "DNP3_CLIENT", "MODBUS_CLIENT",
                  "MODBUS_SERVER", "ENIP_CLIENT", "ENIP_SERVER"):
            self.assertIn(v, grupos)
        for v in ("HTTP_PORTS", "SHELLCODE_PORTS", "ORACLE_PORTS", "SSH_PORTS", "DNP3_PORTS",
                  "MODBUS_PORTS", "FILE_DATA_PORTS", "FTP_PORTS", "GENEVE_PORTS", "VXLAN_PORTS",
                  "TEREDO_PORTS"):
            self.assertIn(v, puertos)

    def test_captura_af_packet_fija(self):
        af = self.cfg["af-packet"]
        self.assertEqual(len(af), 1)
        a = af[0]
        self.assertEqual(a["interface"], "ids-mon")
        self.assertEqual(a["cluster-id"], "103")
        self.assertEqual(a["threads"], "1")
        self.assertEqual(a["cluster-type"], "cluster_flow")
        for k in ("defrag", "use-mmap", "tpacket-v3"):
            self.assertEqual(a[k], "yes", k)
        self.assertEqual(a["checksum-checks"], "no")
        self.assertEqual((a["ring-size"], a["block-size"], a["snaplen"]), ("1024", "131072", "32768"))
        self.assertEqual(self.cfg["runmode"], "workers")
        self.assertEqual(self.cfg["threading"]["set-cpu-affinity"], "no")

    def test_ajustes_de_espejo(self):
        s = self.cfg["stream"]
        self.assertEqual(s["memcap"], "64mb")
        self.assertEqual(s["checksum-validation"], "no")
        self.assertEqual((s["midstream"], s["async-oneside"], s["bypass"]), ("true", "true", "yes"))
        self.assertEqual(s["reassembly"]["memcap"], "256mb")
        # espejo de 10 KB por conexion (205.235.2.157, 2026-10-16): no se llega a mas
        self.assertEqual(s["reassembly"]["depth"], "64kb")
        self.assertEqual(self.cfg["flow"]["memcap"], "64mb")
        self.assertEqual(self.cfg["defrag"]["memcap"], "32mb")
        # timeouts cortos: Suricata casi nunca ve el cierre de una conexion recortada a 10 KB y con 300 s
        # los flujos llenaban la memoria (124 692 activos a ~3 800 paq/s, OOM cada ~5 min)
        ft = self.cfg["flow-timeouts"]
        self.assertEqual([ft[k]["established"] for k in ("default", "tcp", "udp", "icmp")], ["60"] * 4)
        self.assertEqual(ft["tcp"]["closed"], "10")
        tls = self.cfg["app-layer"]["protocols"]["tls"]
        self.assertEqual(tls["encryption-handling"], "bypass")

    def test_deteccion(self):
        d = self.cfg["detect"]
        self.assertEqual((d["profile"], d["sgh-mpm-context"]), ("medium", "auto"))
        self.assertEqual((self.cfg["mpm-algo"], self.cfg["spm-algo"]), ("hs", "hs"))

    def test_eve_principal_sin_tipos_ruidosos_y_con_stats_totales(self):
        eves = salida(self.cfg, "eve-log", filename="eve.json")
        self.assertEqual(len(eves), 1)
        eve = eves[0]
        self.assertEqual(eve["enabled"], "yes")
        tipos = nombres_tipos(eve["types"])
        self.assertFalse(FUERA_DEL_EVE & set(tipos), tipos)
        self.assertIn("alert", tipos)
        stats = [t["stats"] for t in eve["types"] if isinstance(t, dict) and "stats" in t]
        self.assertEqual(stats, [{"totals": "yes", "threads": "no", "deltas": "no"}])

    def test_dns_aparte_solo_consultas(self):
        dns = salida(self.cfg, "eve-log", filename="dns.json")
        self.assertEqual(len(dns), 1)
        self.assertEqual(dns[0]["types"], [{"dns": {"requests": "yes", "responses": "no"}}])

    def test_sin_logs_de_texto_en_disco(self):
        self.assertEqual(salida(self.cfg, "fast")[0]["enabled"], "no")
        self.assertEqual(salida(self.cfg, "stats")[0]["enabled"], "no")
        self.assertEqual(self.cfg["stats"], {"enabled": "yes", "interval": "30"})
        self.assertEqual(self.cfg["logging"]["outputs"], [{"console": {"enabled": "yes"}}])

    def test_dataset_absoluto_solo_lectura(self):
        r = self.cfg["datasets"]["rules"]
        self.assertEqual(r["allow-absolute-filenames"], "yes")
        self.assertEqual(r["allow-write"], "no")

    @unittest.skipIf(pyyaml is None, "PyYAML no disponible (el CI usa solo la stdlib)")
    def test_yaml_valido_con_pyyaml(self):
        cfg = pyyaml.safe_load(self.texto)
        self.assertEqual(cfg["af-packet"][0]["cluster-id"], 103)
        self.assertEqual(cfg["default-rule-path"], "/reglas/current/reducido")
        self.assertEqual(set(cfg), set(self.cfg))


class ValoresPorInstancia(unittest.TestCase):
    def test_otra_instancia_otro_perfil(self):
        cfg = A.yaml_subconjunto(A.render_imagen({
            "SENSOR_NAME": "p012", "CLUSTER_ID": "112", "HILOS": "2",
            "HOME_NET": "[100.70.0.0/16]", "RULE_PATH": "/reglas/current/completo",
            "DETECT_PROFILE": "low", "SGH_MPM_CONTEXT": "single",
            "MPM_ALGO": "ac-ks", "SPM_ALGO": "bm", "REASSEMBLY_MEMCAP": "128mb"}))
        self.assertEqual(cfg["sensor-name"], "p012")
        self.assertEqual(cfg["af-packet"][0]["cluster-id"], "112")
        self.assertEqual(cfg["af-packet"][0]["threads"], "2")
        self.assertEqual(cfg["vars"]["address-groups"]["HOME_NET"], "[100.70.0.0/16]")
        self.assertEqual(cfg["default-rule-path"], "/reglas/current/completo")
        self.assertEqual(cfg["classification-file"], "/reglas/current/completo/classification.config")
        self.assertEqual((cfg["detect"]["profile"], cfg["detect"]["sgh-mpm-context"]), ("low", "single"))
        self.assertEqual((cfg["mpm-algo"], cfg["spm-algo"]), ("ac-ks", "bm"))
        self.assertEqual(cfg["stream"]["reassembly"]["memcap"], "128mb")

    def test_yaml_de_validacion_del_orquestador(self):
        ts = "20261010T081500Z"
        for perfil in ("completo", "reducido"):
            cfg = A.yaml_subconjunto(A.render_imagen({
                "SENSOR_NAME": "validacion", "HOME_NET": "[10.0.0.0/8]",
                "RULE_PATH": "/reglas/releases/%s/%s" % (ts, perfil)}))
            self.assertEqual(cfg["default-rule-path"], "/reglas/releases/%s/%s" % (ts, perfil))
            self.assertEqual(cfg["sensor-name"], "validacion")


class ParserSubconjunto(unittest.TestCase):
    """El parser de las pruebas detecta errores de verdad (si no, las pruebas de arriba no
    valdrían nada)."""

    def test_clave_repetida(self):
        with self.assertRaises(A.ErrorYaml):
            A.yaml_subconjunto("a:\n  b: 1\na:\n  c: 2\n")

    def test_tabulador(self):
        with self.assertRaises(A.ErrorYaml):
            A.yaml_subconjunto("a:\n\tb: 1\n")

    def test_sangria_incoherente(self):
        with self.assertRaises(A.ErrorYaml):
            A.yaml_subconjunto("a:\n  b: 1\n   c: 2\n")

    def test_listas_y_mapas(self):
        self.assertEqual(A.yaml_subconjunto(
            "x:\n  - a: 1\n    b: 2\n  - c\ny: \"q # no\"  # comentario\n"),
            {"x": [{"a": "1", "b": "2"}, "c"], "y": "q # no"})


if __name__ == "__main__":
    unittest.main()
