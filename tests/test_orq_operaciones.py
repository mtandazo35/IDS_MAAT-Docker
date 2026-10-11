"""arrancar/parar/reiniciar, ajustar, vpn.regenerar, reglas.actualizar y reconciliar con el sistema simulado."""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

NORTE = {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]}


class Operaciones(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(ncpu=8)
        r = A.ejecutar_orden(self.orq, "punto.crear", NORTE)
        self.assertEqual(r["codigo"], "OK")
        self.clave = r["resultado"]["clave"]
        self.s.llamadas.clear()

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_parar_y_arrancar(self):
        r = A.ejecutar_orden(self.orq, "punto.parar", {"pid": "p001"})
        self.assertEqual(r["codigo"], "OK")
        self.assertEqual(r["resultado"]["observado"]["vpn"]["estado"], "exited")
        p = self.orq.punto("p001")
        self.assertEqual((p["deseado"], p["estado"]), ("parado", "parado"))
        r = A.ejecutar_orden(self.orq, "punto.parar", {"pid": "p001"})          # parar lo parado: OK
        self.assertEqual(r["codigo"], "OK")
        r = A.ejecutar_orden(self.orq, "punto.arrancar", {"pid": "p001", "parte": "todo"})
        self.assertEqual(r["codigo"], "OK")
        self.assertEqual(self.orq.punto("p001")["deseado"], "activo")
        self.assertTrue(self.s.ordenes("docker compose -p ids-p001 -f"))
        up = [a for a in self.s.llamadas if "up" in a][-1]
        self.assertEqual(up[-4:], ["up", "-d", "--pull", "never"])

    def test_reiniciar_vpn_primero_y_luego_suricata(self):
        r = A.ejecutar_orden(self.orq, "punto.reiniciar", {"pid": "p001", "parte": "vpn"})
        self.assertEqual(r["codigo"], "OK", r)
        reinicios = [a[-1] for a in self.s.llamadas if a[:2] == ["docker", "restart"]]
        self.assertEqual(reinicios, ["ids-p001-vpn", "ids-p001-suricata"])

    def test_reiniciar_no_sano_pasa_a_error(self):
        self.s.salud_inicial = "unhealthy"
        r = A.ejecutar_orden(self.orq, "punto.reiniciar", {"pid": "p001", "parte": "suricata"})
        self.assertEqual(r["codigo"], "FALLO")
        self.assertEqual(self.orq.punto("p001")["estado"], "error")
        self.assertIn("linea normal", r["log_tail"])
        self.assertFalse([x for x in r["log_tail"] if "password" in x])

    def test_ajustar_perfil_recrea_suricata(self):
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "perfil": "completo", "hilos": 2,
                                                         "redes_abonados": ["10.0.0.0/24", "10.1.0.0/24"]})
        self.assertEqual(r["codigo"], "OK", r)
        self.assertEqual(r["resultado"]["recreado"], ["suricata"])
        compose = self.e.ruta("/srv/ids/puntos/p001/compose.yml").read_text(encoding="utf-8")
        self.assertIn("mem_limit: 1700m", compose)
        self.assertIn('cpuset: "2-3"\n    cpus: 2', compose)
        yaml = self.e.ruta("/srv/ids/puntos/p001/suricata/suricata.yaml").read_text(encoding="utf-8")
        self.assertIn('HOME_NET: "[10.0.0.0/24,10.1.0.0/24]"', yaml)
        self.assertIn("default-rule-path: /reglas/current/completo", yaml)
        self.assertTrue([a for a in self.s.llamadas if "-T" in a])

    def test_ajustar_no_cabe(self):
        self.e.escribir_meminfo(3500, 3000)
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "perfil": "completo"})
        self.assertEqual(r["codigo"], "CONFLICTO")
        self.assertIn("caben", r["resultado"])
        self.assertEqual(self.orq.punto("p001")["perfil"], "reducido")

    def test_ajustar_compat_v6_y_origen(self):
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "ros_version": 6, "compat_v6": "legacy",
                                                         "origen_ip": "203.0.113.45"})
        self.assertEqual(r["codigo"], "OK", r)
        self.assertEqual(sorted(r["resultado"]["recreado"]), ["firewall", "openvpn"])
        conf = self.e.ruta("/srv/ids/puntos/p001/vpn/server.conf").read_text(encoding="utf-8")
        self.assertIn("data-ciphers-fallback AES-256-CBC", conf)
        self.assertIn("tls-cert-profile legacy", conf)
        self.assertTrue(self.s.ordenes("docker exec ids-p001-vpn /command/s6-svc -r /run/service/openvpn"))
        self.assertIn("declarado RouterOS v6", r["resultado"]["comandos"])
        self.assertIn('ip saddr != 203.0.113.45 counter drop comment "origen fijo p001"', self.s.nft_aplicado[-1])
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "origen_ip": None})
        self.assertNotIn("origen fijo", self.s.nft_aplicado[-1])

    def test_regenerar_cambia_hash_y_entrega_clave(self):
        usuarios = self.e.ruta("/srv/ids/puntos/p001/vpn/usuarios")
        antes = usuarios.read_text(encoding="utf-8")
        r = A.ejecutar_orden(self.orq, "punto.vpn.regenerar", {"pid": "p001"})
        self.assertEqual(r["codigo"], "OK")
        despues = usuarios.read_text(encoding="utf-8")
        self.assertNotEqual(antes, despues)
        self.assertEqual(antes.split(":")[0], despues.split(":")[0])          # mismo usuario
        nueva = r["resultado"]["clave"]
        self.assertNotEqual(nueva, self.clave)
        self.assertIn("password=%s " % nueva, r["resultado"]["comandos"])

    def test_reconciliar_levanta_lo_que_falta_e_informa_huerfanos(self):
        del self.s.contenedores["ids-p001-suricata"]
        (self.e.ruta("/srv/ids/puntos/p077")).mkdir()
        r = A.ejecutar_orden(self.orq, "sistema.reconciliar", {})
        self.assertEqual(r["codigo"], "OK")
        self.assertEqual(r["resultado"]["levantados"], ["p001"])
        self.assertEqual(len(r["resultado"]["huerfanos"]), 1)
        self.assertTrue(self.e.ruta("/srv/ids/puntos/p077").exists())       # solo se informa
        self.assertIn("ids-p001-suricata", self.s.contenedores)


@unittest.skipUnless(A.symlinks_posibles(), "este sistema no deja crear enlaces simbólicos")
class Reglas(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()
        for nombre in ("norte", "sur"):
            r = A.ejecutar_orden(self.orq, "punto.crear", {"nombre": nombre, "redes_abonados": ["10.0.0.0/24"]})
            self.assertEqual(r["codigo"], "OK")
        self.s.llamadas.clear()

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_descarga_valida_cambia_current_reinicia_en_serie_y_poda(self):
        base = self.e.ruta("/srv/ids/reglas")
        for ts in ("20261001T081500Z", "20261002T081500Z", "20261003T081500Z"):
            (base / "releases" / ts).mkdir(parents=True)
            (base / "releases" / ts / "LISTO").write_text("", encoding="utf-8")
        r = A.ejecutar_orden(self.orq, "reglas.actualizar", {})
        self.assertEqual(r["codigo"], "OK", r)
        ts = self.s.release_ts
        self.assertEqual(r["resultado"], {"ts": ts, "reglas": {"completo": 50000, "reducido": 18000}})
        self.assertEqual(os.readlink(base / "current"), "releases/%s" % ts)
        # validación: los dos perfiles de reglas, con la ruta de la release nueva y sin red
        pasos = [p["nombre"] for p in r["pasos"]]
        self.assertIn("suricata -T completo", pasos)
        self.assertIn("suricata -T reducido", pasos)
        t = [a for a in self.s.llamadas if "-T" in a]
        self.assertEqual(len(t), 2)
        for a in t:
            self.assertEqual(a[a.index("--network") + 1], "none")
        # reinicio en serie: suricata de p001, luego el de p002
        reinicios = [a[-1] for a in self.s.llamadas if a[:2] == ["docker", "restart"]]
        self.assertEqual(reinicios, ["ids-p001-suricata", "ids-p002-suricata"])
        self.assertLess(pasos.index("cambiar current"), pasos.index("reiniciar p001"))
        rel = sorted(x.name for x in (base / "releases").iterdir())
        self.assertEqual(len(rel), 3)
        self.assertEqual(rel[-1], ts)
        descarga = [a for a in self.s.llamadas if "descargar" in a][0]
        self.assertEqual(descarga[descarga.index("--name") + 1], "ids-reglas-%s" % ts)

    def test_validacion_falla_no_toca_current(self):
        base = self.e.ruta("/srv/ids/reglas")
        antes = os.readlink(base / "current")
        self.s.fallar["-T -c"] = 1
        r = A.ejecutar_orden(self.orq, "reglas.actualizar", {})
        self.assertEqual(r["codigo"], "FALLO")
        self.assertEqual(os.readlink(base / "current"), antes)
        self.assertFalse((base / "releases" / self.s.release_ts).exists())
        self.assertFalse([a for a in self.s.llamadas if a[:2] == ["docker", "restart"]])

    def test_sin_descarga(self):
        r = A.ejecutar_orden(self.orq, "reglas.actualizar", {"sin_descarga": True})
        self.assertEqual(r["codigo"], "OK", r)
        self.assertFalse([a for a in self.s.llamadas if "descargar" in a])
        self.assertEqual(r["resultado"]["ts"], "20261010T081500Z")


class Medir(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()
        A.ejecutar_orden(self.orq, "punto.crear", NORTE)

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_medir_lee_cgroup(self):
        cid = self.s.contenedores["ids-p001-suricata"]["id"]
        d = self.e.kdir / ("sys/fs/cgroup/system.slice/docker-%s.scope" % cid)
        d.mkdir(parents=True)
        (d / "memory.current").write_text(str(700 * 1024 * 1024), encoding="utf-8")
        (d / "memory.peak").write_text(str(812 * 1024 * 1024), encoding="utf-8")
        r = self.orq.atender(A.peticion("punto.medir", {"pid": "p001"}))
        self.assertEqual(r["codigo"], "OK")
        self.assertEqual((r["datos"]["memoria_actual_mb"], r["datos"]["memoria_pico_mb"]), (700, 812))
        self.assertEqual(set(r["datos"]), {"memoria_actual_mb", "memoria_pico_mb", "kernel_packets",
                                           "kernel_drops", "reglas_cargadas", "tzsp"})
        json.dumps(r)


if __name__ == "__main__":
    unittest.main()
