"""Puntos, apartado A: espera de salud del alta (D1), logs antes de deshacer (D2), estado `error`
con motivo y que se cura (D3), status de OpenVPN viejo (D5), imágenes presentes (D7) y menores
(D11 RAM antes del pid, D13 nada de reinicios en `creando`). Con el Docker simulado."""

import json
import os
import re
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

NORTE = {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]}

STATUS = """TITLE,OpenVPN 2.6.14 x86_64-pc-linux-gnu
HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher
CLIENT_LIST,vpn3a9f2c,203.0.113.45:51234,100.64.1.2,,1000,2000,2026-10-10 06:15:00,1760077000,vpn3a9f2c,0,0,AES-256-GCM
END
"""


class Base(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(ncpu=8)

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def llamada(self, prefijo):
        """Índice de la primera llamada que empieza por `prefijo` (o None)."""
        for i, a in enumerate(self.s.llamadas):
            if " ".join(a).startswith(prefijo):
                return i
        return None


class EsperaSalud(Base):
    """D1: el alta no se deshace porque Suricata tarde en cargar reglas."""

    def test_limite_propio(self):
        mod = A.cargar_orq()                         # constantes reales, sin el simulador
        self.assertEqual(mod.ESPERA_SALUD_S, 300)
        self.assertEqual(mod.limite_salud(None), 300)
        self.assertEqual(mod.limite_salud(50), 300)
        self.assertEqual(mod.limite_salud(200), 490)          # 2 × 200 + 90

    def test_alta_mide_el_T_y_lo_usa(self):
        vistos = []
        real = self.mod.limite_salud
        self.mod.limite_salud = lambda dur: vistos.append(dur) or real(dur)
        A.crear(self, self.orq, NORTE)
        self.assertEqual(len(vistos), 1)
        self.assertIsInstance(vistos[0], float)               # la duración medida del -T
        vistos.clear()
        r = A.ejecutar_orden(self.orq, "punto.arrancar", {"pid": "p001"})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertEqual(vistos, [None])                      # sin -T: 300 s

    def test_sigue_arrancando_no_deshace(self):
        """Corrección de defecto: antes daba REVERTIDA y lo borraba todo."""
        self.s.salud_inicial = "starting"
        r = A.crear(self, self.orq, NORTE)
        self.assertIn("Suricata sigue cargando reglas; la supervisión lo vigila", r["mensaje"])
        p = self.orq.punto("p001")
        self.assertEqual((p["estado"], p["paso_error"]), ("activo", None))
        self.assertIn("clave", r["resultado"])                # la credencial se entrega igual
        self.assertIn("ids-p001-suricata", self.s.contenedores)

    def test_unhealthy_si_deshace(self):
        self.s.salud_inicial = "unhealthy"
        r = A.crear(self, self.orq, NORTE, "REVERTIDA")
        self.assertIn("esperar salud", r["mensaje"])
        self.assertIsNone(self.orq.punto("p001"))

    def test_exited_deshace_sin_esperar(self):
        self.s.forzar_parte["suricata"] = {"estado": "exited", "salud": "none"}
        self.mod.ESPERA_SALUD_S = 30                          # no llega a esperarlo: sale enseguida
        t0 = time.monotonic()
        r = A.crear(self, self.orq, NORTE, "REVERTIDA")
        self.assertLess(time.monotonic() - t0, 10)
        self.assertIn("suricata=exited", r["mensaje"])

    def test_arrancar_sigue_arrancando_queda_activo_con_aviso(self):
        A.crear(self, self.orq, NORTE)
        A.ejecutar_orden(self.orq, "punto.parar", {"pid": "p001"})
        self.s.salud_inicial = "starting"
        r = A.ejecutar_orden(self.orq, "punto.arrancar", {"pid": "p001"})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertIn("sigue cargando reglas", r["mensaje"])
        self.assertEqual(self.orq.punto("p001")["estado"], "activo")

    def test_plantilla_sondea_cada_5_s_al_arrancar(self):
        A.crear(self, self.orq, NORTE)
        compose = self.e.ruta("/srv/ids/puntos/p001/compose.yml").read_text(encoding="utf-8")
        self.assertEqual(compose.count("start_interval: 5s"), 2)
        m = [int(x) for x in re.findall(r"start_period: (\d+)s", compose)]
        self.assertEqual(len(m), 2)
        # Docker no lo marca unhealthy antes de que venza la espera mínima del orquestador
        self.assertGreaterEqual(m[1], 300)


class LogsAntesDeDeshacer(Base):
    """D2: el log de la op lleva las últimas líneas de cada contenedor antes del deshacer."""

    def comprobar(self, r):
        self.assertIn("[vpn] linea normal", r["log_tail"])
        self.assertIn("[suricata] linea normal", r["log_tail"])
        self.assertIn("[suricata] otra linea", r["log_tail"])
        self.assertFalse([x for x in r["log_tail"] if "password" in x.lower() or "key" in x.lower()])

    def test_salud_fallida_en_el_alta(self):
        self.s.salud_inicial = "unhealthy"
        r = A.crear(self, self.orq, NORTE, "REVERTIDA")
        self.comprobar(r)
        logs = self.llamada("docker logs --tail 40 ids-p001-vpn")
        down = [i for i, a in enumerate(self.s.llamadas) if "down" in a]
        self.assertIsNotNone(logs)
        self.assertTrue(down and logs < down[0], "los logs se leen ANTES de deshacer")

    def test_compose_up_fallido_en_el_alta(self):
        self.s.fallar["up -d --pull never"] = 1
        r = A.crear(self, self.orq, NORTE, "REVERTIDA")
        self.assertIn("compose up", r["mensaje"])
        self.comprobar(r)

    def test_reiniciar_fallido(self):
        A.crear(self, self.orq, NORTE)
        self.s.salud_inicial = "unhealthy"
        r = A.ejecutar_orden(self.orq, "punto.reiniciar", {"pid": "p001", "parte": "suricata"})
        self.assertEqual(r["codigo"], "FALLO")
        self.comprobar(r)

    def test_ajustar_fallido(self):
        A.crear(self, self.orq, NORTE)
        self.s.salud_inicial = "unhealthy"
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "perfil": "completo-low"})
        self.assertEqual(r["codigo"], "FALLO")
        self.comprobar(r)


class EstadoError(Base):
    """D3: `error` publica su motivo y se cura solo cuando todo lleva 3 min sano."""

    def setUp(self):
        super().setUp()
        A.crear(self, self.orq, NORTE)

    def poner_en_error(self):
        self.s.salud_inicial = "unhealthy"
        r = A.ejecutar_orden(self.orq, "punto.reiniciar", {"pid": "p001", "parte": "suricata"})
        self.assertEqual(r["codigo"], "FALLO")
        self.assertEqual(self.orq.punto("p001")["estado"], "error")
        for c in self.s.contenedores.values():
            c["salud"] = "healthy"
        self.s.salud_inicial = "healthy"

    def test_motivo_en_estado_json(self):
        p = self.orq.escribir_estado()["puntos"]["p001"]
        self.assertEqual((p["paso_error"], p["error_desde"]), (None, None))
        antes = int(time.time())
        self.poner_en_error()
        p = json.loads(self.e.ruta("/srv/ids/run/estado.json").read_text(encoding="utf-8"))["puntos"]["p001"]
        self.assertEqual(p["estado"], "error")
        self.assertTrue(p["paso_error"].startswith("esperar salud: "), p["paso_error"])
        self.assertIn("suricata=running/unhealthy", p["paso_error"])
        self.assertLessEqual(len(p["paso_error"]), 300)
        self.assertIsInstance(p["error_desde"], int)
        self.assertGreaterEqual(p["error_desde"], antes)

    def test_tres_reinicios_guardan_motivo(self):
        t = int(time.time())
        for _ in range(3):
            self.orq.x("INSERT INTO reinicio (pid, parte, ts) VALUES ('p001','vpn',?)", (t,))
        self.orq.programar_reinicio("p001", "vpn", t)
        p = self.orq.punto("p001")
        self.assertEqual(p["estado"], "error")
        self.assertEqual(p["paso_error"], "vpn unhealthy tras 3 reinicios en 1 h")
        self.assertIsInstance(p["error_desde"], int)

    def test_se_cura_tras_3_min_sano(self):
        self.poner_en_error()
        t = time.time() + 1000
        self.orq.tick(t)
        self.orq.tick(t + 100)
        self.assertEqual(self.orq.punto("p001")["estado"], "error")
        est = self.orq.tick(t + 181)
        p = self.orq.punto("p001")
        self.assertEqual((p["estado"], p["paso_error"], p["error_desde"]), ("activo", None, None))
        self.assertEqual((est["puntos"]["p001"]["estado"], est["puntos"]["p001"]["paso_error"]),
                         ("activo", None))
        diario = [json.loads(x) for x in self.e.ruta("/srv/ids/estado/orq.jsonl").read_text(
            encoding="utf-8").splitlines()]
        curados = [x for x in diario if x.get("evento") == "supervision.curado"]
        self.assertEqual(len(curados), 1)
        self.assertEqual(curados[0]["pid"], "p001")
        self.assertIn("esperar salud", curados[0]["paso_error"])

    def test_un_bache_reinicia_la_cuenta(self):
        self.poner_en_error()
        t = time.time() + 1000
        self.orq.tick(t)
        self.s.contenedores["ids-p001-vpn"]["salud"] = "starting"
        self.orq.tick(t + 100)
        self.s.contenedores["ids-p001-vpn"]["salud"] = "healthy"
        self.orq.tick(t + 200)
        self.orq.tick(t + 300)
        self.assertEqual(self.orq.punto("p001")["estado"], "error")
        self.orq.tick(t + 381)
        self.assertEqual(self.orq.punto("p001")["estado"], "activo")

    def test_parado_no_se_cura(self):
        self.poner_en_error()
        self.orq.x("UPDATE punto SET deseado='parado'")
        t = time.time() + 1000
        self.orq.tick(t)
        self.orq.tick(t + 200)
        self.assertEqual(self.orq.punto("p001")["estado"], "error")

    def test_migracion_de_orq_db_sin_error_desde(self):
        self.orq.x("ALTER TABLE punto DROP COLUMN error_desde")
        self.orq.db.close()
        self.orq = self.mod.Orquestador()
        columnas = {f[1] for f in self.orq.q("PRAGMA table_info(punto)")}
        self.assertIn("error_desde", columnas)
        self.assertEqual(self.orq.punto("p001")["estado"], "activo")


class StatusViejo(Base):
    """D5: un openvpn-status.log que nadie reescribe no dice «conectado»."""

    def test_mtime(self):
        A.crear(self, self.orq, NORTE)
        f = self.e.ruta("/srv/ids/run/p001/openvpn-status.log")
        f.write_text(STATUS, encoding="utf-8")
        r = self.mod.leer_status_openvpn(f)
        self.assertEqual((r["conectado"], r["viejo"], r["ip_real"]), (True, False, "203.0.113.45"))
        viejo = time.time() - 46
        os.utime(f, (viejo, viejo))
        r = self.mod.leer_status_openvpn(f)
        self.assertEqual((r["conectado"], r["viejo"]), (False, True))
        p = self.orq.escribir_estado()["puntos"]["p001"]
        self.assertEqual((p["vpn_cliente"]["conectado"], p["vpn_cliente"]["viejo"]), (False, True))

    def test_sin_fichero_no_es_viejo(self):
        r = self.mod.leer_status_openvpn(self.e.ruta("/srv/ids/run/p009/openvpn-status.log"))
        self.assertEqual((r["conectado"], r["viejo"]), (False, False))


class Imagenes(Base):
    """D7: sin las imágenes no se empieza y nada descarga a escondidas."""

    def test_falta_una_imagen(self):
        self.s.imagenes_faltan.add(A.IMG_SUR)
        r = A.crear(self, self.orq, NORTE, "FALLO")
        self.assertIn("falta la imagen %s" % A.IMG_SUR, r["mensaje"])
        self.assertIn("docker pull %s" % A.IMG_SUR, r["mensaje"])
        self.assertEqual([p["nombre"] for p in r["pasos"]], ["validar"])
        self.assertFalse([a for a in self.s.llamadas if "-T" in a])
        self.assertIsNone(self.orq.punto("p001"))
        self.s.imagenes_faltan.clear()
        r = A.crear(self, self.orq, NORTE)
        self.assertEqual(r["resultado"]["pid"], "p001")          # el pid no se gastó

    def test_pull_never_en_create_y_run(self):
        A.crear(self, self.orq, NORTE)
        lanzados = [a for a in self.s.llamadas if a[:2] in (["docker", "run"], ["docker", "create"])]
        self.assertTrue(lanzados)
        for a in lanzados:
            self.assertEqual(a[2:4], ["--pull", "never"], a)
        self.assertTrue([a for a in lanzados if "-T" in a])
        self.assertTrue([a for a in lanzados if a[1] == "create"])


class Menores(Base):
    def test_ram_antes_de_reservar_pid(self):
        """D11: un alta que no cabe no gasta pid."""
        self.e.escribir_meminfo(3500, 3000)
        r = A.crear(self, self.orq, NORTE, "CONFLICTO")
        self.assertIn("caben", r["resultado"])
        self.assertEqual([p["nombre"] for p in r["pasos"]], ["validar"])
        self.e.escribir_meminfo(16000, 15000)
        r = A.crear(self, self.orq, NORTE)
        self.assertEqual(r["resultado"]["pid"], "p001")

    def test_no_programa_reinicios_en_creando(self):
        """D13."""
        A.crear(self, self.orq, NORTE)
        self.orq.x("UPDATE punto SET estado='creando'")
        self.orq.programar_reinicio("p001", "suricata")
        self.assertEqual(self.orq._programados, {})


if __name__ == "__main__":
    unittest.main()
