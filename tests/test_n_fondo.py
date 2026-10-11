"""Núcleo del panel (N): tareas de fondo por punto, evidencia reciente y salud por etapas
(CONTRATO-F2 §3, §10.4, §10.6).
"""
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "panel2"))
import _dash  # noqa: E402

K1 = "p001|" + _dash.IP
K2 = "p002|" + _dash.IP


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = _dash.Arbol(self.tmp.name)
        self.d = _dash.cargar(self.a)
        self.n = self.d.nodos
        self.n.asegurar_dirs()
        self.registro = []
        self.d.mk_conectar = _dash.conectar_falso(self.registro)
        self.d.enviar_telegram = lambda txt: False
        self.d.guardar_routers([{"id": "p001", "USER": "ids-api", "PASS": "c1", "ENABLED": "1"},
                                {"id": "p002", "USER": "ids-api", "PASS": "c2", "ENABLED": "1"}])
        self.d.guardar_mk({"AUTO_MANTENER": "1", "POL_AUTO": "1", "POL_BOTNET": "alto"})

    def tearDown(self):
        self.n.quitar_nodo()
        _dash.restaurar()
        self.tmp.cleanup()

    def enviados(self, entradas):
        with open(self.d.MK_SENT, "w", encoding="utf-8") as f:
            json.dump(entradas, f)

    def routers_tocados(self):
        return {rid for rid, w in self.registro if w and w[0] != "/login"}


class PorPunto(Base):
    def test_reconciliar_p001_no_toca_p002(self):
        """Tipo: corrección de defecto (inv_A riesgo 3). Con el reporte de p001 sin
        candidatos, el reconciliador libera SOLO p001|10.0.0.5; la entrada de p002 (misma
        IP) sigue registrada y su router no recibe nada. El heredado, con un solo
        cuarentena.json, daba «ya no ataca» a los CPEs de los demas nodos."""
        self.enviados({K1: {"cuando": 1, "router": "p001", "lista": "suricata-cuarentena"},
                       K2: {"cuando": 1, "router": "p002", "lista": "suricata-cuarentena"}})
        self.a.salida("p001", "cuarentena.json", {"ventana_min": 1440, "candidatos": [], "dns_candidatos": []})
        self.a.salida("p002", "cuarentena.json", {"ventana_min": 1440,
                                                  "candidatos": [{"ip": _dash.IP, "router": "p002"}]})
        self.d.reconciliar_cuarentena("p001")
        env = self.d.cargar_enviados()
        self.assertEqual(sorted(env), [K2])
        self.assertEqual(self.routers_tocados(), {"p001"})
        self.registro.clear()
        self.d.reconciliar_cuarentena("p002")          # en p002 sigue atacando: se queda
        self.assertEqual(sorted(self.d.cargar_enviados()), [K2])
        self.assertEqual(self.routers_tocados(), set())

    def test_sin_reporte_del_punto_no_se_libera_nada(self):
        """Tipo: corrección de defecto. Si el punto aun no tiene cuarentena.json no se
        libera a nadie (no se confunde "sin reporte" con "nadie ataca")."""
        self.enviados({K1: {"cuando": 1, "router": "p001"}})
        self.d.reconciliar_cuarentena("p001")
        self.assertEqual(sorted(self.d.cargar_enviados()), [K1])
        self.assertEqual(self.registro, [])

    def test_evaluar_solo_sus_claves(self):
        """Tipo: corrección de defecto. evaluar_bloqueos(p001) solo sella las entradas de
        p001; las de p002 no se marcan como «ya no sigue»."""
        self.enviados({K1: {"cuando": 1}, K2: {"cuando": 1, "sigue": True}})
        self.a.salida("p001", "cuarentena.json", {"candidatos": []})
        self.d.evaluar_bloqueos("p001")
        env = self.d.cargar_enviados()
        self.assertIs(env[K1]["sigue"], False)
        self.assertIs(env[K2]["sigue"], True)
        self.assertNotIn("last_eval", env[K2])

    def test_politicas_por_punto_y_sin_perder_altas(self):
        """Tipo: corrección de defecto + capacidad nueva. aplicar_politicas(p001) mete en la
        lista de su clase al CPE del Top de p001 (evidencia reciente), en SU router, y no
        saca la entrada por politica de p002 (que no esta en el Top de p001)."""
        self.enviados({K2: {"cuando": 1, "pol": True, "router": "p002", "lista": "clientes-botnet"}})
        self.a.salida("p001", "cuarentena.json", {
            "ventana_min": 1440,
            "top_riesgo": [{"ip": _dash.IP, "router": "p001", "banda": "ALTO", "riesgo": 90,
                            "cats_top": {"Botnet CnC": 3}}]})
        self.d.aplicar_politicas("p001")
        env = self.d.cargar_enviados()
        self.assertEqual(sorted(env), [K1, K2])
        self.assertEqual(env[K1]["router"], "p001")
        self.assertEqual(self.routers_tocados(), {"p001"})

    def test_evidencia_vieja_bloquea_la_cuarentena_automatica(self):
        """Tipo: capacidad nueva (§10.4). Un CPE en el Top cuyas alertas tienen dias no va a
        cuarentena automatica (la IP puede ser hoy de otro abonado); se deja constancia."""
        vieja = "10.0.0.7"
        self.a.eve("p001", [_dash.alerta(src=vieja, hace=3 * 86400), _dash.alerta(src=vieja, hace=3 * 86400 - 5)])
        self.a.salida("p001", "cuarentena.json", {
            "ventana_min": 1440,
            "top_riesgo": [{"ip": vieja, "router": "p001", "banda": "ALTO", "riesgo": 90,
                            "cats_top": {"Botnet CnC": 2}}]})
        ev = self.d.evidencia_reciente("p001|" + vieja)
        self.assertFalse(ev["ok"])
        self.assertGreaterEqual(ev["edad_s"], 3 * 86400 - 10)
        self.d.aplicar_politicas("p001")
        self.assertEqual(self.d.cargar_enviados(), {})
        self.assertEqual(self.routers_tocados(), set())
        with open(self.d.MK_LOG, encoding="utf-8") as f:
            self.assertIn("POLITICA-EVIDENCIA-VIEJA " + vieja, f.read())
        self.assertTrue(self.d.evidencia_reciente(K2)["ok"])     # la de 10.0.0.5 en p002 es de hace segundos

    def test_barrido_rapido_por_punto_y_solo_evidencia_reciente(self):
        """Tipo: corrección de defecto. El barrido rapido de p002 atribuye las alertas a p002
        por el directorio del fichero (no por in_iface, que es igual en todos los puntos) y
        no actua por alertas viejas de la cola."""
        self.a.eve("p001", [_dash.alerta(src="10.0.0.8", hace=3 * 86400 + i) for i in range(5)])
        self.d.barrido_alto_rapido("p001")
        self.assertEqual(self.d.cargar_enviados(), {})
        self.d.barrido_alto_rapido("p002")
        env = self.d.cargar_enviados()
        self.assertEqual(sorted(env), [K2])
        self.assertEqual(self.routers_tocados(), {"p002"})
        self.d.barrido_alto_rapido("p002")                # idempotente: no repite
        self.assertEqual(sorted(self.d.cargar_enviados()), [K2])

    def test_aviso_de_cuarentena_dedupe_por_pid_ip(self):
        """Tipo: corrección de defecto. El aviso de Telegram se deduplica por pid|ip: la
        misma IP en otro punto es otro abonado y otro aviso."""
        enviados = []
        self.d.enviar_telegram = lambda txt: enviados.append(txt) or True
        self.d.notificar_cuarentena(K1, "prueba", "clientes-botnet")
        self.d.notificar_cuarentena(K1, "prueba", "clientes-botnet")
        self.d.notificar_cuarentena(K2, "prueba", "clientes-botnet")
        self.assertEqual(len(enviados), 2)
        self.assertIn("norte", enviados[0])
        self.assertIn("sur", enviados[1])
        with self.n.contexto(self.n.TODOS):                # IP pelada en «Todos»: no se manda
            self.d.notificar_cuarentena(_dash.IP, "prueba", "x")
        self.assertEqual(len(enviados), 2)


class Generador(Base):
    def test_generador_por_nodo_y_todos_de_uno_en_uno(self):
        """Tipo: capacidad nueva. El generador se lanza con --nodo pNNN y con --todos, con
        nice, como subproceso; un pid mal formado no se lanza."""
        llamadas = []

        class R:
            returncode = 0

        def run(cmd, **kw):
            llamadas.append(cmd)
            return R()
        real = self.d.subprocess.run
        self.d.subprocess.run = run
        try:
            self.d.generar_reporte("p002", 60)
            self.d.generar_reporte(self.n.TODOS, 60)
            with self.assertRaises(self.n.NodoInvalido):
                self.d.generar_reporte("../p001", 60)
        finally:
            self.d.subprocess.run = real
        self.assertEqual(llamadas[0][:2], ["nice", "-n"])
        self.assertEqual(llamadas[0][-3:], ["60", "--nodo", "p002"])
        self.assertEqual(llamadas[1][-2:], ["60", "--todos"])
        self.assertEqual(len(llamadas), 2)

    def test_informe_a_las_0730_en_ids_tz(self):
        """Tipo: capacidad nueva. La hora del informe diario se calcula en IDS_TZ."""
        from datetime import datetime
        t = self.d._proximo_informe(time.time())
        dt = datetime.fromtimestamp(t, self.d.TZ_EC)
        self.assertEqual((dt.hour, dt.minute), (7, 30))
        self.assertTrue(0 < t - time.time() <= 86400)


class Salud(Base):
    def salud(self, **cambios):
        p = dict(self.a.puntos["p002"])
        p.update(cambios)
        self.a.puntos["p002"] = p
        self.a.escribir_estado()
        return self.d.salud_punto("p002")

    def test_operativa(self):
        """Tipo: capacidad nueva (§10.6). Con todas las etapas al dia: operativa, con la
        captura reducida y su alcance dichos."""
        s = self.d.salud_punto("p002")
        self.assertEqual(s["estado"], "operativa")
        self.assertEqual([e["id"] for e in s["etapas"]], ["vpn", "tzsp", "suricata", "eventos", "datos"])
        self.assertEqual({e["estado"] for e in s["etapas"]}, {"ok"})
        self.assertIn("10 KB", s["captura"]["alcance"])
        self.assertIn("arranque", s["etapas_por_id"]["suricata"]["alcance"])
        self.assertEqual(s["captura"]["redes"], ["10.0.0.0/24"])

    def test_estados(self):
        """Tipo: capacidad nueva (§10.6). VPN arriba o contenedor en marcha no son «sano»:
        cada etapa dice lo suyo."""
        self.assertEqual(self.salud(vpn_cliente={"conectado": False})["estado"], "desconectada")
        self.assertEqual(self.salud(vpn_cliente={"conectado": True, "ip_real": "198.51.100.9"},
                                    tzsp={"edad_s": None, "tx": None})["estado"], "sin datos")
        self.assertEqual(self.salud(tzsp={"edad_s": 5, "tx": 10, "rechazados": 0},
                                    suricata={"kernel_packets": 1000, "kernel_drops": 500,
                                              "stats_edad_s": 5})["estado"], "degradada")
        self.assertEqual(self.salud(deseado="parado")["estado"], "deshabilitada")
        self.a.escribir_estado(ts=time.time() - 3600)
        self.assertEqual(self.d.salud_punto("p002")["estado"], "desconocido")

    def test_retencion_efectiva(self):
        """Tipo: capacidad nueva (§9). Sin dato del orquestador, la fecha del evento mas viejo
        disponible; con dato, la del orquestador y si hubo borrado anticipado."""
        import gzip
        with gzip.open(os.path.join(self.a.datos, "p001", "eve.json.1.gz"), "wt", encoding="utf-8") as f:
            f.write(_dash.alerta(hace=5 * 86400) + "\n")
        os.utime(os.path.join(self.a.datos, "p001", "eve.json.1.gz"), (time.time() - 5 * 86400,) * 2)
        r = self.d.retencion_efectiva("p001")
        self.assertEqual(r["fuente"], "ficheros")
        self.assertAlmostEqual(r["desde"], time.time() - 5 * 86400, delta=120)
        p = dict(self.a.puntos["p001"], retencion={"desde": 1700000000, "borrado_anticipado": True})
        self.a.puntos["p001"] = p
        self.a.escribir_estado()
        r = self.d.retencion_efectiva("p001")
        self.assertEqual((r["desde"], r["anticipado"], r["fuente"]), (1700000000, True, "orquestador"))

    def test_medir_sensor_por_punto(self):
        """Tipo: capacidad nueva. medir_sensor escribe nodos/<pid>/sensor.json desde estado.json
        (sin systemctl ni suricatasc) y en «Todos» estado_sensor da el peor punto."""
        self.a.puntos["p001"]["contenedores"]["suricata"]["estado"] = "exited"
        self.a.escribir_estado()
        for pid in ("p001", "p002"):
            with self.n.contexto(pid):
                self.d.medir_sensor()
        self.assertTrue(os.path.exists(os.path.join(self.a.panel, "nodos", "p001", "sensor.json")))
        self.assertEqual(self.d.estado_sensor("p001")["nivel"], "down")
        self.assertEqual(self.d.estado_sensor("p002")["nivel"], "ok")
        with self.n.contexto(self.n.TODOS):
            peor = self.d.estado_sensor()
        self.assertEqual(peor["nivel"], "down")
        self.assertTrue(peor["titulo"].startswith("norte:"))


if __name__ == "__main__":
    unittest.main()
