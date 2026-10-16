"""sistema.actualizar en el orquestador (botón «Actualizar» del panel, ACTUALIZACIONES.md §4): deja
el pedido en /srv/ids/estado/actualizar-pedido.json, arranca ids-actualizar.service y, mientras la
unidad corre, la cola no empieza ninguna orden (la unidad reinicia ids-orq y el panel).

Tipo «capacidad nueva»: la orden estaba reservada («no disponible en F1a»). systemctl simulado.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

SHA = "0123456789abcdef0123456789abcdef01234567"
OP = "11111111-2222-4333-8444-555555555555"


class Actualizar(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()
        self.addCleanup(A.cerrar, self.orq, self.e)
        self.unidad = "inactive"
        self.arrancadas = []
        self.s._systemctl = self._systemctl

    def _systemctl(self, a):
        if a[1] == "show":
            return 0, self.unidad + "\n", ""
        if a[1] == "start":
            self.arrancadas.append(a)
            self.unidad = "activating"
            return 0, "", ""
        return 1, "", "no simulado"

    def instalar(self):
        for f in (self.mod.ACTUALIZAR_SCRIPT, "/etc/systemd/system/" + self.mod.ACTUALIZAR_UNIDAD):
            p = self.e.ruta(f)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("#\n", encoding="utf-8")

    def pasar_arranque(self):
        """Como si hubieran pasado los segundos que tarda la unidad en arrancar."""
        self.orq._actualizando -= self.mod.ACTUALIZAR_ARRANQUE_S + 1
        self.orq._actualizando_visto = 0.0

    def test_parametros_invalidos_no_se_encolan(self):
        for prm in ({}, {"commit": "ABCDEF1"}, {"commit": "abc12"}, {"commit": "g" * 7},
                    {"commit": SHA + "0"}, {"commit": SHA, "rama": "x"}, {"commit": 1234567},
                    {"commit": SHA[:7] + "\n"}):
            with self.subTest(prm=prm):
                r = self.orq.atender(A.peticion("sistema.actualizar", prm))
                self.assertEqual(r["codigo"], "INVALIDO", r)
        self.assertEqual(self.orq.q1("SELECT COUNT(*) FROM op")[0], 0)

    def test_sin_actualizador_instalado_falla_sin_lanzar_nada(self):
        r = A.ejecutar_orden(self.orq, "sistema.actualizar", {"commit": SHA[:7]})
        self.assertEqual(r["codigo"], "FALLO", A.explicar(r))
        self.assertIn("no tiene el actualizador", r["mensaje"])
        self.assertEqual(self.arrancadas, [])
        self.assertIsNone(self.orq._actualizando)

    def test_lanza_la_unidad_con_el_pedido(self):
        self.instalar()
        r = A.ejecutar_orden(self.orq, "sistema.actualizar", {"commit": SHA}, op_id=OP)
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertEqual(self.arrancadas, [["systemctl", "start", "--no-block", "ids-actualizar.service"]])
        ped = json.loads(self.e.ruta(self.mod.ACTUALIZAR_PEDIDO).read_text(encoding="utf-8"))
        self.assertEqual((ped["commit"], ped["op_id"], ped["quien"]), (SHA, OP, "prueba"))
        self.assertEqual(r["resultado"], {"commit": SHA, "unidad": "ids-actualizar.service"})
        self.assertEqual([p["nombre"] for p in r["pasos"]], ["validar", "lanzar la actualización"])
        if sys.platform.startswith("linux"):
            self.assertEqual(self.e.ruta(self.mod.ACTUALIZAR_PEDIDO).stat().st_mode & 0o777, 0o600)

    def test_con_otra_en_curso_no_lanza_otra(self):
        self.instalar()
        self.unidad = "activating"
        r = A.ejecutar_orden(self.orq, "sistema.actualizar", {"commit": SHA})
        self.assertEqual(r["codigo"], "CONFLICTO", A.explicar(r))
        self.assertEqual(self.arrancadas, [])
        self.assertFalse(self.e.ruta(self.mod.ACTUALIZAR_PEDIDO).exists())

    def test_si_systemctl_falla_la_cola_no_se_queda_parada(self):
        self.instalar()
        self.s.fallar["systemctl start"] = 1
        r = A.ejecutar_orden(self.orq, "sistema.actualizar", {"commit": SHA})
        self.assertEqual(r["codigo"], "FALLO", A.explicar(r))
        self.assertIsNone(self.orq._actualizando)

    def test_la_cola_espera_a_que_acabe(self):
        """Mientras la unidad corre no empieza ninguna orden; al acabar, la cola sigue sola."""
        self.instalar()
        A.ejecutar_orden(self.orq, "sistema.actualizar", {"commit": SHA})
        r = self.orq.atender(A.peticion("sistema.reconciliar", {}))
        self.assertEqual(r["codigo"], "ACEPTADA")
        self.assertFalse(self.orq.procesar_una())          # recién lanzada: aún no «activating»
        self.pasar_arranque()
        self.assertFalse(self.orq.procesar_una())          # corriendo
        self.unidad = "inactive"
        self.orq._actualizando_visto = 0.0
        self.assertTrue(self.orq.procesar_una())           # acabó: la orden que esperaba se hace
        self.assertIsNone(self.orq._actualizando)
        d = self.orq.atender(A.peticion("op.estado", {"op_id": r["op_id"]}))["datos"]
        self.assertEqual(d["estado"], "terminada")

    def test_una_actualizacion_colgada_no_para_la_cola_para_siempre(self):
        self.instalar()
        A.ejecutar_orden(self.orq, "sistema.actualizar", {"commit": SHA})
        self.orq.atender(A.peticion("sistema.reconciliar", {}))
        self.orq._actualizando = self.mod.ahora() - self.mod.ACTUALIZAR_MAX_S - 1
        self.assertTrue(self.orq.procesar_una())
        self.assertIsNone(self.orq._actualizando)

    def test_arrancar_a_mitad_de_una_actualizacion(self):
        """ids-actualizar reinicia ids-orq y luego aún recrea el panel (o vuelve atrás): el
        orquestador nuevo arranca con la cola en pausa si la unidad sigue corriendo."""
        self.unidad = "activating"
        self.orq.arrancar()
        self.assertIsNotNone(self.orq._actualizando)
        self.assertFalse(self.orq.procesar_una())          # la reconciliación del arranque espera
        self.unidad = "inactive"
        self.pasar_arranque()
        self.assertTrue(self.orq.procesar_una())

    def test_arrancar_sin_actualizacion_no_pausa(self):
        self.orq.arrancar()
        self.assertIsNone(self.orq._actualizando)

    def test_estado_json_lleva_el_commit_instalado(self):
        p = self.e.ruta("/etc/ids-maat/imagenes.json")
        d = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(self.orq.construir_estado(con_puntos=False)["commit"], "")
        for commit, esperado in ((SHA, SHA), ("no-es-un-sha", ""), (None, "")):
            with self.subTest(commit=commit):
                d["commit"] = commit
                p.write_text(json.dumps(d), encoding="utf-8")
                self.assertEqual(self.orq.construir_estado(con_puntos=False)["commit"], esperado)

    def test_cli(self):
        a = self.mod.construir_parser().parse_args(["actualizar", SHA[:7]])
        self.assertEqual(self.mod.orden_desde_args(a), ("sistema.actualizar", {"commit": SHA[:7]}))


if __name__ == "__main__":
    unittest.main()
