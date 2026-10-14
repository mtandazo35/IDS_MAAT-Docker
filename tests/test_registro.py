"""Un solo Registro en Ajustes en vez de Accesos + Bitacora (el user, 2026-10-14: «vamos hacer un
solo LOG»). Tipo: cambio de interfaz pedido.

Una tarjeta «Registro»; una tabla con los intentos de entrar (login.log) y lo que se hizo dentro
(bitacora.log) por fecha, con filtro por tipo (Accesos, Cuarentena, Configuracion, Usuarios) y
Fallos cruzado. /log y /bitacora siguen abriendo el registro, con su filtro.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_f1_cuarentena import Panel  # noqa: E402


class Registro(unittest.TestCase):
    def setUp(self):
        self.p = Panel(http=True)
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d
        with open(self.d.LOGIN_LOG, "w", encoding="utf-8", newline="\n") as f:
            f.write("2026-10-14 09:00:00\t192.0.2.7\tana\tOK\n"
                    "2026-10-14 09:05:00\t198.51.100.4\tana\tFAIL\n")
        with open(self.d.BITACORA_LOG, "w", encoding="utf-8", newline="\n") as f:
            f.write("2026-10-14 09:00:00\tana\t192.0.2.7\tLOGIN\trol=admin\n"
                    "2026-10-14 09:10:00\tana\t192.0.2.7\tENVIADO\t10.0.0.5 botnet\n"
                    "2026-10-14 09:20:00\tana\t192.0.2.7\tCONFIG-TELEGRAM\tchat=-100123\n"
                    "2026-10-14 09:30:00\tana\t192.0.2.7\tUSUARIO-CREADO\tluis\n"
                    "2026-10-14 09:40:00\tauto\t\tERROR-ENVIO\t10.0.0.6 timed out\n")

    def test_una_sola_tarjeta_en_ajustes(self):
        _s, _c, h = self.p.pedir("GET", "/ajustes")
        self.assertIn("data-src='/registro?embed=1'", h)
        self.assertIn("Accesos y cambios: quién, qué y cuándo", h)
        self.assertNotIn("data-src='/log?embed=1'", h)
        self.assertNotIn("data-src='/bitacora?embed=1'", h)

    def test_todo_en_una_tabla_por_fecha_y_sin_repetidos(self):
        _s, _c, h = self.p.pedir("GET", "/registro")
        self.assertIn("<h1>Registro</h1>", h)
        orden = [h.index(x) for x in ("ERROR-ENVIO", "USUARIO-CREADO", "CONFIG-TELEGRAM", "ENVIADO",
                                      "CLAVE INCORRECTA", "ENTRÓ")]
        self.assertEqual(orden, sorted(orden))                      # mas nuevo primero
        self.assertEqual(h.count("ENTRÓ"), 1)                       # el LOGIN de la bitacora no se repite
        for tipo, accion in (("accesos", "CLAVE INCORRECTA"), ("cuarentena", "ENVIADO"),
                             ("configuracion", "CONFIG-TELEGRAM"), ("usuarios", "USUARIO-CREADO")):
            fila = h[h.rindex("<tr", 0, h.index(accion)):h.index(accion)]
            self.assertIn('data-t="%s"' % tipo, fila, accion)
        self.assertEqual(h.count('data-e="1"'), 2)                  # clave incorrecta + ERROR-ENVIO

    def test_filtro_inicial_y_rutas_viejas(self):
        self.assertIn("class='rtipo on' data-tipo='fallos'", self.p.pedir("GET", "/registro?tipo=fallos")[2])
        self.assertIn("class='rtipo on' data-tipo='accesos'", self.p.pedir("GET", "/log")[2])
        self.assertIn("class='rtipo on' data-tipo=''", self.p.pedir("GET", "/bitacora")[2])
        self.assertIn("class='rtipo on' data-tipo=''", self.p.pedir("GET", "/registro?tipo=<x>")[2])

    def test_solo_admin(self):
        for ruta in ("/registro", "/log", "/bitacora"):
            self.assertEqual(self.p.pedir("GET", ruta, quien="olga")[0], 403, ruta)

    def test_clasificacion(self):
        t = self.d._registro_tipo
        self.assertEqual(t("CONFIANZA-AGREGADA"), ("accesos", False))
        self.assertEqual(t("SIN-PERMISO"), ("accesos", True))
        self.assertEqual(t("POLITICA-LIBERADO"), ("cuarentena", False))
        self.assertEqual(t("ERROR-ENVIO"), ("cuarentena", True))
        self.assertEqual(t("USUARIO-ROL"), ("usuarios", False))
        self.assertEqual(t("PUNTO-CREAR"), ("configuracion", False))
        self.assertEqual(t("THRESHOLD-FALLO"), ("configuracion", True))
        self.assertEqual(t("ERROR-PANEL"), ("sistema", True))       # lo hace el panel, no una persona
        self.assertEqual(t("INFORME-DIARIO"), ("sistema", False))


if __name__ == "__main__":
    unittest.main()
