"""«Nunca bloquear» con punto (`pNNN|IP`, `pNNN|CIDR`) en TODOS los caminos que mandan al router.

Correccion de defecto (revision final Q2, ALTA): la entrada `p001|10.0.0.5` la respetaban el
envio a mano, el barrido rapido y la recarga, pero NO las politicas automaticas ni «Enviar
confirmados», y el generador (html_report.nunca_bloquear) no entendia el `pNNN|`: el CPE
protegido seguia saliendo como candidato y la politica lo mandaba a cuarentena.

Tambien QX2 (MEDIA): lo que manda el barrido rapido (infeccion confirmada, `pol: True`) lo
sacaba aplicar_politicas en el ciclo siguiente si la banda del Top no cumplia la politica de la
clase (banda MEDIO con «si ALTO»), y el barrido lo volvia a mandar al minuto.

Panel real sobre el arbol de `fixtures/panel2/_dash.py` (p001 y p002 con la misma red y la
misma IP 10.0.0.5 con alertas recientes), MikroTik simulado por punto; el generador corre como
subproceso. Datos RFC 5737 / 10.x.
"""
import json
import os
import sys
import time
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
from test_f1_cuarentena import Panel, IP, K1, K2  # noqa: E402
from test_hrep_nodos import Entorno  # noqa: E402


def _top(ip=IP, router="p001", banda="ALTO", riesgo=90):
    return {"ip": ip, "router": router, "banda": banda, "riesgo": riesgo,
            "cats_top": {"Botnet CnC": 5}, "ultima": int(time.time())}


class Base(unittest.TestCase):
    HTTP = False

    def setUp(self):
        self.p = Panel(http=self.HTTP)
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d
        self.d._SELLO_CADA = 0          # los ficheros cambian dentro del mismo segundo


# --------------------------------------------------------------------------------------------
class Generador(Entorno):
    """html_report.py: las entradas con punto sacan al CPE de candidatos y del Top de SU punto."""

    def test_ip_con_punto_solo_protege_en_ese_punto(self):
        """Correccion de defecto (Q2): con `p001|10.0.0.5` el generador seguia dando el CPE de
        p001 como candidato y en el Top (la linea no la entendia). Ahora sale solo el de p002."""
        self.tres_cnc("p001")
        self.tres_cnc("p002")
        self.global_("conf/nunca-bloquear.lst", "p001|10.0.0.5\n")
        self.ok("60", "--todos")
        cuar = self.salida("_todos", "cuarentena.json")
        self.assertEqual(self.cpes(cuar), [("p002", "10.0.0.5")])
        self.assertEqual(self.cpes(cuar, "top_riesgo"), [("p002", "10.0.0.5")])
        self.ok("60", "--nodo", "p001")
        cuar1 = self.salida("p001", "cuarentena.json")
        self.assertEqual(cuar1["candidatos"], [])
        self.assertEqual(cuar1["top_riesgo"], [])
        self.ok("60", "--nodo", "p002")
        self.assertEqual(self.cpes(self.salida("p002", "cuarentena.json")), [("p002", "10.0.0.5")])

    def test_red_con_punto_y_entrada_global(self):
        """Correccion de defecto (Q2): `p002|10.0.0.0/24` (antes descartada como red invalida)
        protege toda esa red solo en p002; una entrada sin punto sigue valiendo en todos."""
        self.tres_cnc("p001")
        self.tres_cnc("p002")
        self.global_("conf/nunca-bloquear.lst", "p002|10.0.0.0/24\n")
        self.ok("60", "--todos")
        self.assertEqual(self.cpes(self.salida("_todos", "cuarentena.json")), [("p001", "10.0.0.5")])
        self.global_("conf/nunca-bloquear.lst", "10.0.0.5\n")
        self.ok("60", "--todos")
        cuar = self.salida("_todos", "cuarentena.json")
        self.assertEqual(cuar["candidatos"], [])
        self.assertEqual(cuar["top_riesgo"], [])


# --------------------------------------------------------------------------------------------
class Politicas(Base):
    def _preparar(self):
        self.d.guardar_mk({"POL_AUTO": "1", "POL_BOTNET": "siempre", "AUTO_MANTENER": "1"})
        for pid in ("p001", "p002"):
            self.p.a.salida(pid, "cuarentena.json", {"generado": int(time.time()), "ventana_min": 60,
                                                     "candidatos": [], "top_riesgo": [_top(router=pid)]})

    def test_politica_no_manda_lo_protegido_con_punto(self):
        """Correccion de defecto (Q2): aplicar_politicas mandaba a clientes-botnet el CPE
        `p001|10.0.0.5` aunque estuviera en «Nunca bloquear» (reporte de antes de anadirla). Ahora
        no lo manda; el mismo IP en p002, que no esta protegido, si."""
        self._preparar()
        self.d.guardar_nunca("p001|%s\n" % IP)
        self.d.aplicar_politicas("p001")
        self.d.aplicar_politicas("p002")
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), [])
        self.assertEqual(self.p.lista("p002", "clientes-botnet"), [IP])
        env = self.d.cargar_enviados()
        self.assertNotIn(K1, env)
        self.assertIn(K2, env)

    def test_politica_libera_lo_que_pasa_a_nunca_bloquear(self):
        """Capacidad nueva (Q2): lo que entro por politica y despues se protege con `pNNN|IP`
        sale de la lista en el ciclo siguiente (deja de calificar)."""
        self._preparar()
        self.d.aplicar_politicas("p001")
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), [IP])
        self.d.guardar_nunca("p001|10.0.0.0/24\n")
        self.d.aplicar_politicas("p001")
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), [])
        self.assertNotIn(K1, self.d.cargar_enviados())


class EnviarConfirmados(Base):
    def test_masivo_omite_lo_protegido_con_punto(self):
        """Correccion de defecto (Q2): «Enviar confirmados» desde «Todos» mandaba los dos CPE
        aunque `p001|10.0.0.5` estuviera en «Nunca bloquear». Ahora manda solo el de p002 y el
        resultado dice cual omitio y por que."""
        self.d.guardar_nunca("p001|%s\n" % IP)
        cand = [{"ip": IP, "router": pid, "confianza": "alta", "riesgo": 90, "ultima": int(time.time()),
                 "cats_top": {"Botnet CnC": 5}} for pid in ("p001", "p002")]
        self.p.a.salida("_todos", "cuarentena.json", {"candidatos": cand})
        self.d.CTX.user = "olga"
        n, msg = self.d._enviar_confirmados("_todos", "cuar")
        self.assertEqual(n, 1, msg)
        self.assertIn("«Nunca bloquear»", msg)
        self.assertEqual(self.p.lista("p001", "clientes-botnet") + self.p.lista("p001", "clientes-otros"), [])
        self.assertNotIn(K1, self.d.cargar_enviados())
        self.assertIn(K2, self.d.cargar_enviados())


class Barrido(Base):
    def test_barrido_respeta_la_entrada_con_punto(self):
        """Regresion (Q2, camino que ya lo respetaba): el barrido rapido no manda el CPE
        protegido de p001 y si el de p002 (las dos tienen 3 alertas CnC recientes)."""
        self.d.guardar_mk({"POL_AUTO": "1", "POL_BOTNET": "alto"})
        self.d.guardar_nunca("p001|%s\n" % IP)
        self.d.barrido_alto_rapido("p001")
        self.d.barrido_alto_rapido("p002")
        self.assertNotIn(K1, self.d.cargar_enviados())
        self.assertIn(K2, self.d.cargar_enviados())


class EnvioAMano(Base):
    HTTP = True

    def test_envio_a_mano_respeta_la_entrada_con_punto(self):
        """Regresion (Q2, camino que ya lo respetaba): /cuarentena/enviar con `p001|IP`
        protegido no lo manda y lo dice."""
        self.d.guardar_nunca("p001|%s\n" % IP)
        st, cab, txt = self.p.pedir("POST", "/cuarentena/enviar?nodo=p001", {"ip": K1, "score": "9"}, "olga")
        if st == 303:                    # el resultado va en el aviso de la pagina a la que vuelve
            _st, _c, txt = self.p.pedir("GET", cab["Location"], quien="olga")
        self.assertIn("Nunca bloquear", txt)
        self.assertNotIn(K1, self.d.cargar_enviados())
        self.assertEqual(self.p.routers["p001"].tablas["/ip/firewall/address-list"], [])


# --------------------------------------------------------------------------------------------
class BarridoNoSalePorLaBanda(Base):
    """QX2: lo que manda el barrido rapido no lo saca aplicar_politicas por la banda del Top."""

    def _enviado_por_barrido(self, cuando):
        self.d.guardar_mk({"POL_AUTO": "1", "POL_BOTNET": "alto", "AUTO_MANTENER": "1"})
        self.p.routers["p001"].cargar("/ip/firewall/address-list", [{"list": "clientes-botnet", "address": IP}])
        self.d._registrar_enviados(self.d.MK_SENT, {K1: {
            "cuando": cuando, "score": "", "por": "politica-rapida", "manual": False, "pol": True,
            "router": "p001", "categoria": "botnet", "lista": "clientes-botnet"}}, [])

    def test_infeccion_confirmada_con_banda_medio_se_queda(self):
        """Correccion de defecto (QX2): el barrido mando 10.0.0.5 (CnC confirmado); el reporte
        siguiente lo pone en banda MEDIO y la clase dice «si ALTO»: aplicar_politicas lo sacaba
        (y el barrido lo volvia a mandar al minuto). Ahora se queda mientras el reporte lo siga
        viendo infectado (candidatos) o con alertas (vigiladas)."""
        self._enviado_por_barrido(int(time.time()) - 120)
        self.p.a.salida("p001", "cuarentena.json", {
            "generado": int(time.time()), "ventana_min": 60,
            "candidatos": [dict(_top(banda="MEDIO"), confianza="alta")],
            "top_riesgo": [_top(banda="MEDIO")], "vigiladas": []})
        self.d.aplicar_politicas("p001")
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), [IP])
        self.assertIn(K1, self.d.cargar_enviados())
        # sin candidato pero con alertas en la ventana (vigiladas): tambien se queda
        self.p.a.salida("p001", "cuarentena.json", {
            "generado": int(time.time()), "ventana_min": 60, "candidatos": [],
            "top_riesgo": [_top(banda="BAJO")], "vigiladas": [_top(banda="BAJO")]})
        self.d.aplicar_politicas("p001")
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), [IP])

    def test_reporte_de_antes_del_envio_no_lo_saca(self):
        """Correccion de defecto (QX2): con un reporte generado ANTES del envio del barrido (aun
        no ha podido verlo) no se libera."""
        self._enviado_por_barrido(int(time.time()))
        self.p.a.salida("p001", "cuarentena.json", {
            "generado": int(time.time()) - 300, "ventana_min": 60,
            "candidatos": [], "top_riesgo": [], "vigiladas": []})
        self.d.aplicar_politicas("p001")
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), [IP])

    def test_deja_de_actuar_mal_y_sale(self):
        """Regresion (QX2): cuando un reporte posterior al envio ya no lo trae (ni candidato ni
        con alertas), sale de la lista como cualquier entrada de politica."""
        self._enviado_por_barrido(int(time.time()) - 600)
        self.p.a.salida("p001", "cuarentena.json", {
            "generado": int(time.time()), "ventana_min": 60,
            "candidatos": [], "top_riesgo": [], "vigiladas": []})
        self.d.aplicar_politicas("p001")
        self.assertEqual(self.p.lista("p001", "clientes-botnet"), [])
        self.assertNotIn(K1, self.d.cargar_enviados())


if __name__ == "__main__":
    unittest.main()
