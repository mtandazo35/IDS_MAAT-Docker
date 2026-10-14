"""Envios al MikroTik: caducidad renovada al reenviar y envio masivo con una conexion por nodo.

Tipo: correccion de defecto (tanda MikroTik C1, 2026-10-14), con el panel real y el MikroTik
simulado de tests/_mikrotik_simulado.py (Panel de test_f1_cuarentena):

a) Reenviar una IP que ya estaba en la address-list devolvia exito pero la entrada conservaba
   su timeout viejo: un CPE que seguia atacando salia a la hora de la PRIMERA vez. Ahora se
   le pone el timeout nuevo, y con TTL vacio (permanente) queda sin caducidad.
b) «Enviar confirmados» solo cortaba un nodo si el error decia "conexion" o "login": un tiempo
   agotado o un fallo TLS seguian IP por IP (6 s cada una). Ahora cualquier fallo de
   transporte corta ESE nodo diciendo cuantas quedaron sin enviar, y el rechazo de UNA IP no
   corta las demas.
c) El envio masivo abria una conexion TLS + login por IP; ahora una por nodo.
"""
import json
import os
import ssl
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_f1_cuarentena import Panel  # noqa: E402
import _mikrotik_simulado as sim  # noqa: E402

AL = "/ip/firewall/address-list"
IPS1 = ["10.0.0.%d" % i for i in (31, 32, 33)]      # candidatos de p001
IP2 = "10.0.0.41"                                    # candidato de p002


class _Base(unittest.TestCase):
    def setUp(self):
        self.p = Panel()
        self.addCleanup(self.p.cerrar)
        self.d = self.p.d
        self.conexiones = []
        conectar = self.d.mk_conectar
        self.d.mk_conectar = lambda dd, timeout=6: (self.conexiones.append(dd.get("ROUTER_ID"))
                                                     or conectar(dd, timeout))

    def entradas(self, pid, lista, ip):
        return [f for f in self.p.routers[pid].tablas[AL] if f["list"] == lista and f["address"] == ip]


# --------------------------------------------------------------------------------------------
class RenovarCaducidad(_Base):
    """a) «already have such entry» renueva el timeout de la entrada que ya estaba."""

    def setUp(self):
        super().setUp()
        self.rt = self.p.routers["p001"]
        self.ip = "10.0.0.51"

    def _sesion(self):
        return self.d.mk_sesion(self.d.router_por_id("p001"))

    def test_reenviar_pone_el_timeout_nuevo(self):
        self.rt.cargar(AL, [{"list": "lista-x", "address": self.ip, "timeout": "1h", "comment": "viejo"}])
        with self._sesion() as (s, _dd):
            ok, msg = self.d._mk_add_en(s, self.ip, "lista-x", "1d", "nuevo")
        self.assertTrue(ok, msg)
        e = self.entradas("p001", "lista-x", self.ip)
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0].get("timeout"), "1d")          # antes se quedaba en 1h
        self.assertEqual(e[0].get("comment"), "viejo")        # solo se toca la caducidad

    def test_reenviar_permanente_quita_la_caducidad_y_conserva_el_comentario(self):
        self.rt.cargar(AL, [{"list": "lista-x", "address": self.ip, "timeout": "1h", "comment": "viejo"}])
        with self._sesion() as (s, _dd):
            ok, msg = self.d._mk_add_en(s, self.ip, "lista-x", "", "nuevo")
        self.assertTrue(ok, msg)
        e = self.entradas("p001", "lista-x", self.ip)
        self.assertEqual(len(e), 1)
        self.assertNotIn("timeout", e[0])                    # permanente
        self.assertEqual(e[0].get("comment"), "viejo")

    def test_permanente_que_ya_lo_era_no_se_toca(self):
        self.rt.cargar(AL, [{"list": "lista-x", "address": self.ip, "comment": "viejo"}])
        antes = list(self.rt.escrituras)
        with self._sesion() as (s, _dd):
            self.assertEqual(self.d._mk_add_en(s, self.ip, "lista-x", "", "nuevo"),
                             (True, "ya estaba en la lista"))
        self.assertEqual(self.rt.escrituras, antes)          # ni set ni remove
        self.assertEqual(len(self.entradas("p001", "lista-x", self.ip)), 1)

    def test_set_rechazado_cae_en_quitar_y_anadir_con_el_ttl_nuevo(self):
        self.rt.cargar(AL, [{"list": "lista-x", "address": self.ip, "timeout": "1h", "comment": "viejo"}])
        self.rt._n = 0
        self.rt.fallar_en = 2                 # 1 = el add (duplicado), 2 = el set
        with self._sesion() as (s, _dd):
            ok, msg = self.d._mk_add_en(s, self.ip, "lista-x", "1d", "nuevo")
        self.assertTrue(ok, msg)
        e = self.entradas("p001", "lista-x", self.ip)
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0].get("timeout"), "1d")
        self.assertEqual(e[0].get("comment"), "viejo")

    def test_si_no_la_acepta_de_vuelta_es_fallo(self):
        """Se quito para dejarla permanente y el router rechazo volver a anadirla: ya no esta
        cortada, asi que NO puede salir como exito."""
        self.rt.cargar(AL, [{"list": "lista-x", "address": self.ip, "timeout": "1h"}])
        self.rt._n = 0
        self.rt.fallar_en = 3                 # 1 = add (duplicado), 2 = remove, 3 = add de vuelta
        with self._sesion() as (s, _dd):
            ok, msg = self.d._mk_add_en(s, self.ip, "lista-x", "", "nuevo")
        self.assertFalse(ok)
        self.assertIn("rechazo volver a anadirla", msg)
        self.assertEqual(self.entradas("p001", "lista-x", self.ip), [])

    def test_mk_add_por_fuera_renueva_y_sigue_siendo_exito(self):
        self.rt.cargar(AL, [{"list": "lista-y", "address": self.ip, "timeout": "1h"}])
        r = self.d.router_por_id("p001")
        self.assertEqual(self.d.mk_add(self.ip, comment="c", lista="lista-y", ttl="3d", router=r),
                         (True, "ya estaba en la lista"))
        self.assertEqual(self.entradas("p001", "lista-y", self.ip)[0].get("timeout"), "3d")

    def test_fatal_del_router_se_lanza_como_fallo_de_transporte(self):
        """Un !fatal cierra la API: no es el rechazo de una IP, la sesion ya no sirve."""
        class SocketFatal:
            def __init__(self):
                self.salida = b"".join(sim._codificar(w) for w in ("!fatal", "session terminated")) + b"\x00"

            def sendall(self, _b):
                pass

            def recv(self, n):
                out, self.salida = self.salida[:n], self.salida[n:]
                return out
        with self.assertRaises(OSError):
            self.d._mk_add_en(SocketFatal(), self.ip, "lista-x", "1d", "c")


# --------------------------------------------------------------------------------------------
class EnvioMasivo(_Base):
    """b) y c) en _enviar_confirmados (el cuerpo de /cuarentena/enviar-todos)."""

    def setUp(self):
        super().setUp()
        ahora = int(time.time())
        cand = [{"ip": ip, "router": "p001", "confianza": "alta", "riesgo": 90, "ultima": ahora} for ip in IPS1]
        cand.append({"ip": IP2, "router": "p002", "confianza": "alta", "riesgo": 80, "ultima": ahora})
        for vista, cs in (("p001", cand[:3]), ("p002", cand[3:]), (self.d.nodos.TODOS, cand)):
            ruta = self.d.nodos.salida("cuarentena.json", vista)
            os.makedirs(os.path.dirname(ruta), exist_ok=True)
            with open(ruta, "w", encoding="utf-8", newline="\n") as f:
                json.dump({"candidatos": cs}, f)
        self.d.CTX.user = "olga"

    def lista_de(self, pid, ip):
        return self.d.lista_de_categoria(self.d.categoria_cpe(pid + "|" + ip))

    def ttl(self, pid):
        return self.d._ttl_efectivo(self.d.cargar_mk_de(self.d.router_por_id(pid)), "TTL")

    def en_router(self, pid, ip):
        return bool(self.entradas(pid, self.lista_de(pid, ip), ip))

    def test_una_conexion_por_nodo_y_registro_igual(self):
        n, msg = self.d._enviar_confirmados(self.d.nodos.TODOS, "cuar")
        self.assertEqual(n, 4, msg)
        self.assertEqual(sorted(self.conexiones), ["p001", "p002"])     # antes: una por IP (4)
        self.assertTrue(all(self.en_router("p001", ip) for ip in IPS1))
        self.assertTrue(self.en_router("p002", IP2))
        env = self.d.cargar_enviados()
        for ip in IPS1:
            rec = env["p001|" + ip]
            self.assertEqual(rec["router"], "p001")
            self.assertEqual(rec["lista"], self.lista_de("p001", ip))
            self.assertEqual(rec["por"], "olga")
        self.assertIn("norte: 3 enviado(s)", msg)
        self.assertNotIn("se corto", msg)
        # la entrada lleva el TTL del router y el comentario de siempre
        e = self.entradas("p001", self.lista_de("p001", IPS1[0]), IPS1[0])[0]
        self.assertEqual(e.get("timeout", ""), self.ttl("p001"))
        self.assertTrue(e.get("comment", "").startswith("suricata "))

    def test_el_rechazo_de_una_ip_no_corta_las_demas(self):
        rt = self.p.routers["p001"]
        rt._n = 0
        rt.fallar_en = 2                      # el router rechaza (!trap) la segunda IP
        n, msg = self.d._enviar_confirmados("p001", "cuar")
        self.assertEqual(n, 2, msg)
        self.assertIn("norte: 2 enviado(s), 1 con error", msg)
        self.assertNotIn("se corto", msg)
        self.assertEqual([self.en_router("p001", ip) for ip in IPS1], [True, False, True])
        self.assertEqual(self.conexiones, ["p001"])
        self.assertNotIn("p001|" + IPS1[1], self.d.cargar_enviados())

    def test_tiempo_agotado_corta_ese_nodo_y_no_los_demas(self):
        """Antes un "timed out" no contenia "conexion" ni "login" y se seguia con cada IP."""
        rt = self.p.routers["p001"]
        rt._n = 0
        rt.colgar_en = 2                      # la segunda se aplica y el router se queda callado
        n, msg = self.d._enviar_confirmados(self.d.nodos.TODOS, "cuar")
        self.assertEqual(n, 2, msg)           # la primera de p001 y la de p002
        self.assertIn("norte: 1 enviado(s), 1 con error (timed out", msg)
        self.assertIn("se corto el envio a este nodo", msg)
        self.assertIn("2 sin enviar", msg)    # la que fallo y la que ya no se intento
        self.assertFalse(self.en_router("p001", IPS1[2]))           # no se siguio con la tercera
        self.assertIn("sur: 1 enviado(s)", msg)
        self.assertTrue(self.en_router("p002", IP2))
        env = self.d.cargar_enviados()
        self.assertIn("p001|" + IPS1[0], env)
        self.assertNotIn("p001|" + IPS1[1], env)
        self.assertNotIn("p001|" + IPS1[2], env)
        self.assertEqual(sorted(self.conexiones), ["p001", "p002"])

    def test_fallo_tls_al_conectar_corta_ese_nodo(self):
        conectar = self.d.mk_conectar

        def con_tls_roto(dd, timeout=6):
            if dd.get("ROUTER_ID") == "p001":
                self.conexiones.append("p001")
                raise ssl.SSLError("sslv3 alert handshake failure")
            return conectar(dd, timeout)
        self.d.mk_conectar = con_tls_roto
        n, msg = self.d._enviar_confirmados(self.d.nodos.TODOS, "cuar")
        self.assertEqual(n, 1, msg)
        self.assertIn("norte: 0 enviado(s), 1 con error", msg)
        self.assertIn("3 sin enviar", msg)
        self.assertEqual(self.conexiones.count("p001"), 1)          # no se reintenta por cada IP
        self.assertFalse(any(self.en_router("p001", ip) for ip in IPS1))
        self.assertTrue(self.en_router("p002", IP2))

    def test_reenvio_masivo_tras_liberar_del_panel_renueva_la_caducidad(self):
        """La IP sigue en el router (con su timeout viejo) pero no en el registro: el masivo la
        manda otra vez y ahora la entrada coge el TTL nuevo."""
        lst = self.lista_de("p001", IPS1[0])
        self.p.routers["p001"].cargar(AL, [{"list": lst, "address": IPS1[0], "timeout": "5m"}])
        n, msg = self.d._enviar_confirmados("p001", "cuar")
        self.assertEqual(n, 3, msg)
        self.assertTrue(self.ttl("p001"))     # con auto-mantener seria permanente: otra prueba
        self.assertEqual([f.get("timeout") for f in self.entradas("p001", lst, IPS1[0])], [self.ttl("p001")])


if __name__ == "__main__":
    unittest.main()
