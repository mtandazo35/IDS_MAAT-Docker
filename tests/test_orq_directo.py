"""Punto «directo» (sin VPN, solo LAN; el user, 2026-10-18): el MikroTik manda el espejo a un puerto
UDP propio del punto en el host y el panel llega a su API en su IP de la LAN.

Con el código real del orquestador y el sistema simulado: validación del alta (solo IP privada, sin
chocar con lo interno), lo que se genera (compose sin /dev/net/tun ni OpenVPN, puerto UDP, MODO y
MK_IP; sin certificado, usuario ni server.conf), el firewall del host (puerto publicado; el espejo
desde cualquier IP desde 2026-10-20), el estado, los comandos y las órdenes que no aplican."""

import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

LAN = {"nombre": "lan", "modo": "directo", "mk_ip": "192.168.88.1"}
RUTA_HOST = "192.168.88.1 dev eth1 src 192.168.88.10 uid 0 \\    cache "


class Alta(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()
        self.mod._ip_host_cache.clear()
        self.s._ip = lambda a: (0, RUTA_HOST, "") if a[1:5] == ["-4", "-o", "route", "get"] else (1, "", "")

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def leer(self, rel):
        return self.e.ruta("/srv/ids/puntos/p001/" + rel).read_text(encoding="utf-8")

    def test_crear_directo(self):
        r = A.crear(self, self.orq, LAN)
        d = r["resultado"]
        self.assertEqual((d["pid"], d["n"], d["puerto"], d["modo"], d["mk_ip"]),
                         ("p001", 1, 37008, "directo", "192.168.88.1"))
        p = self.orq.punto("p001")
        self.assertEqual((p["modo"], p["mk_ip"], p["usuario"]), ("directo", "192.168.88.1", None))
        compose = self.leer("compose.yml")
        self.assertIn('ports: ["37008:37008/udp"]', compose)
        self.assertIn('MODO: "directo"', compose)
        self.assertIn('MK_IP: "192.168.88.1"', compose)
        self.assertNotIn("/dev/net/tun", compose)
        self.assertNotIn("1194", compose)
        # nada de la VPN: ni server.conf, ni usuarios, ni certificado, ni clave guardada
        for rel in ("vpn/server.conf", "vpn/usuarios", "vpn/server.crt", "vpn/server.key"):
            self.assertFalse(self.e.ruta("/srv/ids/puntos/p001/" + rel).exists(), rel)
        self.assertFalse(list(self.e.ruta("/srv/ids/puntos/p001/vpn/ccd").iterdir()))
        self.assertIsNone(self.orq.q1("SELECT 1 FROM clave_vpn WHERE pid='p001'"))
        self.assertNotIn("clave", r["resultado"])
        # los comandos dicen adónde va el espejo (la IP del host hacia el MikroTik) y nada de VPN
        com = d["comandos"]
        self.assertIn("sniff-target=192.168.88.10 sniff-target-port=37008", com)
        self.assertIn("Se acepta desde cualquier IP del router", com)
        self.assertNotIn("Solo se acepta desde", com)
        self.assertIn("sin VPN", com)
        self.assertNotIn("ovpn-client", com)
        # nada de la CA de la VPN ni de la API (el dueño, 2026-10-20 y 2026-10-21): la API se
        # configura en la ficha del punto y «Probar la conexión» crea el certificado si falta
        self.assertNotIn("/certificate import", com)
        self.assertNotIn("ids-maat-ca", com)
        self.assertEqual([x for x in com.splitlines() if x.lstrip().startswith("/")], [], com)
        for nada in ("/certificate", "/ip service", "API", "Probar", "8729", "8728", "deja pasar"):
            self.assertNotIn(nada, com)

    def test_firewall_publica_el_udp_desde_cualquier_ip(self):
        """2026-10-20 («necesito que escuche cualquier IP»): el puerto del espejo se publica sin filtro
        de origen; el MikroTik puede mandarlo desde otra IP que la de su API."""
        A.crear(self, self.orq, {"nombre": "vpn1"})                       # p001: con VPN, 1194
        A.crear(self, self.orq, dict(LAN, nombre="lan2"))                 # p002: directo, 37009
        nft = self.s.nft_aplicado[-1]
        self.assertIn("elements = { 1194, 37009 }", nft)
        self.assertNotIn("espejo directo", nft)
        self.assertNotIn("ip saddr != 192.168.88.1", nft)
        self.assertNotIn("origen fijo", nft)              # la VPN de p001 no tiene origen fijo
        # el punto con VPN sigue como siempre
        compose = self.e.ruta("/srv/ids/puntos/p001/compose.yml").read_text(encoding="utf-8")
        self.assertIn('ports: ["1194:1194/tcp"]', compose)
        self.assertIn('devices: ["/dev/net/tun:/dev/net/tun"]', compose)
        self.assertNotIn("MODO", compose)
        self.assertNotIn("MK_IP", compose)

    def test_validacion(self):
        malos = [
            (dict(LAN, mk_ip=None), "mk_ip"),
            ({"nombre": "lan", "modo": "directo"}, "mk_ip"),
            (dict(LAN, mk_ip="8.8.8.8"), "privada"),                 # solo LAN
            (dict(LAN, mk_ip="203.0.113.7"), "privada"),
            (dict(LAN, mk_ip="100.64.5.2"), "túneles"),              # la base de túneles del VPS
            (dict(LAN, mk_ip="10.210.0.20"), "pool de Docker"),
            (dict(LAN, mk_ip="192.168.88.300"), "mk_ip"),
            (dict(LAN, origen_ip="192.168.88.1"), "origen_ip"),
            (dict(LAN, modo="lan"), "modo"),
            ({"nombre": "vpn1", "mk_ip": "192.168.88.1"}, "mk_ip"),     # mk_ip sin directo
        ]
        for params, txt in malos:
            params = {k: v for k, v in params.items() if v is not None}
            with self.subTest(params=params):
                r = A.crear(self, self.orq, params, "INVALIDO")
                self.assertIn(txt, r["mensaje"])
        self.assertIsNone(self.orq.punto("p001"))

    def test_imagen_vpn_anterior_no_crea_un_directo(self):
        """Una imagen vpn de antes (sin la etiqueta ids-maat.modos) arrancaría OpenVPN sin server.conf:
        el alta se para al principio, con el motivo, y no gasta pid. Por VPN sigue creando."""
        self.s.modos_vpn = ""
        r = A.crear(self, self.orq, LAN, "CONFLICTO")
        self.assertIn("no sabe hacer puntos directos", r["mensaje"])
        self.assertIsNone(self.orq.punto("p001"))
        r = A.crear(self, self.orq, {"nombre": "vpn1"})
        self.assertEqual(r["resultado"]["pid"], "p001")
        # la imagen nueva lo declara
        docker = (A.REPO / "images" / "vpn" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn('ids-maat.modos="vpn,directo"', docker)

    def test_puerto_udp_ocupado(self):
        self.s.puertos_ocupados.add(37008)
        r = A.crear(self, self.orq, LAN, "CONFLICTO_PUERTO")
        self.assertIn("37008/udp", r["mensaje"])
        self.assertIn(["ss", "-Hlun"], self.s.llamadas)
        self.assertIsNone(self.orq.punto("p001"))

    def test_alta_repetida_y_con_otra_ip(self):
        A.crear(self, self.orq, LAN)
        r = A.crear(self, self.orq, LAN)
        self.assertTrue(r["resultado"].get("ya_entregada"))
        r = A.crear(self, self.orq, dict(LAN, mk_ip="192.168.88.2"), "CONFLICTO")
        self.assertIn("otros datos", r["mensaje"])

    def test_estado(self):
        A.crear(self, self.orq, LAN)
        est = self.orq.construir_estado()["puntos"]["p001"]
        self.assertEqual((est["modo"], est["mk_ip"], est["mk"], est["sensor"], est["tzsp_puerto"]),
                         ("directo", "192.168.88.1", "192.168.88.1", "192.168.88.10", 37008))
        self.assertIsNone(est["vpn_cliente"])
        self.assertIsNone(est["tzsp"]["visto_s"])               # aún no llegó espejo
        # «conectado» en un punto directo = llega espejo del MikroTik (tzsp-decap apunta cuándo)
        t = int(time.time())
        self.e.ruta("/srv/ids/run/p001/tzsp.json").write_text(json.dumps(
            {"ts": t - 3, "rx": 10, "tx": 10, "rechazados": 0, "ultimo_visto": {"192.168.88.1": t - 7}}),
            encoding="utf-8")
        est = self.orq.construir_estado()["puntos"]["p001"]
        self.assertIn(est["tzsp"]["visto_s"], (7, 8))

    def test_comandos_sin_ruta_al_mikrotik(self):
        self.s._ip = lambda a: (2, "", "RTNETLINK answers: Network is unreachable")
        A.crear(self, self.orq, LAN)
        d = self.orq.atender(A.peticion("punto.comandos", {"pid": "p001"}))["datos"]
        self.assertIn("sniff-target=<IP-DEL-HOST> sniff-target-port=37008", d["comandos"])
        self.assertNotIn("API", d["comandos"])
        self.assertNotIn("clave", d)

    def test_ordenes_de_la_vpn_no_aplican(self):
        A.crear(self, self.orq, LAN)
        r = A.ejecutar_orden(self.orq, "punto.vpn.regenerar", {"pid": "p001"})
        self.assertEqual(r["codigo"], "INVALIDO", r)
        self.assertIn("directo", r["mensaje"])
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "origen_ip": "192.168.88.1"})
        self.assertEqual(r["codigo"], "INVALIDO", r)
        # la versión de RouterOS se guarda sin tocar ninguna VPN
        r = A.ejecutar_orden(self.orq, "punto.ajustar", {"pid": "p001", "ros_version": 6})
        self.assertEqual(r["codigo"], "OK", r)
        self.assertEqual(self.orq.punto("p001")["ros_version"], 6)
        self.assertFalse(self.e.ruta("/srv/ids/puntos/p001/vpn/server.conf").exists())
        self.assertFalse([a for a in self.s.llamadas if "s6-svc" in " ".join(a)])

    def test_reconfigurar_no_crea_server_conf(self):
        A.crear(self, self.orq, LAN)
        r = A.ejecutar_orden(self.orq, "punto.reconfigurar", {"pid": "p001"})
        self.assertEqual(r["codigo"], "OK", r)
        self.assertFalse(self.e.ruta("/srv/ids/puntos/p001/vpn/server.conf").exists())

    def test_borrar_directo_quita_el_udp_del_firewall(self):
        A.crear(self, self.orq, LAN)
        r = A.ejecutar_orden(self.orq, "punto.borrar", {"pid": "p001", "confirmar": "lan"})
        self.assertEqual(r["codigo"], "OK", r)
        self.assertNotIn("37008", self.s.nft_aplicado[-1])


class Piezas(unittest.TestCase):
    def setUp(self):
        self.mod = A.cargar_orq()

    def test_puntos_de_antes_son_vpn(self):
        p = self.mod.fila_a_punto({"pid": "p001", "n": 1, "redes": "[]"})
        self.assertEqual((p["modo"], p["mk_ip"]), ("vpn", None))
        self.assertFalse(self.mod.es_directo({"pid": "p001"}))

    def test_puerto_espejo(self):
        self.assertEqual([self.mod.puerto_espejo(n) for n in (1, 3, 250)], [37008, 37010, 37257])

    def test_render_nft_origenes_tcp_y_udp(self):
        cfg = self.mod.Config({"VERSION": "x", "NOMBRE_DNS": "ids.example", "TUN_BASE": "100.64",
                               "REDES_GESTION": "192.0.2.0/25", "IPS_PROXY": "203.0.113.50",
                               "PUERTO_PANEL": "5637", "POOL_DOCKER": "10.210.0.0/16"})
        txt = self.mod.render_nft(cfg, [1194, 37009], [("p001", 1194, "198.51.100.7"),
                                                     ("p002", 37009, "192.168.88.1", "udp")])
        self.assertIn('meta l4proto tcp ct direction original ct status dnat ct original proto-dst 1194 '
                      'ip saddr != 198.51.100.7 counter drop comment "origen fijo p001"', txt)
        self.assertIn('meta l4proto udp ct direction original ct status dnat ct original proto-dst 37009 '
                      'ip saddr != 192.168.88.1 counter drop comment "espejo directo p002"', txt)

    def test_formato_creado_directo(self):
        txt = self.mod.formato_creado({"pid": "p004", "nombre": "lan", "n": 4, "puerto": 37011,
                                       "modo": "directo", "mk_ip": "192.168.88.1", "perfil": "reducido",
                                       "hilos": 1, "reserva": "900m", "comandos": "# x\n"})
        self.assertIn("directa, sin VPN (solo LAN) · MikroTik 192.168.88.1", txt)
        self.assertIn("37011/udp", txt)
        self.assertNotIn("clave VPN", txt)

    def test_cli_crear_directo(self):
        a = self.mod.construir_parser().parse_args(
            ["punto", "crear", "--nombre", "lan", "--modo", "directo", "--mk-ip", "192.168.88.1"])
        self.assertEqual(self.mod.orden_desde_args(a),
                         ("punto.crear", {"nombre": "lan", "modo": "directo", "mk_ip": "192.168.88.1"}))


if __name__ == "__main__":
    unittest.main()
