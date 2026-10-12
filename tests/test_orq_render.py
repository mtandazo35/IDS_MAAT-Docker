"""Render de los ficheros generados (§4.3-§4.8) contra el texto del contrato."""

import hashlib
import ipaddress
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

COMPOSE_CONTRATO = """# ids-maat — generado por ids-orq; no editar
name: ids-p003
services:
  vpn:
    image: ghcr.io/mtandazo35/ids-maat-vpn@sha256:<digest>
    container_name: ids-p003-vpn
    hostname: ids-p003-vpn
    restart: unless-stopped
    labels: { ids-maat.punto: "p003", ids-maat.parte: "vpn", ids-maat.version: "0.1.0" }
    cap_drop: [ALL]
    cap_add: [NET_ADMIN, NET_RAW]
    devices: ["/dev/net/tun:/dev/net/tun"]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: ["/run:exec,size=16m", "/tmp:size=16m"]
    sysctls:
      net.ipv4.ip_forward: "0"
      net.ipv6.conf.all.disable_ipv6: "1"
      net.ipv6.conf.default.disable_ipv6: "1"
      net.ipv4.conf.default.rp_filter: "1"
      net.ipv4.ipfrag_high_thresh: "67108864"
      net.ipv4.ipfrag_time: "15"
    ports: ["1196:1194/tcp"]
    networks: [punto]
    environment:
      PUNTO: "p003"
      N: "3"
      TUN_NET: "100.64.3.0/24"
      TUN_SENSOR: "100.64.3.1"
      TUN_MK: "100.64.3.2"
      API_PUERTO: "8729"
      TZSP_PUERTO: "37008"
      TZSP_BYTES: "10000"
      TZ: "UTC"
    volumes:
      - /srv/ids/puntos/p003/vpn:/etc/ids/vpn:ro
      - /srv/ids/run/p003:/run/ids
      - /srv/ids/ctl/p003/vpn:/run/ids-ctl
    logging: { driver: journald, options: { tag: ids-vpn } }
    cpuset: "0-1"
    mem_limit: 192m
    memswap_limit: 192m
    pids_limit: 64
    healthcheck:
      test: ["CMD", "/usr/local/bin/salud-vpn"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
  suricata:
    image: ghcr.io/mtandazo35/ids-maat-suricata@sha256:<digest>
    container_name: ids-p003-suricata
    network_mode: "service:vpn"
    depends_on: { vpn: { condition: service_healthy, restart: true } }
    restart: unless-stopped
    labels: { ids-maat.punto: "p003", ids-maat.parte: "suricata", ids-maat.version: "0.1.0" }
    cap_drop: [ALL]
    cap_add: [NET_RAW, NET_ADMIN]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: ["/tmp:size=64m", "/run:size=8m"]
    environment: { PUNTO: "p003", IDS_ESPERA_MON_S: "60", TZ: "UTC" }
    volumes:
      - /srv/ids/reglas:/reglas:ro
      - /srv/ids/puntos/p003/suricata:/etc/ids/suricata:ro
      - /srv/ids/datos/p003:/var/log/suricata
      - /srv/ids/ctl/p003/suricata:/run/suricata
    cpuset: "2"
    cpus: 1
    mem_limit: 900m
    memswap_limit: 900m
    pids_limit: 256
    stop_grace_period: 30s
    healthcheck:
      test: ["CMD", "/usr/local/bin/salud-suricata"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 180s
networks:
  punto:
    name: ids-p003
    driver: bridge
    driver_opts: { com.docker.network.bridge.name: ids-p003 }
    ipam: { config: [ { subnet: 10.210.0.48/28 } ] }
"""

SERVER_CONTRATO = """# ids-maat p003 — generado por ids-orq; no editar
port 1194
proto tcp4-server
dev tun0
topology subnet
server 100.64.3.0 255.255.255.0
max-clients 2
tls-server
tls-version-min 1.2
ca /etc/ids/vpn/ca.crt
cert /etc/ids/vpn/server.crt
key /etc/ids/vpn/server.key
dh /etc/ids/vpn/dh.pem
data-ciphers AES-256-GCM:AES-256-CBC
data-ciphers-fallback AES-256-GCM
auth SHA1
verify-client-cert none
username-as-common-name
auth-user-pass-verify /usr/local/bin/ovpn-auth via-file
script-security 2
tmp-dir /tmp
client-config-dir /etc/ids/vpn/ccd
ccd-exclusive
keepalive 10 60
persist-key
persist-tun
status /run/ids/openvpn-status.log 10
status-version 2
management /run/ids-ctl/ovpn-mgmt.sock unix
suppress-timestamps
verb 3
"""


def punto3(mod, **extra):
    p = {"pid": "p003", "perfil": "reducido", "hilos": 1, "api_puerto": 8729, "cpuset_suricata": "2"}
    p.update(mod.derivar(3, "100.64"))
    p.update(extra)
    return p


class Compose(unittest.TestCase):
    def setUp(self):
        self.mod = A.cargar_orq()
        self.imgs = {"vpn": "ghcr.io/mtandazo35/ids-maat-vpn@sha256:<digest>",
                     "suricata": "ghcr.io/mtandazo35/ids-maat-suricata@sha256:<digest>"}

    def test_texto_exacto_del_contrato(self):
        txt = self.mod.render_compose(punto3(self.mod), self.imgs, "0.1.0", nc=4)
        self.assertEqual(txt, COMPOSE_CONTRATO)

    def test_sin_ipfrag_low_thresh(self):
        # runc escribe los sysctls en orden de mapa (aleatorio): low (48 MB) antes que high daba
        # EINVAL (low <= high, y high vale 4 MB por defecto) y el contenedor no arrancaba.
        txt = self.mod.render_compose(punto3(self.mod), self.imgs, "0.1.0", nc=4)
        self.assertNotIn("ipfrag_low_thresh", txt)
        self.assertIn('net.ipv4.ipfrag_high_thresh: "67108864"', txt)

    def test_sin_arp_ignore(self):
        # Docker mete eth0 en el netns después de aplicar los sysctls: eth0 heredaba
        # default.arp_ignore=8, el host no resolvía la IP del contenedor por ARP y el DNAT
        # (o docker-proxy) a :1194 daba «No route to host». El veth lleva `arp off` en init-veth.
        txt = self.mod.render_compose(punto3(self.mod), self.imgs, "0.1.0", nc=4)
        self.assertNotIn("arp_ignore", txt)

    def test_pocas_cpu_omite_cpuset(self):
        txt = self.mod.render_compose(punto3(self.mod, cpuset_suricata=None), self.imgs, "0.1.0", nc=2)
        self.assertNotIn("cpuset", txt)
        self.assertIn("    cpus: 1\n", txt)

    def test_perfil_completo_y_8728(self):
        txt = self.mod.render_compose(punto3(self.mod, perfil="completo", hilos=2, api_puerto=8728,
                                             cpuset_suricata="2-3"), self.imgs, "0.1.0", nc=8)
        self.assertIn("mem_limit: 1700m", txt)
        self.assertIn("memswap_limit: 1700m", txt)
        self.assertIn('API_PUERTO: "8728"', txt)
        self.assertIn('cpuset: "2-3"\n    cpus: 2\n', txt)

    def test_raiz_de_pruebas_en_los_volumenes(self):
        txt = self.mod.render_compose(punto3(self.mod), self.imgs, "0.1.0", nc=4, raiz_host="/tmp/x/")
        self.assertIn("      - /tmp/x/srv/ids/puntos/p003/vpn:/etc/ids/vpn:ro\n", txt)
        self.assertTrue(A.sin_marcadores(txt))


class CpusetYCapacidad(unittest.TestCase):
    def setUp(self):
        self.mod = A.cargar_orq()

    def test_cpuset(self):
        m = self.mod
        self.assertIsNone(m.cpuset_vpn(3))
        self.assertEqual(m.cpuset_vpn(4), "0-1")
        self.assertIsNone(m.cpuset_suricata(2, 1, set()))
        self.assertEqual(m.cpuset_suricata(4, 1, set()), "2")
        self.assertEqual(m.cpuset_suricata(4, 1, {2}), "3")
        self.assertEqual(m.cpuset_suricata(4, 1, {2, 3}), "2-3")        # compartido
        self.assertEqual(m.cpuset_suricata(8, 2, {2, 3}), "4-5")
        self.assertEqual(m.cpuset_suricata(8, 2, {2, 4, 6, 7}), "3,5")
        self.assertEqual(m.leer_cpus("2-4,7"), {2, 3, 4, 7})

    def test_admision_y_caben(self):
        m = self.mod
        mem = {"total": 7962, "disponible": 3100}
        # 3 reducidos: 3*(900+192+32) + 900 + 1024 (host) + 1536 (panel, CONTRATO-F2 §6) = 6832
        tres = [("reducido", 1)] * 3
        self.assertEqual(m.memoria_comprometida(tres), 6832)
        self.assertTrue(m.cabe(tres, ("reducido", 1), mem))        # 4 -> 7956 <= 7962
        self.assertFalse(m.cabe(tres + [("reducido", 1)], ("reducido", 1), mem))   # 5 -> 9080 > 7962
        self.assertFalse(m.cabe(tres, ("completo", 1), mem))       # la reserva del -T sube a 1700
        self.assertFalse(m.cabe([], ("completo", 1), {"total": 7962, "disponible": 1000}))   # MemAvailable
        self.assertEqual(m.caben([], mem), {"reducido": 2, "completo-low": 1, "completo": 1})
        self.assertEqual(m.caben([], {"total": 16000, "disponible": 16000}),
                         {"reducido": 11, "completo-low": 7, "completo": 6})


class ServerConf(unittest.TestCase):
    def setUp(self):
        self.mod = A.cargar_orq()

    def test_v7_exacto(self):
        self.assertEqual(self.mod.render_server_conf("p003", "100.64.3.0", 7, "no"), SERVER_CONTRATO)

    def test_solo_ipv4_e_igual_al_fixture_de_la_imagen(self):
        # el netns del contenedor no tiene IPv6: tcp-server (dual stack) no sirve, tcp4-server sí
        txt = self.mod.render_server_conf("p003", "100.64.3.0", 7, "no")
        self.assertIn("\nproto tcp4-server\n", txt)
        self.assertNotIn("proto tcp-server", txt)
        fixture = A.REPO / "tests" / "fixtures" / "vpn" / "server.conf"     # el que arranca tests/imagen
        self.assertEqual(txt, fixture.read_text(encoding="utf-8"))

    def test_v6(self):
        txt = self.mod.render_server_conf("p003", "100.64.3.0", 6, "no")
        self.assertEqual(txt, SERVER_CONTRATO.replace("data-ciphers-fallback AES-256-GCM",
                                                      "data-ciphers-fallback AES-256-CBC"))

    def test_seclevel0_y_legacy(self):
        sec = self.mod.render_server_conf("p003", "100.64.3.0", 6, "seclevel0")
        self.assertIn('tls-cipher "DEFAULT:@SECLEVEL=0"\n', sec)
        self.assertNotIn("tls-cert-profile", sec)
        leg = self.mod.render_server_conf("p003", "100.64.3.0", 6, "legacy")
        self.assertIn('tls-cipher "DEFAULT:@SECLEVEL=0"\ntls-cert-profile legacy\n', leg)
        for txt in (sec, leg):
            for prohibido in ("tls-crypt", "tls-auth", "comp-lzo", "push ", "iroute", "user ", "group "):
                self.assertNotIn(prohibido, txt)


class Usuarios(unittest.TestCase):
    def setUp(self):
        self.mod = A.cargar_orq()

    def verificar(self, linea, clave):
        """Implementación propia de §4.5 para comprobar el hash."""
        usuario, resto = linea.split(":", 1)
        alg, n, r, p, sal, h = resto.split("$")
        self.assertEqual((alg, n, r, p), ("scrypt", "16384", "8", "1"))
        self.assertRegex(sal, r"^[0-9a-f]{32}$")
        self.assertRegex(h, r"^[0-9a-f]{64}$")
        calc = hashlib.scrypt(clave.encode(), salt=bytes.fromhex(sal), n=int(n), r=int(r), p=int(p), dklen=32)
        return usuario, calc.hex() == h

    def test_usuarios_y_hash(self):
        usuario = self.mod.nuevo_usuario()
        clave = self.mod.nueva_clave()
        self.assertRegex(usuario, r"^vpn[0-9a-f]{6}$")
        self.assertRegex(clave, r"^[A-Za-z0-9]{24}$")
        txt = self.mod.render_usuarios("p003", usuario, self.mod.hash_clave(clave))
        lineas = txt.splitlines()
        self.assertEqual(lineas[0], "# ids-maat p003 — generado por ids-orq; no editar")
        u, ok = self.verificar(lineas[1], clave)
        self.assertEqual(u, usuario)
        self.assertTrue(ok)
        self.assertFalse(self.verificar(lineas[1], clave + "x")[1])

    def test_ccd_y_threshold(self):
        self.assertEqual(self.mod.render_ccd("100.64.3.2"), "ifconfig-push 100.64.3.2 255.255.255.0\n")
        self.assertEqual(self.mod.render_threshold("p003"), "# ids-maat p003 — generado por ids-orq; no editar\n")


class SuricataYaml(unittest.TestCase):
    def setUp(self):
        import json
        self.mod = A.cargar_orq()
        self.tmpl = (A.FIX / "suricata.yaml.tmpl").read_text(encoding="utf-8")
        self.man = json.loads((A.FIX / "plantilla.json").read_text(encoding="utf-8"))
        self.val = self.mod.valores_suricata("p003", "[10.0.0.0/24,192.168.88.0/24]", "/reglas/current/reducido",
                                             3, 1, "reducido", True)

    def test_render(self):
        txt = self.mod.render_suricata(self.tmpl, self.man, self.val)
        self.assertTrue(A.sin_marcadores(txt))
        for esperado in ("sensor-name: p003", 'HOME_NET: "[10.0.0.0/24,192.168.88.0/24]"',
                         "default-rule-path: /reglas/current/reducido", "cluster-id: 103", "mpm-algo: hs",
                         "spm-algo: hs", "profile: medium", "ring-size: 1024", "block-size: 131072",
                         "snaplen: 32768", "reassembly: {memcap: 256mb}"):
            self.assertIn(esperado, txt)
        sin_hs = self.mod.valores_suricata("p003", "[10.0.0.0/24]", "/reglas/current/completo", 3, 2,
                                           "completo-low", False)
        txt = self.mod.render_suricata(self.tmpl, self.man, sin_hs)
        self.assertIn("mpm-algo: ac-ks", txt)
        self.assertIn("spm-algo: bm", txt)
        self.assertIn("sgh-mpm-context: single", txt)
        self.assertIn("profile: low", txt)

    def test_marcador_que_sobra_o_falta(self):
        E = self.mod.ErrorOrden
        with self.assertRaises(E):
            self.mod.render_suricata(self.tmpl + "\nextra: @@NUEVO@@\n", self.man, self.val)
        with self.assertRaises(E):
            self.mod.render_suricata(self.tmpl.replace("@@SNAPLEN@@", "32768"), self.man, self.val)
        man = dict(self.man, marcadores=self.man["marcadores"] + ["OTRO"])
        with self.assertRaises(E):
            self.mod.render_suricata(self.tmpl + "x: @@OTRO@@\n", man, self.val)


class Nft(unittest.TestCase):
    def setUp(self):
        self.mod = A.cargar_orq()
        self.e = A.Entorno()
        self.cfg = self.mod.config()

    def tearDown(self):
        self.e.cerrar()

    def reglas(self, txt, cadena):
        bloque = re.search(r"chain %s \{(.*?)\n  \}" % cadena, txt, re.S).group(1)
        return [x.strip() for x in bloque.splitlines() if x.strip()]

    def test_sets_y_listas(self):
        txt = self.mod.render_nft(self.cfg, [1196, 1194], [])
        self.assertTrue(A.sin_marcadores(txt))
        self.assertIn("set gestion     { type ipv4_addr; flags interval; elements = { 192.0.2.0/25, 198.51.100.0/26 } }", txt)
        self.assertIn("set proxy       { type ipv4_addr; flags interval; elements = { 203.0.113.50 } }", txt)
        self.assertIn("set puertos_vpn { type inet_service; elements = { 1194, 1196 } }", txt)
        self.assertNotIn("flush ruleset", txt.replace("Nunca «flush ruleset»", ""))
        self.assertTrue(txt.splitlines()[2:5] == ["table inet ids_host", "delete table inet ids_host",
                                                   "table inet ids_host {"])

    def test_ssh_solo_gestion_y_panel_solo_proxy(self):
        txt = self.mod.render_nft(self.cfg, [], [])
        entrada = self.reglas(txt, "input")
        self.assertIn("policy drop;", entrada[0])
        ssh = [r for r in entrada if "dport 22" in r]
        self.assertEqual(ssh, ["ip saddr @gestion tcp dport 22 accept"])
        # nada más se acepta hacia el host salvo lo, established, ICMP
        aceptan = [r for r in entrada if r.endswith("accept")]
        for r in aceptan:
            self.assertTrue(r.startswith(("iif lo", "ct state established", "meta l4proto icmp",
                                          "icmpv6 type", "ip saddr @gestion")), r)
        icmp6 = [r for r in entrada if r.startswith("icmpv6 type")][0]
        # sin nombres de /etc/protocols (ipv6-icmp): en una imagen minima no existe y nft falla
        self.assertNotIn("ipv6-icmp", txt)
        for t in ("nd-neighbor-solicit", "nd-neighbor-advert", "nd-router-advert"):
            self.assertIn(t, icmp6)
        reenvio = self.reglas(txt, "forward")
        self.assertIn("policy accept;", reenvio[0])
        panel = [r for r in reenvio if "proto-dst 5637" in r and "@proxy" in r]
        self.assertEqual(len(panel), 1)
        self.assertIn("ip saddr != @proxy counter drop", panel[0])
        self.assertTrue(any("@puertos_vpn ct state new meter vpn_new { ip saddr limit rate over 10/minute }"
                            " counter drop" in r for r in reenvio))
        self.assertIn("set puertos_vpn { type inet_service; }", txt)
        # el forward solo descarta
        self.assertFalse([r for r in reenvio[1:] if r.endswith("accept")])

    def test_origen_fijo(self):
        txt = self.mod.render_nft(self.cfg, [1196], [("p003", 1196, "203.0.113.45")])
        self.assertIn('meta l4proto tcp ct direction original ct status dnat ct original proto-dst 1196 '
                      'ip saddr != 203.0.113.45 counter drop comment "origen fijo p003"', txt)
        self.assertEqual(len(re.findall("origen fijo", txt)), 1)

    def test_puerto_panel_de_ids_conf(self):
        conf = self.e.ruta("/etc/ids-maat/ids.conf")
        conf.write_text(conf.read_text(encoding="utf-8").replace("PUERTO_PANEL=5637", "PUERTO_PANEL=6000"),
                        encoding="utf-8")
        txt = self.mod.render_nft(self.mod.config(), [], [])
        self.assertIn("proto-dst 6000 ip saddr != @proxy", txt)
        self.assertNotIn("5637", txt)

    def test_proxy_red_pequena(self):
        conf = self.e.ruta("/etc/ids-maat/ids.conf")
        conf.write_text(conf.read_text(encoding="utf-8").replace("IPS_PROXY=203.0.113.50",
                                                                  "IPS_PROXY=203.0.113.48/28,203.0.113.70"),
                        encoding="utf-8")
        txt = self.mod.render_nft(self.mod.config(), [], [])
        self.assertIn("elements = { 203.0.113.48/28, 203.0.113.70 }", txt)
        ipaddress.ip_network("203.0.113.48/28")


if __name__ == "__main__":
    unittest.main()
