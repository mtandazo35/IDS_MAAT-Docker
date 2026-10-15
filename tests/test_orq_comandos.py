"""Salida exacta de `ids-orq punto ovpn-client` (§5.12) para v7 y v6, y CLI con transporte simulado."""

import io
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ayuda_orq as A  # noqa: E402

# La CA del VPS de las pruebas (texto con la forma de un PEM; la de verdad la prueba test_orq_pki)
CA_PRUEBA = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\nAbC+/9==\n-----END CERTIFICATE-----\n"

# Cambiado a propósito (auditoría VPN-01 y VPN-02): la CA del VPS entra en el router y el
# ovpn-client verifica al servidor; ids-vpn queda aislada (drop en forward e input). Los drop de
# input van negados para que el orden respecto al accept de la API no importe, y sin place-before=0
# (que en un script pegado no apunta a nada fijo): la última línea las sube por comentario. La
# primera quita las de un alta anterior; las dos buscan con in-interface=ids-vpn para no tocar las
# reglas del espejo que llevan el mismo comentario. La cabecera pide el reloj en hora (el
# certificado del servidor vale desde 2 días antes de emitirse). Ping del router al sensor
# (2026-10-15): el drop de «no TCP» deja pasar established,related y un accept admite el ICMP de
# respuesta del sensor; un ping o un UDP NUEVO desde el túnel siguen cayendo.
_CA_P003 = r"""# CA del VPS (pública): con ella el MikroTik verifica al servidor (verify-server-certificate)
/file print file=ids-maat-ca-p003
:delay 2s
/file set [find name="ids-maat-ca-p003.txt"] contents="-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\nAbC+/9==\n-----END CERTIFICATE-----\n"
/certificate import file-name=ids-maat-ca-p003.txt passphrase=""
/certificate set [find name~"^ids-maat-ca-p003"] trusted=yes
/file remove [find name="ids-maat-ca-p003.txt"]
"""
_COMUN_P003 = r"""/user group add name=ids-api policy=read,write,api
/user add name=ids-api group=ids-api address=100.64.3.1/32 password=<CLAVE-API>
# Aislamiento de ids-vpn: por el túnel solo entra la API desde el sensor (y la respuesta al
# ping del router al sensor) y nada se enruta desde él.
# Las reglas no dependen del orden entre ellas y la última línea las sube encima
# de las del router. Para rehacerlo en un router ya dado de alta, pega desde aquí hasta el
# final: la primera línea quita las reglas de antes.
/ip firewall filter remove [find comment="IDS ids-maat:p003" in-interface=ids-vpn]
/ip firewall filter add chain=input in-interface=ids-vpn src-address=!100.64.3.1 action=drop \
    comment="IDS ids-maat:p003"
/ip firewall filter add chain=input in-interface=ids-vpn protocol=!tcp \
    connection-state=!established,related action=drop comment="IDS ids-maat:p003"
/ip firewall filter add chain=input in-interface=ids-vpn src-address=100.64.3.1 protocol=icmp \
    connection-state=established,related action=accept comment="IDS ids-maat:p003"
/ip firewall filter add chain=input in-interface=ids-vpn protocol=tcp dst-port=!8729 \
    action=drop comment="IDS ids-maat:p003"
/ip firewall filter add chain=input in-interface=ids-vpn src-address=100.64.3.1 protocol=tcp \
    dst-port=8729 action=accept comment="IDS ids-maat:p003"
/ip firewall filter add chain=forward in-interface=ids-vpn action=drop comment="IDS ids-maat:p003"
:do {/ip firewall filter move [/ip firewall filter find comment="IDS ids-maat:p003" in-interface=ids-vpn] destination=[:pick [/ip firewall filter find dynamic=no] 0]} on-error={}
"""
V7_CONTRATO = r"""# ids-maat p003 (norte) · N=3 · puerto 1196 · túnel 100.64.3.0/24 · declarado RouterOS v7
# El bloque v6 solo conecta tras: ids-orq punto ajustar p003 --ros 6
# Antes de pegar: el reloj del router en hora (/system ntp client). El certificado del
# servidor vale desde 2 días antes de emitirse; con el reloj más atrasado, el MikroTik lo rechaza.
#
# --- Certificado API-SSL ids-promax (6.49 y v7; si ya existe, solo la última línea) ---
/certificate
add name=ids-promax common-name=ids-promax \
    key-usage=key-cert-sign,crl-sign,digital-signature,tls-server,tls-client,data-encipherment,key-encipherment \
    days-valid=4576 trusted=yes
/certificate sign ids-promax
/certificate set ids-promax trusted=yes
/ip service set api-ssl certificate=ids-promax
#
# --- RouterOS v7 ---
""" + _CA_P003 + r"""/interface ovpn-client add name=ids-vpn connect-to=ids.empresa.example port=1196 protocol=tcp mode=ip \
    user=vpn3a9f2c password=<CLAVE-VPN> cipher=aes256-gcm auth=sha1 verify-server-certificate=yes \
    add-default-route=no use-peer-dns=no disabled=no
/ip route add dst-address=100.64.3.0/24 blackhole distance=250 comment="IDS ids-maat:p003"
""" + _COMUN_P003 + r"""#
# --- RouterOS v6 (6.49 o superior) ---
""" + _CA_P003 + r"""/interface ovpn-client add name=ids-vpn connect-to=ids.empresa.example port=1196 mode=ip \
    user=vpn3a9f2c password=<CLAVE-VPN> cipher=aes256 auth=sha1 verify-server-certificate=yes \
    add-default-route=no disabled=no
/ip route add dst-address=100.64.3.0/24 type=blackhole distance=250 comment="IDS ids-maat:p003"
""" + _COMUN_P003


def punto3(mod, **extra):
    p = {"pid": "p003", "nombre": "norte", "usuario": "vpn3a9f2c", "ros_version": 7, "api_puerto": 8729}
    p.update(mod.derivar(3, "100.64"))
    p.update(extra)
    return p


def comandos(mod, p, clave=None, **extra):
    return mod.comandos_mikrotik(p, "ids.empresa.example", clave, ca_pem=CA_PRUEBA, **extra)


def ovpn(b):
    """La orden /interface ovpn-client (3 líneas con continuación) y la ruta blackhole."""
    lineas = b.split("\n")
    i = [n for n, x in enumerate(lineas) if x.startswith("/interface ovpn-client")][0]
    return "\n".join(lineas[i:i + 4])


def bloque(txt, titulo):
    return txt.split("# --- %s" % titulo, 1)[1].split("\n#\n", 1)[0]


class OvpnClient(unittest.TestCase):
    def setUp(self):
        self.mod = A.cargar_orq()

    def test_v7_exacto(self):
        self.assertEqual(comandos(self.mod, punto3(self.mod)), V7_CONTRATO)

    def test_v6_declarado(self):
        txt = comandos(self.mod, punto3(self.mod, ros_version=6))
        self.assertIn("· declarado RouterOS v6\n# El bloque v7 solo conecta tras: ids-orq punto ajustar p003 --ros 7\n",
                      txt)
        self.assertIn("cipher=aes256-cbc auth=sha1", bloque(txt, "RouterOS v7"))

    def test_reglas_routeros(self):
        for ros in (6, 7):
            txt = comandos(self.mod, punto3(self.mod, ros_version=ros), clave="X" * 24)
            v6 = ovpn(bloque(txt, "RouterOS v6"))
            v7 = ovpn(bloque(txt, "RouterOS v7"))
            # v6: sin protocol=, sin use-peer-dns, cifrado aes256, blackhole type=
            self.assertNotIn("protocol=", v6)
            self.assertNotIn("use-peer-dns", v6)
            self.assertRegex(v6, r"cipher=aes256 ")
            self.assertIn("type=blackhole", v6)
            # v7: protocol=tcp y cifrado válido
            self.assertIn("protocol=tcp", v7)
            self.assertRegex(v7, r"cipher=aes256-(gcm|cbc) ")
            for b in (v6, v7):
                self.assertIn("disabled=no", b)
                self.assertIn("add-default-route=no", b)
                self.assertIn("password=%s " % ("X" * 24), b)
                # blackhole /24 (no más específico que la conectada) con distancia 250
                self.assertRegex(b, r"dst-address=100\.64\.3\.0/24 (type=)?blackhole distance=250")
                self.assertNotIn("tls-crypt", b)
            self.assertNotIn("<CLAVE-VPN>", txt)

    def test_api_8728(self):
        txt = comandos(self.mod, punto3(self.mod, api_puerto=8728))
        self.assertEqual(len(re.findall(r"dst-port=8728 ", txt)), 2)


class TransporteFalso:
    """Simula el socket: atiende con un Orquestador real y procesa la cola al pedir op.estado."""

    def __init__(self, orq):
        self.orq = orq
        self.peticiones = []

    def __call__(self, pet):
        self.peticiones.append(pet)
        if pet["orden"] == "op.estado":
            self.orq.procesar_una()
        return json.loads(json.dumps(self.orq.atender(pet)))


class Cli(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()
        self.tr = TransporteFalso(self.orq)

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def cli(self, *argv):
        out = io.StringIO()
        c = self.mod.Cliente(transporte=self.tr, dormir=lambda s: None, salida=out)
        rc = self.mod.main(list(argv), cliente=c)
        return rc, out.getvalue()

    def test_crear_imprime_pasos_clave_y_comandos(self):
        rc, out = self.cli("punto", "crear", "--nombre", "norte", "--redes", "10.0.0.0/24,192.168.88.0/24")
        self.assertEqual(rc, 0, out)
        lineas = out.splitlines()
        self.assertRegex(lineas[0], r"^en cola: op [0-9a-f-]+ \(0 delante\)$")
        self.assertRegex(lineas[1], r"^  \[1/14\] validar \.+ ok$")
        self.assertRegex(lineas[14], r"^  \[14/14\] esperar salud \.+ ok")
        self.assertIn("OK punto p001 creado", out)
        self.assertIn("  túnel        100.64.1.0/24 (sensor 100.64.1.1, MikroTik 100.64.1.2)", out)
        self.assertIn("  perfil       reducido · hilos 1 · cpuset 2 · mem_limit 900m", out)
        clave = re.search(r"clave VPN    ([A-Za-z0-9]{24})      ← se muestra UNA sola vez", out).group(1)
        self.assertEqual(out.count("password=%s " % clave), 2)
        self.assertTrue(all(p["quien"].startswith("cli:") for p in self.tr.peticiones))
        p = self.tr.peticiones[0]
        self.assertEqual(p["params"], {"nombre": "norte", "redes_abonados": ["10.0.0.0/24", "192.168.88.0/24"]})
        # ovpn-client: nunca la clave
        rc, out2 = self.cli("punto", "ovpn-client", "p001")
        self.assertEqual(rc, 0)
        self.assertNotIn(clave, out2)
        self.assertEqual(out2.count("password=<CLAVE-VPN>"), 2)
        self.assertTrue(out2.startswith("# ids-maat p001 (norte) · N=1 · puerto 1194"))

    def test_codigos_de_salida(self):
        rc, out = self.cli("punto", "crear", "--nombre", "norte", "--redes", "0.0.0.0/0")
        self.assertEqual(rc, 2, out)
        self.assertTrue(out.startswith("INVALIDO"))
        rc, _ = self.cli("punto", "estado", "p009")
        self.assertEqual(rc, 4)
        with self.assertRaises(SystemExit) as cm:
            self.cli("punto", "crear", "--nombre", "norte")
        self.assertEqual(cm.exception.code, 2)
        self.e.escribir_meminfo(2048, 1024)
        rc, out = self.cli("punto", "crear", "--nombre", "norte", "--redes", "10.0.0.0/24")
        self.assertEqual(rc, 3, out)
        self.assertIn("CONFLICTO no cabe", out)
        self.assertIn("caben: reducido 0", out)

    def test_compat_v6_sin_valor_es_seclevel0(self):
        a = self.mod.construir_parser().parse_args(["punto", "crear", "--nombre", "x1", "--redes", "10.0.0.0/24",
                                                    "--compat-v6", "--ros", "6"])
        orden, params = self.mod.orden_desde_args(a)
        self.assertEqual((orden, params["compat_v6"], params["ros_version"]), ("punto.crear", "seclevel0", 6))
        a = self.mod.construir_parser().parse_args(["punto", "ajustar", "p001", "--sin-compat-v6",
                                                    "--sin-origen-ip"])
        self.assertEqual(self.mod.orden_desde_args(a), ("punto.ajustar",
                                                        {"pid": "p001", "compat_v6": "no", "origen_ip": None}))

    def test_no_esperar_y_json(self):
        rc, out = self.cli("reconciliar", "--no-esperar")
        self.assertEqual(rc, 0)
        self.assertRegex(out.strip(), r"^[0-9a-f-]{36}$")
        rc, out = self.cli("punto", "estado", "--json")
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["codigo"], "OK")

    def test_estado_tabla(self):
        rc, out = self.cli("punto", "crear", "--nombre", "norte", "--redes", "10.0.0.0/24")
        self.assertEqual(rc, 0, out)
        rc, out = self.cli("estado")
        self.assertEqual(rc, 0, out)
        lineas = out.splitlines()
        self.assertTrue(lineas[0].startswith("ids-orq 0.1.0 · versión 0.1.0 · base de túneles 100.64 · reglas "))
        self.assertTrue(lineas[1].startswith("cola: libre"))
        self.assertTrue(lineas[2].startswith("memoria: total 7962 MB"))
        self.assertEqual(lineas[3].split(), ["PID", "NOMBRE", "N", "PUERTO", "PERFIL", "DESEADO", "ESTADO", "VPN",
                                             "ESPEJO", "NETNS", "AVISOS"])
        self.assertEqual(lineas[4].split()[:7], ["p001", "norte", "1", "1194", "reducido", "activo", "activo"])

    def test_sin_servicio_sale_con_5(self):
        def caido(pet):
            raise self.mod.SinServicio("no existe el socket")
        c = self.mod.Cliente(transporte=caido, dormir=lambda s: None, salida=io.StringIO())
        self.assertEqual(self.mod.main(["estado"], cliente=c), 5)


if __name__ == "__main__":
    unittest.main()
