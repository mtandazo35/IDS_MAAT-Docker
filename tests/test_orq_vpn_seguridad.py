"""VPN de los puntos, auditoría 2026-10-14 (apartado C, servidor), con comportamiento y no con texto:

- VPN-01: el script del MikroTik lleva la CA del VPS (nunca una clave) y verify-server-certificate=yes
  en v6 y v7; el certificado de servidor lleva NOMBRE_DNS y «Regenerar» renueva los de antes.
- Sin firewall ni rutas (decisión del dueño, 2026-10-15; sustituye al aislamiento de VPN-02): el
  script solo crea el ovpn-client y el usuario ids-api limitado al sensor, y la limpieza del espejo
  no toca lo que dejaron las altas de antes ni las reglas del operador.
- VPN-03: server.conf con plazas para conexiones a medio negociar y hand-window corto.
- VPN-05: Suricata sin NET_ADMIN.
- VPN-13: el estado toma la sesión autenticada más reciente, no una conexión a medio negociar.
"""

import re
import sys
import unittest
from pathlib import Path

AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(AQUI))
import _ayuda_orq as A  # noqa: E402

LIB_PANEL = AQUI.parent / "images" / "panel" / "rootfs" / "usr" / "local" / "lib" / "ids-panel"
NORTE = {"nombre": "norte", "redes_abonados": ["10.0.0.0/24"]}


def bloque(txt, titulo):
    return txt.split("# --- %s" % titulo, 1)[1].split("\n#\n", 1)[0]


def ordenes(b):
    """Las órdenes RouterOS de un bloque, con las continuaciones « \\» unidas y sin comentarios."""
    out, actual = [], ""
    for linea in b.splitlines():
        if not actual and (not linea.strip() or linea.startswith("#")):
            continue
        if linea.endswith(" \\"):
            actual += linea[:-2] + " "
            continue
        out.append((actual + linea.strip()).strip())
        actual = ""
    return out


def props(orden):
    return dict(m.groups() for m in re.finditer(r'([a-z-]+)=("[^"]*"|\S+)', orden))


class Base(unittest.TestCase):
    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar(ncpu=8)
        r = A.crear(self, self.orq, NORTE)
        self.crear = r["resultado"]
        self.s.llamadas.clear()

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def comandos(self):
        r = self.orq.atender(A.peticion("punto.comandos", {"pid": "p001"}))
        self.assertEqual(r["codigo"], "OK", r)
        return r["datos"]["comandos"]


class CaYVerificacion(Base):
    """VPN-01."""

    def test_el_alta_lleva_la_ca_y_verifica_en_los_dos_bloques(self):
        ca = self.e.ruta("/srv/ids/pki/ca.crt").read_text(encoding="utf-8").strip()
        for txt in (self.crear["comandos"], self.comandos()):
            self.assertNotIn("# AVISO", txt)                 # el certificado del alta ya lleva el nombre
            self.assertNotIn("PRIVATE", txt)
            for titulo in ("RouterOS v7", "RouterOS v6"):
                cmds = ordenes(bloque(txt, titulo))
                i_import = next(i for i, c in enumerate(cmds) if c.startswith("/certificate import"))
                i_ovpn = next(i for i, c in enumerate(cmds) if c.startswith("/interface ovpn-client add"))
                self.assertLess(i_import, i_ovpn, titulo)    # la CA está antes de que el túnel conecte
                self.assertIn("verify-server-certificate=yes", cmds[i_ovpn])
                self.assertEqual(cmds[i_import], '/certificate import file-name=ids-maat-ca-p001.txt passphrase=""')
                fset = next(c for c in cmds if c.startswith("/file set"))
                contenido = re.search(r'contents="(.*)"$', fset).group(1)
                self.assertEqual(contenido.replace("\\n", "\n").strip(), ca)
                # el fichero de paso se borra y el certificado se puede encontrar para la baja
                self.assertIn('/file remove [find name="ids-maat-ca-p001.txt"]', cmds)
                self.assertIn('/certificate set [find name~"^ids-maat-ca-p001"] trusted=yes', cmds)
        self.assertEqual(self.comandos().count("password=<CLAVE-VPN>"), 2)

    def test_una_ca_que_no_cabe_en_routeros_no_llega_al_script(self):
        ca = self.e.ruta("/srv/ids/pki/ca.crt")
        for malo in ('-----BEGIN CERTIFICATE-----\nAB"; /system reset\n-----END CERTIFICATE-----\n',
                     "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
                     "-----BEGIN CERTIFICATE-----\n" + "A" * 4100 + "\n-----END CERTIFICATE-----\n", ""):
            with self.subTest(malo=malo[:30]):
                ca.write_text(malo, encoding="utf-8")
                r = self.orq.atender(A.peticion("punto.comandos", {"pid": "p001"}))
                self.assertEqual(r["codigo"], "FALLO", r)
                self.assertNotIn("comandos", r["datos"])

    def _certificado_viejo(self):
        """Lo que tiene un punto de antes de VPN-01: un server.crt sin SAN."""
        crt = self.e.ruta("/srv/ids/puntos/p001/vpn/server.crt")
        crt.write_text("-----BEGIN FALSO-----\nCN=server-p001\n", encoding="utf-8")
        return crt

    def test_regenerar_renueva_el_certificado_viejo_y_reinicia_openvpn(self):
        crt = self._certificado_viejo()
        self.assertIn("# AVISO: el certificado del servidor de este punto", self.comandos())
        self.assertIn("ids-orq punto vpn-regenerar p001", self.comandos())
        r = A.ejecutar_orden(self.orq, "punto.vpn.regenerar", {"pid": "p001"})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertIn("certificado del servidor renovado", r["mensaje"])
        self.assertEqual([p["nombre"] for p in r["pasos"]], ["certificado", "usuarios", "reiniciar openvpn"])
        self.assertIn("subjectAltName=DNS:ids.empresa.example", crt.read_text(encoding="utf-8"))
        self.assertTrue(self.mod.cert_lleva_nombre(crt, "ids.empresa.example"))
        self.assertTrue(self.s.ordenes("docker exec ids-p001-vpn /command/s6-svc -r /run/service/openvpn"))
        self.assertNotIn("# AVISO", r["resultado"]["comandos"])
        self.assertIn("password=%s " % r["resultado"]["clave"], r["resultado"]["comandos"])
        self.assertNotIn("# AVISO", self.comandos())

    def test_la_huella_de_la_clave_vigente_cambia_al_regenerar(self):
        """El panel guarda la clave cifrada con `clave_id` y solo la pone en los comandos si es la
        vigente: el alta y punto.comandos dan la misma huella; regenerar (por la CLI también) la
        cambia; y la huella no contiene la clave."""
        c1 = self.orq.atender(A.peticion("punto.comandos", {"pid": "p001"}))["datos"]["clave_id"]
        self.assertRegex(c1, r"^[0-9a-f]{16}$")
        self.assertEqual(self.crear["clave_id"], c1)
        r = A.ejecutar_orden(self.orq, "punto.vpn.regenerar", {"pid": "p001"})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        c2 = self.orq.atender(A.peticion("punto.comandos", {"pid": "p001"}))["datos"]["clave_id"]
        self.assertNotEqual(c1, c2)
        self.assertEqual(r["resultado"]["clave_id"], c2)
        self.assertNotIn(r["resultado"]["clave"], c2)

    def test_regenerar_con_certificado_bueno_no_lo_toca(self):
        crt = self.e.ruta("/srv/ids/puntos/p001/vpn/server.crt")
        antes = crt.read_bytes()
        r = A.ejecutar_orden(self.orq, "punto.vpn.regenerar", {"pid": "p001"})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertEqual(r["mensaje"], "credencial regenerada")
        self.assertEqual(crt.read_bytes(), antes)
        self.assertFalse(self.s.ordenes("docker exec ids-p001-vpn /command/s6-svc"))
        self.assertFalse(self.s.ordenes("openssl req"))

    def test_regenerar_un_punto_parado_renueva_sin_docker(self):
        self.assertEqual(A.ejecutar_orden(self.orq, "punto.parar", {"pid": "p001"})["codigo"], "OK")
        self._certificado_viejo()
        self.s.llamadas.clear()
        r = A.ejecutar_orden(self.orq, "punto.vpn.regenerar", {"pid": "p001"})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertFalse(self.s.ordenes("docker exec"))
        self.assertTrue(any("se carga al arrancar" in x for x in r.get("log_tail", [])), r.get("log_tail"))

    def test_si_openvpn_no_reinicia_la_clave_se_entrega_igual(self):
        self._certificado_viejo()
        self.s.fallar["s6-svc -r"] = 1
        r = A.ejecutar_orden(self.orq, "punto.vpn.regenerar", {"pid": "p001"})
        self.assertEqual(r["codigo"], "OK", A.explicar(r))
        self.assertIn("OpenVPN no se reinició", r["mensaje"])
        self.assertRegex(r["resultado"]["clave"], r"^[A-Za-z0-9]{24}$")


class SinFirewallNiRutas(unittest.TestCase):
    """Decisión del dueño (2026-10-15): el script del MikroTik no lleva reglas de firewall ni rutas.
    Crea la VPN (verificando al servidor) y el usuario de la API limitado al sensor; el firewall y
    las rutas del router son del operador."""

    SENSOR = "100.64.3.1"

    def setUp(self):
        self.mod = A.cargar_orq()
        p = {"pid": "p003", "nombre": "norte", "usuario": "vpn3a9f2c", "ros_version": 7, "api_puerto": 8729}
        p.update(self.mod.derivar(3, "100.64"))
        self.p = p

    def textos(self):
        """(ros declarado, puerto API, script completo) en las cuatro combinaciones."""
        for ros in (7, 6):
            for api in (8729, 8728):
                txt = self.mod.comandos_mikrotik(dict(self.p, ros_version=ros, api_puerto=api),
                                                 "ids.empresa.example",
                                                 ca_pem="-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----")
                yield ros, api, txt

    def test_ninguna_orden_de_firewall_ni_de_rutas(self):
        for ros, api, txt in self.textos():
            for titulo in ("RouterOS v7", "RouterOS v6"):
                with self.subTest(ros=ros, api=api, bloque=titulo):
                    cmds = ordenes(bloque(txt, titulo))
                    self.assertTrue(cmds)
                    self.assertFalse([c for c in cmds if c.startswith(("/ip firewall", "/ip route"))], cmds)
                    self.assertFalse([c for c in cmds if "place-before" in c or "blackhole" in c], cmds)
            with self.subTest(ros=ros, api=api, bloque="script entero"):
                # tampoco en la cabecera ni en el bloque del certificado (órdenes, no comentarios)
                todas = ordenes(txt)
                self.assertFalse([c for c in todas if c.startswith(("/ip firewall", "/ip route"))
                                  or "place-before" in c or "in-interface=" in c], todas)

    def test_vpn_que_verifica_y_usuario_api_limitado_al_sensor(self):
        for ros, api, txt in self.textos():
            for titulo in ("RouterOS v7", "RouterOS v6"):
                with self.subTest(ros=ros, api=api, bloque=titulo):
                    cmds = ordenes(bloque(txt, titulo))
                    ovpn = [c for c in cmds if c.startswith("/interface ovpn-client add ")]
                    self.assertEqual(len(ovpn), 1, cmds)
                    o = props(ovpn[0])
                    self.assertEqual((o["name"], o["verify-server-certificate"], o["add-default-route"],
                                      o["connect-to"]), ("ids-vpn", "yes", "no", "ids.empresa.example"))
                    grupo = [c for c in cmds if c.startswith("/user group add ")]
                    usuario = [c for c in cmds if c.startswith("/user add ")]
                    self.assertEqual((len(grupo), len(usuario)), (1, 1), cmds)
                    self.assertEqual(props(grupo[0]), {"name": "ids-api", "policy": "read,write,api"})
                    u = props(usuario[0])
                    self.assertEqual((u["name"], u["group"], u["address"]),
                                     ("ids-api", "ids-api", "%s/32" % self.SENSOR))
                    # el grupo existe antes que el usuario que lo usa
                    self.assertLess(cmds.index(grupo[0]), cmds.index(usuario[0]))

    def test_el_espejo_no_las_toma_por_suyas(self):
        """mikrotik_init (panel) retira del filter solo lo que reconoce como del espejo. Las reglas
        que dejaron en el router las altas de antes (aislamiento de ids-vpn y accept de la API, con
        el comentario del alta) y las del operador no lo son: retirar o rehacer el espejo no las
        toca. Lo que sí tiene forma de espejo se reconoce (control de que la prueba no es vacía)."""
        sys.path.insert(0, str(LIB_PANEL))
        try:
            import mikrotik_init as mk
        finally:
            sys.path.remove(str(LIB_PANEL))
        alta, s = "IDS ids-maat:p003", self.SENSOR
        ajenas = [
            {"chain": "input", "in-interface": "ids-vpn", "src-address": "!" + s, "action": "drop", "comment": alta},
            {"chain": "input", "in-interface": "ids-vpn", "protocol": "!tcp",
             "connection-state": "!established,related", "action": "drop", "comment": alta},
            {"chain": "input", "in-interface": "ids-vpn", "src-address": s, "protocol": "tcp", "dst-port": "8729",
             "action": "accept", "comment": alta},
            {"chain": "forward", "in-interface": "ids-vpn", "action": "drop", "comment": alta},
            {"chain": "forward", "in-interface": "ids-vpn", "action": "drop", "comment": "regla del operador"},
            {"chain": "forward", "src-address-list": mk.LISTA, "action": "accept", "comment": "IDS ids-maat:p0031"},
            {"chain": "forward", "action": "accept"},
        ]
        for fila in ajenas:
            with self.subTest(fila=fila):
                self.assertFalse(mk.es_del_espejo(fila, "filter", "p003"), fila)
        for fila in ({"chain": "forward", "src-address-list": mk.LISTA, "action": "accept", "comment": alta},
                     {"chain": "forward", "action": "fasttrack-connection", "comment": mk.comentario("p003")}):
            with self.subTest(fila=fila):
                self.assertTrue(mk.es_del_espejo(fila, "filter", "p003"), fila)


class ServerConf(unittest.TestCase):
    """VPN-03: dos TCP colgadas de un desconocido no dejan fuera al MikroTik."""

    def setUp(self):
        self.mod = A.cargar_orq()

    def opciones(self, ros=7):
        txt = self.mod.render_server_conf("p003", "100.64.3.0", ros, "no")
        out = {}
        for linea in txt.splitlines():
            if linea.strip() and not linea.startswith("#"):
                k, _, v = linea.partition(" ")
                out[k] = v.strip()
        return out

    def test_plazas_y_hand_window(self):
        for ros in (6, 7):
            o = self.opciones(ros)
            self.assertGreaterEqual(int(o["max-clients"]), 8, ros)
            self.assertLessEqual(int(o["hand-window"]), 20, ros)
            self.assertGreaterEqual(int(o["hand-window"]), 10, ros)   # margen para un 6.49 lento
            # sigue habiendo un solo túnel útil: sin duplicate-cn, la sesión nueva echa a la vieja
            self.assertNotIn("duplicate-cn", o)
            self.assertIn("ccd-exclusive", o)
            # el freno del host (10 conexiones nuevas/min por IP) y hand-window acotan lo que una IP
            # puede tener abierto a la vez: no llega a llenar las plazas
            por_ip = 10 / 60 * int(o["hand-window"])
            self.assertLess(por_ip * 2, int(o["max-clients"]) - 1)

    def test_fixture_de_la_imagen_igual_que_el_render(self):
        """tests/fixtures/vpn/server.conf es el que arranca la prueba de imagen con OpenVPN real."""
        fix = (AQUI / "fixtures" / "vpn" / "server.conf").read_text(encoding="utf-8")
        self.assertEqual(fix, self.mod.render_server_conf("p003", "100.64.3.0", 7, "no"))


class SuricataSinNetAdmin(unittest.TestCase):
    """VPN-05: Suricata (el que analiza el tráfico hostil) sin NET_ADMIN en el netns del túnel."""

    def test_capacidades(self):
        mod = A.cargar_orq()
        tmpl = (Path(mod.dir_plantillas()) / "compose.yml.tmpl").read_text(encoding="utf-8")
        sur = tmpl.split("\n  suricata:\n", 1)[1].split("\nnetworks:", 1)[0]
        vpn = tmpl.split("\n  vpn:\n", 1)[1].split("\n  suricata:\n", 1)[0]
        caps = re.search(r"^\s*cap_add: \[([^\]]*)\]", sur, re.M).group(1)
        self.assertEqual([c.strip() for c in caps.split(",")], ["NET_RAW"])
        self.assertIn("cap_drop: [ALL]", sur)
        # el vpn sigue con lo suyo (tun0, veth, nft, ethtool) y le deja ids-mon en promisc
        self.assertIn("cap_add: [NET_ADMIN, NET_RAW]", vpn)
        veth = (AQUI.parent / "images" / "vpn" / "rootfs" / "etc" / "s6-overlay" / "scripts" / "init-veth").read_text(
            encoding="utf-8")
        self.assertIn("ids-mon up mtu 65535 promisc on", veth)
        # Suricata no intenta tocar los offloads (eso pediría NET_ADMIN)
        yaml = (AQUI.parent / "images" / "suricata" / "rootfs" / "usr" / "share" / "ids-maat"
                / "suricata.yaml.tmpl").read_text(encoding="utf-8")
        self.assertRegex(yaml, r"(?m)^capture:\n  disable-offloading: false$")


class StatusOpenVPN(unittest.TestCase):
    """VPN-13: con más plazas puede haber conexiones a medio negociar y dos sesiones del MikroTik."""

    def setUp(self):
        self.mod, self.e, self.s, self.orq = A.preparar()

    def tearDown(self):
        A.cerrar(self.orq, self.e)

    def test_sesion_autenticada_mas_reciente(self):
        d = self.e.ruta("/srv/ids/run/p001")
        d.mkdir(parents=True, exist_ok=True)
        f = d / "openvpn-status.log"
        f.write_text(
            "TITLE,OpenVPN 2.6\n"
            "CLIENT_LIST,UNDEF,198.51.100.66:40000,,,0,0,2026-10-10 06:20:00,1760077300,UNDEF,5,5,UNDEF\n"
            "CLIENT_LIST,vpn3a9f2c,203.0.113.45:51234,100.64.1.2,,1000,2000,2026-10-10 06:15:00,1760077000,"
            "vpn3a9f2c,0,0,AES-256-GCM\n"
            "CLIENT_LIST,vpn3a9f2c,203.0.113.46:51300,100.64.1.2,,10,20,2026-10-10 06:18:00,1760077180,"
            "vpn3a9f2c,1,1,AES-256-GCM\n"
            "CLIENT_LIST,UNDEF,198.51.100.67:40001,,,0,0,2026-10-10 06:21:00,1760077360,UNDEF,6,6,UNDEF\n",
            encoding="utf-8")
        r = self.mod.leer_status_openvpn(f)
        self.assertEqual((r["conectado"], r["ip_real"], r["desde"], r["usuario"]),
                         (True, "203.0.113.46", 1760077180, "vpn3a9f2c"))
        f.write_text("CLIENT_LIST,UNDEF,198.51.100.66:40000,,,0,0,x,1760077300,UNDEF,5,5,UNDEF\n", encoding="utf-8")
        self.assertFalse(self.mod.leer_status_openvpn(f)["conectado"])


if __name__ == "__main__":
    unittest.main()
