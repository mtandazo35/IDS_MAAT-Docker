"""VPN de los puntos, auditoría 2026-10-14 (apartado C, servidor), con comportamiento y no con texto:

- VPN-01: el script del MikroTik lleva la CA del VPS (nunca una clave) y verify-server-certificate=yes
  en v6 y v7; el certificado de servidor lleva NOMBRE_DNS y «Regenerar» renueva los de antes.
- VPN-02: con las reglas del script, por ids-vpn solo entra la API desde el sensor (se simulan el
  `add` al final, la negación `!` y el `move` por comentario de RouterOS y se evalúan paquetes), en
  cualquier orden entre ellas, y la limpieza del espejo no las toca.
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


_QUITAR = re.compile(r'^/ip firewall filter remove \[find comment=("[^"]*") in-interface=(\S+)\]$')
_MOVER = re.compile(r'^:do \{/ip firewall filter move \[/ip firewall filter find comment=("[^"]*") '
                    r'in-interface=(\S+)\] '
                    r'destination=\[:pick \[/ip firewall filter find dynamic=no\] 0\]\} on-error=\{\}$')


def _es(r, comment, iface):
    """`find comment=X in-interface=Y` de RouterOS: casan las dos propiedades, tal cual."""
    return r.get("comment") == comment and r.get("in-interface") == iface


def aplicar_filter(previas, cmds):
    """Lo que hace RouterOS con el bloque, sobre /ip firewall filter (una sola lista para todas las
    cadenas):
    - `remove [find comment=X in-interface=Y]`: quita las reglas cuyo comentario Y in-interface
      casan; las del mismo comentario sin ese in-interface (el espejo) se quedan.
    - `add`: al final.
    - `move [find comment=X in-interface=Y] destination=<primera no dinámica>`: las que casan van,
      en su orden, delante de esa regla. Si esa regla es una de las que se mueven (o no hay
      ninguna), RouterOS da error y el on-error lo deja como está.
    Cualquier otra orden de filter (place-before incluido) hace fallar la prueba."""
    reglas = list(previas)
    for c in cmds:
        m = _MOVER.match(c)
        if m:
            com, iface = m.groups()
            fijas = [r for r in reglas if r.get("dynamic") != "yes"]
            mover = [r for r in reglas if _es(r, com, iface)]
            if not fijas or not mover or any(fijas[0] is r for r in mover):
                continue
            destino = fijas[0]
            resto = [r for r in reglas if not _es(r, com, iface)]
            i = next(n for n, r in enumerate(resto) if r is destino)
            reglas = resto[:i] + mover + resto[i:]
            continue
        m = _QUITAR.match(c)
        if m:
            reglas = [r for r in reglas if not _es(r, *m.groups())]
            continue
        if "/ip firewall filter" not in c:
            continue
        if not c.startswith("/ip firewall filter add "):
            raise AssertionError("orden de filter que el simulador no conoce: %s" % c)
        p = props(c)
        if "place-before" in p:
            raise AssertionError("place-before en un script pegado no apunta a nada fijo: %s" % c)
        reglas.append(p)
    return reglas


def _casa(valor, dato):
    """`valor` de la regla (con `!` = negado) contra el dato del paquete."""
    if valor.startswith("!"):
        return str(dato) != valor[1:]
    return str(dato) == valor


def _en_lista(valor, listas):
    """`src-address-list` de la regla (con `!` = negado) contra las listas del origen."""
    if valor.startswith("!"):
        return valor[1:] not in listas
    return valor in listas


def veredicto(reglas, chain, in_iface, src, proto="tcp", dport=None, listas=()):
    """La primera regla que casa decide (accept/drop); si ninguna, la política (accept). Las
    dinámicas (fasttrack) no deciden aquí. `listas`: las address-list en que está el origen."""
    for r in reglas:
        if r.get("chain") != chain or r.get("dynamic") == "yes":
            continue
        if "in-interface" in r and not _casa(r["in-interface"], in_iface):
            continue
        if "src-address" in r and not _casa(r["src-address"], src):
            continue
        if "src-address-list" in r and not _en_lista(r["src-address-list"], listas):
            continue
        if "protocol" in r and not _casa(r["protocol"], proto):
            continue
        if "dst-port" in r and (proto != "tcp" or not _casa(r["dst-port"], dport)):
            continue
        return r["action"]
    return "accept"


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


class Aislamiento(unittest.TestCase):
    """VPN-02: lo que queda en /ip firewall filter tras pegar el bloque, y qué paquetes pasan."""

    def setUp(self):
        self.mod = A.cargar_orq()
        p = {"pid": "p003", "nombre": "norte", "usuario": "vpn3a9f2c", "ros_version": 7, "api_puerto": 8729}
        p.update(self.mod.derivar(3, "100.64"))
        self.p = p

    def bloques(self, **extra):
        txt = self.mod.comandos_mikrotik(dict(self.p, **extra), "ids.empresa.example",
                                         ca_pem="-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----")
        return {t: ordenes(bloque(txt, t)) for t in ("RouterOS v7", "RouterOS v6")}

    def comprobar_aislada(self, reglas, api):
        sensor, otro = "100.64.3.1", "100.64.3.9"
        self.assertEqual(veredicto(reglas, "input", "ids-vpn", sensor, dport=api), "accept")
        for puerto in (22, 8291, 80, 8728 if api == 8729 else 8729):
            self.assertEqual(veredicto(reglas, "input", "ids-vpn", sensor, dport=puerto), "drop", puerto)
        self.assertEqual(veredicto(reglas, "input", "ids-vpn", sensor, "icmp"), "drop")
        self.assertEqual(veredicto(reglas, "input", "ids-vpn", sensor, "udp"), "drop")
        self.assertEqual(veredicto(reglas, "input", "ids-vpn", otro, dport=api), "drop")
        # nada se enruta desde el túnel hacia las redes del ISP
        self.assertEqual(veredicto(reglas, "forward", "ids-vpn", sensor, dport=443), "drop")

    def test_solo_entra_la_api_desde_el_sensor(self):
        # el router ya tenía reglas propias (aceptar todo lo de la LAN y todo forward), con la
        # dinámica del fasttrack delante, que el move se salta
        previas = [{"chain": "forward", "action": "passthrough", "dynamic": "yes"},
                   {"chain": "input", "action": "accept", "in-interface": "bridge-lan"},
                   {"chain": "input", "action": "accept"},
                   {"chain": "forward", "action": "accept"}]
        for api in (8729, 8728):
            for titulo, cmds in self.bloques(api_puerto=api).items():
                with self.subTest(api=api, bloque=titulo):
                    reglas = aplicar_filter(previas, cmds)
                    self.comprobar_aislada(reglas, api)
                    # lo que no viene por ids-vpn sigue con las reglas del router
                    self.assertEqual(veredicto(reglas, "input", "bridge-lan", "192.0.2.7", dport=22), "accept")
                    self.assertEqual(veredicto(reglas, "forward", "ether1", "192.0.2.7", dport=443), "accept")
                    nuevas = [i for i, r in enumerate(reglas) if r.get("comment") == '"IDS ids-maat:p003"']
                    self.assertEqual(nuevas, [1, 2, 3, 4, 5])          # tras la dinámica, antes de las del router
                    self.assertEqual(reglas[0], previas[0])

    def test_con_la_lista_vacia_tambien(self):
        for titulo, cmds in self.bloques().items():
            with self.subTest(bloque=titulo):
                reglas = aplicar_filter([], cmds)
                self.assertEqual(len(reglas), 5)
                self.comprobar_aislada(reglas, 8729)

    def test_el_orden_entre_ellas_da_igual(self):
        """Lo que arreglan las reglas negadas: tres place-before=0 en un script pegado dejaban el
        accept debajo del drop de input. Ahora ningún orden de las cinco abre ni cierra de más."""
        import itertools
        cmds = self.bloques()["RouterOS v7"]
        add = [c for c in cmds if c.startswith("/ip firewall filter add ")]
        self.assertEqual(len(add), 5)
        for orden in itertools.permutations(add):
            self.comprobar_aislada(aplicar_filter([], list(orden)), 8729)

    def test_las_reglas_van_despues_de_crear_la_interfaz(self):
        for titulo, cmds in self.bloques().items():
            i_ovpn = next(i for i, c in enumerate(cmds) if c.startswith("/interface ovpn-client add"))
            for i, c in enumerate(cmds):
                if "in-interface=ids-vpn" in c:
                    self.assertGreater(i, i_ovpn, titulo)

    def del_punto(self, reglas):
        """Las reglas del aislamiento: comentario del alta e in-interface=ids-vpn."""
        return [r for r in reglas if r.get("comment") == '"IDS ids-maat:p003"' and r.get("in-interface") == "ids-vpn"]

    def test_pegarlo_dos_veces_deja_cinco_y_sigue_aislada(self):
        """Router ya dado de alta: volver a pegar el bloque entero (o desde el remove, como dice su
        comentario) no duplica reglas ni las deja por debajo de las del router."""
        previas = [{"chain": "forward", "action": "passthrough", "dynamic": "yes"},
                   {"chain": "input", "action": "accept"},
                   {"chain": "forward", "action": "accept"}]
        for titulo, cmds in self.bloques().items():
            with self.subTest(bloque=titulo):
                dos = aplicar_filter(aplicar_filter(previas, cmds), cmds)
                self.assertEqual(len(self.del_punto(dos)), 5)
                self.assertEqual(len(dos), len(previas) + 5)
                self.comprobar_aislada(dos, 8729)
                self.assertEqual([i for i, r in enumerate(dos) if r in self.del_punto(dos)], [1, 2, 3, 4, 5])
                i = next(n for n, c in enumerate(cmds) if c.startswith("/ip firewall filter remove "))
                tres = aplicar_filter(dos, cmds[i:])
                self.assertEqual(len(self.del_punto(tres)), 5)
                self.assertEqual(len(tres), len(previas) + 5)
                self.comprobar_aislada(tres, 8729)

    def test_rehacer_sobre_un_alta_vieja_con_el_orden_roto(self):
        """Un alta de antes (place-before=0 seguidos): el drop de input tapaba el accept de la API.
        Pegar el bloque nuevo las quita y deja la API abierta solo al sensor."""
        com = '"IDS ids-maat:p003"'
        viejas = [{"chain": "forward", "in-interface": "ids-vpn", "action": "drop", "comment": com},
                  {"chain": "input", "in-interface": "ids-vpn", "action": "drop", "comment": com},
                  {"chain": "input", "in-interface": "ids-vpn", "src-address": "100.64.3.1", "protocol": "tcp",
                   "dst-port": "8729", "action": "accept", "comment": com},
                  {"chain": "input", "action": "accept"}]
        self.assertEqual(veredicto(viejas, "input", "ids-vpn", "100.64.3.1", dport=8729), "drop")
        for titulo, cmds in self.bloques().items():
            with self.subTest(bloque=titulo):
                reglas = aplicar_filter(viejas, cmds)
                self.assertEqual(len(self.del_punto(reglas)), 5)
                self.assertEqual(len(reglas), 1 + 5)
                self.comprobar_aislada(reglas, 8729)

    def test_el_remove_no_toca_el_espejo_con_el_mismo_comentario(self):
        """Las reglas forward del espejo de versiones anteriores llevan el comentario del alta pero
        no in-interface=ids-vpn: ni el remove ni el move las tocan (tampoco pegando dos veces)."""
        com = '"IDS ids-maat:p003"'
        espejo = {"chain": "forward", "src-address-list": "ids-vigilados", "action": "accept", "comment": com}
        previas = [{"chain": "forward", "action": "passthrough", "dynamic": "yes"},
                   espejo,
                   {"chain": "input", "action": "accept"},
                   {"chain": "forward", "action": "drop"}]
        abonado = ("forward", "ether2", "10.0.0.5")
        self.assertEqual(veredicto(previas, *abonado, dport=443, listas=("ids-vigilados",)), "accept")
        for titulo, cmds in self.bloques().items():
            with self.subTest(bloque=titulo):
                una = aplicar_filter(previas, cmds)
                for reglas in (una, aplicar_filter(una, cmds)):
                    self.assertEqual([r for r in reglas if r == espejo], [espejo])
                    self.assertEqual(len(reglas), len(previas) + 5)
                    # el abonado vigilado sigue pasando por la regla del espejo; el resto, por el drop
                    self.assertEqual(veredicto(reglas, *abonado, dport=443, listas=("ids-vigilados",)), "accept")
                    self.assertEqual(veredicto(reglas, *abonado, dport=443), "drop")
                    self.comprobar_aislada(reglas, 8729)
                    # el aislamiento queda delante de la regla del espejo
                    idx = [i for i, r in enumerate(reglas) if r in self.del_punto(reglas)]
                    self.assertEqual(idx, [1, 2, 3, 4, 5])
                    self.assertEqual(reglas.index(espejo), 6)

    def test_el_simulador_rechaza_lo_que_no_conoce(self):
        """Sin in-interface en el find (se llevaría el espejo) o con place-before, la prueba falla."""
        for c in ('/ip firewall filter add chain=input action=drop place-before=0',
                  '/ip firewall filter remove [find comment="IDS ids-maat:p003"]',
                  ':do {/ip firewall filter move [/ip firewall filter find comment="IDS ids-maat:p003"] '
                  'destination=[:pick [/ip firewall filter find dynamic=no] 0]} on-error={}'):
            with self.subTest(orden=c[:40]):
                with self.assertRaises(AssertionError):
                    aplicar_filter([], [c])

    def test_el_espejo_no_las_toma_por_suyas(self):
        """mikrotik_init (panel) retira del filter solo lo que reconoce como del espejo: con el
        comentario del alta, solo `chain=forward` que usa la lista del espejo. Las reglas nuevas
        no lo son: retirar o rehacer el espejo no abre ids-vpn."""
        sys.path.insert(0, str(LIB_PANEL))
        try:
            import mikrotik_init as mk
        finally:
            sys.path.remove(str(LIB_PANEL))
        for cmds in self.bloques().values():
            for r in aplicar_filter([], cmds):
                fila = {k: v.strip('"') for k, v in r.items()}
                self.assertFalse(mk.es_del_espejo(fila, "filter", "p003"), fila)


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
