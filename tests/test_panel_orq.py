"""Panel: cliente del orquestador (protocolo del socket), traducción de errores, comandos,
configuración por entorno y `ids-panel salud`."""

import contextlib
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures" / "panel"))
import _ayuda_panel as A  # noqa: E402
from idspanel import cli, orq  # noqa: E402
from idspanel.app import validar_formulario_punto  # noqa: E402
from idspanel.config import Config, ErrorConfig  # noqa: E402

LINUX = sys.platform.startswith("linux")


class Cliente(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="ids-orqc-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        self.token = self.d / "orq_token"
        self.token.write_text(A.TOKEN + "\n", encoding="utf-8")

    def test_peticion_con_el_formato_del_protocolo(self):
        vistas = []

        def transporte(pet):
            vistas.append(pet)
            return {"op_id": pet["op_id"], "ok": True, "codigo": "OK", "mensaje": "ok", "datos": {"x": 1}}
        c = orq.ClienteOrq(str(self.d / "orq.sock"), str(self.token), transporte, reloj=lambda: 1760090000)
        r = c.pedir("sistema.estado", {}, quien="panel:admin", ip="203.0.113.20", op_id="0" * 8 + "-abc")
        self.assertEqual(r["codigo"], "OK")
        self.assertEqual(vistas[0], {"v": 1, "op_id": "00000000-abc", "token": A.TOKEN, "orden": "sistema.estado",
                                     "params": {}, "quien": "panel:admin", "ip": "203.0.113.20", "ts": 1760090000})
        c.pedir("sistema.estado", {})
        self.assertRegex(vistas[1]["op_id"], r"^[0-9a-f-]{36}$")                    # uuid4 si no se da

    def test_sin_token_y_sin_servicio(self):
        c = orq.ClienteOrq(str(self.d / "no-existe.sock"), str(self.d / "no-existe"))
        self.assertEqual(c.pedir("sistema.estado", {})["codigo"], orq.SIN_TOKEN)
        c = orq.ClienteOrq(str(self.d / "no-existe.sock"), str(self.token))
        r = c.pedir("sistema.estado", {})
        self.assertEqual(r["codigo"], orq.SIN_SERVICIO)
        self.assertFalse(r["ok"])
        self.assertIn("ids-orq", orq.traducir(r["codigo"], r["mensaje"]))

        def roto(pet):
            return "no es un dict"
        self.assertEqual(orq.ClienteOrq("x", str(self.token), roto).pedir("x", {})["codigo"], orq.SIN_SERVICIO)

    @unittest.skipUnless(LINUX, "AF_UNIX: solo Linux")
    def test_socket_unix_una_peticion_por_conexion(self):
        ruta = str(self.d / "orq.sock")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(ruta)
        s.listen(4)
        recibidas = []

        def servidor():
            for _ in range(2):
                conn, _a = s.accept()
                buf = b""
                while b"\n" not in buf:
                    trozo = conn.recv(4096)
                    if not trozo:
                        break
                    buf += trozo
                pet = json.loads(buf.split(b"\n", 1)[0])
                recibidas.append((pet, buf.count(b"\n")))
                resp = {"op_id": pet["op_id"], "ok": True, "codigo": "OK", "mensaje": "ok",
                        "datos": {"comandos": "á" * 70000}}                     # respuesta larga y UTF-8
                conn.sendall((json.dumps(resp, ensure_ascii=False) + "\n").encode())
                conn.close()
        h = threading.Thread(target=servidor, daemon=True)
        h.start()
        c = orq.ClienteOrq(ruta, str(self.token))
        for _ in range(2):
            r = c.pedir("punto.comandos", {"pid": "p003"}, quien="panel:admin")
            self.assertEqual(r["codigo"], "OK")
            self.assertEqual(len(r["datos"]["comandos"]), 70000)
        h.join(5)
        s.close()
        self.assertEqual([n for _p, n in recibidas], [1, 1])                    # una línea por conexión
        self.assertEqual(recibidas[0][0]["token"], A.TOKEN)


class Traducir(unittest.TestCase):
    def test_mensajes(self):
        self.assertIn("Los datos no son válidos: nombre inválido", orq.traducir("INVALIDO", "nombre inválido"))
        t = orq.traducir("CONFLICTO", "no cabe", {"caben": {"reducido": 2}})
        self.assertIn("No se puede hacer ahora", t)
        self.assertIn("reducido 2", t)
        self.assertIn("puerto", orq.traducir("CONFLICTO_PUERTO", "el puerto 1196/tcp está ocupado"))
        self.assertIn("ya no existe", orq.traducir("NO_EXISTE", "no existe p003"))
        self.assertIn("se deshizo", orq.traducir("REVERTIDA", "falló «compose up»"))
        self.assertIn("token", orq.traducir("INVALIDO", "token inválido"))
        self.assertIn("no pudo completar", orq.traducir("FALLO", "error interno"))


class Comandos(unittest.TestCase):
    def test_partir_los_comandos_reales(self):
        o = A.cargar_orq()
        p = {"pid": "p003", "nombre": "norte", "n": 3, "puerto": 1196, "tun_net": "100.64.3.0/24",
             "sensor": "100.64.3.1", "ros_version": 7, "api_puerto": 8729, "usuario": "vpn3a9f2c"}
        for ros in (6, 7):
            txt = o.comandos_mikrotik(dict(p, ros_version=ros), A.DNS, "ClaveDePrueba123456789AB")
            partes = orq.partir_comandos(txt)
            self.assertEqual(set(partes), {"cabecera", "certificado", "v7", "v6"})
            self.assertIn("/interface ovpn-client add", partes["v7"])
            self.assertIn("protocol=tcp", partes["v7"])
            self.assertIn("/interface ovpn-client add", partes["v6"])
            self.assertNotIn("RouterOS v7", partes["v6"])
            self.assertIn("/certificate sign ids-promax", partes["certificado"])
            self.assertIn("password=ClaveDePrueba123456789AB", partes["v6"])
            # nada se pierde al partir
            juntos = "\n".join(partes[k] for k in ("cabecera", "certificado", "v7", "v6"))
            for linea in txt.splitlines():
                if linea.strip("# ").strip():
                    self.assertIn(linea, juntos)
        self.assertEqual(orq.partir_comandos("otra cosa"), {"todo": "otra cosa"})


class FormularioContraOrquestador(unittest.TestCase):
    """Lo que el panel acepta en el formulario lo acepta también el validar_crear real."""

    def test_contrato(self):
        o = A.cargar_orq()
        buenos = [{"nombre": "norte", "redes": "10.0.0.0/24"},
                  {"nombre": "a1", "redes": "10.0.0.0/24, 172.16.5.0/24\n10.9.0.0/16", "ros_version": "6",
                   "perfil": "completo"},
                  {"nombre": "sur-2", "redes": "10.0.0.7/24"}]
        for f in buenos:
            params, err = validar_formulario_punto(f)
            self.assertEqual(err, "", f)
            ref = o.validar_crear(params, A.CfgOrq)
            for k, v in params.items():
                self.assertEqual(ref[k], v, (f, k))
        self.assertEqual(validar_formulario_punto({"nombre": "sur-2", "redes": "10.0.0.7/24"})[0]["redes_abonados"],
                         ["10.0.0.0/24"])
        for f in ({"nombre": "-x", "redes": "10.0.0.0/24"}, {"nombre": "x", "redes": "10.0.0.0/24"},
                  {"nombre": "a" * 32, "redes": "10.0.0.0/24"}, {"nombre": "ok", "redes": "10.0.0.0/8 " * 65}):
            self.assertIsNone(validar_formulario_punto(f)[0], f)


class Configuracion(unittest.TestCase):
    def test_defectos(self):
        c = Config.desde_entorno({})
        self.assertEqual((c.puerto, c.escucha, c.tz, c.proxies), (5637, "0.0.0.0", "UTC", []))
        self.assertEqual(str(c.usuarios_json).replace("\\", "/"), "/srv/ids/panel/usuarios.json")
        self.assertEqual(str(c.estado_json).replace("\\", "/"), "/srv/ids/run/estado.json")
        self.assertEqual(c.orq_sock, "/run/ids-orq/orq.sock")
        self.assertEqual(c.orq_token, "/run/secrets/orq_token")

    def test_entorno(self):
        c = Config.desde_entorno({"IDS_PROXY": "203.0.113.50, 198.51.100.0/28", "IDS_PUERTO": "8080",
                                  "IDS_EMPRESA": "Empresa", "IDS_TZ": "America/Guayaquil"})
        self.assertEqual([str(x) for x in c.proxies], ["203.0.113.50/32", "198.51.100.0/28"])
        self.assertEqual((c.puerto, c.empresa, c.tz), (8080, "Empresa", "America/Guayaquil"))
        for malo in ({"IDS_PROXY": "proxy.example"}, {"IDS_PUERTO": "x"}, {"IDS_PUERTO": "70000"}):
            with self.assertRaises(ErrorConfig):
                Config.desde_entorno(malo)

    def test_zona_desconocida_cae_a_utc(self):
        from idspanel.util import fecha
        self.assertEqual(fecha(0, "Zona/Inexistente"), "1970-01-01 00:00:00")


class Salud(unittest.TestCase):
    def test_salud(self):
        p = A.PanelPrueba()
        try:
            self.assertEqual(cli.salud(Config(puerto=p.puerto)), 0)
        finally:
            p.cerrar()
        self.assertEqual(cli.salud(Config(puerto=p.puerto), timeout=2), 1)

    def test_ejecutable_servir_y_salud(self):
        import subprocess
        import time
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        puerto = s.getsockname()[1]
        s.close()
        d = Path(tempfile.mkdtemp(prefix="ids-panel-s-"))
        self.addCleanup(shutil.rmtree, d, True)
        env = dict(os.environ, IDS_PANEL_DIR=str(d / "panel"), IDS_RUN=str(d / "run"), IDS_DATOS=str(d / "datos"),
                   IDS_PUERTO=str(puerto), IDS_ESCUCHA="127.0.0.1", IDS_ORQ_SOCK=str(d / "no.sock"),
                   IDS_ORQ_TOKEN=str(d / "no-token"), IDS_PROXY="203.0.113.50")
        salud = [sys.executable, str(A.SCRIPT), "salud"]
        self.assertEqual(subprocess.run(salud, env=env, capture_output=True, timeout=30).returncode, 1)
        proc = subprocess.Popen([sys.executable, str(A.SCRIPT)], env=env, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True)          # sin orden = servir
        try:
            fin = time.monotonic() + 20
            rc = 1
            while time.monotonic() < fin and rc != 0:
                rc = subprocess.run(salud, env=env, capture_output=True, timeout=30).returncode
                if rc != 0:
                    time.sleep(0.2)
            self.assertEqual(rc, 0)
        finally:
            proc.terminate()
            _out, err = proc.communicate(timeout=20)
        self.assertIn("no hay usuarios", err)          # arranca sin usuarios ni orquestador, y lo avisa

    def test_main_sin_argumentos_es_servir_y_config_mala_sale_2(self):
        viejo = os.environ.get("IDS_PUERTO")
        os.environ["IDS_PUERTO"] = "no-numero"
        try:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(cli.main([]), 2)
            self.assertIn("IDS_PUERTO", err.getvalue())
        finally:
            if viejo is None:
                os.environ.pop("IDS_PUERTO", None)
            else:
                os.environ["IDS_PUERTO"] = viejo


if __name__ == "__main__":
    unittest.main()
