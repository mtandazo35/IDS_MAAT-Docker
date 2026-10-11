"""Ayudante de las pruebas de pantallas (P) del dashboard: un panel de verdad sobre un directorio
temporal, con dos puntos que usan la MISMA IP privada (10.0.0.5) y un orquestador falso.

- estado.json con p001 «norte» y p002 «sur», los dos con 10.0.0.0/24.
- Usuarios: ana (admin), olga (operador), luis (lectura); clave "clave-de-prueba-1".
- Servidor HTTP del dashboard en 127.0.0.1 (puerto libre) y peticiones con http.client.
- Nada de red real: los routers (mk_add/mk_remove), el espejo y el orquestador son falsos y
  apuntan lo que se les pide.

Si el nucleo (N) aun no esta integrado, se ponen sustitutos con el contrato de N (`_set_ctx` con
nodo y 400/404, `cargar_routers` = un router por punto, `salud_punto`, `espejo_*`). Con N
integrado se usan los suyos (salvo los que hablarian con un router de verdad).
"""
import http.client
import importlib
import inspect
import json
import os
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import ThreadingHTTPServer

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
LIB = os.path.join(RAIZ, "images", "panel", "rootfs", "usr", "local", "lib", "ids-panel")
CLAVE = "clave-de-prueba-1"
USUARIOS = (("ana", "admin"), ("olga", "operador"), ("luis", "lectura"))


class OrqFalso:
    """Orquestador falso (transporte de idspanel/orq.py): apunta las ordenes y responde."""

    def __init__(self):
        self.pedidas = []
        self.lock = threading.Lock()
        self.ops = {}

    def ordenes(self, orden=None):
        return [p for p in self.pedidas if orden is None or p["orden"] == orden]

    def __call__(self, pet):
        with self.lock:
            self.pedidas.append(pet)
        o, prm = pet["orden"], pet.get("params") or {}
        if o == "op.estado":
            op = self.ops.get(prm.get("op_id"))
            if op is None:
                return {"op_id": pet["op_id"], "ok": False, "codigo": "NO_EXISTE", "mensaje": "no", "datos": {}}
            res = {"pid": "p003", "usuario": "ids-p003", "clave": "CLAVE-VPN-UNICA-7Q2",
                   "comandos": "# --- RouterOS v7\n/interface ovpn-client add name=ids-vpn\n"
                               "# --- RouterOS v6\n/interface ovpn-client add name=ids-vpn\n"} \
                if op == "punto.crear" else {"pid": prm.get("pid")}
            return {"op_id": pet["op_id"], "ok": True, "codigo": "OK", "mensaje": "",
                    "datos": {"estado": "terminada", "codigo": "OK", "mensaje": "hecho", "avance": "3/3",
                              "pasos": [{"nombre": "vpn", "estado": "ok"}], "resultado": res}}
        if o == "punto.comandos":
            return {"op_id": pet["op_id"], "ok": True, "codigo": "OK", "mensaje": "",
                    "datos": {"comandos": "# --- RouterOS v7\n/x <CLAVE-VPN>\n# --- RouterOS v6\n/y <CLAVE-VPN>\n"}}
        if o == "punto.api.huella":
            return {"op_id": pet["op_id"], "ok": True, "codigo": "OK", "mensaje": "", "datos": {"sha256": "ab" * 32}}
        if o == "punto.logs":
            return {"op_id": pet["op_id"], "ok": True, "codigo": "OK", "mensaje": "", "datos": {"lineas": ["linea 1"]}}
        self.ops[pet["op_id"]] = o
        return {"op_id": pet["op_id"], "ok": True, "codigo": "ACEPTADA", "mensaje": "en cola", "datos": {}}


class Resp:
    def __init__(self, status, cabeceras, texto):
        self.status, self.cabeceras, self.texto = status, cabeceras, texto

    def cab(self, nombre):
        for k, v in self.cabeceras:
            if k.lower() == nombre.lower():
                return v
        return None


def _es_de_n(dash):
    try:
        return "nodo" in inspect.getsource(dash.H._set_ctx)
    except (OSError, TypeError):
        return False


class PanelP:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        r = self.tmp.name
        for d in ("panel", "datos/p001", "datos/p002", "run/p001", "run/p002", "share/mapa", "sistema", "secretos"):
            os.makedirs(os.path.join(r, d), exist_ok=True)
        with open(os.path.join(r, "secretos", "master_key"), "w", encoding="ascii") as f:
            f.write("11" * 32)
        with open(os.path.join(r, "secretos", "orq_token"), "w", encoding="ascii") as f:
            f.write("token-de-prueba")
        self.escribir_estado()
        os.environ.update({"IDS_PANEL_DIR": os.path.join(r, "panel"), "IDS_DATOS": os.path.join(r, "datos"),
                           "IDS_RUN": os.path.join(r, "run"), "IDS_SHARE": os.path.join(r, "share"),
                           "IDS_MASTER_KEY": os.path.join(r, "secretos", "master_key"),
                           "IDS_ORQ_TOKEN": os.path.join(r, "secretos", "orq_token"),
                           "IDS_ORQ_SOCK": os.path.join(r, "secretos", "orq.sock")})
        if LIB not in sys.path:
            sys.path.insert(0, LIB)
        import nodos
        self.nodos = importlib.reload(nodos)
        self.nodos.asegurar_dirs()
        for m in ("dashboard", "puntos_web", "eventos_web"):
            sys.modules.pop(m, None)
        import dashboard
        self.d = dashboard
        self._redirigir_rutas()
        import puntos_web
        self.pw = puntos_web
        self.orq = OrqFalso()
        puntos_web.TRANSPORTE = self.orq
        puntos_web.ORQ_TOKEN = os.environ["IDS_ORQ_TOKEN"]
        puntos_web._OPS.clear()
        self.n_integrado = _es_de_n(dashboard)
        self.mk = []                       # (accion, ip, router_id)
        self.espejo = []                   # (accion, pid)
        self.plan = ["/ip firewall address-list add list=ids-vigilados address=10.0.0.0/24",
                     "/ip firewall mangle add chain=forward action=sniff-tzsp"]
        self._sustitutos()
        self._usuarios()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.H)
        self.srv.daemon_threads = True
        self.hilo = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.hilo.start()
        self.puerto = self.srv.server_address[1]

    # ---- datos --------------------------------------------------------------------------
    def escribir_estado(self, extra=None):
        pts = {"p001": {"nombre": "norte", "n": 1, "estado": "activo", "deseado": "activo",
                        "redes": ["10.0.0.0/24"], "api_puerto": 8729, "sensor": "100.64.1.1",
                        "mk": "100.64.1.2", "tzsp_puerto": 37008, "ros_version": 7, "perfil": "reducido"},
               "p002": {"nombre": "sur", "n": 2, "estado": "activo", "deseado": "activo",
                        "redes": ["10.0.0.0/24"], "api_puerto": 8729, "sensor": "100.64.2.1",
                        "mk": "100.64.2.2", "tzsp_puerto": 37008, "ros_version": 6, "perfil": "reducido"}}
        if extra:
            pts.update(extra)
        with open(os.path.join(self.tmp.name, "run", "estado.json"), "w", encoding="utf-8") as f:
            json.dump({"v": 1, "ts": int(time.time()), "puntos": pts,
                       "capacidad": {"caben": {"reducido": 3}}, "cola": {"pendientes": 0}}, f)

    def cuarentena(self, nodo, candidatos):
        d = os.path.join(self.tmp.name, "panel", "nodos", nodo)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "cuarentena.json"), "w", encoding="utf-8") as f:
            json.dump({"generado": int(time.time()), "ventana_min": 1440, "candidatos": candidatos,
                       "dns_candidatos": []}, f)

    @staticmethod
    def candidato(ip, pid, confianza="alta"):
        return {"ip": ip, "router": pid, "riesgo": 80, "banda": "ALTO", "confianza": confianza,
                "n_evidencias": 2, "firma": "ET MALWARE prueba", "alertas_cnc": 5, "firmas_cnc": 2,
                "destinos": 1, "puertos": 1, "total_alertas": 5, "evidencias": ["prueba"]}

    def _redirigir_rutas(self):
        """Las rutas viejas de /etc y /var del heredado (si quedan) van al directorio temporal."""
        base = os.path.join(self.tmp.name, "sistema")
        for k, v in list(vars(self.d).items()):
            if isinstance(v, str) and v.startswith(("/etc/", "/var/", "/root/", "/run/")) and k.isupper():
                setattr(self.d, k, os.path.join(base, k + "_" + os.path.basename(v.rstrip("/"))))

    def _sustitutos(self):
        d, nodos = self.d, self.nodos
        prueba = self
        if not self.n_integrado:
            def _set_ctx(h):
                s = h._sesion()
                d.CTX.user = s.get("user"); d.CTX.role = s.get("role"); d.CTX.ip = h._client_ip()
                d.CTX.peer = h._peer_ip(); d.CTX.exp = s.get("exp")
                q = urllib.parse.parse_qs(h.path.split("?", 1)[1]) if "?" in h.path else {}
                n = q.get("nodo", [None])[0]
                if n is None:
                    n = s.get("nodo") or nodos.TODOS
                nodos.poner_nodo(n)          # NodoInvalido / NodoInexistente
                if s:
                    s["nodo"] = n
            d.H._set_ctx = _set_ctx
            guardados = {}

            def cargar_routers():
                out = []
                for p in nodos.puntos():
                    r = {"id": p["pid"], "iface": p["pid"], "nombre": p["nombre"],
                         "HOST": "unix:" + os.path.join(nodos.RUN, p["pid"], "api.sock"), "PORT": "8729",
                         "TLS": "1", "USER": "ids-api", "PASS": "x", "ENABLED": "1", "CERT_FP": "",
                         "LIST": "suricata-cuarentena", "LIST_DNS": "suricata-dns-sospechoso"}
                    r.update(guardados.get(p["pid"], {}))
                    out.append(r)
                return out

            def guardar_routers(lst):
                for r in lst:
                    guardados[r["id"]] = {k: r[k] for k in ("USER", "PASS", "ENABLED", "CERT_FP") if k in r}
                return lst
            d.cargar_routers = cargar_routers
            d.guardar_routers = guardar_routers
            d.router_por_id = lambda rid: next((r for r in cargar_routers() if r["id"] == rid), None)
        if not hasattr(d, "salud_punto"):
            d.salud_punto = lambda pid: {"estado": "operativa", "etapas": [
                {"id": "vpn", "estado": "operativa"}, {"id": "tzsp", "estado": "operativa"}]}
        # lo que hablaria con un MikroTik de verdad: falso, y apunta
        d.cargar_mk_de = lambda r: dict(r or {})
        d.mk_listo = lambda m: True
        d.mk_add = lambda ip, comment="", lista=None, ttl=None, router=None: (
            prueba.mk.append(("add", ip, (router or {}).get("id"))) or (True, ""))
        d.mk_remove = lambda ip, lista=None, router=None: (
            prueba.mk.append(("remove", ip, (router or {}).get("id"))) or (True, "1 quitada"))
        d.notificar_cuarentena = lambda *a, **k: None
        d.enviar_telegram = lambda *a, **k: None
        d.espejo_plan = lambda pid: (prueba.espejo.append(("plan", pid))
                                     or {"ok": True, "mensaje": "plan", "lineas": list(prueba.plan)})
        for acc in ("aplicar", "pausar", "retirar"):
            d.__dict__["espejo_" + acc] = (lambda a: lambda pid: (prueba.espejo.append((a, pid))
                                                                  or {"ok": True, "mensaje": a + " hecho"}))(acc)

    def _usuarios(self):
        lst = []
        for u, rol in USUARIOS:
            salt, h = self.d._hash_pw(CLAVE)
            lst.append({"user": u, "salt": salt, "hash": h, "role": rol, "activo": True})
        self.d.guardar_usuarios(lst)

    # ---- HTTP ---------------------------------------------------------------------------
    def pedir(self, metodo, ruta, form=None, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.puerto, timeout=30)
        cab = {}
        cuerpo = None
        if form is not None:
            cuerpo = urllib.parse.urlencode(form, doseq=True)
            cab["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie:
            cab["Cookie"] = cookie
        c.request(metodo, ruta, body=cuerpo, headers=cab)
        r = c.getresponse()
        texto = r.read().decode("utf-8", "replace")
        c.close()
        return Resp(r.status, r.getheaders(), texto)

    def entrar(self, usuario):
        r = self.pedir("POST", "/login", {"usuario": usuario, "clave": CLAVE})
        sc = r.cab("Set-Cookie") or ""
        assert r.status in (302, 303) and sc, (r.status, r.texto[:200])
        return sc.split(";", 1)[0]

    def cerrar(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.nodos.quitar_nodo()
        self.tmp.cleanup()
