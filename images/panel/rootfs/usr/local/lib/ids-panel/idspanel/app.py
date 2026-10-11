"""Servidor HTTP del panel (detrás del proxy inverso; el TLS lo termina el proxy).

Rutas:
  GET  /salud                          200 sin sesión (healthcheck)
  GET  /static/<fichero>               CSS y JS
  GET  /entrar   POST /entrar          login (freno por IP real y por usuario)
  POST /salir                          cerrar sesión
  GET  /puntos   GET /puntos/tabla     pantalla Puntos (la tabla se refresca sola)
  GET  /puntos/nuevo   POST /puntos/nuevo
  GET  /puntos/<pid>                   ficha (?ip= filtra las alertas)
  POST /puntos/<pid>/borrar            exige confirmar = nombre del punto
  POST /puntos/<pid>/regenerar         punto.vpn.regenerar
  GET  /operaciones/<op_id>[/fragmento]
  GET  /alertas                        ?punto=&ip=
  GET  /documentacion
  GET  /cuenta/clave   POST /cuenta/clave

Todo POST pasa por la comprobación de origen (CSRF) y, con sesión, por el token CSRF de la sesión.
"""

import ipaddress
import os
import re
import sys
import time
import traceback
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import vistas
from .bitacora import Bitacora
from .estado import LectorEstado, pid_valido
from .eve import Contador24h, alertas_empresa, ultimas_alertas
from .operaciones import RE_OPID, Operaciones
from .orq import SIN_SERVICIO, SIN_TOKEN, ClienteOrq, traducir
from .red import Origen, origen_ajeno
from .sesiones import Freno, Sesiones, token_csrf
from .usuarios import MAX_CLAVE, ClaveNoValida, Usuarios

MAX_CUERPO = 64 * 1024
COOKIE_SEGURA = "__Host-ids_s"
COOKIE_LOCAL = "ids_s"
DIR_STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
STATIC = {"panel.css": "text/css; charset=utf-8", "panel.js": "text/javascript; charset=utf-8",
          "tema.js": "text/javascript; charset=utf-8"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
RE_NOMBRE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}$")
PERFILES = ("reducido", "completo")
MAX_REDES = 64
MSG_LOGIN = "Usuario o clave incorrectos."
MSG_FRENO = "Demasiados intentos fallidos. Espera unos minutos y vuelve a intentarlo."


def validar_ip(txt):
    txt = (txt or "").strip()
    if not txt:
        return None, ""
    try:
        return str(ipaddress.ip_address(txt)), ""
    except ValueError:
        return None, "«%s» no es una dirección IP." % txt[:45]


def validar_formulario_punto(f):
    """(params para punto.crear, mensaje de error). Mismos nombres y tipos que valida ids_orq.py."""
    nombre = (f.get("nombre") or "").strip()
    if not RE_NOMBRE.match(nombre):
        return None, ("El nombre solo admite minúsculas, números y guiones, de 2 a 31 caracteres, "
                      "empezando por letra o número (p. ej. norte).")
    trozos = [x.strip() for x in re.split(r"[\s,;]+", f.get("redes") or "") if x.strip()]
    if not trozos:
        return None, "Escribe al menos una red de abonados (p. ej. 10.0.0.0/24)."
    if len(trozos) > MAX_REDES:
        return None, "Como mucho %d redes de abonados por punto." % MAX_REDES
    redes = []
    for r in trozos:
        try:
            net = ipaddress.IPv4Network(r, strict=False)
        except ValueError:
            return None, "«%s» no es una red IPv4 válida (ejemplo: 10.0.0.0/24)." % r[:45]
        if net.prefixlen == 0:
            return None, "0.0.0.0/0 no es una red de abonados."
        if str(net) not in redes:
            redes.append(str(net))
    ros = (f.get("ros_version") or "7").strip()
    if ros not in ("6", "7"):
        return None, "La versión de RouterOS tiene que ser 6 o 7."
    perfil = (f.get("perfil") or "reducido").strip()
    if perfil not in PERFILES:
        return None, "El perfil tiene que ser reducido o completo."
    return {"nombre": nombre, "redes_abonados": redes, "perfil": perfil, "ros_version": int(ros)}, ""


def _porcentaje(avance):
    try:
        hechos, total = str(avance).split("/")
        return max(0, min(100, int(100 * int(hechos) / int(total))))
    except (ValueError, ZeroDivisionError):
        return 0


class Panel:
    """Estado compartido del panel (lo que no es de una petición)."""

    def __init__(self, cfg, transporte=None, reloj=time.time):
        self.cfg = cfg
        self.reloj = reloj
        os.makedirs(str(cfg.panel_dir), exist_ok=True)
        self.usuarios = Usuarios(str(cfg.usuarios_json), reloj)
        self.sesiones = Sesiones(str(cfg.sesiones_json), reloj)
        self.freno = Freno(reloj=reloj)
        self.orq = ClienteOrq(cfg.orq_sock, cfg.orq_token, transporte, reloj)
        self.estado = LectorEstado(cfg.run_dir, reloj)
        self.contador = Contador24h(cfg.datos_dir, reloj)
        self.bitacora = Bitacora(str(cfg.bitacora_jsonl), reloj)
        self.ops = Operaciones(str(cfg.operaciones_json), reloj)
        self._static = {}

    def static(self, nombre):
        if nombre not in STATIC:
            return None
        if nombre not in self._static:
            with open(os.path.join(DIR_STATIC, nombre), "rb") as f:
                self._static[nombre] = f.read()
        return self._static[nombre]

    def precalentar(self):
        try:
            self.tabla_puntos()
        except Exception as e:  # noqa: BLE001 - solo es una caché
            sys.stderr.write("ids-panel: precalentar: %r\n" % e)

    # ---- modelo de la pantalla Puntos ---------------------------------------------------------
    def tabla_puntos(self):
        t = self.reloj()
        filas = []
        emp = {"puntos": 0, "activos": 0, "vpn_sana": 0, "conectados": 0, "con_espejo": 0,
               "suricata_sana": 0, "alertas": 0, "completo": True}
        for pid, p in self.estado.puntos():
            ultimo = self.estado.ultimo_espejo(pid)
            n24 = self.contador.contar(pid)
            filas.append((pid, p, ultimo, n24))
            cont = p.get("contenedores") or {}
            emp["puntos"] += 1
            emp["activos"] += p.get("estado") == "activo"
            emp["vpn_sana"] += (cont.get("vpn") or {}).get("salud") == "healthy"
            emp["suricata_sana"] += (cont.get("suricata") or {}).get("salud") == "healthy"
            emp["conectados"] += bool((p.get("vpn_cliente") or {}).get("conectado"))
            emp["con_espejo"] += bool(ultimo and t - ultimo < 600)
            emp["alertas"] += n24[0]
            emp["completo"] = emp["completo"] and n24[1]
        return vistas.tabla_puntos(filas, emp, self.estado.edad(), t, self.cfg.tz)

    # ---- operaciones --------------------------------------------------------------------------
    def vista_op(self, op_id, usuario, ip):
        """Modelo de la página de una operación. None si no existe o no es de este usuario."""
        rec = self.ops.obtener(op_id)
        if rec is None or rec.get("usuario") != usuario:
            return None
        vm = {"orden": rec.get("orden"), "pid": rec.get("pid"), "titulo_punto": rec.get("nombre") or rec.get("pid"),
              "ros_version": rec.get("ros_version")}
        if rec.get("terminada"):
            vm.update({"terminada": True, "ok": rec.get("codigo") == "OK", "pasos": rec.get("pasos"),
                       "mensaje_claro": traducir(rec.get("codigo"), rec.get("mensaje")),
                       "ya_existia": rec.get("ya_existia")})
            return vm
        r = self.orq.pedir("op.estado", {"op_id": op_id}, quien="panel:%s" % usuario, ip=ip)
        if r.get("codigo") in (SIN_SERVICIO, SIN_TOKEN) or (r.get("codigo") != "OK" and r.get("codigo") != "NO_EXISTE"):
            vm.update({"terminada": False, "error_canal": traducir(r.get("codigo"), r.get("mensaje"))})
            return vm
        if r.get("codigo") == "NO_EXISTE":
            self.ops.terminar(op_id, codigo="FALLO", mensaje="el orquestador no conoce esta operación")
            vm.update({"terminada": True, "ok": False,
                       "mensaje_claro": "El orquestador no conoce esta operación (¿se reinició el servidor?). "
                                        "Mira el estado en Puntos antes de repetirla."})
            return vm
        d = r.get("datos") or {}
        pasos = [p for p in (d.get("pasos") or []) if isinstance(p, dict)]
        total = (str(d.get("avance") or "?/?").split("/") + ["?"])[1]
        vm.update({"pasos": pasos, "total": total, "paso": d.get("paso"), "avance": d.get("avance"),
                   "porcentaje": _porcentaje(d.get("avance")), "delante": d.get("delante")})
        if d.get("estado") != "terminada":
            vm["terminada"] = False
            return vm
        codigo, mensaje = d.get("codigo") or "FALLO", d.get("mensaje") or ""
        res = d.get("resultado") if isinstance(d.get("resultado"), dict) else {}
        pid = res.get("pid") or rec.get("pid")
        ya = bool(res.get("ya_entregada"))
        pasos_limpios = [{k: p.get(k) for k in ("nombre", "estado", "detalle") if p.get(k) is not None}
                         for p in pasos]
        if self.ops.terminar(op_id, codigo=codigo, mensaje=mensaje, pid=pid, pasos=pasos_limpios,
                             ya_existia=ya, total=total):
            self.bitacora.registrar(rec.get("orden") + ".fin", usuario, ip, punto=pid, resultado=codigo,
                                    detalle={"op_id": op_id})
        vm.update({"terminada": True, "ok": codigo == "OK", "pid": pid, "resultado": res, "ya_existia": ya,
                   "mensaje_claro": traducir(codigo, mensaje, res)})
        return vm


class Manejador(BaseHTTPRequestHandler):
    server_version = "ids-panel"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30

    # ---- utilidades de respuesta --------------------------------------------------------------
    @property
    def panel(self):
        return self.server.panel

    def log_message(self, formato, *args):
        if getattr(self.server, "silencioso", False):
            return
        try:
            sys.stderr.write("ids-panel: %s %s\n" % (getattr(self, "_ip", "-"), formato % args))
        except Exception:  # noqa: BLE001
            pass

    def _enviar(self, codigo, cuerpo, tipo="text/html; charset=utf-8", extra=(), cache="no-store"):
        if isinstance(cuerpo, str):
            cuerpo = cuerpo.encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Cache-Control", cache)
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(cuerpo)

    def _redirigir(self, destino, extra=()):
        self._enviar(303, b"", extra=[("Location", destino)] + list(extra))

    def _error(self, codigo, titulo, texto):
        self._enviar(codigo, vistas.error_pagina(codigo, titulo, texto))

    # ---- sesión y origen ----------------------------------------------------------------------
    def _cookies(self):
        out = {}
        for trozo in (self.headers.get("Cookie") or "").split(";"):
            k, _s, v = trozo.strip().partition("=")
            if k and k not in out:
                out[k] = v.strip()
        return out

    def _token(self):
        c = self._cookies()
        return c.get(COOKIE_SEGURA) or c.get(COOKIE_LOCAL) or ""

    def _cookie_sesion(self, token):
        if self.origen.https:
            return "%s=%s; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict; Secure" % (COOKIE_SEGURA, token)
        return "%s=%s; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict" % (COOKIE_LOCAL, token)

    def _borrar_cookies(self):
        return [("Set-Cookie", "%s=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Secure" % COOKIE_SEGURA),
                ("Set-Cookie", "%s=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict" % COOKIE_LOCAL)]

    def _ctx(self):
        s = self.sesion or {}
        return {"usuario": s.get("usuario"), "csrf": token_csrf(self._token_actual) if s else "",
                "empresa": self.panel.cfg.empresa, "clave_temporal": s.get("clave_temporal")}

    def _preparar(self):
        self.origen = Origen(self.headers, self.client_address[0], self.panel.cfg.proxies)
        self._ip = self.origen.ip
        token = self._token_actual = self._token()
        self.sesion = self.panel.sesiones.validar(token, self.panel.usuarios) if token else None
        partes = urllib.parse.urlsplit(self.path)
        self.ruta = partes.path
        self.query = {k: v[0] for k, v in urllib.parse.parse_qs(partes.query, keep_blank_values=True).items()}

    def _form(self):
        try:
            largo = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            largo = -1
        if largo < 0 or largo > MAX_CUERPO:
            return None
        datos = self.rfile.read(largo) if largo else b""
        tipo = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if tipo not in ("application/x-www-form-urlencoded", ""):
            return None
        try:
            q = urllib.parse.parse_qs(datos.decode("utf-8"), keep_blank_values=True, max_num_fields=50)
        except (UnicodeDecodeError, ValueError):
            return None
        return {k: v[0] for k, v in q.items()}

    def _quien(self):
        return "panel:%s" % ((self.sesion or {}).get("usuario") or "-")

    def _bit(self, accion, punto=None, resultado="ok", detalle=None, usuario=None):
        self.panel.bitacora.registrar(accion, usuario or (self.sesion or {}).get("usuario"), self._ip,
                                      punto=punto, resultado=resultado, detalle=detalle)

    # ---- entrada ------------------------------------------------------------------------------
    def do_GET(self):
        self._seguro(self._get)

    def do_HEAD(self):
        self._seguro(self._get)

    def do_POST(self):
        self._seguro(self._post)

    def _seguro(self, fn):
        try:
            self._preparar()
            fn()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            raise
        except Exception:  # noqa: BLE001 - una página rota no tumba el panel
            try:
                sys.stderr.write("ids-panel: ERROR en %s %s\n%s" % (self.command, self.path.split("?", 1)[0],
                                                                    traceback.format_exc()))
            except Exception:  # noqa: BLE001
                pass
            try:
                self._error(500, "Error del panel", "Esta página falló. El resto del panel sigue funcionando; "
                            "el detalle queda en el registro del contenedor del panel.")
            except Exception:  # noqa: BLE001
                self.close_connection = True

    # ---- GET ----------------------------------------------------------------------------------
    def _get(self):
        r = self.ruta
        if r == "/salud":
            return self._enviar(200, b"ok\n", "text/plain; charset=utf-8")
        if r.startswith("/static/"):
            datos = self.panel.static(r[len("/static/"):])
            if datos is None:
                return self._enviar(404, b"no existe\n", "text/plain; charset=utf-8")
            return self._enviar(200, datos, STATIC[r[len("/static/"):]], cache="no-cache")
        if r in ("/entrar", "/login"):
            if self.sesion:
                return self._redirigir("/puntos")
            return self._enviar(200, vistas.entrar(empresa=self.panel.cfg.empresa))
        if not self.sesion:
            if r.endswith("/fragmento") or r == "/puntos/tabla":
                return self._enviar(401, b"sesion caducada\n", "text/plain; charset=utf-8")
            return self._redirigir("/entrar")
        if r == "/":
            return self._redirigir("/puntos")
        if r == "/puntos":
            return self._enviar(200, vistas.puntos(self._ctx(), self.panel.tabla_puntos(), self.panel.estado.estado()))
        if r == "/puntos/tabla":
            return self._enviar(200, self.panel.tabla_puntos())
        if r == "/puntos/nuevo":
            caben = ((self.panel.estado.estado() or {}).get("capacidad") or {}).get("caben")
            return self._enviar(200, vistas.nuevo_punto(self._ctx(), caben=caben))
        m = re.match(r"^/puntos/(p\d{3})$", r)
        if m:
            return self._ficha(m.group(1))
        m = re.match(r"^/operaciones/([0-9a-f-]{36})(/fragmento)?$", r)
        if m and RE_OPID.match(m.group(1)):
            vm = self.panel.vista_op(m.group(1), self.sesion["usuario"], self._ip)
            if vm is None:
                return self._error(404, "Operación desconocida", "Esa operación no existe o no la pediste tú.")
            if m.group(2):
                return self._enviar(200, vistas.op_cuerpo(vm))
            return self._enviar(200, vistas.operacion(self._ctx(), m.group(1), vm))
        if r == "/alertas":
            return self._alertas()
        if r == "/documentacion":
            return self._enviar(200, vistas.documentacion(self._ctx()))
        if r == "/cuenta/clave":
            return self._enviar(200, vistas.cambiar_clave(self._ctx()))
        return self._error(404, "No existe", "Esa página no existe.")

    def _ficha(self, pid, mensaje="", codigo=200):
        p = self.panel.estado.punto(pid)
        r = self.panel.orq.pedir("punto.comandos", {"pid": pid}, quien=self._quien(), ip=self._ip)
        if r.get("codigo") == "NO_EXISTE" and p is None:
            return self._error(404, "Ese punto no existe", "No hay ningún punto %s (quizá se borró)." % pid)
        cmds = (r.get("datos") or {}).get("comandos") if r.get("codigo") == "OK" else None
        cmds_err = "" if cmds else ("No se pudieron obtener los comandos: %s"
                                    % traducir(r.get("codigo"), r.get("mensaje")))
        ip, ip_err = validar_ip(self.query.get("ip"))
        alertas = [] if ip_err else ultimas_alertas(self.panel.cfg.datos_dir, pid, limite=100, ip=ip)
        t = self.panel.reloj()
        html_ = vistas.ficha(self._ctx(), pid, p, self.panel.estado.ultimo_espejo(pid), self.panel.contador.contar(pid),
                             cmds, cmds_err, alertas, ip, ip_err, t, self.panel.cfg.tz, mensaje=mensaje)
        return self._enviar(codigo, html_)

    def _alertas(self):
        puntos = self.panel.estado.puntos()
        pids = [pid for pid, _p in puntos]
        sel = self.query.get("punto") or ""
        if sel and sel not in pids:
            sel = sel if pid_valido(sel) and os.path.isdir(os.path.join(str(self.panel.cfg.datos_dir), sel)) else ""
        ip, ip_err = validar_ip(self.query.get("ip"))
        alertas = [] if ip_err else alertas_empresa(self.panel.cfg.datos_dir, [sel] if sel else pids, limite=200, ip=ip)
        return self._enviar(200, vistas.alertas(self._ctx(), alertas, puntos, sel, ip, ip_err, self.panel.cfg.tz))

    # ---- POST ---------------------------------------------------------------------------------
    def _post(self):
        motivo = origen_ajeno(self.headers, self.origen.hosts())
        if motivo:
            self._bit("csrf.rechazado", resultado="rechazado", detalle={"ruta": self.ruta, "motivo": motivo[:120]})
            return self._error(403, "Petición rechazada", "La petición no viene de este panel.")
        form = self._form()
        if form is None:
            self.close_connection = True          # puede quedar cuerpo sin leer en la conexión
            return self._error(400, "Petición no válida", "El formulario no es válido o es demasiado grande.")
        if self.ruta in ("/entrar", "/login"):
            return self._entrar(form)
        if not self.sesion:
            return self._redirigir("/entrar")
        if not form.get("csrf") or form.get("csrf") != token_csrf(self._token()):
            self._bit("csrf.rechazado", resultado="rechazado", detalle={"ruta": self.ruta, "motivo": "token"})
            return self._error(403, "Petición rechazada", "El formulario caducó. Vuelve atrás, recarga la página "
                               "y repite.")
        if self.ruta == "/salir":
            self.panel.sesiones.borrar(self._token())
            self._bit("sesion.salir")
            return self._redirigir("/entrar", extra=self._borrar_cookies())
        if self.ruta == "/cuenta/clave":
            return self._cambiar_clave(form)
        if self.ruta == "/puntos/nuevo":
            return self._crear(form)
        m = re.match(r"^/puntos/(p\d{3})/(borrar|regenerar)$", self.ruta)
        if m:
            return self._borrar(m.group(1), form) if m.group(2) == "borrar" else self._regenerar(m.group(1))
        return self._error(404, "No existe", "Esa acción no existe.")

    def _entrar(self, form):
        usuario = (form.get("usuario") or "").strip()[:64]
        clave = form.get("clave") or ""
        claves = ["ip:" + self._ip]
        if usuario:
            claves.append("u:" + usuario.lower())
        if self.panel.freno.bloqueado(*claves):
            self._bit("sesion.entrar", resultado="frenado", usuario=usuario[:32] or "-")
            return self._enviar(429, vistas.entrar(MSG_FRENO, usuario, self.panel.cfg.empresa),
                                extra=[("Retry-After", "600")])
        reg = self.panel.usuarios.autenticar(usuario, clave) if len(clave) <= MAX_CLAVE else None
        if reg is None:
            self.panel.freno.fallo(*claves)
            self._bit("sesion.entrar", resultado="fallo", usuario=usuario[:32] or "-")
            return self._enviar(401, vistas.entrar(MSG_LOGIN, usuario, self.panel.cfg.empresa))
        self.panel.freno.limpiar(*claves)
        viejo = self._token()
        if viejo:
            self.panel.sesiones.borrar(viejo)
        token = self.panel.sesiones.crear(usuario, reg.get("sello"), self._ip)
        self._bit("sesion.entrar", usuario=usuario)
        return self._redirigir("/puntos", extra=[("Set-Cookie", self._cookie_sesion(token))])

    def _cambiar_clave(self, form):
        usuario = self.sesion["usuario"]
        if (form.get("nueva") or "") != (form.get("repetir") or ""):
            return self._enviar(400, vistas.cambiar_clave(self._ctx(), "Las dos claves nuevas no coinciden."))
        try:
            sello = self.panel.usuarios.cambiar(usuario, form.get("actual") or "", form.get("nueva") or "")
        except ClaveNoValida as e:
            self._bit("cuenta.clave", resultado="rechazado")
            return self._enviar(400, vistas.cambiar_clave(self._ctx(), str(e).capitalize() + "."))
        self.panel.sesiones.borrar_usuario(usuario)
        token = self.panel.sesiones.crear(usuario, sello, self._ip)
        self._bit("cuenta.clave")
        self.sesion = self.panel.sesiones.validar(token, self.panel.usuarios)
        self._token_actual = token
        return self._enviar(200, vistas.cambiar_clave(self._ctx(), ok="Clave cambiada. Tus otras sesiones se cerraron."),
                            extra=[("Set-Cookie", self._cookie_sesion(token))])

    def _crear(self, form):
        caben = ((self.panel.estado.estado() or {}).get("capacidad") or {}).get("caben")
        params, err = validar_formulario_punto(form)
        if err:
            return self._enviar(400, vistas.nuevo_punto(self._ctx(), form, err, caben))
        op_id = str(uuid.uuid4())
        usuario = self.sesion["usuario"]
        self.panel.ops.registrar(op_id, usuario, "punto.crear", nombre=params["nombre"],
                                 ros_version=params["ros_version"])
        r = self.panel.orq.pedir("punto.crear", params, quien=self._quien(), ip=self._ip, op_id=op_id)
        det = {"nombre": params["nombre"], "redes": len(params["redes_abonados"]), "perfil": params["perfil"],
               "ros_version": params["ros_version"], "op_id": op_id}
        if r.get("codigo") in ("ACEPTADA", "OK"):
            self._bit("punto.crear", resultado=r.get("codigo"), detalle=det)
            return self._redirigir("/operaciones/%s" % op_id)
        self.panel.ops.quitar(op_id)
        self._bit("punto.crear", resultado=r.get("codigo"), detalle=det)
        codigo = 503 if r.get("codigo") in (SIN_SERVICIO, SIN_TOKEN) else (409 if "CONFLICTO" in str(r.get("codigo")) else 400)
        return self._enviar(codigo, vistas.nuevo_punto(self._ctx(), form, traducir(r.get("codigo"), r.get("mensaje"),
                                                                                    r.get("datos")), caben))

    def _borrar(self, pid, form):
        confirmar = (form.get("confirmar") or "").strip()
        p = self.panel.estado.punto(pid)
        if not confirmar or (p is not None and confirmar != p.get("nombre")):
            self._bit("punto.borrar", punto=pid, resultado="nombre-no-coincide")
            return self._ficha(pid, "Para borrar hay que escribir exactamente el nombre del punto.", 400)
        op_id = str(uuid.uuid4())
        self.panel.ops.registrar(op_id, self.sesion["usuario"], "punto.borrar", pid=pid,
                                 nombre=(p or {}).get("nombre") or confirmar)
        r = self.panel.orq.pedir("punto.borrar", {"pid": pid, "confirmar": confirmar}, quien=self._quien(),
                                 ip=self._ip, op_id=op_id)
        self._bit("punto.borrar", punto=pid, resultado=r.get("codigo"), detalle={"op_id": op_id})
        if r.get("codigo") in ("ACEPTADA", "OK"):
            return self._redirigir("/operaciones/%s" % op_id)
        self.panel.ops.quitar(op_id)
        return self._ficha(pid, traducir(r.get("codigo"), r.get("mensaje"), r.get("datos")), 409)

    def _regenerar(self, pid):
        p = self.panel.estado.punto(pid)
        op_id = str(uuid.uuid4())
        self.panel.ops.registrar(op_id, self.sesion["usuario"], "punto.vpn.regenerar", pid=pid,
                                 nombre=(p or {}).get("nombre") or pid, ros_version=(p or {}).get("ros_version"))
        r = self.panel.orq.pedir("punto.vpn.regenerar", {"pid": pid}, quien=self._quien(), ip=self._ip, op_id=op_id)
        self._bit("punto.vpn.regenerar", punto=pid, resultado=r.get("codigo"), detalle={"op_id": op_id})
        if r.get("codigo") in ("ACEPTADA", "OK"):
            return self._redirigir("/operaciones/%s" % op_id)
        self.panel.ops.quitar(op_id)
        return self._ficha(pid, traducir(r.get("codigo"), r.get("mensaje"), r.get("datos")), 409)


class Servidor(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    silencioso = False

    def __init__(self, direccion, panel):
        self.panel = panel
        super().__init__(direccion, Manejador)


def crear_servidor(panel, host=None, puerto=None):
    return Servidor((host if host is not None else panel.cfg.escucha,
                     puerto if puerto is not None else panel.cfg.puerto), panel)
