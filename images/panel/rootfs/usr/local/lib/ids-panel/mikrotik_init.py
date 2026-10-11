#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deja el MikroTik listo desde el sensor: registra el router y monta el espejo.

Existe para no tener que acordarse de nada. Lo que hacia falta hacer a mano eran seis
cosas, y olvidar una sola deja un IDS que parece funcionar y no ve:

  1. dar de alta el router en el panel (sin eso detecta pero no corta);
  2. la address-list de a quien se vigila;
  3. el espejo de IDA y el de VUELTA, los dos en forward;
  4. el recorte, si el sensor esta al otro lado de un enlace;
  5. el DNS aparte y entero;
  6. excluir el fasttrack, sin lo cual mangle solo ve el SYN.

Es IDEMPOTENTE a proposito. Repetirlo no duplica reglas: las nuestras se reconocen por
su comentario y se actualizan. Un espejo duplicado es justo lo que en produccion metio
886 Mbps en un enlace para que el receptor tirase el 91%, y con el enlace lleno el TZSP
(que es UDP) no se retrasa, DESAPARECE.

No se toca nada mas: solo se apagan reglas de espejo que apunten A ESTE sensor. Lo que
el cliente tenga para otras cosas se queda como esta.
"""
import argparse
import ast
import hashlib as _hashlib
import json
import os
import socket
import ssl
import sys
import time

DASHBOARD = "/usr/local/bin/suricata-dashboard"
MK_CONF = "/etc/suricata-mikrotik.conf"
ROUTERS_CONF = "/etc/suricata-routers.json"
COMENTARIO = "espejo IDS"          # marca de las reglas nuestras
# Version de esta herramienta. El panel (mkinit_asegurar) busca ESTA linea para saber si la
# instalada es la de su version: si no la encuentra, la renueva desde el instalador
# publicado. Se cambia cada vez que el panel necesite algo nuevo de aqui (y MK_INIT_MARCA
# en el panel con ella).
MKINIT_VERSION = "2026-10-10b"


def cliente_api():
    """El cliente de la API de RouterOS del propio panel, sin duplicar el protocolo."""
    src = open(DASHBOARD, encoding="utf-8").read()
    arbol = ast.parse(src)
    piezas = ("_mk_len", "_mk_word", "_mk_send", "_mk_rlen", "_mk_read", "_mk_reply",
              "_mk_tls_wrap", "mk_conectar", "_mk_print")
    ns = {"socket": socket, "_socket": socket, "ssl": ssl, "_ssl": ssl,
          "time": time, "_hashlib": _hashlib, "sys": sys}
    for n in arbol.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in piezas:
            exec(ast.get_source_segment(src, n) or "", ns)
    # mk_conectar, con api-ssl y sin huella previa, la fija llamando a guardar_mk() del
    # panel, que aqui no existe: sin esto la conexion moria con un NameError ("No se pudo
    # conectar: name 'guardar_mk' is not defined"). La huella la guarda esta herramienta
    # al registrar el router (CERT_FP); MK_CONF lo cita su mensaje de huella cambiada.
    ns.setdefault("guardar_mk", lambda _d: None)
    ns.setdefault("MK_CONF", MK_CONF)
    faltan = [p for p in piezas if p not in ns]
    if faltan:
        sys.exit("No se encontro el cliente de API en %s (falta %s)" % (DASHBOARD, faltan[0]))
    return ns


def leer_credenciales(ruta):
    """HOST/PORT/USER/PASS de un archivo, nunca de la linea de comandos.

    La clave en un argumento queda en el historial del shell y visible en `ps` para
    cualquier usuario de la maquina mientras corre. En un archivo 600, no."""
    d = {}
    try:
        st = os.stat(ruta)
    except OSError as e:
        sys.exit("No se puede leer %s: %s" % (ruta, e))
    if st.st_mode & 0o077:
        print("  [!] %s es legible por otros (chmod 600 %s)" % (ruta, ruta))
    for crudo in open(ruta, encoding="utf-8", newline=""):
        l = crudo.rstrip("\r\n")
        t = l.strip()
        if not t or t.startswith("#") or "=" not in t:
            continue
        k, v = l.split("=", 1)
        k = k.strip().upper()
        if k == "PASS":
            # Entre comillas (dobles o simples que envuelven todo el valor, quitados los
            # espacios de fuera), lo de dentro EXACTAMENTE: un espacio o una comilla en los
            # bordes pueden ser parte de la clave (el panel la acepta y la escribe asi,
            # PASS="..."). Sin comillas, como se escribe a mano (PASS=clave, PASS = clave),
            # sin los espacios ni tabuladores de los bordes, que no son de la clave.
            t = v.strip()
            if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
                v = t[1:-1]
            else:
                v = t
            d[k] = v
        else:
            d[k] = v.strip().strip('"').strip("'")
    for k in ("HOST", "USER", "PASS"):
        if not d.get(k):
            sys.exit("Falta %s en %s" % (k, ruta))
    d.setdefault("PORT", "8729")
    d.setdefault("TLS", "1")
    return d


def en_terminal(orden, args):
    """La orden de la API escrita como en la terminal del router, para la vista previa:
    /ip/firewall/mangle/add =chain=forward  ->  /ip firewall mangle add chain=forward.
    Asi el operador lee lo que conoce, no el protocolo de la API."""
    partes = orden.strip("/").split("/")
    txt = "/" + " ".join(partes[:-1]) + " " + partes[-1]
    for x in args:
        k, v = x[1:].split("=", 1)
        if k == ".id":
            txt += " " + v          # set *1A ...: el id interno, como lo admite la terminal
            continue
        if v == "" or any(c in v for c in ' \t";\\$[]{}'):
            v = '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
        txt += " %s=%s" % (k, v)
    return txt


def cmd(ns, s, orden, *args):
    ns["_mk_send"](s, [orden] + list(args))
    ok, frases, err = ns["_mk_reply"](s)
    return ok, frases, err


def registrar(d, fp, ident):
    """Da de alta el router en el panel (MK_CONF y, si no habia, la lista de routers)."""
    nuevo = not os.path.exists(MK_CONF)
    viejo = {}
    if not nuevo:
        for l in open(MK_CONF, encoding="utf-8"):
            l = l.strip()
            if l and not l.startswith("#") and "=" in l:
                k, v = l.split("=", 1)
                viejo[k.strip()] = v.strip()
    conf = {"HOST": d["HOST"], "PORT": d["PORT"], "TLS": d.get("TLS", "1"),
            "USER": d["USER"], "PASS": d["PASS"], "CERT_FP": fp,
            "LIST": viejo.get("LIST", "suricata-cuarentena"),
            "TTL": viejo.get("TTL", "1h"),
            "LIST_DNS": viejo.get("LIST_DNS", "suricata-dns-sospechoso"),
            "TTL_DNS": viejo.get("TTL_DNS", "1d"),
            "AUTO_MANTENER": viejo.get("AUTO_MANTENER", "0"),
            # Se registra, pero NO se activa el envio solo: que el sistema empiece a
            # cortar clientes tiene que decidirlo una persona mirando el panel.
            "ENABLED": viejo.get("ENABLED", "0"),
            "POL_AUTO": viejo.get("POL_AUTO", "0"),
            "POL_BAJO": viejo.get("POL_BAJO", "nada"),
            "POL_MEDIO": viejo.get("POL_MEDIO", "nada"),
            "POL_ALTO": viejo.get("POL_ALTO", "nada")}
    tmp = MK_CONF + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("# Conexion API al MikroTik para la cuarentena. La clave se usa para\n"
                "# autenticar (no se puede hashear). Archivo con permisos 600.\n")
        for k, v in conf.items():
            f.write("%s=%s\n" % (k, v))
    os.chmod(tmp, 0o600)
    os.replace(tmp, MK_CONF)

    rs = {"routers": [{"id": "r1", "nombre": ident or d["HOST"], "iface": "ids-mon",
                       "HOST": d["HOST"], "PORT": d["PORT"], "TLS": d.get("TLS", "1"),
                       "USER": d["USER"], "PASS": d["PASS"], "CERT_FP": fp,
                       "LIST": conf["LIST"], "LIST_DNS": conf["LIST_DNS"],
                       "ENABLED": conf["ENABLED"]}]}
    if not os.path.exists(ROUTERS_CONF):
        tmp = ROUTERS_CONF + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rs, f, indent=1, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, ROUTERS_CONF)
        print("  router dado de alta en el panel (modo sugerencia: actívalo en Ajustes)")
    else:
        print("  ya habia routers dados de alta; no se toca esa lista")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("-k", "--credenciales", required=True,
                   help="archivo con HOST/PORT/USER/PASS del MikroTik (chmod 600)")
    p.add_argument("-s", "--sensor", required=True,
                   help="IP de ESTE sensor, a donde el router manda el espejo")
    p.add_argument("-l", "--lista", default="ids-vigilados",
                   help="address-list con las redes de abonados a vigilar")
    p.add_argument("-r", "--redes", default="",
                   help="redes de abonados a meter en la lista, separadas por coma")
    p.add_argument("-e", "--donde", choices=("local", "vpn"), default="vpn",
                   help="donde esta el sensor respecto al router")
    p.add_argument("-p", "--puerto", type=int, default=37008, help="puerto TZSP")
    p.add_argument("--solo-registrar", action="store_true",
                   help="da de alta el router en el panel y NO toca su firewall")
    # Las dos que usa el panel (Ajustes > VPN): el router ya esta dado de alta alli, con
    # sus listas y su politica, y registrar de nuevo pisaria esa configuracion.
    p.add_argument("--sin-registrar", action="store_true",
                   help="no toca la configuracion del panel (el router ya esta dado de alta)")
    p.add_argument("--plan", action="store_true",
                   help="vista previa: dice que cambiaria en el router y NO toca nada")
    a = p.parse_args()

    d = leer_credenciales(a.credenciales)
    ns = cliente_api()
    print("Conectando a %s:%s como %s ..." % (d["HOST"], d["PORT"], d["USER"]))
    try:
        s = ns["mk_conectar"](d, timeout=15)
    except Exception as e:
        sys.exit("No se pudo conectar: %s" % e)

    # --- que clase de TLS es esto ----------------------------------------------------
    # Con api-ssl SIN certificado, RouterOS negocia Diffie-Hellman ANONIMO: el trafico va
    # cifrado pero NO autenticado, asi que no hay huella que fijar y alguien en medio
    # podria hacerse pasar por el router y quedarse con esta clave.
    cert = None
    try:
        cert = s.getpeercert(binary_form=True)
    except Exception:
        pass
    fp = _hashlib.sha256(cert).hexdigest() if cert else ""
    if fp:
        print("  certificado del router: %s..." % fp[:16])
    elif d.get("TLS") != "1":
        # sin TLS no hay certificado que mirar; el aviso de api-ssl confundia
        print("  API sin TLS: la clave viaja en claro salvo que vaya por un tunel (VPN)")
    else:
        print("  [!] api-ssl SIN certificado (cifrado anonimo): el canal va cifrado pero")
        print("      NO autenticado. Ponle un certificado al router y vuelve a correr esto")
        print("      para fijar su huella:  /certificate add name=api common-name=<router>")

    ident = ""
    ok, fr, _e = cmd(ns, s, "/system/identity/print")
    if ok:
        for f in fr:
            for x in f:
                if x.startswith("=name="):
                    ident = x[6:]
    print("  conectado a %s" % (ident or d["HOST"]))

    # --- 1) el panel, para que pueda cortar -------------------------------------------
    if a.plan or a.sin_registrar:
        print("  la configuracion del panel no se toca")
    else:
        registrar(d, fp, ident)

    if a.solo_registrar:
        print("\n--solo-registrar: no se toca el firewall del router.")
        return 0

    # --- 2) que hay que cambiar (solo lectura) -------------------------------------------
    # Primero se calcula TODO lo que hace falta y despues se hace. La vista previa (--plan)
    # y la ejecucion salen de la MISMA lista: lo que se ensena antes de confirmar es
    # exactamente lo que se aplica despues, no una descripcion aproximada.
    cambios = []      # [(que es, orden de la API, argumentos)]

    # la lista de a quien se vigila
    PROP_AL = ["*", ".id", "list", "address"]
    ya = {f.get("address") for f in ns["_mk_print"](s, "/ip/firewall/address-list/print", PROP_AL)
          if f.get("list") == a.lista}
    nuevas = []
    for r in (x.strip() for x in a.redes.split(",")):
        if r and r not in ya and r not in nuevas:
            nuevas.append(r)
    for r in nuevas:
        cambios.append(("anadir %s a la lista %s" % (r, a.lista), "/ip/firewall/address-list/add",
                        ["=list=" + a.lista, "=address=" + r, "=comment=abonados vigilados (IDS)"]))
    print("  address-list %s: %d ya estaban, %d por anadir" % (a.lista, len(ya), len(nuevas)))
    if not ya and not nuevas:
        print("  [!] la lista %s esta VACIA: no se espejara nada hasta que metas redes" % a.lista)

    # las reglas de espejo, sin duplicar
    cb = "0-10000" if a.donde == "vpn" else ""
    quiero = [
        ("%s (ida)" % COMENTARIO,
         {"chain": "forward", "src-address-list": a.lista}),
        ("%s (vuelta)" % COMENTARIO,
         {"chain": "forward", "dst-address-list": a.lista}),
    ]
    if a.donde == "vpn":
        # el DNS entero y sin recorte: pesa nada y es donde mas se detecta
        quiero.append(("%s: DNS completo" % COMENTARIO,
                       {"chain": "forward", "src-address-list": a.lista,
                        "protocol": "udp", "dst-port": "53"}))

    PROP_MG = ["*", ".id", "chain", "action", "comment", "disabled", "connection-bytes",
               "sniff-target", "src-address-list", "dst-address-list", "protocol", "dst-port"]
    actuales = ns["_mk_print"](s, "/ip/firewall/mangle/print", PROP_MG)
    por_comentario = {f.get("comment"): f for f in actuales}

    # las viejas que apuntan a ESTE sensor y no son nuestras: conviviendo con las nuevas,
    # el enlace cargaria el doble para ver lo mismo. Se apagan ANTES de crear las nuevas: si
    # el router rechaza algo a mitad, se para ahi, y lo peor que queda es un espejo de menos
    # (se ve en el panel), nunca dos a la vez llenando el enlace.
    mias = {c for c, _ in quiero}
    sobran = [f for f in actuales
              if f.get("action") == "sniff-tzsp"
              and f.get("sniff-target") == a.sensor
              and (f.get("comment") or "") not in mias
              and (f.get("disabled") or "false") == "false"]
    for f in sobran:
        cambios.append(("apagar un espejo viejo hacia este sensor (comment=%r)" % f.get("comment", ""),
                        "/ip/firewall/mangle/set", ["=.id=" + f[".id"], "=disabled=yes"]))

    for comentario, campos in quiero:
        args = ["=action=sniff-tzsp", "=sniff-target=" + a.sensor,
                "=sniff-target-port=%d" % a.puerto, "=passthrough=yes",
                "=comment=" + comentario, "=disabled=no"]
        for k, v in campos.items():
            args.append("=%s=%s" % (k, v))
        # el DNS nunca lleva recorte; las otras solo en modo vpn
        if cb and "dst-port" not in campos:
            args.append("=connection-bytes=" + cb)
        vieja = por_comentario.get(comentario)
        if vieja:
            cambios.append(("regla '%s': actualizar" % comentario, "/ip/firewall/mangle/set",
                            ["=.id=" + vieja[".id"]] + args))
        else:
            cambios.append(("regla '%s': crear" % comentario, "/ip/firewall/mangle/add", args))

    # el fasttrack: sin excluir la lista, mangle solo ve el SYN y se pierde el handshake TLS
    ft = [f for f in ns["_mk_print"](s, "/ip/firewall/filter/print",
                                     ["*", ".id", "action", "src-address-list", "disabled"])
          if f.get("action") == "fasttrack-connection"]
    if not ft:
        print("  fasttrack: no hay reglas, mangle ve todos los paquetes")
    for f in ft:
        if (f.get("src-address-list") or "") == "!" + a.lista:
            print("  fasttrack: ya excluia %s" % a.lista)
            continue
        cambios.append(("excluir %s del fasttrack (sin esto mangle solo ve el SYN)" % a.lista,
                        "/ip/firewall/filter/set", ["=.id=" + f[".id"], "=src-address-list=!" + a.lista]))

    # --- 3) vista previa: se dice que se haria y no se toca nada ---------------------------
    if a.plan:
        print("\nVISTA PREVIA: no se ha tocado nada. Esto es lo que se haria en %s:" % (ident or d["HOST"]))
        for que, orden, args in cambios:
            print("  # " + que)
            print("  " + en_terminal(orden, args))
        if not cambios:
            print("  nada: el router ya esta como debe")
        try:
            s.close()
        except Exception:
            pass
        return 0

    # --- 4) respaldo antes de tocar el firewall, y los cambios ----------------------------
    # Sin respaldo no se toca nada, y se para en el PRIMER fallo: seguir con el resto podia
    # dejar, por ejemplo, el espejo nuevo creado y el viejo sin apagar (dos espejos llenando
    # el enlace). Lo hecho hasta ahi queda dicho, y el respaldo permite volver atras.
    fallidos = 0
    if cambios:
        marca = time.strftime("%Y%m%d-%H%M")
        ok, _f, err = cmd(ns, s, "/export", "=file=antes-ids-%s" % marca)
        print("  respaldo /export antes-ids-%s.rsc: %s" % (marca, "hecho" if ok else "FALLO: %s" % err))
        if not ok:
            print("\nSin respaldo no se toca nada: el router queda como estaba.")
            fallidos = 1
            cambios = []
    for n, (que, orden, args) in enumerate(cambios, 1):
        ok, _f, err = cmd(ns, s, orden, *args)
        print("  %s: %s" % (que, "hecho" if ok else "FALLO: %s" % err))
        if not ok:
            fallidos = 1
            resto = len(cambios) - n
            print("\nSe para aqui: %s. Lo anterior ya esta aplicado; para volver atras, el respaldo "
                  "antes-ids-%s.rsc del router." % (("no se aplica lo que quedaba (%d orden(es))" % resto)
                                                     if resto else "era la ultima orden", marca))
            break
    if not cambios and not fallidos:
        print("  nada que cambiar: el router ya estaba como debe")
    if fallidos:
        try:
            s.close()
        except Exception:
            pass
        return 1

    print("\nListo. Comprueba que los contadores suben, con clientes activos:")
    print("  /ip firewall mangle print stats where comment~\"%s\"" % COMENTARIO)
    try:
        s.close()
    except Exception:
        pass
    return 1 if fallidos else 0


if __name__ == "__main__":
    sys.exit(main())
