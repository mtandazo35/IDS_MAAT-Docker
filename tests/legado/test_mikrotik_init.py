# -*- coding: utf-8 -*-
"""El espejo del IDS en el MikroTik (mikrotik_init.py) contra un MikroTik de mentira.

Heredada de suricata-ids-lab (suricata-mikrotik-init). ADAPTADA: el programa con CLI
(-k credenciales, -s sensor, -e vpn|local, --plan, --sin-registrar) pasa a ser un modulo del
panel con plan(conexion, pid, sensor, puerto, redes, lista) / aplicar(conexion, plan,
respaldo_dir), que monta lo de docs/OPERACION.md §2. Se conservan las protecciones que siguen
teniendo sentido, por orden de lo que costaria el fallo:

  - Que repetirlo NO duplique reglas (un espejo duplicado lleno el enlace en produccion).
  - Que NO toque espejos que apuntan a otro sensor; los viejos hacia el nuestro se apagan.
  - Que el fasttrack excluya a los vigilados (sin eso mangle solo ve el primer paquete).
  - Que la vista previa NO toque nada y lo aplicado sea exactamente lo que ensena.
  - Que se pare en el PRIMER fallo y que sin respaldo /export no se toque nada.

Cambios deliberados (CONTRATO-F2 §4 y OPERACION.md §2), comprobados como tales:
  - ya no hay regla de DNS aparte: el DNS va dentro del recorte connection-bytes=0-10000;
  - ya no hay modo local sin recorte: el espejo va siempre por el tunel del punto;
  - ninguna regla `accept`, y todo lleva el comentario propio `IDS ids-maat:<pid>:espejo` (A-02).
Retirado: alta del router en el panel (ENABLED=0, mikrotik.conf: ahora es el apartado Puntos),
la clave por fichero de credenciales y su lectura (leer_credenciales) y el cliente api-ssl
sacado del dashboard (lo sustituye la conexion por el rele del punto, zona N).
"""
import importlib.util
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402

SENSOR = "100.64.3.1"
PID = "p003"
COM = "IDS ids-maat:" + PID + ":espejo"   # comentario propio del espejo (A-02)

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)[:400]))
    if not c:
        fallos += 1


def modulo():
    """mikrotik_init.py cargado aparte (sus funciones de red se sustituyen solo en esta copia)."""
    if extraer.LIB not in sys.path:
        sys.path.insert(0, extraer.LIB)
    spec = importlib.util.spec_from_file_location("legado_mikrotik_init", extraer.ruta("MKINIT"))
    m = importlib.util.module_from_spec(spec)
    antes, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(m)
    finally:
        sys.dont_write_bytecode = antes
    return m


class Router(object):
    """Un MikroTik de mentira a nivel de la API: print (con ?k=v), add, set, remove, /export."""

    TABLAS = {"/ip/firewall/mangle/": "mangle", "/ip/firewall/filter/": "filter",
              "/ip/firewall/address-list/": "lista"}

    def __init__(self, mangle=(), filtro=(), lista=()):
        self.t = {"mangle": [dict(x) for x in mangle], "filter": [dict(x) for x in filtro],
                  "lista": [dict(x) for x in lista]}
        self.ordenes = []          # [(comando, {clave: valor})]
        self.falla = None          # una orden que el router rechaza
        self._n = 100
        self._resp = None

    def _tabla(self, cmd):
        for pre, nom in self.TABLAS.items():
            if cmd.startswith(pre):
                return self.t[nom]
        return None

    def send(self, palabras):
        cmd, args, filtros = palabras[0], {}, {}
        for a in palabras[1:]:
            if a.startswith("?") and "=" in a:
                k, v = a[1:].split("=", 1)
                filtros[k] = v
            elif a.startswith("=") and "=" in a[1:]:
                k, v = a[1:].split("=", 1)
                args[k] = v
        self.ordenes.append((cmd, args))
        if self.falla and cmd == self.falla:
            self._resp = (False, [["!trap", "=message=failure: sin permiso"], ["!done"]], "failure: sin permiso")
            return
        filas = []
        tabla = self._tabla(cmd)
        if cmd == "/system/identity/print":
            filas = [{"name": "router-prueba"}]
        elif cmd.endswith("/print") and tabla is not None:
            filas = [f for f in tabla if all(f.get(k, "") == v for k, v in filtros.items())]
        elif cmd.endswith("/add") and tabla is not None:
            self._n += 1
            nueva = {k: v for k, v in args.items() if k != "place-before"}
            nueva[".id"] = "*%X" % self._n
            tabla.append(nueva)
        elif cmd.endswith("/set") and tabla is not None:
            for f in tabla:
                if f.get(".id") == args.get(".id"):
                    f.update({k: v for k, v in args.items() if k != ".id"})
        elif cmd.endswith("/remove") and tabla is not None:
            tabla[:] = [f for f in tabla if f.get(".id") != args.get(".id")]
        frases = [["!re"] + ["=%s=%s" % kv for kv in f.items()] for f in filas] + [["!done"]]
        self._resp = (True, frases, "")

    def reply(self):
        r, self._resp = self._resp, None
        return r

    def escrituras(self):
        return [(c, a) for c, a in self.ordenes if not c.endswith("/print")]


def conectar(mk, router):
    mk._mk_send = lambda s, palabras: s.send(palabras)
    mk._mk_reply = lambda s: s.reply()
    return router


def adds(r, tabla="mangle"):
    return [a for c, a in r.ordenes if c == "/ip/firewall/%s/add" % tabla]


def sets(r, tabla="mangle"):
    return [a for c, a in r.ordenes if c == "/ip/firewall/%s/set" % tabla]


def main():
    mk = modulo()
    tmp = tempfile.mkdtemp()

    # --- primera pasada, router limpio ---------------------------------------------------
    r = conectar(mk, Router(lista=[{".id": "*1", "list": "ids-vigilados", "address": "192.168.0.0/19"}]))
    p = mk.plan(r, PID, SENSOR, 37008, "192.168.0.0/19")
    res = mk.aplicar(r, p, tmp)
    creadas = adds(r)
    check("aplica sin fallos", res["ok"] is True, res)
    # cambio deliberado: antes eran tres (ida, vuelta y DNS)
    check("crea DOS reglas de espejo: ida y vuelta, sin regla de DNS aparte",
          len(creadas) == 2 and not any(x.get("dst-port") == "53" for x in creadas), creadas)
    ida = [x for x in creadas if "src-address-list" in x]
    vue = [x for x in creadas if "dst-address-list" in x]
    check("una de ida y una de vuelta", len(ida) == len(vue) == 1, creadas)
    ida, vue = (ida or [{}])[0], (vue or [{}])[0]
    check("las dos de trafico van en forward",
          ida.get("chain") == "forward" and vue.get("chain") == "forward", (ida, vue))
    check("la vuelta mira el destino, no el origen",
          "dst-address-list" in vue and "src-address-list" not in vue, vue)
    check("las dos llevan el recorte de 10 KB por conexion",
          ida.get("connection-bytes") == "0-10000" and vue.get("connection-bytes") == "0-10000", (ida, vue))
    check("y apuntan a este sensor y a su puerto",
          ida.get("sniff-target") == SENSOR and ida.get("sniff-target-port") == "37008", ida)
    check("con el comentario del punto (para pausar y retirar por comentario)",
          ida.get("comment") == COM and vue.get("comment") == COM, (ida, vue))

    # --- el respaldo antes de tocar el firewall ------------------------------------------
    esc = [c for c, _a in r.escrituras()]
    check("se exporta la configuracion antes de tocar nada",
          esc and esc[0] == "/export", esc[:3])
    check("y queda un respaldo local del firewall leido", bool(res.get("respaldo"))
          and os.path.isfile(res["respaldo"]), res.get("respaldo"))
    if os.name == "posix":
        modo = os.stat(res["respaldo"]).st_mode
        check("el respaldo no lo puede leer otro usuario (modo real)", (modo & 0o077) == 0, oct(modo))

    # --- segunda pasada: NO puede duplicar -------------------------------------------------
    n = len(r.ordenes)
    p2 = mk.plan(r, PID, SENSOR, 37008, "192.168.0.0/19")
    check("repetirlo: la vista previa no tiene ningun cambio", p2["cambios"] == [], p2["terminal"])
    res2 = mk.aplicar(r, p2, tmp)
    check("y aplicar no escribe nada en el router",
          res2["ok"] is True and not [o for o in r.ordenes[n:] if not o[0].endswith("/print")],
          r.ordenes[n:])
    check("ni vuelve a meter la red en la lista", not adds(r, "address-list"), adds(r, "address-list"))

    # --- espejos ajenos: no se tocan --------------------------------------------------------
    ajeno = {".id": "*50", "action": "sniff-tzsp", "comment": "espejo de otro IDS",
             "sniff-target": "203.0.113.77", "disabled": "false", "chain": "forward"}
    propio_viejo = {".id": "*51", "action": "sniff-tzsp", "comment": "IDS",
                    "sniff-target": SENSOR, "disabled": "false", "chain": "forward"}
    r3 = conectar(mk, Router(mangle=[ajeno, propio_viejo],
                             lista=[{".id": "*1", "list": "ids-vigilados", "address": "192.168.0.0/19"}]))
    mk.aplicar(r3, mk.plan(r3, PID, SENSOR, 37008, "192.168.0.0/19"), tmp)
    ids = {a[".id"] for a in sets(r3) if a.get("disabled") == "yes"}
    check("apaga el espejo viejo que venia hacia NUESTRO sensor", "*51" in ids, ids)
    check("y NO toca el espejo que va a otro sensor: el router es del cliente", "*50" not in ids, ids)

    # --- fasttrack ----------------------------------------------------------------------------
    r5 = conectar(mk, Router(filtro=[{".id": "*9", "chain": "forward", "action": "fasttrack-connection",
                                      "connection-state": "established,related", "disabled": "false"}]))
    res5 = mk.aplicar(r5, mk.plan(r5, PID, SENSOR, 37008, "10.0.0.0/8"), tmp)
    ft = sets(r5, "filter")
    check("excluye la lista del fasttrack, sin lo cual mangle solo ve el primer paquete",
          res5["ok"] and ft and ft[0].get("src-address-list") == "!ids-vigilados"
          and ft[0].get("dst-address-list") == "!ids-vigilados", ft)
    nuevas_ft = adds(r5, "filter")
    check("y acelera a los vigilados pasados los 10 KB con las mismas condiciones",
          len(nuevas_ft) == 2 and all(x.get("connection-bytes") == "10000-0"
                                      and x.get("connection-state") == "established,related"
                                      for x in nuevas_ft), nuevas_ft)
    check("NINGUNA regla accept (OPERACION.md §2)",
          not any(a.get("action") == "accept" for _c, a in r5.ordenes + r.ordenes + r3.ordenes), "")
    n5 = len(r5.ordenes)
    p6 = mk.plan(r5, PID, SENSOR, 37008, "10.0.0.0/8")
    check("si ya estaba excluida, no se vuelve a tocar", p6["cambios"] == [] and not
          [o for o in r5.ordenes[n5:] if not o[0].endswith("/print")], p6["terminal"])

    # --- vista previa: la usa el panel antes de confirmar --------------------------------------
    viejo = {".id": "*51", "action": "sniff-tzsp", "comment": "IDS", "chain": "forward",
             "sniff-target": SENSOR, "disabled": "false"}
    fast = {".id": "*9", "chain": "forward", "action": "fasttrack-connection", "disabled": "false"}
    r7 = conectar(mk, Router(mangle=[viejo], filtro=[fast]))
    p7 = mk.plan(r7, PID, SENSOR, 37008, "10.20.0.0/16")
    check("la vista previa no toca NADA: ni reglas, ni lista, ni respaldo en el router",
          r7.escrituras() == [], r7.escrituras())
    term = "\n".join(p7["terminal"])
    check("y dice lo que haria, como se escribe en la terminal del router",
          '/ip firewall address-list add list=ids-vigilados address=10.20.0.0/16 comment="IDS ids-maat:p003:espejo"' in term
          and "/ip firewall mangle add chain=forward action=sniff-tzsp sniff-target=%s" % SENSOR in term
          and "connection-bytes=0-10000" in term
          and "/ip firewall mangle set *51 disabled=yes" in term
          and "/ip firewall filter set *9 src-address-list=!ids-vigilados dst-address-list=!ids-vigilados" in term,
          term)
    r8 = conectar(mk, Router(mangle=[dict(viejo)], filtro=[dict(fast)]))
    res8 = mk.aplicar(r8, p7, tempfile.mkdtemp())
    hechas = [(c, a) for c, a in r8.escrituras() if c != "/export"]
    check("lo aplicado son exactamente las ordenes de la vista previa, en su orden",
          res8["ok"] and [c for c, _a in hechas] == [x["orden"] for x in p7["cambios"]],
          ([c for c, _a in hechas], [x["orden"] for x in p7["cambios"]]))
    check("  y lo apagado va ANTES que lo creado (nunca dos espejos a la vez)",
          [c for c, _a in hechas].index("/ip/firewall/mangle/set")
          < [c for c, _a in hechas].index("/ip/firewall/mangle/add"), hechas)

    r9 = conectar(mk, Router())
    r9.falla = "/ip/firewall/mangle/add"
    res9 = mk.aplicar(r9, mk.plan(r9, PID, SENSOR, 37008, "10.20.0.0/16"), tempfile.mkdtemp())
    check("si el router rechaza una orden, aplicar dice que fallo y cual",
          res9["ok"] is False and "sin permiso" in (res9["fallo"] or ""), res9)

    # --- se para en el PRIMER fallo ------------------------------------------------------------
    r10 = conectar(mk, Router(mangle=[dict(viejo)], filtro=[dict(fast)]))
    p10 = mk.plan(r10, PID, SENSOR, 37008, "10.20.0.0/16")
    r10.falla = "/ip/firewall/mangle/set"          # el router no deja apagar el espejo viejo
    res10 = mk.aplicar(r10, p10, tempfile.mkdtemp())
    hechas10 = [c for c, _a in r10.escrituras()]
    check("si no se puede apagar el espejo viejo, NO se crea el nuevo (nunca dos espejos a la vez)",
          res10["ok"] is False and not adds(r10), (res10, hechas10))
    check("  y se para ahi: ni el fasttrack ni nada de lo que quedaba",
          hechas10[-1] == "/ip/firewall/mangle/set" and "/ip/firewall/filter/set" not in hechas10
          and res10["sin_aplicar"], (hechas10, res10["sin_aplicar"]))
    r11 = conectar(mk, Router(mangle=[dict(viejo)]))
    p11 = mk.plan(r11, PID, SENSOR, 37008, "10.20.0.0/16")
    r11.falla = "/ip/firewall/mangle/add"            # la primera regla nueva falla
    res11 = mk.aplicar(r11, p11, tempfile.mkdtemp())
    check("si falla la primera regla nueva, no se intentan las siguientes",
          res11["ok"] is False and len(adds(r11)) == 1, r11.ordenes)
    r12 = conectar(mk, Router(mangle=[dict(viejo)],
                              lista=[{".id": "*1", "list": "ids-vigilados", "address": "10.20.0.0/16"}]))
    p12 = mk.plan(r12, PID, SENSOR, 37008, "10.20.0.0/16")
    r12.falla = "/export"                            # sin respaldo...
    res12 = mk.aplicar(r12, p12, tempfile.mkdtemp())
    tocadas = [c for c, _a in r12.escrituras() if c != "/export"]
    check("si el /export de respaldo falla, no se toca NADA del router",
          res12["ok"] is False and tocadas == [] and "no se ha tocado nada" in (res12["fallo"] or ""),
          (tocadas, res12["fallo"]))
    check("  (un router ya al dia sigue saliendo con exito)",
          mk.aplicar(r, mk.plan(r, PID, SENSOR, 37008, "192.168.0.0/19"), tmp)["ok"] is True)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0


class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion + cambio deliberado (sin DNS aparte, sin accept). El espejo del MikroTik: idempotente, acotado y que para en el primer fallo."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
