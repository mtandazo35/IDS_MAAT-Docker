# -*- coding: utf-8 -*-
"""Bloquear destinos de mala reputacion: solo publicas, y solo lo que se sostiene.

Es la otra direccion del problema. La cuarentena corta al CPE; esto corta el DESTINO, que
es lo que mantiene vivo al equipo infectado: sin canal de control la botnet no manda nada,
y vale para todos los abonados a la vez sin identificar a ninguno.

Los dos errores caros y por eso se prueban primero:
  - bloquear una IP PRIVADA como destino: seria de la propia red y dejaria a los abonados
    sin verse entre si;
  - bloquear por un feed flojo: una IP que alguna vez escaneo a alguien puede alojar
    ademas algo legitimo, y el abonado se queda sin servicio sin haber hecho nada.

Adaptada al panel portado (CONTRATO-F2 §3, §4): las rutas salen de `nodos.py` real sobre un
arbol de prueba. `destinos-malos.json` es una salida del generador POR NODO
(`nodos.dir_salida(pid)`, leida con `_salida_ctx` desde el nodo del hilo, §3); las publicas
van en `conf/publicas.json` con el pid del punto (p001, antes r1) y los feeds en
`nodos.FEEDS`. §4 quita el `/tool fetch` de `/destinos.rsc`, pero `destinos_rsc()` sigue
existiendo (el panel lo sirve como descarga para importarlo a mano), asi que sus tres
comprobaciones se conservan tal cual. Las comprobaciones son las mismas.
"""
import ast
import io
import json
import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ

DASH = extraer.fuente("DASH")
ARBOL = extraer.arbol("DASH")

PIEZAS = ("DESTINOS_FILE", "MK_SENT_DST", "DST_CONFIABLES", "cargar_destinos_malos",
          "destino_bloqueable", "destinos_malos",
          "ros_lista", "_RE_ROS_RARO",
          "DST_FEED_OK", "DST_FEED_TOPE", "destinos_feed", "destinos_rsc",
          "cargar_publicas",
          # panel portado: rutas por nodos.py (CONTRATO-F2 §3)
          "_salida_ctx", "PUBLICAS_CONF", "FEEDS_META")

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp, enviados=(), confiables=()):
    # nodos.py real, mirando el punto p001 (CONTRATO-F2 §3: el reporte es del nodo que se mira)
    nod, _sec = _comun.panel(tmp, nodo="p001")
    for d in ("conf", "estado"):
        os.makedirs(nod.ruta(d), exist_ok=True)
    os.makedirs(nod.FEEDS, exist_ok=True)
    ns = {"json": json, "os": os, "ipaddress": __import__("ipaddress"), "nodos": nod,
          "time": __import__("time"),
          # como en produccion: MIS_REDES puede incluir rangos PUBLICOS (el NAT de salida)
          "es_mi_cpe": lambda ip: ip.startswith("10.") or ip.startswith("190.0.2."),
          "cargar_enviados": lambda path=None: {k: 1 for k in enviados},
          "_dest_ok_set": lambda: set(confiables)}
    ns["re"] = __import__("re")
    # destinos_feed() ya no pregunta IP a IP: resuelve tus redes y tus publicas UNA vez
    # antes del bucle (abria el JSON de publicas por cada linea del feed). La prueba pasa
    # a darle esas dos fuentes, que es lo que ahora consume.
    _ipa = __import__("ipaddress")
    ns["ipaddress"] = _ipa
    ns["mis_redes"] = lambda: (_ipa.ip_network("10.0.0.0/8"),)
    ns["es_publica_declarada"] = lambda ip: "190.0.2.7" if ip.startswith("190.0.2.") else ""
    ns["cargar_feeds_meta"] = lambda: {"sources": {
        "feodo": {"categoria": "c2-activo"},
        "spamhaus-drop": {"categoria": "infra-delictiva"},
        "cins": {"categoria": "atacante-observado"},
        "abuseipdb": {"categoria": "atacante-denunciado"},
    }}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    with open(ns["PUBLICAS_CONF"], "w", encoding="utf-8") as f:
        json.dump({"nodos": {"p001": ["190.0.2.0/24"]}}, f)
    return ns


def guardar_destinos(ns):
    """destinos-malos.json del nodo que se mira (CONTRATO-F2 §3: salida por nodo)."""
    with open(ns["_salida_ctx"](ns["DESTINOS_FILE"]), "w", encoding="utf-8") as f:
        json.dump({"destinos": DESTINOS}, f)


DESTINOS = {
    # C2 activo: es lo que es, se bloquea
    "1.1.1.1": {"alertas": 800, "cpes": 12, "fuente": "feodo", "categoria": "c2-activo",
                "pais": "NL", "firma": "ET CNC Feodo checkin"},
    # red secuestrada: tambien
    "8.8.8.8": {"alertas": 40, "cpes": 3, "fuente": "spamhaus-drop",
                "categoria": "infra-delictiva", "pais": "RU", "firma": ""},
    # feed flojo: alguna vez escaneo a alguien. NO se propone: puede alojar algo legitimo
    "9.9.9.9": {"alertas": 5000, "cpes": 40, "fuente": "cins",
                "categoria": "atacante-observado", "pais": "US", "firma": ""},
    # una IP de la propia red que se cuele: jamas
    "10.6.1.10": {"alertas": 900, "cpes": 1, "fuente": "feodo", "categoria": "c2-activo",
                  "pais": "EC", "firma": ""},
    # rango de documentacion: no es publica
    "203.0.113.5": {"alertas": 700, "cpes": 4, "fuente": "feodo", "categoria": "c2-activo",
                    "pais": "XX", "firma": ""},
}


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)
    guardar_destinos(ns)

    # --- lo que NUNCA se bloquea como destino ---
    ok, porque = ns["destino_bloqueable"]("10.6.1.10")
    check("una IP de abonado no se puede bloquear como destino", not ok, porque)
    check("y se dice que no es publica", "pública" in porque, porque)
    # el caso que de verdad importa: una IP PUBLICA que es TUYA (tu rango de NAT).
    # Pasa el filtro de "es publica" y aun asi hay que frenarla.
    ok2, porque2 = ns["destino_bloqueable"]("190.0.2.7")
    check("una IP PUBLICA que es tuya tampoco se bloquea", not ok2, porque2)
    check("y ahi si se dice que es de tus redes", "tus redes" in porque2, porque2)
    check("una privada cualquiera tampoco", not ns["destino_bloqueable"]("192.168.1.1")[0])
    check("un rango de documentacion tampoco (no es publica)",
          not ns["destino_bloqueable"]("203.0.113.5")[0])
    check("una cadena que no es IP tampoco", not ns["destino_bloqueable"]("basura")[0])
    check("una publica ajena si", ns["destino_bloqueable"]("1.1.1.1")[0])

    # --- que se propone ---
    lst = {x["ip"]: x for x in ns["destinos_malos"]()}
    check("se propone el C2 activo", "1.1.1.1" in lst, list(lst))
    check("y la red secuestrada", "8.8.8.8" in lst, list(lst))
    check("NO se propone lo que viene de un feed flojo (podria ser legitimo)",
          "9.9.9.9" not in lst, list(lst))
    check("ni la IP de tus redes", "10.6.1.10" not in lst, list(lst))
    check("ni el rango de documentacion", "203.0.113.5" not in lst, list(lst))
    check("se dice cuantos CPEs lo contactan, que es lo que mide el daño",
          lst["1.1.1.1"]["cpes"] == 12, lst["1.1.1.1"])
    check("y de que feed viene", lst["1.1.1.1"]["fuente"] == "feodo", lst["1.1.1.1"])

    # con el filtro flojo abierto, entra todo lo publico
    todos = {x["ip"] for x in ns["destinos_malos"](solo_confiables=False)}
    check("si se pide, se puede ver tambien lo de los feeds flojos", "9.9.9.9" in todos, todos)
    check("pero las privadas siguen fuera", "10.6.1.10" not in todos, todos)

    # --- lo ya marcado como falso positivo no se vuelve a proponer ---
    ns2 = entorno(tmp, confiables=("1.1.1.1",))
    guardar_destinos(ns2)
    check("un destino marcado confiable desaparece de la lista",
          "1.1.1.1" not in {x["ip"] for x in ns2["destinos_malos"]()})

    # --- los ya bloqueados salen marcados y al final ---
    ns3 = entorno(tmp, enviados=("1.1.1.1",))
    guardar_destinos(ns3)
    r3 = ns3["destinos_malos"]()
    check("los ya bloqueados salen marcados", any(x["enviado"] for x in r3), r3)
    check("y van al final, para que arriba quede lo que falta decidir",
          not r3[0]["enviado"] and r3[-1]["enviado"], [(x["ip"], x["enviado"]) for x in r3])

    # --- bloqueo PREVENTIVO desde los feeds --------------------------------------
    # Lo de arriba es reactivo (bloquea lo que YA se contacto). Esto corta antes de que
    # nadie llegue, que es lo que de verdad evita el ataque.
    _feeds = os.path.dirname(ns["FEEDS_META"])          # nodos.FEEDS (CONTRATO-F2 §3)
    with io.open(os.path.join(_feeds, "reputation.lst"), "w", encoding="utf-8") as fh:
        fh.write("1.1.1.1\tfeodo\n")               # C2 activo -> entra
        fh.write("8.8.8.0/24\tspamhaus-drop\n")    # red secuestrada -> entra (CIDR)
        fh.write("9.9.9.9\tcins\n")                # "escaneo a alguien" -> NO entra
        fh.write("2.2.2.2\tabuseipdb\n")           # denunciada -> NO entra
        fh.write("190.0.2.7\tfeodo\n")             # una publica TUYA -> jamas
        fh.write("10.6.1.10\tfeodo\n")             # una privada tuya -> jamas
    with io.open(ns["FEEDS_META"], "w", encoding="utf-8") as fh:
        fh.write("{}")

    feed = dict(ns["destinos_feed"]())
    check("entra el C2 activo", "1.1.1.1" in feed, list(feed))
    check("y la red secuestrada, en CIDR", "8.8.8.0/24" in feed, list(feed))
    check("NO entra 'esta IP escaneo a alguien': puede alojar algo que un abonado visita",
          "9.9.9.9" not in feed and "2.2.2.2" not in feed, list(feed))
    check("NUNCA una publica tuya, aunque el feed la fiche", "190.0.2.7" not in feed, list(feed))
    check("ni una privada tuya", "10.6.1.10" not in feed, list(feed))

    # lo marcado como confiable tampoco entra al preventivo
    ns4 = entorno(tmp, confiables=("1.1.1.1",))
    check("un destino marcado confiable queda fuera del preventivo",
          "1.1.1.1" not in dict(ns4["destinos_feed"]()), dict(ns4["destinos_feed"]()))

    # CONTRATO-F2 §4: ya no se lo baja el router con /tool fetch, pero el script sigue
    # existiendo (descarga para /import a mano) y tiene que seguir siendo seguro
    rsc = ns["destinos_rsc"]("suricata-destinos-malos")
    check("el script solo borra lo que puso el feed, no lo que bloqueaste a mano",
          'comment~"feed"' in rsc, rsc[:300])
    check("y agrega con caducidad", "timeout=1d" in rsc and "add list=suricata-destinos-malos" in rsc)
    check("los CIDR van tal cual", "address=8.8.8.0/24" in rsc, rsc)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, solo cambia como se carga (rutas por nodos.py, salida por nodo: CONTRATO-F2 §3; destinos_rsc sigue tras §4). Bloquear destinos de mala reputacion: solo publicas, y solo lo que se sostiene."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
