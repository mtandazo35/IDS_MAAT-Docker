# -*- coding: utf-8 -*-
"""Una address-list por categoria de abuso, no un unico cajon.

Meter en la misma lista al que tiene una botnet y al que usa BitTorrent obliga a darles
el mismo trato en el firewall, y no es el mismo problema: la botnet se corta, el P2P se
encola, el DNS se redirige al resolutor propio.

Lo que se protege aqui es la clasificacion. Si un CPE cae en la lista equivocada, o se
corta a quien no habia que cortar, o se deja suelto a quien si.

Adaptada al panel portado (CONTRATO-F2 §1, §3): `cuarentena.json` es el del nodo, en
`nodos.dir_salida(pid)`, y la identidad del CPE es SIEMPRE `pid|ip` (`clave_cpe` REAL con
`nodos.py` real); `categoria_cpe` busca en el reporte del punto de la clave. Las
comprobaciones son las mismas.
"""
import ast
import json
import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import re  # noqa: E402
import extraer  # noqa: E402
RAIZ = extraer.RAIZ

DASH = extraer.fuente("DASH")
ARBOL = ast.parse(DASH)

PIEZAS = ("CAT_CPE", "CAT_OTROS", "_CPES_CACHE", "_CPES_LOCK", "_cpes_de_reporte",
          "cuarentena_json", "clave_cpe", "rid_de",
          "lista_de_categoria", "nombre_categoria", "categoria_de_cats", "categoria_cpe",
          "_TRAD", "_TRAD_CACHE", "_TRAD_CACHE_MAX", "_traducir_lento", "traducir", "AIDB_SENAL", "senal_de_categorias", "listas_en_uso",
          "ros_lista", "_RE_ROS_RARO")

fallos = 0
def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp, globales=None, enviados=None):
    # nodos.py real sobre el arbol de prueba (CONTRATO-F2 §3: el reporte es por nodo)
    nod, _sec = _comun.panel(tmp)
    ns = {"json": json, "os": os, "time": __import__("time"), "re": __import__("re"),
          "threading": __import__("threading"), "nodos": nod, "MK_SENT": "",
          "cargar_enviados": lambda path=None: dict(enviados or {}),
          "_mk_globales": lambda: dict(globales or {})}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


REPORTE = {"candidatos": [], "dns_candidatos": [], "top_riesgo": [
    {"ip": "10.0.0.1", "router": "", "cats_top": {"Botnet CnC": 90, "BitTorrent / P2P": 900}},
    {"ip": "10.0.0.2", "router": "", "cats_top": {"BitTorrent / P2P": 5000}},
    {"ip": "10.0.0.3", "router": "", "cats_top": {"DNS sospechoso": 40}},
    {"ip": "10.0.0.4", "router": "", "cats_top": {"Escaneo SSH": 700}},
    {"ip": "10.0.0.5", "router": "", "cats_top": {"Spam": 1200}},
    {"ip": "10.0.0.6", "router": "", "cats_top": {"Criptomineria": 30}},
    {"ip": "10.0.0.7", "router": "", "cats_top": {"Fuerza bruta": 200}},
    {"ip": "10.0.0.8", "router": "", "cats_top": {"Anomalia TLS/SSL": 400}},
]}


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)
    # CONTRATO-F2 §3: el cuarentena.json del punto, en nodos.dir_salida(pid)
    with open(ns["nodos"].salida("cuarentena.json", "p001"), "w", encoding="utf-8") as f:
        json.dump(REPORTE, f)

    # --- cada CPE a su categoria ---
    casos = [("10.0.0.2", "p2p"), ("10.0.0.3", "dns"), ("10.0.0.4", "escaneo"),
             ("10.0.0.5", "spam"), ("10.0.0.6", "minado"), ("10.0.0.7", "fuerza"),
             ("10.0.0.8", "otros")]
    for ip, esperada in casos:
        # CONTRATO-F2 §1: la identidad es pid|ip
        check("%s -> %s" % (ip, esperada), ns["categoria_cpe"]("p001|" + ip) == esperada,
              ns["categoria_cpe"]("p001|" + ip))

    # el caso que decide el diseño: uno que hace las dos cosas
    check("quien tiene botnet Y P2P es un CPE con BOTNET, no un CPE de P2P",
          ns["categoria_cpe"]("p001|10.0.0.1") == "botnet", ns["categoria_cpe"]("p001|10.0.0.1"))
    check("aunque el P2P tenga diez veces mas alertas", True)

    check("un CPE que no esta en el reporte cae en 'otros'",
          ns["categoria_cpe"]("p001|10.9.9.9") == "otros")

    # --- nombres de lista ---
    check("la botnet va a clientes-botnet",
          ns["lista_de_categoria"]("botnet") == "clientes-botnet", ns["lista_de_categoria"]("botnet"))
    check("el DNS de malware a clientes-dns-malware",
          ns["lista_de_categoria"]("dns") == "clientes-dns-malware")
    check("el P2P a clientes-p2p", ns["lista_de_categoria"]("p2p") == "clientes-p2p")
    check("una categoria desconocida cae en la de otros",
          ns["lista_de_categoria"]("inventada") == "clientes-otros")

    # se pueden renombrar, por si el ISP ya tiene su nomenclatura
    ns2 = entorno(tmp, globales={"LISTA_BOTNET": "abusivos-botnet"})
    check("el nombre se puede cambiar desde la configuracion",
          ns2["lista_de_categoria"]("botnet") == "abusivos-botnet",
          ns2["lista_de_categoria"]("botnet"))
    check("y las que no se cambian siguen con el suyo",
          ns2["lista_de_categoria"]("p2p") == "clientes-p2p")

    # =====================================================================================
    # Una categoria que nadie puede producir es una categoria MUERTA
    # =====================================================================================
    # Paso de verdad: CAT_CPE agrupaba por "Spam" y traducir() no producia ese nombre
    # jamas. Nada fallaba. Simplemente la categoria 'spam' no se le asignaba a nadie, la
    # address-list clientes-spam estaba siempre vacia, y la regla que el panel propone para
    # cortar el 25/465/587 no bloqueaba a nadie — siendo el correo saliente la causa numero
    # uno de que un ISP acabe en Spamhaus. Un fallo mudo de los caros.
    producibles = {t for _c, t in ns["_TRAD"]}
    muertas = []
    for c, nom, cats, lista in ns["CAT_CPE"]:
        falta = [x for x in cats if x not in producibles]
        if falta:
            muertas.append((c, falta, lista))
    check("toda categoria de CPE se puede asignar de verdad", not muertas, muertas)

    # lo mismo para la atribucion: busca nombres de categoria, y uno que no exista no
    # encuentra nunca a nadie sin decir por que
    busca = set()
    for d in ns["AIDB_SENAL"].values():
        busca |= set(d.get("cats") or [])
    check("y la atribucion no busca nombres que no existen",
          not (busca - producibles), sorted(busca - producibles))

    # las firmas reales de correo saliente tienen que caer en Spam...
    for fir in ("ET POLICY Outbound Spam", "ET POLICY SMTP Outbound Connection",
                "SMTP Open Relay detected"):
        check("'%s' se clasifica como Spam" % fir[:34],
              ns["traducir"](fir) == "Spam", ns["traducir"](fir))
    # ...sin robarle las suyas a las categorias vecinas, que es el riesgo de meter una
    # palabra tan generica en la tabla
    check("un brute force de SMTP sigue siendo fuerza bruta",
          ns["traducir"]("ET SCAN SMTP Login Brute Force") == "Fuerza bruta",
          ns["traducir"]("ET SCAN SMTP Login Brute Force"))
    check("y Spamhaus sigue siendo mala reputacion, no spam",
          ns["traducir"]("ET DROP Spamhaus DROP Listed") == "Mala reputacion",
          ns["traducir"]("ET DROP Spamhaus DROP Listed"))

    # =====================================================================================
    # Lo que se promete en pantalla es lo que se usa al enviar
    # =====================================================================================
    # La seccion decia "-> lista suricata-dns-sospechoso" y el envio iba a
    # clientes-dns-malware. El operador leia una lista y el sistema usaba otra, y eso pasaba
    # en la pantalla donde se decide dejar sin internet a un abonado.
    check("la fila dice a que lista va ESE CPE, no la de la seccion",
          "lista_de_categoria(categoria_cpe(k))" in DASH, "")
    check("y el modal de confirmacion nombra esa misma lista",
          "entra en la lista {esc(_lst)}" in DASH, "")
    check("la seccion ya no promete una lista unica",
          "address-list de <b>su categoría</b>" in DASH, "")

    # =====================================================================================
    # Las listas se pueden ver: cuales son y quien esta dentro
    # =====================================================================================
    ns3 = entorno(tmp, enviados={
        "p001|10.0.0.1": {"lista": "clientes-botnet"},
        "p001|10.0.0.2": {"lista": "clientes-botnet"},
        "p002|10.0.0.3": {"lista": "clientes-p2p"},
        "p001|10.0.0.4": {},                 # sin lista guardada
    })
    uso = {l: n for _c, _nom, l, n in ns3["listas_en_uso"]()}
    check("se cuenta cuantos CPEs hay en cada lista",
          uso.get("clientes-botnet") == 2 and uso.get("clientes-p2p") == 1, uso)
    check("las vacias salen igual, para saber que existen",
          uso.get("clientes-spam") == 0, uso)
    # el registro guarda la lista con la que se mando cada uno; uno sin ella no se puede
    # colocar en ninguna sin adivinar, y adivinar aqui seria decir que esta cortado donde
    # no lo esta
    check("un enviado sin lista guardada no se cuela en ninguna",
          sum(uso.values()) == 3, uso)
    check("estan las siete categorias mas otros",
          len(ns3["listas_en_uso"]()) == 8, len(ns3["listas_en_uso"]()))

    # las reglas para pegar a mano se quitaron (el user, 2026-10-12): las pone el panel por
    # la API desde Ajustes -> MikroTik; la pagina sigue ensenando las listas
    check("el panel ensena las listas y ya no el texto de reglas para pegar",
          "Las listas del MikroTik" in DASH and "Las reglas que necesita cada lista" not in DASH, "")

    # =====================================================================================
    # El diagnostico vigila las listas que se USAN
    # =====================================================================================
    # Antes miraba LIST y LIST_GRAD y nunca las clientes-*: avisaba de listas que no se
    # usan y callaba sobre las que si. "La lista de cuarentena NO corta nada" podia estar
    # en verde y aun asi no cortarse nada.
    check("el diagnostico incluye las listas de categoria en uso",
          re.search(r"listas_en_uso\([^)]*\) if n\]", DASH) is not None, "")
    # y solo las que tienen a alguien: una instalacion recien montada no puede salir con
    # siete avisos de listas vacias que nadie ha usado todavia
    check("pero solo las que tienen a alguien dentro",
          # auditoria A-18: solo los CPEs de ESE router ([_pid])
          "for _c, nom, l, n in listas_en_uso([_pid] if _pid else None) if n]" in DASH, "")

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada a cuarentena.json por nodo y claves pid|ip (CONTRATO-F2 §1, §3). Una address-list por categoria de abuso, no un unico cajon."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
