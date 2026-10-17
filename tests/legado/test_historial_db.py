# -*- coding: utf-8 -*-
"""Historial persistente: lo ya contado no se pierde ni se cuenta dos veces.

Lo que protege, en orden de importancia:

  - que el historial SOBREVIVA a que desaparezcan los logs. Es el motivo de que exista:
    logrotate parte eve.json y borra los rotados viejos, asi que la historia duraba lo
    que durase el disco. Aqui se vacia el log a proposito y el informe tiene que seguir
    contestando.
  - que un reinicio no duplique. La ingesta acumula (alertas = alertas + nuevas); si la
    marca de agua no se respetara, reingerir el mismo log doblaria todos los numeros y
    nadie lo notaria: los graficos saldrian igual de bonitos, solo que mintiendo.
  - que tampoco pierda: lo escrito despues de la marca tiene que entrar entero.
  - que AVANCE aunque el log sea enorme. Esto se rompio en produccion (cafanet,
    2026-09-27): la ingesta abria cada archivo por el principio y descartaba por marca
    de tiempo DESPUES de contar la linea contra su tope, asi que con dns.json en 2,9 GB
    el tope se agotaba releyendo lo mismo, la marca no avanzaba nunca y el grafico se
    quedo clavado con 100 minutos de atraso, al 48% de CPU y sin que un reinicio lo
    moviera. Releer no es un problema de rendimiento: es el contador parado del todo.
  - que la poda recorte la cola larga y no lo mas consultado.

Adaptada al panel portado (CONTRATO-F2 §3): la base es una POR PUNTO
(`nodos.salida("historial.db", pid)` = PANEL/nodos/<pid>/historial.db) y la ingesta lee los
eventos del punto (`nodos.ficheros_eventos(pid)` = DATOS/<pid>/eve.json*), no un LOGDIR unico.
Se usa el `nodos.py` real sobre un arbol temporal con el nodo p001 puesto. Las comprobaciones
son las mismas; se anade la de «Todos» (§3: la misma IP en dos puntos son dos filas con su
nodo, nunca una suma).
"""
import ast
import json
import os
import sys
import unittest
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ

DASH = extraer.fuente("DASH")
ARBOL = extraer.arbol("DASH")

PIEZAS = ("HIST_DB", "HIST_DIAS", "HIST_TOP", "HIST_CADA", "CONDUCTA_DIAS",
          "CONDUCTA_TOPE", "_cd_abrir", "_CD_TS", "_cd_ts", "_cd_top",
          "_hist_con", "hist_marca", "_hist_huella", "_hist_offsets", "hist_ingerir",
          "hist_podar", "hist_conducta",
          # el dominio de un evento, en el formato de Suricata que sea (2026-10-15)
          "dominio_de",
          # el ruido no cuenta (ET INFO y lo no abusivo; el user, 2026-10-13)
          "_TRAD", "_TRAD_CACHE", "_TRAD_CACHE_MAX", "_traducir_lento", "traducir",
          "CD_NO_CUENTA", "cd_es_ruido", "_cd_firmas_reales")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def entorno(tmp):
    import glob as _glob
    ns = {"json": json, "os": os, "time": time, "glob": _glob, "sys": sys,
          "es_mi_cpe": lambda ip: ip.startswith("192.168.")}
    ns["nodos"], ns["secretos"] = _comun.panel(tmp, nodo="p001")
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    # CONTRATO-F2 §3: HIST_DB es el NOMBRE; la ruta es nodos.salida(HIST_DB, pid), por punto
    return ns


def ev(ip, hace_min, tipo="alert", **kw):
    t = time.time() - hace_min * 60
    d = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000", time.localtime(t)),
         "src_ip": ip, "event_type": tipo}
    d.update(kw)
    return json.dumps(d) + "\n"


def ruta_eve(ns, pid="p001"):
    """eve.json del punto (CONTRATO-F2 §3: DATOS/<pid>/eve.json)."""
    return ns["nodos"].eve_vivo(pid)


def escribir(ns, lineas, modo="w", pid="p001"):
    os.makedirs(os.path.dirname(ruta_eve(ns, pid)), exist_ok=True)
    with open(ruta_eve(ns, pid), modo, encoding="utf-8") as f:
        f.writelines(lineas)


def alertas_de(ns, ip):
    for f in ns["hist_conducta"](3)["filas"]:
        if f["ip"] == ip:
            return f["alertas"]
    return None


def main():
    tmp = tempfile.mkdtemp()
    ns = entorno(tmp)

    escribir(ns, [ev("192.168.1.10", 30, dest_ip="8.8.8.8", dest_port=53,
                      alert={"signature": "ET MALWARE Botnet CnC"}) for _ in range(5)]
             + [ev("192.168.1.11", 20, tipo="dns", dest_ip="8.8.8.8",
                   dns={"rrname": "malo.example.com"})])
    ns["hist_ingerir"]()

    check("lo ingerido se puede consultar", alertas_de(ns, "192.168.1.10") == 5,
          alertas_de(ns, "192.168.1.10"))

    # --- LO IMPORTANTE: el log desaparece y el historial sigue -----------------------
    open(ruta_eve(ns), "w").close()                       # logrotate se lo llevo
    check("el historial sobrevive a que se vacie el log",
          alertas_de(ns, "192.168.1.10") == 5, alertas_de(ns, "192.168.1.10"))
    # el CPE que solo hizo DNS (0 alertas) sigue en la BASE, pero ya no sale en el reporte: solo
    # se listan abonados con alertas reales (el user, 2026-10-13)
    _c = ns["_hist_con"]("p001")
    try:
        _en_base = _c.execute("SELECT COUNT(*) FROM resumen WHERE cpe=?", ("192.168.1.11",)).fetchone()[0]
    finally:
        _c.close()
    check("y el CPE de DNS tambien sigue en la base", _en_base > 0, _en_base)
    check("aunque, sin alertas, no salga en el reporte",
          not any(f["ip"] == "192.168.1.11" for f in ns["hist_conducta"](3)["filas"]))

    # --- reinicio: reingerir no puede duplicar ---------------------------------------
    escribir(ns, [ev("192.168.1.10", 30, dest_ip="8.8.8.8", dest_port=53,
                      alert={"signature": "ET MALWARE Botnet CnC"}) for _ in range(5)])
    ns2 = entorno(tmp)                    # conexion nueva = proceso nuevo tras reiniciar
    ns2["HIST_DB"] = ns["HIST_DB"]       # la misma base del punto (nodos/p001/historial.db)
    ns2["hist_ingerir"]()
    check("tras un reinicio, reingerir lo mismo NO duplica",
          alertas_de(ns2, "192.168.1.10") == 5, alertas_de(ns2, "192.168.1.10"))

    # --- lo nuevo si entra ------------------------------------------------------------
    escribir(ns, [ev("192.168.1.10", 0.2, dest_ip="1.1.1.1", dest_port=443,
                      alert={"signature": "ET SCAN generico"}) for _ in range(3)], modo="a")
    ns2["hist_ingerir"]()
    check("lo escrito despues de la marca entra entero",
          alertas_de(ns2, "192.168.1.10") == 8, alertas_de(ns2, "192.168.1.10"))

    f10 = [f for f in ns2["hist_conducta"](3)["filas"] if f["ip"] == "192.168.1.10"][0]
    check("las firmas se acumulan por tipo", len(f10["firmas"]) == 2, f10["firmas"])
    check("y los destinos tambien", f10["destinos_n"] == 2, f10["destinos"])
    check("el mas ruidoso encabeza el informe",
          ns2["hist_conducta"](3)["filas"][0]["ip"] == "192.168.1.10")

    # --- la marca de agua avanza y se guarda -----------------------------------------
    c = ns2["_hist_con"]()
    try:
        marca = ns2["hist_marca"](c)
    finally:
        c.close()
    check("la marca de agua queda guardada en la base", marca > 0, marca)
    check("y no adelanta al futuro", marca <= time.time() + 1, marca)

    # --- poda: recorta la cola larga, no lo mas visto ---------------------------------
    escribir(ns, [ev("192.168.2.30", 0.1, dest_ip="10.0.0.%d" % i, dest_port=443,
                      alert={"signature": "ET SCAN generico"})
                   for i in range(1, 40) for _ in range(1 if i > 3 else 9)])
    ns2["hist_ingerir"]()
    c = ns2["_hist_con"]()
    try:
        n = c.execute("SELECT COUNT(*) FROM detalle WHERE cpe='192.168.2.30' "
                      "AND tipo='destino'").fetchone()[0]
        quedan = [r[0] for r in c.execute(
            "SELECT clave FROM detalle WHERE cpe='192.168.2.30' AND tipo='destino'")]
    finally:
        c.close()
    check("la poda acota cuantas claves guarda por CPE", n <= ns2["HIST_TOP"], n)
    check("y conserva las mas frecuentes, no las primeras que llegaron",
          "10.0.0.1" in quedan and "10.0.0.39" not in quedan, quedan)

    # --- LO QUE FALLO EN PRODUCCION: log grande, tope agotado, contador parado ------
    # Marcas de tiempo distintas, como en un log real: con todas iguales no se puede
    # distinguir lo ya contado de lo nuevo y la prueba no probaria nada.
    tmp2 = tempfile.mkdtemp()
    ns3 = entorno(tmp2)
    escribir(ns3, [ev("192.168.3.7", 120 - i, dest_ip="8.8.8.8", dest_port=53,
                       alert={"signature": "ET SCAN viejo"}) for i in range(60)])
    ns3["hist_ingerir"](limite_lineas=20)          # no cabe todo en una pasada
    n1 = alertas_de(ns3, "192.168.3.7")
    ns3["hist_ingerir"](limite_lineas=20)
    n2 = alertas_de(ns3, "192.168.3.7")
    check("con el tope agotado, la pasada siguiente AVANZA en vez de releer lo mismo",
          n2 > n1, (n1, n2))
    for _ in range(4):
        ns3["hist_ingerir"](limite_lineas=20)
    check("y acaba contandolo todo, por grande que sea el log",
          alertas_de(ns3, "192.168.3.7") == 60, alertas_de(ns3, "192.168.3.7"))

    # --- rotacion: el archivo nuevo empieza por el principio --------------------------
    # El de antes tenia 60 lineas; el nuevo tiene 4. Si la posicion se guardara por
    # NOMBRE se saltaria hasta el byte del viejo, que en el nuevo ya es el final, y no
    # se leeria ni una linea. Por eso la posicion va por inodo.
    os.rename(ruta_eve(ns3), ruta_eve(ns3) + ".1")
    escribir(ns3, [ev("192.168.3.8", 1, dest_ip="9.9.9.9", dest_port=443,
                       alert={"signature": "ET SCAN nuevo"}) for _ in range(4)])
    ns3["hist_ingerir"]()
    check("tras rotar, el log nuevo se lee desde el principio",
          alertas_de(ns3, "192.168.3.8") == 4, alertas_de(ns3, "192.168.3.8"))

    # --- truncado: el archivo encoge y hay que volver al principio --------------------
    escribir(ns3, [ev("192.168.3.9", 0.5, dest_ip="9.9.9.9", dest_port=80,
                       alert={"signature": "ET SCAN tras truncar"}) for _ in range(3)])
    ns3["hist_ingerir"]()
    check("si truncan el log en caliente, se vuelve a leer desde el principio",
          alertas_de(ns3, "192.168.3.9") == 3, alertas_de(ns3, "192.168.3.9"))

    # --- la posicion se guarda, tambien cuando no hay nada nuevo ----------------------
    ruta = ruta_eve(ns3)
    st = os.stat(ruta)
    k = "%d:%d" % (st.st_dev, st.st_ino)
    c = ns3["_hist_con"]()
    try:
        antes = ns3["_hist_offsets"](c)
    finally:
        c.close()
    check("se guarda por que byte va el log en curso", (antes.get(k) or [0])[0] > 0, antes)
    ns3["hist_ingerir"]()                          # pasada sin novedades
    c = ns3["_hist_con"]()
    try:
        despues = ns3["_hist_offsets"](c)
    finally:
        c.close()
    # si una pasada en vacio olvidara la posicion, la siguiente releeria el archivo
    # entero: exactamente el atasco que se acaba de arreglar
    check("y una pasada sin novedades no la pierde",
          despues.get(k) == antes.get(k), (antes.get(k), despues.get(k)))

    # --- CONTRATO-F2 §3: una base por punto; «Todos» une filas con su nodo -------------
    # La misma IP en otro punto es OTRO abonado: ni se mezcla en la base de p001 ni se
    # suma en la vista acumulada.
    escribir(ns3, [ev("192.168.3.7", 2, dest_ip="8.8.8.8", dest_port=53,
                      alert={"signature": "ET SCAN otro punto"}) for _ in range(2)], pid="p002")
    ns3["hist_ingerir"]("p002")
    check("la base de p001 no ve lo ingerido en p002",
          alertas_de(ns3, "192.168.3.7") == 60, alertas_de(ns3, "192.168.3.7"))
    todos = [(f["nodo"], f["alertas"]) for f in
             ns3["hist_conducta"](3, ns3["nodos"].TODOS)["filas"] if f["ip"] == "192.168.3.7"]
    check("en «Todos» la misma IP de dos puntos son dos filas con su nodo, sin sumar",
          sorted(todos) == [("p001", 60), ("p002", 2)], todos)

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada a base y eventos por punto (CONTRATO-F2 §3: nodos/<pid>/historial.db, DATOS/<pid>/eve.json*; «Todos» une filas con nodo). Historial persistente: lo ya contado no se pierde ni se cuenta dos veces."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
