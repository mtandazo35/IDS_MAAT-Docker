# -*- coding: utf-8 -*-
"""Las exclusiones del panel bajan a threshold.config, y SOLO las que caben exactas.

De donde sale: una exclusion se aplicaba despues de escribir la alerta. Suricata la
generaba, eve.json la guardaba, EveBox la ingeria, el generador la leia, el contador la
leia, y el panel la tiraba al final. La misma causa de tres problemas medidos esta semana
(eve.json a 445 MB/h, el contador atascado, EveBox borrando mil eventos por segundo). Con
threshold.config la alerta no llega a existir.

Lo que se protege, en orden:
  - que NO se amplie la exclusion por conveniencia. `suppress` no tiene puerto, y sin sid
    seria "esta IP nunca alerta de nada". Una exclusion por puerto o sin firma se queda en
    el panel; aqui solo bajan las que Suricata puede decir exactamente igual.
  - que una exclusion caducada no siga activa en el sensor: seria un falso negativo mudo.
  - que lo escrito a mano en threshold.config por el operador no se pise: el archivo es
    compartido y el bloque del panel va entre marcas.
  - que antes de recargar se valide con `suricata -T` y, si falla, se restaure lo anterior.
    Un threshold.config roto deja el sensor SIN NINGUNA regla.
"""
import ast
import ipaddress
import os
import sys
import unittest
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ

DASH = extraer.fuente("DASH")
ARBOL = ast.parse(DASH)

PIEZAS = ("THRESHOLD_FILE", "THRESHOLD_MARCA", "threshold_desde_exclusiones",
          "_threshold_fusionar")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def piezas():
    ns = {"time": time, "ipaddress": ipaddress}
    for n in ARBOL.body:
        nom = getattr(n, "name", None) or (
            getattr(n.targets[0], "id", "") if isinstance(n, ast.Assign) and n.targets else "")
        if nom in PIEZAS:
            exec(ast.get_source_segment(DASH, n) or "", ns)
    return ns


def regla(**k):
    base = {"tipo": "dst", "ip": "198.51.100.7", "motivo": "falso positivo CDN",
            "puertos": [], "sid": "2014169", "hasta": 0}
    base.update(k)
    return base


def main():
    ns = piezas()
    gen = ns["threshold_desde_exclusiones"]
    fus = ns["_threshold_fusionar"]

    # =====================================================================================
    # Lo que baja, y como
    # =====================================================================================
    out = gen([regla()])
    check("una exclusion con sid y sin puerto baja a suppress", len(out) == 1, out)
    check("con el sid exacto", "sig_id 2014169" in out[0], out)
    check("una exclusion de DESTINO rastrea por destino", "track by_dst" in out[0], out)
    check("con la IP", "ip 198.51.100.7" in out[0], out)
    check("y el motivo como comentario, para quien lea el archivo a mano",
          "# falso positivo CDN" in out[0], out)

    out = gen([regla(tipo="src", ip="10.0.0.5")])
    check("una exclusion de ORIGEN rastrea por origen", "track by_src" in out[0], out)
    out = gen([regla(ip="203.0.113.0/24")])
    check("un CIDR vale como IP", "ip 203.0.113.0/24" in out[0], out)

    # =====================================================================================
    # LO IMPORTANTE: no se amplia nada por conveniencia
    # =====================================================================================
    # suppress no tiene puerto: bajar esta exclusion silenciaria la firma en TODOS los
    # puertos, que es mas de lo que el operador pidio
    check("una exclusion por puerto NO baja: suppress no sabe de puertos",
          gen([regla(puertos=[443])]) == [], gen([regla(puertos=[443])]))
    # sin sid seria "esta IP nunca alerta de nada"
    check("una exclusion sin firma NO baja: seria silenciar la IP entera",
          gen([regla(sid="")]) == [], gen([regla(sid="")]))
    check("un sid que no es un numero tampoco",
          gen([regla(sid="ET DNS")]) == [], gen([regla(sid="ET DNS")]))

    # =====================================================================================
    # Una exclusion caducada no puede seguir activa en el sensor
    # =====================================================================================
    check("una exclusion vencida no baja (seria un falso negativo mudo)",
          gen([regla(hasta=time.time() - 60)]) == [], "")
    check("una vigente con fecha si", len(gen([regla(hasta=time.time() + 3600)])) == 1, "")

    # una IP rota de un feed o de un tecleo no puede romper el archivo entero
    check("una IP invalida se salta sin romper el resto",
          len(gen([regla(ip="no-es-ip"), regla()])) == 1, "")
    check("sin exclusiones, sin lineas", gen([]) == [] and gen(None) == [], "")

    # =====================================================================================
    # El archivo es compartido: lo del operador no se pisa
    # =====================================================================================
    a_mano = "# mi regla\nsuppress gen_id 1, sig_id 1, track by_src, ip 10.9.9.9\n"
    f1 = fus(a_mano, ["suppress gen_id 1, sig_id 2, track by_dst, ip 1.2.3.4"])
    check("lo escrito a mano se conserva", "ip 10.9.9.9" in f1, f1)
    check("y lo del panel entra entre marcas",
          ns["THRESHOLD_MARCA"] in f1 and "fin de lo generado" in f1 and "ip 1.2.3.4" in f1, f1)
    # regenerar REEMPLAZA el bloque; si lo anadiera, el archivo creceria con cada cambio
    f2 = fus(f1, ["suppress gen_id 1, sig_id 3, track by_dst, ip 5.6.7.8"])
    check("regenerar reemplaza el bloque, no lo apila",
          f2.count(ns["THRESHOLD_MARCA"]) == 1 and "ip 1.2.3.4" not in f2 and "ip 5.6.7.8" in f2,
          f2)
    check("y sigue sin tocar lo del operador", "ip 10.9.9.9" in f2, f2)
    f3 = fus(f2, [])
    check("sin exclusiones queda el bloque vacio, no desaparecen las marcas",
          ns["THRESHOLD_MARCA"] in f3 and "ip 5.6.7.8" not in f3, f3)
    check("desde un archivo vacio tambien funciona",
          "ip 1.2.3.4" in fus("", ["suppress gen_id 1, sig_id 2, track by_dst, ip 1.2.3.4"]), "")

    # (adaptada) Lo que hacia escribir_threshold() en el servidor viejo (suricata -T antes de
    # recargar, restaurar si falla, sin tocar nada si no cambio) y el threshold-file que activaba
    # el instalador pasan al orquestador: orden `punto.threshold {pid, contenido}` (CONTRATO-F2
    # §6), probada en tests/test_orq_threshold.py. Aqui queda lo que sigue siendo del panel:
    # que contenido se genera a partir de las exclusiones.

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion (prueba heredada de suricata-ids-lab). Las exclusiones del panel bajan a threshold.config, y SOLO las que caben exactas."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
