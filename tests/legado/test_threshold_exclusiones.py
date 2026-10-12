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

Adaptada al panel portado (CONTRATO-F2 §3 y §6): el threshold.config ya no es un fichero
compartido del servidor. Cada punto tiene el suyo (/srv/ids/puntos/<pid>/suricata/), el panel
genera su contenido ENTERO con `threshold_contenido(reglas, pid)` y el orquestador lo escribe
(`punto.threshold`). `_threshold_fusionar` (meter el bloque entre marcas conservando lo escrito
a mano) desaparece con el fichero compartido: las comprobaciones de «no pisar lo del operador»
pasan a «no mezclar lo de otro punto» (exclusiones con campo `nodo`, §3), y las de «el bloque
se reemplaza, no se apila» se hacen sobre el contenido por punto.
"""
import ipaddress
import os
import re
import sys
import unittest
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _comun  # noqa: E402  (pone tests/legado en sys.path)
import extraer  # noqa: E402
RAIZ = extraer.RAIZ

# THRESHOLD_FILE (/etc/suricata/threshold.config) ya no existe en el panel: el fichero es
# del punto y lo escribe el orquestador (§6). THRESHOLD_FIN es la marca de cierre que antes
# vivia dentro de _threshold_fusionar.
PIEZAS = ("THRESHOLD_MARCA", "THRESHOLD_FIN", "threshold_desde_exclusiones",
          "threshold_contenido")

fallos = 0


def check(d, c, e=""):
    global fallos
    print(("  OK   " if c else " FALLA ") + d + ("" if c else "  -> " + str(e)))
    if not c:
        fallos += 1


def piezas():
    return _comun.piezas({"time": time, "ipaddress": ipaddress, "re": re}, PIEZAS)


def regla(**k):
    base = {"tipo": "dst", "ip": "198.51.100.7", "motivo": "falso positivo CDN",
            "puertos": [], "sid": "2014169", "hasta": 0}
    base.update(k)
    return base


def main():
    ns = piezas()
    gen = ns["threshold_desde_exclusiones"]
    # (adaptada, §6) el contenido entero del threshold.config de un punto
    cont = ns["threshold_contenido"]

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
    # (adaptada, CONTRATO-F2 §3/§6) Cada punto tiene SU archivo: lo de otro no se mezcla
    # =====================================================================================
    # Antes el archivo era compartido con el operador y el panel fusionaba su bloque entre
    # marcas (_threshold_fusionar). Ahora cada punto tiene su threshold.config, lo escribe
    # entero el orquestador con lo que manda el panel, y lo que no debe pisarse es lo de los
    # OTROS puntos: una exclusion con `nodo` solo baja a ese punto; sin `nodo`, a todos.
    otra = regla(ip="192.0.2.99", sid="2000001", nodo="p002", motivo="solo en p002")
    f1 = cont([regla(ip="198.51.100.4", sid="2000002"), otra], "p001")
    check("lo de otro punto no entra en el archivo de este (antes: lo escrito a mano se conserva)",
          "ip 192.0.2.99" not in f1 and "ip 192.0.2.99" in cont([otra], "p002"), f1)
    check("y lo del panel entra entre marcas",
          f1.startswith(ns["THRESHOLD_MARCA"] + "\n") and "fin de lo generado" in f1
          and f1.endswith(ns["THRESHOLD_FIN"] + "\n") and "ip 198.51.100.4" in f1, f1)
    # regenerar REEMPLAZA el bloque; si lo anadiera, el archivo creceria con cada cambio
    f2 = cont([regla(ip="203.0.113.8", sid="2000003"), otra], "p001")
    check("regenerar reemplaza el bloque, no lo apila",
          f2.count(ns["THRESHOLD_MARCA"]) == 1 and "ip 198.51.100.4" not in f2
          and "ip 203.0.113.8" in f2, f2)
    check("y sigue sin mezclar lo del otro punto (antes: sin tocar lo del operador)",
          "ip 192.0.2.99" not in f2, f2)
    f3 = cont([otra], "p001")
    check("sin exclusiones queda el bloque vacio, no desaparecen las marcas",
          f3 == ns["THRESHOLD_MARCA"] + "\n" + ns["THRESHOLD_FIN"] + "\n", f3)
    check("desde un punto sin nada anterior (antes: desde un archivo vacio) tambien funciona",
          "ip 198.51.100.4" in cont([regla(ip="198.51.100.4", sid="2000002")], "p002")
          and cont(None, "p002") == f3, "")
    # el campo `nodo` (§3): vacio = todos los nodos; sin pid, todas (lo que hacia el original)
    check("una exclusion de un nodo solo baja a ese nodo",
          len(gen([regla(nodo="p001")], "p001")) == 1 and gen([regla(nodo="p001")], "p002") == [], "")
    check("con nodo vacio baja a todos",
          len(gen([regla(nodo="")], "p001")) == 1 and len(gen([regla(nodo="")], "p002")) == 1, "")
    check("sin pid se generan todas, como antes del multi-nodo",
          len(gen([regla(nodo="p001"), regla(nodo="p002"), regla()])) == 3, "")

    # (adaptada) Lo que hacia escribir_threshold() en el servidor viejo (suricata -T antes de
    # recargar, restaurar si falla, sin tocar nada si no cambio) y el threshold-file que activaba
    # el instalador pasan al orquestador: orden `punto.threshold {pid, contenido}` (CONTRATO-F2
    # §6), probada en tests/test_orq_threshold.py. Aqui queda lo que sigue siendo del panel:
    # que contenido se genera a partir de las exclusiones.

    print("\n" + ("TODO OK" if not fallos else "%d fallo(s)" % fallos))
    return 1 if fallos else 0



class Legado(unittest.TestCase):
    def test_legado(self):
        """Tipo: conservacion, adaptada (CONTRATO-F2 §3, §6): threshold.config por punto con threshold_contenido(reglas, pid) en vez de fusionar en un fichero compartido; exclusiones con campo `nodo`. Las exclusiones del panel bajan a threshold.config, y SOLO las que caben exactas."""
        _comun.correr_main(self, main)


if __name__ == "__main__":
    unittest.main()
