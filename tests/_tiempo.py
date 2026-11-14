"""Umbrales de tiempo de las pruebas, a la medida de la máquina (QA T-14, 2026-11-14).

Las pruebas de «esto tiene que tardar menos de N s» usaban cifras fijas (1,0 o 1,5 s) en una VPS de
producción con Suricata en marcha: con carga fallaban sin que nada estuviera mal, y una prueba que
falla por eso enseña a ignorar los fallos. `tope(n)` multiplica el umbral por la carga media de la
máquina por núcleo (1 en un equipo tranquilo) o por IDS_FACTOR_TIEMPO, lo que sea mayor.

Solo para cotas SUPERIORES: una cota inferior («espera al menos 0,9 s») no se estira.
"""
import os


def factor():
    f = 1.0
    try:
        f = max(f, float(os.environ.get("IDS_FACTOR_TIEMPO") or 1))
    except ValueError:
        pass
    try:
        carga = os.getloadavg()[0] / max(1, os.cpu_count() or 1)
        f = max(f, 1.0 + carga)
    except (AttributeError, OSError):        # sin getloadavg (Windows)
        pass
    return f


def tope(segundos):
    """El umbral superior de una prueba de tiempo, estirado según la carga de la máquina."""
    return segundos * factor()
