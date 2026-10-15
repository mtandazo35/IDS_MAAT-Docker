#!/usr/bin/env python3
"""Base GeoIP del mapa: IPv4 -> país (DB-IP lite, CC-BY-4.0, vía sapics/ip-location-db).

ipv4.bin = [uint32 N][N x inicio u32][N x fin u32][N x 2 bytes ISO2], ordenada por inicio;
html_report.pais() la recorre con bisect. Hay dos copias:

- la de la IMAGEN (IDS_SHARE/geo/ipv4.bin): se construye al hacer la imagen con el CSV fijado por
  commit y SHA256 (`python3 geo_base.py imagen <salida>`). Con ella el mapa funciona desde el
  primer arranque y sin internet. Antes la base solo se bajaba en ejecución, y en la imagen sin
  ca-certificates esa descarga no funcionó nunca (lab .152, 2026-10-15: mapa vacío).
- la de EJECUCIÓN (PANEL/geo/ipv4.bin): el panel la renueva con la última publicada cada
  REFRESCO_S (DB-IP saca una al mes). Si está, manda sobre la de la imagen.

Para pasar la imagen a una base más nueva: `python3 geo_base.py fijar <commit>` comprueba ese CSV
e imprime las líneas COMMIT_IMAGEN y SHA256_IMAGEN que hay que pegar aquí.
"""
import array
import hashlib
import ipaddress
import os
import struct
import sys
import urllib.request

URL_PLANTILLA = ("https://raw.githubusercontent.com/sapics/ip-location-db/%s/"
                 "dbip-country/dbip-country-ipv4.csv")
URL_ULTIMA = URL_PLANTILLA % "main"
COMMIT_IMAGEN = "0446a112ca157c1cf0edae81e92da5200465505b"     # 2026-10-02, 362 108 rangos
SHA256_IMAGEN = "0de8ddf35f4d07c93c59809d226b8e055da54cff377c69b2cfb61c5a674f55c6"
MIN_RANGOS = 1000          # menos = descarga cortada o formato cambiado: no se instala
REFRESCO_S = 30 * 86400    # la de ejecución se renueva cada 30 días
TIMEOUT_S = 180


def construir(texto):
    """CSV «inicio,fin,ISO2» -> (rangos, bytes de ipv4.bin). ValueError si no vale."""
    filas = []
    for ln in texto.splitlines():
        p = ln.split(",")
        if len(p) < 3:
            continue
        cc = p[2].strip().upper()
        if len(cc) != 2 or not cc.isalpha():
            continue
        try:
            s = int(ipaddress.IPv4Address(p[0].strip()))
            e = int(ipaddress.IPv4Address(p[1].strip()))
        except ValueError:
            continue
        if e >= s:
            filas.append((s, e, cc))
    if len(filas) < MIN_RANGOS:
        raise ValueError("solo %d rangos (mínimo %d): descarga cortada o formato distinto"
                         % (len(filas), MIN_RANGOS))
    filas.sort()
    ini = array.array("I", [f[0] for f in filas])
    fin = array.array("I", [f[1] for f in filas])
    if ini.itemsize != 4:
        raise ValueError("array('I') no es de 4 bytes en esta plataforma")
    return len(filas), (struct.pack("<I", len(filas)) + ini.tobytes() + fin.tobytes()
                        + b"".join(f[2].encode("ascii") for f in filas))


def escribir(datos, destino):
    """ipv4.bin de forma atómica (.tmp + rename): un lector nunca ve una base a medias."""
    d = os.path.dirname(destino)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = destino + ".tmp"
    with open(tmp, "wb") as f:
        f.write(datos)
    os.replace(tmp, destino)


def bajar_crudo(url, timeout=TIMEOUT_S):
    r = urllib.request.urlopen(url, timeout=timeout)
    try:
        return r.read()
    finally:
        cerrar = getattr(r, "close", None)
        if cerrar:
            cerrar()


def bajar(url, sha256=None, timeout=TIMEOUT_S):
    """El CSV como texto. Con `sha256`, ValueError si no coincide: la imagen solo acepta el fijado."""
    crudo = bajar_crudo(url, timeout)
    if sha256 is not None:
        h = hashlib.sha256(crudo).hexdigest()
        if h != sha256:
            raise ValueError("SHA256 de %s = %s; se esperaba %s" % (url, h, sha256))
    return crudo.decode("utf-8", "replace")


def disponible(*rutas):
    """La primera ruta con una base no vacía, o None."""
    for ruta in rutas:
        try:
            if os.path.getsize(ruta) > 0:
                return ruta
        except OSError:
            continue
    return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 2 and argv[0] == "imagen":
        n, datos = construir(bajar(URL_PLANTILLA % COMMIT_IMAGEN, SHA256_IMAGEN))
        escribir(datos, argv[1])
        print("geo_base: %d rangos (DB-IP lite, ip-location-db %s) -> %s" % (n, COMMIT_IMAGEN[:7], argv[1]))
        return 0
    if len(argv) == 2 and argv[0] == "fijar":
        crudo = bajar_crudo(URL_PLANTILLA % argv[1])
        n, _ = construir(crudo.decode("utf-8", "replace"))
        print("# %d rangos" % n)
        print('COMMIT_IMAGEN = "%s"' % argv[1])
        print('SHA256_IMAGEN = "%s"' % hashlib.sha256(crudo).hexdigest())
        return 0
    sys.stderr.write("uso: geo_base.py imagen <salida> | fijar <commit>\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
