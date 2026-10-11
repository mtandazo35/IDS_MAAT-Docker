#!/usr/bin/env python3
"""Comprueba que las imágenes de GHCR se descargan SIN credenciales. Lo usa release.yml.

    ghcr_publico.py [--estricto] <etiqueta> <img> [<img>…]      (img: panel, vpn, suricata)

Los paquetes de GHCR nacen privados aunque el repositorio sea público, y la API REST de GitHub no
permite cambiar la visibilidad de un paquete de una cuenta de usuario: se hace UNA vez en la web
(https://github.com/users/<owner>/packages/container/<paquete>/settings → Danger Zone → Change
visibility → Public). Este script lo detecta: por cada paquete privado imprime un `::warning::`
con el enlace y lo añade a GITHUB_STEP_SUMMARY. Con --estricto sale con 1 si alguno es privado.
"""

import json
import os
import sys
import urllib.error
import urllib.request

OWNER = "mtandazo35"
ACEPTA = ", ".join(["application/vnd.oci.image.index.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json"])


def ajustes(nombre):
    return "https://github.com/users/%s/packages/container/ids-maat-%s/settings" % (OWNER, nombre)


def es_publico(nombre, etiqueta, abrir=urllib.request.urlopen):
    """True si un cliente anónimo obtiene el manifiesto de ghcr.io/<owner>/ids-maat-<nombre>:<etiqueta>."""
    repo = "%s/ids-maat-%s" % (OWNER, nombre)
    try:
        with abrir(urllib.request.Request(
                "https://ghcr.io/token?scope=repository:%s:pull&service=ghcr.io" % repo), timeout=30) as r:
            token = json.loads(r.read().decode("utf-8")).get("token", "")
        if not token:
            return False
        req = urllib.request.Request("https://ghcr.io/v2/%s/manifests/%s" % (repo, etiqueta), method="HEAD",
                                     headers={"Authorization": "Bearer " + token, "Accept": ACEPTA})
        with abrir(req, timeout=30) as r:
            return 200 <= r.status < 300
    except urllib.error.HTTPError as e:
        if e.code in (401, 403, 404):
            return False
        raise


def main(argv=None, abrir=urllib.request.urlopen, salida=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    salida = salida or sys.stdout
    estricto = "--estricto" in argv
    argv = [x for x in argv if x != "--estricto"]
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    etiqueta, imgs = argv[0], argv[1:]
    privados = []
    for img in imgs:
        if es_publico(img, etiqueta, abrir):
            print("ids-maat-%s:%s es público" % (img, etiqueta), file=salida)
        else:
            privados.append(img)
            print("::warning title=GHCR privado::ids-maat-%s es privado: el VPS no podrá descargarlo. "
                  "Hazlo público una vez en %s (Danger Zone > Change visibility > Public)"
                  % (img, ajustes(img)), file=salida)
    resumen = os.environ.get("GITHUB_STEP_SUMMARY")
    if resumen and privados:
        with open(resumen, "a", encoding="utf-8") as f:
            f.write("### Paquetes de GHCR privados\n\nEl instalador los descarga sin credenciales: "
                    "hazlos públicos una vez (Danger Zone > Change visibility > Public).\n\n")
            for img in privados:
                f.write("- [ids-maat-%s](%s)\n" % (img, ajustes(img)))
    return 1 if (privados and estricto) else 0


if __name__ == "__main__":
    sys.exit(main())
