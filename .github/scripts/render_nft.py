#!/usr/bin/env python3
"""Renderiza los .nft del repo en un directorio para `nft -c` en CI (job lint):
ids_host.nft del orquestador (vacío y con puntos) y, si existe render.py de la imagen vpn, las
tablas inet ids_punto y netdev ids_mon con el entorno del ejemplo del contrato.

    render_nft.py <directorio>
"""

import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
IDS_CONF = """VERSION=0.1.0
NOMBRE_DNS=ids.empresa.example
TUN_BASE=100.64
REDES_GESTION=192.0.2.0/25,198.51.100.0/26
IPS_PROXY=203.0.113.50
IGNOREIP_DUENO=203.0.113.20
PUERTO_PANEL=5637
POOL_DOCKER=10.210.0.0/16
"""
ENTORNO_VPN = {"PUNTO": "p003", "N": "3", "TUN_NET": "100.64.3.0/24", "TUN_SENSOR": "100.64.3.1",
               "TUN_MK": "100.64.3.2", "API_PUERTO": "8729", "TZSP_PUERTO": "37008", "TZSP_BYTES": "10000",
               "TZ": "UTC"}


def cargar_orq():
    spec = importlib.util.spec_from_file_location("ids_orq_ci", REPO / "orquestador" / "ids_orq.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    destino = Path(argv[0])
    destino.mkdir(parents=True, exist_ok=True)
    escritos = []
    with tempfile.TemporaryDirectory() as raiz:
        antes = os.environ.get("IDS_RAIZ")
        os.environ["IDS_RAIZ"] = raiz
        try:
            etc = Path(raiz, "etc", "ids-maat")
            etc.mkdir(parents=True)
            (etc / "ids.conf").write_text(IDS_CONF, encoding="utf-8")
            mod = cargar_orq()
            cfg = mod.config()
            for nombre, puertos, origenes in (("ids_host-vacio.nft", [], []),
                                              ("ids_host-puntos.nft", [1194, 1196],
                                               [("p003", 1196, "203.0.113.45")])):
                (destino / nombre).write_text(mod.render_nft(cfg, puertos, origenes), encoding="utf-8")
                escritos.append(nombre)
        finally:
            if antes is None:
                os.environ.pop("IDS_RAIZ", None)
            else:
                os.environ["IDS_RAIZ"] = antes
    render = REPO / "images" / "vpn" / "rootfs" / "usr" / "local" / "lib" / "ids-vpn" / "render.py"
    if render.exists():
        env = dict(os.environ, **ENTORNO_VPN)
        for orden, nombre in (("nft-punto", "ids_punto.nft"), ("nft-mon", "ids_mon.nft")):
            r = subprocess.run([sys.executable, str(render), orden], env=env, capture_output=True, text=True)
            if r.returncode != 0:
                print("render.py %s falló: %s" % (orden, r.stderr), file=sys.stderr)
                return 1
            (destino / nombre).write_text(r.stdout, encoding="utf-8")
            escritos.append(nombre)
    print(" ".join(escritos))
    return 0


if __name__ == "__main__":
    sys.exit(main())
