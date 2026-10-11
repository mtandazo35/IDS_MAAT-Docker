#!/usr/bin/env python3
"""Escribe release.json (CONTRATO-F1a §6.4) por stdout. Lo usa release.yml.

    release_json.py --version 0.1.0 --vpn ghcr.io/mtandazo35/ids-maat-vpn@sha256:… \
                    --suricata ghcr.io/mtandazo35/ids-maat-suricata@sha256:… \
                    --panel ghcr.io/mtandazo35/ids-maat-panel@sha256:… \
                    --tar ids-maat-host-0.1.0.tar.gz [--min-orq 0.1.0] [--suricata-version 7.0.10]

--suricata-version: versión exacta del paquete dentro de la imagen
(/usr/share/ids-maat/suricata-version); la etiqueta OCI ids-maat.suricata-version solo lleva la serie.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

RE_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def construir(version, vpn, suricata, panel, tar, min_orq=None, suricata_version=None):
    if not RE_VERSION.match(version):
        raise ValueError("versión inválida: %s" % version)
    if suricata_version is not None and not re.fullmatch(r"\d+\.\d+\.\d+", suricata_version):
        raise ValueError("versión de Suricata inválida: %r" % suricata_version)
    for parte, ref in (("vpn", vpn), ("suricata", suricata), ("panel", panel)):
        if not re.fullmatch(r"ghcr\.io/mtandazo35/ids-maat-%s@sha256:[0-9a-f]{64}" % parte, ref):
            raise ValueError("referencia de %s inválida: %s" % (parte, ref))
    tar = Path(tar)
    if tar.name != "ids-maat-host-%s.tar.gz" % version:
        raise ValueError("el tar debe llamarse ids-maat-host-%s.tar.gz" % version)
    sha = hashlib.sha256(tar.read_bytes()).hexdigest()
    d = {"v": 1, "version": version,
         "imagenes": {"vpn": vpn, "suricata": suricata, "panel": panel}}
    if suricata_version is not None:
        d["suricata_version"] = suricata_version
    d.update({"host_tar": {"nombre": tar.name, "sha256": sha},
              "min_orq": min_orq or version, "migraciones": []})
    return d


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--vpn", required=True)
    ap.add_argument("--suricata", required=True)
    ap.add_argument("--panel", required=True)
    ap.add_argument("--tar", required=True)
    ap.add_argument("--min-orq")
    ap.add_argument("--suricata-version")
    a = ap.parse_args(argv)
    try:
        d = construir(a.version, a.vpn, a.suricata, a.panel, a.tar, a.min_orq, a.suricata_version)
    except ValueError as e:
        print("release_json: %s" % e, file=sys.stderr)
        return 1
    print(json.dumps(d, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
