#!/bin/bash
# ids-maat — build local de una imagen con la base fijada en images/base.env (CONTRATO-F1a §6.3).
#   images/build.sh <vpn|suricata|panel> [etiqueta]   ->   ids-maat-<img>:<etiqueta|dev>
# Variables opcionales: VERSION (por defecto dev), DOCKER (por defecto docker).
# suricata: pasa --build-arg SURICATA_VERSION=<serie> (la del ARG del Dockerfile, p. ej. 7.0). La
# etiqueta ids-maat.suricata-version lleva esa serie; la versión exacta instalada solo se conoce
# dentro del build y queda en /usr/share/ids-maat/suricata-version, release.json y el MANIFEST.json.
set -euo pipefail
cd "$(dirname "$0")"
img="${1:-}"
etiqueta="${2:-dev}"
case "$img" in
  vpn|suricata|panel) ;;
  *) echo "uso: images/build.sh <vpn|suricata|panel> [etiqueta]" >&2; exit 2 ;;
esac
[[ "$etiqueta" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || { echo "etiqueta inválida: $etiqueta" >&2; exit 2; }
base=$(sed -n 's/^BASE_IMAGE=//p' base.env)
[[ "$base" =~ ^debian:trixie-slim@sha256:[0-9a-f]{64}$ ]] || { echo "base.env: BASE_IMAGE sin digest" >&2; exit 1; }
[ -f "$img/Dockerfile" ] || { echo "no existe images/$img/Dockerfile" >&2; exit 1; }
args=(--build-arg "BASE_IMAGE=$base" --build-arg "VERSION=${VERSION:-dev}")
if [ "$img" = suricata ]; then
  serie=$(sed -n 's/^ARG SURICATA_VERSION=//p' suricata/Dockerfile)
  [[ "$serie" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || { echo "suricata/Dockerfile: ARG SURICATA_VERSION sin serie" >&2; exit 1; }
  args+=(--build-arg "SURICATA_VERSION=$serie")
fi
exec "${DOCKER:-docker}" build "${args[@]}" -t "ids-maat-$img:$etiqueta" "$img"
