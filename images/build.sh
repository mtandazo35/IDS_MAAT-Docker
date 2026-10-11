#!/bin/bash
# ids-maat — build local de una imagen con la base fijada en images/base.env (CONTRATO-F1a §6.3).
#   images/build.sh <vpn|suricata> [etiqueta]   ->   ids-maat-<img>:<etiqueta|dev>
# Variables opcionales: VERSION (por defecto dev), DOCKER (por defecto docker).
set -euo pipefail
cd "$(dirname "$0")"
img="${1:-}"
etiqueta="${2:-dev}"
case "$img" in
  vpn|suricata) ;;
  *) echo "uso: images/build.sh <vpn|suricata> [etiqueta]" >&2; exit 2 ;;
esac
[[ "$etiqueta" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || { echo "etiqueta inválida: $etiqueta" >&2; exit 2; }
base=$(sed -n 's/^BASE_IMAGE=//p' base.env)
[[ "$base" =~ ^debian:trixie-slim@sha256:[0-9a-f]{64}$ ]] || { echo "base.env: BASE_IMAGE sin digest" >&2; exit 1; }
[ -f "$img/Dockerfile" ] || { echo "no existe images/$img/Dockerfile" >&2; exit 1; }
exec "${DOCKER:-docker}" build --build-arg "BASE_IMAGE=$base" --build-arg "VERSION=${VERSION:-dev}" \
  -t "ids-maat-$img:$etiqueta" "$img"
