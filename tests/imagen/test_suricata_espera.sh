#!/usr/bin/env bash
# test_suricata_espera.sh — CONTRATO-F1a §5.2 y §8.2 (B).
# Sin ids-mon (red none) y con IDS_ESPERA_MON_S=3, el contenedor sale con 1 en ~3 s y con el
# mensaje del contrato. Necesita Docker Linux e IDS_IMG_SURICATA; si no, sale con 77 (OMITIDA).
set -euo pipefail

IMG="${IDS_IMG_SURICATA:-}"
if [ -z "$IMG" ] || ! command -v docker >/dev/null 2>&1; then
  echo "OMITIDA: hace falta docker e IDS_IMG_SURICATA"
  exit 77
fi
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "OMITIDA: no existe la imagen $IMG"
  exit 77
fi

fallo() { echo "FALLO: $*" >&2; exit 1; }

t0=$(date +%s)
set +e
salida=$(docker run --rm --network none --read-only \
  --tmpfs /tmp:size=64m --tmpfs /run:size=8m \
  --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
  --security-opt no-new-privileges:true \
  -e PUNTO=p003 -e IDS_ESPERA_MON_S=3 -e TZ=UTC \
  "$IMG" 2>&1)
rc=$?
set -e
dur=$(( $(date +%s) - t0 ))

echo "$salida"
[ "$rc" -eq 1 ] || fallo "código de salida $rc (se esperaba 1)"
grep -qF "entrypoint-suricata: ids-mon no existe tras 3 s" <<<"$salida" \
  || fallo "falta el mensaje de espera"
[ "$dur" -ge 3 ] || fallo "salió en $dur s, antes de esperar 3 s"
[ "$dur" -le 30 ] || fallo "tardó $dur s"

# Entorno inválido: sale con 1 al momento, sin esperar.
set +e
salida=$(docker run --rm --network none --read-only --tmpfs /tmp:size=64m --tmpfs /run:size=8m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  -e PUNTO=norte -e IDS_ESPERA_MON_S=3 "$IMG" 2>&1)
rc=$?
set -e
[ "$rc" -eq 1 ] || fallo "con PUNTO inválido salió con $rc"
grep -qF "PUNTO" <<<"$salida" || fallo "sin mensaje claro para PUNTO inválido"

echo "OK test_suricata_espera ($dur s)"
