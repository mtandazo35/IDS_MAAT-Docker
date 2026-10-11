#!/usr/bin/env bash
# test_suricata_reglas.sh — CONTRATO-F1a §5.9 y §8.2 (B).
# `ids-reglas descargar` real (ET Open y feeds de verdad, necesita red) en un contenedor
# efímero como el que lanza el orquestador, y `suricata -T` de los dos perfiles con el yaml de
# validación (SENSOR_NAME=validacion, HOME_NET=[10.0.0.0/8], RULE_PATH=/reglas/releases/<ts>/<perfil>).
# Necesita Docker Linux e IDS_IMG_SURICATA; si no, sale con 77 (OMITIDA).
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
PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || { echo "OMITIDA: falta python3"; exit 77; }

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
TMP="$(mktemp -d)"
# lo que escribe el contenedor es de root: se borra con otro contenedor
trap 'docker run --rm -v "$TMP:/x" --entrypoint /bin/rm "$IMG" -rf /x/reglas >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT
chmod 0755 "$TMP"
mkdir -p "$TMP/reglas"
chmod 0777 "$TMP/reglas"          # el root del contenedor no tiene DAC_OVERRIDE

fallo() { echo "FALLO: $*" >&2; exit 1; }

# --- descarga (exactamente como CONTRATO §5.9)
set +e
docker run --rm --name "ids-reglas-$TS" --network bridge --read-only --tmpfs /tmp:size=512m \
  --cap-drop ALL --security-opt no-new-privileges:true --memory 1g --memory-swap 1g \
  -v "$TMP/reglas:/reglas" --entrypoint /usr/local/bin/ids-reglas \
  "$IMG" descargar --ts "$TS" > "$TMP/descarga.out" 2> "$TMP/descarga.err"
rc=$?
set -e
tail -n 20 "$TMP/descarga.err" || true
[ "$rc" -eq 0 ] || fallo "ids-reglas descargar salió con $rc"

REL="$TMP/reglas/releases/$TS"
[ -f "$REL/LISTO" ] || fallo "falta LISTO"
[ ! -e "$TMP/reglas/current" ] || fallo "ids-reglas no debe crear current"
"$PY" - "$TMP/descarga.out" "$REL" <<'PY' || fallo "resumen o MANIFEST incorrectos"
import json, os, sys
salida, rel = sys.argv[1], sys.argv[2]
ultima = json.loads(open(salida, encoding="utf-8").read().strip().splitlines()[-1])
assert ultima["ok"] is True, ultima
listo = json.loads(open(os.path.join(rel, "LISTO"), encoding="utf-8").read())
assert listo == ultima
m = json.load(open(os.path.join(rel, "MANIFEST.json"), encoding="utf-8"))
assert set(m) == {"v", "ts", "suricata_version", "imagen", "fuentes", "reglas", "dominios"}, m
assert m["suricata_version"].startswith("7.0."), m["suricata_version"]
assert m["fuentes"][0]["nombre"] == "et-open" and m["fuentes"][0]["sha256"], m["fuentes"][0]
assert m["reglas"]["completo"] > m["reglas"]["reducido"] > 1000, m["reglas"]
print("MANIFEST:", json.dumps({k: m[k] for k in ("ts", "suricata_version", "reglas", "dominios")}))
PY
for p in completo reducido; do
  grep -qE '^alert .*sid: ?2100498;' "$REL/$p/suricata.rules" || fallo "sid 2100498 no está activo en $p"
  [ -f "$REL/$p/classification.config" ] || fallo "$p sin classification.config"
done
[ -f "$REL/feeds/domains.dataset" ] || fallo "falta domains.dataset"

# --- validación con suricata -T de los dos perfiles (como hace el orquestador)
docker run --rm --entrypoint cat "$IMG" /usr/share/ids-maat/suricata.yaml.tmpl > "$TMP/plantilla.tmpl"
docker run --rm --entrypoint cat "$IMG" /usr/share/ids-maat/plantilla.json > "$TMP/plantilla.json"
if docker run --rm --entrypoint /usr/bin/suricata "$IMG" --build-info | grep -qE 'Hyperscan support: *yes'; then
  MPM=hs; SPM=hs
else
  MPM=ac-ks; SPM=bm
fi
for p in completo reducido; do
  V="$TMP/val-$p"
  mkdir -p "$V"
  "$PY" "$REPO/tests/_ayuda_suricata.py" render --plantilla "$TMP/plantilla.tmpl" \
    --manifiesto "$TMP/plantilla.json" --salida "$V/suricata.yaml" \
    --valor SENSOR_NAME=validacion --valor "HOME_NET=[10.0.0.0/8]" \
    --valor "RULE_PATH=/reglas/releases/$TS/$p" --valor "MPM_ALGO=$MPM" --valor "SPM_ALGO=$SPM"
  : > "$V/threshold.config"
  chmod -R a+rX "$V"
  echo "--- suricata -T perfil $p"
  docker run --rm --network none --read-only --tmpfs /tmp:size=64m --tmpfs /run:size=8m \
    --cap-drop ALL --security-opt no-new-privileges:true --memory 2g --memory-swap 2g \
    -v "$TMP/reglas:/reglas:ro" -v "$V:/etc/ids/suricata:ro" \
    --entrypoint /usr/bin/suricata "$IMG" -T -c /etc/ids/suricata/suricata.yaml -l /tmp \
    || fallo "suricata -T del perfil $p"
done

echo "OK test_suricata_reglas ($TS)"
