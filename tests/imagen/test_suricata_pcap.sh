#!/usr/bin/env bash
# test_suricata_pcap.sh — CONTRATO-F1a §8.2 (B).
# suricata -r tests/fixtures/suricata/alerta-2100498.pcap con la plantilla de la imagen
# renderizada da la alerta 2100498 con host = SENSOR_NAME, y eve.json sale 0640 (umask 027).
# Las reglas son una release mínima hecha aquí (la regla GPL del fixture + local.rules de la
# imagen + dataset vacío), así que no necesita red.
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
FIX="$REPO/tests/fixtures/suricata"
TS="20261010T081500Z"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
chmod 0755 "$TMP"

fallo() { echo "FALLO: $*" >&2; exit 1; }

# --- release mínima: /reglas/current -> releases/<ts>
REL="$TMP/reglas/releases/$TS"
mkdir -p "$REL/reducido" "$REL/feeds" "$TMP/conf"
ln -s "releases/$TS" "$TMP/reglas/current"
grep -F 'sid:2100498;' "$FIX/et/rules/emerging-attack_response.rules" > "$REL/reducido/suricata.rules"
sed "s#@@DATASET@@#/reglas/releases/$TS/feeds/domains.dataset#" \
  "$REPO/images/suricata/rootfs/usr/share/ids-maat/local.rules.tmpl" > "$REL/reducido/local.rules"
: > "$REL/feeds/domains.dataset"
docker run --rm --entrypoint cat "$IMG" /etc/suricata/classification.config > "$REL/reducido/classification.config"
chmod -R a+rX "$TMP/reglas"

# --- yaml del punto con la plantilla de la imagen (no la del repo: la que va a correr)
docker run --rm --entrypoint cat "$IMG" /usr/share/ids-maat/suricata.yaml.tmpl > "$TMP/plantilla.tmpl"
docker run --rm --entrypoint cat "$IMG" /usr/share/ids-maat/plantilla.json > "$TMP/plantilla.json"
if docker run --rm --entrypoint /usr/bin/suricata "$IMG" --build-info | grep -E 'Hyperscan support: *yes' >/dev/null; then
  MPM=hs; SPM=hs
else
  MPM=ac-ks; SPM=bm
fi
"$PY" "$REPO/tests/_ayuda_suricata.py" render --plantilla "$TMP/plantilla.tmpl" \
  --manifiesto "$TMP/plantilla.json" --salida "$TMP/conf/suricata.yaml" \
  --valor SENSOR_NAME=p003 --valor "HOME_NET=[10.0.0.0/24]" \
  --valor RULE_PATH=/reglas/current/reducido --valor "MPM_ALGO=$MPM" --valor "SPM_ALGO=$SPM"
printf '# ids-maat p003 — generado por ids-orq; no editar\n' > "$TMP/conf/threshold.config"
chmod -R a+rX "$TMP/conf"

# --- suricata -r con umask 027, como el entrypoint; eve en un tmpfs del contenedor.
# Con -r Suricata corre en modo USER y, sin -l, ignora default-log-dir y escribe en el
# directorio actual («.», la raíz de solo lectura). En producción (--af-packet, modo SYSTEM)
# vale el default-log-dir de la plantilla; aquí se le da el mismo directorio con -l.
# El `runmode: workers` de la plantilla es para af-packet; PCAP_FILE solo tiene single y autofp.
DENTRO=$(cat <<'SH'
umask 027
mkdir -p /run/suricata
/usr/bin/suricata -c /etc/ids/suricata/suricata.yaml -r /pcap/alerta-2100498.pcap \
  -l /var/log/suricata --runmode single --pidfile /run/suricata.pid > /tmp/suricata.out 2>&1
rc=$?
echo "=== RC $rc"
[ "$rc" -eq 0 ] || cat /tmp/suricata.out
echo "=== MODO $(stat -c %a /var/log/suricata/eve.json)"
echo "=== EVE"
cat /var/log/suricata/eve.json
SH
)
set +e
docker run --rm --network none --read-only \
  --tmpfs /tmp:size=64m --tmpfs /run:size=8m --tmpfs /var/log/suricata:size=64m,mode=2750 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  -v "$TMP/reglas:/reglas:ro" -v "$TMP/conf:/etc/ids/suricata:ro" -v "$FIX:/pcap:ro" \
  --entrypoint /bin/sh "$IMG" -c "$DENTRO" > "$TMP/salida.txt" 2>&1
set -e

grep -E '^=== (RC|MODO)' "$TMP/salida.txt" || true
grep -q '^=== RC 0$' "$TMP/salida.txt" || { cat "$TMP/salida.txt"; fallo "suricata -r falló"; }
grep -q '^=== MODO 640$' "$TMP/salida.txt" || fallo "eve.json no sale 0640"
"$PY" - "$TMP/salida.txt" <<'PY' || fallo "no está la alerta 2100498 con host p003"
import json, sys
eve = open(sys.argv[1], encoding="utf-8").read().split("=== EVE\n", 1)[1]
alertas = []
for l in eve.splitlines():
    try:
        ev = json.loads(l)
    except ValueError:
        continue
    if ev.get("event_type") == "alert":
        alertas.append((ev["alert"]["signature_id"], ev.get("host")))
print("alertas:", alertas)
sys.exit(0 if (2100498, "p003") in alertas else 1)
PY

echo "OK test_suricata_pcap"
