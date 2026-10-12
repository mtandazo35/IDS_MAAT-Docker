#!/bin/bash
# ids-maat — SOLO LABORATORIO: carga en este VPS un commit o rama del repo sin reinstalar, para ir
# viendo el trabajo en curso. Producción se actualiza por release firmada, nunca con esto.
#
#   bash lab-actualizar.sh <rama|commit> [--imagenes panel[,vpn][,suricata]]
#   bash lab-actualizar.sh --revertir          vuelve a lo que había antes de la última carga
#   bash lab-actualizar.sh --volver-a-release  vuelve a la release instalada (imagenes.json original)
#
# Qué hace: respaldo verificado en /root/backups; checkout del commit en /root/IDS_MAAT-Docker;
# construye las imágenes pedidas (por defecto solo el panel) con images/build.sh; instala el
# orquestador, sus plantillas, unidades y logrotate de ese commit; pone imagenes.json en modo dev con
# las imágenes locales (las demás siguen por digest); `ids-orq panel aplicar` y espera a que el panel
# esté sano. Los puntos y sus datos no se tocan.
set -euo pipefail

REPO_URL="https://github.com/mtandazo35/IDS_MAAT-Docker.git"
SRC=/root/IDS_MAAT-Docker
LIB=/usr/local/lib/ids-orq
ETC=/etc/ids-maat
GUARDA=/root/ids-maat/lab
TS=$(date -u +%Y%m%dT%H%M%SZ)

log() { printf '[lab %s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fallar() { printf '[lab] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fallar "hay que ser root"
[ -f "$ETC/imagenes.json" ] || fallar "no hay instalación de ids-maat ($ETC/imagenes.json)"

respaldar() {
  install -d -m 0700 /root/backups
  local f="/root/backups/ids-maat-lab-${TS}.tar.gz" rutas=() r
  for r in "$ETC" "$LIB" /srv/ids/panel /srv/ids/estado /srv/ids/puntos /srv/ids/fw /usr/local/bin/ids-orq; do
    [ -e "$r" ] && rutas+=("$r")
  done
  ls /etc/systemd/system/ids-* >/dev/null 2>&1 && rutas+=(/etc/systemd/system/ids-*)
  (umask 077; tar -czf "$f" "${rutas[@]}" 2>/dev/null) || fallar "no se pudo crear el respaldo"
  tar -tzf "$f" >/dev/null || fallar "el respaldo $f no se puede leer"
  log "respaldo: $f ($(du -h "$f" | cut -f1), sha256 $(sha256sum "$f" | cut -c1-16)…)"
}

guardar_estado() {     # $1 = destino (anterior | original)
  local d="$GUARDA/$1"
  rm -rf "$d"; install -d -m 0700 "$d"
  cp -a "$ETC/imagenes.json" "$d/"
  cp -a "$LIB" "$d/ids-orq"
  install -d "$d/systemd"; cp -a /etc/systemd/system/ids-* "$d/systemd/" 2>/dev/null || true
  [ -f "$ETC/logrotate.conf" ] && cp -a "$ETC/logrotate.conf" "$d/"
  return 0
}

restaurar_estado() {   # $1 = origen (anterior | original)
  local d="$GUARDA/$1"
  [ -d "$d" ] || fallar "no hay estado guardado en $d"
  respaldar
  cp -a "$d/imagenes.json" "$ETC/imagenes.json"
  rm -rf "$LIB"; cp -a "$d/ids-orq" "$LIB"
  cp -a "$d/systemd/." /etc/systemd/system/ 2>/dev/null || true
  [ -f "$d/logrotate.conf" ] && cp -a "$d/logrotate.conf" "$ETC/logrotate.conf"
  systemctl daemon-reload
  reiniciar_orq
  aplicar_panel
}

reiniciar_orq() {
  systemctl restart ids-orq
  for _ in $(seq 1 30); do
    [ -S /run/ids-orq/orq.sock ] && return 0
    sleep 1
  done
  fallar "ids-orq no levantó su socket en 30 s (journalctl -u ids-orq)"
}

aplicar_panel() {
  ids-orq panel aplicar
  local estado=""
  for _ in $(seq 1 60); do
    estado=$(docker inspect -f '{{.State.Health.Status}}' ids-core-panel 2>/dev/null || true)
    [ "$estado" = healthy ] && { log "panel sano"; return 0; }
    sleep 2
  done
  docker logs --tail 40 ids-core-panel 2>&1 | sed 's/^/[panel] /' >&2 || true
  fallar "el panel no quedó sano en 120 s (estado: ${estado:-desconocido}); vuelve con --revertir"
}

case "${1:-}" in
  ""|-h|--help) sed -n '2,13p' "$0"; exit 0 ;;
  --revertir) log "volviendo a lo anterior"; restaurar_estado anterior; exit 0 ;;
  --volver-a-release) log "volviendo a la release instalada"; restaurar_estado original; exit 0 ;;
esac

REF="$1"; shift
IMGS="panel"
while [ $# -gt 0 ]; do
  case "$1" in
    --imagenes) IMGS="${2:-}"; shift 2 ;;
    *) fallar "opción desconocida: $1" ;;
  esac
done
[[ "$REF" =~ ^[A-Za-z0-9._/-]{1,100}$ ]] || fallar "referencia inválida: $REF"
[[ "$IMGS" =~ ^(panel|vpn|suricata)(,(panel|vpn|suricata))*$ ]] || fallar "--imagenes: panel, vpn o suricata"

respaldar
[ -d "$GUARDA/original" ] || { guardar_estado original; log "guardada la release instalada en $GUARDA/original"; }
guardar_estado anterior

if [ ! -d "$SRC/.git" ]; then
  log "clonando $REPO_URL en $SRC"
  git clone -q "$REPO_URL" "$SRC"
fi
git -C "$SRC" fetch -q --prune origin
if git -C "$SRC" rev-parse -q --verify "origin/$REF^{commit}" >/dev/null; then
  git -C "$SRC" checkout -q --detach "origin/$REF"
else
  git -C "$SRC" checkout -q --detach "$REF"
fi
SHA=$(git -C "$SRC" rev-parse --short=7 HEAD)
log "commit $SHA ($(git -C "$SRC" log -1 --format=%s | cut -c1-70))"

declare -A REFS=()
IFS=, read -r -a lista <<< "$IMGS"
for img in "${lista[@]}"; do
  log "construyendo ids-maat-$img:lab-$SHA"
  VERSION="lab-$SHA" bash "$SRC/images/build.sh" "$img" "lab-$SHA" >/root/ids-maat/lab-build-"$img".log 2>&1 \
    || { tail -30 /root/ids-maat/lab-build-"$img".log >&2; fallar "falló la imagen $img (log en /root/ids-maat/lab-build-$img.log)"; }
  REFS[$img]="ids-maat-$img:lab-$SHA"
done

log "orquestador del commit $SHA"
install -m 0755 "$SRC/orquestador/ids_orq.py" "$LIB/ids_orq.py"
install -m 0644 "$SRC"/orquestador/plantillas/*.tmpl "$LIB/plantillas/"
for u in "$SRC"/host/systemd/*; do install -m 0644 "$u" /etc/systemd/system/; done
install -m 0644 "$SRC/host/logrotate/ids-maat.conf" "$ETC/logrotate.conf"
systemctl daemon-reload

python3 - "$ETC/imagenes.json" "$SHA" "${REFS[panel]:-}" "${REFS[vpn]:-}" "${REFS[suricata]:-}" <<'PY'
import json, os, sys
p, sha, panel, vpn, suri = sys.argv[1:6]
d = json.load(open(p, encoding="utf-8"))
d["dev"] = True
d["version"] = "lab-" + sha
for k, v in (("panel", panel), ("vpn", vpn), ("suricata", suri)):
    if v:
        d["imagenes"][k] = v
t = p + ".tmp"
with open(t, "w", encoding="utf-8") as f:
    json.dump(d, f, indent=1)
os.chmod(t, 0o644)
os.replace(t, p)
PY

reiniciar_orq
aplicar_panel
[ -n "${REFS[vpn]:-}${REFS[suricata]:-}" ] && log "aviso: vpn/suricata nuevos solo se usan al recrear cada punto"
log "listo: lab-$SHA. Para deshacer: bash $0 --revertir"
