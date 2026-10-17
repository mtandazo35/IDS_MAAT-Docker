#!/bin/bash
# ids-maat — actualización desde el panel (botón «Actualizar», docs/ACTUALIZACIONES.md §4).
#
#   ids-actualizar.sh --pedido           lo que hace ids-actualizar.service: lee el pedido que dejó
#                                        ids-orq (orden sistema.actualizar) en
#                                        /srv/ids/estado/actualizar-pedido.json
#   ids-actualizar.sh <commit> [quién]   lo mismo a mano, como root (la cola de ids-orq no se pausa:
#                                        mejor desde el panel o con `ids-orq actualizar <commit>`)
#
# Lleva el PANEL y el ORQUESTADOR al commit pedido de la rama main de GitHub:
#   1. descarga el commit en /root/ids-maat/actualizar/src y comprueba que es de main;
#   2. valida que trae lo necesario y que ids_orq.py arranca;
#   3. construye la imagen del panel en este servidor (ids-maat-panel:main-<sha7>, sin firma);
#   4. respaldo verificado en /root/backups (sin la clave maestra) y copia de lo instalado;
#   5. instala el orquestador de ese commit (plantillas, unidades, logrotate y este script);
#   6. reinicia ids-orq y comprueba que contesta;
#   7. recrea el panel con la imagen nueva y espera a que esté sano.
# Si 5, 6 o 7 fallan, vuelve a lo que había. Los puntos (vpn y suricata) no se tocan: siguen con
# su imagen y su configuración hasta un `punto reconfigurar`.
# El avance queda en /srv/ids/run/actualizacion.json (el panel lo lee), el detalle en
# /root/ids-maat/actualizar/<ts>.log y el resultado en /srv/ids/estado/orq.jsonl.
set -uo pipefail     # sin -e: cada paso comprueba lo suyo y decide si hay que volver atrás

R="${IDS_RAIZ:-}"    # prefijo de rutas: solo las pruebas lo cambian
REPO_URL="${IDS_REPO_URL:-https://github.com/mtandazo35/IDS_MAAT-Docker.git}"
RAMA=main
GUARDA="$R/root/ids-maat/actualizar"
SRC="$GUARDA/src"
LIB="$R/usr/local/lib/ids-orq"
ETC="$R/etc/ids-maat"
SD="$R/etc/systemd/system"
PEDIDO="$R/srv/ids/estado/actualizar-pedido.json"
AVANCE="$R/srv/ids/run/actualizacion.json"
DIARIO="$R/srv/ids/estado/orq.jsonl"
BACKUPS="$R/root/backups"
IDS_ORQ="${IDS_ORQ_BIN:-$R/usr/local/bin/ids-orq}"
ESPERA_ORQ_S="${IDS_ESPERA_ORQ_S:-45}"
GID_PANEL=10500
TS=$(date -u +%Y%m%dT%H%M%SZ)
LOG="$GUARDA/$TS.log"

NOMBRES=("descargar el commit" "validar" "construir la imagen del panel" "respaldo"
         "instalar el orquestador" "reiniciar el orquestador" "recrear el panel")
ESTADOS=(pendiente pendiente pendiente pendiente pendiente pendiente pendiente)
P=0
COMMIT="" QUIEN="" ID="" DESDE="" SHA7="" IMG="" IMG_ANTES="" RESPALDO=""
INICIO=$(date +%s)

uso() { sed -n '2,24p' "$0"; }

log() {
  printf '%s\n' "$*"
  printf '%s %s\n' "$(date '+%F %T')" "$*" >> "$LOG" 2>/dev/null || true
}

escribir_avance() {   # $1 = en_curso | ok | revertida | fallo ; $2 = mensaje
  local i args=()
  for i in "${!NOMBRES[@]}"; do args+=("${NOMBRES[$i]}" "${ESTADOS[$i]}"); done
  python3 - "$AVANCE" "$1" "$2" "$ID" "$QUIEN" "$DESDE" "$COMMIT" "$INICIO" "$RESPALDO" "$GID_PANEL" \
      "${args[@]}" <<'PY' || log "aviso: no se pudo escribir el avance en $AVANCE"
import json, os, sys, time
ruta, estado, mensaje, ident, quien, desde, a, inicio, respaldo, gid = sys.argv[1:11]
pasos = [{"nombre": n, "estado": e} for n, e in zip(sys.argv[11::2], sys.argv[12::2])]
d = {"v": 1, "id": ident, "estado": estado, "mensaje": mensaje, "quien": quien, "desde": desde,
     "a": a, "inicio": int(inicio), "ts": int(time.time()), "respaldo": respaldo, "pasos": pasos}
if estado != "en_curso":
    d["fin"] = d["ts"]
os.makedirs(os.path.dirname(ruta), exist_ok=True)
tmp = ruta + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(d, f, ensure_ascii=False)
os.chmod(tmp, 0o640)
try:
    os.chown(tmp, 0, int(gid))       # /srv/ids/run es root:ids-panel 0750: el panel lo lee
except OSError:
    pass                             # pruebas sin root
os.replace(tmp, ruta)
PY
}

diario() {   # $1 = OK | REVERTIDA | FALLO ; $2 = mensaje
  local i args=()
  for i in "${!NOMBRES[@]}"; do args+=("${NOMBRES[$i]}:${ESTADOS[$i]}"); done
  python3 - "$DIARIO" "$1" "$2" "$ID" "$QUIEN" "$DESDE" "$COMMIT" "${args[@]}" <<'PY' || true
import json, sys, time
ruta, codigo, mensaje, ident, quien, desde, a = sys.argv[1:8]
linea = {"ts": int(time.time()), "op_id": ident, "quien": quien, "orden": "sistema.actualizar",
         "pid": None, "pasos": sys.argv[8:], "codigo": codigo, "mensaje": mensaje, "desde": desde, "a": a}
with open(ruta, "a", encoding="utf-8") as f:
    f.write(json.dumps(linea, ensure_ascii=False) + "\n")
PY
}

empezar() {   # $1 = índice del paso
  P=$1
  ESTADOS[$P]=en_curso
  log "== ${NOMBRES[$P]}"
  escribir_avance en_curso "${NOMBRES[$P]}…"
}

hecho() { ESTADOS[$P]=ok; }

abortar() {   # falló antes de tocar nada del sistema: no hay nada que deshacer
  ESTADOS[$P]=fallo
  log "FALLO en «${NOMBRES[$P]}»: $1 (no se cambió nada)"
  escribir_avance fallo "Falló «${NOMBRES[$P]}»: $1. No se cambió nada."
  diario FALLO "$1"
  exit 1
}

revertir() {   # falló después de tocar el sistema: vuelve a lo guardado en «anterior»
  local i motivo="$1"
  ESTADOS[$P]=fallo
  log "FALLO en «${NOMBRES[$P]}»: $motivo; volviendo a lo anterior"
  escribir_avance en_curso "Falló «${NOMBRES[$P]}»: $motivo. Volviendo a la versión anterior…"
  if restaurar_anterior; then
    for i in "${!ESTADOS[@]}"; do
      [ "$i" -ge 4 ] && [ "${ESTADOS[$i]}" = ok ] && ESTADOS[$i]=revertido
    done
    log "vuelta atrás hecha"
    escribir_avance revertida "Falló «${NOMBRES[$P]}»: $motivo. Se volvió a la versión anterior."
    diario REVERTIDA "$motivo"
    exit 1
  fi
  log "LA VUELTA ATRÁS TAMBIÉN FALLÓ: restaura $RESPALDO desde la consola"
  escribir_avance fallo "Falló «${NOMBRES[$P]}»: $motivo, y la vuelta atrás también falló. Restaura el respaldo $RESPALDO desde la consola del servidor."
  diario FALLO "$motivo; la vuelta atrás también falló"
  exit 2
}

leer_pedido() {
  local salida
  [ -f "$PEDIDO" ] || { echo "no hay pedido en $PEDIDO" >&2; exit 2; }
  salida=$(python3 - "$PEDIDO" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print(d.get("commit", ""))
print(d.get("quien", "") or "panel")
print(d.get("op_id", ""))
PY
  ) || { echo "pedido ilegible: $PEDIDO" >&2; exit 2; }
  COMMIT=$(sed -n 1p <<<"$salida")
  QUIEN=$(sed -n 2p <<<"$salida")
  ID=$(sed -n 3p <<<"$salida")
  rm -f "$PEDIDO"
}

lo_instalado() {   # commit (o versión) que hay ahora, para el «de X a Y» del panel
  python3 - "$ETC/imagenes.json" <<'PY' 2>/dev/null || true
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print(d.get("commit") or d.get("version") or "")
PY
}

panel_instalado() {
  python3 - "$ETC/imagenes.json" <<'PY' 2>/dev/null || true
import json, sys
print((json.load(open(sys.argv[1], encoding="utf-8")).get("imagenes") or {}).get("panel", ""))
PY
}

respaldar() {
  local f="$BACKUPS/ids-maat-actualizar-${TS}.tar.gz" rutas=() r
  install -d -m 0700 "$BACKUPS" || return 1
  # del panel, su configuración y sus registros (lo que una versión nueva podría reescribir); no
  # los informes, los feeds ni la GeoIP, que se regeneran solos
  for r in "$ETC" "$LIB" "$R/srv/ids/panel/conf" "$R/srv/ids/panel/estado" "$R/srv/ids/estado" "$R/srv/ids/pki" \
           "$R/srv/ids/puntos" "$R/srv/ids/fw" "$R/srv/ids/core" "$R/usr/local/bin/ids-orq"; do
    [ -e "$r" ] && rutas+=("$r")
  done
  ls "$SD"/ids-* >/dev/null 2>&1 && rutas+=("$SD"/ids-*)
  # la clave maestra NO va en el mismo tar que los secretos que cifra (OPERACION §3, B-06)
  (umask 077; tar -czf "$f" --exclude=ids-maat/master.key "${rutas[@]}" 2>>"$LOG") || return 1
  tar -tzf "$f" >/dev/null 2>&1 || return 1
  if tar -tzf "$f" | grep -E '(^|/)master\.key$' >/dev/null; then
    rm -f "$f"
    log "el respaldo llevaba la clave maestra: borrado"
    return 1
  fi
  RESPALDO="$f"
  log "respaldo: $f ($(du -h "$f" | cut -f1), sha256 $(sha256sum "$f" | cut -c1-16)…)"
  # se guardan los 5 últimos de esta herramienta; los demás respaldos no se tocan
  ls -1t "$BACKUPS"/ids-maat-actualizar-*.tar.gz 2>/dev/null | tail -n +6 | xargs -r rm -f --
}

guardar_anterior() {
  local d="$GUARDA/anterior"
  rm -rf "$d" && install -d -m 0700 "$d" "$d/systemd" || return 1
  cp -a "$ETC/imagenes.json" "$d/" || return 1
  cp -a "$LIB" "$d/ids-orq" || return 1
  cp -a "$SD"/ids-* "$d/systemd/" 2>/dev/null || true
  [ -f "$ETC/logrotate.conf" ] && { cp -a "$ETC/logrotate.conf" "$d/" || return 1; }
  return 0
}

instalar_fichero() {   # $1 = origen, $2 = destino, $3 = modo; con rename: el script en marcha no se pisa
  install -m "$3" "$1" "$2.nuevo" && mv -f "$2.nuevo" "$2"
}

poner_imagenes() {
  python3 - "$ETC/imagenes.json" "$SHA7" "$COMMIT" "$IMG" <<'PY'
import json, os, sys
p, sha7, commit, panel = sys.argv[1:5]
d = json.load(open(p, encoding="utf-8"))
d["dev"] = True                  # imagen del panel construida aquí, sin firma
d["version"] = "main-" + sha7
d["commit"] = commit
d.setdefault("imagenes", {})["panel"] = panel
t = p + ".tmp"
with open(t, "w", encoding="utf-8") as f:
    json.dump(d, f, indent=1)
os.chmod(t, 0o644)
os.replace(t, p)
PY
}

instalar_commit() {
  local u
  install -d -m 0755 "$LIB" "$LIB/plantillas" "$SD" || return 1
  instalar_fichero "$SRC/orquestador/ids_orq.py" "$LIB/ids_orq.py" 0755 || return 1
  instalar_fichero "$SRC/orquestador/ids-actualizar.sh" "$LIB/ids-actualizar.sh" 0755 || return 1
  install -m 0644 "$SRC"/orquestador/plantillas/*.tmpl "$LIB/plantillas/" || return 1
  for u in "$SRC"/host/systemd/*; do install -m 0644 "$u" "$SD/" || return 1; done
  install -m 0644 "$SRC/host/logrotate/ids-maat.conf" "$ETC/logrotate.conf" || return 1
  poner_imagenes >>"$LOG" 2>&1 || return 1
  systemctl daemon-reload >>"$LOG" 2>&1 || return 1
}

reiniciar_orq() {
  local i
  systemctl restart ids-orq >>"$LOG" 2>&1 || return 1
  for ((i = 0; i < ESPERA_ORQ_S; i++)); do
    "$IDS_ORQ" estado >/dev/null 2>>"$LOG" && return 0
    sleep 1
  done
  return 1
}

aplicar_panel() {
  "$IDS_ORQ" panel aplicar >>"$LOG" 2>&1
}

restaurar_anterior() {
  local d="$GUARDA/anterior"
  [ -d "$d/ids-orq" ] && [ -f "$d/imagenes.json" ] || return 1
  cp -a "$d/imagenes.json" "$ETC/imagenes.json.nuevo" && mv -f "$ETC/imagenes.json.nuevo" "$ETC/imagenes.json" || return 1
  # el directorio entero se cambia con rename: este script, si es el de $LIB, sigue leyendo el viejo
  rm -rf "$LIB.nuevo" && cp -a "$d/ids-orq" "$LIB.nuevo" || return 1
  rm -rf "$LIB" && mv "$LIB.nuevo" "$LIB" || return 1
  cp -a "$d/systemd/." "$SD/" 2>>"$LOG" || return 1
  if [ -f "$d/logrotate.conf" ]; then cp -a "$d/logrotate.conf" "$ETC/logrotate.conf" || return 1; fi
  systemctl daemon-reload >>"$LOG" 2>&1 || return 1
  reiniciar_orq || return 1
  aplicar_panel || return 1
}

# Lo del host que instala install.sh y este botón NO toca (fail2ban, journald, sysctl, módulos):
# si el commit lo trae distinto de lo instalado, se avisa al terminar (revisión 2026-10-15, R1).
# Solo compara lo que el commit trae. Imprime los nombres separados por «, » (nada = al día).
host_pendiente() {
  local dueno c=() IFS
  dueno=$(sed -n 's/^IGNOREIP_DUENO=//p' "$ETC/ids.conf" 2>/dev/null | head -n1)
  distinto() { [ -f "$1" ] && ! cmp -s "$1" "$2"; }
  if { [ -f "$SRC/host/fail2ban/jail.d/10-ids.local.tmpl" ] \
         && ! sed "s|@@IGNOREIP_DUENO@@|${dueno}|" "$SRC/host/fail2ban/jail.d/10-ids.local.tmpl" \
              | cmp -s - "$R/etc/fail2ban/jail.d/10-ids.local"; } \
     || distinto "$SRC/host/fail2ban/filter.d/ids-vpn.conf" "$R/etc/fail2ban/filter.d/ids-vpn.conf" \
     || distinto "$SRC/host/fail2ban/filter.d/sshd.local.tmpl" "$R/etc/fail2ban/filter.d/sshd.local"; then
    c+=(fail2ban)
  fi
  distinto "$SRC/host/journald/90-ids.conf" "$R/etc/systemd/journald.conf.d/90-ids.conf" && c+=(journald)
  distinto "$SRC/host/sysctl/90-ids.conf" "$R/etc/sysctl.d/90-ids.conf" && c+=(sysctl)
  distinto "$SRC/host/modules/ids.conf" "$R/etc/modules-load.d/ids.conf" && c+=("módulos del kernel")
  IFS=,
  printf '%s' "${c[*]}" | sed 's/,/, /g'
}

podar_imagenes() {   # quedan la imagen nueva y la anterior (para volver atrás a mano)
  local img
  docker image ls ids-maat-panel --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep ':main-' \
    | while read -r img; do
        [ "$img" = "$IMG" ] || [ "$img" = "$IMG_ANTES" ] && continue
        docker image rm "$img" >>"$LOG" 2>&1 && log "imagen vieja borrada: $img"
      done
  ls -1t "$GUARDA"/*.log 2>/dev/null | tail -n +11 | xargs -r rm -f --
  return 0
}

# ---- argumentos ------------------------------------------------------------------------------
case "${1:-}" in
  ""|-h|--help) uso; exit 0 ;;
  --pedido) leer_pedido ;;
  *) COMMIT="$1"; QUIEN="${2:-root}"; ID="manual-$TS" ;;
esac
[[ "$COMMIT" =~ ^[0-9a-f]{7,40}$ ]] || { echo "commit inválido: '$COMMIT' (7 a 40 hex en minúsculas)" >&2; exit 2; }
QUIEN=$(printf '%s' "$QUIEN" | tr -c 'A-Za-z0-9_:.@-' '_' | cut -c1-64)
[ "$(id -u)" = 0 ] || [ -n "$R" ] || { echo "hay que ser root" >&2; exit 2; }
command -v git >/dev/null || { echo "falta git (apt-get install git)" >&2; exit 2; }

install -d -m 0700 "$GUARDA" || exit 2
exec 9>"$GUARDA/.cerrojo"
flock -n 9 || { echo "ya hay una actualización en curso" >&2; exit 1; }
DESDE=$(lo_instalado)
IMG_ANTES=$(panel_instalado)
log "actualización $ID pedida por $QUIEN: ${DESDE:-?} -> $COMMIT"
escribir_avance en_curso "Empezando…"

# 1. descargar ------------------------------------------------------------------------------
empezar 0
if [ ! -d "$SRC/.git" ]; then
  rm -rf "$SRC"
  git clone -q --no-checkout "$REPO_URL" "$SRC" >>"$LOG" 2>&1 || abortar "no se pudo clonar $REPO_URL (¿sin salida a GitHub?)"
fi
git -C "$SRC" fetch -q --prune origin "+refs/heads/$RAMA:refs/remotes/origin/$RAMA" >>"$LOG" 2>&1 \
  || abortar "no se pudo descargar la rama $RAMA de GitHub"
COMPLETO=$(git -C "$SRC" rev-parse -q --verify "$COMMIT^{commit}" 2>>"$LOG") || abortar "el commit $COMMIT no está en GitHub"
git -C "$SRC" merge-base --is-ancestor "$COMPLETO" "origin/$RAMA" 2>>"$LOG" || abortar "el commit $COMMIT no es de la rama $RAMA"
git -C "$SRC" checkout -q --force --detach "$COMPLETO" >>"$LOG" 2>&1 || abortar "no se pudo preparar el commit"
git -C "$SRC" clean -q -fdx >>"$LOG" 2>&1 || true
COMMIT="$COMPLETO"
SHA7="${COMMIT:0:7}"
IMG="ids-maat-panel:main-$SHA7"
log "commit $SHA7: $(git -C "$SRC" log -1 --format=%s | cut -c1-100)"
hecho

# 2. validar --------------------------------------------------------------------------------
empezar 1
for f in orquestador/ids_orq.py orquestador/ids-actualizar.sh images/build.sh images/panel/Dockerfile \
         host/logrotate/ids-maat.conf host/systemd/ids-orq.service host/systemd/ids-actualizar.service; do
  [ -f "$SRC/$f" ] || abortar "al commit le falta $f"
done
ls "$SRC"/orquestador/plantillas/*.tmpl >/dev/null 2>&1 || abortar "al commit le faltan las plantillas del orquestador"
python3 "$SRC/orquestador/ids_orq.py" --help >/dev/null 2>>"$LOG" || abortar "el ids_orq.py del commit no arranca"
bash -n "$SRC/orquestador/ids-actualizar.sh" 2>>"$LOG" || abortar "el ids-actualizar.sh del commit tiene errores de sintaxis"
hecho

# 3. construir ------------------------------------------------------------------------------
empezar 2
log "construyendo $IMG (unos minutos)"
VERSION="main-$SHA7" bash "$SRC/images/build.sh" panel "main-$SHA7" >>"$LOG" 2>&1 \
  || abortar "falló la construcción de la imagen del panel (detalle en $LOG)"
hecho

# 4. respaldo -------------------------------------------------------------------------------
empezar 3
respaldar || abortar "no se pudo hacer el respaldo"
guardar_anterior || abortar "no se pudo guardar una copia de lo instalado"
hecho

# 5-7. instalar, reiniciar y recrear (con vuelta atrás) -------------------------------------
empezar 4
instalar_commit || revertir "no se pudo instalar el orquestador nuevo"
hecho
empezar 5
reiniciar_orq || revertir "ids-orq no contesta con el orquestador nuevo"
hecho
empezar 6
aplicar_panel || revertir "el panel nuevo no quedó sano"
hecho

podar_imagenes
log "listo: panel y orquestador en $SHA7"
PEND=$(host_pendiente || true)
if [ -n "$PEND" ]; then
  log "AVISO: host sin actualizar ($PEND): este botón no lo toca; vuelve a ejecutar install.sh"
  escribir_avance ok "Actualizado a $SHA7. Aviso: host sin actualizar ($PEND): vuelve a ejecutar install.sh."
  diario OK "actualizado a $SHA7; host sin actualizar ($PEND): vuelve a ejecutar install.sh"
else
  escribir_avance ok "Actualizado a $SHA7."
  diario OK "actualizado a $SHA7"
fi
exit 0
