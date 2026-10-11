#!/bin/bash
# Pruebas de install.sh SIN instalar nada (CONTRATO-F1a §8.2): bash -n, validación de argumentos y
# trozos ejecutables con las órdenes del sistema simuladas bajo un IDS_RAIZ temporal.
set -u
cd "$(dirname "$0")/.." || exit 1
CHECKOUT="$PWD"
FALLOS=0
ok()  { echo "  ok   $*"; }
mal() { echo "  MAL  $*"; FALLOS=$((FALLOS + 1)); }
esperar() {   # esperar <rc esperado> <descripción> <orden…>
  local esp="$1" desc="$2" rc
  shift 2
  "$@" >"$T/salida" 2>&1
  rc=$?
  if [ "$rc" = "$esp" ]; then ok "$desc"; else mal "$desc (rc=$rc, se esperaba $esp)"; sed 's/^/        /' "$T/salida"; fi
}

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
WINDOWS=0
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) WINDOWS=1 ;; esac
PY=""
for c in python3 python "py -3"; do
  # shellcheck disable=SC2086
  if $c -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then PY="$c"; break; fi
done

echo "== install.sh: sintaxis"
if bash -n install.sh; then ok "bash -n install.sh"; else mal "bash -n install.sh"; fi

echo "== install.sh: argumentos (--solo-validar)"
V=(--version v0.1.0 --nombre ids.empresa.example --gestion 192.0.2.0/25,198.51.100.0/26 --proxy 203.0.113.50)
export IDS_RAIZ="$T/vacio"
mkdir -p "$IDS_RAIZ"
esperar 0 "argumentos del ejemplo del contrato"            bash install.sh --solo-validar "${V[@]}"
esperar 0 "con --tun-base 198.18 y --dueno-ip"             bash install.sh --solo-validar "${V[@]}" --tun-base 198.18 --dueno-ip 203.0.113.20
esperar 0 "formato --opcion=valor"                         bash install.sh --solo-validar --version=v0.1.0 --nombre=ids.empresa.example --gestion=192.0.2.0/25 --proxy=203.0.113.50
esperar 0 "proxy /28 y dos proxies"                        bash install.sh --solo-validar "${V[@]}" --proxy 203.0.113.48/28,203.0.113.70
esperar 0 "--help"                                         bash install.sh --help
esperar 1 "sin --gestion"                                  bash install.sh --solo-validar --version v0.1.0 --nombre ids.empresa.example --proxy 203.0.113.50
esperar 1 "sin --proxy"                                    bash install.sh --solo-validar --version v0.1.0 --nombre ids.empresa.example --gestion 192.0.2.0/25
esperar 1 "gestión más ancha que /16"                      bash install.sh --solo-validar "${V[@]}" --gestion 10.0.0.0/8
esperar 1 "gestión 0.0.0.0/0"                              bash install.sh --solo-validar "${V[@]}" --gestion 0.0.0.0/0
esperar 1 "gestión solapa con la base 100.64"              bash install.sh --solo-validar "${V[@]}" --gestion 100.64.5.0/24
esperar 1 "gestión solapa con la base 198.18"              bash install.sh --solo-validar "${V[@]}" --gestion 198.18.0.0/24 --tun-base 198.18
esperar 0 "198.18 en gestión vale con base 100.64"         bash install.sh --solo-validar "${V[@]}" --gestion 198.18.0.0/24
esperar 1 "gestión solapa con el pool de Docker"           bash install.sh --solo-validar "${V[@]}" --gestion 10.210.8.0/24
esperar 1 "dos redes de gestión que se solapan"            bash install.sh --solo-validar "${V[@]}" --gestion 192.0.2.0/25,192.0.2.64/26
esperar 1 "gestión con octeto > 255"                       bash install.sh --solo-validar "${V[@]}" --gestion 192.0.300.0/24
esperar 1 "proxy más ancho que /28"                        bash install.sh --solo-validar "${V[@]}" --proxy 203.0.113.0/24
esperar 1 "proxy inválido"                                 bash install.sh --solo-validar "${V[@]}" --proxy 203.0.113.500
esperar 1 "tun-base inválida"                              bash install.sh --solo-validar "${V[@]}" --tun-base 10.0
esperar 1 "nombre con espacio"                             bash install.sh --solo-validar "${V[@]}" --nombre "ids empresa"
esperar 1 "nombre sin dominio"                             bash install.sh --solo-validar "${V[@]}" --nombre ids
esperar 1 "versión sin v"                                  bash install.sh --solo-validar "${V[@]}" --version 0.1.0
esperar 1 "dueño inválido"                                 bash install.sh --solo-validar "${V[@]}" --dueno-ip 203.0.113
esperar 1 "--imagenes sin --desde-repo"                    bash install.sh --solo-validar "${V[@]}" --imagenes vpn=a,suricata=b
esperar 1 "opción desconocida"                             bash install.sh --solo-validar "${V[@]}" --nada
esperar 1 "opción sin valor"                               bash install.sh --solo-validar "${V[@]}" --proxy
esperar 0 "laboratorio --desde-repo (versión del repo)"    bash install.sh --solo-validar --nombre ids.empresa.example --gestion 192.0.2.0/25 --proxy 203.0.113.50 --desde-repo "$CHECKOUT" --imagenes vpn=ids-maat-vpn:ci,suricata=ids-maat-suricata:ci
esperar 1 "--desde-repo sin --imagenes"                    bash install.sh --solo-validar --nombre ids.empresa.example --gestion 192.0.2.0/25 --proxy 203.0.113.50 --desde-repo "$CHECKOUT"
esperar 1 "--desde-repo que no es el repo"                 bash install.sh --solo-validar --nombre ids.empresa.example --gestion 192.0.2.0/25 --proxy 203.0.113.50 --desde-repo "$T" --imagenes vpn=a,suricata=b
esperar 1 "--imagenes con referencia peligrosa"            bash install.sh --solo-validar --nombre ids.empresa.example --gestion 192.0.2.0/25 --proxy 203.0.113.50 --desde-repo "$CHECKOUT" --imagenes 'vpn=-v /:/x,suricata=b'

# ---------------------------------------------------------------------------------------------
# Trozos del instalador con órdenes simuladas. Cada prueba corre en un subshell que carga las
# funciones de install.sh (sin ejecutar principal) y devuelve 0 si todo está bien.
# ---------------------------------------------------------------------------------------------
en_instalador() {
  (
    export IDS_RAIZ="$T/raiz"
    rm -rf "$IDS_RAIZ"
    mkdir -p "$IDS_RAIZ"
    IDS_INSTALL_SOLO_FUNCIONES=1
    # shellcheck disable=SC1091
    . ./install.sh
    set +e
    LLAMADAS="$T/llamadas"
    : > "$LLAMADAS"
    # órdenes del sistema simuladas: nunca se ejecuta nada real
    chown() { echo "chown $*" >> "$LLAMADAS"; }
    systemctl() { echo "systemctl $*" >> "$LLAMADAS"; return 0; }
    systemd-run() { echo "systemd-run $*" >> "$LLAMADAS"; }
    groupadd() { echo "groupadd $*" >> "$LLAMADAS"; }
    useradd() { echo "useradd $*" >> "$LLAMADAS"; }
    getent() { return 2; }
    apt-get() { echo "apt-get $*" >> "$LLAMADAS"; }
    # shellcheck disable=SC2086
    python3() { command $PY "$@"; }
    "$@"
  )
}

p_helpers() {
  [ "$(cidr_norm 192.0.2.77/25)" = 192.0.2.0/25 ] || return 1
  [ "$(cidr_norm 203.0.113.50)" = 203.0.113.50 ] || return 1
  [ "$(cidr_norm 010.001.002.003/32)" = 10.1.2.3 ] || return 1      # sin octal
  solapan 10.0.0.0/8 10.210.0.0/16 || return 1
  solapan 192.0.2.0/25 192.0.2.128/25 && return 1
  ip_en_lista 198.51.100.7 192.0.2.0/25,198.51.100.0/26 || return 1
  ip_en_lista 198.51.100.70 192.0.2.0/25,198.51.100.0/26 && return 1
  ip_en_lista 2001:db8::1 192.0.2.0/25 && return 1
  cidr_rango 1.2.3.4/33 >/dev/null && return 1
  return 0
}

p_arbol_conf_secretos() {
  parsear_args "${V[@]}" --dueno-ip 203.0.113.20 && validar_args || return 1
  usuario_y_arbol || return 1
  grep -q "groupadd -g 10500 ids-panel" "$LLAMADAS" || return 2
  grep -q "useradd -u 10500 -g 10500 -M -d /nonexistent -s /usr/sbin/nologin ids-panel" "$LLAMADAS" || return 3
  for d in etc/ids-maat srv/ids/estado srv/ids/pki/servidores srv/ids/fw srv/ids/puntos srv/ids/datos srv/ids/run \
           srv/ids/ctl srv/ids/reglas/releases srv/ids/reglas/cache root/ids-maat root/backups; do
    [ -d "$IDS_RAIZ/$d" ] || { echo "falta $d"; return 4; }
  done
  grep -q "chown root:10500 $IDS_RAIZ/srv/ids/run" "$LLAMADAS" || return 5
  if [ "$WINDOWS" = 0 ]; then
    [ "$(stat -c %a "$IDS_RAIZ/srv/ids/estado")" = 700 ] || return 6
    [ "$(stat -c %a "$IDS_RAIZ/srv/ids/datos")" = 750 ] || return 6
  fi
  escribir_ids_conf || return 7
  cat > "$T/ids.conf.esperado" <<'EOF'
VERSION=0.1.0
NOMBRE_DNS=ids.empresa.example
TUN_BASE=100.64
REDES_GESTION=192.0.2.0/25,198.51.100.0/26
IPS_PROXY=203.0.113.50
IGNOREIP_DUENO=203.0.113.20
PUERTO_PANEL=5637
POOL_DOCKER=10.210.0.0/16
EOF
  diff "$T/ids.conf.esperado" "$IDS_RAIZ/etc/ids-maat/ids.conf" || return 8
  secretos || return 9
  grep -Eq '^[0-9a-f]{64}$' "$IDS_RAIZ/etc/ids-maat/master.key" || return 10
  grep -Eq '^[0-9a-f]{64}$' "$IDS_RAIZ/etc/ids-maat/orq_token" || return 10
  [ "$(cat "$IDS_RAIZ/etc/ids-maat/master.key")" != "$(cat "$IDS_RAIZ/etc/ids-maat/orq_token")" ] || return 11
  local antes
  antes=$(cat "$IDS_RAIZ/etc/ids-maat/orq_token")
  secretos || return 12
  [ "$(cat "$IDS_RAIZ/etc/ids-maat/orq_token")" = "$antes" ] || { echo "el token cambió al repetir"; return 13; }
  grep -q "chown root:10500 $IDS_RAIZ/etc/ids-maat/orq_token" "$LLAMADAS" || return 14
  [ -f "$IDS_RAIZ/etc/ids-maat/avisos.conf" ] || return 15
  return 0
}

p_tun_base_con_puntos() {
  mkdir -p "$IDS_RAIZ/etc/ids-maat" "$IDS_RAIZ/srv/ids/puntos/p001"
  echo "TUN_BASE=198.18" > "$IDS_RAIZ/etc/ids-maat/ids.conf"
  parsear_args "${V[@]}" && validar_args && comprobar_tun_base || return 1
  [ "$TUN_BASE" = 198.18 ] || return 2                      # sin --tun-base se conserva la actual
  TUN_BASE=100.64 TUN_BASE_DADO=1
  comprobar_tun_base                                       # con puntos: fallar (sale del subshell con 1)
  return 0
}

p_respaldo() {
  mkdir -p "$IDS_RAIZ/etc/ssh/sshd_config.d" "$IDS_RAIZ/etc/docker" "$IDS_RAIZ/srv/ids/fw"
  echo "Port 22" > "$IDS_RAIZ/etc/ssh/sshd_config"
  echo "{}" > "$IDS_RAIZ/etc/docker/daemon.json"
  echo "table inet ids_host" > "$IDS_RAIZ/srv/ids/fw/ids_host.nft"
  TS=20261010T081500Z
  respaldo || return 1
  local f="$IDS_RAIZ/root/backups/ids-maat-install-$TS.tar.gz" lista
  lista=$(tar -tzf "$f") || return 2
  for e in etc/ssh/sshd_config etc/docker/daemon.json srv/ids/fw/ids_host.nft; do
    grep -qx "$e" <<<"$lista" || { echo "falta $e en el respaldo"; return 3; }
  done
  return 0
}

p_reversion_y_confirmar() {
  mkdir -p "$IDS_RAIZ/srv/ids/fw" "$IDS_RAIZ/root/ids-maat"
  echo "anterior" > "$IDS_RAIZ/srv/ids/fw/ids_host.nft"
  TS=20261010T081500Z
  armar_reversion || return 1
  [ "$(cat "$IDS_RAIZ/root/ids-maat/acceso-anterior-$TS/ids_host.nft")" = anterior ] || return 2
  bash -n "$IDS_RAIZ/root/ids-maat/revertir-acceso.sh" || return 3
  grep -q 'D="/root/ids-maat/acceso-anterior-20261010T081500Z"' "$IDS_RAIZ/root/ids-maat/revertir-acceso.sh" || return 4
  grep -q "systemd-run --quiet --unit ids-maat-revertir-acceso --on-active=300 /bin/bash /root/ids-maat/revertir-acceso.sh" \
    "$LLAMADAS" || return 5
  grep -q "flush ruleset" "$IDS_RAIZ/root/ids-maat/revertir-acceso.sh" && return 6
  [ -f "$IDS_RAIZ/root/ids-maat/acceso-confirmado" ] && return 7
  confirmar_acceso >/dev/null || return 8
  [ -f "$IDS_RAIZ/root/ids-maat/acceso-confirmado" ] || return 9
  grep -q "systemctl stop ids-maat-revertir-acceso.timer" "$LLAMADAS" || return 10
  VENTANA_REVERSION=12
  esperar_confirmacion >/dev/null || return 11             # ya confirmado: vuelve enseguida
  return 0
}

p_sin_confirmacion_falla() {
  VENTANA_REVERSION=11
  sleep() { :; }
  echo 1000 > "$T/reloj"
  date() {   # reloj simulado que avanza 5 s por llamada (se llama dentro de $(…): estado en fichero)
    if [ "${1:-}" = +%s ]; then
      local n
      n=$(( $(cat "$T/reloj") + 5 ))
      echo "$n" > "$T/reloj"
      echo "$n"
    else
      command date "$@"
    fi
  }
  esperar_confirmacion
  return 0
}

p_acceso_ssh() {
  parsear_args "${V[@]}" && validar_args || return 1
  mkdir -p "$IDS_RAIZ/root/.ssh"
  echo "ssh-ed25519 AAAA prueba" > "$IDS_RAIZ/root/.ssh/authorized_keys"
  sshd() { echo "passwordauthentication yes"; }
  SSH_CONNECTION="198.51.100.7 51000 203.0.113.10 22" comprobar_acceso_ssh || return 2
  ( SSH_CONNECTION="203.0.113.99 51000 203.0.113.10 22" comprobar_acceso_ssh ) >/dev/null 2>&1 && return 3
  ( SSH_CONNECTION="2001:db8::5 51000 2001:db8::1 22" comprobar_acceso_ssh ) >/dev/null 2>&1 && return 4
  FORZAR_ACCESO=1 SSH_CONNECTION="203.0.113.99 51000 203.0.113.10 22" comprobar_acceso_ssh 2>/dev/null || return 5
  DUENO=203.0.113.99 SSH_CONNECTION="203.0.113.99 51000 203.0.113.10 22" comprobar_acceso_ssh || return 6
  rm -f "$IDS_RAIZ/root/.ssh/authorized_keys"
  ( SSH_CONNECTION="198.51.100.7 51000 203.0.113.10 22" comprobar_acceso_ssh ) >/dev/null 2>&1 && return 7
  return 0
}

p_paquetes_rechaza_ufw() {
  dpkg-query() { [ "${*: -1}" = ufw ] && echo "install ok installed"; return 0; }
  paquetes
  return 0
}

p_fail2ban() {
  HOST_DIR="$CHECKOUT" DUENO=203.0.113.20
  fail2ban-regex() {
    echo "fail2ban-regex $*" >> "$LLAMADAS"
    printf 'Results\n=======\nLines: 6 lines, 0 ignored, %s matched, 2 missed\n[processed in 0.00 sec]\n' "${COINCIDEN:-4}"
  }
  fail2ban-client() { return 0; }
  [ "$(casan /dev/null x)" = 4 ] || return 1
  mkdir -p "$IDS_RAIZ/root/ids-maat"
  fail2ban_jaulas >/dev/null || return 2
  local j="$IDS_RAIZ/etc/fail2ban/jail.d/10-ids.local"
  grep -qx "ignoreip   = 127.0.0.1/8 ::1 203.0.113.20" "$j" || return 3
  grep -q "192.0.2" "$j" && return 4                         # las redes de gestión nunca en ignoreip
  grep -qx "journalmatch = _SYSTEMD_UNIT=ssh.service" "$j" || return 5
  cmp -s "$CHECKOUT/host/fail2ban/filter.d/ids-vpn.conf" "$IDS_RAIZ/etc/fail2ban/filter.d/ids-vpn.conf" || return 6
  [ -f "$IDS_RAIZ/etc/fail2ban/filter.d/sshd.local" ] || return 7
  grep -q -- "-d {NONE}" "$LLAMADAS" || return 8
  grep -q "systemctl restart fail2ban" "$LLAMADAS" || return 9
  COINCIDEN=3
  ( fail2ban_jaulas ) >/dev/null 2>&1 && return 10
  return 0
}

p_lineas_contrato() {
  diff <(lineas_ids_vpn) "$CHECKOUT/tests/fixtures/orq/ids-vpn.log"
}

p_daemon_json() {
  HOST_DIR="$CHECKOUT"
  mkdir -p "$IDS_RAIZ/etc/docker"
  echo '{"debug": true, "bip": "172.17.0.1/16", "live-restore": false}' > "$IDS_RAIZ/etc/docker/daemon.json"
  docker() { case "$1" in ps) return 0 ;; info) return 0 ;; esac; }
  update-alternatives() { echo "Value: /usr/sbin/iptables-nft"; }
  docker_daemon >/dev/null || return 1
  grep -q "systemctl restart docker" "$LLAMADAS" || return 2
  $PY - "$IDS_RAIZ/etc/docker/daemon.json" <<'PY' || return 3
import json, sys
d = json.load(open(sys.argv[1]))
assert d["debug"] is True, d
assert d["bip"] == "10.210.254.1/24", d
assert d["live-restore"] is True and d["userland-proxy"] is False, d
assert d["default-address-pools"] == [{"base": "10.210.0.0/16", "size": 28}], d
PY
  : > "$LLAMADAS"
  docker_daemon >/dev/null || return 4
  grep -q "systemctl restart docker" "$LLAMADAS" && return 5     # segunda vez: no cambia, no reinicia
  update-alternatives() { echo "Value: /usr/sbin/iptables-legacy"; }
  ( docker_daemon ) >/dev/null 2>&1 && return 6
  return 0
}

p_instalar_orquestador() {
  HOST_DIR="$CHECKOUT"
  mkdir -p "$IDS_RAIZ/etc/ids-maat"
  instalar_orquestador >/dev/null || return 1
  cmp -s "$CHECKOUT/orquestador/ids_orq.py" "$IDS_RAIZ/usr/local/lib/ids-orq/ids_orq.py" || return 2
  [ "$(ls "$IDS_RAIZ/usr/local/lib/ids-orq/plantillas" | wc -l)" -eq 3 ] || return 3
  grep -qx 'exec python3 /usr/local/lib/ids-orq/ids_orq.py "$@"' "$IDS_RAIZ/usr/local/bin/ids-orq" || return 4
  for u in ids-host-fw.service ids-orq.service ids-reglas.service ids-reglas.timer ids-logrotate.service ids-logrotate.timer; do
    [ -f "$IDS_RAIZ/etc/systemd/system/$u" ] || { echo "falta $u"; return 5; }
  done
  cmp -s "$CHECKOUT/host/logrotate/ids-maat.conf" "$IDS_RAIZ/etc/ids-maat/logrotate.conf" || return 6
  grep -q "systemctl daemon-reload" "$LLAMADAS" || return 7
  return 0
}

p_imagenes_lab() {
  DEV=true VERSION=v0.1.0 IMG_VPN=ids-maat-vpn:ci IMG_SUR=ids-maat-suricata:ci
  mkdir -p "$IDS_RAIZ/etc/ids-maat"
  docker() { echo "docker $*" >> "$LLAMADAS"; [ "$1" = image ] && return 0; return 1; }
  imagenes >/dev/null || return 1
  grep -q "docker pull" "$LLAMADAS" && return 2               # ya están en local: no se descargan
  $PY - "$IDS_RAIZ/etc/ids-maat/imagenes.json" <<'PY' || return 3
import json, sys
d = json.load(open(sys.argv[1]))
assert d == {"v": 1, "version": "0.1.0", "dev": True,
             "imagenes": {"vpn": "ids-maat-vpn:ci", "suricata": "ids-maat-suricata:ci"}}, d
PY
}

p_obtener_release_lab() {
  DESDE_REPO="$CHECKOUT"
  obtener_release 2>/dev/null || return 1
  [ "$HOST_DIR" = "$CHECKOUT" ] || return 2
}

p_puertos_ajenos() {
  ss() { printf '%s\n' "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*" "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*" \
                       "LISTEN 0 4096 127.0.0.1:631 0.0.0.0:*"; }
  docker() { printf '%s\n' "ids-p001-vpn|p001|0.0.0.0:1194->1194/tcp" "nginx-viejo||0.0.0.0:8080->80/tcp" "sin-puertos||"; }
  ( comprobar_puertos_ajenos ) >/dev/null 2>&1 && return 1                  # nginx-viejo publica: no sigue
  docker() { printf '%s\n' "ids-p001-vpn|p001|0.0.0.0:1194->1194/tcp" "sin-puertos||"; }
  local avisos
  avisos=$(comprobar_puertos_ajenos 2>&1) || return 2
  grep -q "TCP 80 " <<<"$avisos" || return 3                                # 80 avisado; 22 y 631 (local) no
  grep -q "631" <<<"$avisos" && return 4
  return 0
}

echo "== install.sh: trozos con órdenes simuladas"
esperar 0 "helpers de direcciones IPv4"                   en_instalador p_helpers
esperar 0 "árbol, ids.conf y secretos (idempotentes)"     en_instalador p_arbol_conf_secretos
esperar 1 "--tun-base distinta con puntos: rechazo"       en_instalador p_tun_base_con_puntos
esperar 0 "respaldo antes de tocar nada"                  en_instalador p_respaldo
esperar 0 "modo seguro: reversión armada y confirmación"  en_instalador p_reversion_y_confirmar
esperar 1 "modo seguro: sin confirmación, aborta"         en_instalador p_sin_confirmacion_falla
esperar 0 "acceso SSH: IP de gestión y claves"            en_instalador p_acceso_ssh
esperar 1 "ufw instalado: no sigue"                       en_instalador p_paquetes_rechaza_ufw
esperar 0 "fail2ban: jaulas y 4 coincidencias"            en_instalador p_fail2ban
esperar 0 "líneas de §5.13 = fixture de C"                en_instalador p_lineas_contrato
if [ -n "$PY" ]; then
  esperar 0 "daemon.json: fusión y comprobaciones"        en_instalador p_daemon_json
  esperar 0 "imagenes.json de laboratorio"                en_instalador p_imagenes_lab
else
  echo "  (sin Python: se omiten daemon.json e imagenes.json)"
fi
esperar 0 "orquestador y unidades instalados"             en_instalador p_instalar_orquestador
esperar 0 "release de laboratorio = checkout"             en_instalador p_obtener_release_lab
esperar 0 "contenedores ajenos con puertos: no sigue"      en_instalador p_puertos_ajenos

echo
if [ "$FALLOS" -gt 0 ]; then
  echo "test_host_install.sh: $FALLOS fallos"
  exit 1
fi
echo "test_host_install.sh: todo bien"
exit 0
