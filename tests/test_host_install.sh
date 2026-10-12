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
V=(--version v0.1.0 --nombre ids.empresa.example --gestion "192.0.2.0/25,198.51.100.0/26" --proxy 203.0.113.50)
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
LAB=(--nombre ids.empresa.example --gestion 192.0.2.0/25 --proxy 203.0.113.50 --desde-repo "$CHECKOUT")
IMGS_CI="vpn=ids-maat-vpn:ci,suricata=ids-maat-suricata:ci,panel=ids-maat-panel:ci"
esperar 0 "laboratorio --desde-repo (versión del repo)"    bash install.sh --solo-validar "${LAB[@]}" --imagenes "$IMGS_CI"
esperar 0 "laboratorio: panel= en cualquier orden"         bash install.sh --solo-validar "${LAB[@]}" --imagenes panel=ids-maat-panel:ci,vpn=ids-maat-vpn:ci,suricata=ids-maat-suricata:ci
esperar 1 "laboratorio sin panel=: no sigue"               bash install.sh --solo-validar "${LAB[@]}" --imagenes vpn=ids-maat-vpn:ci,suricata=ids-maat-suricata:ci
esperar 1 "--imagenes con una parte desconocida"           bash install.sh --solo-validar "${LAB[@]}" --imagenes "$IMGS_CI,web=x"
esperar 1 "--desde-repo sin --imagenes"                    bash install.sh --solo-validar "${LAB[@]}"
esperar 1 "--desde-repo que no es el repo"                 bash install.sh --solo-validar --nombre ids.empresa.example --gestion 192.0.2.0/25 --proxy 203.0.113.50 --desde-repo "$T" --imagenes vpn=a,suricata=b,panel=c
esperar 1 "--imagenes con referencia peligrosa"            bash install.sh --solo-validar "${LAB[@]}" --imagenes 'vpn=-v /:/x,suricata=b,panel=c'
esperar 1 "--imagenes con panel peligroso"                 bash install.sh --solo-validar "${LAB[@]}" --imagenes 'vpn=a,suricata=b,panel=--privileged'
esperar 0 "--zona Región/Ciudad"                           bash install.sh --solo-validar "${V[@]}" --zona America/Guayaquil
esperar 1 "--zona inválida"                                bash install.sh --solo-validar "${V[@]}" --zona 'America/Guayaquil;x'

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
  cidr_rango 192.0.2.4/33 >/dev/null && return 1
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
  # CONTRATO-F2 §10.3: la clave maestra la lee el panel (10500) por grupo, nadie más
  grep -q "chown root:10500 $IDS_RAIZ/etc/ids-maat/master.key" "$LLAMADAS" || return 16
  if [ "$WINDOWS" = 0 ]; then [ "$(stat -c %a "$IDS_RAIZ/etc/ids-maat/master.key")" = 440 ] || return 17; fi
  [ -f "$IDS_RAIZ/etc/ids-maat/avisos.conf" ] || return 15
  return 0
}

p_zona_en_ids_conf() {   # --zona va a ZONA_HORARIA; sin --zona se conserva la que hubiera
  local conf="$IDS_RAIZ/etc/ids-maat/ids.conf"
  mkdir -p "$IDS_RAIZ/etc/ids-maat"
  parsear_args "${V[@]}" --zona America/Guayaquil && validar_args || return 1
  escribir_ids_conf || return 2
  grep -qx "ZONA_HORARIA=America/Guayaquil" "$conf" || return 3
  ZONA=""
  parsear_args "${V[@]}" && validar_args && escribir_ids_conf || return 4
  grep -qx "ZONA_HORARIA=America/Guayaquil" "$conf" || { cat "$conf"; return 5; }
  [ "$(grep -c '^ZONA_HORARIA=' "$conf")" = 1 ] || return 6
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
  # B-05/B-06: el panel y el estado del orquestador entran; la clave maestra no
  mkdir -p "$IDS_RAIZ/etc/ids-maat" "$IDS_RAIZ/srv/ids/panel/conf" "$IDS_RAIZ/srv/ids/estado"
  echo "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" > "$IDS_RAIZ/etc/ids-maat/master.key"
  echo "VERSION=0.1.0" > "$IDS_RAIZ/etc/ids-maat/ids.conf"
  echo '{"p001": {"PASS": "enc1:x"}}' > "$IDS_RAIZ/srv/ids/panel/conf/routers.json"
  echo "db" > "$IDS_RAIZ/srv/ids/estado/orq.db"
  TS=20261010T081500Z
  respaldo || return 1
  local f="$IDS_RAIZ/root/backups/ids-maat-install-$TS.tar.gz" lista
  lista=$(tar -tzf "$f") || return 2
  for e in etc/ssh/sshd_config etc/docker/daemon.json srv/ids/fw/ids_host.nft etc/ids-maat/ids.conf \
           srv/ids/panel/conf/routers.json srv/ids/estado/orq.db; do
    grep -qx "$e" <<<"$lista" || { echo "falta $e en el respaldo"; return 3; }
  done
  if grep -E '(^|/)master\.key$' <<<"$lista" >/dev/null; then echo "la clave maestra está en el respaldo"; return 4; fi
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

# Reloj simulado que avanza 5 s por llamada a «date +%s» (se llama dentro de $(…): estado en fichero)
reloj_simulado() {   # reloj_simulado <segundos iniciales>
  echo "$1" > "$T/reloj"
  : > "$T/suenos"
  sleep() { echo x >> "$T/suenos"; }
  date() {
    if [ "${1:-}" = +%s ]; then
      local n
      n=$(( $(cat "$T/reloj") + 5 ))
      echo "$n" > "$T/reloj"
      echo "$n"
    else
      command date "$@"
    fi
  }
}

suenos() { wc -l < "$T/suenos" | tr -d ' '; }

p_revertir_escribe_marcador_primero() {
  mkdir -p "$IDS_RAIZ/root/ids-maat"
  TS=20261010T081500Z
  armar_reversion >/dev/null || return 1
  local s="$IDS_RAIZ/root/ids-maat/revertir-acceso.sh" l_marca l_nft
  l_marca=$(grep -n 'date -u +%s > /root/ids-maat/acceso-revertido' "$s" | head -n1 | cut -d: -f1)
  l_nft=$(grep -n 'nft ' "$s" | head -n1 | cut -d: -f1)
  [ -n "$l_marca" ] || return 2
  [ "$l_marca" -lt "$l_nft" ] || return 3                    # antes de tocar nada
  : > "$IDS_RAIZ/root/ids-maat/acceso-revertido"
  armar_reversion >/dev/null || return 4                     # rearmar borra el marcador viejo
  [ -e "$IDS_RAIZ/root/ids-maat/acceso-revertido" ] && return 5
  return 0
}

p_confirmar_tras_revertir_falla() {   # el marcador de la reversión existe: --confirmar no confirma
  mkdir -p "$IDS_RAIZ/root/ids-maat"
  TS=20261010T081500Z
  armar_reversion >/dev/null || return 1
  date -u +%s > "$IDS_RAIZ/root/ids-maat/acceso-revertido"
  ( confirmar_acceso ) >"$T/conf" 2>&1 && { cat "$T/conf"; return 2; }
  grep -q CONFIRMADO "$T/conf" && return 3
  [ -f "$IDS_RAIZ/root/ids-maat/acceso-confirmado" ] && return 4
  return 0
}

p_confirmar_sin_timer_falla() {   # el timer ya no está activo (venció): --confirmar no confirma
  mkdir -p "$IDS_RAIZ/root/ids-maat"
  systemctl() {
    echo "systemctl $*" >> "$LLAMADAS"
    case "$*" in *"is-active --quiet ids-maat-revertir-acceso.timer"*) return 3 ;; esac
    return 0
  }
  ( confirmar_acceso ) >/dev/null 2>&1 && return 1
  [ -f "$IDS_RAIZ/root/ids-maat/acceso-confirmado" ] && return 2
  # vencido pero todavía «active (elapsed)»: tampoco
  systemctl() {
    echo "systemctl $*" >> "$LLAMADAS"
    case "$*" in *"show -p SubState --value ids-maat-revertir-acceso.timer"*) echo elapsed ;; esac
    return 0
  }
  ( confirmar_acceso ) >/dev/null 2>&1 && return 3
  [ -f "$IDS_RAIZ/root/ids-maat/acceso-confirmado" ] && return 4
  return 0
}

p_confirmar_carrera_con_el_timer() {   # el timer dispara entre la comprobación y el stop
  mkdir -p "$IDS_RAIZ/root/ids-maat"
  rm -f "$T/parado"
  systemctl() {
    echo "systemctl $*" >> "$LLAMADAS"
    case "$*" in
      "stop ids-maat-revertir-acceso.timer") : > "$T/parado" ;;
      "is-active ids-maat-revertir-acceso.service") [ -e "$T/parado" ] && echo activating; return 3 ;;
    esac
    return 0
  }
  ( confirmar_acceso ) >/dev/null 2>&1 && return 1
  [ -f "$IDS_RAIZ/root/ids-maat/acceso-confirmado" ] && return 2
  return 0
}

p_esperar_revertido_aunque_confirmado() {   # confirmado tarde: la reversión ya corrió
  mkdir -p "$IDS_RAIZ/root/ids-maat"
  TS=20261010T081500Z
  armar_reversion >/dev/null || return 1
  date -u +%s > "$IDS_RAIZ/root/ids-maat/acceso-confirmado"
  date -u +%s > "$IDS_RAIZ/root/ids-maat/acceso-revertido"
  ( esperar_confirmacion ) >/dev/null 2>&1 && return 2
  return 0
}

p_esperar_cuenta_desde_t0() {   # firewall+sshd+fail2ban tardan 280 s: quedan 10 s, no 290
  mkdir -p "$IDS_RAIZ/root/ids-maat"
  TS=20261010T081500Z
  reloj_simulado 995
  armar_reversion >/dev/null || return 1                     # T0 = 1000
  [ "$T0_REVERSION" = 1000 ] || { echo "T0=$T0_REVERSION"; return 2; }
  echo 1275 > "$T/reloj"                                     # ahora = 1280
  ( esperar_confirmacion ) >/dev/null 2>&1 && return 3
  [ "$(suenos)" -le 3 ] || { echo "esperó $(suenos) vueltas más allá de T0+290"; return 4; }
  return 0
}

p_esperar_timer_inactivo_falla_ya() {   # nadie confirmó y el timer ya no está: no esperar a ciegas
  mkdir -p "$IDS_RAIZ/root/ids-maat"
  TS=20261010T081500Z
  reloj_simulado 1000
  armar_reversion >/dev/null || return 1
  systemctl() {
    echo "systemctl $*" >> "$LLAMADAS"
    case "$*" in *"is-active --quiet ids-maat-revertir-acceso.timer"*) return 3 ;; esac
    return 0
  }
  ( esperar_confirmacion ) >"$T/esp" 2>&1 && return 2
  [ "$(suenos)" -le 2 ] || { echo "esperó $(suenos) vueltas con el timer parado"; return 3; }
  return 0
}

p_principal_revertido_no_dice_instalado() {
  # Todo simulado salvo el modo seguro: la reversión se dispara durante fail2ban (lento) y el
  # dueño confirma tarde. El instalador debe fallar y no decir «instalado».
  local paso
  for paso in comprobar_sistema comprobar_tun_base comprobar_acceso_ssh respaldo paquetes obtener_release \
              docker_ce docker_daemon modulos_sysctl_hora usuario_y_arbol escribir_ids_conf secretos pki \
              instalar_orquestador firewall ssh_endurecer imagenes arrancar panel; do
    eval "$paso() { :; }"
  done
  readlink() { echo /root/ids-maat-install.sh; }
  mkdir -p "$IDS_RAIZ/root/ids-maat"
  fail2ban_jaulas() {
    date -u +%s > "$IDS_RAIZ/root/ids-maat/acceso-revertido"
    date -u +%s > "$IDS_RAIZ/root/ids-maat/acceso-confirmado"
  }
  ( principal "${V[@]}" ) >"$T/principal" 2>&1 && { cat "$T/principal"; return 1; }
  grep -q "ids-maat v0.1.0 instalado" "$T/principal" && { cat "$T/principal"; return 2; }
  grep -q "se revirtió" "$T/principal" || { cat "$T/principal"; return 3; }
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

preparar_ssh() {   # claves presentes, sin SSH_CONNECTION heredada, sin /proc ni who reales
  parsear_args "${V[@]}" "$@" && validar_args || return 1
  mkdir -p "$IDS_RAIZ/root/.ssh"
  echo "ssh-ed25519 AAAA prueba" > "$IDS_RAIZ/root/.ssh/authorized_keys"
  sshd() { echo "passwordauthentication yes"; }
  who() { [ -f "$T/who" ] && cat "$T/who"; return 0; }
  rm -f "$T/who"
  unset SSH_CONNECTION
}

p_acceso_ssh() {
  preparar_ssh || return 1
  SSH_CONNECTION="198.51.100.7 51000 203.0.113.10 22" comprobar_acceso_ssh || return 2
  ( SSH_CONNECTION="203.0.113.99 51000 203.0.113.10 22" comprobar_acceso_ssh ) >/dev/null 2>&1 && return 3
  ( SSH_CONNECTION="2001:db8::5 51000 2001:db8::1 22" comprobar_acceso_ssh ) >/dev/null 2>&1 && return 4
  FORZAR_ACCESO=1 SSH_CONNECTION="203.0.113.99 51000 203.0.113.10 22" comprobar_acceso_ssh 2>/dev/null || return 5
  rm -f "$IDS_RAIZ/root/.ssh/authorized_keys"
  ( SSH_CONNECTION="198.51.100.7 51000 203.0.113.10 22" comprobar_acceso_ssh ) >/dev/null 2>&1 && return 7
  return 0
}

p_acceso_ssh_dueno_fuera_de_gestion() {
  # --dueno-ip solo va al ignoreip de fail2ban; el firewall solo deja entrar a --gestion
  preparar_ssh --dueno-ip 203.0.113.99 || return 1
  ( SSH_CONNECTION="203.0.113.99 51000 203.0.113.10 22" comprobar_acceso_ssh ) >/dev/null 2>&1 && return 2
  return 0
}

proc_simulado() {   # proc_simulado <ip SSH>: $$ -> 4321 (sudo, sin SSH_CONNECTION) -> 4000 (sshd-session)
  local pr="$IDS_RAIZ/proc"
  mkdir -p "$pr/$$" "$pr/4321" "$pr/4000"
  printf 'Name:\tbash\nPPid:\t4321\n' > "$pr/$$/status"
  printf 'Name:\tsudo\nPPid:\t4000\n' > "$pr/4321/status"
  printf 'HOME=/root\0USER=root\0' > "$pr/4321/environ"
  printf 'Name:\tbash\nPPid:\t1\n' > "$pr/4000/status"
  printf 'HOME=/home/admin\0SSH_CONNECTION=%s 51000 203.0.113.10 22\0SSH_TTY=/dev/pts/0\0' "$1" > "$pr/4000/environ"
}

p_acceso_ssh_sudo_i_proc() {   # sudo -i: SSH_CONNECTION solo en el entorno de un proceso padre
  preparar_ssh || return 1
  proc_simulado 198.51.100.7
  [ "$(ip_sesion_ssh)" = 198.51.100.7 ] || { echo "ip_sesion_ssh: $(ip_sesion_ssh)"; return 2; }
  comprobar_acceso_ssh 2>/dev/null || return 3
  proc_simulado 203.0.113.99                                # fuera de --gestion: no sigue
  ( comprobar_acceso_ssh ) >/dev/null 2>&1 && return 4
  return 0
}

p_acceso_ssh_who() {   # sin rastro en /proc: «who -m --ips»
  preparar_ssh || return 1
  echo "admin    pts/0        2026-10-11 09:00 (198.51.100.7)" > "$T/who"
  comprobar_acceso_ssh 2>/dev/null || return 2
  echo "admin    pts/0        2026-10-11 09:00 203.0.113.99" > "$T/who"
  ( comprobar_acceso_ssh ) >/dev/null 2>&1 && return 3
  echo "root     tty1         2026-10-11 09:00" > "$T/who"   # consola: la hora no es una IP
  ( comprobar_acceso_ssh ) >/dev/null 2>&1 && return 4
  return 0
}

p_acceso_ssh_ip_desconocida() {   # sin SSH_CONNECTION, /proc ni who: falla salvo con las opciones
  preparar_ssh || return 1
  ( comprobar_acceso_ssh ) >/dev/null 2>&1 && return 2
  FORZAR_ACCESO=1 comprobar_acceso_ssh 2>/dev/null || return 3
  SIN_REVERSION=1 comprobar_acceso_ssh 2>/dev/null || return 4
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
    printf 'Results\n=======\nLines: 6 lines, 0 ignored, %s matched, 4 missed\n[processed in 0.00 sec]\n' "${COINCIDEN:-2}"
  }
  fail2ban-client() { return 0; }
  [ "$(casan /dev/null x)" = 2 ] || return 1
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
  COINCIDEN=4                                                 # el filtro viejo (TLS Auth Error también)
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
  [ "$(ls "$IDS_RAIZ/usr/local/lib/ids-orq/plantillas" | wc -l)" -eq 4 ] || return 3
  cmp -s "$CHECKOUT/orquestador/plantillas/core.yml.tmpl" "$IDS_RAIZ/usr/local/lib/ids-orq/plantillas/core.yml.tmpl" || return 3
  grep -qx 'exec python3 /usr/local/lib/ids-orq/ids_orq.py "$@"' "$IDS_RAIZ/usr/local/bin/ids-orq" || return 4
  for u in ids-host-fw.service ids-orq.service ids-reglas.service ids-reglas.timer ids-logrotate.service ids-logrotate.timer; do
    [ -f "$IDS_RAIZ/etc/systemd/system/$u" ] || { echo "falta $u"; return 5; }
  done
  cmp -s "$CHECKOUT/host/logrotate/ids-maat.conf" "$IDS_RAIZ/etc/ids-maat/logrotate.conf" || return 6
  grep -q "systemctl daemon-reload" "$LLAMADAS" || return 7
  return 0
}

p_imagenes_lab() {
  DEV=true VERSION=v0.1.0
  parsear_args "${LAB[@]}" --imagenes "$IMGS_CI" && validar_args || return 4
  mkdir -p "$IDS_RAIZ/etc/ids-maat"
  docker() { echo "docker $*" >> "$LLAMADAS"; [ "$1" = image ] && return 0; return 1; }
  imagenes >/dev/null || return 1
  grep -q "docker pull" "$LLAMADAS" && return 2               # ya están en local: no se descargan
  grep -q "docker image inspect ids-maat-panel:ci" "$LLAMADAS" || return 5
  $PY - "$IDS_RAIZ/etc/ids-maat/imagenes.json" <<'PY' || return 3
import json, sys
d = json.load(open(sys.argv[1]))
assert d == {"v": 1, "version": "0.1.0", "dev": True,
             "imagenes": {"vpn": "ids-maat-vpn:ci", "suricata": "ids-maat-suricata:ci",
                          "panel": "ids-maat-panel:ci"}}, d
PY
}

p_imagenes_produccion_descarga_las_tres() {
  DEV=false VERSION=v0.2.0
  IMG_VPN="ghcr.io/mtandazo35/ids-maat-vpn@sha256:$(printf '1%.0s' {1..64})"
  IMG_SUR="ghcr.io/mtandazo35/ids-maat-suricata@sha256:$(printf '2%.0s' {1..64})"
  IMG_PANEL="ghcr.io/mtandazo35/ids-maat-panel@sha256:$(printf '3%.0s' {1..64})"
  mkdir -p "$IDS_RAIZ/etc/ids-maat"
  docker() { echo "docker $*" >> "$LLAMADAS"; return 0; }
  imagenes >/dev/null || return 1
  for i in "$IMG_VPN" "$IMG_SUR" "$IMG_PANEL"; do
    grep -qx "docker pull -q $i" "$LLAMADAS" || { echo "no se descargó $i"; return 2; }
  done
  grep -q "\"panel\": \"$IMG_PANEL\"" "$IDS_RAIZ/etc/ids-maat/imagenes.json" || return 3
}

p_imagen_privada_error_claro() {   # paquete de GHCR privado: el error dice qué hacer y dónde
  DEV=false VERSION=v0.2.0
  IMG_VPN="ghcr.io/mtandazo35/ids-maat-vpn@sha256:$(printf '1%.0s' {1..64})"
  IMG_SUR="ghcr.io/mtandazo35/ids-maat-suricata@sha256:$(printf '2%.0s' {1..64})"
  IMG_PANEL="ghcr.io/mtandazo35/ids-maat-panel@sha256:$(printf '3%.0s' {1..64})"
  mkdir -p "$IDS_RAIZ/etc/ids-maat"
  docker() {
    case "$*" in
      *ids-maat-panel*) echo "Error response from daemon: Head \"https://ghcr.io/v2/mtandazo35/ids-maat-panel/manifests/sha256:333\": denied" >&2; return 1 ;;
    esac
    return 0
  }
  ( imagenes ) >"$T/priv" 2>&1 && return 1
  grep -q "ghcr.io/mtandazo35/ids-maat-panel es privado" "$T/priv" || { cat "$T/priv"; return 2; }
  grep -q "https://github.com/users/mtandazo35/packages/container/ids-maat-panel/settings" "$T/priv" || return 3
  # otro fallo (sin red): se dice el motivo real, no «privado»
  docker() { echo "Error response from daemon: Get \"https://ghcr.io/v2/\": dial tcp: lookup ghcr.io: no such host" >&2; return 1; }
  ( imagenes ) >"$T/priv" 2>&1 && return 4
  grep -q "privado" "$T/priv" && return 5
  grep -q "no such host" "$T/priv" || return 6
  return 0
}

p_obtener_release_lab() {
  DESDE_REPO="$CHECKOUT"
  obtener_release 2>/dev/null || return 1
  [ "$HOST_DIR" = "$CHECKOUT" ] || return 2
}

p_puertos_ajenos() {
  ss() { printf '%s\n' "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*" "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*" \
                       "LISTEN 0 4096 127.0.0.1:631 0.0.0.0:*"; }
  docker() { printf '%s\n' "ids-p001-vpn|vpn|0.0.0.0:1194->1194/tcp" "nginx-viejo||0.0.0.0:8080->80/tcp" "sin-puertos||"; }
  ( comprobar_puertos_ajenos ) >/dev/null 2>&1 && return 1                  # nginx-viejo publica: no sigue
  # reinstalación: el panel del IDS publica el 5637 y no es ajeno (no lleva ids-maat.punto, sí
  # ids-maat.parte). El docker simulado contesta según la etiqueta que se le pida.
  docker() {
    case "$*" in
      *ids-maat.parte*) printf '%s\n' "ids-p001-vpn|vpn|0.0.0.0:1194->1194/tcp" \
                                      "ids-core-panel|panel|0.0.0.0:5637->5637/tcp" "sin-puertos||" ;;
      *) printf '%s\n' "ids-p001-vpn|p001|0.0.0.0:1194->1194/tcp" \
                       "ids-core-panel||0.0.0.0:5637->5637/tcp" "sin-puertos||" ;;
    esac
  }
  local avisos
  avisos=$(comprobar_puertos_ajenos 2>&1) || return 2
  grep -q "TCP 80 " <<<"$avisos" || return 3                                # 80 avisado; 22 y 631 (local) no
  grep -q "631" <<<"$avisos" && return 4
  return 0
}

# ids-orq simulado en ${IDS_RAIZ}/usr/local/bin: registra las llamadas; «panel crear-admin» imprime
# CLAVE= y crea usuarios.json (como el contenedor de un solo uso), o sale con ORQ_CREAR_RC.
CLAVE_PRUEBA="Kq7-ZpD2_wX9mR4tLs8V"
orq_falso() {
  mkdir -p "$IDS_RAIZ/usr/local/bin" "$IDS_RAIZ/srv/ids/panel"
  cat > "$IDS_RAIZ/usr/local/bin/ids-orq" <<EOF
#!/bin/bash
echo "\$*" >> "$T/orq"
case "\$*" in
  "panel aplicar") exit \${ORQ_APLICAR_RC:-0} ;;
  "panel crear-admin --usuario admin")
    rc=\${ORQ_CREAR_RC:-0}
    [ "\$rc" = 0 ] || exit "\$rc"
    mkdir -p "$IDS_RAIZ/srv/ids/panel/conf"
    echo '{"admin": "pbkdf2_sha256\$600000\$x\$y"}' > "$IDS_RAIZ/srv/ids/panel/conf/usuarios.json"
    echo "CLAVE=$CLAVE_PRUEBA"
    echo "clave del usuario admin del panel: se muestra UNA sola vez" >&2
    exit 0 ;;
esac
exit 0
EOF
  chmod 0755 "$IDS_RAIZ/usr/local/bin/ids-orq"
  : > "$T/orq"
  ip() { echo "192.0.2.1 via 203.0.113.1 dev eth0 src 203.0.113.10 uid 0"; }
}

preparar_resumen() {
  parsear_args "${V[@]}" "$@" && validar_args || return 1
  orq_falso
  TS=20261011T120000Z
  mkdir -p "$IDS_RAIZ/root/ids-maat"
  LOG_INSTALL="$IDS_RAIZ/root/ids-maat/install-$TS.log"
  : > "$LOG_INSTALL"
}

p_panel_nuevo_resumen_y_log_enmascarado() {
  preparar_resumen || return 1
  panel > "$T/panel" 2>&1 || { cat "$T/panel"; return 2; }
  [ "$(cat "$T/orq")" = "$(printf 'panel aplicar\npanel crear-admin --usuario admin')" ] || { cat "$T/orq"; return 3; }
  grep -qF "$CLAVE_PRUEBA" "$T/panel" && return 4                       # no antes del resumen
  resumen > "$T/resumen" 2>&1 || return 5
  local r="$T/resumen"
  grep -qF "URL               http://ids.empresa.example:5637   (o http://203.0.113.10:5637)" "$r" || { cat "$r"; return 6; }
  grep -qF "solo se abre desde las IP de --proxy: 203.0.113.50" "$r" || return 7
  grep -qF "ssh -L 5637:10.210.255.2:5637 root@ids.empresa.example" "$r" || return 8
  grep -qx "  usuario           admin" "$r" || return 9
  grep -qx "  clave             $CLAVE_PRUEBA" "$r" || return 10
  grep -qF "ids-orq panel restablecer admin" "$r" || return 11
  grep -qF "modo seguro       acceso confirmado" "$r" || return 12
  # el log: el resumen está, la clave no (enmascarada)
  grep -qF "$CLAVE_PRUEBA" "$LOG_INSTALL" && { echo "la clave quedó en el log"; return 13; }
  grep -qF "clave             ********" "$LOG_INSTALL" || { cat "$LOG_INSTALL"; return 14; }
  grep -qF "http://ids.empresa.example:5637" "$LOG_INSTALL" || return 15
  grep -qF "panel: usuario admin creado" "$LOG_INSTALL" || return 16
  [ -z "$CLAVE_PANEL" ] || return 17                                    # no queda en el entorno
  # en ningún fichero del árbol simulado (salvo el usuarios.json del panel, que guarda el hash)
  grep -rlF "$CLAVE_PRUEBA" "$IDS_RAIZ" 2>/dev/null | grep -v "/usr/local/bin/ids-orq$" && return 18
  return 0
}

p_panel_reinstalacion_conserva_la_clave() {
  preparar_resumen || return 1
  mkdir -p "$IDS_RAIZ/srv/ids/panel/conf"
  echo '{"admin": "hash"}' > "$IDS_RAIZ/srv/ids/panel/conf/usuarios.json"
  panel > "$T/panel" 2>&1 || { cat "$T/panel"; return 2; }
  [ "$(cat "$T/orq")" = "panel aplicar" ] || { cat "$T/orq"; return 3; }   # sin crear-admin
  [ "$(cat "$IDS_RAIZ/srv/ids/panel/conf/usuarios.json")" = '{"admin": "hash"}' ] || return 4
  resumen > "$T/resumen" 2>&1 || return 5
  grep -qF "clave             se conserva la existente" "$T/resumen" || { cat "$T/resumen"; return 6; }
  grep -qF "ids-orq panel restablecer admin" "$T/resumen" || return 7
  grep -qF "$CLAVE_PRUEBA" "$T/resumen" && return 8
  return 0
}

p_panel_admin_ya_existia() {   # crear-admin sale con 3 (carrera o usuarios.json en otro sitio)
  preparar_resumen || return 1
  export ORQ_CREAR_RC=3
  panel > "$T/panel" 2>&1 || { cat "$T/panel"; return 2; }
  [ "$PANEL_ESTADO" = existente ] || return 3
  resumen > "$T/resumen" 2>&1
  grep -qF "se conserva la existente" "$T/resumen" || return 4
  return 0
}

p_panel_falla_no_dice_instalado() {
  preparar_resumen || return 1
  export ORQ_APLICAR_RC=1
  ( panel ) > "$T/panel" 2>&1 && return 2
  grep -qF "el panel no quedó sano" "$T/panel" || { cat "$T/panel"; return 3; }
  grep -q "crear-admin" "$T/orq" && return 4
  export ORQ_APLICAR_RC=0 ORQ_CREAR_RC=1
  ( panel ) > "$T/panel" 2>&1 && return 5
  grep -qF "crear-admin falló" "$T/panel" || return 6
  return 0
}

p_sin_reversion_en_el_resumen() {
  preparar_resumen --sin-reversion || return 1
  ip() { return 1; }                                                    # sin ruta: solo el nombre
  PANEL_ESTADO=existente
  resumen > "$T/resumen" 2>&1
  grep -qF "modo seguro       no (--sin-reversion)" "$T/resumen" || return 2
  grep -qx "  URL               http://ids.empresa.example:5637" "$T/resumen" || { cat "$T/resumen"; return 3; }
  return 0
}

p_principal_completo_log_sin_clave() {
  # principal entero con los pasos del sistema simulados: crea el log del instalador, levanta el
  # panel, imprime la clave en la terminal y la deja enmascarada en el log.
  local paso log
  for paso in comprobar_sistema comprobar_tun_base comprobar_acceso_ssh respaldo paquetes obtener_release \
              docker_ce docker_daemon modulos_sysctl_hora usuario_y_arbol escribir_ids_conf secretos pki \
              instalar_orquestador armar_reversion firewall ssh_endurecer fail2ban_jaulas esperar_confirmacion \
              imagenes arrancar; do
    eval "$paso() { :; }"
  done
  orq_falso
  ( principal "${V[@]}" ) > "$T/principal" 2>&1 || { cat "$T/principal"; return 1; }
  grep -qx "  clave             $CLAVE_PRUEBA" "$T/principal" || { cat "$T/principal"; return 2; }
  log=$(ls "$IDS_RAIZ"/root/ids-maat/install-*.log) || return 3
  grep -qF "$CLAVE_PRUEBA" "$log" && return 4
  grep -qF "ids-maat v0.1.0 instalado" "$log" || { cat "$log"; return 5; }
  grep -qF "clave             ********" "$log" || return 6
  grep -qF "log del instalador: $log" "$T/principal" || return 7
  if [ "$WINDOWS" = 0 ]; then [ "$(stat -c %a "$log")" = 600 ] || return 8; fi
  return 0
}

echo "== install.sh: trozos con órdenes simuladas"
esperar 0 "helpers de direcciones IPv4"                   en_instalador p_helpers
esperar 0 "árbol, ids.conf y secretos (idempotentes)"     en_instalador p_arbol_conf_secretos
esperar 1 "--tun-base distinta con puntos: rechazo"       en_instalador p_tun_base_con_puntos
esperar 0 "respaldo antes de tocar nada"                  en_instalador p_respaldo
esperar 0 "modo seguro: reversión armada y confirmación"  en_instalador p_reversion_y_confirmar
esperar 1 "modo seguro: sin confirmación, aborta"         en_instalador p_sin_confirmacion_falla
esperar 0 "modo seguro: la reversión marca antes de tocar" en_instalador p_revertir_escribe_marcador_primero
esperar 0 "modo seguro: --confirmar tras revertir falla"  en_instalador p_confirmar_tras_revertir_falla
esperar 0 "modo seguro: --confirmar sin timer falla"      en_instalador p_confirmar_sin_timer_falla
esperar 0 "modo seguro: --confirmar en carrera falla"     en_instalador p_confirmar_carrera_con_el_timer
esperar 0 "modo seguro: revertido gana a confirmado"      en_instalador p_esperar_revertido_aunque_confirmado
esperar 0 "modo seguro: plazo desde T0, no desde ahora"   en_instalador p_esperar_cuenta_desde_t0
esperar 0 "modo seguro: timer inactivo, falla enseguida"  en_instalador p_esperar_timer_inactivo_falla_ya
esperar 0 "modo seguro: revertido, no dice «instalado»"   en_instalador p_principal_revertido_no_dice_instalado
esperar 0 "acceso SSH: IP de gestión y claves"            en_instalador p_acceso_ssh
esperar 0 "acceso SSH: IP del dueño fuera de --gestion"   en_instalador p_acceso_ssh_dueno_fuera_de_gestion
esperar 0 "acceso SSH: sudo -i, IP desde /proc"           en_instalador p_acceso_ssh_sudo_i_proc
esperar 0 "acceso SSH: IP desde who -m --ips"             en_instalador p_acceso_ssh_who
esperar 0 "acceso SSH: IP desconocida falla sin opciones" en_instalador p_acceso_ssh_ip_desconocida
esperar 1 "ufw instalado: no sigue"                       en_instalador p_paquetes_rechaza_ufw
esperar 0 "fail2ban: jaulas y 2 coincidencias"            en_instalador p_fail2ban
esperar 0 "líneas de §5.13 = fixture de C"                en_instalador p_lineas_contrato
if [ -n "$PY" ]; then
  esperar 0 "daemon.json: fusión y comprobaciones"        en_instalador p_daemon_json
  esperar 0 "imagenes.json de laboratorio (con panel)"    en_instalador p_imagenes_lab
else
  echo "  (sin Python: se omiten daemon.json e imagenes.json)"
fi
esperar 0 "imagenes.json de producción: las tres por digest" en_instalador p_imagenes_produccion_descarga_las_tres
esperar 0 "imagen privada en GHCR: error claro con enlace" en_instalador p_imagen_privada_error_claro
esperar 0 "--zona en ids.conf y se conserva"              en_instalador p_zona_en_ids_conf
esperar 0 "panel nuevo: URL, admin y clave; log sin clave" en_instalador p_panel_nuevo_resumen_y_log_enmascarado
esperar 0 "panel: reinstalación conserva la clave"        en_instalador p_panel_reinstalacion_conserva_la_clave
esperar 0 "panel: crear-admin dice que ya existía"        en_instalador p_panel_admin_ya_existia
esperar 0 "panel: si falla, no sigue"                     en_instalador p_panel_falla_no_dice_instalado
esperar 0 "resumen sin modo seguro y sin IP de ruta"      en_instalador p_sin_reversion_en_el_resumen
esperar 0 "principal completo: clave en pantalla, no en el log" en_instalador p_principal_completo_log_sin_clave
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
