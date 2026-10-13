#!/bin/bash
# ids-maat — instalador del VPS (CONTRATO-F1a §7). Debian 13 (trixie), amd64, como root.
#
#   curl -fsSL https://raw.githubusercontent.com/mtandazo35/IDS_MAAT-Docker/v0.1.0/install.sh \
#        -o /root/ids-maat-install.sh \
#     && bash /root/ids-maat-install.sh --version v0.1.0 --nombre ids.empresa.example \
#          --gestion 192.0.2.0/25,198.51.100.0/26 --proxy 203.0.113.50 \
#          [--tun-base 100.64|198.18] [--dueno-ip 203.0.113.20] [--zona America/Guayaquil]
#
# Al terminar imprime la URL del panel, el usuario «admin» y su clave (UNA sola vez; en el log
# /root/ids-maat/install-<ts>.log sale enmascarada). El panel solo se abre desde --proxy.
#
# Laboratorio (canario antes de la primera release; NO verifica firmas):
#   bash install.sh --desde-repo /root/IDS_MAAT-Docker \
#        --imagenes vpn=<ref>,suricata=<ref>,panel=<ref> --nombre … --gestion … --proxy …
#
# Otras opciones:
#   --zona             zona horaria con la que el panel muestra las fechas (por defecto America/Guayaquil)
#   --solo-validar     valida los argumentos y sale sin tocar nada
#   --confirmar        desde una sesión SSH NUEVA: confirma el acceso y anula la reversión
#   --sin-reversion    sin modo seguro (instalación desde la consola del proveedor)
#   --forzar-acceso    sigue aunque la IP de tu sesión SSH no esté en --gestion o no se pueda
#                      averiguar
#
# Idempotente: volver a ejecutarlo cambia gestión/proxy. Respaldo en /root/backups antes de tocar
# sshd, firewall, Docker o fail2ban. Nunca instala iptables-persistent ni ufw ni hace flush ruleset.
set -euo pipefail
umask 022

OWNER=mtandazo35
REPO=IDS_MAAT-Docker
COSIGN_VERSION=v2.6.5
COSIGN_SHA256=c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644
DOCKER_MAYOR=28
GID_PANEL=10500
UID_PANEL=10500
PUERTO_PANEL=5637
POOL_DOCKER=10.210.0.0/16
VENTANA_REVERSION=300
UNIDAD_REVERSION=ids-maat-revertir-acceso
R="${IDS_RAIZ:-}"            # prefijo de rutas para las pruebas; vacío en producción
R="${R%/}"

VERSION="" NOMBRE="" GESTION="" PROXY="" TUN_BASE="100.64" TUN_BASE_DADO=0 DUENO=""
DESDE_REPO="" IMAGENES="" SOLO_VALIDAR=0 CONFIRMAR=0 SIN_REVERSION=0 FORZAR_ACCESO=0
HOST_DIR="" IMG_VPN="" IMG_SUR="" IMG_PANEL="" DEV=false TS="" T0_REVERSION="" ZONA=""
USUARIO_PANEL=admin PANEL_ESTADO="" CLAVE_PANEL="" LOG_INSTALL=""
PANEL_IP=10.210.255.2      # IP fija del panel en la red ids-core (túnel SSH de emergencia)

# El log del instalador (/root/ids-maat/install-<ts>.log, 0600) recibe lo mismo que log/aviso/
# fallar y el resumen con la clave del panel ENMASCARADA. La clave solo va a la terminal.
registrar() {
  [ -n "$LOG_INSTALL" ] || return 0
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG_INSTALL" 2>/dev/null || true
}
log()    { printf '\033[1;32m==>\033[0m %s\n' "$*"; registrar "==> $*"; }
aviso()  { printf '\033[1;33m!!\033[0m  %s\n' "$*" >&2; registrar "!!  $*"; }
fallar() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; registrar "ERROR: $*"; exit 1; }

uso() {
  sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
}

# ---------------------------------------------------------------------------------------------
# Direcciones IPv4 en bash puro (antes de instalar paquetes no hay python3 garantizado)
# ---------------------------------------------------------------------------------------------
ip_a_int() {
  local o1 o2 o3 o4
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  o1=$((10#${BASH_REMATCH[1]})) o2=$((10#${BASH_REMATCH[2]}))
  o3=$((10#${BASH_REMATCH[3]})) o4=$((10#${BASH_REMATCH[4]}))
  [ "$o1" -le 255 ] && [ "$o2" -le 255 ] && [ "$o3" -le 255 ] && [ "$o4" -le 255 ] || return 1
  echo $(( (o1 << 24) | (o2 << 16) | (o3 << 8) | o4 ))
}

int_a_ip() {
  echo "$(( ($1 >> 24) & 255 )).$(( ($1 >> 16) & 255 )).$(( ($1 >> 8) & 255 )).$(( $1 & 255 ))"
}

# "inicio fin prefijo" de un CIDR o de una IP suelta (/32)
cidr_rango() {
  local ip len n mask ini
  ip="${1%/*}"
  if [[ "$1" == */* ]]; then len="${1#*/}"; else len=32; fi
  [[ "$len" =~ ^[0-9]{1,2}$ ]] && [ "$((10#$len))" -le 32 ] || return 1
  len=$((10#$len))
  n=$(ip_a_int "$ip") || return 1
  if [ "$len" -eq 0 ]; then mask=0; else mask=$(( (0xFFFFFFFF << (32 - len)) & 0xFFFFFFFF )); fi
  ini=$(( n & mask ))
  echo "$ini $(( ini | (~mask & 0xFFFFFFFF) )) $len"
}

cidr_norm() {
  local ini fin len
  read -r ini fin len <<<"$(cidr_rango "$1")" || return 1
  [ -n "$ini" ] || return 1
  : "$fin"
  if [ "$len" -eq 32 ]; then int_a_ip "$ini"; else echo "$(int_a_ip "$ini")/$len"; fi
}

solapan() {
  local a1 a2 b1 b2 x
  read -r a1 a2 x <<<"$(cidr_rango "$1")"
  read -r b1 b2 x <<<"$(cidr_rango "$2")"
  : "$x"
  [ "$a1" -le "$b2" ] && [ "$b1" -le "$a2" ]
}

ip_en_lista() {   # ip_en_lista <ip> <cidr,cidr…>
  local c
  ip_a_int "$1" >/dev/null || return 1
  for c in ${2//,/ }; do
    solapan "$1/32" "$c" && return 0
  done
  return 1
}

# ---------------------------------------------------------------------------------------------
# Argumentos
# ---------------------------------------------------------------------------------------------
parsear_args() {
  local op val
  while [ $# -gt 0 ]; do
    op="$1"; val=""
    case "$op" in
      --*=*) val="${op#*=}"; op="${op%%=*}" ;;
    esac
    case "$op" in
      --solo-validar) SOLO_VALIDAR=1; shift; continue ;;
      --confirmar) CONFIRMAR=1; shift; continue ;;
      --sin-reversion) SIN_REVERSION=1; shift; continue ;;
      --forzar-acceso) FORZAR_ACCESO=1; shift; continue ;;
      -h|--help) uso; exit 0 ;;
      --version|--nombre|--gestion|--proxy|--tun-base|--dueno-ip|--desde-repo|--imagenes|--zona)
        if [ -z "$val" ]; then
          [ $# -ge 2 ] || fallar "falta el valor de $op"
          val="$2"; shift
        fi
        shift ;;
      *) fallar "opción desconocida: $op (--help)" ;;
    esac
    case "$op" in
      --version) VERSION="$val" ;;
      --nombre) NOMBRE="$val" ;;
      --gestion) GESTION="$val" ;;
      --proxy) PROXY="$val" ;;
      --tun-base) TUN_BASE="$val"; TUN_BASE_DADO=1 ;;
      --dueno-ip) DUENO="$val" ;;
      --desde-repo) DESDE_REPO="$val" ;;
      --imagenes) IMAGENES="$val" ;;
      --zona) ZONA="$val" ;;
    esac
  done
}

validar_args() {
  local c norm lista="" lista_proxy="" otro tun
  [[ "$NOMBRE" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] \
    || fallar "--nombre debe ser el nombre DNS del VPS (p. ej. ids.empresa.example)"
  case "$TUN_BASE" in 100.64|198.18) ;; *) fallar "--tun-base debe ser 100.64 o 198.18" ;; esac
  tun="$TUN_BASE.0.0/16"
  [ -n "$GESTION" ] || fallar "--gestion es obligatorio (redes desde las que se entra por SSH)"
  for c in ${GESTION//,/ }; do
    norm=$(cidr_norm "$c") || fallar "--gestion: '$c' no es un CIDR IPv4"
    [ "$(cidr_rango "$c" | cut -d' ' -f3)" -ge 16 ] || fallar "--gestion: '$c' es más ancha que /16 (solo desde la consola)"
    solapan "$c" "$tun" && fallar "--gestion: '$c' se solapa con la base de túneles $tun"
    solapan "$c" "$POOL_DOCKER" && fallar "--gestion: '$c' se solapa con el pool de Docker $POOL_DOCKER"
    for otro in ${lista//,/ }; do
      solapan "$c" "$otro" && fallar "--gestion: '$c' se solapa con '$otro'"
    done
    lista="${lista:+$lista,}$norm"
  done
  GESTION="$lista"
  [ -n "$PROXY" ] || fallar "--proxy es obligatorio (IP del proxy inverso del panel)"
  for c in ${PROXY//,/ }; do
    norm=$(cidr_norm "$c") || fallar "--proxy: '$c' no es una IP o CIDR IPv4"
    [ "$(cidr_rango "$c" | cut -d' ' -f3)" -ge 28 ] || fallar "--proxy: '$c' es más ancha que /28"
    for otro in ${lista_proxy//,/ }; do
      solapan "$c" "$otro" && fallar "--proxy: '$c' se solapa con '$otro'"
    done
    lista_proxy="${lista_proxy:+$lista_proxy,}$norm"
  done
  PROXY="$lista_proxy"
  if [ -n "$DUENO" ]; then
    ip_a_int "$DUENO" >/dev/null || fallar "--dueno-ip debe ser una IPv4"
  fi
  if [ -n "$ZONA" ] && ! [[ "$ZONA" =~ ^(UTC|[A-Za-z]+(/[A-Za-z0-9_+-]+){1,2})$ ]]; then
    fallar "--zona debe ser UTC o Región/Ciudad (p. ej. America/Guayaquil)"
  fi
  if [ -n "$DESDE_REPO" ]; then
    [ -f "$DESDE_REPO/orquestador/ids_orq.py" ] || fallar "--desde-repo: $DESDE_REPO no es un checkout de $REPO"
    [ -n "$IMAGENES" ] || fallar "--desde-repo exige --imagenes vpn=<ref>,suricata=<ref>,panel=<ref>"
    for c in ${IMAGENES//,/ }; do
      case "$c" in
        vpn=*) IMG_VPN="${c#vpn=}" ;;
        suricata=*) IMG_SUR="${c#suricata=}" ;;
        panel=*) IMG_PANEL="${c#panel=}" ;;
        *) fallar "--imagenes: '$c' no es vpn=<ref>, suricata=<ref> ni panel=<ref>" ;;
      esac
    done
    [ -n "$IMG_PANEL" ] || fallar "--imagenes: falta panel=<ref> (el instalador levanta el panel y crea su admin)"
    for c in "$IMG_VPN" "$IMG_SUR" "$IMG_PANEL"; do
      [[ "$c" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$ ]] || fallar "--imagenes: referencia inválida '$c'"
    done
    if [ -z "$VERSION" ]; then
      VERSION="v$(sed -n 's/^ORQ_VERSION = "\(.*\)"$/\1/p' "$DESDE_REPO/orquestador/ids_orq.py")"
    fi
    DEV=true
  else
    [ -z "$IMAGENES" ] || fallar "--imagenes solo vale con --desde-repo (en producción salen de release.json)"
  fi
  [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fallar "--version debe ser vX.Y.Z (p. ej. v0.1.0)"
}

# ---------------------------------------------------------------------------------------------
# Comprobaciones previas
# ---------------------------------------------------------------------------------------------
hay_puntos() {
  compgen -G "${R}/srv/ids/puntos/p[0-9][0-9][0-9]" >/dev/null
}

comprobar_tun_base() {
  local conf="${R}/etc/ids-maat/ids.conf" actual
  [ -f "$conf" ] || return 0
  actual=$(sed -n 's/^TUN_BASE=//p' "$conf")
  [ -n "$actual" ] || return 0
  if [ "$TUN_BASE_DADO" = 0 ]; then
    TUN_BASE="$actual"
  elif [ "$actual" != "$TUN_BASE" ] && hay_puntos; then
    fallar "--tun-base solo se acepta si todavía no hay puntos (la base actual es $actual)"
  fi
}

comprobar_sistema() {
  local os_id os_ver
  [ "$(id -u)" = 0 ] || fallar "ejecútalo como root"
  os_id=$(. "${R}/etc/os-release" && echo "${ID:-}")
  os_ver=$(. "${R}/etc/os-release" && echo "${VERSION_ID:-}")
  [ "$os_id" = debian ] && [ "$os_ver" = 13 ] || fallar "solo Debian 13 (trixie); este es $os_id $os_ver"
  [ "$(dpkg --print-architecture)" = amd64 ] || fallar "solo amd64"
  comprobar_memoria
}

# Admisión del orquestador (INSTANCIA §10.3): host 1024 + panel 1536 (CONTRATO-F2 §6) + un punto
# «reducido» (900 + 192 + 32) + la reserva del suricata -T (900) = 4584 MiB. Por debajo se instala,
# pero no cabe ningún punto: se avisa antes de empezar.
MEM_MIN_UN_PUNTO_MB=4584
comprobar_memoria() {
  local kb
  kb=$(sed -n 's/^MemTotal:[[:space:]]*\([0-9]*\) kB$/\1/p' "${R}/proc/meminfo" 2>/dev/null || true)
  [ -n "$kb" ] || return 0
  if [ $((kb / 1024)) -lt "$MEM_MIN_UN_PUNTO_MB" ]; then
    aviso "memoria: $((kb / 1024)) MiB; con menos de $MEM_MIN_UN_PUNTO_MB MiB no cabe ningún punto (el panel reserva 1536 MiB)"
  fi
  return 0
}

claves_ssh_presentes() {
  local f
  for f in "${R}/root/.ssh/authorized_keys" "${R}/root/.ssh/authorized_keys2"; do
    [ -s "$f" ] && return 0
  done
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    f="$(getent passwd "$SUDO_USER" | cut -d: -f6)/.ssh/authorized_keys"
    [ -s "${R}$f" ] && return 0
  fi
  return 1
}

ppid_de() {   # ppid_de <pid> -> PPid según ${R}/proc/<pid>/status
  sed -n 's/^PPid:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' "${R}/proc/$1/status" 2>/dev/null | head -n1 || true
}

# IP de origen de la sesión SSH. Con «sudo -i» o «su -» se pierde SSH_CONNECTION: se busca en el
# entorno de los procesos padre (/proc/<pid>/environ, subiendo por PPid) y, si no, en «who -m --ips».
ip_sesion_ssh() {
  local pid sc n=0 ip
  if [ -n "${SSH_CONNECTION:-}" ]; then
    echo "${SSH_CONNECTION%% *}"
    return 0
  fi
  pid=$(ppid_de "$$")
  while [[ "$pid" =~ ^[0-9]+$ ]] && [ "$pid" -gt 1 ] && [ "$n" -lt 64 ]; do
    if [ -r "${R}/proc/$pid/environ" ]; then
      sc=$(tr '\0' '\n' < "${R}/proc/$pid/environ" 2>/dev/null | sed -n 's/^SSH_CONNECTION=//p' | head -n1 || true)
      if [ -n "$sc" ]; then
        echo "${sc%% *}"
        return 0
      fi
    fi
    pid=$(ppid_de "$pid")
    n=$((n + 1))
  done
  ip=$(who -m --ips 2>/dev/null | awk 'NF >= 5 {print $NF; exit}' | tr -d '()' || true)
  if [ -n "$ip" ] && { ip_a_int "$ip" >/dev/null || [[ "$ip" =~ ^[0-9A-Fa-f]*:[0-9A-Fa-f]*:[0-9A-Fa-f:.]*$ ]]; }; then
    echo "$ip"
    return 0
  fi
  return 1
}

comprobar_acceso_ssh() {
  local ip
  if ! claves_ssh_presentes && ! sshd -T 2>/dev/null | grep -i '^passwordauthentication no' >/dev/null; then
    fallar "no hay claves en authorized_keys: con PasswordAuthentication no te quedarías fuera"
  fi
  if ! ip=$(ip_sesion_ssh); then
    if [ "$FORZAR_ACCESO" = 1 ] || [ "$SIN_REVERSION" = 1 ]; then
      aviso "no se pudo averiguar la IP de tu sesión SSH: no se comprueba que esté en --gestion"
      return 0
    fi
    fallar "no se pudo averiguar la IP de tu sesión SSH (sudo -i y su - la pierden): ejecútalo como root en la sesión SSH, o usa --sin-reversion desde la consola del proveedor o --forzar-acceso"
  fi
  # Solo cuenta --gestion: es lo único que el set @gestion de ids_host.nft deja entrar al 22
  # (--dueno-ip solo va al ignoreip de fail2ban).
  if ip_en_lista "$ip" "$GESTION"; then
    return 0
  fi
  if [ "$FORZAR_ACCESO" = 1 ]; then
    aviso "tu IP SSH $ip no está en --gestion: te quedarás fuera al aplicar el firewall (--forzar-acceso)"
    return 0
  fi
  fallar "tu IP SSH $ip no está en --gestion ($GESTION): te quedarías fuera. Añádela o usa --forzar-acceso"
}

# ---------------------------------------------------------------------------------------------
# Pasos
# ---------------------------------------------------------------------------------------------
respaldo() {
  local destino rel=() p
  install -d -m 0700 "${R}/root/backups"
  destino="${R}/root/backups/ids-maat-install-${TS}.tar.gz"
  # Incluye el panel (usuarios, routers.json con las claves API cifradas, exclusiones, registros),
  # el estado del orquestador (orq.db), la PKI y los puntos (auditoría B-05). La clave maestra NO
  # entra: con ella y el tar se descifrarían los secretos; se respalda aparte (OPERACION §3, B-06).
  for p in etc/ssh/sshd_config etc/ssh/sshd_config.d etc/docker srv/ids/fw etc/fail2ban etc/ids-maat \
           srv/ids/panel srv/ids/estado srv/ids/pki srv/ids/puntos; do
    [ -e "${R}/$p" ] && rel+=("$p")
  done
  if [ ${#rel[@]} -gt 0 ]; then
    (umask 077; tar -czf "$destino" --exclude=etc/ids-maat/master.key -C "${R:-/}" "${rel[@]}")
  else
    tar -czf "$destino" -T /dev/null
  fi
  chmod 0600 "$destino"
  tar -tzf "$destino" >/dev/null || fallar "el respaldo $destino no se puede leer: no se toca nada"
  if tar -tzf "$destino" | grep -E '(^|/)master\.key$' >/dev/null; then
    fallar "el respaldo $destino lleva la clave maestra: no se toca nada"
  fi
  log "respaldo: $destino (sin la clave maestra: respáldala aparte, OPERACION §3)"
}

paquetes() {
  local pkg
  for pkg in iptables-persistent netfilter-persistent ufw; do
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep 'install ok installed' >/dev/null; then
      fallar "$pkg está instalado: restaura reglas viejas o filtra aparte y pisa a Docker. Quítalo (apt purge $pkg; revisa /etc/iptables/rules.v4) y vuelve a ejecutar"
    fi
  done
  if [ -f "${R}/etc/nftables.conf" ] && systemctl is-enabled nftables.service >/dev/null 2>&1 \
     && grep -Eq '(^|[[:space:]])(accept|drop|reject|dnat|snat|masquerade)([[:space:]]|;|$)' "${R}/etc/nftables.conf"; then
    fallar "nftables.service carga reglas propias de /etc/nftables.conf (empieza por flush ruleset y borraría las de Docker). Pásalas a otra tabla y desactívalo antes"
  fi
  log "paquetes del sistema"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends nftables fail2ban python3 python3-systemd openssl \
    logrotate curl ca-certificates systemd-timesyncd >/dev/null
  # nftables.service hace «flush ruleset» al parar o recargar: se desactiva y se enmascara SIN pararlo
  systemctl disable nftables.service >/dev/null 2>&1 || true
  systemctl mask nftables.service >/dev/null 2>&1 || true
}

docker_ce() {
  local v mayor
  if command -v docker >/dev/null 2>&1; then
    v=$(docker version --format '{{.Server.Version}}' 2>/dev/null || docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    mayor="${v%%.*}"
    [ "$mayor" = "$DOCKER_MAYOR" ] || fallar "hay Docker $v instalado; ids-maat fija la versión mayor $DOCKER_MAYOR y no la cambia sola"
    if ! docker compose version >/dev/null 2>&1; then
      apt-get install -y -qq docker-compose-plugin >/dev/null || fallar "falta docker-compose-plugin"
    fi
    log "Docker $v ya instalado"
    return 0
  fi
  log "Docker CE $DOCKER_MAYOR desde download.docker.com"
  install -d -m 0755 "${R}/etc/apt/keyrings" "${R}/etc/apt/preferences.d"
  curl -fsSL https://download.docker.com/linux/debian/gpg -o "${R}/etc/apt/keyrings/docker.asc"
  chmod a+r "${R}/etc/apt/keyrings/docker.asc"
  echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable" \
    > "${R}/etc/apt/sources.list.d/docker.list"
  cat > "${R}/etc/apt/preferences.d/ids-maat-docker" <<EOF
# ids-maat: versión mayor de Docker fijada; cada salto se prueba en el canario
Package: docker-ce docker-ce-cli docker-ce-rootless-extras
Pin: version 5:${DOCKER_MAYOR}.*
Pin-Priority: 1001
EOF
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
}

docker_daemon() {
  local dst="${R}/etc/docker/daemon.json" r
  install -d -m 0755 "${R}/etc/docker"
  r=$(python3 - "$dst" "$HOST_DIR/host/docker/daemon.json" <<'PY'
import json, os, sys
dst, src = sys.argv[1], sys.argv[2]
nuevo = json.load(open(src, encoding="utf-8"))
actual = json.load(open(dst, encoding="utf-8")) if os.path.exists(dst) and os.path.getsize(dst) else {}
fusion = dict(actual)
fusion.update(nuevo)
if fusion == actual:
    print("igual")
else:
    with open(dst + ".ids-nuevo", "w", encoding="utf-8") as f:
        json.dump(fusion, f, indent=2)
        f.write("\n")
    print("cambia")
PY
)
  if [ "$r" = cambia ]; then
    mv "${dst}.ids-nuevo" "$dst"
    if [ -n "$(docker ps -q 2>/dev/null)" ]; then
      aviso "daemon.json cambia con contenedores en marcha: se reinicia dockerd (live-restore todavía no estaba activo)"
    fi
    systemctl restart docker
    log "daemon.json actualizado (live-restore, userland-proxy false, bip, pool)"
  fi
  systemctl enable --now docker >/dev/null
  docker info >/dev/null || fallar "dockerd no responde"
  update-alternatives --query iptables 2>/dev/null | grep '^Value: /usr/sbin/iptables-nft$' >/dev/null \
    || fallar "iptables no es iptables-nft (update-alternatives --set iptables /usr/sbin/iptables-nft)"
}

modulos_sysctl_hora() {
  local m
  install -m 0644 "$HOST_DIR/host/modules/ids.conf" "${R}/etc/modules-load.d/ids.conf"
  for m in tun veth nft_ct; do modprobe "$m" 2>/dev/null || aviso "no se pudo cargar el módulo $m"; done
  install -m 0644 "$HOST_DIR/host/sysctl/90-ids.conf" "${R}/etc/sysctl.d/90-ids.conf"
  sysctl -q -p "${R}/etc/sysctl.d/90-ids.conf" >/dev/null || aviso "sysctl 90-ids.conf no se aplicó"
  systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || aviso "systemd-timesyncd no arrancó"
}

mkd() {   # mkd <ruta> <modo> [gid]
  install -d -m "$2" "${R}$1"
  chmod "$2" "${R}$1"
  chown "root:${3:-0}" "${R}$1"
}

usuario_y_arbol() {
  local g u
  g=$(getent group ids-panel | cut -d: -f3 || true)
  if [ -z "$g" ]; then
    getent group "$GID_PANEL" >/dev/null && fallar "el gid $GID_PANEL ya lo usa otro grupo"
    groupadd -g "$GID_PANEL" ids-panel
  elif [ "$g" != "$GID_PANEL" ]; then
    fallar "el grupo ids-panel existe con gid $g (se necesita $GID_PANEL)"
  fi
  u=$(getent passwd ids-panel | cut -d: -f3 || true)
  if [ -z "$u" ]; then
    getent passwd "$UID_PANEL" >/dev/null && fallar "el uid $UID_PANEL ya lo usa otro usuario"
    useradd -u "$UID_PANEL" -g "$GID_PANEL" -M -d /nonexistent -s /usr/sbin/nologin ids-panel
  elif [ "$u" != "$UID_PANEL" ]; then
    fallar "el usuario ids-panel existe con uid $u (se necesita $UID_PANEL)"
  fi
  mkd /etc/ids-maat 0750
  mkd /srv/ids 0755
  mkd /srv/ids/estado 0700
  mkd /srv/ids/pki 0700
  mkd /srv/ids/pki/servidores 0700
  mkd /srv/ids/fw 0700
  mkd /srv/ids/puntos 0700
  mkd /srv/ids/datos 0750 "$GID_PANEL"
  mkd /srv/ids/run 0750 "$GID_PANEL"
  mkd /srv/ids/ctl 0700
  mkd /srv/ids/reglas 0755
  mkd /srv/ids/reglas/releases 0755
  mkd /srv/ids/reglas/cache 0755
  mkd /root/ids-maat 0700
  mkd /root/backups 0700
}

escribir_ids_conf() {
  local tmp="${R}/etc/ids-maat/.ids.conf.nuevo" conf="${R}/etc/ids-maat/ids.conf"
  # sin --zona se conserva la que hubiera (como con --tun-base)
  if [ -z "$ZONA" ] && [ -f "$conf" ]; then
    ZONA=$(sed -n 's/^ZONA_HORARIA=//p' "$conf")
  fi
  cat > "$tmp" <<EOF
VERSION=${VERSION#v}
NOMBRE_DNS=$NOMBRE
TUN_BASE=$TUN_BASE
REDES_GESTION=$GESTION
IPS_PROXY=$PROXY
IGNOREIP_DUENO=$DUENO
PUERTO_PANEL=$PUERTO_PANEL
POOL_DOCKER=$POOL_DOCKER
EOF
  if [ -n "$ZONA" ]; then echo "ZONA_HORARIA=$ZONA" >> "$tmp"; fi
  chmod 0644 "$tmp"
  mv "$tmp" "${R}/etc/ids-maat/ids.conf"
}

hex32() {
  od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
}

secretos() {
  local d="${R}/etc/ids-maat"
  if [ ! -s "$d/master.key" ]; then
    (umask 077; hex32 > "$d/master.key")
  fi
  # CONTRATO-F2 §10.3: se monta en el panel (/run/secrets/master_key, ro), que corre como 10500
  # sin capacidades y la lee por grupo. Fuera de los respaldos tar: se guarda aparte (OPERACION §3).
  chmod 0440 "$d/master.key"; chown "root:$GID_PANEL" "$d/master.key"
  if [ ! -s "$d/orq_token" ]; then
    (umask 077; hex32 > "$d/orq_token")
  fi
  chmod 0640 "$d/orq_token"; chown "root:$GID_PANEL" "$d/orq_token"
  [ -e "$d/avisos.conf" ] || : > "$d/avisos.conf"
  chmod 0600 "$d/avisos.conf"; chown root:0 "$d/avisos.conf"
}

pki() {
  local p="${R}/srv/ids/pki"
  if [ ! -s "$p/ca.crt" ] || [ ! -s "$p/ca.key" ]; then
    log "PKI: CA común del VPS (RSA 2048, SHA-256, 20 años)"
    openssl req -x509 -newkey rsa:2048 -sha256 -days 7300 -nodes \
      -keyout "$p/ca.key" -out "$p/ca.crt" -subj "/CN=ids-maat-ca $NOMBRE" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  fi
  chmod 0600 "$p/ca.key"; chmod 0644 "$p/ca.crt"
  if [ ! -s "$p/dh.pem" ]; then
    openssl genpkey -genparam -algorithm DH -pkeyopt dh_param:ffdhe2048 -out "$p/dh.pem" 2>/dev/null
  fi
  chmod 0644 "$p/dh.pem"
}

asegurar_cosign() {
  local bin="${R}/root/ids-maat/bin/cosign-${COSIGN_VERSION}"
  install -d -m 0700 "${R}/root/ids-maat/bin"
  if [ -x "$bin" ] && echo "$COSIGN_SHA256  $bin" | sha256sum -c --status 2>/dev/null; then
    echo "$bin"; return 0
  fi
  curl -fsSL -o "$bin.tmp" "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
  echo "$COSIGN_SHA256  $bin.tmp" | sha256sum -c --status || { rm -f "$bin.tmp"; fallar "sha256 de cosign incorrecto"; }
  chmod 0755 "$bin.tmp"
  mv "$bin.tmp" "$bin"
  echo "$bin"
}

# Por qué falló una descarga o una verificación de imagen. Los paquetes de GHCR nacen privados
# aunque el repo sea público: sin credenciales, el registro contesta «denied»/«unauthorized».
motivo_registro() {   # motivo_registro <ref> <salida de docker pull o de cosign>
  local nombre="${1%%@*}" ultima="" linea
  nombre="${nombre##*/}"
  nombre="${nombre%%:*}"
  if [[ "$1" == ghcr.io/* ]] && [[ "${2,,}" =~ (denied|unauthorized|authentication\ required|forbidden) ]]; then
    echo "el paquete ghcr.io/$OWNER/$nombre es privado (o no existe). Los paquetes de GHCR nacen privados: hazlo público en https://github.com/users/$OWNER/packages/container/$nombre/settings (Danger Zone > Change visibility > Public) y vuelve a ejecutar (docs/ACTUALIZACIONES.md §1)"
    return 0
  fi
  while IFS= read -r linea; do
    [ -n "$linea" ] && ultima="$linea"
  done <<<"$2"
  echo "${ultima:-sin detalle}"
}

obtener_release() {
  local cosign rel base id iss datos v tar_nombre tar_sha destino tmp salida
  if [ -n "$DESDE_REPO" ]; then
    HOST_DIR="$DESDE_REPO"
    aviso "################################################################"
    aviso "#  MODO LABORATORIO: --desde-repo $DESDE_REPO"
    aviso "#  NO se verifican firmas; imagenes.json queda con \"dev\": true"
    aviso "################################################################"
    return 0
  fi
  cosign=$(asegurar_cosign)
  rel="${R}/root/ids-maat/release-${VERSION}"
  install -d -m 0700 "$rel"
  base="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}"
  log "release $VERSION: descarga y verificación (cosign keyless)"
  curl -fsSL -o "$rel/release.json" "$base/release.json"
  curl -fsSL -o "$rel/release.json.bundle" "$base/release.json.bundle"
  id="^https://github\\.com/${OWNER}/${REPO}/\\.github/workflows/release\\.yml@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+\$"
  iss="https://token.actions.githubusercontent.com"
  "$cosign" verify-blob --bundle "$rel/release.json.bundle" --certificate-identity-regexp "$id" \
    --certificate-oidc-issuer "$iss" "$rel/release.json" >/dev/null 2>&1 \
    || fallar "la firma de release.json no es válida"
  datos=$(python3 - "$rel/release.json" <<'PY'
import json, re, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
assert d.get("v") == 1
for parte in ("vpn", "suricata", "panel"):
    ref = d["imagenes"][parte]
    assert re.fullmatch(r"ghcr\.io/mtandazo35/ids-maat-%s@sha256:[0-9a-f]{64}" % parte, ref), ref
t = d["host_tar"]
assert re.fullmatch(r"ids-maat-host-[0-9.]+\.tar\.gz", t["nombre"]) and re.fullmatch(r"[0-9a-f]{64}", t["sha256"])
print(d["version"], d["imagenes"]["vpn"], d["imagenes"]["suricata"], d["imagenes"]["panel"], t["nombre"],
      t["sha256"])
PY
) || fallar "release.json no tiene el formato esperado (¿release anterior a F1b, sin la imagen del panel?)"
  read -r v IMG_VPN IMG_SUR IMG_PANEL tar_nombre tar_sha <<<"$datos"
  [ "v$v" = "$VERSION" ] || fallar "release.json es de la versión $v, no de $VERSION"
  curl -fsSL -o "$rel/$tar_nombre" "$base/$tar_nombre"
  echo "$tar_sha  $rel/$tar_nombre" | sha256sum -c --status || fallar "sha256 de $tar_nombre incorrecto"
  for v in "$IMG_VPN" "$IMG_SUR" "$IMG_PANEL"; do
    salida=$("$cosign" verify --certificate-identity-regexp "$id" --certificate-oidc-issuer "$iss" "$v" 2>&1) \
      || fallar "la firma de la imagen $v no se pudo verificar: $(motivo_registro "$v" "$salida")"
  done
  destino="${R}/root/ids-maat/host-${VERSION#v}"
  tmp="${destino}.tmp"
  rm -rf "$tmp"
  install -d -m 0700 "$tmp"
  tar -xzf "$rel/$tar_nombre" -C "$tmp" --no-same-owner
  rm -rf "$destino"
  mv "$tmp" "$destino"
  HOST_DIR="$destino"
  DEV=false
}

instalar_orquestador() {
  local lib="${R}/usr/local/lib/ids-orq" u
  log "orquestador y unidades systemd"
  install -d -m 0755 "$lib" "$lib/plantillas" "${R}/usr/local/bin" "${R}/etc/systemd/system"
  install -m 0755 "$HOST_DIR/orquestador/ids_orq.py" "$lib/ids_orq.py"
  install -m 0644 "$HOST_DIR"/orquestador/plantillas/*.tmpl "$lib/plantillas/"
  printf '#!/bin/sh\nexec python3 /usr/local/lib/ids-orq/ids_orq.py "$@"\n' > "${R}/usr/local/bin/ids-orq"
  chmod 0755 "${R}/usr/local/bin/ids-orq"
  for u in "$HOST_DIR"/host/systemd/*; do
    install -m 0644 "$u" "${R}/etc/systemd/system/"
  done
  install -m 0644 "$HOST_DIR/host/logrotate/ids-maat.conf" "${R}/etc/ids-maat/logrotate.conf"
  install -d -m 0755 "${R}/var/lib/logrotate"
  systemctl daemon-reload
}

armar_reversion() {
  local ant="${R}/root/ids-maat/acceso-anterior-${TS}" script="${R}/root/ids-maat/revertir-acceso.sh"
  [ "$SIN_REVERSION" = 1 ] && { aviso "sin modo seguro (--sin-reversion)"; return 0; }
  install -d -m 0700 "$ant"
  [ -f "${R}/srv/ids/fw/ids_host.nft" ] && cp -p "${R}/srv/ids/fw/ids_host.nft" "$ant/ids_host.nft"
  [ -f "${R}/etc/ssh/sshd_config.d/10-ids.conf" ] && cp -p "${R}/etc/ssh/sshd_config.d/10-ids.conf" "$ant/10-ids.conf"
  cat > "$script" <<EOF
#!/bin/bash
# Generado por install.sh ($TS): vuelve al acceso anterior (firewall del host y sshd)
# si nadie confirmó desde una sesión SSH nueva en ${VENTANA_REVERSION} s.
set -u
# Marcador primero: desde aquí ni --confirmar ni el instalador pueden darlo por confirmado.
date -u +%s > /root/ids-maat/acceso-revertido
D="/root/ids-maat/acceso-anterior-${TS}"
if [ -f "\$D/ids_host.nft" ]; then
  cp -p "\$D/ids_host.nft" /srv/ids/fw/ids_host.nft
  nft -f /srv/ids/fw/ids_host.nft
else
  nft delete table inet ids_host 2>/dev/null
  rm -f /srv/ids/fw/ids_host.nft
  systemctl disable ids-host-fw.service 2>/dev/null
fi
if [ -f "\$D/10-ids.conf" ]; then
  cp -p "\$D/10-ids.conf" /etc/ssh/sshd_config.d/10-ids.conf
else
  rm -f /etc/ssh/sshd_config.d/10-ids.conf
fi
sshd -t && systemctl reload ssh
logger -t ids-maat "acceso revertido: install.sh no se confirmó a tiempo"
echo "REVERTIDO \$(date -u)"
EOF
  chmod 0700 "$script"
  rm -f "${R}/root/ids-maat/acceso-confirmado" "${R}/root/ids-maat/acceso-revertido"
  systemctl stop "${UNIDAD_REVERSION}.timer" >/dev/null 2>&1 || true
  systemctl reset-failed "${UNIDAD_REVERSION}.service" "${UNIDAD_REVERSION}.timer" >/dev/null 2>&1 || true
  T0_REVERSION=$(date +%s)     # el timer vence en T0 + VENTANA: la espera se mide desde aquí
  systemd-run --quiet --unit "$UNIDAD_REVERSION" --on-active="$VENTANA_REVERSION" /bin/bash /root/ids-maat/revertir-acceso.sh
  log "modo seguro: si no se confirma en $((VENTANA_REVERSION / 60)) min, el acceso vuelve a como estaba"
}

comprobar_puertos_ajenos() {
  # El firewall del IDS descarta todo lo publicado por Docker fuera de @puertos_vpn y del panel, y
  # deja el host con política drop salvo SSH: en un VPS con otros servicios los cortaría.
  # Los del IDS llevan la etiqueta ids-maat.parte (vpn, suricata o panel).
  local ajenos escuchan
  ajenos=$(docker ps --format '{{.Names}}|{{.Label "ids-maat.parte"}}|{{.Ports}}' 2>/dev/null \
           | awk -F'|' '$2 == "" && $3 ~ /->/ {print $1 " (" $3 ")"}')
  if [ -n "$ajenos" ]; then
    fallar "hay contenedores ajenos al IDS con puertos publicados; el firewall del IDS los cortaría (el VPS debe ser dedicado): $ajenos"
  fi
  escuchan=$(ss -Hltn 2>/dev/null | awk '{print $4}' | grep -Ev '^(127\.|\[::1\]|::1)' \
             | sed 's/.*://' | grep -vx 22 | sort -un | tr '\n' ' ' || true)
  if [ -n "$escuchan" ]; then
    aviso "servicios del host escuchando en TCP $escuchan: con el firewall del IDS solo queda abierto el 22 (desde gestión)"
  fi
}

firewall() {
  comprobar_puertos_ajenos
  log "firewall del host (inet ids_host): SSH solo desde $GESTION, panel $PUERTO_PANEL solo desde $PROXY"
  IDS_RAIZ="${R:-/}" "${R}/usr/local/bin/ids-orq" fw-render --aplicar || fallar "el firewall no pasó nft -c"
  systemctl enable ids-host-fw.service >/dev/null
}

ssh_endurecer() {
  install -d -m 0755 "${R}/etc/ssh/sshd_config.d"
  install -m 0644 "$HOST_DIR/host/ssh/10-ids.conf" "${R}/etc/ssh/sshd_config.d/10-ids.conf"
  if ! sshd -t; then
    rm -f "${R}/etc/ssh/sshd_config.d/10-ids.conf"
    fallar "sshd -t falló con 10-ids.conf: retirado"
  fi
  systemctl reload ssh
  sshd -T 2>/dev/null | grep -i '^passwordauthentication no$' >/dev/null \
    || fallar "sshd -T no muestra «passwordauthentication no» (otro fichero de sshd_config.d lo pisa)"
  log "sshd: PasswordAuthentication no"
}

lineas_ids_vpn() {   # CONTRATO-F1a §5.13. Solo casan las 2 de «ovpn-auth: rechazado» (una por intento)
  cat <<'EOF'
203.0.113.45:51234 TLS Auth Error: Auth Username/Password verification failed for peer
203.0.113.45:51234 TLS Error: TLS handshake failed
203.0.113.45:51234 ovpn-auth: rechazado usuario=vpn3a9f2c motivo=clave
203.0.113.45:51234 ovpn-auth: rechazado usuario=- motivo=freno
203.0.113.45:51234 ovpn-auth: aceptado usuario=vpn3a9f2c
tzsp-decap: rx=10 tx=10 descartados=0 muy_grandes=0 rechazados_origen=0 ultimo_origen=100.64.3.2
EOF
}

casan() {   # casan <fichero de líneas> <filtro> -> número de líneas que casan
  fail2ban-regex -d '{NONE}' "$1" "$2" 2>/dev/null | sed -n 's/^Lines: .* \([0-9][0-9]*\) matched.*/\1/p' | head -n1
}

render_jaula() {
  sed "s|@@IGNOREIP_DUENO@@|${DUENO}|" "$HOST_DIR/host/fail2ban/jail.d/10-ids.local.tmpl"
}

fail2ban_jaulas() {
  local f2b="${R}/etc/fail2ban" tmp n
  log "fail2ban: jaulas sshd e ids-vpn"
  install -d -m 0755 "$f2b/jail.d" "$f2b/filter.d"
  render_jaula > "$f2b/jail.d/10-ids.local"
  chmod 0644 "$f2b/jail.d/10-ids.local"
  install -m 0644 "$HOST_DIR/host/fail2ban/filter.d/ids-vpn.conf" "$f2b/filter.d/ids-vpn.conf"
  install -m 0644 "$HOST_DIR/host/fail2ban/filter.d/sshd.local.tmpl" "$f2b/filter.d/sshd.local"
  tmp="${R}/root/ids-maat/ids-vpn-lineas.txt"
  lineas_ids_vpn > "$tmp"
  n=$(casan "$tmp" "$f2b/filter.d/ids-vpn.conf")
  rm -f "$tmp"
  [ "$n" = 2 ] || fallar "el filtro ids-vpn casa con ${n:-0} de las líneas del contrato (se esperaban 2: ovpn-auth rechazado)"
  systemctl enable fail2ban >/dev/null 2>&1
  systemctl restart fail2ban
  for _ in $(seq 1 15); do
    if fail2ban-client status sshd >/dev/null 2>&1 && fail2ban-client status ids-vpn >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fallar "fail2ban no levantó las jaulas sshd e ids-vpn (journalctl -u fail2ban)"
}

reversion_armada() {   # el timer de la reversión sigue pendiente (activo y sin vencer)
  systemctl is-active --quiet "${UNIDAD_REVERSION}.timer" 2>/dev/null || return 1
  [ "$(systemctl show -p SubState --value "${UNIDAD_REVERSION}.timer" 2>/dev/null || true)" != elapsed ]
}

reversion_en_marcha() {   # la reversión ya empezó (marcador) o su servicio está corriendo
  [ -e "${R}/root/ids-maat/acceso-revertido" ] && return 0
  case "$(systemctl is-active "${UNIDAD_REVERSION}.service" 2>/dev/null || true)" in
    active|activating|deactivating|reloading) return 0 ;;
  esac
  return 1
}

esperar_confirmacion() {
  local fin
  [ "$SIN_REVERSION" = 1 ] && return 0
  echo
  log "CONFIRMA EL ACCESO: abre una sesión SSH NUEVA desde una red de gestión y ejecuta"
  log "    bash $(readlink -f "$0") --confirmar"
  log "(si no llega en $((VENTANA_REVERSION / 60)) min, el firewall y sshd vuelven a como estaban)"
  # El plazo cuenta desde que se armó el timer (T0), no desde ahora: firewall, sshd y fail2ban
  # ya gastaron parte de la ventana. Se deja de esperar 10 s antes de que venza.
  fin=$(( ${T0_REVERSION:-$(date +%s)} + VENTANA_REVERSION - 10 ))
  while [ "$(date +%s)" -lt "$fin" ]; do
    if [ -e "${R}/root/ids-maat/acceso-revertido" ]; then
      fallar "el acceso se revirtió (/root/ids-maat/acceso-revertido): ids-maat NO quedó instalado. Revisa --gestion y vuelve a ejecutar"
    fi
    if [ -f "${R}/root/ids-maat/acceso-confirmado" ]; then
      log "acceso confirmado"
      return 0
    fi
    if ! reversion_armada; then
      # --confirmar para el timer justo antes de escribir su marca: se le da un momento
      sleep 2
      if [ -f "${R}/root/ids-maat/acceso-confirmado" ] && [ ! -e "${R}/root/ids-maat/acceso-revertido" ]; then
        log "acceso confirmado"
        return 0
      fi
      fallar "el temporizador de la reversión ya no está activo y nadie confirmó: el acceso puede haberse revertido. Revisa --gestion y vuelve a ejecutar"
    fi
    sleep 2
  done
  fallar "no se confirmó el acceso: se revierte. Revisa --gestion y vuelve a ejecutar"
}

confirmar_acceso() {
  if reversion_en_marcha; then
    fallar "la reversión ya se ejecutó o está en marcha: el acceso vuelve a como estaba. Vuelve a ejecutar el instalador"
  fi
  if ! reversion_armada; then
    fallar "no hay reversión pendiente (${UNIDAD_REVERSION}.timer no está activo): ya venció o no se armó; no se confirma nada"
  fi
  systemctl stop "${UNIDAD_REVERSION}.timer" >/dev/null 2>&1 || true
  # el timer pudo dispararse entre la comprobación y el stop
  if reversion_en_marcha; then
    fallar "la reversión empezó mientras se confirmaba: el acceso vuelve a como estaba. Vuelve a ejecutar el instalador"
  fi
  systemctl reset-failed "${UNIDAD_REVERSION}.service" "${UNIDAD_REVERSION}.timer" >/dev/null 2>&1 || true
  install -d -m 0700 "${R}/root/ids-maat"
  date -u +%s > "${R}/root/ids-maat/acceso-confirmado"
  echo "CONFIRMADO: reversión anulada"
}

imagenes() {
  local f="${R}/etc/ids-maat/imagenes.json" img salida
  printf '{"v": 1, "version": "%s", "dev": %s,\n "imagenes": {"vpn": "%s",\n              "suricata": "%s",\n              "panel": "%s"}}\n' \
    "${VERSION#v}" "$DEV" "$IMG_VPN" "$IMG_SUR" "$IMG_PANEL" > "$f.nuevo"
  chmod 0644 "$f.nuevo"
  mv "$f.nuevo" "$f"
  for img in "$IMG_VPN" "$IMG_SUR" "$IMG_PANEL"; do
    if [ "$DEV" = true ] && docker image inspect "$img" >/dev/null 2>&1; then
      continue
    fi
    log "docker pull $img"
    salida=$(docker pull -q "$img" 2>&1) || fallar "no se pudo descargar $img: $(motivo_registro "$img" "$salida")"
  done
}

arrancar() {
  systemctl enable ids-orq.service >/dev/null
  systemctl restart ids-orq.service
  for _ in $(seq 1 30); do
    [ -S "${R}/run/ids-orq/orq.sock" ] && break
    sleep 1
  done
  [ -S "${R}/run/ids-orq/orq.sock" ] || fallar "ids-orq no abrió su socket (journalctl -u ids-orq)"
  log "reglas: primera descarga y validación (unos minutos)"
  "${R}/usr/local/bin/ids-orq" reglas actualizar || fallar "ids-orq reglas actualizar falló"
  systemctl enable --now ids-reglas.timer ids-logrotate.timer >/dev/null
}

# Núcleo: ids-orq renderiza /srv/ids/core/compose.yml (proyecto ids-core, panel en 10.210.255.2),
# lo levanta y espera a sano. Si no hay usuarios, crea «admin» con un contenedor de un solo uso
# y guarda la clave SOLO en una variable para el resumen. En una reinstalación no la toca.
panel() {
  local salida="" rc=0 linea
  log "panel: núcleo ids-core ($PANEL_IP, $PUERTO_PANEL/tcp publicado solo para --proxy)"
  "${R}/usr/local/bin/ids-orq" panel aplicar >/dev/null \
    || fallar "el panel no quedó sano (docker logs ids-core-panel; ids-orq panel aplicar)"
  if [ -e "${R}/srv/ids/panel/conf/usuarios.json" ]; then
    PANEL_ESTADO=existente
    log "panel: ya hay usuarios (/srv/ids/panel/conf/usuarios.json): se conserva la clave existente"
    return 0
  fi
  salida=$("${R}/usr/local/bin/ids-orq" panel crear-admin --usuario "$USUARIO_PANEL") || rc=$?
  case "$rc" in
    0)
      while IFS= read -r linea; do
        if [[ "$linea" =~ ^CLAVE=([^[:space:]]+)$ ]]; then CLAVE_PANEL="${BASH_REMATCH[1]}"; break; fi
      done <<<"$salida"
      salida=""
      [ -n "$CLAVE_PANEL" ] || fallar "ids-orq panel crear-admin no devolvió la línea CLAVE=…"
      PANEL_ESTADO=nuevo
      log "panel: usuario $USUARIO_PANEL creado (la clave sale en el resumen, una sola vez)" ;;
    3)
      PANEL_ESTADO=existente
      log "panel: el usuario $USUARIO_PANEL ya existía: se conserva su clave" ;;
    *)
      fallar "ids-orq panel crear-admin falló (código $rc)" ;;
  esac
}

ip_publica() {   # IP de origen de la ruta por defecto (sin enviar nada); vacío si no hay
  ip -4 route get 192.0.2.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' || true
}

resumen_texto() {   # resumen_texto <clave tal como se muestra>
  local ip
  ip=$(ip_publica)
  ip="${ip%%$'\n'*}"
  echo
  echo "==> ids-maat $VERSION instalado$([ "$DEV" = true ] && echo ' (LABORATORIO, sin firmas)')"
  echo "  nombre DNS        $NOMBRE"
  echo "  base de túneles   $TUN_BASE.N.0/24"
  echo "  SSH (22/tcp)      solo desde $GESTION"
  echo "  OpenVPN           1194+N-1/tcp, uno por punto, con freno de conexiones nuevas"
  if [ "$SIN_REVERSION" = 1 ]; then
    echo "  modo seguro       no (--sin-reversion)"
  else
    echo "  modo seguro       acceso confirmado; al cambiar --gestion o --proxy se vuelve a pedir"
    echo "                    (bash /root/ids-maat-install.sh --confirmar desde una sesión SSH NUEVA)"
  fi
  echo "  respaldo          /root/backups/ids-maat-install-${TS}.tar.gz"
  echo
  echo "PANEL"
  echo "  URL               http://$NOMBRE:$PUERTO_PANEL${ip:+   (o http://$ip:$PUERTO_PANEL)}"
  echo "                    solo se abre desde las IP de --proxy: $PROXY"
  echo "                    sin proxy, desde gestión: ssh -L $PUERTO_PANEL:$PANEL_IP:5637 root@$NOMBRE"
  echo "                    y en el navegador http://localhost:$PUERTO_PANEL"
  echo "  usuario           $USUARIO_PANEL"
  if [ "$PANEL_ESTADO" = nuevo ]; then
    echo "  clave             $1"
    echo "                    se muestra UNA sola vez: no se guarda en claro en ningún fichero ni log"
  else
    echo "  clave             se conserva la existente (reinstalación)"
  fi
  echo "  restablecer       ids-orq panel restablecer $USUARIO_PANEL   (imprime CLAVE=<nueva>)"
  echo
  echo "Siguiente paso:  entra al panel, o desde SSH: ids-orq punto crear --nombre norte --redes 10.0.0.0/24"
}

resumen() {
  resumen_texto "$CLAVE_PANEL"
  if [ -n "$LOG_INSTALL" ]; then
    resumen_texto "$([ -n "$CLAVE_PANEL" ] && echo '******** (enmascarada; solo se mostró en pantalla)')" \
      >> "$LOG_INSTALL" 2>/dev/null || true
    echo "log del instalador: $LOG_INSTALL (sin la clave)"
  fi
  CLAVE_PANEL=""
}

principal() {
  parsear_args "$@"
  if [ "$CONFIRMAR" = 1 ]; then
    confirmar_acceso
    return 0
  fi
  validar_args
  if [ "$SOLO_VALIDAR" = 1 ]; then
    comprobar_tun_base
    echo "argumentos válidos: nombre=$NOMBRE gestion=$GESTION proxy=$PROXY tun-base=$TUN_BASE version=$VERSION"
    return 0
  fi
  comprobar_sistema
  comprobar_tun_base
  comprobar_acceso_ssh
  TS=$(date -u +%Y%m%dT%H%M%SZ)
  install -d -m 0700 "${R}/root/ids-maat"
  LOG_INSTALL="${R}/root/ids-maat/install-${TS}.log"
  (umask 077; : > "$LOG_INSTALL")
  registrar "install.sh $VERSION: nombre=$NOMBRE gestion=$GESTION proxy=$PROXY tun-base=$TUN_BASE"
  respaldo                   # 2
  paquetes                   # 3
  obtener_release            # 11 (adelantado: host/ y el orquestador salen de la release verificada)
  docker_ce                  # 4
  docker_daemon              # 4
  modulos_sysctl_hora        # 5
  usuario_y_arbol            # 6
  escribir_ids_conf          # 6
  secretos                   # 6
  pki                        # 7
  instalar_orquestador       # 11
  armar_reversion            # modo seguro
  firewall                   # 8
  ssh_endurecer              # 9
  fail2ban_jaulas            # 10
  esperar_confirmacion       # modo seguro
  imagenes                   # 11
  arrancar                   # 12
  panel                      # F1b: núcleo ids-core y primer admin
  resumen                    # 13 (URL, usuario y clave del panel)
}

if [ "${IDS_INSTALL_SOLO_FUNCIONES:-0}" != 1 ]; then
  principal "$@"
fi
