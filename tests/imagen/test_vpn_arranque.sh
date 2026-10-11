#!/usr/bin/env bash
# test_vpn_arranque.sh — prueba de imagen del contenedor vpn (CONTRATO-F1a §8.2, constructor A).
#
# Con una PKI de prueba (openssl) y un /srv temporal:
#   1. el contenedor llega a `healthy` sin tráfico;
#   2. existen ids-in/ids-mon, las tablas `inet ids_punto` y `netdev ids_mon`, api.sock 0660
#      grupo 10500 y tzsp.json 0640 grupo 10500;
#   3. `kill` de openvpn -> s6 lo relanza, el contenedor no se reinicia y el veth sigue;
#   4. con TUN_MK inválido el contenedor sale.
#
# Necesita: Docker Linux, IDS_IMG_VPN (p. ej. ids-maat-vpn:ci), openssl, python3 y ser root o
# tener `sudo -n` (los directorios montados tienen que ser de root, como en producción: el root
# del contenedor no tiene CAP_DAC_OVERRIDE). Si falta algo, sale con 77 (OMITIDA).
set -euo pipefail

omitir() { echo "test_vpn_arranque: OMITIDA: $*"; exit 77; }
fallo() { echo "test_vpn_arranque: FALLO: $*" >&2; exit 1; }
ok() { echo "test_vpn_arranque: ok: $*"; }

[ -n "${IDS_IMG_VPN:-}" ] || omitir "falta IDS_IMG_VPN"
[ "$(uname -s)" = "Linux" ] || omitir "no es Linux"
command -v docker >/dev/null 2>&1 || omitir "sin docker"
docker info >/dev/null 2>&1 || omitir "docker no responde"
command -v openssl >/dev/null 2>&1 || omitir "sin openssl"
command -v python3 >/dev/null 2>&1 || omitir "sin python3"
[ -e /dev/net/tun ] || omitir "sin /dev/net/tun"
if [ "$(id -u)" -eq 0 ]; then
  SUDO=()
elif sudo -n true 2>/dev/null; then
  SUDO=(sudo -n)
else
  omitir "hace falta root o sudo -n"
fi
docker image inspect "$IDS_IMG_VPN" >/dev/null 2>&1 || fallo "no existe la imagen $IDS_IMG_VPN"

RAIZ="$(cd "$(dirname "$0")/../.." && pwd)"
FIX="$RAIZ/tests/fixtures/vpn"
TMP="$(mktemp -d)"
CTR="ids-test-vpn-$$"
CTR_MALO="ids-test-vpn-malo-$$"

# shellcheck disable=SC2317  # se llama desde el trap
limpiar() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 77 ]; then
    echo "--- logs de $CTR ---" >&2
    docker logs "$CTR" 2>&1 | tail -n 80 >&2 || true
  fi
  docker rm -f "$CTR" "$CTR_MALO" >/dev/null 2>&1 || true
  "${SUDO[@]}" rm -rf "$TMP" || true
  exit "$rc"
}
trap limpiar EXIT

# --- /srv de prueba con la forma de §2.1 ---------------------------------------------------
SRV="$TMP/srv"
VPN="$SRV/puntos/p003/vpn"
RUN="$SRV/run/p003"
CTL="$SRV/ctl/p003/vpn"
PKI="$TMP/pki"
mkdir -p "$VPN/ccd" "$RUN" "$CTL" "$PKI"

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 -subj "/CN=ids-maat-ca prueba" \
  -keyout "$PKI/ca.key" -out "$PKI/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -sha256 -subj "/CN=server-p003" \
  -keyout "$VPN/server.key" -out "$PKI/server.csr" 2>/dev/null
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
  > "$PKI/ext.cnf"
openssl x509 -req -in "$PKI/server.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" -CAcreateserial \
  -days 30 -sha256 -extfile "$PKI/ext.cnf" -out "$VPN/server.crt" 2>/dev/null
cp "$PKI/ca.crt" "$VPN/ca.crt"
openssl genpkey -genparam -algorithm DH -pkeyopt dh_param:ffdhe2048 -out "$VPN/dh.pem" 2>/dev/null \
  || openssl dhparam -dsaparam -out "$VPN/dh.pem" 2048 2>/dev/null
cp "$FIX/server.conf" "$VPN/server.conf"
python3 - "$VPN/usuarios" <<'PY'
import hashlib, secrets, sys
sal = secrets.token_bytes(16)
h = hashlib.scrypt(b"ClaveDePrueba123", salt=sal, n=16384, r=8, p=1, dklen=32)
with open(sys.argv[1], "w") as fh:
    fh.write("# ids-maat p003 — generado por ids-orq; no editar\n")
    fh.write(f"vpn3a9f2c:scrypt$16384$8$1${sal.hex()}${h.hex()}\n")
PY
echo "ifconfig-push 100.64.3.2 255.255.255.0" > "$VPN/ccd/vpn3a9f2c"

"${SUDO[@]}" chown -R 0:0 "$SRV/puntos" "$SRV/ctl"
"${SUDO[@]}" chmod 0700 "$SRV/puntos/p003" "$VPN" "$VPN/ccd" "$SRV/ctl" "$SRV/ctl/p003" "$CTL"
"${SUDO[@]}" chmod 0644 "$VPN/server.conf" "$VPN/ca.crt" "$VPN/server.crt" "$VPN/dh.pem" "$VPN/ccd/vpn3a9f2c"
"${SUDO[@]}" chmod 0600 "$VPN/server.key" "$VPN/usuarios"
"${SUDO[@]}" chown 0:10500 "$SRV/run" "$RUN"
"${SUDO[@]}" chmod 0750 "$SRV/run"
"${SUDO[@]}" chmod 2770 "$RUN"

# --- arranque como lo haría el compose de §4.3 ----------------------------------------------
arrancar() {  # $1 = nombre, $2 = TUN_MK
  docker run -d --name "$1" \
    --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW \
    --device /dev/net/tun:/dev/net/tun \
    --security-opt no-new-privileges:true \
    --read-only --tmpfs /run:rw,exec,size=16m --tmpfs /tmp:rw,size=16m \
    --sysctl net.ipv4.ip_forward=0 \
    --sysctl net.ipv6.conf.all.disable_ipv6=1 \
    --sysctl net.ipv6.conf.default.disable_ipv6=1 \
    --sysctl net.ipv4.conf.default.rp_filter=1 \
    --sysctl net.ipv4.ipfrag_high_thresh=67108864 \
    --sysctl net.ipv4.ipfrag_time=15 \
    --memory 192m --memory-swap 192m --pids-limit 64 \
    -e PUNTO=p003 -e N=3 -e TUN_NET=100.64.3.0/24 -e TUN_SENSOR=100.64.3.1 -e TUN_MK="$2" \
    -e API_PUERTO=8729 -e TZSP_PUERTO=37008 -e TZSP_BYTES=10000 -e TZ=UTC \
    -v "$VPN:/etc/ids/vpn:ro" -v "$RUN:/run/ids" -v "$CTL:/run/ids-ctl" \
    --health-cmd /usr/local/bin/salud-vpn --health-interval 5s --health-timeout 10s \
    --health-retries 3 --health-start-period 30s \
    "$IDS_IMG_VPN" >/dev/null
}

estado() { docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$1"; }

arrancar "$CTR" 100.64.3.2
for _ in $(seq 1 60); do
  e="$(estado "$CTR")"
  case "$e" in
    "running healthy") break ;;
    running*) sleep 2 ;;
    *) fallo "el contenedor no sigue en marcha: $e" ;;
  esac
done
[ "$(estado "$CTR")" = "running healthy" ] || fallo "no llegó a healthy en 120 s: $(estado "$CTR")"
ok "healthy sin tráfico"

docker exec "$CTR" ip link show ids-in >/dev/null || fallo "no existe ids-in"
mon="$(docker exec "$CTR" ip link show ids-mon)" || fallo "no existe ids-mon"
grep -q PROMISC <<<"$mon" || fallo "ids-mon no está en promisc: $mon"
grep -q "mtu 65535" <<<"$mon" || fallo "ids-mon sin mtu 65535: $mon"
grep -q NOARP <<<"$mon" || fallo "ids-mon sin arp off: $mon"
grep -q NOARP <<<"$(docker exec "$CTR" ip link show ids-in)" || fallo "ids-in sin arp off"
# eth0 tiene que contestar ARP: si no, el host no llega al contenedor (DNAT/docker-proxy a :1194).
arp_eth0="$(docker exec "$CTR" cat /proc/sys/net/ipv4/conf/eth0/arp_ignore)"
[ "$arp_eth0" = 0 ] || fallo "eth0 con arp_ignore=$arp_eth0: el host no resolvería la IP del contenedor"
ok "veth ids-in/ids-mon (NOARP) y eth0 con ARP"

# `nft list table` reescribe el formato (comillas, contadores, una cadena por bloque): se compara
# regla a regla, normalizado, con el fixture que la prueba unitaria de render.py fija. Sin tubería
# a `grep -q`: con pipefail, el SIGPIPE de docker exec daba un falso «ausente».
tabla_igual() {  # $1 = "familia nombre", $2 = fixture
  local salida
  # shellcheck disable=SC2086  # $1 son dos palabras a propósito
  if ! salida="$(docker exec "$CTR" nft list table $1 2>&1)"; then
    fallo "tabla $1 ausente: nft list table dijo: $salida"
  fi
  printf '%s\n' "$salida" > "$TMP/listado.nft"
  if ! python3 "$RAIZ/tests/_ayuda_vpn.py" comparar-nft "$FIX/$2" "$TMP/listado.nft"; then
    echo "--- nft list table $1 (tal cual)" >&2
    cat "$TMP/listado.nft" >&2
    fallo "tabla $1 distinta de $2"
  fi
}
tabla_igual "inet ids_punto" ids_punto_p003.nft
tabla_igual "netdev ids_mon" ids_mon.nft
ok "tablas nft (inet ids_punto y netdev ids_mon iguales a los fixtures)"

[ "$("${SUDO[@]}" stat -c '%a %g %F' "$RUN/api.sock")" = "660 10500 socket" ] \
  || fallo "api.sock: $("${SUDO[@]}" stat -c '%a %g %F' "$RUN/api.sock" 2>&1)"
[ "$("${SUDO[@]}" stat -c '%a %g' "$RUN/tzsp.json")" = "640 10500" ] \
  || fallo "tzsp.json: $("${SUDO[@]}" stat -c '%a %g' "$RUN/tzsp.json" 2>&1)"
"${SUDO[@]}" cat "$RUN/tzsp.json" > "$TMP/tzsp.json"
python3 - "$TMP/tzsp.json" <<'PY' || fallo "tzsp.json con un esquema inesperado"
import json, sys
e = json.load(open(sys.argv[1]))
assert e["v"] == 1 and e["punto"] == "p003" and e["esperados"] == ["100.64.3.2/32"], e
assert e["recorte_bytes"] == 10000, e
PY
"${SUDO[@]}" test -S "$CTL/ovpn-mgmt.sock" || fallo "no existe ovpn-mgmt.sock"
[ "$("${SUDO[@]}" stat -c '%a %g' "$RUN/openvpn-status.log")" = "640 10500" ] \
  || fallo "openvpn-status.log: $("${SUDO[@]}" stat -c '%a %g' "$RUN/openvpn-status.log" 2>&1)"
ok "api.sock 0660:10500, tzsp.json y openvpn-status.log 0640:10500, ovpn-mgmt.sock"

# --- kill de openvpn: s6 lo relanza dentro del contenedor ----------------------------------
inicio="$(docker inspect -f '{{.State.StartedAt}} {{.RestartCount}}' "$CTR")"
pid_viejo="$(docker exec "$CTR" /command/s6-svstat -p /run/service/openvpn)"
[ "${pid_viejo:-0}" -gt 0 ] || fallo "openvpn no tiene pid ($pid_viejo)"
docker exec "$CTR" sh -c "kill $pid_viejo"
pid_nuevo=0
for _ in $(seq 1 20); do
  sleep 1
  pid_nuevo="$(docker exec "$CTR" /command/s6-svstat -p /run/service/openvpn || echo 0)"
  if [ "${pid_nuevo:-0}" -gt 0 ] && [ "$pid_nuevo" != "$pid_viejo" ]; then break; fi
done
[ "${pid_nuevo:-0}" -gt 0 ] && [ "$pid_nuevo" != "$pid_viejo" ] \
  || fallo "s6 no relanzó openvpn (antes $pid_viejo, ahora $pid_nuevo)"
[ "$(docker inspect -f '{{.State.StartedAt}} {{.RestartCount}}' "$CTR")" = "$inicio" ] \
  || fallo "el contenedor se reinició"
docker exec "$CTR" ip link show ids-in >/dev/null || fallo "el veth desapareció tras relanzar openvpn"
[ "$(docker exec "$CTR" /command/s6-svstat -o up /run/service/openvpn)" = "true" ] \
  || fallo "openvpn no quedó up"
ok "openvpn relanzado por s6 ($pid_viejo -> $pid_nuevo), contenedor intacto, veth intacto"

# --- TUN_MK inválido: init-env falla y el contenedor sale ----------------------------------
arrancar "$CTR_MALO" 100.64.3.9
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Running}}' "$CTR_MALO")" = "false" ] && break
  sleep 1
done
[ "$(docker inspect -f '{{.State.Running}}' "$CTR_MALO")" = "false" ] \
  || fallo "con TUN_MK inválido el contenedor sigue en marcha"
docker logs "$CTR_MALO" 2>&1 | grep -q "TUN_MK" || fallo "el log no explica que TUN_MK es inválido"
codigo="$(docker inspect -f '{{.State.ExitCode}}' "$CTR_MALO")"
[ "$codigo" != "0" ] || fallo "salió con código 0"
ok "TUN_MK inválido: el contenedor sale (código $codigo)"

echo "test_vpn_arranque: PASA"
