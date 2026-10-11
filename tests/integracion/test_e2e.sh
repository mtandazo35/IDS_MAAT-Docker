#!/bin/bash
# Extremo a extremo (CONTRATO-F1a §8.2), con el orquestador y las imágenes reales y un IDS_RAIZ
# temporal. Necesita Linux, root, Docker, red (reglas ET) e IDS_IMG_VPN / IDS_IMG_SURICATA; si
# falta algo sale con 77 (omitida).
#
#  1. ids-orq servicio + reglas actualizar + punto crear -> healthy
#  2. un cliente OpenVPN en contenedor se autentica y envía el pcap de B por TZSP a <sensor>:37008
#     -> alerta 2100498 con host = p001 en datos/p001/eve.json
#  3. sin tráfico, el vpn sigue sano (latido)
#  4. docker restart ids-p001-vpn -> el orquestador ve netns distintos y reinicia suricata
#  5. reglas actualizar --sin-descarga reinicia los suricata de uno en uno
#  6. punto borrar no deja nada en {puntos,datos,run,ctl}/p001
#
# El firewall del runner no se toca: un nft simulado en el PATH solo hace «nft -c» (si hay nft).
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
CHECKOUT="$PWD"

omitir() { echo "test_e2e: OMITIDA ($*)"; exit 77; }
[ "$(uname -s)" = Linux ] || omitir "solo Linux"
[ "$(id -u)" = 0 ] || omitir "necesita root"
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || omitir "sin Docker"
[ -n "${IDS_IMG_VPN:-}" ] && [ -n "${IDS_IMG_SURICATA:-}" ] || omitir "faltan IDS_IMG_VPN / IDS_IMG_SURICATA"
docker image inspect "$IDS_IMG_VPN" "$IDS_IMG_SURICATA" >/dev/null 2>&1 || omitir "imágenes no construidas"
command -v openssl >/dev/null 2>&1 || omitir "sin openssl"
command -v python3 >/dev/null 2>&1 || omitir "sin python3"

R=$(mktemp -d /root/ids-e2e.XXXXXX)
export IDS_RAIZ="$R"
ORQ=(python3 "$CHECKOUT/orquestador/ids_orq.py")
FALLOS=0
ORQ_PID=""
ok()  { echo "  ok   $*"; }
mal() { echo "  MAL  $*"; FALLOS=$((FALLOS + 1)); }

limpiar() {
  [ -n "$ORQ_PID" ] && kill "$ORQ_PID" 2>/dev/null
  docker rm -f ids-e2e-cliente >/dev/null 2>&1
  # shellcheck disable=SC2046
  docker rm -f $(docker ps -aq --filter label=ids-maat.punto) >/dev/null 2>&1
  for n in ids-p001 ids-p002; do docker network rm "$n" >/dev/null 2>&1; done
  if [ "$FALLOS" -gt 0 ]; then
    echo "---- orq.log"; tail -n 80 "$R/orq.log" 2>/dev/null
  fi
  rm -rf "$R"
}
trap limpiar EXIT

esperar() {   # esperar <segundos> <orden…>: reintenta cada 2 s
  local fin=$((SECONDS + $1))
  shift
  until "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -ge "$fin" ] && return 1
    sleep 2
  done
}

# ---- configuración del VPS de prueba ---------------------------------------------------------
mkdir -p "$R/etc/ids-maat" "$R/_bin"
cat > "$R/etc/ids-maat/ids.conf" <<'EOF'
VERSION=0.1.0
NOMBRE_DNS=ids.empresa.example
TUN_BASE=100.64
REDES_GESTION=192.0.2.0/25,198.51.100.0/26
IPS_PROXY=203.0.113.50
IGNOREIP_DUENO=203.0.113.20
PUERTO_PANEL=5637
POOL_DOCKER=10.210.0.0/16
EOF
printf '{"v": 1, "version": "0.1.0", "dev": true, "imagenes": {"vpn": "%s", "suricata": "%s"}}\n' \
  "$IDS_IMG_VPN" "$IDS_IMG_SURICATA" > "$R/etc/ids-maat/imagenes.json"
od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$R/etc/ids-maat/orq_token"
cat > "$R/_bin/nft" <<'EOF'
#!/bin/sh
# e2e: no se aplica nada al firewall del runner; solo se comprueba la sintaxis con el nft real.
echo "nft $*" >> "$IDS_RAIZ/_nft.log"
real=$(PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v nft || true)
[ -n "$real" ] || exit 0
[ "$1" = "-c" ] && shift
exec "$real" -c "$@"
EOF
chmod 0755 "$R/_bin/nft"
export PATH="$R/_bin:$PATH"

echo "== 1. servicio, reglas y alta"
"${ORQ[@]}" servicio > "$R/orq.log" 2>&1 &
ORQ_PID=$!
if esperar 30 test -S "$R/run/ids-orq/orq.sock"; then ok "socket del servicio"; else mal "el servicio no abrió el socket"; exit 1; fi
if "${ORQ[@]}" reglas actualizar > "$R/reglas.log" 2>&1; then ok "reglas actualizar"; else mal "reglas actualizar"; cat "$R/reglas.log"; exit 1; fi
[ -L "$R/srv/ids/reglas/current" ] && ok "reglas/current existe" || mal "sin reglas/current"
if "${ORQ[@]}" punto crear --nombre norte --redes 10.0.0.0/24 > "$R/crear.log" 2>&1; then
  ok "punto crear p001"
else
  mal "punto crear"; cat "$R/crear.log"; exit 1
fi
USUARIO=$(sed -n 's/^  usuario VPN  \(vpn[0-9a-f]\{6\}\)$/\1/p' "$R/crear.log")
CLAVE=$(sed -n 's/^  clave VPN    \([A-Za-z0-9]\{24\}\) .*/\1/p' "$R/crear.log")
[ -n "$USUARIO" ] && [ -n "$CLAVE" ] && ok "usuario y clave entregados" || mal "no se leyó usuario/clave"
for c in ids-p001-vpn ids-p001-suricata; do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$c")" = healthy ] && ok "$c healthy" || mal "$c no healthy"
done

echo "== 2. cliente OpenVPN y espejo TZSP"
mkdir -p "$R/cliente"
cp "$R/srv/ids/pki/ca.crt" "$R/cliente/ca.crt"
printf '%s\n%s\n' "$USUARIO" "$CLAVE" > "$R/cliente/up"
chmod 0600 "$R/cliente/up"
GW=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
cat > "$R/cliente/cliente.conf" <<EOF
client
dev tun
proto tcp-client
remote $GW 1194
nobind
ca /c/ca.crt
auth-user-pass /c/up
auth SHA1
data-ciphers AES-256-GCM:AES-256-CBC
remote-cert-tls server
verb 3
EOF
docker run -d --name ids-e2e-cliente --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$R/cliente:/c:ro" -v "$CHECKOUT/tests:/t:ro" --entrypoint openvpn "$IDS_IMG_VPN" \
  --config /c/cliente.conf >/dev/null
conectado() { docker logs ids-e2e-cliente 2>&1 | grep -q "Initialization Sequence Completed"; }
if esperar 90 conectado; then ok "el cliente se autentica"; else mal "el cliente no conecta"; docker logs ids-e2e-cliente 2>&1 | tail -20; fi
docker exec ids-e2e-cliente python3 /t/integracion/tzsp_enviar.py /t/fixtures/suricata/alerta-2100498.pcap 100.64.1.1 37008 5 \
  && ok "pcap enviado por TZSP" || mal "no se pudo enviar el TZSP"
alerta() {
  grep '"signature_id":2100498' "$R/srv/ids/datos/p001/eve.json" 2>/dev/null | grep -q '"host":"p001"'
}
if esperar 120 alerta; then ok "alerta 2100498 con host = p001"; else mal "no apareció la alerta 2100498"; fi

echo "== 3. sin tráfico el vpn sigue sano"
docker rm -f ids-e2e-cliente >/dev/null 2>&1
sleep 100
[ "$(docker inspect -f '{{.State.Health.Status}}' ids-p001-vpn)" = healthy ] && ok "vpn healthy sin espejo" \
  || mal "vpn no healthy sin tráfico"

echo "== 4. netns huérfano"
ANTES=$(docker inspect -f '{{.State.StartedAt}}' ids-p001-suricata)
docker restart ids-p001-vpn >/dev/null
suricata_reiniciado() { [ "$(docker inspect -f '{{.State.StartedAt}}' ids-p001-suricata)" != "$ANTES" ]; }
if esperar 150 suricata_reiniciado; then ok "el orquestador reinició suricata"; else mal "suricata no se reinició"; fi
coherente() {
  python3 - "$R/srv/ids/run/estado.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))["puntos"]["p001"]
sys.exit(0 if p["netns"]["coherente"] is True else 1)
PY
}
if esperar 120 coherente; then ok "netns coherentes en estado.json"; else mal "netns sin coherencia"; fi

echo "== 5. reglas: reinicio en serie"
if "${ORQ[@]}" punto crear --nombre sur --redes 10.1.0.0/24 > "$R/crear2.log" 2>&1; then ok "punto crear p002"; else mal "punto crear p002"; fi
if "${ORQ[@]}" reglas actualizar --sin-descarga > "$R/reglas2.log" 2>&1; then ok "reglas actualizar --sin-descarga"; else mal "reglas --sin-descarga"; fi
t1=$(date -d "$(docker inspect -f '{{.State.StartedAt}}' ids-p001-suricata)" +%s)
t2=$(date -d "$(docker inspect -f '{{.State.StartedAt}}' ids-p002-suricata)" +%s)
if [ $((t2 - t1)) -ge 5 ]; then ok "p002 arrancó $((t2 - t1)) s después que p001 (en serie)"; else mal "reinicios no en serie ($t1 / $t2)"; fi
grep -q "reiniciar p001" "$R/reglas2.log" && grep -q "reiniciar p002" "$R/reglas2.log" && ok "pasos por punto" || mal "faltan pasos"

echo "== 6. baja"
if "${ORQ[@]}" punto borrar p001 --confirmar norte > "$R/borrar.log" 2>&1; then ok "punto borrar p001"; else mal "punto borrar"; fi
for d in puntos datos run ctl; do
  [ -e "$R/srv/ids/$d/p001" ] && mal "queda $d/p001" || ok "no queda $d/p001"
done
docker inspect ids-p001-vpn >/dev/null 2>&1 && mal "queda el contenedor ids-p001-vpn" || ok "sin contenedores de p001"

echo
[ "$FALLOS" -eq 0 ] || { echo "test_e2e: $FALLOS fallos"; exit 1; }
echo "test_e2e: todo bien"
exit 0
