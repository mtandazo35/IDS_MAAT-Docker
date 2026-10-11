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
#  7. (con IDS_IMG_PANEL) panel: ids-orq panel aplicar -> healthy; crear-admin imprime CLAVE=;
#     login HTTP por el puerto publicado con esa clave; la lista de puntos; alta de un punto desde
#     la web (POST con Origin y token CSRF) que el orquestador crea; crear-admin otra vez no toca
#     la clave; sin el contenedor, reconciliar lo levanta. Rutas: docs/CONTRATO-F1b.md «Panel (P)».
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
  if [ "$FALLOS" -gt 0 ] && docker inspect ids-core-panel >/dev/null 2>&1; then
    echo "---- panel (docker logs ids-core-panel)"; docker logs ids-core-panel 2>&1 | tail -n 60
  fi
  docker rm -f ids-core-panel >/dev/null 2>&1
  for n in ids-p001 ids-p002 ids-p003 ids-core; do docker network rm "$n" >/dev/null 2>&1; done
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
PANEL=0
if [ -n "${IDS_IMG_PANEL:-}" ] && docker image inspect "$IDS_IMG_PANEL" >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
  PANEL=1
  printf '{"v": 1, "version": "0.1.0", "dev": true, "imagenes": {"vpn": "%s", "suricata": "%s", "panel": "%s"}}\n' \
    "$IDS_IMG_VPN" "$IDS_IMG_SURICATA" "$IDS_IMG_PANEL" > "$R/etc/ids-maat/imagenes.json"
else
  printf '{"v": 1, "version": "0.1.0", "dev": true, "imagenes": {"vpn": "%s", "suricata": "%s"}}\n' \
    "$IDS_IMG_VPN" "$IDS_IMG_SURICATA" > "$R/etc/ids-maat/imagenes.json"
fi
od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$R/etc/ids-maat/orq_token"
chown root:10500 "$R/etc/ids-maat/orq_token" && chmod 0640 "$R/etc/ids-maat/orq_token"   # como install.sh
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
conectado() { docker logs ids-e2e-cliente 2>&1 | grep -F "Initialization Sequence Completed" >/dev/null; }
# Diagnóstico del paso 2: lo que dicen los dos extremos del túnel y el camino entre ellos.
diag_vpn() {
  local ip_vpn
  echo "---- cliente (docker logs ids-e2e-cliente)"; docker logs ids-e2e-cliente 2>&1 | tail -n 40
  echo "---- servidor (docker logs ids-p001-vpn)"
  docker logs ids-p001-vpn 2>&1 | tail -n 80 \
    || journalctl --no-pager -n 80 CONTAINER_NAME=ids-p001-vpn 2>&1
  echo "---- ids-p001-vpn: direcciones, sysctls (arp_ignore/rp_filter) y ruleset"
  docker exec ids-p001-vpn ip -br addr 2>&1
  docker exec ids-p001-vpn sh -c 'for d in /proc/sys/net/ipv4/conf/*; do echo "${d##*/} arp_ignore=$(cat "$d/arp_ignore") rp_filter=$(cat "$d/rp_filter")"; done' 2>&1
  docker exec ids-p001-vpn nft list ruleset 2>&1
  ip_vpn=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ids-p001-vpn)
  echo "---- host: conexión directa a $ip_vpn:1194 y vecinos"
  if timeout 6 bash -c "exec 3<>/dev/tcp/$ip_vpn/1194" 2>&1; then echo "TCP $ip_vpn:1194 abre"; else echo "TCP $ip_vpn:1194 NO abre"; fi
  ip neigh show 2>&1 | grep -F "$ip_vpn" || echo "(sin entrada de vecino para $ip_vpn)"
  ss -ltnp 2>/dev/null | grep -E ':1194\b' || true
  iptables -t nat -S DOCKER 2>&1 | grep -E '1194|RETURN' || true
  docker version --format 'docker {{.Server.Version}}' 2>&1
}
if esperar 90 conectado; then ok "el cliente se autentica"; else mal "el cliente no conecta"; diag_vpn; fi
docker exec ids-e2e-cliente python3 /t/integracion/tzsp_enviar.py /t/fixtures/suricata/alerta-2100498.pcap 100.64.1.1 37008 5 \
  && ok "pcap enviado por TZSP" || mal "no se pudo enviar el TZSP"
alerta() {
  grep '"signature_id":2100498' "$R/srv/ids/datos/p001/eve.json" 2>/dev/null | grep -F '"host":"p001"' >/dev/null
}
if esperar 120 alerta; then
  ok "alerta 2100498 con host = p001"
else
  mal "no apareció la alerta 2100498"
  echo "---- tzsp.json"; cat "$R/srv/ids/run/p001/tzsp.json" 2>&1
  echo "---- eve.json (alertas)"; grep '"event_type":"alert"' "$R/srv/ids/datos/p001/eve.json" 2>&1 | tail -n 5
  echo "---- suricata (docker logs ids-p001-suricata)"; docker logs ids-p001-suricata 2>&1 | tail -n 40
  conectado && diag_vpn
fi
echo "  info memoria y CPU tras el paso 2:"
docker stats --no-stream --format '         {{.Name}} {{.MemUsage}} cpu {{.CPUPerc}}' ids-p001-vpn ids-p001-suricata 2>&1

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

echo "== 7. panel: núcleo, primer admin, login y alta desde la web"
if [ "$PANEL" = 0 ]; then
  echo "  (omitido: falta IDS_IMG_PANEL, la imagen o curl)"
else
  # Rutas y campos del panel (los fija P en docs/CONTRATO-F1b.md «Panel (P)»): formulario
  # POST /entrar (usuario, clave) -> 303 a /puntos con la cookie de sesión; GET /puntos; GET
  # /puntos/nuevo trae el token CSRF en <input name="csrf">; POST /puntos/nuevo (csrf, nombre,
  # redes, ros_version, perfil) -> 303 a /operaciones/<op_id>.
  URL="http://127.0.0.1:5637"
  J="$R/panel.cookies"
  web() {   # web <ruta> [datos de formulario]: imprime «código destino» y deja el cuerpo en $R/web.html
    if [ $# -gt 1 ]; then
      curl -s -o "$R/web.html" -w '%{http_code} %{redirect_url}' -b "$J" -c "$J" -H "Origin: $URL" \
        --data "$2" "$URL$1"
    else
      curl -s -o "$R/web.html" -w '%{http_code} %{redirect_url}' -b "$J" -c "$J" "$URL$1"
    fi
  }
  if "${ORQ[@]}" panel aplicar > "$R/panel.log" 2>&1; then ok "ids-orq panel aplicar: ids-core-panel healthy"; else mal "panel aplicar"; cat "$R/panel.log"; fi
  [ "$(docker inspect -f '{{(index .NetworkSettings.Networks "ids-core").IPAddress}}' ids-core-panel 2>/dev/null)" = 10.210.255.2 ] \
    && ok "panel en 10.210.255.2 (red ids-core)" || mal "el panel no está en 10.210.255.2"
  [ "$(docker inspect -f '{{.Config.User}}' ids-core-panel 2>/dev/null)" = "10500:10500" ] && ok "panel como 10500" || mal "panel no corre como 10500"
  SAL=$("${ORQ[@]}" panel crear-admin --usuario admin 2>"$R/admin.err")
  CLAVE_PANEL=$(sed -n 's/^CLAVE=\([^[:space:]]\{1,\}\)$/\1/p' <<<"$SAL")
  [ -n "$CLAVE_PANEL" ] && [ "$(wc -l <<<"$SAL")" = 1 ] && ok "crear-admin imprime una sola línea CLAVE=" \
    || { mal "crear-admin no dio CLAVE="; cat "$R/admin.err"; }
  "${ORQ[@]}" panel crear-admin --usuario admin > "$R/admin2.out" 2>&1
  rc=$?
  [ "$rc" = 3 ] && ! grep -q '^CLAVE=' "$R/admin2.out" && ok "crear-admin otra vez: 3 y no regenera" || mal "crear-admin repetido dio $rc"
  # la clave no queda en ningún log de Docker (contenedor de un solo uso con --log-driver none)
  docker logs ids-core-panel 2>&1 | grep -F -- "$CLAVE_PANEL" >/dev/null && mal "la clave sale en docker logs" || ok "la clave no está en los logs del panel"
  r=$(web /entrar "usuario=admin&clave=mala-$RANDOM")
  [ "${r%% *}" = 401 ] && ok "clave mala: 401" || mal "clave mala dio $r"
  r=$(web /entrar "usuario=admin&clave=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$CLAVE_PANEL")")
  [ "$r" = "303 $URL/puntos" ] && ok "login con la clave impresa" || mal "login dio $r"
  r=$(web /puntos)
  [ "${r%% *}" = 200 ] && grep -F "p002" "$R/web.html" >/dev/null && ok "lista de puntos (p002 sur)" || mal "lista de puntos: $r"
  web /puntos/nuevo >/dev/null
  CSRF=$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' "$R/web.html" | head -n1)
  [ -n "$CSRF" ] && ok "token CSRF del formulario" || mal "sin token CSRF en /puntos/nuevo"
  r=$(curl -s -o /dev/null -w '%{http_code}' -b "$J" -H "Origin: http://ajeno.example" \
        --data "csrf=$CSRF&nombre=ajeno&redes=10.3.0.0/24&ros_version=7&perfil=reducido" "$URL/puntos/nuevo")
  [ "$r" = 403 ] && ok "POST con Origin ajeno: 403" || mal "POST con Origin ajeno dio $r"
  r=$(web /puntos/nuevo "csrf=$CSRF&nombre=web&redes=10.2.0.0/24&ros_version=7&perfil=reducido")
  [[ "$r" =~ ^303\ $URL/operaciones/[0-9a-f-]{36}$ ]] && ok "alta desde la web aceptada (${r##*/})" || { mal "alta desde la web: $r"; head -c 2000 "$R/web.html"; }
  punto_web() { web /puntos >/dev/null && grep -F ">web<" "$R/web.html" >/dev/null; }
  if esperar 60 punto_web; then ok "el punto «web» aparece en la lista"; else mal "el punto web no aparece en /puntos"; fi
  web_activo() { "${ORQ[@]}" punto estado p003 2>/dev/null | grep -x "estado: activo" >/dev/null; }
  if esperar 400 web_activo; then ok "el orquestador creó p003 (web) desde el panel"; else mal "p003 no llegó a activo"; "${ORQ[@]}" punto estado p003; fi
  if grep -E '"quien": ?"panel:admin"' "$R/srv/ids/estado/orq.jsonl" >/dev/null 2>&1; then
    ok "orq.jsonl registra quien = panel:admin"
  else
    mal "orq.jsonl sin panel:admin"
  fi
  docker rm -f ids-core-panel >/dev/null
  "${ORQ[@]}" reconciliar > "$R/reconciliar.log" 2>&1
  panel_corre() { [ "$(docker inspect -f '{{.State.Running}}' ids-core-panel 2>/dev/null)" = true ]; }
  if esperar 60 panel_corre; then
    ok "reconciliar levanta el panel que faltaba"
  else
    mal "reconciliar no levantó el panel"; cat "$R/reconciliar.log"
  fi
fi

echo
[ "$FALLOS" -eq 0 ] || { echo "test_e2e: $FALLOS fallos"; exit 1; }
echo "test_e2e: todo bien"
exit 0
