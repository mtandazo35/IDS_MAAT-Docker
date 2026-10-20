# Red y firewall

Anexo de [ARQUITECTURA.md](ARQUITECTURA.md). Este anexo cubre:

- la red del host y de cada punto;
- el flujo del espejo y el de la API;
- por qué no hay rutas hacia los abonados;
- el firewall del host y el de cada netns;
- fail2ban y el modo seguro;
- el punto directo, sin VPN, para un MikroTik en la red local (§11).

Los comandos que se pegan en el MikroTik están en [OPERACION.md](OPERACION.md).

Ejemplos: VPS `203.0.113.10` (nombre `ids.empresa.example`), redes de gestión `192.0.2.0/25` y
`198.51.100.0/26`, IP del proxy inverso externo `203.0.113.50`, punto N=3 con túnel
`100.64.3.0/24`.

## 1. Docker en el host

`/etc/docker/daemon.json`:

```json
{
  "userland-proxy": false,
  "live-restore": true,
  "no-new-privileges": true,
  "log-driver": "local",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "default-address-pools": [ { "base": "10.210.0.0/16", "size": 28 } ],
  "bip": "10.210.254.1/24"
}
```

- **`bip`.** El `docker0` por defecto queda fijo en `10.210.254.1/24`, fuera de las /28 de los
  puntos (que son deterministas, §2.1) y de la red `ids-core` (`10.210.255.0/24`): ni `docker0` ni
  una red automática pueden quitarle su /28 a un punto.

- **`userland-proxy: false`.** El DNAT de Docker conserva la IP de origen en cualquier caso. Lo
  que cambia con `false` es que no hay `docker-proxy`. Eso importa en dos casos:
  - el hairpin desde el propio host;
  - IPv6: sin el proxy, los puertos publicados no quedan escuchando en `::` cuando las redes Docker
    son solo IPv4.
- **`live-restore: true`.** Actualizar o reiniciar dockerd no tumba todos los túneles a la vez.
- **El pool `10.210.0.0/16` se valida al instalar.** No puede solaparse con las redes de gestión,
  con la base de túneles ni con las LAN de abonados declaradas. Si choca, el instalador pide otro.
- **La versión mayor de Docker se fija** (`apt-mark hold` o pin) y cada salto se prueba en el
  canario.
- **Módulos** (`/etc/modules-load.d/ids.conf`): `tun`, `veth` y `nft_ct`.
- **Hora.** El host usa `systemd-timesyncd`. Los contenedores corren con `TZ=UTC`. El panel
  convierte las horas a la zona de la empresa al mostrarlas.

## 2. Red de cada punto

```
 Internet ──► 203.0.113.10 (ids.empresa.example)
   │  host: nft inet ids_host ─── iptables-nft de Docker (DNAT de puertos publicados)
   ├─ tcp 22   ─────────────► sshd                                [solo @gestion]
   ├─ tcp 5637 ──DNAT──► red ids-core ─► panel-web :5637 (HTTP)   [solo @proxy]
   ├─ tcp 1194 ──DNAT──► red ids-p001 ─► vpn-p001 :1194 ─ tun0 100.64.1.1/24
   └─ tcp 1196 ──DNAT──► red ids-p003 ─► vpn-p003 :1194 ─ tun0 100.64.3.1/24

 netns de p003 (dueño: vpn-p003)
   tun0 ── udp 37008 desde 100.64.3.2 ─► tzsp-decap ─► ids-in ══veth══ ids-mon ─► suricata-p003
   relé: /run/ids/api.sock ─► 100.64.3.2:8729 (sale por tun0)
   ip_forward=0 · nft inet ids_punto (solo datos) · netdev ids_mon (descarta lo inyectado)
```

- **Cada `vpn` tiene su netns.** No se usa `network_mode: host`, porque todos los puntos
  compartirían interfaces, conntrack y firewall.
- **Red bridge por punto (opcional pero recomendada).**
  - Cada punto recibe una /28 del pool, con el bridge `ids-<pid>`
    (`com.docker.network.bridge.name`). Así los contadores nft e `ip link` dicen de qué punto es
    cada cosa.
  - La alternativa válida es una red compartida con
    `com.docker.network.bridge.enable_icc: "false"`, para que los `vpn` no se vean entre sí.
  - La red no puede ser `internal: true`, porque las redes internas no admiten puertos publicados.
- **OpenVPN** escucha `1194/tcp` dentro de cada contenedor. El orquestador lo publica en
  `1194+N-1`.
- **Los MikroTik apuntan a un nombre DNS de la empresa** (`connect-to=ids.empresa.example`), no a
  la IP. Si el VPS cambia de IP o se restaura en otro, basta con cambiar el registro DNS
  ([OPERACION.md](OPERACION.md) §3.3 y §5), siempre que el VPS nuevo conserve el **mismo
  `NOMBRE_DNS`** (`--nombre`) y se restaure `/srv/ids/pki`: el router verifica al servidor con la CA
  del VPS y con ese nombre (§4); con otra CA u otro nombre, no conecta.

### 2.1 Asignación por punto

| Valor | Regla | N=3 |
|---|---|---|
| `N` | menor índice libre entre 1 y 250, fuera de los 7 días de enfriamiento tras una baja | 3 |
| Puerto público | `1194 + N − 1` | 1196 |
| Red de túnel | `<base>.N.0/24`; base `100.64` por defecto o `198.18` si hay CGNAT en `100.64/10` (decisión a de ARQUITECTURA §10) | `100.64.3.0/24` |
| Sensor / MikroTik | `.1` / `.2` | `100.64.3.1` / `.2` |
| Red Docker | /28 fija derivada de `N`: `10.210.0.0 + 16·N` dentro del pool | `10.210.0.48/28` |
| `cluster-id` | `100 + N` (solo por legibilidad: el fanout es por netns) | 103 |

## 3. Flujo del espejo

```
abonado ─► MikroTik chain=forward
            mangle sniff-tzsp (ida y vuelta, connection-bytes=0-10000)
            ─► 100.64.N.1:37008 ─► ovpn-client (TCP) ─► Internet
VPS: DNAT ─► vpn:1194 ─► openvpn ─► tun0 (reensamblado ipfrag del netns)
   ─► tzsp-decap (0.0.0.0:37008; nft solo deja tun0 + 100.64.N.2; ALLOW fail-closed;
                  recorte TZSP_BYTES=10000 por flujo)
   ─► AF_PACKET ─► ids-in ══ ids-mon ─► suricata (af-packet)
                               └─► netdev ingress drop (la pila IP no procesa el espejo)
```

Reglas del espejo:

- **`connection-bytes=0-10000`, siempre y en las dos direcciones.** Incidente real: entraban
  100 Mbps de espejo para que Suricata aprovechara 3, un 97 % desperdiciado. Aquí además el espejo
  viaja por un túnel TCP y consume el ancho de banda del VPS.
- **Sin regla aparte de «DNS completo».** Duplicaría cada consulta DNS, que ya cubren las dos
  reglas.
- **En `forward`, no en `prerouting`.** En `prerouting`, con NAT, el destino todavía es la IP
  pública.
- **Fasttrack, sin ningún `accept`.** Un `accept` termina la cadena y saltaría los `drop` posteriores
  (cuarentena incluida), así que el espejo no añade ninguno. Solo cambia condiciones de las reglas
  `fasttrack-connection`: la existente deja fuera a `ids-vigilados` y se añaden dos fasttrack con sus
  mismas condiciones para los vigilados a partir de `connection-bytes=10000-0`. Los primeros 10 KB de cada
  conexión pasan por la ruta lenta y el mangle los ve; el resto se acelera. Nunca cambia qué tráfico pasa
  ([OPERACION.md](OPERACION.md) §2). El coste de CPU en el router se mide en el canario.
- **Vista previa = lo que se aplica.** El panel guarda el plan y su sha256, y vuelve a generar el
  plan al aplicar. **Antes de aplicar se respalda el firewall del router.**
- **El receptor recorta por su cuenta** con `TZSP_BYTES=10000`, por si al router le falta el
  recorte. Con un desperdicio mayor del 50 %, la pantalla Puntos avisa.
- **`tzsp-decap` escucha en `0.0.0.0`.** `tun0` puede no existir todavía cuando arranca. El filtro
  de interfaz y origen lo hace la tabla nft del netns, y además el receptor lleva su propia lista
  `TZSP_ALLOW=100.64.N.2/32`, que rechaza todo lo demás.

### 3.1 Si cae el túnel

El script del MikroTik no lleva rutas (decisión del dueño: el firewall y las rutas del router los
gestiona el operador). Si el túnel cae, el espejo hacia `100.64.N.1` sigue la ruta por defecto del
router; el operador decide en su router si lo evita.

Si el operador pone una ruta propia para eso (un blackhole hacia `100.64.N.0/24` con distancia
alta), la regla es que **no sea más específica que la ruta conectada del túnel**:

- La distancia solo decide entre rutas del mismo prefijo.
- Con el túnel arriba manda la conectada, y eso funciona tanto si el `ovpn-client` recibe un /24
  como un /32.
- Con el túnel caído, un blackhole /24 le gana a la ruta por defecto.
- Un blackhole /32 hacia `.1` ganaría siempre y cortaría el espejo también con el túnel arriba.

Los routers dados de alta con el script anterior llevan esa ruta con el comentario
`IDS ids-maat:<pid>`; cómo quitarla, en [OPERACION.md](OPERACION.md) §1.5.

## 4. Flujo de la API: un relé por punto

```
panel ── connect(/data/puntos/run/p003/api.sock) ──► socat (netns p003)
      ── TLS API-SSL de extremo a extremo (el relé no ve credenciales) ──►
      TCP 100.64.3.1 → 100.64.3.2:8729 por tun0 ──► MikroTik
```

```sh
# dentro de vpn-<pid>, supervisado por s6; N y API_PUERTO vienen del entorno
socat UNIX-LISTEN:/run/ids/api.sock,fork,unlink-early,mode=660,max-children=4 \
      TCP:100.64.${N}.2:${API_PUERTO:-8729},connect-timeout=5
```

- **Un solo relé por punto, hacia 8729 (API-SSL), sin certificado.** El panel habla siempre TLS con
  la API-SSL del router, que se usa tal como esté: el script no crea ningún certificado ni toca
  `/ip service api-ssl` ([OPERACION.md](OPERACION.md) §1.1). Lo normal es `certificate=none`, con
  el que RouterOS negocia un cifrado anónimo (ADH): el panel prueba primero `ADH:@SECLEVEL=0` y
  después los cifrados normales (router con certificado). **Sin huella fijada hace `/login` con lo
  que presente el router**, con certificado o sin él. Es la decisión del dueño (2026-10-15), como en
  el proyecto original: la clave de `ids-api` la protegen el túnel OpenVPN, en el que el MikroTik
  verifica el certificado del servidor con la CA del VPS, y el netns del sensor, que hacia el router
  solo deja salir la API (§8). Hasta entonces (VPN-06) el panel exigía un certificado (el `ids-promax`
  que creaba el script anterior) y una huella confirmada antes de mandar la clave; lo que hay que
  revisar en esos routers está en [OPERACION.md](OPERACION.md) §1.1.

  **Huella opcional (fijar el certificado):** si el router presenta un certificado, la ficha
  muestra su huella SHA-256 para compararla con el `fingerprint` de `/certificate print detail` y,
  al confirmar, la fija. Desde entonces el panel exige ese certificado: ya no prueba ADH, para que
  nadie pueda rebajar la conexión, y si el router presenta otro **no hace `/login`** (aviso rojo en
  la ficha y `MK-HUELLA-DISTINTA` en el Registro). Cambiarla («Volver a confirmar», «Olvidar la
  huella») es una acción explícita del admin en la ficha del punto, con bitácora; «Olvidar» vuelve
  a conectar sin exigir certificado. Sin certificado no hay huella que fijar. Las huellas que una
  versión anterior fijó sola se siguen exigiendo igual que una confirmada (la ficha las marca
  «fijada automáticamente»), y una huella **vacía** guardada antes (el sha256 de nada, de un
  API-SSL sin certificado) cuenta como sin huella.

  **8728 (en claro): se descarta.** El orquestador la admite por punto (`api_puerto`) y entonces
  genera el relé hacia 8728 y la tabla del netns abre solo ese puerto, pero **el panel no conecta**:
  habla siempre TLS, y contra la API en claro el saludo falla. La ficha lo dice así.
- **Permisos del socket:**
  - el directorio del host `/srv/ids/run/<pid>` pertenece a `root:10500` con modo `2770`
    (setgid), así que el socket hereda el grupo 10500;
  - `socat` solo fija `mode=660` (`group=` exigiría `CAP_CHOWN`);
  - el panel monta el padre `/srv/ids/run` en solo lectura. `connect()` a un socket UNIX funciona
    sobre un bind mount de solo lectura.
- **Del lado del panel**, el cliente RouterOS actual solo cambia la fábrica de sockets: abre un
  `AF_UNIX` y aplica el mismo `wrap_socket`: sin huella fijada, primero ADH y después los cifrados
  normales; con la huella fijada, solo los normales y exigiendo ese certificado.
- **Del lado del router**, el origen es `100.64.N.1`:
  - usuario API exclusivo del IDS, con `address=100.64.N.1/32`;
  - el script no pone reglas de firewall: lo que entra por `ids-vpn` lo decide el firewall del
    operador, y desde el túnel se llega a lo que ese firewall permita. Si la cadena `input` del
    router acaba en `drop`, el operador acepta en ella la API desde `100.64.N.1`
    ([OPERACION.md](OPERACION.md) §1.5);
  - **no se toca `/ip service … address=`**, porque esa lista es del servicio entero y puede
    usarla otro sistema de la empresa, como la facturación.
- **El router verifica al servidor:** importa la CA del VPS y conecta con
  `verify-server-certificate=yes` ([OPERACION.md](OPERACION.md) §1.4). Un impostor del servidor
  OpenVPN no recibe la clave VPN ni hace de `100.64.N.1`.
- **Defensa en profundidad:** la tabla del netns solo deja salir hacia `100.64.N.2` y el puerto de
  la API, aunque alguien cambiara el relé. Esa tabla frena el forwarding IP, pero no a un root con
  `CAP_NET_RAW` dentro del netns (un socket `AF_PACKET` no pasa por los hooks `inet`): lo que llegue
  así al router lo filtra el firewall del operador, y Suricata ya no tiene `NET_ADMIN`
  ([INSTANCIA.md](INSTANCIA.md) §2.1).
- **Alternativas descartadas:**
  - el panel conectado a todas las redes con rutas, que lo deja a un salto de cada túnel;
  - un SOCKS genérico, que es un pivote;
  - un agente RouterOS en cada `vpn`, que duplica la lógica y reparte las credenciales.

## 5. Sin rutas hacia los abonados

- El netns de cada punto solo conoce `100.64.N.0/24` y su /28 de Docker:
  - no hay `iroute`, `push` de rutas ni `rutas.sh`;
  - `net.ipv4.ip_forward=0`.
- Todo termina o se origina en el `vpn`: el TZSP llega a `.1` y la API sale hacia `.2`.
- Ninguna LAN de abonados entra en una tabla de rutas del VPS. Por eso dos puntos con
  `10.0.0.0/24` no chocan en la red; solo podrían mezclarse en los datos, y eso lo resuelve
  [DATOS.md](DATOS.md) §3.
- Un contenedor comprometido no sirve de puente hacia la red de un cliente a través del VPS: el VPS
  no enruta. En el router, lo que entra por `ids-vpn` lo decide el firewall del operador (§4).

## 6. Red de túneles y CGNAT

Muchos ISP usan `100.64.0.0/10` para el CGNAT de sus abonados. Si el MikroTik tiene rutas, pools o
direcciones dentro de `100.64.N.0/24`, el túnel choca **dentro del router**.

- **Base elegida al instalar, antes del primer punto** (decisión a de ARQUITECTURA §10): `100.64`
  por defecto; `198.18` (RFC 2544) si la empresa usa CGNAT en `100.64/10`.
- **Al dar de alta**, se rechazan las `redes_abonados` que se solapen con el rango de túneles o con
  el pool de Docker.
- **En el paso de la API del alta, y después en el diagnóstico periódico** de cada punto (cada
  10 min), el panel ejecuta en el router:
  - `/ip route print where dst-address in 100.64.N.0/24 && !connect`;
  - `/ip pool` comparado contra la red del túnel.

  Si algo solapa, **deshabilita el mangle del espejo** de ese punto y avisa.

## 7. Firewall del host

Tabla propia, cargada por `ids-host-fw.service` (`Before=docker.service`) desde
`/srv/ids/fw/ids_host.nft`. **Nunca hace `flush ruleset`**: borra y recrea solo su tabla.

```
table inet ids_host
delete table inet ids_host
table inet ids_host {
  set gestion     { type ipv4_addr; flags interval; elements = { 192.0.2.0/25, 198.51.100.0/26 } }   # SSH
  set proxy       { type ipv4_addr; flags interval; elements = { 203.0.113.50 } }                   # panel
  set puertos_vpn { type inet_service; elements = { 1194, 1196 } }      # lo mantiene el orquestador

  chain input {
    type filter hook input priority filter - 10; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    meta l4proto icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 20/second accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert,
        echo-request, packet-too-big, time-exceeded, parameter-problem, destination-unreachable } accept
    ip saddr @gestion tcp dport 22 accept
    counter comment "resto al host"
  }

  chain forward {
    type filter hook forward priority filter - 10; policy accept;    # SOLO descarta
    meta l4proto tcp ct direction original ct status dnat ct original proto-dst 5637 \
        ip saddr != @proxy counter drop comment "panel solo proxy"
    meta l4proto tcp ct direction original ct status dnat ct original proto-dst @puertos_vpn \
        ct state new meter vpn_new { ip saddr limit rate over 10/minute } counter drop comment "freno OpenVPN"
    meta l4proto { tcp, udp } ct direction original ct status dnat \
        ct original proto-dst != @puertos_vpn ct original proto-dst != 5637 counter drop comment "nada publicado fuera de lo previsto"
  }
}
```

Por qué cada pieza:

- **`forward` con política accept que solo descarta.** En nftables, un `drop` es definitivo en
  cualquier cadena base, y un `accept` no se salta las cadenas de Docker.
- **Prioridad `filter - 10`.** La tabla se evalúa antes que la de iptables-nft, donde está
  DOCKER-USER. **DOCKER-USER no se toca.** En el backend nftables de Docker no existe, y esta tabla
  sigue valiendo.
- **`ct original proto-dst` y `ct direction original`.** En `forward` el DNAT ya cambió el puerto,
  así que `dport` no casa. Sin `direction original` se tiran las respuestas de los contenedores.
- **La última regla es un cinturón.** Si alguien añade un `ports:` por error, no queda expuesto.
- **Origen fijo opcional por punto.** Si el punto declara la IP pública de su MikroTik, se añade
  una regla de descarte para ese puerto con `ip saddr != <IP>`.
- **Dos listas distintas.** `@gestion` abre el SSH y `@proxy` abre el panel. El panel habla HTTP:
  el TLS lo termina el proxy inverso externo y en el VPS no hay certificados. `@gestion` sale de
  `REDES_GESTION`; `@proxy` es la unión de `REDES_PANEL` (redes que abren el panel directamente) e
  `IPS_PROXY` (el proxy inverso). El panel solo se fía de las cabeceras `X-Forwarded-*` de
  `IPS_PROXY`. Se cambian volviendo a ejecutar `install.sh` con `--gestion`/`--panel`/`--proxy` (con
  su modo seguro) o, desde la consola, editando `ids.conf` y `ids-orq fw-render --aplicar`
  ([OPERACION.md](OPERACION.md) §4). La orden `acceso.aplicar` de §10
  es un diseño sin implementar.
- **Acceso abierto.** Sin `--gestion` ni `--proxy` el instalador escribe `0.0.0.0/0` en las dos
  listas: los conjuntos `@gestion` y `@proxy` dejan entrar a cualquier IP. El orquestador no trata
  `0.0.0.0/0` como red reservada (no quita nada a los prefijos de los abonados) y al panel le pasa
  `IDS_PROXY` vacío: sin proxy de confianza, ignora las cabeceras `X-Forwarded-*`.
- **El túnel SSH de emergencia no pasa por `forward`.** `ssh -L` hacia la IP fija del panel en la
  red `ids-core` (`10.210.255.2`) sale del propio host por la cadena `output`, así que la regla
  `@proxy` no lo bloquea. Solo puede abrirlo quien ya entró por SSH desde una red de gestión.
- **IPv6:** `input` acepta ND/RA y los errores ICMPv6 para que el host no pierda conectividad. Las
  redes Docker son solo IPv4.

### 7.1 Trampas

- **`/etc/nftables.conf` de Debian empieza por `flush ruleset`.** Si `nftables.service` se reinicia
  con Docker arriba, borra sus tablas. No se usa ese servicio.
- **No se instalan `iptables-persistent`/`netfilter-persistent`.** Restauran un `rules.v4` viejo que
  pisa las reglas de Docker. Ya ha pasado.
- **iptables-nft frente a legacy.** `update-alternatives --query iptables` tiene que dar
  `iptables-nft`. Si se cargan reglas legacy, se evalúan los dos conjuntos y `nft list` no muestra
  las legacy.
- **Docker 28 y posteriores** añaden `DOCKER-FORWARD` y reglas en `raw`. Son compatibles con este
  diseño.
- **Sin UFW.** No filtra los puertos de Docker y añade otra capa de reglas que confunde.

## 8. Firewall «solo datos» en cada netns `vpn`

Lo carga el entrypoint del `vpn` antes de crear nada (orden en [INSTANCIA.md](INSTANCIA.md) §4).
Tampoco hace `flush ruleset`: en ese netns, Docker tiene las reglas NAT de su DNS embebido.

```
table inet ids_punto {
  chain input {
    type filter hook input priority filter; policy drop;
    iif lo accept
    ct state established,related accept
    iifname "eth0" tcp dport 1194 accept comment "OpenVPN (DNAT del host)"
    iifname "tun0" ip saddr 100.64.3.2 udp dport 37008 counter accept comment "espejo TZSP"
    iifname "tun0" ip saddr 100.64.3.2 icmp type echo-request limit rate 5/second accept comment "ping del MikroTik"
    counter comment "resto"
  }
  chain output {
    type filter hook output priority filter; policy drop;
    oif lo accept
    ct state established,related accept
    oifname "tun0" ip daddr 100.64.3.2 tcp dport 8729 accept comment "API via rele"
    counter comment "resto"
  }
  chain forward { type filter hook forward priority filter; policy drop; }
}

table netdev ids_mon {
  chain ingreso { type filter hook ingress device "ids-mon" priority -500; policy drop; }
}
```

- Por la VPN **solo entran el espejo, el ping del MikroTik y las respuestas** a lo que abre el
  sensor, que es la API. No se llega al panel, al SSH ni a otros puntos.
- **El MikroTik del punto puede hacer ping al sensor** (`100.64.N.1`), para comprobar el túnel desde
  el router: solo `echo-request`, solo desde su IP del túnel (`100.64.N.2`) y con tope de 5 por
  segundo. La respuesta sale por `ct state established,related`; `output` no abre nada nuevo.
- La salida a internet del `vpn` está cerrada. Si se compromete, no sirve de pivote.
- **`netdev ids_mon` descarta lo inyectado.** AF_PACKET recibe su copia antes del hook de ingreso,
  así que Suricata ve las tramas pero conntrack y la pila IP no las procesan. En el canario se
  comprueba que `capture.kernel_packets` sigue subiendo con esta tabla cargada.

## 9. fail2ban

```ini
# /etc/fail2ban/jail.d/10-ids.local
[DEFAULT]
backend    = systemd
banaction  = nftables[type=multiport]
banaction_allports = nftables[type=allports]
ignoreip   = 127.0.0.1/8 ::1 203.0.113.20      # una sola IPv4 fija del dueño (--dueno-ip); NUNCA las redes de gestión
bantime    = 1h
bantime.increment = true
bantime.maxtime   = 1w
findtime   = 10m
maxretry   = 5

[sshd]
enabled      = true
mode         = aggressive
journalmatch = _SYSTEMD_UNIT=ssh.service

[ids-vpn]
enabled      = true
filter       = ids-vpn
journalmatch = CONTAINER_TAG=ids-vpn
banaction    = nftables[type=allports, chain_hook=forward]
# cadena propia: la de sshd (f2b-chain) ya existe en la tabla f2b-table con el hook input
chain        = f2b-ids-vpn
```

```ini
# /etc/fail2ban/filter.d/ids-vpn.conf (install.sh lo comprueba con fail2ban-regex)
[DEFAULT]
__ids_pref = (?:(?:\S+ )?ids-vpn(?:\[\d+\])?: )?

[Definition]
failregex = ^%(__ids_pref)s<HOST>:\d+ ovpn-auth: rechazado usuario=\S+ motivo=(?:formato|usuario)(?:\s|$)
ignoreregex =
```

- **Una línea por intento.** `TLS Auth Error` y `TLS Error: TLS handshake failed` son el mismo
  intento (contarlas baneaba al 3.er fallo) y no cuentan.
- **Solo lo de quien no conoce el usuario** (`motivo=formato` o `motivo=usuario`). El usuario VPN no
  es público: está en el router y en el panel. `motivo=clave` es el dueño con la clave vieja (tras
  «Regenerar la clave VPN»), y `motivo=freno`/`freno-global` lo que sigue; banearlos cortaba todos los
  puertos de la IP del MikroTik, hasta 1 semana. A ese caso lo frena `ovpn-auth` (5 intentos por IP
  cada 600 s, 30 scrypt por minuto en total) y la fuerza bruta contra un usuario conocido queda
  igual de acotada frente a 62²⁴ claves.
- `__ids_pref` admite el prefijo `<_HOSTNAME> <SYSLOG_IDENTIFIER>[<_PID>]: ` que antepone el backend
  systemd, sin desanclar la regex.

**SSH:**

- Hace falta `python3-systemd`.
- En Debian 13 la unidad es `ssh.service` y los fallos los escribe `sshd-session`, por eso se
  cambia el `journalmatch`. El instalador lo comprueba con `fail2ban-regex`.

**Redes de gestión fuera de `ignoreip`.** Un equipo comprometido dentro de la red del ISP también
se bloquea. Solo se exceptúa **una** IPv4 fija del dueño, para no perder el acceso: `install.sh
--dueno-ip` admite una sola dirección (es el `IGNOREIP_DUENO` de `ids.conf`).

**OpenVPN:**

- Los contenedores `vpn` usan `logging: {driver: journald, options: {tag: ids-vpn}}`.
- El DNAT conserva la IP de origen, así que la jaula banea en el hook `forward`, en su propia tabla
  `f2b-table`, con prioridad anterior a la de Docker, en una cadena propia (`f2b-ids-vpn`), porque
  la de sshd (`f2b-chain`) ya está en esa tabla con el hook `input`.
- Corta a la IP baneada todo lo que publica Docker (la VPN de todos los puntos y el panel), no el SSH
  del host, que no pasa por `forward`.
- Con `allports` no importa que el DNAT haya cambiado el puerto.
- Un MikroTik que sigue reintentando con una clave vieja **no** se banea (ver el filtro); sí un router
  que llama con un usuario que ya no existe (p. ej. el de un punto dado de baja). Desbanear:
  `ids-orq vpn desbanear <ip>` ([OPERACION.md](OPERACION.md) §5).
- **journald:** todos los contenedores escriben por `docker.service` y comparten su límite de ritmo.
  `/etc/systemd/journald.conf.d/90-ids.conf` (de `host/journald/`) lo sube a 50 000 mensajes cada
  30 s, para que una avalancha no tire las líneas que lee fail2ban, y fija el tamaño en 2 GB.
- **Conexiones a medio negociar** (cualquiera puede abrir el puerto): no llegan a `ovpn-auth` ni a
  fail2ban. Las acotan `hand-window 20` y `max-clients 32` del `server.conf`
  ([INSTANCIA.md](INSTANCIA.md) §7.2) junto al freno de conexiones nuevas del §7 (10/min por IP de
  origen, sumando todos los puertos VPN). **Mitigado, no cerrado (VPN-03):** con 10 conexiones
  nuevas por minuto y 20 s de `hand-window`, una IP mantiene unas 3 conexiones colgadas a la vez, así
  que unas 10 u 11 IP llenan las 32 plazas de un punto. Contra eso, la defensa fuerte es el origen fijo
  (`--origen-ip`) del punto. No hay límite de conexiones simultáneas por IP (`ct count`): necesitaría
  el módulo `nft_connlimit` en el **host** y no está validado.

**Panel:** fail2ban no lo cubre, porque todas sus conexiones llegan desde la IP del proxy y banearla
cortaría a todo el mundo. El panel tiene su propio freno de login por **IP real del cliente**,
tomada de `X-Forwarded-For` solo cuando la conexión viene del proxy (ver
[PLAN-PANEL.md](PLAN-PANEL.md) §12).

## 10. Modo seguro para cambiar el acceso

> **Estado real:** `acceso.aplicar` y `acceso.confirmar` son órdenes **reservadas** del orquestador
> (contestan «no disponible»). Lo que existe hoy es el modo seguro de `install.sh`: antes de cambiar
> el firewall del host guarda el anterior en `/root/ids-maat/acceso-anterior-<ts>/`, genera
> `/root/ids-maat/revertir-acceso.sh` y lo programa con `systemd-run` a los 5 min; desde una sesión
> SSH **nueva**, `install.sh --confirmar` lo anula. Con `--sin-reversion` (instalación desde la
> consola) no hay modo seguro. El origen fijo de cada puerto VPN se cambia con
> `ids-orq punto ajustar <pid> --origen-ip …`. Lo de abajo es el diseño pendiente de la orden.

Las redes de gestión (SSH), las IP del proxy (panel) y el origen permitido de cada puerto VPN se
cambiarían con la orden `acceso.aplicar` del orquestador.

### Validaciones (las hace el orquestador; el panel solo las adelanta)

- Ninguna de las dos listas puede quedar vacía.
- **La IP del proxy por la que llega la petición tiene que seguir en la lista de proxies.** Si no,
  el cambio dejaría al operador fuera del panel. Se acepta solo si marca a propósito «voy a entrar
  por otro proxy».
- **IP del proxy:** solo direcciones concretas o redes pequeñas (hasta /28). Un proxy no es una
  red de clientes.
- **No se aceptan redes de gestión más anchas que /16.** Para eso hace falta la consola, editando
  `ids.conf` y `ids-orq fw-render --aplicar` ([OPERACION.md](OPERACION.md) §4).
- No puede haber solape con la base de túneles ni con el pool de Docker: por la VPN solo pasan
  datos.
- sshd no se valida: desde 2026-10-19 el IDS no toca su configuración (el SSH admite contraseña y
  clave, como lo tenga el servidor; decisión del dueño). Lo protege la jaula `sshd` de fail2ban (§9).

### Aplicación

1. Respaldo de `/srv/ids/fw/` en `/root/backups/`.
2. `nft -c -f ids_host.nuevo.nft` y, si es válido, `nft -f` (aplicación atómica).
3. Se arma la reversión: `systemd-run --on-active=300 ids-fw revertir`. La ventana es de **5 min
   por defecto** y se configura en Ajustes.

### Confirmación

- El panel muestra una cuenta atrás. «Confirmar» tiene que llegar por **una conexión nueva**, que
  pasa por las reglas nuevas.
- Si llega, `acceso.confirmar` anula el temporizador y **solo entonces** sustituye el fichero
  persistente `ids_host.nft`.
- Si no llega, al vencer la ventana se vuelve al ruleset anterior.
- **Un reinicio del VPS durante la ventana equivale a revertir.** `ids-host-fw.service` carga el
  fichero persistente, que no ha cambiado.

**Recuperación:** la consola del proveedor y `/root/ids-maat/revertir-acceso.sh` (vuelve a como
estaba antes de la última ejecución de `install.sh`) o `ids.conf` + `ids-orq fw-render --aplicar`
([OPERACION.md](OPERACION.md) §4).

## 11. Punto directo, sin VPN (solo red local)

Desde 0.1.9 un punto se puede crear **directo**: para quien tiene el MikroTik en la misma red
local que el VPS y no quiere la VPN (decisión del dueño, 2026-10-18). Se elige al crearlo
(`modo=directo` y `mk_ip`, la IP del MikroTik en la LAN) y no se cambia después: para pasar a VPN,
o cambiar la IP, se da de baja y se crea otro.

```
 MikroTik 192.168.88.1 ── LAN ──► host 192.168.88.10
   │  host: nft inet ids_host (udp 37009 publicado, desde cualquier IP)
   └─ udp 37009 ──DNAT──► red ids-p002 ─► vpn-p002 :37008 (eth0)

 netns de p002 (dueño: vpn-p002, sin OpenVPN ni tun0)
   eth0 ── udp 37008 desde cualquier IP ─► tzsp-decap ─► ids-in ══veth══ ids-mon ─► suricata-p002
   relé: /run/ids/api.sock ─► 192.168.88.1:8729 (sale por eth0)
```

| Pieza | Con VPN | Directo |
|---|---|---|
| Puerto publicado | `1194+N-1/tcp` (OpenVPN) | `37008+N-1/udp` (el espejo) |
| Origen aceptado | cualquiera, o `origen_ip` si se fija | **cualquiera** desde 2026-10-20 (antes solo `mk_ip`): sin regla `espejo directo <pid>` en el host, `TZSP_ALLOW=0.0.0.0/0` en el receptor y sin `ip saddr` en el `ids_punto` del contenedor |
| `sniff-target` en el MikroTik | `100.64.N.1`, puerto 37008 | la IP del host hacia el MikroTik (`ip -4 route get <mk_ip>`), puerto `37008+N-1` |
| API | relé → `100.64.N.2:8729` por `tun0` | relé → `<mk_ip>:8729` por `eth0`; el router ve la IP del host |
| «Conectado» | cliente OpenVPN conectado | espejo en los últimos 2 min (`tzsp.visto_s`) |
| Certificado, usuario VPN, `server.conf`, fail2ban | sí | no |

- **Solo red local.** `mk_ip` tiene que ser privada o CGNAT (`10/8`, `172.16/12`, `192.168/16`,
  `100.64/10`) y no caer en la base de túneles, el pool de Docker ni la red del panel. Sin VPN el
  espejo va **sin cifrar** y en UDP: dentro de la LAN vale; por internet, no (por eso una IP pública se
  rechaza). Si algún día se permitiera, la API tendría que exigir la huella del certificado de la
  API-SSL antes de mandar la clave de `ids-api` (decisión del dueño, 2026-10-18).
- **Espejo desde cualquier IP** (decisión del dueño 2026-10-20: «necesito que escuche cualquier IP»).
  El MikroTik puede mandarlo desde una dirección que no es la de su API (visto en un cliente: la API
  en 172.16.x y el espejo saliendo por un enlace 100.64.x, que además cae en la base de túneles y no
  se puede dar como `mk_ip`). Lo que tiene que coincidir es el **puerto** UDP del punto. Quien
  alcance ese puerto puede inyectar espejo; la seguridad de la red la decide el cliente. `mk_ip`
  sigue siendo la IP de la API y la que decide qué IP del host va en `sniff-target`.
- **Mismo contenedor.** El `vpn` del punto directo arranca con `MODO=directo`: su servicio OpenVPN
  se queda quieto (`sleep infinity`, para que el árbol de s6 sea el mismo) y `salud-vpn` no lo mira.
  La imagen declara `LABEL ids-maat.modos="vpn,directo"`; sobre una imagen anterior el orquestador no
  crea un punto directo (`CONFLICTO` antes de gastar pid).
- **Fragmentación.** Una trama de 1514 B más la cabecera TZSP no cabe en 1500: el MikroTik la
  fragmenta; el host la reensambla para el DNAT y el netns del punto otra vez (los mismos `ipfrag_*`).
