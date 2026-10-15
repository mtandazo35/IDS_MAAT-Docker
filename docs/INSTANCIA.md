# Instancia por punto y capacidad

Anexo de [ARQUITECTURA.md](ARQUITECTURA.md). Este anexo cubre:

- los dos contenedores de cada punto, su arranque y su captura;
- el `suricata.yaml` y OpenVPN de cada punto;
- la salud y la trampa del netns;
- la capacidad del VPS y las reglas compartidas.

La red y el firewall están en [RED-Y-FIREWALL.md](RED-Y-FIREWALL.md).

## 1. Qué es una instancia

Una instancia son dos contenedores que comparten el netns del `vpn`:

- **`vpn`** es el dueño del netns. Su PID 1 es `s6-overlay` v3, que supervisa:
  - `openvpn`;
  - `tzsp-decap`;
  - un relé `socat` hacia la API-SSL del MikroTik.
- **`suricata`** (`network_mode: "service:vpn"`) captura `ids-mon` con af-packet.

Todo lo que está en disco y todos los nombres de contenedor usan el `punto_id` (`p003`). `N` solo
da la red, el puerto y el `cluster-id`.

## 2. Compose generado

El orquestador escribe `/srv/ids/puntos/<pid>/compose.yml` con su plantilla. El panel no elige
imágenes, rutas, puertos, capacidades ni redes. Extracto:

```yaml
name: ids-p003
services:
  vpn:
    image: ghcr.io/<owner>/ids-maat-vpn@sha256:<digest>
    container_name: ids-p003-vpn
    restart: unless-stopped
    cap_drop: [ALL]
    cap_add: [NET_ADMIN, NET_RAW]
    devices: ["/dev/net/tun:/dev/net/tun"]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: ["/run:exec,size=16m", "/tmp:size=16m"]        # s6-overlay v3 necesita /run ejecutable
    sysctls: { ver §3 }
    ports: ["1196:1194/tcp"]
    networks: [punto]
    environment: { PUNTO: "p003", N: "3", TUN_NET: "100.64.3.0/24", API_PUERTO: "8729", TZSP_BYTES: "10000", TZ: "UTC" }
    volumes:
      - /srv/ids/puntos/p003/vpn:/etc/ids/vpn:ro
      - /srv/ids/run/p003:/run/ids                      # root:10500 2770
      - /srv/ids/ctl/p003/vpn:/run/ids-ctl
    logging: { driver: journald, options: { tag: ids-vpn } }   # fail2ban de OpenVPN
    mem_limit: 192m
    memswap_limit: 192m
    pids_limit: 64
    healthcheck: { test: ["CMD", "/usr/local/bin/salud-vpn"], interval: 30s, retries: 3,
                   start_period: 30s, start_interval: 5s }
  suricata:
    image: ghcr.io/<owner>/ids-maat-suricata@sha256:<digest>
    container_name: ids-p003-suricata
    network_mode: "service:vpn"
    depends_on: { vpn: { condition: service_healthy, restart: true } }
    restart: unless-stopped
    cap_drop: [ALL]
    cap_add: [NET_RAW]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: ["/tmp:size=64m", "/run:size=8m"]
    environment: { TZ: "UTC" }
    volumes:
      - /srv/ids/reglas:/reglas:ro
      - /srv/ids/feeds:/var/lib/suricata-feeds:ro
      - /srv/ids/puntos/p003/suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro
      - /srv/ids/puntos/p003/suricata/threshold.config:/etc/suricata/threshold.config:ro
      - /srv/ids/datos/p003:/var/log/suricata
      - /srv/ids/ctl/p003/suricata:/run/suricata
    cpuset: "4-5"
    cpus: 2
    mem_limit: 1600m          # motor medido + memcaps + 20 % (§10.3)
    memswap_limit: 1600m
    pids_limit: 256
    healthcheck: { test: ["CMD", "/usr/local/bin/salud-suricata"], interval: 30s, retries: 3,
                   start_period: 600s, start_interval: 5s }   # start_interval: Docker Engine >= 25
networks:
  punto:
    driver: bridge
    driver_opts: { com.docker.network.bridge.name: ids-p003 }
    ipam: { config: [ { subnet: 10.210.0.48/28 } ] }
```

### 2.1 Capacidades y endurecimiento

| Contenedor | Necesita | Por qué |
|---|---|---|
| `vpn` | `NET_ADMIN` | `tun0`, veth, nft de su netns, ethtool, `SO_RCVBUFFORCE` |
| `vpn` | `NET_RAW` | `tzsp-decap` inyecta con `AF_PACKET` |
| `vpn` | `/dev/net/tun` | OpenVPN |
| `suricata` | `NET_RAW` | socket af-packet (y el promisc por `PACKET_ADD_MEMBERSHIP`, que no pide más) |
| `suricata` | — (sin `NET_ADMIN`) | **Quitada** (auditoría VPN-05): Suricata analiza el tráfico hostil de los abonados y, con `NET_ADMIN`, un RCE podía borrar `inet ids_punto`/`netdev ids_mon` o reconfigurar `tun0`. No la necesita: `ids-mon` ya está en promisc y sin offloads (`init-veth` del `vpn`) y la plantilla lleva `capture.disable-offloading: false`. La e2e del CI (Docker real) comprueba que la alerta llega; en el canario, que `capture.kernel_packets` sigue subiendo |

- **Sin `privileged` y sin `userns-remap`.** Con `userns-remap`, `NET_ADMIN` no vale sobre el netns
  que crea dockerd, y fallan `tun0`, el veth y nft.
- `cap_drop: ALL`, `read_only`, `no-new-privileges` y los perfiles por defecto de seccomp y
  AppArmor (`docker-default` permite `AF_PACKET`).
- `mem_limit == memswap_limit`: sin swap. Un OOM mata solo a ese Suricata.
- **Suricata con `read_only`** corre sin `--pidfile`, o con el pidfile en el tmpfs `/run`.

## 3. Sysctls del netns

Docker solo admite `net.*` con espacio de nombres. Los `default.*` también los hereda `eth0`:
Docker la mete en el netns después de aplicar los sysctls.

```yaml
sysctls:
  net.ipv4.ip_forward: "0"
  net.ipv6.conf.all.disable_ipv6: "1"
  net.ipv6.conf.default.disable_ipv6: "1"
  net.ipv4.conf.default.rp_filter: "1"
  net.ipv4.ipfrag_high_thresh: "67108864"   # el TZSP llega FRAGMENTADO por tun0
  net.ipv4.ipfrag_time: "15"
```

Sin `ipfrag_low_thresh`: está obsoleto desde Linux 4.17 y el kernel exige `low <= high`. runc escribe
los sysctls en un orden aleatorio, y `low` (48 MB) antes que `high` (4 MB por defecto) da `EINVAL`
y el contenedor no arranca.

Sin `conf.default.arp_ignore=8`: `eth0` lo heredaba, dejaba de contestar ARP y el host no llegaba
al contenedor (el DNAT a `:1194` daba «No route to host»). Lo que se quería, que el veth no hable
ARP, lo hace `arp off` en `ids-in` e `ids-mon` (§4.1).

`net.core.rmem_max` **no es por netns**. `tzsp-decap` pide 16 MB con `SO_RCVBUFFORCE`, que ignora
ese límite cuando hay `NET_ADMIN`. Como respaldo, el host lo sube en `/etc/sysctl.d/90-ids.conf`.

## 4. Arranque

### 4.1 Entrypoint del `vpn` (en este orden)

1. **Carga la tabla `inet ids_punto`** ([RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) §8). El netns queda
   cerrado antes de que exista ningún servicio. Por `tun0` solo entran, desde el MikroTik del punto,
   el espejo TZSP y el ping (`echo-request`, con tope de 5 por segundo); solo sale la API por el
   relé. La tabla se genera al arrancar el contenedor: un punto ya creado recibe una regla nueva al
   recrear su `vpn` con la imagen nueva (`ids-orq punto reconfigurar <pid>`, [OPERACION.md](OPERACION.md) §1.6).
2. **Crea el veth y apaga los offloads:**

   ```sh
   ip link add ids-in type veth peer name ids-mon
   ip link set ids-in  up mtu 65535 arp off
   ip link set ids-mon up mtu 65535 promisc on arp off
   ethtool -K ids-mon gro off lro off tso off gso off rx-gro-hw off 2>/dev/null || true
   ethtool -K ids-in  gro off tso off gso off 2>/dev/null || true
   ```

3. **Carga la tabla `netdev ids_mon`.** Necesita que `ids-mon` ya exista.
4. **s6 arranca los servicios:** `openvpn`, `tzsp-decap` y el relé.

### 4.2 Entrypoint de `suricata`

Antes de hacer `exec suricata`, **espera hasta 60 s a que exista `ids-mon`**. Esto cubre el
arranque tras reiniciar el VPS: ahí dockerd levanta los contenedores por su restart policy y no
aplica `depends_on`. Si a los 60 s no existe, sale con error y la restart policy lo reintenta.

## 5. Captura

Bloque af-packet del `suricata.yaml` del punto:

```yaml
af-packet:
  - interface: ids-mon
    cluster-id: 103          # 100 + N
    cluster-type: cluster_flow
    threads: 2               # SIEMPRE explícito
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    block-size: 131072
    ring-size: 1024          # explícito: el anillo se cuenta en la admisión
    snaplen: 32768           # sin fijarlo se deriva del MTU 65535 y dobla el anillo
    checksum-checks: no
```

`tzsp-decap.py` se reutiliza entero: el parser TZSP, `permitido` (fail-closed), el recorte por
flujo y el estado JSON. Cambia esto:

- **Un solo origen y una sola interfaz:** `TZSP_ALLOW=100.64.N.2/32`, `TZSP_OUT_IF=ids-in` y
  `TZSP_ESTADO=/run/ids/tzsp.json`.
- **Escucha en `0.0.0.0:37008`.** El filtrado por `tun0` y por origen lo hace nft.
- **Latido.** El socket lleva `settimeout(30)` y el receptor escribe `tzsp.json` **cada 30 s
  aunque no llegue tráfico**. Es la señal de vida que usa el healthcheck (§8).

## 6. `suricata.yaml` del punto

**No se usa `include:`.** El orquestador genera siempre el `suricata.yaml` **completo** a partir de
la plantilla de la versión de imagen que va a ejecutar. Al descargar una versión, extrae la
plantilla de la imagen con `docker create` + `docker cp`, renderiza el fichero, lo valida y lo
guarda en `/srv/ids/puntos/<pid>/suricata/`.

Lo que trae la plantilla, ajustado para espejo:

- `midstream`, `async-oneside`, `bypass`;
- `encryption-handling: bypass`;
- `flow-timeouts.tcp.established: 300` y `reassembly.depth: 512kb`;
- `checksum-validation: no`;
- un eve principal sin `flow`, `dns`, `quic`, `anomaly`, `ike` ni `bittorrent-dht`, con `stats`
  cada 30 s;
- un `stats.json` aparte, solo con los `stats` (~8 KB cada 30 s): es de donde los leen el
  orquestador, `salud-suricata` y el panel. Con espejo real, entre dos `stats` del eve caben
  ~1,6 MB de eventos y buscarlos en la cola del eve fallaba casi siempre (punto «sin datos»);
- un `dns.json` aparte, solo con las consultas;
- `local.rules` con el dataset `feeds-dominios`.

Valores que pone el orquestador:

| Clave | Valor | Origen |
|---|---|---|
| `sensor-name` | `p003` | `punto_id`. Suricata lo escribe como `host` en cada evento ([DATOS.md](DATOS.md) §3) |
| `HOME_NET` | `[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10]` más los `redes_abonados` del punto que caen fuera (públicos, POST-NAT) | fijo + punto (`home_net`). Cambiar prefijos privados no reinicia Suricata (decisión del dueño 2026-10-15); los prefijos deciden el espejo del MikroTik y quién es abonado en el panel |
| `af-packet` | §5 | orquestador |
| `threading.set-cpu-affinity` | `no` | la afinidad la da el `cpuset` de Docker |
| `detect.profile`, `sgh-mpm-context` | según el perfil (§10.2) | punto |
| `mpm-algo`/`spm-algo` | `hs` si la build trae Hyperscan; si no, `ac-ks` | `suricata --build-info` |
| memcaps | `flow 64mb`, `stream 64mb`, `reassembly 256mb`, `defrag 32mb` (orientativos) | fijos por perfil |
| `default-rule-path` | `/reglas/current/<completo\|reducido>` | perfil |
| `threshold-file` | `/etc/suricata/threshold.config` | exclusiones globales más las del punto |
| `unix-command` | `/run/suricata/suricata-command.socket` | solo para el orquestador (reapertura de logs, `dataset-add`) |

**Nada de autodetección.** Dentro del contenedor, `/proc/meminfo` y el número de CPU son los del
host:

- la fórmula actual (reassembly = 25 % de la RAM) daría 2 GB de reassembly a cada instancia;
- `threads: auto` daría 8 hilos a cada una.

**Hilos:** 1 o 2 por instancia, en `runmode: workers`. Dos solo si el punto pasa de 150–200 Mbps
de espejo ya recortado.

## 7. OpenVPN

### 7.1 PKI

- **CA común por VPS** en `/srv/ids/pki` del host (0700). Nunca se monta en un contenedor.
- **Certificado de servidor por punto**: `OU=server-<pid>`, `CN=<NOMBRE_DNS>` y
  `subjectAltName=DNS:<NOMBRE_DNS>` (`IP:` si el nombre es una IP), EKU `serverAuth`, RSA 2048 por
  compatibilidad con v6. Con un `NOMBRE_DNS` de más de 64 caracteres el CN es `server-<pid>` y vale
  el SAN.
- En el `vpn` se montan solo `ca.crt`, su certificado y su clave, y `dh.pem`.
- **Sin CRL.** Con `verify-client-cert none` no hay certificados de cliente que revocar. En la baja
  se borran la clave y el certificado del servidor.
- **El MikroTik verifica al servidor** (v6 y v7): el script del alta importa la CA del VPS (pública;
  una por VPS) y pone `verify-server-certificate=yes`. RouterOS exige la cadena hasta esa CA y el
  `connect-to` en el CN o el SAN ([OPERACION.md](OPERACION.md) §1.4).
- **Puntos anteriores a ese cambio:** su certificado solo llevaba `CN=server-<pid>`.
  `punto.vpn.regenerar` lo detecta (`openssl x509 -ext subjectAltName`), lo renueva y reinicia
  OpenVPN; hasta entonces el script lo avisa en la cabecera.
- La seguridad del punto la da su **usuario y clave**, y la del router frente a un impostor, la
  verificación del servidor. El script no lleva reglas de firewall ni rutas: lo que entra al router
  por `ids-vpn` lo decide el firewall del operador ([OPERACION.md](OPERACION.md) §1.5).

### 7.2 `server.conf` (lo esencial)

```
port 1194
proto tcp4-server
dev tun0
topology subnet
server 100.64.3.0 255.255.255.0
max-clients 16
hand-window 20
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-256-CBC
# v6: data-ciphers-fallback AES-256-CBC (cliente cipher=aes256)
# v7: data-ciphers-fallback AES-256-GCM (cliente cipher=aes256-gcm)
auth SHA1
verify-client-cert none
username-as-common-name
auth-user-pass-verify /usr/local/bin/ovpn-auth via-file
script-security 2
client-config-dir /etc/ids/vpn/ccd
ccd-exclusive
keepalive 10 60
persist-key
persist-tun
status /run/ids/openvpn-status.log 10
status-version 2
management /run/ids-ctl/ovpn-mgmt.sock unix
```

- **ccd:** `ccd/<usuario>` contiene solo `ifconfig-push 100.64.N.2 255.255.255.0`. Con
  `ccd-exclusive`, nadie entra sin ese fichero.
- **`proto tcp4-server`:** el `vpn` no usa IPv6. `data-ciphers` es el mismo en v6 y v7; solo cambia
  el `data-ciphers-fallback` según la versión declarada del punto.
- **`max-clients 16` y `hand-window 20` (auditoría VPN-03).** OpenVPN cuenta en `max-clients` las
  conexiones TCP que aún no se han autenticado, que no llegan a `ovpn-auth` ni a fail2ban: con 2
  plazas, dos `nc` colgados de un desconocido dejaban fuera al MikroTik. Ahora quien no termina el
  TLS y la autenticación en 20 s pierde su plaza (antes, 60 s por defecto) y, con el freno del host
  (10 conexiones nuevas/min por IP), una IP sostiene unas 3 a la vez: hace falta más de media
  docena de IP para llenar las 16. **Sin `duplicate-cn`**, sigue habiendo un solo túnel útil: la
  sesión nueva del usuario echa a la vieja (las 2 plazas de antes eran para eso). 20 s deja margen a
  un 6.49 lento en el handshake RSA 2048. Prueba de laboratorio pendiente: 3 `nc <vps> <puerto>`
  colgados, cortar la VPN del router y ver que reconecta.
- **No se usan** `iroute`, `push` de rutas, compresión, `tls-crypt` ni `tls-auth`. RouterOS no
  soporta los dos últimos.
- **`persist-tun`** mantiene `tun0` entre renegociaciones, pero **no sobrevive a la muerte del
  proceso**. Si `openvpn` muere, s6 lo relanza y se crea un `tun0` nuevo. El veth no se toca,
  porque vive en el netns y no en un proceso.
- **Sin DCO:** el módulo no admite CBC, y el kernel 6.12 de trixie no trae `ovpn` (llega en 6.16).
  Con v7 en GCM y un kernel futuro sería posible. Hoy el techo de cifrado es un núcleo por punto.
- **RouterOS 6.49, la versión mínima soportada, con OpenSSL 3 (SECLEVEL 2).** El canario (F1a) la
  prueba con el TLS moderno. Si el handshake falla, se activa el interruptor «compatibilidad v6»
  del punto (`tls_legacy`): primero `tls-cipher "DEFAULT:@SECLEVEL=0"` y, si no basta,
  `tls-cert-profile legacy`. Las dos opciones van **solo en esa instancia** (decisión d de
  ARQUITECTURA §10). No se admiten versiones anteriores a 6.49.

### 7.3 Usuarios sin cuentas del sistema

- `/etc/ids/vpn/usuarios` (ro, 0600 `root:root`) contiene `usuario:scrypt$N$r$p$sal$hash`. Con
  `cap_drop: ALL` el root del contenedor no tiene `DAC_OVERRIDE`: solo cuentan los bits del dueño.
- `ovpn-auth` está escrito con la stdlib y hace esto:
  1. Valida el formato del usuario y de la clave (`motivo=formato`).
  2. **Comprueba el freno ANTES de calcular scrypt**, sin dormir: por `untrusted_ip`, 5 rechazos en
     600 s (`motivo=freno`); global, 30 scrypt en 60 s (`motivo=freno-global`), que no frena a la
     última IP que entró con la clave buena durante 24 h (una avalancha ajena no le tira el túnel al
     MikroTik en la renegociación, auditoría VPN-08).
  3. Busca el usuario (`motivo=usuario`), calcula scrypt y compara con `hmac.compare_digest`
     (`motivo=clave`).
  4. Escribe una línea `<ip>:<puerto> ovpn-auth: rechazado usuario=<u|-> motivo=<m>` (o `aceptado`).
     fail2ban solo cuenta `formato` y `usuario` ([RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) §9).
- **El orquestador guarda solo el hash** y entrega la clave en claro una sola vez, al panel. El panel
  la guarda **cifrada** con la clave maestra (`/srv/ids/panel/conf/vpn-claves.json`, 600, ligada al
  punto) para dar en la ficha los comandos del MikroTik con la clave puesta; la borra en la baja.
- Más frenos en el host: el `meter` de conexiones nuevas y la jaula `ids-vpn`
  ([RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) §7 y §9).

## 8. Salud

| Contenedor | Healthcheck (solo «el proceso está vivo») | Nunca falla por |
|---|---|---|
| `vpn` | `openvpn` vivo y con más de 5 s arriba según s6 (no en bucle de reinicios), un socket TCP en LISTEN en el `port` de `server.conf` (`/proc/net/tcp` del netns), relé vivo, y `tzsp.json` con menos de 90 s (el latido de §5) | que no llegue espejo, que el punto esté pausado o que el MikroTik esté desconectado |
| `suricata` | proceso vivo y el último `stats` de `stats.json` (o de `stats.json.1`, recién rotado) con menos de 120 s **y posterior al arranque del proceso actual** (se abre en modo añadir: tras un reinicio, el último stats es de la instancia anterior). Sin `stats.json` (yaml de antes), la cola de 512 KiB del eve | que no haya tráfico |

- **Sin espejo no es un fallo del contenedor.** Es **salud funcional** y la vigila el orquestador
  ([ORQUESTADOR.md](ORQUESTADOR.md) §8):
  - si `tzsp.json` dice que entra espejo pero `capture.kernel_packets` no sube, avisa «entra pero no
    llega a Suricata»;
  - si un punto activo lleva X minutos sin espejo, avisa.
- **El alta da la instancia por sana cuando los procesos están vivos.** No espera al espejo, porque
  el MikroTik todavía no está conectado.
- **Un punto pausado** (con el mangle deshabilitado) sigue sano.

## 9. Trampa: netns huérfano

Si `vpn-<pid>` se reinicia (por un fallo, un OOM o una actualización), Docker le crea **un netns
nuevo**. `suricata-<pid>` sigue en el viejo: ese netns sigue vivo mientras Suricata lo referencie,
con un `ids-mon` al que ya nadie inyecta. El contenedor está «Up», cualquier prueba local dice que
está sano, y está ciego. `depends_on.restart` solo actúa cuando el reinicio lo hace compose.

Mitigación:

1. **Un `vpn` estable.** s6 reinicia `openvpn`, `tzsp-decap` y el relé **dentro** del contenedor,
   así que un fallo de un proceso no reinicia el contenedor.
2. **El orquestador compara los netns.** Lo hace ante cada `start` de `ids-<pid>-vpn` en
   `docker events` y, además, cada 30 s:
   - obtiene los PID con `docker inspect -f '{{.State.Pid}}'` de los dos contenedores;
   - compara los inodos de `/proc/<pid_vpn>/ns/net` y `/proc/<pid_suricata>/ns/net`;
   - **si difieren, reinicia `suricata`.**
3. **El entrypoint de `suricata` espera a `ids-mon`** (§4.2).

**Plan B,** si en producción sigue dando guerra: un tercer contenedor mínimo por punto que solo
posea el netns (el patrón «pause»).

## 10. Capacidad y dimensionado

### 10.1 Memoria de una instancia

Las cifras son orientativas para Suricata 7.0.x de Debian. **Se miden en el canario** (F1a).

| Componente | ET Open completo (~53k reglas), `medium`, `hs` | Notas |
|---|---|---|
| Motor de detección cargado | 0,6–1,0 GB | depende de las reglas activas y del perfil |
| Memcaps | ~0,4 GB como máximo | fijos |
| Anillo af-packet | 1024 × 32 KB × 2 hilos ≈ 64 MB | probablemente **fuera del cgroup**: se cuenta aparte |
| Datasets | unos MB | por instancia |
| `vpn` | < 192 MB | `mem_limit` |

**No hay recarga en caliente** (`reload-rules`), así que no existe el pico de doble motor (§11).

### 10.2 Perfiles por punto y capacidad estimada en 8 GB

Reservas fijas: ~1 GB para el host y Docker, ~1 GB para el panel, y **una sola reserva** para el
`suricata -T` efímero, del tamaño del motor del perfil más grande que esté en uso.

| Perfil | Reglas / detección | `mem_limit` estimado de `suricata` | Puntos en 8 GB |
|---|---|---|---|
| `reducido` (**por defecto en el alta**) | ~15–20k reglas útiles para un espejo de ISP | 0,6–0,9 GB | **5–7** |
| `completo-low` | ET completo, `profile: low` y `sgh-mpm-context: single` | 1,0–1,3 GB | **3–4** |
| `completo` | ET completo, `profile: medium` | 1,2–1,7 GB | **2–3** |

**A MEDIR EN EL CANARIO.**

- **Decisión del dueño (ARQUITECTURA §10 e):** reglas reducidas por defecto en el alta y
  `completo` solo donde quepa. Los perfiles y las cifras se fijan con las mediciones de F1a.
- El perfil se elige por punto y se cambia con `punto.ajustar`, que pasa por la admisión.
- `reducido` sale de la **misma descarga** que `completo`: `suricata-update --offline` con otro
  `disable.conf`, que quita `policy`, `info`, `games`, `chat`, `inappropriate`, `hunting`… La lista
  exacta se fija tras F1a.

### 10.3 Control de admisión

```
mem_limit(suricata) = (motor medido del perfil + memcaps) × 1,2
Σ mem_limit(suricata) + Σ mem_limit(vpn) + Σ anillos af-packet
  + reserva_T (motor del perfil mayor × 1,2) + host 1 GB + panel 1 GB  ≤  MemTotal
y además  MemAvailable ≥ mem_limit(nuevo) + 512 MB
```

- Si no cabe, el orquestador responde cuántos puntos caben con cada perfil.
- La reserva del `-T` es **una sola**, porque las órdenes que la usan pasan por la cola en serie
  del orquestador.

### 10.4 CPU

- La CPU 0-1 queda para el host, el panel y los OpenVPN.
- Cada Suricata recibe un `cpuset` mientras haya CPU libres. Con más puntos que CPU, se comparte
  con la cuota `cpus:`.

### 10.5 Disco y rotación

- **logrotate del host**, lanzado por un timer cada 15–60 min, para `eve.json`, `dns.json` y
  `orq.jsonl`:
  - eve/dns: `maxsize 1G`, nombre fechado (`dateext`, `-%Y%m%d-%H%M%S`), `rotate -1` (sin tope de
    número) y `nocompress` (F2, CONTRATO-F2 §9);
  - **sin `copytruncate`**;
  - `postrotate`: el orquestador pide `reopen-log-files` a cada instancia.
  - `stats.json`: aparte, `size 5M`, `rotate 1` y **con `copytruncate`** (Suricata lo abre en modo
    añadir); solo queda `stats.json.1`, que los lectores miran también para no quedarse sin dato
    justo después del corte. No cuenta para la retención.

  **Retención por fecha (F2): 30 días.** El orquestador comprime los rotados conservando su mtime,
  poda lo que tiene más de 30 días y, por debajo del 15 % libre, borra antes de tiempo los rotados
  más viejos con registro y aviso ([ORQUESTADOR.md](ORQUESTADOR.md) §8.1).
- **Logs de los contenedores:** el driver `local` con tope; en los `vpn`, journald con la retención
  del journal.
- **Alarma global por `df`.** Con el disco lleno, las capturas salen vacías y nada da error.

## 11. Reglas y feeds compartidos

```
/srv/ids/reglas/releases/<ts>/{completo,reducido}/suricata.rules
/srv/ids/reglas/current -> releases/<ts>        # enlace RELATIVO
/srv/ids/feeds/{reputation.lst,domains.lst,domains.dataset}
```

- **Se monta el directorio padre**, `/srv/ids/reglas:/reglas:ro`. Si se montara el enlace
  `current`, Docker lo resolvería al crear el contenedor y no vería los cambios posteriores.
- **El dataset solo se carga con `load`** (sin `save`/`state`). El fichero tiene que existir aunque
  esté vacío, porque un `load` de un fichero inexistente tumba la carga de **todas** las reglas.

### 11.1 Actualización diaria (`reglas.actualizar`, de madrugada)

1. **Descarga**, en un contenedor efímero de la imagen `suricata`, que es la única pieza con salida
   a las fuentes:
   - `suricata-update` una vez y los perfiles `--offline`;
   - los feeds y `domains.dataset`;
   - todo va a `releases/<ts>/`.
2. **Validación única** con `suricata -T` para cada perfil, con los mismos datasets y dentro de la
   reserva única. Si falla, no se toca `current`.
3. **Cambio atómico de `current`** (`ln -sfn` sobre un temporal y luego `mv -T`).
4. **Reinicio EN SERIE** de cada `suricata`, sin recarga en caliente:
   - por cada punto, 30–90 s sin captura, una vez al día;
   - se espera a que esté sano (reglas cargadas, `stats` al día) antes de pasar al siguiente.
5. **Se conservan 3 releases** para poder volver atrás.

**Alta urgente y suelta en el dataset:** `dataset-add` por el socket de control de cada instancia.
No necesita reiniciar.

### 11.2 Cambios de threshold (exclusiones)

- **F2 (CONTRATO-F2 §6):** el panel manda `punto.threshold {pid, contenido}` a cada punto afectado.
  El orquestador valida las líneas, escribe el fichero de forma atómica y recarga con `reload-rules`
  por el socket de control, **sin reiniciar** (el espejo no se corta); solo si la recarga falla
  reinicia ese `suricata` (30–90 s sin captura) y, si no queda sano, vuelve al threshold anterior
  y avisa (`THRESHOLD-FALLIDO`). Varias órdenes seguidas del mismo punto se agrupan: solo se aplica
  la última ([ORQUESTADOR.md](ORQUESTADOR.md) §5).
