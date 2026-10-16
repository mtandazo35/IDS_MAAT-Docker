# Contrato de construcción — F1a

Anexo de [ARQUITECTURA.md](ARQUITECTURA.md). Es el contrato **exacto** que siguen tres
constructores que trabajan a la vez y no se ven entre sí:

| Constructor | Entrega | Directorios que son suyos (nadie más los toca) |
|---|---|---|
| **A** | imagen `vpn` | `images/vpn/`, `tests/test_vpn_*.py`, `tests/imagen/test_vpn_*.sh`, `tests/fixtures/vpn/`, `tests/_ayuda_vpn.py` |
| **B** | imagen `suricata` y generador de reglas | `images/suricata/`, `tests/test_suricata_*.py`, `tests/test_reglas_*.py`, `tests/imagen/test_suricata_*.sh`, `tests/fixtures/suricata/`, `tests/_ayuda_suricata.py` |
| **C** | orquestador, host, instalador y CI | `orquestador/`, `host/`, `install.sh`, `images/base.env`, `images/build.sh`, `.github/`, `tests/run.sh`, `tests/test_orq_*.py`, `tests/test_host_*.py`, `tests/test_ci_*.py`, `tests/test_host_*.sh`, `tests/fixtures/orq/`, `tests/integracion/`, `tests/_ayuda_orq.py` |

**El panel no entra en F1a** (es F1b). Nadie crea `images/panel/` ni `panel/`.

Reglas del contrato:

- **Este documento manda sobre los anexos** cuando dicen otra cosa. Las diferencias están en §0.2
  y se trasladarán a los anexos al cerrar F1a.
- Lo que el contrato fija y los anexos no decidían va marcado **(decidido en el contrato)**.
- Si un constructor necesita algo que el contrato no fija, **no lo inventa en la interfaz**: lo
  resuelve dentro de su directorio sin cambiar nada de lo que ven los otros dos, y lo anota en su
  entrega.
- Ningún constructor edita un fichero de otro, ni siquiera `tests/run.sh` (§8 lo hace innecesario).
- Ejemplos: solo direcciones de documentación. VPS `203.0.113.10` (`ids.empresa.example`), gestión
  `192.0.2.0/25` y `198.51.100.0/26`, proxy `203.0.113.50`, IP fija del dueño `203.0.113.20`,
  MikroTik `203.0.113.45`, punto `p003`, `N=3`, nombre `norte`, LAN `10.0.0.0/24`.
- Todo el repo va con finales **LF** (`.gitattributes` ya tiene `* text=auto eol=lf`) y sin BOM.
- Commits: no los hace ningún constructor; los hace el dueño.

## Índice

0. [Alcance y diferencias con los anexos](#0-alcance-y-diferencias-con-los-anexos)
1. [Árbol del repo](#1-árbol-del-repo)
2. [Árbol del host, permisos y montajes](#2-árbol-del-host-permisos-y-montajes)
3. [Identificadores](#3-identificadores)
4. [Entorno y ficheros generados](#4-entorno-y-ficheros-generados)
5. [Interfaces internas](#5-interfaces-internas)
6. [Imágenes, etiquetas y CI](#6-imágenes-etiquetas-y-ci)
7. [Instalador](#7-instalador)
8. [Pruebas](#8-pruebas)
9. [Criterio de entrega por constructor](#9-criterio-de-entrega-por-constructor)

---

## 0. Alcance y diferencias con los anexos

### 0.1 Qué entra en F1a

- Imágenes `vpn` y `suricata` publicables en GHCR, firmadas.
- Orquestador `ids-orq` como servicio systemd con su socket y su **CLI**; cola en serie, supervisión,
  comparación de netns, `estado.json`, reglas con reinicio en serie, logrotate.
- Firewall del host (`inet ids_host`), fail2ban (`sshd` e `ids-vpn`), `PasswordAuthentication no`.
- Instalador one-liner y CI de GitHub Actions.
- **Fuera de F1a:** panel, red `ids-core`, avisos por Telegram, modo seguro (`acceso.*`),
  `sistema.actualizar/revertir`, respaldo diario, `punto.threshold`, `bitacora.anclar`. F1a sí deja
  reservados sus nombres y rutas.
- F0 no se ha construido por separado: F1a absorbe la parte de F0 que no es el panel (instalador,
  firewall, CI, release) **(decidido en el contrato)**.

### 0.2 Diferencias con los anexos

| # | Los anexos dicen | El contrato fija | Motivo |
|---|---|---|---|
| 1 | `imagenes/`, `plantillas/`, `instalar.sh` (FASES F0) | `images/`, plantillas dentro de `orquestador/plantillas/` y de cada imagen, `install.sh` | nombres pedidos por el dueño para F1a |
| 2 | `suricata.yaml` y `threshold.config` montados como ficheros sueltos | se monta el **directorio** `/srv/ids/puntos/<pid>/suricata` en `/etc/ids/suricata:ro` | un bind de fichero se queda con el inodo viejo tras un `rename` atómico |
| 3 | feeds en `/srv/ids/feeds/` | feeds **dentro de cada release**: `/srv/ids/reglas/releases/<ts>/feeds/`; no existe `/srv/ids/feeds` | reglas y dataset cambian juntos con el mismo `current`, y se validan juntos |
| 4 | relé hacia `100.64.${N}.2` | relé hacia `${TUN_MK}`, variable explícita | con base `198.18` la fórmula fija era incorrecta |
| 5 | pool Docker `10.210.0.0/16` | además `"bip": "10.210.254.1/24"` en `daemon.json`; subred del punto **determinista** `10.210.0.0 + 16·N`/28; `10.210.255.0/24` reservada para `ids-core` (F1b) | `docker0` y las redes automáticas no pueden quitarle la /28 a un punto |
| 6 | `usuarios` con modo 0640 | 0600 `root:root` | con `cap_drop: ALL` el root del contenedor no tiene `DAC_OVERRIDE`: solo cuentan los bits del dueño |
| 7 | healthcheck del `vpn`: procesos y latido | además, que exista la tabla `inet ids_punto` | un netns sin su firewall no es sano |
| 8 | — | `server.conf` con `suppress-timestamps` y `max-clients 2` | las regex de fail2ban anclan en `^<IP>:`; el reintento del MikroTik no se bloquea con la sesión vieja viva |
| 9 | logrotate en `/etc/logrotate.d` | `/etc/ids-maat/logrotate.conf` con su propio estado | el `logrotate.timer` diario de Debian lo procesaría otra vez con otro estado |
| 10 | La tarea habla de `reglas/<perfil>/current` | se mantiene el diseño de INSTANCIA §11: `reglas/current -> releases/<ts>/<perfil>/` | un solo enlace cambia todos los perfiles a la vez |
| 11 | tag journald `ids-vpn` | igual, **constante** para todos los puntos; el punto sale de `CONTAINER_NAME` | la jaula `ids-vpn` filtra por un solo `CONTAINER_TAG` |
| 12 | `release.yml` con matriz `[panel, vpn, suricata]` | en F1a la matriz es `[vpn, suricata]`; `panel` entra en F1b | no hay panel |
| 13 | órdenes de ORQUESTADOR §5 | se añaden `punto.comandos`, `punto.api.huella`, `punto.medir`, `logs.reabrir`, `sistema.reconciliar`, `sistema.estado` | las pide la CLI de F1a |
| 14 | §6.1 de este contrato: la etiqueta `ids-maat.suricata-version` lleva la versión real del paquete | la etiqueta lleva la **serie** (`7.0`, el `ARG SURICATA_VERSION` del `Dockerfile`, que `images/build.sh` y `release.yml` pasan con `--build-arg`); la versión exacta queda en `/usr/share/ids-maat/suricata-version`, en `release.json` (`"suricata_version": "7.0.x"`, leída de la imagen publicada) y en el `MANIFEST.json` de cada release de reglas | la versión exacta solo se conoce dentro del build, después de instalar el paquete; una etiqueta no se puede escribir desde un `RUN` |
| 15 | §4.4 de este contrato (y INSTANCIA): `proto tcp-server` | `proto tcp4-server` | el contenedor `vpn` no usa IPv6; el socket solo IPv4 evita depender de IPv6 en el netns |
| 16 | §5.13: tres `failregex` (TLS Auth Error, TLS Error, ovpn-auth) y «las cuatro primeras casan» | solo `ovpn-auth: rechazado` (con el prefijo opcional de journald) e `ignoreregex` para `motivo=freno-global`; de las 6 lineas del fixture casan la 3.a y la 4.a | un intento fallido escribia 2 lineas que casaban y baneaba al 3.er intento con maxretry 5; el freno global no es culpa de la IP que lo encuentra |
| 17 | §4.3 de este contrato (e INSTANCIA §3): sysctls `ipfrag_high_thresh` 64 MB **y** `ipfrag_low_thresh` 48 MB | solo `ipfrag_high_thresh` (y `ipfrag_time`); sin `ipfrag_low_thresh` | runc escribe los sysctls en orden aleatorio y el kernel exige `low <= high`: `low` antes que `high` (4 MB por defecto) daba `EINVAL` y el `vpn` no arrancaba (CI, 2026-10-11); `low_thresh` está obsoleto desde Linux 4.17 |
| 18 | §4.3 de este contrato (e INSTANCIA §3): sysctl `net.ipv4.conf.default.arp_ignore: "8"`; §5.1: `ip link set` del veth sin más | sin `arp_ignore` en el compose; el veth lleva `arp off` (`ip link set ids-in up mtu 65535 arp off`, `ip link set ids-mon up mtu 65535 promisc on arp off`) | Docker mete `eth0` en el netns después de aplicar los sysctls, así que `eth0` heredaba `arp_ignore=8`: el host no resolvía la IP del contenedor (`10.210.0.18 dev ids-p001 FAILED`) y la conexión a `:1194` daba «No route to host» (CI e2e, 2026-10-11). `arp off` deja sin ARP solo al veth |
| 19 | §5.14 (e INSTANCIA §10.5): logrotate con `maxage 3`, `rotate 4`, `compress`, `delaycompress`; unos 5 GB por punto | **F2:** `rotate -1`, `dateext` con `dateformat -%Y%m%d-%H%M%S`, `nocompress`, sin `maxage`. El orquestador comprime los rotados (con 2 min sin escribirse) conservando su mtime, poda **por fecha** lo que tiene más de 30 días y, con `/srv/ids` por debajo del 15 % libre, borra antes de tiempo los rotados más viejos de cualquier punto (cada borrado en `orq.jsonl`); `estado.json` publica la retención efectiva por punto (§5.10) | CONTRATO-F2 §9: el objetivo son 30 días; `rotate`/`maxage` cuentan ficheros y no garantizan días, y logrotate/gzip ponían al `.gz` la hora de compresión (Eventos salta ficheros por mtime) |
| 20 | §0.1: `punto.threshold` fuera de F1a (reservada) | **F2:** orden de cola `punto.threshold {pid, contenido}` (§5.11) | CONTRATO-F2 §6: las exclusiones del panel llegan a Suricata |
| 21 | §2.1: `master.key` `root:root 0400`; el panel sin clave maestra | **F2:** `root:10500 0440`, montada en el panel en `/run/secrets/master_key:ro` (`IDS_MASTER_KEY`); `ids-orq panel aplicar` se niega si no existe (Docker crearía un directorio) | CONTRATO-F2 §10.3: el panel corre como 10500 sin capacidades y descifra sus secretos con ella |
| 22 | §5.11: reserva del panel 1024 MiB | **F2:** `RESERVA_PANEL_MB = 1536` (compose `mem_limit` y admisión) | CONTRATO-F2 §6: el dashboard heredado y el generador por nodo (`RLIMIT_AS` 1 GiB, de uno en uno) |
| 23 | §3 (fila 16 de §0.2): fail2ban cuenta todos los `ovpn-auth: rechazado` salvo `freno-global`; §5.13: 6 líneas | solo `motivo=formato` y `motivo=usuario`; §5.13 con 8 líneas (añade una de cada), casan la 5.ª y la 6.ª; orden inmediata `vpn.desbanear {ip}` (`ids-orq vpn desbanear <ip>`); el freno global de `ovpn-auth` no frena a la última IP aceptada durante 24 h | auditoría VPN-04/VPN-08 (2026-10-14): tras «Regenerar la clave VPN» el MikroTik reintentaba con la vieja y acababa baneado en todos los puertos hasta 1 semana |
| 24 | §4.4: `max-clients 2`, sin `hand-window` (60 s) | `max-clients 16` y `hand-window 20`, sin `duplicate-cn` | auditoría VPN-03: las conexiones sin autenticar ocupan plaza y no llegan a fail2ban; 2 `nc` colgados dejaban fuera al MikroTik |
| 25 | §3: certificado de servidor `CN=server-<pid>`; §5.12: el script sin CA ni verificación del servidor | `OU=server-<pid>`, `CN=<NOMBRE_DNS>`, `subjectAltName=DNS:<NOMBRE_DNS>`; el script importa la CA del VPS (`ids-maat-ca-<pid>`) y pone `verify-server-certificate=yes` en v6 y v7; añade `drop` de `input` y `forward` desde `ids-vpn` debajo del `accept` de la API (quitados después, fila 27); `punto.vpn.regenerar` renueva un certificado sin el nombre | auditoría VPN-01/VPN-02: el router no verificaba al servidor y no aislaba `ids-vpn`; RouterOS compara `connect-to` con el CN o el SAN |
| 26 | §4.3: `suricata` con `cap_add: [NET_RAW, NET_ADMIN]` | `cap_add: [NET_RAW]` | auditoría VPN-05: af-packet no necesita `NET_ADMIN` (promisc y offloads los pone el `vpn`, `disable-offloading: false`) |
| 27 | §5.12 (y fila 25): el script lleva la ruta blackhole `100.64.N.0/24` de distancia 250 y reglas de `/ip firewall filter` para `ids-vpn` | el script no lleva reglas de firewall ni rutas: certificado `ids-promax` (quitado después, fila 28), CA del VPS con `ovpn-client` y `verify-server-certificate=yes`, y usuario y grupo `ids-api` (`address=<sensor>/32`); los routers ya dados de alta quitan lo viejo con `/ip firewall filter remove [find comment="IDS ids-maat:<pid>"]` y `/ip route remove [find comment="IDS ids-maat:<pid>"]` | decisión del dueño (2026-10-15): el firewall y las rutas del router los gestiona el operador. Sin blackhole, si el túnel cae, el espejo sigue la ruta por defecto del router |
| 28 | §5.12 (y fila 27): el script lleva el bloque «Certificado API-SSL ids-promax» (`/certificate add`, `sign` y `set trusted=yes`, y `/ip service set api-ssl certificate=ids-promax`) | el script no crea ningún certificado ni toca `/ip service api-ssl` (ni el certificado ni `address=`): la API-SSL del router se usa tal como esté (lo normal, `certificate=none`, con cifrado anónimo). `punto.api.huella` contesta `FALLO` «el router no presentó certificado (API-SSL sin certificado: no hay huella que fijar)» si el router no presenta certificado. Los routers dados de alta con el script anterior revisan `/ip service print detail where name=api-ssl` (OPERACION §1.1) | decisión del dueño (2026-10-15): API-SSL (8729) sin certificado, como el proyecto original; la clave de `ids-api` la protege el túnel. Quien ponga certificado en el router puede fijar su huella en el panel |

---

## 1. Árbol del repo

```
IDS_MAAT-Docker/
├── README.md  .gitattributes  .gitignore            (existentes; no los toca nadie)
├── install.sh                                        C  instalador one-liner (§7)
├── docs/                                             (solo el dueño; CONTRATO-F1a.md es este)
├── images/
│   ├── base.env                                      C  BASE_IMAGE=debian:trixie-slim@sha256:<digest>
│   ├── build.sh                                      C  docker build local con base.env (§6.3)
│   ├── vpn/                                          A  contexto de build = images/vpn
│   │   ├── Dockerfile
│   │   └── rootfs/
│   │       ├── etc/s6-overlay/s6-rc.d/
│   │       │   ├── init-env/   {type=oneshot, up, dependencies.d/base}
│   │       │   ├── init-nft/   {type=oneshot, up, dependencies.d/init-env}
│   │       │   ├── init-veth/  {type=oneshot, up, dependencies.d/init-nft}
│   │       │   ├── init-mon/   {type=oneshot, up, dependencies.d/init-veth}
│   │       │   ├── openvpn/    {type=longrun, run, dependencies.d/init-mon}
│   │       │   ├── tzsp-decap/ {type=longrun, run, dependencies.d/init-mon}
│   │       │   ├── rele-api/   {type=longrun, run, dependencies.d/init-mon}
│   │       │   └── user/contents.d/{init-env,init-nft,init-veth,init-mon,openvpn,tzsp-decap,rele-api}
│   │       ├── usr/local/bin/{tzsp-decap, ovpn-auth, salud-vpn}
│   │       └── usr/local/lib/ids-vpn/render.py        validación del entorno y render de las tablas nft
│   └── suricata/                                     B  contexto de build = images/suricata
│       ├── Dockerfile
│       └── rootfs/
│           ├── usr/local/bin/{entrypoint-suricata, salud-suricata, ids-reglas}
│           └── usr/share/ids-maat/
│               ├── suricata.yaml.tmpl                 plantilla completa con marcadores @@X@@ (§4.6)
│               ├── plantilla.json                     manifiesto de la plantilla (§4.6)
│               ├── local.rules.tmpl                   reglas propias; @@DATASET@@ = ruta del dataset
│               ├── disable-reducido.conf              lo que quita el perfil reducido
│               └── feeds.json                         fuentes de feeds (URL, tipo, licencia)
├── orquestador/                                      C
│   ├── ids_orq.py                                    servicio + CLI, un solo módulo, stdlib
│   └── plantillas/{compose.yml.tmpl, server.conf.tmpl, ids_host.nft.tmpl}
├── host/                                             C
│   ├── systemd/{ids-host-fw.service, ids-orq.service, ids-reglas.service, ids-reglas.timer,
│   │            ids-logrotate.service, ids-logrotate.timer}
│   ├── fail2ban/{jail.d/10-ids.local.tmpl, filter.d/ids-vpn.conf}
│   ├── docker/daemon.json
│   ├── logrotate/ids-maat.conf
│   ├── sysctl/90-ids.conf      modules/ids.conf      ssh/10-ids.conf
├── tests/
│   ├── run.sh                                        C  runner (§8.1)
│   ├── test_vpn_*.py       imagen/test_vpn_*.sh       fixtures/vpn/        A
│   ├── test_suricata_*.py  test_reglas_*.py  imagen/test_suricata_*.sh  fixtures/suricata/  B
│   ├── test_orq_*.py  test_host_*.py  test_ci_*.py  test_host_*.sh  fixtures/orq/  integracion/  C
└── .github/workflows/{ci.yml, release.yml}           C
```

- **No existe `images/reglas/`** (decidido en el contrato): el generador de reglas va en la imagen
  `suricata` (`ids-reglas`), que es la única con salida a las fuentes (INSTANCIA §11.1).
- **Bits de ejecución** (decidido en el contrato): se desarrolla en Windows y git no guarda el bit
  `+x` de forma fiable. Cada Dockerfile hace `chmod 0755` explícito de sus scripts y de los
  `run`/`up` de s6; `install.sh` hace lo mismo con lo que copia. Nadie depende del modo del índice.
- **Python importable en Windows** (decidido en el contrato; desde 2026-10-15 el CI ya no lo
  comprueba, porque no hay job de Windows): todo script Python del repo (también
  los que no llevan `.py`, como `tzsp-decap` u `ovpn-auth`) se puede importar en Windows con
  Python 3.12 sin error: nada de `import fcntl`, `pwd`, `grp` ni `AF_UNIX` a nivel de módulo (se
  importan dentro de la función o con `try/except ImportError`), y el programa arranca en
  `if __name__ == "__main__":`. Sintaxis compatible con **3.11+** (las imágenes y el host traen 3.13).

---

## 2. Árbol del host, permisos y montajes

### 2.1 Árbol y dueños

`10500` = uid y gid `ids-panel` (lo crea `install.sh`, `nologin`, sin home). Todo lo demás es
`root:root`. Lo crea C (instalador u orquestador) salvo lo marcado como «lo crea el contenedor».

| Ruta | Dueño | Modo | Contenido / quién lo escribe |
|---|---|---|---|
| `/etc/ids-maat/` | root:root | 0750 | config del VPS |
| `/etc/ids-maat/ids.conf` | root:root | 0644 | §4.9; `install.sh` |
| `/etc/ids-maat/imagenes.json` | root:root | 0644 | §4.10; `install.sh` |
| `/etc/ids-maat/master.key` | root:10500 | 0440 | 32 bytes aleatorios en hex; F2: montada ro en el panel (§0.2 fila 21) |
| `/etc/ids-maat/orq_token` | root:10500 | 0640 | 32 bytes aleatorios en hex |
| `/etc/ids-maat/avisos.conf` | root:root | 0600 | vacío en F1a (F3) |
| `/etc/ids-maat/logrotate.conf` | root:root | 0644 | copia de `host/logrotate/ids-maat.conf` |
| `/srv/ids/` | root:root | 0755 | raíz |
| `/srv/ids/estado/` | root:root | 0700 | `orq.db` (SQLite WAL), `orq.jsonl`, `plantillas/<digest12>/suricata.yaml.tmpl` |
| `/srv/ids/pki/` | root:root | 0700 | `ca.key` 0600, `ca.crt` 0644, `dh.pem` 0644, `servidores/<pid>.{key 0600, crt 0644}` |
| `/srv/ids/fw/` | root:root | 0700 | `ids_host.nft` (persistente) |
| `/srv/ids/puntos/<pid>/` | root:root | 0700 | `compose.yml` 0600 |
| `/srv/ids/puntos/<pid>/vpn/` | root:root | 0700 | `server.conf` 0644, `ca.crt` 0644, `server.crt` 0644, `server.key` 0600, `dh.pem` 0644, `usuarios` 0600, `ccd/` 0700 con `ccd/<usuario>` 0644 |
| `/srv/ids/puntos/<pid>/suricata/` | root:root | 0755 | `suricata.yaml` 0644, `threshold.config` 0644 |
| `/srv/ids/datos/` | root:10500 | 0750 | padre (lo montará el panel en F1b) |
| `/srv/ids/datos/<pid>/` | root:10500 | **2750** | `eve.json`, `dns.json` y sus rotados — **lo crea el contenedor `suricata`**, ficheros 0640 grupo 10500 |
| `/srv/ids/run/` | root:10500 | 0750 | padre |
| `/srv/ids/run/estado.json` | root:10500 | 0640 | §5.10; el orquestador cada 15 s |
| `/srv/ids/run/<pid>/` | root:10500 | **2770** | `api.sock` (660), `tzsp.json` (0640), `openvpn-status.log` (0640) — **los crea el contenedor `vpn`** |
| `/srv/ids/ctl/` | root:root | 0700 | padre |
| `/srv/ids/ctl/<pid>/vpn/` | root:root | 0700 | `ovpn-mgmt.sock` — lo crea `vpn` |
| `/srv/ids/ctl/<pid>/suricata/` | root:root | 0700 | `suricata-command.socket` — lo crea `suricata` |
| `/srv/ids/reglas/` | root:root | 0755 | §5.9; ficheros 0644 |
| `/srv/ids/reglas/cache/` | root:root | 0755 | caché de `suricata-update` y de feeds (la escribe el contenedor efímero) |
| `/srv/ids/panel/` | — | — | **no se crea en F1a** (F1b) |
| `/run/ids-orq/` | root:10500 | 0750 | `orq.sock` 0660 root:10500 |
| `/usr/local/lib/ids-orq/` | root:root | 0755 | `ids_orq.py`, `plantillas/` |
| `/usr/local/bin/ids-orq` | root:root | 0755 | `#!/bin/sh` → `exec python3 /usr/local/lib/ids-orq/ids_orq.py "$@"` |
| `/root/ids-maat/` | root:root | 0700 | `install.sh` descargado, `host-<version>/` desempaquetado |
| `/root/backups/` | root:root | 0700 | respaldos previos a tocar sshd, firewall o Docker |

- **umask de los contenedores** (decidido en el contrato): los procesos de `vpn` y `suricata` corren
  con `umask 027`. Con el setgid de los directorios, lo que crean queda en el grupo 10500 y 0640.
- **Por qué los contenedores pueden escribir:** corren como uid 0 sin `CAP_DAC_OVERRIDE`; los
  directorios que escriben son de `root` con `rwx` para el dueño.

### 2.2 Montajes por contenedor

| Contenedor | Ruta del host | Ruta en el contenedor | Modo |
|---|---|---|---|
| `vpn` | `/srv/ids/puntos/<pid>/vpn` | `/etc/ids/vpn` | ro |
| `vpn` | `/srv/ids/run/<pid>` | `/run/ids` | rw |
| `vpn` | `/srv/ids/ctl/<pid>/vpn` | `/run/ids-ctl` | rw |
| `vpn` | `/dev/net/tun` (device) | `/dev/net/tun` | — |
| `vpn` | tmpfs | `/run` (`exec,size=16m`), `/tmp` (`size=16m`) | rw |
| `suricata` | `/srv/ids/reglas` (el **padre**) | `/reglas` | ro |
| `suricata` | `/srv/ids/puntos/<pid>/suricata` | `/etc/ids/suricata` | ro |
| `suricata` | `/srv/ids/datos/<pid>` | `/var/log/suricata` | rw |
| `suricata` | `/srv/ids/ctl/<pid>/suricata` | `/run/suricata` | rw |
| `suricata` | tmpfs | `/tmp` (`size=64m`), `/run` (`size=8m`) | rw |
| efímero `ids-reglas descargar` | `/srv/ids/reglas` | `/reglas` | rw |
| efímero `suricata -T` | `/srv/ids/reglas` y un directorio con yaml + threshold | `/reglas`, `/etc/ids/suricata` | ro |

---

## 3. Identificadores

| Identificador | Regla | Ejemplo (N=3, base 100.64) | Dónde vive |
|---|---|---|---|
| `pid` | `^p\d{3}$`; el siguiente de una secuencia en `orq.db` que **nunca** retrocede (p001…p999) | `p003` | todo nombre y ruta |
| `nombre` | `^[a-z0-9][a-z0-9-]{1,30}$`, único entre puntos vivos (decidido en el contrato) | `norte` | `orq.db`, salida de la CLI |
| `N` | menor libre en 1–250, fuera de los 7 días de enfriamiento tras una baja | `3` | `orq.db`, entorno `N` |
| Proyecto compose | `ids-<pid>` | `ids-p003` | `docker compose -p` |
| Contenedores | `ids-<pid>-vpn`, `ids-<pid>-suricata` | `ids-p003-vpn` | `container_name` |
| Red Docker | nombre `ids-<pid>`, bridge Linux `ids-<pid>` | `ids-p003` | compose `networks.punto.name` |
| Subred Docker | `10.210.0.0 + 16·N` /28 (decidido en el contrato) | `10.210.0.48/28` | compose `ipam` |
| Puerto publicado | `1194 + N − 1` (tcp) → 1194 del contenedor | `1196` | compose `ports`, set `puertos_vpn` |
| Base de túneles | `TUN_BASE` de `ids.conf`: `100.64` o `198.18`, elegida al instalar | `100.64` | `ids.conf` |
| Red de túnel | `<base>.N.0/24` | `100.64.3.0/24` | entorno `TUN_NET` |
| IP del sensor | `<base>.N.1` | `100.64.3.1` | entorno `TUN_SENSOR` |
| IP del MikroTik | `<base>.N.2` | `100.64.3.2` | entorno `TUN_MK` |
| `cluster-id` | `100 + N` | `103` | `suricata.yaml` |
| Usuario VPN | `vpn` + 6 hex aleatorios, `^vpn[0-9a-f]{6}$` (decidido en el contrato) | `vpn3a9f2c` | `usuarios`, `ccd/` |
| Clave VPN | 24 caracteres de `[A-Za-z0-9]` con `secrets` (decidido en el contrato) | — | se muestra una vez |
| Certificado de servidor | `OU=server-<pid>`, `CN=<NOMBRE_DNS>`, SAN `DNS:<NOMBRE_DNS>`, RSA 2048, SHA-256, 3650 días, EKU `serverAuth` (§0.2 fila 25) | `OU=server-p003, CN=ids.empresa.example` | `pki/servidores/` |
| Tag journald | `ids-vpn`, **igual en todos los puntos** | `ids-vpn` | `CONTAINER_TAG` |
| Etiquetas Docker | `ids-maat.punto=<pid>`, `ids-maat.parte=vpn\|suricata`, `ids-maat.version=<versión>` (decidido en el contrato) | `ids-maat.punto=p003` | compose `labels` |
| Comentario RouterOS | `IDS ids-maat:<pid>` | `IDS ids-maat:p003` | comandos impresos |
| Interfaz del MikroTik | `ids-vpn` (constante) | `ids-vpn` | comandos impresos |

Ejemplo con base `198.18` y N=12: puerto `1205`, túnel `198.18.12.0/24`, sensor `198.18.12.1`,
MikroTik `198.18.12.2`, subred Docker `10.210.0.192/28`, `cluster-id 112`.

---

## 4. Entorno y ficheros generados

### 4.1 Variables de entorno

Todas las pone **C** en el `compose.yml`. A y B las leen y **validan al arrancar**; si una falla, el
contenedor termina con error y un mensaje claro.

| Contenedor | Variable | Ejemplo | Validación |
|---|---|---|---|
| `vpn` | `PUNTO` | `p003` | `^p\d{3}$` |
| `vpn` | `N` | `3` | entero 1–250 |
| `vpn` | `TUN_NET` | `100.64.3.0/24` | CIDR /24 |
| `vpn` | `TUN_SENSOR` | `100.64.3.1` | `.1` de `TUN_NET` |
| `vpn` | `TUN_MK` | `100.64.3.2` | `.2` de `TUN_NET` |
| `vpn` | `API_PUERTO` | `8729` | `8729` o `8728` |
| `vpn` | `TZSP_PUERTO` | `37008` | 1–65535 |
| `vpn` | `TZSP_BYTES` | `10000` | entero ≥ 0 |
| `vpn` | `TZ` | `UTC` | — |
| `suricata` | `PUNTO` | `p003` | `^p\d{3}$` |
| `suricata` | `IDS_ESPERA_MON_S` | `60` | entero 1–600; las pruebas usan 3 |
| `suricata` | `TZ` | `UTC` | — |

Fijadas por A en el `Dockerfile` (no las pone C): `S6_KEEP_ENV=1`,
`S6_BEHAVIOUR_IF_STAGE2_FAILS=2`, `S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0`, `PATH` con `/command`.

### 4.2 Quién genera cada fichero

| Fichero (host) | Lo genera | A partir de | Formato |
|---|---|---|---|
| `puntos/<pid>/compose.yml` | C | `orquestador/plantillas/compose.yml.tmpl` | §4.3 |
| `puntos/<pid>/vpn/server.conf` | C | `orquestador/plantillas/server.conf.tmpl` | §4.4 |
| `puntos/<pid>/vpn/{ca.crt,server.crt,server.key,dh.pem}` | C | **copia** de `/srv/ids/pki` (no enlaces: no se resuelven dentro del contenedor) | PEM |
| `puntos/<pid>/vpn/usuarios` | C | clave generada | §4.5 |
| `puntos/<pid>/vpn/ccd/<usuario>` | C | — | una línea: `ifconfig-push <TUN_MK> 255.255.255.0` |
| `puntos/<pid>/suricata/suricata.yaml` | C | `suricata.yaml.tmpl` **extraída de la imagen** que se va a ejecutar | §4.6 |
| `puntos/<pid>/suricata/threshold.config` | C | — | F1a: solo la cabecera `# ids-maat <pid> — generado por ids-orq; no editar` |
| `fw/ids_host.nft` | C | `orquestador/plantillas/ids_host.nft.tmpl` + `ids.conf` + puertos en uso | §4.8 |
| tablas `inet ids_punto` y `netdev ids_mon` | **A**, dentro del contenedor, en `/run` | entorno | §4.7 |
| `reglas/releases/<ts>/…` | **B** (`ids-reglas`, contenedor efímero) | fuentes ET y feeds | §5.9 |
| `run/<pid>/tzsp.json` | **A** (`tzsp-decap`) | — | §5.4 |
| `datos/<pid>/{eve,dns}.json` | **B** (Suricata) | — | eve de Suricata |
| `run/estado.json` | C | — | §5.10 |

### 4.3 `compose.yml` (plantilla exacta, N=3)

C renderiza con `str.replace` de marcadores `@@X@@` (como §4.6) y comprueba que no queda ninguno.

```yaml
# ids-maat — generado por ids-orq; no editar
name: ids-p003
services:
  vpn:
    image: ghcr.io/mtandazo35/ids-maat-vpn@sha256:<digest>
    container_name: ids-p003-vpn
    hostname: ids-p003-vpn
    restart: unless-stopped
    labels: { ids-maat.punto: "p003", ids-maat.parte: "vpn", ids-maat.version: "0.1.0" }
    cap_drop: [ALL]
    cap_add: [NET_ADMIN, NET_RAW]
    devices: ["/dev/net/tun:/dev/net/tun"]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: ["/run:exec,size=16m", "/tmp:size=16m"]
    sysctls:
      net.ipv4.ip_forward: "0"
      net.ipv6.conf.all.disable_ipv6: "1"
      net.ipv6.conf.default.disable_ipv6: "1"
      net.ipv4.conf.default.rp_filter: "1"
      net.ipv4.ipfrag_high_thresh: "67108864"
      net.ipv4.ipfrag_time: "15"
    ports: ["1196:1194/tcp"]
    networks: [punto]
    environment:
      PUNTO: "p003"
      N: "3"
      TUN_NET: "100.64.3.0/24"
      TUN_SENSOR: "100.64.3.1"
      TUN_MK: "100.64.3.2"
      API_PUERTO: "8729"
      TZSP_PUERTO: "37008"
      TZSP_BYTES: "10000"
      TZ: "UTC"
    volumes:
      - /srv/ids/puntos/p003/vpn:/etc/ids/vpn:ro
      - /srv/ids/run/p003:/run/ids
      - /srv/ids/ctl/p003/vpn:/run/ids-ctl
    logging: { driver: journald, options: { tag: ids-vpn } }
    cpuset: "0-1"
    mem_limit: 192m
    memswap_limit: 192m
    pids_limit: 64
    healthcheck:
      test: ["CMD", "/usr/local/bin/salud-vpn"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
      start_interval: 5s
  suricata:
    image: ghcr.io/mtandazo35/ids-maat-suricata@sha256:<digest>
    container_name: ids-p003-suricata
    network_mode: "service:vpn"
    depends_on: { vpn: { condition: service_healthy, restart: true } }
    restart: unless-stopped
    labels: { ids-maat.punto: "p003", ids-maat.parte: "suricata", ids-maat.version: "0.1.0" }
    cap_drop: [ALL]
    cap_add: [NET_RAW]                    # §0.2 fila 26
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: ["/tmp:size=64m", "/run:size=8m"]
    environment: { PUNTO: "p003", IDS_ESPERA_MON_S: "60", TZ: "UTC" }
    volumes:
      - /srv/ids/reglas:/reglas:ro
      - /srv/ids/puntos/p003/suricata:/etc/ids/suricata:ro
      - /srv/ids/datos/p003:/var/log/suricata
      - /srv/ids/ctl/p003/suricata:/run/suricata
    cpuset: "2"
    cpus: 1
    mem_limit: 900m
    memswap_limit: 900m
    pids_limit: 256
    stop_grace_period: 30s
    healthcheck:
      test: ["CMD", "/usr/local/bin/salud-suricata"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 600s
      start_interval: 5s
networks:
  punto:
    name: ids-p003
    driver: bridge
    driver_opts: { com.docker.network.bridge.name: ids-p003 }
    ipam: { config: [ { subnet: 10.210.0.48/28 } ] }
```

Reglas de render (decidido en el contrato):

- `cpuset` del `vpn`: `"0-1"` si el host tiene ≥ 4 CPU; si no, se omite la clave.
- `cpuset` de `suricata`: las `hilos` CPU libres más bajas a partir de la 2, asignadas por orden de
  `N`. Si no quedan, `"2-<ncpu-1>"` compartido. Con ≤ 2 CPU se omite. `cpus` = `hilos` siempre.
- `mem_limit` de `suricata` sale de la tabla de perfiles (§4.6.2). Del `vpn`, fijo `192m`.
- `API_PUERTO` es `8728` solo con la excepción explícita del punto.
- Se arranca con `docker compose -p ids-<pid> -f /srv/ids/puntos/<pid>/compose.yml up -d --pull never`.
  Las imágenes se descargan antes, por digest.

### 4.4 `server.conf` (plantilla exacta)

```
# ids-maat p003 — generado por ids-orq; no editar
port 1194
proto tcp-server
dev tun0
topology subnet
server 100.64.3.0 255.255.255.0
max-clients 16
hand-window 20
tls-server
tls-version-min 1.2
ca /etc/ids/vpn/ca.crt
cert /etc/ids/vpn/server.crt
key /etc/ids/vpn/server.key
dh /etc/ids/vpn/dh.pem
data-ciphers AES-256-GCM:AES-256-CBC
data-ciphers-fallback AES-256-GCM
auth SHA1
verify-client-cert none
username-as-common-name
auth-user-pass-verify /usr/local/bin/ovpn-auth via-file
script-security 2
tmp-dir /tmp
client-config-dir /etc/ids/vpn/ccd
ccd-exclusive
keepalive 10 60
persist-key
persist-tun
status /run/ids/openvpn-status.log 10
status-version 2
management /run/ids-ctl/ovpn-mgmt.sock unix
suppress-timestamps
verb 3
```

| Condición | Cambio |
|---|---|
| `ros_version = 6` | `data-ciphers-fallback AES-256-CBC` |
| `compat_v6 = seclevel0` | añade `tls-cipher "DEFAULT:@SECLEVEL=0"` |
| `compat_v6 = legacy` | añade `tls-cipher "DEFAULT:@SECLEVEL=0"` y `tls-cert-profile legacy` |

- Sin `user`/`group` (no hay `CAP_SETUID`), sin `iroute`, `push`, compresión, `tls-crypt` ni
  `tls-auth`.
- A lanza OpenVPN con `exec openvpn --config /etc/ids/vpn/server.conf` (umask 027).

### 4.5 Fichero `usuarios`

```
# ids-maat p003 — generado por ids-orq; no editar
vpn3a9f2c:scrypt$16384$8$1$<sal_hex_32>$<hash_hex_64>
```

- Una línea por usuario (en F1a, una); se ignoran las vacías y las que empiezan por `#`.
- `hash = hashlib.scrypt(clave_utf8, salt=bytes.fromhex(sal), n=16384, r=8, p=1, dklen=32)`;
  sal de 16 bytes con `secrets.token_bytes`. Todo en hex minúscula (decidido en el contrato).
- C escribe el fichero con `rename` atómico dentro del mismo directorio. Como el `vpn` monta el
  **directorio**, el cambio se ve sin reiniciar.

### 4.6 `suricata.yaml`: plantilla de la imagen

**B** entrega en la imagen `/usr/share/ids-maat/suricata.yaml.tmpl` (yaml **completo**, sin
`include:`) y `/usr/share/ids-maat/plantilla.json`:

```json
{"v": 1, "plantilla_version": 1,
 "marcadores": ["SENSOR_NAME","HOME_NET","RULE_PATH","CLUSTER_ID","HILOS","RING_SIZE","BLOCK_SIZE",
                "SNAPLEN","DETECT_PROFILE","SGH_MPM_CONTEXT","MPM_ALGO","SPM_ALGO",
                "FLOW_MEMCAP","STREAM_MEMCAP","REASSEMBLY_MEMCAP","DEFRAG_MEMCAP"]}
```

**C** la extrae (`docker create` + `docker cp` + `docker rm`) la primera vez que ve un digest, la
guarda en `/srv/ids/estado/plantillas/<12 primeros hex del digest>/`, sustituye **cada** `@@X@@`
con `str.replace` y **falla** si sobra o falta algún marcador respecto a `plantilla.json`.

#### 4.6.1 Marcadores

| Marcador | Ejemplo | Lo decide |
|---|---|---|
| `@@SENSOR_NAME@@` | `p003` | `pid` (sale como `host` en cada evento) |
| `@@HOME_NET@@` | `[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,198.51.100.0/24]` | fijo (privadas y CGNAT) más los `redes_abonados` del punto que caen fuera (públicos), sin espacios (`home_net`, 2026-10-15) |
| `@@RULE_PATH@@` | `/reglas/current/reducido` | perfil → `completo` o `reducido` |
| `@@CLUSTER_ID@@` | `103` | `100 + N` |
| `@@HILOS@@` | `1` | punto, 1–2 |
| `@@RING_SIZE@@` | `1024` | fijo |
| `@@BLOCK_SIZE@@` | `131072` | fijo |
| `@@SNAPLEN@@` | `32768` | fijo |
| `@@DETECT_PROFILE@@` | `medium` | perfil |
| `@@SGH_MPM_CONTEXT@@` | `auto` | perfil |
| `@@MPM_ALGO@@` | `hs` | `hs` si `suricata --build-info` de esa imagen dice `Hyperscan support: yes`; si no, `ac-ks` |
| `@@SPM_ALGO@@` | `hs` | `hs` con Hyperscan; si no, `bm` |
| `@@FLOW_MEMCAP@@` | `64mb` | perfil |
| `@@STREAM_MEMCAP@@` | `64mb` | perfil |
| `@@REASSEMBLY_MEMCAP@@` | `256mb` | perfil |
| `@@DEFRAG_MEMCAP@@` | `32mb` | perfil |

Lo que la plantilla trae **fijo** (B): `threshold-file: /etc/ids/suricata/threshold.config`;
`unix-command: {enabled: yes, filename: /run/suricata/suricata-command.socket}`;
`default-log-dir: /var/log/suricata`; `runmode: workers`; `threading.set-cpu-affinity: no`;
`rule-files: [suricata.rules, local.rules]` (relativos a `default-rule-path`); `stats` global con
`interval: 30`; el bloque `af-packet` de INSTANCIA §5 sobre `ids-mon` con
`cluster-type: cluster_flow`, `defrag: yes`, `use-mmap: yes`, `tpacket-v3: yes`,
`checksum-checks: no`; el resto de INSTANCIA §6 (midstream, async-oneside, bypass,
`encryption-handling: bypass`, `flow-timeouts.tcp.established: 300`, `reassembly.depth: 512kb`,
`checksum-validation: no`); eve principal `eve.json` sin `flow`, `dns`, `quic`, `anomaly`, `ike` ni
`bittorrent-dht`, con `stats` (totales, sin hilos); un segundo eve `dns.json` solo con consultas;
`logging.outputs`: solo `console` (nada de `suricata.log` en disco); `fast.log` y `stats.log`
desactivados.

#### 4.6.2 Perfiles (cifras iniciales, se corrigen con las mediciones de F1a)

| Perfil | `RULE_PATH` | `DETECT_PROFILE` | `SGH_MPM_CONTEXT` | memcaps flow/stream/reassembly/defrag | `mem_limit` | Por defecto |
|---|---|---|---|---|---|---|
| `reducido` | `/reglas/current/reducido` | `medium` | `auto` | 64mb/64mb/256mb/32mb | `900m` | **sí** |
| `completo-low` | `/reglas/current/completo` | `low` | `single` | 64mb/64mb/256mb/32mb | `1300m` | — |
| `completo` | `/reglas/current/completo` | `medium` | `auto` | 64mb/64mb/256mb/32mb | `1700m` | — |

La tabla vive **solo** en `ids_orq.py` (constante `PERFILES`). B no la duplica: sus pruebas
renderizan con valores propios.

### 4.7 Tablas nft del netns (las genera A en `init-nft` e `init-mon`)

`render.py` produce exactamente esto (con `TUN_MK`, `TZSP_PUERTO` y `API_PUERTO` del entorno) y lo
carga con `nft -f`. Nunca `flush ruleset`.

```
table inet ids_punto
delete table inet ids_punto
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
```

```
table netdev ids_mon
delete table netdev ids_mon
table netdev ids_mon {
  chain ingreso { type filter hook ingress device "ids-mon" priority -500; policy drop; }
}
```

### 4.8 `ids_host.nft` (plantilla de C)

Exactamente RED-Y-FIREWALL §7, con:

- `@gestion` ← `REDES_GESTION`, `@proxy` ← `IPS_PROXY`, el 5637 ← `PUERTO_PANEL` de `ids.conf`;
- `@puertos_vpn` ← los puertos de los puntos con fichero en `/srv/ids/puntos/` (vacío: el set se
  declara sin `elements`);
- por cada punto con `origen_ip`: en `forward`,
  `meta l4proto tcp ct direction original ct status dnat ct original proto-dst <puerto> ip saddr != <origen_ip> counter drop comment "origen fijo <pid>"`.

El orquestador la regenera y la aplica con `nft -c -f` y luego `nft -f` en cada alta, baja o ajuste
de `origen_ip`. En F1a no hay modo seguro: las listas de acceso solo cambian volviendo a ejecutar
`install.sh`.

### 4.9 `/etc/ids-maat/ids.conf`

`KEY=VALUE`, sin comillas ni espacios, legible por `sh` y por Python (decidido en el contrato):

```
VERSION=0.1.0
NOMBRE_DNS=ids.empresa.example
TUN_BASE=100.64
REDES_GESTION=192.0.2.0/25,198.51.100.0/26
IPS_PROXY=203.0.113.50
IGNOREIP_DUENO=203.0.113.20
PUERTO_PANEL=5637
POOL_DOCKER=10.210.0.0/16
```

### 4.10 `/etc/ids-maat/imagenes.json`

```json
{"v": 1, "version": "0.1.0", "dev": false,
 "imagenes": {"vpn": "ghcr.io/mtandazo35/ids-maat-vpn@sha256:<64 hex>",
              "suricata": "ghcr.io/mtandazo35/ids-maat-suricata@sha256:<64 hex>"}}
```

Con `"dev": false`, el orquestador **rechaza** cualquier referencia que no sea `@sha256:`. Con
`"dev": true` (instalación de laboratorio, §7) acepta referencias locales y lo dice en `ids-orq estado`.

`"commit"` (opcional, 40 hex) es el commit de `main` que instaló el botón «Actualizar» del panel
(`ids-actualizar.sh`, que además pone `"dev": true` y `"version": "main-<sha7>"`) o
`scripts/lab-actualizar.sh`. Una release no lo trae. El orquestador lo publica en `estado.json`
(`commit`, vacío si falta o no es válido) y el panel compara desde ahí con GitHub
([ACTUALIZACIONES.md](ACTUALIZACIONES.md) §4.1).

---

## 5. Interfaces internas

### 5.1 Arranque del `vpn` (A)

`ENTRYPOINT ["/init"]`, sin `CMD`. s6-overlay v3 ejecuta, en este orden y por dependencias:

| # | Servicio s6 | Tipo | Hace | Si falla |
|---|---|---|---|---|
| 1 | `init-env` | oneshot | valida §4.1 con `render.py validar` | el contenedor sale (`S6_BEHAVIOUR_IF_STAGE2_FAILS=2`) |
| 2 | `init-nft` | oneshot | `render.py nft-punto > /run/ids-vpn/ids_punto.nft` y `nft -f` | sale |
| 3 | `init-veth` | oneshot | veth y offloads (abajo); idempotente (`ip link show ids-in` antes de crear) | sale |
| 4 | `init-mon` | oneshot | `render.py nft-mon > /run/ids-vpn/ids_mon.nft` y `nft -f` | sale |
| 5 | `openvpn` | longrun | `umask 027; exec openvpn --config /etc/ids/vpn/server.conf` | s6 lo relanza |
| 5 | `tzsp-decap` | longrun | §5.4 | s6 lo relanza |
| 5 | `rele-api` | longrun | §5.5 | s6 lo relanza |

```sh
ip link add ids-in type veth peer name ids-mon
ip link set ids-in  up mtu 65535 arp off
ip link set ids-mon up mtu 65535 promisc on arp off
ethtool -K ids-mon sg off gro off lro off tso off gso off rx-gro-hw off 2>/dev/null || true
ethtool -K ids-in  sg off gro off tso off gso off 2>/dev/null || true
```

- Los longrun escriben en stdout/stderr del contenedor (sin `s6-log`): de ahí van a journald con
  `CONTAINER_TAG=ids-vpn`.
- s6-overlay **v3.2.0.2**, tarballs `noarch` y `x86_64` con su sha256 comprobado en el `Dockerfile`
  (decidido en el contrato). Solo `linux/amd64`.

### 5.2 Arranque de `suricata` (B)

`ENTRYPOINT ["/usr/local/bin/entrypoint-suricata"]`:

1. `umask 027`.
2. Espera hasta `IDS_ESPERA_MON_S` segundos (sondeo cada 1 s) a que exista `ids-mon`, comprobándolo
   con `python3 -c "import socket; socket.if_nametoindex('ids-mon')"` (mira el netns del proceso,
   no `/sys`). Si no aparece: `entrypoint-suricata: ids-mon no existe tras N s` y `exit 1`.
3. `exec /usr/bin/suricata -c /etc/ids/suricata/suricata.yaml --af-packet --pidfile /run/suricata.pid`.

Suricata corre como root del contenedor (sin `--user`: no hay `CAP_SETUID`).

### 5.3 Veth y captura

| Pieza | Valor |
|---|---|
| Inyecta | `tzsp-decap` por `AF_PACKET` en `ids-in` |
| Captura | Suricata af-packet en `ids-mon`, `cluster-id 100+N` |
| Descarte | `netdev ids_mon`, ingreso de `ids-mon`, prioridad −500 |
| MTU | 65535 en los dos extremos |

### 5.4 `tzsp-decap` y `tzsp.json` (A)

Se reutiliza `tzsp-decap.py` de `suricata-ids-lab` @ `5b89110` (heredoc de `install-suricata.sh`)
con estos cambios:

- Entorno que le pasa el `run` de s6: `TZSP_PORT=${TZSP_PUERTO}`, `TZSP_ALLOW=${TUN_MK}/32`,
  `TZSP_OUT_IF=ids-in`, `TZSP_ESTADO=/run/ids/tzsp.json`, `TZSP_BYTES`. Sin `TZSP_MAP`.
- Escucha en `0.0.0.0:<TZSP_PUERTO>`; `SO_RCVBUFFORCE` de 16 MB y, si falla, `SO_RCVBUF`.
- `settimeout(30)`. **Latido:** escribe `tzsp.json` al arrancar y después **cada 30 s**, llegue o no
  tráfico (`socket.timeout` también escribe). Escritura atómica: `tzsp.json.tmp` + `os.replace`.
- Con `TZSP_ALLOW` vacío o inválido, sale con error (fail-closed, como el original).
- Una línea de resumen por stdout cada 60 s, que empieza por `tzsp-decap: ` (nunca por una IP).

Esquema de `tzsp.json` (v1, decidido en el contrato; contadores acumulados desde el arranque del
proceso, `ventana` = desde la escritura anterior):

```json
{"v": 1, "punto": "p003", "ts": 1760090000, "inicio": 1760080000,
 "rx": 1200, "tx": 1180, "rx_bytes": 1530000, "tx_bytes": 1490000,
 "descartados": 0, "muy_grandes": 0, "rechazados": 20,
 "recortados": 0, "recorte_bytes": 10000,
 "ventana": {"segundos": 30, "aceptados": {"100.64.3.2": 40}, "rechazados": {"192.0.2.9": 2}},
 "ultimo_visto": {"100.64.3.2": 1760089990},
 "esperados": ["100.64.3.2/32"]}
```

F2: `rx_bytes` (bytes de los datagramas TZSP recibidos, también los rechazados) y `tx_bytes` (bytes
de las tramas reenviadas a `ids-in`), acumulados como `rx`/`tx`: el panel calcula los Mbps del espejo
con la diferencia entre dos lecturas.

### 5.5 Relé del API-SSL (A)

```sh
umask 007
exec socat UNIX-LISTEN:/run/ids/api.sock,fork,unlink-early,mode=660,max-children=4 \
           TCP:${TUN_MK}:${API_PUERTO},connect-timeout=5
```

- El socket queda `root:10500` 0660 por el setgid de `/srv/ids/run/<pid>` (2770).
- La tabla `ids_punto` solo deja salir hacia `${TUN_MK}:${API_PUERTO}` por `tun0`.

### 5.6 `ovpn-auth` (A) y usuarios

`/usr/local/bin/ovpn-auth <fichero>` (Python stdlib), llamado por OpenVPN con `via-file`:

1. Lee `untrusted_ip` y `untrusted_port` del entorno, y usuario y clave del fichero (2 líneas).
2. Valida el usuario con `^vpn[0-9a-f]{6}$` y la clave (1–128 caracteres imprimibles). Si no:
   rechaza con `motivo=formato` **sin scrypt**.
3. **Freno, antes de scrypt** (decidido en el contrato), con `flock` sobre
   `/run/ovpn-auth/freno.lock` y estado en `/run/ovpn-auth/freno.json`:
   - por IP: ≥ 5 rechazos en los últimos 600 s → rechazo inmediato `motivo=freno`;
   - global: ≥ 30 cálculos de scrypt en los últimos 60 s → rechazo inmediato `motivo=freno-global`.
   Sin `sleep` en ningún caso.
4. Busca el usuario en `/etc/ids/vpn/usuarios`; si no existe, `motivo=usuario` (sin scrypt).
5. scrypt con los parámetros de la línea y `hmac.compare_digest`. Si no coincide, `motivo=clave`.
6. Sale con 0 si acepta y con 1 si rechaza. Registra el resultado del paso 3 en el estado.

Líneas de log por **stderr** (exactas; las usan fail2ban y las pruebas de C):

```
203.0.113.45:51234 ovpn-auth: rechazado usuario=vpn3a9f2c motivo=clave
203.0.113.45:51234 ovpn-auth: rechazado usuario=- motivo=formato
203.0.113.45:51234 ovpn-auth: aceptado usuario=vpn3a9f2c
```

(`usuario=-` cuando el usuario no pasa el formato: nunca se escribe texto del atacante.)

### 5.7 Healthchecks

| Contenedor | Comando | Sano (exit 0) si… | `interval/timeout/retries/start_period` |
|---|---|---|---|
| `vpn` | `/usr/local/bin/salud-vpn` (sh) | `/command/s6-svstat -o up /run/service/<s>` da `true` para `openvpn`, `tzsp-decap` y `rele-api`; **y** `/run/ids/tzsp.json` tiene menos de 90 s (`stat -c %Y`); **y** `nft list table inet ids_punto` funciona; **y** hay un socket en LISTEN (`/proc/net/tcp`, estado `0A`) en el `port` de `server.conf`; **y** openvpn lleva más de 5 s arriba (`s6-svstat -o updownfor`, si existe) | 30s / 10s / 3 / 30s (start_interval 5s) |
| `suricata` | `/usr/local/bin/salud-suricata` (python3) | `/proc/1/cmdline` contiene `suricata`; **y** en los últimos 512 KiB de `/var/log/suricata/eve.json` hay una línea con `"event_type":"stats"` cuyo `timestamp` tiene menos de 120 s y es posterior al arranque del PID 1 | 30s / 10s / 3 / 600s (start_interval 5s) |

- Ninguno falla por falta de espejo, punto pausado o MikroTik desconectado.
- `salud-suricata` acepta `IDS_EVE` (ruta del eve) y `IDS_AHORA` (epoch) en el entorno para las
  pruebas; sin ellas usa los valores reales (decidido en el contrato).
- Docker **no** reinicia por `unhealthy`: lo hace el orquestador (§5.11, supervisión).

### 5.8 Sockets de control

| Socket (host) | Protocolo | Lo usa | Para |
|---|---|---|---|
| `/srv/ids/ctl/<pid>/suricata/suricata-command.socket` | unix-command de Suricata: envía `{"version": "0.2"}`, espera `{"return":"OK"}`, luego `{"command": "<orden>"}` | C | `reopen-log-files`, `dataset-add` (F1b) |
| `/srv/ids/ctl/<pid>/vpn/ovpn-mgmt.sock` | management de OpenVPN (texto) | C | `kill <usuario>` al regenerar la clave; `status 2` de respaldo |

### 5.9 Reglas y feeds (B genera, C orquesta)

Árbol (el `current` es un enlace **relativo**):

```
/srv/ids/reglas/
├── cache/                                  caché de suricata-update y de feeds (B)
├── releases/20261010T081500Z/              ts = UTC %Y%m%dT%H%M%SZ
│   ├── completo/{suricata.rules, local.rules}
│   ├── reducido/{suricata.rules, local.rules}
│   ├── feeds/{domains.dataset, domains.lst}
│   ├── MANIFEST.json
│   └── LISTO                               se escribe el ÚLTIMO
└── current -> releases/20261010T081500Z
```

**Orden de descarga** (C la lanza; B implementa `ids-reglas`):

```sh
docker run --rm --name ids-reglas-<ts> --network bridge --read-only --tmpfs /tmp:size=512m \
  --cap-drop ALL --security-opt no-new-privileges:true --memory 1g --memory-swap 1g \
  -v /srv/ids/reglas:/reglas --entrypoint /usr/local/bin/ids-reglas \
  <imagen suricata@digest> descargar --ts <ts>
```

Contrato de `ids-reglas descargar --ts <ts>` (B):

- Escribe solo en `/reglas/releases/<ts>/` y `/reglas/cache/`. Nunca toca `current`.
- `suricata-update` con `--data-dir /reglas/cache/suricata-update`, sin `--reload` y sin `-T`; ET
  Open para la versión de Suricata de la imagen. `completo` con lo de ET; `reducido` con
  `--offline` y `disable-reducido.conf` sobre la misma descarga.
- Feeds de `feeds.json` → `feeds/domains.lst` (un dominio por línea, validado) y
  `feeds/domains.dataset` (formato `string` de Suricata: base64 por línea). **El dataset existe
  siempre**, vacío si los feeds fallan (un `load` de un fichero inexistente tumba todas las reglas).
- `local.rules` de cada perfil se genera desde `local.rules.tmpl` y apunta al `domains.dataset`
  **de la misma release** (ruta absoluta `/reglas/releases/<ts>/feeds/domains.dataset`); B elige
  cómo lo admite Suricata 7 (p. ej. `datasets.rules.allow-absolute-filenames: yes` en la plantilla)
  y lo prueba con `suricata -T`. Solo `load` (sin `save`/`state`).
- **La regla de la prueba de extremo a extremo debe estar en los dos perfiles**: sid `2100498`
  (`GPL ATTACK_RESPONSE id check returned root`). `disable-reducido.conf` no puede quitarla.
- `MANIFEST.json`: `{"v":1,"ts":"…","suricata_version":"7.0.x","imagen":"<ref>","fuentes":[{"nombre","url","sha256"}],"reglas":{"completo":<n>,"reducido":<n>},"dominios":<n>}`.
- Escribe `LISTO` al final; la última línea de stdout es ese mismo resumen en JSON con `"ok": true`.
  Código de salida 0 solo si todo está escrito.

**Validación** (C, una por perfil en uso y además los dos perfiles de reglas): renderiza un yaml de
validación con `SENSOR_NAME=validacion`, `HOME_NET=[10.0.0.0/8]`,
`RULE_PATH=/reglas/releases/<ts>/<perfil>`, lo pone con un `threshold.config` vacío en un
directorio temporal bajo `/srv/ids/estado/validacion/` y ejecuta:

```sh
docker run --rm --network none --read-only --tmpfs /tmp:size=64m --tmpfs /run:size=8m \
  --cap-drop ALL --security-opt no-new-privileges:true --memory <reserva>m --memory-swap <reserva>m \
  -v /srv/ids/reglas:/reglas:ro -v <dir>:/etc/ids/suricata:ro \
  --entrypoint /usr/bin/suricata <imagen suricata@digest> -T -c /etc/ids/suricata/suricata.yaml -l /tmp
```

Después, cambio atómico de `current` (`ln -sfn releases/<ts> current.tmp && mv -T current.tmp current`),
reinicio **en serie** de cada `suricata` (espera a sano, máx. 300 s, antes del siguiente) y poda a
3 releases. Si algo falla, `current` no se toca.

### 5.10 `estado.json` (C escribe; el panel de F1b lo leerá)

Cada 15 s, atómico. Esquema v1 (decidido en el contrato):

```json
{
  "v": 1, "ts": 1760090000, "orq_version": "0.1.0", "version": "0.1.0", "dev": false,
  "commit": "", "tun_base": "100.64",
  "cola": {"en_curso": {"op_id": "…", "orden": "punto.crear", "pid": "p003", "paso": "compose up", "desde": 1760089990},
           "pendientes": 0},
  "capacidad": {"mem_total_mb": 7962, "mem_comprometida_mb": 4180, "mem_disponible_mb": 3100,
                "caben": {"reducido": 3, "completo-low": 2, "completo": 1}},
  "reglas": {"current": "20261010T081500Z", "releases": ["20261008T081500Z", "20261009T081500Z", "20261010T081500Z"]},
  "disco": {"srv_ids_libre_pct": 71},
  "puntos": {
    "p003": {
      "nombre": "norte", "n": 3, "puerto": 1196, "tun_net": "100.64.3.0/24",
      "perfil": "reducido", "hilos": 1, "ros_version": 7, "compat_v6": "no",
      "deseado": "activo", "estado": "activo",
      "contenedores": {
        "vpn":      {"estado": "running", "salud": "healthy", "inicio": 1760080000, "reinicios_1h": 0, "imagen": "sha256:…"},
        "suricata": {"estado": "running", "salud": "healthy", "inicio": 1760080010, "reinicios_1h": 0, "imagen": "sha256:…"}
      },
      "netns": {"coherente": true, "vpn": 4026532871, "suricata": 4026532871},
      "vpn_cliente": {"conectado": true, "desde": 1760085000, "ip_real": "203.0.113.45", "usuario": "vpn3a9f2c"},
      "tzsp": {"edad_s": 12, "rx": 1200, "tx": 1180, "rechazados": 20},
      "suricata": {"stats_edad_s": 14, "reglas_cargadas": 18234, "reglas_fallidas": 0,
                   "kernel_packets": 98765, "kernel_drops": 0, "alertas": 5120},
      "avisos": [],
      "retencion": {"objetivo_dias": 30, "desde": 1757500000, "dias": 30.1,
                    "anticipado": false, "ultimo_anticipado": null},
      "alertas_24h": {"n": 5120, "desde": 1760080010, "completo": false}
    }
  }
}
```

- `estado` ∈ `creando`, `activo`, `parado`, `error`, `borrando`; `deseado` ∈ `activo`, `parado`.
- `vpn_cliente` sale de `/srv/ids/run/<pid>/openvpn-status.log` (`CLIENT_LIST`); `suricata.*` del
  último `stats` del eve (`detect.engines[].rules_loaded/rules_failed`, `capture.kernel_*`).
- `avisos`: códigos `SIN-ESPEJO` (activo y sin `tx` en 10 min), `ESPEJO-NO-LLEGA` (`tzsp.tx` sube y
  `kernel_packets` no), `NETNS-DISTINTO`, `REINICIOS` (≥ 3 en 1 h), `DISCO` (< 15 % libre),
  F2: `RETENCION-REDUCIDA` (hubo borrado anticipado por disco en los últimos 30 días) y
  `THRESHOLD-FALLIDO` (el último `punto.threshold` se revirtió; se quita con el siguiente que vaya bien).
- F2 (CONTRATO-F2 §9): `retencion.desde` = marca de tiempo (epoch) del primer evento del fichero más
  viejo que queda en `datos/<pid>/` (eve y dns, vivos y rotados; si no se puede leer, la fecha del
  fichero, que nunca es anterior a sus eventos); `dias` = días desde entonces; `anticipado` =
  hubo poda por disco en los últimos 30 días (entonces no se promete el objetivo) y
  `ultimo_anticipado` su epoch (o `null`). Los rotados `.gz` conservan como mtime el de su
  última escritura (su último evento).
- `suricata.alertas` = `detect.alert` del mismo `stats`: alertas desde que arrancó ese Suricata
  (vuelve a 0 al reiniciarlo); `null` si no viene.
- `alertas_24h`: alertas de las últimas 24 h que cuenta el orquestador con ese contador (la cola
  del eve vivo, con espejo real, son pocos minutos). Lo que sube entre dos muestras va a un cubo
  de 5 min de `/srv/ids/estado/alertas.json` y `n` suma los cubos de las 24 h (ventana aproximada
  a 5 min).
  `desde` = desde cuándo se cuenta: el arranque del Suricata si en la primera muestra llevaba
  menos de 24 h (todo su contador cae dentro), si no la primera muestra (y otra vez tras más de
  un día sin muestras); `completo` = ya cubre las 24 h enteras (si no, `n` es «al menos»). Solo
  cuenta un `stats` del Suricata vivo (no anterior a `contenedores.suricata.inicio`); mientras no
  haya ninguno, `n` y `desde` son `null`.

### 5.11 Orquestador: socket, órdenes y supervisión (C)

- `ids-orq servicio` (lo arranca `ids-orq.service`): socket `/run/ids-orq/orq.sock`, protocolo de
  ORQUESTADOR §3 (JSON por líneas, una petición por conexión, `SO_PEERCRED` uid 0 o 10500, token),
  cola única en serie persistida en `orq.db`, supervisión y `estado.json`.
- **La CLI habla con el servicio por el socket** (decidido en el contrato): lee el token de
  `/etc/ids-maat/orq_token`, manda la orden con `quien = "cli:<SUDO_USER o root>"` y, si la orden
  se encola, sigue `op.estado` cada segundo imprimiendo los pasos hasta el final.
- `IDS_RAIZ` (entorno, por defecto `/`) antepone un prefijo a **todas** las rutas del host, para las
  pruebas y la integración en CI (decidido en el contrato).

Órdenes de F1a y F2 (las demás de ORQUESTADOR §5 responden `INVALIDO "no disponible en F1a"`). Una
baja cancela las órdenes de ese punto que esperaban en la cola: `op.estado` las da `terminada` con
código `CANCELADA` y quedan en `orq.jsonl`; nunca se ejecutan (los `pid` no se reutilizan).

| Orden | Parámetros | Encola | Devuelve en `datos` |
|---|---|---|---|
| `punto.crear` | `nombre`, `redes_abonados[]` (≤ 64, IPv4 CIDR; opcional desde 2026-10-15: sin ella, `redes_por_defecto`, lo privado y el CGNAT menos las redes reservadas), `perfil` (def. `reducido`), `hilos` 1–2 (def. 1), `ros_version` 6/7 (def. 7), `compat_v6` `no`/`seclevel0`/`legacy`, `api_puerto` 8729/8728, `origen_ip?`, `pid?`, `n?` | sí | `pid`, `n`, `puerto`, `tun_net`, `usuario`, `clave` (solo la primera vez), `comandos` |
| `punto.borrar` | `pid`, `confirmar` (= nombre) | sí | — |
| `punto.arrancar` / `punto.parar` / `punto.reiniciar` | `pid`, `parte` ∈ vpn/suricata/todo | sí | `observado` |
| `punto.ajustar` | `pid`, `perfil?`, `hilos?`, `redes_abonados?`, `compat_v6?`, `ros_version?`, `origen_ip?` | sí | lo recreado |
| `punto.vpn.regenerar` | `pid` | sí | `usuario`, `clave`, `comandos` |
| `punto.threshold` (F2) | `pid`, `contenido` (≤ 256 KiB; solo `suppress`/`threshold`/`event_filter` y comentarios, validados línea a línea) | sí (rechaza al encolar un punto inexistente o en baja) | `aplicado`, `recarga` (`reload-rules`, `reinicio` o `al arrancar`), `sha256`; si otra posterior del mismo punto espera en la cola, `aplicado: false` y `sustituida_por`. Escritura atómica; `reload-rules` por el socket de control; si falla, reinicio de `suricata`; si tampoco queda sano, vuelve al anterior y acaba `REVERTIDA` con `THRESHOLD-FALLIDO`. Un punto parado no se levanta |
| `punto.estado` | `pid` o `*` | no | la entrada de `estado.json` |
| `punto.logs` | `pid`, `parte`, `lineas` ≤ 500 | no | líneas (sin `password`/`key`) |
| `punto.comandos` | `pid` | no | `comandos` sin la clave |
| `punto.api.huella` | `pid` | no | `sha256` del certificado del router, vía el relé; `FALLO` si el router no presenta certificado (fila 28 de §0.2) |
| `punto.medir` | `pid` | no | `memoria_actual_mb`, `memoria_pico_mb` (cgroup), `kernel_packets`, `kernel_drops`, `reglas_cargadas`, `tzsp` |
| `reglas.actualizar` | `sin_descarga?` (revalida y reinicia con la release actual) | sí | `ts`, conteos |
| `logs.reabrir` | `pid?` | no | por punto, OK/fallo |
| `sistema.reconciliar` | — | sí | lo levantado, lo huérfano (solo se informa) |
| `sistema.estado` / `sistema.capacidad` | — | no | §5.10 sin `puntos` / capacidad por perfil |
| `op.estado` | `op_id` | no | `{estado, paso, avance, log_tail}` |

Pasos de `punto.crear` (en este orden; un fallo **deshace** todo lo hecho): validar → asignar `pid`
y `N` y guardar en `orq.db` → admisión de RAM (INSTANCIA §10.3, reserva `host 1024 + panel 1536` (F2)
aunque no haya panel) → directorios → certificado de servidor → usuario y hash → `ccd` →
`server.conf` → `suricata.yaml` → `suricata -T` efímero (§5.9) → `threshold.config` →
`compose.yml` → puerto en `@puertos_vpn` y `ids_host.nft` → `docker compose up -d` → espera a
`healthy` de los dos (≤ max(300 s, 2 × duración del -T + 90 s); si al vencer siguen `starting` sin
errores, queda `activo` con aviso y lo vigila la supervisión) → `activo`.

Validaciones de `punto.crear` (respuesta `INVALIDO` con el motivo): `redes_abonados` sin solapes
con `<TUN_BASE>.0.0/16`, con `POOL_DOCKER` ni con `REDES_GESTION`; nunca `0.0.0.0/0`. Puerto
ocupado en el host → `CONFLICTO_PUERTO`. No cabe → `CONFLICTO` con `caben` por perfil.

Supervisión (ORQUESTADOR §8): `docker events --format '{{json .}}' --filter label=ids-maat.punto`
(se reconecta si dockerd se reinicia); netns comparando `os.stat("/proc/<pid>/ns/net").st_ino` del
`vpn` y del `suricata` ante cada `start` de un `vpn` y cada 30 s → si difieren, `docker restart`
de `suricata`; `unhealthy` → reinicio con espera 30 s, 2 min, 10 min; con 3 en una hora, `error` y
no se toca más.

`orq.jsonl`: una línea por orden terminada:
`{"ts","op_id","quien","orden","pid","params_sha256","pasos":[…],"codigo","mensaje"}`, sin
secretos ni parámetros en claro.

### 5.12 CLI `ids-orq` (C)

Códigos de salida (decidido en el contrato): `0` OK/ACEPTADA terminada bien, `1` FALLO o
REVERTIDA, `2` INVALIDO (también argumentos), `3` CONFLICTO/CONFLICTO_PUERTO, `4` NO_EXISTE,
`5` sin servicio (no hay socket). Toda orden admite `--json` (imprime la respuesta tal cual) y las
que encolan, `--no-esperar` (imprime el `op_id` y sale).

| Orden CLI | Orden del socket |
|---|---|
| `ids-orq servicio` | (arranca el servicio) |
| `ids-orq punto crear --nombre X [--redes CIDR[,CIDR…]] [--perfil reducido\|completo-low\|completo] [--hilos 1\|2] [--ros 6\|7] [--compat-v6[=seclevel0\|legacy]] [--api-puerto 8729\|8728] [--origen-ip IP]` | `punto.crear` (`--compat-v6` sin valor = `seclevel0`) |
| `ids-orq punto borrar <pid> --confirmar <nombre>` | `punto.borrar` |
| `ids-orq punto estado [<pid>\|'*']` | `punto.estado` |
| `ids-orq punto arrancar\|parar\|reiniciar <pid> [--parte vpn\|suricata\|todo]` | `punto.*` |
| `ids-orq punto ajustar <pid> [--perfil …] [--hilos …] [--redes …] [--compat-v6[=…]\|--sin-compat-v6] [--ros 6\|7] [--origen-ip IP\|--sin-origen-ip]` | `punto.ajustar` |
| `ids-orq punto ovpn-client <pid>` | `punto.comandos` |
| `ids-orq punto vpn-regenerar <pid>` | `punto.vpn.regenerar` |
| `ids-orq punto logs <pid> [--parte vpn\|suricata] [--lineas 100]` | `punto.logs` |
| `ids-orq punto api-huella <pid>` | `punto.api.huella` |
| `ids-orq punto medir <pid>` | `punto.medir` |
| `ids-orq reglas actualizar [--sin-descarga]` | `reglas.actualizar` |
| `ids-orq reabrir-logs [<pid>]` | `logs.reabrir` (lo llama logrotate) |
| `ids-orq reconciliar` | `sistema.reconciliar` |
| `ids-orq actualizar <commit>` | `sistema.actualizar` (botón «Actualizar» del panel; ACTUALIZACIONES §4.1) |
| `ids-orq estado` | `sistema.estado` + `punto.estado *` |
| `ids-orq op <op_id>` | `op.estado` |

Salida de `ids-orq punto crear --nombre norte --redes 10.0.0.0/24`:

```
en cola: op 6f1c2a90-… (0 delante)
  [1/14] validar ............................ ok
  …
  [14/14] esperar salud ..................... ok (41 s)
OK punto p003 creado
  nombre       norte
  N            3
  puerto       1196/tcp
  túnel        100.64.3.0/24 (sensor 100.64.3.1, MikroTik 100.64.3.2)
  perfil       reducido · hilos 1 · cpuset 2 · mem_limit 900m
  usuario VPN  vpn3a9f2c
  clave VPN    <24 caracteres>      ← se muestra UNA sola vez
<bloque de comandos de punto ovpn-client, con la clave ya puesta>
```

Salida de `ids-orq punto ovpn-client p003` (la clave nunca aparece; en `crear` y `vpn-regenerar`
sí, ya sustituida):

```
# ids-maat p003 (norte) · N=3 · puerto 1196 · túnel 100.64.3.0/24 · declarado RouterOS v7
# El bloque v6 solo conecta tras: ids-orq punto ajustar p003 --ros 6
# Antes de pegar: el reloj del router en hora (/system ntp client). El certificado del
# servidor vale desde 2 días antes de emitirse; con el reloj más atrasado, el MikroTik lo rechaza.
#
# --- RouterOS v7 ---
# CA del VPS (pública): con ella el MikroTik verifica al servidor (verify-server-certificate)
/file print file=ids-maat-ca-p003
:delay 2s
/file set [find name="ids-maat-ca-p003.txt"] contents="-----BEGIN CERTIFICATE-----\nMIID…\n-----END CERTIFICATE-----\n"
/certificate import file-name=ids-maat-ca-p003.txt passphrase=""
/certificate set [find name~"^ids-maat-ca-p003"] trusted=yes
/file remove [find name="ids-maat-ca-p003.txt"]
/interface ovpn-client add name=ids-vpn connect-to=ids.empresa.example port=1196 protocol=tcp mode=ip \
    user=vpn3a9f2c password=<CLAVE-VPN> cipher=aes256-gcm auth=sha1 verify-server-certificate=yes \
    add-default-route=no use-peer-dns=no disabled=no
/user group add name=ids-api policy=read,write,api
/user add name=ids-api group=ids-api address=100.64.3.1/32 password=<CLAVE-API>
#
# --- RouterOS v6 (6.49 o superior) ---
# CA del VPS (pública): con ella el MikroTik verifica al servidor (verify-server-certificate)
/file print file=ids-maat-ca-p003
:delay 2s
/file set [find name="ids-maat-ca-p003.txt"] contents="-----BEGIN CERTIFICATE-----\nMIID…\n-----END CERTIFICATE-----\n"
/certificate import file-name=ids-maat-ca-p003.txt passphrase=""
/certificate set [find name~"^ids-maat-ca-p003"] trusted=yes
/file remove [find name="ids-maat-ca-p003.txt"]
/interface ovpn-client add name=ids-vpn connect-to=ids.empresa.example port=1196 mode=ip \
    user=vpn3a9f2c password=<CLAVE-VPN> cipher=aes256 auth=sha1 verify-server-certificate=yes \
    add-default-route=no disabled=no
/user group add name=ids-api policy=read,write,api
/user add name=ids-api group=ids-api address=100.64.3.1/32 password=<CLAVE-API>
```

- Con `ros_version = 6`, la cabecera dice `RouterOS 6.49+ o 7 (AES-256-CBC)` y la nota, que conectan
  los dos bloques; el bloque v7 lleva `cipher=aes256-cbc`.
- `connect-to` = `NOMBRE_DNS`. La API usa siempre `<CLAVE-API>`: en F1a el orquestador no guarda
  credenciales de la API.
- Sin reglas de firewall ni rutas (fila 27 de §0.2): el firewall y las rutas del router los
  gestiona el operador.
- Sin certificado de la API-SSL ni nada de `/ip service api-ssl` (fila 28 de §0.2): la API-SSL del
  router se usa tal como esté.

Salida de `ids-orq estado`:

```
ids-orq 0.1.0 · versión 0.1.0 · base de túneles 100.64 · reglas 20261010T081500Z (3 releases)
cola: libre · 0 pendientes
memoria: total 7962 MB · comprometida 4180 MB · caben: reducido 3, completo-low 2, completo 1
PID   NOMBRE  N  PUERTO  PERFIL    DESEADO  ESTADO  VPN                    ESPEJO  NETNS  AVISOS
p003  norte   3  1196    reducido  activo   activo  203.0.113.45 (2 h)     12 s    ok     -
```

`ids-orq punto estado p003` imprime la entrada de §5.10 como `clave: valor`, una por línea.

### 5.13 Logs, journald y fail2ban

Líneas que **A** garantiza en journald con `CONTAINER_TAG=ids-vpn` y que **C** usa como fixture de
`fail2ban-regex` y de sus pruebas (`tests/fixtures/orq/ids-vpn.log`, copiadas de aquí):

```
203.0.113.45:51234 TLS Auth Error: Auth Username/Password verification failed for peer
203.0.113.45:51234 TLS Error: TLS handshake failed
203.0.113.45:51234 ovpn-auth: rechazado usuario=vpn3a9f2c motivo=clave
203.0.113.45:51234 ovpn-auth: rechazado usuario=- motivo=freno
203.0.113.45:51234 ovpn-auth: rechazado usuario=- motivo=formato
203.0.113.45:51234 ovpn-auth: rechazado usuario=vpn000000 motivo=usuario
203.0.113.45:51234 ovpn-auth: aceptado usuario=vpn3a9f2c
tzsp-decap: rx=10 tx=10 descartados=0 muy_grandes=0 rechazados_origen=0 ultimo_origen=100.64.3.2
```

**Sustituido (§0.2 filas 16 y 23):** casan solo la 5.a y la 6.a (`motivo=formato` y `motivo=usuario`:
quien no conoce el usuario). `install.sh` comprueba con `fail2ban-regex` que casan 2 de las 8.
Filtro original de C (historico):

```ini
[Definition]
failregex = ^<HOST>:\d+ TLS Auth Error:
            ^<HOST>:\d+ TLS Error: TLS handshake failed
            ^<HOST>:\d+ ovpn-auth: rechazado
ignoreregex =
```

Jaulas: RED-Y-FIREWALL §9, con `ignoreip = 127.0.0.1/8 ::1 <IGNOREIP_DUENO>`. Se validan en el
canario con líneas reales (medición 13).

### 5.14 logrotate

`/etc/ids-maat/logrotate.conf` (C), lanzado por `ids-logrotate.timer` cada 5 min con
`logrotate --state /var/lib/logrotate/ids-maat.status /etc/ids-maat/logrotate.conf`
(comentarios del fichero aparte):

```
/srv/ids/datos/*/eve.json /srv/ids/datos/*/dns.json {
    size 100M
    rotate -1
    dateext
    dateformat -%Y%m%d-%H%M%S
    nocompress
    missingok
    notifempty
    nocreate
    sharedscripts
    postrotate
        /usr/local/bin/ids-orq reabrir-logs >/dev/null 2>&1 || true
    endscript
}
/srv/ids/datos/*/stats.json {
    size 5M
    rotate 1
    copytruncate
    nocompress
    missingok
    notifempty
}
/srv/ids/estado/orq.jsonl {
    monthly
    rotate 24
    compress
    missingok
    notifempty
    nocreate
}
```

eve/dns sin `copytruncate` (se reabren con `reopen-log-files`); solo `stats.json` lo lleva, porque
Suricata lo abre en modo añadir. El orquestador abre `orq.jsonl` en modo append en cada escritura, así
que no necesita reapertura. **F2 (§0.2 fila 19):** los eve/dns rotan con nombre fechado y sin tope de
número; la compresión (conservando el mtime) y la poda por fecha (30 días) y por disco (< 15 % libre)
son del orquestador.

**Por tamaño: `size 100M`, nunca `maxsize`.** Sin `size`, logrotate aplica su umbral por defecto
(1 MB) y rota en cada pasada del timer. Pasaba con `maxsize 1G`: en producción, cada 30 min (2026-10-15).
Un rotado tiene que caber en lo que Eventos descomprime por fichero (`TOPE_GZ`, 150 MB). Con 1 GB
de verdad, la búsqueda se saltaría las horas anteriores. Con el timer cada 5 min, un rotado queda en
100 MB más lo que entra en 5 min (unos 125 MB en el punto con más espejo medido).

### 5.15 Unidades systemd (C)

| Unidad | Lo esencial |
|---|---|
| `ids-host-fw.service` | `Type=oneshot`, `RemainAfterExit=yes`, `Before=docker.service`, `ExecStart=/usr/sbin/nft -f /srv/ids/fw/ids_host.nft`, `WantedBy=multi-user.target` |
| `ids-orq.service` | `After=docker.service ids-host-fw.service`, `Requires=docker.service`, `ExecStart=/usr/local/bin/ids-orq servicio`, `Restart=always`, `RuntimeDirectory=ids-orq`, encierro de ORQUESTADOR §1.1 |
| `ids-reglas.service` / `.timer` | `ExecStart=/usr/local/bin/ids-orq reglas actualizar`; `OnCalendar=*-*-* 08:15:00 UTC` (03:15 en UTC−5), `RandomizedDelaySec=10m`, `Persistent=true` |
| `ids-logrotate.service` / `.timer` | §5.14; `OnCalendar=*:0/5` |

---

## 6. Imágenes, etiquetas y CI

### 6.1 Imágenes

| Imagen | Base | Paquetes (Debian 13) | Usuario | `ENTRYPOINT` |
|---|---|---|---|---|
| `ghcr.io/mtandazo35/ids-maat-vpn` | `${BASE_IMAGE}` | `openvpn` (2.6), `socat`, `nftables`, `iproute2`, `ethtool`, `python3`; s6-overlay v3.2.0.2 (tarball verificado) | root (con capacidades limitadas) | `/init` |
| `ghcr.io/mtandazo35/ids-maat-suricata` | `${BASE_IMAGE}` | `suricata` (7.0.x de trixie), `suricata-update`, `python3`, `ca-certificates` | root | `/usr/local/bin/entrypoint-suricata` |
| `ghcr.io/mtandazo35/ids-maat-panel` | — | **F1b** | 10500 | — |

- **Base:** `images/base.env` (de C) contiene una sola línea
  `BASE_IMAGE=debian:trixie-slim@sha256:<digest>`. Los dos `Dockerfile` empiezan por
  `ARG BASE_IMAGE` **sin valor por defecto** y `FROM ${BASE_IMAGE}`; si no se pasa, el build falla
  (decidido en el contrato). Renovate/Dependabot actualiza solo `base.env`.
- Los dos `Dockerfile` declaran `ARG VERSION=dev` y las etiquetas
  `org.opencontainers.image.source=https://github.com/mtandazo35/IDS_MAAT-Docker`,
  `org.opencontainers.image.version=${VERSION}`, `ids-maat.componente=vpn|suricata`. La de
  `suricata` añade `ids-maat.suricata-version` (la versión real del paquete) y
  `ids-maat.plantilla-version=1`.
- `apt-get install --no-install-recommends` y limpieza de `/var/lib/apt/lists`. Sin `latest` en
  ningún `FROM`.

### 6.2 Etiquetas y referencias

| Contexto | Referencia |
|---|---|
| Release `vX.Y.Z` | `:X.Y.Z` y `:sha-<7 hex>` en GHCR, firmadas con cosign keyless |
| CI (sin publicar) | `ids-maat-<img>:ci` local |
| Producción (compose, `imagenes.json`) | siempre `ghcr.io/mtandazo35/ids-maat-<img>@sha256:<digest>` |
| Primera release de F1a | `v0.1.0` |

### 6.3 `images/build.sh` (C)

`images/build.sh <vpn|suricata> [etiqueta]` → `docker build --build-arg BASE_IMAGE=… --build-arg VERSION=dev -t ids-maat-<img>:<etiqueta|dev> images/<img>`.
Es lo que usan A y B en local y el CI.

### 6.4 GitHub Actions (C)

`ci.yml` (push y PR), acciones fijadas por SHA de commit:

| Job | Runner | Hace |
|---|---|---|
| `lint` | ubuntu-24.04 | `pyflakes` sobre todo `*.py` **y** los ficheros con shebang `python3` bajo `images/*/rootfs/`; `shellcheck` y `bash -n` sobre `*.sh` y shebang `sh`/`bash`; `nft -c` de los ficheros `.nft` renderizados dentro de `debian:trixie-slim` con `--cap-add NET_ADMIN` |

**Solo lint desde 2026-10-15** (decisión del dueño): GitHub ya no corre `tests/run.sh` (jobs
`pruebas` e `imagenes` retirados). Las pruebas se corren en la VPS, en un checkout aparte del commit
(`/root/ids-pruebas/<commit>`): `IDS_OBLIGATORIAS=linux bash tests/run.sh`, y como root con
`--imagenes --integracion` solo fuera de producción (levantan Docker). La e2e, además, solo en una
máquina **sin el IDS instalado**: usa los mismos nombres de proyecto, contenedor y red, y al salir
borraría los de verdad. Desde 2026-10-15 se omite sola si encuentra contenedores `ids-p*` o
`ids-core-panel`, sus redes, `/srv/ids` o `ids-orq` activo (`tests/test_e2e_guarda.py`).

`release.yml` (solo etiquetas `v*`): `ci-verde` (exige un `ci.yml` en verde para el commit
etiquetado y no lo repite; desde 2026-10-15) → `imagen`
(matriz `[vpn, suricata]`: login GHCR, metadata semver + `sha-`, build-push con provenance y SBOM,
`cosign sign --yes …@<digest>`) → `release`: empaqueta `ids-maat-host-<v>.tar.gz` (`orquestador/`,
`host/`, `install.sh`), escribe

```json
{"v": 1, "version": "0.1.0",
 "imagenes": {"vpn": "ghcr.io/mtandazo35/ids-maat-vpn@sha256:…", "suricata": "ghcr.io/mtandazo35/ids-maat-suricata@sha256:…"},
 "host_tar": {"nombre": "ids-maat-host-0.1.0.tar.gz", "sha256": "…"},
 "min_orq": "0.1.0", "migraciones": []}
```

y la firma con `cosign sign-blob --bundle release.json.bundle`; sube los tres a la GitHub Release.
Identidad que verifica el instalador: ACTUALIZACIONES §3 con `<owner>` = `mtandazo35`.

---

## 7. Instalador

One-liner (en `/root`, nunca en `/tmp`, y sin `curl | bash`):

```sh
curl -fsSL https://raw.githubusercontent.com/mtandazo35/IDS_MAAT-Docker/v0.1.4/install.sh -o /root/ids-maat-install.sh \
  && bash /root/ids-maat-install.sh [--version v0.1.4] [--nombre ids.empresa.example] \
       [--gestion 192.0.2.0/25,198.51.100.0/26] [--proxy 203.0.113.50] \
       [--tun-base 100.64|198.18] [--dueno-ip 203.0.113.20] [--zona America/Guayaquil]
```

**Todas las opciones son opcionales** (decisión del dueño 2026-10-15: «debe ser libre, luego yo pongo
seguridad»). En una instalación nueva, la que falta vale:

- `--version`: la release de ese `install.sh` (`VERSION_DEFECTO`, igual a `ORQ_VERSION` de su etiqueta).
- `--nombre`: la IP pública del VPS, la de origen de la ruta por defecto. Va en el certificado del
  servidor OpenVPN y en las órdenes de los MikroTik, así que si es privada (VPS detrás de NAT) el
  instalador se para y pide `--nombre`.
- `--gestion` y `--proxy`: `0.0.0.0/0`, **abierto**. El SSH y el 5637 se abren a cualquier IP
  (fail2ban sigue activo); no hay modo seguro, porque con el SSH abierto no hay nada que revertir.
  Al panel le llega `IDS_PROXY` vacío: no se fía del `X-Forwarded-For` de nadie. `--gestion 0.0.0.0/0`
  dado a mano significa lo mismo.
- `--panel` (desde 2026-10-15): redes que abren el panel directamente, hasta /16, en `REDES_PANEL`.
  El firewall deja llegar al 5637 a `REDES_PANEL` y a `IPS_PROXY`; el panel solo se fía de las
  cabeceras `X-Forwarded-*` de `IPS_PROXY` (el proxy inverso, hasta /28). Dar `--panel` o `--proxy`
  cierra el panel si venía abierto de `ids.conf`.
- `--zona`: `America/Guayaquil`.

En una reinstalación, la que falta conserva el valor de `ids.conf` (`NOMBRE_DNS`, `REDES_GESTION`,
`IPS_PROXY`, `REDES_PANEL`, `ZONA_HORARIA`): volver a ejecutarlo sin opciones no reabre un acceso
cerrado. Para cerrarlo se ejecuta con `--gestion` y `--panel` (o `--proxy`), y entonces sí hay modo
seguro. Un `IPS_PROXY` de `ids.conf` con redes de más de /28 (abiertas por consola antes de que
existiera `--panel`) pasa a `REDES_PANEL` con un aviso: son redes que abren el panel, no proxies.

Modo laboratorio (canario antes de la primera release, decidido en el contrato):
`--desde-repo /root/IDS_MAAT-Docker --imagenes vpn=<ref>,suricata=<ref>` → usa el checkout local,
escribe `imagenes.json` con `"dev": true` y no verifica firmas (lo avisa en grande).

Pasos (idempotente: se puede volver a ejecutar para cambiar gestión/proxy):

1. Comprueba root, Debian 13 y `amd64`. Valida argumentos: gestión ≤ /16 (o abierta); proxy ≤ /28 (o abierto);
   sin solapes entre gestión, `<tun-base>.0.0/16` y `10.210.0.0/16`. `--tun-base` solo se acepta
   si todavía no hay puntos.
2. **Respaldo** en `/root/backups/ids-maat-install-<ts>.tar.gz` de `/etc/ssh/sshd_config*`,
   `/etc/docker/`, `/srv/ids/fw/`, `/etc/fail2ban/` y `/etc/ids-maat/` antes de tocar nada
   (desde 2026-10-15 también `/etc/localtime`, como enlace, y `/etc/timezone`).
3. Paquetes: `nftables fail2ban python3 python3-systemd openssl logrotate curl ca-certificates`
   (más `systemd-timesyncd` y, desde 2026-10-15, `tzdata`).
   **Nunca** `iptables-persistent`/`netfilter-persistent` ni `ufw`. `systemctl disable --now nftables`.
4. Docker CE desde su repositorio con la versión mayor fijada (`28`) por `apt` pin, más
   `docker-compose-plugin`; `daemon.json` = RED §1 **más** `"bip": "10.210.254.1/24"`. Comprueba
   `update-alternatives --query iptables` → `iptables-nft`.
5. `modules/ids.conf` (`tun`, `veth`, `nft_ct`), `sysctl/90-ids.conf` (`net.core.rmem_max=33554432`),
   `systemd-timesyncd`. **Zona horaria del servidor** (2026-10-15, «UTC dentro, Ecuador fuera»):
   `zona_host` deja `/etc/localtime` en `--zona`, la de `ids.conf` o `America/Guayaquil`
   (`timedatectl` o enlace atómico; idempotente; una zona inexistente falla antes de tocar nada). Se
   hace justo tras los paquetes (hace falta `tzdata`), fuera del modo seguro y antes de `arrancar`.
   Los contenedores siguen en UTC.
6. Grupo y usuario `ids-panel` 10500; árbol de §2.1; `ids.conf`; secretos (si no existen).
7. PKI si no existe: CA RSA 2048 SHA-256 de 20 años (`CN=ids-maat-ca <NOMBRE_DNS>`) y `dh.pem`
   `ffdhe2048` con `openssl genpkey -genparam -algorithm DH -pkeyopt dh_param:ffdhe2048`.
8. Firewall: renderiza `ids_host.nft`, `nft -c -f`, instala y arranca `ids-host-fw.service`.
9. SSH: `/etc/ssh/sshd_config.d/10-ids.conf` con `PasswordAuthentication no`; `sshd -t`; reload;
   comprueba `sshd -T`.
10. fail2ban: jaulas y filtro; `fail2ban-regex` del filtro contra las líneas de §5.13 (4 coincidencias).
11. Verifica la release (cosign con sha256 fijado en el script; `release.json`; sha256 del tar), la
    desempaqueta en `/root/ids-maat/host-<v>/`, instala el orquestador y las unidades, escribe
    `imagenes.json` y hace `docker pull` por digest.
12. Arranca `ids-orq`, ejecuta `ids-orq reglas actualizar` (debe existir `current` antes del primer
    punto) y activa los timers.
13. Resumen final: nombre, base de túneles, puertos abiertos, siguiente paso
    (`ids-orq punto crear …`).

---

## 8. Pruebas

### 8.1 Convención

- **Python stdlib `unittest`**, sin dependencias. Ficheros `tests/test_<prefijo>_*.py`; cada uno se
  ejecuta solo y calcula la raíz del repo con `Path(__file__).resolve().parents[1]`. Los scripts
  sin `.py` se cargan con `importlib.machinery.SourceFileLoader`.
- Lo que necesita Linux (AF_UNIX, `fcntl`, `nft`, Docker, root) va con
  `@unittest.skipUnless(sys.platform.startswith("linux"), …)` o se pone en un `.sh` de
  `tests/imagen/` o `tests/integracion/`.
- Prueban **comportamiento** (que funciona), no que el texto esté escrito.
- Ayudas compartidas solo dentro del prefijo: `tests/_ayuda_<vpn|suricata|orq>.py`.
- Las pruebas que necesitan un dato de otro constructor lo copian **de este contrato** a su propio
  `fixtures/<prefijo>/` (p. ej. C copia las líneas de §5.13; B y C escriben cada uno su ejemplo de
  plantilla con los marcadores de §4.6.1).

`tests/run.sh` (C), sin lista de pruebas que mantener:

```
tests/run.sh [--imagenes] [--integracion]
  1. python -m unittest discover -s tests -p "test_*.py"            (python3, python o "py -3")
  2. cada tests/test_*.sh con bash
  3. --imagenes:    cada tests/imagen/test_*.sh   (necesita Docker Linux, IDS_IMG_VPN, IDS_IMG_SURICATA)
  4. --integracion: cada tests/integracion/test_*.sh (necesita root y Docker)
Un .sh que sale con 77 cuenta como OMITIDA. Sale con 1 si falla alguna.
```

Se corre en Linux, en la VPS. **Desde 2026-10-15** (decisión del dueño) no hay Windows (ni job
`pruebas-windows` ni plataforma `windows` en `tests/obligatorias.txt`), GitHub solo hace lint y
nada se ejecuta en el PC de desarrollo.

### 8.2 Qué prueba cada constructor

| Constructor | Unitarias (Windows y Linux) | Imagen / integración (Linux, CI) |
|---|---|---|
| **A** | `render.py`: validación de cada variable de §4.1 (valores buenos y malos, `TUN_MK` fuera de `TUN_NET`) y texto exacto de §4.7. `tzsp-decap`: parser TZSP, `permitido` fail-closed, recorte por flujo, **latido sin tráfico** (socket falso que da `timeout`) y esquema de `tzsp.json`. `ovpn-auth`: acepta la clave buena de una línea de §4.5 generada en la prueba; rechaza la mala; **el freno no llama a scrypt** (se sustituye `hashlib.scrypt` por un contador); freno global; usuario con formato malo → `usuario=-`; cada línea de log casa con la regex de §5.13 | `test_vpn_arranque.sh`: con PKI de prueba (openssl) y un `/srv` temporal, el contenedor llega a `healthy` sin tráfico; existen `ids-in`/`ids-mon`, las dos tablas nft y `api.sock` 0660; `kill` de `openvpn` → s6 lo relanza, el contenedor no se reinicia y el veth sigue; con `TUN_MK` inválido el contenedor sale |
| **B** | Plantilla: todos los marcadores de `plantilla.json` aparecen y no hay otros; render de prueba sin `@@` restantes. `ids-reglas`: dominios inválidos fuera, `domains.dataset` en base64, dataset vacío si el feed falla, `LISTO` el último, `MANIFEST.json`, `disable-reducido.conf` no quita el sid 2100498. `salud-suricata` con `IDS_EVE`/`IDS_AHORA`: stats de hace 30 s → 0, de hace 200 s → 1, sin eve → 1 | `test_suricata_reglas.sh`: `ids-reglas descargar` real y `suricata -T` de los dos perfiles con ET real. `test_suricata_pcap.sh`: `suricata -r tests/fixtures/suricata/alerta-2100498.pcap` con la plantilla renderizada da la alerta 2100498 con `host` = `SENSOR_NAME`, y `eve.json` sale 0640. `test_suricata_espera.sh`: sin `ids-mon` y `IDS_ESPERA_MON_S=3`, sale con 1 en ~3 s |
| **C** | Asignación (N más bajo libre, enfriamiento de 7 días, `pid` nunca reutilizado, puerto, subred, `cluster-id`, base `198.18`); render de `compose.yml`, `server.conf` (v6, v7, `seclevel0`, `legacy`), `ccd`, `usuarios` (verifica el hash con su propia implementación de §4.5), `suricata.yaml` (marcador que sobra o falta → error), `ids_host.nft` (puertos y `origen_ip`); admisión y `caben`; `cpuset`; protocolo (orden desconocida o fuera de rango → `INVALIDO`; mismo `op_id` → una ejecución; otros parámetros → `CONFLICTO`); esquema de `estado.json`; salida exacta de `punto ovpn-client`; regex de fail2ban contra las líneas de §5.13; `test_ci_eol`: ningún CRLF ni BOM en el repo | `test_host_install.sh`: validación de argumentos de `install.sh` (sin instalar). `integracion/test_e2e.sh` (con `IDS_RAIZ` temporal; se omite en un servidor con el IDS instalado): `ids-orq servicio` + `punto crear` → `healthy`; un cliente OpenVPN de prueba en contenedor se autentica, envía el pcap de B por TZSP a `<sensor>:37008` y aparece en `datos/p001/eve.json` la alerta 2100498 con `host = p001`; sin tráfico, `vpn` sigue sano; `docker restart ids-p001-vpn` → el orquestador detecta netns distintos y reinicia `suricata`; `reglas actualizar` reinicia de uno en uno; `punto borrar` no deja nada en `{puntos,datos,run,ctl}/p001` |

Las pruebas de F1a que solo se pueden hacer con un VPS y un MikroTik reales (6.49, `live-restore`,
reinicio del VPS, mediciones 1–15 de FASES §2) **no** van en CI: las ejecuta el dueño en el
canario y se anotan en `docs/MEDICIONES-F1a.md` (lo crea el dueño tras el canario).

---

## 9. Criterio de entrega por constructor

| Constructor | Entrega hecha cuando… |
|---|---|
| **A** | `images/build.sh vpn` construye; sus unitarias pasan en Windows y Linux; `test_vpn_arranque.sh` pasa; `pyflakes` y `shellcheck` limpios; la entrega lista cualquier decisión interna tomada |
| **B** | `images/build.sh suricata` construye; unitarias en verde; `-T` de los dos perfiles con ET real y el pcap con la alerta 2100498; el sid está en `reducido`; lista de decisiones internas (fuentes de feeds, contenido de `disable-reducido.conf`, cómo admite Suricata el dataset absoluto) |
| **C** | `tests/run.sh` en verde en Windows y Linux; `install.sh` valida argumentos; `release.yml` y `ci.yml` listos; con las imágenes de A y B, `integracion/test_e2e.sh` pasa en CI |
| **Los tres** | ninguno ha tocado ficheros de otro; finales LF; sin IPs ni nombres reales; nada fuera de su tabla de propiedad del principio |
