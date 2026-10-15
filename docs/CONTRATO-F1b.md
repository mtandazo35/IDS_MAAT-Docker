# Contrato de construcción — F1b (panel)

> **Sustituido en lo que toca al panel por [CONTRATO-F2-panel.md](CONTRATO-F2-panel.md).** El panel
> mínimo de F1b (`idspanel/app.py`, `vistas.py`, `sesiones.py`, `usuarios.py`, `red.py`, `eve.py`,
> `bitacora.py`, `static/`) y sus pruebas `tests/test_panel_*` se retiraron en F2: el panel es el
> dashboard heredado de suricata-ids-lab con el apartado Puntos. Siguen vigentes la integración con el
> orquestador (núcleo `ids-core`, `ids-orq panel aplicar|crear-admin|restablecer`) y la interfaz de
> la CLI `ids-panel`; los usuarios pasan a `/srv/ids/panel/conf/usuarios.json` (F2 §7).

Anexo de [ARQUITECTURA.md](ARQUITECTURA.md) y continuación de [CONTRATO-F1a.md](CONTRATO-F1a.md),
que sigue vigente salvo lo que cambia aquí. Dos constructores trabajan a la vez:

| Constructor | Entrega | Suyo |
|---|---|---|
| **P** | imagen `panel` | `images/panel/**`, `tests/test_panel_*`, `tests/fixtures/panel/` |
| **I** | integración: núcleo `ids-core`, instalador, CI y release | `install.sh`, `orquestador/**`, `host/**`, `.github/**`, `images/build.sh`, `tests/test_orq_*`, `tests/test_host_*`, `tests/test_ci_*`, `tests/integracion/**`, `tests/run.sh`, `tests/_ayuda_orq.py` |

Cada uno escribe solo bajo su encabezado.

## Panel (P)

Panel mínimo de F1b: entrar, ver los puntos, crear y borrar puntos, regenerar la clave de la VPN,
ver alertas y una página de documentación. Python 3 de Debian **solo con la stdlib**, un paquete
`idspanel` en módulos (no un heredoc). Todo en castellano.

### P.1 Imagen

`images/panel/Dockerfile` (contexto `images/panel`):

- `ARG BASE_IMAGE` sin valor por defecto (`FROM ${BASE_IMAGE}`, el de `images/base.env`) y
  `ARG VERSION=dev`; etiquetas `org.opencontainers.image.source`, `org.opencontainers.image.version`
  e `ids-maat.componente=panel`.
- Paquetes: `python3` y `tzdata` (para `IDS_TZ` con `zoneinfo`), `--no-install-recommends`.
- Usuario y grupo `ids-panel` 10500:10500; `USER 10500:10500`.
- `chmod` explícitos (0755 el ejecutable y los directorios, 0644 el resto) y `compileall` del
  paquete: con `read_only` no se escribe ningún `.pyc` en ejecución. Solo necesita `/tmp` en tmpfs
  (y ni eso: no escribe en `/tmp`).
- `ENTRYPOINT ["/usr/local/bin/ids-panel"]`, `CMD ["servir"]`, `EXPOSE 5637`,
  `HEALTHCHECK CMD ["/usr/local/bin/ids-panel", "salud"]` (el compose de I pone el suyo, igual).

```
images/panel/
├── Dockerfile
└── rootfs/usr/local/
    ├── bin/ids-panel                          #!/usr/bin/python3; carga lib/ids-panel
    └── lib/ids-panel/idspanel/
        ├── config.py     entorno IDS_* -> Config
        ├── usuarios.py   usuarios.json (PBKDF2), crear/restablecer/cambiar
        ├── sesiones.py   sesiones (sha256 del token) y freno de login
        ├── red.py        proxy de confianza, IP real, comprobación de origen (CSRF)
        ├── orq.py        cliente del socket del orquestador y errores en lenguaje claro
        ├── estado.py     estado.json y tzsp.json
        ├── eve.py        alertas leyendo el final del eve.json; conteo de 24 h
        ├── operaciones.py, bitacora.py, util.py
        ├── vistas.py     HTML (todo dato pasa por esc())
        ├── app.py        servidor HTTP y rutas
        ├── cli.py        servir | crear-admin | restablecer | salud
        └── static/       panel.css, panel.js, tema.js
```

### P.2 Órdenes

| Orden | Hace | Salida |
|---|---|---|
| `ids-panel [servir]` | HTTP en `${IDS_ESCUCHA:-0.0.0.0}:${IDS_PUERTO:-5637}`; SIGTERM para limpio. Arranca aunque no haya usuarios (lo avisa por stderr: nadie entra hasta `crear-admin`) ni socket del orquestador | — |
| `ids-panel crear-admin [--usuario admin]` | si `usuarios.json` no existe o no tiene ese usuario, lo crea con una clave aleatoria de 20 `[A-Za-z0-9]` | stdout: **una** línea `CLAVE=<clave>`; 0. Si ya existe: 3, aviso en stderr, nada tocado. Usuario inválido: 2 |
| `ids-panel restablecer --usuario X` | clave aleatoria nueva; cierra todas sus sesiones (cambia su `sello`) | stdout `CLAVE=<clave>`; 0. No existe: 4 |
| `ids-panel salud` | `GET http://127.0.0.1:${IDS_PUERTO}/salud` | 0 si da 200; 1 si no |

`crear-admin` y `restablecer` solo necesitan `/srv/ids/panel` montado (sin red ni orquestador) y se
pueden ejecutar con el panel en marcha: el panel relee `usuarios.json` cuando cambia (mtime,
tamaño, inodo). Usuario: `^[a-z0-9][a-z0-9._-]{0,31}$`. `IDS_ESCUCHA` es interno (pruebas); el
compose no lo pone.

### P.3 Ficheros en `/srv/ids/panel` (todos 0600, escritura atómica en el mismo directorio)

| Fichero | Contenido |
|---|---|
| `usuarios.json` | `{"v":1,"usuarios":{"admin":{"alg":"pbkdf2_sha256","iter":600000,"sal":"<32 hex>","hash":"<64 hex>","sello":"<16 hex>","clave_temporal":true,"creado":<epoch>,"cambiado":<epoch>}}}`. Nunca la clave. `iter` por usuario: si sube la constante, el hash se rehace al entrar. `clave_temporal` = generada por `crear-admin`/`restablecer`: el panel invita (no obliga) a cambiarla |
| `sesiones.json` | `{"v":1,"sesiones":{"<sha256 del token>":{"usuario","sello","creada","ultima","ip"}}}`. El token (256 bits) solo vive en la cookie |
| `operaciones.json` | las órdenes que el panel pidió: `op_id` → `usuario`, `orden`, `pid`, `nombre`, estado final y pasos. Sin claves. 7 días / 300 como máximo |
| `bitacora.jsonl` | una línea por acción: `{"ts","usuario","ip","accion","punto?","resultado","detalle?"}`; acciones `sesion.entrar` (`ok`/`fallo`/`frenado`), `sesion.salir`, `cuenta.clave`, `punto.crear`, `punto.borrar`, `punto.vpn.regenerar` (y `<orden>.fin` con el código final), `csrf.rechazado`. Sin claves, tokens ni cookies |

Con `/srv/ids/panel` en `root:10500` 2770 (I.1) el panel (10500) crea y reemplaza sus ficheros.

### P.4 Entorno y montajes que lee

Los de la interfaz fija (I.2): `IDS_PROXY`, `IDS_EMPRESA` (se muestra en la barra y en el login,
escapado), `IDS_PUERTO`, `IDS_TZ` (zona para **mostrar** fechas; por defecto `America/Guayaquil`; sin tzdata, Ecuador es
UTC−5 fijo y otra zona desconocida → UTC),
`IDS_ORQ_SOCK`, `IDS_ORQ_TOKEN` (ruta; el token se relee en cada petición), `IDS_PANEL_DIR`,
`IDS_DATOS`, `IDS_RUN`. `IDS_PROXY` mal escrito o `IDS_PUERTO` no numérico → sale con 2.

Lecturas (solo lectura, nunca escribe fuera de `IDS_PANEL_DIR`):

- `${IDS_RUN}/estado.json` (CONTRATO-F1a §5.10), releído solo si cambia. Si falta o tiene más de
  60 s, la pantalla lo avisa.
- `${IDS_RUN}/<pid>/tzsp.json` → `ultimo_visto` (máximo) = «último espejo».
- `${IDS_DATOS}/<pid>/eve.json` y, si no basta, `eve.json.1` (el rotado sin comprimir por
  `delaycompress`): se leen **hacia atrás** por bloques de 256 KiB, con tope de bytes, y solo las
  líneas con `"event_type":"alert"`. Alertas 24 h: la primera vez hacia atrás hasta pasar las 24 h
  (tope 256 MiB; si se corta se muestra `N+`), después solo lo nuevo por inodo y posición; rotación
  o truncado → se recuenta. Toda alerta lleva su `pid`: la misma IP en dos puntos son dos filas.
- Todo `pid` se valida con `^p\d{3}$` antes de formar una ruta.

### P.5 Rutas HTTP

| Ruta | Sesión | Hace |
|---|---|---|
| `GET /salud` | no | 200 `ok` |
| `GET /static/{panel.css,panel.js,tema.js}` | no | estáticos |
| `GET /entrar` · `POST /entrar` (`usuario`, `clave`) | no | 303 a `/puntos` con cookie; 401 «Usuario o clave incorrectos.»; 429 frenado |
| `POST /salir` (`csrf`) | sí | borra la sesión y la cookie |
| `GET /puntos` · `GET /puntos/tabla` | sí | pantalla Puntos; el fragmento se refresca cada 15 s (401 sin sesión) |
| `GET /puntos/nuevo` · `POST /puntos/nuevo` (`csrf`, `nombre`; desde 2026-10-15 no se preguntan `redes`, `ros_version` ni `perfil`, y si llegan se ignoran; con `ajax=1`, el modal de la lista, `{op_id}` o `{error}`) | sí | 303 a `/operaciones/<op_id>`; 400/409/503 con el formulario y el error en claro |
| `GET /puntos/<pid>` (`?ip=`) | sí | ficha: estado, comandos sin clave (`punto.comandos`), regenerar, últimas 100 alertas del punto, borrar |
| `POST /puntos/<pid>/borrar` (`csrf`, `confirmar`) | sí | exige `confirmar` = nombre (si `estado.json` lo trae; si no, lo comprueba el orquestador) |
| `POST /puntos/<pid>/regenerar` (`csrf`) | sí | `punto.vpn.regenerar` |
| `GET /operaciones/<op_id>` · `…/fragmento` | sí, **y** ser quien la pidió (si no, 404) | avance (`op.estado`) y, al terminar, el resultado |
| `GET /alertas` (`?punto=&ip=`) | sí | hasta 200 alertas (la más nueva primero) de toda la empresa o de un punto, cada fila con su punto |
| `GET /documentacion` · `GET /cuenta/clave` · `POST /cuenta/clave` (`csrf`, `actual`, `nueva`, `repetir`) | sí | doc; cambiar mi clave (mínimo 12; cierra las demás sesiones) |

### P.6 Seguridad

- **Proxy de confianza:** solo si el par TCP está en `IDS_PROXY` (IPs o CIDR; también
  `::ffff:a.b.c.d`) se usan `X-Forwarded-For` (la **última** entrada), `X-Forwarded-Proto`,
  `X-Forwarded-Host` o `Forwarded` (RFC 7239). Si no, se ignoran: IP real = par TCP, host = `Host`.
- **CSRF:** todo POST pasa por la comprobación de origen del panel anterior (`origen_ajeno`):
  `Sec-Fetch-Site` `cross-site`/`same-site` → 403; `same-origin` → pasa; `Origin` (o `Referer`) con
  host:puerto distinto de `Host` (y de los del proxy, solo si viene del proxy) → 403; `Origin: null`
  solo con `Sec-Fetch-Site: none`. Además todo POST con sesión lleva el campo `csrf` =
  `sha256("ids-panel-csrf\0" + token)[:40]` (derivado de la cookie; no se guarda).
- **Cookie:** `ids_s=<token>; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict`; con
  `X-Forwarded-Proto: https` desde el proxy, `__Host-ids_s=…; Secure`. Rotación al entrar.
- **Sesiones:** 12 h absolutas, 2 h de inactividad, máximo 10 por usuario; se invalidan al cambiar
  o restablecer la clave (`sello`).
- **Freno:** 8 fallos en 10 min por IP real **y** por usuario → 429 con mensaje neutro. Un usuario
  inexistente cuesta lo mismo que una clave mala (PBKDF2 de relleno).
- **Cabeceras:** `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';
  …; frame-ancestors 'none'` (sin nada en línea: ni `<script>` ni `style=`), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Cache-Control: no-store`.
- **Escape:** todo dato (estado.json, eve, IDS_EMPRESA, formularios, mensajes del orquestador) pasa
  por `html.escape(quote=True)`. Modales propios `ask()`/`aviso()`; nunca `alert`/`confirm`.
- **Logs:** una línea por petición a stderr (IP real, método, ruta, código); nunca cuerpos,
  cookies ni claves. Un fallo de una página devuelve 500 con texto claro sin traza.

### P.7 Uso del orquestador

Petición (una por conexión, JSON + `\n`): `{"v":1,"op_id":"<uuid4>","token":"<IDS_ORQ_TOKEN>",
"orden","params","quien":"panel:<usuario>","ip":"<IP real>","ts"}`. Órdenes y parámetros
**exactos** de `ids_orq.py` (las pruebas los pasan por su `validar_params` real):

| Orden | Parámetros que manda el panel | Uso |
|---|---|---|
| `punto.crear` | `nombre`, sin `redes_abonados` (el orquestador pone las de por defecto), `perfil` `reducido` y `ros_version` 6 fijos (VPN compatible con RouterOS 6.49+ y 7). Lo demás, por defecto | Agregar punto |
| `op.estado` | `op_id` | avance (`pasos`, `paso`, `avance`, `delante`) y `resultado` |
| `punto.comandos` | `pid` | ficha: comandos con `<CLAVE-VPN>` y `clave_id` (huella de la clave vigente) |
| `punto.borrar` | `pid`, `confirmar` | Borrar |
| `punto.vpn.regenerar` | `pid` | Regenerar la clave |

- El panel genera el `op_id` y lo guarda en `operaciones.json` **antes** de llamar.
- **Clave:** el orquestador entrega `clave` (y `comandos` con la clave) una sola vez, en el primer
  `op.estado` tras terminar, y guarda solo su hash. El panel la muestra en esa respuesta (usuario,
  clave y bloques v7/v6 y certificado, cada uno con «Copiar») y desde 2026-10-15 la **guarda cifrada**
  con la clave maestra (`conf/vpn-claves.json`, 600) junto a `clave_id`, la huella de la clave vigente
  que dan el resultado y `punto.comandos`. La ficha (solo admin, `Cache-Control: no-store`) pone la
  clave en los comandos solo si `clave_id` coincide; si no (punto anterior, regenerada por la CLI o
  entrega perdida), lo dice y ofrece regenerarla. La baja la borra.
- Comandos: el bloque de `punto.comandos` se parte por sus marcas (`# --- Certificado API-SSL`,
  `# --- RouterOS v7`, `# --- RouterOS v6`); el v7 primero y el v6 plegado (con `ros_version` 7, el v7 sale como la versión declarada). Si el
  formato cambiara, se muestra entero.
- Errores en lenguaje claro: `INVALIDO` «Los datos no son válidos: …», `CONFLICTO` «No se puede
  hacer ahora: … Caben ahora: …», `CONFLICTO_PUERTO`, `NO_EXISTE`, `REVERTIDA` «falló y se deshizo
  todo», `FALLO`, token inválido, demasiadas peticiones, y sin socket/sin token («No se puede hablar
  con el orquestador… revisa systemctl status ids-orq»).

### P.8 Pruebas (P)

`tests/test_panel_*.py` (unittest, stdlib, Windows y Linux; ayuda en
`tests/fixtures/panel/_ayuda_panel.py`, con un servidor real del panel en `127.0.0.1:<libre>` y un
orquestador falso que valida con el `validar_params` real y genera los comandos con el
`comandos_mikrotik` real de `ids_orq.py`, que solo se importa):

| Fichero | Qué comprueba |
|---|---|
| `test_panel_usuarios.py` | `crear-admin` con el ejecutable real: una línea `CLAVE=`, hash PBKDF2 600 000 con sal hex y sin la clave en disco, 0600 (Linux), 3 sin tocar nada, segundo usuario sin tocar el primero, 2 con usuario inválido; `restablecer` (0, nueva clave, sello nuevo; 4); rehash transparente; cambiar exige la actual |
| `test_panel_login.py` | redirección sin sesión, cookie `HttpOnly`/`SameSite=Strict` (y `__Host-…; Secure` tras proxy https), mensaje neutro, freno por IP que ignora `X-Forwarded-For` ajeno y usa el del proxy (última entrada), freno por usuario, salir, `restablecer` cierra sesiones, invitación y cambio de clave |
| `test_panel_csrf.py` | reglas de `origen_ajeno`, cabeceras del proxy solo desde el proxy, login con otro `Origin` → 403, `X-Forwarded-Host` ajeno ignorado, POST sin token de sesión → 403, cabeceras de seguridad y nada en línea |
| `test_panel_paginas.py` | Puntos con un `estado.json` de ejemplo (semáforo, conectado, último espejo, alertas 24 h, «Toda la empresa»), avisos de estado ausente/viejo, ficha y filtro por IP, alertas sin mezclar IPs repetidas entre puntos, escape HTML (firma, `IDS_EMPRESA`, formulario) |
| `test_panel_crear.py` | crear punto: parámetros exactos, `quien`/`ip`/token, avance, clave y comandos en la página de la operación una sola vez (después, solo la ficha con la clave cifrada en el panel), bitácora sin secretos, otro usuario no ve la operación, formulario inválido no llega al orquestador, errores en claro (incluido sin socket y token malo), revertida; borrar exige el nombre (panel y orquestador); regenerar |
| `test_panel_eve.py` | lectura hacia atrás con bloques pequeños, línea a medias, filtro por IP exacto, rotado `.1`, tope de bytes, conteo de 24 h incremental, rotación y truncado, parada al pasar las 24 h |
| `test_panel_orq.py` | formato de la petición, sin token/sin socket, socket AF_UNIX real una petición por conexión (Linux), traducciones, partir los comandos reales, formulario ⊂ `validar_crear` real, configuración por entorno, `ids-panel servir` + `salud` con el ejecutable |

Se comprobó que fallan al romper la lógica (20 mutaciones: CSRF, proxy, freno, verificación de
clave, clave guardada, punto de cada alerta, filtro de IP, escape, nombre al borrar, clave en
claro, exit 3, conteo incremental, sello, `HttpOnly`, dueño de la operación, clave actual,
parámetro inventado…): todas detectadas salvo una equivalente.

### P.9 Decisiones internas y pendientes

- Perfiles del formulario: `reducido` (defecto) y `completo`; `completo-low`, `hilos`,
  `compat_v6`, `api_puerto` y `origen_ip` se quedan en sus valores por defecto (CLI para el resto).
- No se ofrece `punto.ajustar`, arrancar/parar ni logs (fuera del panel mínimo).
- **No implementado:** la comprobación en el propio panel de que el par TCP es una IP del proxy o la
  puerta `10.210.255.1` (PLAN-PANEL §12, «Origen permitido»): hoy lo garantiza solo el nft del host
  (I.5). Si se quiere, hace falta pasarle al panel la puerta de `ids-core` (p. ej. una variable
  `IDS_PUERTA`), que no está en la interfaz fija.
- Las conexiones del túnel SSH comparten la IP `10.210.255.1`: el freno por IP las cuenta juntas.
- **Lo que vendría bien de I (no bloquea):** `redes` del punto en `estado.json` (la ficha no puede
  mostrar las redes de abonados sin pedirlas). Si el orquestador se reinicia entre el final de una
  orden y el primer `op.estado`, la clave se pierde (vive en memoria del orquestador): el panel
  muestra «regénerala desde la ficha».

## Integracion (I)

Integración del panel: núcleo `ids-core`, instalador, orquestador, CI y release. La interfaz del
contenedor (imagen, órdenes `ids-panel …`, montajes y entorno) es la fija que P implementa; aquí
está cómo se usa.

### I.1 Qué cambia respecto de CONTRATO-F1a

| F1a | F1b |
|---|---|
| §0.2 fila 12: matriz del release `[vpn, suricata]` | `[panel, vpn, suricata]` |
| §2.1: `/srv/ids/panel/` no se crea | `/srv/ids/panel/` `root:10500` **2770** (los ficheros del panel, 0600 de 10500, heredan el grupo); `/srv/ids/core/` `root:root` 0700 con `compose.yml` 0600. Los crea `ids-orq panel aplicar` |
| §4.9 `ids.conf` | clave opcional `ZONA_HORARIA=<Región/Ciudad>` (`install.sh --zona`); sin ella, UTC. Sin `--zona`, una reinstalación conserva la que hubiera |
| §4.10 `imagenes.json` | añade `"panel"`. Con `"dev": false`, `ghcr.io/mtandazo35/ids-maat-panel@sha256:<64 hex>`. El orquestador la acepta ausente (un `imagenes.json` de F1a sigue valiendo para los puntos); `panel aplicar` la exige |
| §6.4 `release.json` | `imagenes.panel` por digest (obligatoria: `release_json.py --panel`) y un job `visibilidad` tras `release` |
| §5.15 `ids-orq.service` | `RuntimeDirectoryPreserve=yes`: el panel monta `/run/ids-orq`; si systemd lo borrara al reiniciar el servicio, el montaje se quedaría con el directorio viejo, sin socket |
| §7 instalador | `--imagenes vpn=…,suricata=…,panel=…` (las tres obligatorias en laboratorio), `--zona`, paso `panel` tras `arrancar`, resumen con URL, usuario y clave, log `/root/ids-maat/install-<ts>.log` |

### I.2 Núcleo `ids-core`

**Quién lo renderiza y lo levanta (decidido):** `ids-orq panel aplicar`, orden **local** de root
(como `fw-render`, sin pasar por la cola: el panel no comparte nada con los puntos). Renderiza
`orquestador/plantillas/core.yml.tmpl` con `str.replace` de `@@X@@` (falla si sobra alguno),
escribe `/srv/ids/core/compose.yml` (0600, atómico), ejecuta
`docker compose -p ids-core -f /srv/ids/core/compose.yml up -d --pull never --remove-orphans` y
espera a `healthy` (≤ 120 s). Idempotente: con la misma imagen y el mismo `ids.conf`, compose no
recrea nada. Lo llama `install.sh`; para cambiar la imagen o el proxy se vuelve a ejecutar el
instalador (o `ids-orq panel aplicar` tras editar `imagenes.json`).

**Tras reiniciar el VPS:** Docker relanza el panel (`restart: unless-stopped`; `live-restore`
lo mantiene vivo si solo se reinicia dockerd). Además `ids-orq servicio`, al arrancar, encola
`sistema.reconciliar`, que ahora también hace `compose up -d --pull never` del núcleo si existe
`/srv/ids/core/compose.yml` y `ids-core-panel` no está `running` (cubre un `docker stop`/`rm`).
No re-renderiza. Se informa como `"panel"` en `levantados`.

Compose generado (con `PUERTO_PANEL=5637`, `IPS_PROXY=203.0.113.50`, sin `ZONA_HORARIA`):

```yaml
# ids-maat — núcleo (panel); generado por ids-orq panel aplicar; no editar
name: ids-core
services:
  panel:
    image: ghcr.io/mtandazo35/ids-maat-panel@sha256:<digest>
    container_name: ids-core-panel
    hostname: ids-core-panel
    restart: unless-stopped
    user: "10500:10500"
    labels: { ids-maat.parte: "panel", ids-maat.version: "0.1.0" }
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: ["/tmp:size=64m"]
    ports: ["5637:5637/tcp"]
    networks:
      core: { ipv4_address: 10.210.255.2 }
    environment:
      IDS_PROXY: "203.0.113.50"
      IDS_EMPRESA: "ids.empresa.example"
      IDS_PUERTO: "5637"
      IDS_TZ: "America/Guayaquil"
      TZ: "UTC"
      IDS_ORQ_SOCK: "/run/ids-orq/orq.sock"
      IDS_ORQ_TOKEN: "/run/secrets/orq_token"
      IDS_PANEL_DIR: "/srv/ids/panel"
      IDS_DATOS: "/srv/ids/datos"
      IDS_RUN: "/srv/ids/run"
    volumes:
      - /srv/ids/panel:/srv/ids/panel
      - /srv/ids/datos:/srv/ids/datos:ro
      - /srv/ids/run:/srv/ids/run:ro
      - /run/ids-orq:/run/ids-orq:ro
      - /etc/ids-maat/orq_token:/run/secrets/orq_token:ro
    logging: { driver: journald, options: { tag: ids-panel } }
    mem_limit: 1024m
    memswap_limit: 1024m
    pids_limit: 128
    stop_grace_period: 15s
    healthcheck:
      test: ["CMD", "ids-panel", "salud"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
      start_interval: 5s
networks:
  core:
    name: ids-core
    driver: bridge
    driver_opts: { com.docker.network.bridge.name: ids-core }
    ipam: { config: [ { subnet: 10.210.255.0/24, gateway: 10.210.255.1 } ] }
```

- `mem_limit` = `RESERVA_PANEL_MB` (1024) de la admisión: la reserva que F1a ya descontaba al dar de
  alta puntos es exactamente lo que el panel puede usar.
- Etiqueta `ids-maat.parte=panel` y **sin** `ids-maat.punto`: el panel no es un punto (ni huérfano
  ni supervisado como tal), y `install.sh` no lo toma por un contenedor ajeno con puertos.
- `IDS_PROXY` = `IPS_PROXY` de `ids.conf` (IPs sueltas sin `/32`); `IDS_EMPRESA` = `NOMBRE_DNS`;
  `IDS_TZ` = `ZONA_HORARIA` o `America/Guayaquil` (hora de Ecuador); `TZ` del contenedor siempre `UTC` (la zona solo al mostrar).
- `IDS_ORQ_TOKEN` es la **ruta** del fichero del token (montaje de un fichero `root:10500` 0640);
  el token nunca va en el entorno ni en el compose.
- Red `ids-core`: `10.210.255.0/24` (reservada en F1a; fuera de las /28 de los puntos y del `bip`
  `10.210.254.0/24`), puerta `10.210.255.1`, panel `10.210.255.2`. Las conexiones desde el propio
  host (túnel `ssh -L 5637:10.210.255.2:5637`, `curl 127.0.0.1:5637`) llegan al panel con origen
  `10.210.255.1`.

### I.3 Órdenes de un solo uso: primer admin y restablecer

```
ids-orq panel crear-admin [--usuario admin]   -> stdout: CLAVE=<clave>   (0; 3 si ya existe)
ids-orq panel restablecer <usuario>           -> stdout: CLAVE=<clave>   (0; 1 si falla)
```

Ejecutan `ids-panel crear-admin|restablecer --usuario X` en un contenedor de un solo uso con la
imagen de `imagenes.json`:

```sh
docker run --rm --network none --log-driver none --read-only --tmpfs /tmp:size=16m \
  --cap-drop ALL --security-opt no-new-privileges:true --user 10500:10500 \
  --memory 256m --memory-swap 256m --pids-limit 64 \
  -e IDS_PROXY=… (el mismo entorno de I.2) \
  -v /srv/ids/panel:/srv/ids/panel --entrypoint ids-panel <imagen panel> crear-admin --usuario admin
```

- **Solo** se monta `/srv/ids/panel`; sin red; `--log-driver none` para que la clave no quede en
  ningún log de Docker. `ids-orq` reenvía a stdout **solo** la única línea `CLAVE=<clave>` (si hay
  cero o varias, falla) y a stderr un aviso sin la clave.
- Usuario: `^[a-z0-9][a-z0-9._-]{0,31}$` (el mismo que `ids-panel`).
- Pueden ejecutarse con el panel en marcha: el panel relee `usuarios.json` cuando cambia.

### I.4 Instalador

Orden: … → `imagenes` (descarga también el panel) → `arrancar` (orquestador y reglas) → **`panel`**
→ `resumen`. El modo seguro no cambia: la confirmación llega antes de `imagenes`.

- `panel`: `ids-orq panel aplicar`; si **no** existe `/srv/ids/panel/usuarios.json`,
  `ids-orq panel crear-admin --usuario admin` y la clave se guarda **solo** en una variable del
  shell hasta el resumen (después se vacía). Con `usuarios.json` presente (reinstalación) o con
  salida 3, no se toca: el resumen dice que se conserva la clave existente.
- Resumen final (terminal):

  ```
  PANEL
    URL               http://ids.empresa.example:5637   (o http://203.0.113.10:5637)
                      solo se abre desde las IP de --proxy: 203.0.113.50
                      sin proxy, desde gestión: ssh -L 5637:10.210.255.2:5637 root@ids.empresa.example
                      y en el navegador http://localhost:5637
    usuario           admin
    clave             <clave>
                      se muestra UNA sola vez: no se guarda en claro en ningún fichero ni log
    restablecer       ids-orq panel restablecer admin   (imprime CLAVE=<nueva>)
  ```

  La IP es la de origen de la ruta por defecto (`ip -4 route get`), si la hay. También dice si el
  modo seguro quedó confirmado o si se instaló con `--sin-reversion`.
- **Log del instalador** `/root/ids-maat/install-<ts>.log` (0600): lo que imprimen `log`, `aviso`
  y `fallar`, y el resumen con la clave sustituida por `********`.
- **Imagen que no se puede descargar:** si `docker pull` o `cosign verify` contestan
  `denied`/`unauthorized` para `ghcr.io/…`, el error dice que el paquete es privado (o no existe)
  y da el enlace `https://github.com/users/mtandazo35/packages/container/ids-maat-<img>/settings`.
  Cualquier otro fallo muestra la última línea real del error.

### I.5 Firewall del host

No cambia la plantilla de F1a. El `5637` publicado por Docker es un DNAT a
`10.210.255.2:5637`: en `forward`, la regla
`meta l4proto tcp ct direction original ct status dnat ct original proto-dst 5637 ip saddr != @proxy drop`
casa con el puerto **original** (antes del DNAT), así que solo pasan las IP de `--proxy`, y el
cinturón `ct original proto-dst != @puertos_vpn ct original proto-dst != 5637 drop` lo deja pasar.
El túnel SSH de emergencia y las conexiones locales salen por `output` y no pasan por `forward`.
Las pruebas comprueban que el puerto publicado del compose y el de la regla salen del mismo
`PUERTO_PANEL`. En las pruebas reales, el dueño pone en `--proxy` sus redes de gestión (≤ /28
cada una) para entrar directo.

### I.6 GHCR: paquetes públicos

Los paquetes de GHCR nacen **privados** aunque el repo sea público, y la API REST de GitHub no
permite cambiar la visibilidad de un paquete de una cuenta de usuario. Paso manual, **una vez por
paquete** (tras la primera release que lo publica):
`https://github.com/users/mtandazo35/packages/container/ids-maat-<img>/settings` → *Danger Zone* →
*Change visibility* → *Public*, para `ids-maat-panel`, `ids-maat-vpn` e `ids-maat-suricata`. El job
`visibilidad` de `release.yml` (`.github/scripts/ghcr_publico.py --estricto`) pide el manifiesto
de cada imagen **sin credenciales** y falla, con el enlace en el aviso y en el resumen del job,
mientras alguno siga privado; la release ya está publicada, así que basta con cambiar la
visibilidad y relanzar el job.

### I.7 Pruebas (I)

| Prueba | Qué comprueba |
|---|---|
| `tests/test_orq_panel.py` | compose del núcleo (líneas esenciales, montajes, entorno de la interfaz, sin token, `mem_limit` = reserva de la admisión, red fuera de las /28 y del `bip`, YAML válido si hay PyYAML), puerto publicado = regla del firewall, `ZONA_HORARIA`, `panel aplicar` (ficheros, modos, `compose up`, espera a sano, sin panel en `imagenes.json`, digest en producción), `crear-admin`/`restablecer` (contenedor encerrado, solo la línea `CLAVE=`, 3 sin regenerar, usuario inválido) y reconciliación tras reinicio |
| `tests/test_host_install.sh` | `--imagenes … panel=` (obligatorio en laboratorio), `--zona`, `imagenes.json` con panel (laboratorio y producción), error claro con paquete privado, panel nuevo (URL, usuario, clave en pantalla y `********` en el log; la clave en ningún fichero), reinstalación que no regenera, `crear-admin` con 3, fallo del panel, `principal` completo con el log real |
| `tests/test_ci_workflows.py` | matriz `[panel, vpn, suricata]` y coherencia matriz ↔ `release.json` ↔ visibilidad ↔ `install.sh` ↔ `build.sh`; `release_json.py --panel`; `ghcr_publico.py` con un registro falso; `ci.yml` construye y prueba las tres |
| `tests/test_host_systemd.py` | `RuntimeDirectoryPreserve=yes` |
| `tests/integracion/test_e2e.sh` paso 7 | con `IDS_IMG_PANEL`: `panel aplicar` → healthy en 10.210.255.2 como 10500; `crear-admin` (una línea) y repetido (3); la clave no está en `docker logs`; login por `127.0.0.1:5637` (401 con clave mala, 303 con la buena); lista de puntos; POST con Origin ajeno → 403; alta de `web` desde el formulario → el orquestador crea `p003` con `quien = panel:admin`; sin el contenedor, `reconciliar` lo levanta |

### I.8 Lo que I usa de P (dependencias)

- `ids-panel` en el `PATH` de la imagen (healthcheck `["CMD", "ids-panel", "salud"]` y
  `--entrypoint ids-panel`).
- `crear-admin` y `restablecer` funcionan con **solo** `/srv/ids/panel` montado, sin red y con el
  entorno de I.2; stdout = una sola línea `CLAVE=<clave>`; 3 = ya existe (no toca nada).
- El panel arranca aunque `/run/ids-orq/orq.sock` aún no exista (tras un reinicio Docker puede
  levantarlo antes que `ids-orq`) y relee `usuarios.json` si otro proceso lo cambia.
- Rutas que usa el e2e (las de `app.py` de P a 2026-10-11): `POST /entrar` (`usuario`, `clave`) →
  303 a `/puntos` con cookie `ids_s` por HTTP; `GET /puntos` (lista con el nombre de cada punto
  entre etiquetas, `>web<`); `GET /puntos/nuevo` con `<input type="hidden" name="csrf" value="…">`;
  `POST /puntos/nuevo` (`csrf`, `nombre`; `redes`, `ros_version` y `perfil` se ignoran) → 303 a
  `/operaciones/<op_id>`; POST con `Origin` de otro host → 403; clave mala → 401. Si P cambia
  alguna, se ajusta el paso 7 de `tests/integracion/test_e2e.sh`.
