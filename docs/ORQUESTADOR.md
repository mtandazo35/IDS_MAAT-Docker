# Orquestador

Anexo de [ARQUITECTURA.md](ARQUITECTURA.md). Este anexo cubre:

- dónde corre el orquestador y cómo se protege;
- el protocolo y las órdenes;
- la cola en serie, la supervisión y los avisos;
- los flujos de ciclo de vida de un punto.

## 1. Dónde corre y por qué

- **Es un servicio systemd del host**, `ids-orq`: un único fichero Python con la stdlib, versionado
  en el repo. Incluye una CLI, `ids-orq`, que se usa desde F1a.
- **Necesita poderes de root de todos modos:** Docker, el nft del host, la PKI, logrotate y
  `/root/backups`. En un contenedor con `docker.sock` también sería root, con más piezas.
- **El panel nunca monta `docker.sock`.** Solo monta `/run/ids-orq/`.

### 1.1 Encierro systemd

```ini
[Service]
ProtectSystem=strict
ReadWritePaths=/srv/ids /root/backups /run/ids-orq
PrivateTmp=yes
ProtectHome=read-only        # /root/backups queda escribible por ReadWritePaths
NoNewPrivileges=yes
```

En el canario se comprueba que, con este encierro, siguen funcionando:

- `docker compose`, contra el socket de Docker;
- `nft`;
- `systemd-run`, para la reversión del modo seguro;
- `fail2ban-client set ids-vpn unbanip <ip>` (lo lanza `vpn.desbanear`): con `ProtectSystem=strict`
  el socket de fail2ban (`/run/fail2ban/fail2ban.sock`) queda en una ruta de solo lectura; hay que
  comprobar que conecta y que el desbaneo se ve en `fail2ban-client status ids-vpn`.

Si algo más necesita escritura, se añade a `ReadWritePaths` con su motivo.

### 1.2 Orden de arranque

`ids-host-fw` → `docker` → `ids-orq`. Al arrancar, el orquestador:

1. libera la cola: las órdenes que estaban en curso quedan como `error: interrumpida`, y un
   `punto.crear` interrumpido se deshace;
2. **reconcilia**: compara lo deseado de cada punto con los contenedores reales, levanta lo que
   falte y comprueba los netns (§8);
3. se suscribe a `docker events` y **se reconecta solo** si dockerd se reinicia.

## 2. Transporte y autenticación

- **Socket** `/run/ids-orq/orq.sock`, modo 0660, grupo `ids-panel` (gid 10500). Sin TCP.
- **`SO_PEERCRED`** en cada conexión: solo se acepta el uid 10500 (el del panel; sin userns, el uid
  del contenedor es el del host) o root. Cualquier otro se cierra y se registra.
- **Token** `/etc/ids-maat/orq_token`, montado en el panel como secreto. Va en cada petición y se
  compara en tiempo constante. Es defensa en profundidad.
- **Límites:** tamaño máximo de mensaje y un tope de peticiones por minuto.

## 3. Protocolo

JSON por líneas, una petición y una respuesta por conexión:

```text
Petición:  {"v":1, "op_id":"<uuid4>", "token":"…", "orden":"<nombre>", "params":{…},
            "quien":"<login>", "ip":"<ip del operador>", "ts":<epoch>}
Respuesta: {"op_id":"…", "ok":true|false,
            "codigo":"OK|ACEPTADA|CONFLICTO|NO_EXISTE|INVALIDO|FALLO|REVERTIDA",
            "mensaje":"…", "datos":{…}}
```

- **Nada del panel llega a un shell.** Se usa `subprocess.run([...], shell=False)` con valores ya
  validados (tipos, rangos, regex) y plantillas propias. El panel no elige imágenes, rutas, puertos,
  capacidades ni redes.
- **Las órdenes que modifican algo** responden `ACEPTADA` con su posición en la cola. El panel
  sigue el avance con `op.estado {op_id}`, que devuelve `{estado, paso, avance, log_tail}`.

## 4. Cola única en serie

- **Una sola cola global** para todas las órdenes que modifican algo, persistida en `orq.db` y
  ejecutada de una en una. Sustituye a los cerrojos por punto y globales. Además:
  - garantiza que nunca corren a la vez dos `suricata -T`, dos reinicios ni una actualización y un
    alta;
  - con pocos puntos por VPS no penaliza.
- **Las lecturas no se encolan:** `punto.estado`, `punto.logs`, `punto.comandos`,
  `punto.api.huella`, `punto.medir`, `logs.reabrir`, `sistema.estado`, `sistema.capacidad` y
  `op.estado`.
- **Van por la cola:** `punto.crear`, `punto.borrar`, `punto.arrancar`, `punto.parar`,
  `punto.reiniciar`, `punto.ajustar`, `punto.reconfigurar`, `punto.vpn.regenerar`,
  `punto.threshold`, `reglas.actualizar`, `sistema.reconciliar` y `sistema.actualizar`.
- **Mientras corre `ids-actualizar.service`** (lo arranca `sistema.actualizar`), la cola no empieza
  ninguna orden. Esa unidad reinicia el orquestador y el panel, y las órdenes que lleguen esperan:
  - las hace el orquestador nuevo;
  - si arranca con la unidad aún viva, sigue en pausa hasta que acabe;
  - una actualización colgada solo para la cola 1 h.
- **Tampoco las órdenes inmediatas** (`vpn.desbanear`): cambian algo, pero un alta de minutos no debe
  retrasar un desbaneo. Se ejecutan al recibirlas y dejan su línea en `orq.jsonl` (§10) como las de
  la cola.
- Una orden larga, como `reglas.actualizar` o un `punto.crear`, retiene la cola hasta que termina.
  El panel muestra «en cola detrás de X».

## 5. Órdenes fijas

No hay ninguna orden genérica de «ejecutar».

Hay tres clases (constantes `ORDENES_COLA`, `ORDENES_LECTURA` y `ORDENES_INMEDIATAS` de
`ids_orq.py`), más las **reservadas** del final de la tabla, que hoy contestan `INVALIDO` «no
disponible» y no hacen nada.

| Orden | Parámetros (lista blanca) | Hace / devuelve |
|---|---|---|
| `punto.crear` | `nombre` (`^[a-z0-9][a-z0-9-]{1,30}$`); opcionales: `redes_abonados` CIDR[≤64] (solo los prefijos **adicionales**, p. ej. rangos públicos de abonados; vacía por defecto, y así crea el panel todos los puntos. Lo privado y el CGNAT, `10/8`, `172.16/12`, `192.168/16` y `100.64/10`, van siempre en el espejo, menos la base de túneles, el pool de Docker y las redes de gestión, y en el `HOME_NET`; decisión del dueño 2026-10-16), `perfil` (`reducido` por defecto, `completo-low`, `completo`), `hilos` 1–2, `ros_version` 6/7 (7), `compat_v6` `no`/`seclevel0`/`legacy`, `api_puerto` 8729/8728, `origen_ip`, `n` 1–250 y `pid` `^p\d{3}$` (`pid` solo lo admite una petición de root por el socket, para reconstruir; la CLI no tiene opción para `pid` ni `n`) | §11.1. Devuelve los comandos v6/v7 con la clave VPN puesta (y `clave` aparte); después, `punto.comandos` los vuelve a dar con ella si el orquestador la tiene cifrada (2026-10-16). CLI: `ids-orq punto crear --nombre … [--redes …] [--perfil] [--hilos] [--ros] [--compat-v6] [--api-puerto] [--origen-ip]` |
| `punto.borrar` | `pid` | borrado total del lado del host (§11.2, [DATOS.md](DATOS.md) §8) |
| `punto.arrancar` / `punto.parar` / `punto.reiniciar` | `pid`, `parte` ∈ {vpn, suricata, todo} | `observado` |
| `punto.estado` | `pid` o `*` | lo observado (sin encolar) |
| `punto.logs` | `pid`, `parte`, `lineas` ≤ 500 | líneas filtradas (`password`, `key`) |
| `punto.vpn.regenerar` | `pid` | hash nuevo, la clave cifrada en `clave_vpn`, desconexión por management y la clave en el resultado (una vez; después, `punto.comandos`). Si el MikroTik rechazaría el certificado de servidor del punto, porque no lleva `NOMBRE_DNS` (puntos de antes de la verificación del servidor) o no lo firma la CA actual del VPS (o ha caducado), lo renueva y reinicia OpenVPN en lugar del `kill` ([OPERACION.md](OPERACION.md) §1.4) |
| `punto.comandos` | `pid` | el script del MikroTik con la clave puesta (y `clave` aparte) si el orquestador la tiene cifrada (tabla `clave_vpn`, o la copia del panel) y es la vigente; si no, con `<CLAVE-VPN>` (2026-10-16). Lleva solo la CA del VPS y el `ovpn-client` con `verify-server-certificate=yes`: sin el usuario ni el grupo `ids-api`, que crea a mano el operador si quiere usar la API (2026-10-16; [OPERACION.md](OPERACION.md) §1.2); sin certificado de la API-SSL ni nada de `/ip service api-ssl`, que se usa tal como esté (decisión del dueño, 2026-10-15; [OPERACION.md](OPERACION.md) §1.1), y sin reglas de firewall ni rutas, que gestiona el operador ([OPERACION.md](OPERACION.md) §1.5); con un certificado de servidor viejo, un `# AVISO` en la cabecera. CLI: `ids-orq punto ovpn-client <pid>` |
| `vpn.desbanear` | `ip` (una IPv4/IPv6; nada de rangos) | **inmediata** (§4): `fail2ban-client set ids-vpn unbanip <ip>`; devuelve `{ip, desbaneada, jaula}` («no estaba baneada» también es `OK`). CLI: `ids-orq vpn desbanear <ip>`. En el panel: ficha del punto → «Desbanear IP del MikroTik», solo administradores |
| `punto.ajustar` | `pid`; opcionales: `perfil`, `hilos` 1–2, `redes_abonados`, `compat_v6` `no`/`seclevel0`/`legacy`, `ros_version` 6/7, `origen_ip` (IPv4, o `null` para quitarla) | Solo lo que cambia: **perfil o hilos**: admisión de RAM si sube el perfil o los hilos (§7), yaml nuevo, `-T`, `compose.yml` nuevo y `--force-recreate` de `suricata`; **solo los prefijos**: se guardan y Suricata no se reinicia (ya analiza todo lo privado y el CGNAT); solo si cambia su `HOME_NET` (entra o sale un prefijo público), yaml nuevo sin `-T` y reinicio de `suricata`, que relee el yaml montado; **`compat_v6` o `ros_version`**: `server.conf` nuevo, reinicio de OpenVPN dentro del contenedor (`s6-svc -r`, corta el túnel unos segundos) y devuelve también los `comandos` nuevos del router; **`origen_ip`**: regenera el firewall del host. Sin cambios: `OK` «sin cambios». Devuelve `{recreado}`. Varios ajustes pendientes del mismo punto con los mismos campos se juntan en el último. CLI: `ids-orq punto ajustar <pid> [--perfil] [--hilos] [--redes] [--compat-v6 \| --sin-compat-v6] [--ros] [--origen-ip \| --sin-origen-ip]`. No cambia `api_puerto` ni las imágenes (eso es `punto.reconfigurar`) |
| `punto.reconfigurar` | `pid` | Lleva un punto ya creado a la configuración y las imágenes **actuales**: reescribe `server.conf`, `suricata.yaml` y `compose.yml` con las plantillas actuales, pasa el punto a las imágenes `vpn` y `suricata` de `imagenes.json`, recrea los contenedores y espera la salud (§8); si no queda sano, vuelve a los ficheros y las imágenes de antes y deja el motivo. Devuelve `{recreado, cambios}`. Va por la cola. CLI: `ids-orq punto reconfigurar <pid>` (el botón del panel «Aplicar la configuración actual» está pendiente). Es como reciben los puntos creados antes una corrección del servidor ([OPERACION.md](OPERACION.md) §1.6) |
| `punto.api.huella` | `pid` | lectura: abre TLS con la API-SSL del router por el relé del punto, sin verificar y sin `/login`, y devuelve `{sha256}` del certificado (para fijar la huella, que es opcional). Si el router no presenta certificado, `FALLO` «el router no presentó certificado (API-SSL sin certificado: no hay huella que fijar)». CLI: `ids-orq punto api-huella <pid>` |
| `punto.medir` | `pid` | lectura: memoria actual y pico del contenedor `suricata` (cgroup) y estadísticas de su `eve.json`. CLI: `ids-orq punto medir <pid>` |
| `logs.reabrir` | `pid?` | lectura: `reopen-log-files` por el socket de Suricata del punto (o de todos los `activo`/`error`); la usa logrotate. CLI: `ids-orq reabrir-logs [<pid>]` |
| `sistema.reconciliar` | — | cola: levanta los puntos `activo` cuyos contenedores no corren, levanta el panel si no corre y lista huérfanos; devuelve `{levantados, huerfanos}`. CLI: `ids-orq reconciliar` |
| `sistema.estado` | — | lectura: el estado global de `estado.json` sin los puntos. CLI: `ids-orq estado` |
| `punto.threshold` | `pid`, `contenido` | valida línea a línea (solo `suppress`, `threshold`, `event_filter` y comentarios; ≤ 256 KiB), escribe `/srv/ids/puntos/<pid>/suricata/threshold.config` de forma atómica (guarda el anterior en `threshold.anterior`) y recarga sin cortar el espejo (`reload-rules` por el socket de control); si la recarga falla, reinicia `suricata`; si tampoco queda sano, vuelve al anterior, reinicia y acaba `REVERTIDA` con el aviso `THRESHOLD-FALLIDO`. Varias seguidas del mismo punto: solo se aplica la última. Un punto parado no se levanta (se aplica al arrancar). Se rechaza al encolar si el punto no existe o se está dando de baja ([CONTRATO-F2](CONTRATO-F2-panel.md) §6) |
| `reglas.actualizar` | — | descarga, validación y reinicio en serie ([INSTANCIA.md](INSTANCIA.md) §11.1) |
| `sistema.capacidad` | — | RAM, CPU, disco y cuántos puntos caben por perfil |
| `op.estado` | `op_id` | progreso |
| *reservada* `acceso.aplicar` / `acceso.confirmar` | (diseño: `redes_gestion[]` (SSH), `ips_proxy[]` (panel), `proxy_actual`, `puertos_vpn[{puerto, origen?}]`, `ventana_s` / `token`) | **sin implementar**: contesta «no disponible». El acceso se cambia volviendo a ejecutar `install.sh` (con su modo seguro) o, desde la consola, `ids.conf` + `ids-orq fw-render --aplicar` ([OPERACION.md](OPERACION.md) §4; diseño en [RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) §10) |
| `sistema.actualizar` | `commit` (7–40 hex en minúsculas, de `main`) | cola. Es el botón «Actualizar» del panel ([ACTUALIZACIONES.md](ACTUALIZACIONES.md) §4.1). Deja el pedido en `/srv/ids/estado/actualizar-pedido.json` (0600: `commit`, `quien`, `op_id`) y arranca `ids-actualizar.service` (`systemctl start --no-block`). Acaba al lanzarla y pausa la cola hasta que la unidad termina. La unidad lleva el panel y el orquestador a ese commit, con respaldo y vuelta atrás, sin tocar los puntos; su avance va a `/srv/ids/run/actualizacion.json`. `FALLO` si el servidor no tiene el script o la unidad; `CONFLICTO` si ya hay una en curso. Devuelve `{commit, unidad}`. CLI: `ids-orq actualizar <commit>` |
| *reservada* `sistema.buscar_actualizacion` / `sistema.revertir` | (diseño: `version`, `canario` / `objetivo`, `pid?`) | **sin implementar**: lo nuevo de `main` lo busca el panel en GitHub, y la vuelta atrás de `sistema.actualizar` es automática. Para releases firmadas: `install.sh` y, punto por punto, `punto.reconfigurar` (diseño en [ACTUALIZACIONES.md](ACTUALIZACIONES.md) §4.2) |
| *reservada* `sistema.respaldar` | (diseño: `incluir_eventos`) | **sin implementar** (§11.4; lo que se respalda hoy, [OPERACION.md](OPERACION.md) §3.1) |
| *reservada* `bitacora.anclar` | (diseño: `cabezas`, global y por punto: hash y número de filas) | **sin implementar** ([DATOS.md](DATOS.md) §7) |

## 6. Idempotencia

- **`orq.db` guarda `op_id → (orden, sha256(params), resultado)` durante 30 días:**
  - el mismo `op_id` con los mismos parámetros devuelve el resultado guardado;
  - el mismo `op_id` con otros parámetros devuelve `CONFLICTO`.
  - **El resultado se guarda sin secretos.** Repetir el mismo `op_id` devuelve los comandos sin la
    clave VPN. Un `punto.crear` nuevo de un punto que ya existe («ya existe», `ya_entregada`) y
    `punto.comandos` los dan con la clave puesta si el orquestador la tiene cifrada y es la vigente
    (2026-10-16); si no, con `<CLAVE-VPN>` (para una nueva, `punto.vpn.regenerar`).
  - Al borrar un punto se eliminan sus filas (§11.2). Las órdenes de ese punto que esperaban en la
    cola **se cancelan**: `op.estado` las da `terminada` con código `CANCELADA` (sin parámetros) y
    quedan en `orq.jsonl`; nunca se ejecutan, y como los `pid` no se reutilizan, nada alcanza a un
    punto creado después.
- **Las órdenes son idempotentes por diseño:**
  - crear lo que ya existe igual devuelve `OK "ya existe"`; si existe distinto, `CONFLICTO`;
  - parar lo parado devuelve `OK`;
  - borrar lo inexistente devuelve `OK "no existía"`.
- **El panel genera el `op_id` antes de llamar** y lo guarda en `operacion`. Si el panel se
  reinicia a mitad, consulta `op.estado` en lugar de reenviar la orden.

## 7. Asignación y admisión

- **Todo se guarda en `orq.db` antes de crear nada**, para que la orden se pueda reejecutar: `N`,
  el puerto, la red Docker y el `cluster-id`.
- **Comprueba que el puerto está libre en el host.** Si no lo está, responde `CONFLICTO_PUERTO` y
  el panel propone el siguiente `N`.
- **Admisión de RAM** con la fórmula de [INSTANCIA.md](INSTANCIA.md) §10.3. Se aplica en
  `punto.crear` y en `punto.ajustar` cuando sube el perfil (más reserva, `mem_reservation`; sin
  tope duro desde 2026-10-16) o los hilos.

## 8. Supervisión y estado publicado

- **Cada 15 s** escribe `/srv/ids/run/estado.json` de forma atómica (temporal y `rename`). Contiene,
  por punto:
  - el estado de los contenedores y su salud;
  - si el cliente VPN está conectado, desde cuándo y desde qué IP;
  - las reglas cargadas y el estado de los netns;
  - la cola.

  El panel lo lee en solo lectura y no llama al orquestador para pintar la pantalla Puntos.
- **Netns:** ante cada `start` de un `vpn` y cada 30 s, compara los inodos de `ns/net` del `vpn` y
  del `suricata` de cada punto. Si difieren, reinicia `suricata` ([INSTANCIA.md](INSTANCIA.md) §9).
- **Docker no reinicia por `unhealthy`.** El orquestador reinicia con espera creciente (30 s,
  2 min, 10 min). A partir de 3 reinicios en una hora, deja el contenedor como está, pasa el punto
  a `error` y avisa.
- **`error` dice por qué y se cura.** `estado.json` publica `paso_error` (el motivo, hasta 300
  caracteres) y `error_desde` (epoch del primer paso a `error`); los dos son `null` en cualquier
  otro estado. Si un punto en `error` (deseado activo) tiene sus dos contenedores `healthy` durante
  3 min seguidos, vuelve a `activo` y queda en `orq.jsonl` como `supervision.curado`.
- **Cliente VPN:** `vpn_cliente.viejo` es `true` si `openvpn-status.log` lleva más de 45 s sin
  reescribirse (OpenVPN lo reescribe cada 10 s); entonces `conectado` es `false` diga lo que diga.
- **Espera a la salud** (alta, arrancar, reiniciar, ajustar): `max(300 s, 2 × duración del
  suricata -T de esa orden + 90 s)`, o 300 s si la orden no pasó por un -T. Si al vencer los
  contenedores siguen `running` en `starting` (Suricata cargando reglas), la orden **no se deshace**:
  acaba OK con el aviso «Suricata sigue cargando reglas; la supervisión lo vigila». Si alguno está
  `exited`, `dead` o `unhealthy`, falla, y antes de deshacer (o de dejar el punto en `error`) las
  últimas 40 líneas de `docker logs` de cada contenedor van al log de la orden (`log_tail`), con
  prefijo `[vpn]`/`[suricata]` y sin las líneas que mencionan password o key.
- **Imágenes:** el alta comprueba en «validar» que las dos imágenes están en el Docker local
  (`docker image inspect`) y, si falta alguna, falla diciendo qué `docker pull` hacer. Ningún
  `docker run`/`docker create`/`compose up` del orquestador descarga nada (`--pull never`).
- **Lo deseado frente a lo observado:** un punto `pausado` no se levanta.
- **Salud funcional:** espejo que no llega a Suricata, o punto activo sin espejo.
- **Logs sin reabrir.** Un Suricata `healthy` al que le falta `eve.json` o `dns.json` sigue
  escribiendo en el rotado: el `postrotate` de logrotate no pudo pedir `reopen-log-files`, por
  ejemplo porque el orquestador se reiniciaba en ese segundo. Sin reabrir, el punto no vuelve a
  rotar y el rotado crece hasta llenar el disco. La supervisión le pide `reopen-log-files` como
  mucho una vez por minuto y punto, y lo anota en `orq.jsonl` como `supervision.reabrir_logs`
  (con `faltan` y `resultado`). Con el timer de logrotate cada 5 min ya no hay una hora de rotación
  que evitar al cargar o al actualizar.

### 8.1 Retención de los eventos (CONTRATO-F2 §9)

- **Objetivo: 30 días** de `eve.json` y `dns.json` por punto. logrotate rota por tamaño (100 MB,
  mirado cada 5 min, para que un rotado quepa en lo que Eventos descomprime por fichero) con
  nombre fechado (`eve.json-AAAAMMDD-HHMMSS`) y **sin tope de número** (`rotate -1`, sin `maxage`).
- **Compresión:** la hace el orquestador (hilo aparte, cada minuto) con los rotados que llevan 2 min
  sin escribirse: `.gz` atómico que **conserva el mtime** (= su último evento), el dueño y el modo.
  Eventos y el generador del panel saltan ficheros por mtime. **Nunca pisa un `.gz` que ya existe:**
  logrotate fecha el nombre en hora local y, si el reloj de pared retrocede (cambio de zona horaria
  del host, ajuste de NTP), repite nombres; el nuevo se guarda entonces como
  `eve.json-AAAAMMDD-HHMMSS-2.gz`, `-3.gz`…, que la poda, la retención y Eventos tratan como a los demás.
- **Poda por fecha** (al arrancar y cada 24 h): se borra un rotado cuando su última escritura posible
  (la más tardía entre la fecha del nombre y el mtime) tiene más de 30 días. Una línea `poda.fecha`
  por punto en `orq.jsonl`.
- **Poda por disco** (cada 15 s, si `/srv/ids` baja del 15 % libre): se borran los rotados más viejos
  de **cualquier** punto, de uno en uno, hasta recuperar el umbral; nunca los vivos. Cada borrado
  queda en `orq.jsonl` (`poda.disco` con `pid`, `fichero`, `cota`, `libre_pct`) y marca el punto en
  `/srv/ids/estado/retencion.json`; durante 30 días su `estado.json` lleva `retencion.anticipado`
  y el aviso `RETENCION-REDUCIDA`. El aviso `DISCO` sigue mientras el disco esté bajo el umbral.
- **Retención efectiva** publicada por punto en `estado.json` (`retencion`: `objetivo_dias`, `desde`,
  `dias`, `anticipado`, `ultimo_anticipado`): `desde` es el primer evento del fichero más
  viejo que queda. Nunca se promete el objetivo si hubo borrado anticipado.

## 9. Avisos aunque el panel esté caído (diseño, **sin implementar**)

> **Estado real:** no existe. `install.sh` crea `/etc/ids-maat/avisos.conf` vacío (0600) y el
> orquestador no lo lee ni manda nada por Telegram. Lo de abajo es el diseño pendiente.

El orquestador tendrá su propio canal de avisos: Telegram directo, con el token en
`/etc/ids-maat/avisos.conf` (0600), que se configura al instalar. Avisará de:

- el panel caído o sin responder a `/salud`;
- un punto en `error`;
- un OOM;
- el disco por encima del umbral;
- un respaldo fallido;
- una reversión del modo seguro;
- una actualización revertida.

## 10. Diario

- **`orq.jsonl` solo crece.** Por cada orden guarda el `op_id`, quién la pidió, el `pid` si lo
  hay, el **`sha256` de los parámetros (nunca los parámetros en claro)**, los pasos y el resultado
  sin secretos. También guarda las órdenes canceladas por una baja y las podas de eventos
  (`poda.fecha`, `poda.disco`, §8.1). Los anclajes de la bitácora irían aquí, pero
  `bitacora.anclar` es una orden reservada, sin implementar. Así, cuando se borra un punto, en este
  diario no queda ningún dato suyo (redes, IP), solo las líneas técnicas ([DATOS.md](DATOS.md) §8).
- **Rota con logrotate** ([INSTANCIA.md](INSTANCIA.md) §10.5), con una retención de 2 años, como la
  bitácora.
- **La pantalla Bitácora del panel** une la bitácora y el diario por `op_id`.

## 11. Flujos de ciclo de vida

Notación: **[B]** = el paso se registra en la bitácora; **[O]** = es una orden al orquestador. La
parte de pantalla del asistente está en [PLAN-PANEL.md](PLAN-PANEL.md) §9, y los comandos del
MikroTik en [OPERACION.md](OPERACION.md).

### 11.1 Alta

| # | Paso | Estado | Errores y qué se hace |
|---|---|---|---|
| 1 | El operador da el nombre, `redes_abonados`, RouterOS (6.49 o superior, o v7), el perfil (**`reducido` por defecto**) y, opcionalmente, la IP pública. Se muestra la capacidad. | `borrador` | Nombre repetido. CIDR inválido. Solape con la base de túneles, el pool de Docker o las redes de gestión. El perfil no cabe. |
| 2 | Transacción en el panel: `N` libre más bajo y derivación de túnel, IP y puerto. **[B] PUNTO-RESERVA** | `reservado` | Sin `N` libres: se dice cuándo se liberan. Dos altas a la vez no pueden coger el mismo `N` (`UNIQUE`). |
| 3 | **[O] `punto.crear`**: admisión, certificado de servidor, usuario VPN (hash), ccd, `suricata.yaml` completo, threshold, compose, `up -d`, espera a la salud **de los procesos** (no del espejo) y puerto en `@puertos_vpn`. | `creando` | Fallo parcial: se **deshace** todo (contenedores, volúmenes, certificado, puerto) y se devuelve el paso. El punto vuelve a `reservado` con `paso_error`, y «Reintentar» usa un `op_id` nuevo. |
| 4 | Comandos del MikroTik, en bloques v7 y v6 separados: CA del VPS (pública) y `ovpn-client` con `verify-server-certificate=yes`, y nada más: el usuario de la API, si se quiere usar, lo crea a mano el operador ([OPERACION.md](OPERACION.md) §1.2). Sin certificado de la API-SSL: el script no toca `/ip service api-ssl`, que se usa tal como esté ([OPERACION.md](OPERACION.md) §1.1). Sin reglas de firewall ni rutas: el firewall y las rutas del router los gestiona el operador ([OPERACION.md](OPERACION.md) §1.5). Los comandos salen con la clave VPN puesta. | `esperando_vpn` | «Ver comando» (`punto.comandos`) los vuelve a dar con la clave si el orquestador la tiene cifrada y es la vigente; si no, con `<CLAVE-VPN>`. «Regenerar credencial» invalida la anterior. |
| 5 | Indicador en vivo con `estado.json`: «Conectado desde 203.0.113.45». **[B] VPN-CONECTADA** | `→ esperando_api` | Sin conexión en 30 min: diagnóstico (puerto alcanzable desde fuera, usuario rechazado en el log, handshake TLS fallido en 6.49 → «compatibilidad v6», IP baneada por fail2ban). |
| 6 | **API-SSL:** usuario, clave y «Probar». **Primera conexión:** sin huella fijada, el panel hace `/login` con lo que presente el router, con certificado o sin él: primero prueba el cifrado anónimo (`ADH:@SECLEVEL=0`, router con `certificate=none`) y después los normales, y la clave de `ids-api` va protegida por el túnel (decisión del dueño, 2026-10-15; [OPERACION.md](OPERACION.md) §1.1). **Huella opcional:** si el router presenta un certificado, la ficha muestra su huella SHA-256 para compararla con el `fingerprint` de `/certificate print detail` y, al confirmar («La huella coincide: confirmar»), la fija; desde entonces exige ese certificado (ya no prueba el cifrado anónimo) y, con otro, no manda la clave. Sin certificado no hay huella que fijar. Se guardan `identidad`, `sw_id` y `version_ros`, con la clave cifrada. `envio_habilitado = 0`. Revisión de CGNAT ([RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) §6). **[B] API-ALTA** | `→ esperando_espejo` | **Timeout:** el firewall del router no deja entrar la API desde el sensor por `ids-vpn` (lo añade el operador, [OPERACION.md](OPERACION.md) §1.5). **Conexión cortada al instante:** `/ip service api-ssl` tiene un `address=` sin `100.64.N.1`, y se muestra el comando para añadirla conservando la lista; **el panel no toca esa lista**. En un router dado de alta con el script anterior, si la API-SSL corta nada más conectar («TLS handshake falló … EOF»), se revisa el servicio y, si tiene un certificado asignado, se deja sin él ([OPERACION.md](OPERACION.md) §1.1). **RouterOS anterior a 6.49:** se rechaza, porque no está soportado. En cualquier error **no se guarda nada**. |
| 7 | **Espejo, a mano** (desde 2026-10-16): lo monta el operador en su MikroTik ([OPERACION.md](OPERACION.md) §2); la ficha ya no tiene vista previa ni «Aplicar». Hasta entonces, el generador único producía los comandos exactos (address-list, dos mangle y el ajuste del fasttrack sin ningún `accept`) y se guardaban el plan y su sha256. | `esperando_espejo` | — |
| 8 | **Aplicar** (hasta 2026-10-16; ya no existe): el POST llevaba `plan_sha` y el plan **se regeneraba**; si el hash no coincidía, se rechazaba y se mostraba el nuevo. Después: respaldo del firewall del router (si fallaba, no se tocaba nada), aplicación y **[B] ESPEJO-APLICADO** con los sha. | `esperando_espejo` | Si fallaba a mitad, se quitaba todo lo que llevaba `ids-maat:<pid>` y se informaba. El respaldo no se restauraba solo. |
| 9 | **Verificación** (hasta 120 s): llegan paquetes desde `ip_mk` y hay eventos con `host == pid`. Se calculan los Mbps y el desperdicio. **[B] ESPEJO-VERIFICADO** | `→ activo` | Contador mangle a 0: no hay tráfico. Contador mayor que 0 sin llegada: túnel o ruta. Desperdicio mayor del 50 %: falta el recorte. El punto queda `activo` con aviso. |

### 11.2 Baja

Decisión del dueño (ARQUITECTURA §10 b): **la baja lo borra todo.** El detalle de qué se borra
está en [DATOS.md](DATOS.md) §8. No hay botón «Purgar» ni retención posterior.

1. **Confirmación fuerte.** El operador tiene que escribir el nombre del punto. La pantalla avisa,
   antes de confirmar:
   - de que se borrarán **todos** los datos del punto (alertas, eventos, cuarentenas, públicas,
     exclusiones, bitácora del punto, VPN y certificado) y de que no se puede deshacer;
   - de cuántas cuarentenas vivas hay en el router;
   - de si hay API: con API se retiran del router; sin API, quedan allí.

   `→ dando_de_baja`.
2. **Router, si hay API** (lo hace el panel, en segundo plano, antes de encolar `punto.borrar`; si
   no termina bien, la baja no sigue):
   - saca de las address-lists del router las IPs que puso el panel (cuarentenas y destinos
     bloqueados);
   - **retira el espejo** con su respaldo previo ([OPERACION.md](OPERACION.md) §2): `ids-vigilados`,
     los dos mangle, los dos fasttrack de los vigilados, y la regla fasttrack del operador recupera
     sus valores originales.

   **Nada más.** Lo del alta queda en el router, porque es el camino por el que el panel habla con
   él: la interfaz `ids-vpn` y la CA del VPS con su fichero, el usuario y el grupo `ids-api` si
   el operador los creó y, en un router dado de alta con el script anterior, la ruta blackhole y
   el bloque de aislamiento de `ids-vpn` en `filter`. Se quita a mano tras la baja con el bloque «terminar una baja con API» de [OPERACION.md](OPERACION.md) §2.1
   (todo menos el espejo), mejor antes de que acabe el enfriamiento de `N` (7 días, VPN-12). **La
   API-SSL del router no se toca**: el script actual no crea ningún certificado, y el `ids-promax`
   de un router dado de alta con el script anterior puede usarlo otro servicio del router (si
   ninguno lo usa, se borra a mano, [OPERACION.md](OPERACION.md) §1.1).
3. **Router, si no hay API:** aviso explícito de que esas entradas quedan en el router (las
   cuarentenas, hasta que alguien las quite; las reglas, igual) y entrega de los comandos de
   [OPERACION.md](OPERACION.md) §2.1 para quitarlo todo, espejo incluido.
4. **[O] `punto.borrar`**:
   - `down` y borrado de la red;
   - borrado de los directorios `puntos`, `datos`, `run` y `ctl` del punto;
   - borrado de la clave y el certificado de servidor y del usuario VPN (no hay CRL);
   - el puerto sale de `@puertos_vpn`;
   - borrado de sus filas en `orq.db`, salvo el enfriamiento de `N`.
5. **Panel:** cuando el orquestador confirma, borra todas las filas con ese `punto_id` en
   `estado.db`, `eventos.db` y `bitacora.db` (la cadena del punto), más `reportes/<pid>/` y
   `respaldos/<pid>/`. Cada base se borra en una sola transacción.
6. **Bitácora global:** una única línea, «punto pNNN (nombre) eliminado por <usuario> <fecha>».
   El `punto_id` no se reutiliza nunca. `N` y el puerto quedan libres a los 7 días.

**Si algo falla a mitad**, el punto queda en `dando_de_baja` con el paso que falló y «Reintentar».
Todos los pasos son idempotentes: borrar lo ya borrado devuelve `OK`.

### 11.3 Pausa, reanudación y reinicio

- **Pausar:**
  1. El espejo del router no se toca: desde 2026-10-16 lo monta (y lo pausa, si quiere) el
     operador a mano ([OPERACION.md](OPERACION.md) §2).
  2. **[O] `punto.parar`** con `estado_deseado = pausada`.
  3. La política automática del punto se suspende. Las cuarentenas vivas siguen hasta su TTL.
  **[B]**
- **Reanudar:** **[O] `punto.arrancar`** → espera a la salud (si el operador pausó el espejo, lo
  reactiva él en su router) → se verifica como en 11.1-9.
- **«Reintentar arranque»** (ficha del punto) encola el mismo `punto.arrancar`: `compose up -d` y,
  antes de esperar la salud, se reinician de verdad los contenedores que están `running` pero
  `unhealthy` (o `restarting`), porque un `compose up` solo no los tocaría y la espera vencería con
  el punto igual de roto. La `vpn` se reinicia con `docker restart` y, detrás, siempre `suricata`
  (comparte su netns); `suricata` con `docker restart` y, solo si ese restart falla,
  `--force-recreate`.
- **Reiniciar:** **[O] `punto.reiniciar {parte}`**.
  - El orden es siempre primero el `vpn` y después `suricata`.
  - Antes se avisa de que serán 30–90 s sin captura.
  - Espera a la salud con el límite de §8 («Espera a la salud»). Si no queda sano, las últimas 40
    líneas de `docker logs` de cada contenedor van al log de la orden y, **si lo pidió una
    persona** (panel o CLI), el punto pasa a `error` con el motivo (`paso_error`). Un reinicio de la
    supervisión (quien empieza por `orq:`) no lo pasa a `error` por sí solo: eso lo decide la regla
    de 3 reinicios en 1 h de §8. Lo mismo vale para `punto.arrancar` y `punto.ajustar`.

### 11.4 Respaldo diario (diseño, **sin implementar**)

> **Estado real (auditoría B-05):** no existe. `sistema.respaldar` es una orden reservada y no hay
> timer; lo que se respalda hoy y el procedimiento manual están en [OPERACION.md](OPERACION.md) §3.
> Lo de abajo es el diseño pendiente.

Un timer del orquestador hará cada día un respaldo en `/root/backups/ids-maat-diario-<fecha>.tar.gz`:

- **Qué incluye:** `estado.db`, `bitacora.db` y `orq.db` (con `setpriv`, [DATOS.md](DATOS.md) §1.1),
  más la PKI, `/srv/ids/puntos` y `/srv/ids/panel`; **nunca** `master.key` (se respalda aparte).
- **Permisos y retención:** 0600, con una retención configurable (14 días por defecto).
- **Verificación:** `tar -tzf` y sha256. Si falla, se avisa por el canal propio (§9).
- **Copia fuera del VPS y recuperación:** [OPERACION.md](OPERACION.md) §3.
