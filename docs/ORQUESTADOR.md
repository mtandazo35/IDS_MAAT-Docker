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
- `systemd-run`, para la reversión del modo seguro.

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
- **Las lecturas no se encolan:** `punto.estado`, `punto.logs`, `op.estado` y
  `sistema.capacidad`.
- Una orden larga, como `sistema.actualizar`, retiene la cola hasta que termina. El panel muestra
  «en cola detrás de X».

## 5. Órdenes fijas

No hay ninguna orden genérica de «ejecutar».

| Orden | Parámetros (lista blanca) | Hace / devuelve |
|---|---|---|
| `punto.crear` | `pid` `^p\d{3}$`, `n` 1–250, `redes_abonados` CIDR[≤64], `ros_version` 6/7, `perfil`, `hilos` 1–2, `tls_legacy`, `api_puerto` 8729/8728, `origen_ip?` | §11.1. Devuelve los comandos v6/v7 y la clave VPN (una sola vez) |
| `punto.borrar` | `pid` | borrado total del lado del host (§11.2, [DATOS.md](DATOS.md) §8) |
| `punto.arrancar` / `punto.parar` / `punto.reiniciar` | `pid`, `parte` ∈ {vpn, suricata, todo} | `observado` |
| `punto.estado` | `pid` o `*` | lo observado (sin encolar) |
| `punto.logs` | `pid`, `parte`, `lineas` ≤ 500 | líneas filtradas (`password`, `key`) |
| `punto.vpn.regenerar` | `pid` | hash nuevo, desconexión por management y la clave una sola vez |
| `punto.ajustar` | `pid`, `perfil?`, `hilos?`, `home_net?`, `tls_legacy?` | admisión, yaml completo nuevo, `-T` y recreación de lo afectado |
| `punto.threshold` | `pid`, `contenido` | se agrupa (≤ 1 vez cada 15 min), se valida y se reinicia `suricata` ([INSTANCIA.md](INSTANCIA.md) §11.2) |
| `reglas.actualizar` | — | descarga, validación y reinicio en serie ([INSTANCIA.md](INSTANCIA.md) §11.1) |
| `acceso.aplicar` / `acceso.confirmar` | `redes_gestion[]` (SSH), `ips_proxy[]` (panel), `proxy_actual`, `puertos_vpn[{puerto, origen?}]`, `ventana_s` (por defecto 300) / `token` | modo seguro ([RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) §10) |
| `sistema.capacidad` | — | RAM, CPU, disco y cuántos puntos caben por perfil |
| `sistema.buscar_actualizacion` / `sistema.actualizar` / `sistema.revertir` | `version`, `canario` / `objetivo`, `pid?` | [ACTUALIZACIONES.md](ACTUALIZACIONES.md) |
| `sistema.respaldar` | `incluir_eventos` | `{ruta, sha256}` |
| `bitacora.anclar` | `cabezas` (global y por punto: hash y número de filas) | lo escribe en `orq.jsonl` ([DATOS.md](DATOS.md) §7) |
| `op.estado` | `op_id` | progreso |

## 6. Idempotencia

- **`orq.db` guarda `op_id → (orden, sha256(params), resultado)` durante 30 días:**
  - el mismo `op_id` con los mismos parámetros devuelve el resultado guardado;
  - el mismo `op_id` con otros parámetros devuelve `CONFLICTO`.
  - **El resultado se guarda sin secretos.** Repetir un `punto.crear` ya ejecutado devuelve los
    comandos sin la clave VPN («ya entregada»; para una nueva, `punto.vpn.regenerar`).
  - Al borrar un punto se eliminan sus filas (§11.2).
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
  `punto.crear` y en `punto.ajustar` cuando sube el perfil.

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
- **Lo deseado frente a lo observado:** un punto `pausado` no se levanta.
- **Salud funcional:** espejo que no llega a Suricata, o punto activo sin espejo.

## 9. Avisos aunque el panel esté caído

El orquestador tiene su propio canal de avisos: Telegram directo, con el token en
`/etc/ids-maat/avisos.conf` (0600), que se configura al instalar. Avisa de:

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
  sin secretos. También guarda los anclajes de la bitácora. Así, cuando se borra un punto, en este
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
| 4 | Comandos del MikroTik, en bloques v7 y v6 separados: `ovpn-client`, blackhole, certificado API-SSL `ids-promax` (se reutiliza si ya existe), usuario API y regla de entrada ([OPERACION.md](OPERACION.md) §1). La clave VPN se muestra **una sola vez**. | `esperando_vpn` | «Ver comando» los vuelve a mostrar sin la clave. «Regenerar credencial» invalida la anterior. |
| 5 | Indicador en vivo con `estado.json`: «Conectado desde 203.0.113.45». **[B] VPN-CONECTADA** | `→ esperando_api` | Sin conexión en 30 min: diagnóstico (puerto alcanzable desde fuera, usuario rechazado en el log, handshake TLS fallido en 6.49 → «compatibilidad v6», IP baneada por fail2ban). |
| 6 | **API-SSL:** usuario, clave y «Probar». **Primera conexión (TOFU):** el panel muestra la huella SHA-256 del certificado `ids-promax` para compararla con `/certificate print detail` y, al confirmar, la fija; desde entonces rechaza cualquier otro certificado. Se guardan `identidad`, `sw_id` y `version_ros`, con la clave cifrada. `envio_habilitado = 0`. Revisión de CGNAT ([RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) §6). **[B] API-ALTA** | `→ esperando_espejo` | **Timeout:** falta la regla de entrada del router. **Conexión cortada al instante:** `/ip service api-ssl` tiene un `address=` sin `100.64.N.1`, y se muestra el comando para añadirla conservando la lista; **el panel no toca esa lista**. **Sin certificado (ADH):** se muestra el bloque de `ids-promax`. **RouterOS anterior a 6.49:** se rechaza, porque no está soportado. En cualquier error **no se guarda nada**. |
| 7 | **Vista previa del espejo:** el generador único produce los comandos exactos (address-list, dos mangle y el ajuste del fasttrack sin ningún `accept`). Se guardan el plan y su sha256. | `esperando_espejo` | — |
| 8 | **Aplicar:** el POST lleva `plan_sha` y el plan **se regenera**; si el hash no coincide, se rechaza y se muestra el nuevo. Después: respaldo del firewall del router (si falla, no se toca nada), aplicación y **[B] ESPEJO-APLICADO** con los sha. | `esperando_espejo` | Si falla a mitad, se quita todo lo que lleva `ids-maat:<pid>` y se informa. El respaldo no se restaura solo. |
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
2. **Router, si hay API:**
   - un respaldo del firewall **en el propio router** (`/export file=ids-maat-baja-<pid>`), para
     que no quede nada en el VPS;
   - se retira todo lo que lleva `ids-maat:<pid>`: las cuarentenas vivas, `ids-vigilados`, los
     mangle del espejo, los dos fasttrack de los vigilados, la regla de entrada de la API y la ruta
     blackhole; y la regla fasttrack del operador recupera sus valores originales (del respaldo);
   - se entregan los comandos para quitar el `ovpn-client` y el usuario `ids-api`, que el panel no
     borra porque los usa para hablar con el router. **El certificado `ids-promax` no se toca**:
     puede usarlo otro servicio del router.
3. **Router, si no hay API:** aviso explícito de que esas entradas quedan en el router (las
   cuarentenas, hasta su TTL; las reglas, hasta que alguien las quite) y entrega de los comandos de
   [OPERACION.md](OPERACION.md) §2.1.
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
  1. Se deshabilita el mangle del espejo en el router (activado por defecto).
  2. **[O] `punto.parar`** con `estado_deseado = pausada`.
  3. La política automática del punto se suspende. Las cuarentenas vivas siguen hasta su TTL.
  **[B]**
- **Reanudar:** **[O] `punto.arrancar`** → espera a la salud → se reactiva el mangle → se verifica
  como en 11.1-9.
- **Reiniciar:** **[O] `punto.reiniciar {parte}`**.
  - El orden es siempre primero el `vpn` y después `suricata`.
  - Antes se avisa de que serán 30–90 s sin captura.
  - Si a los 180 s no está sano, el punto pasa a `error` con las últimas 50 líneas del log.

### 11.4 Respaldo diario

Un timer del orquestador hace cada día un respaldo en `/root/backups/ids-maat-diario-<fecha>.tar.gz`:

- **Qué incluye:** `estado.db`, `bitacora.db` y `orq.db` (con `setpriv`, [DATOS.md](DATOS.md) §1.1),
  más la PKI y `/srv/ids/puntos`.
- **Permisos y retención:** 0600, con una retención configurable (14 días por defecto).
- **Verificación:** `tar -tzf` y sha256. Si falla, se avisa por el canal propio (§9).
- **Copia fuera del VPS y recuperación:** [OPERACION.md](OPERACION.md) §3.
