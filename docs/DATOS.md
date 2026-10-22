# Datos e identidad

Anexo de [ARQUITECTURA.md](ARQUITECTURA.md). Este anexo cubre:

- los almacenes y las entidades;
- la regla `(punto_id, ip)`;
- las retenciones;
- los secretos cifrados y la auditoría.

## 1. Almacenes

| Almacén | Contenido | Por qué así |
|---|---|---|
| `estado.db` (SQLite, WAL) | configuración, puntos, instancias, MikroTik, usuarios, roles, sesiones, abonados, cuarentenas, exclusiones, públicas, operaciones | transacciones y `UNIQUE(punto_id, ip, …)` en lugar de unos 40 JSON con cerrojos a mano; es pequeña y se respalda rápido |
| `eventos.db` (SQLite, WAL) | alertas, agregados por hora y por día, offsets de ingesta, espejo por hora | es grande y se puede reconstruir desde los eve; va aparte para podar sin bloquear el estado |
| `bitacora.db` (SQLite, WAL, solo se añaden filas) | auditoría e intentos de login | retención larga y cadena de hashes |
| `eve.json` / `dns.json` por instancia | eventos crudos | fuente de verdad del crudo; solo se agrega lo que el panel consulta |
| Ficheros de intercambio | `threshold.config` por punto, exportaciones, respaldos `.rsc` de los routers | los consumen procesos que no leen SQLite |
| `orq.db` (host) | asignaciones, digests, cola de órdenes, `op_id` | estado propio del orquestador ([ORQUESTADOR.md](ORQUESTADOR.md)) |
| `actualizar-pedido.json` (host, `/srv/ids/estado/`, 0600) | el commit, quién y el `op_id` de la última `sistema.actualizar` | lo deja el orquestador y lo borra `ids-actualizar.sh` al leerlo ([ACTUALIZACIONES.md](ACTUALIZACIONES.md) §4.1) |
| `actualizacion.json` (host, `/srv/ids/run/`, 0640 root:ids-panel) | avance y resultado de la última actualización del panel y el orquestador: pasos, de qué commit a cuál, quién, `ok`/`revertida`/`fallo` | lo escribe `ids-actualizar.sh`; el panel lo lee para la página «Actualizando…» y Ajustes → Versión. Perderlo solo borra el «última actualización» de la tarjeta |
| `actualizacion-busqueda.json` (panel, `/srv/ids/panel/estado/`, 0600) | lo último que contestó GitHub: commits nuevos de `main`, historial y error | caché del botón «Actualizar»; se rehace sola cada 30 min |
| `alertas.json` (host, `/srv/ids/estado/`, 0600) | por punto: el último contador de alertas de Suricata (`detect.alert`) y las alertas de las últimas 24 h en cubos de 5 min | de él sale `alertas_24h` de `estado.json`; se reescribe como mucho cada minuto y, si se pierde, el recuento vuelve a empezar |

Ubicación:

| Host | Panel (`web` y `worker`) | Montaje |
|---|---|---|
| `/srv/ids/panel/` | `/data/panel/` (bases, `reportes/<pid>/`, `respaldos/<pid>/`, `cache/`) | rw |
| `/srv/ids/datos/` (padre) | `/data/puntos/datos/` → `<pid>/eve.json` | ro |
| `/srv/ids/run/` (padre) | `/data/puntos/run/` → `<pid>/api.sock`, `<pid>/tzsp.json`, `estado.json` | ro |
| `/etc/ids-maat/master.key` | `/run/secrets/master_key` | ro, fuera de `/data` |

### 1.1 Reglas de uso de SQLite

- **Ajustes:** `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`, `busy_timeout=5000`.
- **Transacciones:** una conexión por hilo, `BEGIN IMMEDIATE` y transacciones cortas. Escriben dos
  procesos (`web` y `worker`) sobre un volumen local, nunca sobre NFS ni CIFS.
- **Nunca hay una transacción abierta mientras se habla con un MikroTik.** Primero se registra la
  intención, después va la red y al final se confirma.
- **Esquema** en `PRAGMA user_version`. Las migraciones solo avanzan, una por transacción, con un
  respaldo antes de migrar.
- **Respaldo en caliente** con la API `backup` o con `VACUUM INTO`. **Nunca con `cp`.** El
  orquestador lo ejecuta como el usuario del panel:

  ```
  setpriv --reuid=10500 --regid=10500 --clear-groups python3 /usr/local/lib/ids-orq/respaldo_sqlite.py
  ```

  Si lo hiciera como root, los `-wal`/`-shm` que se creen quedarían de root y el panel dejaría de
  poder escribir.

## 2. Entidades

Ámbitos: **G** = global de la empresa; **P** = por punto; **G/P** = global con sobrescritura por
punto (`punto_id NULL` = toda la empresa).

| Entidad | Ámbito | Clave / campos clave | Notas |
|---|---|---|---|
| `empresa` | G | `id=1`, nombre, logo, zona horaria | las horas se guardan en UTC y se muestran en la zona de la empresa |
| `ajuste` / `ajuste_punto` | G / P | `clave` / `(punto_id, clave)` | política por bandas, acciones, listas y TTL, Telegram, AbuseIPDB, Groq, redes de gestión, IP del proxy, retenciones, tope de cuarentenas automáticas |
| `punto` | P (raíz) | `id` `p001…` (secuencia, **nunca se reutiliza**), `nombre` único, `n`, `red_tunel`, `ip_srv`, `ip_mk`, `puerto_vpn`, `ros_version`, `redes_abonados`, `perfil`, `hilos`, `tls_legacy`, `api_puerto`, `ip_publica_esperada`, `estado`, `fila_version` | `UNIQUE(n)` y `UNIQUE(puerto_vpn)`. El `id` sale de una secuencia monotónica (`secuencia_punto`) que no retrocede, ni siquiera tras una baja, en la que la fila se borra. `n` vuelve a estar libre 7 días después (enfriamiento en `orq.db`) |
| `instancia` | P (1:1) | `estado_deseado` (activa / pausada / borrada), digests actual y previo, `observado` | el estado real lo publica el orquestador en `estado.json` |
| `vpn_usuario` | P | `(punto_id, usuario)`, creado, rotado | el hash vive en el fichero del orquestador |
| `mikrotik` | P (1:1) | `cert_fp`, usuario, `clave_cifrada` (`enc1:`, sin `kid`: §6), `identidad`, `sw_id`, `version_ros`, listas, TTL, `envio_habilitado` (0 por defecto) | el destino es el relé del punto; no hay host configurable |
| `usuario`, `rol` | G | `login` inmutable; roles `admin` / `operador` / `lectura` | — |
| puntos que ve cada usuario | G | campo opcional `puntos` (lista de pids) de cada usuario en `conf/usuarios.json` | sin el campo, todos; lista vacía, ninguno; el rol `admin` ve siempre todos (§3.2). Desde 2026-10-22 sustituye a la tabla `visibilidad` del diseño, que nunca llegó al código |
| `sesion` | G | `token_sha256`, `csrf`, expira, ip, `punto_sel` | nunca se guarda el token |
| `abonado`, `abonado_hist` | P | `(punto_id, ip)` | el mapa se pide a cada router por separado |
| `alerta` | P | `(punto_id, ts)`, `cpe_ip`, `sid`, `dir` | en `eventos.db` |
| `resumen_hora`, `detalle_dia`, `espejo_hora` | P | `punto_id` primero en la PK | — |
| `ingesta` | P | `(punto_id, archivo_id dev:ino)`, offset, huella | incremental por inodo y posición |
| `cuarentena` | P | `(punto_id, ip, tipo)`, `estado`, `ros_id`, comentario `ids-maat:<pid>:<id>` | `UNIQUE(punto_id, ip, tipo)` entre las vivas |
| `destino` / `destino_envio` | G / P | la IP externa es global; la entrega va por punto | — |
| `exclusion`, `nunca_bloquear` | G/P | `punto_id NULL` = toda la empresa | el threshold de cada punto = las globales más las suyas |
| `publica` / `publica_rep` | P / G | `(punto_id, entrada)` / `(entrada, ts)` | la reputación de una IP pública es igual para todos |
| `bitacora`, `login_intento` | G y P | `hash = sha256(hash_prev ‖ fila)`, con **una cadena global** (`punto_id NULL`) y **una cadena por punto** | en `bitacora.db`; borrar la cadena de un punto no rompe la global (§7) |
| `operacion` | P/G | `op_id` (uuid) | une el panel con el diario del orquestador |
| Cachés de feeds, AbuseIPDB e IA | G | IP de internet | la cuota de AbuseIPDB es única por empresa |

Estados del punto (las transiciones están en [ORQUESTADOR.md](ORQUESTADOR.md) §11):

```
borrador ─► reservado ─► creando ─► esperando_vpn ─► esperando_api ─► esperando_espejo ─► activo ◄─► pausado
               ▲             │                                                                │
               └── (deshace) ┘ error ◄──────────── cualquier paso ─────────────────────────────┘
activo|pausado|error ─► dando_de_baja ─► (borrado total: no queda la fila, §8)
```

## 3. Identidad: `(punto_id, ip)`

**Regla: una IP privada sola no identifica nada.** Toda función, tabla, caché, URL y formulario que
trate un CPE recibe `CpeRef(punto_id, ip)`:

- Nunca se concatena `"r1|ip"` y no hay valor por defecto.
- `router_defecto()` desaparece. Si falta el punto, la operación falla con un error explícito.
- La forma de la clave no depende de cuántos puntos haya: con uno solo sigue siendo
  `("p001", "10.0.0.5")`.

### 3.1 De dónde sale el punto de un evento

1. **De la carpeta.** El worker recorre `/data/puntos/datos/<pid>/` y asigna el punto por la ruta.
   Cada volumen solo lo monta en rw el Suricata de ese punto.
2. **Comprobación con `host`.** Cada instancia arranca con `sensor-name: <pid>`.
   - `host == pid`: la línea se acepta.
   - Falta `host`: se acepta con aviso.
   - `host` distinto: **se descarta la línea**, se cuenta en `ingesta_rechazos` y se avisa en
     Puntos y en la bitácora con el código **`EVE-MEZCLA`**.
3. **`cpe_ip`** se calcula con las `redes_abonados` **de ese punto**, nunca con una lista global.
4. **`in_iface` ya no identifica nada:** en todas las instancias vale `ids-mon`.
5. **El estado del receptor** (`tzsp.json`) sigue la misma regla de la ruta.

### 3.2 Cómo se evita la mezcla, sitio por sitio

- **Base de datos:** `punto_id NOT NULL` es la primera columna de cada PK y de cada índice por
  punto, con FK a `punto`.
- **Repositorio:** las consultas por punto solo se hacen con `repo.para(alcance)`. La vista «Toda
  la empresa» es `alcance = puntos_visibles`, nunca una consulta sin filtro. Llamar sin alcance
  lanza `AlcanceRequerido`.
- **Puntos que ve cada usuario** (decisión del dueño, 2026-10-22). Cada usuario de
  `conf/usuarios.json` puede llevar el campo `puntos`, una lista de pids:

  | `puntos` | Ve |
  |---|---|
  | sin el campo | todos los puntos (los usuarios de antes siguen igual) |
  | `["p001", "p003"]` | solo esos |
  | `[]`, o un valor que no es una lista | ninguno: el panel le contesta «Sin puntos asignados» |
  | cualquiera, con rol `admin` | todos |

  El panel lee el usuario en cada petición y pone su alcance en el hilo de esa petición
  (`nodos.poner_alcance`). Desde ahí, las funciones comunes de `nodos.py` (`puntos()`, `pids()`,
  `existe()`, `exigir_pid()`, `validar_nodo()`, las rutas por punto y `dir_salida()`) dejan fuera
  los puntos ajenos: para ese usuario no existen (404). Tampoco puede pedir la vista «Toda la
  empresa», porque sus ficheros mezclan todos los puntos. Un cambio en la lista vale en la
  siguiente petición, sin cerrar la sesión. Los hilos de fondo no tienen alcance y trabajan con
  todos los puntos.
- **Cachés:** las claves son `(punto_id, …)` y se invalidan por punto. Las de IP externas van en
  otro módulo.
- **Reportes:** se generan por punto. El de empresa se calcula desde la base con una columna Punto.
  Nunca se fusionan HTML.
- **Formularios:** cada fila lleva su `punto_id` oculto y explícito. Nunca se toma del selector
  global.
- **Address-lists:** el comentario es `ids-maat:<pid>:<id>`. La reconciliación de un punto solo
  mira su prefijo.
- **Telegram y bitácora:** siempre llevan el nombre y el id del punto.
- **Abonados:** una IP sin abonado en su punto se queda sin nombre. No se busca en otro punto.
- **Antes de escribir en un router**, el cliente compara `identidad` y `sw_id` con los guardados en
  el alta. Si no coinciden, rechaza la acción con `ROUTER-NO-COINCIDE` y el punto pasa a `error`.

## 4. Qué es global y qué es por punto

| Global de la empresa | Por punto | Global con sobrescritura por punto |
|---|---|---|
| empresa, usuarios, roles, puntos que ve cada usuario, sesiones | punto, instancia, VPN, MikroTik | política automática |
| redes de gestión, IP del proxy y acceso | abonados y su historial | acciones por categoría |
| feeds, AbuseIPDB (cuota), Groq, Telegram | alertas, agregados, espejo, ingesta | listas y TTL |
| reputación de IP públicas, destinos malos (la IP) | cuarentenas, entrega de destinos | exclusiones, nunca bloquear |
| bitácora global (incluida la línea de cada baja) | IP públicas declaradas, reportes, bitácora del punto | tope de cuarentenas automáticas por hora |

## 5. Retenciones

| Dato | Retención | Mecanismo |
|---|---|---|
| `eve.json`, `dns.json` | **30 días por fecha** (CONTRATO-F2 §9); antes si `/srv/ids` baja del 15 % libre, empezando por los rotados más viejos de cualquier punto, con cada borrado registrado y la retención efectiva publicada por punto | logrotate del host (rotación por tamaño, a los 100 MB, fechada y sin tope de número) + poda del orquestador ([ORQUESTADOR.md](ORQUESTADOR.md) §8.1) |
| `stats.json` | el vivo y el anterior (`stats.json.1`, hasta 5 MB) | logrotate del host con `copytruncate` |
| `alerta` | 90 días | borrado por lotes de 5 000 |
| `resumen_hora` | 180 días | igual |
| `detalle_dia`, `espejo_hora` | 30 días | igual |
| Reportes por punto | 7 días, conservando siempre el último | worker |
| `cuarentena` cerrada | 400 días | igual |
| `abonado_hist`, `publica_rep` | 180 días | igual |
| `bitacora`, `login_intento` | 2 años (nunca menos de 1); no hay botón de borrar | se exporta a `.jsonl.gz` antes de podar |
| `sesion` | 12 h absolutas y 2 h de inactividad | limpieza cada hora |

`auto_vacuum=INCREMENTAL` en `eventos.db`, con un vacuum incremental cada noche.

Estas retenciones rigen **mientras el punto existe**. La baja lo borra todo de inmediato, sin
retención posterior (§8).

## 6. Secretos cifrados

- **Qué se cifra:** las claves API de los MikroTik y los tokens de Telegram, AbuseIPDB y Groq.
- **Cómo:** AES-256-GCM con el paquete `cryptography`. Nonce de 96 bits por cifrado. En la imagen
  del panel va el paquete de Debian `python3-cryptography`, no pip: apt solo instala lo que casa con
  el SHA256 del índice firmado por Debian (la garantía que daría `pip --require-hashes`), sobre la base
  fijada por digest, sin pip ni compilador en la imagen y con el libssl de la base, que recibe los
  avisos de seguridad de Debian. La versión instalada queda en `/usr/share/ids-maat/cryptography-version`.
  Formato: `secretos.py` del panel, `enc1:<base64(nonce de 12 bytes + texto cifrado + etiqueta)>`.
  Un valor sin `enc1:` es texto en claro de una configuración vieja: se usa y el panel lo vuelve a
  guardar cifrado al arrancar (`migrar_secretos`).
- **AAD (`asociado`), exactamente los de `secretos.py` y sus llamadores:**

  | Secreto | Dónde se guarda | AAD |
  |---|---|---|
  | clave API del MikroTik de un punto | `conf/routers.json`, campo `PASS` del punto | `router:<pid>:PASS` |
  | claves de feeds (`ABUSE_CH_AUTH_KEY`, `ABUSEIPDB_KEY`, `GROQ_API_KEY`) | `conf/feeds.conf` | `feeds:<CLAVE>` |
  | token de Telegram | `conf/report.conf`, `TELEGRAM_TOKEN` | `report:TELEGRAM_TOKEN` |

  Copiar el valor cifrado a otro campo o a otro punto no lo descifra (la AAD no casa).
- **Clave maestra:** 32 bytes en `/etc/ids-maat/master.key` (0440 `root:ids-panel`: el panel corre
  como 10500 sin capacidades y la lee por grupo). Se monta **solo en el panel**, en
  `/run/secrets/master_key:ro` (`IDS_MASTER_KEY`), fuera de `/srv/ids/panel`. `ids-orq panel aplicar`
  se niega si no existe (Docker crearía un directorio con ese nombre). Sin ella el panel arranca y
  avisa de que no puede usar esos secretos; no los borra. Una copia del volumen o un respaldo de las bases no basta para
  descifrar. La clave maestra se respalda aparte ([OPERACION.md](OPERACION.md) §3).
- **Rotación:** hoy **no hay** rotación de la clave maestra: `secretos.py` no lleva identificador de
  clave (`kid`) y el formato `enc1:` admite una sola clave. Cambiarla exige descifrar con la vieja y
  volver a guardar cada secreto con la nueva (o volver a escribirlos en Ajustes y en Puntos → API);
  eso es trabajo pendiente, no una orden del panel.
- **Token de Telegram:** no tiene pantalla en Ajustes. Se escribe a mano en
  `/srv/ids/panel/conf/report.conf` (`TELEGRAM_TOKEN=…` y `TELEGRAM_CHAT_ID=…`, fichero 0600 del
  uid 10500) y se reinicia el panel (`docker restart ids-core-panel`): al arrancar lo cifra
  (`migrar_secretos`). **Hasta ese reinicio está en claro en disco.**
- **La clave en claro existe solo en memoria**, al abrir la conexión. **Nunca vuelve al
  navegador**: el campo es de solo escritura y «vacío = no cambiar».
- **Lo que el panel nunca tiene:** la CA, `docker.sock` ni los hashes VPN. Las credenciales VPN del
  MikroTik cruzan el panel una sola vez y no se guardan.

## 7. Bitácora y auditoría

- **Dos tipos de cadena de hashes** (`hash = sha256(hash_prev ‖ fila)`), cada fila con `op_id` y
  resultado:
  - **la global** (`punto_id NULL`): usuarios, roles, acceso, actualizaciones, logins y las líneas
    de baja de los puntos;
  - **una por punto**: todo lo que se hace sobre ese punto y su router.

  Así, borrar un punto elimina su cadena entera **sin romper la global**, que sigue verificándose.
- **Anclaje diario (diseño, sin implementar).** `bitacora.anclar` es hoy una orden reservada del
  orquestador y contesta «no disponible». El diseño: el panel envía cada día la orden
  `bitacora.anclar {cabezas}` al orquestador, con la cabeza y el número de filas de la cadena
  global y de cada cadena de punto. El orquestador
  lo escribe en `orq.jsonl`, un diario que el panel no puede modificar, así que una cadena
  reescrita entera desde el panel no casa con los anclajes. Los anclajes de un punto borrado son
  solo hashes, sin datos.
- **Qué se audita:**
  - los logins correctos y fallidos;
  - los cambios de usuarios, roles y puntos que ve cada uno;
  - cada acción sobre un router, con el sha del plan y del respaldo;
  - cada orden al orquestador;
  - los cambios de acceso, las actualizaciones y las exportaciones.
- **Sin secretos:** un filtro sustituye por `***` cualquier campo `pass|clave|token|key|secret`.
- **Exportación** firmada con sha256.
- **Prueba:** recorre las cadenas y detecta una fila alterada.

## 8. Baja de un punto: borrado total

Decisión del dueño (ARQUITECTURA §10 b): **dar de baja un punto lo borra todo**, para que la
información de un punto viejo nunca se mezcle con la de uno nuevo. El flujo está en
[ORQUESTADOR.md](ORQUESTADOR.md) §11.2.

| Dónde | Qué se borra |
|---|---|
| `estado.db` | la fila `punto` y todas las filas con su `punto_id`: `instancia`, `vpn_usuario`, `mikrotik` (clave cifrada incluida), `abonado`, `abonado_hist`, `cuarentena`, `destino_envio`, `exclusion` y `nunca_bloquear` del punto, `publica`, `ajuste_punto` y `operacion`. Las sesiones que lo tenían seleccionado vuelven a «Toda la empresa» (las de un usuario limitado, a su primer punto) |
| `/srv/ids/panel/conf/usuarios.json` | el pid, de la lista `puntos` de cada usuario que lo tenga (§3.2). Quien se queda con la lista vacía ve «Sin puntos asignados» hasta que el admin le asigne otro; quien no tenía lista sigue viéndolo todo |
| `eventos.db` | `alerta`, `resumen_hora`, `detalle_dia`, `espejo_hora` e `ingesta` del punto, seguido de un vacuum incremental |
| `bitacora.db` | la cadena entera del punto |
| `/srv/ids/panel/` | `reportes/<pid>/` y `respaldos/<pid>/` (los `.rsc` de su router) |
| Orquestador (host) | `/srv/ids/puntos/<pid>/`, `/srv/ids/datos/<pid>/` (eve y dns, también los rotados), `/srv/ids/run/<pid>/` y `/srv/ids/ctl/<pid>/`; la clave y el certificado de servidor; el usuario VPN; las filas de `orq.db` del punto, salvo el enfriamiento de `N` (solo el número y una fecha); su entrada de `alertas.json` |

**Lo único que queda:**

- en la cadena global de la bitácora, **una sola línea**: «punto pNNN (nombre) eliminado por
  <usuario> <fecha>»;
- la secuencia de ids, para que `pNNN` no se reutilice nunca;
- en `orq.jsonl`, las líneas técnicas de las órdenes del punto. Para que no quede nada del punto
  en ese diario, las órdenes guardan el `pid`, el nombre de la orden, el `sha256` de los parámetros
  y el resultado, **nunca los parámetros en claro** (redes, IP).

**Límites que conviene saber:**

- Los **respaldos ya hechos** en `/root/backups/`, y su copia fuera del VPS, contienen el punto
  hasta que caducan por su retención (14 días por defecto). No se reescriben.
- Los **avisos de Telegram** ya enviados no se pueden retirar.
