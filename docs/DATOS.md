# Datos e identidad

Anexo de [ARQUITECTURA.md](ARQUITECTURA.md). Este anexo cubre:

- los almacenes y las entidades;
- la regla `(punto_id, ip)`;
- las retenciones;
- los secretos cifrados y la auditoría.

## 1. Almacenes

| Almacén | Contenido | Por qué así |
|---|---|---|
| `estado.db` (SQLite, WAL) | configuración, puntos, instancias, MikroTik, usuarios, roles, visibilidad, sesiones, abonados, cuarentenas, exclusiones, públicas, operaciones | transacciones y `UNIQUE(punto_id, ip, …)` en lugar de unos 40 JSON con cerrojos a mano; es pequeña y se respalda rápido |
| `eventos.db` (SQLite, WAL) | alertas, agregados por hora y por día, offsets de ingesta, espejo por hora | es grande y se puede reconstruir desde los eve; va aparte para podar sin bloquear el estado |
| `bitacora.db` (SQLite, WAL, solo se añaden filas) | auditoría e intentos de login | retención larga y cadena de hashes |
| `eve.json` / `dns.json` por instancia | eventos crudos | fuente de verdad del crudo; solo se agrega lo que el panel consulta |
| Ficheros de intercambio | `threshold.config` por punto, exportaciones, respaldos `.rsc` de los routers | los consumen procesos que no leen SQLite |
| `orq.db` (host) | asignaciones, digests, cola de órdenes, `op_id` | estado propio del orquestador ([ORQUESTADOR.md](ORQUESTADOR.md)) |

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
| `ajuste` / `ajuste_punto` | G / P | `clave` / `(punto_id, clave)` | política por bandas, acciones, listas y TTL, Telegram, AbuseIPDB, Groq, redes de gestión, retenciones, tope de cuarentenas automáticas |
| `punto` | P (raíz) | `id` `p001…` (secuencia, **nunca se reutiliza**), `nombre` único, `n`, `red_tunel`, `ip_srv`, `ip_mk`, `puerto_vpn`, `ros_version`, `redes_abonados`, `perfil`, `hilos`, `tls_legacy`, `api_puerto`, `ip_publica_esperada`, `estado`, `fila_version` | `UNIQUE(n)` y `UNIQUE(puerto_vpn)` entre los que no están de baja; `n` se reutiliza 7 días después de la baja |
| `instancia` | P (1:1) | `estado_deseado` (activa / pausada / borrada), digests actual y previo, `observado` | el estado real lo publica el orquestador en `estado.json` |
| `vpn_usuario` | P | `(punto_id, usuario)`, creado, rotado | el hash vive en el fichero del orquestador |
| `mikrotik` | P (1:1) | `cert_fp`, usuario, `clave_cifrada`, `clave_kid`, `identidad`, `sw_id`, `version_ros`, listas, TTL, `envio_habilitado` (0 por defecto) | el destino es el relé del punto; no hay host configurable |
| `usuario`, `rol` | G | `login` inmutable; roles `admin` / `operador` / `lectura` | — |
| `visibilidad` | G | `(usuario_id, punto_id NULL, recurso, nivel)` | hoy cada usuario tiene una sola fila `(NULL, '*', 'actuar')` |
| `sesion` | G | `token_sha256`, `csrf`, expira, ip, `punto_sel` | nunca se guarda el token |
| `abonado`, `abonado_hist` | P | `(punto_id, ip)` | el mapa se pide a cada router por separado |
| `alerta` | P | `(punto_id, ts)`, `cpe_ip`, `sid`, `dir` | en `eventos.db` |
| `resumen_hora`, `detalle_dia`, `espejo_hora` | P | `punto_id` primero en la PK | — |
| `ingesta` | P | `(punto_id, archivo_id dev:ino)`, offset, huella | incremental por inodo y posición |
| `cuarentena` | P | `(punto_id, ip, tipo)`, `estado`, `ros_id`, comentario `ids-maat:<pid>:<id>` | `UNIQUE(punto_id, ip, tipo)` entre las vivas |
| `destino` / `destino_envio` | G / P | la IP externa es global; la entrega va por punto | — |
| `exclusion`, `nunca_bloquear` | G/P | `punto_id NULL` = toda la empresa | el threshold de cada punto = las globales más las suyas |
| `publica` / `publica_rep` | P / G | `(punto_id, entrada)` / `(entrada, ts)` | la reputación de una IP pública es igual para todos |
| `bitacora`, `login_intento` | G con `punto_id` | `hash = sha256(hash_prev ‖ fila)` | en `bitacora.db` |
| `operacion` | P/G | `op_id` (uuid) | une el panel con el diario del orquestador |
| Cachés de feeds, AbuseIPDB e IA | G | IP de internet | la cuota de AbuseIPDB es única por empresa |

Estados del punto (las transiciones están en [ORQUESTADOR.md](ORQUESTADOR.md) §11):

```
borrador ─► reservado ─► creando ─► esperando_vpn ─► esperando_api ─► esperando_espejo ─► activo ◄─► pausado
               ▲             │                                                                │
               └── (deshace) ┘ error ◄──────────── cualquier paso ─────────────────────────────┘
activo|pausado|error ─► dando_de_baja ─► baja (solo lectura)
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
- **Visibilidad:** todo pasa por `alcance(usuario)` y `puede(usuario, punto_id, recurso, nivel)`.
  Restringir más adelante será cuestión de datos, no de código.
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
| empresa, usuarios, roles, visibilidad, sesiones | punto, instancia, VPN, MikroTik | política automática |
| redes de gestión y acceso | abonados y su historial | acciones por categoría |
| feeds, AbuseIPDB (cuota), Groq, Telegram | alertas, agregados, espejo, ingesta | listas y TTL |
| reputación de IP públicas, destinos malos (la IP) | cuarentenas, entrega de destinos | exclusiones, nunca bloquear |
| bitácora (con `punto_id`) | IP públicas declaradas, reportes | tope de cuarentenas automáticas por hora |

## 5. Retenciones

| Dato | Retención | Mecanismo |
|---|---|---|
| `eve.json`, `dns.json` | 3 días y ~5 GB por punto | logrotate del host ([INSTANCIA.md](INSTANCIA.md) §10.5) |
| `alerta` | 90 días | borrado por lotes de 5 000 |
| `resumen_hora` | 180 días | igual |
| `detalle_dia`, `espejo_hora` | 30 días | igual |
| Reportes por punto | 7 días, conservando siempre el último | worker |
| `cuarentena` cerrada | 400 días | igual |
| `abonado_hist`, `publica_rep` | 180 días | igual |
| `bitacora`, `login_intento` | 2 años (nunca menos de 1); no hay botón de borrar | se exporta a `.jsonl.gz` antes de podar |
| `sesion` | 12 h absolutas y 2 h de inactividad | limpieza cada hora |

`auto_vacuum=INCREMENTAL` en `eventos.db`, con un vacuum incremental cada noche.

## 6. Secretos cifrados

- **Qué se cifra:** las claves API de los MikroTik y los tokens de Telegram, AbuseIPDB y Groq.
- **Cómo:** AES-256-GCM con el paquete `cryptography`, instalado en la imagen con `pip
  --require-hashes`. Nonce de 96 bits por cifrado.
- **AAD:** `"mikrotik:" + punto_id` o `"ajuste:" + clave`. Copiar el cifrado de un punto a otro no
  descifra.
- **Clave maestra:** 32 bytes en `/etc/ids-maat/master.key` (0400 root). Se monta **solo en el
  panel**, fuera de `/data`. Una copia del volumen o un respaldo de las bases no basta para
  descifrar. La clave maestra se respalda aparte ([OPERACION.md](OPERACION.md) §3).
- **Rotación:** `clave_kid` lo permite. Una tarea descifra con la vieja y cifra con la nueva en una
  sola transacción.
- **La clave en claro existe solo en memoria**, al abrir la conexión. **Nunca vuelve al
  navegador**: el campo es de solo escritura y «vacío = no cambiar».
- **Lo que el panel nunca tiene:** la CA, `docker.sock` ni los hashes VPN. Las credenciales VPN del
  MikroTik cruzan el panel una sola vez y no se guardan.

## 7. Bitácora y auditoría

- **Cadena de hashes:** `bitacora.db` encadena las filas (`hash = sha256(hash_prev ‖ fila)`) y
  guarda `punto_id`, `op_id` y resultado.
- **Anclaje diario.** El panel envía cada día la orden `bitacora.anclar {hash_cabeza, filas}` al
  orquestador, que la escribe en `orq.jsonl`, un diario que el panel no puede modificar. Así, una
  cadena reescrita entera desde el panel no casa con los anclajes.
- **Qué se audita:**
  - los logins correctos y fallidos;
  - los cambios de usuarios, roles y visibilidad;
  - cada acción sobre un router, con el sha del plan y del respaldo;
  - cada orden al orquestador;
  - los cambios de acceso, las actualizaciones y las exportaciones.
- **Sin secretos:** un filtro sustituye por `***` cualquier campo `pass|clave|token|key|secret`.
- **Exportación** firmada con sha256.
- **Prueba:** recorre la cadena y detecta una fila alterada.
