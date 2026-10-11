# Plan del panel

Anexo de [ARQUITECTURA.md](ARQUITECTURA.md). Este anexo cubre:

- el inventario del panel actual;
- la estructura en módulos;
- las pantallas y la API;
- el flujo de cuarentena;
- la seguridad de la aplicación.

Los datos están en [DATOS.md](DATOS.md) y el ciclo de vida de los puntos en
[ORQUESTADOR.md](ORQUESTADOR.md) §11.

## 1. Punto de partida

El panel actual es el heredoc `DASH` de `suricata-ids-lab/install-suricata.sh` (líneas 3641–21208,
unas 17 500 líneas de Python con la stdlib). Tiene estas características:

- Es una sola cadena, con un `_post` de 1 200 líneas de `if/elif`.
- Tiene un hilo `refrescador` secuencial.
- Guarda unos 40 JSON escritos con cerrojos a mano.
- Las plantillas HTML, CSS y JS son cadenas Python.

**Defectos de identidad que hay que cerrar:**

- La clave cambia de forma al pasar de 1 a 2 routers (`ip` → `r1|ip`).
- `historial.db` guarda `cpe` = IP sola.
- Hay caída silenciosa al «router por defecto».
- Existe un modo sin autenticación cuando no hay usuarios.
- Los secretos están en claro: las claves API y los tokens de sesión.

**Lo que funciona y se conserva:**

- el cliente API de RouterOS en stdlib, con la huella fijada;
- el CSRF por `Origin`/`Sec-Fetch-Site`;
- el respaldo del firewall antes de montar el espejo;
- el plan del espejo, que coincide con lo que se aplica;
- la ingesta incremental por inodo y huella;
- el envío a cuarentena apagado hasta que una persona lo enciende.

## 2. Procesos

Son dos servicios de compose con **la misma imagen y sin s6**:

| Servicio | Hace | Montajes |
|---|---|---|
| `panel-web` | servidor **HTTP** en el puerto 5637, con IP fija `10.210.255.2` en la red `ids-core`: páginas, `/api/v1`, `/salud`. El TLS lo termina el proxy inverso externo (§12) | `/data/panel` rw; `/data/puntos/datos` y `/data/puntos/run` ro; `/run/ids-orq`; secretos |
| `panel-worker` | planificador (§6) | los mismos |

Los dos:

- corren con uid 10500, `read_only`, `cap_drop: ALL`, `no-new-privileges` y `tmpfs` en `/tmp`;
- usan `TZ=UTC`; la conversión a la zona de la empresa se hace al mostrar.

## 3. Estructura de módulos

```
panel/
  app.py                 servidor HTTP, tabla de rutas, /salud
  config.py              Config inyectada (adiós a CFG global); ajustes de empresa y de punto
  repo/                  estado.db / eventos.db / bitacora.db; repo.para(alcance)
  auth/                  usuarios (PBKDF2), sesiones, CSRF, roles, alcance()/puede()
  puntos/                modelo Punto, rutas por punto, cliente del orquestador, lector de estado.json
  mikrotik/              api.py (TAL CUAL, con fábrica de socket UNIX), listas, reglas, abonados,
                         diagnostico (incluye CGNAT), espejo (generador único de plan, de MKINIT)
  eve/                   lectura (_RE, abrir_desde, parse_ts), ingesta incremental, clasificacion
  analisis/              generador por punto (antes HREP; devuelve datos, no HTML), conducta, salida, metricas
  cuarentena/            motor (CpeRef), politicas (con tope por hora), proteccion (nunca, exclusiones)
  reputacion/            feeds (lectura), abuseipdb (global), publicas, dnsbl, culpables
  ia/                    groq (sin datos de abonados)
  avisos/                telegram (dedupe por punto|ip), bitacora (+punto, cadena, anclaje)
  salud.py               cobertura TZSP, desperdicio, salud funcional por punto
  tareas.py              planificador: tareas globales + por punto con pool limitado
  paginas/               inicio, cuarentena, ficha, reputacion, conducta, historico, exclusiones,
                         puntos, ficha_punto, ajustes, bitacora, login, documentacion
  static/                CSS y JS que hoy son cadenas (_SORT_JS, _POS_JS, _ASK, masivo, mapa…)
```

## 4. Qué se reutiliza, qué se adapta y qué se descarta

| Se reutiliza casi tal cual | Se adapta (añadir `punto_id`) | Se descarta |
|---|---|---|
| cliente API RouterOS (`_mk_*`, TLS, TOFU) | cuarentena: enviados, candidatos, políticas, barrido rápido | instalador bash entero |
| verificador, plan y aplicación de reglas en el router; `respaldar_firewall` | ficha del CPE (`/puntos/<pid>/cpe/<ip>`) | EveBox y todo lo que lo nombra |
| AbuseIPDB, DNSBL, Groq, lectura de feeds `rep_*` | abonados y su historial | `suricata-panel-update` y `chequear_update` (pasan a «versión de imagen») |
| auth: hash, sesiones, CSRF, roles | conducta, histórico («Abuso saliente»), métricas | `ovpn_*` con `systemd-run` sobre `openvpn.sh`; `espejo_vpn_*`; `mkinit_asegurar` |
| ingesta SQLite por inodo + CRC (`hist_*`) | salud y cobertura (sin `systemctl` ni `suricatasc`) | modo `-e local\|vpn`, `suricata-ids-fw` |
| `_sello`, escrituras atómicas, `traducir`, `sev` | públicas, culpables, exclusiones, `nunca`, threshold (vía orquestador) | `_slot_iface`, `TZSP_MAP`, `CLUSTERID`, varias ifaces |
| `GRUPOS_*`, `GRAD_REGLAS`, `ros_lista`, reglas de salida | bitácora, Telegram, Inicio, Top, Detalle (selector) | `_provisionar_geo` (los assets van en la imagen) |
| plantillas CSS/JS, glosario, guía de conducta | generador HREP (recibe el punto; ya no usa `in_iface`) | **modo sin autenticación**; migraciones de formatos viejos |
| `en_terminal` y la lógica de plan de `MKINIT` | `refrescador` → `tareas.py` | la regla «DNS aparte entero» y la exclusión de la lista del fasttrack |

### 4.1 Supuestos de «una sola caja» que se rompen

Son los más importantes de los 30 inventariados:

| Supuesto | Pasa a |
|---|---|
| Un único `EVE` y un único `LOGDIR` | rutas por punto |
| Un único `cuarentena.json` y un único reporte | uno por punto, en datos (no HTML troceado con regex) |
| Identidad por `in_iface` y `clave_cpe` que cambia de forma | `CpeRef` |
| `historial.db` con `cpe` = IP | `punto_id` en la PK |
| Listas de protección globales por IP privada | campo `punto` |
| `threshold.config` único con `suricatasc` local | uno por punto, aplicado por el orquestador |
| Router por defecto (`cargar_mk()`) | se elimina |
| Hilo secuencial que lanza el generador con `subprocess` | planificador con un pool limitado (8 CPU compartidas con Suricata) |
| Cachés de módulo con una sola versión | indexadas por `(pid, sello)` |

## 5. Pruebas existentes

`tests/` tiene **87 entradas** que hoy extraen piezas de los heredocs con `extraer.py`. Pasan a
`import panel.<módulo>`:

- **Casi tal cual:** TLS de MikroTik, verificador de reglas, AbuseIPDB, DNSBL, CSRF, `parse_ts`,
  salto de ventana, feeds, dataset, culpables, recorte de flujo, banco pcap y las de JS.
- **Se adaptan al punto:** `test_identidad_nodo` y `test_cuarentena_identidad` (base de las pruebas
  de IP repetidas), historial, conducta, salud, `test_mikrotik_init` (con su MikroTik de mentira) y
  bitácora.
- **Se descartan:** las del instalador, `test_clusterid_unico`, `test_solo_vpn`, `test_espejo_vpn`
  y `test_vpn_panel`.

## 6. Planificador (`panel-worker`)

| Cada | Global | Por punto (pool de 2–3 trabajadores, tiempo máximo por tarea) |
|---|---|---|
| 60 s | — | barrido rápido de políticas (con el tope por hora), salud funcional y espejo |
| 5 min | precarga de AbuseIPDB | ingesta del eve, reconciliación de cuarentenas, reporte si está viejo |
| 10 min | — | **diagnóstico del router**: identidad y `sw_id`, y **CGNAT** (`/ip route print where dst-address in 100.64.N.0/24 && !connect` y `/ip pool` contra el túnel); si solapa, deshabilita el mangle y avisa |
| 15 min | lote de cambios de threshold (`punto.threshold`) | — |
| 6 h | vigilancia de públicas y DNSBL | conducta |
| 24 h | podas, retenciones, `bitacora.anclar` | informe diario por punto (Telegram) |

- Un punto lento o caído no frena a los demás.
- **Tope de cuarentenas automáticas.** La política automática no envía más de X cuarentenas por
  hora y punto (configurable, 20 por defecto). Al llegar al tope, se para la automática de ese
  punto y avisa. Protege frente a un feed envenenado o una firma desbocada.

## 7. Pantallas y selector de punto

**Selector global** en la barra superior:

- Opciones: «Toda la empresa» y, debajo, cada punto con su indicador:
  - verde: activo y con espejo;
  - ámbar: aviso;
  - rojo: error o VPN caída;
  - gris: pausado.
- Solo aparecen los puntos de `alcance(usuario)`.
- El valor viaja en la URL (`?punto=p003`) y tiene prioridad. Además se recuerda en
  `sesion.punto_sel`.
- Si se cambia el selector estando en la ficha de un CPE, se vuelve a la lista. **Nunca** se
  reinterpreta la IP en otro punto.
- En la vista de empresa, toda tabla de CPE lleva la columna **Punto**. La misma IP en dos puntos
  aparece en **dos filas**.

| Página | Por punto | «Toda la empresa» | Notas |
|---|---|---|---|
| En vivo, Top, Detalle | sí | sí (suma, con desglose) | «3/4 puntos con espejo» |
| Cuarentena | sí | sí; las acciones van por fila con su punto | masivas agrupadas por punto |
| Ficha de CPE | obligatorio | — | `/puntos/p003/cpe/10.0.0.5` |
| Consultar IP (reputación) | — | global | si se escribe una IP privada, pide el punto |
| Histórico, Reporte (conducta) | sí | sí | el CSV lleva la columna `punto`. Un punto dado de baja no aparece: sus datos se borraron |
| Exclusiones | las del punto más las heredadas | todas, con columna Ámbito | aviso «se aplica en ≤ 15 min» |
| **Puntos** (nueva) | — | global | §8 |
| **Ficha del punto** (nueva) | sí | — | pestañas Resumen, VPN, MikroTik/API, Espejo (plan, aplicar, verificar, respaldos), Redes, Públicas, Política, Listas y TTL, Logs, Baja |
| Ajustes | — | global | empresa, usuarios y roles, feeds y claves, política por defecto, **redes de gestión e IP del proxy (modo seguro, ventana)**, actualizaciones, bitácora, accesos, documentación |

## 8. Pantalla Puntos

Lee `/data/puntos/run/estado.json`, que el orquestador escribe cada 15 s, y el `tzsp.json` de cada
punto. No llama al orquestador en cada carga.

| Columna | Fuente | Aviso cuando |
|---|---|---|
| Punto (nombre, id, N, túnel, puerto, perfil) | `punto` | — |
| Estado | `punto.estado` | `error`, o más de 1 h en `esperando_*` |
| VPN | `estado.json` | desconectada más de 2 min |
| Espejo (Mbps, media de 5 min) | `tzsp.json` | 0 Mbps durante 10 min en un punto activo |
| Desperdicio % / rechazados | receptor | > 50 % / > 20 % |
| Suricata | `estado.json`, eve | drops > 2 %, o sin eventos durante más de 300 s |
| Alertas 24 h | `alerta` | — |
| Cuarentenas vivas / huérfanas | `cuarentena` | huérfanas > 0 |

- Encima de la tabla: «Agregar punto», la capacidad restante por perfil, los totales y la cola del
  orquestador.
- Las acciones que no aplican al estado actual aparecen deshabilitadas, con el motivo.

## 9. Asistente «Agregar punto»

Los pasos y los errores están en [ORQUESTADOR.md](ORQUESTADOR.md) §11.1. En pantalla:

1. **Datos:** nombre, redes, RouterOS (6.49 o superior, o v7), perfil (**`reducido` por
   defecto**, con la capacidad) e IP pública opcional.
2. **Creación:** barra de avance alimentada por `op.estado`.
3. **Conectar el MikroTik:** pestañas **v7** y **v6** con bloques separados para copiar
   ([OPERACION.md](OPERACION.md) §1) y el indicador «Esperando conexión…».
4. **API-SSL:** usuario, clave y «Probar».
   - Se muestran la identidad, la versión y la **huella SHA-256** del certificado `ids-promax`,
     junto con la instrucción «compárala con `/certificate print detail` en el router».
   - Al confirmar, la huella queda fijada (TOFU) y cualquier otro certificado se rechaza.
   - Si falta el certificado, se muestra el bloque de `ids-promax` ([OPERACION.md](OPERACION.md)
     §1).
5. **Espejo:** el plan exacto y el aviso del respaldo, y después «Aplicar».
6. **Verificación:** paquetes, Mbps, desperdicio y primer evento. Al terminar: «El envío a
   cuarentena está APAGADO: actívalo en la ficha del punto cuando lo decidas».

El avance se guarda en `punto.estado`. El asistente se puede cerrar y retomar desde Puntos.

## 10. Cuarentena de un CPE

1. `POST /api/v1/puntos/{pid}/cuarentenas` con `{ip, tipo, motivo}`. Se comprueban el CSRF y
   `puede(u, pid, 'cuarentena', 'actuar')`.
2. Validaciones (`400` con el motivo):
   - la IP está en `redes_abonados(pid)`;
   - no está en `nunca_bloquear`;
   - no es una pública declarada;
   - el envío está habilitado. Si no, se ofrece «registrar sin enviar».
3. **Idempotencia:** si ya hay una fila viva `(pid, ip, tipo)`, se devuelve esa con `200`.
4. Se inserta como `pendiente` y se confirma la transacción. **[B] CUARENTENA-PEDIDA**
5. Fuera de la transacción: relé de **ese** punto, comprobación de identidad y `address-list add …
   timeout=<ttl> comment=ids-maat:<pid>:<id>`.
   - Si sale bien: `enviada`, más un aviso a Telegram con el punto.
   - Si contesta «already have such entry»: si la entrada es nuestra, `enviada`; si es ajena, se
     adopta con `origen = mikrotik`.
   - Si hay timeout: `error`, y se reintenta con espera creciente (1, 2, 5 y 10 min, hasta 6
     intentos). Después, aviso.
6. **Reconciliación** cada 5 min, solo con el prefijo del punto:
   - una `enviada` que ya no está pasa a `vencida` o a `desaparecida`;
   - una entrada nuestra sin fila pasa a `huerfana`. **No se borra sola.**
7. **Liberar:** `enviada → quitando → liberada`, por `ros_id` y comprobando el comentario.
8. **Acciones masivas desde «Toda la empresa»:** se agrupan por punto («p001: 3 CPE, p004: 1
   CPE»). Cada grupo usa su router, el fallo de uno no detiene a los demás y el resultado se da por
   punto.

## 11. API pública

- Todo sale de `/api/v1/…` en JSON. Las páginas HTML son una capa encima.
- Rutas por punto: `/api/v1/puntos/{pid}/{cpe,alertas,cuarentenas,exclusiones,espejo,mikrotik,vpn}`.
- Rutas agregadas: `/api/v1/empresa/…`.
- Autenticación por cookie de sesión más CSRF. Los tokens de API por usuario (con hash y alcance)
  quedan fuera de F0–F6.

## 12. Seguridad de la aplicación

| Tema | Diseño |
|---|---|
| Primer arranque | **Prohibido el modo sin autenticación.** Solo se acepta «crear el primer admin», con un token de un solo uso que se imprime en el log de `panel-web` |
| Proxy inverso y cabeceras | El TLS lo termina un **proxy inverso externo** (decisión c de ARQUITECTURA §10). El panel habla HTTP y el firewall solo deja llegar a las IP del proxy. El panel **solo confía** en `X-Forwarded-For`, `X-Forwarded-Proto` y `X-Forwarded-Host` (o en `Forwarded`) cuando el par TCP es una IP de la lista de proxies; de `X-Forwarded-For` toma la entrada que añadió el proxy (la última). Si la conexión viene de cualquier otra IP, por ejemplo el túnel SSH de emergencia, esas cabeceras se ignoran y se usan la IP y el `Host` reales |
| Uso de la IP real y del protocolo | La IP real alimenta el freno de login, la bitácora y los accesos. `X-Forwarded-Host`/`-Proto` alimentan la comprobación de origen del CSRF. Las cookies `Secure` y `__Host-` se emiten cuando `X-Forwarded-Proto=https` llega de un proxy de confianza |
| CSRF | `Origin`/`Sec-Fetch-Site`, comparados con el host público (`X-Forwarded-Host` del proxy), más un token por sesión en la cabecera `X-CSRF` en todo POST, PUT y DELETE |
| Cookie | `__Host-ids_s`, `SameSite=Strict`, `HttpOnly`, `Secure`. Por el túnel SSH de emergencia (`http://localhost:5637`), los navegadores tratan `localhost` como contexto seguro y la cookie funciona |
| Sesiones | se guarda `sha256(token)` de 256 bits; 12 h absolutas y 2 h de inactividad; rotación al iniciar sesión; se invalidan al cambiar la clave, el rol o la visibilidad, o al desactivar al usuario; máximo 10 por usuario |
| Claves | PBKDF2-SHA256 con 600 000 iteraciones; `iter` por fila con actualización transparente; mínimo 12 caracteres; `hmac.compare_digest` |
| Fuerza bruta | 8 fallos en 10 min por **IP real del cliente** y también por login, en el propio panel. fail2ban no sirve aquí: todas las conexiones llegan desde la IP del proxy |
| Cabeceras | CSP `default-src 'self'` con nonce, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `nosniff` |
| Origen permitido | el panel vuelve a comprobar que el par TCP es una IP del proxy o la puerta de enlace de `ids-core` (el túnel SSH de emergencia), además del nft del host. Quién llega al proxy lo decide el propio proxy |
| Secretos y bitácora | [DATOS.md](DATOS.md) §6 y §7 |
