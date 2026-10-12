# Contrato F2 — el panel completo de suricata-ids-lab dentro del contenedor

Decisión del usuario (2026-10-11): **se mantiene todo el dashboard de suricata-ids-lab** (En vivo, Top orígenes,
Detalle, Cuarentena, Consultar IP, Histórico, Reporte, Exclusiones, Ajustes, Documentación) y **solo se le
añaden las mejoras de contenedores**:

1. **Selector de nodo** en la barra: «Todos los nodos (acumulado)» y cada MikroTik. Con un nodo elegido, cada
   pantalla muestra solo sus datos. En «Todos» se ve todo junto y **una IP repetida en dos nodos sale en dos
   filas**, cada una con la etiqueta de su nodo (nunca se suman).
2. **Apartado Puntos**: alta de cada MikroTik con su propia VPN y su propio Suricata (contenedores que crea el
   orquestador), comandos para pegar en el router, conexión API, espejo, baja.

El código heredado está en `images/panel/rootfs/usr/local/lib/ids-panel/` (ver [PANEL-HEREDADO.md](PANEL-HEREDADO.md)),
copiado tal cual en el commit `522942e`. Este contrato sustituye a [PLAN-PANEL.md](PLAN-PANEL.md) §3–§5 (la
reescritura en módulos queda descartada) y al panel mínimo de [CONTRATO-F1b.md](CONTRATO-F1b.md).

Inventarios de partida (números de línea de `dashboard.py` = los del heredoc `DASH`): `inv_A.md` (l. 1–8800),
`inv_B.md` (l. 8800–fin), `inv_C.md` (generador, feeds, mkinit, informe, panel F1b-min).

## 1. Principios

- **Cambiar lo mínimo.** Una función que funciona igual con «un nodo = un router» no se toca. Nada de
  refactorizar, renombrar ni reformatear código que no hay que cambiar: el diff tiene que poder revisarse.
- **Un punto = un router del multi-nodo viejo**, con `id = iface = pid`. La identidad de un CPE es **siempre**
  `pid|ip` (`nodos.clave`), también con un solo punto (`clave_cpe` y el `MULTI_ROUTER` del generador ya no
  devuelven nunca la IP pelada).
- **Todo lo que dependía del servidor viejo** (systemctl, suricatasc, openvpn.sh, EveBox, el actualizador por
  git, tzsp-decap con `TZSP_MAP`, `suricata-ids-fw`, el instalador en /root) **se quita**, o pasa a una orden del
  orquestador, o se lee de `estado.json`. Nada queda a medias: ni rutas, ni botones, ni textos que lo nombren.
- **Sin modo sin autenticación.**
- Comentarios y textos en el mismo estilo que el código heredado (español, sin tildes donde el original no las
  lleva). Nada de nombres ni IPs reales: RFC 5737 en ejemplos y pruebas.

## 2. Módulo común `nodos.py` (YA ESCRITO, interfaz fija)

`/usr/local/lib/ids-panel/nodos.py`. Lo importan `dashboard.py`, `html_report.py`, `informe_diario.py` y
`mikrotik_init.py`. Si hace falta algo más, se **añade** (sin cambiar lo que hay) y se avisa en el informe.

| Nombre | Qué es |
|---|---|
| `PANEL`, `DATOS`, `RUN`, `SHARE` | raíces (`IDS_PANEL_DIR`, `IDS_DATOS`, `IDS_RUN`, `IDS_SHARE`) |
| `CONF`, `ESTADO`, `LOG`, `FEEDS`, `GEO`, `CACHE`, `RESPALDOS`, `NODOS`, `MAPA` | directorios globales; `asegurar_dirs()` los crea |
| `ruta(*partes)` | ruta bajo `PANEL` |
| `leer_estado()`, `puntos()`, `pids()`, `punto(pid)`, `nombre(pid)`, `pid_valido(pid)` | puntos de `RUN/estado.json`; cada punto trae `redes`, `api_puerto`, `sensor`, `mk`, `tzsp_puerto` |
| `TODOS` (`"_todos"`), `nodo_actual()`, `poner_nodo(n)`, `contexto(n)`, `es_todos(n)`, `nodos_de(n)` | nodo del hilo; por defecto `TODOS` |
| `dir_eventos(pid)`, `eve_vivo(pid)`, `ficheros_eventos(nodo, patrones)` | eventos (ro): `[(pid, ruta)]` del nodo o de todos |
| `dir_salida(nodo)`, `salida(fichero, nodo)` | salidas por nodo: `NODOS/<pid>/` o `NODOS/_todos/` |
| `api_sock(pid)`, `tzsp_json(pid)` | relé API-SSL y latido TZSP del punto |
| `clave(pid, ip)` | identidad del CPE |

Árbol de `PANEL` (`/srv/ids/panel`, uid 10500, 0700): `conf/` (panel.conf, mikrotik.conf, routers.json,
feeds.conf, report.conf, exclusiones.json, listas `.lst`, empresa, usuarios, confianza…), `estado/` (registros
JSON: enviados, acciones, sesiones, abonados, públicas, IA, AbuseIPDB…), `log/` (login, bitácora, cuarentena),
`feeds/`, `geo/`, `cache/`, `respaldos/`, `nodos/<pid>/` y `nodos/_todos/`. La asignación fichero a fichero
está en `inv_A.md` §1 y `inv_C.md` §1; se respeta salvo motivo que se explica en el informe.

## 3. Reglas por tipo de dato

| Dato | Nodo elegido | «Todos» |
|---|---|---|
| eventos en vivo (`tail_grupos`, `top_origenes`, feed, barrido rápido) | `ficheros_eventos(pid)` | todos los ficheros; cada evento lleva su pid |
| reporte del generador (`report-*.html`, `cuarentena.json`, métricas, entrantes, destinos, dominios) | `dir_salida(pid)`, generado con `--nodo pid` | `dir_salida(TODOS)`, generado con `--todos` (chips de nodo del multi-nodo viejo) |
| historial (`historial.db`) y conducta | una base / un fichero por nodo en `dir_salida(pid)` | se unen las filas de cada nodo con su columna **Nodo** |
| enviados, acciones, abonados, públicas, exclusiones | ficheros globales; claves `pid|ip` o campo `nodo` | todos |
| configuración, usuarios, feeds, bitácora, login | global | global |

- **Acciones (cuarentena, liberar, reglas, listas, públicas)** van siempre contra el router **del pid de la
  clave** (`pid|ip`) o del `rid` del formulario, **nunca** el del contexto ni un «router por defecto».
  `router_defecto()` desaparece. En «Todos» las acciones masivas se agrupan por nodo.
- Las tareas de fondo que reconcilian, evalúan o liberan (`reconciliar_cuarentena`, `aplicar_politicas`,
  `evaluar_bloqueos`, `mk_sync_enviados`…) corren **por nodo** y solo tocan claves `pid|…` de ese nodo
  (`inv_A.md` riesgo 3: hoy liberarían CPE de otros nodos).
- Deduplicaciones por IP (avisos de Telegram, `_motivo_bloqueo`…) pasan a `pid|ip`.
- **Exclusiones**: registro con campo opcional `nodo` (vacío = todos los nodos). El generador y el panel las
  aplican así. Al guardarlas, el panel pide al orquestador `punto.threshold` de cada nodo afectado (§6).

## 4. Conexión con los routers

- `cargar_routers()` devuelve un router por punto de `nodos.puntos()`, en ese orden:
  `id = iface = pid`, `nombre` del punto, `HOST = "unix:" + nodos.api_sock(pid)`, `PORT = api_puerto`,
  `TLS = "1"`, más lo que el usuario guarda por punto en `conf/routers.json` (`USER`, `PASS`, `LIST*`, `TTL*`,
  `ENABLED`, `CERT_FP`). Un pid de `routers.json` que ya no existe se ignora (y se borra al guardar).
- `mk_conectar` con `HOST` `unix:…`: `socket.AF_UNIX` al relé + **TLS encima** (`wrap_socket`, huella
  SHA-256 fijada igual que hoy, TOFU). La huella se guarda **por punto** en `routers.json` (corrige el fallo de
  `inv_A.md` §10). El resto del protocolo no cambia.
- El alta, la VPN y la baja del router son del apartado Puntos (§5). Se quitan `/routers/guardar`,
  `/routers/quitar`, `_card_nodos` y el tope de 8 routers.
- **Espejo**: «Montar espejo» en la ficha del punto, con vista previa del plan, respaldo (`/export` en el
  router + JSON local en `RESPALDOS`) y aplicar. Lo hace `mikrotik_init.py` como módulo, por el relé, con
  sensor = `punto.sensor` y puerto `punto.tzsp_puerto`, y las reglas de [OPERACION.md](OPERACION.md) §2
  (comentario `IDS ids-maat:<pid>`, `connection-bytes=0-10000`, fasttrack ajustado **sin ningún `accept`**, **sin**
  regla de DNS aparte). Si OPERACION.md y mkinit chocan, manda OPERACION.md.
- `/destinos.rsc` y `/blocklist.rsc` (`/tool fetch` del MikroTik): el MikroTik no llega al panel por el túnel.
  Se quitan las instrucciones de `fetch` y los destinos se siguen enviando por API (ya existe).

## 5. Apartado Puntos (nuevo, sobre el estilo del dashboard)

Pestaña **Puntos** (solo admin) en `_NAV_LINKS` y mosaico en Ajustes (sustituye a VPN/OpenVPN). Reutiliza la
lógica del panel F1b-min (`idspanel/orq.py`, `estado.py`, `operaciones.py` y las funciones de `app.py`/`vistas.py`
listadas en `inv_C.md` §5.1), pintada con `wrap()`/`nav()` del dashboard y sus modales (nunca `alert`/`confirm`).

| Ruta | Hace |
|---|---|
| `GET /puntos` | tabla de puntos (estado, VPN, espejo Mbps, Suricata, alertas 24 h, avisos), capacidad restante, «Agregar punto» |
| `GET /puntos/nuevo`, `POST /puntos/nuevo` | alta (nombre, redes de abonados, RouterOS 6/7, perfil `reducido` por defecto) → `punto.crear` → `303 /operaciones/<op_id>` |
| `GET /operaciones/<op_id>` | avance; al terminar enseña **una sola vez** usuario y clave de la VPN y los comandos v7/v6 |
| `GET /puntos/<pid>` | ficha: Resumen, VPN (comandos sin clave), API (usuario/clave/probar/huella), Espejo (plan/aplicar), Redes, Logs, Baja |
| `POST /puntos/<pid>/{borrar,regenerar,arrancar,parar,reiniciar,ajustar,api,espejo}` | órdenes del orquestador o configuración del router del punto; `borrar` exige escribir el nombre |

- Los contenedores los crea el orquestador; el panel no toca Docker.
- La baja borra todo el punto en el orquestador **y** en el panel: `nodos/<pid>/`, su entrada de `routers.json`,
  las claves `pid|…` de los registros globales y su cuenta de acciones del Histórico. Queda una línea en la bitácora.
- **Antes** de pedir `punto.borrar` (apartado 2, auditoría A-21(5)), con la casilla «Limpiar antes el MikroTik»
  marcada por defecto, el panel usa el túnel que la baja va a destruir para limpiar el router: **primero** saca de
  sus address-lists lo que puso (CPEs en cuarentena normal, DNS y graduada, de su lista guardada y de la configurada
  hoy; y su parte de los destinos bloqueados), y **al final** retira el espejo (`espejo_retirar`: fasttrack como
  estaba). Cada IP sale del registro solo si el router lo confirma; un timeout corta la limpieza y se explica. Si
  algo falla, **no se pide la baja**, el punto sigue vigilado y el aviso dice si el router ya se tocó; desmarcar la
  casilla (router que ya no existe) da de baja sin hablar con el router. Sin usuario/clave de API solo se sigue si
  el panel no tiene nada apuntado en ese router. Una baja a la vez por punto; la espera por la tarea de fondo es
  corta (30 s). Desde que empieza, ni el fondo ni un envío a mano mandan nada a ese punto: la marca va ligada al
  `op_id` de la baja, caduca a los 15 min y la suelta el barrido si la baja termina mal o el orquestador la
  rechaza. Lo quitado cuenta como `QUITADO-BAJA` (no suma a «liberados»). Las reglas de acción por categoría
  (`Suricata:<cat>:`) se quedan: con las listas vacías no cortan nada.
- **Cada nodo ve solo lo suyo** (apartado 2, auditoría A-18): el Histórico cuenta las acciones del punto mirado
  (`acciones.json` con total y `nodos.<pid>`; un `acciones.json` de antes con un solo punto es de ese punto); «listas en uso» y el diagnóstico cuentan los CPEs del punto; la
  ficha abierta con la IP sola (enlace de Telegram) usa el punto mirado, y en «Todos» el único punto con esa IP o,
  si son varios, pregunta cuál; el historial de asignaciones es el del punto del CPE; «IPs únicas» del informe
  cuenta `pid|ip` para las IPs de abonado. La lista «nunca bloquear» admite `pNNN|IP` (solo ese punto) y la IP sola
  vale en todos (A-12).

## 6. Orquestador

- `estado.json` por punto añade `redes`, `api_puerto`, `sensor`, `mk`, `tzsp_puerto` (YA HECHO).
- **`punto.threshold {pid, contenido}`** pasa de reservada a orden de cola: escribe
  `/srv/ids/puntos/<pid>/suricata/threshold.config` (atómico, validado: solo líneas `suppress`/`threshold`/
  `event_filter`/comentarios) y recarga Suricata de ese punto sin cortar el espejo
  (`suricatasc -c reload-rules` por el socket de control; si falla, reinicio del contenedor `suricata`).
- `threshold.config` de cada punto lo **gestiona entero el panel** desde Exclusiones: una línea escrita a mano en
  el servidor se pierde al siguiente guardado (auditoría B-19). El motivo de cada exclusión va como línea de
  comentario propia, nunca al final de una regla.
- Memoria del panel (`RESERVA_PANEL_MB`): 1536 MiB. El generador corre como subproceso con `RLIMIT_AS` de
  1 GiB y **de un nodo en uno** (nunca en paralelo).

## 7. Servidor y seguridad

- Escucha HTTP en `0.0.0.0:$IDS_PUERTO` (5637). `PROXIES` sale de `IDS_PROXY` y admite CIDR. De
  `X-Forwarded-For` se toma el último salto que no es de confianza. `X-Forwarded-Host`/`-Proto`/`Forwarded` solo
  cuentan si el par TCP es un proxy de confianza. `SIGTERM` cierra limpio.
- Zona horaria: `IDS_TZ` (el contenedor corre con `TZ=UTC`): el dashboard y el generador hacen
  `os.environ["TZ"] = IDS_TZ; time.tzset()` al arrancar y `TZ_EC` pasa a `ZoneInfo(IDS_TZ)`.
- **Usuarios**: se queda el formato del dashboard (lista con PBKDF2) en `conf/usuarios.json`. La CLI
  `ids-panel crear-admin|restablecer|salud|servir` mantiene su interfaz (la usan `install.sh` e
  `ids-orq panel …`: `crear-admin` imprime una línea `CLAVE=…`, sale con 3 si ya hay usuarios; `restablecer
  <usuario>` imprime `CLAVE=…`) pero escribe ese formato con rol `admin`. Un restablecimiento **expulsa** las
  sesiones abiertas de ese usuario (la sesión guarda una marca del hash y deja de valer si cambia).
  Las sesiones se guardan con `sha256(token)`, no con el token.
- La migración desde `/etc/suricata-dashboard.conf` (`USER`/`PASS`) desaparece.
- `ids-panel salud` hace `HEAD /` al propio servidor.

## 8. Feeds, mapa, informe diario

- Feeds: `feeds_update.py` corre en el panel (hilo cada 15 min o botón) **sin** la parte de dataset,
  `suricata -T` y recarga; escribe en `FEEDS`. El dataset de dominios de Suricata sigue siendo del orquestador.
- Mapa: los ficheros vendorizados se sirven desde `nodos.MAPA`; la base GeoIP se baja en ejecución a `GEO`
  (como hoy, solo cambia la ruta).
- Informe diario (`informe_diario.py`): hilo del panel a las 07:30 en `IDS_TZ`, por nodo, un mensaje de
  Telegram con una sección por nodo y `IDS_EMPRESA` como nombre.

## 9. Decisiones de la segunda ronda (usuario, 2026-10-11)

Respuestas al documento «Suricata IDS Lab: definición de la evolución multisonda»:

- Confirmado: 1 VPS = 1 empresa con todos los MikroTik que quiera; un contenedor OpenVPN por MikroTik; RouterOS
  6.49+ y v7 con OpenVPN; por el túnel solo espejo y API; un punto = un MikroTik con identidad fija; almacenamiento
  separado por sonda y baja = borrar todo; cada servicio independiente; alta desde el formulario con espejo por API.
- **Prefijos del espejo: los elige el usuario por punto** (`redes` del alta, editables después con
  `punto.ajustar`). Al cambiarlos, la ficha del punto ofrece volver a aplicar el espejo (la address-list
  `ids-vigilados` del router) con la misma vista previa.
- **Página «Eventos»** por nodo y en «Todos» (sustituye al buscador de EveBox): filtros por fecha/hora, firma
  (texto o SID), severidad, IP origen/destino, puerto, protocolo y tipo de evento; resultados paginados, más
  recientes primero; detalle con el JSON completo del evento; columna Nodo en «Todos». Lee los `eve.json*`/
  `dns.json*` del nodo (también los `.gz` rotados) con tope de bytes leídos y de tiempo por consulta.
- **Retención: objetivo 30 días de eventos** (`eve.json` y `dns.json` de cada punto). `rotate`/`maxage` cuentan
  ficheros y edad, no garantizan días: la poda es **por fecha** (se borra lo que tiene más de 30 días según la
  marca de tiempo de sus eventos), con las rotaciones por tamaño fechadas (fecha y hora) y sin tope de número que
  corte días antes. **Protección de disco:** si `/srv/ids` baja del 15 % libre, el orquestador borra primero los
  rotados más viejos (de cualquier punto), registra cada borrado anticipado y avisa (`DISCO`). **Retención efectiva
  visible por nodo** (desde qué fecha hay eventos) en Puntos y en Eventos; nunca se promete 30 días si hubo
  borrado anticipado. Las bases derivadas del panel (historial, conducta, métricas) se podan a 30 días como mínimo y
  siguen sus tiempos actuales si son mayores.
- **Fuera de esta versión:** IPv6 y el respaldo/restauración por sonda (basta el respaldo del VPS).
- Todo se prueba en el VPS de laboratorio.

## 10. Correcciones de la revisión (instrucciones del coordinador, 2026-10-11)

### 10.1 Nodos inválidos (`nodos.py`, YA HECHO con `tests/test_nodos.py`)

| Situación | Respuesta |
|---|---|
| `?nodo=_todos` (selección expresa de Todos) | vista consolidada |
| Sin `?nodo=` | el de la sesión; si no hay, la vista consolidada (valor por defecto de la interfaz, documentado) |
| Identificador mal formado | `NodoInvalido` → **400**, sin ampliar el alcance |
| Formato correcto pero no existe | `NodoInexistente` → **404** «punto inexistente» |
| Sin contexto en un hilo | `SinContexto` (error de programación; nunca se supone un nodo) |
| Acción | destino = el de la propia operación (`pid|ip` o pid del formulario) validado con `exigir_pid()`; **nunca** el selector, la sesión ni `TODOS`. Sin destino inequívoco no se ejecuta |

El contexto se restablece también con excepción. Una petición sin `?nodo=` usa el último nodo elegido
en la sesión (compartida por las pestañas del navegador): por eso todo enlace y formulario del panel lleva
`nodo=` explícito, y una acción nunca toma su destino de ahí (auditoría A-11). Dos pestañas en nodos distintos: cada petición lleva su nodo y
cada acción su destino; cambiar el selector en una no cambia lo que hace la otra.

### 10.2 Permisos en el servidor (cada operación)

Roles del dashboard (se conservan): **admin**, **operador**, **lectura**. Se comprueban en el servidor en cada
ruta (GET y POST), con `_admin()`/`_operador()` (sin el antiguo `None` = sin autenticación). Ocultar un botón no
cuenta como control. Cambiar el nodo en URL/formulario no da más permisos: todos los usuarios de la empresa ven
todos sus puntos (decisión del usuario), pero cada operación exige su rol.

| Operación | lectura | operador | admin |
|---|---|---|---|
| Ver En vivo, Top, Detalle, Cuarentena, Consultar IP, Histórico, Reporte, **Eventos** (lista y detalle), descargar CSV/reportes, cambiar de nodo | sí | sí | sí |
| Cambiar su propia clave | sí | sí | sí |
| Cuarentena: enviar, quitar, graduada, masivas; excluir/quitar destino de confianza; DNS sospechoso; consultar/denunciar reputación | no | sí | sí |
| Exclusiones de detección, MikroTik (conexión, listas, reglas, políticas), públicas, feeds y claves, DNS, IA, empresa | no | no | sí |
| **Puntos**: ver la gestión, alta, baja, arrancar/parar/reiniciar, regenerar VPN, ajustar prefijos, API, **espejo** (plan/aplicar/pausar/retirar), logs | no | no | sí |
| Usuarios y roles, log de accesos, bitácora, actualizar reglas | no | no | sí |

Precisiones (auditoría B-18, 2026-10-12): «ver Cuarentena» incluye la **ficha de evidencia** de un CPE
(lectura); **refrescar el reporte de conducta** es de operador (lanza trabajo de fondo); **revisar públicas
(DNSBL)** es de admin, como el resto de públicas. Un botón que el rol no puede usar no se muestra.

La vista de estado de cada punto (colores del selector) la ven todos. Toda operación deja en la bitácora:
usuario o proceso, punto, objetivo, operación, fecha y resultado, sin secretos. Una masiva desde «Todos» se
descompone por punto y da el resultado por punto.

### 10.3 Secretos cifrados con la clave maestra (decisión del usuario: opción a)

Las claves de la API de cada router, las claves de AbuseIPDB/abuse.ch/Groq y el token de Telegram se guardan
**cifrados** con `/etc/ids-maat/master.key` ([DATOS.md](DATOS.md) §6), montada en el panel en
`/run/secrets/master_key` (ro). AES-GCM con el paquete `python3-cryptography` de Debian (apt verifica su sha256 contra el índice firmado de la base fijada por digest). En disco
solo va el texto cifrado; se descifra en memoria al usarlo; nunca sale en logs, bitácora, CI ni pantallas. Sin
la clave maestra el panel arranca y avisa de que no puede usar esos secretos (no los borra). Los ficheros de
configuración siguen en 0600. La clave maestra se respalda aparte (OPERACION §3) y su recuperación forma parte de
la prueba de restauración del VPS.

Módulo `secretos.py` YA ESCRITO (interfaz fija, con `tests/test_secretos.py`): `cifrar(texto, asociado)`,
`descifrar(valor, asociado)`, `necesita_cifrar(valor)`, `disponible()`, `SecretoNoDisponible`. `asociado` liga el
valor a su campo (p. ej. `router:p001:PASS`, `feeds:ABUSEIPDB_KEY`).

### 10.4 Evidencia reciente antes de actuar

Antes de enviar a cuarentena (manual, masiva o automática) una IP de abonado, se comprueba que la evidencia que la
justifica es **reciente** (alertas de ese `pid|ip` dentro de la ventana del reporte y como máximo de las últimas
24 h por defecto, configurable). Si la evidencia es más vieja, la acción automática no se ejecuta y la manual pide
confirmación explícita indicando la antigüedad (la IP puede haber cambiado de abonado).

### 10.5 Pruebas y auditoría

- Tres tipos de prueba: **conservación** (la capacidad original pasa en la base y en la adaptada), **corrección
  de defecto** (reproduce el defecto antes y demuestra la corrección después) y **capacidad nueva** (demuestra el
  requisito con resultados concretos). Un fallo de importación no cuenta como prueba de nada.
- Las pruebas de suricata-ids-lab se clasifican una a una: conservadas, adaptadas o retiradas con motivo.
- Casos obligatorios:

  | Caso | Resultado |
  |---|---|
  | Misma IP y mismo flujo en dos puntos | eventos y resultados separados por punto |
  | Acción sobre una IP repetida | solo cambia el MikroTik del destino de esa operación |
  | Dos operadores o tareas a la vez | sin mezcla de contexto ni pérdida de actualizaciones |
  | Doble clic o reintento | no duplica reglas, acciones ni puntos (idempotencia por destino y operación) |
  | Baja con trabajos pendientes | se cancelan o rechazan; nada alcanza a un punto creado después (los pid no se reutilizan) |
  | Timeout de la API tras enviar una orden | se relee el router antes de repetir; no se da por hecha sin comprobarla |
  | Recarga de reglas/threshold fallida | se conserva o recupera una configuración válida y se avisa |
  | Consulta que llega a su límite | se dice que es parcial y hasta dónde llegó; nunca «sin coincidencias» |
  | Rotación mientras se lee | sin mezcla, pérdida silenciosa ni duplicados sin control |
  | Saturación de un punto | se mide el efecto en los demás (cuotas de CPU/memoria por contenedor) |
  | Eventos: rutas manipuladas, enlaces simbólicos, JSON incompleto, `.gz` que descomprime mucho, HTML/JS en campos capturados | se rechaza o se escapa; límites por volumen descomprimido |
- Auditoría iterativa: hallazgo → reproducción → corrección → prueba → revisión independiente, hasta cerrar.
- Estados de cada afirmación: observado, riesgo pendiente, reproducido, corregido, verificado, bloqueado.
- Matriz de conservación (capacidad original → destino → prueba → estado) como entregable.

### 10.6 Salud por etapas

Por punto y por separado: VPN conectada, TZSP recibido, tráfico procesado por Suricata (contadores de captura y
descartes con su alcance), eventos actualizados, datos consultables. Estados: operativa, degradada, sin datos,
desconectada, deshabilitada, desconocido. VPN arriba, contenedor en marcha o cero alertas **no** son «sano». La
captura reducida (10 KB por conexión, prefijos elegidos) se muestra como tal.

## 11. Reparto (constructores en paralelo, cada uno solo en sus zonas)

Las zonas de `dashboard.py` van **por símbolo** (funciones y métodos) en
[CONTRATO-F2-zonas.md](CONTRATO-F2-zonas.md); los números de línea solo orientan sobre el commit base. Quien necesite
algo de otra zona lo pide en su informe en vez de tocarlo. Integración por etapas: N → P y E → R.

| | Zonas | Entrega |
|---|---|---|
| | **Todos**: rol comprobado en cada ruta propia (§10.2), secretos con `secretos.py` donde los toquen (§10.3), destinos con `nodos.exigir_pid()` (§10.1), pruebas de su zona en ficheros propios (`tests/test_n_*.py`, `test_p_*.py`, `test_eventos_*.py`, R el resto) |
| **N (núcleo)** | `dashboard.py` 1–7580, 7801–9399, 12825–13420, 15534–15697 (infra de `class H`: `_seguro`, `_set_ctx`, auth, proxy, CSRF), 17549–fin (`do_HEAD`, `main`); `idspanel/cli.py` | rutas por `nodos`, contexto, routers = puntos, cliente API por relé, tareas de fondo por nodo, eventos/historial/conducta por nodo y «Todos», usuarios y sesiones, evidencia reciente (§10.4), salud por etapas (§10.6, datos), quitar OpenVPN/espejo_vpn/mkinit/updater/systemctl/EveBox de sus zonas |
| **P (pantallas)** | `dashboard.py` 7581–7800 (`_NAV_LINKS`, `nav`), 9400–12824 (Ajustes, Documentación), 13421–15533 (páginas), 15698–17548 (`_get`, `_post`, `_post_perfil`, `_post_exclusiones`); nuevo `puntos_web.py` | selector de nodo (400/404 de §10.1), columnas/chips de Nodo en «Todos», apartado Puntos con salud por etapas y retención efectiva, Ajustes, quitar rutas/tarjetas/textos de lo eliminado, Documentación reescrita donde nombra lo viejo |
| **E (eventos)** | nuevo `eventos_web.py` | búsqueda y detalle de eventos (§9); P registra `GET /eventos` y la pestaña |
| **R (resto)** | `html_report.py`, `feeds_update.py`, `mikrotik_init.py`, `informe_diario.py`, `orquestador/`, `images/panel/Dockerfile`, `images/panel/rootfs/usr/local/bin/ids-panel`, `idspanel/` salvo `cli.py`, `tests/`, `.github/`, docs salvo este contrato | generador por nodo y «Todos», feeds sin dataset, retención objetivo 30 días por fecha + poda por disco registrada + retención efectiva en estado.json (§9), `master.key` montada en el panel y `cryptography` en la imagen (§10.3), espejo sin `accept` (OPERACION §2), espejo como módulo por relé, informe, `punto.threshold`, memoria, imagen, borrar el panel F1b-min que sobra, pruebas (port de las 87 de suricata-ids-lab que sigan aplicando + nuevas), e2e paso 7 |

Cada constructor: trabaja en su worktree sin commitear, escribe pruebas de **comportamiento** de lo suyo en
`tests/`, y entrega un informe con lo hecho, lo que pide a otros y lo que no pudo cerrar.
