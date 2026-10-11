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
  (comentario `IDS ids-maat:<pid>`, `connection-bytes=0-10000`, accept antes del fasttrack, **sin** regla de DNS
  aparte). Si OPERACION.md y mkinit chocan, manda OPERACION.md.
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
- La baja borra todo el punto en el orquestador **y** en el panel: `nodos/<pid>/`, su entrada de `routers.json`
  y las claves `pid|…` de los registros globales. Queda una línea en la bitácora.

## 6. Orquestador

- `estado.json` por punto añade `redes`, `api_puerto`, `sensor`, `mk`, `tzsp_puerto` (YA HECHO).
- **`punto.threshold {pid, contenido}`** pasa de reservada a orden de cola: escribe
  `/srv/ids/puntos/<pid>/suricata/threshold.config` (atómico, validado: solo líneas `suppress`/`threshold`/
  `event_filter`/comentarios) y recarga Suricata de ese punto sin cortar el espejo
  (`suricatasc -c reload-rules` por el socket de control; si falla, reinicio del contenedor `suricata`).
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
- **Retención: 30 días de eventos** (`eve.json` y `dns.json` de cada punto): rotación diaria, `rotate 30`,
  `maxage 30`, comprimidos, nombres con fecha y hora para las rotaciones por tamaño. Si el disco baja del 15 %
  libre, el orquestador borra primero los rotados más viejos de todos los puntos y avisa (`DISCO`). Las bases
  derivadas del panel (historial, conducta, métricas) se podan a 30 días como mínimo y siguen sus tiempos actuales
  si son mayores.
- **Fuera de esta versión:** IPv6 y el respaldo/restauración por sonda (basta el respaldo del VPS).
- Todo se prueba en el VPS de laboratorio.

## 10. Reparto (constructores en paralelo, cada uno solo en sus zonas)

Números de línea del `dashboard.py` heredado (commit `af5fe35`). Quien necesite algo de otra zona lo pide en
su informe en vez de tocarlo.

| | Zonas | Entrega |
|---|---|---|
| **N (núcleo)** | `dashboard.py` 1–7580, 7801–9399, 12825–13420, 15534–15697 (infra de `class H`: `_seguro`, `_set_ctx`, auth, proxy, CSRF), 17549–fin (`do_HEAD`, `main`); `idspanel/cli.py` | rutas por `nodos`, contexto, routers = puntos, cliente API por relé, tareas de fondo por nodo, eventos/historial/conducta por nodo y «Todos», usuarios y sesiones, quitar OpenVPN/espejo_vpn/mkinit/updater/systemctl/EveBox de sus zonas |
| **P (pantallas)** | `dashboard.py` 7581–7800 (`_NAV_LINKS`, `nav`), 9400–12824 (Ajustes, Documentación), 13421–15533 (páginas), 15698–17548 (`_get`, `_post`, `_post_perfil`, `_post_exclusiones`); nuevo `puntos_web.py` | selector de nodo, columnas/chips de Nodo en «Todos», apartado Puntos, Ajustes, quitar rutas/tarjetas/textos de lo eliminado, Documentación reescrita donde nombra lo viejo |
| **E (eventos)** | nuevo `eventos_web.py` | búsqueda y detalle de eventos (§9); P registra `GET /eventos` y la pestaña |
| **R (resto)** | `html_report.py`, `feeds_update.py`, `mikrotik_init.py`, `informe_diario.py`, `orquestador/`, `images/panel/Dockerfile`, `images/panel/rootfs/usr/local/bin/ids-panel`, `idspanel/` salvo `cli.py`, `tests/`, `.github/`, docs salvo este contrato | generador por nodo y «Todos», feeds sin dataset, retención de 30 días (logrotate + poda por disco), espejo como módulo por relé, informe, `punto.threshold`, memoria, imagen, borrar el panel F1b-min que sobra, pruebas (port de las 87 de suricata-ids-lab que sigan aplicando + nuevas), e2e paso 7 |

Cada constructor: trabaja en su worktree sin commitear, escribe pruebas de **comportamiento** de lo suyo en
`tests/`, y entrega un informe con lo hecho, lo que pide a otros y lo que no pudo cerrar.
