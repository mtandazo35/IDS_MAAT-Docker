# Pruebas heredadas de suricata-ids-lab

Clasificación, una a una, de las 87 entradas de `suricata-ids-lab/tests/` (commit `5b89110`, el
mismo del panel copiado; ver [PANEL-HEREDADO.md](PANEL-HEREDADO.md)) al pasar al panel de
IDS_MAAT-Docker ([CONTRATO-F2-panel.md](CONTRATO-F2-panel.md) §10.5).

Las portadas viven en `tests/legado/`, con el mismo nombre de fichero.

## Cómo se ejecutan

```sh
python -m unittest discover -s tests/legado -p "test_*.py" -v    # solo las heredadas
python -m unittest discover -s tests -p "test_*.py"              # todas (tests/legado es un paquete)
python -m pyflakes tests/legado
```

- **Python ≥ 3.11**, sin dependencias externas, sin red y sin rutas fijas: todo lo temporal va con
  `tempfile` y se borra al terminar.
- **node** (cualquier versión con `Proxy` y `new Function`; probado con v24.15.0) para las 7 pruebas
  `.js` (`test_navegador.py`) y para `test_overlay_seleccion.Legado.test_guarda_real_en_node`. Sin
  node esas 8 se **omiten** con el motivo `node no disponible`; el resto corre igual. En el CI
  (ubuntu-latest) node ya viene en el runner.
- `tests/run.sh` ya las ejecuta: su `unittest discover -s tests` entra en `tests/legado/`
  (lleva `__init__.py`). No hace falta tocar `run.sh` ni el CI.

## Cómo están hechas

- `tests/legado/extraer.py`: el `extraer.py` viejo adaptado. Lee directamente los ficheros del panel
  (`dashboard.py`, `html_report.py`, `feeds_update.py`, `mikrotik_init.py`, `informe_diario.py`) en
  vez de los heredocs de `install-suricata.sh`. Mismas firmas: `heredoc(src, nombre)` (ahora `src` se
  ignora y `nombre` es el binario viejo, el marcador del heredoc o el fichero nuevo), `literal`,
  `asignacion`, `funcion`, `cuerpo_ruta`; `extraer(destino)` deja los mismos artefactos
  (`sort.js`, `pos.js`, `ask.js`, `masivo.js`, `mapa.js`, `ruta_uno.py`, `ruta_masivo.py`).
  Nuevos: `fuente(nombre)`, `ruta(nombre)`, `RAIZ`, `LIB`, `SHARE`, `MAPA`.
- `tests/legado/_comun.py`: las pruebas viejas eran guiones (`check()` imprime OK/FALLA y termina
  con «TODO OK»). Se conservan tal cual y `correr_main()` las lanza desde unittest: cualquier FALLA
  es un fallo de la prueba con las líneas que fallaron. `correr_node()` lanza un `.js` y lo omite sin
  node. `cargar_nodos(raiz, puntos)` da un `nodos.py` real con raíces temporales y un `estado.json`.
- **Conservada** = solo cambia cómo se carga el código (cabecera, envoltorio unittest, imports sin
  usar que marcaba pyflakes); la lógica y las comprobaciones son las de origen.
- **Adaptada** = cambia lo que la prueba comprueba o contra qué, y se dice qué y por qué.
- **Retirada** = lo que probaba ya no existe en IDS_MAAT-Docker; se dice qué lo sustituye.

- `_comun.panel(raiz, puntos, nodo)` (añadido al integrar): `nodos` y `secretos` REALES del panel
  portado sobre un árbol temporal (`panel/`, `datos/`, `run/estado.json` con `PUNTOS` = p001 y p002,
  clave maestra de prueba); `correr_main` deja el entorno y el nodo del hilo como estaban.
  `_comun.piezas(ns, nombres)` ejecuta en un espacio de nombres las definiciones reales del
  dashboard (no copias).

Resultado anterior (SHA base `4323145` + árbol de R, `dashboard.py` sin N y P): `Ran 68 tests … OK`.

Resultado con el dashboard integrado (`bfbe690`, N + P + E + R) y las pruebas adaptadas
(2026-10-12, Windows 10 + Python 3.12 + node v24.15.0): `Ran 68 tests … FAILED (failures=2)`, las
dos por lo que se describe en «Posibles regresiones y defectos» (no se ajustan para que pasen);
`pyflakes tests/legado` limpio. `python tests/correr.py --obligatorias windows`: `Ran 605 tests`,
2 fallos (esos dos), 25 omitidas (ninguna obligatoria en Windows).

## Recuento

| Estado | Entradas |
|---|---|
| Conservada | 28 (21 `.py` + 7 `.js`) |
| Adaptada | 40 (38 `.py` + `extraer.py` + `pcap/`) |
| Retirada | 19 (14 `.py` + 3 `.sh` + `run.sh` + `__pycache__/`) |
| **Total** | **87** |

Al integrar N/P pasaron de conservada a adaptada 24 pruebas: cambian contra qué comprueban
(claves `pid|ip`, rutas por nodo, destino validado, relé unix, secretos cifrados, sin modo sin
usuarios…) y cada cambio cita su sección del contrato. Ninguna comprobación se ha quitado: en
todas el número de `check()` es igual o mayor que antes.

## Posibles regresiones y defectos (detectados por las heredadas; ya corregidos en el código)

| Prueba | Comprobación que falla | Símbolo | Evidencia |
|---|---|---|---|
| `test_ip_sensor` | nunca devuelve loopback ni 0.0.0.0 — **corregido**: `sensor_del_punto` vuelve a dar el hueco ante loopback, 0.0.0.0, multicast, link-local o no IPv4, y el espejo se niega; la prueba pasa | `sensor_del_punto` (`dashboard.py`), `_espejo_datos`; `mikrotik_init._validar` solo exige IPv4 | el original `ip_del_sensor` (4323145) nunca daba `0.*` ni `127.*` (ante la duda, hueco y el espejo se negaba); el portado devuelve tal cual el `sensor` de estado.json → un plan de espejo con `sniff-target=127.0.0.1`/`0.0.0.0` sin aviso. Gravedad baja (el valor lo publica el orquestador), pero es una defensa que se perdió |
| `test_rutas_get` | ningún import dentro de una rama del manejador — **corregido**: `import eventos_web` en la cabecera del dashboard; la prueba pasa | `H._get`, `import eventos_web` dentro de la rama `/eventos` | convierte el nombre en local de todo `_get`: el mismo patrón que dio el 502 de `_up` en el original. Hoy no revienta (solo se usa en esa rama). Arreglo en el código: importarlo a nivel de módulo junto a `puntos_web` |

Métodos de unittest en `tests/legado/`: 68 (59 pruebas `.py` heredadas, 7 `.js` en
`test_navegador.py` y 2 métodos nuevos: `test_cobertura_sensor…test_tzsp_json_del_receptor_nuevo` y
`test_overlay_seleccion…test_guarda_real_en_node`).

## Tabla

Columna «Al integrar N/P»: lo que se sabía que cambiaría con los cambios de `dashboard.py` de N y P.
Ya integrados (`bfbe690`): «hecho al integrar» = adaptada y descrita en «Cambio o motivo»; si queda
algo pendiente se dice ahí.

| Fichero origen | Qué probaba | Estado | Cambio o motivo | Destino | Resultado aquí | Al integrar N/P |
|---|---|---|---|---|---|---|
| `extraer.py` | sacar piezas de los heredocs de `install-suricata.sh` | adaptada | lee los ficheros del panel; mismas firmas. Al integrar: `literal` toma la rama `else` de un `IfExp` (el `&nodo=` opcional de `qs_nodo()`), que antes salía como `{}` y rompía `masivo.js` | `tests/legado/extraer.py` | usado por todas | hecho al integrar (bfbe690) |
| `run.sh` | lanzar las 80 pruebas y contar «TODO OK» | retirada | lo sustituye `unittest discover` (`tests/run.sh`) y `_comun.correr_main` | — | — | — |
| `pcap/` | banco de regresión de detección (5 casos + generador + comparador + `run.sh` con Suricata del host) | adaptada | se copian `generar.py`, `comparar.py` y los 5 casos (54 KB); `run.sh` no (pasaba las capturas por el Suricata del host) | `tests/legado/pcap/` | usado por `test_pcap_banco` | — |
| `__pycache__/` | (caché de Python) | retirada | no es una prueba | — | — | — |
| `test_abuseipdb.py` | AbuseIPDB: cuota, caché, privacidad, categorías, bloques | adaptada | `nodos`/`secretos` reales (`_comun.panel`); clave de AbuseIPDB cifrada en feeds.conf (§10.3, +1 comprobación «va cifrada, no en claro»); r1→p001; nodo del hilo p001 para `reputacion_page`; `clave_cpe`/`ip_de` reales | `tests/legado/test_abuseipdb.py` | ok | hecho al integrar (bfbe690) |
| `test_abuseipdb_denuncia.py` | denuncias apagadas por defecto y con frenos | conservada | solo la carga: `nodos`/`secretos` reales; la clave pasa cifrada por `secretos.py` (§10.3) | ídem | ok | hecho al integrar (bfbe690) |
| `test_abuso_saliente.py` | contadores diarios de abuso saliente y tendencia (generador + panel) | adaptada | generador sin cambios; panel con `nodos` real: `metricas.json`, `cuarentena.json` y `entrantes.json` por punto (`nodos/<pid>/`), `acciones.json` global, un router por punto y `clave_cpe` real (`pid|ip`, §1); §4: «el router se baja la lista solo» pasa a «la lista se pega como script, sin `/tool fetch` ni scheduler»; + subcaso §3: p002 no ve las métricas de p001 | ídem | ok | hecho al integrar (bfbe690) |
| `test_accesos_bitacora.py` | Accesos y Bitácora responden cada una su pregunta | conservada | solo la carga: `nodos`/`secretos` reales (los logs salen de `nodos.ruta`) | ídem | ok | hecho al integrar (bfbe690) |
| `test_acciones_router.py` | políticas por categoría en el router (RouterOS falso): plantillas, respaldo, idempotencia | conservada | solo la carga: `nodos` real; `RESPALDOS_MK` = `nodos.RESPALDOS/mikrotik` (§2); router r1 → punto p001 (§1); +1 comprobación: el respaldo queda bajo `nodos.RESPALDOS` | ídem | ok | hecho al integrar (bfbe690) |
| `test_acciones_ui.py` | tarjeta de Ajustes y rutas plan/aplicar/quitar | adaptada | sin `router_defecto` (§3): destino = rid del formulario validado con `_router_de_pid`; selector de router siempre, también con un punto, y preselecciona el nodo mirado; `/routers/*` quitadas (§4); `_prohibido` (§10.2); subcaso: rid vacío/`r1`/`p009` → ERR sin tocar el router | ídem | ok | hecho al integrar (bfbe690) |
| `test_cache_abuseipdb.py` | caché de AbuseIPDB: un parseo por cambio, sin datos viejos | conservada | — | ídem | ok | — |
| `test_cache_config.py` | caché de configuración rápida y sin datos viejos | conservada | — | ídem | ok | — |
| `test_clusterid_unico.py` | cada interfaz de espejo con su cluster-id (instalador) | retirada | clusterid de varias interfaces en un Suricata del host; ahora un Suricata por punto con su interfaz | `tests/test_suricata_plantilla.py` (captura af-packet fija) | — | — |
| `test_cobertura_sensor.py` | cobertura del espejo: nodos mudos, origen rechazado, desperdicio | adaptada | se conserva entera y se añade `test_tzsp_json_del_receptor_nuevo` (`tzsp.json` del receptor REAL del contenedor vpn). Al integrar: el latido pasa a `nodos.tzsp_json(pid)` = `RUN/<pid>/tzsp.json` (§10.6); + subcaso: p002 sin latido no hereda el de p001 | ídem | ok (2 métodos) | hecho al integrar (bfbe690) |
| `test_conducta_3dias.py` | reporte de 3 días por CPE, rotados incluidos, solo tus abonados | adaptada | eventos del punto (`DATOS/<pid>/`) y reporte por punto (`nodos/<pid>/conducta.json`) con `nodos` real; piezas `qs_nodo`/`_nodo_oculto`; + subcasos §3: un punto no ve el otro, «Todos» une filas por nodo sin sumar y el CSV lleva la columna Nodo | ídem | ok | hecho al integrar (bfbe690) |
| `test_csrf_origen.py` | un formulario de otra web no puede mandar acciones (Origin/Referer/Sec-Fetch-Site/proxy) | adaptada | la acción de ejemplo pasa de `/vpn/sensor-aplicar` (retirada) a `/cuarentena/enviar`; piezas reales `_redes_proxy`, `proxy_confiable`, `_Cabeceras`, `_origen_con_proxy` (`PROXIES_OK` = 127.0.0.1, §7); `_seguro`/`_limpiar_ctx` reales con `nodos` (§10.1); + casos: `X-Forwarded-Host`/`Forwarded` de un par no confiable no validan un Origin ajeno (403, §7) | ídem | ok | hecho al integrar (bfbe690) |
| `test_cuarentena_aviso.py` | el aviso de Cuarentena no pinta texto libre de la URL | adaptada | el doble usa el `_ctx_nodo` real (nodo del hilo antes de cada ruta, §10.1; sin él no se pintaba nada); claves `pid|ip` (§1); `_destino_ok`/`_router_de_pid` reales; +1 comprobación: la redirección conserva `&nodo=` | ídem | ok | hecho al integrar (bfbe690) |
| `test_cuarentena_identidad.py` | enviar/quitar por identidad (router, IP), al router del CPE | adaptada | r1/r2 → p001/p002; routers por punto con el `guardar_routers` real y clave cifrada (§4, §10.3); `cuarentena.json` por nodo (§3); el subcaso «con un solo nodo, IP pelada» pasa a `p001|ip` (§1) y se añade «IP pelada → destino no válido, no se envía» (§10.1) | ídem | ok | hecho al integrar (bfbe690) |
| `test_culpables_ficha.py` | la ficha de una pública dice qué CPE privado está detrás | conservada | — | ídem | ok | — |
| `test_culpables_listado.py` | de «me listaron» a «mira a estos abonados» | conservada | — | ídem | ok | — |
| `test_dataset_feeds.py` | dominios de feeds como dataset de Suricata (base64), `suricata -T` y recarga, regla y creación en el instalador | retirada | §8: el panel baja feeds **sin** dataset, `-T` ni recarga; el dataset es del orquestador | `tests/test_reglas_feeds.py` (dataset base64, vacío si fallan), `tests/test_reglas_release.py`, `tests/test_feeds_panel.py` (R: sin dataset) | — | — |
| `test_destinos_malos.py` | bloquear destinos de mala reputación: solo públicas y lo sólido | conservada | solo la carga: rutas por `nodos.py` y `destinos-malos.json` en la salida del nodo (§3). `destinos_rsc` sigue (descarga manual de admin; §4 solo quita el `/tool fetch`): sus 3 comprobaciones se quedan | ídem | ok | hecho al integrar (bfbe690) |
| `test_detectar_publicas.py` | detectar del MikroTik solo WAN y pools de srcnat | adaptada | router obligatorio (`_router_destino`, §3); la ruta usa el rid validado con `_router_de_pid` (§10.1) y guarda por pid; el doble lleva `_ctx_nodo`/`_prohibido`; subcaso: rid vacío/`r1`/`p009` → no se pregunta al router ni se guarda nada | ídem | ok | hecho al integrar (bfbe690) |
| `test_diagnostico_mk.py` | qué le falta al MikroTik para poder cortar | adaptada | router obligatorio (§3, +1 comprobación: sin router, ValueError); el espejo ya no es `/tool sniffer` sino las 2 reglas mangle `sniff-tzsp` hacia `punto.sensor` (§4, OPERACION §2) con `sensor_del_punto` real; subcasos: hacia otro sensor, un solo sentido o desactivadas no cuentan | ídem | ok | hecho al integrar (bfbe690) |
| `test_dnsbl_historial.py` | historial de listas negras: cuándo entró y cuánto estuvo | conservada | — | ídem | ok | — |
| `test_documentacion.py` | documentación por páginas, categorías, buscador, modal | adaptada | el tema de ejemplo «Salud del sensor» (suricatasc/systemctl, quitados por §1) pasa a «Salud de cada punto (por etapas)» (§10.6); 38 temas (≥ 20) y las mismas 5 categorías | ídem | ok | hecho al integrar (bfbe690) |
| `test_dominios_maliciosos.py` | qué dominios malos se consultan, quién y por dónde (generador) | conservada | — | ídem | ok (con el generador de R) | — |
| `test_error_500.py` | una página que revienta da 500 explicado | adaptada | dónde mirar el detalle: `docker logs ids-panel` en vez de journalctl (§1); `_limpiar_ctx` real; + casos §10.1: tras un error no quedan nodo ni usuario en el hilo, la siguiente petición de la conexión recibe su 500, nodo mal formado 400 e inexistente 404 | ídem | ok | hecho al integrar (bfbe690) |
| `test_espejo_estado.py` | `suricata-espejo`: «¿estoy leyendo tráfico?» en el host | retirada | comando del host (systemctl, contadores de tzsp-decap del host) | salud por etapas de N (§10.6), `tests/test_vpn_tzsp.py` (latido `tzsp.json`), `tests/test_suricata_salud.py`, `legado/test_cobertura_sensor.py` | — | — |
| `test_espejo_vpn.py` | Ajustes > VPN: montar el espejo re-ejecutando el instalador (systemd-run, -a, respaldo) | retirada | espejo VPN propio e instalador | `tests/test_mkinit_espejo.py` (R), `legado/test_mikrotik_init.py`, ficha Espejo de Puntos (P) | — | — |
| `test_exclusiones_modal.py` | alta de exclusiones en un modal (página renderizada) | conservada | solo la carga: `nodos` real y la pieza `REPORT_CONF` | ídem | ok | hecho al integrar (bfbe690) |
| `test_fecha_actualizacion.py` | fecha y antigüedad de la última actualización del panel | retirada | actualizador por git (`/etc/suricata-dashboard.updated`) | nada aún: la actualización es por imagen (`sistema.actualizar`, orden reservada) | — | — |
| `test_feeds_nuevas.py` | ThreatFox ip:port, ET compromised, Tor como contexto | adaptada | la comprobación de documentación mira `dashboard.py` (antes el instalador); `DESTINOS_FILE` se localiza sin su ruta vieja (ahora la del nodo) | ídem | ok (con `feeds_update.py` y generador de R) | — |
| `test_ficha_desplegable.py` | «Ver qué hace» se despliega en la tabla | conservada | — | ídem | ok | — |
| `test_ficha_kpis.py` | ficha por firma y cuadros que no se descuadran | conservada | — | ídem | ok | incluye comprobaciones de CSS/texto: frágiles si P toca estilos |
| `test_form_mikrotik.py` | formulario MikroTik: conexión aparte, listas por tipo de abuso | adaptada | §4: sin HOST/puerto (relé unix) ni `/routers/*`; `guardar_mk` guarda solo lo global y la conexión del nodo del formulario va a `routers.json` con la clave cifrada (§10.3, +comprobación con `cargar_routers`/`guardar_routers` reales); el aviso de Telegram recibe `pid|ip` (§3) | ídem | ok | hecho al integrar (bfbe690) |
| `test_groq_ajustes.py` | clave de Groq validada antes de guardar y que no sale | adaptada | clave de Groq cifrada en feeds.conf (§10.3: «`GROQ_API_KEY=clave-secreta` en claro» pasa a «presente y cifrada», +1 comprobación); sin rol admin → `_prohibido()` (403 + bitácora) en vez de `_deny()` (§10.2) | ídem | ok | hecho al integrar (bfbe690) |
| `test_historial_db.py` | historial persistente: sobrevive a reinicio y logrotate | adaptada | una base por punto (`nodos.salida("historial.db", pid)`) y eventos del punto (`DATOS/<pid>/eve.json*`) con `nodos` real; + subcasos §3: la base de p001 no ve p002 y «Todos» une filas con su nodo sin sumar | ídem | ok | hecho al integrar (bfbe690) |
| `test_ia_lectura.py` | lectura con IA sin datos del abonado y con fallo suave | conservada | solo la carga: `nodos` real para las rutas de IA (§2) | ídem | ok | hecho al integrar (bfbe690) |
| `test_identidad_nodo.py` | identidad (router, IP): dos nodos con el mismo rango no se confunden | adaptada | router = pid del fichero (no `in_iface` + `ROUTERS_MAP`, que no existen); con el `html_report.py` y `nodos.py` reales. Cambio deliberado comprobado: con un solo punto la identidad es `pid\|ip`, nunca la IP pelada; chips solo en `--todos` | ídem | ok | — |
| `test_insignia_confianza.py` | insignia «Confirmado» y cuántas pruebas | conservada | — | ídem | ok | casi todo son textos del panel y del generador: frágil si P los reescribe |
| `test_instalador_claves.py` | las claves que entrega el instalador (panel y EveBox) | retirada | instalador y EveBox | `tests/test_orq_panel.py` / `tests/_ayuda_orq.py` (`crear-admin` imprime `CLAVE=`), `tests/test_host_install.sh` | — | — |
| `test_instalador_defectos.sh` | con qué valores nace una caja nueva | retirada | instalador del host viejo | `tests/test_host_install.sh` | — | — |
| `test_instalador_espejo.sh` | instalador local o VPN sin colgar un `curl\|bash` | retirada | instalador y modo local/VPN | `tests/test_host_install.sh` | — | — |
| `test_instalador_multi.sh` | instalador: una interfaz por router | retirada | interfaces `ids-monN` del host | un contenedor vpn y uno Suricata por punto: `tests/test_orq_render.py` | — | — |
| `test_ip_sensor.py` | la IP del sensor puesta en los comandos del MikroTik | adaptada | IP del sensor = `punto.sensor`/`tzsp_puerto` de estado.json (§4), sin adivinar por ruta ni router por defecto (§3); `sensor_del_punto`/`_espejo_datos` reales; sin punto o sin sensor, el espejo se niega | ídem | ok (fallaba hasta corregir `sensor_del_punto`, ver abajo) | regresión corregida en el código |
| `test_listas_categoria.py` | una address-list por categoría de abuso | adaptada | `cuarentena.json` del punto de la clave (§3) y `pid|ip` (§1); `clave_cpe`/`cuarentena_json` reales | ídem | ok | hecho al integrar (bfbe690) |
| `test_listas_desplegable.py` | desplegable con las IPs de cada lista | adaptada | la ficha se abre por identidad `verFicha('pid|ip')`, igual que «ver evidencia» (§1); lista filtrada por los nodos vistos (§3, +1 comprobación) | ídem | ok | hecho al integrar (bfbe690) |
| `test_mapa.js` | mapa del reporte: zoom, detalle, sin bordes negros | conservada | se lanza desde `test_navegador.py` | `tests/legado/test_mapa.js` | ok (node) | — |
| `test_masivo_progreso.js` | quitado masivo: avance, fallo a mitad y cierre | conservada | se lanza desde `test_navegador.py`; `masivo.js` sale con el `extraer.literal` corregido (`IfExp`) | `tests/legado/test_masivo_progreso.js` | ok (node) | hecho al integrar (bfbe690) |
| `test_masivo_ui.js` | quitado masivo: selección y modal | conservada | ídem | `tests/legado/test_masivo_ui.js` | ok (node) | hecho al integrar (bfbe690) |
| `test_mikrotik_init.py` | `suricata-mikrotik-init` contra un MikroTik falso | adaptada | módulo `plan`/`aplicar` en vez de CLI; se conservan idempotencia, espejos ajenos intactos, apagar el viejo antes de crear, fasttrack, vista previa = lo aplicado, parar en el primer fallo, sin `/export` no se toca nada. Cambios deliberados comprobados: **sin regla DNS aparte**, recorte siempre, ninguna `accept`, comentario propio `IDS ids-maat:<pid>:espejo` (auditoría A-02: el del alta, `IDS ids-maat:<pid>`, no se toca). Retirado: alta en el panel (`ENABLED=0`), fichero de credenciales, modo local, cliente api-ssl del dashboard | ídem | ok (29 comprobaciones) | — |
| `test_mis_redes.py` | `es_mi_cpe`: solo tus redes entran a la cuarentena | adaptada | el generador corre por nodo: se le da `nodos.py` con un punto; se añade la capacidad nueva (sin `MIS_REDES`, valen las `redes` del punto); IPs reales del caso cambiadas por RFC 5737 | ídem | ok | — |
| `test_mk_tls.py` | api-ssl: recuerda el cifrado, dice cada fallo, una conexión | adaptada | conexión solo por relé unix + TLS (§4): hosts `unix:<api.sock>` del punto, `_mk_abrir_unix` con doble (sin AF_UNIX real); «por router» pasa a «por relé de punto»; + host no `unix:` rechazado sin abrir socket | ídem | ok | hecho al integrar (bfbe690) |
| `test_modal_confirm.js` | el modal propio repite la pulsación al confirmar | conservada | se lanza desde `test_navegador.py` | `tests/legado/test_modal_confirm.js` | ok (node) | — |
| `test_nav_usuario.py` | menú del usuario y su foto por `/mi-foto` | adaptada | §1 sin modo sin usuarios: se conserva el «Salir» de `_menu_usuario` y se añade, con `_auth_ok`/`_sesion_ok` reales, «sin sesión y sin usuarios no se entra → /login»; «botón en la barra y panel fuera» pasa de literal a regex (detrás de `_upanel` ya no van los modales del actualizador retirado) | ídem | ok | hecho al integrar (bfbe690) |
| `test_openvpn_cli.py` | `/root/openvpn.sh` sin menú (usuarios, redes) | retirada | OpenVPN propio | `tests/test_vpn_scripts.py`, `tests/test_vpn_ovpn_auth.py`, `tests/test_vpn_render.py`, `tests/test_orq_comandos.py` | — | — |
| `test_openvpn_sh.py` | instalador de OpenVPN en /root | retirada | OpenVPN propio e instalador | ídem | — | — |
| `test_orden.js` | tablas: orden asc/desc y fechas por tiempo real | conservada | se lanza desde `test_navegador.py` | `tests/legado/test_orden.js` | ok (node) | — |
| `test_orden_persiste.js` | el orden sobrevive a la recarga | conservada | ídem | `tests/legado/test_orden_persiste.js` | ok (node) | — |
| `test_overlay_seleccion.py` | seleccionar texto en un modal no lo cierra | adaptada | se recorren `dashboard.py`, `html_report.py`, `puntos_web.py` y `eventos_web.py`; `test_guarda_real_en_node` con los manejadores reales. Al integrar: el mínimo de capas baja de 11 a 9 (`CAPAS_MIN`) porque se quitan `updov` y `updask` del actualizador (§1); +1 comprobación: no quedan restos de esas capas | ídem + `guarda_capas.js` | ok (2 métodos) | hecho al integrar (bfbe690) |
| `test_parse_ts.py` | `parse_ts` con memoria: mismo resultado | conservada | — | ídem | ok (generador de R) | — |
| `test_pcap_banco.py` | banco de PCAP: generador determinista y comparador fallo/aviso | adaptada | el generador corre sobre una copia temporal (escribía en el árbol) y se comprueba que da lo versionado | ídem | ok | — |
| `test_perf_generador.py` | índice de flujos y memorias del generador, mismos resultados | conservada | — | ídem | ok (generador de R) | — |
| `test_plan_bloqueo.py` | la IA ordena lo medido y no inventa puertos | conservada | solo la carga: `nodos` real para las rutas de IA (§2) | ídem | ok | hecho al integrar (bfbe690) |
| `test_politicas_clase.py` | políticas por clase de abuso | adaptada | `aplicar_politicas(pid)` por punto con claves `pid|ip` reales, el `cuarentena.json` del punto y `mk_listo` de su router (§3); + subcasos: otro punto ni entra ni sale (§3), evidencia vieja no se envía (§10.4); la documentación se mira en `dashboard.py` | ídem | ok | hecho al integrar (bfbe690) |
| `test_posicion.js` | la página conserva la posición tras una acción | conservada | se lanza desde `test_navegador.py` | `tests/legado/test_posicion.js` | ok (node) | — |
| `test_publicas_limpiar.py` | vaciar de una vez las públicas de un nodo | adaptada | «ningún byte NUL» se mira en cada fichero del panel (antes en el instalador); `nodos` real (`PUBLICAS_CONF` por `nodos.ruta`); r1..r9 → p001..p009 (§1) | ídem | ok | hecho al integrar (bfbe690) |
| `test_publicas_mitigacion.py` | públicas del cliente: vigilancia y cruce con el abonado | adaptada | claves `pid|ip` y r1/r2 → p001/p002 (§1); `cuarentena.json` por nodo vía `nodos.salida` (§3); clave AbuseIPDB cifrada (§10.3); +1 comprobación: mirando p002 salen los suyos | ídem | ok | hecho al integrar (bfbe690) |
| `test_recargar_listas.py` | sync contra SU lista y recargar lo que falta | adaptada | sync y recarga por nodo con `pid|ip`, sin router por defecto (`_router_destino`, §1, §3, §10.1); + una entrada vieja sin pid no se toca; recargar sin destino o con `p009` lanza sin conectar | ídem | ok | hecho al integrar (bfbe690) |
| `test_recorte_flujo.py` | recorte por flujo en el receptor TZSP del host | retirada | tzsp-decap del host | `tests/test_vpn_tzsp.py` (primeros bytes, dos sentidos, VLAN, DNS sin recortar, flujos callados) | — | — |
| `test_resolutores_dns.py` | un resolutor DNS no es la víctima | adaptada | la carga del fichero se localiza sin su ruta vieja; se quita la comprobación del instalador que sembraba la lista (el generador y el panel ya tienen `RESOLUTORES_DEFECTO`, que se prueba); documentación en `dashboard.py` | ídem | ok | N: `RESOLUTORES_FILE` del panel a `nodos.CONF/resolutores.lst`, la misma que usa el generador |
| `test_routers.py` | registro de routers y migración desde `mikrotik.conf` | retirada | §4: routers = puntos de `estado.json`; desaparecen la migración, `ROUTERS_MAP` y `router_defecto` | pruebas de N (`test_n_*`: `cargar_routers` por punto) y `tests/test_nodos.py` | — | — |
| `test_ruta_quitar_uno.py` | `/cuarentena/quitar-uno` con dobles | adaptada | el cuerpo de la ruta sale de `extraer.extraer()`; claves `pid|ip` (r2/r3 → p001/p002) y `_destino_ok`/`_router_de_pid` reales con `nodos` real (§1, §10.1); + subcaso: IP pelada o punto inexistente → 400 sin tocar nada | ídem | ok | hecho al integrar (bfbe690) |
| `test_ruta_quitar_varios.py` | `/cuarentena/quitar-varios` con dobles | adaptada | ídem que quitar-uno: claves `pid|ip`, `_destino_ok`/`_router_de_pid` reales (§1, §10.1); 403 por `_prohibido` (§10.2); + subcaso «sin pid, sin destino» | ídem | ok | hecho al integrar (bfbe690) |
| `test_rutas_get.py` | ninguna ruta GET revienta por un nombre sin definir | adaptada | el doble lleva el `_ctx_nodo` REAL y un `_set_ctx` que pone «Todos» con `nodos` real (§10.1; sin él ninguna ruta se ejecutaba); se cubren `/eventos`, `/eventos/detalle` (con `eventos_web` real) y `/puntos` | ídem | **falla 1**: «ningún import dentro de una rama del manejador» por `import eventos_web` dentro de `_get` (defecto del código, ver abajo) | defecto del código pendiente: `import eventos_web` a nivel de módulo |
| `test_rutas_nodos.py` | alta, edición y baja de nodos desde Ajustes | retirada | §4: se quitan `/routers/guardar`, `/routers/quitar` y `_card_nodos` | apartado Puntos de P (`test_p_*`) y `tests/test_orq_operaciones.py` | — | — |
| `test_salida_listas.py` | salir de listas negras: cuándo y con qué pruebas | conservada | — | ídem | ok | — |
| `test_salto_ventana.py` | saltar al inicio de la ventana sin perder eventos | adaptada | `logs_de_la_ventana(nodo, corte)` sobre `DATOS/<pid>/` con `nodos.py` real; se comprueba además que cada fichero lleva su pid | ídem | ok | — |
| `test_salud_sensor.py` | memcaps, drops, disco y eve | adaptada | `LOGDIR` → `nodos.eve_vivo(pid)` (`DATOS/<pid>/eve.json`) con `nodos` real (§3); + subcaso: los contadores son del punto pedido (p002 sin eve.json → {}) | ídem | ok | hecho al integrar (bfbe690) |
| `test_sin_dialogos_nativos.py` | ni un `confirm()/alert()/prompt()` | adaptada | se recorre todo `lib/ids-panel/` y `share/ids-panel/` (incluidos los futuros `puntos_web.py` y `eventos_web.py`) en vez del instalador | ídem | ok | — |
| `test_solo_vpn.py` | modo VPN: solo se recibe por el túnel (suricata-ids-fw, nft, systemctl) | retirada | firewall propio del host y solo-VPN | `tests/test_vpn_render.py` (nft del contenedor vpn), `tests/test_orq_render.py` | — | — |
| `test_threshold_exclusiones.py` | exclusiones → `threshold.config` (solo las exactas, `-T` antes) | adaptada | se conserva qué contenido sale de las exclusiones (solo las exactas, ni vencidas ni IP inválida); `suricata -T`, restaurar y recarga pasan al orquestador (`tests/test_orq_threshold.py`). Al integrar: la fusión con lo escrito a mano (`_threshold_fusionar`) desaparece: cada punto tiene su `threshold.config`, que el panel genera entero con `threshold_contenido(reglas, pid)` y escribe el orquestador (§6); «no pisar lo del operador» pasa a «no mezclar lo de otro punto» (campo `nodo`, §3) | ídem + `tests/test_orq_threshold.py` (R) | ok | hecho al integrar (bfbe690) |
| `test_tzsp_multi.py` | receptor TZSP con varios MikroTik, cada uno a su interfaz | retirada | `TZSP_MAP` del host | `tests/test_vpn_tzsp.py` (un receptor por punto, solo su MikroTik) | — | — |
| `test_usuario_fijo.py` | el usuario de entrar no se cambia nunca | conservada | solo la carga: piezas reales `PBKDF2_ITER` y las de sesión (`sesion_abrir`, `sesion_de`, `_hash_token`, `marca_usuario`...); + comprobaciones §7: en memoria va el sha256 del token y cambiar la propia clave expulsa la otra sesión | ídem | ok | hecho al integrar (bfbe690) |
| `test_verificador_reglas.py` | verificador de reglas: errores, avisos, releer tras aplicar | conservada | solo la carga (router r1 → punto p001; reutiliza el entorno de `test_acciones_router`) | ídem | ok | hecho al integrar (bfbe690) |
| `test_vpn_panel.py` | Ajustes > VPN: estado OpenVPN, redes, respaldo | retirada | OpenVPN propio | apartado Puntos (P), `tests/test_orq_operaciones.py`, `tests/test_vpn_render.py` | — | — |

## Limitaciones conocidas

- `_comun.panel()` recarga el módulo `nodos` compartido: un espacio de nombres montado antes ve el
  árbol del último `panel()`. Las pruebas lo llaman una vez por árbol.
- `test_verificador_reglas` y `test_recargar_listas` reutilizan `test_acciones_router` (`entorno`,
  `RouterFalso`): un cambio de esa prueba les afecta.
- Varias conservadas mezclan comportamiento con comprobaciones de texto del código (CSS, frases de la
  documentación). Se conservan porque así eran; son las primeras que romperá un cambio de estilo o de
  textos de P, y entonces se adaptan a lo que la página pinta.
- `cargar_nodos()` recarga el módulo `nodos` compartido del proceso (restaura el entorno al acabar);
  las pruebas de `tests/` que usan `nodos` ya lo recargan en su `setUp`.
- El banco de PCAP conserva sus IPs de servicios públicos (resolutores y NTP) porque forman parte del
  tráfico benigno que se modela. Las capturas son binarias; `.gitattributes` no tiene `*.pcap binary`
  (git las detecta como binarias por los NUL), igual que `tests/fixtures/suricata/alerta-2100498.pcap`.
- El banco completo (pasar las capturas por Suricata) no se porta aquí; para hacerlo habría que
  añadir un `tests/imagen/` que las pase por la imagen de Suricata.
