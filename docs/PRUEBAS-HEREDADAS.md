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

Resultado: ejecutado sobre el SHA base `4323145` **más el árbol de trabajo del constructor R a
2026-10-11** (`html_report.py`, `mikrotik_init.py` y `feeds_update.py` ya reescritos por R;
`dashboard.py` todavía sin los cambios de N y P), Windows 10 + Python 3.12 + node v24.15.0:
`Ran 68 tests … OK` (0 fallos, 0 omitidas) y `pyflakes tests/legado` limpio. Con
`discover -s tests`: `Ran 493 tests … OK (skipped=17)` (las 17 omitidas son de otras pruebas).

## Recuento

| Estado | Entradas |
|---|---|
| Conservada | 52 (45 `.py` + 7 `.js`) |
| Adaptada | 16 (14 `.py` + `extraer.py` + `pcap/`) |
| Retirada | 19 (14 `.py` + 3 `.sh` + `run.sh` + `__pycache__/`) |
| **Total** | **87** |

Métodos de unittest en `tests/legado/`: 68 (59 pruebas `.py` heredadas, 7 `.js` en
`test_navegador.py` y 2 métodos nuevos: `test_cobertura_sensor…test_tzsp_json_del_receptor_nuevo` y
`test_overlay_seleccion…test_guarda_real_en_node`).

## Tabla

Columna «Al integrar N/P»: lo que ya se sabe que cambiará cuando entren los cambios de `dashboard.py`
de N y P (aquí `dashboard.py` está sin ellos). Si una de esas comprobaciones falla entonces, se
**adapta** al comportamiento nuevo del contrato; no se borra.

| Fichero origen | Qué probaba | Estado | Cambio o motivo | Destino | Resultado aquí | Al integrar N/P |
|---|---|---|---|---|---|---|
| `extraer.py` | sacar piezas de los heredocs de `install-suricata.sh` | adaptada | lee los ficheros del panel; mismas firmas | `tests/legado/extraer.py` | usado por todas | — |
| `run.sh` | lanzar las 80 pruebas y contar «TODO OK» | retirada | lo sustituye `unittest discover` (`tests/run.sh`) y `_comun.correr_main` | — | — | — |
| `pcap/` | banco de regresión de detección (5 casos + generador + comparador + `run.sh` con Suricata del host) | adaptada | se copian `generar.py`, `comparar.py` y los 5 casos (54 KB); `run.sh` no (pasaba las capturas por el Suricata del host) | `tests/legado/pcap/` | usado por `test_pcap_banco` | — |
| `__pycache__/` | (caché de Python) | retirada | no es una prueba | — | — | — |
| `test_abuseipdb.py` | AbuseIPDB: cuota, caché, privacidad, categorías, bloques | conservada | — | `tests/legado/test_abuseipdb.py` | ok | §10.3 claves cifradas: `aidb_set`/`aidb_configurada` pasan por `secretos.py` |
| `test_abuseipdb_denuncia.py` | denuncias apagadas por defecto y con frenos | conservada | — | ídem | ok | — |
| `test_abuso_saliente.py` | contadores diarios de abuso saliente y tendencia (generador + panel) | conservada | — | ídem | ok (con el generador de R) | conducta/métricas por nodo (N): la prueba inyecta `LOGDIR` |
| `test_accesos_bitacora.py` | Accesos y Bitácora responden cada una su pregunta | conservada | — | ídem | ok | — |
| `test_acciones_router.py` | políticas por categoría en el router (RouterOS falso): plantillas, respaldo, idempotencia | conservada | — | ídem | ok | `RESPALDOS_MK` → `nodos.RESPALDOS` (la prueba lo inyecta) |
| `test_acciones_ui.py` | tarjeta de Ajustes y rutas plan/aplicar/quitar | conservada | — | ídem | ok | usa `router_defecto` como doble: desaparece (§3); acción contra el pid del formulario |
| `test_cache_abuseipdb.py` | caché de AbuseIPDB: un parseo por cambio, sin datos viejos | conservada | — | ídem | ok | — |
| `test_cache_config.py` | caché de configuración rápida y sin datos viejos | conservada | — | ídem | ok | — |
| `test_clusterid_unico.py` | cada interfaz de espejo con su cluster-id (instalador) | retirada | clusterid de varias interfaces en un Suricata del host; ahora un Suricata por punto con su interfaz | `tests/test_suricata_plantilla.py` (captura af-packet fija) | — | — |
| `test_cobertura_sensor.py` | cobertura del espejo: nodos mudos, origen rechazado, desperdicio | adaptada | se conserva entera y se añade `test_tzsp_json_del_receptor_nuevo`: `cobertura_tzsp`/`desperdicio_espejo` sobre el `tzsp.json` que escribe el receptor REAL del contenedor vpn | ídem | ok (2 métodos) | el fichero pasa a `RUN/<pid>/tzsp.json` por punto (N, §10.6) |
| `test_conducta_3dias.py` | reporte de 3 días por CPE, rotados incluidos, solo tus abonados | conservada | — | ídem | ok | una base por nodo y «Todos» con columna Nodo (N) |
| `test_csrf_origen.py` | un formulario de otra web no puede mandar acciones (Origin/Referer/Sec-Fetch-Site/proxy) | adaptada | la acción de ejemplo pasa de `/vpn/sensor-aplicar` (retirada) a `/cuarentena/enviar`; el par TCP del proxy (127.0.0.1) se declara de confianza (`PROXIES_OK`), como exige §7 para `X-Forwarded-Host`/`Forwarded` | ídem | ok | N: cabeceras de proxy solo desde proxy de confianza (ya preparado) |
| `test_cuarentena_aviso.py` | el aviso de Cuarentena no pinta texto libre de la URL | conservada | — | ídem | ok | — |
| `test_cuarentena_identidad.py` | enviar/quitar por identidad (router, IP), al router del CPE | conservada | — | ídem | ok | el subcaso «con un solo nodo la clave sigue siendo la IP pelada» contradice §1: cuando N haga `pid\|ip` siempre, cambiarlo a `p001\|ip` |
| `test_culpables_ficha.py` | la ficha de una pública dice qué CPE privado está detrás | conservada | — | ídem | ok | — |
| `test_culpables_listado.py` | de «me listaron» a «mira a estos abonados» | conservada | — | ídem | ok | — |
| `test_dataset_feeds.py` | dominios de feeds como dataset de Suricata (base64), `suricata -T` y recarga, regla y creación en el instalador | retirada | §8: el panel baja feeds **sin** dataset, `-T` ni recarga; el dataset es del orquestador | `tests/test_reglas_feeds.py` (dataset base64, vacío si fallan), `tests/test_reglas_release.py`, `tests/test_feeds_panel.py` (R: sin dataset) | — | — |
| `test_destinos_malos.py` | bloquear destinos de mala reputación: solo públicas y lo sólido | conservada | — | ídem | ok | §4 quita el `/tool fetch` de `/destinos.rsc`: las 3 comprobaciones de `destinos_rsc` se retiran cuando se quite la función |
| `test_detectar_publicas.py` | detectar del MikroTik solo WAN y pools de srcnat | conservada | — | ídem | ok | — |
| `test_diagnostico_mk.py` | qué le falta al MikroTik para poder cortar | conservada | — | ídem | ok | la IP del sensor pasa a `punto.sensor` (N) |
| `test_dnsbl_historial.py` | historial de listas negras: cuándo entró y cuánto estuvo | conservada | — | ídem | ok | — |
| `test_documentacion.py` | documentación por páginas, categorías, buscador, modal | conservada | — | ídem | ok | P reescribe temas que nombran lo retirado: debe seguir habiendo ≥ 20 temas y anclas |
| `test_dominios_maliciosos.py` | qué dominios malos se consultan, quién y por dónde (generador) | conservada | — | ídem | ok (con el generador de R) | — |
| `test_error_500.py` | una página que revienta da 500 explicado | conservada | — | ídem | ok | — |
| `test_espejo_estado.py` | `suricata-espejo`: «¿estoy leyendo tráfico?» en el host | retirada | comando del host (systemctl, contadores de tzsp-decap del host) | salud por etapas de N (§10.6), `tests/test_vpn_tzsp.py` (latido `tzsp.json`), `tests/test_suricata_salud.py`, `legado/test_cobertura_sensor.py` | — | — |
| `test_espejo_vpn.py` | Ajustes > VPN: montar el espejo re-ejecutando el instalador (systemd-run, -a, respaldo) | retirada | espejo VPN propio e instalador | `tests/test_mkinit_espejo.py` (R), `legado/test_mikrotik_init.py`, ficha Espejo de Puntos (P) | — | — |
| `test_exclusiones_modal.py` | alta de exclusiones en un modal (página renderizada) | conservada | — | ídem | ok | — |
| `test_fecha_actualizacion.py` | fecha y antigüedad de la última actualización del panel | retirada | actualizador por git (`/etc/suricata-dashboard.updated`) | nada aún: la actualización es por imagen (`sistema.actualizar`, orden reservada) | — | — |
| `test_feeds_nuevas.py` | ThreatFox ip:port, ET compromised, Tor como contexto | adaptada | la comprobación de documentación mira `dashboard.py` (antes el instalador); `DESTINOS_FILE` se localiza sin su ruta vieja (ahora la del nodo) | ídem | ok (con `feeds_update.py` y generador de R) | — |
| `test_ficha_desplegable.py` | «Ver qué hace» se despliega en la tabla | conservada | — | ídem | ok | — |
| `test_ficha_kpis.py` | ficha por firma y cuadros que no se descuadran | conservada | — | ídem | ok | incluye comprobaciones de CSS/texto: frágiles si P toca estilos |
| `test_form_mikrotik.py` | formulario MikroTik: conexión aparte, listas por tipo de abuso | conservada | — | ídem | ok | §4: la conexión (host/puerto) pasa a Puntos; la parte «conexión» cambiará con P |
| `test_groq_ajustes.py` | clave de Groq validada antes de guardar y que no sale | conservada | — | ídem | ok | §10.3 clave cifrada |
| `test_historial_db.py` | historial persistente: sobrevive a reinicio y logrotate | conservada | — | ídem | ok | una base por nodo (N) |
| `test_ia_lectura.py` | lectura con IA sin datos del abonado y con fallo suave | conservada | — | ídem | ok | — |
| `test_identidad_nodo.py` | identidad (router, IP): dos nodos con el mismo rango no se confunden | adaptada | router = pid del fichero (no `in_iface` + `ROUTERS_MAP`, que no existen); con el `html_report.py` y `nodos.py` reales. Cambio deliberado comprobado: con un solo punto la identidad es `pid\|ip`, nunca la IP pelada; chips solo en `--todos` | ídem | ok | — |
| `test_insignia_confianza.py` | insignia «Confirmado» y cuántas pruebas | conservada | — | ídem | ok | casi todo son textos del panel y del generador: frágil si P los reescribe |
| `test_instalador_claves.py` | las claves que entrega el instalador (panel y EveBox) | retirada | instalador y EveBox | `tests/test_orq_panel.py` / `tests/_ayuda_orq.py` (`crear-admin` imprime `CLAVE=`), `tests/test_host_install.sh` | — | — |
| `test_instalador_defectos.sh` | con qué valores nace una caja nueva | retirada | instalador del host viejo | `tests/test_host_install.sh` | — | — |
| `test_instalador_espejo.sh` | instalador local o VPN sin colgar un `curl\|bash` | retirada | instalador y modo local/VPN | `tests/test_host_install.sh` | — | — |
| `test_instalador_multi.sh` | instalador: una interfaz por router | retirada | interfaces `ids-monN` del host | un contenedor vpn y uno Suricata por punto: `tests/test_orq_render.py` | — | — |
| `test_ip_sensor.py` | la IP del sensor puesta en los comandos del MikroTik | conservada | — | ídem | ok | N sustituye «adivinar la IP por la ruta» por `punto.sensor`: entonces se adapta |
| `test_listas_categoria.py` | una address-list por categoría de abuso | conservada | — | ídem | ok | — |
| `test_listas_desplegable.py` | desplegable con las IPs de cada lista | conservada | — | ídem | ok | — |
| `test_mapa.js` | mapa del reporte: zoom, detalle, sin bordes negros | conservada | se lanza desde `test_navegador.py` | `tests/legado/test_mapa.js` | ok (node) | — |
| `test_masivo_progreso.js` | quitado masivo: avance, fallo a mitad y cierre | conservada | ídem | `tests/legado/test_masivo_progreso.js` | ok (node) | — |
| `test_masivo_ui.js` | quitado masivo: selección y modal | conservada | ídem | `tests/legado/test_masivo_ui.js` | ok (node) | — |
| `test_mikrotik_init.py` | `suricata-mikrotik-init` contra un MikroTik falso | adaptada | módulo `plan`/`aplicar` en vez de CLI; se conservan idempotencia, espejos ajenos intactos, apagar el viejo antes de crear, fasttrack, vista previa = lo aplicado, parar en el primer fallo, sin `/export` no se toca nada. Cambios deliberados comprobados: **sin regla DNS aparte**, recorte siempre, ninguna `accept`, comentario `IDS ids-maat:<pid>`. Retirado: alta en el panel (`ENABLED=0`), fichero de credenciales, modo local, cliente api-ssl del dashboard | ídem | ok (29 comprobaciones) | — |
| `test_mis_redes.py` | `es_mi_cpe`: solo tus redes entran a la cuarentena | adaptada | el generador corre por nodo: se le da `nodos.py` con un punto; se añade la capacidad nueva (sin `MIS_REDES`, valen las `redes` del punto); IPs reales del caso cambiadas por RFC 5737 | ídem | ok | — |
| `test_mk_tls.py` | api-ssl: recuerda el cifrado, dice cada fallo, una conexión | conservada | — | ídem | ok | N añade el relé AF_UNIX + TLS (§4): necesita su propia prueba (zona N) |
| `test_modal_confirm.js` | el modal propio repite la pulsación al confirmar | conservada | se lanza desde `test_navegador.py` | `tests/legado/test_modal_confirm.js` | ok (node) | — |
| `test_nav_usuario.py` | menú del usuario y su foto por `/mi-foto` | conservada | — | ídem | ok | «sin sesión: el Salir de siempre» es el modo sin usuarios, que desaparece (§1) |
| `test_openvpn_cli.py` | `/root/openvpn.sh` sin menú (usuarios, redes) | retirada | OpenVPN propio | `tests/test_vpn_scripts.py`, `tests/test_vpn_ovpn_auth.py`, `tests/test_vpn_render.py`, `tests/test_orq_comandos.py` | — | — |
| `test_openvpn_sh.py` | instalador de OpenVPN en /root | retirada | OpenVPN propio e instalador | ídem | — | — |
| `test_orden.js` | tablas: orden asc/desc y fechas por tiempo real | conservada | se lanza desde `test_navegador.py` | `tests/legado/test_orden.js` | ok (node) | — |
| `test_orden_persiste.js` | el orden sobrevive a la recarga | conservada | ídem | `tests/legado/test_orden_persiste.js` | ok (node) | — |
| `test_overlay_seleccion.py` | seleccionar texto en un modal no lo cierra | adaptada | se recorren `dashboard.py` + `html_report.py` (antes el instalador entero); la simulación en Python se sustituye por `test_guarda_real_en_node`: los manejadores **reales** de las 11 capas ejecutados con node (`guarda_capas.js`) | ídem + `guarda_capas.js` | ok (2 métodos) | si P quita capas (`updask`, del actualizador) baja el «≥ 11»: ajustar la cifra, no quitar la comprobación |
| `test_parse_ts.py` | `parse_ts` con memoria: mismo resultado | conservada | — | ídem | ok (generador de R) | — |
| `test_pcap_banco.py` | banco de PCAP: generador determinista y comparador fallo/aviso | adaptada | el generador corre sobre una copia temporal (escribía en el árbol) y se comprueba que da lo versionado | ídem | ok | — |
| `test_perf_generador.py` | índice de flujos y memorias del generador, mismos resultados | conservada | — | ídem | ok (generador de R) | — |
| `test_plan_bloqueo.py` | la IA ordena lo medido y no inventa puertos | conservada | — | ídem | ok | — |
| `test_politicas_clase.py` | políticas por clase de abuso | adaptada | la comprobación de documentación mira `dashboard.py` (antes el instalador) | ídem | ok | — |
| `test_posicion.js` | la página conserva la posición tras una acción | conservada | se lanza desde `test_navegador.py` | `tests/legado/test_posicion.js` | ok (node) | — |
| `test_publicas_limpiar.py` | vaciar de una vez las públicas de un nodo | adaptada | «ningún byte NUL» se mira en cada fichero del panel (antes en el instalador) | ídem | ok | — |
| `test_publicas_mitigacion.py` | públicas del cliente: vigilancia y cruce con el abonado | conservada | — | ídem | ok | — |
| `test_recargar_listas.py` | sync contra SU lista y recargar lo que falta | conservada | — | ídem | ok | por nodo (§3) |
| `test_recorte_flujo.py` | recorte por flujo en el receptor TZSP del host | retirada | tzsp-decap del host | `tests/test_vpn_tzsp.py` (primeros bytes, dos sentidos, VLAN, DNS sin recortar, flujos callados) | — | — |
| `test_resolutores_dns.py` | un resolutor DNS no es la víctima | adaptada | la carga del fichero se localiza sin su ruta vieja; se quita la comprobación del instalador que sembraba la lista (el generador y el panel ya tienen `RESOLUTORES_DEFECTO`, que se prueba); documentación en `dashboard.py` | ídem | ok | N: `RESOLUTORES_FILE` del panel a `nodos.CONF/resolutores.lst`, la misma que usa el generador |
| `test_routers.py` | registro de routers y migración desde `mikrotik.conf` | retirada | §4: routers = puntos de `estado.json`; desaparecen la migración, `ROUTERS_MAP` y `router_defecto` | pruebas de N (`test_n_*`: `cargar_routers` por punto) y `tests/test_nodos.py` | — | — |
| `test_ruta_quitar_uno.py` | `/cuarentena/quitar-uno` con dobles | conservada | el cuerpo de la ruta sale de `extraer.extraer()` en el proceso | ídem | ok | — |
| `test_ruta_quitar_varios.py` | `/cuarentena/quitar-varios` con dobles | conservada | ídem | ídem | ok | — |
| `test_rutas_get.py` | ninguna ruta GET revienta por un nombre sin definir | conservada | — | ídem | ok | recorre las rutas reales: cubrirá también las nuevas de P/E |
| `test_rutas_nodos.py` | alta, edición y baja de nodos desde Ajustes | retirada | §4: se quitan `/routers/guardar`, `/routers/quitar` y `_card_nodos` | apartado Puntos de P (`test_p_*`) y `tests/test_orq_operaciones.py` | — | — |
| `test_salida_listas.py` | salir de listas negras: cuándo y con qué pruebas | conservada | — | ídem | ok | — |
| `test_salto_ventana.py` | saltar al inicio de la ventana sin perder eventos | adaptada | `logs_de_la_ventana(nodo, corte)` sobre `DATOS/<pid>/` con `nodos.py` real; se comprueba además que cada fichero lleva su pid | ídem | ok | — |
| `test_salud_sensor.py` | memcaps, drops, disco y eve | conservada | — | ídem | ok | `LOGDIR` → eventos del punto (N) |
| `test_sin_dialogos_nativos.py` | ni un `confirm()/alert()/prompt()` | adaptada | se recorre todo `lib/ids-panel/` y `share/ids-panel/` (incluidos los futuros `puntos_web.py` y `eventos_web.py`) en vez del instalador | ídem | ok | — |
| `test_solo_vpn.py` | modo VPN: solo se recibe por el túnel (suricata-ids-fw, nft, systemctl) | retirada | firewall propio del host y solo-VPN | `tests/test_vpn_render.py` (nft del contenedor vpn), `tests/test_orq_render.py` | — | — |
| `test_threshold_exclusiones.py` | exclusiones → `threshold.config` (solo las exactas, `-T` antes) | adaptada | se conserva lo del panel (qué contenido sale de las exclusiones y cómo se fusiona); `suricata -T`, restaurar, hilo y el `threshold-file` del instalador pasan al orquestador | ídem + `tests/test_orq_threshold.py` (R) | ok | exclusiones con campo `nodo` (§3): filtrar por nodo |
| `test_tzsp_multi.py` | receptor TZSP con varios MikroTik, cada uno a su interfaz | retirada | `TZSP_MAP` del host | `tests/test_vpn_tzsp.py` (un receptor por punto, solo su MikroTik) | — | — |
| `test_usuario_fijo.py` | el usuario de entrar no se cambia nunca | conservada | — | ídem | ok | — |
| `test_verificador_reglas.py` | verificador de reglas: errores, avisos, releer tras aplicar | conservada | — | ídem | ok | — |
| `test_vpn_panel.py` | Ajustes > VPN: estado OpenVPN, redes, respaldo | retirada | OpenVPN propio | apartado Puntos (P), `tests/test_orq_operaciones.py`, `tests/test_vpn_render.py` | — | — |

## Limitaciones conocidas

- Las pruebas que dependen de `dashboard.py` pasan sobre el panel heredado **sin** los cambios de N y P
  (están en otro árbol). La columna «Al integrar N/P» dice cuáles se sabe que tocarán.
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
