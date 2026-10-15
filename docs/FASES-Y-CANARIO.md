# Fases, canario y riesgos

Anexo de [ARQUITECTURA.md](ARQUITECTURA.md). Este anexo cubre:

- las fases, con su contenido, sus pruebas de comportamiento y su criterio de hecho;
- qué se mide en el canario;
- la tabla completa de riesgos.

Reglas para todas las fases:

- las pruebas viven **en el repo** (`tests/`), corren en CI y comprueban **que funciona**, no que
  el código esté escrito;
- `pyflakes` es obligatorio en CI, porque un `except` ancho tapa los `NameError`;
- cada fase termina con un commit, un push y la nota de memoria del proyecto actualizada.

## 1. Fases

### F0 — Esqueleto, CI y GHCR

- **Contenido:**
  - estructura `panel/`, `orquestador/`, `imagenes/{panel,vpn,suricata}/`, `plantillas/`,
    `tests/` y `docs/`;
  - un `instalar.sh` mínimo:
    - Docker con versión fijada y `daemon.json`;
    - módulos y timesyncd;
    - el firewall del host estático con las redes de gestión (SSH) y las IP del proxy (panel);
    - el panel en HTTP, sin certificados en el VPS;
    - la base de túneles (`100.64` o `198.18`), elegida en la instalación;
    - `PasswordAuthentication no`;
    - fail2ban para SSH;
    - `master.key`, `orq_token` y `avisos.conf`;
    - validación del pool de Docker;
  - los workflows `ci.yml` y `release.yml` ([ACTUALIZACIONES.md](ACTUALIZACIONES.md) §2);
  - los paquetes de GHCR hechos públicos.
- **Pruebas:**
  - en una VM limpia de Debian 13, `GET /salud` responde 200 con la versión del esquema;
  - sin usuarios, solo se puede crear el primer admin;
  - una imagen de panel que no corra como uid 10500 hace fallar CI;
  - un `.sh` con CRLF hace fallar CI.
- **Hecho cuando:** CI está en verde, las tres imágenes están en GHCR por digest y firmadas, y una
  instalación limpia llega al login **a través del proxy inverso** y **no** directamente desde
  fuera. SSH solo responde desde una red de gestión.

### F1a — Infraestructura de una instancia (canario real)

- **Contenido:**
  - la plantilla de compose y el `vpn` completo (entrypoint ordenado, s6, `tzsp-decap` con latido,
    relé API-SSL, tablas nft);
  - `suricata` con el yaml completo renderizado;
  - el orquestador **por CLI** (`ids-orq punto crear|borrar|estado`), con la cola, la supervisión,
    la comparación de netns y `estado.json`;
  - la actualización de reglas con reinicio en serie;
  - logrotate;
  - **sin panel**: los eve se leen a mano.
- **Pruebas:**
  - un TZSP de prueba hacia `100.64.1.1` produce eventos con `host = p001` en el eve;
  - un pcap reproducido produce la alerta esperada;
  - sin tráfico, el `vpn` sigue sano (latido);
  - matar `openvpn` no corta la captura;
  - `docker restart ids-p001-vpn` hace que el orquestador detecte netns distintos y reinicie
    `suricata`;
  - tras reiniciar el VPS, `suricata` espera a `ids-mon` y captura;
  - `systemctl restart docker` (con `live-restore`) mantiene túneles y captura;
  - `reglas.actualizar` reinicia las instancias de una en una;
  - desde fuera, solo se ve el puerto OpenVPN; desde el túnel, solo el 37008;
  - un CHR o MikroTik con **RouterOS 6.49** conecta con el TLS moderno. Si no lo hace, se prueba la
    «compatibilidad v6» (primero `SECLEVEL=0`, después `legacy`) y se anota el resultado;
  - la API-SSL responde a través del relé en 6.49 y en v7 con `certificate=none` (cifrado anónimo;
    decisión del dueño, 2026-10-15) y con un certificado asignado ([OPERACION.md](OPERACION.md)
    §1.1).
- **Mediciones de capacidad** de §2, anotadas en el repo. **Con ellas se fijan los perfiles y el
  número de puntos por VPS antes de invertir en el panel.**
- **Hecho cuando:** un MikroTik real o un CHR manda el espejo por la VPN, Suricata alerta y la tabla
  de capacidad tiene cifras medidas.

### F1b — Panel modular con un punto

- **Contenido:**
  - el panel dividido en módulos ([PLAN-PANEL.md](PLAN-PANEL.md)), con **todas** las funciones
    actuales contra `estado.db` y `eventos.db`, con el punto fijo `p001`;
  - los servicios `web` y `worker`;
  - sin EveBox.
- **Pruebas:**
  - el pcap aparece en Detalle y en `alerta` con `punto_id = p001`;
  - el TZSP de prueba muestra Mbps y desperdicio en el panel;
  - reiniciar a mitad de la ingesta no deja **ni duplicados ni huecos** (filas frente a líneas);
  - rotar el eve no corta la ingesta;
  - una cuarentena contra un CHR de laboratorio aparece con `comment=ids-maat:p001:<id>` y al
    liberarla desaparece;
  - si el CHR cae a mitad del envío, la cuarentena queda en `error` y se reintenta;
  - la API va por el relé, también con un router sin certificado; con la huella fijada, un
    certificado cambiado se rechaza sin mandar la clave.
- **Hecho cuando:** se ven las alertas en el panel, la cuarentena funciona de ida y vuelta, y las
  pruebas pasan en CI (las del CHR, en un job de laboratorio marcado).

### F2 — Varios puntos y filtro

- **Contenido:** dos instancias, el selector global, `alcance()` y `puede()` en todas las rutas, y
  `CpeRef` en tablas y cachés.
- **Pruebas**, todas con **la misma IP `10.0.0.5` en p001 y en p002**:
  - con un pcap distinto en cada punto, la vista de p001 solo muestra lo de p001 y la de empresa
    muestra **dos filas**;
  - una cuarentena de `(p001, 10.0.0.5)` aparece solo en el CHR-1, y el CHR-2 no recibe ninguna
    llamada a la API (se comprueba en su log);
  - el nombre del abonado de p002 no aparece en la ficha de p001;
  - la exclusión de p001 no silencia a p002, y una global silencia a los dos;
  - el reporte de p001 no contiene datos de p002;
  - cada función del repositorio llamada sin alcance lanza `AlcanceRequerido`;
  - una línea con `host = p002` en el volumen de p001 genera `EVE-MEZCLA`;
  - un `sw_id` cambiado hace rechazar la acción con `ROUTER-NO-COINCIDE`;
  - el `vpn` de p001 no alcanza la red de p002.
- **Hecho cuando:** todas las pruebas de mezcla pasan y una revisión manual con los dos CHR no
  encuentra ningún dato cruzado.

### F3 — Alta de punto desde el panel

- **Contenido:**
  - el socket del orquestador, con `SO_PEERCRED`, el token y todas las órdenes;
  - el asistente, la pantalla Puntos, la baja, la pausa y el reinicio;
  - el diagnóstico de CGNAT;
  - los avisos directos del orquestador.
- **Pruebas:**
  - alta de principio a fin con un CHR v6 **y** con un CHR v7: los comandos generados se pegan y
    el punto llega a `activo`;
  - dos altas simultáneas obtienen `N` distintos;
  - el mismo `op_id` dos veces produce una sola ejecución;
  - si se mata el orquestador a mitad de `punto.crear`, al arrancar se deshace y el punto queda en
    `reservado`;
  - otro uid en el socket es rechazado;
  - una orden desconocida o un parámetro fuera de rango devuelve `INVALIDO`;
  - un alta que no cabe se niega con la capacidad por perfil;
  - **la baja borra todo:**
    - después de dar de baja `p001`, una consulta de todas las tablas de `estado.db`, `eventos.db`
      y `bitacora.db` no devuelve **ninguna fila** con `punto_id = p001`;
    - no queda **ningún archivo** en `/srv/ids/{puntos,datos,run,ctl}/p001`, ni en
      `/srv/ids/panel/{reportes,respaldos}/p001`;
    - `orq.db` solo guarda el enfriamiento de `N`, y `orq.jsonl` no contiene ninguna red ni IP del
      punto;
    - la bitácora global tiene exactamente una línea «punto p001 (nombre) eliminado por <usuario>
      <fecha>» y su cadena sigue verificándose;
  - **un punto nuevo no ve nada del anterior:** con la misma LAN y, pasado el enfriamiento, el
    mismo `N`, el punto nuevo recibe otro id (`p002`, nunca `p001`). Su histórico, sus cuarentenas,
    sus exclusiones y su bitácora están vacíos;
  - **baja con API:** antes de encolar la baja, el panel saca del router las IPs que puso
    (cuarentenas y destinos bloqueados) y retira el espejo (con su respaldo y la regla fasttrack
    devuelta a sus valores originales); en el router **siguen** lo del alta (`ids-vpn`, usuario y grupo
    `ids-api`, CA del VPS; en un router del script anterior, también la ruta blackhole y el bloque
    de aislamiento de `filter`), que se quita con
    el bloque «terminar una baja con API» de [OPERACION.md](OPERACION.md) §2.1, y tras pegarlo no
    queda ninguna entrada `ids-maat:p001`;
  - **baja sin API:** el panel avisa de que las entradas quedan en el router y entrega los
    comandos;
  - las credenciales borradas ya no conectan;
  - la confirmación exige escribir el nombre exacto del punto;
  - la pausa deshabilita el mangle y el `vpn` sigue sano;
  - con el túnel caído se anota por dónde sale el TZSP (sin ruta del IDS, sigue la ruta por defecto
    del router; el operador decide si lo evita);
  - una ruta estática del CHR dentro de `100.64.N.0/24` deshabilita el mangle y avisa;
  - con el panel parado, un punto en error llega por Telegram desde el orquestador.
- **Hecho cuando:** tras una baja no queda ninguna fila ni archivo del punto, y un operador sin
  consola da de alta, pausa y da de baja un punto solo desde la
  web, y todo queda en la bitácora unido por `op_id`.

### F4 — Seguridad, acceso, fail2ban y modo seguro

- **Pruebas:**
  - redes que excluyen la IP del operador: la reversión llega al vencer la ventana (5 min por
    defecto) y el panel vuelve a responder;
  - con confirmación, las reglas persisten;
  - un reinicio del VPS durante la ventana deja las reglas anteriores;
  - una red más ancha que /16 se rechaza en el orquestador;
  - con `PasswordAuthentication yes`, `acceso.aplicar` se niega;
  - 5 fallos de SSH bloquean la IP, **también si viene de una red de gestión**; la IP fija del
    dueño que está en `ignoreip` no se bloquea;
  - 5 intentos con un usuario VPN que no existe (`ovpn-auth: rechazado … motivo=usuario`) bloquean
    la IP en el hook `forward`, y el túnel de otro punto sigue arriba; un MikroTik con la clave vieja
    (`motivo=clave`, tras regenerarla) **no** se bloquea y entra solo en ≤ 10 min tras poner la
    nueva; `ids-orq vpn desbanear <ip>` quita un ban;
  - 3 `nc <vps> <puerto>` colgados no impiden que el MikroTik reconecte tras cortarle la VPN
    (`max-clients 16`, `hand-window 20`; en el log del `vpn` no aparece «would exceed maximum
    number of clients»);
  - más de 10 conexiones nuevas por minuto **desde una misma IP de origen** se descartan; el freno
    suma todos los puertos VPN del VPS (11 conexiones repartidas entre los puertos de dos puntos
    también lo disparan);
  - una conexión directa al puerto del panel desde una IP que no es del proxy se descarta en el
    firewall del host;
  - **cabeceras del proxy:**
    - una petición por el túnel SSH con `X-Forwarded-For: 198.51.100.7` y
      `X-Forwarded-Proto: https` falsificados: el panel registra la IP real de la puerta de enlace
      y no marca la conexión como HTTPS;
    - la misma petición desde la IP del proxy: el panel usa `198.51.100.7` en la bitácora y en el
      freno de login, y emite las cookies `Secure` y `__Host-`;
  - 8 fallos de login a través del proxy con la misma `X-Forwarded-For` bloquean **esa IP real**,
    no al proxy, y otro cliente detrás del mismo proxy sigue entrando;
  - un `acceso.aplicar` que quita de la lista la IP del proxy por la que llega la petición se
    rechaza;
  - por el túnel SSH de emergencia (`ssh -L`) se entra al panel con el proxy parado;
  - un POST con `Sec-Fetch-Site: cross-site` o sin `X-CSRF` devuelve 403;
  - cambiar la clave cierra las demás sesiones del usuario;
  - `strings estado.db` no muestra ninguna clave API;
  - `estado.db` copiada sin `master.key` no se descifra;
  - el cifrado del punto A no se descifra copiado al punto B;
  - `docker inspect` del panel no muestra `docker.sock`, sí `read_only` y ninguna capacidad;
  - una cadena de bitácora alterada se detecta, también frente al anclaje de `orq.jsonl`;
  - desde `100.64.x.x`, el panel y SSH no responden.
- **Hecho cuando:** todas las pruebas pasan y una auditoría interna (otro agente) no encuentra
  ningún hallazgo alto.

### F5 — Documentación

- **Contenido:**
  - `README.md`;
  - estos documentos actualizados;
  - [OPERACION.md](OPERACION.md) completo;
  - la sección Documentación del panel, reescrita sin EveBox, sin `systemctl` y sin `openvpn.sh`;
  - el changelog en las etiquetas de las imágenes.
- **Pruebas:** cada comando de OPERACION se ejecuta en una VM limpia siguiendo el texto al pie de
  la letra, incluida una **recuperación completa en otro VPS desde el respaldo manual** de
  [OPERACION.md](OPERACION.md) §3.1 (no hay respaldo diario: `sistema.respaldar` está reservada).
  CI comprueba los enlaces internos.
- **Hecho cuando:** otra persona instala, da de alta un punto y recupera el VPS **solo con la
  documentación**.

### F6 — Importación desde suricata-ids-lab (opcional)

- **Contenido:** `ids-maat importar --origen <tar.gz> [--aplicar]`. Por defecto hace un ensayo y
  entrega un informe.
- **Se importa solo configuración y bitácora:**
  - cada router pasa a ser un punto en `esperando_vpn`;
  - los enviados con clave `ip` o `rN|ip` pasan a `(punto, ip)`;
  - la clave API se cifra al importarla;
  - usuarios, exclusiones (globales), públicas por router y la lista de nunca bloquear;
  - la bitácora se marca como `importada`.
- **No se importan** los eventos ni `historial.db`.
- **Pruebas:**
  - muestras anonimizadas (un router, varios, JSON corruptos) producen el informe esperado;
  - importar dos veces no duplica nada;
  - una IP sin router en una instalación de varios routers se descarta con su motivo.
- **Hecho cuando:** un sensor real anonimizado se importa en ensayo sin ningún «no sé a qué punto
  va» que quede sin explicar.

## 2. Qué se mide en el canario

El canario es un VPS de pruebas con 2 puntos que **repiten la misma LAN** (dos CHR o MikroTik con
`10.0.0.0/24`). Las mediciones 1–6 entran en F1a; las demás, en F1a y F3.

| # | Medición | Para qué |
|---|---|---|
| 1 | RSS de Suricata cargado con ET completo `medium`, `low` y `reducido`, más el anillo | rellenar la tabla de [INSTANCIA.md](INSTANCIA.md) §10.2 y la fórmula de admisión |
| 2 | Pico del `suricata -T` efímero por perfil | dimensionar la reserva única |
| 3 | Tiempo sin captura al reiniciar cada perfil | confirmar los 30–90 s del reinicio en serie |
| 4 | `capture.kernel_packets` con `netdev ingress drop` cargado | validar el descarte |
| 5 | `kernel_drops` y `decoder.invalid` con `snaplen 32768` y tráfico real | validar el snaplen |
| 6 | Que `suricata` captura sin `NET_ADMIN` (ya quitada en el código, auditoría VPN-05; la e2e del CI lo prueba con Docker real): `capture.kernel_packets` sube y no hay avisos de promisc ni de offload | si no captura, volver a ponerla y anotar por qué |
| 7 | Desperdicio y Mbps reales por punto con el recorte | ancho de banda del VPS |
| 8 | CPU del router con los vigilados acelerados solo a partir de 10 KB | coste en el MikroTik |
| 9 | **RouterOS 6.49** (el más antiguo de la flota y la versión mínima): TLS moderno; si falla, `SECLEVEL=0` y luego `legacy` | decisión d de ARQUITECTURA §10 |
| 10 | `connect-to` por nombre DNS | nombre DNS por empresa |
| 11 | v7 con `cipher=aes256-gcm` y `verify-server-certificate=yes`; **6.49** pegando el bloque tal cual: `/file print file=` + `/file set contents=` (línea de ~1,3 KB) + `/certificate import` dejan `ids-maat-ca-<pid>.txt_0` con flag T, y el túnel conecta con la verificación activa; con un `connect-to` que no está en el certificado, no conecta | el script v6/v7 de [OPERACION.md](OPERACION.md) §1.4 |
| 11b | Router dado de alta con el script anterior (ruta blackhole y bloque de aislamiento de `ids-vpn`), en 6.49 y v7: `/ip firewall filter remove [find comment="IDS ids-maat:<pid>"]` y `/ip route remove [find comment="IDS ids-maat:<pid>"]` quitan solo eso y no tocan el espejo (`IDS ids-maat:<pid>:espejo`) ni las cuarentenas; con el `accept` de la API del operador en su cadena `input`, la API del panel sigue entrando; el espejo sigue llegando; `/ping 100.64.N.1` desde el router responde (con el `vpn` recreado con la imagen nueva) | [OPERACION.md](OPERACION.md) §1.5 |
| 12 | Con el túnel caído, por dónde sale el TZSP (sin ruta del IDS en el router) | dato para el operador ([RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) §3.1) |
| 13 | `fail2ban-regex` de `ids-vpn` sobre fallos reales | jaula OpenVPN |
| 14 | El encierro systemd del orquestador no rompe docker, nft, `systemd-run` ni `fail2ban-client` (el `ids-orq vpn desbanear <ip>` desbanea de verdad con `ProtectSystem=strict`) | `ReadWritePaths` |
| 15 | Actualización de `vX` a `vX+1` y una reversión forzada (fallo de salud simulado en el punto 2) | flujo de actualización |

## 3. Riesgos

| # | Riesgo | Impacto | Mitigación |
|---|---|---|---|
| 1 | RAM: un ruleset por instancia | pocos puntos por VPS, OOM | perfiles, admisión con margen del 20 %, capacidad visible, medir en F1a |
| 2 | El `-T` efímero coincide con otra carga | OOM | una sola reserva y cola en serie |
| 3 | Autodetección dentro del contenedor ve el host | memcaps de 2 GB y 8 hilos por instancia | yaml completo con valores fijos |
| 4 | Anillo af-packet fuera del cgroup | RAM sin contabilizar | `ring-size` y `snaplen` explícitos; se suma en la admisión |
| 5 | Netns huérfano tras reiniciar el `vpn` | punto ciego y «sano» | comparación de inodos, `docker events`, espera a `ids-mon`; plan B «pause» |
| 6 | Healthcheck ligado al espejo | reinicios en bucle de puntos pausados o sin tráfico | healthcheck solo de procesos con latido; la falta de espejo es salud funcional |
| 7 | 30–90 s ciego por punto en cada cambio de reglas | huecos de detección | una vez al día de madrugada; threshold agrupado cada 15 min |
| 8 | `flush ruleset` o `iptables-persistent` | se caen los puertos de Docker | tablas propias con `delete table`; ninguno de los dos se instala |
| 9 | Red de túnel choca con el CGNAT | túnel roto o espejo mal enrutado | base `100.64` o `198.18` elegida al instalar, validación al alta, diagnóstico periódico que deshabilita el mangle |
| 10 | Espejo en claro por la WAN si cae el túnel | fuga de tráfico de abonados | a cargo del operador en su router: el script no lleva rutas (decisión del dueño, [RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) §3.1) |
| 11 | Espejo por túnel TCP | latencia, colas, ancho de banda | recorte obligatorio, `TZSP_BYTES`, vigilar el desperdicio |
| 12 | TZSP fragmentado en `tun0` | pérdidas silenciosas | `ipfrag_*` por netns |
| 13 | Fasttrack del router | el mangle no ve la conexión o la CPU sube | fasttrack de los vigilados a partir de `connection-bytes=10000-0`, sin `accept`; medir |
| 14 | OpenSSL 3 con RouterOS 6.49 | el v6 no conecta | prueba en F1a; `SECLEVEL=0` y después `legacy`, solo en ese punto; nada anterior a 6.49 |
| 15 | Puertos OpenVPN abiertos a internet | fuerza bruta, CPU por scrypt | `meter` en el host, freno antes de scrypt, jaula `ids-vpn`, origen fijo opcional |
| 16 | `/ip service … address=` pisa a otros sistemas | facturación sin API | usuario API exclusivo; el panel nunca toca la lista |
| 17 | API sin certificado (ADH) o en claro | suplantación del router | API-SSL sin certificado (ADH) admitida, y es lo normal, por decisión del dueño (2026-10-15): la clave de `ids-api` la protegen el túnel OpenVPN (el MikroTik verifica al servidor con la CA del VPS) y el netns del sensor; quien ponga certificado en el router puede fijar su huella, y desde entonces se exige ese certificado (sin ADH); una huella vacía heredada cuenta como sin huella; con 8728 (en claro) el panel no conecta, porque habla siempre TLS |
| 18 | `tzsp-decap` en Python | techo de pps | `SO_RCVBUFFORCE`, comparar rx con tx; receptor en C/Go si hace falta |
| 19 | Disco lleno | capturas vacías sin error | logrotate cada 30 min (`ids-logrotate.timer`) por tamaño (`maxsize 1G`, `rotate -1`, sin `maxage`); el orquestador comprime los rotados, poda por fecha a los 30 días y, si `/srv/ids` baja del 15 % libre, borra los rotados más viejos y avisa (`DISCO`, `RETENCION-REDUCIDA`; [ORQUESTADOR.md](ORQUESTADOR.md) §8.1) |
| 20 | Actualización a medias o GHCR caído | instancias mezcladas | digests en `orq.db`, pull antes, serie y reversión |
| 21 | Migración del panel sin vuelta atrás | datos perdidos al revertir | respaldo previo; revertir el panel exige restaurar y se avisa |
| 22 | Montar el enlace `current` | las reglas nuevas nunca se ven | montar el padre, enlace relativo |
| 23 | Dataset con `load` de un fichero inexistente | caen todas las reglas | el actualizador crea el fichero vacío |
| 24 | `privileged` o `userns-remap` «para que funcione» | sin aislamiento, o tun y nft rotos | capacidades documentadas; prohibido en las plantillas |
| 25 | fail2ban con el `journalmatch` por defecto | no banea nada | `_SYSTEMD_UNIT=ssh.service` y `fail2ban-regex` al instalar |
| 26 | Datos de puntos mezclados | cuarentena al abonado equivocado | `CpeRef`, `AlcanceRequerido`, `EVE-MEZCLA`, `ROUTER-NO-COINCIDE`, borrado total en la baja, ids nunca reutilizados, pruebas F2 y F3 |
| 27 | Feed envenenado | cuarentenas masivas | tope de cuarentenas automáticas por hora y punto, y aviso |
| 28 | Panel caído sin avisos | ceguera sin que nadie se entere | avisos directos del orquestador |
| 29 | VPS perdido | reconfigurar todos los MikroTik | `connect-to` por nombre DNS; **no hay respaldo diario** (`sistema.respaldar` reservada): instantánea del proveedor y respaldo manual con copia fuera ([OPERACION.md](OPERACION.md) §3), `master.key` aparte; recuperación probada en F5 |
| 30 | Cabeceras `X-Forwarded-*` falsificadas | IP falsa en la bitácora, freno de login esquivado, cookie `Secure` mal decidida | solo se creen si el par TCP es una IP del proxy; el firewall solo deja llegar al proxy; pruebas F4 |
| 31 | Proxy inverso caído | panel inaccesible | túnel SSH de emergencia desde las redes de gestión |
| 32 | Baja por error | pérdida irreversible de todo el histórico del punto | confirmación escribiendo el nombre y aviso explícito. No hay respaldo diario que lo conserve: solo un respaldo manual o de `install.sh` hecho antes de la baja (sin los eventos de `/srv/ids/datos`, [OPERACION.md](OPERACION.md) §3.1) o la instantánea del proveedor |
