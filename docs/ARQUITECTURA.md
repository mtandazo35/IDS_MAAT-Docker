# IDS_MAAT-Docker — Arquitectura

- **Estado:** propuesta para revisión. No hay código todavía; este documento y sus anexos son el
  contrato que seguirán quienes lo escriban.
- **Fecha:** 2026-10-10.
- **Base:** `suricata-ids-lab` @ `5b89110` (`install-suricata.sh`: panel `DASH`, generador `HREP`,
  receptor `tzsp-decap.py`, montaje del espejo `MKINIT`, `openvpn.sh`).
- **Ejemplos:** solo direcciones de documentación.
  - VPS: `203.0.113.10`, con el nombre `ids.empresa.example`.
  - Redes de gestión: `192.0.2.0/25` y `198.51.100.0/26`.
  - Túnel del punto N: `100.64.N.0/24`.
  - LAN de abonados: `10.0.0.0/24`, repetida a propósito en dos puntos.

## Documentos

Este documento resume y decide. El detalle está en los anexos, y cada tema vive en un solo sitio.

| Anexo | Contenido |
|---|---|
| [RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) | Docker en el host, red por punto, flujo del espejo, relé de la API, CGNAT, nft del host y de cada netns, fail2ban, modo seguro |
| [INSTANCIA.md](INSTANCIA.md) | compose de cada punto, arranque, captura, `suricata.yaml`, OpenVPN, salud, netns huérfano, **capacidad**, reglas y feeds |
| [DATOS.md](DATOS.md) | SQLite, entidades, identidad `(punto_id, ip)`, retenciones, secretos cifrados, bitácora |
| [ORQUESTADOR.md](ORQUESTADOR.md) | servicio del host, protocolo, órdenes, cola, supervisión, avisos, flujos de alta, baja y pausa, respaldo diario |
| [ACTUALIZACIONES.md](ACTUALIZACIONES.md) | imágenes, GitHub Actions, firma y verificación, botón Actualizar, reversión, CVE |
| [FASES-Y-CANARIO.md](FASES-Y-CANARIO.md) | fases con pruebas y criterio de hecho, mediciones del canario, tabla completa de riesgos |
| [PLAN-PANEL.md](PLAN-PANEL.md) | inventario y refactor del panel actual, pantallas, cuarentena, API, seguridad de la aplicación |
| [OPERACION.md](OPERACION.md) | comandos MikroTik v7 y v6, respaldos, recuperación, acceso de emergencia |

## Índice

1. [Resumen](#1-resumen)
2. [Decisiones](#2-decisiones)
3. [Componentes](#3-componentes)
4. [Red y puertos](#4-red-y-puertos)
5. [Regla de identidad](#5-regla-de-identidad)
6. [Seguridad y acceso](#6-seguridad-y-acceso)
7. [Capacidad](#7-capacidad)
8. [Fases](#8-fases)
9. [Riesgos principales](#9-riesgos-principales)
10. [Preguntas abiertas](#10-preguntas-abiertas)
- [Anexo A. Glosario](#anexo-a-glosario)

---

## 1. Resumen

### 1.1 Qué es

IDS_MAAT-Docker es el sucesor en contenedores de `suricata-ids-lab`. Cada empresa (un ISP cliente)
tiene **un VPS** propio, normalmente de 8 CPU y 8 GB con Debian 13. En ese VPS corren:

- **Un panel central**: el panel actual, dividido en módulos, que es a la vez la web y la API.
- **Un orquestador**: un servicio del host que crea, para y actualiza las instancias. Solo acepta
  un conjunto fijo de órdenes del panel.
- **Una instancia por punto.** Un punto es un MikroTik de la empresa. Cada instancia tiene dos
  contenedores que comparten el netns:
  - `vpn`: OpenVPN, receptor TZSP, relé de la API y firewall «solo datos»;
  - `suricata`.

El MikroTik de cada punto abre un túnel OpenVPN TCP hacia su instancia y manda por él un espejo
recortado del tráfico de sus abonados (TZSP). Suricata lo analiza y el panel muestra las alertas
por punto. Cuando el operador lo decide, el panel mete a los CPE en address-lists del MikroTik de
ese punto a través de su API-SSL.

### 1.2 Qué no es

- **No es un IPS en línea.** Analiza una copia y actúa con address-lists en el router.
- **No es multiempresa.** Dos empresas, dos VPS.
- **No da acceso a las LAN de abonados.** El VPS no tiene rutas hacia ellas.
- **No es una vía de gestión.** Por la VPN no se llega al panel ni al SSH.
- **No lleva EveBox.** Si algún día hace falta, será una página «Eventos» del panel.
- **No migra solo los sensores actuales.** La migración la hace el dueño a mano; la importación es
  la fase opcional F6.

### 1.3 Diagrama general

```
                               Internet
                                  │
            ┌─────────────────────┼──────────────────────────────────────────────┐
            │ VPS de la empresa   │ 203.0.113.10 (ids.empresa.example)            │
            │ (Debian 13)         │                                               │
            │   nft inet ids_host: SSH y panel solo redes de gestión;            │
            │                      1194, 1195, … abiertos (OpenVPN de cada punto) │
            │                                                                      │
            │  ┌─ instancia p001 (netns propio) ──┐  ┌─ instancia p002 ─────────┐ │
            │  │ vpn:  openvpn tun0 100.64.1.1    │  │ vpn: tun0 100.64.2.1     │ │
            │  │       tzsp-decap → ids-in ─┐     │  │      …                   │ │
            │  │       relé API-SSL (socket)│     │  │                          │ │
            │  │ suricata: af-packet ids-mon┘     │  │ suricata                 │ │
            │  └──────▲──────────┬────────────────┘  └────▲─────────┬───────────┘ │
            │   tcp 1194│   eve.json (ro)            tcp 1195│   eve.json (ro)     │
            │         │          ▼                         │         ▼             │
            │         │   ┌───── panel-web + panel-worker (misma imagen) ──────┐  │
            │         │   │ estado.db · eventos.db · bitacora.db               │  │
            │         │   └───────────────┬────────────────────────────────────┘  │
            │         │                   │ socket UNIX, órdenes fijas             │
            │         │           ids-orq (systemd, host) ── docker, nft, PKI     │
            └─────────┼───────────────────────────────────────────────────────────┘
                      │ OpenVPN TCP (TZSP dentro)
          ┌───────────┴──────────┐                ┌──────────────────────┐
          │ MikroTik punto p001  │                │ MikroTik punto p002  │
          │ LAN 10.0.0.0/24      │                │ LAN 10.0.0.0/24      │
          └──────────────────────┘                └──────────────────────┘
```

---

## 2. Decisiones

Las filas marcadas con **(D)** son decisiones del dueño. El resto se derivan de ellas, de lo
aprendido en `suricata-ids-lab` y de la auditoría del diseño.

| Decisión | Por qué | Detalle |
|---|---|---|
| **(D)** 1 VPS = 1 empresa; 1 MikroTik = 1 punto. | Aísla a los clientes del ISP y deja el dimensionado en cada VPS. | — |
| **(D)** Por punto, `vpn` y `suricata` en un netns compartido; un OpenVPN y un Suricata por MikroTik. | Cada punto tiene su túnel, su interfaz de captura y su firewall. | [INSTANCIA](INSTANCIA.md) |
| **(D)** Puerto OpenVPN propio por punto (1194, 1195, …) y red de túnel `100.64.N.0/24`: sensor `.1`, MikroTik `.2`. | Puertos fijos; los túneles no se solapan entre puntos. | [RED](RED-Y-FIREWALL.md) §2 |
| **(D)** Un solo panel, que es también la API; crea las instancias por el orquestador y nunca ve `docker.sock`. | Un panel comprometido no se convierte en root. | [ORQUESTADOR](ORQUESTADOR.md) |
| **(D)** Todo dato lleva su punto. Filtro por punto y vista «Toda la empresa». | Los puntos pueden repetir LAN privadas. | §5, [DATOS](DATOS.md) |
| **(D)** Hoy todos ven todo; el modelo está preparado para restringir por punto. | Tabla `visibilidad` desde el primer día. | [DATOS](DATOS.md) §2 |
| **(D)** Sin EveBox. | Una web menos que asegurar. | — |
| **(D)** Imágenes en GHCR construidas con GitHub Actions. | Versionadas, firmadas y reversibles. | [ACTUALIZACIONES](ACTUALIZACIONES.md) |
| **(D)** Panel y SSH solo desde las redes de gestión. Por la VPN, solo el espejo (udp 37008) y las respuestas a lo que abre el sensor. fail2ban. Modo seguro con reversión. | La VPN transporta datos, nunca sirve para gestionar. | §6 |
| **(D)** Migración manual; la importación de datos es opcional y va al final (F6). | El proyecto no depende de ella. | [FASES](FASES-Y-CANARIO.md) |
| Relé de destino fijo por punto (socket UNIX → `100.64.N.2:8729`), uno solo, con API-SSL obligatoria y huella fijada. | El panel no comparte red con los puntos y el destino es inmutable. | [RED](RED-Y-FIREWALL.md) §4 |
| Sin `iroute` ni rutas hacia las LAN de abonados. | Las IP repetidas no chocan en la red; un contenedor comprometido no es un puente. | [RED](RED-Y-FIREWALL.md) §5 |
| Tres SQLite en WAL (`estado.db`, `eventos.db`, `bitacora.db` encadenada y anclada) más el `eve.json` por instancia. | Integridad `(punto_id, ip)` y transacciones, en lugar de unos 40 JSON con cerrojos. | [DATOS](DATOS.md) |
| El punto de un evento lo da la carpeta; se comprueba con el campo `host` del eve. | Detecta cableados erróneos (`EVE-MEZCLA`). | [DATOS](DATOS.md) §3 |
| `suricata.yaml` completo generado por punto, con memcaps e hilos fijos. Perfil de reglas por punto. | Dentro del contenedor, la RAM y las CPU que se ven son las del host. | [INSTANCIA](INSTANCIA.md) §6 |
| Sin recarga en caliente: un cambio de reglas es un reinicio **en serie** de cada instancia. | No existe el pico de doble motor; la admisión es predecible. | [INSTANCIA](INSTANCIA.md) §11 |
| Orquestador como servicio systemd del host, encerrado, con socket UNIX, `SO_PEERCRED`, token, órdenes fijas y **una cola única en serie**. | Es root de todos modos; la cola evita cerrojos y cargas simultáneas. | [ORQUESTADOR](ORQUESTADOR.md) |
| CA común por VPS fuera de los contenedores, certificado de servidor por punto, usuario y clave con hash (scrypt), sin cuentas del sistema y sin CRL. | La seguridad del punto la dan sus credenciales; con `verify-client-cert none`, una CRL no hace nada. | [INSTANCIA](INSTANCIA.md) §7 |
| Tabla nft propia en el host, con freno de conexiones VPN, y tabla «solo datos» en cada netns. DOCKER-USER no se toca. | Convive con Docker y con su backend nftables. | [RED](RED-Y-FIREWALL.md) §7–8 |
| Espejo siempre con `connection-bytes=0-10000` en ida y vuelta, sin regla de DNS aparte, y con `accept` antes del fasttrack. | Incidente real: 100 Mbps de espejo para que Suricata usara 3 (97 % desperdiciado). | [RED](RED-Y-FIREWALL.md) §3 |
| Healthcheck = procesos vivos (con latido). La falta de espejo es salud funcional. | Un punto pausado o sin tráfico no entra en reinicios en bucle. | [INSTANCIA](INSTANCIA.md) §8 |
| Imágenes por digest, firmadas con cosign keyless; reversión a los digests anteriores. | La producción nunca usa `latest`. | [ACTUALIZACIONES](ACTUALIZACIONES.md) |
| Los MikroTik apuntan a un nombre DNS de la empresa, no a la IP del VPS. | Recuperar el VPS en otro sitio no obliga a tocar los routers. | [OPERACION](OPERACION.md) §3 |
| Modo seguro de 5 min por defecto, configurable. | Da tiempo a confirmar desde una conexión nueva. | [RED](RED-Y-FIREWALL.md) §10 |

---

## 3. Componentes

| Componente | Qué es | Puntos clave |
|---|---|---|
| **Panel** (`panel-web`, `panel-worker`) | dos servicios de compose con la misma imagen y uid 10500 | `web` sirve las páginas y `/api/v1`; `worker` ingiere los eve, genera reportes, reconcilia, aplica políticas y hace el diagnóstico. Lee los eve, el estado del receptor y `estado.json` en ro; escribe sus tres SQLite. Habla con cada MikroTik por su relé y pide los cambios al orquestador. Sin `docker.sock`, sin capacidades, sin la CA. Salida a internet solo para AbuseIPDB, Groq y Telegram. [PLAN-PANEL](PLAN-PANEL.md) |
| **Orquestador** (`ids-orq`) | servicio systemd del host, Python stdlib, con CLI | el único que toca Docker, el nft del host, la PKI, logrotate y los respaldos. Compose generado por punto, cola en serie, admisión de RAM, supervisión (netns, salud, reinicios), `estado.json` cada 15 s, avisos propios por Telegram. [ORQUESTADOR](ORQUESTADOR.md) |
| **`vpn`** (uno por punto) | s6-overlay v3; dueño del netns | entrypoint: tabla nft → veth → tabla de ingreso → servicios. OpenVPN TCP, `tzsp-decap` (escucha en 0.0.0.0, filtra nft, latido cada 30 s), relé hacia `:8729`. Logs en journald (`ids-vpn`) para fail2ban. [INSTANCIA](INSTANCIA.md) |
| **`suricata`** (uno por punto) | af-packet sobre `ids-mon` | espera a `ids-mon` antes de arrancar; yaml completo del punto (`sensor-name = pid`); escribe el eve en su volumen; reglas y feeds en ro; el socket de control solo lo usa el orquestador. [INSTANCIA](INSTANCIA.md) |
| **Reglas y feeds** | `/srv/ids/reglas` (releases + `current`) y `/srv/ids/feeds` | una descarga diaria en un contenedor efímero; validación única; reinicio en serie. [INSTANCIA](INSTANCIA.md) §11 |
| **Firewall del host** | `inet ids_host`, servicio propio antes de Docker | `input` drop; SSH y panel solo desde gestión; puertos VPN abiertos con freno; `forward` que solo descarta. [RED](RED-Y-FIREWALL.md) §7 |
| **fail2ban** | jaulas `sshd` e `ids-vpn` | `journalmatch` correcto en Debian 13; la de OpenVPN banea en `forward`; las redes de gestión no van en `ignoreip`. [RED](RED-Y-FIREWALL.md) §9 |

Árbol del host:

```
/etc/ids-maat/{master.key,orq_token,avisos.conf}
/srv/ids/estado/{orq.db,orq.jsonl}   /srv/ids/pki/ (0700)   /srv/ids/fw/
/srv/ids/reglas/  /srv/ids/feeds/    /srv/ids/panel/ (bases, reportes, respaldos de routers)
/srv/ids/puntos/<pid>/  (compose, vpn/, suricata/suricata.yaml, threshold.config)
/srv/ids/datos/<pid>/   (eve.json, dns.json)          → panel ro (montaje del padre)
/srv/ids/run/<pid>/     (api.sock, tzsp.json) + estado.json → panel ro (montaje del padre)
/srv/ids/ctl/<pid>/     (sockets de control: solo orquestador)
/root/backups/
```

---

## 4. Red y puertos

| Puerto / socket | Escucha | Quién puede llegar | Notas |
|---|---|---|---|
| tcp 22 | sshd del host | solo las redes de gestión | fail2ban; `PasswordAuthentication no` |
| tcp 8443 | `panel-web` (publicado) | solo las redes de gestión | HTTPS (pregunta c) |
| tcp `1194+N-1` | `vpn` del punto N (publicado sobre su 1194) | internet, o solo la IP del MikroTik si se declara | límite de conexiones nuevas por IP, freno en `ovpn-auth`, jaula `ids-vpn` |
| udp 37008 | `tzsp-decap` del punto | solo `100.64.N.2` por `tun0` | el espejo |
| tcp 8729 en `100.64.N.2` | API-SSL del MikroTik | solo `100.64.N.1` (el relé) | única salida del netns |
| `/run/ids-orq/orq.sock` | orquestador | uid 10500 o root | `SO_PEERCRED` más token |
| `/srv/ids/run/<pid>/api.sock` | relé del punto | panel (grupo 10500) | destino fijo |
| `/srv/ids/ctl/<pid>/*` | Suricata y OpenVPN | solo el orquestador | reapertura de logs, `dataset-add`, desconexión de clientes |

Salidas a internet:

- **Panel:** 443 hacia AbuseIPDB, Groq y Telegram.
- **Contenedor efímero de reglas:** fuentes ET y feeds.
- **Orquestador:** GHCR, GitHub, sigstore y Telegram.
- **Contenedores `vpn`:** ninguna.

Cuatro ideas fijan la red (el detalle está en [RED-Y-FIREWALL.md](RED-Y-FIREWALL.md)):

- **El espejo** va por `forward` en el MikroTik, recortado a 10 KB por conexión en las dos
  direcciones, por el túnel TCP, hasta `tzsp-decap`. De ahí pasa al veth `ids-in`/`ids-mon`, que
  Suricata captura; el ingreso de `ids-mon` se descarta para que la pila IP no procese el espejo.
  Una ruta blackhole /24 de distancia 250 en el router impide que el espejo salga en claro si cae
  el túnel.
- **La API** va del panel al socket del relé, de ahí a `100.64.N.2:8729` y por `tun0`, con TLS de
  extremo a extremo. En el router hay un usuario API exclusivo y una regla de entrada propia; la
  lista `address=` del servicio no se toca.
- **No hay rutas hacia los abonados:** `ip_forward=0`, sin `iroute` ni `push`. Todo termina o se
  origina en el `vpn`.
- **CGNAT:** la base de túneles es configurable (pregunta a). El alta y un diagnóstico periódico
  comprueban las rutas y los pools del router contra el túnel; si hay solape, deshabilitan el
  mangle y avisan.

---

## 5. Regla de identidad

**Una IP privada sola no identifica nada.** En todo el panel, un CPE es `CpeRef(punto_id, ip)`:

- La forma de la clave no depende de cuántos puntos haya. Con uno solo es `("p001", "10.0.0.5")`.
- No existe «router por defecto». Si falta el punto, la operación falla con un error explícito.
- **El punto de un evento lo da la carpeta** del volumen (`/srv/ids/datos/<pid>/`). Además se
  compara con el campo `host` del eve (`sensor-name`); una discrepancia descarta la línea y avisa
  con `EVE-MEZCLA`.
- **`punto_id` es la primera columna** de toda PK e índice por punto. El repositorio exige un
  alcance: «Toda la empresa» es el conjunto de puntos visibles, nunca una consulta sin filtro.
- **Cada acción sobre un router usa solo el relé de su punto**, con el `punto_id` explícito en el
  formulario. Antes de escribir se comprueban `identidad` y `sw_id`
  (`ROUTER-NO-COINCIDE`).
- **El `punto_id` (`p001`…) nunca se reutiliza.** `N` (red y puerto) se reutiliza 7 días después
  de una baja.

Detalle, entidades, retenciones y secretos: [DATOS.md](DATOS.md).

---

## 6. Seguridad y acceso

### 6.1 Quién llega a qué

| Desde | Llega a | No llega a |
|---|---|---|
| Redes de gestión | SSH (22), panel (8443) | — |
| Internet | puerto OpenVPN de cada punto, con freno | SSH, panel, cualquier otro puerto |
| Túnel del punto N | `udp 37008` en `100.64.N.1` y respuestas a la API | panel, SSH, otros puntos, internet, el host |
| Panel | relés de API, eve y estado en ro, socket del orquestador, internet 443 | `docker.sock`, la CA, los sockets de control, la red de los puntos |
| Contenedor `vpn` | `100.64.N.2:8729` | internet, otros puntos, el panel |

### 6.2 Piezas

- **Las redes de gestión son obligatorias** desde la instalación. Se aplican en el nft del host y
  el panel las vuelve a comprobar.
- **Las cambia solo el orquestador** (`acceso.aplicar`), que valida:
  - que incluyen la IP del operador;
  - que no hay redes más anchas que /16 (para eso, la consola);
  - que no hay solape con los túneles ni con el pool de Docker;
  - `PasswordAuthentication no`.
- **Modo seguro:** aplica, arma la reversión (5 min por defecto) y solo hace persistente el cambio
  si el admin confirma desde una conexión nueva. Un reinicio del VPS en la ventana equivale a
  revertir. Recuperación: consola del proveedor y `acceso-emergencia.sh`.
- **fail2ban:**
  - SSH, con `journalmatch` para Debian 13;
  - OpenVPN, con los logs en journald y el baneo en `forward`;
  - `ignoreip` solo localhost y 1–2 IP fijas del dueño. **Las redes de gestión no se exceptúan.**
- **OpenVPN** a internet:
  - `meter` de 10 conexiones nuevas por minuto y por IP en el host;
  - `ovpn-auth` frena **antes** de scrypt;
  - `ccd-exclusive`;
  - origen fijo opcional por punto.
- **Panel:**
  - sin modo sin autenticación;
  - sesiones con hash;
  - CSRF con token;
  - PBKDF2 con 600k iteraciones;
  - freno de login propio;
  - CSP;
  - contenedor `read_only` sin capacidades.

  Detalle en [PLAN-PANEL.md](PLAN-PANEL.md) §12.
- **Secretos:** las claves API y los tokens van cifrados con AES-256-GCM (con AAD por punto). La
  clave maestra está fuera de `/data` y se respalda aparte ([DATOS.md](DATOS.md) §6).
- **Auditoría:** la bitácora encadena las filas con hashes y se ancla cada día en el diario del
  orquestador. Lleva `punto_id` y `op_id`, y nunca secretos.
- **Si se compromete el panel:**
  - puede hablar con la API de los MikroTik (por diseño) y dar órdenes fijas;
  - no puede usar Docker, leer la CA, entrar en la red de un punto ni llegar a un abonado;
  - lo mitigan el usuario API mínimo con `address=`, `envio_habilitado` apagado por defecto, el
    tope de cuarentenas automáticas por hora y la bitácora.

---

## 7. Capacidad

Con 8 GB, el número de MikroTik por VPS lo limita **la RAM, no la CPU**, porque cada instancia
carga su propio ruleset. Estimación, **a medir en el canario (F1a)**:

| Perfil del punto | Reglas / detección | `mem_limit` de `suricata` (motor + memcaps + 20 %) | Puntos en 8 GB |
|---|---|---|---|
| `completo` | ET completo, `profile: medium` | 1,2–1,7 GB | **2–3** |
| `completo-low` | ET completo, `profile: low` | 1,0–1,3 GB | **3–4** |
| `reducido` | ~15–20k reglas útiles para un espejo de ISP | 0,6–0,9 GB | **5–7** |

- **Reservas:** host ~1 GB, panel ~1 GB y **una sola reserva** para el `suricata -T` efímero. La
  cola en serie garantiza que solo hay uno a la vez.
- **El orquestador niega** crear un punto, o subirle el perfil, si no cabe, y dice cuántos caben
  con cada perfil. El panel muestra la capacidad restante.
- **Valores fijos:** memcaps, hilos (1–2), `ring-size` y `snaplen`. Un `cpuset` por Suricata y la
  CPU 0-1 para el host, el panel y los OpenVPN.
- **Coste de cambiar las reglas:** 30–90 s sin captura por punto, una vez al día de madrugada. Los
  cambios de exclusiones se agrupan como mucho cada 15 min.

Fórmula, componentes y disco: [INSTANCIA.md](INSTANCIA.md) §10.

---

## 8. Fases

Cada fase tiene pruebas de comportamiento en el repo y un criterio de hecho
([FASES-Y-CANARIO.md](FASES-Y-CANARIO.md)).

| Fase | Contenido | Hecho cuando |
|---|---|---|
| **F0** | esqueleto, `instalar.sh` mínimo (firewall estático, fail2ban SSH, secretos), CI y release a GHCR firmada | instalación limpia: login desde gestión sí, desde fuera no |
| **F1a** | **infraestructura** de una instancia: compose, `vpn`, `suricata`, orquestador por CLI, reglas en serie y **mediciones de capacidad**; eve leído a mano | un MikroTik o CHR manda el espejo, Suricata alerta y la capacidad está medida. **Con eso se fijan los perfiles antes de invertir en el panel** |
| **F1b** | panel en módulos con un punto fijo (`web` y `worker`) | alertas en el panel y cuarentena de ida y vuelta contra un CHR |
| **F2** | varios puntos, selector, `alcance()`, `CpeRef` | todas las pruebas con `10.0.0.5` en p001 y p002 sin un solo dato cruzado |
| **F3** | alta, baja, pausa y reinicio desde el panel por el orquestador; diagnóstico CGNAT; avisos directos | un operador sin consola gestiona un punto entero y la bitácora lo une por `op_id` |
| **F4** | seguridad: modo seguro, fail2ban SSH y VPN, cifrado, CSRF, cabeceras, cadena de la bitácora | todas las pruebas pasan y una auditoría interna no encuentra ningún hallazgo alto |
| **F5** | documentación y OPERACION probada, incluida la recuperación en otro VPS | otra persona instala, da de alta y recupera solo con los documentos |
| **F6** (opcional) | importación de configuración desde suricata-ids-lab, en ensayo por defecto | un sensor anonimizado se importa sin destinos sin explicar |

---

## 9. Riesgos principales

La tabla completa (29 riesgos) está en [FASES-Y-CANARIO.md](FASES-Y-CANARIO.md) §3.

| Riesgo | Mitigación |
|---|---|
| RAM: pocos puntos por VPS con ET completo | perfiles por punto, admisión con un 20 % de margen, mediciones en F1a |
| Netns huérfano tras reiniciar el `vpn` (punto ciego que parece sano) | el orquestador compara los inodos de `ns/net` y reinicia `suricata`; Suricata espera a `ids-mon` |
| Datos de puntos mezclados (cuarentena al abonado equivocado) | `CpeRef`, carpeta + `host`, `AlcanceRequerido`, `ROUTER-NO-COINCIDE`, pruebas F2 |
| Espejo en claro por la WAN si cae el túnel | blackhole /24 de distancia 250 |
| Desperdicio del espejo por un túnel TCP | `connection-bytes=0-10000` obligatorio y recorte en el receptor |
| Choque con el CGNAT del ISP | base configurable, validación al alta, diagnóstico periódico que deshabilita el mangle |
| Romper el firewall de Docker (`flush ruleset`, `iptables-persistent`) | tablas propias; ninguno de los dos se instala |
| Dejar fuera al dueño al cambiar el acceso | modo seguro, validaciones en el orquestador, consola y `acceso-emergencia.sh` |
| Fuerza bruta contra OpenVPN | `meter` en el host, freno antes de scrypt, jaula `ids-vpn` |
| RouterOS v6 antiguos con OpenSSL 3 | `SECLEVEL=0` y después `legacy`, solo en ese punto |
| Pérdida del VPS | respaldo diario con copia fuera, nombre DNS para los routers, recuperación probada |

---

## 10. Preguntas abiertas

**a) Base de la red de túneles.** Por decisión del dueño es `100.64.N.0/24`. Choca dentro del
router si la empresa usa `100.64.0.0/10` para el CGNAT de sus abonados.

*Recomendación:* que la base sea configurable por VPS y se elija al instalar:

- `100.64` por defecto;
- `198.18.N.0/24` (RFC 2544, reservada para pruebas de rendimiento y fuera de cualquier CGNAT)
  como alternativa recomendada para las empresas que usan `100.64/10`.

El alta y el diagnóstico periódico vigilan los solapes. Cambiar la base después obliga a dar de
alta todos los puntos otra vez, así que hay que decidirla antes del primer punto.

**b) Qué se conserva al dar de baja un punto.**

*Recomendación:*

- **Se borra en el acto:** los secretos, la configuración de la instancia, las credenciales VPN y
  el certificado de servidor.
- **Se conserva en solo lectura** hasta su retención normal: las alertas, el histórico, las
  cuarentenas cerradas y la bitácora (90 días / 180 días / 400 días / 2 años).
- **El `eve.json` crudo** se archiva comprimido 7 días y después se borra.
- **«Purgar datos de este punto»:** un botón aparte, solo para el admin, que deja constancia en la
  bitácora.

**c) HTTPS del panel.** Opciones: Let's Encrypt con un dominio, certificado autofirmado, o HTTP
solo desde las redes de gestión.

*Recomendación:* siempre TLS. Por las redes de gestión pasan contraseñas y claves de API, y las
cookies `__Host-`/`Secure` lo exigen.

- **Por defecto:** autofirmado, generado al instalar, mostrando su huella para fijarla en el
  navegador.
- **Si la empresa tiene dominio:** Let's Encrypt por **DNS-01**. HTTP-01 obligaría a abrir el
  puerto 80 a internet.
- **HTTP en claro:** descartado.

**d) Perfil TLS legacy para RouterOS v6 antiguos.**

*Recomendación:* TLS moderno por defecto (`tls-version-min 1.2`, SECLEVEL 2), con un interruptor
por punto, «compatibilidad v6», que solo se activa tras comprobar que el handshake falla:

1. primero `tls-cipher "DEFAULT:@SECLEVEL=0"`;
2. si no basta, `tls-cert-profile legacy`.

Hace falta que el dueño indique **la versión v6 más antigua de la flota** para probarla en el
canario, y que decida si acepta un TLS más débil en esos puntos o prefiere actualizar su RouterOS.

**e) Capacidad real tras el canario.** La estimación es de 2–3 puntos por VPS de 8 GB con ET
completo, 3–4 con `profile: low` y 5–7 con reglas reducidas. Está pendiente de medir.

*Recomendación:* decidirlo con las cifras de F1a, **antes de construir el panel**:

- el perfil `reducido` como valor por defecto del alta;
- `completo` solo en los puntos que lo justifiquen y quepan;
- para empresas con más puntos de los que admite un VPS de 8 GB, un VPS de 16 GB en lugar de
  varios VPS, lo que mantiene la regla 1 VPS = 1 empresa.

---

## Anexo A. Glosario

| Término | Significado |
|---|---|
| **Punto** | Un MikroTik de la empresa, con sus abonados. Se identifica con un `punto_id` (`p001`…) que nunca se reutiliza. Todo dato lleva su punto. |
| **Instancia** | Los dos contenedores de un punto (`vpn` y `suricata`) que comparten netns, con su puerto OpenVPN y su red de túnel `100.64.N.0/24`. |
| **Espejo** | La copia del tráfico de los abonados que el MikroTik envía por TZSP (udp 37008) a `100.64.N.1` a través del túnel, mediante reglas mangle `sniff-tzsp` en `forward`. |
| **Recorte** | Limitar el espejo a los primeros 10 000 bytes de cada conexión (`connection-bytes=0-10000` en el router y `TZSP_BYTES` en el receptor). Es donde Suricata encuentra casi todo, y evita desperdiciar el ancho de banda del túnel. |
| **Redes de gestión** | Los CIDR desde los que se entra al panel y al SSH del VPS. Son obligatorios, no más anchos que /16 y nunca incluyen la red de túneles. |
| **Modo seguro** | Forma de aplicar un cambio de acceso: se aplica, se arma una reversión automática (5 min por defecto) y solo se hace permanente si el admin confirma desde una conexión nueva. Un reinicio durante la ventana revierte. |
