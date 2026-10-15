# Auditoría de la VPN de los puntos — IDS_MAAT-Docker

- **Fecha:** 2026-10-14
- **Tipo:** auditoría de **solo lectura** del código. No se ejecutó nada, no se tocó el repo y no hubo conexión a servidores ni routers.
- **Repo:** IDS_MAAT-Docker, `HEAD = 95e627e48a88ca755989df1af5ce8a3bb9880247` (árbol limpio al auditar).
- **Estado:** corregida; ver §6 al final (qué se aplicó, en qué commit y qué queda).
- **Destinatario:** otra IA o una persona que vaya a aplicar los parches. El documento se lee solo, sin más contexto.

## 0. Ficheros auditados (SHA-256)

| Fichero | SHA-256 |
|---|---|
| `orquestador/ids_orq.py` | `afdfbd3c75a7e754e6f29319661c63e79f1528ea08c517ffbc3801953d37944d` |
| `orquestador/plantillas/server.conf.tmpl` | `8f2ebd3a356c0cc1d67b5abe3dc718fd887f887d381d510570724f4168178191` |
| `orquestador/plantillas/compose.yml.tmpl` | `ded65297e68849548cd5a9ca6cb8998f4eb7f4a5f86053227cc4ceb98dbc9022` |
| `orquestador/plantillas/ids_host.nft.tmpl` | `9c8db47b28f9579598de1b2e0f1b4221bce86e0fd368114478a21135f0c83d88` |
| `images/vpn/rootfs/usr/local/bin/ovpn-auth` | `ba32bbb2319d78bb5f13aff3c26f55b600f0d661c0d1857840dbbecffd844a3a` |
| `images/vpn/rootfs/usr/local/bin/salud-vpn` | `65864414df3eced5b7793e1c60aa77a81a9657fbf94da6e4bea683890a582bfd` |
| `images/vpn/rootfs/usr/local/lib/ids-vpn/render.py` | `65ea6224ee538a931428974bfbfc7bfcf8d2576ceca5385eff9ff170458ea962` |
| `host/fail2ban/filter.d/ids-vpn.conf` | `78b913e567b1a1f821abe13c0cbe6c8618d5f98300bbf40b7e9f68483f4b0038` |
| `host/fail2ban/jail.d/10-ids.local.tmpl` | `8b9163618f2d9966e89a8bb8b65a542df4f0a9c1774ee4906efac619e54b58db` |
| `images/panel/rootfs/usr/local/lib/ids-panel/puntos_web.py` | `9a4c027640c5d7263df7919fef65f13e69ca0209da0978f66846c90b6a246c9d` |
| `images/panel/rootfs/usr/local/lib/ids-panel/dashboard.py` | `eb8056dd41be725e507c3b04754de8d6aa1bb83c12e0061bb7f2c5175beb1000` |
| `install.sh` | `1fc772858d1a18c00b66b2576d4496e8ea2dbf3c67a00e04ed2b392c01e948c3` |

También se leyeron estos ficheros, sin hash: los scripts s6 de `images/vpn/rootfs/etc/s6-overlay/`, `images/vpn/Dockerfile`, `tzsp-decap`, `host/docker/daemon.json`, `host/sysctl/90-ids.conf`, `host/logrotate/ids-maat.conf`, `images/suricata/rootfs/usr/local/bin/entrypoint-suricata`, `idspanel/orq.py` y `docs/` (ARQUITECTURA, CONTRATO-F1a, INSTANCIA, OPERACION, ORQUESTADOR, RED-Y-FIREWALL, FASES-Y-CANARIO).

## 1. Resumen ejecutivo

El lado servidor está bien construido. Cada punto tiene su netns cerrado («solo datos»), con `ip_forward=0`, salida limitada a la API del MikroTik y entrada limitada al TZSP del MikroTik. El host tiene su propia tabla nft, que descarta todo lo publicado que no estaba previsto, y fail2ban banea en el hook `forward` con la IP real (`userland-proxy: false`). La credencial es fuerte: 24 caracteres aleatorios, guardados con hash scrypt y mostrados una sola vez. No existe ninguna clave privada de cliente que tenga que pasar por el panel o por el navegador.

Los problemas importantes están en **la frontera con el MikroTik**, no dentro del VPS:

1. **ALTA — VPN-01.** El MikroTik **no verifica el servidor OpenVPN**. El script generado no le entrega la CA ni pone `verify-server-certificate=yes`. Quien suplante el servidor (DNS de `NOMBRE_DNS` envenenado o alguien en el camino) se queda con la clave VPN y pasa a ser el «sensor» `.1` para el router. Como el panel fija la huella de la API-SSL **automáticamente** en la primera conexión (TOFU sin confirmar), en un alta interceptada también se lleva la clave de `ids-api`, que tiene `policy=read,write,api` sobre el core.
2. **ALTA (condicional) — VPN-02.** El script del MikroTik solo **añade un `accept`** en `ids-vpn`; no hay ningún `drop` en `input` ni en `forward` para esa interfaz. Toda la contención depende del nft del contenedor, y ese nft no detiene a un root con `CAP_NET_RAW` dentro del netns: un socket AF_PACKET no pasa por los hooks `inet`. En ese netns corren como root, con NET_RAW, Suricata (que analiza tráfico hostil de los abonados) y OpenVPN (expuesto a internet antes de autenticar). Si se compromete cualquiera de los dos, o se da VPN-01, el atacante llega al plano de gestión del core y, por `forward`, a las redes del ISP. Es condicional porque depende del firewall que ya tenga cada router, y eso no se ve en el código.

En gravedad **MEDIA** quedan cuatro hallazgos:

- **VPN-03.** Probable DoS previo a la autenticación: con `max-clients 2`, dos conexiones TCP sin autenticar desde una sola IP bastan para dejar fuera al MikroTik, y fail2ban no las ve. Sin confirmar en laboratorio; si se confirma, sube a ALTA.
- **VPN-04.** Tras «Regenerar la clave VPN» o una clave mal puesta, el router legítimo acaba **baneado en todos los puertos**, con un ban que crece hasta 1 semana. El panel no ofrece desbanear.
- **VPN-05.** Suricata sigue con `NET_ADMIN` en el netns compartido (el canario lo tenía pendiente).
- **VPN-06.** El TOFU de la API-SSL se fija solo, sin confirmación, aunque la documentación dice «al confirmar».

No hay hallazgos **CRÍTICOS**: nada se explota desde internet sin una condición previa (suplantar el DNS o el camino, o tener un RCE). Los dos ALTA bajan casi por completo con **cambios solo en el script del MikroTik**, compatibles con 6.49 y v7 (falta verificar en el canario un punto de 6.49, marcado abajo).

Nota de coherencia (no es un hallazgo): el encargo habla de «puerto 1194+N», pero el código usa `1194 + N − 1` (`ids_orq.py:447`; N=1 → 1194, N=3 → 1196, N=12 → 1205). La documentación (`CONTRATO-F1a.md:242`, `OPERACION.md:53`) coincide con el código.

## 2. Tabla de hallazgos

| ID | Gravedad | Dónde (archivo:línea) | Resumen |
|---|---|---|---|
| VPN-01 | **ALTA** | `orquestador/ids_orq.py:712-757`; `docs/OPERACION.md:60-66`; `dashboard.py:1394-1403` | El MikroTik no verifica el certificado del servidor; no se le entrega la CA |
| VPN-02 | **ALTA** (condicional) | `orquestador/ids_orq.py:721-726`; `compose.yml.tmpl:11,58`; `render.py:92-116`; `entrypoint-suricata:16` | El router no aísla `ids-vpn` (solo `accept`); el nft del netns no frena a root con NET_RAW |
| VPN-03 | MEDIA (ALTA si se confirma) | `server.conf.tmpl:7`; `ids_host.nft.tmpl:25`; `filter.d/ids-vpn.conf:15` | `max-clients 2` + `hand-window` de 60 s por defecto: DoS previo a la autenticación desde 1 IP, sin ban (sin confirmar) |
| VPN-04 | MEDIA | `ovpn-auth:231-232`; `filter.d/ids-vpn.conf:15-16`; `jail.d/10-ids.local.tmpl:8-12`; `ids_orq.py:2961-2979` | Router legítimo baneado (allports, hasta 1 semana) tras regenerar la clave o equivocarse al teclearla |
| VPN-05 | MEDIA | `compose.yml.tmpl:58`; `docs/INSTANCIA.md:96`; `docs/FASES-Y-CANARIO.md:238` | Suricata (root, analiza tráfico hostil) con `NET_ADMIN` en el netns del túnel |
| VPN-06 | MEDIA | `dashboard.py:1394-1403`; `docs/ORQUESTADOR.md:211`; `docs/OPERACION.md:44-48` | TOFU de la API-SSL fijado solo y clave de `ids-api` enviada en esa misma conexión; con 8728 no hay TLS |
| VPN-07 | BAJA | `salud-vpn:13-35` | El healthcheck no mide que OpenVPN escuche ni que exista `tun0` |
| VPN-08 | BAJA | `ovpn-auth:43-46,233-234` | El freno global también rechaza al router legítimo (con renegociación cada hora) |
| VPN-09 | BAJA | `server.conf.tmpl:21`; `ovpn-auth` | `auth-user-pass-verify` síncrono (arranque de Python + scrypt) bloquea el bucle de OpenVPN durante una avalancha |
| VPN-10 | BAJA (sin confirmar) | `ids_host.nft.tmpl:25` | `meter vpn_new` sin `timeout`: se llena con 65 535 IP y deja de frenar |
| VPN-11 | BAJA | `ids_orq.py:1374-1430` | Sin CRL ni revocación del certificado de servidor; CA de 20 años y servidores de 10 (importa solo tras VPN-01) |
| VPN-12 | BAJA | `ids_orq.py:2566-2609` (enfriamiento de 7 días) | Un N reutilizado más un router viejo todavía configurado provoca un ban allports de su IP |
| VPN-13 | BAJA | `ids_orq.py:963-982` | `leer_status_openvpn` toma la primera línea `CLIENT_LIST`, que con 2 sesiones puede ser la vieja |
| VPN-14 | BAJA | `docs/RED-Y-FIREWALL.md:350-351`; `docs/INSTANCIA.md:243,248,282`; `docs/ORQUESTADOR.md:211` | La documentación no coincide con el código (filtro fail2ban, `proto`, `data-ciphers`, modo de `usuarios`, TOFU) |
| VPN-15 | BAJA (sin confirmar) | `compose.yml.tmpl` (journald); `host/` sin `journald.conf` | Logs de todos los puntos por `docker.service`: límites de tamaño y de ritmo de journald sin fijar |
| VPN-16 | INFO | `server.conf.tmpl:16-18`; `ids_orq.py:593-600` | `auth SHA1`/CBC en v6 y `SECLEVEL=0`/`legacy` por punto: son restricciones de RouterOS y están documentadas |

---

## 3. Detalle de los hallazgos

### VPN-01 — ALTA — El MikroTik no verifica el servidor OpenVPN

**Evidencia**

- Los bloques que genera `comandos_mikrotik()` (`orquestador/ids_orq.py:734-746`) no incluyen `verify-server-certificate` ni importan ninguna CA:
  ```
  /interface ovpn-client add name=ids-vpn connect-to=%s port=%s protocol=tcp mode=ip \
      user=%s password=%s cipher=%s auth=sha1 \
      add-default-route=no use-peer-dns=no disabled=no
  ```
- `docs/OPERACION.md:60-66` lo deja como recomendación **manual** («importar la CA de la empresa y verificar el servidor»). Ni el panel ni el orquestador ofrecen el `ca.crt` para descargarlo: `grep ca.crt` solo aparece en la PKI (`ids_orq.py:1377-1409`, `install.sh:526-532`) y en `server.conf.tmpl:12`.
- `connect-to` es el `NOMBRE_DNS` de `ids.conf` (`ids_orq.py:369,744`), así que el router resuelve por DNS.
- El panel fija la huella de la API-SSL **en la primera conexión y sin preguntar**, y en esa misma conexión envía la clave (`dashboard.py:1399-1408`):
  ```python
  if not esperada:
      d["CERT_FP"] = fp
      try: _guardar_huella(pid, fp)
      ...
  _mk_send(sock, ["/login", f"=name={d['USER']}", f"=password={d['PASS']}"])
  ```

**Impacto**

- Quien controle la resolución de `NOMBRE_DNS` para ese router (resolver envenenado, DNS del dominio comprometido) o esté en el camino puede presentar **cualquier** certificado. El router lo acepta y le entrega usuario y clave VPN.
- Con esa clave el atacante hace de relé hacia el servidor real (MITM completo del túnel) y para el router pasa a ser `100.64.N.1`. Esa es justo la dirección a la que el script le da acceso a la API (`/user add ... address=<sensor>/32` y la regla `accept`).
- En un alta interceptada, el panel conecta por el relé al «router», que en realidad es el atacante. El panel fija la huella del atacante y le envía la clave de `ids-api` (`read,write,api`). Con ella, desde `.1`, el atacante tiene escritura en el core.
- La gravedad se calibra así: hace falta suplantar DNS o estar en el camino. No es explotable de forma directa desde internet, por eso no es CRÍTICA. Es ALTA porque el resultado es escritura sobre el router principal de un ISP y el arreglo es barato.

**Parche propuesto**

1. **Entregar la CA en el script** (es pública, no es secreta). En `comandos_mikrotik()`, añadir un parámetro `ca_pem` (que el orquestador lee de `/srv/ids/pki/ca.crt`) y generar estas líneas **dentro** de cada bloque v7/v6, justo después del `ovpn-client add`. Así `partir_comandos()` (`idspanel/orq.py:131-158`) no cambia:
   ```python
   def lineas_ca(pid, ca_pem):
       nombre = "ids-ca-%s" % pid
       cuerpo = ca_pem.strip().replace("\r", "").replace("\n", "\\n")
       return (
           "/file print file=%s\n"
           ":delay 2s\n"
           "/file set [find name=\"%s.txt\"] contents=\"%s\\n\"\n"
           "/certificate import file-name=%s.txt passphrase=\"\"\n"
           "/interface ovpn-client set [find name=ids-vpn] verify-server-certificate=yes\n"
           % (nombre, nombre, cuerpo, nombre))
   ```
   - El PEM de una CA RSA 2048 ocupa unos 1,2 KB, por debajo del límite de 4 KB de `/file set contents` en v6.
   - La CA es una por VPS (`asegurar_ca`), así que vale para todos los puntos de ese VPS.
   - Hay que actualizar `tests/test_orq_comandos.py`, que fija la salida exacta.
2. **Compatibilidad:**
   - **v7:** `verify-server-certificate` existe y el propio proyecto ya lo tiene como prueba del canario (`FASES-Y-CANARIO.md:243`).
   - **6.49: sin confirmar.** Hay que probar en el canario `/interface ovpn-client set ids-vpn verify-server-certificate=yes`. Si 6.49 no lo admite, el bloque v6 se queda sin esa línea y el riesgo se documenta.
   - El truco `/file print file=` + `/file set contents=` funciona en v6 y en v7. En v7 también vale `/file add name=... contents=...`. Hay que validarlo en el canario.
   - RouterOS, por lo que se sabe, valida la cadena y no el CN o SAN frente a `connect-to`. Con una CA por VPS que solo firma certificados de servidor, la cadena basta.
     **Corrección posterior:** falso. La documentación de v7 dice que `verify-server-certificate` comprueba el CN o el SAN frente a `connect-to`; por eso el arreglo también cambió el certificado del servidor (ver §6).
3. **Cerrar el TOFU automático** (ver VPN-06): no mandar `/login` mientras la huella no esté confirmada.

---

### VPN-02 — ALTA (condicional) — El MikroTik no aísla `ids-vpn` y el nft del netns no es una barrera ante root con NET_RAW

**Evidencia**

- El script solo añade un `accept` (`ids_orq.py:721-726`):
  ```
  /ip firewall filter add chain=input in-interface=ids-vpn src-address=<sensor> protocol=tcp \
      dst-port=<api> action=accept place-before=0 comment="IDS ids-maat:<pid>"
  ```
  No hay `drop` para `in-interface=ids-vpn` ni en `input` ni en `forward`.
- La contención del lado servidor es la tabla `inet ids_punto` (`render.py:92-116`): hooks `input`/`output`/`forward` de IP.
- Los dos procesos que reciben datos hostiles corren como **root** con `CAP_NET_RAW` en ese netns:
  - El contenedor `vpn` (`compose.yml.tmpl:11`, `cap_add: [NET_ADMIN, NET_RAW]`). OpenVPN no baja de usuario (`openvpn/run:2`, «Sin user/group»).
  - El contenedor `suricata`, que comparte el netns (`compose.yml.tmpl:53` `network_mode: "service:vpn"` y `:58` `cap_add: [NET_RAW, NET_ADMIN]`). Su arranque dice «Suricata corre como root del contenedor, sin --user» (`entrypoint-suricata:16`).
- Razonamiento sin prueba de laboratorio: un socket `AF_PACKET` sobre `tun0` envía y recibe sin pasar por los hooks `inet` de netfilter. Las capturas se toman antes del hook de entrada, y el envío por packet socket no atraviesa `output`. Con NET_ADMIN, además, basta con `nft delete table inet ids_punto`. La afirmación de `RED-Y-FIREWALL.md:191` («Un contenedor comprometido no sirve de puente») es cierta para el forwarding IP, pero **no** frente a root con NET_RAW que hable directamente por `tun0`.

**Impacto**

- Un RCE en Suricata llega con el tráfico espejado de los abonados, que es tráfico de internet. Un RCE en OpenVPN llega antes de autenticar, también desde internet. VPN-01 da el mismo resultado sin RCE.
- En cualquiera de esos casos el atacante habla con el MikroTik como `100.64.N.1`:
  - por `input`: Winbox, SSH, API y el resto de servicios que el router acepte desde esa interfaz;
  - por `forward`: hacia las redes del ISP, porque el router enruta lo que entra por `ids-vpn`.
- **Condicional:** depende del firewall que ya tenga cada router. Si su `input` descarta lo que no viene de una interface-list «LAN» y `ids-vpn` no está en esa lista, el daño se limita a la API. Eso no se puede confirmar en el código.

**Parche propuesto** (en `comandos_mikrotik()`, bloque `comun`; vale para 6.49 y v7 con la misma sintaxis)

```
/ip firewall filter add chain=forward in-interface=ids-vpn action=drop place-before=0 comment="IDS ids-maat:<pid>"
/ip firewall filter add chain=input   in-interface=ids-vpn action=drop place-before=0 comment="IDS ids-maat:<pid>"
/ip firewall filter add chain=input   in-interface=ids-vpn src-address=<sensor> protocol=tcp \
    dst-port=<api> action=accept place-before=0 comment="IDS ids-maat:<pid>"
```

- El orden importa. Cada `place-before=0` deja la regla arriba del todo, así que se escriben los `drop` primero y el `accept` al final. Queda `accept(input)` → `drop(input)` → `drop(forward)` → reglas del cliente.
- El espejo no se ve afectado. `sniff-tzsp` lo genera el propio router (sale por `output` hacia el sensor), no entra por `ids-vpn`. Las respuestas de la API van en la conexión que ya casa con el `accept`.
- Llevan el mismo comentario `IDS ids-maat:<pid>`, así que la limpieza de la baja (manual, `puntos_web.py:1083-1086`) las encuentra.
- Si la lista `filter` del router está vacía, `place-before=0` falla, igual que la regla actual. Conviene añadir una nota en el script.
- Defensa en el servidor, complementaria: ver VPN-05 (quitar NET_ADMIN a Suricata). Como opción, OpenVPN puede correr sin privilegios: `tun0` precreado en un oneshot (`ip tuntap add dev tun0 mode tun user <uid>`), `ifconfig-noexec` con la IP puesta en ese oneshot, y `s6-setuidgid` con `SETUID/SETGID` solo en el `vpn`. Esto requiere pruebas.

---

### VPN-03 — MEDIA (ALTA si se confirma) — DoS previo a la autenticación con `max-clients 2`

**Evidencia**

- `server.conf.tmpl:7`: `max-clients 2`. El motivo está en `CONTRATO-F1a.md:70`: «el reintento del MikroTik no se bloquea con la sesión vieja viva».
- No hay `hand-window`, así que vale el valor por defecto de OpenVPN: **60 s** para completar el handshake.
- Freno del host: `ids_host.nft.tmpl:25`, `limit rate over 10/minute` por IP en conexiones **nuevas**. No limita las conexiones **simultáneas**.
- fail2ban solo cuenta `ovpn-auth: rechazado` (`filter.d/ids-vpn.conf:15`). Una conexión TCP que no termina el TLS nunca llega a `ovpn-auth`. El filtro original, que contaba `TLS Error: TLS handshake failed`, se quitó (`CONTRATO-F1a.md:77`, fila 16).
- **Sin confirmar:** en modo servidor TCP, OpenVPN crea la instancia al aceptar la conexión. Según el código de OpenVPN 2.6 (`multi_create_instance`), el límite `max-clients` se compara con las instancias del hash, **incluidas las que aún no se han autenticado**. No se ha probado en laboratorio.

**Impacto**

- Desde una sola IP, sin credenciales, bastan 2 conexiones TCP abiertas cada < 60 s (muy por debajo de 10/min). Ningún log llega a fail2ban.
- Con eso el MikroTik de ese punto no puede reconectar: tras un corte, un cambio de IP o una renegociación fallida, la sesión vieja ocupa una plaza hasta `ping-restart` (120 s en el servidor). El punto se queda ciego para el IDS.
- Prueba de laboratorio: abrir 2 o 3 `nc <vps> <puerto>` y dejarlos colgados. Después cortar la VPN del router y ver si reconecta. En el log del `vpn` hay que buscar `MULTI: new incoming connection would exceed maximum number of clients`.

**Parche propuesto** (solo en el servidor; compatible con 6.49 y v7)

1. En `server.conf.tmpl`: `max-clients 8` y `hand-window 20`. `duplicate-cn` sigue ausente, así que una sesión nueva del mismo usuario sigue echando a la vieja y solo puede haber un túnel útil.
2. Límite de conexiones simultáneas por IP en `ids_host.nft.tmpl`, delante del freno:
   ```
   set vpn_conc { type ipv4_addr; flags dynamic; size 65536; }
   ...
   meta l4proto tcp ct direction original ct status dnat ct original proto-dst @puertos_vpn ct state new add @vpn_conc { ip saddr ct count over 3 } counter drop comment "máx. 3 VPN simultáneas por IP"
   ```
3. Una jaula aparte `ids-vpn-tls` con `failregex = ^%(__ids_pref)s<HOST>:\d+ TLS Error: TLS handshake failed` y `maxretry = 10`, para no repetir el doble conteo que se corrigió en la fila 16. Inconveniente: un router con un fallo de compatibilidad TLS también acabaría baneado.
4. Recomendar `--origen-ip` siempre que el router tenga IP fija. Ya existe (`ids_host.nft.tmpl:24`) y es la mitigación más fuerte.

---

### VPN-04 — MEDIA — El router legítimo acaba baneado (allports, hasta 1 semana) tras regenerar la clave o equivocarse al teclearla

**Evidencia**

- `o_regenerar` (`ids_orq.py:2961-2979`) cambia el hash y corta la sesión con `kill <usuario>`. El router sigue reintentando con la clave vieja.
- `ovpn-auth:231-232`: tras 5 rechazos en 600 s, **rechaza incluso la clave correcta** (`motivo=freno`), porque el freno va antes de scrypt.
- `filter.d/ids-vpn.conf:15-16`: cuenta **todos** los `rechazado`, también `motivo=clave` y `motivo=freno`. Solo excluye `freno-global`.
- `jail.d/10-ids.local.tmpl:8-12`: `maxretry 5` en `10m`, `bantime 1h`, `bantime.increment = true`, `maxtime 1w`. El ban es `allports` en `forward` (`:27-28`), así que corta también los demás puntos y el panel desde esa IP.
- El panel no tiene forma de desbanear. Solo `fail2ban-client set ids-vpn unbanip` por SSH (`OPERACION.md:305-325`). El aviso del panel («la VPN actual del MikroTik se corta hasta que pongas la nueva», `puntos_web.py:1572`) no menciona el ban.

**Impacto**

- RouterOS reintenta cada pocos segundos, así que el ban llega en menos de un minuto.
- Al poner la clave nueva, el router sigue baneado 1 h. Si se repite, el ban sube a 2 h, 4 h… hasta una semana.
- Si hay varios puntos detrás de la misma IP pública, caen todos.

**Parche propuesto** (solo en el servidor)

1. Que fail2ban cuente solo lo que hace un escáner o un atacante, no al dueño del usuario. El nombre de usuario no es público: está en el router y en el panel.
   ```ini
   failregex = ^%(__ids_pref)s<HOST>:\d+ ovpn-auth: rechazado usuario=\S+ motivo=(?:formato|usuario)\b
   ignoreregex =
   ```
   - Un escáner suma 5 `formato`/`usuario` y queda baneado igual.
   - El router con la clave vieja (`motivo=clave`, y después `freno`) nunca se banea. El freno por IP le deja un intento cada pocos minutos y entra solo en ≤ 10 min tras corregir la clave.
   - La fuerza bruta contra un usuario conocido sigue acotada: 5 intentos cada 600 s por IP y 30 scrypt/min en total, frente a 62²⁴ claves posibles.
   - Hay que actualizar `tests/test_host_fail2ban.py` y la fixture.
2. Una orden `punto.vpn.desbanear`, con el último `ip_real` del status y, si no lo hay, una IP indicada a mano. El orquestador ejecuta `fail2ban-client set ids-vpn unbanip <ip>`. El panel la ofrece en la ficha del punto, junto a «Regenerar».

---

### VPN-05 — MEDIA — Suricata con `NET_ADMIN` en el netns del túnel

**Evidencia:** `compose.yml.tmpl:58` (`cap_add: [NET_RAW, NET_ADMIN]`). `INSTANCIA.md:96` dice: «Se prueba sin ella en el canario: si captura igual, se quita». En `FASES-Y-CANARIO.md:238` sigue pendiente. `init-veth` ya pone `ids-mon` en promisc y apaga los offloads (`init-veth:8-11`).

**Impacto:** Suricata es el mayor analizador de datos hostiles del sistema. Con NET_ADMIN, un RCE puede borrar `inet ids_punto` y `netdev ids_mon` y reconfigurar `tun0`. Ver VPN-02.

**Parche:** `cap_add: [NET_RAW]` en el servicio `suricata` y, si hace falta, `af-packet.disable-promisc: yes` en la plantilla, porque el promisc ya lo pone `init-veth`. La prueba de aceptación es la del canario: `capture.kernel_packets` sigue subiendo y desaparecen los avisos de offload. No afecta al MikroTik.

---

### VPN-06 — MEDIA — TOFU de la API-SSL automático; la clave de `ids-api` se envía en la conexión que fija la huella

**Evidencia:** `dashboard.py:1394-1408`: sin huella guardada, la fija y hace `/login` en esa misma conexión. La documentación dice lo contrario: «el panel muestra la huella … y, al confirmar, la fija» (`ORQUESTADOR.md:211`, `OPERACION.md:44-48`). La ficha muestra «ninguna (se fija en la primera conexion)» (`puntos_web.py:1531`). Con `api_puerto=8728`, que se acepta (`ids_orq.py:1610`, `render.py:74`), la API va en claro dentro del túnel y no hay huella que comprobar.

**Impacto:** si se combina con VPN-01, la primera conexión puede pinchar contra un impostor. Por sí solo, dentro de un túnel cifrado y legítimo, el riesgo es bajo.

**Parche:**

- Si no hay `CERT_FP`, abrir TLS, leer la huella, **cerrar sin `/login`** y mostrarla en la ficha con un botón «Confirmar huella» (admin, queda en el registro), junto al comando `/certificate print detail where name=ids-promax` para compararla.
- Solo después se guarda la clave y se usa.
- Desaconsejar 8728 en el formulario, o exigir una confirmación explícita.
- Compatible con 6.49 y v7: no cambia nada en el router.

---

### VPN-07 — BAJA — El healthcheck del `vpn` no mide que OpenVPN escuche

**Evidencia:** `salud-vpn:13-35` comprueba `s6-svstat -o up` de los 3 servicios, la edad de `tzsp.json` (latido del proceso `tzsp-decap`, no del tráfico) y que exista la tabla nft. No comprueba `:1194` en LISTEN ni `tun0`. Si OpenVPN cae y vuelve en bucle, s6 puede dar `up=true` de forma intermitente.

**Bien:** la falta de tráfico se vigila fuera del healthcheck, a propósito: `SIN-ESPEJO`/`ESPEJO-NO-LLEGA` en `ids_orq.py:2227-2253` y `vpn_cliente` en el estado.

**Parche** (iproute2 ya está en la imagen):

```sh
ss -Hltn 'sport = :1194' | grep -q . || { echo "salud-vpn: openvpn no escucha en 1194"; exit 1; }
ip link show tun0 >/dev/null 2>&1   || { echo "salud-vpn: falta tun0"; exit 1; }
```

Opcional: exigir que el servicio lleve más de 5 s levantado (`s6-svstat -o up,updownfor`).

### VPN-08 — BAJA — El freno global también rechaza al router legítimo

**Evidencia:** `ovpn-auth:233-234`. Con ≥ 30 scrypt por minuto en el contenedor, se rechaza a todos. Solo se calcula scrypt si el usuario existe (`:235-238`), así que el atacante necesita conocer el usuario y unas 6 IP, porque cada IP tiene 5 intentos cada 600 s.

**Impacto:** OpenVPN renegocia cada `reneg-sec` (3600 s por defecto) y vuelve a pasar por el script. Durante una avalancha, el router legítimo pierde el túnel.

**Parche:** guardar en el estado del freno la última IP aceptada (`"ok": {"ip": ..., "ts": ...}`) y no aplicarle el freno global durante 24 h.

### VPN-09 — BAJA — Verificación síncrona que bloquea OpenVPN

**Evidencia:** `server.conf.tmpl:21`. OpenVPN espera a que termine el script: un arranque de `python3` más scrypt con N=16384, r=8 (unos 16 MB) por intento.

**Impacto:** una avalancha distribuida, aunque acabe en rechazos baratos por formato o freno, consume el bucle del único proceso OpenVPN del punto y frena el TZSP. Hace falta una botnet y el efecto se limita a un punto.

**Parche (opcional):** autenticación diferida de OpenVPN 2.6 (el script devuelve 2 y escribe `auth_control_file`) o un plugin. Es suficiente con documentarlo.

### VPN-10 — BAJA (sin confirmar) — `meter` sin caducidad

**Evidencia:** `ids_host.nft.tmpl:25`, `meter vpn_new { ip saddr limit rate over 10/minute }`, sin `timeout` ni `size`. Se borra solo cuando se recrea la tabla (`regenerar_fw`).

**Impacto:** con el tamaño por defecto (65 535), los escáneres de meses llenan el set. A partir de ahí no se pueden añadir IP nuevas y la regla deja de frenar. No bloquea a nadie: el freno simplemente deja de actuar.

**Parche:**

```
set vpn_new { type ipv4_addr; flags dynamic,timeout; timeout 10m; size 65536; }
... ct state new update @vpn_new { ip saddr limit rate over 10/minute } counter drop comment "freno OpenVPN"
```

### VPN-11 — BAJA — PKI sin revocación del lado servidor

**Evidencia:**

- La CA es RSA 2048, de 20 años, sin clave de paso, en `/srv/ids/pki/ca.key` con modo 0600 (`ids_orq.py:1374-1389`, `install.sh:524-537`).
- Cada punto tiene su certificado de servidor de 10 años, con serial aleatorio de 128 bits y EKU serverAuth (`:1400-1418`).
- En la baja se **borra** la clave (`borrar_cert`, `:1421-1426`), pero no se revoca.
- La clave de servidor existe dos veces: `pki/servidores/<pid>.key` y `puntos/<pid>/vpn/server.key`.
- No hay CRL (decisión documentada en `ARQUITECTURA.md:139`).

**Impacto:** hoy, ninguno, porque los routers no verifican el servidor (VPN-01). Si se aplica VPN-01, una clave de servidor filtrada valdría 10 años para suplantar **cualquier** punto del VPS. Todas esas claves viven en el mismo host que la CA, así que el riesgo real es pequeño.

**Parche (opcional):** cuando se aplique VPN-01, bajar la validez de los certificados de servidor a 2-3 años con renovación en `punto ajustar`, o publicar una CRL y usar `crl-check` en v7. Hay que confirmar antes que RouterOS 6.49 consulta la CRL.

### VPN-12 — BAJA — N reutilizado y router viejo todavía configurado

**Evidencia:** el pid no se reutiliza nunca, pero N sí, tras 7 días de enfriamiento (`ENFRIAMIENTO_S`, `ids_orq.py:78,2583-2584`). El panel avisa de que en el router quedan `ids-vpn` y las reglas (`puntos_web.py:1083-1086`).

**Impacto:** si nadie limpia ese router, cuando N se reasigna el router viejo entra en el puerto nuevo con un usuario que no existe. Tras 5 intentos su IP queda baneada en todos los puertos, también para otros puntos detrás de esa IP.

**Parche:** que la baja intente `/interface ovpn-client disable ids-vpn` por la API mientras el túnel sigue arriba (ya limpia el espejo por ese camino). Si no se puede, alargar el enfriamiento.

### VPN-13 — BAJA — `leer_status_openvpn` toma la primera sesión

**Evidencia:** `ids_orq.py:963-982` devuelve la primera línea `CLIENT_LIST`. Con `max-clients 2` puede haber durante un rato una sesión vieja y una nueva.

**Parche:** quedarse con la línea de mayor `Connected Since (time_t)` (`c[8]`).

### VPN-14 — BAJA — Documentación que no coincide con el código

- `RED-Y-FIREWALL.md:350-351`: el filtro fail2ban todavía cuenta `AUTH_FAILED` y `TLS handshake failed`. El real (`filter.d/ids-vpn.conf:15`) solo cuenta `ovpn-auth: rechazado`, como fija `CONTRATO-F1a.md:77`. Lo mismo en `FASES-Y-CANARIO.md:167` («5 `AUTH_FAILED`»).
- `INSTANCIA.md:243`: `proto tcp-server`; el código usa `tcp4-server` (`server.conf.tmpl:3`).
- `INSTANCIA.md:248`: dice «v6: data-ciphers AES-256-CBC»; el código pone `AES-256-GCM:AES-256-CBC` en todas las versiones y solo cambia el fallback (`server.conf.tmpl:16-17`).
- `INSTANCIA.md:282`: dice `usuarios (ro, 0640)`; el código usa 0600 (`ids_orq.py:2669`, `CONTRATO-F1a.md:68`).
- `ORQUESTADOR.md:211` y `OPERACION.md:44-48` dicen que el TOFU se fija «al confirmar»; el código lo hace solo (VPN-06).

### VPN-15 — BAJA (sin confirmar) — Retención y ritmo de los logs

**Evidencia:** los contenedores escriben en journald (`compose.yml.tmpl`, `logging: journald`). En `host/` no hay ningún `journald.conf.d`. Todos los puntos llegan a journald a través de `docker.service`, así que comparten el límite de ritmo por unidad (`RateLimitBurst`).

**Impacto:** con una avalancha de logs de OpenVPN (`verb 3`), journald puede descartar líneas de todos los puntos, también las `ovpn-auth: rechazado` que alimentan fail2ban. Además, el tamaño queda en el valor por defecto de journald (10 % del disco, máximo 4 GB). No se ha comprobado en un VPS.

**Parche:** añadir `host/journald/90-ids.conf` con `SystemMaxUse=` explícito y `RateLimitIntervalSec=30s` / `RateLimitBurst=` acorde, y valorar `verb 2` en producción.

### VPN-16 — INFO — Restricciones de RouterOS (no son hallazgos)

- `auth SHA1` con AES-256-CBC en v6: HMAC-SHA1 sigue siendo seguro como MAC, y 6.49 no ofrece nada mejor de forma fiable. En v7 con GCM, `auth` no se usa en el canal de datos.
- Mejora opcional para puntos declarados v7: `data-ciphers AES-256-GCM` sin CBC. Rompería un router v7 configurado con el bloque v6, cosa que el script ya advierte.
- `tls-cipher "DEFAULT:@SECLEVEL=0"` y `tls-cert-profile legacy` solo se activan por punto (`ids_orq.py:593-600`), y solo si el canario de 6.49 lo necesita (`INSTANCIA.md:274-278`). Está bien acotado.
- Sin `tls-crypt`/`tls-auth`: RouterOS no los soporta.

---

## 4. Lo que está bien hecho

**OpenVPN**

- Solo TCP (`tcp4-server`), `tls-version-min 1.2`, RSA 2048 con SHA-256 y `ffdhe2048`.
- AES-256-GCM en v7, con el fallback ajustado a la versión declarada.
- Sin compresión, sin `push` de rutas, sin `iroute` y sin `client-to-client`.
- Sin `duplicate-cn`: una sesión nueva del mismo usuario echa a la vieja.
- `topology subnet` y `ccd-exclusive`, con `ifconfig-push` fijo a `.2`.
- `keepalive 10 60`, `persist-key`/`persist-tun`.
- `management` por socket UNIX en un directorio 0700 del host; `status` cada 10 s.

**Autenticación**

- `verify-client-cert none` con usuario aleatorio y clave de 24 caracteres alfanuméricos (≈ 143 bits), hash scrypt (`ids_orq.py:526-538`).
- `ovpn-auth`:
  - valida el formato antes de nada y nunca escribe en el log texto que venga del atacante;
  - aplica el freno antes de scrypt;
  - compara con `hmac.compare_digest`;
  - acota los parámetros de scrypt leídos del fichero.
- `username-as-common-name` con un usuario que ya ha pasado la regex: no hay recorrido de rutas en `ccd`.

**Entrega de secretos**

- No hay clave privada de cliente: nada privado pasa por el panel ni por el navegador, salvo la clave VPN.
- La clave VPN:
  - se guarda solo en memoria del orquestador (`_secretos`) y se entrega **una vez**: el primer `op.estado` la saca de memoria (`ids_orq.py:1979,2104-2106`);
  - se muestra con `Cache-Control: no-store`, `X-Frame-Options: DENY` y CSP `frame-ancestors 'none'` (`puntos_web.py:958-981`);
  - no se escribe en el registro (`_bit`, «Nunca claves»).
- `_salud_o_error` filtra las líneas con `password|key` (`ids_orq.py:2832`).

**PKI**

- La CA no se monta nunca en un contenedor.
- El certificado de servidor es propio de cada punto, con serial aleatorio y EKU serverAuth; la clave tiene modo 0600.
- El pid no se reutiliza nunca y el usuario es aleatorio en cada alta.

**Aislamiento en el netns**

- `ip_forward=0` y cadena `forward` con política drop.
- En `input`, solo el 1194 por `eth0` y el TZSP de `TUN_MK` por `tun0`. En `output`, solo la API hacia `TUN_MK`.
- `netdev ids_mon` descarta lo inyectado antes de la pila IP.
- `tzsp-decap` vuelve a filtrar el origen (`TZSP_ALLOW`).
- El firewall se carga **antes** de crear la interfaz `tun0` y de arrancar los servicios.

**Host**

- Tabla nft propia y nunca `flush ruleset`.
- Descarta cualquier puerto publicado que no esté previsto (`ids_host.nft.tmpl:26`) y deja el panel solo para los proxies.
- `origen_ip` opcional por punto y freno de conexiones nuevas.
- `userland-proxy: false`, así que fail2ban y el freno ven la IP real. fail2ban banea en `forward`, antes que Docker.

**Contenedores**

- `read_only`, `cap_drop: ALL`, `no-new-privileges`, `pids_limit`, memoria limitada y tmpfs acotados.
- El orquestador lee los ficheros que escribe el contenedor con `O_NOFOLLOW` y comprobando el inodo, y solo conecta a sockets después de `lstat` + `S_ISSOCK` (A-04).

**Robustez**

- Un cambio de IP pública del router no rompe nada (salvo con `origen_ip`).
- `depends_on … restart: true` y comprobación de que los dos contenedores comparten netns, con reinicio de Suricata si no.
- Reinicios con espera creciente y paso a `error` tras 3 en una hora.
- Avisos funcionales `SIN-ESPEJO`/`ESPEJO-NO-LLEGA`.
- La ruta `blackhole` del túnel en el router evita fugas cuando el túnel cae.

**Coherencia panel ↔ servidor**

- El panel no genera su propio script: muestra el de `comandos_mikrotik()`, la misma función que usa la CLI (`punto.comandos`).
- Por eso puerto, usuario, red, sensor y cifrado (`aes256-gcm` en v7 y `aes256` CBC en v6, frente a `data-ciphers-fallback`) salen siempre de la misma fuente.
- El usuario `ids-api` del router está limitado a `address=<sensor>/32`.

## 5. Orden de aplicación sugerido

1. **VPN-02** (3 líneas en el script del MikroTik) y **VPN-01** (CA y `verify-server-certificate` en el script, con la prueba de 6.49 en el canario) → regenerar `tests/test_orq_comandos.py`.
2. **VPN-06** (TOFU con confirmación) y **VPN-04** (filtro fail2ban y orden de desbaneo).
3. **VPN-03**: primero la prueba de laboratorio; después `max-clients`/`hand-window` y `ct count` en el nft del host.
4. **VPN-05** dentro del canario pendiente.
5. Los BAJA, junto con la corrección de la documentación (VPN-14).

Para los routers ya desplegados, VPN-01 y VPN-02 se aplican pegando solo las líneas nuevas: no hace falta rehacer la VPN.

---

## 6. Estado tras la corrección (2026-10-14/15)

Commits en `main`: `1aa307e` (servidor) y `950fca3` (panel). VPN-07 ya lo había resuelto el
apartado A de Puntos (`580b27f`). Todo lleva pruebas de comportamiento en `tests/`; el CI con
Docker real (job `imagenes`, e2e con cliente OpenVPN) pasa con VPN-01 y VPN-05 aplicados.

| ID | Estado | Qué se hizo |
|---|---|---|
| VPN-01 | **Corregido** (confirmar 6.49 en el canario) | El script lleva la CA del VPS (PEM público validado: sin `PRIVATE`, ≤ 4000 bytes, solo base64) con `/file print` + `/file set contents=` + `/certificate import` + `trusted=yes`, y `verify-server-certificate=yes` en v6 y v7. El certificado del servidor pasa a `CN=<nombre del VPS>` con `subjectAltName` (DNS o IP), porque RouterOS v7 compara CN/SAN con `connect-to`. Los puntos viejos lo renuevan al «Regenerar la clave VPN»; mientras tanto su script lleva un `# AVISO:`. |
| VPN-02 | **Corregido** | El script añade `drop` en `input` y `forward` para `ids-vpn`, con el `accept` de la API por encima (`place-before=0`, comentario `IDS ids-maat:<pid>`). Lo único que el sensor manda por el túnel es la API (relé). |
| VPN-03 | **Mitigado** (confirmar con `nc` en el laboratorio) | `max-clients 16` y `hand-window 20`. No se añadió `ct count` en el nft (necesita `nft_connlimit` en el netns; sin validar). |
| VPN-04 | **Corregido** | fail2ban `ids-vpn` solo cuenta `motivo=formato\|usuario`; orden inmediata `vpn.desbanear` e `ids-orq vpn desbanear <ip>`; botón «Desbanear IP del MikroTik» en la ficha (solo admin). |
| VPN-05 | **Corregido** | Suricata con `cap_add: [NET_RAW]` (sin `NET_ADMIN`); la e2e del CI sigue recibiendo la alerta. Falta ver `capture.kernel_packets` en el canario. |
| VPN-06 | **Corregido** | Sin huella guardada, el panel lee la huella por TLS y **no** hace `/login`; la ficha la enseña con el comando del router y «La huella coincide: confirmar». Huella distinta = sin login y aviso rojo. Las huellas fijadas antes se respetan como «fijadas automáticamente». Con 8728, aviso en la ficha. |
| VPN-07 | **Corregido** (`580b27f`) | `salud-vpn` exige LISTEN en el puerto de `server.conf` y openvpn con más de 5 s arriba. |
| VPN-08 | **Corregido** | El freno global no frena a la última IP aceptada durante 24 h. |
| VPN-09 | Abierto (BAJA) | Autenticación diferida: solo documentado. |
| VPN-10 | Abierto (BAJA) | `meter vpn_new` sin timeout: parche propuesto en §3, sin aplicar. |
| VPN-11 | Abierto (BAJA) | Sin CRL; con VPN-01 aplicado, valorar certificados de servidor más cortos. |
| VPN-12 | Abierto (BAJA) | Que la baja desactive el `ovpn-client` por la API. La baja ya explica cómo quitar la CA y las reglas. |
| VPN-13 | **Corregido** | `leer_status_openvpn` toma la sesión más reciente y solo usuarios del IDS. |
| VPN-14 | **Corregido** | Documentación al día (RED-Y-FIREWALL, INSTANCIA, ORQUESTADOR, OPERACION, CONTRATO-F1a, FASES-Y-CANARIO). |
| VPN-15 | **Corregido** | `host/journald/90-ids.conf` (`RateLimitBurst=50000` cada 30 s, `SystemMaxUse=2G`), instalado por `install.sh`. |
| VPN-16 | Info | Sin cambios. |

**Pendiente de confirmar en el canario (RouterOS 6.49 y v7 reales):** pegar el bloque de la CA en
la terminal (una línea de ~1,3 KB), el nombre que queda tras importar, que 6.49 acepte
`verify-server-certificate` con el certificado nuevo, que el `fingerprint` de
`/certificate print detail` coincida en formato con la huella del panel, y la prueba de conexiones
TCP colgadas.
