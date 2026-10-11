# Operación

Anexo de [ARQUITECTURA.md](ARQUITECTURA.md). Este anexo reúne lo que se ejecuta a mano:

- los comandos del MikroTik (v7 y v6);
- los respaldos y la recuperación;
- el acceso de emergencia;
- el mantenimiento.

En F5 se completa y se prueba al pie de la letra.

Ejemplo: punto `p003`, N=3, puerto 1196, túnel `100.64.3.0/24`, nombre del VPS
`ids.empresa.example`. El panel genera estos comandos con los valores reales de cada punto; aquí
solo se muestran como referencia.

## 1. Preparar el MikroTik

Versiones soportadas: **RouterOS 6.49 o superior** en v6, y v7. Anteriores a 6.49, no.

### 1.1 Certificado de la API-SSL: `ids-promax` (6.49 y v7)

Es el formato del dueño y vale igual en 6.49 y en v7:

```
/certificate
add name=ids-promax common-name=ids-promax \
    key-usage=key-cert-sign,crl-sign,digital-signature,tls-server,tls-client,data-encipherment,key-encipherment \
    days-valid=4576 trusted=yes
/certificate sign ids-promax
/certificate set ids-promax trusted=yes
/ip service set api-ssl certificate=ids-promax
```

- **Si `ids-promax` ya existe en el router, se reutiliza.** No se vuelve a crear y basta con la
  última línea.
- **Sin `ca-crl-host`:** no se usa CRL.
- **`sign` tarda unos segundos, sobre todo en v6.** Antes del `set`, hay que esperar a que
  `/certificate print` lo muestre con los flags **K** (tiene clave privada) y **T** (de confianza).
- Si el servicio está deshabilitado: `/ip service enable api-ssl`.
- **Huella fijada (TOFU).** En la primera conexión del alta, el panel muestra la huella SHA-256
  del certificado. Se compara con la que da `/certificate print detail where name=ids-promax` y, al
  confirmar, queda fijada. Desde entonces el panel rechaza cualquier otro certificado. Si se
  regenera `ids-promax`, hay que volver a fijar la huella desde la ficha del punto (admin, queda en
  la bitácora).
- **En una baja no se borra:** el certificado puede usarlo otro servicio del router.

### 1.2 RouterOS v7

```
/interface ovpn-client add name=ids-vpn connect-to=ids.empresa.example port=1196 protocol=tcp mode=ip \
    user=vpn3a9f2c password=<CLAVE-VPN> cipher=aes256-gcm auth=sha1 \
    add-default-route=no use-peer-dns=no disabled=no
/ip route add dst-address=100.64.3.0/24 blackhole distance=250 comment="IDS ids-maat:p003"
/user group add name=ids-api policy=read,write,api
/user add name=ids-api group=ids-api address=100.64.3.1/32 password=<CLAVE-API>
/ip firewall filter add chain=input in-interface=ids-vpn src-address=100.64.3.1 protocol=tcp \
    dst-port=8729 action=accept place-before=0 comment="IDS ids-maat:p003"
```

- Si el servidor del punto no tiene GCM habilitado, se usa `cipher=aes256-cbc`.
- **Recomendado en v7:** importar la CA de la empresa y verificar el servidor:

  ```
  /certificate import file-name=ids-ca.crt
  /interface ovpn-client set ids-vpn verify-server-certificate=yes
  ```

### 1.3 RouterOS v6 (6.49 o superior)

```
/interface ovpn-client add name=ids-vpn connect-to=ids.empresa.example port=1196 mode=ip \
    user=vpn3a9f2c password=<CLAVE-VPN> cipher=aes256 auth=sha1 \
    add-default-route=no disabled=no
/ip route add dst-address=100.64.3.0/24 type=blackhole distance=250 comment="IDS ids-maat:p003"
/user group add name=ids-api policy=read,write,api
/user add name=ids-api group=ids-api address=100.64.3.1/32 password=<CLAVE-API>
/ip firewall filter add chain=input in-interface=ids-vpn src-address=100.64.3.1 protocol=tcp \
    dst-port=8729 action=accept place-before=0 comment="IDS ids-maat:p003"
```

v6 solo admite TCP, así que no lleva `protocol=`, y no tiene `use-peer-dns`. Si el handshake TLS
falla en 6.49, se activa la «compatibilidad v6» del punto desde su ficha
([INSTANCIA.md](INSTANCIA.md) §7.2).

En los dos bloques, el certificado de la API-SSL es el de §1.1.

### 1.4 Notas

- **La lista de `/ip service api-ssl address=` no se toca.** Si ya tiene direcciones y no incluye
  `100.64.3.1`, el paso API del asistente lo detecta y muestra el comando para **añadirla**
  conservando las demás. Lo aplica el operador.
- **Si la cadena `input` está vacía**, `place-before=0` falla: hay que quitar ese parámetro.
- **El blackhole va siempre como /24** ([RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) §3.1).
- **Puerto 8728 en claro.** Solo como excepción por punto, con aviso permanente. Hay que cambiar
  `dst-port` y el servicio `api` en consecuencia.

## 2. Espejo

Lo aplica el panel desde la ficha del punto, siempre después de la vista previa y del respaldo
(`/export` en el router y copia JSON en el panel). Requisito que manda sobre todo lo demás:

> **Instalar, actualizar, pausar o retirar el espejo no autoriza tráfico que la política original del
> router rechazaba.** Por eso el espejo **nunca añade reglas `accept`**: en RouterOS un `accept` termina
> la cadena y los paquetes se saltarían los `drop` que vienen detrás (incluidos los de cuarentena).

Es equivalente a:

```
/ip firewall address-list add list=ids-vigilados address=10.0.0.0/24 comment="IDS ids-maat:p003"
/ip firewall mangle add chain=forward src-address-list=ids-vigilados connection-bytes=0-10000     action=sniff-tzsp sniff-target=100.64.3.1 sniff-target-port=37008 comment="IDS ids-maat:p003"
/ip firewall mangle add chain=forward dst-address-list=ids-vigilados connection-bytes=0-10000     action=sniff-tzsp sniff-target=100.64.3.1 sniff-target-port=37008 comment="IDS ids-maat:p003"
```

**FastTrack.** Los paquetes acelerados no pasan por mangle, así que sin tocar el fasttrack el espejo solo
vería el primer paquete de cada conexión. Solo se cambian **condiciones de reglas `fasttrack-connection`**,
que deciden qué conexiones se aceleran y nunca qué tráfico pasa:

```
# 1) la regla fasttrack existente (<id-ft>) deja fuera a los vigilados (se respalda su valor original)
/ip firewall filter set <id-ft> src-address-list=!ids-vigilados dst-address-list=!ids-vigilados
# 2) los vigilados se aceleran a partir de los 10 KB, con las MISMAS condiciones que <id-ft>
#    (connection-state, hw-offload, interfaces...), justo detrás de ella
/ip firewall filter add chain=forward action=fasttrack-connection <condiciones de id-ft>     src-address-list=ids-vigilados connection-bytes=10000-0 place-before=<siguiente a id-ft>     comment="IDS ids-maat:p003"
/ip firewall filter add chain=forward action=fasttrack-connection <condiciones de id-ft>     dst-address-list=ids-vigilados connection-bytes=10000-0 place-before=<siguiente a id-ft>     comment="IDS ids-maat:p003"
```

- Por qué no amplía nada: un paquete que no se acelera sigue recorriendo el filtro entero, así que con
  el espejo se evalúan **las mismas reglas o más** que antes, nunca menos. El veredicto de cada paquete
  lo siguen dando las reglas del operador.
- Si la regla fasttrack ya usa `src-address-list` o `dst-address-list`, el panel **no la modifica**: lo
  muestra en la vista previa y pide resolverlo a mano. Si hay varias reglas fasttrack, se tratan todas
  igual. Sin regla fasttrack, solo van la address-list y los dos mangle.
- No hay regla de DNS aparte. IPv6 queda fuera de esta versión: no se toca el fasttrack de `/ipv6`.
- **Idempotente**: aplicar dos veces no duplica nada (se busca por comentario y por las condiciones).
- **Pausa**: deshabilita los dos mangle (`disabled=yes`, por comentario). El fasttrack queda como está.
- **Retirada**: borra lo que lleva el comentario del punto y devuelve a `<id-ft>` sus valores originales de
  `src-address-list`/`dst-address-list` (del respaldo). Nunca borra reglas sin el comentario del punto.
- **Prueba de aceptación** (laboratorio, con un MikroTik real de cada versión): mismo resultado antes y
  después en tráfico permitido, bloqueado y en cuarentena; espejo en las dos direcciones; aceleración
  pasados los 10 KB; aplicar dos veces sin duplicar; retirar sin tocar reglas ajenas.

### 2.1 Quitar todo lo del IDS de un router

Sirve para una baja sin API, o para terminar una baja con API (`ovpn-client` y usuario). El
certificado `ids-promax` no se borra.

```
/ip firewall mangle remove [find comment~"ids-maat:p003"]
/ip firewall filter remove [find comment~"ids-maat:p003"]
# y devolver a la regla fasttrack sus valores originales (los da el respaldo del panel), p. ej.:
/ip firewall filter set <id-ft> !src-address-list !dst-address-list
/ip firewall address-list remove [find comment~"ids-maat:p003"]
/ip route remove [find comment~"ids-maat:p003"]
/interface ovpn-client remove [find name=ids-vpn]
/user remove [find name=ids-api]
/user group remove [find name=ids-api]
```

## 3. Respaldos y recuperación

### 3.1 Qué se respalda y cuándo

| Respaldo | Cuándo | Contenido | Dónde |
|---|---|---|---|
| Diario | timer del orquestador | `estado.db`, `bitacora.db`, `orq.db` (con `setpriv`), PKI, `/srv/ids/puntos` | `/root/backups/ids-maat-diario-<fecha>.tar.gz`, 0600, 14 días |
| Antes de actualizar | `sistema.actualizar` | lo mismo, más el firewall | `/root/backups/ids-maat-<ts>.tar.gz` |
| Antes de cambiar el acceso | `acceso.aplicar` | `/srv/ids/fw/` | `/root/backups/` |
| Firewall del router | antes de aplicar o quitar el espejo | `/export` de `ip firewall`, `ip route` e `interface ovpn-client` | `/srv/ids/panel/respaldos/<pid>/` |
| `eventos.db` | opcional | alertas y agregados | aparte, porque es grande y se puede reconstruir |

**La clave maestra (`/etc/ids-maat/master.key`) nunca va dentro de esos tar.** Se guarda aparte en
el gestor de secretos del dueño. Sin ella, las claves API cifradas no sirven. Con ella y el
respaldo, sí.

### 3.2 Copia fuera del VPS

La copia la **descarga** una máquina de las redes de gestión, por SSH con una clave restringida
(`command=` y `from=`). No es el VPS quien la sube: así el VPS no guarda credenciales de otro
sistema.

```sh
# en la máquina de respaldo (cron diario)
rsync -a --chmod=F600 root@ids.empresa.example:/root/backups/ids-maat-diario-*.tar.gz /respaldos/empresa/
```

### 3.3 Recuperar en un VPS nuevo

1. Instalar Debian 13 y ejecutar `instalar.sh` **con la misma versión** que figura en el respaldo
   (`release.json`).
2. Copiar `master.key` a `/etc/ids-maat/master.key` (0400).
3. Restaurar el tar en `/srv/ids` y comprobar el sha256.
4. Ejecutar `ids-orq reconstruir`: recrea las instancias desde `orq.db` y `/srv/ids/puntos`, con
   los mismos puertos y las mismas credenciales VPN, porque la PKI y los usuarios están en el
   respaldo.
5. Apuntar `ids.empresa.example` a la IP nueva. Los MikroTik reconectan solos, sin tocarlos.
6. Comprobar en Puntos que cada punto vuelve a `activo` con espejo.

## 4. Acceso de emergencia

- **Si el proxy inverso está caído o mal configurado:** se entra al panel por un túnel SSH desde
  una red de gestión, sin pasar por el proxy:

  ```sh
  ssh -L 5637:10.210.255.2:5637 root@ids.empresa.example
  # y en el navegador del equipo de gestión: http://localhost:5637
  ```

  - `10.210.255.2` es la IP fija de `panel-web` en la red `ids-core`.
  - La conexión llega al panel desde la puerta de enlace de esa red, no desde un proxy, así que el
    panel ignora cualquier cabecera `X-Forwarded-*`.
  - Los navegadores tratan `localhost` como contexto seguro, y la cookie `__Host-` funciona.
- **Si las redes de gestión dejan fuera al dueño** (y, con ellas, el SSH):
  1. Entrar por la consola del proveedor del VPS.
  2. Ejecutar `/root/ids-maat/acceso-emergencia.sh` (restaura el ruleset anterior) o
     `/root/ids-maat/acceso-emergencia.sh 203.0.113.20` (abre esa IP para SSH). Con
     `--proxy 203.0.113.50` abre el panel a esa IP de proxy.
  3. Revisar `/root/backups/` y la bitácora.
- **Una red más ancha que /16 solo se puede abrir así**, desde la consola.

### 4.1 Primer acceso al panel y clave olvidada

- Al terminar, `install.sh` imprime la URL (`http://<nombre>:5637`), el usuario `admin` y su clave
  **una sola vez**. La clave no se guarda en claro: en `/root/ids-maat/install-<ts>.log` sale como
  `********`. Una reinstalación no la cambia.
- El 5637 solo se abre desde las IP de `--proxy`. Para entrar directo durante las pruebas, se
  ponen en `--proxy` las redes de gestión (≤ /28 cada una); si no, el túnel SSH de arriba.
- Clave olvidada o perdida, desde SSH como root:

  ```sh
  ids-orq panel restablecer admin      # imprime CLAVE=<nueva>; la anterior deja de valer
  ```

  Ejecuta `ids-panel restablecer --usuario admin` en un contenedor de un solo uso con la imagen
  del panel (sin red, sin logs, solo `/srv/ids/panel` montado). Si todavía no hay ningún usuario:
  `ids-orq panel crear-admin --usuario admin`.
- El panel es el contenedor `ids-core-panel` del proyecto `ids-core`
  (`/srv/ids/core/compose.yml`). `ids-orq panel aplicar` lo vuelve a generar y levantar;
  `docker logs ids-core-panel` (o `journalctl CONTAINER_TAG=ids-panel`) muestra su registro.

## 5. Mantenimiento

| Tarea | Cómo |
|---|---|
| Ver las jaulas de fail2ban | `fail2ban-client status sshd` y `fail2ban-client status ids-vpn` |
| Desbanear una IP | `fail2ban-client set ids-vpn unbanip 203.0.113.45` (OpenVPN) o `fail2ban-client set sshd unbanip 203.0.113.45` (SSH); ver abajo |
| Estado de los puntos | `ids-orq punto estado '*'` o `cat /srv/ids/run/estado.json` |
| Rotar la clave maestra | orden de mantenimiento en Ajustes; antes, guardar la clave nueva fuera del VPS |
| Cambiar la IP del VPS | restaurar o mover y cambiar el registro DNS `ids.empresa.example`; los MikroTik no se tocan |
| Actualizar el orquestador | `/root/ids-maat/actualizar-orquestador.sh <version>` |

**Cuándo banea `ids-vpn` y cómo desbanear.** La jaula cuenta solo las líneas
`<ip>:<puerto> ovpn-auth: rechazado …`, una por intento fallido (clave mala, usuario desconocido,
formato, freno o freno global). La línea `TLS Auth Error` que OpenVPN escribe por el mismo intento
no cuenta. Con `maxretry = 5` y `findtime = 10m`, una IP queda baneada al 5.º intento fallido en
10 minutos, durante 1 h la primera vez y más en las siguientes (`bantime.increment`, hasta 1 semana).
El ban se aplica en el hook `forward`, así que corta todos los puertos de esa IP hacia los
contenedores.

Si un MikroTik legítimo queda baneado (por ejemplo, tras regenerar la credencial sin actualizarla en el
router):

1. Ver qué IP está baneada: `fail2ban-client status ids-vpn`.
2. Corregir la credencial en el MikroTik. Si no, vuelve a banearse.
3. Desbanear: `fail2ban-client set ids-vpn unbanip <ip>`.
4. Si la IP es fija y del dueño, puede ir en `--dueno-ip` (es el `ignoreip` de fail2ban). Las redes
   de gestión nunca van en `ignoreip`.
