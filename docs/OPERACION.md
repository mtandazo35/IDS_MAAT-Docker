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
- **Huella confirmada (VPN-06).** Mientras la huella no esté confirmada, el panel no manda la clave
  de `ids-api`: conecta, lee la huella SHA-256 del certificado y corta. La ficha del punto (API) la
  enseña en bloques; se compara con el `fingerprint` de `/certificate print detail where
  name~"ids-promax"` y se pulsa «La huella coincide: confirmar» (el panel la vuelve a leer y solo la
  guarda si sigue siendo esa; queda en la bitácora quién la confirmó). Desde entonces el panel
  rechaza cualquier otro certificado sin mandar la clave, con aviso rojo en la ficha y una línea en el
  Registro. Si se regenera `ids-promax`, «Volver a confirmar» en la ficha (admin). Las huellas que
  una versión anterior del panel fijó solas se siguen usando y la ficha las marca «fijada
  automáticamente» para revisarlas.
- **En una baja no se borra:** el certificado puede usarlo otro servicio del router.

### 1.2 RouterOS v7

```
# CA del VPS (pública): con ella el MikroTik verifica al servidor (verify-server-certificate)
/file print file=ids-maat-ca-p003
:delay 2s
/file set [find name="ids-maat-ca-p003.txt"] contents="-----BEGIN CERTIFICATE-----\nMIID…\n-----END CERTIFICATE-----\n"
/certificate import file-name=ids-maat-ca-p003.txt passphrase=""
/certificate set [find name~"^ids-maat-ca-p003"] trusted=yes
/file remove [find name="ids-maat-ca-p003.txt"]
/interface ovpn-client add name=ids-vpn connect-to=ids.empresa.example port=1196 protocol=tcp mode=ip \
    user=vpn3a9f2c password=<CLAVE-VPN> cipher=aes256-gcm auth=sha1 verify-server-certificate=yes \
    add-default-route=no use-peer-dns=no disabled=no
/ip route add dst-address=100.64.3.0/24 blackhole distance=250 comment="IDS ids-maat:p003"
/user group add name=ids-api policy=read,write,api
/user add name=ids-api group=ids-api address=100.64.3.1/32 password=<CLAVE-API>
# ids-vpn aislada: por ella solo entra la API desde el sensor (el orden de estas cinco da igual).
# Router configurado antes: quita primero las reglas viejas del alta con
#   /ip firewall filter remove [find comment="IDS ids-maat:p003"]
/ip firewall filter add chain=input in-interface=ids-vpn src-address=!100.64.3.1 action=drop \
    comment="IDS ids-maat:p003"
/ip firewall filter add chain=input in-interface=ids-vpn protocol=!tcp action=drop \
    comment="IDS ids-maat:p003"
/ip firewall filter add chain=input in-interface=ids-vpn protocol=tcp dst-port=!8729 action=drop \
    comment="IDS ids-maat:p003"
/ip firewall filter add chain=input in-interface=ids-vpn src-address=100.64.3.1 protocol=tcp \
    dst-port=8729 action=accept comment="IDS ids-maat:p003"
/ip firewall filter add chain=forward in-interface=ids-vpn action=drop \
    comment="IDS ids-maat:p003"
# arriba del todo (con la lista vacía no hay nada que mover y no pasa nada):
:do {/ip firewall filter move [/ip firewall filter find comment="IDS ids-maat:p003"] destination=[:pick [/ip firewall filter find dynamic=no] 0]} on-error={}
```

- Si el servidor del punto no tiene GCM habilitado, se usa `cipher=aes256-cbc`.
- El contenido de `/file set` es el `ca.crt` del VPS (`/srv/ids/pki/ca.crt`) con cada salto de línea
  escrito como `\n`. El panel y `ids-orq punto ovpn-client <pid>` lo dan ya puesto.

### 1.3 RouterOS v6 (6.49 o superior)

```
# (las mismas 7 líneas de la CA del VPS que en v7)
/interface ovpn-client add name=ids-vpn connect-to=ids.empresa.example port=1196 mode=ip \
    user=vpn3a9f2c password=<CLAVE-VPN> cipher=aes256 auth=sha1 verify-server-certificate=yes \
    add-default-route=no disabled=no
/ip route add dst-address=100.64.3.0/24 type=blackhole distance=250 comment="IDS ids-maat:p003"
/user group add name=ids-api policy=read,write,api
/user add name=ids-api group=ids-api address=100.64.3.1/32 password=<CLAVE-API>
# (las mismas 5 reglas de /ip firewall filter y el move que en v7)
```

v6 solo admite TCP, así que no lleva `protocol=`, y no tiene `use-peer-dns`. Si el handshake TLS
falla en 6.49, se activa la «compatibilidad v6» del punto desde su ficha
([INSTANCIA.md](INSTANCIA.md) §7.2).

En los dos bloques, el certificado de la API-SSL es el de §1.1.

### 1.4 El MikroTik verifica al servidor

El script lleva la CA del VPS y `verify-server-certificate=yes` en los dos bloques, sin paso manual.
Sin eso, quien suplantara `ids.empresa.example` (DNS envenenado o alguien en el camino) se quedaría
con la clave VPN y haría de «sensor» para el router.

- **Qué comprueba RouterOS:** que la cadena llega a una CA de confianza del router (la que importa el
  script) y que el `connect-to` está en el CN o en el SAN del certificado del servidor
  ([help.mikrotik.com, OpenVPN](https://help.mikrotik.com/docs/spaces/ROS/pages/2031655/OpenVPN)).
  El certificado de cada punto lleva `CN=<NOMBRE_DNS>` y `subjectAltName=DNS:<NOMBRE_DNS>` (o `IP:` si
  el nombre es una IP) e EKU `serverAuth`.
- **La CA es una por VPS y es pública.** Nunca va una clave privada en el script. El certificado
  importado se llama `ids-maat-ca-<pid>.txt_0` (6.49 no admite `name=` en `/certificate import`) y se
  quita en la baja por ese prefijo (§2.1).
- **Puntos dados de alta antes de este cambio:** su certificado de servidor solo lleva
  `CN=server-<pid>` y el MikroTik lo rechazaría con la verificación. El script lo avisa en la
  cabecera (`# AVISO: …`). El orden es:
  1. «Regenerar la clave VPN» en la ficha del punto (o `ids-orq punto vpn-regenerar <pid>`): renueva
     el certificado del servidor y reinicia OpenVPN.
  2. Pegar en el router las 7 líneas de la CA, poner la clave nueva y activar la verificación:
     `/interface ovpn-client set [find name=ids-vpn] password=<CLAVE-VPN> verify-server-certificate=yes`.
- **Por confirmar en el canario de 6.49:** que `/file print file=` + `/file set contents=` + `/certificate
  import` funcionan pegados en la terminal (la línea de la CA mide ~1,3 KB) y que 6.49 acepta el
  certificado con la verificación activa. `verify-server-certificate` ya existe en 6.45 y en v7.

### 1.5 Notas

- **La lista de `/ip service api-ssl address=` no se toca.** Si ya tiene direcciones y no incluye
  `100.64.3.1`, el paso API del asistente lo detecta y muestra el comando para **añadirla**
  conservando las demás. Lo aplica el operador.
- **`ids-vpn` queda aislada en el router.** Por el túnel solo entra la API desde el sensor
  (`100.64.3.1` → `8729`); el resto de `input` y todo `forward` desde `ids-vpn` se descartan. Así, un
  sensor comprometido (o un impostor) no llega ni a Winbox/SSH del core ni a las redes del ISP. El
  espejo no se ve afectado: `sniff-tzsp` lo genera el propio router (sale por `output`), y el sensor
  no envía nada más al router (su netns solo deja salir la API, [RED-Y-FIREWALL.md](RED-Y-FIREWALL.md)
  §8).
- **El orden entre las cinco da igual.** Los `drop` de `input` van negados (lo que no viene del
  sensor, lo que no es TCP, lo que no va al puerto de la API), así que ninguno tapa al `accept`. No se
  usa `place-before=0`: en RouterOS los números son los del último `print` de la sesión, y en un
  script pegado tres `place-before=0` seguidos dejaban el `accept` debajo del `drop` de `input` (el
  panel se quedaba sin API). La última línea sube las cinco, por su comentario, por encima de la
  primera regla no dinámica (la dinámica del fasttrack se salta); con la lista vacía no hay nada que
  mover y el `on-error` lo deja pasar.
- **Routers ya desplegados** (con las tres reglas de antes): quitar las del alta con
  `/ip firewall filter remove [find comment="IDS ids-maat:p003"]` y pegar las cinco y el `move`.
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
/ip firewall address-list add list=ids-vigilados address=10.0.0.0/24 comment="IDS ids-maat:p003:espejo"
/ip firewall mangle add chain=forward src-address-list=ids-vigilados connection-bytes=0-10000     action=sniff-tzsp sniff-target=100.64.3.1 sniff-target-port=37008 comment="IDS ids-maat:p003:espejo"
/ip firewall mangle add chain=forward dst-address-list=ids-vigilados connection-bytes=0-10000     action=sniff-tzsp sniff-target=100.64.3.1 sniff-target-port=37008 comment="IDS ids-maat:p003:espejo"
```

**Comentario propio del espejo: `IDS ids-maat:<pid>:espejo`.** Lo del alta (§1.2/§1.3: la regla
`chain=input` que acepta la API-SSL desde el sensor, los dos `drop` que aíslan `ids-vpn` y el
blackhole del túnel) lleva
`IDS ids-maat:<pid>` y **el espejo no lo toca nunca**: ni al aplicar, ni al pausar, ni al retirar.
Sin esa regla, en un router con la cadena `input` en `drop`, el panel se quedaría sin API en ese
punto. Un espejo montado por una versión anterior (con el comentario del alta) se reconoce solo
por su forma (mangle `sniff-tzsp`; filter `chain=forward` que usa `ids-vigilados`; entradas de
`ids-vigilados`) y al volver a aplicar pasa al comentario propio.

**FastTrack.** Los paquetes acelerados no pasan por mangle, así que sin tocar el fasttrack el espejo solo
vería el primer paquete de cada conexión. Solo se cambian **condiciones de reglas `fasttrack-connection`**,
que deciden qué conexiones se aceleran y nunca qué tráfico pasa:

```
# 1) la regla fasttrack existente (<id-ft>) deja fuera a los vigilados (se respalda su valor original)
/ip firewall filter set <id-ft> src-address-list=!ids-vigilados dst-address-list=!ids-vigilados
# 2) los vigilados se aceleran a partir de los 10 KB, con las MISMAS condiciones que <id-ft>
#    (connection-state, hw-offload, interfaces...), justo detrás de ella
/ip firewall filter add chain=forward action=fasttrack-connection <condiciones de id-ft>     src-address-list=ids-vigilados connection-bytes=10000-0 place-before=<siguiente a id-ft>     comment="IDS ids-maat:p003:espejo"
/ip firewall filter add chain=forward action=fasttrack-connection <condiciones de id-ft>     dst-address-list=ids-vigilados connection-bytes=10000-0 place-before=<siguiente a id-ft>     comment="IDS ids-maat:p003:espejo"
```

- Por qué no amplía nada: un paquete que no se acelera sigue recorriendo el filtro entero, así que con
  el espejo se evalúan **las mismas reglas o más** que antes, nunca menos. El veredicto de cada paquete
  lo siguen dando las reglas del operador.
- Si la regla fasttrack ya usa `src-address-list` o `dst-address-list`, el panel **no la modifica**: lo
  muestra en la vista previa y pide resolverlo a mano. Si hay varias reglas fasttrack, se tratan todas
  igual. Sin regla fasttrack, solo van la address-list y los dos mangle.
- No hay regla de DNS aparte. IPv6 queda fuera de esta versión: no se toca el fasttrack de `/ipv6`.
- **Espejos viejos hacia el mismo sensor:** un mangle `sniff-tzsp` ajeno (sin el comentario del espejo)
  que ya apunta al sensor del punto se **apaga** (`disabled=yes`, no se borra) antes de crear los
  nuestros: dos espejos a la vez llenan el túnel y el TZSP (UDP) se pierde. Sale en la vista previa.
  **Retirar no lo vuelve a encender** (se apagó a propósito); si hace falta, se enciende a mano.
- **Respaldo local corrupto:** retirar usa el último JSON de respaldo del punto que se pueda leer;
  si ninguno vale, quita `!ids-vigilados` de las fasttrack que lo tengan en los dos campos.
- **Idempotente**: aplicar dos veces no duplica nada (se busca por comentario y por las condiciones).
- **Pausa**: deshabilita los dos mangle del espejo (`disabled=yes`, por comentario). El fasttrack queda como está.
- **Retirada**: borra lo que lleva el comentario del espejo y devuelve a `<id-ft>` sus valores originales de
  `src-address-list`/`dst-address-list` (del respaldo). Nunca borra reglas sin ese comentario, ni las del
  alta (`IDS ids-maat:<pid>`: API-SSL y blackhole), que solo se quitan en la baja (§2.1).
- **Prueba de aceptación** (laboratorio, con un MikroTik real de cada versión): mismo resultado antes y
  después en tráfico permitido, bloqueado y en cuarentena; espejo en las dos direcciones; aceleración
  pasados los 10 KB; aplicar dos veces sin duplicar; retirar sin tocar reglas ajenas.

### 2.1 Quitar todo lo del IDS de un router

Sirve para una baja sin API, o para terminar una baja con API (`ovpn-client` y usuario). El
certificado `ids-promax` no se borra.

La expresión `ids-maat:p003(:|\$)` casa lo del alta (`IDS ids-maat:p003`), lo del espejo
(`IDS ids-maat:p003:espejo`) y las cuarentenas `ids-maat:p003:<id>`, pero no `ids-maat:p0031` ni otro
punto (con `comment~"ids-maat:p003"` a secas se borrarían también las de `p0031`). El panel no usa
expresiones: borra solo lo que lleva exactamente su comentario.

```
/ip firewall mangle remove [find comment~"ids-maat:p003(:|\$)"]
/ip firewall filter remove [find comment~"ids-maat:p003(:|\$)"]
# y devolver a la regla fasttrack sus valores originales (los da el respaldo del panel), p. ej.:
/ip firewall filter set <id-ft> !src-address-list !dst-address-list
/ip firewall address-list remove [find comment~"ids-maat:p003(:|\$)"]
/ip route remove [find comment~"ids-maat:p003(:|\$)"]
/interface ovpn-client remove [find name=ids-vpn]
/user remove [find name=ids-api]
/user group remove [find name=ids-api]
# la CA del VPS que importó el alta (los certificados no llevan comentario: se buscan por nombre)
/certificate remove [find name~"^ids-maat-ca-p003"]
/file remove [find name~"^ids-maat-ca-p003"]
```

Las dos reglas `drop` de `ids-vpn` llevan el comentario del alta, así que la línea de `filter`
también las quita.

## 3. Respaldos y recuperación

### 3.1 Qué se respalda hoy y cuándo

**No hay respaldo diario automático.** La orden `sistema.respaldar` del orquestador está
**reservada y sin implementar** (contesta «no disponible») y no hay ningún timer de respaldo en
`host/systemd/`. Lo que existe de verdad:

| Respaldo | Cuándo | Contenido | Dónde |
|---|---|---|---|
| Instalación | cada `install.sh` (también al reinstalar), antes de tocar nada | `etc/ssh`, `etc/docker`, `etc/fail2ban`, `/srv/ids/fw`, `/etc/ids-maat` **sin `master.key`**, `/srv/ids/panel`, `/srv/ids/estado` (`orq.db`), `/srv/ids/pki`, `/srv/ids/puntos` | `/root/backups/ids-maat-install-<ts>.tar.gz`, 0600 |
| Laboratorio | cada `scripts/lab-actualizar.sh` (solo el VPS de laboratorio) | `/etc/ids-maat` **sin `master.key`**, el orquestador instalado y sus unidades, `/srv/ids/panel`, `estado`, `pki`, `puntos`, `fw` | `/root/backups/ids-maat-lab-<ts>.tar.gz`, 0600 |
| Firewall del host | cada vez que el orquestador regenera `ids_host.nft` | el `ids_host.nft` anterior | `/root/backups/ids-maat-fw-<ts>.nft` (los 20 últimos) |
| Firewall del router | antes de aplicar, pausar o retirar el espejo | `/export` en el router (fichero `ids-maat-<pid>-<ts>.rsc` del propio MikroTik) y copia JSON de las tablas | `/srv/ids/panel/respaldos/espejo/<pid>/` |
| Eventos (`/srv/ids/datos`) | no se respaldan | `eve.json`/`dns.json` de cada punto | son grandes y caducan a los 30 días; si se quieren, aparte |

Mientras no exista el respaldo diario, **el respaldo del VPS es el del proveedor** (instantánea del
disco) más, si se quiere una copia propia, el procedimiento manual de abajo. Ninguno de los dos se
lleva la clave maestra.

**Respaldo manual completo (como root).** Para una copia coherente se para el panel (sus bases
SQLite se escriben en vivo) y se copia `orq.db` con la API de copia de SQLite:

```sh
ts=$(date -u +%Y%m%dT%H%M%SZ); f=/root/backups/ids-maat-manual-$ts.tar.gz
install -d -m 0700 /root/backups
python3 -c 'import sqlite3; s = sqlite3.connect("/srv/ids/estado/orq.db"); d = sqlite3.connect("/srv/ids/estado/orq.db.copia"); s.backup(d); d.close()'
docker stop ids-core-panel
(umask 077; tar -czf "$f" --exclude=ids-maat/master.key --exclude=estado/orq.db --exclude='estado/orq.db-*' \
    -C / etc/ids-maat srv/ids/estado srv/ids/pki srv/ids/puntos srv/ids/panel srv/ids/fw srv/ids/core)
docker start ids-core-panel
rm -f /srv/ids/estado/orq.db.copia
tar -tzf "$f" >/dev/null && sha256sum "$f" > "$f.sha256"
tar -tzf "$f" | grep -c 'master\.key$'     # tiene que dar 0
```

**La clave maestra (`/etc/ids-maat/master.key`, 0440 `root:ids-panel`, montada ro en el panel) nunca
va dentro de esos tar** (`install.sh` y `lab-actualizar.sh` la excluyen y lo comprueban): con ella y
el tar se descifrarían las claves API de los MikroTik y los tokens. Se guarda **aparte**, una vez y
cada vez que cambie, en el gestor de secretos del dueño:

```sh
cat /etc/ids-maat/master.key     # 64 caracteres hex: copiarlos al gestor de secretos, nunca a /root/backups
```

Sin ella, las claves cifradas del respaldo no sirven (el panel arranca y avisa). Con ella y el
respaldo, sí.

### 3.2 Copia fuera del VPS

La copia la **descarga** una máquina de las redes de gestión, por SSH con una clave restringida
(`command=` y `from=`). No es el VPS quien la sube: así el VPS no guarda credenciales de otro
sistema.

```sh
# en la máquina de respaldo (cron), los tar que existen de verdad (manuales y de instalación)
rsync -a --chmod=F600 'root@ids.empresa.example:/root/backups/ids-maat-manual-*' /respaldos/empresa/
rsync -a --chmod=F600 'root@ids.empresa.example:/root/backups/ids-maat-install-*' /respaldos/empresa/
```

### 3.3 Recuperar en un VPS nuevo

1. Instalar Debian 13 y ejecutar `install.sh` **con la misma versión** que figura en el respaldo
   (`/etc/ids-maat/imagenes.json` del tar), con las mismas opciones de red (`--tun-base`, gestión,
   proxy).
2. Copiar `master.key` desde el gestor de secretos a `/etc/ids-maat/master.key`
   (`chown root:10500`, `chmod 0440`; el panel la lee por grupo).
3. Comprobar el sha256 del tar y restaurarlo: `systemctl stop ids-orq; docker stop ids-core-panel`,
   `tar -xzf ids-maat-manual-<ts>.tar.gz -C /` (no trae `master.key`), y
   `mv /srv/ids/estado/orq.db.copia /srv/ids/estado/orq.db` si el tar es del procedimiento manual.
4. `systemctl start ids-orq`, `ids-orq reconciliar` (levanta los puntos de `orq.db` con su
   `compose.yml`, sus puertos y sus credenciales VPN, que van en `/srv/ids/puntos` y la PKI) e
   `ids-orq panel aplicar`.
5. Apuntar `ids.empresa.example` a la IP nueva. Los MikroTik reconectan solos, sin tocarlos.
6. **Prueba de restauración:** en Ajustes no sale el aviso de clave maestra; en Puntos cada punto
   vuelve a `activo`, y en su ficha **API → probar** conecta (eso descifra `routers.json` con la
   `master.key` restaurada). Si la clave no es la buena, el panel avisa y las claves hay que volver
   a escribirlas.

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
| Desbanear una IP | `ids-orq vpn desbanear 203.0.113.45` (OpenVPN; queda en `orq.jsonl`) o `fail2ban-client set sshd unbanip 203.0.113.45` (SSH); ver abajo |
| Estado de los puntos | `ids-orq punto estado '*'` o `cat /srv/ids/run/estado.json` |
| Rotar la clave maestra | todavía no existe (no hay `kid`; [DATOS.md](DATOS.md) §6): cambiarla exige volver a guardar cada secreto |
| Cambiar la IP del VPS | restaurar o mover y cambiar el registro DNS `ids.empresa.example`; los MikroTik no se tocan |
| Actualizar el orquestador | `/root/ids-maat/actualizar-orquestador.sh <version>` |

**Cuándo banea `ids-vpn` y cómo desbanear.** La jaula cuenta solo las líneas
`<ip>:<puerto> ovpn-auth: rechazado … motivo=formato` y `… motivo=usuario`, una por intento fallido de
quien **no conoce el usuario** (un escáner: el usuario VPN no es público, solo está en el router y en
el panel). No cuentan:

- `motivo=clave`: el dueño del usuario con una clave vieja o mal tecleada, por ejemplo el MikroTik
  que sigue reintentando tras «Regenerar la clave VPN». Lo frena `ovpn-auth` (5 intentos por IP cada
  600 s, sin calcular scrypt mientras dura) y entra solo en ≤ 10 min tras poner la clave buena.
- `motivo=freno` (lo que sigue a esos 5 intentos) y `motivo=freno-global` (salta por la carga de
  todos; tampoco frena a la última IP que entró con la clave buena, durante 24 h).
- La línea `TLS Auth Error` que OpenVPN escribe por el mismo intento.

Con `maxretry = 5` y `findtime = 10m`, una IP queda baneada al 5.º intento fallido en 10 minutos,
durante 1 h la primera vez y más en las siguientes (`bantime.increment`, hasta 1 semana). El ban se
aplica en el hook `forward`, así que corta todos los puertos de esa IP hacia los contenedores (también
otros puntos detrás de esa misma IP).

Si una IP legítima queda baneada (p. ej. un router de un punto dado de baja que sigue llamando con su
usuario viejo, detrás de la misma IP pública que otro punto):

1. Ver qué IP está baneada: `fail2ban-client status ids-vpn`.
2. Quitar la causa (en ese ejemplo, `/interface ovpn-client remove [find name=ids-vpn]` en el router
   viejo). Si no, vuelve a banearse.
3. Desbanear: `ids-orq vpn desbanear <ip>`. Hace `fail2ban-client set ids-vpn unbanip <ip>` solo con
   una IP validada y deja la orden en `orq.jsonl` (quién la pidió, sin la IP en claro). En el panel:
   ficha del punto → Servicio → «Desbanear IP del MikroTik» (solo administradores; propone la IP del
   túnel o la última conocida y deja una línea en el Registro).
4. Si la IP es fija y del dueño, puede ir en `--dueno-ip` (es el `ignoreip` de fail2ban). Las redes
   de gestión nunca van en `ignoreip`.
