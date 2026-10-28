# Operación

Anexo de [ARQUITECTURA.md](ARQUITECTURA.md). Este anexo reúne lo que se ejecuta a mano:

- los comandos del MikroTik (v7 y v6);
- los respaldos y la recuperación;
- el acceso de emergencia;
- el mantenimiento;
- los usuarios y los puntos que ve cada uno.

En F5 se completa y se prueba al pie de la letra.

Ejemplo: punto `p003`, N=3, puerto 1196, túnel `100.64.3.0/24`, nombre del VPS
`ids.empresa.example`. El panel genera estos comandos con los valores reales de cada punto; aquí
solo se muestran como referencia.

## 1. Preparar el MikroTik

Versiones soportadas: **RouterOS 6.49 o superior** en v6, y v7. Anteriores a 6.49, no.

### 1.1 La API del router: API-SSL (con o sin certificado) o API sin SSL

El script no crea ningún certificado ni toca `/ip service api-ssl` (ni el certificado ni
`address=`, §1.5): el panel usa la API-SSL (8729) del router tal como esté. Es como trabaja el
proyecto original (decisión del dueño, 2026-10-15) y vale igual en 6.49 y en v7. Lo único que el
panel crea en el router es el certificado de la API-SSL, y solo si la ficha lo pide («Con
certificado») y el router no tiene ninguno (abajo, 2026-10-20).

- **Sin certificado (`certificate=none`)** RouterOS 6.49 y algunos 7 negocian un cifrado anónimo
  (ADH). El panel prueba primero ese cifrado (`ADH:@SECLEVEL=0`) y después los normales, por si el
  router tiene un certificado asignado.
- **Hay RouterOS 7 que no aceptan la API-SSL sin certificado** (visto el 2026-10-20 en un cliente):
  cierran el saludo TLS y «Probar la conexión» dice «el MikroTik cerró la API-SSL sin contestar al
  saludo TLS». Con un certificado propio conectan. «Probar la conexión» lo crea (abajo) y, si no
  puede, el aviso da estas órdenes para pegarlas en el router:

  ```
  /certificate add name=ids-api common-name=ids-api days-valid=3650 trusted=yes key-usage=key-cert-sign,crl-sign,digital-signature,key-encipherment,tls-server
  /certificate sign ids-api
  /ip service set api-ssl certificate=ids-api disabled=no
  ```
- **Con certificado o API normal, y el puerto** (decisión del dueño, 2026-10-20). En la ficha del
  punto (API) están la casilla «Con certificado (API-SSL)» y el «Puerto de la API en el MikroTik», el
  que diga `/ip service print`, que puede estar cambiado. Sin la casilla el panel habla la **API
  normal** (en el router, `/ip service set api disabled=no`): no hay certificado ni huella, y la clave
  de `ids-api` viaja sin cifrar por la red del punto. La casilla se guarda al momento. Cambiar el puerto
  (al «Guardar», o `ids-orq punto ajustar <pid> --api-puerto <1-65535>`) recrea los dos contenedores
  del punto, con vuelta atrás si falla. Un puerto que no sea 8729 ni 8728 necesita la imagen `vpn`
  0.1.13 o posterior (etiqueta `ids-maat.api-puerto=libre`); con una anterior el orquestador contesta
  CONFLICTO y pide volver a ejecutar `install.sh`.
- **«Probar la conexión» crea el certificado si falta** (el dueño, 2026-10-20). Con «Con certificado»
  confirma la conexión y el certificado y, si el router no tiene ninguno, lo crea: entra una vez por
  la API normal (8728, que RouterOS trae encendida y que el contenedor del punto alcanza por un
  segundo relé, `api-claro.sock`, desde la 0.1.14), crea el certificado y se lo pone a la API-SSL.
  Sin la casilla solo confirma la conexión. Si no puede crearlo (la API normal apagada o filtrada, o
  el contenedor del punto de una versión anterior), el aviso da las órdenes de arriba para pegarlas.
  Por eso los datos para el MikroTik de un punto directo no dicen nada de la API (el dueño,
  2026-10-21): solo adónde va el espejo.
- Si el servicio está deshabilitado: `/ip service enable api-ssl`.
- **La clave de `ids-api` la protege el túnel.** Sin huella fijada, el panel hace `/login` con lo
  que presente el router, con certificado o sin él. La clave va por el túnel OpenVPN, en el que el
  MikroTik verifica el certificado del servidor con la CA del VPS (§1.4), y sale del netns del
  sensor, que hacia el router solo deja salir la API y la respuesta al ping
  ([RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) §8).
- **Fijar el certificado (opcional).** Si el router presenta un certificado, la ficha del punto (API)
  enseña su huella SHA-256 en bloques. Se compara con la del router (`/ip service print detail
  where name=api-ssl` dice qué certificado usa la API-SSL, y `/certificate print detail
  where name=<certificado>` da su `fingerprint`) y se pulsa «La huella coincide: confirmar» (el
  panel la vuelve a leer y solo la guarda si sigue siendo esa; queda en la bitácora quién la
  confirmó). Desde
  entonces el panel exige ese certificado: ya no prueba el cifrado anónimo, para que nadie pueda
  rebajar la conexión, y si el router presenta otro no le manda la clave, con aviso rojo en la ficha
  y una línea `MK-HUELLA-DISTINTA` en el Registro. Si el certificado del router cambia a propósito,
  «Volver a confirmar» en la ficha (admin, o el operador del punto: §6). «Olvidar la huella» vuelve a conectar sin exigir
  certificado.
- **Sin certificado no hay huella que fijar.** La ficha lo dice: la API-SSL no tiene certificado, no
  hay huella que fijar y la clave de `ids-api` va protegida por el túnel. Una huella vacía guardada
  por una versión anterior del panel (el sha256 de nada, de un API-SSL sin certificado) cuenta como
  sin huella.
- **Huellas de antes de VPN-06.** Las que una versión anterior del panel fijó solas se siguen
  exigiendo igual que una confirmada; la ficha las marca «fijada automáticamente» para revisarlas.
- **Routers dados de alta con el script anterior** (el que creaba el certificado `ids-promax` y lo
  asignaba a `api-ssl`): si la API-SSL corta la conexión nada más conectar («TLS handshake falló …
  EOF» en «Probar la conexión»), revisar el servicio en el router:

  ```
  /ip service print detail where name=api-ssl
  ```

  Que esté habilitado, que `address` incluya al sensor (`100.64.3.1`) o esté vacía y, si tiene un
  certificado asignado que corta la conexión, cambiarlo por el `ids-api` de arriba o, en RouterOS 6,
  dejarlo sin él:

  ```
  /ip service set api-ssl certificate=none
  ```

  El certificado `ids-promax` puede quedarse (no estorba) o borrarse con
  `/certificate remove [find name=ids-promax]` si ningún otro servicio del router lo usa. Si el
  punto tenía fijada la huella de ese certificado, el panel la sigue exigiendo: tras dejar la
  API-SSL sin certificado, «Olvidar la huella» en la ficha.
- **La baja no toca la API-SSL** ni ningún certificado del router (§2.1).

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
```

El script no lleva reglas de firewall, ni rutas, ni el usuario de la API: crea la VPN (con la CA
del VPS) y nada más (desde 2026-10-16). El firewall y las rutas del router los gestiona el operador
(§1.5).

- **El usuario de la API lo crea el operador**, a mano, si quiere que el panel hable con el router
  por la API: un usuario exclusivo que solo pueda entrar desde el sensor del punto (`100.64.N.1`,
  por el túnel). Igual en v6 y en v7:

  ```
  /user group add name=ids-api policy=read,write,api
  /user add name=ids-api group=ids-api address=100.64.3.1/32 password=<CLAVE-API>
  ```

  La clave la elige el operador y se pone en la ficha del punto (apartado API), que la guarda
  cifrada.

- **El cifrado del bloque v7 sale de la versión del punto.** RouterOS 7 no negocia el cifrado de
  datos (solo manda `IV_PROTO=2`) y OpenVPN usa el respaldo del servidor (`data-ciphers-fallback`).
  Con `ros_version` 7 el respaldo es GCM y el bloque v7 lleva `cipher=aes256-gcm`; el v6 no conecta.
  Con `ros_version` 6 el respaldo es CBC y el bloque v7 sale con `cipher=aes256-cbc`: conectan los dos
  bloques, y la cabecera lo dice. **El panel crea así todos los puntos**, sin preguntar la versión.
  Para pasar a GCM un punto cuyo MikroTik es v7: `ids-orq punto ajustar p003 --ros 7` y volver a
  copiar el bloque v7.
- El contenido de `/file set` es el `ca.crt` del VPS (`/srv/ids/pki/ca.crt`) con cada salto de línea
  escrito como `\n`. El panel y `ids-orq punto ovpn-client <pid>` lo dan ya puesto.

### 1.3 RouterOS v6 (6.49 o superior)

```
# (las mismas 7 líneas de la CA del VPS que en v7)
/interface ovpn-client add name=ids-vpn connect-to=ids.empresa.example port=1196 mode=ip \
    user=vpn3a9f2c password=<CLAVE-VPN> cipher=aes256 auth=sha1 verify-server-certificate=yes \
    add-default-route=no disabled=no
```

v6 solo admite TCP, así que no lleva `protocol=`, y no tiene `use-peer-dns`. Si el handshake TLS
falla en 6.49, se activa la «compatibilidad v6» del punto desde su ficha
([INSTANCIA.md](INSTANCIA.md) §7.2).

En los dos bloques, la API-SSL del router se usa tal como esté (§1.1): el script no crea ningún
certificado.

### 1.4 El MikroTik verifica al servidor

El script lleva la CA del VPS y `verify-server-certificate=yes` en los dos bloques, sin paso manual.
Sin eso, quien suplantara `ids.empresa.example` (DNS envenenado o alguien en el camino) se quedaría
con la clave VPN y haría de «sensor» para el router.

- **Qué comprueba RouterOS:** que la cadena llega a una CA de confianza del router (la que importa el
  script) y que el `connect-to` está en el CN o en el SAN del certificado del servidor
  ([help.mikrotik.com, OpenVPN](https://help.mikrotik.com/docs/spaces/ROS/pages/2031655/OpenVPN)).
  El certificado de cada punto lleva `CN=<NOMBRE_DNS>` y `subjectAltName=DNS:<NOMBRE_DNS>` (o `IP:` si
  el nombre es una IP) e EKU `serverAuth`.
- **El reloj del router cuenta.** Con la verificación activa, un router con la fecha atrasada ve el
  certificado del servidor «todavía no válido» y no conecta. El certificado de cada punto vale desde
  **2 días antes** de emitirse (y la CA del VPS, desde 2 días antes de crearse), para cubrir un
  reloj algo atrasado, pero un router que arranca sin hora (sin batería de reloj, en 1970 o en la fecha de fábrica) sigue fallando. **Antes de pegar el
  script:** activar el cliente NTP del router (`/system ntp client`, con un servidor que alcance) y
  comprobar la fecha con `/system clock print`.
- **La CA es una por VPS y es pública.** Nunca va una clave privada en el script. El certificado
  importado se llama `ids-maat-ca-<pid>.txt_0` (6.49 no admite `name=` en `/certificate import`) y se
  quita en la baja por ese prefijo (§2.1).
- **Puntos dados de alta antes de este cambio:** su certificado de servidor solo lleva
  `CN=server-<pid>` y el MikroTik lo rechazaría con la verificación. El script lo avisa en la
  cabecera (`# AVISO: …`). El orden es:
  1. «Regenerar la clave VPN» en la ficha del punto (o `ids-orq punto vpn-regenerar <pid>`): renueva
     el certificado del servidor y reinicia OpenVPN.
  2. Pegar en el router las 7 líneas de la CA, poner la clave nueva y activar la verificación:
     `/interface ovpn-client set [find name=ids-vpn] password=<CLAVE-VPN> verify-server-certificate=yes`
     (en el panel, la página de regenerar ya la da con la clave puesta).
- **Por confirmar en el canario de 6.49:** que `/file print file=` + `/file set contents=` + `/certificate
  import` funcionan pegados en la terminal (la línea de la CA mide ~1,3 KB) y que 6.49 acepta el
  certificado con la verificación activa. `verify-server-certificate` ya existe en 6.45 y en v7.

### 1.5 Notas

- **`/ip service api-ssl` no se toca** (ni la lista `address=` ni el certificado, §1.1). Si la
  lista ya tiene direcciones y no incluye `100.64.3.1`, el paso API del asistente lo detecta y
  muestra el comando para **añadirla** conservando las demás. Lo aplica el operador.
- **El script no toca el firewall ni las rutas del router** (decisión del dueño). Lo que entra
  por `ids-vpn` y adónde llega lo decide el firewall del operador: sin reglas propias del IDS, desde
  el túnel se alcanza lo que ese firewall permita. Para que el panel hable con el router, el `input`
  del router tiene que dejar pasar la API-SSL desde el sensor (`100.64.3.1` → `8729` por
  `ids-vpn`); si la cadena `input` acaba en `drop`, el operador añade ese `accept` en su firewall.
  Del lado del sensor no cambia nada: su netns solo deja salir el espejo TZSP, la API y la respuesta
  al ping del MikroTik ([RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) §8).
- **Sin ruta blackhole.** Si el túnel cae, el espejo hacia `100.64.3.1` sigue la ruta por defecto
  del router ([RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) §3.1); el operador decide si pone su propia
  ruta o regla para evitarlo.
- **Comprobar el túnel desde el router:** `/ping 100.64.3.1` (el sensor es `100.64.N.1`, con N el
  número del punto) o `/interface ovpn-client monitor ids-vpn`. El sensor contesta al ping solo si
  viene de la IP del MikroTik en el túnel (`100.64.3.2`), con tope de 5 por segundo.
- **Routers dados de alta con el script anterior** (el que llevaba la ruta blackhole y el bloque
  de aislamiento de `ids-vpn` en `/ip firewall filter`): esas reglas y esa ruta se quitan a mano con

  ```
  /ip firewall filter remove [find comment="IDS ids-maat:p003"]
  /ip route remove [find comment="IDS ids-maat:p003"]
  ```

  Las dos líneas buscan el comentario **exacto** del alta: no tocan el espejo
  (`IDS ids-maat:p003:espejo`) ni las cuarentenas. Antes de quitarlas, si la cadena `input` del
  router acaba en `drop`, el operador deja puesto su propio `accept` de la API desde el sensor (el
  del bloque viejo se va con el `remove`). Si ese script dejó además el certificado `ids-promax`
  asignado a `api-ssl`, lo que se revisa está en §1.1.
- **El ping necesita también el sensor nuevo.** En un punto creado antes de este cambio, la regla
  del ping de la tabla `inet ids_punto` ([RED-Y-FIREWALL.md](RED-Y-FIREWALL.md) §8) entra al recrear
  su contenedor `vpn` con la imagen nueva: `ids-orq punto reconfigurar p003` (§1.6). Hasta entonces
  el sensor descarta el ping.
- **Puerto 8728 (API en claro).** Desde la 0.1.13 el panel la habla: en la ficha del punto (API) se
  desmarca «Con certificado (API-SSL)» y se pone el puerto (§1.1). Hasta la 0.1.12 el panel hablaba
  siempre TLS y con 8728 no conectaba.

### 1.6 Llevar una corrección a lo ya desplegado

Una corrección en el código **no llega sola** a lo que ya está funcionando. Cada parte se actualiza
por su camino:

| Parte | Qué recibe | Cómo |
|---|---|---|
| Host (fail2ban, journald, sysctl, firewall del host) | filtros y jaulas de fail2ban, `journald.conf.d/90-ids.conf` | volver a ejecutar `install.sh` con las mismas opciones (`--nombre`, `--gestion`, `--proxy`…); es idempotente y respalda antes de tocar nada (§3.1). **Actualizar no lleva el host:** si los ficheros de fail2ban, journald, sysctl o módulos del kernel del commit difieren de los instalados, termina con el aviso «host sin actualizar (…): vuelve a ejecutar install.sh» |
| El orquestador | `ids_orq.py` y sus plantillas, unidades systemd, logrotate | el botón **Actualizar** del panel (o `ids-orq actualizar <commit>`) lo lleva a un commit de `main` (§5); `install.sh` también lo instala (el de su release) |
| Cada punto (contenedores `vpn` y `suricata`) | `server.conf` (p. ej. `max-clients 32`, `hand-window 20`), `suricata.yaml`, `compose.yml` (p. ej. `NET_RAW` sin `NET_ADMIN`, `start_interval`) y las imágenes actuales de `imagenes.json` (p. ej. `ovpn-auth` y `salud-vpn` nuevos) | `ids-orq punto reconfigurar p003` (en el servidor, como root; el botón del panel «Aplicar la configuración actual» está pendiente). Va por la cola: reescribe los tres ficheros con las plantillas actuales, pasa el punto a las imágenes actuales, recrea los contenedores y espera la salud; si no queda sano, vuelve a los ficheros y a las imágenes de antes y deja el motivo. Devuelve qué se recreó y qué cambió (`recreado`, `cambios`). Mientras se recrean los contenedores, ese punto no captura y su VPN se corta (el MikroTik reconecta solo) |
| Cada MikroTik | lo que va en el script del router (p. ej. la CA y la verificación de §1.4) | a mano en el router: no se puede hacer desde el VPS. Para la verificación del servidor, §1.4; para quitar la ruta y las reglas del script anterior, §1.5; para la API-SSL con el certificado del script anterior, §1.1 |

Orden recomendado tras una corrección: el orquestador (Actualizar, o `install.sh` si la corrección
toca también el host) → `ids-orq punto reconfigurar <pid>` punto por punto (el botón del panel está
pendiente), empezando por uno y comprobando que vuelve a `activo` → los routers.

## 2. Espejo

> **Desde 2026-10-16 el espejo lo monta el operador a mano en el MikroTik** (decisión del dueño: «yo uso
> esas reglas para enviar los datos»). La ficha del punto ya no tiene la sección Espejo (ni «Ver el plan»,
> «Aplicar», «Pausar», «Retirar»). Las reglas que se usan son dos `mangle` `sniff-tzsp` en `forward` sobre
> la address-list del operador, p. ej.:
>
> ```
> /ip firewall mangle
> add action=sniff-tzsp chain=forward comment="IDS ida" connection-bytes=0-10000 passthrough=yes sniff-target=100.64.3.1 sniff-target-port=37008 src-address-list="Redes Privadas"
> add action=sniff-tzsp chain=forward comment="IDS vuelta" connection-bytes=0-10000 dst-address-list="Redes Privadas" passthrough=yes sniff-target=100.64.3.1 sniff-target-port=37008
> ```
>
> Si el punto tiene prefijos adicionales, también se añaden a esa address-list. Lo que sigue describe el
> montaje que hacía el panel (`mikrotik_init.py`): sigue valiendo para la **baja**, que retira lo que lleve
> el comentario `IDS ids-maat:<pid>:espejo` (nunca las reglas a mano), y como referencia del fasttrack.

Lo aplicaba el panel desde la ficha del punto, siempre después de la vista previa y del respaldo
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

**Comentario propio del espejo: `IDS ids-maat:<pid>:espejo`.** Lo que lleva `IDS ids-maat:<pid>`
(en un router dado de alta con el script anterior, la ruta blackhole y el bloque de aislamiento de
`ids-vpn`, §1.5) **el espejo no lo toca nunca**: ni al aplicar, ni al pausar, ni al retirar. Un espejo montado por una versión anterior (con el comentario del alta) se reconoce solo
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
  `src-address-list`/`dst-address-list` (del respaldo). Nunca borra reglas sin ese comentario, ni las que
  lleven el comentario del alta (`IDS ids-maat:<pid>`, de un script anterior), que se quitan a mano
  (§1.5, §2.1).
- **Prueba de aceptación** (laboratorio, con un MikroTik real de cada versión): mismo resultado antes y
  después en tráfico permitido, bloqueado y en cuarentena; espejo en las dos direcciones; aceleración
  pasados los 10 KB; aplicar dos veces sin duplicar; retirar sin tocar reglas ajenas.

### 2.1 Quitar todo lo del IDS de un router

**Qué quita el panel en una baja con API, y qué no.** Antes de encolar la baja, el panel limpia el
router por la API: saca de las address-lists las IPs que puso él (cuarentenas, destinos
bloqueados) y **retira el espejo** (address-list `ids-vigilados`, los dos mangle, los fasttrack de
los vigilados, y devuelve la regla fasttrack del operador a sus valores originales; con el respaldo
previo de §2). **Nada más.** Lo del alta se queda en el router porque es el camino por el que el
panel habla con él: la interfaz `ids-vpn` y la CA del VPS con su fichero, el usuario y el grupo
`ids-api` si el operador los creó (§1.2) y, en un router dado de alta con el script anterior, la
ruta blackhole y el bloque de aislamiento de `ids-vpn` en `filter`.
Eso se quita a mano, después de la baja, con el bloque de **terminar una baja con API** de abajo
(todo menos el espejo, que ya no está). La API-SSL del router no se toca: el script actual no
crea ningún certificado, y el `ids-promax` de un router dado de alta con el script anterior no se
borra en la baja (puede usarlo otro servicio del router); si ninguno lo usa, se quita a mano (§1.1).

**Terminar una baja con API** (el panel ya quitó el espejo y las IPs):

```
/ip firewall filter remove [find comment="IDS ids-maat:p003"]
/ip route remove [find comment="IDS ids-maat:p003"]
/interface ovpn-client remove [find name=ids-vpn]
/user remove [find name=ids-api]
/user group remove [find name=ids-api]
/certificate remove [find name~"^ids-maat-ca-p003"]
/file remove [find name~"^ids-maat-ca-p003"]
```

Conviene hacerlo antes de 7 días: pasado el enfriamiento, el `N` del punto (y su puerto) se puede
dar a un alta nueva, y un router viejo que siga llamando a ese puerto con su usuario de antes acaba
con su IP pública baneada por fail2ban (VPN-12; §5).

**Baja sin API** (o router que el panel no alcanza): todo, espejo incluido.

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

El script actual no pone reglas de `filter` ni rutas; las líneas de `filter` y `route` con el
comentario del alta quitan lo que dejó un script anterior (la ruta blackhole y el bloque de
aislamiento de `ids-vpn`, §1.5) y, si no hay nada, no hacen nada.

## 3. Respaldos y recuperación

### 3.1 Qué se respalda hoy y cuándo

**No hay respaldo diario automático.** La orden `sistema.respaldar` del orquestador está
**reservada y sin implementar** (contesta «no disponible») y no hay ningún timer de respaldo en
`host/systemd/`. Lo que existe de verdad:

| Respaldo | Cuándo | Contenido | Dónde |
|---|---|---|---|
| Instalación | cada `install.sh` (también al reinstalar), antes de tocar nada | `etc/ssh`, `etc/docker`, `etc/fail2ban`, `etc/systemd/journald.conf.d` (el `90-ids.conf` de journald), `/srv/ids/fw`, `/etc/ids-maat` **sin `master.key`**, `/srv/ids/panel`, `/srv/ids/estado` (`orq.db`), `/srv/ids/pki`, `/srv/ids/puntos` | `/root/backups/ids-maat-install-<ts>.tar.gz`, 0600 |
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
  2. Si el problema lo trajo la **última ejecución de `install.sh`**:
     `bash /root/ids-maat/revertir-acceso.sh`. Es el mismo script que el modo seguro ejecuta solo si
     nadie confirma a tiempo: devuelve el firewall del host (`ids_host.nft`) a como estaba antes de
     esa ejecución (sshd no lo toca: el IDS no cambia su configuración). No admite parámetros (ni IP ni `--proxy`). Solo
     existe si esa ejecución fue con modo seguro: con `--sin-reversion` no se genera (y queda el de
     una ejecución anterior, que devolvería un estado más viejo).
  3. Si no, **abrir una IP o red concreta**: editar `/etc/ids-maat/ids.conf` (`REDES_GESTION` para
     SSH y `REDES_PANEL` para el panel, separadas por comas; `IPS_PROXY` solo para un proxy inverso,
     porque el panel se fía de sus cabeceras) y aplicar con `ids-orq fw-render --aplicar` (genera
     `ids_host.nft`, lo prueba con `nft -c` y lo carga). Si se cambió `IPS_PROXY`, además
     `ids-orq panel aplicar` (el panel lee esa lista al arrancar). La próxima ejecución de
     `install.sh` sin `--gestion`/`--panel`/`--proxy` conserva lo que haya en `ids.conf`; con ellos, lo
     sustituye.
  4. Revisar `/root/backups/` y la bitácora.
- **Una red más ancha que /16 solo se puede abrir así**, editando `ids.conf` desde la consola:
  `install.sh --gestion` la rechaza. La excepción es `0.0.0.0/0`: abierto a cualquier IP, lo mismo
  que instalar sin `--gestion`.

### 4.1 Primer acceso al panel y clave olvidada

- Al terminar, `install.sh` imprime la URL (`http://<nombre>:5637`), el usuario `admin` y su clave
  **una sola vez**. La clave no se guarda en claro: en `/root/ids-maat/install-<ts>.log` sale como
  `********`. Una reinstalación no la cambia.
- El 5637 solo se abre desde las redes de `--panel` y las IP de `--proxy`. Para entrar directo, las
  redes van en `--panel` (hasta /16), no en `--proxy`: así el panel no se fía de sus cabeceras
  `X-Forwarded-*`. Si no, el túnel SSH de arriba.
- **Instalación abierta** (sin `--gestion` ni `--proxy`, el one-liner del README): el SSH y el 5637
  se abren a cualquier IP, con fail2ban activo, y el resumen del instalador lo avisa en grande. Se
  cierra volviendo a ejecutar `bash /root/ids-maat-install.sh --gestion <redes> --panel <redes>`,
  que pide confirmar desde una sesión SSH nueva (modo seguro).
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
| Actualizar el panel y el orquestador a lo último de `main` | aviso **Actualización disponible** del menú del usuario o **Ajustes → Versión → Actualizar** (solo admin), o `ids-orq actualizar <commit>` en el servidor. Construye el panel en el servidor (sin firma), con respaldo en `/root/backups/ids-maat-actualizar-<ts>.tar.gz` y vuelta atrás automática; no toca los puntos. Avance: `/srv/ids/run/actualizacion.json` y `journalctl -u ids-actualizar` ([ACTUALIZACIONES.md](ACTUALIZACIONES.md) §4.1) |
| Actualizar el orquestador y el host a una release | volver a ejecutar `install.sh` con la versión nueva y las mismas opciones (§1.6); deja otra vez las imágenes firmadas de esa release |
| Llevar un punto a la configuración y las imágenes actuales | `ids-orq punto reconfigurar <pid>` en el servidor (§1.6; el botón del panel está pendiente) |
| Ver los logs de un punto | `ids-orq punto logs <pid>` (OpenVPN) o `ids-orq punto logs <pid> --parte suricata`; `--lineas N` (≤ 500) |

**Cortar atacantes de internet por la API (2026-10-28).** En la ficha del punto, sección «Cortar
atacantes de internet» (permiso `puntos.atacantes`): apagado (por defecto), automático (cada 15 min)
o solo a mano («Enviar ahora» ahí o en Histórico). El panel manda al MikroTik del punto las IPs de
internet que atacan a sus abonados (las de Histórico, como mucho 500 por envío) a la address-list
`suricata-atacantes` con `timeout=1d` (comentario `Suricata atacante: …`) y pone dos reglas en
`/ip firewall filter`, forward e input, `connection-state=new src-address-list=suricata-atacantes
action=drop`, arriba de su cadena (comentario `Suricata:atacantes:01` y `:02`), con respaldo del
firewall en `/srv/ids/panel/respaldos/mikrotik/` antes del primer cambio. Lo enviado queda en
`/srv/ids/panel/estado/atacantes-enviados.json` y el modo de cada punto en
`/srv/ids/panel/conf/atacantes.json`; en el Registro, `ATACANTES-ENVIO`, `ATACANTES-ENVIO-FALLO` y
`ATACANTES-APAGADO`. Al apagarlo se quitan del router las dos reglas y las entradas con ese
comentario (lo importado a mano con `/blocklist.rsc` no se toca); sin API usable hay que configurarla
o marcar «Apagar sin limpiar el router» (y quitarlo a mano). La baja del punto quita también las dos
reglas y esas entradas, y olvida su modo y su registro. Antes de cada envío se lee la lista del router
(lo que falta se reenvía; lo puesto a mano no se toca). Nunca se manda la IP WAN desde la que conecta
el MikroTik de ningún punto, la del panel, ni nada que no sea IPv4; hace falta «Enviar: sí» en la API
del punto, y el automático no manda con datos de más de `EVIDENCIA_MAX_HORAS`.

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
aplica en el hook `forward`, así que corta a esa IP todo lo que publica Docker: la VPN de **todos**
los puntos (también otros puntos detrás de esa misma IP) y el panel. El SSH del host no pasa por
`forward` y no lo corta (ese lo vigila la jaula `sshd`).

Si una IP legítima queda baneada (p. ej. un router de un punto dado de baja que sigue llamando con su
usuario viejo, detrás de la misma IP pública que otro punto):

1. Ver qué IP está baneada: `fail2ban-client status ids-vpn`. Es la IP **pública** desde la que el
   router llega al VPS, no la del túnel (`100.64.N.2`).
2. Quitar la causa (en ese ejemplo, `/interface ovpn-client remove [find name=ids-vpn]` en el router
   viejo). Si no, vuelve a banearse.
3. Desbanear: `ids-orq vpn desbanear <ip>`. Hace `fail2ban-client set ids-vpn unbanip <ip>` solo con
   una IP validada y deja la orden en `orq.jsonl` (quién la pidió y el sha256 de los parámetros, no
   la IP escrita; ese hash **no la oculta**: con una IPv4 se recupera probando todas las
   direcciones). En el panel: ficha del punto → Servicio → «Desbanear IP del MikroTik» (solo
   administradores). Propone la IP pública desde la que el router está conectado o, si ya no
   conecta, la última que se le conoció; se puede cambiar. Deja una línea en el Registro.
4. Si la IP es fija y del dueño, puede ir en `--dueno-ip` (es el `ignoreip` de fail2ban). Las redes
   de gestión nunca van en `ignoreip`.

## 6. Usuarios por punto

Un VPS puede dar servicio a varios clientes: el admin asigna a cada usuario los puntos que ve, y cada
usuario ve solo los suyos, como si tuviera un panel propio (decisión del dueño, 2026-10-22). Llega a
un servidor ya instalado con **Actualizar**: solo cambia el panel; el orquestador, las imágenes y los
puntos no se tocan.

**Asignar.** En **Ajustes › Usuarios**, al crear o editar un usuario, «Puntos que ve»:

- «Todos los puntos»: los de hoy y los que se den de alta después;
- «Solo estos puntos»: una casilla por punto.

La columna «Puntos» de la tabla de usuarios dice qué ve cada uno. El cambio vale en la siguiente
petición del usuario, sin cerrarle la sesión. En el servidor es el campo opcional `puntos` de
`/srv/ids/panel/conf/usuarios.json` ([DATOS.md](DATOS.md) §3.2): sin el campo ve todos, con `[]`
ninguno.

**Administradores limitados** (fase 1 de permisos, 2026-10-22). Un administrador también puede
tener «Solo estos puntos»: entonces ve y gestiona solo esos, como un operador de esos puntos, y lo
global (ajustes, usuarios, exclusiones, actualizaciones) queda para un administrador con todos los
puntos. Salvaguarda: siempre queda al menos un administrador activo con todos los puntos; al único
no se le pueden limitar los puntos, quitar el rol, borrar ni desactivar.

**Permisos a la carta** (en curso, por fases): `permisos.py` tiene ya el catálogo por secciones
(Resumen, Cuarentena, Reputación, Puntos, Usuarios, Ajustes) y los roles de siempre como plantillas.
Cada fase pasa una sección a pedir su permiso concreto y la muestra en el acordeón de Usuarios;
mientras tanto, lo que aún no ha pasado decide por rol.

- **Fase 2 (Puntos).** En Ajustes › Usuarios, cada usuario tiene el acordeón «Permisos» con la
  sección Puntos («Activos X/10»): ver la lista y la ficha, API del MikroTik, prefijos, ver los
  comandos y la clave de la VPN, regenerarla, arrancar/parar/reiniciar, logs, crear, borrar y
  desbanear. Al cambiar el rol se marcan los de su plantilla («Usar los del rol» los repone). Crear,
  borrar y desbanear son **globales**: solo valen si el usuario ve todos los puntos. La ficha enseña
  solo lo que el usuario puede usar y el servidor rechaza (403) el resto. Si los marcados coinciden
  con la plantilla del rol no se guarda lista (`permisos` en usuarios.json), y cambiar el rol desde
  la tabla la borra.
- **Fase 3 (Cuarentena y Reputación).** El acordeón suma Cuarentena (ver; enviar y quitar;
  graduada; lista DNS; envío masivo; bloquear destinos; destinos de confianza, global) y Reputación
  (ver las IPs públicas; consultar AbuseIPDB; denunciar, global). Cada ruta pide el suyo (403 sin
  él). La página de Cuarentena enseña los botones si el usuario tiene alguno de los de actuar; cada
  envío vuelve a comprobar el suyo en el servidor.
- **Fase 4 (Resumen).** El acordeón suma Resumen: En vivo, Top y Detalle; Histórico; Conducta (y
  su CSV); Informe PDF; Eventos; y la vista «Todos» (global). Sin el permiso de una página no sale
  su pestaña y la página da 403; sin «En vivo», la portada lleva a la primera pestaña que el usuario
  sí puede ver (o a Ajustes). Sin «Vista Todos», un usuario que ve todos los puntos los mira de uno
  en uno, como un limitado.
- **Fase 5 (Usuarios).** El acordeón suma Usuarios: ver, crear y editar, borrar y desactivar. Quien
  no es administrador con todos los puntos gestiona solo a quien no tiene más que él: con sus
  puntos (si está limitado, solo «Solo estos puntos» y de los suyos), con permisos dentro de los
  suyos y con un rol que no sea mayor. En su lista no salen los demás; editarlos, borrarlos o
  desactivarlos responde «Ese usuario no existe». No se edita a sí mismo (su clave y su foto, sí,
  desde Perfil). Un administrador limitado a unos puntos es, así, el administrador de ese cliente.
- **Fase 6 (Ajustes y cierre).** El acordeón suma Ajustes (empresa, MikroTik, IPs públicas, feeds e IA,
  Telegram, DNS, exclusiones, IPs de confianza, ventana, actualizar reglas, actualizar el panel,
  bitácora), todos globales: cada tarjeta de Ajustes, la pestaña Exclusiones y el aviso de
  actualización salen con su permiso. Cuarentena enseña cada bloque con el suyo. Salvaguarda: no se
  guarda un cambio que deje sin ningún administrador activo con todos los puntos y todos los
  permisos. Con esto todas las secciones deciden por permiso; el rol queda como plantilla.
- **Roles y Usuarios separados** (2026-10-23). Ajustes › **Roles y permisos** lista los tres roles con cuántos
  usuarios tiene cada uno y sus permisos; Operador y Lectura se editan con el acordeón y el cambio vale para
  todos sus usuarios en su siguiente clic («Valores de fábrica» los repone). Administrador es fijo,
  con todo. Solo los edita un administrador con todo. Se guardan en `conf/roles.json` (solo los
  que difieren de fábrica). La ventana de **Usuarios** queda con nombre, correo, rol, puntos, clave
  y foto, sin acordeón. Quien tenía permisos propios los conserva (sale marcado «propios» en la
  tabla) hasta que se marque «Usar los permisos de su rol».

**Qué ve un usuario limitado:**

- solo sus puntos: nunca la vista «Todos los nodos» (`nodos/_todos/`), porque sus ficheros mezclan
  todos los puntos. Con un solo punto no ve el selector;
- con dos o más puntos y el permiso `resumen.todos` (bloque C, 2026-10-23), **Todos mis puntos
  (acumulado)**: el acumulado de SUS puntos, en su propia carpeta `nodos/_g<12 hex>` (huella de la
  lista ordenada de pids, `nodos.grupo_id`). Es su vista por defecto. El refrescador genera cada
  combinación de puntos en uso (usuarios activos con lista `puntos`, el permiso y ≥ 2 puntos que
  existen; dos usuarios con los mismos puntos comparten carpeta) en cada ciclo, después de «Todos»,
  con `html_report.py <vmin> --grupo p001,p003`. Coste: una generación más por combinación y ciclo,
  solo de las que están en uso. Las carpetas `_g*` que ya nadie usa se borran tras cada ciclo y la
  poda diaria de reportes también las recorre;
- un punto ajeno no existe para él: en la URL o en un formulario da 404, igual que uno que no
  existe;
- sin ningún punto asignado, el panel le dice «Sin puntos asignados» y solo le deja su cuenta:
  Ajustes › Perfil (cambiar su clave y su foto), la Documentación y Salir (2026-10-23).

**Qué puede cada rol dentro de sus puntos:**

| | lectura | operador | admin |
|---|---|---|---|
| Ver paneles, eventos y reportes | sí | sí | sí, de todos |
| Incidentes y cuarentenas; bloquear un destino (si es limitado, solo en sus routers) | no | sí | sí |
| Ficha del punto: API del MikroTik (usuario, clave, puerto, «Con certificado», «Probar la conexión», confirmar u olvidar la huella), prefijos, comandos de la VPN y regenerar su clave, arrancar, parar y reiniciar, logs | no | sí | sí |
| Dar de alta o de baja un punto; desbanear una IP (fail2ban es global) | no | no | sí |

Un operador sin límite gana la ficha de todos los puntos, pero tampoco crea ni borra puntos.

**Lo global nunca lo toca un usuario limitado.** Para los demás manda su rol, como antes (casi todo es
solo del admin): ajustes del sistema, feeds, IA, Telegram, DNS, empresa, ajustes MikroTik globales,
exclusiones, bitácora y registro, actualizaciones, la ventana del resumen, usuarios, IPs de confianza,
la lista global de destinos de confianza y denunciar a AbuseIPDB.

**Lo que no cambia:**

- **Telegram**: el chat global, el del admin, recibe los avisos de todos los puntos. Desde 2026-10-23
  cada punto puede tener además su propio chat (ficha del punto › Avisos por Telegram, con el
  permiso «Avisos por Telegram del punto» y el mismo bot), que recibe solo lo suyo: cuarentenas,
  sensor, públicas, su parte de los envíos masivos y su sección del informe diario;
- los procesos de fondo (informes, políticas, sincronización con los routers) trabajan con todos los
  puntos;
- la baja de un punto lo quita de la lista `puntos` de cada usuario; quien se queda sin ninguno ve
  «Sin puntos asignados» hasta que el admin le asigne otro.
