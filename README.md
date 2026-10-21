# IDS_MAAT-Docker

IDS para ISP con MikroTik, en contenedores: **un panel central por empresa (VPS)** y, por
detras, **una instancia por cada MikroTik** (cada punto de la empresa) con su propio
OpenVPN y su propio Suricata.

- Cada punto en su red aislada: los puntos pueden repetir IPs privadas; el panel filtra
  por punto.
- Por la VPN de cada punto solo entran el espejo de trafico (TZSP), la API del MikroTik y su ping al sensor; el panel y SSH solo
  desde las redes de gestion.
- Alta de un punto desde el panel: crea los contenedores y entrega el `/interface
  ovpn-client` para RouterOS v6 y v7 (con la CA del VPS; sin reglas de firewall ni rutas, que
  gestiona el operador). El usuario de la API no va en esos comandos: lo crea el operador a mano en
  el router si quiere usar la API (docs/OPERACION.md §1.2).
- Si el MikroTik está en la misma red local que el VPS, el punto puede ser **directo**, sin VPN: el
  espejo llega por UDP al puerto del punto, desde cualquier IP del router, y el panel entra a su API
  por la LAN (docs/RED-Y-FIREWALL.md §11).

## ⚡ Quick install (one-liner)

En un VPS **Debian 13 (trixie) amd64** recién instalado, como `root` y entrando por SSH:

```bash
curl -fsSL --retry 5 --retry-all-errors https://raw.githubusercontent.com/mtandazo35/IDS_MAAT-Docker/main/install.sh -o /root/ids-maat-install.sh && bash /root/ids-maat-install.sh
```

El instalador sale siempre de `main`, así que una instalación nueva lleva sus últimos arreglos sin
esperar a una release. Instala la última release (imágenes firmadas, `VERSION_DEFECTO`); el panel y el
orquestador se ponen al día con `main` desde el botón «Actualizar». Para fijar una versión concreta:
`--version vX.Y.Z`, o el `install.sh` de su etiqueta (`.../vX.Y.Z/install.sh`).

Si la red corta conexiones a GitHub (errores de curl `35`/`56`, «unexpected eof»), el instalador
reintenta cada descarga, la verificación de firmas y cada `docker pull`, y avisa en pantalla de cada
reintento.

Sin opciones instala todo (la última release, reglas, timers y panel) con:

- **nombre** = la IP pública del VPS (la que reciben los MikroTik para conectar la VPN). Si el VPS
  está detrás de NAT (IP privada), usa la pública con la que sale a internet y avisa de los puertos
  que el NAT tiene que pasar; si no la averigua, usa la privada, que solo alcanzan los MikroTik de la
  misma red. Para otro nombre, `--nombre`;
- **zona horaria** `America/Guayaquil` (la del servidor y las fechas del panel; los contenedores
  siguen en UTC por dentro);
- **acceso abierto**: SSH y panel desde cualquier IP, con fail2ban activo. Sin modo seguro, porque con
  el SSH abierto no hay nada que revertir.

Para cerrar el acceso, vuelve a ejecutarlo con tus redes (no reinstala nada, solo cambia el firewall):

```bash
bash /root/ids-maat-install.sh --gestion 192.0.2.0/25 --panel 192.0.2.0/25
```

| Opción | Qué es |
|---|---|
| `--gestion` | redes desde las que entras por SSH, en CIDR y separadas por comas (como mucho /16). La IP de tu sesión SSH actual tiene que estar dentro |
| `--panel` | redes desde las que abres el panel directamente, en CIDR y separadas por comas (como mucho /16). El panel no se fía de sus cabeceras `X-Forwarded-*` |
| `--proxy` | IP de tu proxy inverso (el que pone HTTPS): abre el panel y el panel se fía de sus cabeceras `X-Forwarded-*` (la IP real del cliente). IPs o redes de hasta /28, separadas por comas |
| `--nombre` | nombre DNS o IP del VPS con el que llegan los MikroTik (va en el certificado del servidor VPN) |
| `--zona` | otra zona horaria (`Región/Ciudad`) |
| `--version` | otra release `vX.Y.Z` (por defecto, la de esa línea) |

En una reinstalación, la opción que no pases conserva lo que ya había: volver a ejecutarlo sin
opciones no reabre un acceso cerrado. Opcionales: `--tun-base 198.18` (si tus abonados ya usan CGNAT
`100.64.0.0/10`) y `--dueno-ip <tu IP fija>` (fail2ban nunca la banea).

- **Prueba antes los valores** sin tocar nada: añade `--solo-validar` al final.
- **Al cerrar el acceso, confirma.** Con `--gestion` el instalador se para y pide abrir una **sesión
  SSH nueva** desde una red de gestión y ejecutar `bash /root/ids-maat-install.sh --confirmar`. Si no
  llega en 5 minutos, el firewall vuelve a como estaba, para que no te quedes fuera.
- Tarda unos 10 minutos: verifica la firma de la release, instala Docker, descarga las reglas ET y las
  imágenes firmadas. Antes de tocar el firewall, Docker o fail2ban deja un respaldo en `/root/backups/`.
- **No toca la configuración de SSH:** se entra con contraseña o con clave, como lo tenga el servidor.
  fail2ban vigila el SSH (5 fallos en 10 minutos banean la IP).
- Al terminar imprime la URL del panel, el usuario `admin` y su clave **una sola vez** (en el log sale
  enmascarada). Cámbiala desde el panel.

Sucesor en contenedores de [suricata-ids-lab](https://github.com/mtandazo35/suricata-ids-lab).

**Estado:** versión publicada `v0.1.13` (la primera fue `v0.1.0`). La arquitectura está en
[docs/ARQUITECTURA.md](docs/ARQUITECTURA.md), con sus anexos en docs/.
