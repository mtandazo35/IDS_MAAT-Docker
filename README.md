# IDS_MAAT-Docker

IDS para ISP con MikroTik, en contenedores: **un panel central por empresa (VPS)** y, por
detras, **una instancia por cada MikroTik** (cada punto de la empresa) con su propio
OpenVPN y su propio Suricata.

- Cada punto en su red aislada: los puntos pueden repetir IPs privadas; el panel filtra
  por punto.
- Por la VPN de cada punto solo entran el espejo de trafico (TZSP), la API del MikroTik y su ping al sensor; el panel y SSH solo
  desde las redes de gestion.
- Alta de un punto desde el panel: crea los contenedores y entrega el `/interface
  ovpn-client` para RouterOS v6 y v7 (con la CA del VPS y el usuario de la API; sin reglas
  de firewall ni rutas, que gestiona el operador).

## ⚡ Quick install (one-liner)

En un VPS **Debian 13 (trixie) amd64** recién instalado, como `root` y entrando por SSH con clave:

```bash
curl -fsSL https://raw.githubusercontent.com/mtandazo35/IDS_MAAT-Docker/v0.1.4/install.sh -o /root/ids-maat-install.sh && bash /root/ids-maat-install.sh
```

Sin opciones instala todo (la release de esa línea, reglas, timers y panel) con:

- **nombre** = la IP pública del VPS (la que reciben los MikroTik para conectar la VPN; si el VPS está
  detrás de NAT, pásala con `--nombre`);
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
  llega en 5 minutos, el firewall y sshd vuelven a como estaban, para que no te quedes fuera.
- Tarda unos 10 minutos: verifica la firma de la release, instala Docker, descarga las reglas ET y las
  imágenes firmadas. Antes de tocar sshd, el firewall, Docker o fail2ban deja un respaldo en `/root/backups/`.
- Al terminar imprime la URL del panel, el usuario `admin` y su clave **una sola vez** (en el log sale
  enmascarada). Cámbiala desde el panel.

Sucesor en contenedores de [suricata-ids-lab](https://github.com/mtandazo35/suricata-ids-lab).

**Estado:** versión publicada `v0.1.4` (la primera fue `v0.1.0`). La arquitectura está en
[docs/ARQUITECTURA.md](docs/ARQUITECTURA.md), con sus anexos en docs/.
