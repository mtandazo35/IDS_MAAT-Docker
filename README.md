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

En un VPS **Debian 13 (trixie) amd64** recién instalado, como `root`:

```bash
curl -fsSL https://raw.githubusercontent.com/mtandazo35/IDS_MAAT-Docker/v0.1.0/install.sh -o /root/ids-maat-install.sh && bash /root/ids-maat-install.sh --version v0.1.0 --nombre ids.empresa.example --gestion 192.0.2.0/25 --proxy 203.0.113.50 --zona America/Guayaquil
```

Cambia los valores por los tuyos:

| Opción | Qué es |
|---|---|
| `--nombre` | nombre DNS del VPS (va en el certificado del servidor VPN) |
| `--gestion` | redes desde las que entras por SSH, en CIDR y separadas por comas (como mucho /16). La IP de tu sesión SSH actual tiene que estar dentro |
| `--proxy` | IP de tu proxy inverso (el que pone HTTPS): el panel solo se abre desde ahí. IPs o redes de hasta /28, separadas por comas |
| `--zona` | zona horaria con la que el panel muestra las fechas (`Región/Ciudad`; sin ella, UTC) |

Opcionales: `--tun-base 198.18` (si tus abonados ya usan CGNAT `100.64.0.0/10`) y
`--dueno-ip <tu IP fija>` (fail2ban nunca la banea).

- **Prueba antes los valores** sin tocar nada: añade `--solo-validar` al final.
- **Confirma el acceso.** A mitad de la instalación el instalador se para y pide abrir una **sesión
  SSH nueva** desde una red de gestión y ejecutar `bash /root/ids-maat-install.sh --confirmar`. Si no
  llega en 5 minutos, el firewall y sshd vuelven a como estaban, para que no te quedes fuera.
- Tarda unos 10 minutos: verifica la firma de la release, instala Docker, descarga las reglas ET y las
  imágenes firmadas. Antes de tocar sshd, el firewall, Docker o fail2ban deja un respaldo en `/root/backups/`.
- Al terminar imprime la URL del panel, el usuario `admin` y su clave **una sola vez** (en el log sale
  enmascarada). Cámbiala desde el panel.
- Volver a ejecutarlo con otros `--gestion` o `--proxy` los cambia sin reinstalar.

Sucesor en contenedores de [suricata-ids-lab](https://github.com/mtandazo35/suricata-ids-lab).

**Estado:** primera versión publicada (`v0.1.0`). La arquitectura está en
[docs/ARQUITECTURA.md](docs/ARQUITECTURA.md), con sus anexos en docs/.
