# IDS_MAAT-Docker

IDS para ISP con MikroTik, en contenedores: **un panel central por empresa (VPS)** y, por
detras, **una instancia por cada MikroTik** (cada punto de la empresa) con su propio
OpenVPN y su propio Suricata.

- Cada punto en su red aislada: los puntos pueden repetir IPs privadas; el panel filtra
  por punto.
- Por la VPN de cada punto solo entra el espejo de trafico (TZSP); el panel y SSH solo
  desde las redes de gestion.
- Alta de un punto desde el panel: crea los contenedores y entrega el `/interface
  ovpn-client` para RouterOS v6 y v7.

Sucesor en contenedores de [suricata-ids-lab](https://github.com/mtandazo35/suricata-ids-lab).

**Estado:** en diseno. La arquitectura esta en [docs/ARQUITECTURA.md](docs/ARQUITECTURA.md) (con sus anexos en docs/)
(en revision); el codigo viene despues.
