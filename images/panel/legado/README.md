# Panel heredado de suricata-ids-lab

Copia **tal cual** del panel de [suricata-ids-lab](https://github.com/mtandazo35/suricata-ids-lab) en el commit
`5b89110`, sacada de los heredocs de `install-suricata.sh`:

| Fichero | Heredoc de origen | Instalado antes en |
|---|---|---|
| `suricata-dashboard.py` | `DASH` | `/usr/local/bin/suricata-dashboard` |
| `suricata-html-report.py` | `HREP` | `/usr/local/bin/suricata-html-report` |
| `suricata-feeds-update.py` | `FEEDS` | `/usr/local/bin/suricata-feeds-update` |
| `suricata-mikrotik-init.py` | `MKINIT` | `/usr/local/bin/suricata-mikrotik-init` |
| `suricata-report.py` | `REP` | `/usr/local/bin/suricata-report` |
| `vendor/` | `vendor/` del repo | assets del mapa |

Sobre esta copia se integran, en commits aparte, las mejoras de IDS_MAAT-Docker: selector de nodo (cada
MikroTik = un punto con su VPN y su Suricata), apartado Puntos y ejecución dentro del contenedor del panel.
