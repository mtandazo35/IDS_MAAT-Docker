"""Configuración del panel, leída del entorno (la pone el compose de I)."""

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path


class ErrorConfig(ValueError):
    pass


def redes_proxy(txt):
    """IDS_PROXY: IPs o CIDR separados por comas -> lista de ip_network. Vacío = sin proxy."""
    out = []
    for trozo in (txt or "").replace(";", ",").split(","):
        trozo = trozo.strip()
        if not trozo:
            continue
        try:
            out.append(ipaddress.ip_network(trozo, strict=False))
        except ValueError:
            raise ErrorConfig("IDS_PROXY: %r no es una IP ni un CIDR" % trozo)
    return out


@dataclass
class Config:
    panel_dir: Path = Path("/srv/ids/panel")
    datos_dir: Path = Path("/srv/ids/datos")
    run_dir: Path = Path("/srv/ids/run")
    orq_sock: str = "/run/ids-orq/orq.sock"
    orq_token: str = "/run/secrets/orq_token"
    puerto: int = 5637
    escucha: str = "0.0.0.0"
    empresa: str = ""
    tz: str = "UTC"
    proxies: list = field(default_factory=list)

    @property
    def usuarios_json(self):
        return self.panel_dir / "usuarios.json"

    @property
    def sesiones_json(self):
        return self.panel_dir / "sesiones.json"

    @property
    def operaciones_json(self):
        return self.panel_dir / "operaciones.json"

    @property
    def bitacora_jsonl(self):
        return self.panel_dir / "bitacora.jsonl"

    @property
    def estado_json(self):
        return self.run_dir / "estado.json"

    @classmethod
    def desde_entorno(cls, env=None):
        env = os.environ if env is None else env
        try:
            puerto = int(env.get("IDS_PUERTO") or 5637)
        except ValueError:
            raise ErrorConfig("IDS_PUERTO debe ser un número")
        if not 1 <= puerto <= 65535:
            raise ErrorConfig("IDS_PUERTO fuera de rango")
        return cls(
            panel_dir=Path(env.get("IDS_PANEL_DIR") or "/srv/ids/panel"),
            datos_dir=Path(env.get("IDS_DATOS") or "/srv/ids/datos"),
            run_dir=Path(env.get("IDS_RUN") or "/srv/ids/run"),
            orq_sock=env.get("IDS_ORQ_SOCK") or "/run/ids-orq/orq.sock",
            orq_token=env.get("IDS_ORQ_TOKEN") or "/run/secrets/orq_token",
            puerto=puerto,
            escucha=env.get("IDS_ESCUCHA") or "0.0.0.0",
            empresa=(env.get("IDS_EMPRESA") or "").strip()[:80],
            tz=(env.get("IDS_TZ") or "UTC").strip() or "UTC",
            proxies=redes_proxy(env.get("IDS_PROXY", "")),
        )
