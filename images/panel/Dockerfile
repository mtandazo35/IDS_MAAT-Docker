# ids-maat-panel — panel web (F2: dashboard heredado de suricata-ids-lab + Puntos). Contexto de build:
# images/panel. Se construye con la base fijada por digest en images/base.env (BASE_IMAGE). Sin
# BASE_IMAGE el build falla a propósito. Pensada para correr con read_only, tmpfs en /tmp,
# cap_drop ALL y no-new-privileges, como 10500.
#
# Dependencias: python3 de Debian (stdlib), tzdata (IDS_TZ con zoneinfo), python3-cryptography
# (AES-GCM de secretos.py, CONTRATO-F2 §10.3) y python3-reportlab (informe PDF del Reporte,
# informe_pdf.py). Las dos salen del paquete de Debian y no de pip:
# - integridad equivalente a `pip --require-hashes`: apt solo instala lo que casa con el SHA256 del
#   índice Packages, firmado por el InRelease de Debian, sobre una base fijada por digest;
# - no hace falta pip, ni compilador, ni un wheel con su propio OpenSSL dentro de la imagen: usa
#   el libssl de la base, que recibe los avisos de seguridad de Debian con la imagen nueva;
# - la versión exacta instalada queda en /usr/share/ids-maat/cryptography-version (y en dpkg).
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/mtandazo35/IDS_MAAT-Docker" \
      org.opencontainers.image.version="${VERSION}" \
      ids-maat.componente="panel"

ENV LANG=C.UTF-8 \
    PYTHONUTF8=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    IDS_MAAT_VERSION=${VERSION} \
    IDS_PUERTO=5637 \
    IDS_SHARE=/usr/local/share/ids-panel

RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-cryptography python3-reportlab tzdata ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /usr/share/ids-maat; \
    dpkg-query -W -f='${Version}\n' python3-cryptography > /usr/share/ids-maat/cryptography-version; \
    dpkg-query -W -f='${Version}\n' python3-reportlab > /usr/share/ids-maat/reportlab-version; \
    groupadd -g 10500 ids-panel; \
    useradd -u 10500 -g 10500 -M -d /nonexistent -s /usr/sbin/nologin ids-panel

COPY rootfs/ /

# git en Windows no guarda el bit +x de forma fiable: modos explícitos. El código se precompila
# (la raíz es de solo lectura en ejecución) y se comprueba que arranca: CLI, módulos del panel
# heredado (dashboard con puntos_web y eventos_web, generador, feeds, informe, espejo) y AES-GCM
# de cryptography. dashboard se importa con un entorno mínimo en /tmp (IDS_*), como en las pruebas:
# compileall solo ve errores de sintaxis, no un import roto (auditoría B-21). La imagen usa el
# Python 3.13 de trixie y el CI de unittest el 3.12: este import es la comprobación en 3.13.
RUN set -eux; \
    chmod 0755 /usr/local/bin/ids-panel; \
    find /usr/local/lib/ids-panel /usr/local/share/ids-panel -type d -exec chmod 0755 {} +; \
    find /usr/local/lib/ids-panel /usr/local/share/ids-panel -type f -exec chmod 0644 {} +; \
    python3 -m compileall -q /usr/local/lib/ids-panel; \
    find /usr/local/lib/ids-panel -type f -name '*.pyc' -exec chmod 0644 {} +; \
    test -s /usr/local/share/ids-panel/mapa/countries-110m.json; \
    test -s /usr/local/share/ids-panel/mapa/topojson-client.min.js; \
    cd /usr/local/lib/ids-panel; \
    python3 -c 'import nodos, secretos, mikrotik_init, informe_diario, informe_pdf; from cryptography.hazmat.primitives.ciphers.aead import AESGCM; AESGCM(bytes(32))'; \
    e=$(mktemp -d); mkdir -p "$e/panel" "$e/datos" "$e/run"; \
    env IDS_PANEL_DIR="$e/panel" IDS_DATOS="$e/datos" IDS_RUN="$e/run" IDS_MASTER_KEY="$e/master_key" \
        IDS_ORQ_SOCK="$e/orq.sock" IDS_ORQ_TOKEN="$e/orq_token" IDS_TZ=UTC \
        python3 -c 'import dashboard, puntos_web, eventos_web'; \
    rm -rf "$e"; \
    python3 html_report.py --help >/dev/null; \
    python3 informe_diario.py --help >/dev/null; \
    cd /; \
    mkdir -p /srv/ids/panel /srv/ids/datos /srv/ids/run /run/ids-orq /run/secrets; \
    chown 10500:10500 /srv/ids/panel; \
    chmod 0700 /srv/ids/panel; \
    /usr/local/bin/ids-panel --help >/dev/null

USER 10500:10500
WORKDIR /srv/ids/panel
EXPOSE 5637

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=20s \
    CMD ["/usr/local/bin/ids-panel", "salud"]

ENTRYPOINT ["/usr/local/bin/ids-panel"]
CMD ["servir"]
