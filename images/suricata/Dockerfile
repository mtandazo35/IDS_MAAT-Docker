# ids-maat-suricata — CONTRATO-F1a §5.2, §5.9 y §6.1. Contexto de build: images/suricata.
# Se construye con images/build.sh (pasa BASE_IMAGE desde images/base.env). Sin BASE_IMAGE
# el build falla a propósito: la base va siempre fijada por digest.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VERSION=dev
# Serie (o versión exacta) de Suricata esperada. El build falla si el paquete instalado no
# empieza por ella. La versión exacta instalada queda en /usr/share/ids-maat/suricata-version
# y en el MANIFEST.json de cada release; la etiqueta lleva lo que se pase aquí.
ARG SURICATA_VERSION=7.0

LABEL org.opencontainers.image.source="https://github.com/mtandazo35/IDS_MAAT-Docker" \
      org.opencontainers.image.version="${VERSION}" \
      ids-maat.componente="suricata" \
      ids-maat.suricata-version="${SURICATA_VERSION}" \
      ids-maat.plantilla-version="1"

ENV LANG=C.UTF-8 \
    PYTHONUTF8=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    IDS_MAAT_VERSION=${VERSION}

RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        suricata suricata-update python3 ca-certificates; \
    rm -rf /var/lib/apt/lists/*

COPY rootfs/ /

# git en Windows no guarda el bit +x de forma fiable: modos explícitos.
RUN set -eux; \
    chmod 0755 /usr/local/bin/entrypoint-suricata /usr/local/bin/salud-suricata \
               /usr/local/bin/ids-reglas; \
    chmod 0755 /usr/share/ids-maat; \
    chmod 0644 /usr/share/ids-maat/*; \
    instalada="$(suricata -V | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"; \
    case "${instalada}." in \
        "${SURICATA_VERSION}".*) ;; \
        *) echo "Suricata ${instalada} no es de la serie ${SURICATA_VERSION}" >&2; exit 1 ;; \
    esac; \
    printf '%s\n' "${instalada}" > /usr/share/ids-maat/suricata-version; \
    chmod 0644 /usr/share/ids-maat/suricata-version; \
    mkdir -p /reglas /etc/ids/suricata /var/log/suricata /run/suricata; \
    python3 -c "import json; json.load(open('/usr/share/ids-maat/plantilla.json')); json.load(open('/usr/share/ids-maat/feeds.json'))"

ENTRYPOINT ["/usr/local/bin/entrypoint-suricata"]
