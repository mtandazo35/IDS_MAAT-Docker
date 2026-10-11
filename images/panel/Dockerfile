# ids-maat-panel — panel web (F1b). Contexto de build: images/panel.
# Se construye con la base fijada por digest en images/base.env (BASE_IMAGE). Sin BASE_IMAGE el
# build falla a propósito. Solo python3 de Debian, sin dependencias externas (stdlib).
# Pensada para correr con read_only, tmpfs en /tmp, cap_drop ALL y no-new-privileges, como 10500.
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
    IDS_PUERTO=5637

# tzdata: IDS_TZ (zona para mostrar fechas) con zoneinfo
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 tzdata; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd -g 10500 ids-panel; \
    useradd -u 10500 -g 10500 -M -d /nonexistent -s /usr/sbin/nologin ids-panel

COPY rootfs/ /

# git en Windows no guarda el bit +x de forma fiable: modos explícitos. El código se precompila
# (la raíz es de solo lectura en ejecución) y se comprueba que arranca.
RUN set -eux; \
    chmod 0755 /usr/local/bin/ids-panel; \
    find /usr/local/lib/ids-panel -type d -exec chmod 0755 {} +; \
    find /usr/local/lib/ids-panel -type f -exec chmod 0644 {} +; \
    python3 -m compileall -q /usr/local/lib/ids-panel; \
    find /usr/local/lib/ids-panel -type f -name '*.pyc' -exec chmod 0644 {} +; \
    mkdir -p /srv/ids/panel /srv/ids/datos /srv/ids/run /run/ids-orq; \
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
