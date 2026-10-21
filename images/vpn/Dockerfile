# ids-maat-vpn — CONTRATO-F1a §5.1 y §6.1. Contexto de build: images/vpn.
# Se construye con images/build.sh (pasa BASE_IMAGE desde images/base.env). Sin BASE_IMAGE
# el build falla a propósito: la base va siempre fijada por digest.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG VERSION=dev
ARG S6_OVERLAY_VERSION=3.2.0.2
ARG S6_OVERLAY_NOARCH_SHA256=6dbcde158a3e78b9bb141d7bcb5ccb421e563523babbe2c64470e76f4fd02dae
ARG S6_OVERLAY_X86_64_SHA256=59289456ab1761e277bd456a95e737c06b03ede99158beb24f12b165a904f478

# ids-maat.modos: los modos de punto que sabe hacer la imagen (el orquestador no crea un punto
# directo sobre una imagen anterior, que no lo tiene). ids-maat.api-puerto=libre: acepta cualquier
# puerto para la API del router, no solo 8729/8728 (2026-10-20)
LABEL org.opencontainers.image.source="https://github.com/mtandazo35/IDS_MAAT-Docker" \
      org.opencontainers.image.version="${VERSION}" \
      ids-maat.componente="vpn" \
      ids-maat.modos="vpn,directo" \
      ids-maat.api-puerto="libre"

ENV S6_KEEP_ENV=1 \
    S6_BEHAVIOUR_IF_STAGE2_FAILS=2 \
    S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0 \
    PATH=/command:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        openvpn socat nftables iproute2 ethtool python3 xz-utils; \
    rm -rf /var/lib/apt/lists/*

# s6-overlay v3 (solo linux/amd64): tarballs noarch y x86_64 con su sha256 comprobado.
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz /tmp/s6-overlay-noarch.tar.xz
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz /tmp/s6-overlay-x86_64.tar.xz
RUN set -eux; \
    echo "${S6_OVERLAY_NOARCH_SHA256}  /tmp/s6-overlay-noarch.tar.xz" | sha256sum -c -; \
    echo "${S6_OVERLAY_X86_64_SHA256}  /tmp/s6-overlay-x86_64.tar.xz" | sha256sum -c -; \
    tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz; \
    tar -C / -Jxpf /tmp/s6-overlay-x86_64.tar.xz; \
    rm -f /tmp/s6-overlay-noarch.tar.xz /tmp/s6-overlay-x86_64.tar.xz

COPY rootfs/ /

# Bits de ejecución explícitos: git en Windows no los guarda de forma fiable (§1).
RUN set -eux; \
    chmod 0755 /usr/local/bin/tzsp-decap /usr/local/bin/ovpn-auth /usr/local/bin/salud-vpn \
               /usr/local/lib/ids-vpn/render.py \
               /etc/s6-overlay/scripts/init-env /etc/s6-overlay/scripts/init-nft \
               /etc/s6-overlay/scripts/init-veth /etc/s6-overlay/scripts/init-mon \
               /etc/s6-overlay/s6-rc.d/init-env/up /etc/s6-overlay/s6-rc.d/init-nft/up \
               /etc/s6-overlay/s6-rc.d/init-veth/up /etc/s6-overlay/s6-rc.d/init-mon/up \
               /etc/s6-overlay/s6-rc.d/openvpn/run /etc/s6-overlay/s6-rc.d/tzsp-decap/run \
               /etc/s6-overlay/s6-rc.d/rele-api/run /etc/s6-overlay/s6-rc.d/rele-api-claro/run; \
    python3 -m py_compile /usr/local/lib/ids-vpn/render.py; \
    for f in /usr/local/bin/tzsp-decap /usr/local/bin/ovpn-auth; do \
        python3 -c "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')" "$f"; \
    done; \
    rm -rf /usr/local/lib/ids-vpn/__pycache__

ENTRYPOINT ["/init"]
