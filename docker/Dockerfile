ARG ALPINE_VER=3.17

FROM ghcr.io/by275/base:alpine AS prebuilt
FROM ghcr.io/by275/base:alpine${ALPINE_VER} AS base

ARG AUTOSCAN_VERSION=master

ENV \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN \
    echo "**** install apk packages ****" && \
    apk add --no-cache \
        `# python3` \
        python3 \
        py3-pip \
        py3-wheel \
        `# pre-compiled python packages` \
        py3-psutil \
        `# core` \
        findutils \
        git \
        unzip \
        `# util` \
        docker-cli \
        jq \
    && \
    if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi && \
    if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi && \
    echo "**** install plex_autoscan ****" && \
    pip install "git+https://github.com/by275/plex_autoscan.git@${AUTOSCAN_VERSION}" && \
    echo "**** cleanup ****" && \
    rm -rf \
        /root/.cache \
        /tmp/*

# 
# BUILD
# 
FROM base AS rclone

RUN \
    echo "**** install rclone ****" && \
    curl -fsSL https://rclone.org/install.sh | bash

# 
# COLLECT
# 
FROM base AS collector

# add s6-overlay
COPY --from=prebuilt /s6/ /bar/
ADD https://raw.githubusercontent.com/by275/docker-base/main/_/etc/cont-init.d/adduser /bar/etc/cont-init.d/10-adduser
ADD https://raw.githubusercontent.com/by275/docker-base/main/_/etc/cont-init.d/wait-for-mnt /bar/etc/cont-init.d/30-wait-for-mnt

# add rclone
COPY --from=rclone /usr/bin/rclone /bar/usr/bin/

# add local files
COPY root/ /bar/

RUN \
    echo "**** permissions ****" && \
    chmod a+x \
        /bar/usr/local/bin/* \
        /bar/etc/cont-init.d/* \
        /bar/etc/s6-overlay/s6-rc.d/*/run

RUN \
    echo "**** s6: resolve dependencies ****" && \
    for dir in /bar/etc/s6-overlay/s6-rc.d/*; do mkdir -p "$dir/dependencies.d"; done && \
    for dir in /bar/etc/s6-overlay/s6-rc.d/*; do touch "$dir/dependencies.d/legacy-cont-init"; done && \
    echo "**** s6: create a new bundled service ****" && \
    mkdir -p /tmp/app/contents.d && \
    for dir in /bar/etc/s6-overlay/s6-rc.d/*; do touch "/tmp/app/contents.d/$(basename "$dir")"; done && \
    echo "bundle" > /tmp/app/type && \
    mv /tmp/app /bar/etc/s6-overlay/s6-rc.d/app && \
    echo "**** s6: deploy services ****" && \
    rm /bar/package/admin/s6-overlay/etc/s6-rc/sources/top/contents.d/legacy-services && \
    touch /bar/package/admin/s6-overlay/etc/s6-rc/sources/top/contents.d/app

# 
# RELEASE
# 
FROM base
LABEL maintainer="by275"
LABEL org.opencontainers.image.source https://github.com/by275/plex_autoscan

COPY --from=collector /bar/ /

ENV \
    S6_BEHAVIOUR_IF_STAGE2_FAILS=2 \
    PLEX_AUTOSCAN_COLORLOG=1 \
    PLEX_AUTOSCAN_CONFIG="/config/config.json" \
    PLEX_AUTOSCAN_QUEUEFILE="/config/queue.db" \
    PLEX_AUTOSCAN_CACHEFILE="/config/cache.db"

EXPOSE 3467/tcp
VOLUME /config

HEALTHCHECK --interval=1m --timeout=30s --start-period=10s --retries=3 \
    CMD /usr/local/bin/healthcheck

ENTRYPOINT ["/init"]
