FROM debian:13

ENV container=docker
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        systemd systemd-sysv polkitd passwd util-linux python3 gcc libc6-dev procps libcap2-bin \
        nodejs openssl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
