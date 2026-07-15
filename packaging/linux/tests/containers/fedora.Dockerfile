FROM fedora:42

ENV container=docker
RUN dnf install --assumeyes \
        systemd polkit shadow-utils util-linux python3 gcc glibc-devel procps-ng findutils libcap \
    && dnf clean all

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
