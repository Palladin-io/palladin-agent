FROM node:24-alpine3.22@sha256:191c9f0080fcbbc6547a85dc0ff7988072214a355aabdc1d2ec55a7dae5eea8a

ARG QA_UID

RUN apk add --no-cache dbus gnome-keyring libsecret \
    && npm install --global --ignore-scripts npm@11.18.0 \
    && if [ "$(id -u node)" != "$QA_UID" ]; then adduser -D -u "$QA_UID" qa; fi

USER ${QA_UID}
