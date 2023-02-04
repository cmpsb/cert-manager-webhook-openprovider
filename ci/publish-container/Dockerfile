FROM debian:stable-slim

SHELL ["/bin/bash", "-c"]

RUN apt-get -q update \
    && apt-get upgrade -yq \
    && apt-get install -yq --no-install-recommends python3 python3-distutils curl ca-certificates jq git \
    && curl -sSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash \
    && useradd -Um user

USER user:user
WORKDIR /home/user
ENV PATH "$PATH:/home/user/.local/bin"

RUN curl -sSL https://bootstrap.pypa.io/get-pip.py | python3 \
    && pip install 'yq >= 3.0.0'
