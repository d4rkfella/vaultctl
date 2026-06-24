FROM python:3.14-slim@sha256:63a4c7f612a00f92042cbdcc7cdc6a306f38485af0a200b9c89de7d9b1607d15

ARG PYPI_VERSION

RUN \
    groupadd -g 65532 nonroot \
    && \
    useradd -r -u 65532 -g 65532 -m nonroot

RUN pip install --no-cache-dir "vaultctl==${PYPI_VERSION}"

USER nonroot

ENTRYPOINT ["vaultctl"]
