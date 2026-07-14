FROM python:3.14-slim@sha256:d3400aa122fa42cf0af0dbe8ec3091b047eac5c8f7e3539f7135e86d855dc015

ARG PYPI_VERSION

RUN \
    groupadd -g 65532 nonroot \
    && \
    useradd -r -u 65532 -g 65532 -m nonroot

RUN pip install --no-cache-dir "vaultctl==${PYPI_VERSION}"

USER nonroot

ENTRYPOINT ["vaultctl"]
