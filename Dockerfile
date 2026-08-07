FROM python:3.14-slim@sha256:a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc

ARG PYPI_VERSION

RUN \
    groupadd -g 65532 nonroot \
    && \
    useradd -r -u 65532 -g 65532 -m nonroot

RUN pip install --no-cache-dir "vaultctl==${PYPI_VERSION}"

USER nonroot

ENTRYPOINT ["vaultctl"]
