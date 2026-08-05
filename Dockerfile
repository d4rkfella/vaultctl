FROM python:3.14-slim@sha256:e11c17f46f87983eb946b121694dedba6290ee2b0dd5294d137d82943502d179

ARG PYPI_VERSION

RUN \
    groupadd -g 65532 nonroot \
    && \
    useradd -r -u 65532 -g 65532 -m nonroot

RUN pip install --no-cache-dir "vaultctl==${PYPI_VERSION}"

USER nonroot

ENTRYPOINT ["vaultctl"]
