FROM python:3.14-slim@sha256:44dd04494ee8f3b538294360e7c4b3acb87c8268e4d0a4828a6500b1eff50061

ARG PYPI_VERSION

RUN \
    groupadd -g 65532 nonroot \
    && \
    useradd -r -u 65532 -g 65532 -m nonroot

RUN pip install --no-cache-dir "vaultctl==${PYPI_VERSION}"

USER nonroot

ENTRYPOINT ["vaultctl"]
