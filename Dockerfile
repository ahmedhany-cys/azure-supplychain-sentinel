# syntax=docker/dockerfile:1
#
# Azure SupplyChain Sentinel - reproducible local container.
# - Base image pinned by digest (python:3.12-slim as of 2026-10-28).
# - Syft, OSV-Scanner and Cosign pinned to exact versions and SHA-256 verified
#   against each project's published checksum file.
# - Python dependencies installed with --require-hashes.
# - Runs as an unprivileged user; no credentials are baked into the image.

ARG PYTHON_IMAGE=python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

FROM ${PYTHON_IMAGE} AS tools
ARG TARGETARCH=amd64
ARG SYFT_VERSION=1.55.0
ARG OSV_SCANNER_VERSION=2.7.0
ARG COSIGN_VERSION=3.1.4
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /tools
RUN set -eux; \
    syft="syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    curl -fsSLO "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/${syft}"; \
    curl -fsSLO "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_checksums.txt"; \
    grep " ${syft}\$" "syft_${SYFT_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "${syft}" syft; \
    osv="osv-scanner_linux_${TARGETARCH}"; \
    curl -fsSLO "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/${osv}"; \
    curl -fsSLO "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_SHA256SUMS"; \
    grep " ${osv}\$" osv-scanner_SHA256SUMS | sha256sum -c -; \
    mv "${osv}" osv-scanner; \
    cos="cosign-linux-${TARGETARCH}"; \
    curl -fsSLO "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/${cos}"; \
    curl -fsSLO "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign_checksums.txt"; \
    grep " ${cos}\$" cosign_checksums.txt | sha256sum -c -; \
    mv "${cos}" cosign; \
    chmod 0755 syft osv-scanner cosign

FROM ${PYTHON_IMAGE} AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SENTINEL_DATA_DIR=/data \
    PYTHONPATH=/app \
    HOME=/tmp \
    SYFT_CHECK_FOR_APP_UPDATE=false
RUN groupadd --system --gid 10001 sentinel \
 && useradd --system --uid 10001 --gid sentinel --home-dir /app --shell /usr/sbin/nologin sentinel
WORKDIR /app
COPY requirements/requirements.txt requirements/requirements.txt
RUN python -m pip install --require-hashes --no-deps -r requirements/requirements.txt
COPY --from=tools /tools/syft /tools/osv-scanner /tools/cosign /usr/local/bin/
COPY pyproject.toml LICENSE ./
COPY sentinel ./sentinel
COPY config ./config
COPY examples ./examples
COPY fixtures ./fixtures
COPY scripts/fault_injection ./scripts/fault_injection
COPY .streamlit ./.streamlit
# Run from the source tree (config/, examples/ are resolved relative to it) via a wrapper,
# instead of installing a copy into site-packages.
RUN printf '#!/bin/sh\nexec python -m sentinel.cli "$@"\n' > /usr/local/bin/sentinel \
 && chmod 0755 /usr/local/bin/sentinel \
 && mkdir -p /data && chown sentinel:sentinel /data
USER sentinel
VOLUME ["/data"]
EXPOSE 8000 8501
# Default: show help. docker-compose.yml starts the API and dashboard services.
CMD ["sentinel", "--help"]
