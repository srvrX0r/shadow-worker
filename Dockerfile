# syntax=docker/dockerfile:1
#
# Shadow Worker container image.
#
# Build:  docker build -t shadow-worker:1.2.0 .
# Run:    docker run --rm shadow-worker:1.2.0 --version
#
# The image is deliberately thin: no package manager calls at runtime, no
# compilers, no optional scanners. Install extras (semgrep, bandit, yara-python)
# in a derived image when a deployment needs them.

FROM python:3.14-slim AS builder

# Keep pip's download cache on a BuildKit cache mount: dependency wheels are
# downloaded once and the image layer stays free of caches.
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip \
    && pip wheel --wheel-dir /wheels .

FROM python:3.14-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    SHADOW_CONFIG=/config/shadow-config.yaml \
    SHADOW_DATA_DIR=/var/lib/shadow-worker/data

ARG VERSION=1.2.0
ARG REVISION=

LABEL org.opencontainers.image.title="shadow-worker" \
      org.opencontainers.image.description="Defensive security operations framework" \
      org.opencontainers.image.source="https://github.com/srvrX0r/shadow-worker" \
      org.opencontainers.image.documentation="https://github.com/srvrX0r/shadow-worker/blob/main/docs/INSTALLATION.md" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 shadowworker \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin shadowworker \
    && mkdir -p /var/lib/shadow-worker/data /config

COPY --from=builder /wheels /wheels
# --no-index: the runtime layer never reaches the network; every dependency
# wheel is built in the builder stage.
RUN pip install --no-cache-dir --no-index --find-links /wheels shadow-worker \
    && rm -rf /wheels

COPY --chown=10001:10001 rules /var/lib/shadow-worker/rules

WORKDIR /var/lib/shadow-worker
RUN chown -R 10001:10001 /var/lib/shadow-worker /config

# Numeric user keeps `runAsNonRoot` enforceable in Kubernetes, which cannot
# resolve image user names.
USER 10001:10001

ENTRYPOINT ["shadow"]
CMD ["--help"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD shadow --help >/dev/null || exit 1
