# syntax=docker/dockerfile:1

FROM python:3.14-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --upgrade pip \
    && pip wheel --wheel-dir /wheels .

FROM python:3.14-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SHADOW_CONFIG=/config/shadow-config.yaml \
    SHADOW_DATA_DIR=/var/lib/shadow-worker

LABEL org.opencontainers.image.title="shadow-worker" \
      org.opencontainers.image.description="Defensive security operations framework" \
      org.opencontainers.image.source="https://github.com/srvrX0r/shadow-worker" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="1.1.0"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin --uid 10001 --user-group shadowworker \
    && mkdir -p /var/lib/shadow-worker /config

COPY --from=builder /wheels /wheels
RUN pip install --upgrade pip \
    && pip install /wheels/*.whl \
    && rm -rf /wheels

COPY --chown=shadowworker:shadowworker rules /var/lib/shadow-worker/rules

WORKDIR /var/lib/shadow-worker
RUN chown -R shadowworker:shadowworker /var/lib/shadow-worker /config

USER shadowworker

ENTRYPOINT ["shadow"]
CMD ["--help"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD shadow --help >/dev/null || exit 1
