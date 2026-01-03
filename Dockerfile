# Shadow Worker - Docker Image
# Defensive Security Operations Framework

FROM python:3.11-slim

LABEL maintainer="Shadow Worker Team"
LABEL description="Defensive Security Operations Framework"
LABEL version="1.0.0"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash shadow

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
COPY rules/ ./rules/

# Install Shadow Worker
RUN pip install --no-cache-dir -e .

# Install additional security tools
RUN pip install --no-cache-dir semgrep bandit yara-python

# Create data directory
RUN mkdir -p /app/data /config && chown -R shadow:shadow /app /config

# Switch to non-root user
USER shadow

# Set environment variables
ENV SHADOW_CONFIG=/config/shadow-config.yaml
ENV SHADOW_DATA_DIR=/app/data

# Default command
ENTRYPOINT ["shadow"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD shadow status || exit 1
