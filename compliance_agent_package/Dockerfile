# Compliance Agent Dockerfile for Remote Scanning
FROM ubuntu:22.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    wget \
    xmlstarlet \
    unzip \
    supervisor \
    git \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Create compliance user
RUN groupadd -r compliance && useradd -r -g compliance -d /app -s /bin/bash compliance

# Copy requirements for agent
COPY requirements.txt /app/requirements.txt

# Create virtual environment and install Python dependencies
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Copy agent source code
COPY src/ /app/src/
COPY config/ /app/config/
COPY scripts/ /app/scripts/

# Create necessary directories
RUN mkdir -p /app/logs /app/results /app/content && \
    chown -R compliance:compliance /app

# Create content directory (SCAP content will be downloaded if available, otherwise mock scans)
RUN mkdir -p /app/content && \
    chown -R compliance:compliance /app/content

# Copy entrypoint and supervisor configuration
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
RUN chmod +x /entrypoint.sh

# Expose health check port
EXPOSE 8080

# Set user
USER compliance

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Start supervisor to manage services
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
