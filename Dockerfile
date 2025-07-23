# Multi-stage Dockerfile for Security Compliance Automation Agent
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install OpenSCAP and security tools
RUN apt-get update && apt-get install -y \
    libopenscap25 \
    openscap-common \
    openscap-utils \
    openscap-scanner \
    curl \
    wget \
    gnupg \
    ca-certificates \
    netcat-openbsd \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Create OpenSCAP content directory and download content
RUN mkdir -p /usr/share/xml/scap/ssg/content/ && \
    mkdir -p /app/openscap-content && \
    cd /app/openscap-content && \
    wget -q https://github.com/ComplianceAsCode/content/releases/download/v0.1.72/scap-security-guide-0.1.72.zip && \
    apt-get update && apt-get install -y unzip && \
    unzip -q scap-security-guide-0.1.72.zip && \
    cp -r scap-security-guide-0.1.72/* /usr/share/xml/scap/ssg/content/ && \
    rm -rf /app/openscap-content && \
    apt-get remove -y unzip && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r compliance && useradd -r -g compliance -d /app -s /sbin/nologin compliance

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY src/ ./src/
COPY config/ ./config/

# Create necessary directories
RUN mkdir -p /app/scan_results /app/keys /app/logs && \
    chown -R compliance:compliance /app

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Security: Run as non-root user
USER compliance

# Expose ports
EXPOSE 8000 9090

# Set environment variables
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

# Use entrypoint script
ENTRYPOINT ["/entrypoint.sh"]

# Default command
CMD ["python", "-m", "src.main"]