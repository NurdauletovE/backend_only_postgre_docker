# 🚀 Operations & Deployment Guide

## 📋 Overview

This comprehensive operations guide covers deployment, monitoring, maintenance, and troubleshooting procedures for the Security Compliance Automation Agent in production environments.

---

## 🏗️ Deployment Strategies

### 1. Development Environment

#### Quick Start with Docker Compose
```bash
# Clone repository
git clone https://github.com/NurdauletovE/backend_only_postgre_docker.git
cd backend_only_postgre_docker

# Create environment file
cp config/.env.example .env
vim .env  # Configure your settings

# Generate JWT keys
mkdir -p keys
openssl genpkey -algorithm RSA -out keys/private_unencrypted.pem
openssl rsa -in keys/private_unencrypted.pem -pubout -out keys/public_unencrypted.pem

# Start services
docker-compose up -d

# Verify deployment
curl http://localhost:8000/health
```

#### Native Python Deployment
```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3.12 python3.12-venv postgresql-client

# Create virtual environment
python3.12 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Configure environment
export DATABASE_URL="postgresql://compliance:password@localhost:5440/compliance_db"
export JWT_PRIVATE_KEY_PATH="./keys/private_unencrypted.pem"
export JWT_PUBLIC_KEY_PATH="./keys/public_unencrypted.pem"

# Start application
python src/main.py
```

### 2. Production Environment

#### High Availability Setup
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  # Load Balancer
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - compliance-app-1
      - compliance-app-2

  # Application Instances
  compliance-app-1:
    build: .
    environment:
      - DATABASE_URL=postgresql://compliance:${DB_PASSWORD}@postgres-primary:5432/compliance_db
      - REDIS_URL=redis://redis-cluster:6379
      - API_PORT=8000
    depends_on:
      - postgres-primary
      - redis-cluster

  compliance-app-2:
    build: .
    environment:
      - DATABASE_URL=postgresql://compliance:${DB_PASSWORD}@postgres-primary:5432/compliance_db
      - REDIS_URL=redis://redis-cluster:6379
      - API_PORT=8000
    depends_on:
      - postgres-primary
      - redis-cluster

  # Database Cluster
  postgres-primary:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: compliance_db
      POSTGRES_USER: compliance
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_REPLICATION_USER: replicator
      POSTGRES_REPLICATION_PASSWORD: ${REPLICATION_PASSWORD}
    volumes:
      - postgres_primary_data:/var/lib/postgresql/data
      - ./postgresql.conf:/etc/postgresql/postgresql.conf

  postgres-replica:
    image: postgres:15-alpine
    environment:
      PGUSER: replicator
      POSTGRES_PASSWORD: ${REPLICATION_PASSWORD}
      POSTGRES_MASTER_SERVICE: postgres-primary
    depends_on:
      - postgres-primary

  # Cache Cluster
  redis-cluster:
    image: redis:7-alpine
    command: redis-server --appendonly yes --cluster-enabled yes
    volumes:
      - redis_data:/data

  # Monitoring
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    volumes:
      - grafana_data:/var/lib/grafana

volumes:
  postgres_primary_data:
  redis_data:
  prometheus_data:
  grafana_data:
```

#### Kubernetes Deployment
```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: compliance-agent
  labels:
    app: compliance-agent
spec:
  replicas: 3
  selector:
    matchLabels:
      app: compliance-agent
  template:
    metadata:
      labels:
        app: compliance-agent
    spec:
      containers:
      - name: compliance-agent
        image: compliance-agent:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: compliance-secrets
              key: database-url
        - name: JWT_PRIVATE_KEY_PATH
          value: "/etc/keys/private.pem"
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: jwt-keys
          mountPath: /etc/keys
          readOnly: true
      volumes:
      - name: jwt-keys
        secret:
          secretName: jwt-keys
---
apiVersion: v1
kind: Service
metadata:
  name: compliance-agent-service
spec:
  selector:
    app: compliance-agent
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8000
  type: LoadBalancer
```

---

## 🔧 Configuration Management

### Environment Variables
```bash
# Core Application
APP_NAME=compliance-agent
APP_VERSION=1.0.0
APP_ENVIRONMENT=production

# Database Configuration
DATABASE_URL=postgresql://compliance:secure_password@db-cluster:5432/compliance_db
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=30
DATABASE_POOL_TIMEOUT=30

# Redis Configuration
REDIS_URL=redis://redis-cluster:6379/0
REDIS_MAX_CONNECTIONS=100

# JWT Configuration
JWT_PRIVATE_KEY_PATH=/etc/keys/private.pem
JWT_PUBLIC_KEY_PATH=/etc/keys/public.pem
JWT_ALGORITHM=RS256
JWT_EXPIRATION_HOURS=24

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4
API_MAX_REQUEST_SIZE=10485760

# Monitoring
PROMETHEUS_HOST=0.0.0.0
PROMETHEUS_PORT=9090
METRICS_ENABLED=true

# Scanning Configuration
SCAN_SCHEDULE=0 */4 * * *
DEFAULT_PROFILE=cis_ubuntu2204
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT_MINUTES=30

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE=/var/log/compliance-agent/app.log
LOG_MAX_SIZE=100MB
LOG_BACKUP_COUNT=5

# Security
CORS_ORIGINS=https://compliance.example.com
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=1000
RATE_LIMIT_WINDOW=3600

# External Integrations
SIEM_ENABLED=false
SIEM_KAFKA_BROKERS=kafka-cluster:9092
SIEM_TOPIC=security-events

# Backup Configuration
BACKUP_ENABLED=true
BACKUP_SCHEDULE=0 2 * * *
BACKUP_RETENTION_DAYS=30
BACKUP_S3_BUCKET=compliance-backups
```

### Secrets Management
```bash
# Using Kubernetes Secrets
kubectl create secret generic compliance-secrets \
  --from-literal=database-url="postgresql://compliance:secure_password@db:5432/compliance_db" \
  --from-literal=jwt-private-key="$(cat keys/private.pem)" \
  --from-literal=jwt-public-key="$(cat keys/public.pem)"

# Using Docker Secrets
echo "postgresql://compliance:secure_password@db:5432/compliance_db" | docker secret create db_url -
echo "$(cat keys/private.pem)" | docker secret create jwt_private_key -
```

---

## 📊 Monitoring & Alerting

### Prometheus Metrics
```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

scrape_configs:
  - job_name: 'compliance-agent'
    static_configs:
      - targets: ['compliance-app:9090']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['postgres-exporter:9187']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Alert Rules
```yaml
# alert_rules.yml
groups:
- name: compliance_agent_alerts
  rules:
  - alert: ComplianceAgentDown
    expr: up{job="compliance-agent"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Compliance Agent is down"
      description: "The compliance agent has been down for more than 1 minute"

  - alert: HighScanFailureRate
    expr: rate(compliance_scan_failures_total[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High scan failure rate detected"
      description: "Scan failure rate is {{ $value }} failures per second"

  - alert: LowComplianceScore
    expr: compliance_score_percentage < 70
    for: 0m
    labels:
      severity: warning
    annotations:
      summary: "Low compliance score detected"
      description: "System {{ $labels.system_id }} has compliance score of {{ $value }}%"

  - alert: DatabaseConnectionsHigh
    expr: postgresql_stat_database_numbackends > 80
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High database connection count"
      description: "Database has {{ $value }} active connections"
```

### Grafana Dashboards
```json
{
  "dashboard": {
    "title": "Compliance Agent Overview",
    "panels": [
      {
        "title": "System Compliance Scores",
        "type": "stat",
        "targets": [
          {
            "expr": "avg(compliance_score_percentage)",
            "legendFormat": "Average Score"
          }
        ]
      },
      {
        "title": "Scan Success Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(compliance_scans_successful_total[1h]) / rate(compliance_scans_total[1h]) * 100",
            "legendFormat": "Success Rate %"
          }
        ]
      },
      {
        "title": "API Response Times",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th Percentile"
          }
        ]
      }
    ]
  }
}
```

---

## 🔄 Backup & Recovery

### Database Backup
```bash
#!/bin/bash
# backup-database.sh

set -e

BACKUP_DIR="/var/backups/compliance"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="compliance_db"
DB_USER="compliance"
DB_HOST="localhost"
DB_PORT="5440"

# Create backup directory
mkdir -p $BACKUP_DIR

# Perform backup
pg_dump -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME \
  --verbose --clean --no-owner --no-privileges \
  | gzip > $BACKUP_DIR/compliance_db_$DATE.sql.gz

# Upload to S3 (optional)
if [ "$BACKUP_S3_ENABLED" = "true" ]; then
  aws s3 cp $BACKUP_DIR/compliance_db_$DATE.sql.gz \
    s3://$BACKUP_S3_BUCKET/database/compliance_db_$DATE.sql.gz
fi

# Cleanup old backups (keep last 30 days)
find $BACKUP_DIR -name "compliance_db_*.sql.gz" -mtime +30 -delete

echo "Backup completed: compliance_db_$DATE.sql.gz"
```

### Application State Backup
```bash
#!/bin/bash
# backup-application.sh

BACKUP_DIR="/var/backups/compliance"
DATE=$(date +%Y%m%d_%H%M%S)

# Backup JWT keys
tar -czf $BACKUP_DIR/keys_$DATE.tar.gz -C /etc/compliance keys/

# Backup configuration
tar -czf $BACKUP_DIR/config_$DATE.tar.gz -C /etc/compliance config/

# Backup scan results
tar -czf $BACKUP_DIR/scan_results_$DATE.tar.gz -C /var/lib/compliance scan_results/

# Backup logs
tar -czf $BACKUP_DIR/logs_$DATE.tar.gz -C /var/log compliance-agent/

echo "Application backup completed: $DATE"
```

### Recovery Procedures
```bash
#!/bin/bash
# recover-database.sh

BACKUP_FILE=$1
DB_NAME="compliance_db"

if [ -z "$BACKUP_FILE" ]; then
  echo "Usage: $0 <backup_file.sql.gz>"
  exit 1
fi

# Stop application
systemctl stop compliance-agent

# Restore database
zcat $BACKUP_FILE | psql -h localhost -p 5440 -U compliance -d $DB_NAME

# Start application
systemctl start compliance-agent

echo "Recovery completed from $BACKUP_FILE"
```

---

## 🚦 Health Checks & Monitoring

### Application Health Checks
```python
# health_check.py
import aiohttp
import asyncio
import sys

async def check_health():
    """Comprehensive health check script"""
    checks = []
    
    # API Health
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://localhost:8000/health') as resp:
                if resp.status == 200:
                    checks.append(("API", "HEALTHY"))
                else:
                    checks.append(("API", f"UNHEALTHY - {resp.status}"))
    except Exception as e:
        checks.append(("API", f"UNHEALTHY - {e}"))
    
    # Database Health
    try:
        import asyncpg
        conn = await asyncpg.connect("postgresql://compliance:password@localhost:5440/compliance_db")
        await conn.fetchval("SELECT 1")
        await conn.close()
        checks.append(("Database", "HEALTHY"))
    except Exception as e:
        checks.append(("Database", f"UNHEALTHY - {e}"))
    
    # Print results
    all_healthy = True
    for service, status in checks:
        print(f"{service}: {status}")
        if "UNHEALTHY" in status:
            all_healthy = False
    
    return 0 if all_healthy else 1

if __name__ == "__main__":
    exit_code = asyncio.run(check_health())
    sys.exit(exit_code)
```

### System Resource Monitoring
```bash
#!/bin/bash
# system-monitor.sh

# CPU Usage
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
echo "CPU Usage: ${CPU_USAGE}%"

# Memory Usage
MEMORY_USAGE=$(free | grep Mem | awk '{printf "%.2f", $3/$2 * 100.0}')
echo "Memory Usage: ${MEMORY_USAGE}%"

# Disk Usage
DISK_USAGE=$(df -h / | tail -1 | awk '{print $5}' | cut -d'%' -f1)
echo "Disk Usage: ${DISK_USAGE}%"

# Database Connections
DB_CONNECTIONS=$(psql -h localhost -p 5440 -U compliance -d compliance_db -t -c "SELECT count(*) FROM pg_stat_activity;")
echo "Database Connections: $DB_CONNECTIONS"

# Application Processes
APP_PROCESSES=$(pgrep -f "compliance-agent" | wc -l)
echo "Application Processes: $APP_PROCESSES"
```

---

## 🐛 Troubleshooting Guide

### Common Issues

#### 1. Application Won't Start
```bash
# Check logs
journalctl -u compliance-agent -f

# Common causes:
# - Database connection issues
# - Missing JWT keys
# - Port conflicts
# - Permission issues

# Solutions:
# Check database connectivity
pg_isready -h localhost -p 5440 -U compliance

# Verify JWT keys exist and are readable
ls -la /etc/compliance/keys/
```

#### 2. High Memory Usage
```bash
# Check memory usage by process
ps aux --sort=-%mem | head -10

# Check for memory leaks
valgrind --tool=memcheck --leak-check=yes python src/main.py

# Solutions:
# - Increase server memory
# - Tune database connection pool
# - Enable memory profiling
```

#### 3. Slow API Responses
```bash
# Check database performance
psql -h localhost -p 5440 -U compliance -d compliance_db -c "
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;"

# Check connection pool status
# Enable slow query logging
# Optimize database queries
```

#### 4. Scan Failures
```bash
# Check OpenSCAP installation
oscap --version

# Verify scan content
ls -la /usr/share/xml/scap/ssg/content/

# Check system permissions
sudo -u compliance-agent oscap info /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
```

### Log Analysis
```bash
# Real-time log monitoring
tail -f /var/log/compliance-agent/app.log | jq '.'

# Error filtering
grep "ERROR" /var/log/compliance-agent/app.log | jq '.message'

# Performance analysis
grep "duration" /var/log/compliance-agent/app.log | jq '.duration'

# Security events
grep "authentication" /var/log/compliance-agent/app.log | jq '.'
```

---

## 🔄 Maintenance Procedures

### Regular Maintenance Tasks

#### Daily
```bash
# Check system health
./health_check.py

# Monitor resource usage
./system-monitor.sh

# Review error logs
grep "ERROR" /var/log/compliance-agent/app.log | tail -20
```

#### Weekly
```bash
# Database maintenance
psql -h localhost -p 5440 -U compliance -d compliance_db -c "VACUUM ANALYZE;"

# Log rotation
logrotate /etc/logrotate.d/compliance-agent

# Update compliance content
sudo apt update && sudo apt upgrade ssg-*
```

#### Monthly
```bash
# Security updates
sudo apt update && sudo apt upgrade

# Certificate renewal
certbot renew

# Performance review
./generate-performance-report.sh

# Capacity planning review
./capacity-analysis.sh
```

### Database Maintenance
```sql
-- Cleanup old scan results (older than 1 year)
DELETE FROM rule_results 
WHERE scan_id IN (
    SELECT id FROM compliance_scans 
    WHERE scan_timestamp < NOW() - INTERVAL '1 year'
);

DELETE FROM compliance_scans 
WHERE scan_timestamp < NOW() - INTERVAL '1 year';

-- Cleanup expired attestations
DELETE FROM attestations 
WHERE expires_at < NOW() - INTERVAL '30 days';

-- Update statistics
ANALYZE;

-- Rebuild indexes if needed
REINDEX DATABASE compliance_db;
```

---

## 🔒 Security Hardening

### System Hardening
```bash
# Firewall configuration
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 8000/tcp  # API
ufw allow 9090/tcp  # Metrics
ufw allow 5440/tcp  # Database
ufw enable

# Disable unnecessary services
systemctl disable apache2
systemctl disable cups
systemctl disable bluetooth

# Secure SSH
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
systemctl restart ssh

# File permissions
chmod 600 /etc/compliance/keys/*
chown compliance-agent:compliance-agent /etc/compliance/keys/*
```

### Application Security
```bash
# Run as non-root user
useradd -r -s /bin/false compliance-agent

# Secure configuration files
chmod 640 /etc/compliance/config/*
chown root:compliance-agent /etc/compliance/config/*

# Enable SELinux/AppArmor
setenforce 1  # CentOS/RHEL
aa-enforce /etc/apparmor.d/compliance-agent  # Ubuntu
```

This comprehensive operations guide provides all the necessary procedures for successfully deploying, monitoring, and maintaining the Security Compliance Automation Agent in production environments.
