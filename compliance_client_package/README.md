# Security Compliance Automation Agent

A standalone Python-based security compliance automation agent that performs scheduled CIS compliance scans using OpenSCAP, creates signed attestations, and submits them to compliance authority servers.

## Features

- **OpenSCAP Integration**: Automated CIS benchmark compliance scanning
- **JWT Attestation**: Cryptographically signed compliance attestations using RSA-2048
- **Plugin Architecture**: Extensible framework for different compliance standards
- **REST API**: Comprehensive API for compliance management and attestation
- **Real-time Monitoring**: Prometheus metrics and Grafana dashboards
- **SIEM Integration**: Kafka-based event streaming for security infrastructure
- **Database Storage**: PostgreSQL backend with comprehensive audit trails
- **Container Ready**: Docker and Kubernetes deployment configurations
- **Security Hardened**: Zero Trust architecture with comprehensive security controls

## Quick Start

### Using Docker Compose

1. **Clone and Setup**:
```bash
git clone <repository>
cd compliance-agent
cp config/.env.example config/.env
# Edit config/.env with your settings
```

2. **Start the Stack**:
```bash
# Start core services
docker-compose up -d

# Start with SIEM integration
docker-compose --profile siem up -d

# Start with reverse proxy
docker-compose --profile proxy up -d
```

3. **Access Services**:
- API: http://localhost:8000
- Grafana: http://localhost:3000 (admin/admin_password_2024)
- Prometheus: http://localhost:9091

### Using Kubernetes

1. **Deploy to Kubernetes**:
```bash
# Deploy using Kustomize
kubectl apply -k k8s/

# Or deploy individual manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/compliance-agent.yaml
kubectl apply -f k8s/monitoring.yaml
```

2. **Access Services**:
```bash
# Port forward API
kubectl port-forward -n compliance-system svc/compliance-agent 8000:8000

# Port forward Grafana
kubectl port-forward -n compliance-system svc/grafana 3000:3000
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `JWT_PRIVATE_KEY_PATH` | Path to RSA private key | `/app/keys/private.pem` |
| `JWT_PUBLIC_KEY_PATH` | Path to RSA public key | `/app/keys/public.pem` |
| `OPENSCAP_CONTENT_PATH` | OpenSCAP content directory | `/usr/share/xml/scap/ssg/content/` |
| `DEFAULT_SCAN_PROFILE` | Default compliance profile | `xccdf_org.ssgproject.content_profile_cis` |
| `SCAN_INTERVAL` | Scan interval in seconds | `3600` |
| `MAX_CONCURRENT_SCANS` | Maximum concurrent scans | `3` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `LOG_FORMAT` | Log format (json/detailed) | `json` |
| `ENABLE_METRICS` | Enable Prometheus metrics | `true` |
| `KAFKA_BOOTSTRAP_SERVERS` | Kafka servers for SIEM | Optional |

### CIS Compliance Profiles

The agent supports multiple CIS benchmark profiles:

- `xccdf_org.ssgproject.content_profile_cis` - CIS Benchmark Level 1
- `xccdf_org.ssgproject.content_profile_cis_server_l1` - CIS Server Level 1
- `xccdf_org.ssgproject.content_profile_cis_server_l2` - CIS Server Level 2
- `xccdf_org.ssgproject.content_profile_cis_workstation_l1` - CIS Workstation Level 1
- `xccdf_org.ssgproject.content_profile_cis_workstation_l2` - CIS Workstation Level 2

## API Usage

### Authentication

All API endpoints require JWT authentication. Include the token in the Authorization header:

```bash
curl -H "Authorization: Bearer <jwt-token>" http://localhost:8000/health
```

### Key Endpoints

#### Execute a Compliance Scan
```bash
curl -X POST http://localhost:8000/scans \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "profile": "xccdf_org.ssgproject.content_profile_cis",
    "plugin": "CIS"
  }'
```

#### Generate Attestation
```bash
curl -X POST http://localhost:8000/attestations \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "scan-uuid-here"
  }'
```

#### Get Compliance Status
```bash
curl http://localhost:8000/systems/{system_id}/compliance \
  -H "Authorization: Bearer <jwt-token>"
```

#### Get Dashboard Data
```bash
curl http://localhost:8000/dashboard \
  -H "Authorization: Bearer <jwt-token>"
```

## Development

### Local Development Setup

1. **Install Dependencies**:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

pip install -r requirements.txt
```

2. **Install OpenSCAP** (Ubuntu/Debian):
```bash
sudo apt-get update
sudo apt-get install -y libopenscap25t64 openscap-utils openscap-scanner ssg-base
```

3. **Setup Database**:
```bash
# Using Docker
docker run -d --name postgres \
  -e POSTGRES_DB=compliance_db \
  -e POSTGRES_USER=compliance \
  -e POSTGRES_PASSWORD=compliance_password \
  -p 5432:5432 \
  postgres:15-alpine

# Initialize schema
psql -h localhost -U compliance -d compliance_db -f src/db/schema.sql
```

4. **Configure Environment**:
```bash
export DATABASE_URL="postgresql://compliance:compliance_password@localhost:5432/compliance_db"
export JWT_PRIVATE_KEY_PATH="./keys/private.pem"
export JWT_PUBLIC_KEY_PATH="./keys/public.pem"
export LOG_LEVEL="DEBUG"
```

5. **Run the Agent**:
```bash
python src/main.py
```

### Testing

```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=src tests/

# Run specific test categories
pytest -m "unit" tests/     # Unit tests only
pytest -m "integration" tests/  # Integration tests only
```

## Monitoring and Observability

### Prometheus Metrics

The agent exposes comprehensive metrics on port 9090:

- `compliance_scans_total` - Total compliance scans executed
- `compliance_score` - Current compliance score per system
- `compliance_rules_failed` - Failed compliance rules by severity
- `compliance_agent_uptime_seconds` - Agent uptime
- `compliance_api_requests_total` - API request metrics

### Grafana Dashboards

Pre-configured Grafana dashboards include:

- **Compliance Overview**: System-wide compliance status and trends
- **Scan Performance**: Scan execution times and success rates
- **Security Alerts**: Critical compliance violations and alerts
- **System Health**: Agent and infrastructure health metrics

### Alerting

Prometheus alerting rules monitor:

- Low compliance scores (< 70%)
- Critical compliance scores (< 50%)
- Scan failures
- Agent downtime
- High resource usage

## Security Features

### Zero Trust Architecture

- **Mutual TLS**: Encrypted communication between components
- **JWT Signatures**: RSA-2048 signed attestations
- **Input Validation**: Comprehensive input sanitization
- **Audit Logging**: Immutable audit trails for all actions
- **Least Privilege**: Minimal required permissions

### Security Hardening

- **Non-root Execution**: Containers run as non-privileged users
- **File Permissions**: Secure key file permissions (600/644)
- **Network Policies**: Kubernetes network isolation
- **Secret Management**: Kubernetes secrets for sensitive data
- **Log Sanitization**: Automatic sensitive data masking

### Compliance Standards

- **CIS Controls**: Center for Internet Security benchmarks
- **NIST Framework**: National Institute of Standards and Technology
- **PCI-DSS**: Payment Card Industry Data Security Standard
- **STIG**: Security Technical Implementation Guides

## SIEM Integration

### Kafka Event Streaming

Events are sent to Kafka topics for SIEM consumption:

```json
{
  "event_id": "scan_12345",
  "event_type": "compliance_scan_completed",
  "timestamp": "2024-01-15T10:30:00Z",
  "system_id": "server-01",
  "severity": "medium",
  "compliance_data": {
    "scan_id": "12345",
    "compliance_score": 75.5,
    "failed_rules": 12,
    "total_rules": 150
  }
}
```

### Security Infrastructure APIs

Integration with existing security tools:

- **Vulnerability Management**: Submit compliance findings
- **Incident Response**: Create security incidents for critical failures
- **SOAR Platforms**: Trigger automated remediation workflows

## Production Deployment

### High Availability

- **Database**: PostgreSQL with replication
- **Application**: Multiple agent replicas with load balancing
- **Monitoring**: Redundant Prometheus and Grafana instances
- **Storage**: Persistent volumes for data and logs

### Scaling

- **Horizontal Pod Autoscaling**: Automatic scaling based on CPU/memory
- **Database Sharding**: Scale database for large deployments
- **Kafka Partitioning**: Distribute SIEM events across partitions

### Backup and Recovery

- **Database Backups**: Automated PostgreSQL backups
- **Configuration Backup**: GitOps for infrastructure as code
- **Key Management**: Secure backup of cryptographic keys

## Troubleshooting

### Common Issues

1. **OpenSCAP Content Missing**:
```bash
# Install SCAP content
sudo apt-get install scap-security-guide

# Verify content location
ls /usr/share/xml/scap/ssg/content/
```

2. **Database Connection Issues**:
```bash
# Check connection
psql $DATABASE_URL -c "SELECT 1"

# Check database logs
docker logs postgres
```

3. **Key Generation Failures**:
```bash
# Generate keys manually
openssl genpkey -algorithm RSA -out private.pem -pkcs8
openssl rsa -pubout -in private.pem -out public.pem

# Set correct permissions
chmod 600 private.pem
chmod 644 public.pem
```

### Logs and Debugging

- **Application Logs**: `/app/logs/compliance-agent.log`
- **API Logs**: Structured JSON logs via stdout
- **Audit Logs**: Separate audit trail in database
- **Debug Mode**: Set `LOG_LEVEL=DEBUG` for verbose logging

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run security and compliance checks
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:

- **Documentation**: [docs/](docs/)
- **Issues**: GitHub Issues
- **Security**: security@example.com