# Compliance Agent - Remote OpenSCAP Scanner

This is a containerized compliance agent that runs on remote systems to perform OpenSCAP security scans and send results to a central compliance API server.

## Features

- **OpenSCAP Integration**: Performs CIS benchmark compliance scanning using OpenSCAP tools
- **Automated Scanning**: Configurable scheduled scanning intervals
- **API Integration**: Submits scan results to centralized compliance API
- **Health Monitoring**: Built-in health check endpoint for monitoring
- **Manual Triggers**: Support for on-demand scan execution
- **Containerized**: Easy deployment using Docker containers
- **Multi-OS Support**: Supports Ubuntu, Debian, RHEL, CentOS systems

## Quick Start

### 1. Set Environment Variables

```bash
export COMPLIANCE_API_URL="http://your-compliance-server:8002"
export COMPLIANCE_API_TOKEN="your-api-token"  # Optional
export SCAN_INTERVAL="3600"  # 1 hour
```

### 2. Deploy Using Script

```bash
# Build and deploy the agent
./agent/scripts/deploy-agent.sh deploy

# Check status
./agent/scripts/deploy-agent.sh status

# View logs
./agent/scripts/deploy-agent.sh logs
```

### 3. Deploy Using Docker Compose

```bash
# Start the agent
docker-compose -f docker-compose-agent.yml up -d

# Check logs
docker-compose -f docker-compose-agent.yml logs -f
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPLIANCE_API_URL` | `http://host.docker.internal:8002` | URL of the compliance API server |
| `COMPLIANCE_API_TOKEN` | - | Authentication token for API access |
| `SCAN_INTERVAL` | `3600` | Scan interval in seconds (0 to disable) |
| `DEFAULT_PROFILE` | `xccdf_org.ssgproject.content_profile_cis` | Default compliance profile |
| `AGENT_PORT` | `8080` | Port for health check endpoint |
| `LOG_LEVEL` | `INFO` | Logging level |

### Compliance Profiles

Common CIS benchmark profiles:

- `xccdf_org.ssgproject.content_profile_cis` - General CIS profile
- `xccdf_org.ssgproject.content_profile_cis_level1_server` - CIS Level 1 Server
- `xccdf_org.ssgproject.content_profile_cis_level2_server` - CIS Level 2 Server
- `xccdf_org.ssgproject.content_profile_standard` - Standard security profile
- `xccdf_org.ssgproject.content_profile_stig` - STIG compliance profile

## API Endpoints

The agent exposes a simple API for monitoring and control:

### Health Check
```bash
GET /health
```

Response:
```json
{
    "status": "healthy",
    "timestamp": "2025-08-17T02:00:00Z",
    "version": "1.0.0"
}
```

### Manual Scan Trigger
```bash
POST /scan?profile=xccdf_org.ssgproject.content_profile_cis
```

Response:
```json
{
    "status": "completed",
    "scan_id": "uuid-here",
    "results": { ... }
}
```

## Usage Examples

### Basic Deployment

```bash
# Deploy with default settings
docker run -d \
  --name compliance-agent \
  --restart unless-stopped \
  -p 8080:8080 \
  -e COMPLIANCE_API_URL="http://your-server:8002" \
  --privileged \
  compliance-agent:latest
```

### Advanced Deployment with Custom Configuration

```bash
docker run -d \
  --name compliance-agent \
  --restart unless-stopped \
  -p 8080:8080 \
  -e COMPLIANCE_API_URL="http://your-server:8002" \
  -e COMPLIANCE_API_TOKEN="your-token" \
  -e SCAN_INTERVAL="7200" \
  -e DEFAULT_PROFILE="xccdf_org.ssgproject.content_profile_cis_level2_server" \
  -v /path/to/custom-content:/app/content \
  -v agent-logs:/app/logs \
  -v agent-results:/app/results \
  --privileged \
  compliance-agent:latest
```

### Manual Scan Execution

```bash
# Trigger a scan with default profile
curl -X POST http://localhost:8080/scan

# Trigger a scan with specific profile
curl -X POST "http://localhost:8080/scan?profile=xccdf_org.ssgproject.content_profile_cis_level1_server"

# Check agent health
curl http://localhost:8080/health
```

## Docker Compose Deployment

Create a `.env` file:
```bash
COMPLIANCE_API_URL=http://your-compliance-server:8002
COMPLIANCE_API_TOKEN=your-optional-token
SCAN_INTERVAL=3600
DEFAULT_PROFILE=xccdf_org.ssgproject.content_profile_cis
AGENT_PORT=8080
```

Then run:
```bash
docker-compose -f docker-compose-agent.yml up -d
```

## Security Considerations

### Privileged Mode

The agent runs in privileged mode to access system files for comprehensive scanning. For enhanced security:

1. **Use specific capabilities** instead of privileged mode when possible
2. **Limit network access** to only the compliance API
3. **Monitor agent logs** for suspicious activity
4. **Use read-only mounts** for sensitive directories

### Alternative Security Configuration

```yaml
# More secure but limited scanning capabilities
cap_add:
  - SYS_ADMIN
  - DAC_READ_SEARCH
security_opt:
  - apparmor:unconfined
# Remove: privileged: true
```

## Monitoring and Troubleshooting

### Check Agent Status

```bash
# Using deployment script
./agent/scripts/deploy-agent.sh status

# Direct health check
curl http://localhost:8080/health
```

### View Logs

```bash
# Container logs
docker logs compliance-agent -f

# Agent application logs
docker exec compliance-agent tail -f /app/logs/agent.log
```

### Common Issues

1. **OpenSCAP not found**: Ensure the container has proper SCAP content
2. **API connectivity**: Check network connectivity and API URL
3. **Permission denied**: Verify the agent has necessary privileges
4. **Scan failures**: Check SCAP content compatibility with target OS

### Debug Mode

```bash
# Run with debug logging
docker run -e LOG_LEVEL=DEBUG compliance-agent:latest
```

## Building from Source

```bash
# Build the image
docker build -f Dockerfile.agent -t compliance-agent:latest .

# Or use the script
./agent/scripts/deploy-agent.sh build
```

## Integration with Compliance API

The agent automatically submits scan results to the configured compliance API. Results include:

- System information (hostname, OS, hardware details)
- Scan metadata (timestamp, profile, scan ID)
- Compliance scores and rule results
- Raw OpenSCAP output for detailed analysis

## Support

For issues and questions:

1. Check the logs for error messages
2. Verify API connectivity and authentication
3. Ensure proper SCAP content is available
4. Check container privileges and security settings

## License

This compliance agent is part of the security compliance automation system.
