# Compliance Agent Client Usage Guide

## Overview

I've created a comprehensive Python client for the Compliance Automation Agent API with both asynchronous and synchronous versions. Here's everything you need to know to use them effectively.

## Available Client Files

### 1. `compliance_client.py` - Full-Featured Async Client
- Complete async implementation with all API features
- Support for system management, scanning, attestation, reporting
- Robust error handling and connection management
- Best for integration into async applications

### 2. `simple_compliance_client.py` - Synchronous Client
- Synchronous implementation for simple scripts
- Easy to use in traditional Python applications
- Command-line interface included
- Perfect for automation scripts and basic integrations

### 3. `compliance_cli.py` - Command Line Tool
- Full CLI interface for all operations
- Great for testing, automation, and manual operations
- Uses the simple synchronous client internally

### 4. `compliance_examples.py` - Practical Examples
- Real-world usage examples
- Common automation scenarios
- Best practices demonstrations

### 5. `generate_token.py` - JWT Token Generator
- Creates valid JWT tokens for API authentication
- Configurable expiration and claims
- Essential for testing and automation

## Authentication Setup

The API uses JWT tokens for authentication. Generate a token first:

```bash
# Generate a test token (valid for 1 week)
python3 generate_token.py --key-path keys/private_unencrypted.pem --hours 168

# This will output a JWT token like:
# eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Note**: The current API implementation has a token verification issue. For now, you can test non-authenticated endpoints like `/health` and work around authentication for development.

## Quick Start Examples

### 1. Health Check (No Authentication Required)
```bash
# CLI
python3 compliance_cli.py health

# Python script
from simple_compliance_client import quick_health_check
if quick_health_check("http://localhost:8000"):
    print("API is healthy")
```

### 2. Using the Simple Client
```python
from simple_compliance_client import SimpleComplianceClient, SimpleSystemInfo

# Create client with token
client = SimpleComplianceClient(
    base_url="http://localhost:8000",
    auth_token="your-jwt-token-here"
)

# Register a system
system_info = SimpleSystemInfo(
    system_id="web-server-01",
    hostname="web01.company.com",
    ip_address="192.168.1.100",
    operating_system="Ubuntu",
    os_version="22.04 LTS",
    environment="production"
)

# Register and scan
result = client.register_and_scan(system_info, wait_for_completion=True)
print(f"Scan completed: {result['scan_id']}")
```

### 3. Using the CLI Tool
```bash
# List systems (when auth is working)
python3 compliance_cli.py --token "your-jwt-token" list-systems

# Register a system
python3 compliance_cli.py --token "your-jwt-token" register web-01 \
    --hostname web01.company.com \
    --ip 192.168.1.100 \
    --os Ubuntu \
    --os-version "22.04 LTS" \
    --environment production

# Trigger a scan and wait for completion
python3 compliance_cli.py --token "your-jwt-token" scan web-01 \
    --wait --attestation --timeout 600

# Generate compliance report
python3 compliance_cli.py --token "your-jwt-token" report \
    --format json --output compliance_report.json
```

### 4. Automation Examples
```python
# Example: Daily compliance check script
from simple_compliance_client import SimpleComplianceClient

client = SimpleComplianceClient(auth_token="your-token")

# Get all systems
systems = client.get_systems()
for system in systems['systems']:
    system_id = system['system_id']
    
    # Trigger daily scan
    print(f"Scanning {system_id}...")
    result = client.scan_system_and_wait(
        system_id=system_id,
        generate_attestation=True
    )
    
    if result['scan_result']['status'] == 'completed':
        print(f"✅ {system_id} compliance scan successful")
        if 'attestation' in result:
            print(f"   Attestation: {result['attestation']['attestation_id']}")
    else:
        print(f"❌ {system_id} compliance scan failed")
```

## Advanced Usage

### Async Client Example
```python
import asyncio
from compliance_client import ComplianceAgentClient

async def compliance_workflow():
    client = ComplianceAgentClient(
        base_url="http://localhost:8000",
        auth_token="your-jwt-token"
    )
    
    # Bulk system registration
    systems = [
        {"system_id": "web-01", "hostname": "web01.company.com"},
        {"system_id": "db-01", "hostname": "db01.company.com"},
        {"system_id": "app-01", "hostname": "app01.company.com"}
    ]
    
    # Register all systems concurrently
    await client.bulk_register_systems(systems)
    
    # Scan all systems
    scan_ids = await client.bulk_scan_systems(
        [s["system_id"] for s in systems]
    )
    
    # Wait for all scans to complete
    results = await client.wait_for_scans(scan_ids)
    
    # Generate attestations for successful scans
    attestations = []
    for scan_id, result in results.items():
        if result['status'] == 'completed':
            attestation = await client.generate_attestation(scan_id)
            attestations.append(attestation)
    
    return attestations

# Run the workflow
attestations = asyncio.run(compliance_workflow())
```

### CI/CD Integration
```bash
#!/bin/bash
# CI/CD compliance check script

# Set environment variables
export COMPLIANCE_API_URL="http://compliance-server:8000"
export COMPLIANCE_TOKEN="your-jwt-token"
export SYSTEM_ID="build-server-${BUILD_NUMBER}"

# Register current build environment
python3 compliance_cli.py --url "$COMPLIANCE_API_URL" --token "$COMPLIANCE_TOKEN" \
    register "$SYSTEM_ID" \
    --hostname "$(hostname)" \
    --ip "$(hostname -I | awk '{print $1}')" \
    --os "$(lsb_release -si)" \
    --os-version "$(lsb_release -sr)" \
    --environment "ci-cd"

# Run compliance scan
python3 compliance_cli.py --url "$COMPLIANCE_API_URL" --token "$COMPLIANCE_TOKEN" \
    scan "$SYSTEM_ID" --wait --timeout 300

# Check scan results and fail build if non-compliant
SCAN_STATUS=$(python3 compliance_cli.py --url "$COMPLIANCE_API_URL" --token "$COMPLIANCE_TOKEN" \
    list-scans --system-id "$SYSTEM_ID" --json | jq -r '.scans[0].status')

if [ "$SCAN_STATUS" != "completed" ]; then
    echo "❌ Compliance scan failed: $SCAN_STATUS"
    exit 1
fi

echo "✅ Compliance check passed"
```

## Configuration

### Environment Variables
```bash
# Server Configuration
export COMPLIANCE_API_URL="http://localhost:8000"
export COMPLIANCE_AUTH_TOKEN="your-jwt-token"

# Client Configuration
export COMPLIANCE_TIMEOUT=300
export COMPLIANCE_RETRY_COUNT=3
export COMPLIANCE_VERIFY_SSL=true
```

### Client Configuration File
```python
# config.py
COMPLIANCE_CONFIG = {
    "base_url": "http://localhost:8000",
    "timeout": 300,
    "retry_count": 3,
    "verify_ssl": True,
    "auth_token": "your-jwt-token-here"
}
```

## Authentication Troubleshooting

Currently, there's an issue with JWT token verification in the API. Here are some workarounds:

1. **For Development**: Test with non-authenticated endpoints like `/health`
2. **For Token Generation**: Use `generate_token.py` to create valid tokens
3. **For Testing**: The token format is correct, but the API verification needs fixing

### Expected Token Format
```json
{
  "iss": "compliance-agent",
  "sub": "admin",
  "aud": "compliance-authority",
  "iat": 1753392240,
  "exp": 1753997040,
  "system_id": "test-system",
  "role": "admin",
  "permissions": ["read", "write", "scan", "attest"]
}
```

## Available API Endpoints

The clients support all these endpoints:

- `GET /health` - Health check (no auth required)
- `GET /systems` - List registered systems
- `POST /systems` - Register a new system
- `GET /systems/{system_id}` - Get system details
- `POST /scans` - Trigger compliance scan
- `GET /scans` - List scans
- `GET /scans/{scan_id}` - Get scan details
- `POST /attestations` - Generate attestation
- `POST /attestations/verify` - Verify attestation
- `GET /reports/compliance` - Generate compliance report
- `GET /dashboard` - Get dashboard data
- `GET /failed-rules` - Get failed compliance rules
- `GET /plugins` - List available plugins
- `GET /agent/status` - Get agent status

## Error Handling

The clients include comprehensive error handling:

```python
try:
    result = client.trigger_scan("system-01")
except Exception as e:
    if "Authentication failed" in str(e):
        print("Please check your JWT token")
    elif "Not Found" in str(e):
        print("System not registered")
    else:
        print(f"Unexpected error: {e}")
```

## Best Practices

1. **Token Management**: Store tokens securely and rotate regularly
2. **Error Handling**: Always wrap API calls in try/catch blocks
3. **Timeouts**: Set appropriate timeouts for long-running scans
4. **Logging**: Enable logging for debugging and monitoring
5. **Rate Limiting**: Implement rate limiting for bulk operations
6. **Retries**: Use exponential backoff for failed requests

## Next Steps

1. **Fix Authentication**: Resolve the JWT token verification issue in the API
2. **Test Thoroughly**: Test all client functions once authentication works
3. **Deploy**: Use the clients in your automation and monitoring systems
4. **Monitor**: Set up monitoring for compliance status and alerts
5. **Integrate**: Connect with your CI/CD pipeline and security tools

The clients are ready for use once the authentication issue is resolved. They provide a complete interface to the Compliance Automation Agent API with both simple and advanced usage patterns.
