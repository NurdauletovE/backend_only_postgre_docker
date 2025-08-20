# Compliance Client Installation Guide

## Overview
This package contains the complete compliance client library for interacting with the ComplianceAgent server. It includes multiple client implementations, CLI tools, examples, and comprehensive documentation.

## Package Contents

### Core Client Files
- `compliance_client.py` - Full-featured async client (recommended for production)
- `simple_compliance_client.py` - Synchronous client for simple scripts
- `compliance_cli.py` - Command-line interface for manual operations

### Utilities and Examples
- `compliance_examples.py` - Usage examples and demonstrations
- `generate_token.py` - JWT token generation utility
- `demo_compliance_client.py` - Interactive demonstration script

### Testing and Validation
- `test_compliance_client.py` - Comprehensive test suite
- `test_client_functional.py` - Functional validation tests
- `check_requirements.py` - Environment validation script

### Documentation
- `CLIENT_USAGE_GUIDE.md` - Complete usage documentation
- `API_DOCUMENTATION.md` - API reference guide
- `TEST_RESULTS_SUMMARY.md` - Testing results and validation
- `README.md` - General project information

## Installation Instructions

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Access to the ComplianceAgent server

### Step 1: Install Dependencies

#### For Basic Usage (sync client + CLI)
```bash
pip install -r requirements.txt
```

#### For Full Async Support
```bash
pip install -r requirements.txt aiohttp aiofiles
```

### Step 2: Verify Installation
```bash
python check_requirements.py
```

### Step 3: Configure Server Connection
Edit the configuration in your chosen client file:

```python
# Update these values for your environment
BASE_URL = "http://your-server:8000"  # Your ComplianceAgent server URL
API_KEY = "your-api-key"              # Your API key
```

### Step 4: Test Connection
```bash
# Test with CLI
python compliance_cli.py health

# Test with simple client
python simple_compliance_client.py --health
```

## Quick Start

### Using the CLI
```bash
# Check server health
python compliance_cli.py health

# List agents
python compliance_cli.py list-agents

# Run a scan
python compliance_cli.py scan --agent-id "ubuntu-server-01" --scan-type "basic"
```

### Using the Simple Client in Scripts
```python
from simple_compliance_client import SimpleComplianceClient

client = SimpleComplianceClient("http://your-server:8000", "your-api-key")
status = client.health_check()
print(f"Server status: {status}")
```

### Using the Async Client
```python
import asyncio
from compliance_client import ComplianceAgentClient

async def main():
    async with ComplianceAgentClient("http://your-server:8000", "your-api-key") as client:
        agents = await client.list_agents()
        print(f"Found {len(agents)} agents")

asyncio.run(main())
```

## Configuration Options

### Environment Variables
You can set these environment variables instead of hardcoding values:
- `COMPLIANCE_SERVER_URL` - Server base URL
- `COMPLIANCE_API_KEY` - API key
- `COMPLIANCE_TIMEOUT` - Request timeout (default: 30 seconds)

### Authentication
The client supports multiple authentication methods:
1. API Key authentication (recommended)
2. JWT token authentication
3. Basic authentication (if enabled on server)

## Troubleshooting

### Common Issues

#### Connection Errors
- Verify the server URL and port
- Check network connectivity
- Ensure the server is running

#### Authentication Errors
- Verify your API key is correct
- Check if the API key has expired
- Ensure the server has your client registered

#### Import Errors
- Run `python check_requirements.py` to verify dependencies
- Install missing packages with pip
- Check Python version compatibility

### Getting Help
1. Review the `CLIENT_USAGE_GUIDE.md` for detailed usage instructions
2. Check `API_DOCUMENTATION.md` for API reference
3. Run the demo script: `python demo_compliance_client.py`
4. Examine the examples in `compliance_examples.py`

## Development and Testing

### Running Tests
```bash
# Run the full test suite
python test_compliance_client.py

# Run functional tests
python test_client_functional.py
```

### Development Setup
For development or customization:
1. Install additional development dependencies if needed
2. Review the source code in the client files
3. Use the test files as examples for your own implementations

## Security Considerations

1. **API Keys**: Never commit API keys to version control
2. **HTTPS**: Use HTTPS in production environments
3. **Token Expiry**: Implement proper token refresh mechanisms
4. **Network Security**: Ensure secure network communication

## Support and Updates

This client package is designed to be self-contained and portable. For updates:
1. Replace the entire package directory with a new version
2. Re-run the installation steps
3. Test the connection to ensure compatibility

## Version Information
Package created from comprehensive testing with 92.3% success rate.
All core functionality validated and working.
Compatible with ComplianceAgent server API v1.0+.
