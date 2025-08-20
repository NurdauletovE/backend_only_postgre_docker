#!/bin/bash

# Compliance Client Setup Script
# This script helps set up the compliance client on a new machine

set -e

echo "==========================================="
echo "Compliance Client Setup Script"
echo "==========================================="

# Check Python version
echo "Checking Python version..."
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "Found Python $PYTHON_VERSION"

if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
    echo "✓ Python version is compatible"
else
    echo "✗ Python 3.8 or higher is required"
    exit 1
fi

# Check if pip is available
echo "Checking pip availability..."
if command -v pip3 &> /dev/null; then
    echo "✓ pip3 is available"
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    echo "✓ pip is available"
    PIP_CMD="pip"
else
    echo "✗ pip is not available. Please install pip first."
    exit 1
fi

# Install basic requirements
echo "Installing basic requirements..."
$PIP_CMD install -r requirements.txt

echo "Checking if aiohttp is needed..."
read -p "Do you want async client support? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Installing async dependencies..."
    $PIP_CMD install aiohttp aiofiles
    echo "✓ Async dependencies installed"
else
    echo "Skipping async dependencies (you can install them later with: pip install aiohttp aiofiles)"
fi

# Verify installation
echo "Verifying installation..."
python3 check_requirements.py

echo ""
echo "==========================================="
echo "Setup Complete!"
echo "==========================================="
echo ""
echo "Next steps:"
echo "1. Edit the client configuration in your chosen client file"
echo "2. Update BASE_URL and API_KEY variables"
echo "3. Test the connection:"
echo "   python3 compliance_cli.py health"
echo ""
echo "For detailed usage instructions, see:"
echo "- INSTALLATION_GUIDE.md"
echo "- CLIENT_USAGE_GUIDE.md"
echo ""
echo "Quick test:"
echo "  python3 simple_compliance_client.py --health"
echo ""
