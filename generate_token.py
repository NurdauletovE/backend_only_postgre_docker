#!/usr/bin/env python3
"""
Token Generator for Testing

Generates test JWT tokens for API authentication.
"""

import jwt
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path


def generate_test_token(
    system_id="test-system",
    user_id="test-user", 
    validity_hours=24,
    private_key_path="keys/jwt_private_key.pem"
):
    """Generate a test JWT token"""
    
    # Load private key
    key_path = Path(private_key_path)
    if not key_path.exists():
        raise FileNotFoundError(f"Private key not found: {private_key_path}")
    
    with open(key_path, 'rb') as f:
        private_key = f.read()
    
    # Create payload
    now = datetime.now(timezone.utc)
    payload = {
        "iss": "compliance-agent",
        "sub": user_id,
        "aud": "compliance-authority",  # Must match JWT_AUDIENCE in .env
        "iat": now,
        "exp": now + timedelta(hours=validity_hours),
        "system_id": system_id,
        "role": "admin",
        "permissions": ["read", "write", "scan", "attest"]
    }
    
    # Generate token
    token = jwt.encode(payload, private_key, algorithm="RS256")
    
    return token


def create_simple_auth_token():
    """Create a simple test token for API access"""
    try:
        token = generate_test_token(
            system_id="test-client",
            user_id="admin", 
            validity_hours=168  # 1 week
        )
        
        print("Generated test token:")
        print(token)
        print("\nUse this token with the --token parameter:")
        print(f"python3 compliance_cli.py --token '{token}' list-systems")
        
        return token
        
    except Exception as e:
        print(f"Error generating token: {e}")
        return None


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate test JWT tokens")
    parser.add_argument("--system-id", default="test-system", help="System ID")
    parser.add_argument("--user-id", default="admin", help="User ID")
    parser.add_argument("--hours", type=int, default=24, help="Validity in hours")
    parser.add_argument("--key-path", default="keys/jwt_private_key.pem", help="Private key path")
    
    args = parser.parse_args()
    
    try:
        token = generate_test_token(
            system_id=args.system_id,
            user_id=args.user_id,
            validity_hours=args.hours,
            private_key_path=args.key_path
        )
        
        print("Generated JWT token:")
        print(token)
        print(f"\nToken valid for {args.hours} hours")
        print("\nExample usage:")
        print(f"python3 compliance_cli.py --token '{token}' health")
        
    except Exception as e:
        print(f"Error: {e}")
