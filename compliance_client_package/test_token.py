#!/usr/bin/env python3
"""
Token Verification Test

Test JWT token verification with the same logic as the application.
"""

import jwt
import json
from pathlib import Path
from datetime import datetime, timezone

def test_token_verification():
    """Test token verification"""
    
    # The token we generated
    token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJjb21wbGlhbmNlLWFnZW50Iiwic3ViIjoiYWRtaW4iLCJhdWQiOiJjb21wbGlhbmNlLWF1dGhvcml0eSIsImlhdCI6MTc1MzM5MjI0MCwiZXhwIjoxNzUzOTk3MDQwLCJzeXN0ZW1faWQiOiJ0ZXN0LXN5c3RlbSIsInJvbGUiOiJhZG1pbiIsInBlcm1pc3Npb25zIjpbInJlYWQiLCJ3cml0ZSIsInNjYW4iLCJhdHRlc3QiXX0.qDKAvzPm4hFX1wF-P_9rxkXufu9rUA_lSaI9FWo9Oq4qfbegfTzXqC6nDbCNZW7NbpRqXaIXxZB7P96h1TXJIhDsrk5mlCZv2fM9Wyy3yjABr5j8-e1QIQnciJhZ5TLJyNr3wf1YzatGLOy0ZBsnRnp_bcRWQdbAg2d9MRIMVB2wppIEncnkId4C9z6qOD9_FzuqPloHPyLOlA6qdcF5hAWzI3wnREtPaQERNPk05WYE_tcTX0nevCQ5HC4h3yL1oxSandZLE_VTDc1HHIEMEifY8-DJKIVVappqLbrpZd4x1sacKlVbQEoTa1OimA1ob1nqnVwJ-yUlL9AU0W7H-w"
    
    # Load public key
    with open("keys/public_unencrypted.pem", "rb") as f:
        public_key = f.read()
    
    print("Testing token verification...")
    
    try:
        # First decode without verification to see contents
        unverified = jwt.decode(token, options={"verify_signature": False})
        print("Token contents (unverified):")
        print(json.dumps(unverified, indent=2))
        
        # Convert timestamp
        iat = datetime.fromtimestamp(unverified['iat'], tz=timezone.utc)
        exp = datetime.fromtimestamp(unverified['exp'], tz=timezone.utc)
        now = datetime.now(timezone.utc)
        
        print(f"\nIssued at: {iat}")
        print(f"Expires at: {exp}")
        print(f"Current time: {now}")
        print(f"Time until expiry: {exp - now}")
        
        # Now verify signature (same as API does)
        verified = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            options={"verify_signature": True, "verify_exp": True, "verify_aud": False}
        )
        
        print("\n✅ Token verification successful!")
        print("Verified payload:")
        print(json.dumps(verified, indent=2))
        
    except jwt.ExpiredSignatureError:
        print("❌ Token has expired")
    except jwt.InvalidTokenError as e:
        print(f"❌ Invalid token: {e}")
    except Exception as e:
        print(f"❌ Verification error: {e}")


if __name__ == "__main__":
    test_token_verification()
