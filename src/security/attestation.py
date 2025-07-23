import jwt
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)


class ComplianceAttestation:
    def __init__(self, private_key_path: Optional[str] = None, public_key_path: Optional[str] = None):
        """
        Initialize the attestation system with cryptographic keys
        
        Args:
            private_key_path: Path to RSA private key file
            public_key_path: Path to RSA public key file
        """
        self.private_key = None
        self.public_key = None
        
        if private_key_path and public_key_path:
            self.private_key = self._load_private_key(private_key_path)
            self.public_key = self._load_public_key(public_key_path)
        else:
            logger.warning("No key paths provided. Keys must be loaded manually.")
    
    def _load_private_key(self, private_key_path: str):
        """Load RSA private key from file"""
        try:
            key_path = Path(private_key_path)
            if not key_path.exists():
                raise FileNotFoundError(f"Private key file not found: {private_key_path}")
            
            with open(key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,  # Assume no password for simplicity
                    backend=default_backend()
                )
            
            logger.info(f"Private key loaded from {private_key_path}")
            return private_key
            
        except Exception as e:
            logger.error(f"Error loading private key: {e}")
            raise
    
    def _load_public_key(self, public_key_path: str):
        """Load RSA public key from file"""
        try:
            key_path = Path(public_key_path)
            if not key_path.exists():
                raise FileNotFoundError(f"Public key file not found: {public_key_path}")
            
            with open(key_path, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            
            logger.info(f"Public key loaded from {public_key_path}")
            return public_key
            
        except Exception as e:
            logger.error(f"Error loading public key: {e}")
            raise
    
    def set_keys(self, private_key, public_key):
        """Set keys programmatically"""
        self.private_key = private_key
        self.public_key = public_key
    
    def create_attestation(self, scan_results: Dict, system_id: str, 
                          issuer: str = "compliance-agent",
                          audience: str = "compliance-authority",
                          validity_hours: int = 24) -> str:
        """
        Generate signed compliance attestation JWT
        
        Args:
            scan_results: Results from compliance scan
            system_id: Unique identifier for the scanned system
            issuer: JWT issuer claim
            audience: JWT audience claim
            validity_hours: Token validity period in hours
            
        Returns:
            Signed JWT token as string
        """
        if not self.private_key:
            raise RuntimeError("Private key not loaded. Cannot create attestation.")
        
        now = datetime.now(timezone.utc)
        
        payload = {
            "iss": issuer,
            "sub": system_id,
            "aud": audience,
            "iat": now,
            "exp": now + timedelta(hours=validity_hours),
            "jti": self._generate_jti(scan_results, system_id),
            "compliance_data": {
                "scan_timestamp": scan_results.get("timestamp"),
                "profile": scan_results.get("profile"),
                "compliance_score": scan_results.get("score"),
                "scanner": scan_results.get("system_info", {}).get("scanner", "OpenSCAP"),
                "rule_results": self._summarize_rules(scan_results.get("rules", [])),
                "system_info": scan_results.get("system_info", {})
            }
        }
        
        try:
            token = jwt.encode(
                payload=payload,
                key=self.private_key,
                algorithm='RS256'
            )
            
            logger.info(f"Attestation created for system {system_id}")
            return token
            
        except Exception as e:
            logger.error(f"Error creating attestation: {e}")
            raise
    
    def verify_attestation(self, token: str, 
                          expected_audience: str = "compliance-authority",
                          expected_issuer: str = "compliance-agent") -> Dict:
        """
        Verify and decode a compliance attestation JWT
        
        Args:
            token: JWT token to verify
            expected_audience: Expected audience claim
            expected_issuer: Expected issuer claim
            
        Returns:
            Decoded token payload if valid
        """
        if not self.public_key:
            raise RuntimeError("Public key not loaded. Cannot verify attestation.")
        
        try:
            payload = jwt.decode(
                jwt=token,
                key=self.public_key,
                algorithms=['RS256'],
                audience=expected_audience,
                issuer=expected_issuer,
                options={
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_signature": True
                }
            )
            
            logger.info(f"Attestation verified for system {payload.get('sub')}")
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.error("Attestation token has expired")
            raise
        except jwt.InvalidAudienceError:
            logger.error("Invalid audience in attestation token")
            raise
        except jwt.InvalidIssuerError:
            logger.error("Invalid issuer in attestation token")
            raise
        except jwt.InvalidSignatureError:
            logger.error("Invalid signature in attestation token")
            raise
        except Exception as e:
            logger.error(f"Error verifying attestation: {e}")
            raise
    
    def _generate_jti(self, scan_results: Dict, system_id: str) -> str:
        """Generate unique JWT ID based on scan data"""
        import hashlib
        
        data = f"{system_id}_{scan_results.get('timestamp')}_{scan_results.get('profile')}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def _summarize_rules(self, rules: list, max_rules: int = 10) -> list:
        """Summarize rule results for inclusion in attestation"""
        if not rules:
            return []
        
        # Include up to max_rules, prioritizing failed rules
        failed_rules = [r for r in rules if r.get("result") != "pass"]
        passed_rules = [r for r in rules if r.get("result") == "pass"]
        
        summarized = []
        
        # Add failed rules first (up to max_rules)
        for rule in failed_rules[:max_rules]:
            summarized.append({
                "id": rule.get("id"),
                "result": rule.get("result"),
                "severity": rule.get("severity"),
                "title": rule.get("title", "")[:100]  # Truncate title
            })
        
        # Fill remaining slots with passed rules
        remaining_slots = max_rules - len(summarized)
        for rule in passed_rules[:remaining_slots]:
            summarized.append({
                "id": rule.get("id"),
                "result": rule.get("result"),
                "severity": rule.get("severity"),
                "title": rule.get("title", "")[:100]
            })
        
        return summarized
    
    @staticmethod
    def generate_key_pair(key_size: int = 2048) -> tuple:
        """
        Generate a new RSA key pair for testing/development
        
        Args:
            key_size: RSA key size in bits (minimum 2048 recommended)
            
        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    @staticmethod
    def save_key_pair(private_key, public_key, 
                     private_key_path: str, public_key_path: str):
        """
        Save RSA key pair to PEM files
        
        Args:
            private_key: RSA private key object
            public_key: RSA public key object
            private_key_path: Path to save private key
            public_key_path: Path to save public key
        """
        # Save private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        
        # Save public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        
        logger.info(f"Key pair saved to {private_key_path} and {public_key_path}")
    
    def get_token_info(self, token: str) -> Dict:
        """
        Get token information without verification (for debugging)
        
        Args:
            token: JWT token to analyze
            
        Returns:
            Token header and payload (unverified)
        """
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            return {
                "header": header,
                "payload": payload,
                "expires_at": datetime.fromtimestamp(payload.get("exp", 0), tz=timezone.utc),
                "issued_at": datetime.fromtimestamp(payload.get("iat", 0), tz=timezone.utc)
            }
        except Exception as e:
            logger.error(f"Error analyzing token: {e}")
            raise