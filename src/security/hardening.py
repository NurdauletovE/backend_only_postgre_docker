import os
import stat
import logging
import hashlib
import secrets
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime, timezone
import asyncio
import ssl
import socket

logger = logging.getLogger(__name__)


class SecurityHardening:
    """Security hardening utilities for the compliance agent"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def validate_file_permissions(self, file_path: str, expected_permissions: int = 0o600) -> bool:
        """
        Validate file permissions for security-sensitive files
        
        Args:
            file_path: Path to file to check
            expected_permissions: Expected octal permissions
            
        Returns:
            True if permissions are correct
        """
        try:
            path = Path(file_path)
            if not path.exists():
                self.logger.error(f"File does not exist: {file_path}")
                return False
            
            current_permissions = stat.filemode(path.stat().st_mode)
            expected_mode = stat.filemode(expected_permissions | stat.S_IFREG)
            
            if current_permissions != expected_mode:
                self.logger.warning(
                    f"Incorrect permissions on {file_path}: "
                    f"current={current_permissions}, expected={expected_mode}"
                )
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking file permissions: {e}")
            return False
    
    async def secure_file_permissions(self, file_path: str, permissions: int = 0o600) -> bool:
        """
        Set secure permissions on a file
        
        Args:
            file_path: Path to file
            permissions: Octal permissions to set
            
        Returns:
            True if permissions were set successfully
        """
        try:
            path = Path(file_path)
            if not path.exists():
                self.logger.error(f"File does not exist: {file_path}")
                return False
            
            path.chmod(permissions)
            self.logger.info(f"Set permissions {oct(permissions)} on {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting file permissions: {e}")
            return False
    
    async def validate_key_files(self, private_key_path: str, public_key_path: str) -> bool:
        """
        Validate security of cryptographic key files
        
        Args:
            private_key_path: Path to private key
            public_key_path: Path to public key
            
        Returns:
            True if key files are secure
        """
        try:
            # Check private key permissions (should be 600)
            if not await self.validate_file_permissions(private_key_path, 0o600):
                await self.secure_file_permissions(private_key_path, 0o600)
            
            # Check public key permissions (can be 644)
            if not await self.validate_file_permissions(public_key_path, 0o644):
                await self.secure_file_permissions(public_key_path, 0o644)
            
            # Validate key file contents
            if not await self._validate_key_file_content(private_key_path, "PRIVATE"):
                return False
            
            if not await self._validate_key_file_content(public_key_path, "PUBLIC"):
                return False
            
            self.logger.info("Key files validated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating key files: {e}")
            return False
    
    async def _validate_key_file_content(self, key_path: str, key_type: str) -> bool:
        """Validate that key file contains proper PEM format"""
        try:
            with open(key_path, 'r') as f:
                content = f.read()
            
            if key_type == "PRIVATE":
                if not ("-----BEGIN PRIVATE KEY-----" in content and 
                       "-----END PRIVATE KEY-----" in content):
                    self.logger.error(f"Invalid private key format in {key_path}")
                    return False
            elif key_type == "PUBLIC":
                if not ("-----BEGIN PUBLIC KEY-----" in content and 
                       "-----END PUBLIC KEY-----" in content):
                    self.logger.error(f"Invalid public key format in {key_path}")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating key file content: {e}")
            return False
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate cryptographically secure random token
        
        Args:
            length: Length of token in bytes
            
        Returns:
            Hex-encoded secure token
        """
        return secrets.token_hex(length)
    
    def hash_sensitive_data(self, data: str, salt: Optional[str] = None) -> Dict[str, str]:
        """
        Hash sensitive data with salt
        
        Args:
            data: Data to hash
            salt: Optional salt (generated if not provided)
            
        Returns:
            Dictionary with hash and salt
        """
        if salt is None:
            salt = secrets.token_hex(32)
        
        # Use PBKDF2 for secure hashing
        import hashlib
        
        hash_obj = hashlib.pbkdf2_hmac('sha256', data.encode(), salt.encode(), 100000)
        return {
            'hash': hash_obj.hex(),
            'salt': salt
        }
    
    async def validate_environment_security(self) -> Dict[str, Any]:
        """
        Validate security configuration of the environment
        
        Returns:
            Dictionary with validation results
        """
        results = {
            'overall_secure': True,
            'checks': {},
            'warnings': [],
            'errors': []
        }
        
        try:
            # Check environment variables for sensitive data
            env_check = await self._check_environment_variables()
            results['checks']['environment'] = env_check
            if not env_check['secure']:
                results['overall_secure'] = False
                results['errors'].extend(env_check['issues'])
            
            # Check file permissions
            file_check = await self._check_critical_file_permissions()
            results['checks']['file_permissions'] = file_check
            if not file_check['secure']:
                results['overall_secure'] = False
                results['errors'].extend(file_check['issues'])
            
            # Check network security
            network_check = await self._check_network_security()
            results['checks']['network'] = network_check
            if not network_check['secure']:
                results['warnings'].extend(network_check['issues'])
            
            # Check process security
            process_check = await self._check_process_security()
            results['checks']['process'] = process_check
            if not process_check['secure']:
                results['warnings'].extend(process_check['issues'])
            
            self.logger.info(f"Security validation completed. Secure: {results['overall_secure']}")
            return results
            
        except Exception as e:
            self.logger.error(f"Error validating environment security: {e}")
            results['overall_secure'] = False
            results['errors'].append(f"Validation error: {str(e)}")
            return results
    
    async def _check_environment_variables(self) -> Dict[str, Any]:
        """Check environment variables for security issues"""
        result = {'secure': True, 'issues': []}
        
        # Check for sensitive data in environment variables
        sensitive_patterns = ['password', 'secret', 'key', 'token', 'credential']
        
        for var_name, var_value in os.environ.items():
            # Skip if variable name suggests it should contain sensitive data
            if any(pattern in var_name.lower() for pattern in sensitive_patterns):
                continue
            
            # Check if value looks like sensitive data
            if var_value and len(var_value) > 20:
                # Simple heuristic for potential secrets
                if (var_value.isalnum() and len(set(var_value)) > 10) or \
                   any(char in var_value for char in ['=', '+', '/']):
                    result['issues'].append(f"Potential sensitive data in environment variable: {var_name}")
                    result['secure'] = False
        
        return result
    
    async def _check_critical_file_permissions(self) -> Dict[str, Any]:
        """Check permissions on critical files"""
        result = {'secure': True, 'issues': []}
        
        critical_files = [
            ('/app/keys/private.pem', 0o600),
            ('/app/keys/public.pem', 0o644),
            ('/app/config/', 0o755),  # Directory
            ('/app/logs/', 0o755),    # Directory
        ]
        
        for file_path, expected_perms in critical_files:
            try:
                path = Path(file_path)
                if path.exists():
                    current_perms = path.stat().st_mode & 0o777
                    if current_perms != expected_perms:
                        result['issues'].append(
                            f"Incorrect permissions on {file_path}: "
                            f"{oct(current_perms)} (expected {oct(expected_perms)})"
                        )
                        result['secure'] = False
            except Exception as e:
                result['issues'].append(f"Error checking {file_path}: {str(e)}")
                result['secure'] = False
        
        return result
    
    async def _check_network_security(self) -> Dict[str, Any]:
        """Check network security configuration"""
        result = {'secure': True, 'issues': []}
        
        try:
            # Check if running on privileged ports
            import socket
            
            # Common ports the application might use
            ports_to_check = [8000, 9090]  # API and metrics ports
            
            for port in ports_to_check:
                if port < 1024:
                    result['issues'].append(f"Running on privileged port {port}")
                    result['secure'] = False
            
            # Check SSL/TLS configuration
            ssl_context = ssl.create_default_context()
            if ssl_context.check_hostname:
                result['issues'].append("SSL hostname checking enabled (good)")
            else:
                result['issues'].append("SSL hostname checking disabled (warning)")
                result['secure'] = False
        
        except Exception as e:
            result['issues'].append(f"Network security check error: {str(e)}")
        
        return result
    
    async def _check_process_security(self) -> Dict[str, Any]:
        """Check process security configuration"""
        result = {'secure': True, 'issues': []}
        
        try:
            # Check if running as root
            if os.getuid() == 0:
                result['issues'].append("Process running as root (security risk)")
                result['secure'] = False
            
            # Check umask
            current_umask = os.umask(0o022)
            os.umask(current_umask)  # Restore original umask
            
            if current_umask != 0o022:
                result['issues'].append(f"Insecure umask: {oct(current_umask)} (recommended: 0o022)")
                result['secure'] = False
        
        except Exception as e:
            result['issues'].append(f"Process security check error: {str(e)}")
        
        return result
    
    async def apply_security_hardening(self) -> bool:
        """
        Apply security hardening measures
        
        Returns:
            True if hardening was successful
        """
        try:
            success = True
            
            # Set secure umask
            os.umask(0o022)
            
            # Secure key files if they exist
            key_paths = ['/app/keys/private.pem', '/app/keys/public.pem']
            for key_path in key_paths:
                if Path(key_path).exists():
                    if key_path.endswith('private.pem'):
                        if not await self.secure_file_permissions(key_path, 0o600):
                            success = False
                    else:
                        if not await self.secure_file_permissions(key_path, 0o644):
                            success = False
            
            # Create secure directories
            secure_dirs = ['/app/logs', '/app/scan_results', '/app/keys']
            for dir_path in secure_dirs:
                try:
                    Path(dir_path).mkdir(parents=True, exist_ok=True, mode=0o755)
                except Exception as e:
                    self.logger.error(f"Error creating secure directory {dir_path}: {e}")
                    success = False
            
            self.logger.info(f"Security hardening completed. Success: {success}")
            return success
            
        except Exception as e:
            self.logger.error(f"Error applying security hardening: {e}")
            return False
    
    def sanitize_log_data(self, data: Any) -> str:
        """
        Sanitize data for logging to prevent log injection
        
        Args:
            data: Data to sanitize
            
        Returns:
            Sanitized string safe for logging
        """
        if data is None:
            return "None"
        
        # Convert to string
        data_str = str(data)
        
        # Remove/replace dangerous characters
        dangerous_chars = ['\n', '\r', '\t', '\x00']
        for char in dangerous_chars:
            data_str = data_str.replace(char, '_')
        
        # Truncate if too long
        max_length = 1000
        if len(data_str) > max_length:
            data_str = data_str[:max_length] + "...[truncated]"
        
        return data_str
    
    def mask_sensitive_data(self, data: str, mask_char: str = '*') -> str:
        """
        Mask sensitive data for logging
        
        Args:
            data: Data to mask
            mask_char: Character to use for masking
            
        Returns:
            Masked string
        """
        if not data or len(data) <= 4:
            return mask_char * len(data)
        
        # Show first 2 and last 2 characters, mask the rest
        return data[:2] + mask_char * (len(data) - 4) + data[-2:]
    
    async def validate_input_data(self, data: Dict[str, Any], 
                                 schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate input data against schema for security
        
        Args:
            data: Input data to validate
            schema: Validation schema
            
        Returns:
            Validation result dictionary
        """
        result = {'valid': True, 'errors': [], 'sanitized_data': {}}
        
        try:
            for field, rules in schema.items():
                if field not in data:
                    if rules.get('required', False):
                        result['errors'].append(f"Required field missing: {field}")
                        result['valid'] = False
                    continue
                
                value = data[field]
                sanitized_value = value
                
                # Type validation
                expected_type = rules.get('type')
                if expected_type and not isinstance(value, expected_type):
                    result['errors'].append(f"Invalid type for {field}: expected {expected_type.__name__}")
                    result['valid'] = False
                    continue
                
                # String validations
                if isinstance(value, str):
                    # Length validation
                    max_length = rules.get('max_length')
                    if max_length and len(value) > max_length:
                        result['errors'].append(f"Field {field} exceeds maximum length {max_length}")
                        result['valid'] = False
                        continue
                    
                    min_length = rules.get('min_length', 0)
                    if len(value) < min_length:
                        result['errors'].append(f"Field {field} below minimum length {min_length}")
                        result['valid'] = False
                        continue
                    
                    # Pattern validation
                    pattern = rules.get('pattern')
                    if pattern:
                        import re
                        if not re.match(pattern, value):
                            result['errors'].append(f"Field {field} does not match required pattern")
                            result['valid'] = False
                            continue
                    
                    # Sanitize string
                    sanitized_value = self.sanitize_log_data(value)
                
                # Numeric validations
                elif isinstance(value, (int, float)):
                    min_val = rules.get('min_value')
                    max_val = rules.get('max_value')
                    
                    if min_val is not None and value < min_val:
                        result['errors'].append(f"Field {field} below minimum value {min_val}")
                        result['valid'] = False
                        continue
                    
                    if max_val is not None and value > max_val:
                        result['errors'].append(f"Field {field} exceeds maximum value {max_val}")
                        result['valid'] = False
                        continue
                
                result['sanitized_data'][field] = sanitized_value
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error validating input data: {e}")
            return {'valid': False, 'errors': [f"Validation error: {str(e)}"], 'sanitized_data': {}}


# Global security hardening instance
security_hardening = SecurityHardening()