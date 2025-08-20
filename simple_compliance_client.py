#!/usr/bin/env python3
"""
Simple Compliance Client - Synchronous Version

A simplified synchronous Python client for basic interactions with the
Compliance Automation Agent API. Perfect for simple scripts and integrations.
"""

import requests
import json
import time
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class SimpleSystemInfo:
    """Simple system information"""
    system_id: str
    hostname: str = None
    ip_address: str = None
    operating_system: str = None
    os_version: str = None
    environment: str = None


class SimpleComplianceClient:
    """
    Simple synchronous compliance client
    
    Basic client for common compliance operations without async complexity.
    Perfect for scripts, automation, and simple integrations.
    """
    
    def __init__(
        self, 
        base_url: str = "http://localhost:8000",
        username: str = None,
        password: str = None,
        auth_token: str = None,
        timeout: int = 30,
        verify_ssl: bool = True
    ):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.auth_token = auth_token
        
        # Setup session
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "SimpleComplianceClient/1.0.0"
        })
        
        # Setup logging
        self.logger = logging.getLogger("simple_compliance_client")
        
        # Authenticate if credentials provided
        if auth_token:
            self.set_auth_token(auth_token)
        elif username and password:
            # Note: This API doesn't have a login endpoint
            # You need to generate a JWT token using generate_token.py
            print("Warning: This API uses JWT tokens, not username/password")
            print("Generate a token with: python3 generate_token.py")
            raise Exception("API requires JWT token authentication. Use --token parameter.")
    
    def set_auth_token(self, token: str):
        """Set authentication token"""
        self.auth_token = token
        self.session.headers["Authorization"] = f"Bearer {token}"
    
    def authenticate(self, username: str, password: str) -> str:
        """
        Authenticate with username/password
        
        Returns:
            Authentication token
        """
        auth_data = {
            "username": username,
            "password": password
        }
        
        response = self.session.post(
            f"{self.base_url}/auth/token",
            json=auth_data,
            timeout=self.timeout,
            verify=self.verify_ssl
        )
        
        if response.status_code != 200:
            raise Exception(f"Authentication failed: {response.status_code}")
        
        token_data = response.json()
        self.auth_token = token_data.get("access_token")
        
        if not self.auth_token:
            raise Exception("No token received from authentication")
        
        self.set_auth_token(self.auth_token)
        return self.auth_token
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """Make HTTP request"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        response = self.session.request(
            method=method,
            url=url,
            timeout=self.timeout,
            verify=self.verify_ssl,
            **kwargs
        )
        
        if response.status_code == 401:
            raise Exception("Authentication failed - invalid or expired token")
        
        if response.status_code >= 400:
            try:
                error_data = response.json()
                error_msg = error_data.get("error", f"HTTP {response.status_code}")
            except:
                error_msg = f"HTTP {response.status_code}: {response.text}"
            raise Exception(f"API Error: {error_msg}")
        
        try:
            return response.json()
        except:
            return {"text": response.text}
    
    # Basic API Methods
    
    def health_check(self) -> Dict:
        """Check API health"""
        return self._request("GET", "/health")
    
    def register_system(self, system_info: SimpleSystemInfo) -> Dict:
        """Register a new system"""
        data = {k: v for k, v in system_info.__dict__.items() if v is not None}
        return self._request("POST", "/systems", json=data)
    
    def get_systems(self, limit: int = 50, environment: str = None) -> Dict:
        """Get list of systems"""
        params = {"limit": limit}
        if environment:
            params["environment"] = environment
        return self._request("GET", "/systems", params=params)
    
    def get_system(self, system_id: str) -> Dict:
        """Get system details"""
        return self._request("GET", f"/systems/{system_id}")
    
    def trigger_scan(
        self, 
        system_id: str, 
        profile: str = "cis_ubuntu2204",
        plugin: str = "CIS"
    ) -> Dict:
        """Trigger a compliance scan"""
        data = {
            "system_id": system_id,
            "profile": profile,
            "plugin": plugin
        }
        return self._request("POST", "/scans", json=data)
    
    def get_scan(self, scan_id: str) -> Dict:
        """Get scan details"""
        return self._request("GET", f"/scans/{scan_id}")
    
    def get_scans(
        self, 
        system_id: str = None, 
        limit: int = 50,
        status: str = None
    ) -> Dict:
        """Get list of scans"""
        params = {"limit": limit}
        if system_id:
            params["system_id"] = system_id
        if status:
            params["status"] = status
        return self._request("GET", "/scans", params=params)
    
    def wait_for_scan(self, scan_id: str, timeout: int = 600, poll_interval: int = 10) -> Dict:
        """Wait for scan to complete"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            scan = self.get_scan(scan_id)
            status = scan.get("status")
            
            if status in ["completed", "failed", "cancelled"]:
                return scan
            
            print(f"Scan {scan_id} status: {status}, waiting...")
            time.sleep(poll_interval)
        
        raise Exception(f"Scan {scan_id} did not complete within {timeout} seconds")
    
    def generate_attestation(self, scan_id: str, validity_hours: int = 24) -> Dict:
        """Generate attestation for a scan"""
        data = {
            "scan_id": scan_id,
            "validity_hours": validity_hours
        }
        return self._request("POST", "/attestations", json=data)
    
    def verify_attestation(self, jwt_token: str) -> Dict:
        """Verify an attestation token"""
        data = {"jwt_token": jwt_token}
        return self._request("POST", "/attestations/verify", json=data)
    
    def get_compliance_report(
        self, 
        system_id: str = None,
        environment: str = None,
        format: str = "json"
    ) -> Dict:
        """Get compliance report"""
        params = {"format": format}
        if system_id:
            params["system_id"] = system_id
        if environment:
            params["environment"] = environment
        return self._request("GET", "/reports/compliance", params=params)
    
    # High-level convenience methods
    
    def scan_system_and_wait(
        self, 
        system_id: str, 
        profile: str = "cis_ubuntu2204",
        generate_attestation: bool = True,
        timeout: int = 600
    ) -> Dict:
        """Complete scan workflow: trigger scan, wait for completion, generate attestation"""
        print(f"Triggering scan for system: {system_id}")
        scan_response = self.trigger_scan(system_id, profile)
        scan_id = scan_response["scan_id"]
        
        print(f"Waiting for scan {scan_id} to complete...")
        scan_result = self.wait_for_scan(scan_id, timeout)
        
        result = {
            "scan_id": scan_id,
            "scan_result": scan_result
        }
        
        if generate_attestation and scan_result.get("status") == "completed":
            print(f"Generating attestation for scan: {scan_id}")
            attestation = self.generate_attestation(scan_id)
            result["attestation"] = attestation
        
        return result
    
    def register_and_scan(
        self,
        system_info: SimpleSystemInfo,
        profile: str = "cis_ubuntu2204",
        wait_for_completion: bool = True
    ) -> Dict:
        """Register system and perform scan"""
        print(f"Registering system: {system_info.system_id}")
        registration = self.register_system(system_info)
        
        if wait_for_completion:
            scan_result = self.scan_system_and_wait(system_info.system_id, profile)
            return {
                "registration": registration,
                **scan_result
            }
        else:
            scan_response = self.trigger_scan(system_info.system_id, profile)
            return {
                "registration": registration,
                "scan_initiated": scan_response
            }


# CLI functions for easy use
def quick_health_check(base_url: str = "http://localhost:8000") -> bool:
    """Quick health check without authentication"""
    try:
        response = requests.get(f"{base_url}/health", timeout=10)
        return response.status_code == 200
    except:
        return False


def quick_scan(
    system_id: str,
    profile: str = "cis_ubuntu2204",
    base_url: str = "http://localhost:8000",
    username: str = None,
    password: str = None,
    auth_token: str = None
) -> Dict:
    """Quick scan without system registration"""
    client = SimpleComplianceClient(
        base_url=base_url,
        username=username,
        password=password,
        auth_token=auth_token
    )
    
    return client.scan_system_and_wait(system_id, profile)


# Example usage
if __name__ == "__main__":
    import argparse
    
    def main():
        parser = argparse.ArgumentParser(description="Simple Compliance Client")
        parser.add_argument("--url", default="http://localhost:8000", help="API URL")
        parser.add_argument("--username", help="Username")
        parser.add_argument("--password", help="Password")
        parser.add_argument("--token", help="Auth token")
        
        subparsers = parser.add_subparsers(dest="action", help="Actions")
        
        # Health check
        subparsers.add_parser("health", help="Check API health")
        
        # System registration
        register_parser = subparsers.add_parser("register", help="Register system")
        register_parser.add_argument("system_id", help="System ID")
        register_parser.add_argument("--hostname", help="Hostname")
        register_parser.add_argument("--ip", help="IP address")
        register_parser.add_argument("--os", help="Operating system")
        register_parser.add_argument("--os-version", help="OS version")
        register_parser.add_argument("--environment", help="Environment")
        
        # Scanning
        scan_parser = subparsers.add_parser("scan", help="Trigger scan")
        scan_parser.add_argument("system_id", help="System ID")
        scan_parser.add_argument("--profile", default="cis_ubuntu2204", help="Compliance profile")
        scan_parser.add_argument("--wait", action="store_true", help="Wait for completion")
        scan_parser.add_argument("--attestation", action="store_true", help="Generate attestation")
        
        # List systems
        subparsers.add_parser("list-systems", help="List registered systems")
        
        # List scans
        list_scans_parser = subparsers.add_parser("list-scans", help="List scans")
        list_scans_parser.add_argument("--system-id", help="Filter by system ID")
        
        args = parser.parse_args()
        
        if not args.action:
            parser.print_help()
            return
        
        # Health check doesn't need authentication
        if args.action == "health":
            if quick_health_check(args.url):
                print("✅ API is healthy")
            else:
                print("❌ API is not responding")
            return
        
        # Create authenticated client
        client = SimpleComplianceClient(
            base_url=args.url,
            username=args.username,
            password=args.password,
            auth_token=args.token
        )
        
        try:
            if args.action == "register":
                system_info = SimpleSystemInfo(
                    system_id=args.system_id,
                    hostname=args.hostname,
                    ip_address=args.ip,
                    operating_system=args.os,
                    os_version=args.os_version,
                    environment=args.environment
                )
                result = client.register_system(system_info)
                print(json.dumps(result, indent=2))
                
            elif args.action == "scan":
                if args.wait:
                    result = client.scan_system_and_wait(
                        args.system_id, 
                        args.profile,
                        generate_attestation=args.attestation
                    )
                    print(json.dumps(result, indent=2))
                else:
                    result = client.trigger_scan(args.system_id, args.profile)
                    print(json.dumps(result, indent=2))
                    
            elif args.action == "list-systems":
                systems = client.get_systems()
                print(json.dumps(systems, indent=2))
                
            elif args.action == "list-scans":
                scans = client.get_scans(system_id=getattr(args, 'system_id', None))
                print(json.dumps(scans, indent=2))
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    main()
