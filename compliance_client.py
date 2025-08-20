#!/usr/bin/env python3
"""
Compliance Agent Client - Standalone Python Client

A comprehensive Python client for interacting with the Security Compliance
Automation Agent API. This client provides easy-to-use methods for system
registration, scan management, attestation handling, and report generation.
"""

import asyncio
import aiohttp
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import jwt
import ssl


@dataclass
class ComplianceClientConfig:
    """Configuration for the compliance client"""
    base_url: str = "http://localhost:8000"
    api_version: str = "v1"
    timeout: int = 30
    max_retries: int = 3
    verify_ssl: bool = True
    auth_token: Optional[str] = None
    
    # Authentication settings
    username: Optional[str] = None
    password: Optional[str] = None
    
    # Client identification
    client_id: str = "compliance-client"
    client_version: str = "1.0.0"


@dataclass
class SystemInfo:
    """System information for registration"""
    system_id: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    operating_system: Optional[str] = None
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    environment: Optional[str] = None
    location: Optional[str] = None
    owner_email: Optional[str] = None
    tags: Optional[Dict[str, str]] = None


@dataclass
class ScanRequest:
    """Scan request parameters"""
    system_id: str
    profile: str
    plugin: str = "CIS"
    scan_type: str = "full"
    config: Optional[Dict[str, Any]] = None


@dataclass
class ScanResult:
    """Scan result information"""
    id: str
    system_id: str
    profile: str
    status: str
    compliance_score: Optional[float] = None
    scan_start_time: Optional[str] = None
    scan_end_time: Optional[str] = None
    duration_seconds: Optional[int] = None
    total_rules: Optional[int] = None
    passed_rules: Optional[int] = None
    failed_rules: Optional[int] = None
    attestation_id: Optional[str] = None


class ComplianceClientError(Exception):
    """Base exception for compliance client errors"""
    pass


class AuthenticationError(ComplianceClientError):
    """Authentication-related errors"""
    pass


class APIError(ComplianceClientError):
    """API request errors"""
    def __init__(self, message: str, status_code: int = None, response_data: Dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data or {}


class ComplianceAgentClient:
    """
    Compliance Agent Client for interacting with the Compliance Automation API
    
    This client provides a comprehensive interface for:
    - System registration and management
    - Compliance scan execution and monitoring
    - Attestation generation and verification
    - Report generation and retrieval
    """
    
    def __init__(self, config: ComplianceClientConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.logger = self._setup_logging()
        self._auth_token: Optional[str] = config.auth_token
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for the client"""
        logger = logging.getLogger(f"compliance_client_{self.config.client_id}")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.disconnect()
    
    async def connect(self):
        """Initialize the HTTP session"""
        connector = aiohttp.TCPConnector(
            ssl=ssl.create_default_context() if self.config.verify_ssl else False
        )
        
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                "User-Agent": f"{self.config.client_id}/{self.config.client_version}",
                "Content-Type": "application/json"
            }
        )
        
        self.logger.info(f"Connected to compliance API at {self.config.base_url}")
    
    async def disconnect(self):
        """Close the HTTP session"""
        if self.session:
            await self.session.close()
            self.logger.info("Disconnected from compliance API")
    
    def _get_url(self, endpoint: str) -> str:
        """Construct full URL for an endpoint"""
        return f"{self.config.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers including authentication"""
        headers = {}
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        return headers
    
    async def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make HTTP request with retry logic"""
        if not self.session:
            await self.connect()
        
        url = self._get_url(endpoint)
        headers = self._get_headers()
        
        for attempt in range(self.config.max_retries + 1):
            try:
                self.logger.debug(f"{method} {url} (attempt {attempt + 1})")
                
                async with self.session.request(
                    method=method,
                    url=url,
                    json=data,
                    params=params,
                    headers=headers
                ) as response:
                    
                    response_data = {}
                    try:
                        response_data = await response.json()
                    except Exception:
                        response_data = {"text": await response.text()}
                    
                    if response.status == 401:
                        raise AuthenticationError("Authentication failed - invalid or expired token")
                    
                    if response.status >= 400:
                        error_msg = response_data.get("error", f"HTTP {response.status}")
                        raise APIError(error_msg, response.status, response_data)
                    
                    return response_data
                    
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt == self.config.max_retries:
                    raise ComplianceClientError(f"Request failed after {self.config.max_retries + 1} attempts: {e}")
                
                wait_time = 2 ** attempt
                self.logger.warning(f"Request failed, retrying in {wait_time}s: {e}")
                await asyncio.sleep(wait_time)
    
    # Authentication Methods
    
    async def authenticate(self, username: str = None, password: str = None) -> str:
        """
        Authenticate with the compliance API
        
        Args:
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            JWT authentication token
        """
        username = username or self.config.username
        password = password or self.config.password
        
        if not username or not password:
            raise AuthenticationError("Username and password required for authentication")
        
        auth_data = {
            "username": username,
            "password": password
        }
        
        try:
            response = await self._make_request("POST", "/auth/token", data=auth_data)
            self._auth_token = response.get("access_token")
            
            if not self._auth_token:
                raise AuthenticationError("No token received from authentication")
            
            self.logger.info("Successfully authenticated with compliance API")
            return self._auth_token
            
        except APIError as e:
            raise AuthenticationError(f"Authentication failed: {e}")
    
    def set_auth_token(self, token: str):
        """Set authentication token manually"""
        self._auth_token = token
        self.logger.info("Authentication token set manually")
    
    # Health and Status Methods
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check API health status
        
        Returns:
            Health status information
        """
        return await self._make_request("GET", "/health")
    
    async def get_api_info(self) -> Dict[str, Any]:
        """Get API information and version"""
        health_data = await self.health_check()
        return {
            "version": health_data.get("version"),
            "status": health_data.get("status"),
            "timestamp": health_data.get("timestamp")
        }
    
    # System Management Methods
    
    async def register_system(self, system_info: SystemInfo) -> Dict[str, Any]:
        """
        Register a new system for compliance monitoring
        
        Args:
            system_info: System information for registration
            
        Returns:
            Registration response with system ID
        """
        data = {k: v for k, v in asdict(system_info).items() if v is not None}
        return await self._make_request("POST", "/systems", data=data)
    
    async def get_systems(
        self, 
        limit: int = 50, 
        offset: int = 0,
        environment: str = None,
        active_only: bool = True
    ) -> Dict[str, Any]:
        """
        Get list of registered systems
        
        Args:
            limit: Number of results to return
            offset: Pagination offset
            environment: Filter by environment
            active_only: Show only active systems
            
        Returns:
            List of systems with pagination info
        """
        params = {
            "limit": limit,
            "offset": offset,
            "active_only": active_only
        }
        if environment:
            params["environment"] = environment
            
        return await self._make_request("GET", "/systems", params=params)
    
    async def get_system(self, system_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific system
        
        Args:
            system_id: System identifier
            
        Returns:
            Detailed system information
        """
        return await self._make_request("GET", f"/systems/{system_id}")
    
    async def update_system(self, system_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update system information
        
        Args:
            system_id: System identifier
            updates: Fields to update
            
        Returns:
            Updated system information
        """
        return await self._make_request("PUT", f"/systems/{system_id}", data=updates)
    
    async def deregister_system(self, system_id: str) -> Dict[str, Any]:
        """
        Deregister a system from compliance monitoring
        
        Args:
            system_id: System identifier
            
        Returns:
            Deregistration confirmation
        """
        return await self._make_request("DELETE", f"/systems/{system_id}")
    
    # Scan Management Methods
    
    async def trigger_scan(self, scan_request: ScanRequest) -> Dict[str, Any]:
        """
        Trigger a new compliance scan
        
        Args:
            scan_request: Scan configuration and parameters
            
        Returns:
            Scan initiation response with scan ID
        """
        data = {k: v for k, v in asdict(scan_request).items() if v is not None}
        return await self._make_request("POST", "/scans", data=data)
    
    async def get_scans(
        self,
        system_id: str = None,
        profile: str = None,
        status: str = None,
        start_date: str = None,
        end_date: str = None,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Get list of compliance scans
        
        Args:
            system_id: Filter by system ID
            profile: Filter by compliance profile
            status: Filter by scan status
            start_date: Filter scans after date (ISO 8601)
            end_date: Filter scans before date (ISO 8601)
            limit: Number of results
            offset: Pagination offset
            
        Returns:
            List of scans with pagination info
        """
        params = {"limit": limit, "offset": offset}
        
        for key, value in {
            "system_id": system_id,
            "profile": profile,
            "status": status,
            "start_date": start_date,
            "end_date": end_date
        }.items():
            if value:
                params[key] = value
                
        return await self._make_request("GET", "/scans", params=params)
    
    async def get_scan(self, scan_id: str) -> ScanResult:
        """
        Get detailed scan results
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Detailed scan results
        """
        response = await self._make_request("GET", f"/scans/{scan_id}")
        return ScanResult(**{k: v for k, v in response.items() if k in ScanResult.__annotations__})
    
    async def wait_for_scan_completion(
        self, 
        scan_id: str, 
        timeout: int = 600,
        poll_interval: int = 10
    ) -> ScanResult:
        """
        Wait for a scan to complete
        
        Args:
            scan_id: Scan identifier
            timeout: Maximum wait time in seconds
            poll_interval: How often to check status in seconds
            
        Returns:
            Final scan results
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            scan_result = await self.get_scan(scan_id)
            
            if scan_result.status in ["completed", "failed", "cancelled"]:
                self.logger.info(f"Scan {scan_id} finished with status: {scan_result.status}")
                return scan_result
            
            self.logger.info(f"Scan {scan_id} status: {scan_result.status}, waiting...")
            await asyncio.sleep(poll_interval)
        
        raise ComplianceClientError(f"Scan {scan_id} did not complete within {timeout} seconds")
    
    async def download_scan_results(
        self, 
        scan_id: str, 
        format: str = "json",
        output_path: str = None
    ) -> Union[Dict, bytes]:
        """
        Download scan results in specified format
        
        Args:
            scan_id: Scan identifier
            format: Result format (json, xml, html, pdf)
            output_path: Optional file path to save results
            
        Returns:
            Scan results data or saves to file
        """
        params = {"format": format}
        
        url = self._get_url(f"/scans/{scan_id}/results")
        headers = self._get_headers()
        
        async with self.session.get(url, params=params, headers=headers) as response:
            if response.status >= 400:
                raise APIError(f"Failed to download scan results: HTTP {response.status}")
            
            if format == "json":
                data = await response.json()
                if output_path:
                    with open(output_path, 'w') as f:
                        json.dump(data, f, indent=2)
                return data
            else:
                data = await response.read()
                if output_path:
                    with open(output_path, 'wb') as f:
                        f.write(data)
                return data
    
    # Attestation Methods
    
    async def generate_attestation(
        self, 
        scan_id: str, 
        validity_hours: int = 24,
        include_remediation: bool = True
    ) -> Dict[str, Any]:
        """
        Generate compliance attestation for a scan
        
        Args:
            scan_id: Scan identifier
            validity_hours: Token validity in hours
            include_remediation: Include remediation info
            
        Returns:
            Attestation with JWT token
        """
        data = {
            "scan_id": scan_id,
            "validity_hours": validity_hours,
            "include_remediation": include_remediation
        }
        return await self._make_request("POST", "/attestations", data=data)
    
    async def verify_attestation(self, jwt_token: str) -> Dict[str, Any]:
        """
        Verify an attestation token
        
        Args:
            jwt_token: JWT attestation token
            
        Returns:
            Verification result with claims
        """
        data = {"jwt_token": jwt_token}
        return await self._make_request("POST", "/attestations/verify", data=data)
    
    async def get_attestations(
        self,
        system_id: str = None,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Get list of compliance attestations
        
        Args:
            system_id: Filter by system ID
            limit: Number of results
            offset: Pagination offset
            
        Returns:
            List of attestations
        """
        params = {"limit": limit, "offset": offset}
        if system_id:
            params["system_id"] = system_id
            
        return await self._make_request("GET", "/attestations", params=params)
    
    # Report Methods
    
    async def get_compliance_report(
        self,
        system_id: str = None,
        environment: str = None,
        format: str = "json",
        start_date: str = None,
        end_date: str = None
    ) -> Dict[str, Any]:
        """
        Generate compliance status report
        
        Args:
            system_id: Filter by system
            environment: Filter by environment
            format: Report format
            start_date: Report start date
            end_date: Report end date
            
        Returns:
            Compliance report data
        """
        params = {"format": format}
        
        for key, value in {
            "system_id": system_id,
            "environment": environment,
            "start_date": start_date,
            "end_date": end_date
        }.items():
            if value:
                params[key] = value
                
        return await self._make_request("GET", "/reports/compliance", params=params)
    
    async def get_trend_analysis(
        self,
        system_id: str = None,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get compliance trend analysis
        
        Args:
            system_id: Filter by system
            days: Number of days for trend analysis
            
        Returns:
            Trend analysis data
        """
        params = {"days": days}
        if system_id:
            params["system_id"] = system_id
            
        return await self._make_request("GET", "/reports/trends", params=params)
    
    # Plugin Methods
    
    async def get_plugins(self) -> Dict[str, Any]:
        """
        Get list of available compliance plugins
        
        Returns:
            List of available plugins
        """
        return await self._make_request("GET", "/plugins")
    
    async def get_plugin_profiles(self, plugin_name: str) -> Dict[str, Any]:
        """
        Get available profiles for a plugin
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            List of available profiles
        """
        return await self._make_request("GET", f"/plugins/{plugin_name}/profiles")
    
    # High-level Workflow Methods
    
    async def register_and_scan_system(
        self,
        system_info: SystemInfo,
        profile: str,
        wait_for_completion: bool = True,
        generate_attestation: bool = True
    ) -> Dict[str, Any]:
        """
        Complete workflow: register system and perform scan
        
        Args:
            system_info: System information
            profile: Compliance profile to use
            wait_for_completion: Wait for scan to complete
            generate_attestation: Generate attestation after scan
            
        Returns:
            Complete workflow results
        """
        # Register system
        self.logger.info(f"Registering system: {system_info.system_id}")
        registration = await self.register_system(system_info)
        
        # Trigger scan
        scan_request = ScanRequest(
            system_id=system_info.system_id,
            profile=profile
        )
        
        self.logger.info(f"Triggering scan for system: {system_info.system_id}")
        scan_response = await self.trigger_scan(scan_request)
        scan_id = scan_response["scan_id"]
        
        results = {
            "registration": registration,
            "scan_initiated": scan_response
        }
        
        if wait_for_completion:
            self.logger.info(f"Waiting for scan completion: {scan_id}")
            scan_result = await self.wait_for_scan_completion(scan_id)
            results["scan_result"] = asdict(scan_result)
            
            if generate_attestation and scan_result.status == "completed":
                self.logger.info(f"Generating attestation for scan: {scan_id}")
                attestation = await self.generate_attestation(scan_id)
                results["attestation"] = attestation
        
        return results
    
    async def bulk_scan_systems(
        self,
        system_ids: List[str],
        profile: str,
        max_concurrent: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Perform bulk scanning of multiple systems
        
        Args:
            system_ids: List of system IDs to scan
            profile: Compliance profile to use
            max_concurrent: Maximum concurrent scans
            
        Returns:
            List of scan results
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_system(system_id: str) -> Dict[str, Any]:
            async with semaphore:
                try:
                    scan_request = ScanRequest(system_id=system_id, profile=profile)
                    scan_response = await self.trigger_scan(scan_request)
                    scan_result = await self.wait_for_scan_completion(scan_response["scan_id"])
                    
                    return {
                        "system_id": system_id,
                        "status": "success",
                        "scan_result": asdict(scan_result)
                    }
                except Exception as e:
                    self.logger.error(f"Failed to scan system {system_id}: {e}")
                    return {
                        "system_id": system_id,
                        "status": "error",
                        "error": str(e)
                    }
        
        self.logger.info(f"Starting bulk scan of {len(system_ids)} systems")
        tasks = [scan_system(system_id) for system_id in system_ids]
        results = await asyncio.gather(*tasks)
        
        successful = len([r for r in results if r["status"] == "success"])
        self.logger.info(f"Bulk scan completed: {successful}/{len(system_ids)} successful")
        
        return results


# Convenience Functions

async def create_client(
    base_url: str = "http://localhost:8000",
    username: str = None,
    password: str = None,
    auth_token: str = None,
    **kwargs
) -> ComplianceAgentClient:
    """
    Create and authenticate a compliance client
    
    Args:
        base_url: API base URL
        username: Username for authentication
        password: Password for authentication
        auth_token: Pre-existing auth token
        **kwargs: Additional config options
        
    Returns:
        Authenticated compliance client
    """
    config = ComplianceClientConfig(
        base_url=base_url,
        username=username,
        password=password,
        auth_token=auth_token,
        **kwargs
    )
    
    client = ComplianceAgentClient(config)
    await client.connect()
    
    if auth_token:
        client.set_auth_token(auth_token)
    elif username and password:
        await client.authenticate(username, password)
    
    return client


# CLI Interface (optional)
if __name__ == "__main__":
    import argparse
    import sys
    
    async def main():
        parser = argparse.ArgumentParser(description="Compliance Agent Client")
        parser.add_argument("--url", default="http://localhost:8000", help="API base URL")
        parser.add_argument("--username", help="Username for authentication")
        parser.add_argument("--password", help="Password for authentication")
        parser.add_argument("--token", help="Authentication token")
        
        subparsers = parser.add_subparsers(dest="command", help="Available commands")
        
        # Health check command
        health_parser = subparsers.add_parser("health", help="Check API health")
        
        # System commands
        system_parser = subparsers.add_parser("system", help="System management")
        system_subparsers = system_parser.add_subparsers(dest="system_action")
        
        list_systems_parser = system_subparsers.add_parser("list", help="List systems")
        list_systems_parser.add_argument("--limit", type=int, default=50)
        
        register_parser = system_subparsers.add_parser("register", help="Register system")
        register_parser.add_argument("--system-id", required=True)
        register_parser.add_argument("--hostname")
        register_parser.add_argument("--ip-address")
        register_parser.add_argument("--os")
        register_parser.add_argument("--os-version")
        
        # Scan commands
        scan_parser = subparsers.add_parser("scan", help="Scan management")
        scan_subparsers = scan_parser.add_subparsers(dest="scan_action")
        
        trigger_parser = scan_subparsers.add_parser("trigger", help="Trigger scan")
        trigger_parser.add_argument("--system-id", required=True)
        trigger_parser.add_argument("--profile", default="cis_ubuntu2204")
        trigger_parser.add_argument("--wait", action="store_true", help="Wait for completion")
        
        list_scans_parser = scan_subparsers.add_parser("list", help="List scans")
        list_scans_parser.add_argument("--system-id")
        list_scans_parser.add_argument("--limit", type=int, default=10)
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
        
        # Create client
        client = await create_client(
            base_url=args.url,
            username=args.username,
            password=args.password,
            auth_token=args.token
        )
        
        try:
            if args.command == "health":
                health = await client.health_check()
                print(json.dumps(health, indent=2))
                
            elif args.command == "system":
                if args.system_action == "list":
                    systems = await client.get_systems(limit=args.limit)
                    print(json.dumps(systems, indent=2))
                    
                elif args.system_action == "register":
                    system_info = SystemInfo(
                        system_id=args.system_id,
                        hostname=args.hostname,
                        ip_address=args.ip_address,
                        operating_system=args.os,
                        os_version=args.os_version
                    )
                    result = await client.register_system(system_info)
                    print(json.dumps(result, indent=2))
                    
            elif args.command == "scan":
                if args.scan_action == "trigger":
                    scan_request = ScanRequest(
                        system_id=args.system_id,
                        profile=args.profile
                    )
                    result = await client.trigger_scan(scan_request)
                    print(json.dumps(result, indent=2))
                    
                    if args.wait:
                        scan_id = result["scan_id"]
                        print(f"Waiting for scan {scan_id} to complete...")
                        scan_result = await client.wait_for_scan_completion(scan_id)
                        print(json.dumps(asdict(scan_result), indent=2))
                        
                elif args.scan_action == "list":
                    scans = await client.get_scans(
                        system_id=args.system_id,
                        limit=args.limit
                    )
                    print(json.dumps(scans, indent=2))
                    
        finally:
            await client.disconnect()
    
    asyncio.run(main())
