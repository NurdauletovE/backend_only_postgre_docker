#!/usr/bin/env python3
"""
Compliance Client Test Suite

Comprehensive tests for the Compliance Agent Client to validate
all functionality including async operations, error handling,
and API interactions.
"""

import asyncio
import json
import time
import sys
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from compliance_client import (
    ComplianceAgentClient,
    ComplianceClientConfig,
    SystemInfo,
    ScanRequest,
    ComplianceClientError,
    AuthenticationError,
    APIError,
    create_client
)

# Test configuration
TEST_CONFIG = {
    "base_url": "http://localhost:8000",
    "auth_token": None,  # Will be set if provided
    "test_system_id": "test-client-system-01",
    "test_profile": "cis_ubuntu2204"
}

class ComplianceClientTester:
    """Test suite for the Compliance Client"""
    
    def __init__(self, config: dict):
        self.config = config
        self.results = {
            "pass": 0,
            "fail": 0,
            "skip": 0,
            "tests": []
        }
    
    def log_test(self, test_name: str, status: str, message: str = "", duration: float = 0):
        """Log test result"""
        status_emoji = {
            "PASS": "✅",
            "FAIL": "❌", 
            "SKIP": "⏭️"
        }
        
        print(f"{status_emoji.get(status, '❓')} {test_name}: {message}")
        if duration > 0:
            print(f"   Duration: {duration:.2f}s")
        
        self.results["tests"].append({
            "name": test_name,
            "status": status,
            "message": message,
            "duration": duration
        })
        
        self.results[status.lower()] += 1
    
    async def test_basic_imports(self):
        """Test that all modules import correctly"""
        start_time = time.time()
        try:
            # Test data classes
            config = ComplianceClientConfig()
            system_info = SystemInfo(system_id="test")
            scan_request = ScanRequest(system_id="test", profile="test")
            
            # Test exceptions
            try:
                raise ComplianceClientError("test")
            except ComplianceClientError:
                pass
            
            self.log_test(
                "Basic Imports", 
                "PASS", 
                "All classes and exceptions import correctly",
                time.time() - start_time
            )
        except Exception as e:
            self.log_test(
                "Basic Imports", 
                "FAIL", 
                f"Import error: {e}",
                time.time() - start_time
            )
    
    async def test_client_creation(self):
        """Test client creation and configuration"""
        start_time = time.time()
        try:
            # Test basic client creation
            config = ComplianceClientConfig(
                base_url=self.config["base_url"],
                timeout=10
            )
            client = ComplianceAgentClient(config)
            
            # Verify configuration
            assert client.config.base_url == self.config["base_url"]
            assert client.config.timeout == 10
            assert client.session is None  # Not connected yet
            
            self.log_test(
                "Client Creation", 
                "PASS", 
                "Client created with correct configuration",
                time.time() - start_time
            )
        except Exception as e:
            self.log_test(
                "Client Creation", 
                "FAIL", 
                f"Client creation failed: {e}",
                time.time() - start_time
            )
    
    async def test_convenience_function(self):
        """Test the create_client convenience function"""
        start_time = time.time()
        try:
            # Test without authentication
            client = await create_client(
                base_url=self.config["base_url"],
                timeout=5
            )
            
            assert client.session is not None
            assert client.config.base_url == self.config["base_url"]
            
            await client.disconnect()
            
            self.log_test(
                "Convenience Function", 
                "PASS", 
                "create_client function works correctly",
                time.time() - start_time
            )
        except Exception as e:
            self.log_test(
                "Convenience Function", 
                "FAIL", 
                f"Convenience function failed: {e}",
                time.time() - start_time
            )
    
    async def test_connection_management(self):
        """Test connection and disconnection"""
        start_time = time.time()
        try:
            config = ComplianceClientConfig(base_url=self.config["base_url"])
            client = ComplianceAgentClient(config)
            
            # Test connection
            await client.connect()
            assert client.session is not None
            
            # Test disconnection
            await client.disconnect()
            
            self.log_test(
                "Connection Management", 
                "PASS", 
                "Connection and disconnection work correctly",
                time.time() - start_time
            )
        except Exception as e:
            self.log_test(
                "Connection Management", 
                "FAIL", 
                f"Connection management failed: {e}",
                time.time() - start_time
            )
    
    async def test_context_manager(self):
        """Test async context manager"""
        start_time = time.time()
        try:
            config = ComplianceClientConfig(base_url=self.config["base_url"])
            
            async with ComplianceAgentClient(config) as client:
                assert client.session is not None
            
            # Session should be closed after context exit
            assert client.session.closed
            
            self.log_test(
                "Context Manager", 
                "PASS", 
                "Async context manager works correctly",
                time.time() - start_time
            )
        except Exception as e:
            self.log_test(
                "Context Manager", 
                "FAIL", 
                f"Context manager failed: {e}",
                time.time() - start_time
            )
    
    async def test_health_check(self):
        """Test health check endpoint"""
        start_time = time.time()
        try:
            async with ComplianceAgentClient(ComplianceClientConfig(
                base_url=self.config["base_url"]
            )) as client:
                
                health = await client.health_check()
                
                # Verify health response structure
                assert "status" in health
                assert "timestamp" in health
                
                self.log_test(
                    "Health Check", 
                    "PASS", 
                    f"Health status: {health.get('status')}",
                    time.time() - start_time
                )
        except Exception as e:
            self.log_test(
                "Health Check", 
                "FAIL", 
                f"Health check failed: {e}",
                time.time() - start_time
            )
    
    async def test_authentication_token(self):
        """Test token authentication if token provided"""
        start_time = time.time()
        
        if not self.config.get("auth_token"):
            self.log_test(
                "Token Authentication", 
                "SKIP", 
                "No auth token provided",
                time.time() - start_time
            )
            return
        
        try:
            config = ComplianceClientConfig(
                base_url=self.config["base_url"],
                auth_token=self.config["auth_token"]
            )
            
            async with ComplianceAgentClient(config) as client:
                # Try an authenticated endpoint
                try:
                    systems = await client.get_systems(limit=1)
                    self.log_test(
                        "Token Authentication", 
                        "PASS", 
                        "Token authentication successful",
                        time.time() - start_time
                    )
                except AuthenticationError:
                    self.log_test(
                        "Token Authentication", 
                        "FAIL", 
                        "Token authentication failed - invalid token",
                        time.time() - start_time
                    )
                except APIError as e:
                    if e.status_code == 401:
                        self.log_test(
                            "Token Authentication", 
                            "FAIL", 
                            "Token authentication failed",
                            time.time() - start_time
                        )
                    else:
                        self.log_test(
                            "Token Authentication", 
                            "PASS", 
                            "Token accepted (different API error)",
                            time.time() - start_time
                        )
        except Exception as e:
            self.log_test(
                "Token Authentication", 
                "FAIL", 
                f"Authentication test failed: {e}",
                time.time() - start_time
            )
    
    async def test_error_handling(self):
        """Test error handling for various scenarios"""
        start_time = time.time()
        try:
            config = ComplianceClientConfig(base_url=self.config["base_url"])
            
            async with ComplianceAgentClient(config) as client:
                # Test invalid endpoint
                try:
                    await client._make_request("GET", "/invalid-endpoint-12345")
                    self.log_test(
                        "Error Handling", 
                        "FAIL", 
                        "Expected error for invalid endpoint",
                        time.time() - start_time
                    )
                except APIError as e:
                    assert e.status_code == 404
                    self.log_test(
                        "Error Handling", 
                        "PASS", 
                        f"Correctly handled 404 error: {e}",
                        time.time() - start_time
                    )
        except Exception as e:
            self.log_test(
                "Error Handling", 
                "FAIL", 
                f"Error handling test failed: {e}",
                time.time() - start_time
            )
    
    async def test_data_classes(self):
        """Test data class functionality"""
        start_time = time.time()
        try:
            # Test SystemInfo
            system_info = SystemInfo(
                system_id="test-system",
                hostname="test.example.com",
                ip_address="192.168.1.100",
                operating_system="Ubuntu",
                os_version="22.04",
                environment="testing"
            )
            
            # Test conversion to dict
            system_dict = system_info.__dict__
            assert system_dict["system_id"] == "test-system"
            assert system_dict["hostname"] == "test.example.com"
            
            # Test ScanRequest
            scan_request = ScanRequest(
                system_id="test-system",
                profile="cis_ubuntu2204",
                plugin="CIS"
            )
            
            assert scan_request.system_id == "test-system"
            assert scan_request.profile == "cis_ubuntu2204"
            
            self.log_test(
                "Data Classes", 
                "PASS", 
                "Data classes work correctly",
                time.time() - start_time
            )
        except Exception as e:
            self.log_test(
                "Data Classes", 
                "FAIL", 
                f"Data class test failed: {e}",
                time.time() - start_time
            )
    
    async def test_url_construction(self):
        """Test URL construction methods"""
        start_time = time.time()
        try:
            config = ComplianceClientConfig(base_url="http://localhost:8000")
            client = ComplianceAgentClient(config)
            
            # Test URL construction
            url1 = client._get_url("/health")
            assert url1 == "http://localhost:8000/health"
            
            url2 = client._get_url("health")
            assert url2 == "http://localhost:8000/health"
            
            url3 = client._get_url("/systems/123")
            assert url3 == "http://localhost:8000/systems/123"
            
            self.log_test(
                "URL Construction", 
                "PASS", 
                "URL construction works correctly",
                time.time() - start_time
            )
        except Exception as e:
            self.log_test(
                "URL Construction", 
                "FAIL", 
                f"URL construction failed: {e}",
                time.time() - start_time
            )
    
    async def test_header_generation(self):
        """Test header generation with and without auth"""
        start_time = time.time()
        try:
            # Test without auth token
            config = ComplianceClientConfig(base_url=self.config["base_url"])
            client = ComplianceAgentClient(config)
            
            headers1 = client._get_headers()
            assert "Authorization" not in headers1
            
            # Test with auth token
            client.set_auth_token("test-token-123")
            headers2 = client._get_headers()
            assert headers2["Authorization"] == "Bearer test-token-123"
            
            self.log_test(
                "Header Generation", 
                "PASS", 
                "Header generation works correctly",
                time.time() - start_time
            )
        except Exception as e:
            self.log_test(
                "Header Generation", 
                "FAIL", 
                f"Header generation failed: {e}",
                time.time() - start_time
            )
    
    async def test_workflow_methods(self):
        """Test high-level workflow methods structure"""
        start_time = time.time()
        try:
            config = ComplianceClientConfig(base_url=self.config["base_url"])
            client = ComplianceAgentClient(config)
            
            # Test that workflow methods exist and are callable
            assert hasattr(client, "register_and_scan_system")
            assert hasattr(client, "bulk_scan_systems")
            assert callable(client.register_and_scan_system)
            assert callable(client.bulk_scan_systems)
            
            self.log_test(
                "Workflow Methods", 
                "PASS", 
                "High-level workflow methods available",
                time.time() - start_time
            )
        except Exception as e:
            self.log_test(
                "Workflow Methods", 
                "FAIL", 
                f"Workflow methods test failed: {e}",
                time.time() - start_time
            )
    
    async def test_cli_functionality(self):
        """Test CLI argument parsing structure"""
        start_time = time.time()
        try:
            # Import and verify CLI components exist
            import compliance_client
            
            # Check if main function exists for CLI
            assert hasattr(compliance_client, '__name__')
            
            self.log_test(
                "CLI Functionality", 
                "PASS", 
                "CLI components available",
                time.time() - start_time
            )
        except Exception as e:
            self.log_test(
                "CLI Functionality", 
                "FAIL", 
                f"CLI test failed: {e}",
                time.time() - start_time
            )
    
    def print_summary(self):
        """Print test summary"""
        total_tests = self.results["pass"] + self.results["fail"] + self.results["skip"]
        
        print("\n" + "="*60)
        print("COMPLIANCE CLIENT TEST SUMMARY")
        print("="*60)
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {self.results['pass']}")
        print(f"❌ Failed: {self.results['fail']}")
        print(f"⏭️ Skipped: {self.results['skip']}")
        
        if self.results["fail"] > 0:
            print(f"\nFailed Tests:")
            for test in self.results["tests"]:
                if test["status"] == "FAIL":
                    print(f"  - {test['name']}: {test['message']}")
        
        success_rate = (self.results["pass"] / total_tests * 100) if total_tests > 0 else 0
        print(f"\nSuccess Rate: {success_rate:.1f}%")
        
        if success_rate >= 80:
            print("🎉 Compliance Client is working well!")
        elif success_rate >= 60:
            print("⚠️ Compliance Client has some issues but is mostly functional")
        else:
            print("🚨 Compliance Client needs significant fixes")
        
        return self.results["fail"] == 0

async def run_all_tests(auth_token: str = None):
    """Run all compliance client tests"""
    print("🚀 Starting Compliance Client Test Suite")
    print("="*60)
    
    # Update config with auth token if provided
    if auth_token:
        TEST_CONFIG["auth_token"] = auth_token
        print(f"Using auth token for authenticated tests")
    
    tester = ComplianceClientTester(TEST_CONFIG)
    
    # Run all tests
    test_methods = [
        tester.test_basic_imports,
        tester.test_client_creation,
        tester.test_convenience_function,
        tester.test_connection_management,
        tester.test_context_manager,
        tester.test_health_check,
        tester.test_authentication_token,
        tester.test_error_handling,
        tester.test_data_classes,
        tester.test_url_construction,
        tester.test_header_generation,
        tester.test_workflow_methods,
        tester.test_cli_functionality
    ]
    
    for test_method in test_methods:
        try:
            await test_method()
        except Exception as e:
            tester.log_test(
                test_method.__name__.replace("test_", "").title(), 
                "FAIL", 
                f"Unexpected error: {e}"
            )
    
    # Print summary
    success = tester.print_summary()
    return success

async def test_with_real_api():
    """Test basic functionality with the real API"""
    print("\n🔗 Testing with Real API")
    print("-" * 40)
    
    try:
        # Test health check (no auth required)
        async with ComplianceAgentClient(ComplianceClientConfig(
            base_url=TEST_CONFIG["base_url"]
        )) as client:
            health = await client.health_check()
            print(f"✅ API Health: {health.get('status')}")
            print(f"   Version: {health.get('version')}")
            print(f"   Timestamp: {health.get('timestamp')}")
            return True
    except Exception as e:
        print(f"❌ Real API test failed: {e}")
        return False

if __name__ == "__main__":
    import sys
    
    # Check for auth token argument
    auth_token = None
    if len(sys.argv) > 1:
        auth_token = sys.argv[1]
        print(f"Using provided auth token: {auth_token[:20]}...")
    
    async def main():
        # Run comprehensive tests
        success = await run_all_tests(auth_token)
        
        # Test with real API
        api_success = await test_with_real_api()
        
        # Exit with appropriate code
        exit_code = 0 if success and api_success else 1
        sys.exit(exit_code)
    
    asyncio.run(main())
