#!/usr/bin/env python3
"""
Compliance Client Demo

Demonstrates the key features of the Compliance Agent Client.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from compliance_client import (
    ComplianceAgentClient,
    ComplianceClientConfig,
    SystemInfo,
    ScanRequest,
    create_client
)

async def demo_basic_operations():
    """Demonstrate basic client operations"""
    print("🔧 Basic Operations Demo")
    print("-" * 30)
    
    # Create client using convenience function
    client = await create_client(base_url="http://localhost:8000")
    
    try:
        # 1. Health check
        print("1. Health Check:")
        health = await client.health_check()
        print(f"   Status: {health.get('status')}")
        print(f"   Version: {health.get('version')}")
        print(f"   Database: {health.get('components', {}).get('database', 'Unknown')}")
        
        # 2. API info
        print("\n2. API Information:")
        api_info = await client.get_api_info()
        print(f"   API Version: {api_info.get('version')}")
        print(f"   Status: {api_info.get('status')}")
        
        # 3. Demonstrate URL construction
        print("\n3. URL Construction:")
        test_urls = ["/health", "systems", "/scans/123"]
        for endpoint in test_urls:
            url = client._get_url(endpoint)
            print(f"   {endpoint} -> {url}")
        
        # 4. Header generation
        print("\n4. Header Generation:")
        headers_without_auth = client._get_headers()
        print(f"   Without auth: {len(headers_without_auth)} headers")
        
        client.set_auth_token("demo-token-123")
        headers_with_auth = client._get_headers()
        print(f"   With auth: {len(headers_with_auth)} headers")
        print(f"   Authorization header present: {'Authorization' in headers_with_auth}")
        
    finally:
        await client.disconnect()

async def demo_data_classes():
    """Demonstrate data class usage"""
    print("\n📊 Data Classes Demo")
    print("-" * 25)
    
    # 1. SystemInfo
    print("1. SystemInfo Example:")
    system_info = SystemInfo(
        system_id="demo-web-server-01",
        hostname="web01.demo.company.com",
        ip_address="192.168.1.100",
        operating_system="Ubuntu",
        os_version="22.04 LTS",
        architecture="x86_64",
        environment="production",
        location="us-east-1",
        owner_email="admin@company.com",
        tags={"role": "web-server", "tier": "frontend"}
    )
    
    print(f"   System ID: {system_info.system_id}")
    print(f"   Hostname: {system_info.hostname}")
    print(f"   Environment: {system_info.environment}")
    print(f"   Tags: {system_info.tags}")
    
    # 2. ScanRequest
    print("\n2. ScanRequest Example:")
    scan_request = ScanRequest(
        system_id=system_info.system_id,
        profile="cis_ubuntu2204",
        plugin="CIS",
        scan_type="full",
        config={"timeout": 300, "verbose": True}
    )
    
    print(f"   System: {scan_request.system_id}")
    print(f"   Profile: {scan_request.profile}")
    print(f"   Plugin: {scan_request.plugin}")
    print(f"   Config: {scan_request.config}")

async def demo_error_handling():
    """Demonstrate error handling"""
    print("\n🛡️ Error Handling Demo")
    print("-" * 25)
    
    client = await create_client(base_url="http://localhost:8000")
    
    try:
        # 1. Test 404 error
        print("1. Testing 404 Error:")
        try:
            await client._make_request("GET", "/non-existent-endpoint")
            print("   ❌ Expected error but got none")
        except Exception as e:
            print(f"   ✅ Caught expected error: {type(e).__name__}")
            print(f"   Message: {str(e)[:50]}...")
        
        # 2. Test timeout (simulate with very short timeout)
        print("\n2. Testing Connection Management:")
        short_timeout_client = ComplianceAgentClient(
            ComplianceClientConfig(
                base_url="http://localhost:8000",
                timeout=0.001  # Very short timeout
            )
        )
        
        try:
            await short_timeout_client.connect()
            await short_timeout_client.health_check()
            await short_timeout_client.disconnect()
            print("   ⚠️ Expected timeout but request succeeded")
        except Exception as e:
            print(f"   ✅ Timeout handled correctly: {type(e).__name__}")
    
    finally:
        await client.disconnect()

async def demo_async_features():
    """Demonstrate async capabilities"""
    print("\n⚡ Async Features Demo")
    print("-" * 25)
    
    # 1. Context manager
    print("1. Async Context Manager:")
    async with ComplianceAgentClient(ComplianceClientConfig(
        base_url="http://localhost:8000"
    )) as client:
        health = await client.health_check()
        print(f"   ✅ Context manager worked, status: {health.get('status')}")
    
    # 2. Concurrent operations
    print("\n2. Concurrent Operations:")
    
    async def health_check_task(client_id: int):
        """Individual health check task"""
        async with ComplianceAgentClient(ComplianceClientConfig(
            base_url="http://localhost:8000",
            client_id=f"demo-client-{client_id}"
        )) as client:
            health = await client.health_check()
            return f"Client {client_id}: {health.get('status')}"
    
    # Run multiple health checks concurrently
    tasks = [health_check_task(i) for i in range(3)]
    results = await asyncio.gather(*tasks)
    
    for result in results:
        print(f"   {result}")

async def demo_configuration_options():
    """Demonstrate configuration options"""
    print("\n⚙️ Configuration Options Demo")
    print("-" * 30)
    
    # 1. Basic configuration
    print("1. Basic Configuration:")
    basic_config = ComplianceClientConfig()
    print(f"   Default URL: {basic_config.base_url}")
    print(f"   Default timeout: {basic_config.timeout}")
    print(f"   Default retries: {basic_config.max_retries}")
    
    # 2. Custom configuration
    print("\n2. Custom Configuration:")
    custom_config = ComplianceClientConfig(
        base_url="https://compliance.company.com",
        timeout=60,
        max_retries=5,
        verify_ssl=True,
        client_id="production-client",
        client_version="2.0.0"
    )
    print(f"   Custom URL: {custom_config.base_url}")
    print(f"   Custom timeout: {custom_config.timeout}")
    print(f"   SSL verification: {custom_config.verify_ssl}")
    print(f"   Client ID: {custom_config.client_id}")

async def demo_workflow_structure():
    """Demonstrate high-level workflow structure"""
    print("\n🔄 Workflow Structure Demo")
    print("-" * 30)
    
    client = await create_client(base_url="http://localhost:8000")
    
    try:
        # Show available workflow methods
        print("1. Available Workflow Methods:")
        workflow_methods = [
            "register_and_scan_system",
            "bulk_scan_systems"
        ]
        
        for method_name in workflow_methods:
            method = getattr(client, method_name, None)
            if method:
                print(f"   ✅ {method_name}: Available")
            else:
                print(f"   ❌ {method_name}: Not found")
        
        # Show available API methods
        print("\n2. Available API Methods:")
        api_methods = [
            "register_system",
            "get_systems", 
            "trigger_scan",
            "get_scans",
            "generate_attestation",
            "verify_attestation",
            "get_compliance_report"
        ]
        
        for method_name in api_methods:
            method = getattr(client, method_name, None)
            if method:
                print(f"   ✅ {method_name}: Available")
            else:
                print(f"   ❌ {method_name}: Not found")
    
    finally:
        await client.disconnect()

async def main():
    """Run all demonstrations"""
    print("🎯 Compliance Client Feature Demonstration")
    print("=" * 50)
    
    try:
        await demo_basic_operations()
        await demo_data_classes()
        await demo_error_handling()
        await demo_async_features()
        await demo_configuration_options()
        await demo_workflow_structure()
        
        print("\n" + "=" * 50)
        print("✅ All demonstrations completed successfully!")
        print("\nThe Compliance Client provides:")
        print("  • Async/await support for high performance")
        print("  • Comprehensive error handling")
        print("  • Flexible configuration options")
        print("  • Easy-to-use data classes")
        print("  • Context manager support")
        print("  • High-level workflow methods")
        print("  • Full API coverage")
        print("  • Built-in retry logic")
        print("  • Proper connection management")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    print(f"\nDemo completed with exit code: {exit_code}")
    sys.exit(exit_code)
