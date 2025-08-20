#!/usr/bin/env python3
"""
Compliance Client Examples

Practical examples showing how to use the compliance clients
for various automation scenarios.
"""

import os
import sys
import time
import json
from simple_compliance_client import SimpleComplianceClient, SimpleSystemInfo, quick_health_check

# Configuration
API_URL = "http://localhost:8000"  # Change to your server's IP if remote
USERNAME = "admin"  # Your admin username
PASSWORD = "admin"  # Your admin password

def example_1_basic_health_check():
    """Example 1: Basic health check"""
    print("=== Example 1: Basic Health Check ===")
    
    if quick_health_check(API_URL):
        print("✅ Compliance API is healthy and accessible")
    else:
        print("❌ Compliance API is not responding")
        print(f"   Check if the server is running at: {API_URL}")
        return False
    return True


def example_2_register_and_scan_system():
    """Example 2: Register a system and perform a scan"""
    print("\n=== Example 2: Register System and Scan ===")
    
    # Create client
    client = SimpleComplianceClient(
        base_url=API_URL,
        username=USERNAME,
        password=PASSWORD
    )
    
    # Define system information
    system_info = SimpleSystemInfo(
        system_id="web-server-01",
        hostname="web01.company.com",
        ip_address="192.168.1.100",
        operating_system="Ubuntu",
        os_version="22.04 LTS",
        environment="production"
    )
    
    try:
        # Register the system
        print(f"Registering system: {system_info.system_id}")
        registration = client.register_system(system_info)
        print(f"✅ System registered successfully")
        
        # Trigger a scan
        print(f"Triggering CIS compliance scan...")
        scan_result = client.scan_system_and_wait(
            system_id=system_info.system_id,
            profile="cis_ubuntu2204",
            generate_attestation=True,
            timeout=300  # 5 minutes
        )
        
        print(f"✅ Scan completed!")
        print(f"   Scan ID: {scan_result['scan_id']}")
        print(f"   Status: {scan_result['scan_result']['status']}")
        
        if 'attestation' in scan_result:
            print(f"   Attestation generated: {scan_result['attestation']['attestation_id']}")
        
        return scan_result
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return None


def example_3_monitor_multiple_systems():
    """Example 3: Monitor multiple systems"""
    print("\n=== Example 3: Monitor Multiple Systems ===")
    
    client = SimpleComplianceClient(
        base_url=API_URL,
        username=USERNAME,
        password=PASSWORD
    )
    
    # Define multiple systems
    systems = [
        SimpleSystemInfo(
            system_id="db-server-01",
            hostname="db01.company.com",
            ip_address="192.168.1.101",
            operating_system="Ubuntu",
            os_version="22.04 LTS",
            environment="production"
        ),
        SimpleSystemInfo(
            system_id="app-server-01",
            hostname="app01.company.com",
            ip_address="192.168.1.102",
            operating_system="Ubuntu",
            os_version="22.04 LTS",
            environment="production"
        )
    ]
    
    scan_results = []
    
    try:
        for system in systems:
            print(f"\nProcessing system: {system.system_id}")
            
            # Register or update system
            try:
                client.register_system(system)
                print(f"✅ System {system.system_id} registered")
            except Exception as e:
                if "already exists" in str(e).lower():
                    print(f"ℹ️  System {system.system_id} already registered")
                else:
                    raise
            
            # Trigger scan (don't wait for all to complete)
            scan_response = client.trigger_scan(system.system_id)
            scan_results.append({
                "system_id": system.system_id,
                "scan_id": scan_response["scan_id"]
            })
            print(f"✅ Scan triggered for {system.system_id}: {scan_response['scan_id']}")
        
        # Now wait for all scans to complete
        print(f"\nWaiting for {len(scan_results)} scans to complete...")
        for result in scan_results:
            print(f"Waiting for scan {result['scan_id']} ({result['system_id']})...")
            scan_details = client.wait_for_scan(result['scan_id'], timeout=300)
            result['status'] = scan_details['status']
            result['completed_at'] = scan_details.get('completed_at')
            
            if scan_details['status'] == 'completed':
                print(f"✅ {result['system_id']}: Scan completed successfully")
            else:
                print(f"❌ {result['system_id']}: Scan failed with status: {scan_details['status']}")
        
        return scan_results
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return scan_results


def example_4_compliance_reporting():
    """Example 4: Generate compliance reports"""
    print("\n=== Example 4: Compliance Reporting ===")
    
    client = SimpleComplianceClient(
        base_url=API_URL,
        username=USERNAME,
        password=PASSWORD
    )
    
    try:
        # Get all systems
        print("Getting all registered systems...")
        systems_response = client.get_systems(limit=100)
        systems = systems_response.get("systems", [])
        print(f"Found {len(systems)} registered systems")
        
        # Get all scans
        print("Getting recent scans...")
        scans_response = client.get_scans(limit=50)
        scans = scans_response.get("scans", [])
        print(f"Found {len(scans)} recent scans")
        
        # Generate compliance report
        print("Generating compliance report...")
        report = client.get_compliance_report(format="json")
        
        print(f"✅ Compliance report generated")
        print(f"   Report contains data for multiple systems")
        
        # Show summary
        if isinstance(report, dict):
            summary = {
                "total_systems": len(systems),
                "total_scans": len(scans),
                "report_generated_at": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            print(f"   Summary: {json.dumps(summary, indent=4)}")
        
        return report
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return None


def example_5_attestation_workflow():
    """Example 5: Complete attestation workflow"""
    print("\n=== Example 5: Attestation Workflow ===")
    
    client = SimpleComplianceClient(
        base_url=API_URL,
        username=USERNAME,
        password=PASSWORD
    )
    
    try:
        # Get the most recent completed scan
        print("Finding most recent completed scan...")
        scans_response = client.get_scans(limit=10, status="completed")
        scans = scans_response.get("scans", [])
        
        if not scans:
            print("❌ No completed scans found. Run a scan first.")
            return None
        
        latest_scan = scans[0]  # Most recent
        scan_id = latest_scan["scan_id"]
        system_id = latest_scan["system_id"]
        
        print(f"Using scan: {scan_id} for system: {system_id}")
        
        # Generate attestation
        print("Generating attestation...")
        attestation = client.generate_attestation(
            scan_id=scan_id,
            validity_hours=168  # 1 week
        )
        
        attestation_token = attestation["jwt_token"]
        print(f"✅ Attestation generated: {attestation['attestation_id']}")
        print(f"   Valid until: {attestation['valid_until']}")
        
        # Verify the attestation
        print("Verifying attestation...")
        verification = client.verify_attestation(attestation_token)
        
        if verification.get("valid"):
            print("✅ Attestation verified successfully")
            print(f"   System: {verification.get('system_id')}")
            print(f"   Compliance Status: {verification.get('compliance_status')}")
        else:
            print("❌ Attestation verification failed")
        
        return {
            "attestation": attestation,
            "verification": verification
        }
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return None


def example_6_automated_compliance_check():
    """Example 6: Automated compliance check script"""
    print("\n=== Example 6: Automated Compliance Check ===")
    
    # This example shows how you might use this in a CI/CD pipeline
    # or automated compliance monitoring system
    
    client = SimpleComplianceClient(
        base_url=API_URL,
        username=USERNAME,
        password=PASSWORD
    )
    
    # System to check (could come from environment variables)
    system_id = os.environ.get("COMPLIANCE_SYSTEM_ID", "web-server-01")
    required_compliance_score = float(os.environ.get("MIN_COMPLIANCE_SCORE", "80.0"))
    
    try:
        print(f"Checking compliance for system: {system_id}")
        print(f"Required compliance score: {required_compliance_score}%")
        
        # Trigger scan and wait
        scan_result = client.scan_system_and_wait(
            system_id=system_id,
            profile="cis_ubuntu2204",
            generate_attestation=False,
            timeout=600
        )
        
        if scan_result['scan_result']['status'] != 'completed':
            print(f"❌ Scan failed: {scan_result['scan_result']['status']}")
            return False
        
        # Check compliance score (mock - would come from actual scan results)
        # In real implementation, you'd parse the scan results
        mock_compliance_score = 85.5  # This would come from actual scan results
        
        print(f"Compliance scan completed")
        print(f"Compliance score: {mock_compliance_score}%")
        
        if mock_compliance_score >= required_compliance_score:
            print("✅ COMPLIANCE CHECK PASSED")
            
            # Generate attestation for successful compliance
            attestation = client.generate_attestation(scan_result['scan_id'])
            print(f"✅ Compliance attestation generated: {attestation['attestation_id']}")
            
            return True
        else:
            print("❌ COMPLIANCE CHECK FAILED")
            print(f"   Score {mock_compliance_score}% is below required {required_compliance_score}%")
            return False
            
    except Exception as e:
        print(f"❌ Error during compliance check: {e}")
        return False


def run_all_examples():
    """Run all examples in sequence"""
    print("🚀 Running Compliance Client Examples")
    print("="*50)
    
    # Example 1: Health check
    if not example_1_basic_health_check():
        print("\n❌ Cannot continue - API not accessible")
        return
    
    # Example 2: Basic registration and scanning
    scan_result = example_2_register_and_scan_system()
    
    # Example 3: Multiple systems
    example_3_monitor_multiple_systems()
    
    # Example 4: Reporting
    example_4_compliance_reporting()
    
    # Example 5: Attestation workflow
    example_5_attestation_workflow()
    
    # Example 6: Automated compliance check
    example_6_automated_compliance_check()
    
    print("\n" + "="*50)
    print("✅ All examples completed!")
    print("\nNext steps:")
    print("1. Modify the examples for your specific systems")
    print("2. Set up environment variables for automation")
    print("3. Integrate with your CI/CD pipeline")
    print("4. Set up monitoring and alerting")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Compliance Client Examples")
    parser.add_argument("--url", default=API_URL, help="API URL")
    parser.add_argument("--username", default=USERNAME, help="Username")
    parser.add_argument("--password", default=PASSWORD, help="Password")
    parser.add_argument("--example", type=int, choices=[1,2,3,4,5,6], help="Run specific example")
    
    args = parser.parse_args()
    
    # Update global configuration
    API_URL = args.url
    USERNAME = args.username
    PASSWORD = args.password
    
    if args.example:
        # Run specific example
        examples = {
            1: example_1_basic_health_check,
            2: example_2_register_and_scan_system,
            3: example_3_monitor_multiple_systems,
            4: example_4_compliance_reporting,
            5: example_5_attestation_workflow,
            6: example_6_automated_compliance_check
        }
        examples[args.example]()
    else:
        # Run all examples
        run_all_examples()
