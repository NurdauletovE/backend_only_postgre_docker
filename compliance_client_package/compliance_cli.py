#!/usr/bin/env python3
"""
Compliance CLI Tool

A simple command-line interface for the Compliance Automation Agent.
Perfect for quick operations and automation scripts.
"""

import sys
import json
import argparse
from simple_compliance_client import SimpleComplianceClient, SimpleSystemInfo, quick_health_check


def cmd_health(args):
    """Health check command"""
    print("Checking API health...")
    if quick_health_check(args.url):
        print("✅ API is healthy and accessible")
        return 0
    else:
        print("❌ API is not responding")
        print(f"   URL: {args.url}")
        print("   Check if the server is running and accessible")
        return 1


def cmd_register(args):
    """Register system command"""
    client = SimpleComplianceClient(
        base_url=args.url,
        username=args.username,
        password=args.password,
        auth_token=args.token
    )
    
    system_info = SimpleSystemInfo(
        system_id=args.system_id,
        hostname=args.hostname,
        ip_address=args.ip,
        operating_system=args.os,
        os_version=args.os_version,
        environment=args.environment
    )
    
    try:
        result = client.register_system(system_info)
        print(f"✅ System registered successfully: {args.system_id}")
        if args.json:
            print(json.dumps(result, indent=2))
        return 0
    except Exception as e:
        print(f"❌ Registration failed: {e}")
        return 1


def cmd_scan(args):
    """Scan command"""
    client = SimpleComplianceClient(
        base_url=args.url,
        username=args.username,
        password=args.password,
        auth_token=args.token
    )
    
    try:
        if args.wait:
            print(f"Triggering scan for {args.system_id} and waiting for completion...")
            result = client.scan_system_and_wait(
                system_id=args.system_id,
                profile=args.profile,
                generate_attestation=args.attestation,
                timeout=args.timeout
            )
            
            status = result['scan_result']['status']
            if status == 'completed':
                print(f"✅ Scan completed successfully")
                print(f"   Scan ID: {result['scan_id']}")
                if 'attestation' in result:
                    print(f"   Attestation: {result['attestation']['attestation_id']}")
            else:
                print(f"❌ Scan failed with status: {status}")
                return 1
        else:
            result = client.trigger_scan(args.system_id, args.profile)
            print(f"✅ Scan triggered: {result['scan_id']}")
        
        if args.json:
            print(json.dumps(result, indent=2))
        return 0
        
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        return 1


def cmd_list_systems(args):
    """List systems command"""
    client = SimpleComplianceClient(
        base_url=args.url,
        username=args.username,
        password=args.password,
        auth_token=args.token
    )
    
    try:
        result = client.get_systems(limit=args.limit, environment=args.environment)
        systems = result.get('systems', [])
        
        if not systems:
            print("No systems found")
            return 0
        
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Found {len(systems)} systems:")
            print("-" * 80)
            for system in systems:
                print(f"ID: {system.get('system_id', 'N/A')}")
                print(f"  Hostname: {system.get('hostname', 'N/A')}")
                print(f"  IP: {system.get('ip_address', 'N/A')}")
                print(f"  OS: {system.get('operating_system', 'N/A')} {system.get('os_version', '')}")
                print(f"  Environment: {system.get('environment', 'N/A')}")
                print(f"  Registered: {system.get('created_at', 'N/A')}")
                print("-" * 40)
        
        return 0
        
    except Exception as e:
        print(f"❌ Failed to list systems: {e}")
        return 1


def cmd_list_scans(args):
    """List scans command"""
    client = SimpleComplianceClient(
        base_url=args.url,
        username=args.username,
        password=args.password,
        auth_token=args.token
    )
    
    try:
        result = client.get_scans(
            system_id=args.system_id,
            limit=args.limit,
            status=args.status
        )
        scans = result.get('scans', [])
        
        if not scans:
            print("No scans found")
            return 0
        
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Found {len(scans)} scans:")
            print("-" * 80)
            for scan in scans:
                print(f"Scan ID: {scan.get('scan_id', 'N/A')}")
                print(f"  System: {scan.get('system_id', 'N/A')}")
                print(f"  Profile: {scan.get('profile', 'N/A')}")
                print(f"  Status: {scan.get('status', 'N/A')}")
                print(f"  Started: {scan.get('started_at', 'N/A')}")
                print(f"  Completed: {scan.get('completed_at', 'N/A')}")
                print("-" * 40)
        
        return 0
        
    except Exception as e:
        print(f"❌ Failed to list scans: {e}")
        return 1


def cmd_report(args):
    """Generate report command"""
    client = SimpleComplianceClient(
        base_url=args.url,
        username=args.username,
        password=args.password,
        auth_token=args.token
    )
    
    try:
        result = client.get_compliance_report(
            system_id=args.system_id,
            environment=args.environment,
            format=args.format
        )
        
        if args.output:
            with open(args.output, 'w') as f:
                if args.format == 'json':
                    json.dump(result, f, indent=2)
                else:
                    f.write(str(result))
            print(f"✅ Report saved to: {args.output}")
        else:
            if args.format == 'json':
                print(json.dumps(result, indent=2))
            else:
                print(result)
        
        return 0
        
    except Exception as e:
        print(f"❌ Failed to generate report: {e}")
        return 1


def cmd_attestation(args):
    """Attestation command"""
    client = SimpleComplianceClient(
        base_url=args.url,
        username=args.username,
        password=args.password,
        auth_token=args.token
    )
    
    try:
        if args.action == 'generate':
            result = client.generate_attestation(
                scan_id=args.scan_id,
                validity_hours=args.validity
            )
            print(f"✅ Attestation generated: {result['attestation_id']}")
            print(f"   Valid until: {result['valid_until']}")
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"   JWT Token: {result['jwt_token']}")
                
        elif args.action == 'verify':
            result = client.verify_attestation(args.jwt_token)
            if result.get('valid'):
                print("✅ Attestation is valid")
                print(f"   System: {result.get('system_id')}")
                print(f"   Compliance: {result.get('compliance_status')}")
            else:
                print("❌ Attestation is invalid or expired")
                return 1
                
            if args.json:
                print(json.dumps(result, indent=2))
        
        return 0
        
    except Exception as e:
        print(f"❌ Attestation operation failed: {e}")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="Compliance CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --username admin --password admin health
  %(prog)s --username admin --password admin register web-01 --hostname web01.company.com --ip 192.168.1.100
  %(prog)s --username admin --password admin scan web-01 --wait --attestation
  %(prog)s --username admin --password admin list-systems
  %(prog)s --username admin --password admin list-scans --system-id web-01
  %(prog)s --username admin --password admin report --format json --output compliance_report.json
        """
    )
    
    # Global options
    parser.add_argument("--url", default="http://localhost:8000", help="API URL")
    parser.add_argument("--username", help="Username")
    parser.add_argument("--password", help="Password") 
    parser.add_argument("--token", help="Auth token")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Health command
    subparsers.add_parser("health", help="Check API health")
    
    # Register command
    register_parser = subparsers.add_parser("register", help="Register a system")
    register_parser.add_argument("system_id", help="System ID")
    register_parser.add_argument("--hostname", help="Hostname")
    register_parser.add_argument("--ip", help="IP address")
    register_parser.add_argument("--os", help="Operating system")
    register_parser.add_argument("--os-version", help="OS version")
    register_parser.add_argument("--environment", help="Environment")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Trigger a compliance scan")
    scan_parser.add_argument("system_id", help="System ID")
    scan_parser.add_argument("--profile", default="cis_ubuntu2204", help="Compliance profile")
    scan_parser.add_argument("--wait", action="store_true", help="Wait for completion")
    scan_parser.add_argument("--attestation", action="store_true", help="Generate attestation")
    scan_parser.add_argument("--timeout", type=int, default=600, help="Timeout in seconds")
    
    # List systems command
    list_systems_parser = subparsers.add_parser("list-systems", help="List registered systems")
    list_systems_parser.add_argument("--limit", type=int, default=50, help="Max results")
    list_systems_parser.add_argument("--environment", help="Filter by environment")
    
    # List scans command
    list_scans_parser = subparsers.add_parser("list-scans", help="List scans")
    list_scans_parser.add_argument("--system-id", help="Filter by system ID")
    list_scans_parser.add_argument("--status", help="Filter by status")
    list_scans_parser.add_argument("--limit", type=int, default=50, help="Max results")
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate compliance report")
    report_parser.add_argument("--system-id", help="Filter by system ID")
    report_parser.add_argument("--environment", help="Filter by environment")
    report_parser.add_argument("--format", choices=["json", "html"], default="json", help="Report format")
    report_parser.add_argument("--output", help="Output file path")
    
    # Attestation command
    attestation_parser = subparsers.add_parser("attestation", help="Attestation operations")
    attestation_subparsers = attestation_parser.add_subparsers(dest="action", help="Attestation actions")
    
    # Generate attestation
    generate_parser = attestation_subparsers.add_parser("generate", help="Generate attestation")
    generate_parser.add_argument("scan_id", help="Scan ID")
    generate_parser.add_argument("--validity", type=int, default=24, help="Validity in hours")
    
    # Verify attestation
    verify_parser = attestation_subparsers.add_parser("verify", help="Verify attestation")
    verify_parser.add_argument("jwt_token", help="JWT token to verify")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Command mapping
    commands = {
        "health": cmd_health,
        "register": cmd_register,
        "scan": cmd_scan,
        "list-systems": cmd_list_systems,
        "list-scans": cmd_list_scans,
        "report": cmd_report,
        "attestation": cmd_attestation
    }
    
    if args.command in commands:
        return commands[args.command](args)
    else:
        print(f"Unknown command: {args.command}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
