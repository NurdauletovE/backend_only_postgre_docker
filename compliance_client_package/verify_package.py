#!/usr/bin/env python3
"""
Package Verification Script
Verifies that all necessary files are present in the compliance client package
"""

import os
import sys

def check_file_exists(filepath, description):
    """Check if a file exists and report status"""
    if os.path.exists(filepath):
        size = os.path.getsize(filepath)
        print(f"✓ {description}: {filepath} ({size} bytes)")
        return True
    else:
        print(f"✗ MISSING {description}: {filepath}")
        return False

def main():
    """Verify package completeness"""
    print("Compliance Client Package Verification")
    print("=" * 50)
    
    # Define expected files
    files_to_check = [
        ("compliance_client.py", "Main async client"),
        ("simple_compliance_client.py", "Synchronous client"),
        ("compliance_cli.py", "Command-line interface"),
        ("compliance_examples.py", "Usage examples"),
        ("generate_token.py", "Token generation utility"),
        ("demo_compliance_client.py", "Demo script"),
        ("test_compliance_client.py", "Test suite"),
        ("test_client_functional.py", "Functional tests"),
        ("check_requirements.py", "Requirements checker"),
        ("requirements.txt", "Python dependencies"),
        ("INSTALLATION_GUIDE.md", "Installation guide"),
        ("CLIENT_USAGE_GUIDE.md", "Usage documentation"),
        ("API_DOCUMENTATION.md", "API reference"),
        ("TEST_RESULTS_SUMMARY.md", "Test results"),
        ("README.md", "Project README"),
        ("setup.sh", "Setup script"),
    ]
    
    missing_count = 0
    total_files = len(files_to_check)
    
    print("Checking core files...")
    print("-" * 30)
    
    for filename, description in files_to_check:
        if not check_file_exists(filename, description):
            missing_count += 1
    
    print("\n" + "=" * 50)
    print(f"Package Verification Results:")
    print(f"Files found: {total_files - missing_count}/{total_files}")
    
    if missing_count == 0:
        print("✓ Package is COMPLETE and ready for distribution!")
        print("\nTo use this package on a client machine:")
        print("1. Copy the entire compliance_client_package directory")
        print("2. Run: chmod +x setup.sh && ./setup.sh")
        print("3. Follow the prompts to install dependencies")
        print("4. Configure your server URL and API key")
        print("5. Test with: python3 compliance_cli.py health")
    else:
        print(f"✗ Package is INCOMPLETE - {missing_count} files missing")
        return 1
    
    print(f"\nPackage size:")
    total_size = sum(os.path.getsize(f[0]) for f in files_to_check if os.path.exists(f[0]))
    print(f"Total: {total_size:,} bytes ({total_size/1024:.1f} KB)")
    
    return 0

if __name__ == "__main__":
    # Change to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    sys.exit(main())
