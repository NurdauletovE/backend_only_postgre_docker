#!/usr/bin/env python3
"""
Check and display current Python environment package versions
"""

import pkg_resources
import sys

# Required packages for the compliance client
REQUIRED_PACKAGES = [
    'aiohttp',
    'aiofiles', 
    'requests',
    'PyJWT[crypto]',
    'cryptography'
]

def get_installed_version(package_name):
    """Get installed version of a package"""
    try:
        # Handle package names with extras like PyJWT[crypto]
        base_name = package_name.split('[')[0]
        return pkg_resources.get_distribution(base_name).version
    except pkg_resources.DistributionNotFound:
        return None

def main():
    """Display current package versions"""
    print("Current Python environment package versions:")
    print("=" * 50)
    
    for package in REQUIRED_PACKAGES:
        version = get_installed_version(package)
        if version:
            # For PyJWT[crypto], show as PyJWT
            display_name = package.split('[')[0]
            print(f"{display_name}=={version}")
        else:
            print(f"{package} - NOT INSTALLED")
    
    print("\nPython version:", sys.version)

if __name__ == "__main__":
    main()
