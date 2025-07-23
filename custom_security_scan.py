#!/usr/bin/env python3
"""
Custom Security Compliance Scanner
Creates real compliance scores by checking actual system configuration
"""

import os
import subprocess
import json
import pwd
import grp
import stat
from datetime import datetime

class SecurityComplianceScanner:
    def __init__(self):
        self.results = {
            'scan_date': datetime.now().isoformat(),
            'system': self._get_system_info(),
            'checks': {},
            'summary': {}
        }
    
    def _get_system_info(self):
        """Get system information"""
        try:
            with open('/etc/os-release', 'r') as f:
                os_info = {}
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        os_info[key] = value.strip('"')
                return os_info
        except:
            return {"error": "Could not read system info"}
    
    def _run_command(self, command, shell=False):
        """Run system command and return output"""
        try:
            if shell:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
            else:
                result = subprocess.run(command.split(), capture_output=True, text=True)
            return {
                'returncode': result.returncode,
                'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def check_password_policy(self):
        """Check password policy compliance"""
        checks = {}
        
        # Check if password complexity is enforced
        pam_pwquality_result = self._run_command('grep -r "pam_pwquality" /etc/pam.d/', shell=True)
        checks['password_complexity'] = {
            'status': 'PASS' if pam_pwquality_result['returncode'] == 0 else 'FAIL',
            'details': 'Password complexity checking via pam_pwquality',
            'evidence': pam_pwquality_result.get('stdout', '')
        }
        
        # Check password aging
        login_defs_result = self._run_command('grep -E "^PASS_(MAX|MIN|WARN)_AGE" /etc/login.defs', shell=True)
        checks['password_aging'] = {
            'status': 'PASS' if login_defs_result['returncode'] == 0 else 'FAIL',
            'details': 'Password aging policy configuration',
            'evidence': login_defs_result.get('stdout', '')
        }
        
        return checks
    
    def check_file_permissions(self):
        """Check critical file permissions"""
        checks = {}
        critical_files = {
            '/etc/passwd': 0o644,
            '/etc/shadow': 0o640,
            '/etc/group': 0o644,
            '/etc/gshadow': 0o640
        }
        
        for file_path, expected_mode in critical_files.items():
            try:
                file_stat = os.stat(file_path)
                actual_mode = stat.S_IMODE(file_stat.st_mode)
                checks[f'permissions_{file_path.replace("/", "_")}'] = {
                    'status': 'PASS' if actual_mode <= expected_mode else 'FAIL',
                    'details': f'File permissions for {file_path}',
                    'evidence': f'Expected: {oct(expected_mode)}, Actual: {oct(actual_mode)}'
                }
            except Exception as e:
                checks[f'permissions_{file_path.replace("/", "_")}'] = {
                    'status': 'ERROR',
                    'details': f'Could not check {file_path}',
                    'evidence': str(e)
                }
        
        return checks
    
    def check_ssh_configuration(self):
        """Check SSH security configuration"""
        checks = {}
        ssh_config_file = '/etc/ssh/sshd_config'
        
        if not os.path.exists(ssh_config_file):
            return {'ssh_config_missing': {
                'status': 'FAIL',
                'details': 'SSH configuration file not found',
                'evidence': f'{ssh_config_file} does not exist'
            }}
        
        # Check for root login disabled
        root_login_result = self._run_command(f'grep -i "^PermitRootLogin" {ssh_config_file}', shell=True)
        checks['ssh_root_login'] = {
            'status': 'PASS' if 'no' in root_login_result.get('stdout', '').lower() else 'FAIL',
            'details': 'SSH root login should be disabled',
            'evidence': root_login_result.get('stdout', 'Not configured')
        }
        
        # Check for password authentication
        password_auth_result = self._run_command(f'grep -i "^PasswordAuthentication" {ssh_config_file}', shell=True)
        checks['ssh_password_auth'] = {
            'status': 'INFO',
            'details': 'SSH password authentication configuration',
            'evidence': password_auth_result.get('stdout', 'Not explicitly configured')
        }
        
        # Check SSH protocol version
        protocol_result = self._run_command(f'grep -i "^Protocol" {ssh_config_file}', shell=True)
        checks['ssh_protocol'] = {
            'status': 'PASS' if protocol_result['returncode'] != 0 else 'INFO',
            'details': 'SSH protocol version (Protocol 2 is default in modern SSH)',
            'evidence': protocol_result.get('stdout', 'Using default (Protocol 2)')
        }
        
        return checks
    
    def check_firewall_status(self):
        """Check firewall configuration"""
        checks = {}
        
        # Check UFW status
        ufw_result = self._run_command('sudo ufw status')
        checks['ufw_firewall'] = {
            'status': 'PASS' if 'active' in ufw_result.get('stdout', '').lower() else 'FAIL',
            'details': 'UFW firewall should be active',
            'evidence': ufw_result.get('stdout', 'UFW not found')
        }
        
        # Check iptables rules
        iptables_result = self._run_command('iptables -L')
        checks['iptables_rules'] = {
            'status': 'INFO',
            'details': 'Current iptables rules',
            'evidence': f"Rules count: {len(iptables_result.get('stdout', '').split('\\n'))}"
        }
        
        return checks
    
    def check_system_updates(self):
        """Check for available system updates"""
        checks = {}
        
        # Check for available updates
        updates_result = self._run_command('apt list --upgradable 2>/dev/null | wc -l', shell=True)
        try:
            update_count = int(updates_result.get('stdout', '0')) - 1  # Subtract header line
            checks['system_updates'] = {
                'status': 'PASS' if update_count == 0 else 'WARN',
                'details': 'System should be up to date',
                'evidence': f'{update_count} updates available'
            }
        except:
            checks['system_updates'] = {
                'status': 'ERROR',
                'details': 'Could not check for updates',
                'evidence': updates_result.get('stdout', '')
            }
        
        return checks
    
    def check_user_accounts(self):
        """Check user account security"""
        checks = {}
        
        # Check for users with UID 0 (should only be root)
        uid_zero_result = self._run_command('awk -F: \'$3 == 0 {print $1}\' /etc/passwd', shell=True)
        uid_zero_users = uid_zero_result.get('stdout', '').split('\\n')
        checks['uid_zero_users'] = {
            'status': 'PASS' if uid_zero_users == ['root'] else 'FAIL',
            'details': 'Only root should have UID 0',
            'evidence': f'Users with UID 0: {", ".join(uid_zero_users)}'
        }
        
        # Check for accounts with empty passwords
        empty_passwords_result = self._run_command('awk -F: \'$2 == "" {print $1}\' /etc/shadow', shell=True)
        empty_passwords = empty_passwords_result.get('stdout', '').strip()
        checks['empty_passwords'] = {
            'status': 'PASS' if not empty_passwords else 'FAIL',
            'details': 'No accounts should have empty passwords',
            'evidence': f'Accounts with empty passwords: {empty_passwords if empty_passwords else "None"}'
        }
        
        return checks
    
    def run_all_checks(self):
        """Run all security checks"""
        print("🔍 Running Security Compliance Scan...")
        
        # Run all check categories
        check_categories = [
            ('Password Policy', self.check_password_policy),
            ('File Permissions', self.check_file_permissions),
            ('SSH Configuration', self.check_ssh_configuration),
            ('Firewall Status', self.check_firewall_status),
            ('System Updates', self.check_system_updates),
            ('User Accounts', self.check_user_accounts)
        ]
        
        for category_name, check_function in check_categories:
            print(f"  ✓ Checking {category_name}...")
            try:
                category_results = check_function()
                self.results['checks'][category_name.lower().replace(' ', '_')] = category_results
            except Exception as e:
                self.results['checks'][category_name.lower().replace(' ', '_')] = {
                    'error': str(e)
                }
        
        # Generate summary
        self._generate_summary()
        
        return self.results
    
    def _generate_summary(self):
        """Generate compliance summary"""
        total_checks = 0
        passed_checks = 0
        failed_checks = 0
        warning_checks = 0
        
        for category, checks in self.results['checks'].items():
            if isinstance(checks, dict) and 'error' not in checks:
                for check_name, check_result in checks.items():
                    if isinstance(check_result, dict) and 'status' in check_result:
                        total_checks += 1
                        if check_result['status'] == 'PASS':
                            passed_checks += 1
                        elif check_result['status'] == 'FAIL':
                            failed_checks += 1
                        elif check_result['status'] == 'WARN':
                            warning_checks += 1
        
        compliance_percentage = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        self.results['summary'] = {
            'total_checks': total_checks,
            'passed': passed_checks,
            'failed': failed_checks,
            'warnings': warning_checks,
            'compliance_percentage': round(compliance_percentage, 2)
        }
    
    def generate_report(self):
        """Generate a formatted report"""
        print("\\n" + "="*80)
        print("🔐 SECURITY COMPLIANCE SCAN REPORT")
        print("="*80)
        
        # System Information
        print(f"📋 System: {self.results['system'].get('PRETTY_NAME', 'Unknown')}")
        print(f"📅 Scan Date: {self.results['scan_date']}")
        
        # Summary
        summary = self.results['summary']
        print(f"\\n📊 COMPLIANCE SUMMARY:")
        print(f"   Total Checks: {summary['total_checks']}")
        print(f"   ✅ Passed: {summary['passed']}")
        print(f"   ❌ Failed: {summary['failed']}")
        print(f"   ⚠️  Warnings: {summary['warnings']}")
        print(f"   📈 Compliance Score: {summary['compliance_percentage']:.1f}%")
        
        # Detailed Results
        print("\\n📝 DETAILED RESULTS:")
        for category, checks in self.results['checks'].items():
            if isinstance(checks, dict) and 'error' not in checks:
                print(f"\\n🔍 {category.replace('_', ' ').title()}:")
                for check_name, check_result in checks.items():
                    if isinstance(check_result, dict) and 'status' in check_result:
                        status_icon = {
                            'PASS': '✅',
                            'FAIL': '❌',
                            'WARN': '⚠️',
                            'INFO': 'ℹ️',
                            'ERROR': '🚨'
                        }.get(check_result['status'], '?')
                        
                        print(f"   {status_icon} {check_result['details']}")
                        if check_result.get('evidence'):
                            print(f"      Evidence: {check_result['evidence']}")
        
        print("\\n" + "="*80)
        
        # Save JSON report
        with open('/home/chironex/comp_agent_claude/scan_results/custom_compliance_report.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print("💾 Full report saved to: scan_results/custom_compliance_report.json")


if __name__ == "__main__":
    scanner = SecurityComplianceScanner()
    scanner.run_all_checks()
    scanner.generate_report()
