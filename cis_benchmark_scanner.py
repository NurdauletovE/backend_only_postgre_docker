#!/usr/bin/env python3
"""
CIS Benchmark Security Compliance Scanner
Implements CIS Controls and Ubuntu Linux Benchmark checks
Based on CIS Controls v8 and CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0
"""

import os
import subprocess
import json
import pwd
import grp
import stat
import re
from datetime import datetime
from pathlib import Path

class CISBenchmarkScanner:
    def __init__(self):
        self.results = {
            'scan_date': datetime.now().isoformat(),
            'benchmark': 'CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0',
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
    
    def _check_file_permissions(self, file_path, expected_mode, expected_owner='root', expected_group='root'):
        """Helper to check file permissions"""
        try:
            if not os.path.exists(file_path):
                return {'status': 'FAIL', 'reason': 'File does not exist'}
            
            file_stat = os.stat(file_path)
            actual_mode = stat.S_IMODE(file_stat.st_mode)
            actual_owner = pwd.getpwuid(file_stat.st_uid).pw_name
            actual_group = grp.getgrgid(file_stat.st_gid).gr_name
            
            issues = []
            if actual_mode != expected_mode:
                issues.append(f"Mode: expected {oct(expected_mode)}, got {oct(actual_mode)}")
            if actual_owner != expected_owner:
                issues.append(f"Owner: expected {expected_owner}, got {actual_owner}")
            if actual_group != expected_group:
                issues.append(f"Group: expected {expected_group}, got {actual_group}")
            
            if issues:
                return {'status': 'FAIL', 'reason': '; '.join(issues)}
            else:
                return {'status': 'PASS', 'reason': f'Correct permissions: {oct(expected_mode)} {expected_owner}:{expected_group}'}
        except Exception as e:
            return {'status': 'ERROR', 'reason': str(e)}

    # CIS Control 1: Inventory and Control of Hardware Assets
    def cis_1_1_filesystem_configuration(self):
        """CIS 1.1.x - Filesystem Configuration"""
        checks = {}
        
        # 1.1.1 Disable unused filesystems
        unused_filesystems = ['cramfs', 'freevxfs', 'jffs2', 'hfs', 'hfsplus', 'squashfs', 'udf']
        for fs in unused_filesystems:
            result = self._run_command(f'modprobe -n -v {fs}', shell=True)
            lsmod_result = self._run_command(f'lsmod | grep {fs}', shell=True)
            
            checks[f'1.1.1_{fs}_disabled'] = {
                'status': 'PASS' if ('install /bin/true' in result.get('stdout', '') and 
                                   lsmod_result['returncode'] != 0) else 'FAIL',
                'details': f'Ensure mounting of {fs} filesystems is disabled',
                'evidence': result.get('stdout', 'No output'),
                'remediation': f'echo "install {fs} /bin/true" >> /etc/modprobe.d/{fs}.conf'
            }
        
        # 1.1.2 Check /tmp partition
        tmp_mount = self._run_command('mount | grep -E "\\s/tmp\\s"', shell=True)
        checks['1.1.2_tmp_partition'] = {
            'status': 'PASS' if tmp_mount['returncode'] == 0 else 'FAIL',
            'details': 'Ensure /tmp is configured as separate partition',
            'evidence': tmp_mount.get('stdout', 'No separate /tmp partition'),
            'remediation': 'Configure /tmp as separate partition or tmpfs'
        }
        
        # 1.1.3 Check /tmp mount options
        if tmp_mount['returncode'] == 0:
            tmp_options = tmp_mount.get('stdout', '')
            required_options = ['nodev', 'nosuid', 'noexec']
            missing_options = [opt for opt in required_options if opt not in tmp_options]
            
            checks['1.1.3_tmp_mount_options'] = {
                'status': 'PASS' if not missing_options else 'FAIL',
                'details': 'Ensure nodev, nosuid, and noexec options set on /tmp partition',
                'evidence': f'Current options: {tmp_options}',
                'remediation': f'Add missing options: {", ".join(missing_options)}' if missing_options else 'All options present'
            }
        
        return checks
    
    # CIS Control 2: Inventory and Control of Software Assets
    def cis_1_2_software_updates(self):
        """CIS 1.2.x - Software Updates"""
        checks = {}
        
        # 1.2.1 Ensure package manager repositories are configured
        sources_list = self._run_command('apt-cache policy', shell=True)
        checks['1.2.1_package_repositories'] = {
            'status': 'PASS' if sources_list['returncode'] == 0 else 'FAIL',
            'details': 'Ensure package manager repositories are configured',
            'evidence': f'Repository sources configured: {sources_list["returncode"] == 0}',
            'remediation': 'Configure /etc/apt/sources.list and /etc/apt/sources.list.d/'
        }
        
        # 1.2.2 Ensure GPG keys are configured
        gpg_keys = self._run_command('apt-key list', shell=True)
        checks['1.2.2_gpg_keys'] = {
            'status': 'PASS' if gpg_keys['returncode'] == 0 else 'FAIL',
            'details': 'Ensure GPG keys are configured',
            'evidence': f'GPG keys present: {gpg_keys["returncode"] == 0}',
            'remediation': 'Configure GPG keys for package verification'
        }
        
        return checks
    
    # CIS Control 3: Continuous Vulnerability Management
    def cis_1_3_filesystem_integrity(self):
        """CIS 1.3.x - Filesystem Integrity Checking"""
        checks = {}
        
        # 1.3.1 Ensure AIDE is installed
        aide_installed = self._run_command('dpkg -l | grep aide', shell=True)
        checks['1.3.1_aide_installed'] = {
            'status': 'PASS' if aide_installed['returncode'] == 0 else 'FAIL',
            'details': 'Ensure AIDE is installed',
            'evidence': f'AIDE installed: {aide_installed["returncode"] == 0}',
            'remediation': 'apt install aide aide-common'
        }
        
        # 1.3.2 Ensure filesystem integrity is regularly checked
        if aide_installed['returncode'] == 0:
            aide_cron = self._run_command('crontab -l | grep aide', shell=True)
            checks['1.3.2_aide_cron'] = {
                'status': 'PASS' if aide_cron['returncode'] == 0 else 'FAIL',
                'details': 'Ensure filesystem integrity is regularly checked',
                'evidence': f'AIDE cron job configured: {aide_cron["returncode"] == 0}',
                'remediation': 'Configure cron job for regular AIDE checks'
            }
        
        return checks
    
    # CIS Control 4: Secure Configuration of Enterprise Assets
    def cis_1_4_secure_boot(self):
        """CIS 1.4.x - Secure Boot Settings"""
        checks = {}
        
        # 1.4.1 Ensure permissions on bootloader config are configured
        grub_config_paths = ['/boot/grub/grub.cfg', '/boot/grub2/grub.cfg']
        for grub_path in grub_config_paths:
            if os.path.exists(grub_path):
                perm_check = self._check_file_permissions(grub_path, 0o400, 'root', 'root')
                checks[f'1.4.1_grub_permissions_{grub_path.replace("/", "_")}'] = {
                    'status': perm_check['status'],
                    'details': f'Ensure permissions on {grub_path} are configured',
                    'evidence': perm_check['reason'],
                    'remediation': f'chown root:root {grub_path}; chmod 400 {grub_path}'
                }
        
        # 1.4.2 Ensure bootloader password is set
        grub_password = self._run_command('grep "^password" /boot/grub/grub.cfg', shell=True)
        checks['1.4.2_bootloader_password'] = {
            'status': 'PASS' if grub_password['returncode'] == 0 else 'FAIL',
            'details': 'Ensure bootloader password is set',
            'evidence': f'Bootloader password set: {grub_password["returncode"] == 0}',
            'remediation': 'Configure GRUB password in /etc/grub.d/40_custom'
        }
        
        return checks
    
    # CIS Control 5: Account Management
    def cis_5_access_control(self):
        """CIS 5.x - Access, Authentication and Authorization"""
        checks = {}
        
        # 5.1.1 Ensure cron daemon is enabled
        cron_enabled = self._run_command('systemctl is-enabled cron', shell=True)
        checks['5.1.1_cron_enabled'] = {
            'status': 'PASS' if 'enabled' in cron_enabled.get('stdout', '') else 'FAIL',
            'details': 'Ensure cron daemon is enabled',
            'evidence': f'Cron status: {cron_enabled.get("stdout", "disabled")}',
            'remediation': 'systemctl enable cron'
        }
        
        # 5.1.2 Ensure permissions on /etc/crontab are configured
        crontab_perm = self._check_file_permissions('/etc/crontab', 0o600, 'root', 'root')
        checks['5.1.2_crontab_permissions'] = {
            'status': crontab_perm['status'],
            'details': 'Ensure permissions on /etc/crontab are configured',
            'evidence': crontab_perm['reason'],
            'remediation': 'chown root:root /etc/crontab; chmod 600 /etc/crontab'
        }
        
        # 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured
        sshd_config_perm = self._check_file_permissions('/etc/ssh/sshd_config', 0o600, 'root', 'root')
        checks['5.2.1_sshd_config_permissions'] = {
            'status': sshd_config_perm['status'],
            'details': 'Ensure permissions on /etc/ssh/sshd_config are configured',
            'evidence': sshd_config_perm['reason'],
            'remediation': 'chown root:root /etc/ssh/sshd_config; chmod 600 /etc/ssh/sshd_config'
        }
        
        # 5.2.2 Ensure SSH access is limited
        ssh_config_file = '/etc/ssh/sshd_config'
        if os.path.exists(ssh_config_file):
            allow_users = self._run_command(f'grep "^AllowUsers" {ssh_config_file}', shell=True)
            allow_groups = self._run_command(f'grep "^AllowGroups" {ssh_config_file}', shell=True)
            deny_users = self._run_command(f'grep "^DenyUsers" {ssh_config_file}', shell=True)
            deny_groups = self._run_command(f'grep "^DenyGroups" {ssh_config_file}', shell=True)
            
            access_controls = [allow_users, allow_groups, deny_users, deny_groups]
            has_access_control = any(result['returncode'] == 0 for result in access_controls)
            
            checks['5.2.2_ssh_access_limited'] = {
                'status': 'PASS' if has_access_control else 'WARN',
                'details': 'Ensure SSH access is limited',
                'evidence': f'SSH access controls configured: {has_access_control}',
                'remediation': 'Configure AllowUsers, AllowGroups, DenyUsers, or DenyGroups in sshd_config'
            }
        
        # 5.2.3 Ensure permissions on SSH private host key files are configured
        ssh_keys = self._run_command('find /etc/ssh -xdev -type f -name "ssh_host_*_key"', shell=True)
        if ssh_keys['returncode'] == 0:
            key_files = ssh_keys['stdout'].split('\n')
            for key_file in key_files:
                if key_file.strip():
                    key_perm = self._check_file_permissions(key_file, 0o600, 'root', 'root')
                    checks[f'5.2.3_ssh_private_key_{key_file.replace("/", "_")}'] = {
                        'status': key_perm['status'],
                        'details': f'Ensure permissions on {key_file} are configured',
                        'evidence': key_perm['reason'],
                        'remediation': f'chown root:root {key_file}; chmod 600 {key_file}'
                    }
        
        return checks
    
    # CIS Control 6: Access Control Management
    def cis_5_authentication_authorization(self):
        """CIS 5.x - Authentication and Authorization"""
        checks = {}
        
        # 5.3.1 Ensure password creation requirements are configured
        pwquality_config = self._run_command('grep -E "^(minlen|dcredit|ucredit|lcredit|ocredit)" /etc/security/pwquality.conf', shell=True)
        checks['5.3.1_password_requirements'] = {
            'status': 'PASS' if pwquality_config['returncode'] == 0 else 'FAIL',
            'details': 'Ensure password creation requirements are configured',
            'evidence': f'Password requirements configured: {pwquality_config["returncode"] == 0}',
            'remediation': 'Configure password complexity in /etc/security/pwquality.conf'
        }
        
        # 5.3.2 Ensure lockout for failed password attempts is configured
        faillock_config = self._run_command('grep -E "pam_faillock" /etc/pam.d/common-auth', shell=True)
        checks['5.3.2_password_lockout'] = {
            'status': 'PASS' if faillock_config['returncode'] == 0 else 'FAIL',
            'details': 'Ensure lockout for failed password attempts is configured',
            'evidence': f'Account lockout configured: {faillock_config["returncode"] == 0}',
            'remediation': 'Configure pam_faillock in PAM configuration'
        }
        
        # 5.3.3 Ensure password reuse is limited
        password_history = self._run_command('grep -E "remember=" /etc/pam.d/common-password', shell=True)
        checks['5.3.3_password_reuse'] = {
            'status': 'PASS' if password_history['returncode'] == 0 else 'FAIL',
            'details': 'Ensure password reuse is limited',
            'evidence': f'Password history configured: {password_history["returncode"] == 0}',
            'remediation': 'Configure password history in /etc/pam.d/common-password'
        }
        
        # 5.3.4 Ensure password hashing algorithm is SHA-512
        sha512_config = self._run_command('grep -E "^ENCRYPT_METHOD\\s+SHA512" /etc/login.defs', shell=True)
        checks['5.3.4_password_hashing'] = {
            'status': 'PASS' if sha512_config['returncode'] == 0 else 'FAIL',
            'details': 'Ensure password hashing algorithm is SHA-512',
            'evidence': f'SHA-512 hashing configured: {sha512_config["returncode"] == 0}',
            'remediation': 'Set ENCRYPT_METHOD SHA512 in /etc/login.defs'
        }
        
        return checks
    
    # CIS Control 7: Email and Web Browser Protections
    def cis_6_system_maintenance(self):
        """CIS 6.x - System Maintenance"""
        checks = {}
        
        # 6.1.1 Audit system file permissions
        critical_files = {
            '/etc/passwd': 0o644,
            '/etc/shadow': 0o640,
            '/etc/group': 0o644,
            '/etc/gshadow': 0o640
        }
        
        for file_path, expected_mode in critical_files.items():
            perm_check = self._check_file_permissions(file_path, expected_mode, 'root', 'root')
            checks[f'6.1.1_permissions_{file_path.replace("/", "_")}'] = {
                'status': perm_check['status'],
                'details': f'Audit system file permissions for {file_path}',
                'evidence': perm_check['reason'],
                'remediation': f'chown root:root {file_path}; chmod {oct(expected_mode)} {file_path}'
            }
        
        # 6.1.2 Ensure no world writable files exist
        world_writable = self._run_command('find / -xdev -type f -perm -0002 2>/dev/null', shell=True)
        world_writable_count = len([f for f in world_writable.get('stdout', '').split('\n') if f.strip()])
        checks['6.1.2_world_writable_files'] = {
            'status': 'PASS' if world_writable_count == 0 else 'FAIL',
            'details': 'Ensure no world writable files exist',
            'evidence': f'World writable files found: {world_writable_count}',
            'remediation': 'Review and fix permissions on world writable files'
        }
        
        # 6.1.3 Ensure no unowned files or directories exist
        unowned_files = self._run_command('find / -xdev -nouser 2>/dev/null', shell=True)
        unowned_count = len([f for f in unowned_files.get('stdout', '').split('\n') if f.strip()])
        checks['6.1.3_unowned_files'] = {
            'status': 'PASS' if unowned_count == 0 else 'FAIL',
            'details': 'Ensure no unowned files or directories exist',
            'evidence': f'Unowned files found: {unowned_count}',
            'remediation': 'Review and assign ownership to unowned files'
        }
        
        # 6.2.1 Ensure password fields are not empty
        empty_passwords = self._run_command('awk -F: \'($2 == "" ) { print $1 " does not have a password "}\' /etc/shadow', shell=True)
        checks['6.2.1_empty_passwords'] = {
            'status': 'PASS' if not empty_passwords.get('stdout', '').strip() else 'FAIL',
            'details': 'Ensure password fields are not empty',
            'evidence': f'Users with empty passwords: {empty_passwords.get("stdout", "None")}',
            'remediation': 'Set passwords for users with empty password fields'
        }
        
        # 6.2.2 Ensure no legacy "+" entries exist in passwd files
        legacy_passwd = self._run_command('grep "^+:" /etc/passwd', shell=True)
        checks['6.2.2_legacy_passwd_entries'] = {
            'status': 'PASS' if legacy_passwd['returncode'] != 0 else 'FAIL',
            'details': 'Ensure no legacy "+" entries exist in /etc/passwd',
            'evidence': f'Legacy entries found: {legacy_passwd["returncode"] == 0}',
            'remediation': 'Remove legacy "+" entries from /etc/passwd'
        }
        
        return checks
    
    # CIS Control 8: Malware Defenses
    def cis_3_network_configuration(self):
        """CIS 3.x - Network Configuration"""
        checks = {}
        
        # 3.1.1 Disable unused network protocols
        network_protocols = ['dccp', 'sctp', 'rds', 'tipc']
        for protocol in network_protocols:
            protocol_check = self._run_command(f'modprobe -n -v {protocol}', shell=True)
            checks[f'3.1.1_{protocol}_disabled'] = {
                'status': 'PASS' if 'install /bin/true' in protocol_check.get('stdout', '') else 'FAIL',
                'details': f'Ensure {protocol} is disabled',
                'evidence': protocol_check.get('stdout', 'Not disabled'),
                'remediation': f'echo "install {protocol} /bin/true" >> /etc/modprobe.d/{protocol}.conf'
            }
        
        # 3.2.1 Ensure source routed packets are not accepted
        sysctl_params = {
            'net.ipv4.conf.all.accept_source_route': '0',
            'net.ipv4.conf.default.accept_source_route': '0',
            'net.ipv6.conf.all.accept_source_route': '0',
            'net.ipv6.conf.default.accept_source_route': '0'
        }
        
        for param, expected_value in sysctl_params.items():
            sysctl_check = self._run_command(f'sysctl {param}', shell=True)
            current_value = sysctl_check.get('stdout', '').split('=')[-1].strip()
            
            checks[f'3.2.1_{param.replace(".", "_")}'] = {
                'status': 'PASS' if current_value == expected_value else 'FAIL',
                'details': f'Ensure {param} is set to {expected_value}',
                'evidence': f'Current value: {current_value}',
                'remediation': f'sysctl -w {param}={expected_value}'
            }
        
        # 3.3.1 Ensure IPv6 router advertisements are not accepted
        ipv6_params = {
            'net.ipv6.conf.all.accept_ra': '0',
            'net.ipv6.conf.default.accept_ra': '0'
        }
        
        for param, expected_value in ipv6_params.items():
            sysctl_check = self._run_command(f'sysctl {param}', shell=True)
            current_value = sysctl_check.get('stdout', '').split('=')[-1].strip()
            
            checks[f'3.3.1_{param.replace(".", "_")}'] = {
                'status': 'PASS' if current_value == expected_value else 'FAIL',
                'details': f'Ensure {param} is set to {expected_value}',
                'evidence': f'Current value: {current_value}',
                'remediation': f'sysctl -w {param}={expected_value}'
            }
        
        return checks
    
    # CIS Control 9: Email and Web Browser Protections
    def cis_4_logging_auditing(self):
        """CIS 4.x - Logging and Auditing"""
        checks = {}
        
        # 4.1.1 Ensure auditing is enabled
        auditd_enabled = self._run_command('systemctl is-enabled auditd', shell=True)
        checks['4.1.1_auditd_enabled'] = {
            'status': 'PASS' if 'enabled' in auditd_enabled.get('stdout', '') else 'FAIL',
            'details': 'Ensure auditing is enabled',
            'evidence': f'Auditd status: {auditd_enabled.get("stdout", "disabled")}',
            'remediation': 'systemctl enable auditd'
        }
        
        # 4.2.1 Ensure rsyslog is installed
        rsyslog_installed = self._run_command('dpkg -l | grep rsyslog', shell=True)
        checks['4.2.1_rsyslog_installed'] = {
            'status': 'PASS' if rsyslog_installed['returncode'] == 0 else 'FAIL',
            'details': 'Ensure rsyslog is installed',
            'evidence': f'Rsyslog installed: {rsyslog_installed["returncode"] == 0}',
            'remediation': 'apt install rsyslog'
        }
        
        # 4.2.2 Ensure rsyslog Service is enabled
        rsyslog_enabled = self._run_command('systemctl is-enabled rsyslog', shell=True)
        checks['4.2.2_rsyslog_enabled'] = {
            'status': 'PASS' if 'enabled' in rsyslog_enabled.get('stdout', '') else 'FAIL',
            'details': 'Ensure rsyslog Service is enabled',
            'evidence': f'Rsyslog status: {rsyslog_enabled.get("stdout", "disabled")}',
            'remediation': 'systemctl enable rsyslog'
        }
        
        # 4.2.3 Ensure rsyslog default file permissions configured
        rsyslog_permissions = self._run_command('grep "^$FileCreateMode" /etc/rsyslog.conf', shell=True)
        checks['4.2.3_rsyslog_permissions'] = {
            'status': 'PASS' if '0640' in rsyslog_permissions.get('stdout', '') else 'FAIL',
            'details': 'Ensure rsyslog default file permissions configured',
            'evidence': f'File permissions: {rsyslog_permissions.get("stdout", "Not configured")}',
            'remediation': 'Add "$FileCreateMode 0640" to /etc/rsyslog.conf'
        }
        
        return checks
    
    def run_all_checks(self):
        """Run all CIS benchmark checks"""
        print("🔍 Running CIS Benchmark Compliance Scan...")
        
        # Run all check categories
        check_categories = [
            ('1.1 Filesystem Configuration', self.cis_1_1_filesystem_configuration),
            ('1.2 Software Updates', self.cis_1_2_software_updates),
            ('1.3 Filesystem Integrity', self.cis_1_3_filesystem_integrity),
            ('1.4 Secure Boot', self.cis_1_4_secure_boot),
            ('3.x Network Configuration', self.cis_3_network_configuration),
            ('4.x Logging and Auditing', self.cis_4_logging_auditing),
            ('5.x Access Control', self.cis_5_access_control),
            ('5.x Authentication', self.cis_5_authentication_authorization),
            ('6.x System Maintenance', self.cis_6_system_maintenance)
        ]
        
        for category_name, check_function in check_categories:
            print(f"  ✓ Checking {category_name}...")
            try:
                category_results = check_function()
                self.results['checks'][category_name.lower().replace(' ', '_').replace('.', '_')] = category_results
            except Exception as e:
                self.results['checks'][category_name.lower().replace(' ', '_').replace('.', '_')] = {
                    'error': str(e)
                }
        
        # Generate summary
        self._generate_summary()
        
        return self.results
    
    def _generate_summary(self):
        """Generate CIS compliance summary"""
        total_checks = 0
        passed_checks = 0
        failed_checks = 0
        warning_checks = 0
        error_checks = 0
        
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
                        elif check_result['status'] == 'ERROR':
                            error_checks += 1
        
        compliance_percentage = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        self.results['summary'] = {
            'total_checks': total_checks,
            'passed': passed_checks,
            'failed': failed_checks,
            'warnings': warning_checks,
            'errors': error_checks,
            'compliance_percentage': round(compliance_percentage, 2)
        }
    
    def generate_report(self):
        """Generate a formatted CIS compliance report"""
        print("\n" + "="*80)
        print("🏛️  CIS BENCHMARK COMPLIANCE REPORT")
        print("="*80)
        
        # System Information
        print(f"📋 System: {self.results['system'].get('PRETTY_NAME', 'Unknown')}")
        print(f"📖 Benchmark: {self.results['benchmark']}")
        print(f"📅 Scan Date: {self.results['scan_date']}")
        
        # Summary
        summary = self.results['summary']
        print(f"\n📊 CIS COMPLIANCE SUMMARY:")
        print(f"   Total Checks: {summary['total_checks']}")
        print(f"   ✅ Passed: {summary['passed']}")
        print(f"   ❌ Failed: {summary['failed']}")
        print(f"   ⚠️  Warnings: {summary['warnings']}")
        print(f"   🚨 Errors: {summary['errors']}")
        print(f"   📈 CIS Compliance Score: {summary['compliance_percentage']:.1f}%")
        
        # Compliance Level Assessment
        compliance_level = "Non-Compliant"
        if summary['compliance_percentage'] >= 95:
            compliance_level = "Excellent (CIS Level 1+ Ready)"
        elif summary['compliance_percentage'] >= 85:
            compliance_level = "Good (CIS Level 1 Ready)"
        elif summary['compliance_percentage'] >= 70:
            compliance_level = "Fair (Needs Improvement)"
        elif summary['compliance_percentage'] >= 50:
            compliance_level = "Poor (Significant Issues)"
        
        print(f"   🎯 Compliance Level: {compliance_level}")
        
        # Detailed Results
        print("\n📝 DETAILED CIS BENCHMARK RESULTS:")
        for category, checks in self.results['checks'].items():
            if isinstance(checks, dict) and 'error' not in checks:
                print(f"\n🔍 {category.replace('_', ' ').title()}:")
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
                        if check_result.get('remediation') and check_result['status'] in ['FAIL', 'WARN']:
                            print(f"      Remediation: {check_result['remediation']}")
        
        print("\n" + "="*80)
        
        # Save JSON report
        report_path = '/home/chironex/comp_agent_claude/scan_results/cis_benchmark_report.json'
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"💾 Full CIS Benchmark report saved to: {report_path}")
        
        # Generate remediation script
        self._generate_remediation_script()
    
    def _generate_remediation_script(self):
        """Generate automated remediation script"""
        script_path = '/home/chironex/comp_agent_claude/scan_results/cis_remediation.sh'
        
        with open(script_path, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write("# CIS Benchmark Remediation Script\n")
            f.write("# Generated by CIS Benchmark Scanner\n")
            f.write(f"# Date: {self.results['scan_date']}\n\n")
            f.write("echo 'Starting CIS Benchmark Remediation...'\n\n")
            
            for category, checks in self.results['checks'].items():
                if isinstance(checks, dict) and 'error' not in checks:
                    f.write(f"# {category.replace('_', ' ').title()}\n")
                    for check_name, check_result in checks.items():
                        if (isinstance(check_result, dict) and 
                            check_result.get('status') == 'FAIL' and 
                            check_result.get('remediation')):
                            f.write(f"echo 'Fixing: {check_result['details']}'\n")
                            f.write(f"{check_result['remediation']}\n\n")
            
            f.write("echo 'CIS Benchmark Remediation Complete'\n")
            f.write("echo 'Please review changes and reboot if necessary'\n")
        
        os.chmod(script_path, 0o755)
        print(f"🛠️  Remediation script generated: {script_path}")
        print("   Run with: sudo ./scan_results/cis_remediation.sh")


if __name__ == "__main__":
    scanner = CISBenchmarkScanner()
    scanner.run_all_checks()
    scanner.generate_report()
