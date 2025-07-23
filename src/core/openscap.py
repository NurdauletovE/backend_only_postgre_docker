import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timezone
import logging
import asyncio

logger = logging.getLogger(__name__)


class OpenSCAPAgent:
    def __init__(self, content_path: str = "/usr/share/xml/scap/ssg/content/"):
        self.content_path = Path(content_path)
        
    async def scan_system(self, profile: str, datastream: str, output_dir: Optional[str] = None) -> Dict:
        """Execute OpenSCAP scan and return structured results"""
        if output_dir is None:
            output_dir = Path.cwd() / "scan_results"
        else:
            output_dir = Path(output_dir)
        
        output_dir.mkdir(exist_ok=True)
        
        results_file = output_dir / "results.xml"
        report_file = output_dir / "report.html"
        
        cmd = [
            "oscap", "xccdf", "eval",
            "--profile", profile,
            "--results-arf", str(results_file),
            "--report", str(report_file),
            "--oval-results",
            str(self.content_path / datastream)
        ]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode not in [0, 2]:  # 0 = success, 2 = some rules failed
                logger.error(f"OpenSCAP scan failed: {stderr.decode()}")
                raise RuntimeError(f"OpenSCAP scan failed with return code {process.returncode}")
            
            return await self._parse_results(str(results_file))
            
        except FileNotFoundError:
            logger.error("OpenSCAP tools not found. Please install openscap-utils package.")
            raise RuntimeError("OpenSCAP tools not installed")
        except Exception as e:
            logger.error(f"Error during OpenSCAP scan: {e}")
            raise
    
    async def _parse_results(self, results_file: str) -> Dict:
        """Parse OpenSCAP ARF results into structured format"""
        try:
            tree = ET.parse(results_file)
            root = tree.getroot()
            
            # Define namespaces
            namespaces = {
                'arf': 'http://scap.nist.gov/schema/asset-reporting-format/1.1',
                'xccdf': 'http://checklists.nist.gov/xccdf/1.2',
                'oval': 'http://oval.mitre.org/XMLSchema/oval-results-5'
            }
            
            return {
                "timestamp": self._get_timestamp(root, namespaces),
                "profile": self._get_profile(root, namespaces),
                "rules": self._extract_rules(root, namespaces),
                "score": self._calculate_score(root, namespaces),
                "system_info": self._get_system_info(root, namespaces)
            }
        except Exception as e:
            logger.error(f"Error parsing OpenSCAP results: {e}")
            raise
    
    def _get_timestamp(self, root: ET.Element, namespaces: Dict[str, str]) -> str:
        """Extract scan timestamp from results"""
        try:
            # Look for TestResult start-time
            test_result = root.find('.//xccdf:TestResult', namespaces)
            if test_result is not None and 'start-time' in test_result.attrib:
                return test_result.attrib['start-time']
            
            # Fallback to current timestamp
            return datetime.now(timezone.utc).isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()
    
    def _get_profile(self, root: ET.Element, namespaces: Dict[str, str]) -> str:
        """Extract profile ID from results"""
        try:
            test_result = root.find('.//xccdf:TestResult', namespaces)
            if test_result is not None:
                profile_elem = test_result.find('xccdf:profile', namespaces)
                if profile_elem is not None and 'idref' in profile_elem.attrib:
                    return profile_elem.attrib['idref']
            return "unknown"
        except Exception:
            return "unknown"
    
    def _extract_rules(self, root: ET.Element, namespaces: Dict[str, str]) -> List[Dict]:
        """Extract rule results from scan"""
        rules = []
        try:
            rule_results = root.findall('.//xccdf:rule-result', namespaces)
            
            for rule_result in rule_results:
                rule_id = rule_result.attrib.get('idref', 'unknown')
                result_elem = rule_result.find('xccdf:result', namespaces)
                result = result_elem.text if result_elem is not None else 'unknown'
                
                # Extract rule details from benchmark
                rule_info = self._get_rule_info(root, rule_id, namespaces)
                
                rules.append({
                    "id": rule_id,
                    "result": result,
                    "title": rule_info.get("title", ""),
                    "severity": rule_info.get("severity", "unknown"),
                    "description": rule_info.get("description", ""),
                    "remediation": rule_info.get("remediation", "")
                })
                
        except Exception as e:
            logger.error(f"Error extracting rules: {e}")
        
        return rules
    
    def _get_rule_info(self, root: ET.Element, rule_id: str, namespaces: Dict[str, str]) -> Dict:
        """Get detailed rule information from benchmark"""
        try:
            # Find the rule in the benchmark
            rule_xpath = f".//xccdf:Rule[@id='{rule_id}']"
            rule_elem = root.find(rule_xpath, namespaces)
            
            if rule_elem is None:
                return {}
            
            title_elem = rule_elem.find('xccdf:title', namespaces)
            desc_elem = rule_elem.find('xccdf:description', namespaces)
            
            return {
                "title": title_elem.text if title_elem is not None else "",
                "severity": rule_elem.attrib.get('severity', 'unknown'),
                "description": desc_elem.text if desc_elem is not None else "",
                "remediation": self._extract_remediation(rule_elem, namespaces)
            }
        except Exception:
            return {}
    
    def _extract_remediation(self, rule_elem: ET.Element, namespaces: Dict[str, str]) -> str:
        """Extract remediation information from rule"""
        try:
            fix_elem = rule_elem.find('xccdf:fixtext', namespaces)
            if fix_elem is not None:
                return fix_elem.text or ""
            return ""
        except Exception:
            return ""
    
    def _calculate_score(self, root: ET.Element, namespaces: Dict[str, str]) -> float:
        """Calculate compliance score from results"""
        try:
            score_elem = root.find('.//xccdf:score', namespaces)
            if score_elem is not None and score_elem.text:
                return float(score_elem.text)
            
            # Fallback: calculate based on pass/fail ratio
            rule_results = root.findall('.//xccdf:rule-result', namespaces)
            if not rule_results:
                return 0.0
            
            passed = sum(1 for rr in rule_results 
                        if rr.find('xccdf:result', namespaces) is not None 
                        and rr.find('xccdf:result', namespaces).text == 'pass')
            
            return passed / len(rule_results) * 100.0
            
        except Exception as e:
            logger.error(f"Error calculating score: {e}")
            return 0.0
    
    def _get_system_info(self, root: ET.Element, namespaces: Dict[str, str]) -> Dict:
        """Extract system information from scan results"""
        try:
            target_elem = root.find('.//xccdf:target', namespaces)
            target = target_elem.text if target_elem is not None else "unknown"
            
            return {
                "target": target,
                "scanner": "OpenSCAP",
                "scan_type": "CIS Benchmark"
            }
        except Exception:
            return {
                "target": "unknown",
                "scanner": "OpenSCAP",
                "scan_type": "CIS Benchmark"
            }
    
    async def get_available_profiles(self, datastream: str) -> List[Dict]:
        """Get list of available profiles from datastream"""
        cmd = [
            "oscap", "info",
            str(self.content_path / datastream)
        ]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Failed to get profiles: {stderr.decode()}")
                return []
            
            return self._parse_profile_info(stdout.decode())
            
        except Exception as e:
            logger.error(f"Error getting available profiles: {e}")
            return []
    
    def _parse_profile_info(self, info_output: str) -> List[Dict]:
        """Parse oscap info output to extract profile information"""
        profiles = []
        in_profiles_section = False
        
        for line in info_output.split('\n'):
            line = line.strip()
            
            if 'Profiles:' in line:
                in_profiles_section = True
                continue
            
            if in_profiles_section and line.startswith('Id:'):
                profile_id = line.replace('Id:', '').strip()
                profiles.append({
                    "id": profile_id,
                    "title": "",
                    "description": ""
                })
            elif in_profiles_section and line.startswith('Title:') and profiles:
                profiles[-1]["title"] = line.replace('Title:', '').strip()
            elif in_profiles_section and line.startswith('Description:') and profiles:
                profiles[-1]["description"] = line.replace('Description:', '').strip()
            elif in_profiles_section and line == '':
                # Empty line might indicate end of profiles section
                continue
            elif in_profiles_section and not any(line.startswith(prefix) for prefix in ['Id:', 'Title:', 'Description:']):
                # End of profiles section
                break
        
        return profiles