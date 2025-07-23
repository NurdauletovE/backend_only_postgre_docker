from typing import Dict, List, Any
from pathlib import Path
import logging

from .base import CompliancePlugin, PluginConfig, ScanRequest, ScanResult
from core.openscap import OpenSCAPAgent

logger = logging.getLogger(__name__)


class CISPlugin(CompliancePlugin):
    """Plugin for CIS (Center for Internet Security) compliance scanning"""
    
    def __init__(self, config: PluginConfig):
        super().__init__(config)
        self.openscap_agent = None
        self.content_path = config.settings.get("content_path", "/usr/share/xml/scap/ssg/content/")
    
    @property
    def name(self) -> str:
        return "CIS"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def supported_frameworks(self) -> List[str]:
        return ["CIS", "Center for Internet Security"]
    
    async def initialize(self) -> bool:
        """Initialize the CIS plugin with OpenSCAP agent"""
        try:
            if not await super().initialize():
                return False
            
            self.openscap_agent = OpenSCAPAgent(self.content_path)
            
            # Verify OpenSCAP tools are available
            content_dir = Path(self.content_path)
            if not content_dir.exists():
                self.logger.error(f"OpenSCAP content directory not found: {self.content_path}")
                return False
            
            self.logger.info("CIS plugin initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize CIS plugin: {e}")
            return False
    
    async def scan(self, request: ScanRequest) -> ScanResult:
        """
        Execute CIS compliance scan using OpenSCAP
        
        Args:
            request: Scan request with CIS-specific configuration
            
        Returns:
            Scan result with CIS compliance data
        """
        try:
            if not self.openscap_agent:
                return ScanResult(
                    success=False,
                    data={},
                    error_message="CIS plugin not properly initialized"
                )
            
            # Extract CIS-specific configuration
            profile = request.config.get("profile")
            datastream = request.config.get("datastream")
            
            if not profile or not datastream:
                return ScanResult(
                    success=False,
                    data={},
                    error_message="CIS scan requires 'profile' and 'datastream' parameters"
                )
            
            self.logger.info(f"Starting CIS scan for system {request.system_id} with profile {profile}")
            
            # Execute OpenSCAP scan
            scan_results = await self.openscap_agent.scan_system(
                profile=profile,
                datastream=datastream,
                output_dir=request.output_dir
            )
            
            # Enhance results with CIS-specific metadata
            enhanced_results = self._enhance_cis_results(scan_results, request)
            
            self.logger.info(f"CIS scan completed for system {request.system_id}")
            
            return ScanResult(
                success=True,
                data=enhanced_results,
                metadata={
                    "plugin": self.name,
                    "plugin_version": self.version,
                    "framework": "CIS",
                    "scan_type": "automated"
                }
            )
            
        except Exception as e:
            self.logger.error(f"CIS scan failed for system {request.system_id}: {e}")
            return ScanResult(
                success=False,
                data={},
                error_message=f"CIS scan error: {str(e)}"
            )
    
    def _enhance_cis_results(self, scan_results: Dict, request: ScanRequest) -> Dict:
        """Enhance scan results with CIS-specific information"""
        enhanced = scan_results.copy()
        
        # Add CIS-specific metadata
        enhanced["framework"] = "CIS"
        enhanced["framework_version"] = self._extract_cis_version(request.config.get("profile", ""))
        enhanced["benchmark_type"] = self._determine_benchmark_type(request.config.get("profile", ""))
        
        # Enhance rule results with CIS control mappings
        if "rules" in enhanced:
            enhanced["rules"] = [
                self._enhance_rule_with_cis_info(rule) for rule in enhanced["rules"]
            ]
        
        # Calculate CIS-specific metrics
        enhanced["cis_metrics"] = self._calculate_cis_metrics(enhanced.get("rules", []))
        
        return enhanced
    
    def _extract_cis_version(self, profile: str) -> str:
        """Extract CIS version from profile identifier"""
        # CIS profiles typically contain version information
        # Example: xccdf_org.ssgproject.content_profile_cis_server_l1
        if "cis" in profile.lower():
            # Try to extract version from common patterns
            return "1.0"  # Default version, could be enhanced with regex parsing
        return "unknown"
    
    def _determine_benchmark_type(self, profile: str) -> str:
        """Determine CIS benchmark type from profile"""
        profile_lower = profile.lower()
        
        if "server" in profile_lower:
            if "l1" in profile_lower or "level_1" in profile_lower:
                return "Server Level 1"
            elif "l2" in profile_lower or "level_2" in profile_lower:
                return "Server Level 2"
            return "Server"
        elif "workstation" in profile_lower:
            if "l1" in profile_lower or "level_1" in profile_lower:
                return "Workstation Level 1"
            elif "l2" in profile_lower or "level_2" in profile_lower:
                return "Workstation Level 2"
            return "Workstation"
        elif "l1" in profile_lower or "level_1" in profile_lower:
            return "Level 1"
        elif "l2" in profile_lower or "level_2" in profile_lower:
            return "Level 2"
        
        return "Standard"
    
    def _enhance_rule_with_cis_info(self, rule: Dict) -> Dict:
        """Enhance individual rule with CIS-specific information"""
        enhanced_rule = rule.copy()
        
        # Extract CIS control number from rule ID
        cis_control = self._extract_cis_control(rule.get("id", ""))
        if cis_control:
            enhanced_rule["cis_control"] = cis_control
        
        # Map severity to CIS impact levels
        enhanced_rule["cis_impact"] = self._map_severity_to_impact(rule.get("severity", "unknown"))
        
        return enhanced_rule
    
    def _extract_cis_control(self, rule_id: str) -> str:
        """Extract CIS control number from rule ID"""
        # CIS rule IDs often contain control numbers
        # This is a simplified implementation - could be enhanced with regex patterns
        if "cis" in rule_id.lower():
            # Try to find patterns like "1.1.1" or "2.3"
            import re
            pattern = r'(\d+\.\d+(?:\.\d+)?)'
            match = re.search(pattern, rule_id)
            if match:
                return match.group(1)
        
        return ""
    
    def _map_severity_to_impact(self, severity: str) -> str:
        """Map OpenSCAP severity to CIS impact levels"""
        severity_mapping = {
            "critical": "High",
            "high": "High", 
            "medium": "Medium",
            "low": "Low",
            "unknown": "Unknown"
        }
        return severity_mapping.get(severity.lower(), "Unknown")
    
    def _calculate_cis_metrics(self, rules: List[Dict]) -> Dict:
        """Calculate CIS-specific compliance metrics"""
        if not rules:
            return {}
        
        total_rules = len(rules)
        passed_rules = sum(1 for rule in rules if rule.get("result") == "pass")
        failed_rules = sum(1 for rule in rules if rule.get("result") == "fail")
        
        # Count by CIS impact levels
        high_impact_rules = sum(1 for rule in rules if rule.get("cis_impact") == "High")
        high_impact_passed = sum(1 for rule in rules 
                                if rule.get("cis_impact") == "High" and rule.get("result") == "pass")
        
        medium_impact_rules = sum(1 for rule in rules if rule.get("cis_impact") == "Medium")
        medium_impact_passed = sum(1 for rule in rules 
                                  if rule.get("cis_impact") == "Medium" and rule.get("result") == "pass")
        
        metrics = {
            "total_controls": total_rules,
            "passed_controls": passed_rules,
            "failed_controls": failed_rules,
            "compliance_percentage": (passed_rules / total_rules * 100) if total_rules > 0 else 0,
            "high_impact": {
                "total": high_impact_rules,
                "passed": high_impact_passed,
                "compliance_percentage": (high_impact_passed / high_impact_rules * 100) if high_impact_rules > 0 else 0
            },
            "medium_impact": {
                "total": medium_impact_rules,
                "passed": medium_impact_passed,
                "compliance_percentage": (medium_impact_passed / medium_impact_rules * 100) if medium_impact_rules > 0 else 0
            }
        }
        
        return metrics
    
    def get_supported_profiles(self) -> List[Dict[str, str]]:
        """Get list of supported CIS profiles"""
        return [
            {
                "id": "xccdf_org.ssgproject.content_profile_cis",
                "name": "CIS Benchmark",
                "description": "Center for Internet Security Benchmark",
                "framework": "CIS",
                "level": "1"
            },
            {
                "id": "xccdf_org.ssgproject.content_profile_cis_server_l1",
                "name": "CIS Server Level 1",
                "description": "CIS Benchmark for Server Level 1",
                "framework": "CIS",
                "level": "1"
            },
            {
                "id": "xccdf_org.ssgproject.content_profile_cis_server_l2",
                "name": "CIS Server Level 2", 
                "description": "CIS Benchmark for Server Level 2",
                "framework": "CIS",
                "level": "2"
            },
            {
                "id": "xccdf_org.ssgproject.content_profile_cis_workstation_l1",
                "name": "CIS Workstation Level 1",
                "description": "CIS Benchmark for Workstation Level 1", 
                "framework": "CIS",
                "level": "1"
            },
            {
                "id": "xccdf_org.ssgproject.content_profile_cis_workstation_l2",
                "name": "CIS Workstation Level 2",
                "description": "CIS Benchmark for Workstation Level 2",
                "framework": "CIS", 
                "level": "2"
            }
        ]
    
    async def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate CIS plugin configuration"""
        try:
            # Check required parameters
            if "profile" not in config:
                self.logger.error("CIS config missing required 'profile' parameter")
                return False
            
            if "datastream" not in config:
                self.logger.error("CIS config missing required 'datastream' parameter")
                return False
            
            # Validate profile format
            profile = config["profile"]
            if not isinstance(profile, str) or not profile.strip():
                self.logger.error("CIS profile must be a non-empty string")
                return False
            
            # Validate datastream file exists
            datastream = config["datastream"]
            datastream_path = Path(self.content_path) / datastream
            if not datastream_path.exists():
                self.logger.error(f"CIS datastream file not found: {datastream_path}")
                return False
            
            self.logger.info("CIS plugin configuration validated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating CIS config: {e}")
            return False
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for CIS plugin"""
        return {
            **super().get_default_config(),
            "profile": "xccdf_org.ssgproject.content_profile_cis",
            "datastream": "ssg-rhel9-ds.xml",
            "content_path": "/usr/share/xml/scap/ssg/content/",
            "include_informational": False,
            "generate_report": True
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check for CIS plugin"""
        base_health = await super().health_check()
        
        try:
            # Check OpenSCAP tools availability
            content_dir = Path(self.content_path)
            openscap_available = content_dir.exists()
            
            # Check if we can list profiles
            profiles_available = False
            if self.openscap_agent and openscap_available:
                try:
                    profiles = await self.openscap_agent.get_available_profiles("ssg-rhel9-ds.xml")
                    profiles_available = len(profiles) > 0
                except Exception:
                    profiles_available = False
            
            base_health.update({
                "openscap_content_available": openscap_available,
                "content_path": str(content_dir),
                "profiles_available": profiles_available,
                "supported_profiles_count": len(self.get_supported_profiles())
            })
            
            if not openscap_available or not profiles_available:
                base_health["status"] = "unhealthy"
                base_health["issues"] = []
                if not openscap_available:
                    base_health["issues"].append("OpenSCAP content directory not found")
                if not profiles_available:
                    base_health["issues"].append("No profiles available")
            
        except Exception as e:
            base_health["status"] = "unhealthy"
            base_health["error"] = str(e)
        
        return base_health