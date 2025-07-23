import json
import logging
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from aiokafka.errors import KafkaError

logger = logging.getLogger(__name__)


@dataclass
class ComplianceEvent:
    """Standardized compliance event for SIEM integration"""
    event_id: str
    event_type: str
    timestamp: str
    system_id: str
    severity: str
    source: str
    description: str
    compliance_data: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class SIEMConfig:
    """Configuration for SIEM integration"""
    bootstrap_servers: List[str]
    topic: str = "compliance-events"
    security_protocol: str = "PLAINTEXT"
    sasl_mechanism: Optional[str] = None
    sasl_username: Optional[str] = None
    sasl_password: Optional[str] = None
    ssl_cafile: Optional[str] = None
    ssl_certfile: Optional[str] = None
    ssl_keyfile: Optional[str] = None
    enable_idempotence: bool = True
    acks: str = "all"
    retries: int = 3
    max_in_flight_requests: int = 1


class ComplianceEventProducer:
    """Kafka producer for sending compliance events to SIEM"""
    
    def __init__(self, config: SIEMConfig):
        self.config = config
        self.producer = None
        self.logger = logging.getLogger(__name__)
        self._running = False
    
    async def start(self):
        """Start the Kafka producer"""
        try:
            producer_config = {
                'bootstrap_servers': self.config.bootstrap_servers,
                'enable_idempotence': self.config.enable_idempotence,
                'acks': self.config.acks,
                'retries': self.config.retries,
                'max_in_flight_requests_per_connection': self.config.max_in_flight_requests,
                'value_serializer': lambda v: json.dumps(v, default=str).encode('utf-8'),
                'key_serializer': lambda k: str(k).encode('utf-8') if k else None,
            }
            
            # Add security configuration if provided
            if self.config.security_protocol != "PLAINTEXT":
                producer_config['security_protocol'] = self.config.security_protocol
                
                if self.config.sasl_mechanism:
                    producer_config['sasl_mechanism'] = self.config.sasl_mechanism
                    producer_config['sasl_plain_username'] = self.config.sasl_username
                    producer_config['sasl_plain_password'] = self.config.sasl_password
                
                if self.config.ssl_cafile:
                    producer_config['ssl_cafile'] = self.config.ssl_cafile
                if self.config.ssl_certfile:
                    producer_config['ssl_certfile'] = self.config.ssl_certfile
                if self.config.ssl_keyfile:
                    producer_config['ssl_keyfile'] = self.config.ssl_keyfile
            
            self.producer = AIOKafkaProducer(**producer_config)
            await self.producer.start()
            self._running = True
            
            self.logger.info(f"Kafka producer started, connected to {self.config.bootstrap_servers}")
            
        except Exception as e:
            self.logger.error(f"Failed to start Kafka producer: {e}")
            raise
    
    async def stop(self):
        """Stop the Kafka producer"""
        if self.producer:
            try:
                await self.producer.stop()
                self._running = False
                self.logger.info("Kafka producer stopped")
            except Exception as e:
                self.logger.error(f"Error stopping Kafka producer: {e}")
    
    async def send_compliance_event(self, event: ComplianceEvent) -> bool:
        """
        Send compliance event to SIEM via Kafka
        
        Args:
            event: Compliance event to send
            
        Returns:
            True if event was sent successfully
        """
        if not self._running or not self.producer:
            self.logger.error("Kafka producer not running")
            return False
        
        try:
            # Convert event to dictionary
            event_data = asdict(event)
            
            # Add SIEM-specific fields
            event_data.update({
                'source_ip': '127.0.0.1',  # Could be enhanced to get actual IP
                'event_category': 'security',
                'event_subcategory': 'compliance',
                'vendor': 'compliance-agent',
                'product': 'security-compliance-automation',
                'version': '1.0.0'
            })
            
            # Use event_id as key for partitioning
            key = event.event_id
            
            # Send to Kafka
            await self.producer.send_and_wait(
                topic=self.config.topic,
                key=key,
                value=event_data
            )
            
            self.logger.debug(f"Sent compliance event {event.event_id} to SIEM")
            return True
            
        except KafkaError as e:
            self.logger.error(f"Kafka error sending event {event.event_id}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error sending compliance event {event.event_id}: {e}")
            return False
    
    async def send_scan_completion_event(self, scan_data: Dict[str, Any]) -> bool:
        """Send scan completion event to SIEM"""
        try:
            event = ComplianceEvent(
                event_id=f"scan_{scan_data.get('scan_id', 'unknown')}",
                event_type="compliance_scan_completed",
                timestamp=datetime.now(timezone.utc).isoformat(),
                system_id=scan_data.get('system_id', 'unknown'),
                severity=self._determine_severity(scan_data.get('compliance_score', 0)),
                source="compliance-agent",
                description=f"Compliance scan completed with score {scan_data.get('compliance_score', 0)}%",
                compliance_data={
                    'scan_id': scan_data.get('scan_id'),
                    'compliance_score': scan_data.get('compliance_score'),
                    'profile': scan_data.get('profile'),
                    'total_rules': len(scan_data.get('rules', [])),
                    'failed_rules': len([r for r in scan_data.get('rules', []) if r.get('result') == 'fail']),
                    'scanner': scan_data.get('system_info', {}).get('scanner', 'OpenSCAP')
                },
                metadata={
                    'scan_duration': scan_data.get('duration_seconds'),
                    'framework': scan_data.get('framework', 'CIS')
                }
            )
            
            return await self.send_compliance_event(event)
            
        except Exception as e:
            self.logger.error(f"Error sending scan completion event: {e}")
            return False
    
    async def send_low_compliance_alert(self, system_id: str, compliance_score: float, 
                                       threshold: float = 70.0) -> bool:
        """Send low compliance alert to SIEM"""
        try:
            severity = "critical" if compliance_score < 50 else "high" if compliance_score < 60 else "medium"
            
            event = ComplianceEvent(
                event_id=f"alert_low_compliance_{system_id}_{int(datetime.now().timestamp())}",
                event_type="compliance_alert",
                timestamp=datetime.now(timezone.utc).isoformat(),
                system_id=system_id,
                severity=severity,
                source="compliance-agent",
                description=f"Low compliance score detected: {compliance_score}% (threshold: {threshold}%)",
                compliance_data={
                    'alert_type': 'low_compliance',
                    'compliance_score': compliance_score,
                    'threshold': threshold,
                    'deviation': threshold - compliance_score
                },
                metadata={
                    'requires_action': True,
                    'escalation_level': severity
                }
            )
            
            return await self.send_compliance_event(event)
            
        except Exception as e:
            self.logger.error(f"Error sending low compliance alert: {e}")
            return False
    
    async def send_rule_failure_event(self, system_id: str, rule_data: Dict[str, Any]) -> bool:
        """Send individual rule failure event to SIEM"""
        try:
            event = ComplianceEvent(
                event_id=f"rule_failure_{system_id}_{rule_data.get('id', 'unknown')}",
                event_type="compliance_rule_failure",
                timestamp=datetime.now(timezone.utc).isoformat(),
                system_id=system_id,
                severity=rule_data.get('severity', 'medium'),
                source="compliance-agent",
                description=f"Compliance rule failed: {rule_data.get('title', 'Unknown rule')}",
                compliance_data={
                    'rule_id': rule_data.get('id'),
                    'rule_title': rule_data.get('title'),
                    'rule_description': rule_data.get('description'),
                    'remediation': rule_data.get('remediation'),
                    'rule_result': rule_data.get('result')
                },
                metadata={
                    'cis_control': rule_data.get('cis_control'),
                    'impact_level': rule_data.get('cis_impact')
                }
            )
            
            return await self.send_compliance_event(event)
            
        except Exception as e:
            self.logger.error(f"Error sending rule failure event: {e}")
            return False
    
    async def send_attestation_event(self, system_id: str, attestation_data: Dict[str, Any]) -> bool:
        """Send attestation creation event to SIEM"""
        try:
            event = ComplianceEvent(
                event_id=f"attestation_{attestation_data.get('attestation_id', 'unknown')}",
                event_type="compliance_attestation_created",
                timestamp=datetime.now(timezone.utc).isoformat(),
                system_id=system_id,
                severity="info",
                source="compliance-agent",
                description="Compliance attestation created and signed",
                compliance_data={
                    'attestation_id': attestation_data.get('attestation_id'),
                    'scan_id': attestation_data.get('scan_id'),
                    'expires_at': attestation_data.get('expires_at'),
                    'algorithm': 'RS256',
                    'issuer': 'compliance-agent'
                },
                metadata={
                    'signature_valid': True,
                    'token_length': len(attestation_data.get('token', ''))
                }
            )
            
            return await self.send_compliance_event(event)
            
        except Exception as e:
            self.logger.error(f"Error sending attestation event: {e}")
            return False
    
    def _determine_severity(self, compliance_score: float) -> str:
        """Determine event severity based on compliance score"""
        if compliance_score >= 90:
            return "info"
        elif compliance_score >= 80:
            return "low"
        elif compliance_score >= 70:
            return "medium"
        elif compliance_score >= 50:
            return "high"
        else:
            return "critical"


class SecurityInfrastructureClient:
    """Client for integrating with existing security infrastructure"""
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = None
        self.logger = logging.getLogger(__name__)
    
    async def __aenter__(self):
        """Async context manager entry"""
        import aiohttp
        
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'compliance-agent/1.0.0'
        }
        
        self.session = aiohttp.ClientSession(
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def submit_compliance_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Submit compliance finding to security infrastructure"""
        try:
            async with self.session.post(
                f"{self.base_url}/compliance/findings",
                json=finding
            ) as response:
                response.raise_for_status()
                return await response.json()
                
        except Exception as e:
            self.logger.error(f"Error submitting compliance finding: {e}")
            raise
    
    async def submit_vulnerability_report(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Submit vulnerability report to security infrastructure"""
        try:
            async with self.session.post(
                f"{self.base_url}/vulnerabilities",
                json=vulnerability
            ) as response:
                response.raise_for_status()
                return await response.json()
                
        except Exception as e:
            self.logger.error(f"Error submitting vulnerability report: {e}")
            raise
    
    async def create_security_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Create security incident for severe compliance violations"""
        try:
            async with self.session.post(
                f"{self.base_url}/incidents",
                json=incident
            ) as response:
                response.raise_for_status()
                return await response.json()
                
        except Exception as e:
            self.logger.error(f"Error creating security incident: {e}")
            raise


class SIEMIntegrationManager:
    """Manager for SIEM and security infrastructure integrations"""
    
    def __init__(self, kafka_config: Optional[SIEMConfig] = None):
        self.kafka_config = kafka_config
        self.kafka_producer = None
        self.security_clients = {}
        self.logger = logging.getLogger(__name__)
        self._running = False
    
    async def start(self):
        """Start SIEM integration services"""
        try:
            if self.kafka_config:
                self.kafka_producer = ComplianceEventProducer(self.kafka_config)
                await self.kafka_producer.start()
            
            self._running = True
            self.logger.info("SIEM integration manager started")
            
        except Exception as e:
            self.logger.error(f"Failed to start SIEM integration: {e}")
            raise
    
    async def stop(self):
        """Stop SIEM integration services"""
        try:
            if self.kafka_producer:
                await self.kafka_producer.stop()
            
            self._running = False
            self.logger.info("SIEM integration manager stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping SIEM integration: {e}")
    
    def add_security_client(self, name: str, client: SecurityInfrastructureClient):
        """Add security infrastructure client"""
        self.security_clients[name] = client
        self.logger.info(f"Added security client: {name}")
    
    async def process_scan_results(self, scan_data: Dict[str, Any]):
        """Process scan results and send to all configured integrations"""
        try:
            if not self._running:
                self.logger.warning("SIEM integration not running")
                return
            
            # Send to Kafka/SIEM
            if self.kafka_producer:
                await self.kafka_producer.send_scan_completion_event(scan_data)
                
                # Check for low compliance and send alert
                compliance_score = scan_data.get('compliance_score', 0)
                if compliance_score < 70:
                    await self.kafka_producer.send_low_compliance_alert(
                        scan_data.get('system_id', 'unknown'),
                        compliance_score
                    )
                
                # Send critical rule failures
                for rule in scan_data.get('rules', []):
                    if (rule.get('result') == 'fail' and 
                        rule.get('severity') in ['critical', 'high']):
                        await self.kafka_producer.send_rule_failure_event(
                            scan_data.get('system_id', 'unknown'),
                            rule
                        )
            
            # Send to security infrastructure APIs
            for name, client in self.security_clients.items():
                try:
                    async with client as c:
                        # Submit compliance finding
                        finding = self._create_compliance_finding(scan_data)
                        await c.submit_compliance_finding(finding)
                        
                        # Create incident for critical compliance failures
                        if compliance_score < 50:
                            incident = self._create_security_incident(scan_data)
                            await c.create_security_incident(incident)
                            
                except Exception as e:
                    self.logger.error(f"Error sending to security client {name}: {e}")
            
            self.logger.info(f"Processed scan results for system {scan_data.get('system_id')}")
            
        except Exception as e:
            self.logger.error(f"Error processing scan results: {e}")
    
    async def process_attestation(self, attestation_data: Dict[str, Any]):
        """Process attestation creation and send to integrations"""
        try:
            if self.kafka_producer:
                await self.kafka_producer.send_attestation_event(
                    attestation_data.get('system_id', 'unknown'),
                    attestation_data
                )
            
            self.logger.info(f"Processed attestation {attestation_data.get('attestation_id')}")
            
        except Exception as e:
            self.logger.error(f"Error processing attestation: {e}")
    
    def _create_compliance_finding(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create compliance finding for security infrastructure"""
        return {
            'id': scan_data.get('scan_id'),
            'title': f"Compliance Scan - {scan_data.get('profile', 'Unknown Profile')}",
            'description': f"System compliance scan completed with score {scan_data.get('compliance_score', 0)}%",
            'severity': self._map_score_to_severity(scan_data.get('compliance_score', 0)),
            'system_id': scan_data.get('system_id'),
            'category': 'compliance',
            'subcategory': 'automated_scan',
            'compliance_score': scan_data.get('compliance_score'),
            'total_rules': len(scan_data.get('rules', [])),
            'failed_rules': len([r for r in scan_data.get('rules', []) if r.get('result') == 'fail']),
            'scan_timestamp': scan_data.get('timestamp'),
            'remediation_required': scan_data.get('compliance_score', 0) < 80
        }
    
    def _create_security_incident(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create security incident for critical compliance failures"""
        return {
            'title': f"Critical Compliance Failure - {scan_data.get('system_id')}",
            'description': f"System {scan_data.get('system_id')} has critical compliance score of {scan_data.get('compliance_score', 0)}%",
            'severity': 'critical',
            'category': 'compliance_violation',
            'affected_system': scan_data.get('system_id'),
            'compliance_score': scan_data.get('compliance_score'),
            'scan_id': scan_data.get('scan_id'),
            'requires_immediate_action': True,
            'escalation_required': True
        }
    
    def _map_score_to_severity(self, score: float) -> str:
        """Map compliance score to security severity"""
        if score >= 90:
            return "info"
        elif score >= 80:
            return "low"
        elif score >= 70:
            return "medium"
        elif score >= 50:
            return "high"
        else:
            return "critical"