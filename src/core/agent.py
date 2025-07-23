import asyncio
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging
import uuid
import platform
import socket

from db.database import ComplianceDatabase
from security.attestation import ComplianceAttestation
from plugins.base import plugin_manager, ScanRequest
from monitoring.metrics import ComplianceMetrics

logger = logging.getLogger(__name__)


@dataclass
class ComplianceConfig:
    """Configuration for the compliance agent"""
    scan_interval: int = 3600  # Default 1 hour
    profiles: List[str] = None
    notification_endpoints: List[str] = None
    storage_backend: str = "postgresql"
    max_concurrent_scans: int = 3
    scan_timeout: int = 1800  # 30 minutes
    auto_remediation: bool = False
    
    def __post_init__(self):
        if self.profiles is None:
            self.profiles = ["xccdf_org.ssgproject.content_profile_cis"]
        if self.notification_endpoints is None:
            self.notification_endpoints = []


class ComplianceScheduler:
    """Scheduler for compliance scans"""
    
    def __init__(self, agent):
        self.agent = agent
        self.scheduled_tasks = {}
        self.running = False
        self.logger = logging.getLogger(__name__)
    
    async def start(self):
        """Start the scheduler"""
        self.running = True
        self.logger.info("Compliance scheduler started")
    
    async def stop(self):
        """Stop the scheduler and cancel all tasks"""
        self.running = False
        
        # Cancel all scheduled tasks
        for task_id, task in self.scheduled_tasks.items():
            if not task.done():
                task.cancel()
                self.logger.info(f"Cancelled scheduled task: {task_id}")
        
        self.scheduled_tasks.clear()
        self.logger.info("Compliance scheduler stopped")
    
    async def schedule_recurring(self, func, interval: int, *args, **kwargs):
        """
        Schedule a recurring task
        
        Args:
            func: Function to execute
            interval: Interval in seconds
            *args, **kwargs: Arguments for the function
        """
        task_id = str(uuid.uuid4())
        
        async def recurring_task():
            while self.running:
                try:
                    await func(*args, **kwargs)
                    await asyncio.sleep(interval)
                except asyncio.CancelledError:
                    self.logger.info(f"Recurring task {task_id} cancelled")
                    break
                except Exception as e:
                    self.logger.error(f"Error in recurring task {task_id}: {e}")
                    await self._handle_task_failure(task_id, e)
                    await asyncio.sleep(min(interval, 300))  # Wait at least 5 minutes on error
        
        task = asyncio.create_task(recurring_task())
        self.scheduled_tasks[task_id] = task
        
        self.logger.info(f"Scheduled recurring task {task_id} with interval {interval}s")
        return task_id
    
    async def schedule_once(self, func, delay: int, *args, **kwargs):
        """
        Schedule a one-time task
        
        Args:
            func: Function to execute
            delay: Delay in seconds before execution
            *args, **kwargs: Arguments for the function
        """
        task_id = str(uuid.uuid4())
        
        async def delayed_task():
            try:
                await asyncio.sleep(delay)
                if self.running:
                    await func(*args, **kwargs)
            except asyncio.CancelledError:
                self.logger.info(f"Delayed task {task_id} cancelled")
            except Exception as e:
                self.logger.error(f"Error in delayed task {task_id}: {e}")
                await self._handle_task_failure(task_id, e)
            finally:
                self.scheduled_tasks.pop(task_id, None)
        
        task = asyncio.create_task(delayed_task())
        self.scheduled_tasks[task_id] = task
        
        self.logger.info(f"Scheduled one-time task {task_id} with delay {delay}s")
        return task_id
    
    async def _handle_task_failure(self, task_id: str, error: Exception):
        """Handle task failure"""
        await self.agent.log_audit_event(
            actor_type="system",
            actor_id="scheduler",
            event_type="task_failure",
            description=f"Scheduled task {task_id} failed: {str(error)}"
        )


class ComplianceAgent:
    """Main compliance automation agent"""
    
    def __init__(self, config: ComplianceConfig, database: ComplianceDatabase):
        self.config = config
        self.database = database
        self.attestation = None
        self.scheduler = ComplianceScheduler(self)
        self.metrics = ComplianceMetrics()
        self.system_id = self._generate_system_id()
        self.logger = logging.getLogger(__name__)
        self.running = False
        self._scan_semaphore = asyncio.Semaphore(config.max_concurrent_scans)
    
    def _generate_system_id(self) -> str:
        """Generate unique system identifier"""
        try:
            hostname = socket.gethostname()
            return f"{hostname}_{platform.machine()}_{platform.system()}"
        except Exception:
            return f"unknown_{uuid.uuid4().hex[:8]}"
    
    async def initialize(self, attestation_service: ComplianceAttestation):
        """Initialize the compliance agent"""
        try:
            self.attestation = attestation_service
            
            # Initialize database
            if not self.database.pool:
                await self.database.initialize()
            
            # Register system
            await self._register_system()
            
            # Initialize plugins
            await self._initialize_plugins()
            
            self.logger.info(f"Compliance agent initialized for system {self.system_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize compliance agent: {e}")
            return False
    
    async def _register_system(self):
        """Register this system in the database"""
        try:
            system_info = {
                "system_id": self.system_id,
                "hostname": socket.gethostname(),
                "ip_address": socket.gethostbyname(socket.gethostname()),
                "operating_system": platform.system(),
                "os_version": platform.release(),
                "architecture": platform.machine(),
                "environment": "development",  # Could be configurable
                "tags": {
                    "agent_version": "1.0.0",
                    "python_version": platform.python_version()
                }
            }
            
            await self.database.register_system(system_info)
            self.logger.info(f"System {self.system_id} registered")
            
        except Exception as e:
            self.logger.error(f"Failed to register system: {e}")
    
    async def _initialize_plugins(self):
        """Initialize compliance plugins"""
        try:
            # This would typically load plugins from configuration
            # For now, we'll register the CIS plugin
            from plugins.cis_plugin import CISPlugin
            from plugins.base import PluginConfig
            
            cis_config = PluginConfig(
                name="CIS",
                version="1.0.0",
                enabled=True,
                settings={"content_path": "/usr/share/xml/scap/ssg/content/"}
            )
            
            cis_plugin = CISPlugin(cis_config)
            await plugin_manager.register_plugin(cis_plugin)
            
            self.logger.info("Plugins initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize plugins: {e}")
    
    async def start(self):
        """Start the compliance agent"""
        try:
            self.running = True
            
            # Start scheduler
            await self.scheduler.start()
            
            # Schedule recurring scans
            for profile in self.config.profiles:
                await self.scheduler.schedule_recurring(
                    self._perform_scheduled_scan,
                    self.config.scan_interval,
                    profile
                )
            
            # Schedule health checks
            await self.scheduler.schedule_recurring(
                self._perform_health_check,
                300  # Every 5 minutes
            )
            
            await self.log_audit_event(
                actor_type="system",
                actor_id="agent",
                event_type="agent_started",
                description=f"Compliance agent started for system {self.system_id}"
            )
            
            self.logger.info("Compliance agent started")
            
        except Exception as e:
            self.logger.error(f"Failed to start compliance agent: {e}")
            raise
    
    async def stop(self):
        """Stop the compliance agent"""
        try:
            self.running = False
            
            # Stop scheduler
            await self.scheduler.stop()
            
            # Shutdown plugins
            await plugin_manager.shutdown_all()
            
            # Close database connection
            await self.database.close()
            
            await self.log_audit_event(
                actor_type="system",
                actor_id="agent",
                event_type="agent_stopped",
                description=f"Compliance agent stopped for system {self.system_id}"
            )
            
            self.logger.info("Compliance agent stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping compliance agent: {e}")
    
    async def _perform_scheduled_scan(self, profile: str):
        """Perform a scheduled compliance scan"""
        async with self._scan_semaphore:
            try:
                self.logger.info(f"Starting scheduled scan with profile {profile}")
                
                # Record scan start
                self.metrics.increment_scan_counter()
                start_time = datetime.now(timezone.utc)
                
                # Execute scan
                result = await self.execute_scan(profile)
                
                # Record scan completion
                duration = (datetime.now(timezone.utc) - start_time).total_seconds()
                
                if result["success"]:
                    self.metrics.record_scan_success(result["compliance_score"])
                    self.logger.info(f"Scheduled scan completed successfully. Score: {result['compliance_score']}")
                    
                    # Check if compliance score is below threshold
                    if result["compliance_score"] < 80:
                        await self._handle_low_compliance(result)
                else:
                    self.metrics.record_scan_failure()
                    self.logger.error(f"Scheduled scan failed: {result.get('error')}")
                
                self.metrics.record_scan_duration(duration)
                
            except Exception as e:
                self.metrics.record_scan_failure()
                self.logger.error(f"Error in scheduled scan: {e}")
                await self.log_audit_event(
                    actor_type="system",
                    actor_id="agent",
                    event_type="scan_error",
                    description=f"Scheduled scan failed: {str(e)}"
                )
    
    async def execute_scan(self, profile: str, plugin_name: str = "CIS") -> Dict[str, Any]:
        """
        Execute a compliance scan
        
        Args:
            profile: Compliance profile to scan against
            plugin_name: Plugin to use for scanning
            
        Returns:
            Scan result dictionary
        """
        try:
            # Create scan request
            scan_request = ScanRequest(
                system_id=self.system_id,
                profile=profile,
                config={
                    "profile": profile,
                    "datastream": "ssg-rhel9-ds.xml"  # Could be configurable
                },
                metadata={
                    "scan_type": "automated",
                    "agent_version": "1.0.0"
                }
            )
            
            # Execute scan using plugin
            scan_result = await plugin_manager.execute_scan(plugin_name, scan_request)
            
            if not scan_result.success:
                return {
                    "success": False,
                    "error": scan_result.error_message
                }
            
            # Store scan results
            scan_id = await self.database.store_scan_results(
                scan_result.data, 
                self.system_id
            )
            
            # Create attestation
            attestation_token = self.attestation.create_attestation(
                scan_result.data, 
                self.system_id
            )
            
            # Store attestation
            import jwt
            payload = jwt.decode(attestation_token, options={"verify_signature": False})
            await self.database.store_attestation(attestation_token, scan_id, payload)
            
            await self.log_audit_event(
                actor_type="system",
                actor_id="agent",
                event_type="scan_completed",
                description=f"Compliance scan completed for profile {profile}",
                resource_type="scan",
                resource_id=scan_id
            )
            
            return {
                "success": True,
                "scan_id": scan_id,
                "compliance_score": scan_result.data.get("score", 0),
                "attestation_token": attestation_token,
                "scan_data": scan_result.data
            }
            
        except Exception as e:
            self.logger.error(f"Error executing scan: {e}")
            await self.log_audit_event(
                actor_type="system",
                actor_id="agent",
                event_type="scan_error",
                description=f"Scan execution failed: {str(e)}"
            )
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _handle_low_compliance(self, scan_result: Dict):
        """Handle low compliance scores"""
        try:
            compliance_score = scan_result.get("compliance_score", 0)
            
            await self.log_audit_event(
                actor_type="system",
                actor_id="agent",
                event_type="low_compliance_detected",
                description=f"Low compliance score detected: {compliance_score}%",
                metadata={"compliance_score": compliance_score}
            )
            
            # Could trigger notifications, remediation, etc.
            self.logger.warning(f"Low compliance score detected: {compliance_score}%")
            
        except Exception as e:
            self.logger.error(f"Error handling low compliance: {e}")
    
    async def _perform_health_check(self):
        """Perform system health check"""
        try:
            # Check plugin health
            plugin_health = await plugin_manager.health_check_all()
            
            # Check database connectivity
            try:
                async with self.database.get_connection() as conn:
                    await conn.fetchval("SELECT 1")
                db_healthy = True
            except Exception:
                db_healthy = False
            
            health_status = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "system_id": self.system_id,
                "agent_running": self.running,
                "database_healthy": db_healthy,
                "plugin_health": plugin_health
            }
            
            # Log health status
            if not db_healthy or plugin_health["overall_status"] != "healthy":
                self.logger.warning(f"Health check issues detected: {health_status}")
                await self.log_audit_event(
                    actor_type="system",
                    actor_id="agent",
                    event_type="health_check_warning",
                    description="Health check detected issues",
                    metadata=health_status
                )
            
        except Exception as e:
            self.logger.error(f"Error in health check: {e}")
    
    async def get_status(self) -> Dict[str, Any]:
        """Get current agent status"""
        try:
            # Get latest scan
            latest_scan = await self.database.get_latest_scan(self.system_id)
            
            # Get plugin status
            plugin_health = await plugin_manager.health_check_all()
            
            return {
                "system_id": self.system_id,
                "running": self.running,
                "latest_scan": latest_scan,
                "plugin_health": plugin_health,
                "scheduled_tasks": len(self.scheduler.scheduled_tasks),
                "config": {
                    "scan_interval": self.config.scan_interval,
                    "profiles": self.config.profiles,
                    "max_concurrent_scans": self.config.max_concurrent_scans
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting agent status: {e}")
            return {
                "system_id": self.system_id,
                "running": self.running,
                "error": str(e)
            }
    
    async def log_audit_event(self, actor_type: str, actor_id: str, 
                             event_type: str, description: str,
                             resource_type: Optional[str] = None,
                             resource_id: Optional[str] = None,
                             metadata: Optional[Dict] = None):
        """Log audit event to database"""
        try:
            await self.database.log_audit_event(
                actor_type, actor_id, event_type, description,
                resource_type, resource_id, metadata
            )
        except Exception as e:
            self.logger.error(f"Failed to log audit event: {e}")