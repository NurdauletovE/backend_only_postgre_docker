from prometheus_client import Counter, Histogram, Gauge, Info, start_http_server, CollectorRegistry, REGISTRY
import time
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import asyncio

logger = logging.getLogger(__name__)


class ComplianceMetrics:
    """Prometheus metrics for compliance monitoring"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, 'initialized'):
            return
        self.initialized = True
        # Scan metrics
        self.scan_counter = Counter(
            'compliance_scans_total',
            'Total number of compliance scans executed',
            ['system_id', 'profile', 'plugin', 'status']
        )
        
        self.scan_duration = Histogram(
            'compliance_scan_duration_seconds',
            'Time spent executing compliance scans',
            ['system_id', 'profile', 'plugin'],
            buckets=[30, 60, 120, 300, 600, 1200, 1800, 3600]
        )
        
        self.compliance_score = Gauge(
            'compliance_score',
            'Current compliance score percentage',
            ['system_id', 'profile', 'framework']
        )
        
        self.compliance_score_histogram = Histogram(
            'compliance_score_distribution',
            'Distribution of compliance scores',
            ['profile', 'framework'],
            buckets=[0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 95, 100]
        )
        
        # Rule metrics
        self.rules_total = Gauge(
            'compliance_rules_total',
            'Total number of compliance rules checked',
            ['system_id', 'profile', 'severity']
        )
        
        self.rules_passed = Gauge(
            'compliance_rules_passed',
            'Number of compliance rules that passed',
            ['system_id', 'profile', 'severity']
        )
        
        self.rules_failed = Gauge(
            'compliance_rules_failed',
            'Number of compliance rules that failed',
            ['system_id', 'profile', 'severity']
        )
        
        # System metrics
        self.systems_registered = Gauge(
            'compliance_systems_registered_total',
            'Total number of systems registered for compliance monitoring'
        )
        
        self.systems_scanned_recently = Gauge(
            'compliance_systems_scanned_recently',
            'Number of systems scanned in the last 24 hours'
        )
        
        # Agent metrics
        self.agent_info = Info(
            'compliance_agent_info',
            'Information about the compliance agent'
        )
        
        self.agent_uptime = Gauge(
            'compliance_agent_uptime_seconds',
            'Agent uptime in seconds'
        )
        
        self.scheduled_tasks = Gauge(
            'compliance_scheduled_tasks',
            'Number of scheduled compliance tasks'
        )
        
        # Plugin metrics
        self.plugin_health = Gauge(
            'compliance_plugin_health',
            'Plugin health status (1=healthy, 0=unhealthy)',
            ['plugin_name', 'plugin_version']
        )
        
        self.plugin_scan_duration = Histogram(
            'compliance_plugin_scan_duration_seconds',
            'Time spent in plugin scan execution',
            ['plugin_name'],
            buckets=[10, 30, 60, 120, 300, 600, 1200]
        )
        
        # Database metrics
        self.db_operations = Counter(
            'compliance_db_operations_total',
            'Total database operations',
            ['operation', 'table', 'status']
        )
        
        self.db_operation_duration = Histogram(
            'compliance_db_operation_duration_seconds',
            'Database operation duration',
            ['operation', 'table'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
        )
        
        # Attestation metrics
        self.attestations_created = Counter(
            'compliance_attestations_created_total',
            'Total number of attestations created',
            ['system_id', 'profile']
        )
        
        self.attestations_verified = Counter(
            'compliance_attestations_verified_total',
            'Total number of attestations verified',
            ['status']
        )
        
        # API metrics
        self.api_requests = Counter(
            'compliance_api_requests_total',
            'Total API requests',
            ['method', 'endpoint', 'status_code']
        )
        
        self.api_request_duration = Histogram(
            'compliance_api_request_duration_seconds',
            'API request duration',
            ['method', 'endpoint'],
            buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        
        # Error metrics
        self.errors_total = Counter(
            'compliance_errors_total',
            'Total number of errors',
            ['component', 'error_type']
        )
        
        # Alert metrics
        self.low_compliance_alerts = Counter(
            'compliance_low_compliance_alerts_total',
            'Number of low compliance alerts triggered',
            ['system_id', 'profile', 'threshold']
        )
        
        # Initialize agent info
        self._start_time = time.time()
        self._set_agent_info()
    
    def _set_agent_info(self):
        """Set static agent information"""
        import platform
        import socket
        
        self.agent_info.info({
            'version': '1.0.0',
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'architecture': platform.machine(),
            'python_version': platform.python_version()
        })
    
    def increment_scan_counter(self, system_id: str = "unknown", 
                              profile: str = "unknown", 
                              plugin: str = "unknown", 
                              status: str = "started"):
        """Increment scan counter"""
        self.scan_counter.labels(
            system_id=system_id,
            profile=profile,
            plugin=plugin,
            status=status
        ).inc()
    
    def record_scan_duration(self, duration: float, 
                           system_id: str = "unknown",
                           profile: str = "unknown", 
                           plugin: str = "unknown"):
        """Record scan duration"""
        self.scan_duration.labels(
            system_id=system_id,
            profile=profile,
            plugin=plugin
        ).observe(duration)
    
    def record_scan_success(self, compliance_score: float,
                           system_id: str = "unknown",
                           profile: str = "unknown",
                           framework: str = "unknown"):
        """Record successful scan with compliance score"""
        self.compliance_score.labels(
            system_id=system_id,
            profile=profile,
            framework=framework
        ).set(compliance_score)
        
        self.compliance_score_histogram.labels(
            profile=profile,
            framework=framework
        ).observe(compliance_score)
        
        self.increment_scan_counter(system_id, profile, framework, "success")
    
    def record_scan_failure(self, system_id: str = "unknown",
                           profile: str = "unknown",
                           plugin: str = "unknown"):
        """Record scan failure"""
        self.increment_scan_counter(system_id, profile, plugin, "failure")
    
    def update_rule_metrics(self, rules_data: Dict[str, Any],
                           system_id: str = "unknown",
                           profile: str = "unknown"):
        """Update rule-based metrics from scan results"""
        try:
            # Count rules by severity and result
            severity_counts = {}
            
            rules = rules_data.get("rules", [])
            for rule in rules:
                severity = rule.get("severity", "unknown")
                result = rule.get("result", "unknown")
                
                if severity not in severity_counts:
                    severity_counts[severity] = {"total": 0, "passed": 0, "failed": 0}
                
                severity_counts[severity]["total"] += 1
                
                if result == "pass":
                    severity_counts[severity]["passed"] += 1
                elif result == "fail":
                    severity_counts[severity]["failed"] += 1
            
            # Update metrics
            for severity, counts in severity_counts.items():
                self.rules_total.labels(
                    system_id=system_id,
                    profile=profile,
                    severity=severity
                ).set(counts["total"])
                
                self.rules_passed.labels(
                    system_id=system_id,
                    profile=profile,
                    severity=severity
                ).set(counts["passed"])
                
                self.rules_failed.labels(
                    system_id=system_id,
                    profile=profile,
                    severity=severity
                ).set(counts["failed"])
                
        except Exception as e:
            logger.error(f"Error updating rule metrics: {e}")
    
    def update_system_metrics(self, total_systems: int, recently_scanned: int):
        """Update system-level metrics"""
        self.systems_registered.set(total_systems)
        self.systems_scanned_recently.set(recently_scanned)
    
    def update_agent_uptime(self):
        """Update agent uptime"""
        uptime = time.time() - self._start_time
        self.agent_uptime.set(uptime)
    
    def update_scheduled_tasks(self, task_count: int):
        """Update scheduled tasks count"""
        self.scheduled_tasks.set(task_count)
    
    def update_plugin_health(self, plugin_name: str, plugin_version: str, is_healthy: bool):
        """Update plugin health status"""
        self.plugin_health.labels(
            plugin_name=plugin_name,
            plugin_version=plugin_version
        ).set(1 if is_healthy else 0)
    
    def record_plugin_scan_duration(self, plugin_name: str, duration: float):
        """Record plugin scan duration"""
        self.plugin_scan_duration.labels(plugin_name=plugin_name).observe(duration)
    
    def record_db_operation(self, operation: str, table: str, 
                           duration: float, success: bool = True):
        """Record database operation metrics"""
        status = "success" if success else "failure"
        
        self.db_operations.labels(
            operation=operation,
            table=table,
            status=status
        ).inc()
        
        if success:
            self.db_operation_duration.labels(
                operation=operation,
                table=table
            ).observe(duration)
    
    def record_attestation_created(self, system_id: str, profile: str):
        """Record attestation creation"""
        self.attestations_created.labels(
            system_id=system_id,
            profile=profile
        ).inc()
    
    def record_attestation_verified(self, success: bool):
        """Record attestation verification"""
        status = "success" if success else "failure"
        self.attestations_verified.labels(status=status).inc()
    
    def record_api_request(self, method: str, endpoint: str, 
                          status_code: int, duration: float):
        """Record API request metrics"""
        self.api_requests.labels(
            method=method,
            endpoint=endpoint,
            status_code=str(status_code)
        ).inc()
        
        self.api_request_duration.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
    
    def record_error(self, component: str, error_type: str):
        """Record error occurrence"""
        self.errors_total.labels(
            component=component,
            error_type=error_type
        ).inc()
    
    def record_low_compliance_alert(self, system_id: str, profile: str, threshold: float):
        """Record low compliance alert"""
        self.low_compliance_alerts.labels(
            system_id=system_id,
            profile=profile,
            threshold=str(int(threshold))
        ).inc()


class MetricsCollector:
    """Collects and updates metrics periodically"""
    
    def __init__(self, metrics: ComplianceMetrics, database=None, agent=None):
        self.metrics = metrics
        self.database = database
        self.agent = agent
        self.running = False
        self.collection_interval = 60  # 1 minute
        self.logger = logging.getLogger(__name__)
    
    async def start(self):
        """Start metrics collection"""
        self.running = True
        self.logger.info("Metrics collector started")
        
        # Start periodic collection
        asyncio.create_task(self._collect_metrics_periodically())
    
    async def stop(self):
        """Stop metrics collection"""
        self.running = False
        self.logger.info("Metrics collector stopped")
    
    async def _collect_metrics_periodically(self):
        """Collect metrics periodically"""
        while self.running:
            try:
                await self._collect_system_metrics()
                await self._collect_agent_metrics()
                await asyncio.sleep(self.collection_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error collecting metrics: {e}")
                await asyncio.sleep(self.collection_interval)
    
    async def _collect_system_metrics(self):
        """Collect system-level metrics"""
        try:
            if not self.database:
                return
            
            # Get system counts
            systems = await self.database.get_systems_summary()
            total_systems = len(systems)
            
            # Count recently scanned systems (last 24 hours)
            from datetime import timedelta
            recent_cutoff = datetime.now(timezone.utc) - timedelta(days=1)
            recently_scanned = sum(
                1 for system in systems 
                if system.get("scan_timestamp") and 
                   system["scan_timestamp"] > recent_cutoff
            )
            
            self.metrics.update_system_metrics(total_systems, recently_scanned)
            
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")
    
    async def _collect_agent_metrics(self):
        """Collect agent-level metrics"""
        try:
            if not self.agent:
                return
            
            # Update uptime
            self.metrics.update_agent_uptime()
            
            # Update scheduled tasks count
            if hasattr(self.agent, 'scheduler') and self.agent.scheduler:
                task_count = len(self.agent.scheduler.scheduled_tasks)
                self.metrics.update_scheduled_tasks(task_count)
            
        except Exception as e:
            self.logger.error(f"Error collecting agent metrics: {e}")


class PrometheusServer:
    """Prometheus metrics server"""
    
    def __init__(self, port: int = 9090):
        self.port = port
        self.server = None
        self.logger = logging.getLogger(__name__)
    
    def start(self):
        """Start Prometheus metrics server"""
        try:
            start_http_server(self.port)
            self.logger.info(f"Prometheus metrics server started on port {self.port}")
        except Exception as e:
            self.logger.error(f"Failed to start Prometheus server: {e}")
            raise
    
    def get_metrics_url(self) -> str:
        """Get metrics endpoint URL"""
        return f"http://localhost:{self.port}/metrics"


# Context manager for timing operations
class MetricsTimer:
    """Context manager for timing operations and recording metrics"""
    
    def __init__(self, metrics: ComplianceMetrics, operation_type: str, **labels):
        self.metrics = metrics
        self.operation_type = operation_type
        self.labels = labels
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            
            # Record based on operation type
            if self.operation_type == "scan":
                self.metrics.record_scan_duration(duration, **self.labels)
            elif self.operation_type == "db":
                success = exc_type is None
                self.metrics.record_db_operation(
                    duration=duration, 
                    success=success, 
                    **self.labels
                )
            elif self.operation_type == "api":
                self.metrics.record_api_request(duration=duration, **self.labels)


# Global metrics instance
compliance_metrics = ComplianceMetrics()