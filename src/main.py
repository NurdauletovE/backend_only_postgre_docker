#!/usr/bin/env python3
"""
Security Compliance Automation Agent - Main Entry Point

This module serves as the main entry point for the standalone security compliance
automation agent that performs scheduled CIS compliance scans using OpenSCAP,
creates signed attestations, and submits them to compliance authorities.
"""

import asyncio
import signal
import sys
import os
from pathlib import Path
from typing import Optional
import uvicorn

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from security.logging import initialize_logging, get_logger, audit_logger
from security.hardening import security_hardening
from security.attestation import ComplianceAttestation
from db.database import ComplianceDatabase
from core.agent import ComplianceAgent, ComplianceConfig
from api.main import app, initialize_api
from monitoring.metrics import PrometheusServer, MetricsCollector, compliance_metrics
from integrations.kafka_siem import SIEMIntegrationManager, SIEMConfig


class ComplianceAgentApplication:
    """Main application class for the compliance agent"""
    
    def __init__(self):
        self.logger = None
        self.database = None
        self.attestation_service = None
        self.compliance_agent = None
        self.prometheus_server = None
        self.metrics_collector = None
        self.siem_manager = None
        self.api_server = None
        self.running = False
    
    async def initialize(self):
        """Initialize all application components"""
        try:
            # Initialize logging first
            log_level = os.getenv('LOG_LEVEL', 'INFO')
            log_format = os.getenv('LOG_FORMAT', 'json')
            log_file = os.getenv('LOG_FILE', '/app/logs/compliance-agent.log')
            
            initialize_logging(log_level, log_format, log_file)
            self.logger = get_logger(__name__)
            
            self.logger.info("Starting Security Compliance Automation Agent")
            
            # Apply security hardening
            self.logger.info("Applying security hardening measures")
            await security_hardening.apply_security_hardening()
            
            # Validate security configuration
            security_validation = await security_hardening.validate_environment_security()
            if not security_validation['overall_secure']:
                self.logger.warning(f"Security validation issues: {security_validation['errors']}")
            
            # Initialize database
            database_url = os.getenv('DATABASE_URL')
            if not database_url:
                raise RuntimeError("DATABASE_URL environment variable is required")
            
            self.database = ComplianceDatabase(database_url)
            await self.database.initialize()
            self.logger.info("Database initialized")
            
            # Initialize JWT attestation service
            private_key_path = os.getenv('JWT_PRIVATE_KEY_PATH', '/app/keys/private.pem')
            public_key_path = os.getenv('JWT_PUBLIC_KEY_PATH', '/app/keys/public.pem')
            
            # Generate keys if they don't exist
            if not Path(private_key_path).exists() or not Path(public_key_path).exists():
                self.logger.info("Generating RSA key pair for JWT attestation")
                private_key, public_key = ComplianceAttestation.generate_key_pair()
                
                # Create keys directory
                Path(private_key_path).parent.mkdir(parents=True, exist_ok=True)
                
                ComplianceAttestation.save_key_pair(
                    private_key, public_key, 
                    private_key_path, public_key_path
                )
                
                # Secure key file permissions
                await security_hardening.validate_key_files(private_key_path, public_key_path)
            
            self.attestation_service = ComplianceAttestation(private_key_path, public_key_path)
            self.logger.info("JWT attestation service initialized")
            
            # Initialize compliance agent
            agent_config = ComplianceConfig(
                scan_interval=int(os.getenv('SCAN_INTERVAL', '3600')),
                profiles=[os.getenv('DEFAULT_SCAN_PROFILE', 'xccdf_org.ssgproject.content_profile_cis')],
                max_concurrent_scans=int(os.getenv('MAX_CONCURRENT_SCANS', '3'))
            )
            
            self.compliance_agent = ComplianceAgent(agent_config, self.database)
            await self.compliance_agent.initialize(self.attestation_service)
            self.logger.info("Compliance agent initialized")
            
            # Initialize SIEM integration if configured
            kafka_servers = os.getenv('KAFKA_BOOTSTRAP_SERVERS')
            if kafka_servers:
                siem_config = SIEMConfig(
                    bootstrap_servers=kafka_servers.split(','),
                    topic=os.getenv('KAFKA_TOPIC', 'compliance-events')
                )
                self.siem_manager = SIEMIntegrationManager(siem_config)
                await self.siem_manager.start()
                self.logger.info("SIEM integration initialized")
            
            # Initialize Prometheus metrics server
            if os.getenv('ENABLE_METRICS', 'true').lower() == 'true':
                prometheus_port = int(os.getenv('PROMETHEUS_PORT', '9090'))
                self.prometheus_server = PrometheusServer(prometheus_port)
                self.prometheus_server.start()
                
                # Initialize metrics collector
                self.metrics_collector = MetricsCollector(
                    compliance_metrics, 
                    self.database, 
                    self.compliance_agent
                )
                await self.metrics_collector.start()
                self.logger.info(f"Prometheus metrics server started on port {prometheus_port}")
            
            # Initialize API
            await initialize_api(self.database, self.attestation_service, self.compliance_agent)
            self.logger.info("API initialized")
            
            audit_logger.log_security_event(
                'application_start',
                'system',
                'Compliance agent application initialized successfully'
            )
            
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to initialize application: {e}", exc_info=True)
            else:
                print(f"Failed to initialize application: {e}")
            return False
    
    async def start(self):
        """Start the compliance agent application"""
        try:
            if not await self.initialize():
                return False
            
            self.running = True
            
            # Start compliance agent
            await self.compliance_agent.start()
            
            # Start API server in background
            api_host = os.getenv('API_HOST', '0.0.0.0')
            api_port = int(os.getenv('API_PORT', '8000'))
            
            config = uvicorn.Config(
                app,
                host=api_host,
                port=api_port,
                log_config=None,  # Use our custom logging
                access_log=False  # Disable uvicorn access log (we'll handle this)
            )
            
            self.api_server = uvicorn.Server(config)
            
            # Run API server
            self.logger.info(f"Starting API server on {api_host}:{api_port}")
            await self.api_server.serve()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting application: {e}", exc_info=True)
            return False
    
    async def stop(self):
        """Stop the compliance agent application"""
        try:
            self.logger.info("Stopping compliance agent application")
            self.running = False
            
            # Stop compliance agent
            if self.compliance_agent:
                await self.compliance_agent.stop()
            
            # Stop metrics collector
            if self.metrics_collector:
                await self.metrics_collector.stop()
            
            # Stop SIEM integration
            if self.siem_manager:
                await self.siem_manager.stop()
            
            # Stop API server
            if self.api_server:
                self.api_server.should_exit = True
            
            # Close database
            if self.database:
                await self.database.close()
            
            audit_logger.log_security_event(
                'application_stop',
                'system',
                'Compliance agent application stopped gracefully'
            )
            
            self.logger.info("Compliance agent application stopped")
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error stopping application: {e}", exc_info=True)
            else:
                print(f"Error stopping application: {e}")
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, initiating graceful shutdown")
            asyncio.create_task(self.stop())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)


async def main():
    """Main application entry point"""
    app = ComplianceAgentApplication()
    
    try:
        # Setup signal handlers
        app.setup_signal_handlers()
        
        # Start application
        success = await app.start()
        
        if not success:
            sys.exit(1)
        
    except KeyboardInterrupt:
        print("\nReceived keyboard interrupt, shutting down...")
        await app.stop()
    except Exception as e:
        print(f"Fatal error: {e}")
        await app.stop()
        sys.exit(1)


if __name__ == "__main__":
    # Set up asyncio event loop policy for better performance
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    else:
        try:
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        except ImportError:
            pass  # uvloop not available, use default policy
    
    # Run the application
    asyncio.run(main())