import logging
import logging.config
import json
import sys
import os
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from pathlib import Path
import structlog
from pythonjsonlogger import jsonlogger


class SecurityAwareFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with security-aware logging"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sensitive_fields = {
            'password', 'secret', 'token', 'key', 'credential', 
            'authorization', 'auth', 'jwt', 'session'
        }
    
    def add_fields(self, log_record, record, message_dict):
        """Add custom fields to log record"""
        super().add_fields(log_record, record, message_dict)
        
        # Add timestamp in ISO format
        log_record['timestamp'] = datetime.now(timezone.utc).isoformat()
        
        # Add process and thread info
        log_record['process_id'] = os.getpid()
        log_record['thread_id'] = record.thread
        
        # Add source information
        log_record['source'] = {
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add severity level
        log_record['severity'] = record.levelname
        
        # Sanitize sensitive data
        self._sanitize_sensitive_data(log_record)
    
    def _sanitize_sensitive_data(self, log_record):
        """Remove or mask sensitive data from log record"""
        def sanitize_value(value, key_name=''):
            if isinstance(value, dict):
                return {k: sanitize_value(v, k.lower()) for k, v in value.items()}
            elif isinstance(value, list):
                return [sanitize_value(item, key_name) for item in value]
            elif isinstance(value, str):
                # Check if this looks like sensitive data
                if (key_name and any(sensitive in key_name for sensitive in self.sensitive_fields)) or \
                   self._looks_like_sensitive_data(value):
                    return self._mask_sensitive_value(value)
                return value
            else:
                return value
        
        # Recursively sanitize all fields
        for key, value in list(log_record.items()):
            log_record[key] = sanitize_value(value, key.lower())
    
    def _looks_like_sensitive_data(self, value: str) -> bool:
        """Heuristic to detect if a string might be sensitive data"""
        if not value or len(value) < 8:
            return False
        
        # Check for common token/key patterns
        if value.startswith(('ey', 'sk_', 'pk_', 'Bearer ', 'Basic ')):
            return True
        
        # Check for base64-like patterns
        if len(value) > 20 and value.replace('+', '').replace('/', '').replace('=', '').isalnum():
            return True
        
        # Check for high entropy (potential random strings)
        if len(value) > 16 and len(set(value)) > len(value) * 0.6:
            return True
        
        return False
    
    def _mask_sensitive_value(self, value: str) -> str:
        """Mask sensitive value for logging"""
        if len(value) <= 8:
            return '*' * len(value)
        
        # Show first and last few characters
        visible_chars = min(3, len(value) // 4)
        masked_length = len(value) - (2 * visible_chars)
        
        return f"{value[:visible_chars]}{'*' * masked_length}{value[-visible_chars:]}"


class ComplianceLogger:
    """Centralized logging configuration for compliance agent"""
    
    def __init__(self, log_level: str = "INFO", log_format: str = "json", 
                 log_file: Optional[str] = None):
        self.log_level = log_level.upper()
        self.log_format = log_format.lower()
        self.log_file = log_file
        self._configured = False
    
    def configure_logging(self):
        """Configure logging for the entire application"""
        if self._configured:
            return
        
        # Create logs directory
        if self.log_file:
            log_path = Path(self.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Base logging configuration
        config = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'json': {
                    '()': SecurityAwareFormatter,
                    'format': '%(asctime)s %(name)s %(levelname)s %(message)s'
                },
                'detailed': {
                    'format': '[%(asctime)s] %(name)s.%(funcName)s:%(lineno)d %(levelname)s - %(message)s',
                    'datefmt': '%Y-%m-%d %H:%M:%S'
                },
                'simple': {
                    'format': '%(levelname)s - %(message)s'
                }
            },
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'level': self.log_level,
                    'formatter': self.log_format if self.log_format in ['json', 'detailed', 'simple'] else 'detailed',
                    'stream': sys.stdout
                }
            },
            'loggers': {
                # Application loggers
                'src': {
                    'level': self.log_level,
                    'handlers': ['console'],
                    'propagate': False
                },
                # Third-party loggers (with higher log levels to reduce noise)
                'asyncpg': {
                    'level': 'WARNING',
                    'handlers': ['console'],
                    'propagate': False
                },
                'aiokafka': {
                    'level': 'WARNING',
                    'handlers': ['console'],
                    'propagate': False
                },
                'urllib3': {
                    'level': 'WARNING',
                    'handlers': ['console'],
                    'propagate': False
                },
                'fastapi': {
                    'level': 'WARNING',
                    'handlers': ['console'],
                    'propagate': False
                }
            },
            'root': {
                'level': 'WARNING',
                'handlers': ['console']
            }
        }
        
        # Add file handler if log file is specified
        if self.log_file:
            config['handlers']['file'] = {
                'class': 'logging.handlers.RotatingFileHandler',
                'level': self.log_level,
                'formatter': 'json',
                'filename': self.log_file,
                'maxBytes': 50 * 1024 * 1024,  # 50MB
                'backupCount': 5,
                'encoding': 'utf-8'
            }
            
            # Add file handler to all loggers
            for logger_name in config['loggers']:
                config['loggers'][logger_name]['handlers'].append('file')
            config['root']['handlers'].append('file')
        
        # Apply configuration
        logging.config.dictConfig(config)
        self._configured = True
        
        # Configure structlog if using JSON format
        if self.log_format == 'json':
            self._configure_structlog()
        
        logger = logging.getLogger(__name__)
        logger.info(f"Logging configured: level={self.log_level}, format={self.log_format}")
    
    def _configure_structlog(self):
        """Configure structlog for structured logging"""
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )


class AuditLogger:
    """Specialized logger for audit events"""
    
    def __init__(self):
        self.logger = logging.getLogger('audit')
        self.logger.setLevel(logging.INFO)
    
    def log_security_event(self, event_type: str, actor: str, 
                          description: str, **kwargs):
        """Log security-related events"""
        event_data = {
            'event_type': 'security',
            'event_subtype': event_type,
            'actor': actor,
            'description': description,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'additional_data': kwargs
        }
        
        self.logger.info("Security event", extra=event_data)
    
    def log_compliance_event(self, event_type: str, system_id: str,
                           description: str, **kwargs):
        """Log compliance-related events"""
        event_data = {
            'event_type': 'compliance',
            'event_subtype': event_type,
            'system_id': system_id,
            'description': description,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'additional_data': kwargs
        }
        
        self.logger.info("Compliance event", extra=event_data)
    
    def log_api_access(self, method: str, endpoint: str, 
                      status_code: int, user_id: str = None,
                      ip_address: str = None, **kwargs):
        """Log API access events"""
        event_data = {
            'event_type': 'api_access',
            'method': method,
            'endpoint': endpoint,
            'status_code': status_code,
            'user_id': user_id,
            'ip_address': ip_address,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'additional_data': kwargs
        }
        
        self.logger.info("API access", extra=event_data)
    
    def log_authentication_event(self, event_type: str, user_id: str,
                                success: bool, ip_address: str = None,
                                **kwargs):
        """Log authentication events"""
        event_data = {
            'event_type': 'authentication',
            'event_subtype': event_type,
            'user_id': user_id,
            'success': success,
            'ip_address': ip_address,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'additional_data': kwargs
        }
        
        level = logging.INFO if success else logging.WARNING
        self.logger.log(level, "Authentication event", extra=event_data)
    
    def log_data_access(self, operation: str, resource_type: str,
                       resource_id: str, user_id: str = None, **kwargs):
        """Log data access events"""
        event_data = {
            'event_type': 'data_access',
            'operation': operation,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'user_id': user_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'additional_data': kwargs
        }
        
        self.logger.info("Data access", extra=event_data)


class PerformanceLogger:
    """Logger for performance monitoring"""
    
    def __init__(self):
        self.logger = logging.getLogger('performance')
        self.logger.setLevel(logging.INFO)
    
    def log_operation_timing(self, operation: str, duration: float,
                           success: bool = True, **kwargs):
        """Log operation timing information"""
        event_data = {
            'event_type': 'performance',
            'operation': operation,
            'duration_seconds': duration,
            'success': success,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'additional_data': kwargs
        }
        
        # Log as warning if operation took too long
        level = logging.WARNING if duration > 30 else logging.INFO
        self.logger.log(level, f"Operation timing: {operation}", extra=event_data)
    
    def log_resource_usage(self, resource_type: str, usage_value: float,
                          unit: str = "percent", **kwargs):
        """Log resource usage information"""
        event_data = {
            'event_type': 'resource_usage',
            'resource_type': resource_type,
            'usage_value': usage_value,
            'unit': unit,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'additional_data': kwargs
        }
        
        # Log as warning if usage is high
        warning_thresholds = {'cpu': 80, 'memory': 85, 'disk': 90}
        threshold = warning_thresholds.get(resource_type.lower(), 95)
        level = logging.WARNING if usage_value > threshold else logging.INFO
        
        self.logger.log(level, f"Resource usage: {resource_type}", extra=event_data)


class ComplianceLogContext:
    """Context manager for adding compliance context to logs"""
    
    def __init__(self, system_id: str = None, scan_id: str = None,
                 profile: str = None, **context):
        self.context = {
            'system_id': system_id,
            'scan_id': scan_id,
            'profile': profile,
            **context
        }
        # Remove None values
        self.context = {k: v for k, v in self.context.items() if v is not None}
        self.old_context = {}
    
    def __enter__(self):
        # Store existing context
        for key in self.context:
            if hasattr(logging, '_compliance_context'):
                self.old_context[key] = getattr(logging._compliance_context, key, None)
        
        # Set new context
        if not hasattr(logging, '_compliance_context'):
            logging._compliance_context = {}
        
        logging._compliance_context.update(self.context)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore old context
        if hasattr(logging, '_compliance_context'):
            for key, value in self.old_context.items():
                if value is None:
                    logging._compliance_context.pop(key, None)
                else:
                    logging._compliance_context[key] = value


# Enhanced logging filter to add compliance context
class ComplianceContextFilter(logging.Filter):
    """Filter to add compliance context to log records"""
    
    def filter(self, record):
        # Add compliance context if available
        if hasattr(logging, '_compliance_context'):
            for key, value in logging._compliance_context.items():
                setattr(record, key, value)
        
        return True


# Initialize global loggers
def initialize_logging(log_level: str = None, log_format: str = None, 
                      log_file: str = None):
    """Initialize logging for the compliance agent"""
    # Get configuration from environment if not provided
    log_level = log_level or os.getenv('LOG_LEVEL', 'INFO')
    log_format = log_format or os.getenv('LOG_FORMAT', 'json')
    log_file = log_file or os.getenv('LOG_FILE')
    
    # Configure main logging
    compliance_logger = ComplianceLogger(log_level, log_format, log_file)
    compliance_logger.configure_logging()
    
    # Add compliance context filter to all handlers
    context_filter = ComplianceContextFilter()
    for handler in logging.root.handlers:
        handler.addFilter(context_filter)
    
    return compliance_logger


# Global instances
audit_logger = AuditLogger()
performance_logger = PerformanceLogger()


# Convenience functions
def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name"""
    return logging.getLogger(name)


def log_compliance_scan_start(system_id: str, profile: str, scan_id: str):
    """Log compliance scan start"""
    audit_logger.log_compliance_event(
        'scan_start',
        system_id,
        f'Starting compliance scan with profile {profile}',
        scan_id=scan_id,
        profile=profile
    )


def log_compliance_scan_complete(system_id: str, profile: str, scan_id: str,
                                score: float, duration: float):
    """Log compliance scan completion"""
    audit_logger.log_compliance_event(
        'scan_complete',
        system_id,
        f'Compliance scan completed with score {score}%',
        scan_id=scan_id,
        profile=profile,
        compliance_score=score
    )
    
    performance_logger.log_operation_timing(
        'compliance_scan',
        duration,
        success=True,
        system_id=system_id,
        profile=profile,
        compliance_score=score
    )