from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class PluginConfig:
    """Configuration for compliance plugins"""
    name: str
    version: str
    enabled: bool = True
    settings: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.settings is None:
            self.settings = {}


@dataclass
class ScanRequest:
    """Request object for compliance scans"""
    system_id: str
    profile: str
    config: Dict[str, Any]
    output_dir: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ScanResult:
    """Result object from compliance scans"""
    success: bool
    data: Dict[str, Any]
    error_message: Optional[str] = None
    warnings: List[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []
        if self.metadata is None:
            self.metadata = {}


class CompliancePlugin(ABC):
    """Abstract base class for compliance framework plugins"""
    
    def __init__(self, config: PluginConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass
    
    @property
    @abstractmethod
    def supported_frameworks(self) -> List[str]:
        """List of supported compliance frameworks"""
        pass
    
    @abstractmethod
    async def scan(self, request: ScanRequest) -> ScanResult:
        """
        Execute compliance scan
        
        Args:
            request: Scan request with configuration
            
        Returns:
            Scan result with compliance data
        """
        pass
    
    @abstractmethod
    def get_supported_profiles(self) -> List[Dict[str, str]]:
        """
        Get list of supported compliance profiles
        
        Returns:
            List of profile dictionaries with id, name, description
        """
        pass
    
    @abstractmethod
    async def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate plugin configuration
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            True if configuration is valid
        """
        pass
    
    async def initialize(self) -> bool:
        """
        Initialize plugin resources
        
        Returns:
            True if initialization successful
        """
        try:
            self.logger.info(f"Initializing plugin: {self.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize plugin {self.name}: {e}")
            return False
    
    async def cleanup(self):
        """Cleanup plugin resources"""
        try:
            self.logger.info(f"Cleaning up plugin: {self.name}")
        except Exception as e:
            self.logger.error(f"Error during plugin cleanup: {e}")
    
    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for this plugin"""
        return {
            "timeout": 300,
            "max_retries": 3,
            "output_format": "json"
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check for the plugin
        
        Returns:
            Health status dictionary
        """
        try:
            return {
                "status": "healthy",
                "plugin": self.name,
                "version": self.version,
                "enabled": self.config.enabled
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "plugin": self.name,
                "version": self.version,
                "enabled": self.config.enabled,
                "error": str(e)
            }


class PluginManager:
    """Manager for compliance plugins"""
    
    def __init__(self):
        self.plugins: Dict[str, CompliancePlugin] = {}
        self.logger = logging.getLogger(__name__)
    
    async def register_plugin(self, plugin: CompliancePlugin) -> bool:
        """
        Register a compliance plugin
        
        Args:
            plugin: Plugin instance to register
            
        Returns:
            True if registration successful
        """
        try:
            if not plugin.config.enabled:
                self.logger.info(f"Plugin {plugin.name} is disabled, skipping registration")
                return False
            
            # Initialize plugin
            if not await plugin.initialize():
                self.logger.error(f"Failed to initialize plugin {plugin.name}")
                return False
            
            # Check for naming conflicts
            if plugin.name in self.plugins:
                self.logger.warning(f"Plugin {plugin.name} already registered, replacing")
            
            self.plugins[plugin.name] = plugin
            self.logger.info(f"Registered plugin: {plugin.name} v{plugin.version}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error registering plugin {plugin.name}: {e}")
            return False
    
    async def unregister_plugin(self, plugin_name: str) -> bool:
        """
        Unregister a plugin
        
        Args:
            plugin_name: Name of plugin to unregister
            
        Returns:
            True if unregistration successful
        """
        try:
            if plugin_name not in self.plugins:
                self.logger.warning(f"Plugin {plugin_name} not found for unregistration")
                return False
            
            plugin = self.plugins[plugin_name]
            await plugin.cleanup()
            del self.plugins[plugin_name]
            
            self.logger.info(f"Unregistered plugin: {plugin_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error unregistering plugin {plugin_name}: {e}")
            return False
    
    def get_plugin(self, plugin_name: str) -> Optional[CompliancePlugin]:
        """Get plugin by name"""
        return self.plugins.get(plugin_name)
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """
        List all registered plugins
        
        Returns:
            List of plugin information dictionaries
        """
        return [
            {
                "name": plugin.name,
                "version": plugin.version,
                "enabled": plugin.config.enabled,
                "frameworks": plugin.supported_frameworks
            }
            for plugin in self.plugins.values()
        ]
    
    async def get_plugins_by_framework(self, framework: str) -> List[CompliancePlugin]:
        """
        Get plugins that support a specific framework
        
        Args:
            framework: Compliance framework name (e.g., 'CIS', 'NIST')
            
        Returns:
            List of matching plugins
        """
        matching_plugins = []
        for plugin in self.plugins.values():
            if framework.upper() in [f.upper() for f in plugin.supported_frameworks]:
                matching_plugins.append(plugin)
        
        return matching_plugins
    
    async def execute_scan(self, plugin_name: str, request: ScanRequest) -> ScanResult:
        """
        Execute scan using specified plugin
        
        Args:
            plugin_name: Name of plugin to use
            request: Scan request
            
        Returns:
            Scan result
        """
        try:
            plugin = self.get_plugin(plugin_name)
            if not plugin:
                return ScanResult(
                    success=False,
                    data={},
                    error_message=f"Plugin {plugin_name} not found"
                )
            
            if not plugin.config.enabled:
                return ScanResult(
                    success=False,
                    data={},
                    error_message=f"Plugin {plugin_name} is disabled"
                )
            
            self.logger.info(f"Executing scan with plugin {plugin_name} for system {request.system_id}")
            result = await plugin.scan(request)
            
            if result.success:
                self.logger.info(f"Scan completed successfully with plugin {plugin_name}")
            else:
                self.logger.error(f"Scan failed with plugin {plugin_name}: {result.error_message}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing scan with plugin {plugin_name}: {e}")
            return ScanResult(
                success=False,
                data={},
                error_message=f"Plugin execution error: {str(e)}"
            )
    
    async def health_check_all(self) -> Dict[str, Any]:
        """
        Perform health check on all plugins
        
        Returns:
            Health status for all plugins
        """
        health_status = {
            "overall_status": "healthy",
            "plugins": {}
        }
        
        unhealthy_count = 0
        
        for plugin_name, plugin in self.plugins.items():
            try:
                status = await plugin.health_check()
                health_status["plugins"][plugin_name] = status
                
                if status["status"] != "healthy":
                    unhealthy_count += 1
                    
            except Exception as e:
                health_status["plugins"][plugin_name] = {
                    "status": "error",
                    "error": str(e)
                }
                unhealthy_count += 1
        
        if unhealthy_count > 0:
            health_status["overall_status"] = "degraded" if unhealthy_count < len(self.plugins) else "unhealthy"
        
        health_status["total_plugins"] = len(self.plugins)
        health_status["unhealthy_plugins"] = unhealthy_count
        
        return health_status
    
    async def shutdown_all(self):
        """Shutdown all plugins"""
        self.logger.info("Shutting down all plugins")
        
        for plugin_name in list(self.plugins.keys()):
            await self.unregister_plugin(plugin_name)
        
        self.logger.info("All plugins shut down")


# Global plugin manager instance
plugin_manager = PluginManager()