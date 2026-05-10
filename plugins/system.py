"""
Plugin System Module
====================

Provides extensible plugin system:
- Custom payload plugins
- Custom detection method plugins
- Custom analyzer plugins
"""

import importlib.util
import inspect
from typing import Any, Callable, Dict, List, Optional, Type
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..utils import setup_logging


logger = setup_logging()


@dataclass
class PluginMetadata:
    """Metadata for a plugin."""
    name: str
    version: str
    author: str
    description: str
    plugin_type: str
    dependencies: List[str] = field(default_factory=list)


class Plugin(ABC):
    """Base class for all plugins."""
    
    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        pass
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin with configuration."""
        pass
    
    @abstractmethod
    def cleanup(self) -> None:
        """Clean up plugin resources."""
        pass


class PayloadPlugin(Plugin):
    """Plugin for custom SQL injection payloads."""
    
    @abstractmethod
    def generate_payloads(self, context: Dict[str, Any]) -> List[str]:
        """Generate payloads for the given context."""
        pass
    
    @abstractmethod
    def get_payload_types(self) -> List[str]:
        """Get list of payload types this plugin generates."""
        pass


class DetectionPlugin(Plugin):
    """Plugin for custom detection methods."""
    
    @abstractmethod
    def detect(
        self,
        baseline: Any,
        response: Any,
        payload: str
    ) -> Dict[str, Any]:
        """Detect vulnerability using custom method."""
        pass
    
    @abstractmethod
    def get_detection_type(self) -> str:
        """Get the type of detection this plugin provides."""
        pass


class AnalyzerPlugin(Plugin):
    """Plugin for custom result analysis."""
    
    @abstractmethod
    def analyze(
        self,
        results: List[Any]
    ) -> Dict[str, Any]:
        """Analyze detection results."""
        pass
    
    @abstractmethod
    def get_analysis_type(self) -> str:
        """Get the type of analysis this plugin provides."""
        pass


class PluginManager:
    """Manages loading and execution of plugins."""
    
    def __init__(self):
        self._payload_plugins: Dict[str, PayloadPlugin] = {}
        self._detection_plugins: Dict[str, DetectionPlugin] = {}
        self._analyzer_plugins: Dict[str, AnalyzerPlugin] = {}
        self._plugin_paths: List[Path] = []
        self._loaded = False
    
    def add_plugin_path(self, path: str) -> None:
        """Add a path to search for plugins."""
        plugin_path = Path(path)
        if plugin_path.exists() and plugin_path.is_dir():
            self._plugin_paths.append(plugin_path)
    
    def load_plugins(self) -> None:
        """Load all plugins from configured paths."""
        if self._loaded:
            return
        
        for plugin_path in self._plugin_paths:
            self._load_plugins_from_path(plugin_path)
        
        self._loaded = True
        logger.info(f"Loaded {len(self._payload_plugins)} payload plugins, "
                   f"{len(self._detection_plugins)} detection plugins, "
                   f"{len(self._analyzer_plugins)} analyzer plugins")
    
    def _load_plugins_from_path(self, path: Path) -> None:
        """Load plugins from a specific path."""
        
        for plugin_file in path.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue
            
            try:
                self._load_plugin_from_file(plugin_file)
            except Exception as e:
                logger.warning(f"Failed to load plugin {plugin_file}: {e}")
    
    def _load_plugin_from_file(self, plugin_file: Path) -> None:
        """Load a single plugin from a file."""
        
        spec = importlib.util.spec_from_file_location(
            plugin_file.stem,
            plugin_file
        )
        
        if not spec or not spec.loader:
            return
        
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        for name, obj in inspect.getmembers(module):
            if inspect.isclass(obj) and issubclass(obj, Plugin) and obj is not Plugin:
                try:
                    plugin = obj()
                    metadata = plugin.get_metadata()
                    
                    if isinstance(plugin, PayloadPlugin):
                        self._payload_plugins[metadata.name] = plugin
                    elif isinstance(plugin, DetectionPlugin):
                        self._detection_plugins[metadata.name] = plugin
                    elif isinstance(plugin, AnalyzerPlugin):
                        self._analyzer_plugins[metadata.name] = plugin
                        
                except Exception as e:
                    logger.warning(f"Failed to instantiate plugin {name}: {e}")
    
    def register_payload_plugin(self, name: str, plugin: PayloadPlugin) -> None:
        """Register a payload plugin manually."""
        self._payload_plugins[name] = plugin
    
    def register_detection_plugin(self, name: str, plugin: DetectionPlugin) -> None:
        """Register a detection plugin manually."""
        self._detection_plugins[name] = plugin
    
    def register_analyzer_plugin(self, name: str, plugin: AnalyzerPlugin) -> None:
        """Register an analyzer plugin manually."""
        self._analyzer_plugins[name] = plugin
    
    def get_payload_plugin(self, name: str) -> Optional[PayloadPlugin]:
        """Get a payload plugin by name."""
        return self._payload_plugins.get(name)
    
    def get_detection_plugin(self, name: str) -> Optional[DetectionPlugin]:
        """Get a detection plugin by name."""
        return self._detection_plugins.get(name)
    
    def get_analyzer_plugin(self, name: str) -> Optional[AnalyzerPlugin]:
        """Get an analyzer plugin by name."""
        return self._analyzer_plugins.get(name)
    
    def get_all_payload_plugins(self) -> Dict[str, PayloadPlugin]:
        """Get all registered payload plugins."""
        return self._payload_plugins.copy()
    
    def get_all_detection_plugins(self) -> Dict[str, DetectionPlugin]:
        """Get all registered detection plugins."""
        return self._detection_plugins.copy()
    
    def get_all_analyzer_plugins(self) -> Dict[str, AnalyzerPlugin]:
        """Get all registered analyzer plugins."""
        return self._analyzer_plugins.copy()
    
    def unregister_plugin(self, name: str) -> bool:
        """Unregister a plugin by name."""
        removed = False
        
        if name in self._payload_plugins:
            del self._payload_plugins[name]
            removed = True
        
        if name in self._detection_plugins:
            del self._detection_plugins[name]
            removed = True
        
        if name in self._analyzer_plugins:
            del self._analyzer_plugins[name]
            removed = True
        
        return removed
    
    def list_plugins(self) -> Dict[str, List[str]]:
        """List all loaded plugins."""
        return {
            'payload': list(self._payload_plugins.keys()),
            'detection': list(self._detection_plugins.keys()),
            'analyzer': list(self._analyzer_plugins.keys()),
        }


class PluginRegistry:
    """Registry for plugin configurations and states."""
    
    def __init__(self):
        self._configs: Dict[str, Dict[str, Any]] = {}
        self._states: Dict[str, Any] = {}
    
    def register_config(self, plugin_name: str, config: Dict[str, Any]) -> None:
        """Register configuration for a plugin."""
        self._configs[plugin_name] = config
    
    def get_config(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get configuration for a plugin."""
        return self._configs.get(plugin_name)
    
    def register_state(self, plugin_name: str, state: Any) -> None:
        """Register state for a plugin."""
        self._states[plugin_name] = state
    
    def get_state(self, plugin_name: str) -> Optional[Any]:
        """Get state for a plugin."""
        return self._states.get(plugin_name)
    
    def clear(self) -> None:
        """Clear all configurations and states."""
        self._configs.clear()
        self._states.clear()


def create_payload_plugin(
    name: str,
    version: str,
    author: str,
    description: str,
    payload_generator: Callable[[Dict[str, Any]], List[str]],
    payload_types: List[str]
) -> Type[PayloadPlugin]:
    """Factory function to create a payload plugin."""
    
    class CustomPayloadPlugin(PayloadPlugin):
        def get_metadata(self) -> PluginMetadata:
            return PluginMetadata(
                name=name,
                version=version,
                author=author,
                description=description,
                plugin_type="payload"
            )
        
        def initialize(self, config: Dict[str, Any]) -> bool:
            return True
        
        def cleanup(self) -> None:
            pass
        
        def generate_payloads(self, context: Dict[str, Any]) -> List[str]:
            return payload_generator(context)
        
        def get_payload_types(self) -> List[str]:
            return payload_types
    
    return CustomPayloadPlugin


def create_detection_plugin(
    name: str,
    version: str,
    author: str,
    description: str,
    detector: Callable[[Any, Any, str], Dict[str, Any]],
    detection_type: str
) -> Type[DetectionPlugin]:
    """Factory function to create a detection plugin."""
    
    class CustomDetectionPlugin(DetectionPlugin):
        def get_metadata(self) -> PluginMetadata:
            return PluginMetadata(
                name=name,
                version=version,
                author=author,
                description=description,
                plugin_type="detection"
            )
        
        def initialize(self, config: Dict[str, Any]) -> bool:
            return True
        
        def cleanup(self) -> None:
            pass
        
        def detect(self, baseline: Any, response: Any, payload: str) -> Dict[str, Any]:
            return detector(baseline, response, payload)
        
        def get_detection_type(self) -> str:
            return detection_type
    
    return CustomDetectionPlugin