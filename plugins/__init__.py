"""
Plugin System Module
====================

Extensible plugin system for payloads, detection, and analysis.
"""

from .system import (
    PluginManager,
    PluginRegistry,
    Plugin,
    PayloadPlugin,
    DetectionPlugin,
    AnalyzerPlugin,
    PluginMetadata,
    create_payload_plugin,
    create_detection_plugin,
)

__all__ = [
    'PluginManager',
    'PluginRegistry',
    'Plugin',
    'PayloadPlugin',
    'DetectionPlugin',
    'AnalyzerPlugin',
    'PluginMetadata',
    'create_payload_plugin',
    'create_detection_plugin',
]