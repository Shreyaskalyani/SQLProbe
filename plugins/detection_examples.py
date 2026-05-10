"""
Example Custom Detection Plugin
=================================

Demonstrates how to create a custom detection plugin.
"""

from typing import Any, Dict

from ..plugins.system import (
    DetectionPlugin,
    PluginMetadata,
)


class CustomDetectionPlugin(DetectionPlugin):
    """Example custom detection plugin."""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="custom_detection",
            version="1.0.0",
            author="Security Researcher",
            description="Custom detection logic for SQL injection",
            plugin_type="detection"
        )
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        return True
    
    def cleanup(self) -> None:
        pass
    
    def detect(
        self,
        baseline: Any,
        response: Any,
        payload: str
    ) -> Dict[str, Any]:
        """Custom detection logic."""
        
        result = {
            'is_vulnerable': False,
            'confidence': 0.0,
            'injection_type': 'custom',
            'evidence': {},
        }
        
        if baseline and response:
            baseline_length = getattr(baseline, 'content_length', 0)
            response_length = getattr(response, 'content_length', 0)
            
            length_diff = abs(response_length - baseline_length) / max(baseline_length, 1)
            
            if length_diff > 0.2:
                result['is_vulnerable'] = True
                result['confidence'] = 0.7
                result['evidence']['length_diff'] = length_diff
        
        return result
    
    def get_detection_type(self) -> str:
        return "custom_length_based"


class AdvancedSignatureDetection(DetectionPlugin):
    """Advanced detection using signature matching."""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="advanced_signature",
            version="1.0.0",
            author="Security Researcher",
            description="Advanced signature-based SQL injection detection",
            plugin_type="detection"
        )
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        return True
    
    def cleanup(self) -> None:
        pass
    
    def detect(
        self,
        baseline: Any,
        response: Any,
        payload: str
    ) -> Dict[str, Any]:
        """Detect using advanced signature matching."""
        
        result = {
            'is_vulnerable': False,
            'confidence': 0.0,
            'injection_type': 'signature',
            'evidence': {},
        }
        
        if not response:
            return result
        
        response_text = getattr(response, 'text', '') or ''
        
        sql_signatures = [
            r"SQL syntax.*error",
            r"Warning.*mysql",
            r"ORA-\d{5}",
            r"PostgreSQL.*ERROR",
            r"SQLServer.*ERROR",
            r"Unclosed quotation",
            r"SQLSTATE\[.*\]",
            r"Invalid SQL",
            r"System.Data.SqlClient",
            r"com\.mysql\.jdbc",
        ]
        
        import re
        
        matched_signatures = []
        for sig in sql_signatures:
            if re.search(sig, response_text, re.IGNORECASE):
                matched_signatures.append(sig)
        
        if matched_signatures:
            result['is_vulnerable'] = True
            result['confidence'] = 0.9
            result['evidence']['signatures'] = matched_signatures
        
        return result
    
    def get_detection_type(self) -> str:
        return "signature_matching"