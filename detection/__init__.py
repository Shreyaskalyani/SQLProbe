"""
Detection Module
================

Detection engines for SQL injection vulnerability identification.
"""

from .engine import (
    DetectionEngine,
    DetectionResult,
    BaselineResponse,
    ConfidenceLevel,
    InjectionType,
    DifferentialFuzzer,
    SQL_ERROR_PATTERNS,
)

__all__ = [
    'DetectionEngine',
    'DetectionResult',
    'BaselineResponse',
    'ConfidenceLevel',
    'InjectionType',
    'DifferentialFuzzer',
    'SQL_ERROR_PATTERNS',
]