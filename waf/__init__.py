"""
WAF Module
==========

WAF detection and adaptive testing capabilities.
"""

from .detector import (
    WAFDetector,
    WAFDetectionResult,
    WAFType,
    BlockingBehavior,
    WAFConfig,
    WAFAdapter,
)

__all__ = [
    'WAFDetector',
    'WAFDetectionResult',
    'WAFType',
    'BlockingBehavior',
    'WAFConfig',
    'WAFAdapter',
]