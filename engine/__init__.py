"""
Engine Module
=============

Core engine components for the SQL injection assessment framework.
"""

from .http_engine import (
    AsyncHTTPEngine,
    RequestConfig,
    HTTPResponse,
    SessionManager,
    RequestBatcher,
)
from .assessment import (
    AssessmentEngine,
    AssessmentConfig,
    AssessmentResult,
    VulnerabilityFinding,
)

__all__ = [
    'AsyncHTTPEngine',
    'RequestConfig',
    'HTTPResponse',
    'SessionManager',
    'RequestBatcher',
    'AssessmentEngine',
    'AssessmentConfig',
    'AssessmentResult',
    'VulnerabilityFinding',
]