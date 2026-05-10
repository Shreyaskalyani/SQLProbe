"""
Analyzer Module
===============

Result analysis and correlation.
"""

from .engine import (
    ResultAnalyzer,
    AnalyzedFinding,
    SeverityCalculator,
)

__all__ = [
    'ResultAnalyzer',
    'AnalyzedFinding',
    'SeverityCalculator',
]