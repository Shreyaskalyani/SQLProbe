"""
Crawler Module
==============

Smart web crawling for endpoint and parameter discovery.
"""

from .engine import (
    SmartCrawler,
    CrawlResult,
    Endpoint,
    FormParameter,
    HiddenParameterDetector,
)

__all__ = [
    'SmartCrawler',
    'CrawlResult',
    'Endpoint',
    'FormParameter',
    'HiddenParameterDetector',
]