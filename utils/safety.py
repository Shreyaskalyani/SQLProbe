"""
Safety Controls Module
======================

Implements safety controls including:
- Target confirmation
- Domain whitelist checking
- Rate limiting
- Legal warnings
"""

import asyncio
import re
import time
from typing import Optional, Set
from urllib.parse import urlparse


class SafetyControls:
    """Safety controls for the framework."""
    
    DEFAULT_WHITELIST: Set[str] = set()
    _confirmed_targets: Set[str] = set()
    _last_request_time: float = 0
    _min_request_interval: float = 0.1
    
    @classmethod
    def set_min_interval(cls, interval: float) -> None:
        """Set minimum interval between requests for rate limiting."""
        cls._min_request_interval = interval
    
    @classmethod
    async def wait_for_rate_limit(cls) -> None:
        """Wait if necessary to maintain rate limit."""
        elapsed = time.time() - cls._last_request_time
        if elapsed < cls._min_request_interval:
            await asyncio.sleep(cls._min_request_interval - elapsed)
        cls._last_request_time = time.time()
    
    @classmethod
    def confirm_target(cls, target: str) -> bool:
        """Confirm target for testing."""
        parsed = urlparse(target)
        domain = parsed.netloc
        cls._confirmed_targets.add(domain)
        return True
    
    @classmethod
    def is_confirmed(cls, target: str) -> bool:
        """Check if target has been confirmed."""
        parsed = urlparse(target)
        domain = parsed.netloc
        return domain in cls._confirmed_targets


def validate_target(target: str) -> bool:
    """Validate target URL format."""
    if not target:
        return False
    
    parsed = urlparse(target)
    
    if not parsed.scheme in ('http', 'https'):
        return False
    
    if not parsed.netloc:
        return False
    
    domain_with_port = parsed.netloc
    if ':' in domain_with_port:
        host_part = domain_with_port.split(':')[0]
    else:
        host_part = domain_with_port
    
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    if not re.match(domain_pattern, host_part):
        return False
    
    return True


def check_whitelist(target: str, whitelist: Optional[str] = None) -> bool:
    """Check if target is in whitelist."""
    if not whitelist:
        return True
    
    parsed = urlparse(target)
    domain = parsed.netloc
    
    whitelist_domains = whitelist.split(',')
    
    for whitelisted in whitelist_domains:
        whitelisted = whitelisted.strip()
        if '*' in whitelisted:
            pattern = whitelisted.replace('.', r'\.').replace('*', '.*')
            if re.match(pattern, domain):
                return True
        elif whitelisted in domain or domain.endswith('.' + whitelisted):
            return True
    
    return False


from typing import Optional as TypingOptional