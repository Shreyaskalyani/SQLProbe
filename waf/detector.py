"""
WAF Detection Module
===================

Provides WAF detection and adaptive testing capabilities:
- Detect blocking behavior (403, CAPTCHA, anomalies)
- Adapt payload encoding strategies
- Slow down or rotate payloads on detection
"""

import re
from typing import Optional, Dict, Any, List, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..engine import AsyncHTTPEngine, HTTPResponse
from ..utils import setup_logging


logger = setup_logging()


class WAFType(Enum):
    """Types of WAF/Protection systems."""
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    F5_BIGIP = "f5_bigip"
    IMPERVA = "imperva"
    FORTIWEB = "fortiweb"
    MODSECURITY = "modsecurity"
    BARRACUDA = "barracuda"
    SUCURI = "sucuri"
    UNKNOWN = "unknown"


class BlockingBehavior(Enum):
    """Types of blocking behavior detected."""
    STATUS_403 = "403_forbidden"
    STATUS_419 = "419_timeout"
    STATUS_429 = "rate_limiting"
    STATUS_503 = "service_unavailable"
    CAPTCHA = "captcha_required"
    IP_BLOCK = "ip_blocked"
    CONTENT_BLOCK = "content_blocked"
    EMPTY_RESPONSE = "empty_response"
    REDIRECT_BLOCK = "redirect_to_block_page"
    NONE = "none"


@dataclass
class WAFDetectionResult:
    """Result of WAF detection."""
    detected: bool
    waf_type: Optional[WAFType] = None
    blocking_behavior: BlockingBehavior = BlockingBehavior.NONE
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


WAF_SIGNATURES = {
    WAFType.CLOUDFLARE: [
        "cf-ray",
        "__cfduid",
        "cloudflare",
        "Attention Required! | Cloudflare",
        "Cloudflare Ray ID:",
        "Checking your browser before accessing",
    ],
    WAFType.AWS_WAF: [
        "aws-waf-token",
        "X-Amzn-Trace-Id",
        "AWSWAF",
        "AWS WAF",
    ],
    WAFType.AKAMAI: [
        "akamai-origin-hop",
        "AkamaiGHost",
        "X-Akamai-*",
        "Reference #",
        "Access Denied",
    ],
    WAFType.F5_BIGIP: [
        "X-Correlation-ID",
        "BigIP",
        "F5 Networks",
        "TRAFFIC_SEQ",
    ],
    WAFType.IMPERVA: [
        "x-cdn",
        "x-iinfo",
        "imperva",
        "Incapsula",
    ],
    WAFType.FORTIWEB: [
        "FortiWeb",
        "FORTIWEB",
    ],
    WAFType.MODSECURITY: [
        "mod_security",
        "ModSecurity",
        "mod_security enabled",
    ],
    WAFType.BARRACUDA: [
        "barra_counter_session",
        "barracuda",
        "BND",
    ],
    WAFType.SUCURI: [
        "sucuri",
        "X-Sucuri-",
        "SUCURI",
    ],
}

BLOCK_STATUS_CODES = {
    403: BlockingBehavior.STATUS_403,
    429: BlockingBehavior.STATUS_429,
    419: BlockingBehavior.STATUS_419,
    503: BlockingBehavior.STATUS_503,
}

BLOCK_CONTENT_PATTERNS = [
    r"access denied",
    r"forbidden",
    r"blocked",
    r"security violation",
    r"attack detected",
    r"malicious.*detected",
    r"sql.*injection.*detected",
    r"xss.*detected",
    r"captcha",
    r"verify you are human",
    r"rate limit",
    r"too many requests",
    r"IP.*blocked",
    r"banned",
    r"suspended",
    r"firewall",
    r"WAF",
]


@dataclass
class WAFConfig:
    """Configuration for WAF handling."""
    enabled: bool = True
    auto_adapt: bool = True
    max_retries: int = 3
    retry_delay: float = 2.0
    encoding_strategies: List[str] = field(default_factory=lambda: ["url", "double_url", "unicode"])


class WAFDetector:
    """Detects WAF and adjusts testing strategy accordingly."""
    
    def __init__(self, config: Optional[WAFConfig] = None):
        self.config = config or WAFConfig()
        self._detected_wafs: Set[WAFType] = set()
        self._blocking_history: List[BlockingBehavior] = []
        self._current_strategy = "standard"
        self._consecutive_blocks = 0
    
    async def detect_waf(
        self,
        http_engine: AsyncHTTPEngine,
        url: str
    ) -> WAFDetectionResult:
        """Detect WAF presence."""
        
        try:
            response = await http_engine.get(url)
            
            return self._analyze_response(response)
            
        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")
            return WAFDetectionResult(
                detected=False,
                recommendations=["Unable to determine WAF status"]
            )
    
    def _analyze_response(self, response: HTTPResponse) -> WAFDetectionResult:
        """Analyze response for WAF indicators."""
        
        evidence = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content_preview': response.text[:500] if response.text else "",
        }
        
        detected_waf = self._detect_waf_type(response.headers, response.text)
        
        blocking = self._detect_blocking(response)
        
        if detected_waf:
            self._detected_wafs.add(detected_waf)
            evidence['waf_type'] = detected_waf.value
        
        if blocking != BlockingBehavior.NONE:
            self._blocking_history.append(blocking)
            self._consecutive_blocks += 1
            evidence['blocking'] = blocking.value
        else:
            self._consecutive_blocks = 0
        
        recommendations = self._generate_recommendations(detected_waf, blocking)
        
        return WAFDetectionResult(
            detected=detected_waf is not None or blocking != BlockingBehavior.NONE,
            waf_type=detected_waf,
            blocking_behavior=blocking,
            evidence=evidence,
            recommendations=recommendations,
        )
    
    def _detect_waf_type(
        self,
        headers: Dict[str, str],
        content: str
    ) -> Optional[WAFType]:
        """Detect specific WAF type from headers and content."""
        
        header_str = str(headers).lower()
        content_lower = content.lower()
        
        for waf_type, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in header_str or sig.lower() in content_lower:
                    return waf_type
        
        return None
    
    def _detect_blocking(self, response: HTTPResponse) -> BlockingBehavior:
        """Detect blocking behavior from response."""
        
        status_block = BLOCK_STATUS_CODES.get(response.status_code)
        if status_block:
            return status_block
        
        content_lower = response.text.lower() if response.text else ""
        
        for pattern in BLOCK_CONTENT_PATTERNS:
            if re.search(pattern, content_lower):
                if "captcha" in pattern or "human" in pattern:
                    return BlockingBehavior.CAPTCHA
                return BlockingBehavior.CONTENT_BLOCK
        
        if response.content_length == 0 and response.status_code != 204:
            return BlockingBehavior.EMPTY_RESPONSE
        
        return BlockingBehavior.NONE
    
    def _generate_recommendations(
        self,
        waf_type: Optional[WAFType],
        blocking: BlockingBehavior
    ) -> List[str]:
        """Generate recommendations based on detected WAF/blocking."""
        recommendations = []
        
        if blocking == BlockingBehavior.STATUS_403:
            recommendations.append("Target is returning 403 - try encoding payloads")
            recommendations.append("Consider using slower rate to avoid blocking")
        
        elif blocking == BlockingBehavior.STATUS_429:
            recommendations.append("Rate limited - reduce concurrency")
            recommendations.append("Add delays between requests")
        
        elif blocking == BlockingBehavior.CAPTCHA:
            recommendations.append("CAPTCHA detected - manual verification may be required")
            recommendations.append("Consider reducing aggressive testing")
        
        if waf_type == WAFType.CLOUDFLARE:
            recommendations.append("Cloudflare detected - use longer delays between requests")
            recommendations.append("Try double URL encoding for payloads")
        
        elif waf_type == WAFType.IMPERVA:
            recommendations.append("Imperva/Incapsula detected - use different IP addresses")
            recommendations.append("Consider using proxy rotation")
        
        if not recommendations:
            recommendations.append("No WAF detected - standard testing can continue")
        
        return recommendations
    
    def should_adapt_strategy(self) -> bool:
        """Determine if strategy should be adapted."""
        return (
            self.config.auto_adapt and
            self._consecutive_blocks >= 2
        )
    
    def get_adaptive_encoding(self) -> str:
        """Get adaptive encoding strategy based on blocking history."""
        if self._consecutive_blocks >= 3:
            return "double_url"
        elif self._consecutive_blocks >= 1:
            return "url"
        return "standard"
    
    def reset(self) -> None:
        """Reset WAF detection state."""
        self._detected_wafs.clear()
        self._blocking_history.clear()
        self._consecutive_blocks = 0
        self._current_strategy = "standard"


class WAFAdapter:
    """Adapter that adjusts testing based on WAF detection."""
    
    def __init__(self, detector: WAFDetector):
        self._detector = detector
        self._current_delay = 0.5
        self._encoding_strategy = "none"
    
    def on_block(self, blocking: BlockingBehavior) -> Dict[str, Any]:
        """Handle blocking detection."""
        
        actions = {
            BlockingBehavior.STATUS_403: {
                'increase_delay': True,
                'change_encoding': True,
                'reduce_concurrency': False,
            },
            BlockingBehavior.STATUS_429: {
                'increase_delay': True,
                'change_encoding': False,
                'reduce_concurrency': True,
            },
            BlockingBehavior.CAPTCHA: {
                'increase_delay': True,
                'change_encoding': False,
                'reduce_concurrency': True,
                'stop_testing': True,
            },
            BlockingBehavior.IP_BLOCK: {
                'increase_delay': True,
                'change_encoding': True,
                'reduce_concurrency': True,
                'change_proxy': True,
            },
        }
        
        action = actions.get(blocking, {})
        
        if action.get('increase_delay'):
            self._current_delay = min(self._current_delay * 2, 10.0)
        
        if action.get('change_encoding'):
            encodings = ['url', 'double_url', 'unicode', 'base64']
            try:
                idx = encodings.index(self._encoding_strategy)
                self._encoding_strategy = encodings[(idx + 1) % len(encodings)]
            except ValueError:
                self._encoding_strategy = 'url'
        
        return {
            'delay': self._current_delay,
            'encoding': self._encoding_strategy,
            'stop': action.get('stop_testing', False),
        }
    
    def get_delay(self) -> float:
        """Get current delay between requests."""
        return self._current_delay
    
    def get_encoding(self) -> str:
        """Get current encoding strategy."""
        return self._encoding_strategy
    
    def reset(self) -> None:
        """Reset adapter state."""
        self._current_delay = 0.5
        self._encoding_strategy = "none"
        self._detector.reset()