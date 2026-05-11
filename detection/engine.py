"""
Detection Engine Module
========================

Provides detection capabilities:
- Baseline response establishment
- Response comparison (length, status, content)
- SQL error pattern recognition
- Time-delay inference detection
- Heuristic scoring system with confidence levels
"""

import re
import time
import asyncio
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from difflib import SequenceMatcher
import hashlib

from ..engine import AsyncHTTPEngine, HTTPResponse
from ..utils import setup_logging


logger = setup_logging()


class ConfidenceLevel(Enum):
    """Confidence levels for vulnerability detection."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class InjectionType(Enum):
    """Types of SQL injection detected."""
    BOOLEAN_BASED = "boolean_based"
    ERROR_BASED = "error_based"
    TIME_BASED = "time_based"
    UNION_BASED = "union_based"
    STACKED_QUERY = "stacked_query"
    BLIND = "blind"
    GRAPHQL = "graphql"
    JSON_API = "json_api"
    NOSQL = "nosql"
    HEADER_INJECTION = "header_injection"
    COOKIE_INJECTION = "cookie_injection"
    UNKNOWN = "unknown"


SQL_ERROR_PATTERNS = {
    'mysql': [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"MySQLClient.",
        r"You have an error in your SQL syntax",
        r"mysql_fetch",
        r"SQLSTATE\[HY000\]",
        r"Column .* doesn't exist",
        r"Table .* doesn't exist",
        r"Unknown column",
        r"Duplicate entry",
    ],
    'postgresql': [
        r"PostgreSQL.*ERROR",
        r"Warning.*PostgreSQL",
        r"valid PostgreSQL result",
        r"psql.*ERROR",
        r"PG::.*Error",
        r"org\.postgresql\.util",
        r"relation .* does not exist",
        r"column .* does not exist",
    ],
    'mssql': [
        r"SQL Server.*ERROR",
        r"Unclosed quotation mark",
        r"Microsoft SQL Native Error",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"System\.Data\.SqlClient",
        r"Invalid column name",
        r"Invalid object name",
    ],
    'oracle': [
        r"ORA-\d{5}",
        r"Oracle error",
        r"PL/SQL.*ORA-",
        r"SQL.*ORA-",
        r"oracle\.jdbc",
        r"ORA-00942",
        r"ORA-01756",
    ],
    'sqlite': [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"database locked",
        r"sqlite3\.OperationalError",
        r"no such table",
        r"no such column",
    ],
    'mongodb': [
        r"BSON field .* had an invalid value",
        r"Failed to parse",
        r"SyntaxError.*unexpected",
        r"mongodb.*error",
        r"MongoDB.*Exception",
        r"errmsg",
        r"code.*\d+",
    ],
    'modern_framework': [
        r"SQLSTATE\[\d+\]",
        r"Invalid parameter",
        r"Parameter index out of range",
        r"preg_match\(\)",
        r"Undefined array key",
        r"Undefined variable.*sql",
        r"500 Internal Server Error",
        r"Syntax error.*JSON",
    ],
    'generic': [
        r"SQL syntax.*error",
        r"mysql_fetch_array\(\)",
        r"Error.*SQL",
        r"\\bODBC\\b",
        r"SQLSTATE\\[\\w+\\]",
        r"quoted string not properly terminated",
        r"unclosed quotation mark",
        r"near\\s+[\"'].*[\"']:\\s*syntax error",
    ],
}

DIFFERENCE_THRESHOLDS = {
    'status_code': 0,
    'content_length_percent': 0.5,
    'content_similarity': 0.95,
    'time_delay_ms': 1000,
    'min_payload_tests': 1,
}


@dataclass
class BaselineResponse:
    """Baseline response for comparison."""
    url: str
    method: str
    status_code: int
    content_length: int
    content_hash: str
    content_text: str
    headers: Dict[str, str]
    elapsed_ms: float


@dataclass
class DetectionResult:
    """Result of a detection test."""
    endpoint: str
    parameter: str
    method: str
    payload: str
    injection_type: InjectionType
    is_vulnerable: bool
    confidence: float
    evidence: Dict[str, Any] = field(default_factory=dict)
    baseline: Optional[BaselineResponse] = None
    response: Optional[HTTPResponse] = None
    
    def __post_init__(self):
        if isinstance(self.injection_type, str):
            try:
                self.injection_type = InjectionType(self.injection_type)
            except ValueError:
                self.injection_type = InjectionType.UNKNOWN


class DetectionEngine:
    """Engine for detecting SQL injection vulnerabilities."""
    
    def __init__(self, verbosity: int = 0):
        self.verbosity = verbosity
        self._baselines: Dict[str, BaselineResponse] = {}
        self._error_patterns = self._compile_error_patterns()
    
    def _compile_error_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns for SQL error detection."""
        compiled = {}
        for db_type, patterns in SQL_ERROR_PATTERNS.items():
            compiled[db_type] = [re.compile(p, re.IGNORECASE) for p in patterns]
        return compiled
    
    async def establish_baseline(
        self,
        http_engine: AsyncHTTPEngine,
        url: str,
        method: str,
        parameters: List[Any]
    ) -> Optional[BaselineResponse]:
        """Establish baseline response for comparison."""
        try:
            if method.upper() == 'GET':
                response = await http_engine.get(url)
            else:
                response = await http_engine.post(url)
            
            baseline = BaselineResponse(
                url=url,
                method=method,
                status_code=response.status_code,
                content_length=response.content_length,
                content_hash=hashlib.md5(response.text.encode()).hexdigest(),
                content_text=response.text,
                headers=response.headers,
                elapsed_ms=response.elapsed_ms,
            )
            
            self._baselines[url] = baseline
            return baseline
            
        except Exception as e:
            logger.debug(f"Failed to establish baseline for {url}: {e}")
            return None
    
    async def test_parameter(
        self,
        http_engine: AsyncHTTPEngine,
        endpoint: str,
        method: str,
        parameter: str,
        payload: str,
        baseline: Optional[BaselineResponse] = None
    ) -> DetectionResult:
        """Test a parameter for SQL injection."""
        
        baseline = baseline or self._baselines.get(endpoint)
        
        try:
            start_time = time.time()
            
            if method.upper() == 'GET':
                params = {parameter: payload}
                response = await http_engine.get(endpoint, params=params)
            else:
                data = {parameter: payload}
                response = await http_engine.post(endpoint, data=data, follow_redirects=False)
            
            elapsed_ms = (time.time() - start_time) * 1000
            
            is_vulnerable, confidence, injection_type, evidence = self._analyze_response(
                baseline=baseline,
                response=response,
                elapsed_ms=elapsed_ms,
                payload=payload,
            )
            
            return DetectionResult(
                endpoint=endpoint,
                parameter=parameter,
                method=method,
                payload=payload,
                injection_type=injection_type,
                is_vulnerable=is_vulnerable,
                confidence=confidence,
                evidence=evidence,
                baseline=baseline,
                response=response,
            )
            
        except Exception as e:
            logger.debug(f"Test failed for {parameter}: {e}")
            return DetectionResult(
                endpoint=endpoint,
                parameter=parameter,
                method=method,
                payload=payload,
                injection_type=InjectionType.UNKNOWN,
                is_vulnerable=False,
                confidence=0.0,
                evidence={'error': str(e)},
            )
    
    def _analyze_response(
        self,
        baseline: Optional[BaselineResponse],
        response: HTTPResponse,
        elapsed_ms: float,
        payload: str
    ) -> Tuple[bool, float, InjectionType, Dict[str, Any]]:
        """Analyze response for signs of SQL injection."""
        
        evidence = {
            'status_code': response.status_code,
            'content_length': response.content_length,
            'elapsed_ms': elapsed_ms,
            'payload': payload,
        }
        
        if baseline:
            evidence['baseline_status'] = baseline.status_code
            evidence['baseline_length'] = baseline.content_length
            evidence['baseline_elapsed'] = baseline.elapsed_ms
        
        error_type, error_evidence = self._detect_sql_errors(response.text)
        if error_type or (response.status_code >= 500):
            if response.status_code >= 500:
                error_evidence = error_evidence or {}
                error_evidence['status_code'] = response.status_code
            evidence['sql_error'] = error_evidence
            return True, 0.95, InjectionType.ERROR_BASED, evidence
        
        time_type, time_evidence = self._detect_time_based(elapsed_ms, baseline)
        if time_type:
            evidence['time_delay'] = time_evidence
            return True, 0.9, InjectionType.TIME_BASED, evidence
        
        if baseline:
            boolean_type, boolean_evidence = self._detect_boolean_based(
                baseline, response
            )
            if boolean_type:
                evidence['boolean_diff'] = boolean_evidence
                confidence = 0.7 if boolean_evidence.get('high_confidence') else 0.5
                return True, confidence, InjectionType.BOOLEAN_BASED, evidence
        
        union_type, union_evidence = self._detect_union_based(response, baseline)
        if union_type:
            evidence['union_detected'] = union_evidence
            return True, 0.75, InjectionType.UNION_BASED, evidence
        
        return False, 0.0, InjectionType.UNKNOWN, evidence
    
    def _detect_sql_errors(self, content: str) -> Tuple[Optional[str], Dict[str, Any]]:
        """Detect SQL error patterns in response with strict matching."""
        # Skip JSON/API responses that echo input (common false positives)
        if '"args"' in content or 'httpbin.org' in content:
            return None, {}
            
        for db_type, patterns in self._error_patterns.items():
            for pattern in patterns:
                match = pattern.search(content)
                if match:
                    return db_type, {'matched_pattern': pattern.pattern, 'database': db_type}
        return None, {}
    
    def _detect_time_based(
        self,
        elapsed_ms: float,
        baseline: Optional[BaselineResponse]
    ) -> Tuple[bool, Dict[str, Any]]:
        """Detect time-based blind SQL injection with adaptive thresholds for modern websites."""
        threshold = DIFFERENCE_THRESHOLDS['time_delay_ms']
        
        if elapsed_ms >= threshold:
            if baseline:
                delay_diff = elapsed_ms - baseline.elapsed_ms
                if delay_diff >= 1500 or elapsed_ms >= 3000:
                    return True, {
                        'delay_detected': True,
                        'elapsed_ms': elapsed_ms,
                        'baseline_ms': baseline.elapsed_ms,
                        'difference_ms': delay_diff,
                    }
            else:
                if elapsed_ms >= 3000:
                    return True, {
                        'delay_detected': True,
                        'elapsed_ms': elapsed_ms,
                    }
        
        return False, {}
    
    def _detect_boolean_based(
        self,
        baseline: BaselineResponse,
        response: HTTPResponse
    ) -> Tuple[bool, Dict[str, Any]]:
        """Detect boolean-based SQL injection with improved accuracy for modern websites."""
        
        if '"args"' in response.text or 'httpbin.org' in response.text:
            return False, {}
        
        if response.status_code == 403 or response.status_code == 429:
            return False, {}
        
        status_changed = response.status_code != baseline.status_code
        
        length_diff = abs(response.content_length - baseline.content_length)
        length_diff_percent = (length_diff / max(baseline.content_length, 1)) * 100
        content_changed = length_diff_percent > DIFFERENCE_THRESHOLDS['content_length_percent']
        
        similarity = SequenceMatcher(None, baseline.content_text, response.text).ratio()
        content_differed = similarity < DIFFERENCE_THRESHOLDS['content_similarity']
        
        indicators_count = sum([status_changed, content_changed, content_differed])
        
        if status_changed and response.status_code >= 400:
            return True, {'high_confidence': True, 'reason': 'error_status', 'status': response.status_code, 'sim': similarity}
        
        if status_changed and baseline.status_code >= 400:
            return True, {'high_confidence': True, 'reason': 'status_became_200', 'sim': similarity}
        
        if content_changed and content_differed and length_diff > 50:
            return True, {
                'high_confidence': True,
                'reason': 'content_differ_substantial',
                'similarity': similarity,
                'length_diff': length_diff,
            }
        
        if indicators_count >= 2 and similarity < 0.80:
            return True, {
                'high_confidence': True,
                'reason': 'multiple_indicators',
                'similarity': similarity,
                'length_diff': length_diff,
            }
        
        if status_changed and (response.status_code == 500 or response.status_code == 200):
            if similarity < 0.92:
                return True, {
                    'high_confidence': True,
                    'reason': 'status_change_content_diff',
                    'status': response.status_code,
                    'similarity': similarity,
                }
        
        if content_changed and length_diff > 100:
            return True, {
                'high_confidence': True,
                'reason': 'substantial_length_change',
                'length_diff': length_diff,
            }
        
        if indicators_count == 1 and content_changed and similarity < 0.70:
            return True, {
                'high_confidence': False,
                'reason': 'single_indicator_weak',
                'similarity': similarity,
            }
        
        if content_changed or content_differed:
            return True, {
                'high_confidence': False,
                'reason': 'content_changed',
                'similarity': similarity,
                'length_diff': length_diff,
            }
        
        if similarity < 0.90 and length_diff > 10:
            return True, {
                'high_confidence': False,
                'reason': 'minor_change',
                'similarity': similarity,
                'length_diff': length_diff,
            }
        
        return False, {}
    
    def _detect_union_based(
        self,
        response: HTTPResponse,
        baseline: Optional[BaselineResponse]
    ) -> Tuple[bool, Dict[str, Any]]:
        """Detect UNION-based SQL injection."""
        
        # Skip API echo responses
        if response.text and ('"args"' in response.text or 'httpbin.org' in response.text):
            return False, {}
        
        union_keywords = re.findall(r'(union|select|from|where|order by)', response.text, re.IGNORECASE)
        
        if len(union_keywords) >= 2:
            if baseline:
                if response.content_length != baseline.content_length:
                    return True, {
                        'union_keywords_found': len(union_keywords),
                        'content_length_diff': response.content_length - baseline.content_length,
                    }
            else:
                return True, {
                    'union_keywords_found': len(union_keywords),
                }
        
        return False, {}
    
    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """Calculate overall confidence score from evidence."""
        score = 0.0
        
        if evidence.get('sql_error'):
            score += 0.4
        
        if evidence.get('time_delay', {}).get('delay_detected'):
            score += 0.35
        
        if evidence.get('boolean_diff', {}).get('high_confidence'):
            score += 0.35
        elif evidence.get('boolean_diff', {}).get('reason'):
            score += 0.2
        
        if evidence.get('union_detected'):
            score += 0.3
        
        return min(score, 1.0)
    
    def detect_database_type(self, response: HTTPResponse) -> str:
        """Detect database type from response patterns."""
        content = response.text.lower()
        
        db_indicators = {
            'mysql': ['mysql', 'mysqli', 'sql_syntax', '1064', '1064 you'],
            'postgresql': ['postgresql', 'pg_', 'psql', 'ora-'],
            'mssql': ['sql server', 'odbc', 'mssql', 'unclosed quotation'],
            'oracle': ['ora-', 'pl/sql', 'oracle'],
            'sqlite': ['sqlite', 'sqlite3'],
        }
        
        scores = {}
        for db, keywords in db_indicators.items():
            scores[db] = sum(1 for kw in keywords if kw in content)
        
        if scores:
            return max(scores, key=scores.get)
        return 'unknown'
    
    def behavioral_analysis(
        self,
        baseline: BaselineResponse,
        responses: List[HTTPResponse]
    ) -> Dict[str, Any]:
        """Perform behavioral analysis on responses."""
        anomalies = []
        
        for i, resp in enumerate(responses):
            # Check for unusual response time
            if baseline:
                time_diff = abs(resp.elapsed_ms - baseline.elapsed_ms)
                if time_diff > 1000:  # More than 1s difference
                    anomalies.append({
                        'type': 'time_anomaly',
                        'index': i,
                        'difference_ms': time_diff
                    })
            
            # Check for unusual content length changes
            if baseline:
                len_diff = abs(resp.content_length - baseline.content_length)
                if len_diff > baseline.content_length * 0.5:
                    anomalies.append({
                        'type': 'length_anomaly',
                        'index': i,
                        'difference': len_diff
                    })
        
        return {'anomalies': anomalies, 'count': len(anomalies)}


class DifferentialFuzzer:
    """Differential fuzzing engine for advanced detection."""
    
    def __init__(self, detection_engine: DetectionEngine):
        self._detection = detection_engine
    
    async def fuzz_parameter(
        self,
        http_engine: AsyncHTTPEngine,
        endpoint: str,
        method: str,
        parameter: str,
        payloads: List[str],
        baseline: Optional[BaselineResponse]
    ) -> List[DetectionResult]:
        """Fuzz a parameter with multiple payloads."""
        
        results = []
        responses = []
        
        if baseline:
            responses.append(('baseline', baseline.content_text))
        
        for payload in payloads:
            try:
                if method.upper() == 'GET':
                    response = await http_engine.get(endpoint, params={parameter: payload})
                else:
                    response = await http_engine.post(endpoint, data={parameter: payload})
                
                responses.append((payload, response.text))
                
                result = await self._detection.test_parameter(
                    http_engine, endpoint, method, parameter, payload, baseline
                )
                results.append(result)
                
            except Exception as e:
                logger.debug(f"Fuzz failed for payload {payload}: {e}")
        
        differential_results = self._analyze_differences(responses)
        
        for result in results:
            if result.is_vulnerable:
                result.evidence['differential_analysis'] = differential_results
        
        return results
    
    def _analyze_differences(self, responses: List[Tuple[str, str]]) -> Dict[str, Any]:
        """Analyze differences between responses."""
        if len(responses) < 2:
            return {}
        
        baseline_text = responses[0][1]
        differences = []
        
        for payload, response_text in responses[1:]:
            similarity = SequenceMatcher(None, baseline_text, response_text).ratio()
            differences.append({
                'payload': payload,
                'similarity': similarity,
                'diff_ratio': 1 - similarity,
            })
        
        return {
            'total_responses': len(responses),
            'differences': differences,
            'avg_similarity': sum(d['similarity'] for d in differences) / len(differences) if differences else 1.0,
        }