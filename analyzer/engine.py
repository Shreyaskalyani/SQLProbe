"""
Analyzer Module
===============

Provides result correlation and analysis:
- Correlate findings across payloads
- Reduce false positives
- Assign severity levels
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime

from ..detection import DetectionResult, InjectionType
from ..utils import setup_logging


logger = setup_logging()


@dataclass
class AnalyzedFinding:
    """An analyzed vulnerability finding with reduced false positives."""
    endpoint: str
    parameter: str
    method: str
    injection_type: InjectionType
    payload: str
    confidence: float
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    related_payloads: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


class ResultAnalyzer:
    """Analyzes and correlates detection results."""
    
    def __init__(self, min_confidence_threshold: float = 0.3):
        self.min_confidence_threshold = min_confidence_threshold
        self._correlation_cache: Dict[str, List[DetectionResult]] = {}
    
    def correlate_results(
        self,
        results: List[DetectionResult]
    ) -> List[DetectionResult]:
        """Correlate results - show all unique vulnerabilities per parameter and type."""
        
        unique_results = {}
        
        for result in results:
            if not result.is_vulnerable:
                continue
            
            key = f"{result.endpoint}:{result.parameter}:{result.injection_type.value}"
            
            if key not in unique_results:
                unique_results[key] = result
            elif result.confidence > unique_results[key].confidence:
                unique_results[key] = result
        
        return list(unique_results.values())
    
    def _group_by_endpoint_parameter(
        self,
        results: List[DetectionResult]
    ) -> Dict[str, List[DetectionResult]]:
        """Group results by endpoint and parameter."""
        grouped = defaultdict(list)
        
        for result in results:
            key = f"{result.endpoint}:{result.parameter}"
            grouped[key].append(result)
        
        return grouped
    
    def assign_severity(self, confidence: float) -> str:
        """Assign severity based on confidence score."""
        if confidence >= 0.9:
            return "critical"
        elif confidence >= 0.75:
            return "high"
        elif confidence >= 0.5:
            return "medium"
        elif confidence >= 0.25:
            return "low"
        else:
            return "info"
    
    def filter_false_positives(
        self,
        results: List[DetectionResult]
    ) -> List[DetectionResult]:
        """Filter out likely false positives."""
        filtered = []
        
        for result in results:
            if self._is_likely_false_positive(result):
                logger.debug(f"Filtered false positive: {result.parameter} at {result.endpoint}")
                continue
            
            filtered.append(result)
        
        return filtered
    
    def _is_likely_false_positive(self, result: DetectionResult) -> bool:
        """Determine if a result is likely a false positive."""
        
        if result.confidence < self.min_confidence_threshold:
            return True
        
        evidence = result.evidence or {}
        
        if not evidence:
            return True
        
        if result.is_vulnerable and result.injection_type == InjectionType.UNKNOWN:
            if result.confidence < 0.7:
                return True
        
        time_delay = evidence.get('time_delay', {})
        if time_delay.get('delay_detected'):
            delay_ms = time_delay.get('elapsed_ms', 0)
            if delay_ms < 1500:
                return True
        
        boolean_diff = evidence.get('boolean_diff', {})
        if boolean_diff and not boolean_diff.get('high_confidence'):
            if result.confidence < 0.6:
                return True
        
        return False
    
    def analyze_trends(
        self,
        results: List[DetectionResult]
    ) -> Dict[str, Any]:
        """Analyze trends in detection results."""
        
        by_type = defaultdict(int)
        by_endpoint = defaultdict(int)
        by_parameter_type = defaultdict(int)
        
        confidence_scores = []
        
        for result in results:
            by_type[result.injection_type.value] += 1
            
            endpoint = result.endpoint
            by_endpoint[endpoint] += 1
            
            param = result.parameter
            if any(c.isdigit() for c in param):
                by_parameter_type['numeric'] += 1
            else:
                by_parameter_type['string'] += 1
            
            confidence_scores.append(result.confidence)
        
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        return {
            'total_findings': len(results),
            'by_injection_type': dict(by_type),
            'by_endpoint': dict(by_endpoint),
            'by_parameter_type': dict(by_parameter_type),
            'average_confidence': avg_confidence,
            'high_confidence_count': len([c for c in confidence_scores if c >= 0.75]),
        }


class SeverityCalculator:
    """Calculates severity based on multiple factors."""
    
    def __init__(self):
        self.weights = {
            'confidence': 0.4,
            'injection_type': 0.3,
            'impact': 0.3,
        }
        
        self.type_severity = {
            InjectionType.UNION_BASED: 1.0,
            InjectionType.STACKED_QUERY: 1.0,
            InjectionType.ERROR_BASED: 0.8,
            InjectionType.TIME_BASED: 0.7,
            InjectionType.BOOLEAN_BASED: 0.6,
            InjectionType.BLIND: 0.6,
            InjectionType.UNKNOWN: 0.3,
        }
        
        self.impact_factors = {
            'data_exposure': 1.0,
            'authentication_bypass': 1.0,
            'privilege_escalation': 0.9,
            'denial_of_service': 0.7,
            'information_disclosure': 0.5,
        }
    
    def calculate(
        self,
        confidence: float,
        injection_type: InjectionType,
        evidence: Dict[str, Any]
    ) -> str:
        """Calculate overall severity."""
        
        confidence_score = confidence
        
        type_score = self.type_severity.get(injection_type, 0.3)
        
        impact_score = self._calculate_impact(evidence)
        
        weighted = (
            confidence_score * self.weights['confidence'] +
            type_score * self.weights['injection_type'] +
            impact_score * self.weights['impact']
        )
        
        if weighted >= 0.85:
            return "critical"
        elif weighted >= 0.7:
            return "high"
        elif weighted >= 0.5:
            return "medium"
        elif weighted >= 0.3:
            return "low"
        else:
            return "info"
    
    def _calculate_impact(self, evidence: Dict[str, Any]) -> float:
        """Calculate impact score from evidence."""
        if not evidence:
            return 0.3
        
        score = 0.3
        
        if evidence.get('sql_error'):
            score += 0.2
        
        if evidence.get('union_detected'):
            score += 0.3
        
        if evidence.get('stacked_query'):
            score += 0.4
        
        if evidence.get('time_delay', {}).get('delay_detected'):
            score += 0.1
        
        return min(score, 1.0)