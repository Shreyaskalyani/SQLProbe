"""
Reporting Module
================

Provides reporting capabilities:
- JSON report generation
- HTML report generation
- Save and load scan sessions
"""

import json
import html
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

from ..engine import AssessmentResult, VulnerabilityFinding
from ..utils import setup_logging


logger = setup_logging()


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    output_format: str = "json"
    output_file: Optional[str] = None
    include_evidence: bool = True
    include_metadata: bool = True
    template: Optional[str] = None


class ReportGenerator:
    """Generates reports in various formats."""
    
    def __init__(
        self,
        results: AssessmentResult,
        output_format: str = "json",
        output_file: Optional[str] = None,
        include_evidence: bool = True
    ):
        self.results = results
        self.output_format = output_format
        self.output_file = output_file
        self.include_evidence = include_evidence
    
    def generate(self) -> str:
        """Generate report in specified format."""
        
        if self.output_format == "json":
            return self._generate_json()
        elif self.output_format == "html":
            return self._generate_html()
        elif self.output_format == "both":
            json_result = self._generate_json()
            html_result = self._generate_html()
            return json_result
    
    def _serialize_evidence(self, evidence: dict) -> dict:
        """Serialize evidence dict, converting non-serializable objects."""
        result = {}
        for key, value in evidence.items():
            if hasattr(value, 'value'):
                result[key] = value.value
            elif isinstance(value, (dict, list)):
                result[key] = self._serialize_evidence(value) if isinstance(value, dict) else [
                    self._serialize_evidence(v) if isinstance(v, dict) else v for v in value
                ]
            else:
                result[key] = value
        return result
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for non-serializable objects."""
        if hasattr(obj, 'value'):
            return obj.value
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
    
    def _generate_json(self) -> str:
        """Generate JSON report."""
        
        report = {
            "scan_info": {
                "target": self.results.target,
                "scan_start": self.results.scan_start.isoformat(),
                "scan_end": self.results.scan_end.isoformat() if self.results.scan_end else None,
                "duration_seconds": self.results.duration_seconds,
            },
            "summary": {
                "endpoints_tested": self.results.endpoints_tested,
                "parameters_tested": self.results.parameters_tested,
                "vulnerabilities_found": self.results.total_vulnerabilities,
                "errors": len(self.results.errors),
                "vulnerable_urls": list(set(v.endpoint for v in self.results.vulnerabilities_found)),
            },
            "vulnerabilities": [],
            "metadata": self.results.metadata,
        }
        
        for vuln in self.results.vulnerabilities_found:
            vuln_data = {
                "endpoint": vuln.endpoint,
                "parameter": vuln.parameter,
                "method": vuln.method,
                "injection_type": vuln.injection_type.value if hasattr(vuln.injection_type, 'value') else str(vuln.injection_type),
                "payload": vuln.payload,
                "confidence": vuln.confidence,
                "severity": vuln.severity,
                "timestamp": vuln.timestamp.isoformat(),
            }
            
            if self.include_evidence:
                vuln_data["evidence"] = self._serialize_evidence(vuln.evidence)
            
            report["vulnerabilities"].append(vuln_data)
        
        json_str = json.dumps(report, indent=2, default=self._json_serializer)
        
        if self.output_file:
            output_path = Path(self.output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_str, encoding='utf-8')
            logger.info(f"JSON report saved to {self.output_file}")
        
        return json_str
    
    def _generate_html(self) -> str:
        """Generate HTML report."""
        
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Assessment Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { font-size: 2rem; margin-bottom: 10px; }
        .header .meta { opacity: 0.8; font-size: 0.9rem; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .summary-card .label { font-size: 0.85rem; color: #666; margin-bottom: 5px; }
        .summary-card .value { font-size: 2rem; font-weight: bold; color: #1a1a2e; }
        .summary-card.critical .value { color: #dc3545; }
        .summary-card.high .value { color: #fd7e14; }
        .summary-card.medium .value { color: #ffc107; }
        .summary-card.low .value { color: #28a745; }
        .section { background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .section h2 { font-size: 1.3rem; margin-bottom: 20px; color: #1a1a2e; border-bottom: 2px solid #f0f0f0; padding-bottom: 10px; }
        .vulnerability { border: 1px solid #e0e0e0; border-radius: 6px; padding: 20px; margin-bottom: 15px; }
        .vulnerability.critical { border-left: 4px solid #dc3545; }
        .vulnerability.high { border-left: 4px solid #fd7e14; }
        .vulnerability.medium { border-left: 4px solid #ffc107; }
        .vulnerability.low { border-left: 4px solid #28a745; }
        .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .vuln-title { font-weight: bold; font-size: 1.1rem; }
        .badge { padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: bold; }
        .badge.critical { background: #dc3545; color: white; }
        .badge.high { background: #fd7e14; color: white; }
        .badge.medium { background: #ffc107; color: #333; }
        .badge.low { background: #28a745; color: white; }
        .badge.confidence { background: #6c757d; color: white; }
        .vuln-details { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }
        .detail-item { }
        .detail-label { font-size: 0.8rem; color: #666; margin-bottom: 3px; }
        .detail-value { font-family: 'Courier New', monospace; background: #f8f9fa; padding: 8px; border-radius: 4px; word-break: break-all; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 0.85rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SQL Injection Assessment Report</h1>
            <div class="meta">
                Target: {target} | Scan Date: {scan_date}
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="label">Total Vulnerabilities</div>
                <div class="value">{total_vulns}</div>
            </div>
            <div class="summary-card critical">
                <div class="label">Critical</div>
                <div class="value">{critical_count}</div>
            </div>
            <div class="summary-card high">
                <div class="label">High</div>
                <div class="value">{high_count}</div>
            </div>
            <div class="summary-card medium">
                <div class="label">Medium</div>
                <div class="value">{medium_count}</div>
            </div>
            <div class="summary-card low">
                <div class="label">Low</div>
                <div class="value">{low_count}</div>
            </div>
            <div class="summary-card">
                <div class="label">Duration (seconds)</div>
                <div class="value">{duration}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Detailed Findings</h2>
            {vulnerabilities_html}
        </div>
        
        <div class="footer">
            Generated by SQL Injection Assessment Framework | {generation_date}
        </div>
    </div>
</body>
</html>"""
        
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
        }
        
        for vuln in self.results.vulnerabilities_found:
            severity_counts[vuln.severity] += 1
        
        vulns_html = ""
        for vuln in self.results.vulnerabilities_found:
            evidence_html = ""
            if self.include_evidence and vuln.evidence:
                for key, value in vuln.evidence.items():
                    evidence_html += f"""
                    <div class="detail-item">
                        <div class="detail-label">{html.escape(str(key))}</div>
                        <div class="detail-value">{html.escape(str(value))}</div>
                    </div>
                    """
            
            vulns_html += f"""
            <div class="vulnerability {vuln.severity}">
                <div class="vuln-header">
                    <span class="vuln-title">{html.escape(vuln.parameter)} @ {html.escape(vuln.endpoint)}</span>
                    <div>
                        <span class="badge confidence">{vuln.confidence:.0%} confidence</span>
                        <span class="badge {vuln.severity}">{vuln.severity.upper()}</span>
                    </div>
                </div>
                <div class="vuln-details">
                    <div class="detail-item">
                        <div class="detail-label">Method</div>
                        <div class="detail-value">{html.escape(vuln.method)}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Injection Type</div>
                        <div class="detail-value">{html.escape(str(vuln.injection_type.value) if hasattr(vuln.injection_type, 'value') else str(vuln.injection_type))}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Payload</div>
                        <div class="detail-value">{html.escape(vuln.payload[:200])}</div>
                    </div>
                    {evidence_html}
                </div>
            </div>
            """
        
        if not vulns_html:
            vulns_html = "<p>No vulnerabilities detected.</p>"
        
        scan_date = self.results.scan_start.strftime("%Y-%m-%d %H:%M:%S")
        generation_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html_content = html_template.format(
            target=html.escape(self.results.target),
            scan_date=scan_date,
            total_vulns=self.results.total_vulnerabilities,
            critical_count=severity_counts['critical'],
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
            duration=f"{self.results.duration_seconds:.2f}",
            vulnerabilities_html=vulns_html,
            generation_date=generation_date,
        )
        
        if self.output_file:
            output_path = Path(self.output_file).with_suffix('.html')
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(html_content, encoding='utf-8')
            logger.info(f"HTML report saved to {output_path}")
        
        return html_content


class SessionManager:
    """Manages saving and loading scan sessions."""
    
    @staticmethod
    def save_session(results: AssessmentResult, filepath: str) -> None:
        """Save scan session to file."""
        session_data = {
            'target': results.target,
            'scan_start': results.scan_start.isoformat(),
            'scan_end': results.scan_end.isoformat() if results.scan_end else None,
            'endpoints_tested': results.endpoints_tested,
            'parameters_tested': results.parameters_tested,
            'vulnerabilities': [
                {
                    'endpoint': v.endpoint,
                    'parameter': v.parameter,
                    'method': v.method,
                    'injection_type': v.injection_type,
                    'payload': v.payload,
                    'confidence': v.confidence,
                    'severity': v.severity,
                    'evidence': v.evidence,
                    'timestamp': v.timestamp.isoformat(),
                }
                for v in results.vulnerabilities_found
            ],
            'errors': results.errors,
            'metadata': results.metadata,
        }
        
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(session_data, f, indent=2)
        
        logger.info(f"Session saved to {filepath}")
    
    @staticmethod
    def load_session(filepath: str) -> Optional[AssessmentResult]:
        """Load scan session from file."""
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
            
            vulnerabilities = []
            for v in session_data.get('vulnerabilities', []):
                vulnerabilities.append(VulnerabilityFinding(
                    endpoint=v['endpoint'],
                    parameter=v['parameter'],
                    method=v['method'],
                    injection_type=v['injection_type'],
                    payload=v['payload'],
                    confidence=v['confidence'],
                    severity=v['severity'],
                    evidence=v.get('evidence', {}),
                    timestamp=datetime.fromisoformat(v['timestamp']),
                ))
            
            results = AssessmentResult(
                target=session_data['target'],
                scan_start=datetime.fromisoformat(session_data['scan_start']),
                scan_end=datetime.fromisoformat(session_data['scan_end']) if session_data.get('scan_end') else None,
                endpoints_tested=session_data.get('endpoints_tested', 0),
                parameters_tested=session_data.get('parameters_tested', 0),
                vulnerabilities_found=vulnerabilities,
                errors=session_data.get('errors', []),
                metadata=session_data.get('metadata', {}),
            )
            
            logger.info(f"Session loaded from {filepath}")
            return results
            
        except Exception as e:
            logger.error(f"Failed to load session: {e}")
            return None