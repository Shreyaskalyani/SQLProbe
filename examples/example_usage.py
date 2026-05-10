"""
Example Usage - SQL Injection Assessment Framework
====================================================

This file demonstrates how to use the framework programmatically.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlprobe.engine import AssessmentEngine
from sqlprobe.reporting import ReportGenerator, SessionManager
from sqlprobe.payloads import PayloadEngine, PayloadType


async def basic_scan():
    """Run a basic SQL injection scan."""
    
    print("=" * 60)
    print("Running Basic SQL Injection Scan")
    print("=" * 60)
    
    engine = AssessmentEngine(
        target="http://example.com/page.php?id=1",
        depth=2,
        concurrency=10,
        timeout=30.0,
        verbosity=1,
    )
    
    results = await engine.run()
    
    summary = engine.get_summary()
    print(f"\nScan Results:")
    print(f"  Target: {summary['target']}")
    print(f"  Endpoints Tested: {summary['endpoints_tested']}")
    print(f"  Parameters Tested: {summary['parameters_tested']}")
    print(f"  Vulnerabilities Found: {summary['vulnerabilities']}")
    print(f"  Duration: {summary['duration']:.2f} seconds")
    
    return results


async def scan_with_proxy():
    """Run scan with proxy (e.g., for Burp Suite)."""
    
    print("\n" + "=" * 60)
    print("Running Scan with Proxy")
    print("=" * 60)
    
    engine = AssessmentEngine(
        target="http://example.com",
        proxy="http://localhost:8080",
        depth=2,
        concurrency=5,
    )
    
    results = await engine.run()
    
    return results


async def custom_payloads():
    """Demonstrate custom payload usage."""
    
    print("\n" + "=" * 60)
    print("Custom Payload Usage")
    print("=" * 60)
    
    from sqlprobe.payloads import Payload, PayloadType
    
    payload_engine = PayloadEngine(max_payloads=50)
    
    custom_payload = Payload(
        value="' AND (SELECT COUNT(*) FROM users) > 0--",
        payload_type=PayloadType.BLIND,
        category="custom_blind",
        description="Custom blind SQL injection",
        expected_behavior="Response differs based on user count",
    )
    
    payload_engine.add_custom_payload(custom_payload)
    
    all_payloads = payload_engine.get_all_payloads()
    print(f"Total payloads: {len(all_payloads)}")
    
    boolean_payloads = payload_engine.get_payloads_by_type(PayloadType.BOOLEAN_BASED)
    print(f"Boolean-based payloads: {len(boolean_payloads)}")
    
    mutated = payload_engine.generate_mutated_payloads(
        all_payloads[0],
        mutation_types=['case_random', 'inline_comment'],
    )
    print(f"Generated mutated variants: {len(mutated)}")


async def generate_report(results):
    """Generate report from scan results."""
    
    print("\n" + "=" * 60)
    print("Generating Reports")
    print("=" * 60)
    
    report_gen = ReportGenerator(
        results=results,
        output_format="json",
        output_file="scan_results.json",
    )
    json_report = report_gen.generate()
    print("JSON report generated: scan_results.json")
    
    report_gen_html = ReportGenerator(
        results=results,
        output_format="html",
        output_file="scan_results.html",
    )
    html_report = report_gen_html.generate()
    print("HTML report generated: scan_results.html")
    
    SessionManager.save_session(results, "scan_session.json")
    print("Session saved: scan_session.json")


async def load_and_analyze():
    """Load a previous scan session and analyze."""
    
    print("\n" + "=" * 60)
    print("Loading Previous Session")
    print("=" * 60)
    
    results = SessionManager.load_session("scan_session.json")
    
    if results:
        print(f"Loaded session for: {results.target}")
        print(f"Total vulnerabilities: {results.total_vulnerabilities}")
        
        for vuln in results.vulnerabilities_found:
            print(f"\n  [{vuln.severity.upper()}] {vuln.parameter}")
            print(f"    Endpoint: {vuln.endpoint}")
            print(f"    Type: {vuln.injection_type}")
            print(f"    Confidence: {vuln.confidence:.0%}")
    else:
        print("Failed to load session")


def main():
    """Main entry point for examples."""
    
    print("\nSQL Injection Assessment Framework - Examples\n")
    
    try:
        asyncio.run(basic_scan())
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
    
    try:
        asyncio.run(custom_payloads())
    except Exception as e:
        print(f"Error in custom payloads: {e}")


if __name__ == "__main__":
    main()