"""
SQL Injection Assessment Framework
==================================

A production-grade, modular framework for authorized security testing.
Detection and analysis only - NO exploitation capabilities.

Legal Notice: This tool is provided for authorized security testing only.
Unauthorized scanning of systems you do not own or have permission to test
is illegal and strictly prohibited. By using this tool, you agree to use it
only in compliance with all applicable laws and with proper authorization.
"""

import sys
import asyncio
import warnings
from typing import Optional

from .cli import create_parser, display_banner, parse_cookies, parse_headers, parse_auth
from .engine import AssessmentEngine
from .reporting import ReportGenerator
from .utils import validate_target, check_whitelist, SafetyControls


__version__ = "2.0.0"
__author__ = "Security Assessment Framework"


def main() -> int:
    """Main entry point for the SQL Injection Assessment Framework."""
    
    parser = create_parser()
    args = parser.parse_args()
    
    if args.version:
        print(f"SQL Injection Assessment Framework v{__version__}")
        return 0
    
    if args.banner:
        display_banner()
        return 0
    
    if not args.target:
        parser.print_help()
        return 1
    
    display_banner()
    
    print("\n[!] LEGAL WARNING: This tool is for authorized security testing only.")
    print("[!] Unauthorized use is illegal and strictly prohibited.")
    print("[!] By proceeding, you confirm you have explicit permission to test the target.\n")
    
    if not SafetyControls.confirm_target(args.target):
        print("\n[-] Scan aborted. Target confirmation required.")
        return 1
    
    if args.skip_whitelist:
        pass
    elif not check_whitelist(args.target, args.whitelist):
        print("\n[-] Target not in whitelist. Add to whitelist or use --skip-whitelist")
        return 1
    
    if not validate_target(args.target):
        print("\n[-] Invalid target URL. Please provide a valid HTTP/HTTPS URL.")
        return 1
    
    try:
        cookies = parse_cookies(args.cookies) if args.cookies else None
        headers = parse_headers(args.headers) if args.headers else None
        auth = parse_auth(args.auth) if args.auth else None
        
        custom_payloads = None
        if args.payloads:
            try:
                with open(args.payloads, 'r') as f:
                    custom_payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                print(f"[+] Loaded {len(custom_payloads)} custom payloads from {args.payloads}")
            except Exception as e:
                print(f"[!] Warning: Could not load payloads file: {e}")
        
        max_payloads = args.max_payloads
        delay_between_tests = args.delay
        
        if args.quick:
            max_payloads = min(30, args.max_payloads)
            delay_between_tests = 0.05
            print("[+] Quick scan mode enabled (reduced payloads and delays)")
        
        engine = AssessmentEngine(
            target=args.target,
            depth=args.depth,
            concurrency=args.concurrency,
            timeout=args.timeout,
            proxy=args.proxy,
            cookies=cookies,
            headers=headers,
            auth=auth,
            verbosity=args.verbose,
            output=args.output,
            save_session=args.save_session,
            load_session=args.load_session,
            custom_payloads=custom_payloads,
            max_payloads=max_payloads,
            delay_between_tests=delay_between_tests,
            follow_redirects=not args.no_follow_redirects,
            verify_ssl=not args.no_verify_ssl,
        )
        
        results = asyncio.run(engine.run())
        
        if results and args.output:
            try:
                from .reporting import ReportGenerator
                report_gen = ReportGenerator(
                    results=results,
                    output_format=args.format,
                    output_file=args.output,
                )
                report_gen.generate()
                print(f"\n[+] Scan complete. Results saved to: {args.output}")
            except Exception as e:
                print(f"\n[!] Report generation error: {e}")
                print(f"[!] Results found but HTML output failed. Try with --format json")
            return 0
        elif results:
            summary = engine.get_summary()
            by_severity = summary['by_severity']
            total = results.total_vulnerabilities
            
            C_RED = '\033[91m'
            C_YELLOW = '\033[93m'
            C_GREEN = '\033[92m'
            C_RESET = '\033[0m'
            C_BOLD = '\033[1m'
            
            print(f"\n{'='*70}")
            print(f"{C_BOLD}SCAN RESULT:{C_RESET} Found {total} SQL injection vulnerabilities")
            print(f"{'='*70}")
            print(f"\n    Severity Breakdown:")
            print(f"    - {C_RED}Critical: {by_severity['critical']}{C_RESET}")
            print(f"    - {C_RED}High:     {by_severity['high']}{C_RESET}")
            print(f"    - {C_YELLOW}Medium:   {by_severity['medium']}{C_RESET}")
            print(f"    - {C_GREEN}Low:      {by_severity['low']}{C_RESET}")
            
            if results.vulnerabilities_found:
                print(f"\n    Detailed Findings:")
                for v in results.vulnerabilities_found:
                    sev_color = {'critical': C_RED, 'high': C_RED, 'medium': C_YELLOW, 'low': C_GREEN}.get(v.severity, '')
                    print(f"    [{sev_color}{v.severity.upper():8}{C_RESET}] {v.parameter} @ {v.endpoint}")
                    print(f"              Type: {v.injection_type}")
                    print(f"              Payload: {v.payload}")
                    print(f"              Confidence: {v.confidence:.0%}")
            print(f"{'='*70}")
            return 0
        else:
            print("\n[*] No vulnerabilities detected.")
            return 0
            
    except KeyboardInterrupt:
        print("\n\n[-] Scan interrupted by user.")
        return 130
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())