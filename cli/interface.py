"""
CLI Module
==========

Command-line interface for the SQL Injection Assessment Framework.
"""

import argparse
import sys
from typing import Optional, List

from ..utils import setup_logging


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the CLI."""
    
    parser = argparse.ArgumentParser(
        prog='sqlprobe',
        description='SQL Injection Assessment Framework v1.0 (2026) - For authorized security testing only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Features:
  - Auto-Parameter Discovery (forms, links, JS, common params)
  - WAF/Cloud/CDN Detection (Cloudflare, Akamai, AWS WAF, etc.)
  - Tech Stack Fingerprinting (React, Vue, Node, Python, PHP, etc.)
  - Header/Cookie/JSON Injection Testing
  
Examples:
  python %(prog)s -u "http://example.com/page.php?id=1"
  python %(prog)s -u "http://example.com" --depth 3 --concurrency 20
  python %(prog)s -u "http://example.com" --proxy "http://localhost:8080"
  python %(prog)s -u "http://example.com" -o results.json --format html
  python %(prog)s --load-session session.json
  
Legal Notice:
  This tool is provided for authorized security testing only.
  Unauthorized use is illegal and strictly prohibited.
        """
    )
    
    parser.add_argument(
        '-u', '--target',
        type=str,
        help='Target URL to test (e.g., http://example.com/page.php?id=1)'
    )
    
    parser.add_argument(
        '-d', '--depth',
        type=int,
        default=2,
        help='Crawling depth (default: 2)'
    )
    
    parser.add_argument(
        '-c', '--concurrency',
        type=int,
        default=10,
        help='Maximum concurrent requests (default: 10)'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=float,
        default=30.0,
        help='Request timeout in seconds (default: 30)'
    )
    
    parser.add_argument(
        '-p', '--proxy',
        type=str,
        help='HTTP/HTTPS proxy (e.g., http://localhost:8080)'
    )
    
    parser.add_argument(
        '--cookies',
        type=str,
        help='Cookies to include in requests (format: "key1=val1; key2=val2")'
    )
    
    parser.add_argument(
        '--headers',
        type=str,
        help='Custom headers (format: "Header1: value1; Header2: value2")'
    )
    
    parser.add_argument(
        '--auth',
        type=str,
        help='Basic authentication (format: "username:password")'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file path for results'
    )
    
    parser.add_argument(
        '-f', '--format',
        type=str,
        choices=['json', 'html', 'both'],
        default='json',
        help='Output format (default: json)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='Increase verbosity (-v, -vv, -vvv)'
    )
    
    parser.add_argument(
        '--save-session',
        type=str,
        help='Save scan session to file'
    )
    
    parser.add_argument(
        '--load-session',
        type=str,
        help='Load scan session from file'
    )
    
    parser.add_argument(
        '--whitelist',
        type=str,
        help='Comma-separated list of allowed domains'
    )
    
    parser.add_argument(
        '--skip-whitelist',
        action='store_true',
        help='Skip whitelist check'
    )
    
    parser.add_argument(
        '--max-payloads',
        type=int,
        default=100,
        help='Maximum payloads to test (default: 100)'
    )
    
    parser.add_argument(
        '--payloads',
        type=str,
        help='Custom payloads file (one payload per line)'
    )
    
    parser.add_argument(
        '--delay',
        type=float,
        default=0.5,
        help='Delay between tests in seconds (default: 0.5)'
    )

    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick scan mode with reduced payloads and delays'
    )
    
    parser.add_argument(
        '--no-follow-redirects',
        action='store_true',
        help='Do not follow HTTP redirects'
    )
    
    parser.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Do not verify SSL certificates'
    )
    
    parser.add_argument(
        '--banner',
        action='store_true',
        help='Display banner and exit'
    )
    
    parser.add_argument(
        '--version',
        action='store_true',
        help='Show version information'
    )
    
    parser.add_argument(
        '--log',
        type=str,
        help='Log file path'
    )
    
    return parser


def display_banner() -> None:
    """Display the framework banner."""
    try:
        banner = """
╔═════════════════════════════════════════════════════════════════════════╗
║                                                                         ║
║    ███████╗ ██████╗ ██╗     ██████╗ ██████╗  ██████╗ ██████╗ ███████╗   ║
║    ██╔════╝██╔═══██╗██║     ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝   ║
║    ███████╗██║   ██║██║     ██████╔╝██████╔╝██║   ██║██████╔╝█████╗     ║
║    ╚════██║██║▄▄ ██║██║     ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝     ║
║    ███████║╚██████╔╝███████╗██║     ██║  ██║╚██████╔╝██████╔╝███████╗   ║
║    ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝   ║
║                                                                         ║
║               Assessment Framework v1.0 (2026)                          ║
║               For Authorized Security Testing                           ║
║                                                                         ║
╚═════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    except UnicodeEncodeError:
        print("=" * 70)
        print("SQL INJECTION ASSESSMENT FRAMEWORK v1.0 (2026)")
        print("For Authorized Security Testing Only")
        print("=" * 70)


def parse_cookies(cookie_str: str) -> dict:
    """Parse cookie string into dictionary."""
    cookies = {}
    if cookie_str:
        for cookie in cookie_str.split(';'):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
    return cookies


def parse_headers(header_str: str) -> dict:
    """Parse header string into dictionary."""
    headers = {}
    if header_str:
        for header in header_str.split(';'):
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    return headers


def parse_auth(auth_str: str) -> Optional[tuple]:
    """Parse authentication string."""
    if auth_str and ':' in auth_str:
        return tuple(auth_str.split(':', 1))
    return None


def validate_args(args) -> bool:
    """Validate command-line arguments."""
    if args.load_session and args.target:
        print("Error: Cannot specify both --load-session and --target")
        return False
    
    if not args.load_session and not args.target and not args.banner and not args.version:
        print("Error: Must specify either --target or --load-session")
        return False
    
    if args.concurrency < 1 or args.concurrency > 100:
        print("Error: Concurrency must be between 1 and 100")
        return False
    
    if args.depth < 1 or args.depth > 5:
        print("Error: Depth must be between 1 and 5")
        return False
    
    return True


def run_cli() -> int:
    """Run the CLI."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not validate_args(args):
        return 1
    
    if args.banner:
        display_banner()
        return 0
    
    if args.version:
        print("SQL Injection Assessment Framework v1.0 (2026)")
        return 0
    
    display_banner()
    
    print("\n[!] LEGAL WARNING: This tool is for authorized security testing only.")
    print("[!] Unauthorized use is illegal and strictly prohibited.")
    print("[!] By proceeding, you confirm you have explicit permission to test the target.\n")
    
    return 0


if __name__ == '__main__':
    sys.exit(run_cli())