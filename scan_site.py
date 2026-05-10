import asyncio
from sqlprobe.engine import AsyncHTTPEngine, RequestConfig
from sqlprobe.detection import DetectionEngine
from sqlprobe.payloads import PayloadEngine, PayloadType
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qs, urlparse
from concurrent.futures import ThreadPoolExecutor

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
║               Assessment Framework v2.0 (2026)                         ║
║               For Authorized Security Testing                           ║
║                                                                         ║
╚═════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    except UnicodeEncodeError:
        print("=" * 70)
        print("SQL INJECTION ASSESSMENT FRAMEWORK v2.0")
        print("For Authorized Security Testing Only")
        print("=" * 70)

display_banner()

async def discover_endpoints(base_url):
    endpoints = []
    seen_urls = set()
    
    async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
        try:
            r = await client.get(base_url)
            content_type = r.headers.get('content-type', '')
            is_html = 'text/html' in content_type
            
            if is_html:
                soup = BeautifulSoup(r.text, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    if href and '?' in href:
                        full_url = urljoin(base_url, href)
                        if full_url not in seen_urls and 'acunetix' not in full_url.lower():
                            seen_urls.add(full_url)
                            parsed = urlparse(full_url)
                            params = list(parse_qs(parsed.query).keys())
                            if params:
                                endpoints.append((full_url, params, 'GET'))
                
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    method = form.get('method', 'GET').upper()
                    if action:
                        full_url = urljoin(base_url, action)
                        inputs = []
                        for inp in form.find_all(['input', 'select', 'textarea']):
                            name = inp.get('name')
                            if name:
                                inputs.append(name)
                        if inputs and full_url not in seen_urls:
                            seen_urls.add(full_url)
                            endpoints.append((full_url, inputs, method))
                
                scripts = soup.find_all('script', src=True)
                for script in scripts:
                    src = script.get('src', '')
                    if 'api' in src.lower() or 'data' in src.lower():
                        full_url = urljoin(base_url, src)
                        if full_url not in seen_urls:
                            seen_urls.add(full_url)
                            endpoints.append((full_url, ['_'], 'GET'))
                
                meta_refresh = soup.find_all('meta', attrs={'http-equiv': 'refresh'})
                for meta in meta_refresh:
                    content = meta.get('content', '')
                    if 'url=' in content.lower():
                        url_part = content.split('url=')[-1].strip()
                        full_url = urljoin(base_url, url_part)
                        if full_url not in seen_urls and '?' in full_url:
                            seen_urls.add(full_url)
                            parsed = urlparse(full_url)
                            params = list(parse_qs(parsed.query).keys())
                            if params:
                                endpoints.append((full_url, params, 'GET'))
            
            if '/api/' in base_url.lower() or 'application/json' in content_type:
                endpoints.append((base_url, ['json_body'], 'POST'))
            
            graphql_patterns = ['/graphql', '/graphiql', '/api/graphql']
            for pattern in graphql_patterns:
                if pattern in base_url.lower():
                    endpoints.append((base_url, ['query'], 'POST'))
                    break
                    
        except Exception as e:
            print(f"Discovery error: {e}")
    
    return list(set([(u, tuple(p), m) for u, p, m in endpoints]))

async def test_endpoint(engine, detection, payloads, url, params, method='GET'):
    vulnerabilities = []
    
    try:
        baseline = await detection.establish_baseline(engine, url, method, list(params))
    except Exception:
        baseline = None
    
    test_payloads = []
    test_payloads.extend([(p.value, 'boolean') for p in payloads.get_payloads_by_type(PayloadType.BOOLEAN_BASED)[:8]])
    test_payloads.extend([(p.value, 'error') for p in payloads.get_payloads_by_type(PayloadType.ERROR_BASED)[:6]])
    test_payloads.extend([(p.value, 'union') for p in payloads.get_payloads_by_type(PayloadType.UNION_BASED)[:4]])
    
    param_results = {}
    for param in params:
        param_results[param] = {'true_count': 0, 'false_count': 0, 'error_found': False, 'results': []}
        
        for payload, ptype in test_payloads:
            try:
                if method == 'GET':
                    result = await detection.test_parameter(engine, url, 'GET', param, payload, baseline)
                else:
                    result = await detection.test_parameter(engine, url, 'POST', param, payload, baseline)
                
                if result.is_vulnerable:
                    param_results[param]['results'].append((result.confidence, result.injection_type.value, payload))
                    if ptype == 'boolean':
                        if '1=1' in payload or '1\'=\'1' in payload:
                            param_results[param]['true_count'] += 1
                        elif '1=2' in payload or '1\'=\'2' in payload:
                            param_results[param]['false_count'] += 1
                    if result.injection_type.value == 'error_based':
                        param_results[param]['error_found'] = True
                        
            except Exception:
                pass
    
    for param, data in param_results.items():
        if data['error_found']:
            best_result = max(data['results'], key=lambda x: x[0]) if data['results'] else (0.9, 'error', '')
            vulnerabilities.append({
                'parameter': param,
                'payload': best_result[2][:30] if best_result[2] else 'Error-based detected',
                'confidence': best_result[0],
                'type': best_result[1]
            })
        elif data['true_count'] >= 2 and data['false_count'] >= 1:
            if data['true_count'] > data['false_count']:
                best_result = max(data['results'], key=lambda x: x[0]) if data['results'] else (0.7, 'boolean', '')
                vulnerabilities.append({
                    'parameter': param,
                    'payload': best_result[2][:30] if best_result[2] else 'Boolean-based detected',
                    'confidence': best_result[0],
                    'type': best_result[1]
                })
        elif len(data['results']) >= 3:
            avg_conf = sum(r[0] for r in data['results']) / len(data['results'])
            if avg_conf > 0.65:
                best_result = max(data['results'], key=lambda x: x[0])
                vulnerabilities.append({
                    'parameter': param,
                    'payload': best_result[2][:30] if best_result[2] else 'Multiple indicators',
                    'confidence': avg_conf,
                    'type': best_result[1]
                })
    
    return vulnerabilities

async def main():
    url = input("Enter Target Url: ").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    base_url = url
    engine = AsyncHTTPEngine(base_url=base_url, config=RequestConfig(timeout=15))
    detection = DetectionEngine(verbosity=0)
    payloads = PayloadEngine()
    
    print('\n[+] Discovering endpoints...')
    endpoints = await discover_endpoints(base_url)
    print(f'[+] Found {len(endpoints)} endpoints with parameters')
    
    all_vulns = []
    tested = 0
    
    async with engine:
        for url, params, method in endpoints:
            tested += 1
            print(f'\r[{tested}/{len(endpoints)}] Testing: {url[:200]}', end='', flush=True)
            vulns = await test_endpoint(engine, detection, payloads, url, list(params), method)
            for v in vulns:
                print(f'\n  [!] VULNERABLE: {v["parameter"]}')
                print(f'      Type: {v["type"]}, Confidence: {v["confidence"]:.0%}')
                print(f'      Payload: {v["payload"]}')
                all_vulns.append({'url': url, 'parameter': v['parameter'], 'payload': v['payload'], 'confidence': v['confidence'], 'type': v['type']})
    
    print(f'\n\n{"="*60}')
    print(f'SCAN COMPLETE')
    print(f"{'='*60}")
    print(f'Total endpoints tested: {tested}')
    print(f'Total vulnerabilities found: {len(all_vulns)}')
    
    if all_vulns:
        print(f'\n[CRITICAL] Vulnerabilities:')
        for v in all_vulns:
            if v['confidence'] > 0.8:
                print(f'  [!] {v["url"]} - {v["parameter"]} ({v["type"]}) - {v["confidence"]:.0%}')
        
        print(f'\n[WARNING] Lower confidence:')
        for v in all_vulns:
            if v['confidence'] <= 0.8:
                print(f'  [?] {v["url"]} - {v["parameter"]} ({v["type"]}) - {v["confidence"]:.0%}')
    
    return all_vulns

if __name__ == '__main__':
    asyncio.run(main())