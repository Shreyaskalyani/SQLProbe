"""
Smart Crawler Module
================
"""

import httpx
from typing import List
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup


@dataclass
class FormParameter:
    name: str
    value: str = ""
    param_type: str = "text"
    required: bool = False
    hidden: bool = False
    form_action: str = ""
    form_method: str = "POST"


@dataclass
class CrawlResult:
    url: str
    method: str
    parameters: List[FormParameter] = field(default_factory=list)
    forms: List[FormParameter] = field(default_factory=list)
    links: List[str] = field(default_factory=list)


@dataclass
class Endpoint:
    url: str
    method: str
    parameters: List[str] = field(default_factory=list)


class SmartCrawler:
    """Smart crawler for endpoint and parameter discovery."""
    
    COMMON_PARAMS = [
        'search', 'query', 'q', 'keyword', 's', 'id', 'user', 'username', 'email',
        'page', 'limit', 'offset', 'sort', 'order', 'category', 'tag', 'item',
        'login', 'admin', 'password', 'token', 'redirect', 'url', 'next', 'retURL',
        'file', 'filename', 'path', 'callback', 'return', 'view', 'action', 'do',
    ]
    
    def __init__(self, http_engine, max_depth: int = 2, verbosity: int = 0):
        self._http_engine = http_engine
        self.max_depth = max_depth
        self._visited = set()
    
    async def crawl(self, url: str) -> List[CrawlResult]:
        """Simple crawl."""
        results = []
        
        if url in self._visited:
            return results
        self._visited.add(url)
        
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url)
                
                if r.status_code != 200:
                    return results
                
                soup = BeautifulSoup(r.text, 'html.parser')
                parsed = urlparse(url)
                
                params = []
                for name, vals in parse_qs(parsed.query).items():
                    params.append(FormParameter(name=name, value=vals[0], param_type='query'))
                
                for inp in soup.find_all('input'):
                    name = inp.get('name')
                    if name:
                        params.append(FormParameter(
                            name=name,
                            value=inp.get('value', ''),
                            param_type=inp.get('type', 'text')
                        ))
                
                if not params:
                    for p in self.COMMON_PARAMS[:15]:
                        params.append(FormParameter(name=p, value='', param_type='common'))
                
                results.append(CrawlResult(
                    url=url,
                    method='GET',
                    parameters=params,
                    forms=[]
                ))
                
        except Exception as e:
            print(f"Crawl error: {e}")
        
        return results


class HiddenParameterDetector:
    """Detects hidden parameters in forms."""
    
    @staticmethod
    def detect(soup) -> List[FormParameter]:
        """Detect hidden parameters in HTML."""
        params = []
        for inp in soup.find_all('input', type='hidden'):
            params.append(FormParameter(
                name=inp.get('name', ''),
                value=inp.get('value', ''),
                param_type='hidden',
                hidden=True
            ))
        return params