"""
Async HTTP Engine Module
========================

Provides async HTTP client with:
- Connection pooling
- Retry logic with exponential backoff
- Timeout control
- Adaptive rate limiting
- Request batching with concurrency control
"""

import asyncio
import httpx
from typing import Optional, Dict, Any, List, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlencode, urlparse
import ssl

from ..utils import setup_logging, RequestLogger, SafetyControls


logger = setup_logging()


@dataclass
class RequestConfig:
    """Configuration for HTTP requests."""
    timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0
    follow_redirects: bool = True
    verify_ssl: bool = True
    allow_redirects: bool = True


@dataclass
class HTTPResponse:
    """Standardized HTTP response object."""
    status_code: int
    text: str
    headers: Dict[str, str]
    url: str
    elapsed_ms: float
    content_length: int
    cookies: Dict[str, str] = field(default_factory=dict)
    
    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300
    
    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400
    
    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500
    
    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600


class AsyncHTTPEngine:
    """Async HTTP engine with connection pooling and advanced features."""
    
    def __init__(
        self,
        base_url: str,
        config: Optional[RequestConfig] = None,
        proxy: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[tuple] = None,
        timeout: float = 30.0,
        max_connections: int = 100,
        max_keepalive_connections: int = 20,
    ):
        self.base_url = base_url
        self.config = config or RequestConfig(timeout=timeout)
        self.proxy = proxy
        self._cookies = cookies or {}
        self._headers = headers or {}
        self._auth = auth
        
        self._client: Optional[httpx.AsyncClient] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._request_logger = RequestLogger(logger)
        
        self._rate_limit_delay = 0.1
        self._consecutive_errors = 0
        self._last_request_time = 0.0
        
        self._limits = httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
        )
        
        self._transport: Optional[httpx.AsyncHTTPTransport] = None
        if proxy:
            self._transport = httpx.AsyncHTTPTransport(proxy=proxy)
    
    async def __aenter__(self):
        await self._init_client()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def _init_client(self) -> None:
        """Initialize the HTTP client."""
        ssl_context = ssl.create_default_context()
        if not self.config.verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.config.timeout),
            limits=self._limits,
            transport=self._transport,
            follow_redirects=self.config.follow_redirects,
            cookies=self._cookies,
            headers=self._headers,
            auth=self._auth,
        )
        
        self._semaphore = asyncio.Semaphore(self._limits.max_connections)
    
    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def _apply_rate_limit(self) -> None:
        """Apply adaptive rate limiting."""
        current_time = asyncio.get_event_loop().time()
        elapsed = current_time - self._last_request_time
        
        if elapsed < self._rate_limit_delay:
            await asyncio.sleep(self._rate_limit_delay - elapsed)
        
        self._last_request_time = asyncio.get_event_loop().time()
    
    async def _retry_with_backoff(
        self,
        func: Callable[[], Awaitable[HTTPResponse]],
        max_retries: Optional[int] = None
    ) -> HTTPResponse:
        """Execute request with retry logic and exponential backoff."""
        max_retries = max_retries or self.config.max_retries
        last_exception = None
        
        for attempt in range(max_retries):
            try:
                await self._apply_rate_limit()
                await SafetyControls.wait_for_rate_limit()
                
                response = await func()
                self._consecutive_errors = 0
                return response
                
            except httpx.TimeoutException as e:
                last_exception = e
                self._consecutive_errors += 1
                logger.warning(f"Request timeout (attempt {attempt + 1}/{max_retries})")
                
            except httpx.ConnectError as e:
                last_exception = e
                self._consecutive_errors += 1
                logger.warning(f"Connection error (attempt {attempt + 1}/{max_retries}): {e}")
                
            except Exception as e:
                last_exception = e
                self._consecutive_errors += 1
                logger.warning(f"Request failed (attempt {attempt + 1}/{max_retries}): {e}")
            
            if attempt < max_retries - 1:
                delay = self.config.retry_delay * (2 ** attempt)
                await asyncio.sleep(delay)
        
        raise last_exception or Exception("Max retries exceeded")
    
    async def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> HTTPResponse:
        """Make an HTTP request with retry logic."""
        
        if not self._client:
            await self._init_client()
        
        async def _do_request() -> HTTPResponse:
            start_time = datetime.now()
            
            merged_headers = {**self._headers}
            if headers:
                merged_headers.update(headers)
            
            merged_cookies = {**self._cookies}
            if cookies:
                merged_cookies.update(cookies)
            
            response = await self._client.request(
                method=method,
                url=path,
                params=params,
                data=data,
                json=json,
                headers=merged_headers,
                cookies=merged_cookies,
            )
            
            elapsed = (datetime.now() - start_time).total_seconds() * 1000
            
            return HTTPResponse(
                status_code=response.status_code,
                text=response.text,
                headers=dict(response.headers),
                url=str(response.url),
                elapsed_ms=elapsed,
                content_length=len(response.content),
                cookies=dict(response.cookies),
            )
        
        return await self._retry_with_backoff(_do_request)
    
    async def get(self, path: str, **kwargs) -> HTTPResponse:
        """Make GET request."""
        return await self.request("GET", path, **kwargs)
    
    async def post(self, path: str, **kwargs) -> HTTPResponse:
        """Make POST request."""
        return await self.request("POST", path, **kwargs)
    
    async def put(self, path: str, **kwargs) -> HTTPResponse:
        """Make PUT request."""
        return await self.request("PUT", path, **kwargs)
    
    async def delete(self, path: str, **kwargs) -> HTTPResponse:
        """Make DELETE request."""
        return await self.request("DELETE", path, **kwargs)
    
    async def head(self, path: str, **kwargs) -> HTTPResponse:
        """Make HEAD request."""
        return await self.request("HEAD", path, **kwargs)
    
    async def batch_request(
        self,
        requests: List[Dict[str, Any]],
        concurrency: int = 10
    ) -> List[HTTPResponse]:
        """Execute multiple requests with concurrency control."""
        
        semaphore = asyncio.Semaphore(concurrency)
        
        async def _bounded_request(req: Dict[str, Any]) -> HTTPResponse:
            async with semaphore:
                return await self.request(**req)
        
        tasks = [_bounded_request(req) for req in requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for result in results:
            if isinstance(result, HTTPResponse):
                valid_results.append(result)
            elif isinstance(result, Exception):
                logger.warning(f"Request failed: {result}")
                valid_results.append(None)
        
        return valid_results
    
    def set_rate_limit(self, delay: float) -> None:
        """Set rate limit delay."""
        self._rate_limit_delay = max(0.1, delay)
    
    def adjust_rate_limit(self, success: bool) -> None:
        """Adjust rate limit based on success/failure."""
        if success:
            self._rate_limit_delay = max(0.1, self._rate_limit_delay * 0.95)
        else:
            self._rate_limit_delay = min(5.0, self._rate_limit_delay * 1.5)
    
    @property
    def cookies(self) -> Dict[str, str]:
        return self._cookies
    
    @cookies.setter
    def cookies(self, value: Dict[str, str]) -> None:
        self._cookies = value


class SessionManager:
    """Manages HTTP sessions with cookie persistence."""
    
    def __init__(self, engine: AsyncHTTPEngine):
        self._engine = engine
        self._session_cookies: Dict[str, Dict[str, str]] = {}
    
    def set_cookies(self, domain: str, cookies: Dict[str, str]) -> None:
        """Set cookies for a domain."""
        self._session_cookies[domain] = cookies
    
    def get_cookies(self, domain: str) -> Dict[str, str]:
        """Get cookies for a domain."""
        return self._session_cookies.get(domain, {})
    
    def update_from_response(self, domain: str, response: HTTPResponse) -> None:
        """Update session cookies from response."""
        if response.cookies:
            current = self.get_cookies(domain)
            current.update(response.cookies)
            self._session_cookies[domain] = current
    
    def apply_to_engine(self, domain: str) -> None:
        """Apply session cookies to engine."""
        self._engine.cookies = self.get_cookies(domain)


class RequestBatcher:
    """Batches requests for efficient processing."""
    
    def __init__(self, engine: AsyncHTTPEngine, batch_size: int = 10):
        self._engine = engine
        self._batch_size = batch_size
        self._pending: List[Dict[str, Any]] = []
    
    async def add(self, request: Dict[str, Any]) -> List[HTTPResponse]:
        """Add request to batch and execute when full."""
        self._pending.append(request)
        
        if len(self._pending) >= self._batch_size:
            return await self.flush()
        
        return []
    
    async def flush(self) -> List[HTTPResponse]:
        """Execute all pending requests."""
        if not self._pending:
            return []
        
        results = await self._engine.batch_request(self._pending)
        self._pending.clear()
        return results