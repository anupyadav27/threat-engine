"""
Playwright Crawler - JavaScript-Rendered Content
Handles Single Page Applications (SPAs) and JavaScript-heavy sites
Uses browser automation to discover dynamically loaded endpoints
"""

from typing import List, Set, Optional, Dict, TYPE_CHECKING
import asyncio
import logging
from urllib.parse import urljoin, urlparse

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
    if TYPE_CHECKING:
        from playwright.async_api import Page, Browser, BrowserContext, Route
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    if TYPE_CHECKING:
        Page = Browser = BrowserContext = Route = None  # type: ignore

from dast_engine.models import Endpoint, EndpointType, HTTPMethod, Parameter, ParameterLocation
from dast_engine.crawler.rate_limiter import RateLimiter
from dast_engine.crawler.link_extractor import ScopeFilter


class PlaywrightCrawler:
    """
    Browser-based crawler for JavaScript-rendered content
    Intercepts network requests to discover API endpoints
    """
    
    def __init__(
        self,
        base_url: str,
        max_pages: int = 50,
        max_depth: int = 3,
        scope_filter: Optional[ScopeFilter] = None,
        rate_limiter: Optional[RateLimiter] = None,
        headless: bool = True,
        timeout: int = 30000,  # milliseconds
    ):
        """
        Initialize Playwright crawler
        
        Args:
            base_url: Starting URL
            max_pages: Maximum pages to crawl
            max_depth: Maximum crawl depth
            scope_filter: Optional scope filter
            rate_limiter: Optional rate limiter
            headless: Run browser in headless mode
            timeout: Page load timeout in milliseconds
        """
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError(
                "Playwright is not installed. Install with: pip install playwright && playwright install chromium"
            )
        
        self.base_url = base_url
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.scope_filter = scope_filter or ScopeFilter(base_url)
        self.rate_limiter = rate_limiter
        self.headless = headless
        self.timeout = timeout
        
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: List[Endpoint] = []
        self.api_calls: List[Dict] = []  # Captured network requests
        
        self.logger = logging.getLogger('DASTScanner.PlaywrightCrawler')
    
    async def crawl(self, auth_cookies: Optional[List[Dict]] = None) -> List[Endpoint]:
        """
        Start crawling with Playwright
        
        Args:
            auth_cookies: Optional authentication cookies
        
        Returns:
            List of discovered endpoints
        """
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context()
            
            # Set cookies if provided
            if auth_cookies:
                await context.add_cookies(auth_cookies)
            
            try:
                page = await context.new_page()
                
                # Setup request interception
                await self._setup_request_interception(page)
                
                # Start crawling from base URL
                await self._crawl_page(page, self.base_url, depth=0)
                
                # Convert captured API calls to endpoints
                self.logger.info(f"Playwright captured {len(self.api_calls)} API calls")
                self._process_api_calls()
                
            finally:
                await browser.close()
        
        self.logger.info(f"Playwright crawling completed: {len(self.discovered_endpoints)} endpoints")
        return self.discovered_endpoints
    
    async def _setup_request_interception(self, page: 'Page'):
        """
        Setup network request interception to capture API calls
        
        Args:
            page: Playwright page
        """
        async def handle_request(route: 'Route'):
            request = route.request
            
            # Capture API-like requests
            url = request.url
            method = request.method
            
            # Check if this looks like an API call
            if self._is_api_request(url, request.resource_type):
                self.api_calls.append({
                    'url': url,
                    'method': method,
                    'headers': request.headers,
                    'post_data': request.post_data if method in ['POST', 'PUT', 'PATCH'] else None,
                    'resource_type': request.resource_type,
                })
                self.logger.debug(f"Captured API call: {method} {url}")
            
            # Continue the request
            await route.continue_()
        
        # Intercept all requests
        await page.route('**/*', handle_request)
    
    def _is_api_request(self, url: str, resource_type: str) -> bool:
        """
        Determine if a request is an API call
        
        Args:
            url: Request URL
            resource_type: Resource type (document, fetch, xhr, etc.)
        
        Returns:
            True if likely an API request
        """
        # XHR and Fetch requests are typically API calls
        if resource_type in ['xhr', 'fetch']:
            return True
        
        # Check URL patterns
        url_lower = url.lower()
        api_patterns = ['/api/', '/rest/', '/graphql', '/v1/', '/v2/', '/v3/']
        
        return any(pattern in url_lower for pattern in api_patterns)
    
    async def _crawl_page(self, page: 'Page', url: str, depth: int):
        """
        Crawl a single page and extract links
        
        Args:
            page: Playwright page
            url: URL to crawl
            depth: Current depth
        """
        # Check limits
        if len(self.visited_urls) >= self.max_pages:
            return
        
        if depth > self.max_depth:
            return
        
        # Check if already visited
        if url in self.visited_urls:
            return
        
        # Check scope
        if not self.scope_filter.is_in_scope(url):
            return
        
        # Rate limit
        if self.rate_limiter:
            self.rate_limiter.wait_if_needed()
        
        self.visited_urls.add(url)
        self.logger.info(f"Crawling (Playwright): {url} [depth={depth}]")

        try:
            # Navigate to page
            response = await page.goto(url, wait_until='networkidle', timeout=self.timeout)

            if not response or response.status >= 400:
                self.logger.warning(f"Failed to load: {url} [status={response.status if response else 'N/A'}]")
                return

            # Wait for page to fully render
            await page.wait_for_load_state('networkidle')

            # Additional wait for dynamic content
            await asyncio.sleep(2)
            
            # Extract links from rendered page
            links = await self._extract_links(page)
            
            # Crawl discovered links
            for link in links:
                if len(self.visited_urls) >= self.max_pages:
                    break
                await self._crawl_page(page, link, depth + 1)
            
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {e}")
    
    async def _extract_links(self, page: 'Page') -> List[str]:
        """
        Extract all links from rendered page
        
        Args:
            page: Playwright page
        
        Returns:
            List of absolute URLs
        """
        links = []
        
        try:
            # Get all anchor tags
            link_elements = await page.query_selector_all('a[href]')
            
            for element in link_elements:
                href = await element.get_attribute('href')
                if href:
                    # Make absolute
                    absolute_url = urljoin(page.url, href)
                    
                    # Filter
                    if self.scope_filter.is_in_scope(absolute_url):
                        links.append(absolute_url)
        except Exception as e:
            self.logger.error(f"Error extracting links: {e}")
        
        return list(set(links))
    
    def _process_api_calls(self):
        """
        Convert captured API calls to Endpoint objects
        """
        seen = set()
        
        for call in self.api_calls:
            url = call['url']
            method = call['method']
            
            # Deduplicate
            key = (url, method)
            if key in seen:
                continue
            seen.add(key)
            
            # Parse parameters from POST data
            parameters = []
            if call['post_data']:
                # Try to parse JSON body
                try:
                    import json
                    body = json.loads(call['post_data'])
                    if isinstance(body, dict):
                        for key, value in body.items():
                            parameters.append(Parameter(
                                name=key,
                                location=ParameterLocation.BODY,
                                value=str(value),
                                required=False
                            ))
                except:
                    # Not JSON, add as raw body
                    parameters.append(Parameter(
                        name='body',
                        location=ParameterLocation.BODY,
                        value=call['post_data'],
                        required=False
                    ))
            
            # Create endpoint
            endpoint = Endpoint(
                url=url,
                method=HTTPMethod[method.upper()],
                endpoint_type=EndpointType.API,
                parameters=parameters,
                found_on='playwright_network_capture'
            )
            
            self.discovered_endpoints.append(endpoint)
    
    def get_statistics(self) -> Dict:
        """
        Get crawling statistics
        
        Returns:
            Statistics dictionary
        """
        return {
            'pages_visited': len(self.visited_urls),
            'api_calls_captured': len(self.api_calls),
            'endpoints_discovered': len(self.discovered_endpoints),
        }


def run_playwright_crawler(
    base_url: str,
    max_pages: int = 50,
    max_depth: int = 3,
    auth_cookies: Optional[List[Dict]] = None,
    **kwargs
) -> List[Endpoint]:
    """
    Convenience function to run Playwright crawler synchronously
    
    Args:
        base_url: Starting URL
        max_pages: Maximum pages to crawl
        max_depth: Maximum depth
        auth_cookies: Optional authentication cookies
        **kwargs: Additional arguments for PlaywrightCrawler
    
    Returns:
        List of discovered endpoints
    """
    crawler = PlaywrightCrawler(
        base_url=base_url,
        max_pages=max_pages,
        max_depth=max_depth,
        **kwargs
    )
    
    # Run async crawler
    return asyncio.run(crawler.crawl(auth_cookies))
