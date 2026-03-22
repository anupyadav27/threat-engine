"""
Web Crawler using Requests + BeautifulSoup
Primary crawler for HTML pages
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from typing import List, Set, Optional, Dict
from collections import deque
import logging

from dast_engine.crawler.link_extractor import LinkExtractor, URLNormalizer
from dast_engine.crawler.form_detector import FormDetector
from dast_engine.crawler.rate_limiter import RateLimiter
from dast_engine.models import CrawlResult, Endpoint


class WebCrawler:
    """
    BFS-based web crawler using Requests + BeautifulSoup
    Fast and efficient for traditional HTML websites
    """
    
    def __init__(self, start_url: str, session: requests.Session, config: dict):
        """
        Initialize web crawler
        
        Args:
            start_url: Starting URL for crawl
            session: Authenticated requests session
            config: Configuration dictionary
        """
        self.start_url = URLNormalizer.normalize(start_url)
        self.session = session
        self.config = config
        self.logger = logging.getLogger('DASTScanner.Crawler')
        
        # Crawler settings
        crawler_config = config.get('scan', {}).get('crawler', {})
        self.max_depth = crawler_config.get('max_depth', 5)
        self.max_pages = crawler_config.get('max_pages', 1000)
        self.follow_redirects = crawler_config.get('follow_redirects', True)
        self.user_agent = crawler_config.get('user_agent', 'DAST-Scanner/1.0')
        
        # Performance settings
        perf_config = config.get('scan', {}).get('performance', {})
        self.timeout = perf_config.get('request_timeout', 30)
        self.retry_attempts = perf_config.get('retry_attempts', 3)
        rate_limit = perf_config.get('rate_limit', 50)
        
        # Initialize components
        self.link_extractor = LinkExtractor(start_url, config)
        self.form_detector = FormDetector()
        self.rate_limiter = RateLimiter(rate_limit)
        
        # Crawl state
        self.visited: Set[str] = set()
        self.to_visit: deque = deque()
        self.crawl_results: List[CrawlResult] = []
        self.discovered_endpoints: List[Endpoint] = []
        
        # Statistics
        self.stats = {
            'pages_crawled': 0,
            'links_found': 0,
            'forms_found': 0,
            'errors': 0,
            'depth_reached': 0
        }
    
    def crawl(self) -> List[CrawlResult]:
        """
        Perform BFS crawl starting from start_url
        
        Returns:
            List of CrawlResult objects
        """
        self.logger.info(f"Starting crawl from {self.start_url}")
        self.logger.info(f"Max depth: {self.max_depth}, Max pages: {self.max_pages}")
        
        # Initialize queue
        self.to_visit.append((self.start_url, 0))  # (url, depth)
        
        while self.to_visit and len(self.visited) < self.max_pages:
            url, depth = self.to_visit.popleft()
            
            # Skip if already visited
            if url in self.visited:
                continue
            
            # Check depth limit
            if depth > self.max_depth:
                continue
            
            # Update depth statistics
            if depth > self.stats['depth_reached']:
                self.stats['depth_reached'] = depth
            
            # Crawl the page
            result = self._crawl_page(url, depth)
            
            if result:
                self.visited.add(url)
                self.crawl_results.append(result)
                self.stats['pages_crawled'] += 1
                
                # Add discovered links to queue
                for link in result.links:
                    if link not in self.visited:
                        self.to_visit.append((link, depth + 1))
                        self.stats['links_found'] += 1
                
                # Store discovered forms
                self.discovered_endpoints.extend(result.forms)
                self.stats['forms_found'] += len(result.forms)
                
                # Progress logging
                if self.stats['pages_crawled'] % 10 == 0:
                    self.logger.info(
                        f"Progress: {self.stats['pages_crawled']} pages, "
                        f"{len(self.to_visit)} queued, "
                        f"{self.stats['forms_found']} forms"
                    )
        
        self.logger.info(f"Crawl complete: {self.stats['pages_crawled']} pages crawled")
        return self.crawl_results
    
    def _crawl_page(self, url: str, depth: int) -> Optional[CrawlResult]:
        """
        Crawl a single page
        
        Args:
            url: URL to crawl
            depth: Current depth in crawl tree
        
        Returns:
            CrawlResult or None if error
        """
        self.logger.debug(f"Crawling [{depth}]: {url}")
        
        # Rate limiting
        self.rate_limiter.wait_if_needed()
        
        # Fetch page
        try:
            response = self._fetch_url(url)
            
            if not response:
                return None
            
            # Check if HTML content
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type.lower():
                self.logger.debug(f"Skipping non-HTML: {url} ({content_type})")
                return CrawlResult(
                    url=url,
                    status_code=response.status_code,
                    content='',
                    headers=dict(response.headers),
                    content_type=content_type
                )
            
            # Parse content
            html_content = response.text
            
            # Extract links
            links = self.link_extractor.extract_from_html(html_content, url)
            
            # Extract forms
            forms = self.form_detector.extract_forms(html_content, url)
            
            # Update form parameters to reflect method
            for form in forms:
                for param in form.parameters:
                    from dast_engine.models import HTTPMethod, ParameterLocation
                    if form.method == HTTPMethod.GET:
                        param.location = ParameterLocation.QUERY
                    else:
                        param.location = ParameterLocation.BODY
                form.depth = depth
            
            return CrawlResult(
                url=url,
                status_code=response.status_code,
                content=html_content,
                headers=dict(response.headers),
                content_type=content_type,
                links=links,
                forms=forms
            )
            
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {e}")
            self.stats['errors'] += 1
            
            return CrawlResult(
                url=url,
                status_code=0,
                content='',
                headers={},
                error=str(e)
            )
    
    def _fetch_url(self, url: str) -> Optional[requests.Response]:
        """
        Fetch URL with retries
        
        Args:
            url: URL to fetch        
        
        Returns:
            Response object or None
        """
        headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        for attempt in range(self.retry_attempts):
            try:
                response = self.session.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                    verify=True  # Verify SSL certificates
                )
                
                # Check for successful response
                if response.status_code < 400:
                    return response
                elif response.status_code == 404:
                    self.logger.debug(f"404 Not Found: {url}")
                    return None
                elif response.status_code in [401, 403]:
                    self.logger.warning(f"Access denied ({response.status_code}): {url}")
                    return response  # Return it anyway, might be interesting
                else:
                    self.logger.warning(f"HTTP {response.status_code}: {url}")
                    return response
                    
            except requests.Timeout:
                self.logger.warning(f"Timeout (attempt {attempt + 1}/{self.retry_attempts}): {url}")
                if attempt == self.retry_attempts - 1:
                    return None
                    
            except requests.ConnectionError as e:
                self.logger.warning(f"Connection error (attempt {attempt + 1}/{self.retry_attempts}): {url}")
                if attempt == self.retry_attempts - 1:
                    return None
                    
            except requests.RequestException as e:
                self.logger.error(f"Request error: {url} - {e}")
                return None
        
        return None
    
    def get_statistics(self) -> Dict:
        """Get crawl statistics"""
        stats = self.stats.copy()
        stats['rate_limiter'] = self.rate_limiter.get_stats()
        stats['visited_urls'] = len(self.visited)
        stats['queued_urls'] = len(self.to_visit)
        return stats
    
    def get_discovered_endpoints(self) -> List[Endpoint]:
        """Get all discovered endpoints (forms)"""
        return self.discovered_endpoints
