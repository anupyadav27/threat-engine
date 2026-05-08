"""
Pattern-Based API Discovery
Brute-force common API endpoint patterns when OpenAPI is not available
"""

import requests
from typing import List, Set, Optional
from urllib.parse import urljoin
import logging

from dast_engine.models import Endpoint, EndpointType, HTTPMethod
from dast_engine.crawler.rate_limiter import RateLimiter


class PatternBasedDiscovery:
    """
    Discover API endpoints by trying common patterns
    Useful when OpenAPI/Swagger is not available
    """
    
    # Common API path patterns
    COMMON_API_PREFIXES = [
        '/api',
        '/rest',
        '/v1',
        '/v2',
        '/v3',
        '/api/v1',
        '/api/v2',
        '/api/v3',
        '/rest/v1',
        '/rest/v2',
    ]
    
    # Common resource names (REST endpoints)
    COMMON_RESOURCES = [
        'users',
        'user',
        'customers',
        'customer',
        'products',
        'product',
        'items',
        'item',
        'orders',
        'order',
        'accounts',
        'account',
        'auth',
        'login',
        'logout',
        'register',
        'profile',
        'settings',
        'config',
        'data',
        'search',
        'admin',
        'dashboard',
        'posts',
        'post',
        'comments',
        'comment',
        'files',
        'file',
        'upload',
        'download',
        'export',
        'import',
        'reports',
        'report',
        'analytics',
        'stats',
        'health',
        'status',
        'info',
        'version',
    ]
    
    # Common ID patterns for parameterized endpoints
    ID_PATTERNS = [
        '1',
        '123',
        'me',
        'current',
    ]
    
    def __init__(self, session: Optional[requests.Session] = None, rate_limiter: Optional[RateLimiter] = None):
        """
        Initialize pattern-based discovery
        
        Args:
            session: Optional requests session with authentication
            rate_limiter: Optional rate limiter
        """
        self.session = session or requests.Session()
        self.rate_limiter = rate_limiter
        self.logger = logging.getLogger('DASTScanner.PatternDiscovery')
    
    def discover(self, base_url: str, max_attempts: int = 100, timeout: int = 5) -> List[Endpoint]:
        """
        Discover API endpoints by trying common patterns
        
        Args:
            base_url: Base URL of the target
            max_attempts: Maximum number of URLs to try
            timeout: Request timeout in seconds
        
        Returns:
            List of discovered endpoints
        """
        discovered = []
        attempted = 0
        
        # Generate candidate URLs
        candidates = self._generate_candidates(base_url)
        
        for url in candidates:
            if attempted >= max_attempts:
                break
            
            # Rate limit
            if self.rate_limiter:
                self.rate_limiter.wait_if_needed()
            
            # Try to access the endpoint
            if self._check_endpoint(url, timeout):
                endpoint = Endpoint(
                    url=url,
                    method=HTTPMethod.GET,
                    endpoint_type=EndpointType.API,
                    parameters=[],
                    found_on='pattern_discovery'
                )
                discovered.append(endpoint)
                self.logger.info(f"Discovered API endpoint: {url}")
            
            attempted += 1
        
        self.logger.info(f"Pattern discovery found {len(discovered)} endpoints from {attempted} attempts")
        return discovered
    
    def _generate_candidates(self, base_url: str) -> List[str]:
        """
        Generate candidate API URLs to try
        
        Args:
            base_url: Base URL
        
        Returns:
            List of candidate URLs
        """
        candidates = []
        
        # 1. Try base API prefixes alone
        for prefix in self.COMMON_API_PREFIXES:
            candidates.append(urljoin(base_url, prefix))
        
        # 2. Try API prefix + resource
        for prefix in self.COMMON_API_PREFIXES:
            for resource in self.COMMON_RESOURCES:
                candidates.append(urljoin(base_url, f"{prefix}/{resource}"))
        
        # 3. Try resource without API prefix (sometimes APIs don't use /api/)
        for resource in self.COMMON_RESOURCES:
            candidates.append(urljoin(base_url, resource))
        
        # 4. Try resource with ID patterns (e.g., /api/users/1)
        for prefix in self.COMMON_API_PREFIXES:
            for resource in self.COMMON_RESOURCES[:15]:  # Limit to avoid too many requests
                for id_pattern in self.ID_PATTERNS:
                    candidates.append(urljoin(base_url, f"{prefix}/{resource}/{id_pattern}"))
        
        return candidates
    
    def _check_endpoint(self, url: str, timeout: int) -> bool:
        """
        Check if an endpoint exists and is accessible
        
        Args:
            url: URL to check
            timeout: Request timeout
        
        Returns:
            True if endpoint exists (200-299 or 401/403)
        """
        try:
            response = self.session.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                headers={'Accept': 'application/json'}
            )
            
            # Consider endpoint valid if:
            # - Successful (200-299)
            # - Requires auth (401, 403) - means endpoint exists
            # - Not found (404) or other errors = not valid
            if 200 <= response.status_code < 300:
                return True
            elif response.status_code in [401, 403]:
                # Endpoint exists but requires authentication
                self.logger.debug(f"Found protected endpoint: {url}")
                return True
            else:
                return False
        except requests.exceptions.Timeout:
            return False
        except requests.exceptions.RequestException:
            return False
    
    def discover_with_wordlist(self, base_url: str, wordlist_path: str, timeout: int = 5) -> List[Endpoint]:
        """
        Discover endpoints using a custom wordlist
        
        Args:
            base_url: Base URL
            wordlist_path: Path to wordlist file (one path per line)
            timeout: Request timeout
        
        Returns:
            List of discovered endpoints
        """
        discovered = []
        
        try:
            with open(wordlist_path, 'r') as f:
                paths = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.logger.error(f"Wordlist not found: {wordlist_path}")
            return []
        
        for path in paths:
            if self.rate_limiter:
                self.rate_limiter.wait_if_needed()
            
            url = urljoin(base_url, path.lstrip('/'))
            
            if self._check_endpoint(url, timeout):
                endpoint = Endpoint(
                    url=url,
                    method=HTTPMethod.GET,
                    endpoint_type=EndpointType.API,
                    parameters=[],
                    found_on='wordlist_discovery'
                )
                discovered.append(endpoint)
                self.logger.info(f"Discovered endpoint from wordlist: {url}")
        
        return discovered
