"""
Link extraction and URL normalization utilities
"""

from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from typing import List, Set, Optional
import re
from fnmatch import fnmatch


class URLNormalizer:
    """Normalize and filter URLs"""
    
    @staticmethod
    def normalize(url: str) -> str:
        """
        Normalize URL for deduplication
        - Remove fragment (#section)
        - Sort query parameters
        - Lowercase scheme and domain
        
        Args:
            url: URL to normalize
        
        Returns:
            Normalized URL
        """
        parsed = urlparse(url)
        
        # Normalize scheme and netloc to lowercase
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # Keep path as-is (case-sensitive)
        path = parsed.path or '/'
        
        # Sort query parameters for consistency
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(query_params.items()), doseq=True)
        
        # Remove fragment
        normalized = urlunparse((
            scheme,
            netloc,
            path,
            parsed.params,
            sorted_query,
            ''  # No fragment
        ))
        
        return normalized
    
    @staticmethod
    def is_valid(url: str) -> bool:
        """Check if URL is valid"""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    @staticmethod
    def get_domain(url: str) -> Optional[str]:
        """Extract domain from URL"""
        try:
            return urlparse(url).netloc.lower()
        except:
            return None


class ScopeFilter:
    """
    Filter URLs based on scope rules
    """
    
    def __init__(
        self,
        base_url: str,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        allow_subdomains: bool = True
    ):
        """
        Initialize scope filter
        
        Args:
            base_url: Base URL for scope
            include_patterns: Patterns to include (e.g., ['/api/*'])
            exclude_patterns: Patterns to exclude (e.g., ['/admin/*'])
            allow_subdomains: Allow subdomains of base domain
        """
        self.base_url = base_url
        self.base_domain = URLNormalizer.get_domain(base_url)
        self.include_patterns = include_patterns or ['/*']
        self.exclude_patterns = exclude_patterns or []
        self.allow_subdomains = allow_subdomains
    
    def is_in_scope(self, url: str) -> bool:
        """
        Check if URL is in scope
        
        Args:
            url: URL to check
        
        Returns:
            True if in scope
        """
        # Check if valid URL
        if not URLNormalizer.is_valid(url):
            return False
        
        # Check domain
        domain = URLNormalizer.get_domain(url)
        if not self._is_domain_allowed(domain):
            return False
        
        # Check against exclude patterns
        parsed = urlparse(url)
        path = parsed.path
        
        for pattern in self.exclude_patterns:
            if fnmatch(path, pattern):
                return False
        
        # Check against include patterns
        if self.include_patterns:
            for pattern in self.include_patterns:
                if fnmatch(path, pattern):
                    return True
            return False
        
        return True
    
    def _is_domain_allowed(self, domain: str) -> bool:
        """Check if domain is allowed"""
        if domain == self.base_domain:
            return True
        
        if self.allow_subdomains and domain.endswith('.' + self.base_domain):
            return True
        
        return False


class LinkExtractor:
    """Extract links from HTML and other sources"""
    
    def __init__(self, base_url: str, config: dict):
        """
        Initialize link extractor
        
        Args:
            base_url: Base URL for resolving relative links
            config: Configuration dictionary
        """
        self.base_url = base_url
        self.base_domain = URLNormalizer.get_domain(base_url)
        
        # Scope configuration
        scope_config = config.get('target', {}).get('scope', {})
        self.include_patterns = scope_config.get('include', ['/*'])
        self.exclude_patterns = scope_config.get('exclude', [])
        
        # Domain configuration
        target_config = config.get('target', {})
        self.allowed_domains = target_config.get('allowed_domains', [self.base_domain])
        self.blocked_extensions = target_config.get('blocked_extensions', [
            '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
            '.pdf', '.zip', '.tar', '.gz', '.rar',
            '.mp3', '.mp4', '.avi', '.mov',
            '.css', '.js',  # We handle these separately
            '.woff', '.woff2', '.ttf', '.eot'
        ])
        
        # Follow external links setting
        crawler_config = config.get('scan', {}).get('crawler', {})
        self.follow_external = crawler_config.get('follow_external_links', False)
    
    def extract_from_html(self, html: str, page_url: str) -> List[str]:
        """
        Extract all links from HTML content
        
        Args:
            html: HTML content
            page_url: URL of the page
        
        Returns:
            List of extracted URLs
        """
        from bs4 import BeautifulSoup
        
        try:
            import lxml  # noqa: F401
            parser = 'lxml'
        except ImportError:
            parser = 'html.parser'
        soup = BeautifulSoup(html, parser)
        links = set()
        
        # Extract from <a> tags
        for anchor in soup.find_all('a', href=True):
            href = anchor['href']
            if href.startswith('javascript:') or href.startswith('mailto:') or href.startswith('tel:'):
                continue
            absolute_url = self._make_absolute(href, page_url)
            if absolute_url and self.is_in_scope(absolute_url):
                links.add(absolute_url)
        
        # Extract from <link> tags (stylesheets, etc.)
        for link in soup.find_all('link', href=True):
            href = link['href']
            absolute_url = self._make_absolute(href, page_url)
            if absolute_url and self.is_in_scope(absolute_url):
                links.add(absolute_url)
        
        # Extract from <script> tags
        for script in soup.find_all('script', src=True):
            src = script['src']
            absolute_url = self._make_absolute(src, page_url)
            if absolute_url and self.is_in_scope(absolute_url):
                links.add(absolute_url)
        
        # Extract from <img> tags
        for img in soup.find_all('img', src=True):
            src = img['src']
            absolute_url = self._make_absolute(src, page_url)
            if absolute_url and self.is_in_scope(absolute_url):
                links.add(absolute_url)
        
        # Extract from <iframe> tags
        for iframe in soup.find_all('iframe', src=True):
            src = iframe['src']
            absolute_url = self._make_absolute(src, page_url)
            if absolute_url and self.is_in_scope(absolute_url):
                links.add(absolute_url)
        
        return list(links)
    
    def _make_absolute(self, url: str, base: str) -> Optional[str]:
        """
        Convert relative URL to absolute
        
        Args:
            url: Possibly relative URL
            base: Base URL for resolution
        
        Returns:
            Absolute URL or None if invalid
        """
        if not url or url.startswith('#') or url.startswith('javascript:') or url.startswith('mailto:'):
            return None
        
        # Handle data URLs
        if url.startswith('data:'):
            return None
        
        try:
            absolute = urljoin(base, url)
            return URLNormalizer.normalize(absolute)
        except:
            return None
    
    def is_in_scope(self, url: str) -> bool:
        """
        Check if URL is in scan scope
        
        Args:
            url: URL to check
        
        Returns:
            True if in scope
        """
        if not URLNormalizer.is_valid(url):
            return False
        
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Check domain
        domain = parsed.netloc.lower()
        if not self.follow_external:
            # Only scan allowed domains
            if domain not in self.allowed_domains and domain != self.base_domain:
                # Check wildcard domains (*.example.com)
                allowed = False
                for allowed_domain in self.allowed_domains:
                    if allowed_domain.startswith('*.'):
                        pattern = allowed_domain[2:]  # Remove *.
                        if domain.endswith(pattern):
                            allowed = True
                            break
                
                if not allowed:
                    return False
        
        # Check file extension
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in self.blocked_extensions):
            return False
        
        # Check include patterns
        if self.include_patterns:
            if not any(fnmatch(parsed.path, pattern) for pattern in self.include_patterns):
                return False
        
        # Check exclude patterns
        if self.exclude_patterns:
            if any(fnmatch(parsed.path, pattern) for pattern in self.exclude_patterns):
                return False
        
        return True
    
    def extract_from_text(self, text: str, page_url: str) -> List[str]:
        """
        Extract URLs from plain text using regex
        Useful for JavaScript, JSON responses, etc.
        
        Args:
            text: Text content
            page_url: Base URL for context
        
        Returns:
            List of extracted URLs
        """
        # Pattern to match URLs
        url_pattern = r'https?://[^\s\'"<>)]+'
        
        matches = re.findall(url_pattern, text)
        links = set()
        
        for match in matches:
            # Clean up trailing punctuation
            match = match.rstrip('.,;:!?')
            if self.is_in_scope(match):
                normalized = URLNormalizer.normalize(match)
                if normalized:
                    links.add(normalized)
        
        return list(links)
