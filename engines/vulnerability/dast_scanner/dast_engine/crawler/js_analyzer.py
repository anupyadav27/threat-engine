"""
JavaScript Analyzer - Static Analysis
Extracts API endpoints from JavaScript code without executing it
"""

import re
from typing import List, Set
from urllib.parse import urljoin
import logging

from dast_engine.crawler.link_extractor import URLNormalizer


class JavaScriptAnalyzer:
    """
    Analyze JavaScript files to discover API endpoints
    Uses regex patterns to extract fetch(), axios, XMLHttpRequest calls
    """
    
    def __init__(self, base_url: str):
        """
        Initialize JavaScript analyzer
        
        Args:
            base_url: Base URL for resolving relative paths
        """
        self.base_url = base_url
        self.logger = logging.getLogger('DASTScanner.JSAnalyzer')
    
    def analyze_inline_scripts(self, html: str, page_url: str) -> List[str]:
        """
        Extract API calls from inline <script> tags
        
        Args:
            html: HTML content
            page_url: URL of the page
        
        Returns:
            List of discovered API endpoints
        """
        from bs4 import BeautifulSoup
        
        try:
            import lxml  # noqa: F401
            parser = 'lxml'
        except ImportError:
            parser = 'html.parser'
        soup = BeautifulSoup(html, parser)
        api_endpoints = set()
        
        # Find all inline script tags
        for script in soup.find_all('script'):
            if not script.get('src'):  # Inline script
                script_content = script.string or ''
                endpoints = self.extract_from_js_code(script_content, page_url)
                api_endpoints.update(endpoints)
        
        return list(api_endpoints)
    
    def analyze_external_scripts(self, script_content: str, script_url: str) -> List[str]:
        """
        Extract API calls from external JavaScript files
        
        Args:
            script_content: JavaScript code
            script_url: URL of the script file
        
        Returns:
            List of discovered API endpoints
        """
        return self.extract_from_js_code(script_content, script_url)
    
    def extract_from_js_code(self, js_code: str, base_url: str) -> List[str]:
        """
        Extract API endpoints from JavaScript code using regex
        
        Args:
            js_code: JavaScript code
            base_url: Base URL for resolving relative paths
        
        Returns:
            List of API endpoint URLs
        """
        endpoints = set()
        
        # Pattern 1: fetch() API
        # fetch('/api/users') or fetch("https://api.example.com/data")
        fetch_patterns = [
            r'fetch\s*\(\s*[\'"`]([^\'"` ]+)[\'"`]',
            r'fetch\s*\(\s*`([^`]+)`',  # Template literals
        ]
        
        for pattern in fetch_patterns:
            matches = re.findall(pattern, js_code)
            for match in matches:
                endpoint = self._resolve_endpoint(match, base_url)
                if endpoint:
                    endpoints.add(endpoint)
        
        # Pattern 2: axios
        # axios.get('/api/data') or axios.post('/api/submit', data)
        axios_patterns = [
            r'axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"` ]+)[\'"`]',
            r'axios\s*\(\s*{\s*url\s*:\s*[\'"`]([^\'"` ]+)[\'"`]',
        ]
        
        for pattern in axios_patterns:
            matches = re.findall(pattern, js_code)
            for match in matches:
                # match could be tuple (method, url) or just url
                url = match[1] if isinstance(match, tuple) and len(match) > 1 else match[0] if isinstance(match, tuple) else match
                endpoint = self._resolve_endpoint(url, base_url)
                if endpoint:
                    endpoints.add(endpoint)
        
        # Pattern 3: XMLHttpRequest
        # xhr.open('GET', '/api/data')
        xhr_patterns = [
            r'\.open\s*\(\s*[\'"`](GET|POST|PUT|DELETE|PATCH)[\'"`]\s*,\s*[\'"`]([^\'"` ]+)[\'"`]',
        ]
        
        for pattern in xhr_patterns:
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            for match in matches:
                url = match[1] if isinstance(match, tuple) else match
                endpoint = self._resolve_endpoint(url, base_url)
                if endpoint:
                    endpoints.add(endpoint)
        
        # Pattern 4: jQuery AJAX
        # $.ajax({url: '/api/data'}), $.get('/api/data'), $.post('/api/data')
        jquery_patterns = [
            r'\$\.ajax\s*\(\s*{\s*url\s*:\s*[\'"`]([^\'"` ]+)[\'"`]',
            r'\$\.(get|post)\s*\(\s*[\'"`]([^\'"` ]+)[\'"`]',
        ]
        
        for pattern in jquery_patterns:
            matches = re.findall(pattern, js_code)
            for match in matches:
                url = match[1] if isinstance(match, tuple) and len(match) > 1 else match[0] if isinstance(match, tuple) else match
                endpoint = self._resolve_endpoint(url, base_url)
                if endpoint:
                    endpoints.add(endpoint)
        
        # Pattern 5: Simple URL strings (less reliable, more noise)
        # Look for strings that look like API endpoints
        api_string_patterns = [
            r'[\'"`](/api/[^\'"` ]*)[\'"`]',
            r'[\'"`](/rest/[^\'"` ]*)[\'"`]',
            r'[\'"`](/v\d+/[^\'"` ]*)[\'"`]',
        ]
        
        for pattern in api_string_patterns:
            matches = re.findall(pattern, js_code)
            for match in matches:
                endpoint = self._resolve_endpoint(match, base_url)
                if endpoint:
                    endpoints.add(endpoint)
        
        # Pattern 6: Route definitions (React Router, Vue Router, etc.)
        # path: '/users/:id', { path: '/api/data' }
        route_patterns = [
            r'path\s*:\s*[\'"`]([^\'"` ]+)[\'"`]',
            r'route\s*:\s*[\'"`]([^\'"` ]+)[\'"`]',
        ]
        
        for pattern in route_patterns:
            matches = re.findall(pattern, js_code)
            for match in matches:
                # These might be frontend routes, but worth checking
                if match.startswith('/api') or match.startswith('/rest'):
                    endpoint = self._resolve_endpoint(match, base_url)
                    if endpoint:
                        endpoints.add(endpoint)
        
        self.logger.debug(f"Extracted {len(endpoints)} API endpoints from JavaScript")
        return list(endpoints)
    
    def _resolve_endpoint(self, url: str, base_url: str) -> str:
        """
        Resolve relative URL to absolute
        Filter out invalid URLs
        
        Args:
            url: Possibly relative URL
            base_url: Base URL for resolution
        
        Returns:
            Absolute URL or None
        """
        # Skip obviously invalid URLs
        if not url or url.startswith('#') or url.startswith('javascript:'):
            return None
        
        # Skip template variables
        if '${' in url or '{' in url or '<' in url:
            return None
        
        # Skip very short paths (likely false positives)
        if len(url) < 3:
            return None
        
        try:
            # Make absolute
            if url.startswith('http://') or url.startswith('https://'):
                absolute = url
            else:
                absolute = urljoin(base_url, url)
            
            # Normalize
            normalized = URLNormalizer.normalize(absolute)
            return normalized
        except:
            return None
    
    def extract_websocket_endpoints(self, js_code: str, base_url: str) -> List[str]:
        """
        Extract WebSocket endpoints
        
        Args:
            js_code: JavaScript code
            base_url: Base URL
        
        Returns:
            List of WebSocket URLs
        """
        endpoints = set()
        
        # WebSocket patterns
        # new WebSocket('ws://example.com/socket')
        ws_patterns = [
            r'new\s+WebSocket\s*\(\s*[\'"`](wss?://[^\'"` ]+)[\'"`]',
            r'new\s+WebSocket\s*\(\s*[\'"`]([/][^\'"` ]+)[\'"`]',  # Relative paths
        ]
        
        for pattern in ws_patterns:
            matches = re.findall(pattern, js_code)
            for match in matches:
                if match.startswith('ws://') or match.startswith('wss://'):
                    endpoints.add(match)
                else:
                    # Convert to absolute WebSocket URL
                    ws_url = urljoin(base_url, match).replace('http://', 'ws://').replace('https://', 'wss://')
                    endpoints.add(ws_url)
        
        return list(endpoints)
