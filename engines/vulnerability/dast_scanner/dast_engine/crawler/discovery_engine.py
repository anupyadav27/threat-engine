"""
Application Discovery Engine - Main Orchestrator
Coordinates all discovery methods to build comprehensive endpoint inventory
"""

import requests
import logging
from typing import Optional, Dict, List
from pathlib import Path
from dataclasses import dataclass, field

from dast_engine.config.config_parser import TargetConfig
from dast_engine.auth.auth_manager import AuthenticationManager
from dast_engine.models import Endpoint

# Crawler components
from dast_engine.crawler.rate_limiter import RateLimiter
from dast_engine.crawler.link_extractor import ScopeFilter
from dast_engine.crawler.web_crawler import WebCrawler
from dast_engine.crawler.js_analyzer import JavaScriptAnalyzer
from dast_engine.crawler.openapi_parser import OpenAPIParser
from dast_engine.crawler.pattern_discovery import PatternBasedDiscovery
from dast_engine.crawler.endpoint_inventory import EndpointInventory


@dataclass
class DiscoveryResult:
    """Result from application discovery process"""
    target_url: str
    endpoints_discovered: List[Endpoint] = field(default_factory=list)
    total_endpoints: int = 0
    statistics: Dict = field(default_factory=dict)
    
    def __post_init__(self):
        """Set total_endpoints if not provided"""
        if self.total_endpoints == 0:
            self.total_endpoints = len(self.endpoints_discovered)

# Optional Playwright
try:
    from dast_engine.crawler.playwright_crawler import PlaywrightCrawler, PLAYWRIGHT_AVAILABLE
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class ApplicationDiscoveryEngine:
    """
    Main orchestrator for application discovery (Step 2)
    Runs multiple discovery methods and aggregates results
    """
    
    def __init__(self, config: TargetConfig):
        """
        Initialize discovery engine
        
        Args:
            config: Target configuration from Step 1
        """
        self.config = config
        self.logger = logging.getLogger('DASTScanner.Discovery')
        
        # Initialize components
        self.auth_manager = AuthenticationManager(
            config.get('authentication') or {'type': 'none'}
        )
        self.session = self.auth_manager.get_session()
        self.rate_limiter = RateLimiter(requests_per_second=config.get('scan.performance.rate_limit', 50))
        self.scope_filter = ScopeFilter(
            base_url=config.get('target.url'),
            include_patterns=config.get('target.scope.include', ['/*']),
            exclude_patterns=config.get('target.scope.exclude', [])
        )
        
        # Inventory for all discoveries
        self.inventory = EndpointInventory()
        
        # Statistics
        self.stats = {
            'web_crawler': {'enabled': False, 'endpoints': 0},
            'openapi': {'enabled': False, 'endpoints': 0},
            'pattern_discovery': {'enabled': False, 'endpoints': 0},
            'playwright': {'enabled': False, 'endpoints': 0},
        }
    
    def discover(self, enable_js_rendering: bool = False, enable_pattern_discovery: bool = True) -> DiscoveryResult:
        """
        Run complete discovery process
        
        Args:
            enable_js_rendering: Enable Playwright for JavaScript-rendered content
            enable_pattern_discovery: Enable pattern-based API discovery
        
        Returns:
            CrawlResult with all discovered endpoints
        """
        self.logger.info(f"Starting application discovery for: {self.config.get('target.url')}")
        
        # 1. OpenAPI/Swagger Discovery (highest value, try first)
        self._discover_openapi()
        
        # 2. Web Crawler (traditional crawling)
        self._discover_with_web_crawler()
        
        # 3. Pattern-based API Discovery
        if enable_pattern_discovery:
            self._discover_with_patterns()
        
        # 4. Playwright (JavaScript-rendered content)
        if enable_js_rendering:
            if PLAYWRIGHT_AVAILABLE:
                self._discover_with_playwright()
            else:
                self.logger.warning("Playwright not available — install with: pip install playwright && playwright install chromium")
        # JS rendering disabled: silently skip
        
        # Generate crawl result
        result = self._generate_result()
        
        # Log summary
        self._log_summary()
        
        return result
    
    def _discover_openapi(self):
        """Discover endpoints from OpenAPI/Swagger specification"""
        self.logger.info("Running OpenAPI/Swagger discovery...")
        self.stats['openapi']['enabled'] = True
        try:
            parser = OpenAPIParser(session=self.session)
            endpoints = parser.discover_and_parse(
                base_url=self.config.get('target.url'),
                timeout=10
            )
            count = self.inventory.add_many(endpoints)
            self.stats['openapi']['endpoints'] = count
            self.logger.info(f"OpenAPI discovery: {count} new endpoints")
        except Exception as e:
            self.logger.debug(f"OpenAPI discovery: {e}")
    
    def _discover_with_web_crawler(self):
        """Discover endpoints with traditional web crawler"""
        self.logger.info("Running web crawler (BeautifulSoup)...")
        self.stats['web_crawler']['enabled'] = True
        try:
            crawler = WebCrawler(
                start_url=self.config.get('target.url'),
                session=self.session,
                config=self.config.to_dict()
            )
            crawler.crawl()
            endpoints = crawler.get_discovered_endpoints()
            count = self.inventory.add_many(endpoints)
            self.stats['web_crawler']['endpoints'] = count
            crawler_stats = crawler.get_statistics()
            # Store page count so caller can display it
            self.stats['web_crawler']['pages_crawled'] = crawler_stats.get('pages_crawled', 0)
            self.logger.info(f"Web crawler: {count} endpoints, {crawler_stats.get('pages_crawled', 0)} pages")
        except Exception as e:
            self.logger.error(f"Web crawler failed: {e}")
            self.stats['web_crawler']['pages_crawled'] = 0
    
    def _discover_with_patterns(self):
        """Discover endpoints with pattern-based brute-forcing"""
        self.logger.info("Running pattern-based API discovery...")
        self.stats['pattern_discovery']['enabled'] = True
        try:
            discovery = PatternBasedDiscovery(
                session=self.session,
                rate_limiter=self.rate_limiter
            )
            endpoints = discovery.discover(
                base_url=self.config.get('target.url'),
                max_attempts=self.config.get('scan.crawler.pattern_max_attempts', 100),
                timeout=5
            )
            count = self.inventory.add_many(endpoints)
            self.stats['pattern_discovery']['endpoints'] = count
            self.logger.info(f"Pattern discovery: {count} new endpoints")
        except Exception as e:
            self.logger.error(f"Pattern discovery failed: {e}")
    
    def _discover_with_playwright(self):
        """Discover endpoints with Playwright (JavaScript rendering)"""
        self.logger.info("Running Playwright crawler (JavaScript rendering)...")
        self.stats['playwright']['enabled'] = True
        
        try:
            # Get auth cookies if using cookie auth
            auth_cookies = None
            if self.config.get('authentication.type') == 'cookie':
                cookies = self.config.get('authentication.cookies', {})
                auth_cookies = [
                    {'name': k, 'value': v, 'domain': self.config.get('target.url').split('/')[2]}
                    for k, v in cookies.items()
                ]
            
            from dast_engine.crawler.playwright_crawler import run_playwright_crawler
            
            endpoints = run_playwright_crawler(
                base_url=self.config.get('target.url'),
                max_pages=self.config.get('scan.crawler.max_pages', 50),
                max_depth=self.config.get('scan.crawler.max_depth', 3),
                auth_cookies=auth_cookies,
                rate_limiter=self.rate_limiter,
                scope_filter=self.scope_filter,
            )
            
            count = self.inventory.add_many(endpoints)
            self.stats['playwright']['endpoints'] = count
            self.logger.info(f"Playwright crawler: {count} new endpoints")
        except Exception as e:
            self.logger.error(f"Playwright crawler failed: {e}")
    
    def _generate_result(self) -> DiscoveryResult:
        """
        Generate final crawl result
        
        Returns:
            DiscoveryResult object
        """
        # Get prioritized endpoints
        prioritized_endpoints = self.inventory.prioritize_for_testing()
        
        # Build result
        result = DiscoveryResult(
            target_url=self.config.get('target.url'),
            endpoints_discovered=prioritized_endpoints,
            total_endpoints=len(prioritized_endpoints),
            statistics=self.inventory.get_statistics()
        )
        
        return result
    
    def _log_summary(self):
        """Log discovery summary"""
        self.logger.info("=" * 60)
        self.logger.info("APPLICATION DISCOVERY SUMMARY")
        self.logger.info("=" * 60)
        self.logger.info(f"Target: {self.config.get('target.url')}")
        self.logger.info(f"Total Endpoints Discovered: {self.inventory.count()}")
        self.logger.info("")
        
        # By discovery method
        self.logger.info("Discovery Methods:")
        for method, stats in self.stats.items():
            if stats['enabled']:
                self.logger.info(f"  - {method}: {stats['endpoints']} endpoints")
        self.logger.info("")
        
        # By type
        type_counts = self.inventory.count_by_type()
        self.logger.info("Endpoint Types:")
        for type_name, count in type_counts.items():
            self.logger.info(f"  - {type_name}: {count}")
        self.logger.info("")
        
        # By method
        method_counts = self.inventory.count_by_method()
        self.logger.info("HTTP Methods:")
        for method_name, count in method_counts.items():
            self.logger.info(f"  - {method_name}: {count}")
        
        self.logger.info("=" * 60)
    
    def export_results(self, output_dir: str = "scan_results"):
        """
        Export discovery results to files
        
        Args:
            output_dir: Directory for output files
        """
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Export to JSON
        json_path = output_path / f"endpoints_{self.config.get('target.url').replace('://', '_').replace('/', '_')}.json"
        self.inventory.export_to_json(str(json_path))
        
        # Export to Burp format
        burp_path = output_path / f"endpoints_burp_{self.config.get('target.url').replace('://', '_').replace('/', '_')}.txt"
        self.inventory.export_to_burp_format(str(burp_path))
        
        self.logger.info(f"Results exported to {output_dir}/")


def run_discovery(config: TargetConfig, enable_js_rendering: bool = False) -> DiscoveryResult:
    """
    Convenience function to run discovery
    
    Args:
        config: Target configuration
        enable_js_rendering: Enable Playwright
    
    Returns:
        DiscoveryResult
    """
    engine = ApplicationDiscoveryEngine(config)
    result = engine.discover(enable_js_rendering=enable_js_rendering)
    engine.export_results()
    return result
