"""
Crawler Package
Application Discovery Engine - Step 2 of DAST Scanner
"""

from dast_engine.crawler.discovery_engine import ApplicationDiscoveryEngine, run_discovery
from dast_engine.crawler.endpoint_inventory import EndpointInventory
from dast_engine.crawler.web_crawler import WebCrawler
from dast_engine.crawler.openapi_parser import OpenAPIParser
from dast_engine.crawler.pattern_discovery import PatternBasedDiscovery
from dast_engine.crawler.js_analyzer import JavaScriptAnalyzer

__all__ = [
    'ApplicationDiscoveryEngine',
    'run_discovery',
    'EndpointInventory',
    'WebCrawler',
    'OpenAPIParser',
    'PatternBasedDiscovery',
    'JavaScriptAnalyzer',
]
