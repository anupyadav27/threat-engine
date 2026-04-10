"""
Parameter Enricher - Main orchestrator for Step 3
Enriches endpoints with comprehensive parameter information
"""

from typing import List
import logging

from dast_engine.models import Endpoint, CrawlResult
from dast_engine.parameters.parameter_types import ParameterMetadata, EnrichedEndpoint
from dast_engine.parameters.parameter_extractor import ParameterExtractor
from dast_engine.parameters.parameter_analyzer import ParameterAnalyzer
from dast_engine.parameters.value_generator import ValueGenerator


class ParameterEnricher:
    """
    Main orchestrator for parameter identification (Step 3)
    Takes endpoints from Step 2 and enriches them with:
    - Extracted parameters from all sources
    - Type detection and analysis
    - Test value generation
    """
    
    def __init__(self):
        """Initialize parameter enricher"""
        self.extractor = ParameterExtractor()
        self.analyzer = ParameterAnalyzer()
        self.value_generator = ValueGenerator()
        self.logger = logging.getLogger('DASTScanner.ParameterEnricher')
    
    def enrich_endpoint(self, endpoint: Endpoint) -> EnrichedEndpoint:
        """
        Enrich a single endpoint with parameter information
        
        Args:
            endpoint: Basic endpoint from Step 2
        
        Returns:
            EnrichedEndpoint with full parameter metadata
        """
        self.logger.debug(f"Enriching endpoint: {endpoint.method.value} {endpoint.url}")
        
        # Extract parameters from all sources
        extracted = self.extractor.extract_all(endpoint)
        
        # Analyze parameters
        query_params = self.analyzer.analyze_batch(extracted['query'])
        path_params = self.analyzer.analyze_batch(extracted['path'])
        body_params = self.analyzer.analyze_batch(extracted['body'])
        header_params = self.analyzer.analyze_batch(extracted['headers'])
        cookie_params = self.analyzer.analyze_batch(extracted['cookies'])
        
        # Generate test values
        query_params = [self.value_generator.generate_test_values(p) for p in query_params]
        path_params = [self.value_generator.generate_test_values(p) for p in path_params]
        body_params = [self.value_generator.generate_test_values(p) for p in body_params]
        header_params = [self.value_generator.generate_test_values(p) for p in header_params]
        cookie_params = [self.value_generator.generate_test_values(p) for p in cookie_params]
        
        # Create enriched endpoint
        enriched = EnrichedEndpoint(
            url=endpoint.url,
            method=endpoint.method.value,
            endpoint_type=endpoint.endpoint_type.value,
            query_params=query_params,
            path_params=path_params,
            body_params=body_params,
            header_params=header_params,
            cookie_params=cookie_params,
        )
        
        # Count parameters
        enriched.count_parameters()
        
        self.logger.debug(
            f"Enriched {endpoint.url}: "
            f"{enriched.total_params} total params "
            f"({enriched.injectable_params} injectable, "
            f"{enriched.sensitive_params} sensitive)"
        )
        
        return enriched
    
    def enrich_endpoints(self, endpoints: List[Endpoint]) -> List[EnrichedEndpoint]:
        """
        Enrich multiple endpoints
        
        Args:
            endpoints: List of basic endpoints from Step 2
        
        Returns:
            List of enriched endpoints
        """
        self.logger.info(f"Enriching {len(endpoints)} endpoints with parameter information...")
        
        enriched_endpoints = []
        
        for i, endpoint in enumerate(endpoints, 1):
            try:
                enriched = self.enrich_endpoint(endpoint)
                enriched_endpoints.append(enriched)
                
                if i % 10 == 0:
                    self.logger.info(f"Progress: {i}/{len(endpoints)} endpoints enriched")
            
            except Exception as e:
                self.logger.error(f"Failed to enrich endpoint {endpoint.url}: {e}")
                continue
        
        self.logger.info(f"Enrichment complete: {len(enriched_endpoints)} endpoints ready for testing")
        
        return enriched_endpoints
    
    def enrich_crawl_result(self, crawl_result: CrawlResult) -> List[EnrichedEndpoint]:
        """
        Enrich all endpoints from a crawl result
        
        Args:
            crawl_result: CrawlResult from Step 2
        
        Returns:
            List of enriched endpoints
        """
        return self.enrich_endpoints(crawl_result.endpoints_discovered)
    
    def get_statistics(self, enriched_endpoints: List[EnrichedEndpoint]) -> dict:
        """
        Get statistics about enriched parameters
        
        Args:
            enriched_endpoints: List of enriched endpoints
        
        Returns:
            Statistics dictionary
        """
        total_params = sum(ep.total_params for ep in enriched_endpoints)
        injectable_params = sum(ep.injectable_params for ep in enriched_endpoints)
        sensitive_params = sum(ep.sensitive_params for ep in enriched_endpoints)
        
        # Count by location
        query_count = sum(len(ep.query_params) for ep in enriched_endpoints)
        path_count = sum(len(ep.path_params) for ep in enriched_endpoints)
        body_count = sum(len(ep.body_params) for ep in enriched_endpoints)
        header_count = sum(len(ep.header_params) for ep in enriched_endpoints)
        cookie_count = sum(len(ep.cookie_params) for ep in enriched_endpoints)
        
        # Count by type
        type_counts = {}
        for ep in enriched_endpoints:
            for param in ep.get_all_parameters():
                type_name = param.param_type.value
                type_counts[type_name] = type_counts.get(type_name, 0) + 1
        
        return {
            'total_endpoints': len(enriched_endpoints),
            'total_parameters': total_params,
            'injectable_parameters': injectable_params,
            'sensitive_parameters': sensitive_params,
            'parameters_by_location': {
                'query': query_count,
                'path': path_count,
                'body': body_count,
                'headers': header_count,
                'cookies': cookie_count,
            },
            'parameters_by_type': type_counts,
        }
    
    def export_to_json(self, enriched_endpoints: List[EnrichedEndpoint], output_path: str):
        """
        Export enriched endpoints to JSON
        
        Args:
            enriched_endpoints: List of enriched endpoints
            output_path: Output file path
        """
        import json
        
        data = {
            'endpoints': [ep.to_dict() for ep in enriched_endpoints],
            'statistics': self.get_statistics(enriched_endpoints),
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        self.logger.info(f"Exported {len(enriched_endpoints)} enriched endpoints to {output_path}")
    
    def log_summary(self, enriched_endpoints: List[EnrichedEndpoint]):
        """
        Log summary of parameter identification
        
        Args:
            enriched_endpoints: List of enriched endpoints
        """
        stats = self.get_statistics(enriched_endpoints)
        
        self.logger.info("=" * 60)
        self.logger.info("PARAMETER IDENTIFICATION SUMMARY (STEP 3)")
        self.logger.info("=" * 60)
        self.logger.info(f"Total Endpoints: {stats['total_endpoints']}")
        self.logger.info(f"Total Parameters: {stats['total_parameters']}")
        self.logger.info(f"  - Injectable: {stats['injectable_parameters']}")
        self.logger.info(f"  - Sensitive: {stats['sensitive_parameters']}")
        self.logger.info("")
        self.logger.info("Parameters by Location:")
        for location, count in stats['parameters_by_location'].items():
            self.logger.info(f"  - {location}: {count}")
        self.logger.info("")
        self.logger.info("Top Parameter Types:")
        sorted_types = sorted(
            stats['parameters_by_type'].items(),
            key=lambda x: x[1],
            reverse=True
        )
        for type_name, count in sorted_types[:10]:
            self.logger.info(f"  - {type_name}: {count}")
        self.logger.info("=" * 60)


def enrich_endpoints(endpoints: List[Endpoint]) -> List[EnrichedEndpoint]:
    """
    Convenience function to enrich endpoints
    
    Args:
        endpoints: List of endpoints from Step 2
    
    Returns:
        List of enriched endpoints
    """
    enricher = ParameterEnricher()
    return enricher.enrich_endpoints(endpoints)
