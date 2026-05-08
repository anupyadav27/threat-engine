"""
Endpoint Inventory - Storage and Management
Stores discovered endpoints with deduplication and risk scoring
"""

import json
from typing import List, Dict, Optional, Set
from collections import defaultdict
from pathlib import Path
import logging

from dast_engine.models import Endpoint, EndpointType, HTTPMethod


class EndpointInventory:
    """
    Manages discovered endpoints with deduplication
    Provides filtering, sorting, and persistence
    """
    
    def __init__(self):
        """Initialize endpoint inventory"""
        self.endpoints: List[Endpoint] = []
        self._url_method_set: Set[tuple] = set()  # For deduplication
        self.logger = logging.getLogger('DASTScanner.Inventory')
    
    def add(self, endpoint: Endpoint) -> bool:
        """
        Add endpoint to inventory (with deduplication)

        Args:
            endpoint: Endpoint to add

        Returns:
            True if added, False if duplicate
        """
        # Reject non-HTTP(S) endpoints (e.g. javascript:, mailto:)
        from urllib.parse import urlparse
        parsed_scheme = urlparse(endpoint.url).scheme.lower()
        if parsed_scheme not in ('http', 'https'):
            self.logger.debug(f"Skipping non-HTTP endpoint: {endpoint.url}")
            return False

        # Deduplicate by URL + method combination
        key = (endpoint.url, endpoint.method.value)
        
        if key in self._url_method_set:
            return False
        
        self.endpoints.append(endpoint)
        self._url_method_set.add(key)
        return True
    
    def add_many(self, endpoints: List[Endpoint]) -> int:
        """
        Add multiple endpoints
        
        Args:
            endpoints: List of endpoints
        
        Returns:
            Number of new endpoints added
        """
        count = 0
        for endpoint in endpoints:
            if self.add(endpoint):
                count += 1
        return count
    
    def get_all(self) -> List[Endpoint]:
        """Get all endpoints"""
        return self.endpoints
    
    def get_by_type(self, endpoint_type: EndpointType) -> List[Endpoint]:
        """
        Get endpoints by type
        
        Args:
            endpoint_type: Type of endpoints to retrieve
        
        Returns:
            Filtered list of endpoints
        """
        return [ep for ep in self.endpoints if ep.endpoint_type == endpoint_type]
    
    def get_by_method(self, method: HTTPMethod) -> List[Endpoint]:
        """
        Get endpoints by HTTP method
        
        Args:
            method: HTTP method
        
        Returns:
            Filtered list of endpoints
        """
        return [ep for ep in self.endpoints if ep.method == method]
    
    def get_api_endpoints(self) -> List[Endpoint]:
        """Get only API endpoints"""
        return self.get_by_type(EndpointType.API)
    
    def get_web_pages(self) -> List[Endpoint]:
        """Get only web page endpoints"""
        return self.get_by_type(EndpointType.WEB_PAGE)
    
    def get_forms(self) -> List[Endpoint]:
        """Get only form endpoints"""
        return self.get_by_type(EndpointType.FORM)
    
    def count(self) -> int:
        """Get total number of endpoints"""
        return len(self.endpoints)
    
    def count_by_type(self) -> Dict[str, int]:
        """
        Count endpoints by type
        
        Returns:
            Dictionary of type -> count
        """
        counts = defaultdict(int)
        for endpoint in self.endpoints:
            counts[endpoint.endpoint_type.value] = counts.get(endpoint.endpoint_type.value, 0) + 1
        return dict(counts)
    
    def count_by_method(self) -> Dict[str, int]:
        """
        Count endpoints by HTTP method
        
        Returns:
            Dictionary of method -> count
        """
        counts = defaultdict(int)
        for endpoint in self.endpoints:
            counts[endpoint.method.value] = counts.get(endpoint.method.value, 0) + 1
        return dict(counts)
    
    def get_statistics(self) -> Dict:
        """
        Get inventory statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            'total': self.count(),
            'by_type': self.count_by_type(),
            'by_method': self.count_by_method(),
            'has_parameters': sum(1 for ep in self.endpoints if ep.parameters),
            'requires_auth': sum(1 for ep in self.endpoints if ep.auth_required),
        }
    
    def prioritize_for_testing(self) -> List[Endpoint]:
        """
        Prioritize endpoints for security testing
        Order by risk/importance:
        1. Forms (high risk - injection, CSRF)
        2. APIs with parameters (high risk - injection, parameter tampering)
        3. APIs without parameters
        4. Web pages with parameters
        5. Web pages without parameters
        
        Returns:
            Sorted list of endpoints
        """
        def priority_score(endpoint: Endpoint) -> int:
            score = 0
            
            # Type priority
            if endpoint.endpoint_type == EndpointType.FORM:
                score += 1000
            elif endpoint.endpoint_type == EndpointType.API:
                score += 500
            
            # Has parameters
            if endpoint.parameters:
                score += 200
            
            # Write operations are higher risk
            if endpoint.method in [HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.DELETE]:
                score += 100
            
            # More parameters = more attack surface
            score += len(endpoint.parameters) * 10
            
            return score
        
        return sorted(self.endpoints, key=priority_score, reverse=True)
    
    def export_to_json(self, output_path: str):
        """
        Export inventory to JSON file
        
        Args:
            output_path: Path to output JSON file
        """
        data = {
            'statistics': self.get_statistics(),
            'endpoints': [ep.to_dict() for ep in self.endpoints]
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        self.logger.info(f"Exported {len(self.endpoints)} endpoints to {output_path}")
    
    def import_from_json(self, input_path: str) -> int:
        """
        Import endpoints from JSON file
        
        Args:
            input_path: Path to JSON file
        
        Returns:
            Number of endpoints imported
        """
        try:
            with open(input_path, 'r') as f:
                data = json.load(f)
            
            endpoint_dicts = data.get('endpoints', [])
            count = 0
            
            for ep_dict in endpoint_dicts:
                endpoint = Endpoint.from_dict(ep_dict)
                if self.add(endpoint):
                    count += 1
            
            self.logger.info(f"Imported {count} new endpoints from {input_path}")
            return count
        except Exception as e:
            self.logger.error(f"Failed to import endpoints: {e}")
            return 0
    
    def export_to_burp_format(self, output_path: str):
        """
        Export to Burp Suite compatible format
        
        Args:
            output_path: Path to output file
        """
        # Simple text format with URL\tMETHOD
        with open(output_path, 'w') as f:
            for endpoint in self.endpoints:
                f.write(f"{endpoint.url}\t{endpoint.method.value}\n")
        
        self.logger.info(f"Exported to Burp format: {output_path}")
    
    def clear(self):
        """Clear all endpoints"""
        self.endpoints.clear()
        self._url_method_set.clear()
    
    def __len__(self):
        """Support len() function"""
        return self.count()
    
    def __iter__(self):
        """Support iteration"""
        return iter(self.endpoints)
