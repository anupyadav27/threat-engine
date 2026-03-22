"""
OpenAPI/Swagger Parser
Discovers and parses OpenAPI specifications to extract all API endpoints
"""

import json
import yaml
import requests
from typing import List, Dict, Optional
from urllib.parse import urljoin
import logging

from dast_engine.models import Endpoint, EndpointType, HTTPMethod, Parameter, ParameterLocation


class OpenAPIParser:
    """
    Parse OpenAPI 2.0 (Swagger) and OpenAPI 3.x specifications
    Automatically discovers spec files at common paths
    """
    
    # Common paths where OpenAPI specs are hosted
    COMMON_SPEC_PATHS = [
        '/swagger.json',
        '/swagger.yaml',
        '/openapi.json',
        '/openapi.yaml',
        '/api-docs',
        '/api-docs.json',
        '/api/swagger.json',
        '/api/openapi.json',
        '/v1/swagger.json',
        '/v2/swagger.json',
        '/v3/swagger.json',
        '/docs/swagger.json',
        '/docs/openapi.json',
        '/api/v1/swagger.json',
        '/api/v2/swagger.json',
        '/api/v3/swagger.json',
        '/swagger/v1/swagger.json',
        '/swagger-ui.json',
        '/.well-known/openapi.json',
    ]
    
    def __init__(self, session: Optional[requests.Session] = None):
        """
        Initialize OpenAPI parser
        
        Args:
            session: Optional requests session with authentication
        """
        self.session = session or requests.Session()
        self.logger = logging.getLogger('DASTScanner.OpenAPIParser')
    
    def discover_and_parse(self, base_url: str, timeout: int = 10) -> List[Endpoint]:
        """
        Automatically discover and parse OpenAPI specification
        
        Args:
            base_url: Base URL of the target
            timeout: Request timeout in seconds
        
        Returns:
            List of discovered endpoints
        """
        # Try to find OpenAPI spec
        spec_url = self._discover_spec(base_url, timeout)
        
        if not spec_url:
            self.logger.info("No OpenAPI specification found")
            return []
        
        # Parse the spec
        return self.parse_spec_from_url(spec_url, timeout)
    
    def _discover_spec(self, base_url: str, timeout: int) -> Optional[str]:
        """
        Try common paths to find OpenAPI specification
        
        Args:
            base_url: Base URL
            timeout: Request timeout
        
        Returns:
            URL of discovered spec or None
        """
        for path in self.COMMON_SPEC_PATHS:
            spec_url = urljoin(base_url, path)
            try:
                response = self.session.get(spec_url, timeout=timeout, allow_redirects=True)
                if response.status_code == 200:
                    # Check if it looks like OpenAPI spec
                    content_type = response.headers.get('Content-Type', '')
                    if 'json' in content_type or 'yaml' in content_type:
                        self.logger.info(f"Found OpenAPI spec at: {spec_url}")
                        return spec_url
            except Exception:
                continue
        
        return None
    
    def parse_spec_from_url(self, spec_url: str, timeout: int = 10) -> List[Endpoint]:
        """
        Download and parse OpenAPI spec from URL
        
        Args:
            spec_url: URL of the spec
            timeout: Request timeout
        
        Returns:
            List of endpoints
        """
        try:
            response = self.session.get(spec_url, timeout=timeout)
            response.raise_for_status()
            
            # Detect format
            content_type = response.headers.get('Content-Type', '')
            if 'yaml' in content_type or spec_url.endswith('.yaml') or spec_url.endswith('.yml'):
                spec = yaml.safe_load(response.text)
            else:
                spec = response.json()
            
            return self.parse_spec(spec, spec_url)
        except Exception as e:
            self.logger.error(f"Failed to parse OpenAPI spec from {spec_url}: {e}")
            return []
    
    def parse_spec(self, spec: Dict, base_url: str) -> List[Endpoint]:
        """
        Parse OpenAPI specification dictionary
        
        Args:
            spec: OpenAPI spec dictionary
            base_url: Base URL for resolving paths
        
        Returns:
            List of endpoints
        """
        endpoints = []
        
        # Detect OpenAPI version
        if 'openapi' in spec:
            version = spec['openapi']
            if version.startswith('3.'):
                endpoints = self._parse_openapi_v3(spec, base_url)
            else:
                self.logger.warning(f"Unsupported OpenAPI version: {version}")
        elif 'swagger' in spec:
            version = spec['swagger']
            if version.startswith('2.'):
                endpoints = self._parse_swagger_v2(spec, base_url)
            else:
                self.logger.warning(f"Unsupported Swagger version: {version}")
        else:
            self.logger.error("Invalid OpenAPI spec: missing version field")
        
        self.logger.info(f"Parsed {len(endpoints)} endpoints from OpenAPI spec")
        return endpoints
    
    def _parse_openapi_v3(self, spec: Dict, base_url: str) -> List[Endpoint]:
        """Parse OpenAPI 3.x specification"""
        endpoints = []
        
        # Get base path from servers
        server_url = base_url
        if 'servers' in spec and spec['servers']:
            server_url = spec['servers'][0].get('url', base_url)
            if not server_url.startswith('http'):
                server_url = urljoin(base_url, server_url)
        
        # Parse paths
        paths = spec.get('paths', {})
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                    continue
                
                # Build endpoint URL
                endpoint_url = urljoin(server_url, path.lstrip('/'))
                
                # Extract parameters
                parameters = self._extract_parameters_v3(operation, path_item)
                
                # Create endpoint
                endpoint = Endpoint(
                    url=endpoint_url,
                    method=HTTPMethod[method.upper()],
                    endpoint_type=EndpointType.API,
                    parameters=parameters,
                    description=operation.get('summary', operation.get('description', '')),
                    source='openapi_v3'
                )
                endpoints.append(endpoint)
        
        return endpoints
    
    def _parse_swagger_v2(self, spec: Dict, base_url: str) -> List[Endpoint]:
        """Parse Swagger 2.0 specification"""
        endpoints = []
        
        # Build base URL
        host = spec.get('host', '')
        base_path = spec.get('basePath', '')
        schemes = spec.get('schemes', ['http'])
        
        if host:
            server_url = f"{schemes[0]}://{host}{base_path}"
        else:
            server_url = urljoin(base_url, base_path)
        
        # Parse paths
        paths = spec.get('paths', {})
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                    continue
                
                # Build endpoint URL
                endpoint_url = urljoin(server_url, path.lstrip('/'))
                
                # Extract parameters
                parameters = self._extract_parameters_v2(operation, path_item)
                
                # Create endpoint
                endpoint = Endpoint(
                    url=endpoint_url,
                    method=HTTPMethod[method.upper()],
                    endpoint_type=EndpointType.API,
                    parameters=parameters,
                    description=operation.get('summary', operation.get('description', '')),
                    source='swagger_v2'
                )
                endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_parameters_v3(self, operation: Dict, path_item: Dict) -> List[Parameter]:
        """Extract parameters from OpenAPI 3.x operation"""
        parameters = []
        
        # Get parameters from operation and path level
        all_params = operation.get('parameters', []) + path_item.get('parameters', [])
        
        for param in all_params:
            # Handle parameter references
            if '$ref' in param:
                continue  # Skip for now, would need to resolve reference
            
            param_name = param.get('name', '')
            param_in = param.get('in', 'query')
            
            # Map location
            location_map = {
                'query': ParameterLocation.QUERY,
                'header': ParameterLocation.HEADER,
                'path': ParameterLocation.PATH,
                'cookie': ParameterLocation.COOKIE,
            }
            location = location_map.get(param_in, ParameterLocation.QUERY)
            
            # Get schema for type info
            schema = param.get('schema', {})
            param_type = schema.get('type', 'string')
            
            # Get example value
            example = param.get('example', schema.get('example'))
            
            parameters.append(Parameter(
                name=param_name,
                location=location,
                required=param.get('required', False),
                value=str(example) if example else '',
                param_type=param_type
            ))
        
        # Handle requestBody (for POST/PUT)
        request_body = operation.get('requestBody', {})
        if request_body:
            content = request_body.get('content', {})
            # Check for JSON body
            if 'application/json' in content:
                parameters.append(Parameter(
                    name='body',
                    location=ParameterLocation.BODY,
                    required=request_body.get('required', False),
                    value='{}',
                    param_type='object'
                ))
        
        return parameters
    
    def _extract_parameters_v2(self, operation: Dict, path_item: Dict) -> List[Parameter]:
        """Extract parameters from Swagger 2.0 operation"""
        parameters = []
        
        # Get parameters from operation and path level
        all_params = operation.get('parameters', []) + path_item.get('parameters', [])
        
        for param in all_params:
            param_name = param.get('name', '')
            param_in = param.get('in', 'query')
            
            # Map location
            location_map = {
                'query': ParameterLocation.QUERY,
                'header': ParameterLocation.HEADER,
                'path': ParameterLocation.PATH,
                'formData': ParameterLocation.BODY,
                'body': ParameterLocation.BODY,
            }
            location = location_map.get(param_in, ParameterLocation.QUERY)
            
            param_type = param.get('type', 'string')
            
            parameters.append(Parameter(
                name=param_name,
                location=location,
                required=param.get('required', False),
                value='',
                param_type=param_type
            ))
        
        return parameters
