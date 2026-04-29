"""
Parameter Extractor - Extracts parameters from various sources
"""

from urllib.parse import urlparse, parse_qs, parse_qsl
from typing import List, Dict, Any, Optional
import json
import re
import logging

from dast_engine.parameters.parameter_types import ParameterMetadata, ParameterType
from dast_engine.models import Endpoint, ParameterLocation


class ParameterExtractor:
    """
    Extract parameters from various sources:
    - Query parameters (from URL)
    - Path parameters (from URL patterns)
    - Body parameters (from JSON/form data)
    - Headers (standard and custom)
    - Cookies
    """
    
    def __init__(self):
        self.logger = logging.getLogger('DASTScanner.ParameterExtractor')
    
    def extract_all(self, endpoint: Endpoint) -> Dict[str, List[ParameterMetadata]]:
        """
        Extract all parameters from an endpoint
        
        Args:
            endpoint: Endpoint object from Step 2
        
        Returns:
            Dictionary with parameter lists by location
        """
        return {
            'query': self.extract_query_params(endpoint.url, endpoint=endpoint),
            'path': self.extract_path_params(endpoint.url),
            'body': self.extract_body_params(endpoint),
            'headers': self.extract_header_params(endpoint),
            'cookies': self.extract_cookie_params(endpoint),
        }
    
    def extract_query_params(self, url: str, endpoint=None) -> List[ParameterMetadata]:
        """
        Extract query parameters from URL
        
        Args:
            url: URL string
        
        Returns:
            List of parameter metadata
        """
        params = []
        
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            seen_names = set()

            for name, values in query_params.items():
                example_values = values if isinstance(values, list) else [values]
                param = ParameterMetadata(
                    name=name,
                    location='query',
                    param_type=ParameterType.UNKNOWN,
                    example_values=example_values,
                    source='url_query'
                )
                params.append(param)
                seen_names.add(name)

            # Also pick up QUERY-located params stored on the endpoint object
            # (e.g. GET form fields assigned ParameterLocation.QUERY by form_detector)
            if endpoint is not None:
                for p in getattr(endpoint, 'parameters', []):
                    loc_str = str(getattr(p, 'location', ''))
                    # Match 'QUERY', 'ParameterLocation.QUERY', or 'query'
                    if 'QUERY' in loc_str.upper():
                        if p.name not in seen_names:
                            param = ParameterMetadata(
                                name=p.name,
                                location='query',
                                param_type=ParameterType.UNKNOWN,
                                example_values=list(p.example_values) if p.example_values else [],
                                source='form_get_field'
                            )
                            params.append(param)
                            seen_names.add(p.name)

        except Exception as e:
            self.logger.error(f"Error extracting query params from {url}: {e}")

        return params
    
    def extract_path_params(self, url: str) -> List[ParameterMetadata]:
        """
        Extract path parameters from URL
        Detects patterns like:
        - /users/{id}
        - /users/:id
        - /users/123 (numeric path segment)
        
        Args:
            url: URL string
        
        Returns:
            List of parameter metadata
        """
        params = []
        
        try:
            parsed = urlparse(url)
            path = parsed.path
            segments = [s for s in path.split('/') if s]
            
            # Pattern 1: {param} or :param templates
            template_pattern = r'\{(\w+)\}|:(\w+)'
            for match in re.finditer(template_pattern, path):
                param_name = match.group(1) or match.group(2)
                param = ParameterMetadata(
                    name=param_name,
                    location='path',
                    param_type=ParameterType.UNKNOWN,
                    required=True,  # Path params are always required
                    source='url_template'
                )
                params.append(param)
            
            # Pattern 2: Detect numeric/uuid segments as potential params
            for i, segment in enumerate(segments):
                # Skip common static segments
                if segment.lower() in ['api', 'v1', 'v2', 'v3', 'rest']:
                    continue
                
                # Numeric ID
                if re.match(r'^\d+$', segment):
                    param = ParameterMetadata(
                        name=f'id_{i}',  # Generic name
                        location='path',
                        param_type=ParameterType.INTEGER,
                        example_values=[segment],
                        required=True,
                        source='path_segment'
                    )
                    params.append(param)
                
                # UUID
                elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', segment, re.I):
                    param = ParameterMetadata(
                        name=f'uuid_{i}',
                        location='path',
                        param_type=ParameterType.UUID,
                        example_values=[segment],
                        required=True,
                        source='path_segment'
                    )
                    params.append(param)
        
        except Exception as e:
            self.logger.error(f"Error extracting path params from {url}: {e}")
        
        return params
    
    def extract_body_params(self, endpoint: Endpoint) -> List[ParameterMetadata]:
        """
        Extract body parameters from endpoint
        Uses parameters already discovered in Step 2
        
        Args:
            endpoint: Endpoint object
        
        Returns:
            List of parameter metadata
        """
        params = []
        
        try:
            # Get existing parameters from Step 2
            for param in endpoint.parameters:
                if param.location == ParameterLocation.BODY:
                    # Convert to ParameterMetadata
                    meta = ParameterMetadata(
                        name=param.name,
                        location='body',
                        param_type=ParameterType.UNKNOWN,  # Will be analyzed
                        example_values=param.example_values if param.example_values else [],
                        required=param.required,
                        source='step2_discovery'
                    )
                    params.append(meta)
        
        except Exception as e:
            self.logger.error(f"Error extracting body params: {e}")
        
        return params
    
    def extract_json_body_params(self, json_data: Any, path: str = '') -> List[ParameterMetadata]:
        """
        Extract parameters from JSON body structure
        Handles nested objects and arrays
        
        Args:
            json_data: JSON data (dict, list, or primitive)
            path: Current path in JSON structure (for nested params)
        
        Returns:
            List of parameter metadata
        """
        params = []
        
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                param_path = f"{path}.{key}" if path else key
                
                if isinstance(value, (dict, list)):
                    # Nested structure - recurse
                    params.extend(self.extract_json_body_params(value, param_path))
                else:
                    # Leaf value
                    param = ParameterMetadata(
                        name=param_path,
                        location='body',
                        param_type=ParameterType.UNKNOWN,
                        example_values=[value] if value is not None else [],
                        source='json_body'
                    )
                    params.append(param)
        
        elif isinstance(json_data, list) and json_data:
            # Array - analyze first element
            params.extend(self.extract_json_body_params(json_data[0], f"{path}[0]"))
        
        return params
    
    def extract_header_params(self, endpoint: Endpoint) -> List[ParameterMetadata]:
        """
        Extract header parameters
        Includes both standard and custom headers
        
        Args:
            endpoint: Endpoint object
        
        Returns:
            List of parameter metadata
        """
        params = []
        
        # Standard testable headers
        standard_headers = [
            'User-Agent',
            'Referer',
            'X-Forwarded-For',
            'X-Real-IP',
            'Host',
            'Accept',
            'Accept-Language',
            'Accept-Encoding',
            'Content-Type',
        ]
        
        for header in standard_headers:
            param = ParameterMetadata(
                name=header,
                location='header',
                param_type=ParameterType.STRING,
                required=False,
                injectable=True,
                source='standard_headers',
                confidence=0.8  # Lower confidence as headers might not be checked
            )
            params.append(param)
        
        # Check for custom headers in endpoint parameters
        for param in endpoint.parameters:
            if param.location == ParameterLocation.HEADER:
                meta = ParameterMetadata(
                    name=param.name,
                    location='header',
                    param_type=ParameterType.UNKNOWN,
                    example_values=param.example_values if param.example_values else [],
                    required=param.required,
                    source='step2_discovery'
                )
                params.append(meta)
        
        return params
    
    def extract_cookie_params(self, endpoint: Endpoint) -> List[ParameterMetadata]:
        """
        Extract cookie parameters
        
        Args:
            endpoint: Endpoint object
        
        Returns:
            List of parameter metadata
        """
        params = []
        
        # Common cookie patterns to test
        common_cookies = [
            'session',
            'sessionid',
            'sid',
            'token',
            'auth',
            'jwt',
            'PHPSESSID',
            'JSESSIONID',
            'ASP.NET_SessionId',
        ]
        
        for cookie_name in common_cookies:
            param = ParameterMetadata(
                name=cookie_name,
                location='cookie',
                param_type=ParameterType.SESSION_ID,
                required=False,
                sensitive=True,  # Cookies often contain sensitive data
                injectable=True,
                source='common_cookies',
                confidence=0.6  # Lower confidence as cookies might not exist
            )
            params.append(param)
        
        # Check for cookies discovered in Step 2
        for param in endpoint.parameters:
            if param.location == ParameterLocation.COOKIE:
                meta = ParameterMetadata(
                    name=param.name,
                    location='cookie',
                    param_type=ParameterType.UNKNOWN,
                    example_values=param.example_values if param.example_values else [],
                    required=param.required,
                    sensitive=True,
                    source='step2_discovery'
                )
                params.append(meta)
        
        return params
    
    def extract_from_openapi_param(self, openapi_param: Dict) -> ParameterMetadata:
        """
        Extract parameter metadata from OpenAPI specification
        
        Args:
            openapi_param: OpenAPI parameter object
        
        Returns:
            ParameterMetadata object
        """
        name = openapi_param.get('name', 'unknown')
        location = openapi_param.get('in', 'query')
        required = openapi_param.get('required', False)
        
        # Get schema info
        schema = openapi_param.get('schema', {})
        param_type_str = schema.get('type', 'string')
        format_hint = schema.get('format')
        
        # Map OpenAPI types to our types
        type_mapping = {
            'string': ParameterType.STRING,
            'integer': ParameterType.INTEGER,
            'number': ParameterType.FLOAT,
            'boolean': ParameterType.BOOLEAN,
            'array': ParameterType.ARRAY,
            'object': ParameterType.OBJECT,
        }
        
        param_type = type_mapping.get(param_type_str, ParameterType.UNKNOWN)
        
        # Get constraints
        min_length = schema.get('minLength')
        max_length = schema.get('maxLength')
        min_value = schema.get('minimum')
        max_value = schema.get('maximum')
        pattern = schema.get('pattern')
        enum_values = schema.get('enum')
        
        # Get example
        example = openapi_param.get('example', schema.get('example'))
        example_values = [example] if example is not None else []
        
        return ParameterMetadata(
            name=name,
            location=location,
            param_type=param_type,
            example_values=example_values,
            required=required,
            min_length=min_length,
            max_length=max_length,
            min_value=min_value,
            max_value=max_value,
            pattern=pattern,
            enum_values=enum_values,
            format_hint=format_hint,
            source='openapi_spec',
            confidence=1.0  # High confidence from spec
        )
