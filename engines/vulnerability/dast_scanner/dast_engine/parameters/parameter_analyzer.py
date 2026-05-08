"""
Parameter Analyzer - Analyzes parameter types, constraints, and characteristics
"""

import re
from typing import List, Optional, Any
import logging

from dast_engine.parameters.parameter_types import ParameterMetadata, ParameterType


class ParameterAnalyzer:
    """
    Analyze parameters to detect:
    - Data types (string, int, email, uuid, etc.)
    - Constraints (min/max length, patterns)
    - Characteristics (sensitive, injectable)
    """
    
    # Regex patterns for type detection
    PATTERNS = {
        ParameterType.EMAIL: r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
        ParameterType.UUID: r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        ParameterType.URL: r'^https?://[^\s]+$',
        ParameterType.IP_ADDRESS: r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
        ParameterType.DATE: r'^\d{4}-\d{2}-\d{2}$',  # ISO date
        ParameterType.DATETIME: r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',  # ISO datetime
        ParameterType.TIME: r'^\d{2}:\d{2}:\d{2}$',  # HH:MM:SS
        ParameterType.PHONE: r'^\+?[\d\s\-\(\)]{10,}$',
        ParameterType.CREDIT_CARD: r'^\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}$',
    }
    
    # Name-based type hints
    NAME_HINTS = {
        'email': ParameterType.EMAIL,
        'mail': ParameterType.EMAIL,
        'password': ParameterType.PASSWORD,
        'passwd': ParameterType.PASSWORD,
        'pwd': ParameterType.PASSWORD,
        'token': ParameterType.TOKEN,
        'api_key': ParameterType.TOKEN,
        'apikey': ParameterType.TOKEN,
        'key': ParameterType.TOKEN,
        'session': ParameterType.SESSION_ID,
        'sid': ParameterType.SESSION_ID,
        'sessionid': ParameterType.SESSION_ID,
        'url': ParameterType.URL,
        'link': ParameterType.URL,
        'href': ParameterType.URL,
        'uuid': ParameterType.UUID,
        'guid': ParameterType.UUID,
        'id': ParameterType.INTEGER,
        'count': ParameterType.INTEGER,
        'age': ParameterType.INTEGER,
        'phone': ParameterType.PHONE,
        'telephone': ParameterType.PHONE,
        'date': ParameterType.DATE,
        'time': ParameterType.TIME,
        'datetime': ParameterType.DATETIME,
        'timestamp': ParameterType.DATETIME,
        'ip': ParameterType.IP_ADDRESS,
        'ipaddress': ParameterType.IP_ADDRESS,
        'image': ParameterType.IMAGE,
        'file': ParameterType.FILE,
        'upload': ParameterType.FILE,
    }
    
    # Sensitive parameter name patterns
    SENSITIVE_PATTERNS = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'private', 'credential', 'auth', 'session', 'ssn', 'credit', 'card',
        'cvv', 'pin', 'security'
    ]
    
    def __init__(self):
        self.logger = logging.getLogger('DASTScanner.ParameterAnalyzer')
    
    def analyze(self, param: ParameterMetadata) -> ParameterMetadata:
        """
        Analyze a parameter to detect its type and constraints
        
        Args:
            param: Parameter metadata to analyze
        
        Returns:
            Updated parameter metadata
        """
        # Skip if type already determined with high confidence
        if param.param_type != ParameterType.UNKNOWN and param.confidence >= 0.9:
            return param
        
        # Detect type
        param.param_type = self._detect_type(param)
        
        # Detect if sensitive
        param.sensitive = self._is_sensitive(param)
        
        # Detect injectability
        param.injectable = self._is_injectable(param)
        
        # Infer constraints from examples
        self._infer_constraints(param)
        
        # Set format hint
        param.format_hint = self._get_format_hint(param)
        
        return param
    
    def _detect_type(self, param: ParameterMetadata) -> ParameterType:
        """
        Detect parameter type based on name and example values
        
        Args:
            param: Parameter metadata
        
        Returns:
            Detected parameter type
        """
        # Priority 1: Check name hints
        name_lower = param.name.lower()
        for hint, param_type in self.NAME_HINTS.items():
            if hint in name_lower:
                return param_type
        
        # Priority 2: Analyze example values
        if param.example_values:
            return self._detect_type_from_values(param.example_values)
        
        # Default: string
        return ParameterType.STRING
    
    def _detect_type_from_values(self, values: List[Any]) -> ParameterType:
        """
        Detect type from example values
        
        Args:
            values: List of example values
        
        Returns:
            Detected parameter type
        """
        if not values:
            return ParameterType.STRING
        
        # Get first non-null value
        sample = None
        for v in values:
            if v is not None and v != '':
                sample = v
                break
        
        if sample is None:
            return ParameterType.STRING
        
        # Convert to string for pattern matching
        str_value = str(sample)
        
        # Check patterns in order of specificity
        for param_type, pattern in self.PATTERNS.items():
            if re.match(pattern, str_value, re.IGNORECASE):
                return param_type
        
        # Check if integer
        if isinstance(sample, int) or (isinstance(sample, str) and sample.isdigit()):
            return ParameterType.INTEGER
        
        # Check if float
        if isinstance(sample, float):
            return ParameterType.FLOAT
        
        try:
            float(sample)
            return ParameterType.FLOAT
        except (ValueError, TypeError):
            pass
        
        # Check if boolean
        if isinstance(sample, bool):
            return ParameterType.BOOLEAN
        
        if isinstance(sample, str):
            lower_val = str_value.lower()
            if lower_val in ['true', 'false', 'yes', 'no', '1', '0']:
                return ParameterType.BOOLEAN
        
        # Check if array
        if isinstance(sample, list):
            return ParameterType.ARRAY
        
        # Check if object
        if isinstance(sample, dict):
            return ParameterType.OBJECT
        
        # Default: string
        return ParameterType.STRING
    
    def _is_sensitive(self, param: ParameterMetadata) -> bool:
        """
        Determine if parameter contains sensitive data
        
        Args:
            param: Parameter metadata
        
        Returns:
            True if sensitive
        """
        name_lower = param.name.lower()
        
        # Check sensitive patterns
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern in name_lower:
                return True
        
        # Check by type
        sensitive_types = [
            ParameterType.PASSWORD,
            ParameterType.TOKEN,
            ParameterType.SESSION_ID,
            ParameterType.CREDIT_CARD,
        ]
        
        if param.param_type in sensitive_types:
            return True
        
        return False
    
    def _is_injectable(self, param: ParameterMetadata) -> bool:
        """
        Determine if parameter can be tested for injection attacks
        
        Args:
            param: Parameter metadata
        
        Returns:
            True if injectable
        """
        # File uploads are not injectable with text payloads
        if param.param_type in [ParameterType.FILE, ParameterType.IMAGE]:
            return False
        
        # Boolean parameters have limited attack surface
        if param.param_type == ParameterType.BOOLEAN:
            return False
        
        # Most other parameters can be tested
        return True
    
    def _infer_constraints(self, param: ParameterMetadata):
        """
        Infer constraints from example values
        
        Args:
            param: Parameter metadata (modified in place)
        """
        if not param.example_values:
            return
        
        # For string-like types, infer length constraints
        if param.param_type in [ParameterType.STRING, ParameterType.EMAIL, ParameterType.URL]:
            lengths = [len(str(v)) for v in param.example_values if v is not None]
            if lengths:
                param.min_length = min(lengths)
                param.max_length = max(lengths) * 2  # Allow some flexibility
        
        # For numeric types, infer value constraints
        if param.param_type in [ParameterType.INTEGER, ParameterType.FLOAT]:
            try:
                numeric_values = [float(v) for v in param.example_values if v is not None]
                if numeric_values:
                    param.min_value = min(numeric_values)
                    param.max_value = max(numeric_values) * 2
            except (ValueError, TypeError):
                pass
        
        # Check if parameter has enum-like values
        unique_values = list(set(param.example_values))
        if len(unique_values) <= 10 and len(param.example_values) > len(unique_values):
            # Looks like an enum
            param.enum_values = unique_values
    
    def _get_format_hint(self, param: ParameterMetadata) -> Optional[str]:
        """
        Get format hint for parameter
        
        Args:
            param: Parameter metadata
        
        Returns:
            Format hint string
        """
        format_map = {
            ParameterType.EMAIL: 'email',
            ParameterType.UUID: 'uuid',
            ParameterType.URL: 'uri',
            ParameterType.DATE: 'date',
            ParameterType.DATETIME: 'date-time',
            ParameterType.TIME: 'time',
            ParameterType.IP_ADDRESS: 'ipv4',
            ParameterType.PASSWORD: 'password',
        }
        
        return format_map.get(param.param_type)
    
    def analyze_batch(self, params: List[ParameterMetadata]) -> List[ParameterMetadata]:
        """
        Analyze multiple parameters
        
        Args:
            params: List of parameter metadata
        
        Returns:
            List of analyzed parameters
        """
        return [self.analyze(param) for param in params]
