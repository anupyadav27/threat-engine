"""
Value Generator - Generates test values for parameters
Creates boundary values, invalid values, and attack payloads
"""

from typing import List, Any
import random
import string
import logging
import os
import sys

from dast_engine.parameters.parameter_types import ParameterMetadata, ParameterType

# Import payload library
try:
    # Add payloads directory to path
    payloads_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'payloads')
    if os.path.exists(payloads_dir) and payloads_dir not in sys.path:
        sys.path.insert(0, os.path.dirname(payloads_dir))
    
    from payloads import PayloadLoader, PayloadEncoder
    PAYLOADS_AVAILABLE = True
except ImportError as e:
    PAYLOADS_AVAILABLE = False
    PayloadLoader = None
    PayloadEncoder = None


class ValueGenerator:
    """
    Generate test values for parameters:
    - Valid boundary values (min, max, empty)
    - Invalid values (wrong type, overflow)
    - Attack payloads (using payload library from Step 4)
    """
    
    def __init__(self):
        self.logger = logging.getLogger('DASTScanner.ValueGenerator')
        
        # Initialize payload loader if available
        if PAYLOADS_AVAILABLE:
            try:
                self.payload_loader = PayloadLoader()
                self.payload_encoder = PayloadEncoder()
                self.logger.info("Payload library loaded successfully")
            except Exception as e:
                self.logger.warning(f"Could not load payload library: {e}")
                self.payload_loader = None
                self.payload_encoder = None
        else:
            self.logger.warning("Payload library not available - using fallback payloads")
            self.payload_loader = None
            self.payload_encoder = None
    
    @staticmethod
    def _is_string_like(param_type: ParameterType) -> bool:
        """Check if parameter type is string-like"""
        return param_type in [
            ParameterType.STRING,
            ParameterType.EMAIL,
            ParameterType.URL,
            ParameterType.UUID,
            ParameterType.PASSWORD,
            ParameterType.TOKEN,
            ParameterType.SESSION_ID,
            ParameterType.IP_ADDRESS,
            ParameterType.DOMAIN,
            ParameterType.PHONE,
            ParameterType.CREDIT_CARD,
            ParameterType.DATE,
            ParameterType.DATETIME,
            ParameterType.TIME,
        ]
    
    @staticmethod
    def _is_numeric(param_type: ParameterType) -> bool:
        """Check if parameter type is numeric"""
        return param_type in [ParameterType.INTEGER, ParameterType.FLOAT]
    
    def generate_test_values(self, param: ParameterMetadata) -> ParameterMetadata:
        """
        Generate all test values for a parameter
        
        Args:
            param: Parameter metadata
        
        Returns:
            Parameter with test_values, boundary_values, and invalid_values populated
        """
        param.test_values = self._generate_valid_values(param)
        param.boundary_values = self._generate_boundary_values(param)
        param.invalid_values = self._generate_invalid_values(param)
        
        return param
    
    def _generate_valid_values(self, param: ParameterMetadata) -> List[Any]:
        """Generate valid test values based on parameter type"""
        values = []
        
        # Type-specific valid values
        type_generators = {
            ParameterType.STRING: self._generate_string_values,
            ParameterType.INTEGER: self._generate_integer_values,
            ParameterType.FLOAT: self._generate_float_values,
            ParameterType.BOOLEAN: self._generate_boolean_values,
            ParameterType.EMAIL: self._generate_email_values,
            ParameterType.URL: self._generate_url_values,
            ParameterType.UUID: self._generate_uuid_values,
            ParameterType.DATE: self._generate_date_values,
            ParameterType.DATETIME: self._generate_datetime_values,
            ParameterType.IP_ADDRESS: self._generate_ip_values,
            ParameterType.PHONE: self._generate_phone_values,
        }
        
        generator = type_generators.get(param.param_type, self._generate_string_values)
        values = generator(param)
        
        # Add example values if available
        if param.example_values:
            values.extend(param.example_values[:2])
        
        return list(set(values))[:10]  # Limit to 10 unique values
    
    def _generate_boundary_values(self, param: ParameterMetadata) -> List[Any]:
        """Generate boundary test values"""
        values = []
        
        # Empty value
        if not param.required:
            values.extend(['', None])
        
        # String length boundaries
        if self._is_string_like(param.param_type):
            if param.min_length:
                values.append('a' * param.min_length)
                values.append('a' * (param.min_length - 1))  # Below min
            
            if param.max_length:
                values.append('a' * param.max_length)
                values.append('a' * (param.max_length + 1))  # Above max
            
            # Very long string
            values.append('a' * 1000)
            values.append('a' * 10000)
        
        # Numeric boundaries
        if self._is_numeric(param.param_type):
            if param.min_value is not None:
                values.append(param.min_value)
                values.append(param.min_value - 1)
            
            if param.max_value is not None:
                values.append(param.max_value)
                values.append(param.max_value + 1)
            
            # Common edge cases
            values.extend([0, -1, 1, 2147483647, -2147483648])  # 32-bit int limits
        
        return values
    
    def _generate_invalid_values(self, param: ParameterMetadata) -> List[Any]:
        """Generate invalid values for negative testing"""
        values = []
        
        # Type mismatch
        if param.param_type == ParameterType.INTEGER:
            values.extend(['not_a_number', 'abc', '12.34.56'])
        
        elif param.param_type == ParameterType.EMAIL:
            values.extend(['not-an-email', '@example.com', 'user@', 'user@@example.com'])
        
        elif param.param_type == ParameterType.URL:
            values.extend(['not-a-url', 'htp://invalid', 'javascript:alert(1)'])
        
        elif param.param_type == ParameterType.UUID:
            values.extend(['not-a-uuid', '12345', 'abcd-efgh-ijkl'])
        
        # Common invalid patterns
        values.extend([
            '../../../etc/passwd',  # Path traversal
            '<script>alert(1)</script>',  # XSS
            "' OR '1'='1",  # SQL injection
            '${7*7}',  # Template injection
            '\x00',  # Null byte
        ])
        
        return values
    
    # Type-specific value generators
    
    def _generate_string_values(self, param: ParameterMetadata) -> List[str]:
        """Generate string test values"""
        values = []
        
        # Basic strings
        values.extend(['test', 'example', 'value123'])
        
        # Special characters
        values.extend(['test@123', 'test spaces', 'test\ttab', 'test\nnewline'])
        
        # Unicode
        values.extend(['тест', '测试', 'テスト'])
        
        # If enum values exist, use them
        if param.enum_values:
            values.extend(param.enum_values)
        
        return values
    
    def _generate_integer_values(self, param: ParameterMetadata) -> List[int]:
        """Generate integer test values"""
        values = [0, 1, -1, 10, 100, 1000]
        
        if param.enum_values:
            values.extend([int(v) for v in param.enum_values if str(v).isdigit()])
        
        return values
    
    def _generate_float_values(self, param: ParameterMetadata) -> List[float]:
        """Generate float test values"""
        return [0.0, 1.0, -1.0, 0.5, 10.5, 100.99, -100.99]
    
    def _generate_boolean_values(self, param: ParameterMetadata) -> List[Any]:
        """Generate boolean test values"""
        return [True, False, 'true', 'false', 'yes', 'no', 1, 0]
    
    def _generate_email_values(self, param: ParameterMetadata) -> List[str]:
        """Generate email test values"""
        return [
            'test@example.com',
            'user.name@example.com',
            'user+tag@example.co.uk',
            'test123@test-domain.com',
        ]
    
    def _generate_url_values(self, param: ParameterMetadata) -> List[str]:
        """Generate URL test values"""
        return [
            'http://example.com',
            'https://example.com/path',
            'https://example.com/path?query=value',
            'http://subdomain.example.com:8080/path',
        ]
    
    def _generate_uuid_values(self, param: ParameterMetadata) -> List[str]:
        """Generate UUID test values"""
        return [
            '550e8400-e29b-41d4-a716-446655440000',
            'a1b2c3d4-e5f6-4a5b-8c7d-9e0f1a2b3c4d',
            '00000000-0000-0000-0000-000000000000',
        ]
    
    def _generate_date_values(self, param: ParameterMetadata) -> List[str]:
        """Generate date test values"""
        return [
            '2024-01-01',
            '2024-12-31',
            '2000-01-01',
            '1970-01-01',
        ]
    
    def _generate_datetime_values(self, param: ParameterMetadata) -> List[str]:
        """Generate datetime test values"""
        return [
            '2024-01-01T00:00:00Z',
            '2024-12-31T23:59:59Z',
            '2024-06-15T12:30:45.123Z',
        ]
    
    def _generate_ip_values(self, param: ParameterMetadata) -> List[str]:
        """Generate IP address test values"""
        return [
            '127.0.0.1',
            '192.168.1.1',
            '10.0.0.1',
            '8.8.8.8',
        ]
    
    def _generate_phone_values(self, param: ParameterMetadata) -> List[str]:
        """Generate phone number test values"""
        return [
            '+1-555-123-4567',
            '555-123-4567',
            '(555) 123-4567',
            '+44 20 7123 4567',
        ]
    
    def generate_attack_payloads(self, param: ParameterMetadata, attack_type: str = 'all', limit: int = 20) -> List[str]:
        """
        Generate attack payloads for security testing using payload library
        
        Args:
            param: Parameter metadata
            attack_type: Type of attack ('sqli', 'xss', 'all')
            limit: Maximum number of payloads to return
        
        Returns:
            List of attack payloads
        """
        payloads = []
        
        # Use payload library if available
        if self.payload_loader:
            payloads = self._get_payloads_from_library(attack_type, limit)
        else:
            # Fallback to basic hardcoded payloads
            payloads = self._get_fallback_payloads(attack_type)
        
        return payloads[:limit]
    
    def _get_payloads_from_library(self, attack_type: str, limit: int = 20) -> List[str]:
        """Get payloads from the payload library"""
        payloads = []
        
        try:
            if attack_type in ['sqli', 'all']:
                sqli = self.payload_loader.get_sqli_payloads()
                payloads.extend(sqli[:limit // 4])
            
            if attack_type in ['xss', 'all']:
                xss = self.payload_loader.get_xss_payloads()
                payloads.extend(xss[:limit // 4])
            
            if attack_type in ['path_traversal', 'all']:
                path = self.payload_loader.get_path_traversal_payloads('unix')
                payloads.extend(path[:limit // 4])
            
            if attack_type in ['command_injection', 'all']:
                cmd = self.payload_loader.get_command_injection_payloads('unix')
                payloads.extend(cmd[:limit // 4])
            
            if attack_type in ['ssrf', 'all']:
                ssrf = self.payload_loader.get_ssrf_payloads()
                payloads.extend(ssrf[:limit // 5])
            
            if attack_type in ['nosql', 'all']:
                nosql = self.payload_loader.get_nosql_payloads()
                payloads.extend(nosql[:limit // 5])
            
            if attack_type in ['xxe', 'all']:
                xxe = self.payload_loader.get_xxe_payloads()
                payloads.extend(xxe[:limit // 5])
            
            if attack_type in ['ssti', 'all']:
                ssti = self.payload_loader.get_ssti_payloads()
                payloads.extend(ssti[:limit // 5])
                
        except Exception as e:
            self.logger.warning(f"Error loading payloads from library: {e}")
            payloads = self._get_fallback_payloads(attack_type)
        
        return payloads
    
    def _get_fallback_payloads(self, attack_type: str) -> List[str]:
        """Fallback payloads if library is not available"""
        payloads = []
        
        if attack_type in ['sqli', 'all']:
            payloads.extend(self._get_sqli_payloads())
        
        if attack_type in ['xss', 'all']:
            payloads.extend(self._get_xss_payloads())
        
        if attack_type in ['path_traversal', 'all']:
            payloads.extend(self._get_path_traversal_payloads())
        
        if attack_type in ['command_injection', 'all']:
            payloads.extend(self._get_command_injection_payloads())
        
        return payloads
    
    def _get_sqli_payloads(self) -> List[str]:
        """SQL injection payloads (fallback)"""
        return [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "admin' --",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
        ]
    
    def _get_xss_payloads(self) -> List[str]:
        """XSS payloads (fallback)"""
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "'-alert(1)-'",
        ]
    
    def _get_path_traversal_payloads(self) -> List[str]:
        """Path traversal payloads (fallback)"""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
    
    def _get_command_injection_payloads(self) -> List[str]:
        """Command injection payloads (fallback)"""
        return [
            "; ls -la",
            "| whoami",
            "& dir",
            "`id`",
            "$(whoami)",
        ]
    
    def get_context_aware_payloads(self, param: ParameterMetadata, limit: int = 50) -> List[str]:
        """
        Get payloads based on parameter context (type, location, name)
        
        Args:
            param: Parameter metadata
            limit: Maximum number of payloads
            
        Returns:
            List of context-appropriate payloads
        """
        if not self.payload_loader:
            return self.generate_attack_payloads(param, 'all', limit)
        
        payloads = []
        
        # Select payloads based on parameter type and location
        if param.param_type in [ParameterType.STRING, ParameterType.EMAIL]:
            # String parameters are vulnerable to most attacks
            payloads.extend(self.payload_loader.get_sqli_payloads()[:10])
            payloads.extend(self.payload_loader.get_xss_payloads()[:10])
            payloads.extend(self.payload_loader.get_command_injection_payloads('unix')[:5])
        
        elif param.param_type == ParameterType.INTEGER:
            # Integer parameters mainly for SQL injection
            payloads.extend(self.payload_loader.get_sqli_payloads()[:15])
        
        elif param.param_type == ParameterType.URL:
            # URL parameters for SSRF
            payloads.extend(self.payload_loader.get_ssrf_payloads()[:20])
        
        # Location-based selection
        if param.location == 'body':
            # Body parameters can handle XML/JSON attacks
            payloads.extend(self.payload_loader.get_xxe_payloads()[:5])
            payloads.extend(self.payload_loader.get_nosql_payloads()[:5])
            payloads.extend(self.payload_loader.get_ssti_payloads()[:5])
        
        elif param.location == 'query' or param.location == 'path':
            # Query/path parameters for path traversal
            payloads.extend(self.payload_loader.get_path_traversal_payloads('unix')[:10])
        
        return payloads[:limit]
    
    def get_encoded_payloads(self, payload: str, max_variants: int = 5) -> List[str]:
        """
        Get encoded variants of a payload
        
        Args:
            payload: Original payload
            max_variants: Maximum number of variants
            
        Returns:
            List of encoded payloads
        """
        if not self.payload_encoder:
            return [payload]
        
        return self.payload_encoder.get_all_variants(payload, max_variants)
    
    def _get_fallback_payloads(self, attack_type: str) -> List[str]:
        """Fallback payloads if library is not available"""
        payloads = []
        
        if attack_type in ['sqli', 'all']:
            payloads.extend(self._get_sqli_payloads())
        
        if attack_type in ['xss', 'all']:
            payloads.extend(self._get_xss_payloads())
        
        if attack_type in ['path_traversal', 'all']:
            payloads.extend(self._get_path_traversal_payloads())
        
        if attack_type in ['command_injection', 'all']:
            payloads.extend(self._get_command_injection_payloads())
        
        return payloads
    
    def _get_sqli_payloads(self) -> List[str]:
        """SQL injection payloads (fallback)"""
        return [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "admin' --",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
        ]
    
    def _get_xss_payloads(self) -> List[str]:
        """XSS payloads (fallback)"""
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "'-alert(1)-'",
        ]
    
    def _get_path_traversal_payloads(self) -> List[str]:
        """Path traversal payloads (fallback)"""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
    
    def _get_command_injection_payloads(self) -> List[str]:
        """Command injection payloads (fallback)"""
        return [
            "; ls -la",
            "| whoami",
            "& dir",
            "`id`",
            "$(whoami)",
        ]
