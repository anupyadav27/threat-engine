"""
CSRF (Cross-Site Request Forgery) Vulnerability Tester
Actively tests for CSRF vulnerabilities by attempting requests without valid tokens
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import requests


class CSRFSeverity(Enum):
    """Severity levels for CSRF vulnerabilities"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class CSRFVulnerability:
    """Represents a CSRF vulnerability finding"""
    endpoint_url: str
    http_method: str
    vulnerability_type: str  # missing_token, bypassable, weak_validation
    severity: CSRFSeverity
    csrf_token_field: Optional[str]
    description: str
    evidence: str
    impact: str
    remediation: str
    confidence: float
    references: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'endpoint_url': self.endpoint_url,
            'http_method': self.http_method,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity.value,
            'csrf_token_field': self.csrf_token_field,
            'description': self.description,
            'evidence': self.evidence,
            'impact': self.impact,
            'remediation': self.remediation,
            'confidence': self.confidence,
            'references': self.references
        }


class CSRFTester:
    """
    Tests endpoints for CSRF vulnerabilities.
    Performs active testing by submitting requests without CSRF tokens.
    """
    
    def __init__(self, auth_manager=None):
        """
        Initialize CSRF tester.
        
        Args:
            auth_manager: Authentication manager for making authenticated requests
        """
        self.auth_manager = auth_manager
        self.session = auth_manager.get_session() if auth_manager else requests.Session()
        
        # Common CSRF token field names
        self.csrf_token_names = [
            'csrf_token', 'csrfmiddlewaretoken', '_token',
            'authenticity_token', 'csrf', '_csrf', 
            '__RequestVerificationToken', 'token',
            'anti_csrf_token', 'xsrf_token', '_xsrf'
        ]
    
    def test_endpoint(self, endpoint) -> Optional[CSRFVulnerability]:
        """
        Test an endpoint for CSRF vulnerability.
        
        Args:
            endpoint: Endpoint object with URL, method, parameters, and csrf_token
            
        Returns:
            CSRFVulnerability if vulnerable, None otherwise
        """
        # Only test state-changing methods
        if endpoint.method.value not in ['POST', 'PUT', 'DELETE', 'PATCH']:
            return None
        
        # Check if endpoint has CSRF token
        has_csrf_token = hasattr(endpoint, 'csrf_token') and endpoint.csrf_token
        csrf_token_field = None
        
        # Also check parameters for CSRF token fields
        if not has_csrf_token:
            has_csrf_token, csrf_token_field = self._check_parameters_for_csrf(endpoint)
        
        # Test scenario 1: No CSRF token at all
        if not has_csrf_token:
            return self._test_missing_csrf_protection(endpoint)
        
        # Test scenario 2: CSRF token exists - try to bypass it
        csrf_bypass = self._test_csrf_bypass(endpoint, csrf_token_field or endpoint.csrf_token)
        if csrf_bypass:
            return csrf_bypass
        
        return None
    
    def _check_parameters_for_csrf(self, endpoint) -> tuple[bool, Optional[str]]:
        """
        Check if endpoint parameters include CSRF token fields.
        
        Args:
            endpoint: Endpoint object
            
        Returns:
            Tuple of (has_csrf_token, token_field_name)
        """
        # Collect all parameters
        all_params = []
        if hasattr(endpoint, 'query_params'):
            all_params.extend(endpoint.query_params or [])
        if hasattr(endpoint, 'body_params'):
            all_params.extend(endpoint.body_params or [])
        if hasattr(endpoint, 'parameters'):
            all_params.extend(endpoint.parameters or [])
        
        # Check for CSRF token field names
        for param in all_params:
            if param.name.lower() in [name.lower() for name in self.csrf_token_names]:
                return True, param.name
        
        return False, None
    
    def _test_missing_csrf_protection(self, endpoint) -> Optional[CSRFVulnerability]:
        """
        Test endpoint that appears to have no CSRF protection.
        
        Args:
            endpoint: Endpoint object
            
        Returns:
            CSRFVulnerability if the request succeeds without CSRF token
        """
        try:
            # Build a minimal request without CSRF token
            request_params = self._build_test_request(endpoint, include_csrf=False)
            
            # Send request
            response = self._send_request(
                method=endpoint.method.value,
                url=endpoint.url,
                **request_params
            )
            
            # If request succeeds (2xx or 3xx), it's vulnerable
            if 200 <= response.status_code < 400:
                severity = self._determine_severity(endpoint, response)
                
                return CSRFVulnerability(
                    endpoint_url=endpoint.url,
                    http_method=endpoint.method.value,
                    vulnerability_type='missing_csrf_protection',
                    severity=severity,
                    csrf_token_field=None,
                    description=(
                        f"The endpoint {endpoint.method.value} {endpoint.url} accepts state-changing "
                        f"requests without any CSRF token validation. This allows attackers to forge "
                        f"requests on behalf of authenticated users."
                    ),
                    evidence=(
                        f"Request succeeded with status {response.status_code} without CSRF token. "
                        f"No CSRF protection mechanism detected."
                    ),
                    impact=(
                        "Attackers can perform unauthorized actions on behalf of authenticated users "
                        "by tricking them into visiting a malicious website that submits forged requests."
                    ),
                    remediation=(
                        "1. Implement CSRF tokens (synchronizer token pattern)\n"
                        "2. Use SameSite cookie attribute (SameSite=Lax or SameSite=Strict)\n"
                        "3. Verify Origin/Referer headers\n"
                        "4. Require re-authentication for sensitive actions\n"
                        "5. Use framework built-in CSRF protection (e.g., Django, Rails, Spring Security)"
                    ),
                    confidence=0.85,
                    references=[
                        'https://owasp.org/www-community/attacks/csrf',
                        'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
                        'https://cwe.mitre.org/data/definitions/352.html'
                    ]
                )
        
        except requests.RequestException:
            # If request fails, we can't determine vulnerability
            pass
        
        return None
    
    def _test_csrf_bypass(self, endpoint, csrf_field_name: str) -> Optional[CSRFVulnerability]:
        """
        Test if CSRF protection can be bypassed.
        
        Args:
            endpoint: Endpoint object
            csrf_field_name: Name of the CSRF token field
            
        Returns:
            CSRFVulnerability if bypass is successful
        """
        bypass_tests = [
            ('empty_token', ''),
            ('null_token', None),
            ('invalid_token', 'invalid_token_12345'),
            ('remove_token', 'REMOVE'),  # Signal to omit the parameter
        ]
        
        for test_name, test_value in bypass_tests:
            try:
                # Build request with modified CSRF token
                request_params = self._build_test_request(
                    endpoint, 
                    include_csrf=True,
                    csrf_value=test_value,
                    csrf_field=csrf_field_name
                )
                
                # Send request
                response = self._send_request(
                    method=endpoint.method.value,
                    url=endpoint.url,
                    **request_params
                )
                
                # If request succeeds, CSRF protection is bypassable
                if 200 <= response.status_code < 400:
                    return CSRFVulnerability(
                        endpoint_url=endpoint.url,
                        http_method=endpoint.method.value,
                        vulnerability_type='bypassable_csrf_protection',
                        severity=CSRFSeverity.HIGH,
                        csrf_token_field=csrf_field_name,
                        description=(
                            f"The CSRF protection on {endpoint.method.value} {endpoint.url} can be bypassed. "
                            f"The endpoint accepted a request with {test_name.replace('_', ' ')}."
                        ),
                        evidence=(
                            f"Bypass method: {test_name} | "
                            f"Response status: {response.status_code} | "
                            f"CSRF field: {csrf_field_name}"
                        ),
                        impact=(
                            "Although CSRF token is present, it can be bypassed, allowing attackers "
                            "to perform unauthorized actions on behalf of authenticated users."
                        ),
                        remediation=(
                            "1. Ensure CSRF token validation is mandatory (not optional)\n"
                            "2. Reject requests with missing, empty, or invalid CSRF tokens\n"
                            "3. Use cryptographically strong, random CSRF tokens\n"
                            "4. Tie CSRF tokens to user sessions\n"
                            "5. Implement proper server-side validation"
                        ),
                        confidence=0.9,
                        references=[
                            'https://owasp.org/www-community/attacks/csrf',
                            'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
                        ]
                    )
            
            except requests.RequestException:
                continue
        
        return None
    
    def _build_test_request(self, endpoint, include_csrf: bool = False, 
                           csrf_value: Any = None, csrf_field: str = None) -> Dict[str, Any]:
        """
        Build test request parameters.
        
        Args:
            endpoint: Endpoint object
            include_csrf: Whether to include CSRF token
            csrf_value: Value for CSRF token (if including)
            csrf_field: Name of CSRF field
            
        Returns:
            Dictionary with request parameters (data, params, headers, etc.)
        """
        request_params = {
            'data': {},
            'params': {},
            'headers': {},
            'cookies': {}
        }
        
        # Add minimal valid data for each parameter
        all_params = []
        if hasattr(endpoint, 'body_params'):
            all_params.extend(endpoint.body_params or [])
        if hasattr(endpoint, 'query_params'):
            all_params.extend(endpoint.query_params or [])
        if hasattr(endpoint, 'parameters'):
            all_params.extend(endpoint.parameters or [])
        
        for param in all_params:
            # Skip CSRF token field initially
            is_csrf_field = (csrf_field and param.name == csrf_field) or \
                           (param.name.lower() in [n.lower() for n in self.csrf_token_names])
            
            if is_csrf_field:
                if include_csrf and csrf_value != 'REMOVE':
                    # Include CSRF with test value
                    if param.location.value == 'body':
                        request_params['data'][param.name] = csrf_value or ''
                    elif param.location.value == 'query':
                        request_params['params'][param.name] = csrf_value or ''
                # Otherwise skip it (testing without CSRF)
            else:
                # Add minimal valid value for non-CSRF parameters
                test_value = self._get_test_value(param)
                if param.location.value == 'body':
                    request_params['data'][param.name] = test_value
                elif param.location.value == 'query':
                    request_params['params'][param.name] = test_value
        
        return request_params
    
    def _get_test_value(self, param) -> str:
        """Get a minimal test value for a parameter."""
        if param.example_values:
            return param.example_values[0]
        elif param.default_value:
            return param.default_value
        else:
            # Return type-appropriate default
            param_type = param.param_type.value if hasattr(param, 'param_type') else 'string'
            return {
                'integer': '1',
                'boolean': 'true',
                'string': 'test'
            }.get(param_type, 'test')
    
    def _send_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Send HTTP request using session.
        
        Args:
            method: HTTP method
            url: Target URL
            **kwargs: Request parameters
            
        Returns:
            Response object
        """
        return self.session.request(method, url, timeout=10, **kwargs)
    
    def _determine_severity(self, endpoint, response) -> CSRFSeverity:
        """
        Determine severity based on endpoint characteristics.
        
        Args:
            endpoint: Endpoint object
            response: Response from test request
            
        Returns:
            CSRFSeverity level
        """
        # Check endpoint type and method for severity assessment
        method = endpoint.method.value
        
        # DELETE and state-changing operations are critical
        if method in ['DELETE', 'PATCH']:
            return CSRFSeverity.CRITICAL
        
        # POST to sensitive endpoints
        if method == 'POST':
            url_lower = endpoint.url.lower()
            sensitive_keywords = [
                'delete', 'remove', 'admin', 'password', 'transfer',
                'payment', 'purchase', 'account', 'user', 'profile'
            ]
            if any(keyword in url_lower for keyword in sensitive_keywords):
                return CSRFSeverity.CRITICAL
            return CSRFSeverity.HIGH
        
        # PUT operations
        if method == 'PUT':
            return CSRFSeverity.HIGH
        
        return CSRFSeverity.MEDIUM
