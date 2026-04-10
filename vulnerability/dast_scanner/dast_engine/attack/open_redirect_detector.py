"""
Open Redirect Vulnerability Detector
Tests for unvalidated redirects that could be exploited for phishing
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse, urlencode


class RedirectSeverity(Enum):
    """Severity levels for open redirect vulnerabilities"""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class OpenRedirectVulnerability:
    """Represents an open redirect vulnerability"""
    endpoint_url: str
    http_method: str
    parameter_name: str
    parameter_location: str
    test_payload: str
    redirect_destination: str
    severity: RedirectSeverity
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
            'parameter_name': self.parameter_name,
            'parameter_location': self.parameter_location,
            'test_payload': self.test_payload,
            'redirect_destination': self.redirect_destination,
            'severity': self.severity.value,
            'description': self.description,
            'evidence': self.evidence,
            'impact': self.impact,
            'remediation': self.remediation,
            'confidence': self.confidence,
            'references': self.references
        }


class OpenRedirectDetector:
    """
    Detects open redirect vulnerabilities by testing redirect parameters.
    """
    
    def __init__(self, auth_manager=None):
        """
        Initialize open redirect detector.
        
        Args:
            auth_manager: Authentication manager for making authenticated requests
        """
        self.auth_manager = auth_manager
        self.session = auth_manager.get_session() if auth_manager else requests.Session()
        
        # Test payloads for open redirect detection
        self.test_payloads = [
            'https://evil.com',
            'http://evil.com',
            '//evil.com',
            '///evil.com',
            '/\\evil.com',
            'https://evil.com@attacker.com',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
        ]
        
        # Common redirect parameter names
        self.redirect_param_names = [
            'redirect', 'url', 'return', 'next', 'returnurl', 'return_url',
            'redirect_url', 'redirect_uri', 'redirecturl', 'callback',
            'continue', 'goto', 'target', 'link', 'destination', 'dest',
            'redir', 'out', 'view', 'to', 'forward', 'success_url'
        ]
    
    def test_endpoint(self, endpoint) -> List[OpenRedirectVulnerability]:
        """
        Test an endpoint for open redirect vulnerabilities.
        
        Args:
            endpoint: Endpoint object with URL, method, and parameters
            
        Returns:
            List of OpenRedirectVulnerability objects (if vulnerable)
        """
        vulnerabilities = []
        
        # Collect all parameters
        all_params = []
        if hasattr(endpoint, 'query_params'):
            all_params.extend(endpoint.query_params or [])
        if hasattr(endpoint, 'body_params'):
            all_params.extend(endpoint.body_params or [])
        if hasattr(endpoint, 'parameters'):
            all_params.extend(endpoint.parameters or [])
        
        # Test parameters that might be redirect targets
        for param in all_params:
            if self._is_potential_redirect_param(param):
                param_vulns = self._test_parameter(endpoint, param)
                vulnerabilities.extend(param_vulns)
        
        return vulnerabilities
    
    def _is_potential_redirect_param(self, param) -> bool:
        """
        Check if parameter name suggests it's a redirect parameter.
        
        Args:
            param: Parameter object
            
        Returns:
            True if parameter might control redirects
        """
        param_name_lower = param.name.lower()
        
        # Check against known redirect parameter names
        if param_name_lower in self.redirect_param_names:
            return True
        
        # Check if name contains redirect-related keywords
        redirect_keywords = ['redirect', 'url', 'return', 'next', 'goto', 'callback', 'continue']
        if any(keyword in param_name_lower for keyword in redirect_keywords):
            return True
        
        # Check parameter type (URL type parameters)
        if hasattr(param, 'detected_type'):
            if param.detected_type and param.detected_type.value == 'URL':
                return True
        
        return False
    
    def _test_parameter(self, endpoint, param) -> List[OpenRedirectVulnerability]:
        """
        Test a specific parameter for open redirect vulnerability.
        
        Args:
            endpoint: Endpoint object
            param: Parameter to test
            
        Returns:
            List of vulnerabilities found (if any)
        """
        vulnerabilities = []
        
        for payload in self.test_payloads:
            try:
                # Build request with test payload
                test_url = self._build_test_url(endpoint, param, payload)
                
                # Send request (don't follow redirects automatically)
                response = self.session.request(
                    method=endpoint.method.value,
                    url=test_url,
                    allow_redirects=False,
                    timeout=10
                )
                
                # Check if response is a redirect
                if response.status_code in [301, 302, 303, 307, 308]:
                    redirect_location = response.headers.get('Location', '')
                    
                    # Check if redirect goes to our test domain
                    if self._is_external_redirect(redirect_location, endpoint.url, payload):
                        vulnerability = self._create_vulnerability(
                            endpoint=endpoint,
                            param=param,
                            payload=payload,
                            redirect_location=redirect_location,
                            response_code=response.status_code
                        )
                        vulnerabilities.append(vulnerability)
                        break  # Found vulnerability, no need to test more payloads
                
                # Check for JavaScript redirects in response body
                elif response.status_code == 200:
                    if self._check_javascript_redirect(response.text, payload):
                        vulnerability = self._create_vulnerability(
                            endpoint=endpoint,
                            param=param,
                            payload=payload,
                            redirect_location=f"JavaScript redirect to {payload}",
                            response_code=200,
                            redirect_type='javascript'
                        )
                        vulnerabilities.append(vulnerability)
                        break
            
            except requests.RequestException:
                # Request failed, continue to next payload
                continue
        
        return vulnerabilities
    
    def _build_test_url(self, endpoint, param, payload: str) -> str:
        """
        Build test URL with payload in specified parameter.
        
        Args:
            endpoint: Endpoint object
            param: Parameter to inject payload into
            payload: Test payload
            
        Returns:
            URL with injected payload
        """
        parsed = urlparse(endpoint.url)
        
        if param.location.value == 'query':
            # Parse existing query parameters
            query_params = parse_qs(parsed.query)
            query_params[param.name] = [payload]
            
            # Rebuild URL with modified query
            new_query = urlencode(query_params, doseq=True)
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
        
        elif param.location.value == 'path':
            # For path parameters, try to replace in path
            # This is simplified - real implementation would need path template
            new_path = parsed.path.replace(f'{{{param.name}}}', payload)
            return urlunparse((
                parsed.scheme, parsed.netloc, new_path,
                parsed.params, parsed.query, parsed.fragment
            ))
        
        else:
            # For body parameters, we'd need to build POST request
            # For now, just return base URL
            return endpoint.url
    
    def _is_external_redirect(self, redirect_location: str, original_url: str, payload: str) -> bool:
        """
        Check if redirect goes to external/attacker-controlled domain.
        
        Args:
            redirect_location: The Location header value
            original_url: Original endpoint URL
            payload: The test payload used
            
        Returns:
            True if redirect appears to be to external domain
        """
        if not redirect_location:
            return False
        
        # Parse URLs
        original_domain = urlparse(original_url).netloc
        redirect_parsed = urlparse(redirect_location)
        
        # Check if redirect contains our evil domain marker
        if 'evil.com' in redirect_location.lower():
            return True
        
        # Check if redirect contains attacker domain
        if 'attacker.com' in redirect_location.lower():
            return True
        
        # Check if redirect is to different domain than original
        if redirect_parsed.netloc and redirect_parsed.netloc != original_domain:
            # Check if it matches our payload
            if payload.replace('https://', '').replace('http://', '').replace('//', '') in redirect_location:
                return True
        
        # Check for protocol-relative URLs (//evil.com)
        if redirect_location.startswith('//') and 'evil.com' in redirect_location:
            return True
        
        # Check for dangerous protocols
        dangerous_protocols = ['javascript:', 'data:', 'vbscript:']
        if any(redirect_location.lower().startswith(proto) for proto in dangerous_protocols):
            return True
        
        return False
    
    def _check_javascript_redirect(self, response_body: str, payload: str) -> bool:
        """
        Check if response contains JavaScript redirect with our payload.
        
        Args:
            response_body: HTTP response body
            payload: Test payload
            
        Returns:
            True if JavaScript redirect with payload is found
        """
        # Check for common JavaScript redirect patterns with our payload
        js_redirect_patterns = [
            f'window.location = "{payload}"',
            f"window.location = '{payload}'",
            f'window.location.href = "{payload}"',
            f"window.location.href = '{payload}'",
            f'location.href = "{payload}"',
            f"location.href = '{payload}'",
            f'document.location = "{payload}"',
        ]
        
        for pattern in js_redirect_patterns:
            if pattern in response_body:
                return True
        
        # Check if payload appears in any window.location assignment
        if 'evil.com' in response_body and 'window.location' in response_body:
            return True
        
        return False
    
    def _create_vulnerability(self, endpoint, param, payload: str, 
                            redirect_location: str, response_code: int,
                            redirect_type: str = 'http') -> OpenRedirectVulnerability:
        """
        Create vulnerability object for detected open redirect.
        
        Args:
            endpoint: Endpoint object
            param: Vulnerable parameter
            payload: Payload that triggered redirect
            redirect_location: Where the redirect goes
            response_code: HTTP response code
            redirect_type: Type of redirect (http or javascript)
            
        Returns:
            OpenRedirectVulnerability object
        """
        # Determine severity
        severity = self._determine_severity(redirect_location, param)
        
        # Build description
        if redirect_type == 'http':
            description = (
                f"Open redirect vulnerability detected in parameter '{param.name}' of "
                f"{endpoint.method.value} {endpoint.url}. The application redirects to "
                f"user-supplied URLs without validation, returning HTTP {response_code}."
            )
            evidence = f"Payload: {payload} → Redirect to: {redirect_location} (HTTP {response_code})"
        else:
            description = (
                f"JavaScript-based open redirect vulnerability detected in parameter '{param.name}' of "
                f"{endpoint.method.value} {endpoint.url}. The application uses user-supplied URLs "
                f"in JavaScript redirect without validation."
            )
            evidence = f"Payload: {payload} → {redirect_location}"
        
        return OpenRedirectVulnerability(
            endpoint_url=endpoint.url,
            http_method=endpoint.method.value,
            parameter_name=param.name,
            parameter_location=param.location.value,
            test_payload=payload,
            redirect_destination=redirect_location,
            severity=severity,
            description=description,
            evidence=evidence,
            impact=(
                "Attackers can use this vulnerability for phishing attacks by crafting "
                "legitimate-looking URLs that redirect to malicious sites. This can be used "
                "to steal credentials, distribute malware, or bypass security controls."
            ),
            remediation=(
                "1. Use allowlist of permitted redirect destinations\n"
                "2. Validate redirect URLs against allowed domains/paths\n"
                "3. Use indirect references (mapping IDs to URLs server-side)\n"
                "4. Avoid using user input directly in redirects\n"
                "5. If redirects are necessary, validate the protocol and domain\n"
                "6. Display warning page before external redirects"
            ),
            confidence=0.95,
            references=[
                'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet',
                'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
                'https://cwe.mitre.org/data/definitions/601.html'
            ]
        )
    
    def _determine_severity(self, redirect_location: str, param) -> RedirectSeverity:
        """
        Determine severity of open redirect vulnerability.
        
        Args:
            redirect_location: Where redirect goes
            param: Parameter being tested
            
        Returns:
            RedirectSeverity level
        """
        # Dangerous protocols are high severity
        if any(redirect_location.lower().startswith(proto) for proto in ['javascript:', 'data:', 'vbscript:']):
            return RedirectSeverity.HIGH
        
        # Full external redirects are high severity
        if redirect_location.startswith('http://') or redirect_location.startswith('https://'):
            return RedirectSeverity.HIGH
        
        # Protocol-relative URLs are medium severity
        if redirect_location.startswith('//'):
            return RedirectSeverity.MEDIUM
        
        return RedirectSeverity.MEDIUM
