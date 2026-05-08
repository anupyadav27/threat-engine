"""
Security Headers Analyzer
Checks for missing or misconfigured security headers in HTTP responses
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum


class HeaderSeverity(Enum):
    """Severity levels for missing headers"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class SecurityHeaderIssue:
    """Represents a security header issue"""
    header_name: str
    severity: HeaderSeverity
    status: str  # missing, weak, misconfigured, insecure
    current_value: Optional[str]
    recommended_value: str
    description: str
    impact: str
    remediation: str
    references: List[str]
    endpoint_url: str = ''
    http_method: str = ''

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (normalizer-compatible keys)."""
        return {
            'header_name': self.header_name,
            'severity': self.severity.value,
            'status': self.status,
            'current_value': self.current_value,
            'recommended_value': self.recommended_value,
            'description': self.description,
            'impact': self.impact,
            'remediation': self.remediation,
            'references': self.references,
            'endpoint': {
                'url': self.endpoint_url,
                'method': self.http_method,
            },
            'parameter': {},
        }


class SecurityHeadersAnalyzer:
    """
    Analyzes HTTP response headers for security issues.
    Checks for missing, weak, or misconfigured security headers.
    """
    
    def __init__(self):
        """Initialize security headers analyzer."""
        # Define critical security headers
        self.required_headers = {
            'Strict-Transport-Security': {
                'severity': HeaderSeverity.HIGH,
                'recommended': 'max-age=31536000; includeSubDomains',
                'description': 'HTTP Strict Transport Security (HSTS) forces browsers to use HTTPS',
                'impact': 'Without HSTS, users can be vulnerable to man-in-the-middle attacks via SSL stripping',
                'remediation': 'Add HSTS header with max-age of at least 1 year (31536000 seconds)',
                'references': [
                    'https://owasp.org/www-project-secure-headers/#http-strict-transport-security',
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
                ]
            },
            'X-Frame-Options': {
                'severity': HeaderSeverity.HIGH,
                'recommended': 'DENY or SAMEORIGIN',
                'description': 'Prevents clickjacking attacks by controlling whether page can be embedded in frames',
                'impact': 'Without this header, site is vulnerable to clickjacking attacks',
                'remediation': 'Add X-Frame-Options: DENY (or SAMEORIGIN if framing needed)',
                'references': [
                    'https://owasp.org/www-project-secure-headers/#x-frame-options',
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'
                ]
            },
            'X-Content-Type-Options': {
                'severity': HeaderSeverity.MEDIUM,
                'recommended': 'nosniff',
                'description': 'Prevents browsers from MIME-sniffing responses away from declared content-type',
                'impact': 'Without this header, browsers may interpret files as different MIME type, enabling XSS',
                'remediation': 'Add X-Content-Type-Options: nosniff',
                'references': [
                    'https://owasp.org/www-project-secure-headers/#x-content-type-options',
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'
                ]
            },
            'Content-Security-Policy': {
                'severity': HeaderSeverity.HIGH,
                'recommended': "default-src 'self'; script-src 'self'",
                'description': 'Controls which resources browser is allowed to load, mitigates XSS attacks',
                'impact': 'Without CSP, application has no protection against XSS and data injection attacks',
                'remediation': "Implement Content-Security-Policy with restrictive directives (start with default-src 'self')",
                'references': [
                    'https://owasp.org/www-project-secure-headers/#content-security-policy',
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
                    'https://content-security-policy.com/'
                ]
            },
            'X-XSS-Protection': {
                'severity': HeaderSeverity.LOW,
                'recommended': '1; mode=block',
                'description': 'Enables browser XSS filter (legacy, superseded by CSP)',
                'impact': 'Limited impact as modern browsers prioritize CSP, but provides defense-in-depth',
                'remediation': 'Add X-XSS-Protection: 1; mode=block (though CSP is preferred)',
                'references': [
                    'https://owasp.org/www-project-secure-headers/#x-xss-protection',
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection'
                ]
            },
            'Referrer-Policy': {
                'severity': HeaderSeverity.MEDIUM,
                'recommended': 'strict-origin-when-cross-origin or no-referrer',
                'description': 'Controls how much referrer information is sent with requests',
                'impact': 'Without this, sensitive information in URLs may leak via Referer header',
                'remediation': 'Add Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for more privacy)',
                'references': [
                    'https://owasp.org/www-project-secure-headers/#referrer-policy',
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'
                ]
            },
            'Permissions-Policy': {
                'severity': HeaderSeverity.LOW,
                'recommended': 'geolocation=(), microphone=(), camera=()',
                'description': 'Controls which browser features and APIs can be used',
                'impact': 'Without this, malicious scripts could abuse browser features',
                'remediation': 'Add Permissions-Policy to restrict unnecessary browser features',
                'references': [
                    'https://owasp.org/www-project-secure-headers/#permissions-policy',
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'
                ]
            }
        }
    
    def analyze_headers(self, response_headers: Dict[str, str], url: str, is_https: bool = False, http_method: str = 'GET') -> List[SecurityHeaderIssue]:
        """
        Analyze HTTP response headers for security issues.
        
        Args:
            response_headers: Dictionary of HTTP response headers
            url: URL that was requested
            is_https: Whether the request was made over HTTPS
            
        Returns:
            List of SecurityHeaderIssue objects
        """
        issues = []
        
        # Normalize header names (case-insensitive)
        normalized_headers = {k.lower(): v for k, v in response_headers.items()}
        
        # Check each required header
        for header_name, config in self.required_headers.items():
            header_key = header_name.lower()
            
            # Special case: HSTS only applies to HTTPS
            if header_name == 'Strict-Transport-Security' and not is_https:
                continue
            
            if header_key not in normalized_headers:
                # Header is missing
                issues.append(SecurityHeaderIssue(
                    header_name=header_name,
                    severity=config['severity'],
                    status='missing',
                    current_value=None,
                    recommended_value=config['recommended'],
                    description=config['description'],
                    impact=config['impact'],
                    remediation=config['remediation'],
                    references=config['references'],
                    endpoint_url=url,
                    http_method=http_method,
                ))
            else:
                # Header exists - check if it's properly configured
                current_value = normalized_headers[header_key]
                weakness = self._check_header_weakness(header_name, current_value)

                if weakness:
                    issues.append(SecurityHeaderIssue(
                        header_name=header_name,
                        severity=config['severity'],
                        status=weakness['status'],
                        current_value=current_value,
                        recommended_value=config['recommended'],
                        description=weakness['description'],
                        impact=config['impact'],
                        remediation=weakness['remediation'],
                        references=config['references'],
                        endpoint_url=url,
                        http_method=http_method,
                    ))

        # Check for insecure headers that should not be present
        insecure_issues = self._check_insecure_headers(normalized_headers, url, http_method)
        issues.extend(insecure_issues)
        
        return issues
    
    def _check_header_weakness(self, header_name: str, value: str) -> Optional[Dict[str, str]]:
        """
        Check if a header value is weak or misconfigured.
        
        Args:
            header_name: Name of the header
            value: Current value of the header
            
        Returns:
            Dictionary with weakness details or None if properly configured
        """
        value_lower = value.lower()
        
        if header_name == 'Strict-Transport-Security':
            # Check for weak max-age
            if 'max-age' in value_lower:
                try:
                    max_age_part = [p for p in value.split(';') if 'max-age' in p.lower()][0]
                    max_age = int(max_age_part.split('=')[1].strip())
                    if max_age < 31536000:  # Less than 1 year
                        return {
                            'status': 'weak',
                            'description': f'HSTS max-age is too short ({max_age} seconds, should be at least 31536000)',
                            'remediation': 'Increase max-age to at least 1 year (31536000 seconds)'
                        }
                except (ValueError, IndexError):
                    return {
                        'status': 'misconfigured',
                        'description': 'HSTS header has invalid max-age value',
                        'remediation': 'Fix HSTS header syntax: Strict-Transport-Security: max-age=31536000'
                    }
        
        elif header_name == 'X-Frame-Options':
            # Check for weak values
            if value_lower not in ['deny', 'sameorigin']:
                return {
                    'status': 'weak',
                    'description': f'X-Frame-Options value "{value}" is not restrictive enough',
                    'remediation': 'Use X-Frame-Options: DENY or SAMEORIGIN'
                }
        
        elif header_name == 'X-Content-Type-Options':
            # Must be exactly "nosniff"
            if value_lower != 'nosniff':
                return {
                    'status': 'misconfigured',
                    'description': f'X-Content-Type-Options has invalid value "{value}"',
                    'remediation': 'Set X-Content-Type-Options: nosniff'
                }
        
        elif header_name == 'X-XSS-Protection':
            # Check if XSS protection is disabled
            if '0' in value_lower:
                return {
                    'status': 'insecure',
                    'description': 'XSS Protection is explicitly disabled',
                    'remediation': 'Enable XSS Protection: X-XSS-Protection: 1; mode=block'
                }
        
        elif header_name == 'Content-Security-Policy':
            # Check for overly permissive CSP
            if 'unsafe-inline' in value_lower or 'unsafe-eval' in value_lower:
                return {
                    'status': 'weak',
                    'description': 'CSP allows unsafe-inline or unsafe-eval, which weakens XSS protection',
                    'remediation': "Remove 'unsafe-inline' and 'unsafe-eval' from CSP directives"
                }
        
        return None
    
    def _check_insecure_headers(self, headers: Dict[str, str], url: str = '', http_method: str = 'GET') -> List[SecurityHeaderIssue]:
        """
        Check for headers that should not be present (leak information).
        
        Args:
            headers: Normalized response headers (lowercase keys)
            
        Returns:
            List of issues for insecure headers
        """
        issues = []
        
        # Headers that leak server information
        info_leak_headers = {
            'server': {
                'description': 'Server header reveals web server software and version',
                'impact': 'Information leakage helps attackers identify known vulnerabilities',
                'remediation': 'Remove or obscure Server header to hide technology stack'
            },
            'x-powered-by': {
                'description': 'X-Powered-By header reveals application framework and version',
                'impact': 'Information leakage helps attackers target framework-specific vulnerabilities',
                'remediation': 'Remove X-Powered-By header to hide technology stack'
            },
            'x-aspnet-version': {
                'description': 'X-AspNet-Version header reveals ASP.NET version',
                'impact': 'Information leakage helps attackers target version-specific vulnerabilities',
                'remediation': 'Disable X-AspNet-Version header in web.config'
            }
        }
        
        for header_key, config in info_leak_headers.items():
            if header_key in headers:
                issues.append(SecurityHeaderIssue(
                    header_name=header_key.title(),
                    severity=HeaderSeverity.INFO,
                    status='information_leak',
                    current_value=headers[header_key],
                    recommended_value='<removed>',
                    description=config['description'],
                    impact=config['impact'],
                    remediation=config['remediation'],
                    references=[
                        'https://owasp.org/www-project-secure-headers/',
                        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'
                    ],
                    endpoint_url=url,
                    http_method=http_method,
                ))
        
        return issues
    
    def generate_summary(self, issues: List[SecurityHeaderIssue]) -> Dict[str, Any]:
        """
        Generate summary of security header issues.
        
        Args:
            issues: List of SecurityHeaderIssue objects
            
        Returns:
            Dictionary with summary statistics
        """
        if not issues:
            return {
                'total_issues': 0,
                'by_severity': {},
                'security_score': 100,
                'status': 'excellent'
            }
        
        # Count by severity
        severity_counts = {}
        for issue in issues:
            severity = issue.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Calculate security score (0-100)
        max_points = len(self.required_headers) * 10
        deductions = 0
        deductions += severity_counts.get('Critical', 0) * 10
        deductions += severity_counts.get('High', 0) * 7
        deductions += severity_counts.get('Medium', 0) * 4
        deductions += severity_counts.get('Low', 0) * 2
        deductions += severity_counts.get('Info', 0) * 1
        
        score = max(0, 100 - (deductions * 100 // max_points))
        
        # Determine status
        if score >= 90:
            status = 'excellent'
        elif score >= 70:
            status = 'good'
        elif score >= 50:
            status = 'fair'
        else:
            status = 'poor'
        
        return {
            'total_issues': len(issues),
            'by_severity': severity_counts,
            'security_score': score,
            'status': status,
            'issues': [issue.to_dict() for issue in issues]
        }
