"""
Cookie Security Analyzer
Analyzes cookies for security misconfigurations (missing Secure, HttpOnly, SameSite flags)
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
from http.cookies import SimpleCookie


class CookieSeverity(Enum):
    """Severity levels for cookie security issues"""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class CookieSecurityIssue:
    """Represents a cookie security issue"""
    cookie_name: str
    cookie_value_preview: str  # Truncated for security
    issue_type: str  # missing_secure, missing_httponly, missing_samesite, weak_samesite
    severity: CookieSeverity
    current_flags: Dict[str, Any]
    description: str
    impact: str
    remediation: str
    references: List[str]
    endpoint_url: str = ''
    http_method: str = ''

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (normalizer-compatible keys)."""
        return {
            'cookie_name': self.cookie_name,
            'cookie_value_preview': self.cookie_value_preview,
            'issue_type': self.issue_type,
            'severity': self.severity.value,
            'current_flags': self.current_flags,
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


class CookieSecurityAnalyzer:
    """
    Analyzes cookies for security misconfigurations.
    Checks for missing or weak Secure, HttpOnly, and SameSite attributes.
    """
    
    def __init__(self):
        """Initialize cookie security analyzer."""
        # Session/authentication cookie patterns (case-insensitive)
        self.sensitive_cookie_patterns = [
            'session', 'sess', 'sessionid', 'sessid', 'jsessionid',
            'phpsessid', 'aspsessionid', 'token', 'auth', 'authentication',
            'jwt', 'access_token', 'refresh_token', 'remember', 'user',
            'login', 'account', 'csrf', 'xsrf'
        ]
    
    def analyze_response_cookies(self, response_headers: Dict[str, str],
                                 url: str, is_https: bool, http_method: str = 'GET') -> List[CookieSecurityIssue]:
        """
        Analyze cookies from HTTP response headers.
        
        Args:
            response_headers: Dictionary of HTTP response headers
            url: URL that was requested
            is_https: Whether request was over HTTPS
            
        Returns:
            List of CookieSecurityIssue objects
        """
        issues = []
        
        # Extract Set-Cookie headers
        set_cookie_headers = []
        for key, value in response_headers.items():
            if key.lower() == 'set-cookie':
                set_cookie_headers.append(value)
        
        # Analyze each cookie
        for cookie_header in set_cookie_headers:
            cookie_issues = self._analyze_cookie(cookie_header, url, is_https, http_method)
            issues.extend(cookie_issues)
        
        return issues
    
    def analyze_request_cookies(self, request_cookies: Dict[str, str]) -> List[CookieSecurityIssue]:
        """
        Analyze cookies from HTTP request (informational only - can't determine flags).
        
        Args:
            request_cookies: Dictionary of request cookies
            
        Returns:
            List of informational issues about potentially sensitive cookies
        """
        issues = []
        
        for cookie_name, cookie_value in request_cookies.items():
            if self._is_sensitive_cookie(cookie_name):
                issues.append(CookieSecurityIssue(
                    cookie_name=cookie_name,
                    cookie_value_preview=self._truncate_value(cookie_value),
                    issue_type='sensitive_cookie_detected',
                    severity=CookieSeverity.INFO,
                    current_flags={'source': 'request'},
                    description=(
                        f"Sensitive cookie '{cookie_name}' detected in request. "
                        f"Verify this cookie has proper security flags (Secure, HttpOnly, SameSite)."
                    ),
                    impact="If security flags are missing, cookie may be vulnerable to theft or manipulation",
                    remediation="Ensure server sets Secure, HttpOnly, and SameSite=Strict flags when creating this cookie",
                    references=[
                        'https://owasp.org/www-community/controls/SecureCookieAttribute',
                        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes'
                    ]
                ))
        
        return issues
    
    def _analyze_cookie(self, cookie_header: str, url: str, is_https: bool, http_method: str = 'GET') -> List[CookieSecurityIssue]:
        """
        Analyze a single Set-Cookie header.
        
        Args:
            cookie_header: Set-Cookie header value
            url: URL that set the cookie
            is_https: Whether connection is HTTPS
            
        Returns:
            List of issues for this cookie
        """
        issues = []
        
        # Parse cookie
        try:
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            
            # Get cookie name and morsel
            if not cookie:
                return issues
            
            cookie_name = list(cookie.keys())[0]
            morsel = cookie[cookie_name]
            
            # Extract flags
            flags = {
                'secure': morsel.get('secure', False) or 'secure' in cookie_header.lower(),
                'httponly': morsel.get('httponly', False) or 'httponly' in cookie_header.lower(),
                'samesite': morsel.get('samesite', '').lower() or self._extract_samesite(cookie_header),
                'path': morsel.get('path', '/'),
                'domain': morsel.get('domain', ''),
                'max-age': morsel.get('max-age', ''),
                'expires': morsel.get('expires', '')
            }
            
            value_preview = self._truncate_value(morsel.value)
            is_sensitive = self._is_sensitive_cookie(cookie_name)
            
            # Check for missing Secure flag (HTTPS only)
            if is_https and not flags['secure']:
                severity = CookieSeverity.HIGH if is_sensitive else CookieSeverity.MEDIUM
                issues.append(CookieSecurityIssue(
                    cookie_name=cookie_name,
                    cookie_value_preview=value_preview,
                    issue_type='missing_secure_flag',
                    severity=severity,
                    current_flags=flags,
                    description=(
                        f"Cookie '{cookie_name}' is missing the Secure flag. "
                        f"This cookie can be transmitted over unencrypted HTTP connections."
                    ),
                    impact=(
                        "Without Secure flag, cookies can be intercepted over insecure connections, "
                        "allowing attackers to steal session tokens or authentication credentials."
                    ),
                    remediation=(
                        f"Add Secure flag to cookie: Set-Cookie: {cookie_name}=...; Secure\n"
                        "Ensure cookie is only set over HTTPS connections."
                    ),
                    references=[
                        'https://owasp.org/www-community/controls/SecureCookieAttribute',
                        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies'
                    ],
                    endpoint_url=url,
                    http_method=http_method,
                ))

            # Check for missing HttpOnly flag
            if not flags['httponly']:
                severity = CookieSeverity.HIGH if is_sensitive else CookieSeverity.MEDIUM
                issues.append(CookieSecurityIssue(
                    cookie_name=cookie_name,
                    cookie_value_preview=value_preview,
                    issue_type='missing_httponly_flag',
                    severity=severity,
                    current_flags=flags,
                    description=(
                        f"Cookie '{cookie_name}' is missing the HttpOnly flag. "
                        f"This cookie can be accessed by JavaScript code."
                    ),
                    impact=(
                        "Without HttpOnly flag, cookies are accessible via JavaScript (document.cookie), "
                        "making them vulnerable to theft via XSS attacks."
                    ),
                    remediation=(
                        f"Add HttpOnly flag to cookie: Set-Cookie: {cookie_name}=...; HttpOnly\n"
                        "This prevents JavaScript access to the cookie."
                    ),
                    references=[
                        'https://owasp.org/www-community/HttpOnly',
                        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies'
                    ],
                    endpoint_url=url,
                    http_method=http_method,
                ))

            # Check for missing or weak SameSite flag
            samesite_issue = self._check_samesite(cookie_name, flags['samesite'],
                                                  value_preview, flags, is_sensitive,
                                                  url, http_method)
            if samesite_issue:
                issues.append(samesite_issue)
        
        except Exception as e:
            # Cookie parsing failed - this itself might be an issue
            pass
        
        return issues
    
    def _extract_samesite(self, cookie_header: str) -> str:
        """
        Extract SameSite value from cookie header string.
        
        Args:
            cookie_header: Raw Set-Cookie header
            
        Returns:
            SameSite value (strict, lax, none, or empty string)
        """
        cookie_lower = cookie_header.lower()
        
        if 'samesite=strict' in cookie_lower:
            return 'strict'
        elif 'samesite=lax' in cookie_lower:
            return 'lax'
        elif 'samesite=none' in cookie_lower:
            return 'none'
        
        return ''
    
    def _check_samesite(self, cookie_name: str, samesite: str,
                       value_preview: str, flags: Dict,
                       is_sensitive: bool, url: str = '', http_method: str = 'GET') -> Optional[CookieSecurityIssue]:
        """
        Check SameSite attribute for security issues.
        
        Args:
            cookie_name: Name of cookie
            samesite: SameSite value
            value_preview: Truncated cookie value
            flags: Dictionary of cookie flags
            is_sensitive: Whether cookie is sensitive
            
        Returns:
            CookieSecurityIssue if there's a problem, None otherwise
        """
        if not samesite or samesite == '':
            # Missing SameSite attribute
            severity = CookieSeverity.HIGH if is_sensitive else CookieSeverity.MEDIUM
            return CookieSecurityIssue(
                cookie_name=cookie_name,
                cookie_value_preview=value_preview,
                issue_type='missing_samesite',
                severity=severity,
                current_flags=flags,
                description=(
                    f"Cookie '{cookie_name}' is missing the SameSite attribute. "
                    f"This cookie may be vulnerable to CSRF attacks."
                ),
                impact=(
                    "Without SameSite attribute, cookies are sent with cross-site requests, "
                    "making the application vulnerable to Cross-Site Request Forgery (CSRF) attacks."
                ),
                remediation=(
                    f"Add SameSite attribute to cookie: Set-Cookie: {cookie_name}=...; SameSite=Strict\n"
                    "Use SameSite=Strict for authentication cookies, or SameSite=Lax for less strict requirements."
                ),
                references=[
                    'https://owasp.org/www-community/SameSite',
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite'
                ],
                endpoint_url=url,
                http_method=http_method,
            )

        elif samesite == 'none':
            # SameSite=None is weak (requires Secure flag)
            if not flags['secure']:
                return CookieSecurityIssue(
                    cookie_name=cookie_name,
                    cookie_value_preview=value_preview,
                    issue_type='weak_samesite',
                    severity=CookieSeverity.HIGH,
                    current_flags=flags,
                    description=(
                        f"Cookie '{cookie_name}' uses SameSite=None without Secure flag. "
                        f"This is a dangerous configuration."
                    ),
                    impact=(
                        "SameSite=None without Secure allows cookies to be sent cross-site over HTTP, "
                        "enabling both CSRF attacks and cookie theft via network sniffing."
                    ),
                    remediation=(
                        f"Either add Secure flag with SameSite=None, or change to SameSite=Strict/Lax:\n"
                        f"Set-Cookie: {cookie_name}=...; SameSite=None; Secure (or use SameSite=Strict)"
                    ),
                    references=[
                        'https://web.dev/samesite-cookies-explained/',
                        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite'
                    ],
                    endpoint_url=url,
                    http_method=http_method,
                )
            elif is_sensitive:
                # SameSite=None is generally weak for sensitive cookies even with Secure
                return CookieSecurityIssue(
                    cookie_name=cookie_name,
                    cookie_value_preview=value_preview,
                    issue_type='weak_samesite',
                    severity=CookieSeverity.MEDIUM,
                    current_flags=flags,
                    description=(
                        f"Sensitive cookie '{cookie_name}' uses SameSite=None. "
                        f"Consider using SameSite=Strict or Lax for better CSRF protection."
                    ),
                    impact="SameSite=None allows cookies to be sent with cross-site requests, reducing CSRF protection",
                    remediation=(
                        f"Change to SameSite=Strict for maximum protection:\n"
                        f"Set-Cookie: {cookie_name}=...; SameSite=Strict; Secure; HttpOnly"
                    ),
                    references=[
                        'https://web.dev/samesite-cookies-explained/',
                        'https://owasp.org/www-community/SameSite'
                    ],
                    endpoint_url=url,
                    http_method=http_method,
                )

        return None
    
    def _is_sensitive_cookie(self, cookie_name: str) -> bool:
        """
        Determine if cookie is likely to contain sensitive data.
        
        Args:
            cookie_name: Name of the cookie
            
        Returns:
            True if cookie appears sensitive
        """
        cookie_lower = cookie_name.lower()
        return any(pattern in cookie_lower for pattern in self.sensitive_cookie_patterns)
    
    def _truncate_value(self, value: str, max_length: int = 20) -> str:
        """
        Truncate cookie value for display (security).
        
        Args:
            value: Cookie value
            max_length: Maximum length to display
            
        Returns:
            Truncated value with ellipsis
        """
        if len(value) <= max_length:
            return value
        return value[:max_length] + '...'
    
    def generate_summary(self, issues: List[CookieSecurityIssue]) -> Dict[str, Any]:
        """
        Generate summary of cookie security issues.
        
        Args:
            issues: List of CookieSecurityIssue objects
            
        Returns:
            Dictionary with summary statistics
        """
        if not issues:
            return {
                'total_issues': 0,
                'by_severity': {},
                'by_type': {},
                'status': 'secure'
            }
        
        # Count by severity
        severity_counts = {}
        for issue in issues:
            severity = issue.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count by type
        type_counts = {}
        for issue in issues:
            issue_type = issue.issue_type
            type_counts[issue_type] = type_counts.get(issue_type, 0) + 1
        
        # Determine status
        if severity_counts.get('High', 0) > 0:
            status = 'vulnerable'
        elif severity_counts.get('Medium', 0) > 0:
            status = 'at_risk'
        else:
            status = 'minor_issues'
        
        return {
            'total_issues': len(issues),
            'by_severity': severity_counts,
            'by_type': type_counts,
            'status': status,
            'issues': [issue.to_dict() for issue in issues]
        }
