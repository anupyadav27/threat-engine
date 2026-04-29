"""
Error Disclosure Detector
Enhanced detection of information leakage through error messages, stack traces, and debug info
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import re


class ErrorSeverity(Enum):
    """Severity levels for error disclosure"""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class ErrorDisclosureIssue:
    """Represents an error disclosure finding"""
    endpoint_url: str
    http_method: str
    error_type: str  # stack_trace, database_error, path_disclosure, debug_info, etc.
    severity: ErrorSeverity
    evidence: str
    evidence_preview: str
    description: str
    impact: str
    remediation: str
    confidence: float
    references: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (normalizer-compatible keys)."""
        return {
            'type': self.error_type,
            'severity': self.severity.value,
            'evidence': self.evidence_preview,
            'endpoint': {
                'url': self.endpoint_url,
                'method': self.http_method,
            },
            'parameter': {},
            'description': self.description,
            'impact': self.impact,
            'remediation': self.remediation,
            'confidence': self.confidence,
            'references': self.references,
        }


class ErrorDisclosureDetector:
    """
    Detects information leakage through error messages and debug output.
    Enhanced version with comprehensive pattern matching.
    """
    
    def __init__(self):
        """Initialize error disclosure detector with detection patterns."""
        
        # Stack trace patterns (language/framework specific)
        self.stack_trace_patterns = [
            # Python
            (r'Traceback \(most recent call last\):', 'Python stack trace', ErrorSeverity.HIGH),
            (r'File ".*?", line \d+, in \w+', 'Python stack trace', ErrorSeverity.HIGH),
            (r'  File ".*?", line \d+', 'Python stack trace', ErrorSeverity.HIGH),
            
            # Java
            (r'Exception in thread ".*?" .*?Exception', 'Java exception', ErrorSeverity.HIGH),
            (r'at .*?\(.*?\.java:\d+\)', 'Java stack trace', ErrorSeverity.HIGH),
            (r'Caused by: .*?Exception', 'Java nested exception', ErrorSeverity.HIGH),
            (r'javax\.servlet\..*?Exception', 'Java Servlet exception', ErrorSeverity.HIGH),
            (r'org\.springframework\..*?Exception', 'Spring Framework exception', ErrorSeverity.HIGH),
            
            # .NET/C#
            (r'Server Error in .*? Application', '.NET error page', ErrorSeverity.HIGH),
            (r'System\..*?Exception:', '.NET exception', ErrorSeverity.HIGH),
            (r'at .*? in .*?:line \d+', '.NET stack trace', ErrorSeverity.HIGH),
            (r'\[.*?Exception: .*?\]', '.NET exception', ErrorSeverity.HIGH),
            
            # PHP
            (r'Fatal error:.*? in .*? on line \d+', 'PHP fatal error', ErrorSeverity.HIGH),
            (r'Warning:.*? in .*? on line \d+', 'PHP warning', ErrorSeverity.MEDIUM),
            (r'Parse error:.*? in .*? on line \d+', 'PHP parse error', ErrorSeverity.HIGH),
            (r'Notice:.*? in .*? on line \d+', 'PHP notice', ErrorSeverity.LOW),
            
            # Ruby/Rails
            (r'.*?Error \(.*?\):', 'Ruby error', ErrorSeverity.HIGH),
            (r'from .*?:\d+:in `.*?\'', 'Ruby stack trace', ErrorSeverity.HIGH),
            
            # Node.js/JavaScript
            (r'Error: .*?\n\s+at .*? \(.*?:\d+:\d+\)', 'Node.js stack trace', ErrorSeverity.HIGH),
            (r'at .*? \(.*?\.js:\d+:\d+\)', 'JavaScript stack trace', ErrorSeverity.HIGH),
        ]
        
        # Path disclosure patterns
        self.path_disclosure_patterns = [
            (r'[A-Za-z]:\\(?:[\w\s\-\.]+\\)+[\w\s\-\.]+', 'Windows path disclosure', ErrorSeverity.MEDIUM),
            (r'/(?:home|var|usr|etc|opt|root)/(?:[\w\-\.]+/)+[\w\-\.]+', 'Unix path disclosure', ErrorSeverity.MEDIUM),
            (r'/Applications/.*?/.*?', 'macOS path disclosure', ErrorSeverity.MEDIUM),
        ]
        
        # Database error patterns (already in vulnerability_detector, but enhanced here)
        self.database_error_patterns = [
            (r'SQL syntax.*?error', 'SQL syntax error', ErrorSeverity.HIGH),
            (r'mysql_fetch.*?\(\)', 'MySQL function error', ErrorSeverity.HIGH),
            (r'You have an error in your SQL syntax', 'MySQL syntax error', ErrorSeverity.HIGH),
            (r'pg_query\(\).*?failed', 'PostgreSQL query error', ErrorSeverity.HIGH),
            (r'supplied argument is not a valid.*?result', 'Database result error', ErrorSeverity.HIGH),
            (r'Microsoft SQL Server.*?error', 'SQL Server error', ErrorSeverity.HIGH),
            (r'ORA-\d+:', 'Oracle database error', ErrorSeverity.HIGH),
            (r'DB2 SQL error', 'DB2 error', ErrorSeverity.HIGH),
            (r'SQLite.*?Exception', 'SQLite error', ErrorSeverity.HIGH),
        ]
        
        # Debug information patterns
        self.debug_info_patterns = [
            (r'<!--.*?debug.*?-->', 'Debug comment', ErrorSeverity.MEDIUM),
            (r'<pre>.*?Array.*?\(.*?\).*?</pre>', 'Debug array output', ErrorSeverity.MEDIUM),
            (r'var_dump\(', 'PHP var_dump output', ErrorSeverity.MEDIUM),
            (r'print_r\(', 'PHP print_r output', ErrorSeverity.MEDIUM),
            (r'Debug mode is (on|enabled|true)', 'Debug mode enabled', ErrorSeverity.HIGH),
            (r'SQLSTATE\[\w+\]:', 'PDO database error', ErrorSeverity.HIGH),
        ]
        
        # Framework/Server version disclosure
        self.version_disclosure_patterns = [
            (r'Apache/[\d\.]+', 'Apache version disclosure', ErrorSeverity.LOW),
            (r'nginx/[\d\.]+', 'Nginx version disclosure', ErrorSeverity.LOW),
            (r'PHP/[\d\.]+', 'PHP version disclosure', ErrorSeverity.LOW),
            (r'Python/[\d\.]+', 'Python version disclosure', ErrorSeverity.LOW),
            (r'Microsoft-IIS/[\d\.]+', 'IIS version disclosure', ErrorSeverity.LOW),
            (r'ASP\.NET Version:\s*[\d\.]+', 'ASP.NET version disclosure', ErrorSeverity.LOW),
            (r'Rails [\d\.]+', 'Rails version disclosure', ErrorSeverity.LOW),
            (r'Django version [\d\.]+', 'Django version disclosure', ErrorSeverity.LOW),
        ]
        
        # Configuration/sensitive data patterns
        self.sensitive_data_patterns = [
            (r'Connection string:.*?["\'].*?["\']', 'Database connection string', ErrorSeverity.HIGH),
            (r'password\s*=\s*["\'].*?["\']', 'Password in output', ErrorSeverity.HIGH),
            (r'api[_-]?key\s*[=:]\s*["\'][\w\-]+["\']', 'API key disclosure', ErrorSeverity.HIGH),
            (r'secret[_-]?key\s*[=:]\s*["\'].*?["\']', 'Secret key disclosure', ErrorSeverity.HIGH),
            (r'access[_-]?token\s*[=:]\s*["\'].*?["\']', 'Access token disclosure', ErrorSeverity.HIGH),
        ]
        
        # Compile all patterns
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile all regex patterns for efficiency."""
        self.compiled_patterns = {
            'stack_trace': [(re.compile(p, re.IGNORECASE | re.DOTALL), desc, sev)
                            for p, desc, sev in self.stack_trace_patterns],
            'path_disclosure': [(re.compile(p), desc, sev)
                                for p, desc, sev in self.path_disclosure_patterns],
            'database_error': [(re.compile(p, re.IGNORECASE), desc, sev)
                               for p, desc, sev in self.database_error_patterns],
            'debug_info': [(re.compile(p, re.IGNORECASE | re.DOTALL), desc, sev)
                           for p, desc, sev in self.debug_info_patterns],
            'version_disclosure': [(re.compile(p), desc, sev)
                                   for p, desc, sev in self.version_disclosure_patterns],
            'sensitive_data': [(re.compile(p, re.IGNORECASE), desc, sev)
                               for p, desc, sev in self.sensitive_data_patterns],
        }
    
    def analyze_response(self, response_body: str, response_headers: Dict[str, str],
                        endpoint_url: str, http_method: str) -> List[ErrorDisclosureIssue]:
        """
        Analyze HTTP response for error disclosure issues.
        
        Args:
            response_body: HTTP response body
            response_headers: HTTP response headers
            endpoint_url: URL of endpoint
            http_method: HTTP method used
            
        Returns:
            List of ErrorDisclosureIssue objects
        """
        issues = []
        
        # Check response body
        for category, patterns in self.compiled_patterns.items():
            for pattern, description, severity in patterns:
                matches = pattern.finditer(response_body)
                for match in matches:
                    evidence = match.group(0)
                    issue = self._create_issue(
                        endpoint_url=endpoint_url,
                        http_method=http_method,
                        error_type=category,
                        description=description,
                        severity=severity,
                        evidence=evidence
                    )
                    issues.append(issue)
                    # Only report first match per pattern to avoid spam
                    break
        
        # Check response headers for version disclosure
        header_issues = self._check_headers(response_headers, endpoint_url, http_method)
        issues.extend(header_issues)
        
        return issues
    
    def _check_headers(self, headers: Dict[str, str], endpoint_url: str, 
                      http_method: str) -> List[ErrorDisclosureIssue]:
        """
        Check response headers for information disclosure.
        
        Args:
            headers: Response headers
            endpoint_url: URL of endpoint
            http_method: HTTP method
            
        Returns:
            List of issues found in headers
        """
        issues = []
        
        # Headers that may leak version information
        version_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']
        
        for header_name in version_headers:
            header_value = headers.get(header_name) or headers.get(header_name.title())
            if header_value:
                # Check if version number is present
                if re.search(r'[\d\.]+', header_value):
                    issues.append(ErrorDisclosureIssue(
                        endpoint_url=endpoint_url,
                        http_method=http_method,
                        error_type='version_disclosure',
                        severity=ErrorSeverity.LOW,
                        evidence=f"{header_name}: {header_value}",
                        evidence_preview=f"{header_name}: {header_value[:50]}",
                        description=f"Server version information disclosed in {header_name} header",
                        impact=(
                            "Version information helps attackers identify known vulnerabilities "
                            "in specific software versions, facilitating targeted attacks."
                        ),
                        remediation=(
                            f"Remove or obscure the {header_name} header to hide version information:\n"
                            "- Configure web server to suppress version headers\n"
                            "- Use generic values without version numbers"
                        ),
                        confidence=0.95,
                        references=[
                            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
                            'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'
                        ]
                    ))
        
        return issues
    
    def _create_issue(self, endpoint_url: str, http_method: str, error_type: str,
                     description: str, severity: ErrorSeverity, evidence: str) -> ErrorDisclosureIssue:
        """
        Create ErrorDisclosureIssue object.
        
        Args:
            endpoint_url: URL of endpoint
            http_method: HTTP method
            error_type: Type of error/disclosure
            description: Description of the issue
            severity: Severity level
            evidence: Full evidence text
            
        Returns:
            ErrorDisclosureIssue object
        """
        # Truncate evidence for preview
        evidence_preview = evidence[:200] + '...' if len(evidence) > 200 else evidence
        
        # Build impact and remediation based on error type
        impact, remediation = self._get_impact_and_remediation(error_type)
        
        return ErrorDisclosureIssue(
            endpoint_url=endpoint_url,
            http_method=http_method,
            error_type=error_type,
            severity=severity,
            evidence=evidence,
            evidence_preview=evidence_preview,
            description=f"{description} detected in response from {endpoint_url}",
            impact=impact,
            remediation=remediation,
            confidence=0.9,
            references=[
                'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage',
                'https://cwe.mitre.org/data/definitions/209.html',
                'https://cwe.mitre.org/data/definitions/497.html'
            ]
        )
    
    def _get_impact_and_remediation(self, error_type: str) -> tuple[str, str]:
        """
        Get impact and remediation text for error type.
        
        Args:
            error_type: Type of error disclosure
            
        Returns:
            Tuple of (impact, remediation)
        """
        impacts = {
            'stack_trace': (
                "Stack traces reveal internal application structure, file paths, function names, "
                "and logic flow. Attackers can use this to identify vulnerable code, understand "
                "the technology stack, and plan more sophisticated attacks."
            ),
            'path_disclosure': (
                "File path disclosure reveals internal directory structure, which helps attackers "
                "understand the application layout and identify potential targets for path traversal "
                "or local file inclusion attacks."
            ),
            'database_error': (
                "Database errors reveal database type, version, and sometimes query structure. "
                "This information significantly aids SQL injection attacks and database-specific exploits."
            ),
            'debug_info': (
                "Debug information exposes internal application state, variable values, and logic. "
                "Attackers can use this to understand business logic and identify vulnerabilities."
            ),
            'version_disclosure': (
                "Version information helps attackers identify known vulnerabilities in specific "
                "software versions, enabling targeted exploitation of public CVEs."
            ),
            'sensitive_data': (
                "Exposure of credentials, API keys, or tokens in error messages can lead to "
                "direct compromise of the application, database, or third-party services."
            )
        }
        
        remediations = {
            'stack_trace': (
                "1. Disable detailed error messages in production\n"
                "2. Implement custom error pages without technical details\n"
                "3. Log detailed errors server-side for debugging\n"
                "4. Use try-catch blocks to handle exceptions gracefully\n"
                "5. Configure framework to hide stack traces (e.g., DEBUG=False in Django)"
            ),
            'path_disclosure': (
                "1. Configure error handling to suppress path information\n"
                "2. Use custom error pages without file paths\n"
                "3. Review application configuration for debug settings\n"
                "4. Log detailed paths server-side only"
            ),
            'database_error': (
                "1. Use generic error messages for database failures\n"
                "2. Catch and handle database exceptions properly\n"
                "3. Disable database error display in production\n"
                "4. Log detailed database errors securely server-side"
            ),
            'debug_info': (
                "1. Disable debug mode in production environments\n"
                "2. Remove debug output functions (var_dump, print_r, console.log)\n"
                "3. Remove HTML comments containing debugging information\n"
                "4. Use proper logging mechanisms instead of debug output"
            ),
            'version_disclosure': (
                "1. Remove or obscure version information from headers\n"
                "2. Configure web server to suppress version banners\n"
                "3. Use security.txt file for disclosure policy\n"
                "4. Implement security through defense-in-depth, not obscurity alone"
            ),
            'sensitive_data': (
                "1. Never include credentials or secrets in error messages\n"
                "2. Sanitize all output to remove sensitive data\n"
                "3. Use environment variables for sensitive configuration\n"
                "4. Implement proper secrets management\n"
                "5. Review code for hardcoded credentials"
            )
        }
        
        return (
            impacts.get(error_type, "Information leakage can aid attackers in reconnaissance"),
            remediations.get(error_type, "Implement proper error handling and disable debug output in production")
        )
