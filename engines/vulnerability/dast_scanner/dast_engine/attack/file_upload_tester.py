"""
File Upload Security Tester
Tests file upload endpoints for security vulnerabilities (malicious file upload, type bypasses)
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import io
import requests


class UploadSeverity(Enum):
    """Severity levels for file upload vulnerabilities"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class FileUploadVulnerability:
    """Represents a file upload vulnerability"""
    endpoint_url: str
    http_method: str
    parameter_name: str
    vulnerability_type: str  # unrestricted_upload, weak_validation, path_traversal, etc.
    test_file_name: str
    test_file_type: str
    severity: UploadSeverity
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
            'vulnerability_type': self.vulnerability_type,
            'test_file_name': self.test_file_name,
            'test_file_type': self.test_file_type,
            'severity': self.severity.value,
            'description': self.description,
            'evidence': self.evidence,
            'impact': self.impact,
            'remediation': self.remediation,
            'confidence': self.confidence,
            'references': self.references
        }


class FileUploadSecurityTester:
    """
    Tests file upload endpoints for security vulnerabilities.
    NOTE: Uses safe, non-destructive test payloads only.
    """
    
    def __init__(self, auth_manager=None):
        """
        Initialize file upload security tester.
        
        Args:
            auth_manager: Authentication manager for making authenticated requests
        """
        self.auth_manager = auth_manager
        self.session = auth_manager.get_session() if auth_manager else requests.Session()
        
        # Safe test files (non-malicious content, just testing validation)
        self.test_files = [
            # Executable extensions (safe content)
            {
                'name': 'test.php',
                'content': '<!-- Safe test file -->',
                'mime': 'application/x-php',
                'type': 'executable',
                'severity': UploadSeverity.CRITICAL
            },
            {
                'name': 'test.jsp',
                'content': '<!-- Safe test file -->',
                'mime': 'application/x-jsp',
                'type': 'executable',
                'severity': UploadSeverity.CRITICAL
            },
            {
                'name': 'test.asp',
                'content': '<!-- Safe test file -->',
                'mime': 'application/x-asp',
                'type': 'executable',
                'severity': UploadSeverity.CRITICAL
            },
            {
                'name': 'test.aspx',
                'content': '<!-- Safe test file -->',
                'mime': 'application/x-aspx',
                'type': 'executable',
                'severity': UploadSeverity.CRITICAL
            },
            # Script extensions
            {
                'name': 'test.js',
                'content': '// Safe test file',
                'mime': 'application/javascript',
                'type': 'script',
                'severity': UploadSeverity.HIGH
            },
            {
                'name': 'test.sh',
                'content': '# Safe test file',
                'mime': 'application/x-sh',
                'type': 'script',
                'severity': UploadSeverity.HIGH
            },
            # Path traversal attempts
            {
                'name': '../test.txt',
                'content': 'Safe test content',
                'mime': 'text/plain',
                'type': 'path_traversal',
                'severity': UploadSeverity.HIGH
            },
            {
                'name': '..\\test.txt',
                'content': 'Safe test content',
                'mime': 'text/plain',
                'type': 'path_traversal',
                'severity': UploadSeverity.HIGH
            },
            # Double extension bypass
            {
                'name': 'test.jpg.php',
                'content': '<!-- Safe test file -->',
                'mime': 'image/jpeg',
                'type': 'double_extension',
                'severity': UploadSeverity.HIGH
            },
            # Null byte injection
            {
                'name': 'test.php\x00.jpg',
                'content': '<!-- Safe test file -->',
                'mime': 'image/jpeg',
                'type': 'null_byte',
                'severity': UploadSeverity.HIGH
            },
            # Content-Type bypass (PHP with image MIME)
            {
                'name': 'test.php',
                'content': '<!-- Safe test file -->',
                'mime': 'image/jpeg',
                'type': 'mime_bypass',
                'severity': UploadSeverity.HIGH
            },
            # HTML with JavaScript (for stored XSS via upload)
            {
                'name': 'test.html',
                'content': '<!-- Safe test file --><html><body>Test</body></html>',
                'mime': 'text/html',
                'type': 'html_upload',
                'severity': UploadSeverity.MEDIUM
            },
            # SVG with script (potential XSS)
            {
                'name': 'test.svg',
                'content': '<svg xmlns="http://www.w3.org/2000/svg"><text>Test</text></svg>',
                'mime': 'image/svg+xml',
                'type': 'svg_upload',
                'severity': UploadSeverity.MEDIUM
            },
        ]
    
    def test_endpoint(self, endpoint) -> List[FileUploadVulnerability]:
        """
        Test file upload endpoint for vulnerabilities.
        
        Args:
            endpoint: Endpoint object with file parameter
            
        Returns:
            List of FileUploadVulnerability objects
        """
        vulnerabilities = []
        
        # Find file upload parameters
        file_params = self._find_file_parameters(endpoint)
        
        if not file_params:
            return vulnerabilities
        
        # Test each file parameter
        for param in file_params:
            param_vulns = self._test_file_parameter(endpoint, param)
            vulnerabilities.extend(param_vulns)
        
        return vulnerabilities
    
    def _find_file_parameters(self, endpoint) -> List[Any]:
        """
        Find parameters that accept file uploads.
        
        Args:
            endpoint: Endpoint object
            
        Returns:
            List of file parameters
        """
        file_params = []
        
        # Collect all parameters
        all_params = []
        if hasattr(endpoint, 'body_params'):
            all_params.extend(endpoint.body_params or [])
        if hasattr(endpoint, 'parameters'):
            all_params.extend(endpoint.parameters or [])
        
        # Filter for file parameters
        for param in all_params:
            # Check if parameter type is FILE
            if hasattr(param, 'param_type') and param.param_type.value == 'file':
                file_params.append(param)
            # Check if parameter name suggests file upload
            elif any(keyword in param.name.lower() for keyword in ['file', 'upload', 'attachment', 'document', 'image', 'photo']):
                file_params.append(param)
        
        return file_params
    
    def _test_file_parameter(self, endpoint, param) -> List[FileUploadVulnerability]:
        """
        Test a file parameter with various test files.
        
        Args:
            endpoint: Endpoint object
            param: File parameter to test
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        for test_file in self.test_files:
            try:
                # Prepare file upload
                files = {
                    param.name: (
                        test_file['name'],
                        io.BytesIO(test_file['content'].encode('utf-8')),
                        test_file['mime']
                    )
                }
                
                # Send upload request
                response = self.session.request(
                    method=endpoint.method.value,
                    url=endpoint.url,
                    files=files,
                    timeout=10
                )
                
                # Check if upload was accepted
                if self._upload_accepted(response, test_file):
                    vuln = self._create_vulnerability(
                        endpoint=endpoint,
                        param=param,
                        test_file=test_file,
                        response=response
                    )
                    vulnerabilities.append(vuln)
            
            except requests.RequestException:
                # Upload failed, continue to next test
                continue
        
        return vulnerabilities
    
    def _upload_accepted(self, response: requests.Response, test_file: Dict) -> bool:
        """
        Determine if file upload was accepted by server.
        
        Args:
            response: HTTP response
            test_file: Test file configuration
            
        Returns:
            True if upload appears to have been accepted
        """
        # Success status codes
        if response.status_code in [200, 201, 202, 204]:
            # Check response for success indicators
            response_text = response.text.lower()
            
            success_indicators = [
                'success', 'uploaded', 'saved', 'accepted',
                'file received', 'upload complete', test_file['name'].lower()
            ]
            
            if any(indicator in response_text for indicator in success_indicators):
                return True
            
            # Check for absence of error indicators
            error_indicators = [
                'error', 'invalid', 'forbidden', 'not allowed',
                'rejected', 'failed', 'denied'
            ]
            
            if not any(indicator in response_text for indicator in error_indicators):
                # Likely accepted (no explicit error)
                return True
        
        return False
    
    def _create_vulnerability(self, endpoint, param, test_file: Dict,
                            response: requests.Response) -> FileUploadVulnerability:
        """
        Create vulnerability object for accepted dangerous file upload.
        
        Args:
            endpoint: Endpoint object
            param: File parameter
            test_file: Test file configuration
            response: HTTP response
            
        Returns:
            FileUploadVulnerability object
        """
        vuln_type = test_file['type']
        
        descriptions = {
            'executable': (
                f"The application accepts server-side executable files (*.{test_file['name'].split('.')[-1]}) "
                f"without proper validation. This could allow remote code execution."
            ),
            'script': (
                f"The application accepts script files ({test_file['name']}) that could be executed "
                f"or interpreted by the server or client."
            ),
            'path_traversal': (
                f"The application accepts filenames with path traversal sequences ({test_file['name']}), "
                f"potentially allowing files to be written outside intended directories."
            ),
            'double_extension': (
                f"The application accepts files with double extensions ({test_file['name']}), "
                f"which could bypass extension-based security controls."
            ),
            'null_byte': (
                f"The application accepts filenames with null byte injection, "
                f"potentially bypassing extension validation."
            ),
            'mime_bypass': (
                f"The application accepts executable files with spoofed MIME types, "
                f"indicating weak file type validation."
            ),
            'html_upload': (
                f"The application accepts HTML files which could lead to stored XSS "
                f"if files are served without proper Content-Type headers."
            ),
            'svg_upload': (
                f"The application accepts SVG files which can contain embedded JavaScript, "
                f"potentially leading to stored XSS attacks."
            ),
        }
        
        impacts = {
            'executable': (
                "CRITICAL: Attackers can upload and execute malicious code on the server, "
                "leading to complete system compromise, data breach, or use of server for attacks."
            ),
            'script': (
                "HIGH: Uploaded scripts may be executed server-side or client-side, "
                "potentially leading to code execution or cross-site scripting."
            ),
            'path_traversal': (
                "HIGH: Attackers can write files to arbitrary locations, potentially overwriting "
                "critical system files or placing malicious files in executable directories."
            ),
            'double_extension': (
                "HIGH: Weak extension filtering can be bypassed, allowing upload of malicious files "
                "that may be executed by the server."
            ),
            'null_byte': (
                "HIGH: Null byte injection bypasses security controls, allowing upload of "
                "dangerous file types that should be blocked."
            ),
            'mime_bypass': (
                "HIGH: MIME-type based validation is insufficient, allowing upload of executable "
                "files disguised as safe file types."
            ),
            'html_upload': (
                "MEDIUM: HTML uploads can lead to stored XSS attacks if files are accessible "
                "without proper Content-Security-Policy headers."
            ),
            'svg_upload': (
                "MEDIUM: SVG files can contain JavaScript and lead to stored XSS if not "
                "properly sanitized and served with correct headers."
            ),
        }
        
        return FileUploadVulnerability(
            endpoint_url=endpoint.url,
            http_method=endpoint.method.value,
            parameter_name=param.name,
            vulnerability_type=vuln_type,
            test_file_name=test_file['name'],
            test_file_type=test_file['type'],
            severity=test_file['severity'],
            description=descriptions.get(vuln_type, "File upload security issue detected"),
            evidence=(
                f"Test file '{test_file['name']}' (MIME: {test_file['mime']}) was accepted. "
                f"Response status: {response.status_code}"
            ),
            impact=impacts.get(vuln_type, "Insecure file upload can lead to security compromise"),
            remediation=(
                "1. Implement allowlist-based file type validation (extension AND content)\n"
                "2. Validate file content (magic bytes) not just extension/MIME type\n"
                "3. Rename uploaded files with random names\n"
                "4. Store uploads outside webroot or in non-executable directory\n"
                "5. Set proper Content-Type and Content-Disposition headers when serving files\n"
                "6. Implement file size limits\n"
                "7. Scan uploaded files with antivirus\n"
                "8. Use Content-Security-Policy headers to restrict script execution\n"
                "9. Never trust user-supplied filenames (sanitize path traversal)\n"
                "10. Consider using dedicated file storage service (S3, etc.)"
            ),
            confidence=0.85,
            references=[
                'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
                'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
                'https://cwe.mitre.org/data/definitions/434.html'
            ]
        )
