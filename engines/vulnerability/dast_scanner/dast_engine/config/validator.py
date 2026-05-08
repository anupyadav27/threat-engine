"""
Input validation for DAST configuration
"""

import re
from urllib.parse import urlparse
from typing import List, Tuple, Dict, Any


class ValidationError(Exception):
    """Validation error"""
    pass


class InputValidator:
    """Validates all DAST configuration inputs"""
    
    @staticmethod
    def validate_url(url: str) -> Tuple[bool, str]:
        """
        Validate target URL
        
        Args:
            url: Target URL
        
        Returns:
            (is_valid, error_message)
        """
        if not url:
            return False, "URL is required"
        
        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"Invalid URL format: {e}"
        
        # Check scheme
        if parsed.scheme not in ['http', 'https']:
            return False, "URL must use http or https scheme"
        
        # Check hostname
        if not parsed.hostname:
            return False, "URL must include a hostname"
        
        # Check if localhost/internal IP (warning for production)
        if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
            return True, "WARNING: Scanning localhost"
        
        # Check for private IPs
        if InputValidator._is_private_ip(parsed.hostname):
            return True, "WARNING: Scanning private IP address"
        
        return True, ""
    
    @staticmethod
    def _is_private_ip(hostname: str) -> bool:
        """Check if hostname is a private IP"""
        if not hostname:
            return False
        
        # Simple check for private IP ranges
        private_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.',
        ]
        
        for pattern in private_patterns:
            if re.match(pattern, hostname):
                return True
        
        return False
    
    @staticmethod
    def validate_scope(scope_patterns: List[str]) -> Tuple[bool, str]:
        """
        Validate scope patterns
        
        Args:
            scope_patterns: List of URL patterns
        
        Returns:
            (is_valid, error_message)
        """
        if not scope_patterns:
            return False, "At least one scope pattern is required"
        
        for pattern in scope_patterns:
            if not isinstance(pattern, str):
                return False, f"Scope pattern must be a string: {pattern}"
            if not pattern.startswith('/'):
                return False, f"Scope pattern must start with '/': {pattern}"
        
        return True, ""
    
    @staticmethod
    def validate_intensity(intensity: str) -> Tuple[bool, str]:
        """Validate scan intensity"""
        valid_intensities = ['quick', 'normal', 'thorough', 'aggressive']
        
        if intensity not in valid_intensities:
            return False, f"Invalid intensity. Must be one of: {', '.join(valid_intensities)}"
        
        return True, ""
    
    @staticmethod
    def validate_authentication(auth_config: dict) -> Tuple[bool, str]:
        """Validate authentication configuration"""
        auth_type = auth_config.get('type', 'none')
        
        if auth_type == 'none':
            return True, ""
        
        elif auth_type == 'bearer':
            bearer = auth_config.get('bearer', {})
            if 'token' in bearer and bearer['token']:
                return True, ""
            return False, "Bearer token required for bearer auth"
        
        elif auth_type == 'basic':
            basic = auth_config.get('basic', {})
            if 'username' in basic and 'password' in basic:
                if basic['username'] and basic['password']:
                    return True, ""
            return False, "Username and password required for basic auth"
        
        elif auth_type == 'cookie':
            cookie = auth_config.get('cookie', {})
            if 'cookie_value' in cookie or 'login_url' in cookie:
                return True, ""
            return False, "Cookie value or login URL required"
        
        elif auth_type == 'oauth2':
            oauth = auth_config.get('oauth2', {})
            required_fields = ['token_url', 'client_id', 'client_secret']
            for field in required_fields:
                if field not in oauth:
                    return False, f"OAuth2 requires {field}"
            return True, ""
        
        else:
            return False, f"Unsupported auth type: {auth_type}"
    
    @staticmethod
    def validate_rate_limit(rate_limit: int, environment: str) -> Tuple[bool, str]:
        """Validate rate limit based on environment"""
        if rate_limit <= 0:
            return False, "Rate limit must be positive"
        
        # Production safety checks
        if environment == 'production' and rate_limit > 10:
            return False, "Production scans limited to 10 req/s max for safety"
        
        if rate_limit > 1000:
            return False, "Rate limit too high (max: 1000 req/s)"
        
        return True, ""
    
    @staticmethod
    def validate_environment(environment: str) -> Tuple[bool, str]:
        """Validate environment value"""
        valid_environments = ['development', 'staging', 'production']
        
        if environment not in valid_environments:
            return False, f"Invalid environment. Must be one of: {', '.join(valid_environments)}"
        
        return True, ""
    
    @staticmethod
    def validate_full_config(config: dict) -> List[str]:
        """
        Validate entire configuration
        
        Returns:
            List of error messages (empty if valid)
        """
        errors = []
        warnings = []
        
        # Validate URL
        url = config.get('target', {}).get('url')
        valid, msg = InputValidator.validate_url(url)
        if not valid:
            errors.append(f"URL: {msg}")
        elif msg:  # Warning message
            warnings.append(msg)
        
        # Validate scope
        scope = config.get('target', {}).get('scope', {}).get('include', [])
        valid, msg = InputValidator.validate_scope(scope)
        if not valid:
            errors.append(f"Scope: {msg}")
        
        # Validate intensity
        intensity = config.get('scan', {}).get('intensity', 'normal')
        valid, msg = InputValidator.validate_intensity(intensity)
        if not valid:
            errors.append(f"Intensity: {msg}")
        
        # Validate authentication
        auth = config.get('authentication', {})
        valid, msg = InputValidator.validate_authentication(auth)
        if not valid:
            errors.append(f"Authentication: {msg}")
        
        # Validate environment
        environment = config.get('safety', {}).get('environment', 'staging')
        valid, msg = InputValidator.validate_environment(environment)
        if not valid:
            errors.append(f"Environment: {msg}")
        
        # Validate rate limit
        rate_limit = config.get('scan', {}).get('performance', {}).get('rate_limit', 50)
        valid, msg = InputValidator.validate_rate_limit(rate_limit, environment)
        if not valid:
            errors.append(f"Rate limit: {msg}")
        
        # Validate numeric values
        max_depth = config.get('scan', {}).get('crawler', {}).get('max_depth', 5)
        if not isinstance(max_depth, int) or max_depth <= 0:
            errors.append("Max depth must be a positive integer")
        
        max_pages = config.get('scan', {}).get('crawler', {}).get('max_pages', 1000)
        if not isinstance(max_pages, int) or max_pages <= 0:
            errors.append("Max pages must be a positive integer")
        
        # Display warnings
        if warnings:
            for warning in warnings:
                print(f"[WARN]  {warning}")
        
        return errors
