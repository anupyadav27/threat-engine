"""
Authentication Manager
Handles different authentication methods
"""

import requests
from typing import Dict, Any, Optional
import time
import base64
import logging

logger = logging.getLogger('DASTScanner.Auth')


class AuthenticationError(Exception):
    """Authentication-related errors"""
    pass


class AuthenticationManager:
    """
    Manages authentication for DAST scanning
    Supports: None, Basic, Bearer, Cookie, OAuth2
    """
    
    def __init__(self, auth_config: Dict[str, Any]):
        """
        Initialize authentication manager
        
        Args:
            auth_config: Authentication configuration
        """
        self.auth_config = auth_config
        self.auth_type = auth_config.get('type', 'none')
        self.session = requests.Session()
        self.token = None
        self.token_expiry = None
        
        # Initialize authentication
        self._initialize_auth()
    
    def _initialize_auth(self):
        """Initialize authentication based on type"""
        if self.auth_type == 'none':
            return
        
        elif self.auth_type == 'bearer':
            self._setup_bearer_auth()
        
        elif self.auth_type == 'basic':
            self._setup_basic_auth()
        
        elif self.auth_type == 'cookie':
            self._setup_cookie_auth()
        
        elif self.auth_type == 'oauth2':
            self._setup_oauth2()
        
        else:
            raise AuthenticationError(f"Unsupported auth type: {self.auth_type}")
    
    def _setup_bearer_auth(self):
        """Setup Bearer token authentication"""
        bearer_config = self.auth_config.get('bearer', {})
        self.token = bearer_config.get('token')
        
        if not self.token:
            raise AuthenticationError("Bearer token not provided")
        
        # Add to session headers
        header_name = bearer_config.get('header_name', 'Authorization')
        prefix = bearer_config.get('prefix', 'Bearer')
        self.session.headers[header_name] = f"{prefix} {self.token}"
        
        logger.info("Bearer authentication configured")
    
    def _setup_basic_auth(self):
        """Setup HTTP Basic authentication"""
        basic_config = self.auth_config.get('basic', {})
        username = basic_config.get('username')
        password = basic_config.get('password')
        
        if not username or not password:
            raise AuthenticationError("Username and password required for basic auth")
        
        # Set auth on session
        self.session.auth = (username, password)
        
        logger.info("Basic authentication configured (user: %s)", username)
    
    def _setup_cookie_auth(self):
        """Setup cookie-based authentication"""
        cookie_config = self.auth_config.get('cookie', {})
        
        # Method 1: Direct cookie value
        if 'cookie_value' in cookie_config:
            cookie_name = cookie_config.get('session_cookie_name', 'session')
            cookie_value = cookie_config['cookie_value']
            self.session.cookies.set(cookie_name, cookie_value)
            logger.info("Cookie authentication configured (%s)", cookie_name)
        
        # Method 2: Login to get cookie
        elif 'login_url' in cookie_config:
            self._perform_login(cookie_config)
        else:
            raise AuthenticationError("Cookie authentication requires cookie_value or login_url")
    
    def _perform_login(self, login_config: Dict[str, Any]):
        """
        Perform login to obtain session cookie
        
        Args:
            login_config: Login configuration
        """
        login_url = login_config['login_url']
        credentials = login_config.get('login_credentials', {})
        method = login_config.get('login_method', 'POST').upper()
        
        logger.info("Performing login at %s", login_url)
        
        # Prepare login data
        login_params = login_config.get('login_params', {})
        login_data = {}
        
        for key, value in login_params.items():
            # Replace placeholders like {{username}}
            if isinstance(value, str) and value.startswith('{{') and value.endswith('}}'):
                cred_key = value[2:-2]
                login_data[key] = credentials.get(cred_key, value)
            else:
                login_data[key] = value
        
        # Perform login
        try:
            if method == 'POST':
                response = self.session.post(login_url, data=login_data, timeout=30)
            else:
                response = self.session.get(login_url, params=login_data, timeout=30)
            
            # Check success
            success_indicator = login_config.get('success_indicator')
            if success_indicator:
                if success_indicator not in response.text:
                    raise AuthenticationError(
                        f"Login failed: '{success_indicator}' not found in response"
                    )
            
            # Check for cookies
            if not self.session.cookies:
                raise AuthenticationError("Login did not set any cookies")
            
            logger.info("Login successful, session established")
            
        except requests.RequestException as e:
            raise AuthenticationError(f"Login request failed: {e}")
    
    def _setup_oauth2(self):
        """Setup OAuth2 authentication"""
        oauth_config = self.auth_config.get('oauth2', {})
        
        token_url = oauth_config.get('token_url')
        client_id = oauth_config.get('client_id')
        client_secret = oauth_config.get('client_secret')
        scope = oauth_config.get('scope', '')
        
        logger.info("Requesting OAuth2 token from %s", token_url)
        
        # Request access token
        data = {
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': scope
        }
        
        try:
            response = requests.post(token_url, data=data, timeout=30)
            response.raise_for_status()
            
            token_data = response.json()
            self.token = token_data.get('access_token')
            
            if not self.token:
                raise AuthenticationError("OAuth2 response missing access_token")
            
            expires_in = token_data.get('expires_in', 3600)
            self.token_expiry = time.time() + expires_in
            
            # Add to session
            self.session.headers['Authorization'] = f"Bearer {self.token}"
            
            logger.info("OAuth2 token acquired (expires in %ds)", expires_in)
            
        except requests.RequestException as e:
            raise AuthenticationError(f"OAuth2 token request failed: {e}")
    
    def get_session(self) -> requests.Session:
        """
        Get authenticated session
        
        Returns:
            requests.Session with authentication
        """
        # Refresh token if needed
        if self.auth_type == 'oauth2' and self._token_expired():
            logger.info("OAuth2 token expired, refreshing...")
            self._setup_oauth2()
        
        return self.session
    
    def _token_expired(self) -> bool:
        """Check if OAuth2 token is expired"""
        if not self.token_expiry:
            return False
        # Refresh 60 seconds before expiry
        return time.time() >= (self.token_expiry - 60)
    
    def verify_authentication(self, verify_endpoint: Optional[str] = None) -> bool:
        """
        Verify authentication is working
        
        Args:
            verify_endpoint: Optional endpoint to test auth
        
        Returns:
            True if authenticated
        """
        if not verify_endpoint:
            verify_endpoint = self.auth_config.get('session', {}).get('verify_endpoint')
        
        if not verify_endpoint:
            # No verification endpoint, assume OK
            return True
        
        try:
            logger.info("Verifying authentication at %s", verify_endpoint)
            response = self.session.get(verify_endpoint, timeout=10)
            
            if response.status_code == 200:
                logger.info("Authentication verified successfully")
                return True
            elif response.status_code == 401:
                logger.warning("Authentication failed: 401 Unauthorized")
                return False
            else:
                logger.warning("Verification returned status %d", response.status_code)
                return True  # Allow scan to continue with warning

        except requests.RequestException as e:
            logger.warning("Authentication verification failed: %s", e)
            return False
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Return authentication-specific HTTP headers for the current session.
        Refreshes OAuth2 token first if it is near expiry.
        """
        if self.auth_type == 'oauth2' and self._token_expired():
            self._setup_oauth2()

        auth_headers: Dict[str, str] = {}
        # Pull any custom auth headers that were set on the session
        skip = {'user-agent', 'accept-encoding', 'accept', 'connection', 'content-length'}
        for key, value in self.session.headers.items():
            if key.lower() not in skip:
                auth_headers[key] = value
        return auth_headers

    def get_auth_type(self) -> str:
        """Get current authentication type"""
        return self.auth_type
