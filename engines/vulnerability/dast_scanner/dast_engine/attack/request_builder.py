"""
Request Builder - Constructs complete HTTP requests with payloads
Handles authentication, headers, and different request types
"""

import json
import logging
import time
from typing import Dict, Any, Optional
from urllib.parse import urlencode, urlparse

import requests

logger = logging.getLogger('DASTScanner.RequestBuilder')


class RequestBuilder:
    """
    Builds and sends HTTP requests with injected payloads.
    Applies authentication and proper headers.
    """

    def __init__(self, auth_manager=None, config=None):
        """
        Initialize request builder.

        Args:
            auth_manager: Authentication manager from Step 1
            config: DAST configuration dict (used for ssl_verify, user_agent, timeout, retries)
        """
        self.auth_manager = auth_manager
        self.config = config or {}

        ssl_verify = self.config.get('ssl_verify', True)
        user_agent = self.config.get('user_agent', 'DAST-Scanner/1.0')
        self.timeout = self.config.get('timeout', 10)
        self.retry_attempts = self.config.get('retry_attempts', 2)
        self.retry_delay = self.config.get('retry_delay', 1.0)

        if not ssl_verify:
            logger.warning(
                "SSL verification is DISABLED. Only use this in isolated test environments."
            )
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.ssl_verify = ssl_verify

        # Use the auth manager's pre-configured session when available so
        # bearer tokens, basic-auth credentials, and cookies are carried
        # automatically.  Fall back to a plain session if no auth is needed.
        if auth_manager is not None:
            try:
                self.session = auth_manager.get_session()
            except Exception:
                logger.warning("Could not obtain auth session; using plain session.")
                self.session = requests.Session()
        else:
            self.session = requests.Session()

        self.session.headers.update({
            'User-Agent': user_agent,
            'Accept': '*/*',
        })

    def build_request(self, endpoint, parameter, payload_value) -> Dict[str, Any]:
        """
        Build complete HTTP request data.

        Args:
            endpoint: Endpoint object with URL, method, etc.
            parameter: Parameter object with location info
            payload_value: Injected payload value or modified URL

        Returns:
            Dictionary with request data (url, method, headers, body, etc.)
        """
        location = self._normalize_location(parameter)

        if location in ('query', 'path'):
            url = payload_value  # Already modified by injector
        else:
            url = endpoint.url

        headers = self._prepare_headers(endpoint)

        body = None
        if location == 'body':
            body = self._prepare_body(endpoint, parameter, payload_value)

        method = getattr(endpoint.method, 'value', endpoint.method)

        return {
            'method': method,
            'url': url,
            'headers': headers,
            'body': body,
            'timeout': self.timeout,
        }

    def send_request(self, request_data: Dict[str, Any]) -> Optional[requests.Response]:
        """
        Send HTTP request with retry logic.

        Args:
            request_data: Request data from build_request()

        Returns:
            Response object or None on failure
        """
        last_exc: Optional[Exception] = None

        for attempt in range(1, self.retry_attempts + 2):  # +2 so default 2 retries = 3 total attempts
            try:
                response = self.session.request(
                    method=request_data.get('method', 'GET'),
                    url=request_data.get('url'),
                    headers=request_data.get('headers'),
                    data=request_data.get('body'),
                    timeout=request_data.get('timeout', self.timeout),
                    allow_redirects=False,
                    verify=self.ssl_verify,
                )
                return response

            except requests.exceptions.Timeout as exc:
                logger.debug("Request timed out (attempt %d): %s", attempt, request_data.get('url'))
                last_exc = exc
            except requests.exceptions.ConnectionError as exc:
                logger.debug("Connection error (attempt %d): %s", attempt, request_data.get('url'))
                last_exc = exc
            except requests.exceptions.RequestException as exc:
                logger.debug("Request error (attempt %d): %s - %s", attempt, request_data.get('url'), exc)
                last_exc = exc
                break  # Non-transient; don't retry

            if attempt <= self.retry_attempts:
                time.sleep(self.retry_delay)

        logger.warning("Request failed after %d attempts: %s — %s",
                       self.retry_attempts + 1, request_data.get('url'), last_exc)
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize_location(self, parameter) -> str:
        """Return parameter location as a lowercase string, handling enums."""
        loc = getattr(parameter, 'location', 'query')
        if hasattr(loc, 'value'):
            loc = loc.value
        return str(loc).lower()

    def _prepare_headers(self, endpoint) -> Dict[str, str]:
        """
        Prepare HTTP headers.  Auth headers come from the shared session;
        this method only adds Content-Type when needed.
        """
        headers: Dict[str, str] = {}

        if hasattr(endpoint, 'content_type'):
            headers['Content-Type'] = endpoint.content_type
        elif hasattr(endpoint, 'method'):
            method = getattr(endpoint.method, 'value', endpoint.method)
            if str(method).upper() in ('POST', 'PUT', 'PATCH'):
                headers['Content-Type'] = 'application/json'

        return headers

    def _prepare_body(self, endpoint, parameter, payload_value) -> Optional[str]:
        """
        Prepare request body with injected payload.
        """
        if hasattr(endpoint, 'body_template'):
            try:
                body_dict = json.loads(endpoint.body_template)
                body_dict[parameter.name] = payload_value
                return json.dumps(body_dict)
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                logger.debug("Could not inject into body_template: %s", exc)
                return endpoint.body_template

        content_type = getattr(endpoint, 'content_type', '')
        if 'json' in content_type.lower():
            return json.dumps({parameter.name: payload_value})

        return urlencode({parameter.name: payload_value})


class RateLimiter:
    """Simple rate limiter for request throttling."""

    def __init__(self, requests_per_second: int = 10):
        import time as _time
        from threading import Lock
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0.0
        self.lock = Lock()

    def wait(self):
        """Wait if necessary to respect rate limit."""
        import time
        with self.lock:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_request_time = time.time()
