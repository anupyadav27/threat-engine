"""
Payload Injector - Injects payloads into different parameter locations
Handles query, path, body (JSON/form), headers, and cookies
"""

from urllib.parse import urlencode, parse_qs, urlparse, urlunparse, quote
import json
from typing import Any, Dict


class PayloadInjector:
    """
    Injects payloads into various parameter locations.
    Supports query, path, body (JSON/form), headers, and cookies.
    """
    
    def inject(self, endpoint, parameter, payload: str) -> str:
        """
        Main injection method. Routes to appropriate injection function.
        
        Args:
            endpoint: Endpoint object
            parameter: Parameter object with location info
            payload: Payload string to inject
            
        Returns:
            Injected value or modified URL/body
        """
        loc = getattr(parameter, 'location', 'query')
        location = str(getattr(loc, 'value', loc)).lower()
        
        if location == 'query':
            return self.inject_query_param(endpoint.url, parameter.name, payload)
        elif location == 'path':
            return self.inject_path_param(endpoint.url, parameter.name, payload)
        elif location == 'body':
            return payload  # Will be handled by RequestBuilder
        elif location == 'header':
            return payload
        elif location == 'cookie':
            return payload
        else:
            return payload
    
    def inject_query_param(self, url: str, param_name: str, payload: str) -> str:
        """
        Inject payload into query parameter.
        
        Example:
            URL: https://example.com/search?q=test
            Inject: q = <script>alert(1)</script>
            Result: https://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
        
        Args:
            url: Original URL
            param_name: Parameter name
            payload: Payload to inject
            
        Returns:
            Modified URL with payload injected
        """
        parsed = urlparse(url)
        
        # Parse existing query parameters
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Inject payload
        params[param_name] = [payload]
        
        # Rebuild query string (URL-encoded)
        new_query = urlencode(params, doseq=True)
        
        # Rebuild URL
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)
    
    def inject_path_param(self, url: str, param_name: str, payload: str) -> str:
        """
        Inject payload into path parameter.
        
        Example:
            URL: /api/users/{user_id}/profile
            Inject: user_id = ../../etc/passwd
            Result: /api/users/../../etc/passwd/profile
        
        Args:
            url: Original URL with path parameter placeholder
            param_name: Parameter name (e.g., 'user_id')
            payload: Payload to inject
            
        Returns:
            Modified URL with payload in path
        """
        # Replace {param_name} with payload
        if f'{{{param_name}}}' in url:
            return url.replace(f'{{{param_name}}}', quote(payload, safe=''))
        
        # If no placeholder, try to find and replace the value
        # This is a simplified approach - in production you'd need more context
        return url
    
    def inject_json_body(self, body: str, param_name: str, payload: str) -> str:
        """
        Inject payload into JSON body parameter.
        
        Example:
            Body: {"username": "admin", "password": "pass"}
            Inject: username = admin' OR 1=1--
            Result: {"username": "admin' OR 1=1--", "password": "pass"}
        
        Args:
            body: Original JSON body
            param_name: Parameter name
            payload: Payload to inject
            
        Returns:
            Modified JSON body string
        """
        try:
            # Parse JSON
            data = json.loads(body) if isinstance(body, str) else body
            
            # Inject payload
            data[param_name] = payload
            
            # Return as JSON string
            return json.dumps(data)
        except (json.JSONDecodeError, TypeError):
            return body
    
    def inject_form_body(self, body: str, param_name: str, payload: str) -> str:
        """
        Inject payload into form-encoded body parameter.
        
        Example:
            Body: username=admin&password=pass
            Inject: username = admin' OR 1=1--
            Result: username=admin%27+OR+1%3D1--&password=pass
        
        Args:
            body: Original form-encoded body
            param_name: Parameter name
            payload: Payload to inject
            
        Returns:
            Modified form-encoded body string
        """
        # Parse form data
        params = parse_qs(body, keep_blank_values=True)
        
        # Inject payload
        params[param_name] = [payload]
        
        # Rebuild form data
        return urlencode(params, doseq=True)
    
    def inject_header(self, headers: Dict[str, str], header_name: str, payload: str) -> Dict[str, str]:
        """
        Inject payload into HTTP header.
        
        Example:
            Headers: {"User-Agent": "Mozilla/5.0"}
            Inject: User-Agent = <script>alert(1)</script>
            Result: {"User-Agent": "<script>alert(1)</script>"}
        
        Args:
            headers: Original headers dict
            header_name: Header name
            payload: Payload to inject
            
        Returns:
            Modified headers dict
        """
        headers = headers.copy()
        headers[header_name] = payload
        return headers
    
    def inject_cookie(self, cookies: Dict[str, str], cookie_name: str, payload: str) -> Dict[str, str]:
        """
        Inject payload into cookie.
        
        Example:
            Cookies: {"session": "abc123"}
            Inject: session = <payload>
            Result: {"session": "<payload>"}
        
        Args:
            cookies: Original cookies dict
            cookie_name: Cookie name
            payload: Payload to inject
            
        Returns:
            Modified cookies dict
        """
        cookies = cookies.copy()
        cookies[cookie_name] = payload
        return cookies
    
    def prepare_multipart_injection(self, files: Dict[str, Any], param_name: str, payload: str) -> Dict[str, Any]:
        """
        Inject payload into multipart/form-data.
        
        Args:
            files: Original files dict for multipart upload
            param_name: Parameter name
            payload: Payload to inject
            
        Returns:
            Modified files dict
        """
        files = files.copy()
        files[param_name] = (f'{param_name}.txt', payload, 'text/plain')
        return files
