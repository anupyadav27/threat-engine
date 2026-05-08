"""
Form detection and parsing
Extracts forms and converts them to testable endpoints
"""

from bs4 import BeautifulSoup
from urllib.parse import urljoin

try:
    import lxml  # noqa: F401
    _BS_PARSER = 'lxml'
except ImportError:
    _BS_PARSER = 'html.parser'
from typing import List, Optional
from dast_engine.models import (
    Endpoint, Parameter, EndpointType, HTTPMethod,
    ParameterLocation, ParameterType
)


class FormDetector:
    """Detect and parse HTML forms"""
    
    COMMON_CSRF_NAMES = [
        'csrf_token', 'csrfmiddlewaretoken', '_token',
        'authenticity_token', 'csrf', '_csrf',  '__RequestVerificationToken'
    ]
    
    def __init__(self):
        """Initialize form detector"""
        pass
    
    def extract_forms(self, html: str, page_url: str) -> List[Endpoint]:
        """
        Extract all forms from HTML
        
        Args:
            html: HTML content
            page_url: URL of the page containing forms
        
        Returns:
            List of Endpoint objects representing forms
        """
        soup = BeautifulSoup(html, _BS_PARSER)
        forms = []
        
        for form_tag in soup.find_all('form'):
            endpoint = self._parse_form(form_tag, page_url)
            if endpoint:
                forms.append(endpoint)
        
        return forms
    
    def _parse_form(self, form_tag, page_url: str) -> Optional[Endpoint]:
        """
        Parse a single form element
        
        Args:
            form_tag: BeautifulSoup form element
            page_url: URL of the page
        
        Returns:
            Endpoint object or None
        """
        # Get form action
        action = form_tag.get('action', '')
        if not action:
            action = page_url  # Submit to same page
        
        form_url = urljoin(page_url, action)
        
        # Get form method
        method_str = form_tag.get('method', 'GET').upper()
        try:
            method = HTTPMethod[method_str]
        except KeyError:
            method = HTTPMethod.POST  # Default to POST
        
        # Get encoding type
        enctype = form_tag.get('enctype', 'application/x-www-form-urlencoded')
        
        # Extract all form fields
        parameters = []
        
        # Input fields
        for input_tag in form_tag.find_all('input'):
            param = self._parse_input_field(input_tag)
            if param:
                parameters.append(param)
        
        # Textarea fields
        for textarea in form_tag.find_all('textarea'):
            param = self._parse_textarea_field(textarea)
            if param:
                parameters.append(param)
        
        # Select dropdowns
        for select in form_tag.find_all('select'):
            param = self._parse_select_field(select)
            if param:
                parameters.append(param)
        
        # Detect CSRF token
        csrf_token = self._detect_csrf_token(form_tag)
        
        # GET forms submit fields as query parameters, not body
        if method == HTTPMethod.GET:
            for param in parameters:
                param.location = ParameterLocation.QUERY

        # Create endpoint
        endpoint = Endpoint(
            url=form_url,
            method=method,
            endpoint_type=EndpointType.FORM,
            parameters=parameters,
            found_on=page_url,
            form_encoding=enctype,
            csrf_token=csrf_token
        )
        
        # Calculate risk score
        endpoint.calculate_risk_score()
        
        return endpoint
    
    def _parse_input_field(self, input_tag) -> Optional[Parameter]:
        """Parse an input field"""
        name = input_tag.get('name')
        if not name:
            return None
        
        input_type = input_tag.get('type', 'text').lower()
        
        # Map HTML input types to parameter types
        type_mapping = {
            'text': ParameterType.STRING,
            'password': ParameterType.STRING,
            'email': ParameterType.STRING,
            'url': ParameterType.STRING,
            'tel': ParameterType.STRING,
            'search': ParameterType.STRING,
            'number': ParameterType.INTEGER,
            'range': ParameterType.INTEGER,
            'checkbox': ParameterType.BOOLEAN,
            'radio': ParameterType.STRING,
            'file': ParameterType.FILE,
            'hidden': ParameterType.STRING,
        }
        
        param_type = type_mapping.get(input_type, ParameterType.STRING)
        
        # Check if required
        required = input_tag.has_attr('required')
        
        # Get default value
        default_value = input_tag.get('value')
        
        # Determine parameter location
        # For GET forms, parameters go in query string
        # For POST forms, parameters go in body
        location = ParameterLocation.BODY  # Default, will be adjusted by method
        
        return Parameter(
            name=name,
            location=location,
            param_type=param_type,
            required=required,
            default_value=default_value,
            description=f"{input_type} input field"
        )
    
    def _parse_textarea_field(self, textarea) -> Optional[Parameter]:
        """Parse a textarea field"""
        name = textarea.get('name')
        if not name:
            return None
        
        required = textarea.has_attr('required')
        default_value = textarea.get_text(strip=True) or None
        
        return Parameter(
            name=name,
            location=ParameterLocation.BODY,
            param_type=ParameterType.STRING,
            required=required,
            default_value=default_value,
            description="textarea field"
        )
    
    def _parse_select_field(self, select) -> Optional[Parameter]:
        """Parse a select dropdown field"""
        name = select.get('name')
        if not name:
            return None
        
        # Extract options
        options = []
        default_value = None
        
        for option in select.find_all('option'):
            value = option.get('value', option.get_text(strip=True))
            options.append(value)
            
            if option.has_attr('selected'):
                default_value = value
        
        required = select.has_attr('required')
        
        return Parameter(
            name=name,
            location=ParameterLocation.BODY,
            param_type=ParameterType.STRING,
            required=required,
            default_value=default_value,
            example_values=options,
            description=f"select field with {len(options)} options"
        )
    
    def _detect_csrf_token(self, form_tag) -> Optional[str]:
        """
        Detect CSRF token in form
        
        Args:
            form_tag: BeautifulSoup form element
        
        Returns:
            CSRF token value or None
        """
        # Check hidden inputs for CSRF token
        for input_tag in form_tag.find_all('input', type='hidden'):
            name = input_tag.get('name', '').lower()
            
            # Check if name matches common CSRF token names
            for csrf_name in self.COMMON_CSRF_NAMES:
                if csrf_name.lower() in name:
                    return input_tag.get('value')
        
        # Check meta tags in page
        # This would require access to the full soup, not just form_tag
        # Skipping for now, can be enhanced later
        
        return None
    
    def is_login_form(self, endpoint: Endpoint) -> bool:
        """
        Heuristically determine if form is a login form
        
        Args:
            endpoint: Endpoint to check
        
        Returns:
            True if likely a login form
        """
        if endpoint.endpoint_type != EndpointType.FORM:
            return False
        
        # Check URL
        url_lower = endpoint.url.lower()
        if any(keyword in url_lower for keyword in ['login', 'signin', 'auth']):
            return True
        
        # Check parameters
        param_names = [p.name.lower() for p in endpoint.parameters]
        
        # Look for username/password combination
        has_username = any(name in param_names for name in ['username', 'user', 'email', 'login'])
        has_password = any(name in param_names for name in ['password', 'pass', 'pwd'])
        
        return has_username and has_password
    
    def is_search_form(self, endpoint: Endpoint) -> bool:
        """Check if form is a search form"""
        if endpoint.endpoint_type != EndpointType.FORM:
            return False
        
        url_lower = endpoint.url.lower()
        if 'search' in url_lower:
            return True
        
        param_names = [p.name.lower() for p in endpoint.parameters]
        return any(name in param_names for name in ['q', 'query', 'search', 's'])
