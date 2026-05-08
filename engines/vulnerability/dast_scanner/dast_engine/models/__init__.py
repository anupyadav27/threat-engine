"""
Data models for endpoints and parameters
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class EndpointType(Enum):
    """Type of endpoint discovered"""
    PAGE = "page"
    FORM = "form"
    API = "api"
    AJAX = "ajax"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"


class HTTPMethod(Enum):
    """HTTP methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ParameterLocation(Enum):
    """Location of parameter"""
    QUERY = "query"        # URL query string
    BODY = "body"          # Request body
    HEADER = "header"      # HTTP header
    COOKIE = "cookie"      # Cookie
    PATH = "path"          # URL path segment


class ParameterType(Enum):
    """Type of parameter"""
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    FILE = "file"
    ARRAY = "array"
    OBJECT = "object"


@dataclass
class Parameter:
    """Represents a parameter in an endpoint"""
    name: str
    location: ParameterLocation
    param_type: ParameterType = ParameterType.STRING
    required: bool = False
    default_value: Optional[str] = None
    example_values: List[str] = field(default_factory=list)
    description: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'location': self.location.value,
            'type': self.param_type.value,
            'required': self.required,
            'default_value': self.default_value,
            'example_values': self.example_values,
            'description': self.description
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Parameter':
        """Create from dictionary"""
        return cls(
            name=data['name'],
            location=ParameterLocation(data['location']),
            param_type=ParameterType(data.get('type', 'string')),
            required=data.get('required', False),
            default_value=data.get('default_value'),
            example_values=data.get('example_values', []),
            description=data.get('description')
        )


@dataclass
class Endpoint:
    """Represents a discovered endpoint"""
    url: str
    method: HTTPMethod
    endpoint_type: EndpointType
    parameters: List[Parameter] = field(default_factory=list)
    
    # Metadata
    found_on: Optional[str] = None          # Source page URL
    depth: int = 0                           # Crawl depth
    response_type: Optional[str] = None      # Content-Type
    status_code: Optional[int] = None        # HTTP status
    
    # Security metadata
    auth_required: bool = False
    csrf_token: Optional[str] = None
    
    # Form-specific
    form_encoding: Optional[str] = None     # application/x-www-form-urlencoded, multipart/form-data
    
    # Analysis metadata
    tested: bool = False
    vulnerabilities: List[Any] = field(default_factory=list)
    risk_score: int = 0                      # 0-10 priority for testing
    discovered_at: datetime = field(default_factory=datetime.now)
    
    def __hash__(self):
        """Make endpoint hashable for deduplication"""
        return hash(f"{self.method.value}:{self.url}")
    
    def __eq__(self, other):
        """Equality based on method and URL"""
        if not isinstance(other, Endpoint):
            return False
        return self.method == other.method and self.url == other.url
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'url': self.url,
            'method': self.method.value,
            'type': self.endpoint_type.value,
            'parameters': [p.to_dict() for p in self.parameters],
            'found_on': self.found_on,
            'depth': self.depth,
            'response_type': self.response_type,
            'status_code': self.status_code,
            'auth_required': self.auth_required,
            'csrf_token': self.csrf_token,
            'form_encoding': self.form_encoding,
            'tested': self.tested,
            'risk_score': self.risk_score,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Endpoint':
        """Create from dictionary"""
        return cls(
            url=data['url'],
            method=HTTPMethod(data['method']),
            endpoint_type=EndpointType(data['type']),
            parameters=[Parameter.from_dict(p) for p in data.get('parameters', [])],
            found_on=data.get('found_on'),
            depth=data.get('depth', 0),
            response_type=data.get('response_type'),
            status_code=data.get('status_code'),
            auth_required=data.get('auth_required', False),
            csrf_token=data.get('csrf_token'),
            form_encoding=data.get('form_encoding'),
            tested=data.get('tested', False),
            risk_score=data.get('risk_score', 0),
            discovered_at=datetime.fromisoformat(data['discovered_at']) if data.get('discovered_at') else None
        )
    
    def get_parameter_names(self) -> List[str]:
        """Get list of parameter names"""
        return [p.name for p in self.parameters]
    
    def add_parameter(self, param: Parameter):
        """Add a parameter if not already present"""
        if param.name not in self.get_parameter_names():
            self.parameters.append(param)
    
    def calculate_risk_score(self):
        """Calculate risk score for prioritization"""
        score = 0
        
        # Higher risk for forms (user input)
        if self.endpoint_type == EndpointType.FORM:
            score += 3
        
        # Higher risk for POST/PUT/DELETE (state-changing)
        if self.method in [HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.DELETE]:
            score += 2
        
        # Higher risk if no CSRF protection
        if self.method == HTTPMethod.POST and not self.csrf_token:
            score += 2
        
        # Higher risk for authentication endpoints
        url_lower = self.url.lower()
        if any(keyword in url_lower for keyword in ['login', 'auth', 'password', 'admin']):
            score += 2
        
        # Higher risk for more parameters (more attack surface)
        if len(self.parameters) > 5:
            score += 1
        
        self.risk_score = min(score, 10)  # Cap at 10
        return self.risk_score


@dataclass
class CrawlResult:
    """Result of crawling a single page"""
    url: str
    status_code: int
    content: str
    headers: Dict[str, str]
    content_type: Optional[str] = None
    links: List[str] = field(default_factory=list)
    forms: List[Endpoint] = field(default_factory=list)
    api_calls: List[str] = field(default_factory=list)
    error: Optional[str] = None
