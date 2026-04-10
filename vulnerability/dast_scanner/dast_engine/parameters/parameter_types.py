"""
Parameter type definitions and metadata
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict


class ParameterType(Enum):
    """Enhanced parameter types for security testing"""
    
    # Basic types
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    
    # Structured types
    ARRAY = "array"
    OBJECT = "object"
    
    # Format-specific types
    EMAIL = "email"
    URL = "url"
    UUID = "uuid"
    DATE = "date"
    DATETIME = "datetime"
    TIME = "time"
    
    # Security-relevant types
    PASSWORD = "password"
    TOKEN = "token"
    SESSION_ID = "session_id"
    
    # File types
    FILE = "file"
    IMAGE = "image"
    
    # Network types
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    
    # Other
    PHONE = "phone"
    CREDIT_CARD = "credit_card"
    UNKNOWN = "unknown"


class ParameterConstraint(Enum):
    """Parameter constraints for validation"""
    
    MIN_LENGTH = "min_length"
    MAX_LENGTH = "max_length"
    MIN_VALUE = "min_value"
    MAX_VALUE = "max_value"
    PATTERN = "pattern"
    ENUM = "enum"
    REQUIRED = "required"
    UNIQUE = "unique"
    FORMAT = "format"


@dataclass
class ParameterMetadata:
    """
    Enhanced parameter metadata for security testing
    """
    
    # Basic info
    name: str
    location: str  # query, path, body, header, cookie
    param_type: ParameterType
    
    # Value information
    example_values: List[Any] = field(default_factory=list)
    default_value: Optional[Any] = None
    
    # Constraints
    required: bool = False
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    pattern: Optional[str] = None
    enum_values: Optional[List[Any]] = None
    
    # Format hints
    format_hint: Optional[str] = None  # email, uuid, date, etc.
    
    # Security context
    sensitive: bool = False  # Contains sensitive data (password, token, etc.)
    injectable: bool = True   # Can be tested for injection attacks
    
    # Testing metadata
    test_values: List[Any] = field(default_factory=list)
    boundary_values: List[Any] = field(default_factory=list)
    invalid_values: List[Any] = field(default_factory=list)
    
    # Source information
    source: str = "discovered"  # discovered, openapi, manual, etc.
    confidence: float = 1.0  # 0.0 to 1.0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'location': self.location,
            'type': self.param_type.value,
            'required': self.required,
            'sensitive': self.sensitive,
            'example_values': self.example_values[:3],  # Limit examples
            'constraints': {
                'min_length': self.min_length,
                'max_length': self.max_length,
                'min_value': self.min_value,
                'max_value': self.max_value,
                'pattern': self.pattern,
                'enum_values': self.enum_values,
            },
            'format': self.format_hint,
            'source': self.source,
        }
    
    def is_numeric(self) -> bool:
        """Check if parameter is numeric"""
        return self.param_type in [ParameterType.INTEGER, ParameterType.FLOAT]
    
    def is_string_like(self) -> bool:
        """Check if parameter is string-like"""
        return self.param_type in [
            ParameterType.STRING,
            ParameterType.EMAIL,
            ParameterType.URL,
            ParameterType.UUID,
            ParameterType.PASSWORD,
            ParameterType.TOKEN,
        ]
    
    def has_length_constraints(self) -> bool:
        """Check if parameter has length constraints"""
        return self.min_length is not None or self.max_length is not None
    
    def has_value_constraints(self) -> bool:
        """Check if parameter has value constraints"""
        return self.min_value is not None or self.max_value is not None


@dataclass
class EnrichedEndpoint:
    """
    Endpoint with enriched parameter information
    Extends the basic Endpoint from Step 2
    """
    
    # Original endpoint data
    url: str
    method: str
    endpoint_type: str
    
    # Enhanced parameters
    query_params: List[ParameterMetadata] = field(default_factory=list)
    path_params: List[ParameterMetadata] = field(default_factory=list)
    body_params: List[ParameterMetadata] = field(default_factory=list)
    header_params: List[ParameterMetadata] = field(default_factory=list)
    cookie_params: List[ParameterMetadata] = field(default_factory=list)
    
    # Metadata
    total_params: int = 0
    injectable_params: int = 0
    sensitive_params: int = 0
    
    def get_all_parameters(self) -> List[ParameterMetadata]:
        """Get all parameters across all locations"""
        return (
            self.query_params +
            self.path_params +
            self.body_params +
            self.header_params +
            self.cookie_params
        )
    
    def get_injectable_parameters(self) -> List[ParameterMetadata]:
        """Get parameters that can be tested for injection"""
        return [p for p in self.get_all_parameters() if p.injectable]
    
    def get_sensitive_parameters(self) -> List[ParameterMetadata]:
        """Get parameters containing sensitive data"""
        return [p for p in self.get_all_parameters() if p.sensitive]
    
    def count_parameters(self):
        """Update parameter counts"""
        all_params = self.get_all_parameters()
        self.total_params = len(all_params)
        self.injectable_params = len([p for p in all_params if p.injectable])
        self.sensitive_params = len([p for p in all_params if p.sensitive])
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'url': self.url,
            'method': self.method,
            'type': self.endpoint_type,
            'parameters': {
                'query': [p.to_dict() for p in self.query_params],
                'path': [p.to_dict() for p in self.path_params],
                'body': [p.to_dict() for p in self.body_params],
                'headers': [p.to_dict() for p in self.header_params],
                'cookies': [p.to_dict() for p in self.cookie_params],
            },
            'stats': {
                'total_params': self.total_params,
                'injectable_params': self.injectable_params,
                'sensitive_params': self.sensitive_params,
            }
        }
