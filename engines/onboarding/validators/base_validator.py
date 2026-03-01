"""
Base validator class for all CSP validators
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from pydantic import BaseModel


class ValidationResult(BaseModel):
    """Validation result model"""
    success: bool
    message: str
    account_number: str = None
    errors: List[str] = []
    warnings: List[str] = []


class BaseValidator(ABC):
    """Base class for all credential validators"""
    
    @abstractmethod
    async def validate(self, credentials: Dict[str, Any]) -> ValidationResult:
        """
        Validate credentials
        
        Args:
            credentials: Dictionary containing credential data
            
        Returns:
            ValidationResult with success status and details
        """
        pass
    
    def _create_error_result(self, message: str, errors: List[str] = None) -> ValidationResult:
        """Helper to create error result"""
        return ValidationResult(
            success=False,
            message=message,
            errors=errors or []
        )
    
    def _create_success_result(self, message: str, account_number: str = None) -> ValidationResult:
        """Helper to create success result"""
        return ValidationResult(
            success=True,
            message=message,
            account_number=account_number
        )

