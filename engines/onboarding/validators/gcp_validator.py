"""
GCP credential validator
"""
import json
from typing import Dict, Any
from google.oauth2 import service_account
from google.cloud import resourcemanager
from google.auth.exceptions import GoogleAuthError
from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult


class GCPValidator(BaseValidator):
    """Validator for GCP credentials"""
    
    async def validate(self, credentials: Dict[str, Any]) -> ValidationResult:
        """
        Validate GCP credentials
        
        Supports:
        - gcp_service_account: service_account_json (full JSON key file content)
        """
        credential_type = credentials.get('credential_type')
        
        if credential_type == 'gcp_service_account':
            return await self._validate_service_account(credentials)
        else:
            return self._create_error_result(
                f"Unsupported GCP credential type: {credential_type}",
                ["Supported types: gcp_service_account"]
            )
    
    async def _validate_service_account(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Validate GCP Service Account credentials"""
        try:
            service_account_json = credentials.get('service_account_json')

            # Support both formats:
            # 1. {"service_account_json": {...}} — wrapped format
            # 2. {"type": "service_account", "project_id": "..."} — direct SA JSON
            if not service_account_json and credentials.get('type') == 'service_account':
                service_account_json = credentials

            if not service_account_json:
                return self._create_error_result(
                    "Missing required field",
                    ["service_account_json is required or credentials must be a service account JSON"]
                )
            
            # Parse JSON
            try:
                if isinstance(service_account_json, str):
                    service_account_info = json.loads(service_account_json)
                else:
                    service_account_info = service_account_json
            except json.JSONDecodeError as e:
                return self._create_error_result(
                    "Invalid JSON format",
                    [f"JSON parsing error: {str(e)}"]
                )
            
            # Create credentials
            creds = service_account.Credentials.from_service_account_info(
                service_account_info
            )
            
            project_id = service_account_info.get('project_id')
            if not project_id:
                return self._create_error_result(
                    "Missing project_id in service account JSON",
                    ["Service account JSON must contain project_id"]
                )
            
            # Test credentials by getting project
            client = resourcemanager.ProjectsClient(credentials=creds)
            project = client.get_project(name=f"projects/{project_id}")
            
            return self._create_success_result(
                "Service account validated successfully",
                account_number=project_id
            )
            
        except GoogleAuthError as e:
            return self._create_error_result(
                f"GCP Authentication Error: {str(e)}",
                [str(e)]
            )
        except Exception as e:
            return self._create_error_result(
                f"Validation failed: {str(e)}",
                [str(e)]
            )

