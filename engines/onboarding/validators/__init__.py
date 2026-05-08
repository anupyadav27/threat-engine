"""
Credential validators for all CSPs and VCS providers.
"""
from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult
from engine_onboarding.validators.aws_validator import AWSValidator
from engine_onboarding.validators.azure_validator import AzureValidator
from engine_onboarding.validators.gcp_validator import GCPValidator
from engine_onboarding.validators.alicloud_validator import AliCloudValidator
from engine_onboarding.validators.oci_validator import OCIValidator
from engine_onboarding.validators.ibm_validator import IBMValidator
from engine_onboarding.validators.git_validator import GitValidator

__all__ = [
    'BaseValidator',
    'ValidationResult',
    'AWSValidator',
    'AzureValidator',
    'GCPValidator',
    'AliCloudValidator',
    'OCIValidator',
    'IBMValidator',
    'GitValidator',
]

