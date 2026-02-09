"""
Credential models
"""
from pydantic import BaseModel
from typing import Optional, Literal, Dict, Any


class CredentialSubmit(BaseModel):
    """Generic credential submit"""
    account_id: str
    credential_type: str
    credentials: Dict[str, Any]


class CredentialResponse(BaseModel):
    """Credential response (no sensitive data)"""
    credential_id: str
    account_id: str
    credential_type: str
    created_at: str
    last_used_at: Optional[str]


# AWS Credentials
class AWSAccessKeyCredentials(BaseModel):
    """AWS Access Key credentials"""
    credential_type: Literal["aws_access_key"] = "aws_access_key"
    access_key_id: str
    secret_access_key: str
    account_number: Optional[str] = None


class AWSIAMRoleCredentials(BaseModel):
    """AWS IAM Role credentials"""
    credential_type: Literal["aws_iam_role"] = "aws_iam_role"
    role_arn: str
    external_id: str
    account_number: str
    role_name: Optional[str] = None


# Azure Credentials
class AzureServicePrincipalCredentials(BaseModel):
    """Azure Service Principal credentials"""
    credential_type: Literal["azure_service_principal"] = "azure_service_principal"
    client_id: str
    client_secret: str
    tenant_id: str
    subscription_id: str


# GCP Credentials
class GCPServiceAccountCredentials(BaseModel):
    """GCP Service Account credentials"""
    credential_type: Literal["gcp_service_account"] = "gcp_service_account"
    service_account_json: str  # Full JSON key file content
    project_id: Optional[str] = None


# AliCloud Credentials
class AliCloudAccessKeyCredentials(BaseModel):
    """AliCloud Access Key credentials"""
    credential_type: Literal["alicloud_access_key"] = "alicloud_access_key"
    access_key_id: str
    access_key_secret: str
    account_id: Optional[str] = None

