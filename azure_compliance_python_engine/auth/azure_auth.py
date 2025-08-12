import os
from typing import Optional
from azure.identity import DefaultAzureCredential


def get_default_credential() -> DefaultAzureCredential:
    # This uses a chained credential honoring env, managed identity, CLI, etc.
    # Optionally you can set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET in env.
    return DefaultAzureCredential(exclude_visual_studio_code_credential=False)


def get_credential_for_tenant(tenant_id: Optional[str] = None) -> DefaultAzureCredential:
    if tenant_id:
        os.environ['AZURE_TENANT_ID'] = tenant_id
    return get_default_credential() 