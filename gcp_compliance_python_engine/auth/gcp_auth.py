import os
from typing import Any, Optional

try:
    import google.auth
    from google.auth.credentials import Credentials
    from google.cloud import storage as gcs_storage
    from googleapiclient.discovery import build as gcp_build
except Exception:  # pragma: no cover - optional deps
    google = None
    Credentials = Any  # type: ignore
    gcs_storage = None
    gcp_build = None

# Default scopes for read-only compliance scanning
_CLOUD_PLATFORM_RO_SCOPE = "https://www.googleapis.com/auth/cloud-platform.read-only"
_STORAGE_RO_SCOPE = "https://www.googleapis.com/auth/devstorage.read_only"


def _get_credentials(scopes: list[str]) -> Credentials:
    # Try ADC first
    if google is None:
        raise ImportError("google-auth not installed")
    try:
        creds, _ = google.auth.default(scopes=scopes)
        return creds
    except Exception:
        # Optional OAuth flow using client secrets
        secrets_path = os.getenv("GCP_OAUTH_CLIENT_SECRETS")
        if not secrets_path:
            raise
        from google.oauth2.credentials import Credentials as OAuthCreds
        from google_auth_oauthlib.flow import InstalledAppFlow
        from google.auth.transport.requests import Request
        token_path = os.getenv("GCP_OAUTH_TOKEN_PATH", os.path.expanduser("~/.config/gcp_compliance/token.json"))
        os.makedirs(os.path.dirname(token_path), exist_ok=True)
        creds = None
        if os.path.exists(token_path):
            try:
                creds = OAuthCreds.from_authorized_user_file(token_path, scopes)
            except Exception:
                creds = None
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(secrets_path, scopes=scopes)
                creds = flow.run_local_server(port=0)
            with open(token_path, "w") as fh:
                fh.write(creds.to_json())
        return creds  # type: ignore[return-value]


def get_default_project_id() -> Optional[str]:
    try:
        if google is None:
            return os.getenv("GCP_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT")
        creds, project_id = google.auth.default()
        return project_id or os.getenv("GCP_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT")
    except Exception:
        return os.getenv("GCP_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT")


def get_storage_client(project_id: Optional[str] = None) -> Any:
    if gcs_storage is None:
        raise ImportError("google-cloud-storage not installed")
    creds = _get_credentials([_STORAGE_RO_SCOPE, _CLOUD_PLATFORM_RO_SCOPE])
    return gcs_storage.Client(project=project_id or get_default_project_id(), credentials=creds)


def get_compute_client(project_id: Optional[str] = None) -> Any:
    if gcp_build is None:
        raise ImportError("google-api-python-client not installed")
    creds = _get_credentials([_CLOUD_PLATFORM_RO_SCOPE])
    return gcp_build("compute", "v1", cache_discovery=False, credentials=creds)


def get_resource_manager_client() -> Any:
    if gcp_build is None:
        raise ImportError("google-api-python-client not installed")
    creds = _get_credentials([_CLOUD_PLATFORM_RO_SCOPE])
    return gcp_build("cloudresourcemanager", "v1", cache_discovery=False, credentials=creds)


def get_service_usage_client() -> Any:
    if gcp_build is None:
        raise ImportError("google-api-python-client not installed")
    creds = _get_credentials([_CLOUD_PLATFORM_RO_SCOPE])
    return gcp_build("serviceusage", "v1", cache_discovery=False, credentials=creds) 