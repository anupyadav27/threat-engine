"""
Common FastAPI server for Multi-CSP Discoveries Engine

This server handles discovery scans for ALL cloud providers (AWS, Azure, GCP, OCI, AliCloud).
It routes requests to the appropriate CSP-specific scanner based on the provider field.

Common Orchestration Flow:
1. Receive orchestration_id from API request
2. Get scan metadata from onboarding DB (scan_orchestration table)
3. Retrieve credentials from Secrets Manager
4. Select CSP-specific scanner based on provider
5. Execute scan using common discovery engine
6. Return scan_id to caller
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
import asyncio
from datetime import datetime
from pathlib import Path
import sys
import os

# Add project root for engine_common
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from engine_common.logger import setup_logger, LogContext, log_duration
from engine_common.telemetry import configure_telemetry
from consolidated_services.database.orchestration_client import (
    get_scan_context as get_orchestration_metadata,
    update_engine_scan_id,
)

# Import common orchestration components
from common.orchestration.discovery_engine import DiscoveryEngine
from common.database.database_manager import DatabaseManager
from common.models.provider_interface import DiscoveryScanner, AuthenticationError, DiscoveryError

# Import CSP-specific scanners
from providers.aws.scanner.service_scanner import AWSDiscoveryScanner
from providers.azure.scanner.service_scanner import AzureDiscoveryScanner
from providers.gcp.scanner.service_scanner import GCPDiscoveryScanner
from providers.oci.scanner.service_scanner import OCIDiscoveryScanner
from providers.ibm.scanner.service_scanner import IBMDiscoveryScanner
from providers.kubernetes.scanner.service_scanner import K8sDiscoveryScanner

# Import SecretsManagerStorage for credential retrieval
from engine_onboarding.storage.secrets_manager_storage import SecretsManagerStorage

logger = setup_logger(__name__, engine_name="engine-discoveries-common")

app = FastAPI(
    title="Multi-CSP Discoveries Engine API",
    description="API for running discovery scans across AWS, Azure, GCP, OCI, and AliCloud",
    version="2.0.0"
)
configure_telemetry("engine-discoveries", app)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Provider scanner registry - maps provider name to scanner class
PROVIDER_SCANNERS = {
    'aws': AWSDiscoveryScanner,
    'azure': AzureDiscoveryScanner,
    'gcp': GCPDiscoveryScanner,
    'oci': OCIDiscoveryScanner,
    'ibm': IBMDiscoveryScanner,
    'k8s': K8sDiscoveryScanner,
    # 'alicloud': AliCloudDiscoveryScanner,  # TODO: Implement
}

# Shared DatabaseManager for health checks
_health_db_manager = None

def _get_health_db_manager():
    global _health_db_manager
    if _health_db_manager is None:
        try:
            _health_db_manager = DatabaseManager()
        except Exception:
            pass
    return _health_db_manager

# In-memory scan storage (use Redis/DB in production)
scans = {}
scan_tasks = {}  # Track running scan tasks for cancellation
metrics = {
    "total_scans": 0,
    "successful_scans": 0,
    "failed_scans": 0,
    "cancelled_scans": 0,
    "total_duration_seconds": 0,
    "service_counts": {}
}


class DiscoveryRequest(BaseModel):
    """Discovery scan request model (CSP-agnostic)"""
    # New orchestration-aware parameter
    orchestration_id: Optional[str] = None

    # Legacy parameters (optional when orchestration_id is provided)
    customer_id: Optional[str] = None
    tenant_id: Optional[str] = None
    provider: str = "aws"  # aws, azure, gcp, oci, alicloud
    hierarchy_id: Optional[str] = None
    hierarchy_type: str = "account"  # account, subscription, project, tenancy
    include_services: Optional[List[str]] = None
    include_regions: Optional[List[str]] = None
    exclude_regions: Optional[List[str]] = None
    credentials: Optional[Dict[str, Any]] = None
    use_database: Optional[bool] = None  # If None, auto-detect


class DiscoveryResponse(BaseModel):
    """Discovery scan response model"""
    discovery_scan_id: str
    status: str
    message: str
    orchestration_id: Optional[str] = None
    provider: Optional[str] = None


# Orchestration Integration Helper Functions

async def _get_scan_context_from_orchestration(orchestration_id: str) -> Dict[str, Any]:
    """
    Query onboarding database for complete scan context using orchestration_id.

    Returns:
        {
            "tenant_id": "...",
            "customer_id": "...",
            "account_id": "588989875114",  # AWS account, Azure subscription, GCP project, etc.
            "provider": "aws" | "azure" | "gcp" | "oci" | "alicloud",
            "hierarchy_id": "...",
            "credential_type": "access_key" | "iam_role" | "service_principal" | "...",
            "credential_ref": "threat-engine/account/..." | "arn:aws:iam::...",
            "include_services": ["ec2", "s3"] or None (all services),
            "include_regions": ["us-east-1", "eastus"] or None (all regions),
            "discovery_scan_id": "..." (if already exists - for retry scenarios)
        }
    """
    try:
        logger.info(f"Retrieving orchestration metadata for orchestration_id: {orchestration_id}")
        metadata = get_orchestration_metadata(orchestration_id)

        if not metadata:
            raise ValueError(f"No orchestration metadata found for orchestration_id: {orchestration_id}")

        logger.info(f"Successfully retrieved orchestration metadata", extra={
            "extra_fields": {
                "orchestration_id": orchestration_id,
                "account_id": metadata.get('account_id'),
                "provider": metadata.get('provider')
            }
        })

        return metadata
    except Exception as e:
        logger.error(f"Failed to retrieve orchestration metadata: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve orchestration metadata: {str(e)}"
        )


async def _retrieve_credentials_from_secrets_manager(
    account_id: str,
    credential_ref: str,
    provider: str
) -> Dict[str, Any]:
    """
    Retrieve credentials from Secrets Manager using credential_ref.

    Args:
        account_id: Cloud account ID (AWS account, Azure subscription, GCP project, etc.)
        credential_ref: Secrets Manager path (e.g., "threat-engine/account/588989875114")
        provider: CSP name (aws, azure, gcp, oci)

    Returns:
        Credentials dict ready to use for CSP authentication
    """
    try:
        secrets_manager = SecretsManagerStorage()

        # Retrieve secret using account_id
        secret_data = secrets_manager.retrieve(account_id=account_id)

        logger.info(f"Retrieved credentials from Secrets Manager: {credential_ref}")

        if not isinstance(secret_data, dict) or not secret_data:
            raise ValueError(f"Empty/invalid credentials found in secret: {credential_ref}")

        # Normalize credential_type based on provider
        cred_type_raw = (secret_data.get("credential_type") or "").lower()

        if provider == "aws":
            if cred_type_raw in ("aws_access_key", "access_key", "access_key_id"):
                secret_data["credential_type"] = "access_key"
            elif "role" in cred_type_raw:
                secret_data["credential_type"] = "iam_role"
        elif provider == "azure":
            if "service_principal" in cred_type_raw:
                secret_data["credential_type"] = "service_principal"
            elif "managed_identity" in cred_type_raw:
                secret_data["credential_type"] = "managed_identity"
        elif provider == "gcp":
            if "service_account" in cred_type_raw:
                secret_data["credential_type"] = "service_account"
        elif provider == "oci":
            if "api_key" in cred_type_raw or "user_principal" in cred_type_raw:
                secret_data["credential_type"] = "api_key"
        elif provider == "ibm":
            if "api_key" in cred_type_raw:
                secret_data["credential_type"] = "ibm_api_key"
        elif provider == "k8s":
            if "in_cluster" in cred_type_raw:
                secret_data["credential_type"] = "in_cluster"
            elif "kubeconfig" in cred_type_raw:
                secret_data["credential_type"] = "kubeconfig"

        return secret_data

    except Exception as e:
        logger.error(f"Failed to retrieve credentials from Secrets Manager: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve credentials: {str(e)}"
        )


def _get_scanner_for_provider(provider: str, credentials: Dict[str, Any]) -> DiscoveryScanner:
    """
    Get CSP-specific scanner instance based on provider.

    Args:
        provider: CSP name (aws, azure, gcp, oci, alicloud)
        credentials: Provider-specific credentials

    Returns:
        Instantiated scanner implementing DiscoveryScanner interface

    Raises:
        HTTPException: If provider not supported
    """
    provider_lower = provider.lower()

    if provider_lower not in PROVIDER_SCANNERS:
        supported = ', '.join(PROVIDER_SCANNERS.keys())
        raise HTTPException(
            status_code=400,
            detail=f"Provider '{provider}' not supported. Supported providers: {supported}"
        )

    scanner_class = PROVIDER_SCANNERS[provider_lower]
    scanner = scanner_class(credentials=credentials, provider=provider_lower)

    logger.info(f"Selected scanner: {scanner_class.__name__} for provider: {provider}")

    return scanner


@app.post("/api/v1/discovery", response_model=DiscoveryResponse)
async def create_discovery(request: DiscoveryRequest, background_tasks: BackgroundTasks):
    """
    Run discovery scan - discovers cloud resources across all supported CSPs.

    Supports two modes:
    1. Orchestration mode: Provide orchestration_id to fetch metadata from onboarding database
    2. Legacy mode: Provide all parameters directly (backward compatibility)

    Flow:
    1. Get scan metadata from onboarding DB (if orchestration_id provided)
    2. Retrieve credentials from Secrets Manager
    3. Select CSP-specific scanner based on provider
    4. Execute scan using common discovery engine
    5. Return scan_id
    """
    discovery_scan_id = str(uuid.uuid4())
    orchestration_id = request.orchestration_id

    # If orchestration_id provided, fetch metadata and credentials from database
    if orchestration_id:
        try:
            # Get scan context from onboarding DB (scan_orchestration table)
            metadata = await _get_scan_context_from_orchestration(orchestration_id)

            # Extract provider
            provider = metadata.get('provider', 'aws')

            # Retrieve credentials from Secrets Manager
            account_id = metadata.get('account_id')
            credential_ref = metadata.get('credential_ref')
            credential_type = (metadata.get("credential_type") or "").lower()

            if not account_id or not credential_ref:
                raise HTTPException(
                    status_code=400,
                    detail=f"Missing account_id or credential_ref in orchestration metadata"
                )

            # Handle role-based credentials (AWS IAM role, Azure managed identity, etc.)
            if credential_type in ("aws_iam_role", "iam_role", "role", "managed_identity"):
                cred_data = {
                    "credential_type": credential_type,
                    "role_arn": credential_ref,  # AWS
                    "external_id": metadata.get("external_id"),
                }
            else:
                cred_data = await _retrieve_credentials_from_secrets_manager(
                    account_id=account_id,
                    credential_ref=credential_ref,
                    provider=provider
                )

            # Populate request with orchestration metadata.
            # Request-body values take priority over orchestration metadata
            # (allows parallel scan partitioning via include_services).
            request.tenant_id = metadata.get('tenant_id', 'default-tenant')
            request.customer_id = metadata.get('customer_id', 'default')
            request.provider = provider
            request.hierarchy_id = metadata.get('hierarchy_id') or account_id
            request.hierarchy_type = metadata.get('hierarchy_type', 'account')
            request.include_services = request.include_services or metadata.get('include_services')
            request.include_regions = request.include_regions or metadata.get('include_regions')
            request.exclude_regions = request.exclude_regions or metadata.get('exclude_regions')
            request.credentials = cred_data
            request.use_database = True  # Always use database when orchestrated

            logger.info("Orchestration mode enabled", extra={
                "extra_fields": {
                    "orchestration_id": orchestration_id,
                    "account_id": account_id,
                    "provider": provider,
                    "discovery_scan_id": discovery_scan_id
                }
            })

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to process orchestration request: {e}", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to process orchestration request: {str(e)}"
            )

    # Validate provider is supported
    provider = request.provider
    if provider.lower() not in PROVIDER_SCANNERS:
        supported = ', '.join(PROVIDER_SCANNERS.keys())
        raise HTTPException(
            status_code=400,
            detail=f"Provider '{provider}' not supported. Supported providers: {supported}"
        )

    # Select CSP-specific scanner
    scanner = _get_scanner_for_provider(provider, request.credentials)

    # Execute scan in background using common discovery engine
    background_tasks.add_task(
        _run_discovery_scan,
        discovery_scan_id=discovery_scan_id,
        orchestration_id=orchestration_id,
        scanner=scanner,
        request=request
    )

    # Update orchestration table with discovery_scan_id if orchestration mode
    if orchestration_id:
        try:
            update_engine_scan_id(
                orchestration_id=orchestration_id,
                engine="discovery",
                scan_id=discovery_scan_id
            )
        except Exception as e:
            logger.warning(f"Failed to update orchestration table with scan_id: {e}")

    metrics["total_scans"] += 1

    return DiscoveryResponse(
        discovery_scan_id=discovery_scan_id,
        status="running",
        message=f"Discovery scan started for provider: {provider}",
        orchestration_id=orchestration_id,
        provider=provider
    )


async def _run_discovery_scan(
    discovery_scan_id: str,
    orchestration_id: Optional[str],
    scanner: DiscoveryScanner,
    request: DiscoveryRequest
):
    """
    Execute discovery scan using common orchestration engine.

    This function is CSP-agnostic. It uses the common DiscoveryEngine
    which calls scanner methods for CSP-specific operations.
    """
    start_time = datetime.now()

    try:
        # Authenticate scanner to cloud provider
        scanner.authenticate()

        # Create common discovery engine
        db_manager = DatabaseManager()
        discovery_engine = DiscoveryEngine(scanner=scanner, db_manager=db_manager)

        # Build scan metadata
        metadata = {
            "discovery_scan_id": discovery_scan_id,
            "orchestration_id": orchestration_id,
            "provider": request.provider,
            "tenant_id": request.tenant_id,
            "customer_id": request.customer_id,
            "hierarchy_id": request.hierarchy_id,
            "hierarchy_type": request.hierarchy_type,
            "include_services": request.include_services,
            "include_regions": request.include_regions,
            "exclude_regions": request.exclude_regions,
            "use_database": request.use_database
        }

        # Execute scan using common engine
        await discovery_engine.run_scan(metadata=metadata)

        # Update scan status
        scans[discovery_scan_id] = {
            "status": "completed",
            "provider": request.provider,
            "started_at": start_time.isoformat(),
            "completed_at": datetime.now().isoformat()
        }

        metrics["successful_scans"] += 1
        duration = (datetime.now() - start_time).total_seconds()
        metrics["total_duration_seconds"] += duration

        logger.info(f"Discovery scan completed: {discovery_scan_id}", extra={
            "extra_fields": {
                "discovery_scan_id": discovery_scan_id,
                "provider": request.provider,
                "duration_seconds": duration
            }
        })

    except AuthenticationError as e:
        logger.error(f"Authentication failed for scan {discovery_scan_id}: {e}")
        scans[discovery_scan_id] = {"status": "failed", "error": f"Authentication error: {str(e)}"}
        metrics["failed_scans"] += 1

    except DiscoveryError as e:
        logger.error(f"Discovery failed for scan {discovery_scan_id}: {e}")
        scans[discovery_scan_id] = {"status": "failed", "error": f"Discovery error: {str(e)}"}
        metrics["failed_scans"] += 1

    except Exception as e:
        logger.error(f"Discovery scan failed: {discovery_scan_id}", exc_info=True)
        scans[discovery_scan_id] = {"status": "failed", "error": str(e)}
        metrics["failed_scans"] += 1


@app.get("/api/v1/discovery/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get status of discovery scan (CSP-agnostic)"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]


@app.get("/health")
async def health_check():
    """Health check endpoint (CSP-agnostic)"""
    db = _get_health_db_manager()
    if db is None:
        return {"status": "degraded", "database": "unavailable"}

    try:
        db.test_connection()
        return {"status": "healthy", "database": "connected"}
    except Exception:
        return {"status": "degraded", "database": "error"}


@app.get("/api/v1/health/live")
async def liveness_check():
    """Kubernetes liveness probe endpoint"""
    return {"status": "alive"}


@app.get("/api/v1/health/ready")
async def readiness_check():
    """Kubernetes readiness probe endpoint - lightweight check without database"""
    # For now, just return ready if the app started successfully
    # Database connection will be checked on first scan request
    return {"status": "ready", "message": "Application started successfully"}


@app.get("/metrics")
async def get_metrics():
    """Get scan metrics (CSP-agnostic)"""
    return metrics


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
