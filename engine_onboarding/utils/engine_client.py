"""
Client for calling engine APIs
"""
import httpx
import asyncio
from typing import List, Optional, Dict, Any
from engine_onboarding.config import settings


class EngineClient:
    """HTTP client to call engine APIs via ClusterIP"""
    
    def __init__(self):
        self.aws_url = settings.aws_engine_url
        self.azure_url = settings.azure_engine_url
        self.gcp_url = settings.gcp_engine_url
        self.alicloud_url = settings.alicloud_engine_url
        self.oci_url = settings.oci_engine_url
        self.ibm_url = settings.ibm_engine_url
    
    async def scan_aws(
        self,
        credentials: Dict[str, Any],
        account_number: str,
        tenant_id: Optional[str] = None,
        scan_run_id: Optional[str] = None,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
        exclude_services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Call AWS engine API and wait for completion"""
        import logging
        logger = logging.getLogger(__name__)
        
        # If regions/services are None or empty, omit them from payload (means scan all)
        # The AWS engine treats [] as "scan nothing" and None/missing as "scan all"
        request_payload = {
            "account": account_number,
            "credentials": credentials
        }
        # Add tenant_id and scan_run_id if provided
        if tenant_id:
            request_payload["tenant_id"] = tenant_id
        if scan_run_id:
            request_payload["scan_run_id"] = scan_run_id
        # Only include regions/services if explicitly provided
        if regions:
            request_payload["include_regions"] = regions
        if services:
            request_payload["include_services"] = services
        if exclude_services:
            request_payload["exclude_services"] = exclude_services
        
        logger.info(f"Calling AWS Engine API at {self.aws_url}/api/v1/scan")
        logger.info(f"Request payload - Account: {account_number}")
        logger.info(f"  Include Regions: {request_payload.get('include_regions', 'None (scan all)')}")
        logger.info(f"  Include Services: {request_payload.get('include_services', 'None (scan all)')}")
        logger.info(f"  Exclude Services: {request_payload.get('exclude_services', 'None')}")
        if credentials.get('role_arn'):
            logger.info(f"  Credentials - Role ARN: {credentials.get('role_arn')}")
        elif credentials.get('role_name'):
            logger.info(f"  Credentials - Role Name: {credentials.get('role_name')}")
        
        async def _start_scan_with_retries(client: httpx.AsyncClient) -> str:
            """Start scan and return scan_id. Retries a few times for transient disconnects/restarts."""
            backoffs = [0.0, 1.0, 2.0]  # fast retry; AWS engine used to restart during scans
            last_err: Exception | None = None
            for i, delay in enumerate(backoffs, start=1):
                if delay:
                    await asyncio.sleep(delay)
                try:
                    logger.info(f"POST {self.aws_url}/api/v1/scan (attempt {i}/{len(backoffs)})")
                    resp = await client.post(
                        f"{self.aws_url}/api/v1/scan",
                        json=request_payload,
                        timeout=httpx.Timeout(60.0, connect=30.0, read=60.0, write=60.0),
                    )
                    resp.raise_for_status()
                    scan_id = resp.json().get("scan_id")
                    if not scan_id:
                        raise RuntimeError(f"AWS engine response missing scan_id: {resp.text[:300]}")
                    return scan_id
                except (httpx.RemoteProtocolError, httpx.ConnectError, httpx.ReadTimeout) as e:
                    last_err = e
                    logger.warning(f"Start scan attempt {i} failed: {type(e).__name__}: {e}")
                except httpx.HTTPStatusError as e:
                    # Non-2xx from engine: no point retrying in most cases
                    raise Exception(f"AWS engine HTTP {e.response.status_code}: {e.response.text}") from e
            raise Exception(f"Failed to start scan after retries: {last_err}") from last_err

        async with httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=30.0)) as client:
            scan_id = await _start_scan_with_retries(client)
            logger.info(f"AWS scan started. scan_id={scan_id}")

            # Poll for completion (configurable; full scans can take a long time)
            max_wait = int(getattr(settings, "engine_scan_max_wait_seconds", 3600))
            poll_interval = int(getattr(settings, "engine_scan_poll_interval_seconds", 10))
            elapsed = 0

            while elapsed < max_wait:
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval

                try:
                    status_response = await client.get(
                        f"{self.aws_url}/api/v1/scan/{scan_id}/status",
                        timeout=30.0
                    )
                    status_response.raise_for_status()
                    status_data = status_response.json()
                except httpx.HTTPStatusError as e:
                    # If the engine pod restarted, it loses in-memory scan state and returns 404.
                    if e.response is not None and e.response.status_code == 404:
                        raise Exception(
                            f"Scan {scan_id} not found on AWS engine (engine restarted / lost state)"
                        ) from e
                    raise
                status = status_data.get("status")
                logger.info(f"Scan {scan_id} status: {status} (elapsed: {elapsed}s)")

                if status == "completed":
                    summary_response = await client.get(
                        f"{self.aws_url}/api/v1/scan/{scan_id}/summary",
                        timeout=30.0
                    )
                    summary_response.raise_for_status()
                    summary_data = summary_response.json()
                    summary = summary_data.get("summary", {})
                    return {
                        "scan_id": scan_id,
                        "status": "completed",
                        "total_checks": summary.get("total_checks", 0),
                        "passed_checks": summary.get("passed_checks", 0),
                        "failed_checks": summary.get("failed_checks", 0),
                        "duration_seconds": summary_data.get("duration_seconds", 0),
                    }

                if status == "failed":
                    raise Exception(f"Scan failed: {status_data.get('error', 'Unknown error')}")

            raise Exception(f"Scan {scan_id} timed out after {max_wait} seconds")
    
    async def scan_azure(
        self,
        credentials: Dict[str, Any],
        subscription_id: str,
        tenant_id: Optional[str] = None,
        scan_run_id: Optional[str] = None,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Call Azure engine API"""
        request_payload = {
            "subscription": subscription_id,
            "credentials": credentials,
            "regions": regions or [],
            "services": services or []
        }
        if tenant_id:
            request_payload["tenant_id"] = tenant_id
        if scan_run_id:
            request_payload["scan_run_id"] = scan_run_id
        
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(
                f"{self.azure_url}/api/v1/scan",
                json=request_payload
            )
            response.raise_for_status()
            return response.json()
    
    async def scan_gcp(
        self,
        credentials: Dict[str, Any],
        project_id: str,
        tenant_id: Optional[str] = None,
        scan_run_id: Optional[str] = None,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Call GCP engine API"""
        request_payload = {
            "project": project_id,
            "credentials": credentials,
            "regions": regions or [],
            "services": services or []
        }
        if tenant_id:
            request_payload["tenant_id"] = tenant_id
        if scan_run_id:
            request_payload["scan_run_id"] = scan_run_id
        
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(
                f"{self.gcp_url}/api/v1/scan",
                json=request_payload
            )
            response.raise_for_status()
            return response.json()
    
    async def scan_alicloud(
        self,
        credentials: Dict[str, Any],
        account_id: str,
        tenant_id: Optional[str] = None,
        scan_run_id: Optional[str] = None,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Call AliCloud engine API"""
        request_payload = {
            "account": account_id,
            "credentials": credentials,
            "regions": regions or [],
            "services": services or []
        }
        if tenant_id:
            request_payload["tenant_id"] = tenant_id
        if scan_run_id:
            request_payload["scan_run_id"] = scan_run_id
        
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(
                f"{self.alicloud_url}/api/v1/scan",
                json=request_payload
            )
            response.raise_for_status()
            return response.json()
    
    # Common methods for all engines
    async def cancel_scan(self, provider: str, scan_id: str) -> Dict[str, Any]:
        """Cancel a running scan"""
        url_map = {
            "aws": self.aws_url,
            "azure": self.azure_url,
            "gcp": self.gcp_url,
            "alicloud": self.alicloud_url,
            "oci": self.oci_url,
            "ibm": self.ibm_url
        }
        
        url = url_map.get(provider.lower())
        if not url:
            raise ValueError(f"Unknown provider: {provider}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(f"{url}/api/v1/scan/{scan_id}/cancel")
            response.raise_for_status()
            return response.json()
    
    async def get_scan_progress(self, provider: str, scan_id: str) -> Dict[str, Any]:
        """Get scan progress"""
        url_map = {
            "aws": self.aws_url,
            "azure": self.azure_url,
            "gcp": self.gcp_url,
            "alicloud": self.alicloud_url,
            "oci": self.oci_url,
            "ibm": self.ibm_url
        }
        
        url = url_map.get(provider.lower())
        if not url:
            raise ValueError(f"Unknown provider: {provider}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{url}/api/v1/scan/{scan_id}/progress")
            response.raise_for_status()
            return response.json()
    
    async def get_scan_status(self, provider: str, scan_id: str) -> Dict[str, Any]:
        """Get scan status with progress"""
        url_map = {
            "aws": self.aws_url,
            "azure": self.azure_url,
            "gcp": self.gcp_url,
            "alicloud": self.alicloud_url,
            "oci": self.oci_url,
            "ibm": self.ibm_url
        }
        
        url = url_map.get(provider.lower())
        if not url:
            raise ValueError(f"Unknown provider: {provider}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{url}/api/v1/scan/{scan_id}/status")
            response.raise_for_status()
            return response.json()
    
    async def get_scan_results(
        self,
        provider: str,
        scan_id: str,
        page: int = 1,
        page_size: int = 100
    ) -> Dict[str, Any]:
        """Get scan results with pagination"""
        url_map = {
            "aws": self.aws_url,
            "azure": self.azure_url,
            "gcp": self.gcp_url,
            "alicloud": self.alicloud_url,
            "oci": self.oci_url,
            "ibm": self.ibm_url
        }
        
        url = url_map.get(provider.lower())
        if not url:
            raise ValueError(f"Unknown provider: {provider}")
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(
                f"{url}/api/v1/scan/{scan_id}/results",
                params={"page": page, "page_size": page_size}
            )
            response.raise_for_status()
            return response.json()
    
    async def get_scan_summary(self, provider: str, scan_id: str) -> Dict[str, Any]:
        """Get scan summary with statistics"""
        url_map = {
            "aws": self.aws_url,
            "azure": self.azure_url,
            "gcp": self.gcp_url,
            "alicloud": self.alicloud_url,
            "oci": self.oci_url,
            "ibm": self.ibm_url
        }
        
        url = url_map.get(provider.lower())
        if not url:
            raise ValueError(f"Unknown provider: {provider}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{url}/api/v1/scan/{scan_id}/summary")
            response.raise_for_status()
            return response.json()
    
    async def list_scans(
        self,
        provider: str,
        status: Optional[str] = None,
        filter_key: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """List scans with filters"""
        url_map = {
            "aws": (self.aws_url, "account"),
            "azure": (self.azure_url, "subscription"),
            "gcp": (self.gcp_url, "project"),
            "alicloud": (self.alicloud_url, "account"),
            "oci": (self.oci_url, "compartment"),
            "ibm": (self.ibm_url, "account")
        }
        
        url_info = url_map.get(provider.lower())
        if not url_info:
            raise ValueError(f"Unknown provider: {provider}")
        
        url, filter_param = url_info
        
        params = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        if filter_key:
            params[filter_param] = filter_key
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{url}/api/v1/scans", params=params)
            response.raise_for_status()
            return response.json()
    
    async def get_engine_metrics(self, provider: str) -> Dict[str, Any]:
        """Get engine metrics"""
        url_map = {
            "aws": self.aws_url,
            "azure": self.azure_url,
            "gcp": self.gcp_url,
            "alicloud": self.alicloud_url,
            "oci": self.oci_url,
            "ibm": self.ibm_url
        }
        
        url = url_map.get(provider.lower())
        if not url:
            raise ValueError(f"Unknown provider: {provider}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{url}/api/v1/metrics")
            response.raise_for_status()
            return response.json()

