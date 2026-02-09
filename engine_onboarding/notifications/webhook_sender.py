"""
Webhook sender for scan completion notifications
"""
import httpx
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)


class WebhookSender:
    """Sends webhook notifications for scan events"""
    
    def __init__(self, timeout: float = 10.0):
        """
        Initialize webhook sender
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
    
    async def send_scan_completed(
        self,
        webhook_url: str,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        provider: str,
        status: str,
        scan_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send webhook notification for scan completion
        
        Args:
            webhook_url: Webhook URL to send notification to
            scan_run_id: Unified scan identifier
            tenant_id: Tenant identifier
            account_id: Account identifier
            provider: Cloud provider
            status: Scan status (completed, failed)
            scan_id: Engine-specific scan ID
            metadata: Additional metadata
        
        Returns:
            True if notification sent successfully, False otherwise
        """
        payload = {
            "event_type": "scan_completed",
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "account_id": account_id,
            "provider": provider,
            "status": status,
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": metadata or {}
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                response.raise_for_status()
                logger.info(f"Webhook notification sent successfully to {webhook_url}")
                return True
        except Exception as e:
            logger.error(f"Failed to send webhook notification to {webhook_url}: {e}")
            return False
    
    async def send_orchestration_completed(
        self,
        webhook_url: str,
        scan_run_id: str,
        orchestration_results: Dict[str, Any]
    ) -> bool:
        """
        Send webhook notification for orchestration completion
        
        Args:
            webhook_url: Webhook URL
            scan_run_id: Unified scan identifier
            orchestration_results: Results from orchestration
        
        Returns:
            True if notification sent successfully, False otherwise
        """
        payload = {
            "event_type": "orchestration_completed",
            "scan_run_id": scan_run_id,
            "timestamp": datetime.utcnow().isoformat(),
            "orchestration": orchestration_results
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                response.raise_for_status()
                logger.info(f"Orchestration webhook notification sent successfully to {webhook_url}")
                return True
        except Exception as e:
            logger.error(f"Failed to send orchestration webhook to {webhook_url}: {e}")
            return False
