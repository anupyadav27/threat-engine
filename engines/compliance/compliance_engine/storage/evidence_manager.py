"""
Evidence Manager - Stores evidence payloads in S3 by reference
"""

import json
import uuid
import os
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from ..schemas.enterprise_report_schema import Evidence, EvidenceType


class EvidenceManager:
    """Manages evidence storage in S3 or local filesystem."""
    
    def __init__(
        self,
        s3_bucket: str = None,
        tenant_id: str = None,
        scan_run_id: str = None,
        local_storage_path: str = None
    ):
        """
        Initialize evidence manager.
        
        Args:
            s3_bucket: S3 bucket name (if using S3)
            tenant_id: Tenant identifier
            scan_run_id: Scan run identifier
            local_storage_path: Local path for evidence storage (for testing)
        """
        self.s3_bucket = s3_bucket or os.getenv("S3_BUCKET", "cspm-lgtech")
        self.tenant_id = tenant_id
        self.scan_run_id = scan_run_id
        self.local_storage_path = local_storage_path
        self.use_local = local_storage_path is not None
        
        if not self.use_local:
            try:
                import boto3
                self.s3_client = boto3.client('s3')
            except ImportError:
                raise ImportError("boto3 required for S3 storage. Install with: pip install boto3")
    
    def store_evidence(
        self,
        evidence_payload: Dict[str, Any],
        evidence_type: EvidenceType,
        collected_at: Optional[str] = None
    ) -> Evidence:
        """
        Store evidence payload in S3/local and return Evidence object with data_ref.
        
        Args:
            evidence_payload: Evidence data to store
            evidence_type: Type of evidence
            collected_at: ISO8601 timestamp (defaults to now)
        
        Returns:
            Evidence object with data_ref
        """
        evidence_id = str(uuid.uuid4())
        collected_at = collected_at or datetime.now(timezone.utc).isoformat() + 'Z'
        
        if self.use_local:
            # Local storage for testing
            evidence_dir = os.path.join(
                self.local_storage_path,
                "reports",
                self.tenant_id or "default",
                self.scan_run_id or "default",
                "evidence"
            )
            os.makedirs(evidence_dir, exist_ok=True)
            
            evidence_file = os.path.join(evidence_dir, f"{evidence_id}.json")
            with open(evidence_file, 'w') as f:
                json.dump(evidence_payload, f, indent=2)
            
            data_ref = evidence_file  # Local path
        else:
            # S3 storage
            s3_key = f"reports/{self.tenant_id}/{self.scan_run_id}/evidence/{evidence_id}.json"
            
            self.s3_client.put_object(
                Bucket=self.s3_bucket,
                Key=s3_key,
                Body=json.dumps(evidence_payload, indent=2).encode('utf-8'),
                ContentType='application/json'
            )
            
            data_ref = f"s3://{self.s3_bucket}/{s3_key}"
        
        return Evidence(
            evidence_id=evidence_id,
            type=evidence_type,
            data_ref=data_ref,
            collected_at=collected_at
        )
    
    def retrieve_evidence(self, data_ref: str) -> Dict[str, Any]:
        """
        Retrieve evidence payload from S3 or local filesystem.
        
        Args:
            data_ref: S3 path (s3://bucket/key) or local file path
        
        Returns:
            Evidence payload dictionary
        """
        if data_ref.startswith("s3://"):
            # Parse s3://bucket/key
            parts = data_ref[5:].split("/", 1)
            bucket = parts[0]
            key = parts[1] if len(parts) > 1 else ""
            
            response = self.s3_client.get_object(Bucket=bucket, Key=key)
            return json.loads(response['Body'].read())
        else:
            # Local file
            with open(data_ref, 'r') as f:
                return json.load(f)

