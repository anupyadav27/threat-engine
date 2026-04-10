"""
Report Storage.

Saves AI security reports as JSON files for S3 sync sidecar.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, Any

logger = logging.getLogger(__name__)


class ReportStorage:
    """Saves AI security reports as JSON files for S3 sync."""

    OUTPUT_DIR = "/output/ai-security/reports"

    def __init__(self, output_dir: str = None):
        """Initialize report storage.

        Args:
            output_dir: Override default output directory.
        """
        if output_dir:
            self.OUTPUT_DIR = output_dir

    def save_report(self, scan_run_id: str, report_data: Dict[str, Any]) -> str:
        """Save full report as JSON file.

        Path: {OUTPUT_DIR}/{scan_run_id}.json

        Args:
            scan_run_id: Pipeline scan run identifier.
            report_data: Full report dict with structure:
                {
                    "scan_run_id": str,
                    "tenant_id": str,
                    "account_id": str,
                    "provider": str,
                    "timestamp": str (ISO),
                    "summary": {...scores, counts...},
                    "inventory": [...],
                    "findings": [...],
                    "shadow_ai": [...],
                    "coverage_metrics": {...},
                }

        Returns:
            Absolute file path of the saved report.
        """
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)
        file_path = os.path.join(self.OUTPUT_DIR, f"{scan_run_id}.json")

        # Inject metadata if not present
        report_data.setdefault("scan_run_id", scan_run_id)
        report_data.setdefault("exported_at", datetime.now(timezone.utc).isoformat())

        try:
            with open(file_path, "w", encoding="utf-8") as fh:
                json.dump(report_data, fh, indent=2, default=str)
            logger.info("Saved AI security report to %s", file_path)
            return file_path
        except Exception:
            logger.exception("Failed to save report to %s", file_path)
            raise
