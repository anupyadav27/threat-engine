"""
SecOps Management – maps to SecOps Engine API / engine_secops schema.
All data via SecOpsEngineClient; models define shape (scan_id, customer_id, tenant_id).
"""

# No DB models – we use SecOps Engine API (GET /api/v1/secops/scans, etc.)
# and engine_secops.secops_scans / secops_findings as source of truth.
