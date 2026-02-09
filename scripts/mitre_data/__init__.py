"""
MITRE ATT&CK guidance data for all 7 CSPs.

This package contains CSP-specific detection and remediation guidance
that gets merged into mitre_technique_reference.detection_guidance
and mitre_technique_reference.remediation_guidance JSONB columns.

Structure:
    guidance_aws.py       — AWS CloudTrail, GuardDuty, CloudWatch guidance
    guidance_azure.py     — Azure Activity Logs, Defender, Sentinel guidance
    guidance_gcp.py       — GCP Audit Logs, SCC, Chronicle guidance
    guidance_oci.py       — OCI Audit Logs, Cloud Guard guidance
    guidance_ibm.py       — IBM Activity Tracker, Security Advisor guidance
    guidance_alicloud.py  — Alicloud ActionTrail, Security Center guidance
    guidance_k8s.py       — Kubernetes Audit Logs, Falco guidance
"""
