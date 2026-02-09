"""
FastAPI server for Data Security Engine.

Provides endpoints for data security queries and report generation.
"""

import sys
import os
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime

# Add common to path for logger import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from engine_common.logger import setup_logger, LogContext, log_duration, audit_log, security_event_log
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware

from .input.threat_db_reader import ThreatDBReader
from .input.rule_db_reader import RuleDBReader
from .enricher.finding_enricher import FindingEnricher
from .mapper.rule_to_module_mapper import RuleToModuleMapper
from .reporter.data_security_reporter import DataSecurityReporter
from .storage.report_storage import ReportStorage

import json

logger = setup_logger(__name__, engine_name="engine-datasec")

app = FastAPI(
    title="Data Security Engine API",
    description="Data Security module for CSPM - Discovery, Classification, Governance, Protection, Lineage, Monitoring, Residency, Compliance",
    version="1.0.0"
)

# Add logging middleware
app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(RequestLoggingMiddleware, engine_name="engine-datasec")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request/Response Models
class ScanRequest(BaseModel):
    """Request to generate data security report."""
    csp: str = Field(..., description="Cloud service provider (e.g., 'aws')")
    scan_id: str = Field(..., description="Threat scan_run_id (from Threat engine)")
    tenant_id: str = Field(default="default-tenant", description="Tenant ID")
    include_classification: bool = Field(default=True, description="Include classification analysis")
    include_lineage: bool = Field(default=True, description="Include lineage analysis")
    include_residency: bool = Field(default=True, description="Include residency checks")
    include_activity: bool = Field(default=True, description="Include activity monitoring")
    allowed_regions: Optional[List[str]] = Field(default=None, description="Allowed regions for residency compliance (e.g., ['us-east-1', 'us-west-2'])")
    max_findings: Optional[int] = Field(default=None, description="Maximum findings to process (for testing/large scans)")
    residency_allowed_regions: Optional[List[str]] = Field(default=None, description="List of allowed regions for residency compliance (e.g., ['us-east-1', 'us-west-2'])")


class ReportResponse(BaseModel):
    """Data security report response."""
    schema_version: str
    tenant_id: str
    scan_context: Dict[str, Any]
    summary: Dict[str, Any]
    findings: List[Dict[str, Any]]
    classification: List[Dict[str, Any]]
    lineage: Dict[str, Any]
    residency: List[Dict[str, Any]]
    activity: Dict[str, Any]


# Global instances (would use dependency injection in production)
threat_db_reader = ThreatDBReader()
rule_db_reader = RuleDBReader()
finding_enricher = FindingEnricher()
reporter = DataSecurityReporter()
report_storage = ReportStorage()


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Data Security Engine",
        "version": "1.0.0",
        "status": "operational"
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    import time
    start = time.time()
    
    health_status = {"status": "healthy"}
    
    duration_ms = (time.time() - start) * 1000
    logger.info("Health check", extra={
        "extra_fields": {
            "status": "healthy",
            "duration_ms": duration_ms
        }
    })
    
    return health_status


@app.post("/api/v1/data-security/scan", response_model=ReportResponse)
async def generate_report(request: ScanRequest):
    """
    Generate comprehensive data security report.
    
    Combines enriched configScan findings with new analysis:
    - Data classification (PII/PCI/PHI detection)
    - Data lineage (flow tracking)
    - Data residency (geographic compliance)
    - Data activity monitoring (anomaly detection)
    """
    import time
    start_time = time.time()
    
    with LogContext(tenant_id=request.tenant_id, scan_run_id=request.scan_id):
        logger.info("Generating data security report", extra={
            "extra_fields": {
                "scan_id": request.scan_id,
                "csp": request.csp,
                "include_classification": request.include_classification,
                "include_lineage": request.include_lineage,
                "include_residency": request.include_residency,
                "include_activity": request.include_activity
            }
        })
        try:
            logger.info("Generating data security report", extra={
                "extra_fields": {
                    "scan_id": request.scan_id,
                    "csp": request.csp
                }
            })
            
            report = reporter.generate_report(
                csp=request.csp,
                scan_id=request.scan_id,
                tenant_id=request.tenant_id,
                include_classification=request.include_classification,
                include_lineage=request.include_lineage,
                include_residency=request.include_residency,
                include_activity=request.include_activity,
                allowed_regions=request.allowed_regions,
                max_findings=request.max_findings,
            )
            
            # Add report_id if missing
            if "report_id" not in report:
                import uuid as uuid_lib
                report["report_id"] = str(uuid_lib.uuid4())
            
            # Save to local file storage
            try:
                report_path = report_storage.save_report(
                    report=report,
                    tenant_id=request.tenant_id,
                    scan_id=request.scan_id
                )
                logger.info(f"Data security report saved to: {report_path}")
            except Exception as e:
                logger.error(f"Error saving data security report to file storage: {e}")
            
            # Save to /output for S3 sync
            try:
                output_dir = os.getenv("OUTPUT_DIR", "/output")
                if output_dir and os.path.exists(output_dir):
                    datasec_dir = os.path.join(output_dir, "datasec", request.tenant_id, request.scan_id)
                    os.makedirs(datasec_dir, exist_ok=True)
                    
                    with open(os.path.join(datasec_dir, "datasec_report.json"), "w") as f:
                        json.dump(report, f, indent=2, default=str)
                    
                    logger.info(f"DataSec report saved to {datasec_dir}")
            except Exception as e:
                logger.error(f"Error saving DataSec report to output dir: {e}")
            
            # Save to database
            try:
                from .storage.datasec_db_writer import save_datasec_report_to_db
                saved_id = save_datasec_report_to_db(report)
                logger.info(f"DataSec report saved to database: {saved_id}")
            except Exception as e:
                logger.error(f"Error saving DataSec report to database: {e}", exc_info=True)
            
            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Data security report generated", duration_ms)
            audit_log(
                logger,
                "datasec_report_generated",
                f"scan:{request.scan_id}",
                tenant_id=request.tenant_id,
                result="success",
                details={
                    "csp": request.csp,
                    "findings_count": len(report.get("findings", []))
                }
            )
            
            logger.info("Data security report generated successfully", extra={
                "extra_fields": {
                    "findings_count": len(report.get("findings", [])),
                    "classification_count": len(report.get("classification", []))
                }
            })
            
            return report
        
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Error generating data security report", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "scan_id": request.scan_id,
                    "duration_ms": duration_ms
                }
            })
            audit_log(
                logger,
                "datasec_report_generation_failed",
                f"scan:{request.scan_id}",
                tenant_id=request.tenant_id,
                result="failure",
                details={"error": str(e)}
            )
            raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/data-security/catalog")
async def get_data_catalog(
    csp: str = Query(..., description="Cloud service provider"),
    scan_id: str = Query(..., description="ConfigScan scan ID"),
    account_id: Optional[str] = Query(None, description="Filter by account ID"),
    service: Optional[str] = Query(None, description="Filter by service (e.g., 's3', 'rds', 'dynamodb')"),
    region: Optional[str] = Query(None, description="Filter by region")
):
    """Get data catalog (list of data stores) with optional filtering."""
    try:
        data_stores = configscan_reader.filter_data_stores(csp, scan_id)
        
        # Apply filters
        if account_id:
            data_stores = [ds for ds in data_stores if ds.get("account_id") == account_id]
        if service:
            data_stores = [ds for ds in data_stores if service.lower() in ds.get("service", "").lower()]
        if region:
            data_stores = [ds for ds in data_stores if ds.get("region") == region]
        
        return {
            "total_stores": len(data_stores),
            "filters": {
                "account_id": account_id,
                "service": service,
                "region": region
            },
            "stores": data_stores
        }
    except Exception as e:
        logger.error("Error getting data catalog", exc_info=True, extra={
            "extra_fields": {
                "error": str(e),
                "csp": csp,
                "scan_id": scan_id
            }
        })
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/data-security/governance/{resource_id}")
async def get_access_governance(
    resource_id: str,
    csp: str = Query(..., description="Cloud service provider"),
    scan_id: str = Query(..., description="Threat scan_run_id (from Threat engine)"),
    tenant_id: str = Query(default="default-tenant", description="Tenant ID")
):
    """Get access governance analysis for a resource from Threat DB."""
    try:
        from ..input.rule_db_reader import RuleDBReader
        rule_db_reader = RuleDBReader()
        data_security_rule_ids = rule_db_reader.get_all_data_security_rule_ids()
        # Get findings for resource
        findings = threat_db_reader.get_findings_by_resource(tenant_id, scan_id, resource_id, data_security_rule_ids)
        
        # Filter for access governance findings
        enriched = finding_enricher.enrich_findings(findings)
        governance_findings = [
            f for f in enriched
            if "data_access_governance" in f.get("data_security_modules", [])
        ]
        
        return {
            "resource_id": resource_id,
            "findings": governance_findings
        }
    except Exception as e:
        logger.error("Error getting access governance", exc_info=True, extra={
            "extra_fields": {
                "error": str(e),
                "resource_id": resource_id,
                "csp": csp,
                "scan_id": scan_id
            }
        })
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/data-security/protection/{resource_id}")
async def get_protection_status(
    resource_id: str,
    csp: str = Query(..., description="Cloud service provider"),
    scan_id: str = Query(..., description="ConfigScan scan ID")
):
    """Get encryption/protection status for a resource."""
    try:
        findings = configscan_reader.get_findings_by_resource(csp, scan_id, resource_id)
        enriched = finding_enricher.enrich_findings(findings)
        protection_findings = [
            f for f in enriched
            if "data_protection_encryption" in f.get("data_security_modules", [])
        ]
        
        return {
            "resource_id": resource_id,
            "findings": protection_findings
        }
    except Exception as e:
        logger.error("Error getting protection status", exc_info=True, extra={
            "extra_fields": {
                "error": str(e),
                "resource_id": resource_id,
                "csp": csp,
                "scan_id": scan_id
            }
        })
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/data-security/rules/{rule_id}")
async def get_rule_info(rule_id: str, service: Optional[str] = None):
    """Get data security information for a rule."""
    try:
        # Try to determine service from rule_id if not provided
        if not service:
            parts = rule_id.split(".")
            if len(parts) >= 2:
                service = parts[1]  # e.g., "aws.s3.bucket..." -> "s3"
        
        if not service:
            raise HTTPException(status_code=400, detail="Could not determine service from rule_id")
        
        metadata = rule_db_reader.read_metadata(service, rule_id)
        if not metadata:
            raise HTTPException(status_code=404, detail=f"Rule not found: {rule_id}")
        
        data_security = rule_db_reader.get_data_security_info(service, rule_id)
        
        return {
            "rule_id": rule_id,
            "metadata": metadata,
            "data_security": data_security
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting rule info: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/data-security/modules")
async def list_modules():
    """List all data security modules."""
    return {
        "modules": [
            "data_protection_encryption",
            "data_access_governance",
            "data_activity_monitoring",
            "data_residency",
            "data_compliance",
            "data_classification"
        ]
    }


@app.get("/api/v1/data-security/modules/{module}/rules")
async def get_rules_by_module(
    module: str,
    service: Optional[str] = Query(None, description="Filter by service")
):
    """Get rules for a specific data security module."""
    try:
        services = [service] if service else rule_db_reader.list_services()
        
        rules = {}
        for svc in services:
            rule_list = rule_db_reader.get_rules_by_module(svc, module)
            if rule_list:
                rules[svc] = rule_list
        
        return {
            "module": module,
            "rules": rules
        }
    except Exception as e:
        logger.error(f"Error getting rules by module: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ===== New Endpoints: Data Security Features =====

@app.get("/api/v1/data-security/classification")
async def get_classification(
    csp: str = Query(..., description="Cloud service provider"),
    scan_id: str = Query(..., description="Threat scan_run_id (from Threat engine)"),
    tenant_id: str = Query(default="default-tenant", description="Tenant ID"),
    account_id: Optional[str] = Query(None, description="Filter by account ID"),
    service: Optional[str] = Query(None, description="Filter by service (e.g., 's3', 'rds')"),
    resource_id: Optional[str] = Query(None, description="Filter by resource ID/ARN")
):
    """Get data classification results (PII/PCI/PHI detection) from Threat DB."""
    try:
        from .analyzer.classification_analyzer import ClassificationAnalyzer
        from ..input.rule_db_reader import RuleDBReader
        
        rule_db_reader = RuleDBReader()
        data_security_rule_ids = rule_db_reader.get_all_data_security_rule_ids()
        # Get data stores from Threat DB
        data_stores = threat_db_reader.filter_data_stores(tenant_id, scan_id, data_security_rule_ids)
        
        # Filter by account, service, or resource
        if account_id:
            data_stores = [ds for ds in data_stores if ds.get("account_id") == account_id]
        if service:
            data_stores = [ds for ds in data_stores if service.lower() in ds.get("service", "").lower()]
        if resource_id:
            data_stores = [ds for ds in data_stores if resource_id in ds.get("resource_arn", "") or resource_id in ds.get("resource_id", "")]
        
        # Run classification analysis
        analyzer = ClassificationAnalyzer()
        classification_results = analyzer.classify_resources(data_stores)
        
        return {
            "total_resources": len(data_stores),
            "classified_resources": len(classification_results),
            "results": [{
                "resource_id": cr.resource_id,
                "resource_arn": cr.resource_arn,
                "resource_type": cr.resource_type,
                "classification": [c.value for c in cr.classification],
                "confidence": cr.confidence,
                "matched_patterns": cr.matched_patterns
            } for cr in classification_results]
        }
    except Exception as e:
        logger.error(f"Error getting classification: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/data-security/lineage")
async def get_lineage(
    csp: str = Query(..., description="Cloud service provider"),
    scan_id: str = Query(..., description="Threat scan_run_id (from Threat engine)"),
    tenant_id: str = Query(default="default-tenant", description="Tenant ID"),
    account_id: Optional[str] = Query(None, description="Filter by account ID"),
    service: Optional[str] = Query(None, description="Filter by service"),
    resource_id: Optional[str] = Query(None, description="Filter by resource ID/ARN")
):
    """Get data lineage (flow tracking across services) from Threat DB."""
    try:
        from .analyzer.lineage_analyzer import LineageAnalyzer
        from ..input.rule_db_reader import RuleDBReader
        
        rule_db_reader = RuleDBReader()
        data_security_rule_ids = rule_db_reader.get_all_data_security_rule_ids()
        # Get data stores from Threat DB
        data_stores = threat_db_reader.filter_data_stores(tenant_id, scan_id, data_security_rule_ids)
        
        # Filter by account, service, or resource
        if account_id:
            data_stores = [ds for ds in data_stores if ds.get("account_id") == account_id]
        if service:
            data_stores = [ds for ds in data_stores if service.lower() in ds.get("service", "").lower()]
        if resource_id:
            data_stores = [ds for ds in data_stores if resource_id in ds.get("resource_arn", "") or resource_id in ds.get("resource_id", "")]
        
        # Build lineage graph
        analyzer = LineageAnalyzer()
        lineage_graph = analyzer.build_lineage_graph(data_stores)
        
        # Format lineage data
        formatted_lineage = {}
        for resource_id_key, flows in lineage_graph.items():
            formatted_lineage[resource_id_key] = [{
                "source_resource_id": flow.source_resource_id,
                "source_resource_type": flow.source_resource_type,
                "target_resource_id": flow.target_resource_id,
                "target_resource_type": flow.target_resource_type,
                "transformation": flow.transformation,
                "relationship_type": flow.relationship_type,
                "timestamp": flow.timestamp.isoformat() if flow.timestamp else None
            } for flow in flows] if flows else []
        
        return {
            "total_resources": len(data_stores),
            "lineage_graph": formatted_lineage
        }
    except Exception as e:
        logger.error(f"Error getting lineage: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/data-security/residency")
async def get_residency(
    csp: str = Query(..., description="Cloud service provider"),
    scan_id: str = Query(..., description="Threat scan_run_id (from Threat engine)"),
    tenant_id: str = Query(default="default-tenant", description="Tenant ID"),
    account_id: Optional[str] = Query(None, description="Filter by account ID"),
    service: Optional[str] = Query(None, description="Filter by service"),
    resource_id: Optional[str] = Query(None, description="Filter by resource ID/ARN"),
    allowed_regions: Optional[List[str]] = Query(None, description="List of allowed regions for compliance check")
):
    """Get data residency compliance (geographic location checks) from Threat DB."""
    try:
        from .analyzer.residency_analyzer import ResidencyAnalyzer, ResidencyPolicy
        from ..input.rule_db_reader import RuleDBReader
        
        rule_db_reader = RuleDBReader()
        data_security_rule_ids = rule_db_reader.get_all_data_security_rule_ids()
        # Get data stores from Threat DB
        data_stores = threat_db_reader.filter_data_stores(tenant_id, scan_id, data_security_rule_ids)
        
        # Filter by account, service, or resource
        if account_id:
            data_stores = [ds for ds in data_stores if ds.get("account_id") == account_id]
        if service:
            data_stores = [ds for ds in data_stores if service.lower() in ds.get("service", "").lower()]
        if resource_id:
            data_stores = [ds for ds in data_stores if resource_id in ds.get("resource_arn", "") or resource_id in ds.get("resource_id", "")]
        
        # Create residency policy if allowed_regions provided
        policies = []
        if allowed_regions:
            policy = ResidencyPolicy("custom", allowed_regions, "Custom residency policy")
            policies = [policy]
        
        # Run residency checks
        analyzer = ResidencyAnalyzer(policies)
        residency_results = analyzer.check_all_resources(data_stores)
        
        return {
            "total_resources": len(data_stores),
            "results": [{
                "resource_id": rr.resource_id,
                "resource_arn": rr.resource_arn,
                "primary_region": rr.primary_region,
                "replication_regions": rr.replication_regions,
                "policy_name": rr.policy_name,
                "compliance_status": rr.compliance_status.value,
                "violations": rr.violations
            } for rr in residency_results]
        }
    except Exception as e:
        logger.error(f"Error getting residency: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/data-security/activity")
async def get_activity(
    csp: str = Query(..., description="Cloud service provider"),
    scan_id: str = Query(..., description="ConfigScan scan ID"),
    account_id: Optional[str] = Query(None, description="Filter by account ID"),
    service: Optional[str] = Query(None, description="Filter by service"),
    resource_id: Optional[str] = Query(None, description="Filter by resource ID/ARN"),
    days_back: int = Query(7, description="Number of days to look back for activity")
):
    """Get data activity monitoring (anomaly detection)."""
    try:
        from .analyzer.activity_analyzer import ActivityAnalyzer
        
        # Get data stores
        data_stores = configscan_reader.filter_data_stores(csp, scan_id)
        
        # Filter by account, service, or resource
        if account_id:
            data_stores = [ds for ds in data_stores if ds.get("account_id") == account_id]
        if service:
            data_stores = [ds for ds in data_stores if service.lower() in ds.get("service", "").lower()]
        if resource_id:
            data_stores = [ds for ds in data_stores if resource_id in ds.get("resource_arn", "") or resource_id in ds.get("resource_id", "")]
        
        # Run activity monitoring
        analyzer = ActivityAnalyzer()
        activity_results = analyzer.monitor_data_access(data_stores, days_back=days_back)
        
        # Format activity data
        formatted_activity = {}
        for res_id, events in activity_results.items():
            formatted_activity[res_id] = [{
                "event_id": ae.event_id,
                "timestamp": ae.timestamp.isoformat() if isinstance(ae.timestamp, datetime) else str(ae.timestamp),
                "resource_id": ae.resource_id,
                "resource_arn": ae.resource_arn,
                "principal": ae.principal,
                "action": ae.action,
                "ip_address": ae.ip_address,
                "location": ae.location,
                "anomaly_score": ae.anomaly_score,
                "risk_level": ae.risk_level,
                "alert_triggered": ae.alert_triggered
            } for ae in events]
        
        return {
            "total_resources": len(data_stores),
            "days_back": days_back,
            "activity": formatted_activity
        }
    except Exception as e:
        logger.error(f"Error getting activity: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/data-security/compliance")
async def get_compliance(
    csp: str = Query(..., description="Cloud service provider"),
    scan_id: str = Query(..., description="Threat scan_run_id (from Threat engine)"),
    tenant_id: str = Query(default="default-tenant", description="Tenant ID"),
    account_id: Optional[str] = Query(None, description="Filter by account ID"),
    service: Optional[str] = Query(None, description="Filter by service"),
    resource_id: Optional[str] = Query(None, description="Filter by resource ID/ARN"),
    framework: Optional[str] = Query(None, description="Filter by compliance framework (e.g., 'gdpr', 'pci', 'hipaa')")
):
    """Get data compliance status (GDPR, PCI, HIPAA compliance checks) from Threat DB."""
    try:
        from ..input.rule_db_reader import RuleDBReader
        rule_db_reader = RuleDBReader()
        data_security_rule_ids = rule_db_reader.get_all_data_security_rule_ids()
        # Get data-related findings from Threat DB
        findings = threat_db_reader.get_misconfig_findings(tenant_id, scan_id, data_security_rule_ids)
        
        # Filter by account, service, or resource
        if account_id:
            findings = [f for f in findings if f.get("account_id") == account_id]
        if service:
            findings = [f for f in findings if service.lower() in f.get("service", "").lower()]
        if resource_id:
            findings = [f for f in findings if resource_id in f.get("resource_arn", "") or resource_id in f.get("resource_uid", "")]
        
        # Enrich findings
        enriched = finding_enricher.enrich_findings(findings)
        
        # Filter for compliance-related findings
        compliance_findings = [
            f for f in enriched
            if "data_compliance" in f.get("data_security_modules", [])
        ]
        
        # Filter by framework if specified
        if framework:
            compliance_findings = [
                f for f in compliance_findings
                if framework.lower() in f.get("data_security_context", {}).get("impact", {}).keys()
            ]
        
        # Aggregate compliance status
        compliance_summary = {
            "total_findings": len(compliance_findings),
            "by_framework": {},
            "by_status": {"PASS": 0, "FAIL": 0, "WARN": 0}
        }
        
        for finding in compliance_findings:
            status = finding.get("status", "UNKNOWN")
            compliance_summary["by_status"][status] = compliance_summary["by_status"].get(status, 0) + 1
            
            impact = finding.get("data_security_context", {}).get("impact", {})
            for framework_name in impact.keys():
                if framework_name not in compliance_summary["by_framework"]:
                    compliance_summary["by_framework"][framework_name] = {"total": 0, "pass": 0, "fail": 0}
                compliance_summary["by_framework"][framework_name]["total"] += 1
                if status == "PASS":
                    compliance_summary["by_framework"][framework_name]["pass"] += 1
                elif status == "FAIL":
                    compliance_summary["by_framework"][framework_name]["fail"] += 1
        
        return {
            "account_id": account_id,
            "service": service,
            "resource_id": resource_id,
            "framework": framework,
            "summary": compliance_summary,
            "findings": compliance_findings
        }
    except Exception as e:
        logger.error(f"Error getting compliance: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/data-security/findings")
async def get_findings(
    csp: str = Query(..., description="Cloud service provider"),
    scan_id: str = Query(..., description="Threat scan_run_id (from Threat engine)"),
    tenant_id: str = Query(default="default-tenant", description="Tenant ID"),
    account_id: Optional[str] = Query(None, description="Filter by account ID"),
    service: Optional[str] = Query(None, description="Filter by service"),
    module: Optional[str] = Query(None, description="Filter by data security module"),
    status: Optional[str] = Query(None, description="Filter by status (PASS/FAIL/WARN)"),
    resource_id: Optional[str] = Query(None, description="Filter by resource ID/ARN")
):
    """Get all data security findings from Threat DB with optional filtering."""
    try:
        from ..input.rule_db_reader import RuleDBReader
        rule_db_reader = RuleDBReader()
        data_security_rule_ids = rule_db_reader.get_all_data_security_rule_ids()
        # Get data-related findings from Threat DB
        findings = threat_db_reader.get_misconfig_findings(tenant_id, scan_id, data_security_rule_ids)
        
        # Apply filters
        if account_id:
            findings = [f for f in findings if f.get("account_id") == account_id]
        if service:
            findings = [f for f in findings if service.lower() in f.get("service", "").lower()]
        if resource_id:
            findings = [f for f in findings if resource_id in f.get("resource_arn", "") or resource_id in f.get("resource_uid", "")]
        
        # Enrich findings
        enriched = finding_enricher.enrich_findings(findings)
        
        # Filter by module
        if module:
            enriched = [f for f in enriched if module in f.get("data_security_modules", [])]
        
        # Filter by status
        if status:
            enriched = [f for f in enriched if f.get("status") == status.upper()]
        
        # Get summary statistics
        summary = {
            "total_findings": len(enriched),
            "by_module": {},
            "by_status": {"PASS": 0, "FAIL": 0, "WARN": 0, "UNKNOWN": 0}
        }
        
        for finding in enriched:
            status_val = finding.get("status", "UNKNOWN")
            summary["by_status"][status_val] = summary["by_status"].get(status_val, 0) + 1
            
            for mod in finding.get("data_security_modules", []):
                summary["by_module"][mod] = summary["by_module"].get(mod, 0) + 1
        
        return {
            "filters": {
                "account_id": account_id,
                "service": service,
                "module": module,
                "status": status,
                "resource_id": resource_id
            },
            "summary": summary,
            "findings": enriched
        }
    except Exception as e:
        logger.error(f"Error getting findings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/data-security/accounts/{account_id}")
async def get_account_data_security(
    account_id: str,
    csp: str = Query(..., description="Cloud service provider"),
    scan_id: str = Query(..., description="Threat scan_run_id (from Threat engine)"),
    tenant_id: str = Query(default="default-tenant", description="Tenant ID"),
    service: Optional[str] = Query(None, description="Filter by service")
):
    """Get comprehensive data security status for a specific account from Threat DB."""
    try:
        from ..input.rule_db_reader import RuleDBReader
        rule_db_reader = RuleDBReader()
        data_security_rule_ids = rule_db_reader.get_all_data_security_rule_ids()
        # Get all findings for account from Threat DB
        findings = threat_db_reader.get_misconfig_findings(tenant_id, scan_id, data_security_rule_ids)
        account_findings = [f for f in findings if f.get("account_id") == account_id]
        
        if service:
            account_findings = [f for f in account_findings if service.lower() in f.get("service", "").lower()]
        
        # Enrich findings
        enriched = finding_enricher.enrich_findings(account_findings)
        
        # Get data stores for account from Threat DB
        data_stores = threat_db_reader.filter_data_stores(tenant_id, scan_id, data_security_rule_ids)
        account_stores = [ds for ds in data_stores if ds.get("account_id") == account_id]
        
        if service:
            account_stores = [ds for ds in account_stores if service.lower() in ds.get("service", "").lower()]
        
        # Aggregate summary
        summary = {
            "account_id": account_id,
            "total_findings": len(enriched),
            "total_data_stores": len(account_stores),
            "findings_by_status": {"PASS": 0, "FAIL": 0, "WARN": 0},
            "findings_by_module": {},
            "services": list(set([ds.get("service", "") for ds in account_stores]))
        }
        
        for finding in enriched:
            status = finding.get("status", "UNKNOWN")
            summary["findings_by_status"][status] = summary["findings_by_status"].get(status, 0) + 1
            
            for mod in finding.get("data_security_modules", []):
                summary["findings_by_module"][mod] = summary["findings_by_module"].get(mod, 0) + 1
        
        return {
            "account_id": account_id,
            "summary": summary,
            "findings": enriched,
            "data_stores": account_stores
        }
    except Exception as e:
        logger.error(f"Error getting account data security: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/data-security/services/{service}")
async def get_service_data_security(
    service: str,
    csp: str = Query(..., description="Cloud service provider"),
    scan_id: str = Query(..., description="Threat scan_run_id (from Threat engine)"),
    tenant_id: str = Query(default="default-tenant", description="Tenant ID"),
    account_id: Optional[str] = Query(None, description="Filter by account ID")
):
    """Get comprehensive data security status for a specific service from Threat DB."""
    try:
        from ..input.rule_db_reader import RuleDBReader
        rule_db_reader = RuleDBReader()
        data_security_rule_ids = rule_db_reader.get_all_data_security_rule_ids()
        # Get findings for service from Threat DB
        findings = threat_db_reader.get_misconfig_findings(tenant_id, scan_id, data_security_rule_ids)
        findings = [f for f in findings if service.lower() in (f.get("service") or "").lower()]
        
        if account_id:
            findings = [f for f in findings if f.get("account_id") == account_id]
        
        # Enrich findings
        enriched = finding_enricher.enrich_findings(findings)
        
        # Get data stores for service from Threat DB
        data_stores = threat_db_reader.filter_data_stores(tenant_id, scan_id, data_security_rule_ids)
        service_stores = [ds for ds in data_stores if service.lower() in ds.get("service", "").lower()]
        
        if account_id:
            service_stores = [ds for ds in service_stores if ds.get("account_id") == account_id]
        
        # Aggregate summary
        summary = {
            "service": service,
            "total_findings": len(enriched),
            "total_resources": len(service_stores),
            "findings_by_status": {"PASS": 0, "FAIL": 0, "WARN": 0},
            "findings_by_module": {},
            "accounts": list(set([f.get("account_id", "") for f in enriched]))
        }
        
        for finding in enriched:
            status = finding.get("status", "UNKNOWN")
            summary["findings_by_status"][status] = summary["findings_by_status"].get(status, 0) + 1
            
            for mod in finding.get("data_security_modules", []):
                summary["findings_by_module"][mod] = summary["findings_by_module"].get(mod, 0) + 1
        
        return {
            "service": service,
            "account_id": account_id,
            "summary": summary,
            "findings": enriched,
            "resources": service_stores
        }
    except Exception as e:
        logger.error(f"Error getting service data security: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("DATASEC_ENGINE_PORT", "8004"))  # Changed from 8000 to avoid conflict
    uvicorn.run(app, host="0.0.0.0", port=port)

