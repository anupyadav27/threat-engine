"""
Compliance Engine API Server

FastAPI server for generating compliance reports from CSP scan results.
"""

import sys
import os
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
import json
from datetime import datetime
import psycopg2

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from engine_common.logger import setup_logger, LogContext, log_duration, audit_log
from engine_common.telemetry import configure_telemetry
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware
from engine_common.storage_paths import get_project_root
from engine_common.orchestration import get_orchestration_metadata

logger = setup_logger(__name__, engine_name="engine-compliance")

from .mapper.rule_mapper import RuleMapper
from .mapper.framework_loader import FrameworkLoader
from .aggregator.result_aggregator import ResultAggregator
from .aggregator.score_calculator import ScoreCalculator
from .reporter.executive_dashboard import ExecutiveDashboard
from .reporter.framework_report import FrameworkReport
from .reporter.resource_drilldown import ResourceDrilldown
from .reporter.enterprise_reporter import EnterpriseReporter
from .exporter.json_exporter import JSONExporter
from .exporter.csv_exporter import CSVExporter
from .storage.trend_tracker import TrendTracker
from .storage.report_storage import ReportStorage
from .loader.check_db_loader import CheckDBLoader
try:
    from .exporter.pdf_exporter import PDFExporter
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
try:
    from .exporter.db_exporter import DatabaseExporter
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

# Additional imports for new features
from .reporter.grouping_helper import group_by_control, group_by_resource
from .loader.consolidated_csv_loader import ConsolidatedCSVLoader
from .mock.compliance_mock_data import ComplianceMockDataGenerator
try:
    from .exporter.excel_exporter import ExcelExporter
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False

app = FastAPI(
    title="Compliance Engine API",
    description="Generate compliance reports from CSP scan results",
    version="1.0.0"
)
configure_telemetry("engine-compliance", app)

# Add logging middleware
app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(RequestLoggingMiddleware, engine_name="compliance-engine")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for reports (use Redis/DB in production)
reports = {}

# Initialize components
rule_mapper = RuleMapper()
aggregator = ResultAggregator(rule_mapper)
score_calculator = ScoreCalculator(aggregator)
executive_dashboard = ExecutiveDashboard(aggregator, score_calculator)
framework_report = FrameworkReport(aggregator, score_calculator)
resource_drilldown = ResourceDrilldown(aggregator)
trend_tracker = TrendTracker()
report_storage = ReportStorage()


# DEPRECATED: Replaced by get_orchestration_metadata() from engine_common.orchestration
# This wrapper maintained for backward compatibility
def get_check_scan_id_from_orchestration(scan_run_id: str) -> Optional[str]:
    """Query scan_orchestration table to get check_scan_id for a given scan_run_id."""
    try:
        metadata = get_orchestration_metadata(scan_run_id)
        if metadata:
            check_scan_id = metadata.get("check_scan_id")
            if check_scan_id:
                logger.info(f"Found check_scan_id={check_scan_id} for scan_run_id={scan_run_id}")
                return check_scan_id
            else:
                logger.warning(f"No check_scan_id found in scan_orchestration for scan_run_id={scan_run_id}")
                return None
        return None
    except Exception as e:
        logger.error(f"Error querying scan_orchestration table: {e}", exc_info=True)
        return None


class GenerateReportRequest(BaseModel):
    """Request to generate compliance report."""
    scan_id: Optional[str] = None  # Direct check_scan_id (ad-hoc mode)
    orchestration_id: Optional[str] = None  # Orchestration ID (pipeline mode)
    scan_run_id: Optional[str] = None  # Alias for orchestration_id
    csp: str  # aws, azure, gcp, alicloud, oci, ibm
    frameworks: Optional[List[str]] = None  # Optional: filter specific frameworks


class GenerateEnterpriseReportRequest(BaseModel):
    """Request to generate enterprise-grade compliance report."""
    scan_id: Optional[str] = None  # Direct check_scan_id (ad-hoc mode)
    orchestration_id: Optional[str] = None  # Orchestration ID (pipeline mode)
    scan_run_id: Optional[str] = None  # Alias for orchestration_id
    csp: Optional[str] = None  # aws, azure, gcp (OPTIONAL - queried from scan_orchestration if not provided)
    tenant_id: Optional[str] = None  # OPTIONAL - queried from scan_orchestration if not provided
    tenant_name: Optional[str] = None
    trigger_type: Optional[str] = "manual"  # scheduled, manual, api, webhook
    collection_mode: Optional[str] = "full"  # full, incremental
    export_to_db: Optional[bool] = False  # Export to PostgreSQL


class ScanResultsInput(BaseModel):
    """Direct scan results input (alternative to scan_id)."""
    scan_results: Dict[str, Any]
    csp: str
    frameworks: Optional[List[str]] = None


def save_report_to_s3(report: Dict[str, Any], csp: str) -> None:
    """
    Save compliance report to S3.
    
    S3 Structure:
    s3://cspm-lgtech/compliance-engine/output/{csp}/{report_id}/
        - report.json
        - executive_summary.pdf
        - executive_summary.csv
        - {framework}_report.pdf (for each framework)
        - {framework}_report.csv (for each framework)
    """
    try:
        import boto3
        s3_bucket = os.getenv("S3_BUCKET", "cspm-lgtech")
        s3_client = boto3.client('s3')
        
        report_id = report.get('report_id')
        s3_base_path = f"compliance-engine/output/{csp}/{report_id}"
        
        # Save JSON report
        json_exporter = JSONExporter()
        json_content = json_exporter.export(report, pretty=True)
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=f"{s3_base_path}/report.json",
            Body=json_content.encode('utf-8'),
            ContentType='application/json'
        )
        
        # Save executive dashboard CSV
        csv_exporter = CSVExporter()
        csv_content = csv_exporter.export_executive_summary(report.get('executive_dashboard', {}))
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=f"{s3_base_path}/executive_summary.csv",
            Body=csv_content.encode('utf-8'),
            ContentType='text/csv'
        )
        
        # Save executive dashboard PDF
        if PDF_AVAILABLE:
            try:
                pdf_exporter = PDFExporter()
                pdf_bytes = pdf_exporter.export_executive_summary(report.get('executive_dashboard', {}))
                s3_client.put_object(
                    Bucket=s3_bucket,
                    Key=f"{s3_base_path}/executive_summary.pdf",
                    Body=pdf_bytes,
                    ContentType='application/pdf'
                )
            except Exception as e:
                logger.warning("Could not generate PDF", exc_info=True, extra={
                    "extra_fields": {"error": str(e)}
                })
        
        # Save framework reports
        framework_reports = report.get('framework_reports', {})
        for framework, fw_report in framework_reports.items():
            # CSV
            csv_content = csv_exporter.export_framework_report(fw_report)
            framework_safe = framework.replace(' ', '_').replace('/', '_')
            s3_client.put_object(
                Bucket=s3_bucket,
                Key=f"{s3_base_path}/{framework_safe}_report.csv",
                Body=csv_content.encode('utf-8'),
                ContentType='text/csv'
            )
            
            # PDF
            if PDF_AVAILABLE:
                try:
                    pdf_bytes = pdf_exporter.export_framework_report(fw_report)
                    s3_client.put_object(
                        Bucket=s3_bucket,
                        Key=f"{s3_base_path}/{framework_safe}_report.pdf",
                        Body=pdf_bytes,
                        ContentType='application/pdf'
                    )
                except Exception as e:
                    logger.warning("Could not generate PDF for framework", exc_info=True, extra={
                        "extra_fields": {
                            "framework": framework,
                            "error": str(e)
                        }
                    })
        
        logger.info("Report saved to S3", extra={
            "extra_fields": {
                "s3_path": f"s3://{s3_bucket}/{s3_base_path}/",
                "report_id": report_id
            }
        })
    
    except Exception as e:
        logger.error("Error saving report to S3", exc_info=True, extra={
            "extra_fields": {
                "error": str(e),
                "report_id": report.get('report_id') if 'report' in locals() else None
            }
        })


def get_csp_s3_path(csp: str) -> str:
    """
    Get S3 output path for a CSP.
    
    Maps CSP names to S3 folder structure:
    - aws → aws-compliance-engine/output
    - azure → azure-compliance-engine/output
    - gcp → gcp-compliance-engine/output
    - alicloud → alicloud-compliance-engine/output
    - oci → oci-compliance-engine/output
    - ibm → ibm-compliance-engine/output
    
    Args:
        csp: Cloud service provider (aws, azure, gcp, alicloud, oci, ibm)
    
    Returns:
        S3 path prefix (e.g., "aws-compliance-engine/output")
    """
    csp_paths = {
        'aws': 'aws-compliance-engine/output',
        'azure': 'azure-compliance-engine/output',
        'gcp': 'gcp-compliance-engine/output',
        'alicloud': 'alicloud-compliance-engine/output',
        'oci': 'oci-compliance-engine/output',
        'ibm': 'ibm-compliance-engine/output'
    }
    
    return csp_paths.get(csp.lower(), f"{csp}-compliance-engine/output")


def load_scan_results_from_s3(scan_id: str, csp: str) -> Dict[str, Any]:
    """
    Load scan results from S3 or local storage.
    
    S3 Structure:
    s3://cspm-lgtech/{csp}-configScan-engine/output/{scan_id}/results.ndjson
    s3://cspm-lgtech/{csp}-configScan-engine/output/{scan_id}/summary.json
    
    Local Structure (for testing):
    engine_output/engine_configscan_{csp}/output/{scan_id}/results.ndjson
    engine_output/engine_configscan_{csp}/output/{scan_id}/summary.json
    
    Args:
        scan_id: Scan ID
        csp: Cloud service provider (aws, azure, gcp, alicloud, oci, ibm)
    
    Returns:
        Scan results dictionary
    """
    # Get S3 path for this CSP
    s3_bucket = os.getenv("S3_BUCKET", "cspm-lgtech")
    csp_s3_path = get_csp_s3_path(csp)
    s3_path = f"{csp_s3_path}/{scan_id}/results.ndjson"
    
    try:
        import boto3
        s3_client = boto3.client('s3')
        
        # Try to load results.ndjson
        try:
            obj = s3_client.get_object(Bucket=s3_bucket, Key=s3_path)
            results = []
            for line in obj['Body'].read().decode('utf-8').split('\n'):
                if line.strip():
                    results.append(json.loads(line))
            
            # Reconstruct scan results format
            # Each line in results.ndjson is a service/region result with structure:
            # {
            #   "account_id": "...",
            #   "service": "...",
            #   "region": "...",
            #   "scope": "global|regional",
            #   "checks": [...]
            # }
            if results:
                # Extract account_id and scanned_at from first result or summary
                account_id = results[0].get('account_id')
                scanned_at = results[0].get('scanned_at')
                
                # If not in results, try to get from summary.json
                if not account_id or not scanned_at:
                    try:
                        summary_path = f"{csp_s3_path}/{scan_id}/summary.json"
                        summary_obj = s3_client.get_object(Bucket=s3_bucket, Key=summary_path)
                        summary = json.loads(summary_obj['Body'].read().decode('utf-8'))
                        account_id = account_id or summary.get('account_id')
                        scanned_at = scanned_at or summary.get('scanned_at')
                    except Exception:
                        pass

                return {
                    'scan_id': scan_id,
                    'csp': csp,
                    'account_id': account_id,
                    'scanned_at': scanned_at or datetime.utcnow().isoformat() + 'Z',
                    'results': results
                }
        except s3_client.exceptions.NoSuchKey:
            pass
        
        # Try to load summary.json
        summary_path = f"{csp_s3_path}/{scan_id}/summary.json"
        try:
            obj = s3_client.get_object(Bucket=s3_bucket, Key=summary_path)
            summary = json.loads(obj['Body'].read().decode('utf-8'))
            # If summary exists but no results, return minimal structure
            return {
                'scan_id': scan_id,
                'csp': csp,
                'account_id': summary.get('account_id'),
                'scanned_at': summary.get('scanned_at'),
                'results': []
            }
        except s3_client.exceptions.NoSuchKey:
            pass
    
    except Exception as e:
        logger.warning("Error loading from S3", exc_info=True, extra={
            "extra_fields": {
                "error": str(e),
                "scan_id": scan_id,
                "csp": csp
            }
        })
    
    # Fallback: try local file system (project-root relative)
    from pathlib import Path
    root = get_project_root()
    configscan_folder = f"engine_configscan_{csp}"
    configscan_path = root / "engine_output" / configscan_folder / "output" / scan_id / "results.ndjson"
    if configscan_path.exists():
        local_path = str(configscan_path)
    else:
        local_path = str(root / "engine_output" / configscan_folder / "output" / scan_id / "results.ndjson")
        
        if not os.path.exists(local_path):
            output_dir = os.getenv("OUTPUT_DIR", "/output")
            local_path = os.path.join(output_dir, scan_id, "results.ndjson")
    
    if os.path.exists(local_path):
        results = []
        with open(local_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        # Skip malformed lines
                        continue
        
        if results:
            # Try to get account_id and scanned_at from summary.json
            # Check summary.json in same directory as results.ndjson
            summary_path = os.path.join(os.path.dirname(local_path), "summary.json")
            # Also try OUTPUT_DIR fallback
            if not os.path.exists(summary_path):
                output_dir = os.getenv("OUTPUT_DIR", "/output")
                summary_path = os.path.join(output_dir, scan_id, "summary.json")
            account_id = results[0].get('account_id')
            scanned_at = results[0].get('scanned_at')
            
            if os.path.exists(summary_path):
                try:
                    with open(summary_path, 'r', encoding='utf-8') as f:
                        summary = json.load(f)
                        account_id = account_id or summary.get('account_id')
                        scanned_at = scanned_at or summary.get('scanned_at')
                except Exception:
                    pass

            return {
                'scan_id': scan_id,
                'csp': csp,
                'account_id': account_id,
                'scanned_at': scanned_at or datetime.utcnow().isoformat() + 'Z',
                'results': results
            }
    
    raise HTTPException(
        status_code=404,
        detail=f"Scan results not found for scan_id: {scan_id} (checked S3: s3://{s3_bucket}/{csp_s3_path}/{scan_id}/ and local: {local_path})"
    )


@app.post("/api/v1/compliance/generate")
async def generate_compliance_report(
    request: GenerateReportRequest,
    background_tasks: BackgroundTasks
):
    """
    Generate compliance report from scan results.

    Can either:
    1. Load scan results from S3/storage using scan_id
    2. Accept direct scan results in request body
    """
    import time
    start_time = time.time()
    report_id = str(uuid.uuid4())

    # Determine which check_scan_id to use
    # Priority: direct scan_id > orchestration_id lookup > scan_run_id lookup
    check_query_scan_id = None

    if request.scan_id:
        # MODE 1: Direct scan_id provided (ad-hoc testing)
        check_query_scan_id = request.scan_id
        logger.info(f"Using direct check_scan_id: {check_query_scan_id}")
    elif request.orchestration_id or request.scan_run_id:
        # MODE 2: Orchestrated run - query scan_orchestration table
        orchestration_id = request.orchestration_id or request.scan_run_id
        check_query_scan_id = get_check_scan_id_from_orchestration(orchestration_id)

        if not check_query_scan_id:
            raise HTTPException(status_code=400, detail=f"No check_scan_id found in scan_orchestration for scan_run_id={orchestration_id}. Check engine may not have completed yet.")
    else:
        raise HTTPException(status_code=400, detail="Either scan_id, scan_run_id, or orchestration_id must be provided")

    with LogContext(scan_run_id=check_query_scan_id):
        logger.info("Generating compliance report", extra={
            "extra_fields": {
                "check_scan_id": check_query_scan_id,
                "csp": request.csp,
                "frameworks": request.frameworks,
                "report_id": report_id
            }
        })

        try:
            # Load scan results
            logger.info("Loading scan results")
            scan_results = load_scan_results_from_s3(check_query_scan_id, request.csp)

            # Generate executive dashboard
            dashboard = executive_dashboard.generate(
                scan_results,
                request.csp,
                request.frameworks
            )

            # Generate framework reports
            framework_reports = {}
            frameworks_to_process = request.frameworks or dashboard.get('frameworks', [])

            for fw_data in frameworks_to_process:
                if isinstance(fw_data, dict):
                    framework = fw_data.get('framework')
                else:
                    framework = fw_data

                if framework:
                    fw_report = framework_report.generate(scan_results, request.csp, framework)
                    framework_reports[framework] = fw_report

            # Store report
            report = {
                'report_id': report_id,
                'scan_id': check_query_scan_id,  # Use resolved check_scan_id
                'csp': request.csp,
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'executive_dashboard': dashboard,
                'framework_reports': framework_reports
            }

            reports[report_id] = report

            # Record trends for each framework
            for fw_data in dashboard.get('frameworks', []):
                if isinstance(fw_data, dict):
                    framework = fw_data.get('framework')
                    score = fw_data.get('compliance_score', 0)
                else:
                    continue

                if framework and scan_results.get('account_id'):
                    trend_tracker.record_score(
                        csp=request.csp,
                        account_id=scan_results.get('account_id'),
                        framework=framework,
                        score=score,
                        scanned_at=scan_results.get('scanned_at')
                    )

            # Save to S3 in background
            background_tasks.add_task(save_report_to_s3, report, request.csp)

            duration_ms = (time.time() - start_time) * 1000
            log_duration(logger, "Compliance report generated", duration_ms)
            audit_log(
                logger,
                "compliance_report_generated",
                f"report:{report_id}",
                result="success",
                details={
                    "scan_id": request.scan_id,
                    "csp": request.csp,
                    "frameworks_count": len(framework_reports)
                }
            )

            logger.info("Compliance report generated successfully", extra={
                "extra_fields": {
                    "report_id": report_id,
                    "frameworks": list(framework_reports.keys())
                }
            })

            return {
                'report_id': report_id,
                'status': 'completed',
                'compliance_report': report
            }

        except HTTPException:
            raise
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error("Failed to generate compliance report", exc_info=True, extra={
                "extra_fields": {
                    "error": str(e),
                    "scan_id": request.scan_id,
                    "duration_ms": duration_ms
                }
            })
            audit_log(
                logger,
                "compliance_report_generation_failed",
                f"scan:{request.scan_id}",
                result="failure",
                details={"error": str(e)}
            )
            raise HTTPException(
                status_code=500,
                detail=f"Error generating compliance report: {str(e)}"
            )


@app.post("/api/v1/compliance/generate/direct")
async def generate_compliance_report_direct(request: ScanResultsInput):
    """
    Generate compliance report from direct scan results input.
    """
    report_id = str(uuid.uuid4())
    
    try:
        # Generate executive dashboard
        dashboard = executive_dashboard.generate(
            request.scan_results,
            request.csp,
            request.frameworks
        )
        
        # Generate framework reports
        framework_reports = {}
        frameworks_to_process = request.frameworks or dashboard.get('frameworks', [])
        
        for fw_data in frameworks_to_process:
            if isinstance(fw_data, dict):
                framework = fw_data.get('framework')
            else:
                framework = fw_data
            
            if framework:
                fw_report = framework_report.generate(
                    request.scan_results,
                    request.csp,
                    framework
                )
                framework_reports[framework] = fw_report
        
        # Store report
        report = {
            'report_id': report_id,
            'scan_id': request.scan_results.get('scan_id'),
            'csp': request.csp,
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'executive_dashboard': dashboard,
            'framework_reports': framework_reports
        }
        
        reports[report_id] = report
        
        return {
            'report_id': report_id,
            'status': 'completed',
            'compliance_report': report
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generating compliance report: {str(e)}"
        )


class GenerateFromThreatEngineRequest(BaseModel):
    """Request to generate compliance report from threat engine output."""
    tenant_id: Optional[str] = None
    scan_id: Optional[str] = None
    csp: str = "aws"
    frameworks: Optional[List[str]] = None


@app.post("/api/v1/compliance/generate/from-threat-engine")
async def generate_compliance_report_from_threat_engine(
    request: GenerateFromThreatEngineRequest,
    background_tasks: BackgroundTasks
):
    """
    Generate compliance report from threat engine check results.
    
    Loads check results from findings.ndjson and uses rule metadata
    to map to compliance frameworks.
    """
    report_id = str(uuid.uuid4())
    
    try:
        from .loader.threat_engine_loader import ThreatEngineLoader
        from .mapper.rule_mapper import RuleMapper
        
        # Load check results from threat engine
        threat_loader = ThreatEngineLoader()
        scan_results = threat_loader.load_and_convert(
            tenant_id=request.tenant_id,
            scan_id=request.scan_id,
            csp=request.csp
        )
        
        if not scan_results.get('results'):
            raise HTTPException(
                status_code=404,
                detail=f"No check results found (tenant_id={request.tenant_id}, scan_id={request.scan_id})"
            )
        
        # Use metadata loader for compliance mappings
        rule_mapper = RuleMapper()
        rule_mapper.framework_loader = FrameworkLoader()
        
        # Update rule mapper to use metadata
        # We need to ensure metadata mappings are loaded
        for result in scan_results.get('results', []):
            for check in result.get('checks', []):
                rule_id = check.get('rule_id')
                if rule_id:
                    # This will trigger metadata loading if needed
                    rule_mapper.get_controls_for_rule(rule_id, request.csp, use_metadata=True)
        
        # Generate executive dashboard (with metadata support)
        # Temporarily update aggregator to use metadata
        aggregator_with_metadata = ResultAggregator(rule_mapper)
        score_calculator_with_metadata = ScoreCalculator(aggregator_with_metadata)
        executive_dashboard_with_metadata = ExecutiveDashboard(aggregator_with_metadata, score_calculator_with_metadata)
        
        dashboard = executive_dashboard_with_metadata.generate(
            scan_results,
            request.csp,
            request.frameworks
        )
        
        # Generate framework reports
        framework_report_with_metadata = FrameworkReport(aggregator_with_metadata, score_calculator_with_metadata)
        framework_reports = {}
        frameworks_to_process = request.frameworks or dashboard.get('frameworks', [])
        
        for fw_data in frameworks_to_process:
            if isinstance(fw_data, dict):
                framework = fw_data.get('framework')
            else:
                framework = fw_data
            
            if framework:
                fw_report = framework_report_with_metadata.generate(
                    scan_results,
                    request.csp,
                    framework
                )
                framework_reports[framework] = fw_report
        
        # Store report
        report = {
            'report_id': report_id,
            'scan_id': scan_results.get('scan_id'),
            'csp': request.csp,
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'source': 'threat_engine',
            'executive_dashboard': dashboard,
            'framework_reports': framework_reports
        }
        
        reports[report_id] = report
        
        # Record trends
        for fw_data in dashboard.get('frameworks', []):
            if isinstance(fw_data, dict):
                framework = fw_data.get('framework')
                score = fw_data.get('compliance_score', 0)
            else:
                continue
            
            if framework and scan_results.get('account_id'):
                trend_tracker.record_score(
                    csp=request.csp,
                    account_id=scan_results.get('account_id'),
                    framework=framework,
                    score=score,
                    scanned_at=scan_results.get('scanned_at')
                )
        
        # Save to S3 in background
        background_tasks.add_task(save_report_to_s3, report, request.csp)
        
        return {
            'report_id': report_id,
            'status': 'completed',
            'compliance_report': report
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generating compliance report from threat engine: {str(e)}"
        )


class GenerateFromCheckDBRequest(BaseModel):
    """Request to generate compliance report from Check DB (PostgreSQL)."""
    tenant_id: str
    scan_id: str  # check_scan_id, or 'latest' for most recent completed scan
    csp: str = "aws"
    frameworks: Optional[List[str]] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    service: Optional[str] = None
    status_filter: Optional[str] = None  # PASS, FAIL, or None for all


@app.post("/api/v1/compliance/generate/from-check-db")
async def generate_compliance_report_from_check_db(
    request: GenerateFromCheckDBRequest,
    background_tasks: BackgroundTasks
):
    """
    Generate compliance report from Check DB (threat_engine_check).

    Reads check_results from PostgreSQL. Use for Discovery → Check → Threat →
    Compliance flow when all data is stored in local DB. Configure via
    CHECK_DB_HOST, CHECK_DB_PORT, CHECK_DB_NAME, CHECK_DB_USER, CHECK_DB_PASSWORD.
    """
    report_id = str(uuid.uuid4())

    try:
        from .loader.check_db_loader import CheckDBLoader

        with CheckDBLoader() as loader:
            scan_results = loader.load_and_convert(
                scan_id=request.scan_id,
                tenant_id=request.tenant_id,
                csp=request.csp,
                account_id=request.account_id,
                region=request.region,
                service=request.service,
                status_filter=request.status_filter,
            )

        if not scan_results.get("results"):
            raise HTTPException(
                status_code=404,
                detail=(
                    f"No check results found (tenant_id={request.tenant_id}, "
                    f"scan_id={request.scan_id}). Ensure Check DB is populated."
                ),
            )

        rule_mapper_db = RuleMapper()
        rule_mapper_db.framework_loader = FrameworkLoader()
        for result in scan_results.get("results", []):
            for check in result.get("checks", []):
                rid = check.get("rule_id")
                if rid:
                    rule_mapper_db.get_controls_for_rule(rid, request.csp, use_metadata=True)

        agg = ResultAggregator(rule_mapper_db)
        sc = ScoreCalculator(agg)
        ed = ExecutiveDashboard(agg, sc)
        fr = FrameworkReport(agg, sc)

        dashboard = ed.generate(scan_results, request.csp, request.frameworks)
        framework_reports = {}
        fw_list = request.frameworks or [
            x.get("framework") for x in dashboard.get("frameworks", [])
            if isinstance(x, dict) and x.get("framework")
        ]
        for fw in fw_list:
            if fw:
                framework_reports[fw] = fr.generate(scan_results, request.csp, fw)

        report = {
            "report_id": report_id,
            "scan_id": scan_results.get("scan_id"),
            "csp": request.csp,
            "tenant_id": request.tenant_id,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "source": "check_db",
            "executive_dashboard": dashboard,
            "framework_reports": framework_reports,
        }
        reports[report_id] = report

        for fw_data in dashboard.get("frameworks", []):
            if not isinstance(fw_data, dict):
                continue
            fw = fw_data.get("framework")
            score = fw_data.get("compliance_score", 0)
            if fw and scan_results.get("account_id"):
                trend_tracker.record_score(
                    csp=request.csp,
                    account_id=scan_results.get("account_id"),
                    framework=fw,
                    score=score,
                    scanned_at=scan_results.get("scanned_at"),
                )

        # Save report to engine_output/compliance/reports/ (local JSON)
        try:
            report_path = report_storage.save_report(
                report=report,
                tenant_id=request.tenant_id,
                scan_id=scan_results.get("scan_id") or request.scan_id
            )
            logger.info(f"Compliance report saved to: {report_path}")
        except Exception as e:
            logger.error(f"Error saving compliance report to storage: {e}")
        
        # Save to database (normalized tables) - PRIMARY storage
        try:
            from .storage.compliance_db_writer import save_compliance_report_to_db
            compliance_scan_id = save_compliance_report_to_db(report)
            logger.info(f"Compliance report saved to database: {compliance_scan_id}")
        except Exception as e:
            logger.error(f"Error saving compliance report to database: {e}")

        background_tasks.add_task(save_report_to_s3, report, request.csp)

        return {
            "report_id": report_id,
            "status": "completed",
            "compliance_report": report,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generating compliance report from Check DB: {str(e)}",
        )


class GenerateFromThreatDBRequest(BaseModel):
    """Request to generate compliance report from Threat DB (threat_reports)."""
    tenant_id: str
    scan_run_id: str  # threat report key, or 'latest' for most recent
    csp: str = "aws"
    frameworks: Optional[List[str]] = None


@app.post("/api/v1/compliance/generate/from-threat-db")
async def generate_compliance_report_from_threat_db(
    request: GenerateFromThreatDBRequest,
    background_tasks: BackgroundTasks,
):
    """
    Generate compliance report from Threat DB (threat_reports).

    Reads report_data from PostgreSQL, extracts misconfig_findings, and produces
    compliance reports. Use when Threat engine writes to DB (THREAT_USE_DB=true).
    Configure via THREAT_DB_HOST, THREAT_DB_PORT, THREAT_DB_NAME, THREAT_DB_USER, THREAT_DB_PASSWORD.
    """
    report_id = str(uuid.uuid4())

    try:
        from .loader.threat_db_loader import ThreatDBLoader

        with ThreatDBLoader() as loader:
            scan_run_id = request.scan_run_id
            if (scan_run_id or "").lower() == "latest":
                listed = loader.list_scan_ids(request.tenant_id, limit=1)
                if not listed:
                    raise HTTPException(
                        status_code=404,
                        detail=f"No threat reports found for tenant_id={request.tenant_id}.",
                    )
                scan_run_id = listed[0]["scan_run_id"]

            scan_results = loader.load_and_convert(
                tenant_id=request.tenant_id,
                scan_run_id=scan_run_id,
                csp=request.csp,
            )

        if not scan_results.get("results"):
            raise HTTPException(
                status_code=404,
                detail=(
                    f"No threat report or misconfig_findings found (tenant_id={request.tenant_id}, "
                    f"scan_run_id={scan_run_id}). Ensure Threat DB has report for this scan."
                ),
            )

        rule_mapper_t = RuleMapper()
        rule_mapper_t.framework_loader = FrameworkLoader()
        for result in scan_results.get("results", []):
            for check in result.get("checks", []):
                rid = check.get("rule_id")
                if rid:
                    rule_mapper_t.get_controls_for_rule(rid, request.csp, use_metadata=True)

        agg = ResultAggregator(rule_mapper_t)
        sc = ScoreCalculator(agg)
        ed = ExecutiveDashboard(agg, sc)
        fr = FrameworkReport(agg, sc)

        dashboard = ed.generate(scan_results, request.csp, request.frameworks)
        framework_reports = {}
        fw_list = request.frameworks or [
            x.get("framework") for x in dashboard.get("frameworks", [])
            if isinstance(x, dict) and x.get("framework")
        ]
        for fw in fw_list:
            if fw:
                framework_reports[fw] = fr.generate(scan_results, request.csp, fw)

        report = {
            "report_id": report_id,
            "scan_id": scan_results.get("scan_id"),
            "csp": request.csp,
            "tenant_id": request.tenant_id,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "source": "threat_db",
            "executive_dashboard": dashboard,
            "framework_reports": framework_reports,
        }
        reports[report_id] = report

        for fw_data in dashboard.get("frameworks", []):
            if not isinstance(fw_data, dict):
                continue
            fw = fw_data.get("framework")
            score = fw_data.get("compliance_score", 0)
            if fw and scan_results.get("account_id"):
                trend_tracker.record_score(
                    csp=request.csp,
                    account_id=scan_results.get("account_id"),
                    framework=fw,
                    score=score,
                    scanned_at=scan_results.get("scanned_at"),
                )

        background_tasks.add_task(save_report_to_s3, report, request.csp)

        return {
            "report_id": report_id,
            "status": "completed",
            "compliance_report": report,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generating compliance report from Threat DB: {str(e)}",
        )


@app.get("/api/v1/compliance/report/{report_id}")
async def get_compliance_report(report_id: str):
    """Get compliance report by ID. Reads from DB first, then in-memory."""
    # DB-first lookup
    if DB_AVAILABLE:
        try:
            db_exp = DatabaseExporter()
            db_report = db_exp.get_report(report_id)
            if db_report is not None:
                db_report['report_id'] = report_id
                db_report['source'] = 'database'
                return db_report
        except Exception as db_err:
            logger.warning(f"DB get_report failed for {report_id}: {db_err}")

    # In-memory fallback
    if report_id not in reports:
        raise HTTPException(status_code=404, detail="Report not found")
    return reports[report_id]


@app.get("/api/v1/compliance/framework/{framework}/status")
async def get_framework_status(
    framework: str,
    scan_id: Optional[str] = Query(None),
    csp: Optional[str] = Query(None)
):
    """Get compliance status for a specific framework."""
    if not scan_id or not csp:
        raise HTTPException(
            status_code=400,
            detail="scan_id and csp query parameters are required"
        )
    
    try:
        scan_results = load_scan_results_from_s3(scan_id, csp)
        fw_report = framework_report.generate(scan_results, csp, framework)
        return fw_report
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generating framework report: {str(e)}"
        )


@app.get("/api/v1/compliance/resource/drilldown")
async def get_resource_drilldown(
    scan_id: str = Query(...),
    csp: str = Query(...),
    resource_id: Optional[str] = Query(None),
    service: Optional[str] = Query(None)
):
    """Get resource-level compliance drill-down."""
    try:
        scan_results = load_scan_results_from_s3(scan_id, csp)
        drilldown = resource_drilldown.generate(
            scan_results,
            csp,
            resource_id,
            service
        )
        return drilldown
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generating resource drill-down: {str(e)}"
        )


@app.post("/api/v1/scan")
async def generate_enterprise_report(
    request: GenerateEnterpriseReportRequest,
    background_tasks: BackgroundTasks
):
    """
    Run compliance scan and generate enterprise-grade compliance report (cspm_misconfig_report.v1).

    Features:
    - Deduplicated findings with stable IDs
    - Evidence stored by reference (S3)
    - Controls linked to findings
    - Asset snapshots
    - PostgreSQL export (optional)
    """
    report_id = str(uuid.uuid4())

    # Determine which check_scan_id to use and fetch metadata
    # Priority: direct scan_id > orchestration_id lookup > scan_run_id lookup
    check_query_scan_id = None
    csp = request.csp  # May be None
    tenant_id = request.tenant_id  # May be None

    if request.scan_id:
        # MODE 1: Direct scan_id provided (ad-hoc testing)
        check_query_scan_id = request.scan_id
        logger.info(f"Using direct check_scan_id: {check_query_scan_id}")
        # In ad-hoc mode, csp and tenant_id MUST be provided
        if not csp or not tenant_id:
            raise HTTPException(status_code=400, detail="In ad-hoc mode (using scan_id), both csp and tenant_id must be provided")
    elif request.orchestration_id or request.scan_run_id:
        # MODE 2: Orchestrated run - query scan_orchestration table for ALL metadata
        orchestration_id = request.orchestration_id or request.scan_run_id
        logger.info(f"Querying metadata for orchestration_id: {orchestration_id}")

        try:
            metadata = get_orchestration_metadata(orchestration_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

        check_query_scan_id = metadata.get("check_scan_id")
        if not check_query_scan_id:
            raise HTTPException(status_code=400, detail=f"No check_scan_id found in scan_orchestration for orchestration_id={orchestration_id}. Check engine may not have completed yet.")

        # Get metadata from orchestration table (override request params if provided)
        csp = metadata.get("provider_type", "aws").lower()  # aws, azure, gcp
        tenant_id = metadata.get("tenant_id")

        logger.info(f"Retrieved metadata: check_scan_id={check_query_scan_id}, csp={csp}, tenant_id={tenant_id}")
    else:
        raise HTTPException(status_code=400, detail="Either scan_id, scan_run_id, or orchestration_id must be provided")

    try:
        import asyncio
        from concurrent.futures import ThreadPoolExecutor
        from .schemas.enterprise_report_schema import (
            ScanContext, TriggerType, Cloud, CollectionMode
        )

        # Run all blocking I/O and CPU work in a thread so the event loop
        # remains free to serve liveness probes during a long scan.
        def _run_scan_blocking():
            # Load scan results from DATABASE using existing CheckDBLoader (NOT S3)
            logger.info(f"Querying check findings from database: check_scan_id={check_query_scan_id}, tenant_id={tenant_id}")

            loader = CheckDBLoader()
            try:
                scan_results = loader.load_and_convert(
                    scan_id=check_query_scan_id,
                    tenant_id=tenant_id,
                    csp=csp,
                    status_filter=None  # Get all findings
                )
            finally:
                loader.close()

            if not scan_results or not scan_results.get('results'):
                return None  # caller checks for None

            scan_run_id = check_query_scan_id
            scan_context = ScanContext(
                scan_run_id=scan_run_id,
                trigger_type=TriggerType(request.trigger_type),
                cloud=Cloud(csp),
                collection_mode=CollectionMode(request.collection_mode),
                started_at=scan_results.get('scanned_at', datetime.utcnow().isoformat() + 'Z'),
                completed_at=datetime.utcnow().isoformat() + 'Z'
            )

            s3_bucket = os.getenv("S3_BUCKET", "cspm-lgtech")
            reporter = EnterpriseReporter(tenant_id=tenant_id, s3_bucket=s3_bucket)
            enterprise_report = reporter.generate_report(
                scan_results=scan_results,
                scan_context=scan_context,
                tenant_name=request.tenant_name
            )
            return enterprise_report

        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as pool:
            enterprise_report = await loop.run_in_executor(pool, _run_scan_blocking)

        if enterprise_report is None:
            raise HTTPException(status_code=404, detail=f"No check findings found in database for check_scan_id={check_query_scan_id}")
        
        # Export to database if requested
        db_report_id = None
        if request.export_to_db and DB_AVAILABLE:
            try:
                db_exporter = DatabaseExporter()
                db_exporter.create_schema()  # Ensure schema exists
                db_report_id = db_exporter.export_report(enterprise_report)
                logger.info("Report exported to database", extra={
                    "extra_fields": {
                        "db_report_id": db_report_id,
                        "report_id": report_id
                    }
                })
            except Exception as e:
                # Log error but don't fail the request
                logger.warning("Database export failed", exc_info=True, extra={
                    "extra_fields": {
                        "error": str(e),
                        "report_id": report_id
                    }
                })

        # The canonical compliance_scan_id is the DB export ID (if written), else the report_id
        compliance_scan_id = db_report_id or report_id

        # Save to S3 in background (don't hold report in memory for response)
        background_tasks.add_task(
            save_enterprise_report_to_s3,
            enterprise_report,
            csp  # Use csp from metadata query, not request
        )

        # Update scan_orchestration with compliance_scan_id (if in pipeline mode)
        if request.orchestration_id or request.scan_run_id:
            try:
                import psycopg2 as _pg2
                _orch_conn = _pg2.connect(
                    host=os.getenv("ONBOARDING_DB_HOST", "localhost"),
                    port=int(os.getenv("ONBOARDING_DB_PORT", "5432")),
                    database=os.getenv("ONBOARDING_DB_NAME", "threat_engine_onboarding"),
                    user=os.getenv("ONBOARDING_DB_USER", "postgres"),
                    password=os.getenv("ONBOARDING_DB_PASSWORD", ""),
                    sslmode=os.getenv("DB_SSLMODE", "prefer"),
                )
                with _orch_conn:
                    with _orch_conn.cursor() as _cur:
                        _cur.execute(
                            "UPDATE scan_orchestration SET compliance_scan_id = %s WHERE orchestration_id = %s",
                            (compliance_scan_id, request.orchestration_id or request.scan_run_id)
                        )
                _orch_conn.close()
                logger.info(f"Updated scan_orchestration with compliance_scan_id: {compliance_scan_id}")
            except Exception as e:
                logger.error(f"Failed to update scan_orchestration: {e}")
                # Don't fail the request - this is tracking only

        posture = enterprise_report.posture_summary
        return {
            'report_id': compliance_scan_id,
            'status': 'completed',
            'scan_id': compliance_scan_id,
            'compliance_scan_id': compliance_scan_id,
            'total_findings': posture.total_findings,
            'total_controls': posture.total_controls,
            'controls_passed': posture.controls_passed,
            'controls_failed': posture.controls_failed,
            'findings_by_severity': posture.findings_by_severity,
            'frameworks': [f.framework_id for f in enterprise_report.frameworks],
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generating enterprise report: {str(e)}"
        )


def save_enterprise_report_to_s3(report: Any, csp: str) -> None:
    """Save enterprise compliance report to S3."""
    try:
        import boto3
        s3_bucket = os.getenv("S3_BUCKET", "cspm-lgtech")
        s3_client = boto3.client('s3')
        
        # Convert Pydantic model to dict if needed
        if hasattr(report, 'model_dump'):
            report_dict = report.model_dump()
            scan_run_id = report.scan_context.scan_run_id
            tenant_id = report.tenant.tenant_id
        else:
            report_dict = report
            scan_run_id = report_dict.get('scan_context', {}).get('scan_run_id', 'unknown')
            tenant_id = report_dict.get('tenant', {}).get('tenant_id', 'unknown')
        
        s3_base_path = f"compliance-engine/enterprise/{tenant_id}/{scan_run_id}"
        
        # Save JSON report
        json_exporter = JSONExporter()
        json_content = json_exporter.export(report_dict, pretty=True)
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=f"{s3_base_path}/report.json",
            Body=json_content.encode('utf-8'),
            ContentType='application/json'
        )
        
        print(f"Enterprise report saved to s3://{s3_bucket}/{s3_base_path}/report.json")
    except Exception as e:
        print(f"Error saving enterprise report to S3: {e}")


@app.get("/api/v1/compliance/report/{report_id}/export")
async def export_report(
    report_id: str,
    format: str = Query("json", regex="^(json|pdf|csv)$")
):
    """
    Export compliance report in various formats.
    
    Formats:
    - json: Full JSON report
    - pdf: Executive summary PDF
    - csv: Executive summary CSV
    """
    if report_id not in reports:
        raise HTTPException(status_code=404, detail="Report not found")
    
    report = reports[report_id]
    
    if format == "json":
        from fastapi.responses import JSONResponse
        return JSONResponse(content=report)
    
    elif format == "csv":
        from fastapi.responses import Response
        csv_exporter = CSVExporter()
        csv_content = csv_exporter.export_executive_summary(report.get('executive_dashboard', {}))
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=compliance_report_{report_id}.csv"}
        )
    
    elif format == "pdf":
        if not PDF_AVAILABLE:
            raise HTTPException(
                status_code=501,
                detail="PDF export not available. Install reportlab: pip install reportlab"
            )
        from fastapi.responses import Response
        pdf_exporter = PDFExporter()
        pdf_bytes = pdf_exporter.export_executive_summary(report.get('executive_dashboard', {}))
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=compliance_report_{report_id}.pdf"}
        )


@app.get("/api/v1/compliance/accounts/{account_id}")
async def get_account_compliance(
    account_id: str,
    scan_id: str = Query(...),
    csp: str = Query(...)
):
    """
    Get compliance status for a specific account across all frameworks.
    
    Returns account-level compliance summary with framework breakdown.
    """
    try:
        scan_results = load_scan_results_from_s3(scan_id, csp)
        
        # Filter results by account_id
        filtered_results = {
            'scan_id': scan_results.get('scan_id'),
            'csp': scan_results.get('csp'),
            'account_id': account_id,
            'scanned_at': scan_results.get('scanned_at'),
            'results': [
                r for r in scan_results.get('results', [])
                if r.get('account_id') == account_id
            ]
        }
        
        # Generate executive dashboard for this account
        dashboard = executive_dashboard.generate(
            filtered_results,
            csp,
            None  # All frameworks
        )
        
        # Generate framework reports
        framework_reports = {}
        frameworks_to_process = dashboard.get('frameworks', [])
        
        for fw_data in frameworks_to_process:
            if isinstance(fw_data, dict):
                framework = fw_data.get('framework')
            else:
                framework = fw_data
            
            if framework:
                fw_report = framework_report.generate(filtered_results, csp, framework)
                framework_reports[framework] = fw_report
        
        return {
            'account_id': account_id,
            'scan_id': scan_id,
            'csp': csp,
            'scanned_at': scan_results.get('scanned_at'),
            'overall_score': dashboard.get('summary', {}).get('overall_compliance_score', 0),
            'frameworks': framework_reports,
            'summary': dashboard.get('summary', {})
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generating account compliance: {str(e)}"
        )


@app.get("/api/v1/compliance/trends")
async def get_compliance_trends(
    csp: str = Query(...),
    account_id: Optional[str] = Query(None),
    framework: Optional[str] = Query(None),
    days: int = Query(30, ge=1, le=365)
):
    """
    Get historical compliance trends.
    
    Returns compliance scores over time for trend analysis.
    """
    try:
        if account_id and framework:
            # Get trends for specific account and framework
            trends = trend_tracker.get_trends(csp, account_id, framework, days)
            trend_direction = trend_tracker.calculate_trend_direction(csp, account_id, framework, days)
            
            return {
                'csp': csp,
                'account_id': account_id,
                'framework': framework,
                'days': days,
                'trends': trends,
                'trend_direction': trend_direction
            }
        else:
            # Return all trends (would need database in production)
            return {
                'csp': csp,
                'account_id': account_id,
                'framework': framework,
                'days': days,
                'message': 'Please specify both account_id and framework for trend data',
                'trends': []
            }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving trends: {str(e)}"
        )


@app.get("/api/v1/compliance/framework/{framework}/control/{control_id}")
async def get_control_detail(
    framework: str,
    control_id: str,
    scan_id: str = Query(...),
    csp: str = Query(...)
):
    """
    Get detailed information about a specific compliance control.
    
    Returns control status, affected resources, evidence, and remediation steps.
    """
    try:
        scan_results = load_scan_results_from_s3(scan_id, csp)
        fw_report = framework_report.generate(scan_results, csp, framework)
        
        # Find the specific control
        controls = fw_report.get('controls', [])
        control = None
        
        for c in controls:
            if c.get('control_id') == control_id:
                control = c
                break
        
        if not control:
            raise HTTPException(
                status_code=404,
                detail=f"Control {control_id} not found in framework {framework}"
            )
        
        # Get affected resources
        failed_checks = [c for c in control.get('checks', []) if c.get('check_result') == 'FAIL']
        passed_checks = [c for c in control.get('checks', []) if c.get('check_result') == 'PASS']
        
        return {
            'framework': framework,
            'control_id': control_id,
            'control_title': control.get('control_title'),
            'category': control.get('category'),
            'status': control.get('status'),
            'compliance_percentage': control.get('compliance_percentage', 0),
            'total_resources': len(control.get('checks', [])),
            'passed_resources': len(passed_checks),
            'failed_resources': len(failed_checks),
            'affected_resources': failed_checks,
            'evidence': [c.get('evidence', {}) for c in failed_checks],
            'checks': control.get('checks', [])
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving control detail: {str(e)}"
        )


@app.get("/api/v1/compliance/reports")
async def list_reports(
    tenant_id: Optional[str] = Query(None),
    csp: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """
    List generated compliance reports.

    Returns paginated list of reports with metadata. Reads from DB first,
    then merges any in-memory-only reports (e.g. generated this session but
    not yet flushed).
    """
    try:
        # --- DB-first: query compliance_report table ---
        if DB_AVAILABLE:
            try:
                db_exp = DatabaseExporter()
                result = db_exp.list_reports(tenant_id=tenant_id, csp=csp, limit=limit, offset=offset)
                return {
                    'total': result['total'],
                    'limit': limit,
                    'offset': offset,
                    'reports': result['reports'],
                    'source': 'database',
                }
            except Exception as db_err:
                logger.warning(f"DB list_reports failed, falling back to in-memory: {db_err}")

        # --- Fallback: in-memory dict ---
        filtered_reports = []
        for report_id, report in reports.items():
            if tenant_id:
                if isinstance(report, dict):
                    report_tenant = report.get('tenant', {}).get('tenant_id') if isinstance(report.get('tenant'), dict) else None
                    if report_tenant != tenant_id:
                        continue
            if csp:
                report_csp = report.get('csp') if isinstance(report, dict) else None
                if report_csp != csp:
                    continue
            filtered_reports.append({
                'report_id': report_id,
                'scan_id': report.get('scan_id') if isinstance(report, dict) else None,
                'csp': report.get('csp') if isinstance(report, dict) else None,
                'generated_at': report.get('generated_at') if isinstance(report, dict) else None,
                'tenant_id': report.get('tenant', {}).get('tenant_id') if isinstance(report, dict) and isinstance(report.get('tenant'), dict) else None,
            })
        filtered_reports.sort(key=lambda x: x.get('generated_at') or '', reverse=True)
        total = len(filtered_reports)
        paginated = filtered_reports[offset:offset + limit]
        return {
            'total': total,
            'limit': limit,
            'offset': offset,
            'reports': paginated,
            'source': 'memory',
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error listing reports: {str(e)}"
        )


@app.get("/api/v1/compliance/reports/{report_id}/status")
async def get_report_status(report_id: str):
    """
    Get generation status for a compliance report.

    Useful for async report generation.
    """
    # DB-first
    if DB_AVAILABLE:
        try:
            db_exp = DatabaseExporter()
            db_report = db_exp.get_report(report_id)
            if db_report is not None:
                return {
                    'report_id': report_id,
                    'status': 'completed',
                    'source': 'database',
                    'scan_id': db_report.get('scan_run_id'),
                    'csp': db_report.get('cloud'),
                    'generated_at': db_report.get('generated_at'),
                }
        except Exception as db_err:
            logger.warning(f"DB get_report_status failed for {report_id}: {db_err}")

    # In-memory fallback
    if report_id not in reports:
        raise HTTPException(status_code=404, detail="Report not found")
    report = reports[report_id]
    return {
        'report_id': report_id,
        'status': 'completed',
        'source': 'memory',
        'generated_at': report.get('generated_at') if isinstance(report, dict) else None,
        'scan_id': report.get('scan_id') if isinstance(report, dict) else None,
        'csp': report.get('csp') if isinstance(report, dict) else None,
    }


@app.delete("/api/v1/compliance/reports/{report_id}")
async def delete_report(report_id: str):
    """
    Delete a compliance report.
    
    Removes report from storage.
    """
    if report_id not in reports:
        raise HTTPException(status_code=404, detail="Report not found")
    
    del reports[report_id]
    
    return {
        'report_id': report_id,
        'status': 'deleted',
        'message': 'Report deleted successfully'
    }


@app.get("/api/v1/compliance/frameworks")
async def list_frameworks(
    csp: str = Query(...),
    scan_id: Optional[str] = Query(None)
):
    """
    List available compliance frameworks for a CSP.
    
    Returns list of frameworks that can be used for compliance reporting.
    If scan_id is provided, returns frameworks found in that scan.
    """
    try:
        if scan_id:
            # Get frameworks from actual scan results
            scan_results = load_scan_results_from_s3(scan_id, csp)
            frameworks = rule_mapper.get_frameworks_for_scan(scan_results, csp)
            
            return {
                'csp': csp,
                'scan_id': scan_id,
                'frameworks': frameworks,
                'source': 'scan_results'
            }
        else:
            # Return common frameworks (would need framework loader to list all)
            common_frameworks = [
                'CIS AWS Foundations Benchmark',
                'ISO 27001:2022',
                'NIST CSF 1.1',
                'PCI DSS 4.0',
                'HIPAA',
                'GDPR'
            ]
            
            return {
                'csp': csp,
                'frameworks': common_frameworks,
                'note': 'Using default framework list. Provide scan_id to get frameworks from actual scan results.'
            }
    except Exception as e:
        # Fallback to common frameworks on error
        common_frameworks = [
            'CIS AWS Foundations Benchmark',
            'ISO 27001:2022',
            'NIST CSF 1.1',
            'PCI DSS 4.0',
            'HIPAA',
            'GDPR'
        ]
        
        return {
            'csp': csp,
            'frameworks': common_frameworks,
            'note': 'Using default framework list',
            'error': str(e)
        }


@app.get("/api/v1/compliance/controls/search")
async def search_controls(
    query: str = Query(..., min_length=1),
    framework: Optional[str] = Query(None),
    csp: str = Query(...),
    scan_id: Optional[str] = Query(None)
):
    """
    Search for controls across frameworks.
    
    Searches control titles, IDs, and categories.
    """
    try:
        results = []
        
        if scan_id:
            # Search in actual scan results
            scan_results = load_scan_results_from_s3(scan_id, csp)
            
            frameworks_to_search = [framework] if framework else None
            framework_data = aggregator.aggregate_by_framework(scan_results, csp, frameworks_to_search)
            
            query_lower = query.lower()
            
            for fw_name, controls in framework_data.items():
                if framework and fw_name != framework:
                    continue
                
                for control_id, control_checks in controls.items():
                    # Search in control metadata (would need control titles from mapper)
                    if query_lower in control_id.lower():
                        results.append({
                            'framework': fw_name,
                            'control_id': control_id,
                            'matches': len(control_checks)
                        })
        else:
            # Search in framework definitions (would need framework loader)
            return {
                'query': query,
                'framework': framework,
                'csp': csp,
                'message': 'Please provide scan_id to search in actual scan results',
                'results': []
            }
        
        return {
            'query': query,
            'framework': framework,
            'csp': csp,
            'scan_id': scan_id,
            'total_results': len(results),
            'results': results
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error searching controls: {str(e)}"
        )


@app.get("/api/v1/compliance/framework/{framework}/detailed")
async def get_framework_report_detailed(
    framework: str,
    scan_id: str = Query(...),
    csp: str = Query(...)
):
    """Get framework report with detailed grouping (by control and by resource)."""
    try:
        scan_results = load_scan_results_from_s3(scan_id, csp)
        fw_report = framework_report.generate(scan_results, csp, framework)
        framework_data = aggregator.aggregate_by_framework(scan_results, csp, [framework])
        
        fw_report['grouped_by_control'] = group_by_control(framework_data, framework)
        fw_report['grouped_by_resource'] = group_by_resource(framework_data, framework)
        
        fw_report['grouping_summary'] = {
            'total_controls': len(fw_report['grouped_by_control']),
            'total_resources': len(fw_report['grouped_by_resource']),
            'controls_with_failures': sum(1 for c in fw_report['grouped_by_control'].values() 
                                          if c['statistics']['failed'] > 0),
            'resources_with_failures': sum(1 for r in fw_report['grouped_by_resource'].values() 
                                          if r['compliance_summary']['failed'] > 0)
        }
        return fw_report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating detailed report: {str(e)}")


@app.get("/api/v1/compliance/framework/{framework}/controls/grouped")
async def get_controls_grouped(
    framework: str,
    scan_id: str = Query(...),
    csp: str = Query(...)
):
    """Get controls grouped by control ID."""
    try:
        scan_results = load_scan_results_from_s3(scan_id, csp)
        framework_data = aggregator.aggregate_by_framework(scan_results, csp, [framework])
        grouped = group_by_control(framework_data, framework)
        return {
            'framework': framework,
            'scan_id': scan_id,
            'csp': csp,
            'grouped_by_control': grouped,
            'total_controls': len(grouped)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error grouping controls: {str(e)}")


@app.get("/api/v1/compliance/framework/{framework}/resources/grouped")
async def get_resources_grouped(
    framework: str,
    scan_id: str = Query(...),
    csp: str = Query(...)
):
    """Get resources grouped by resource."""
    try:
        scan_results = load_scan_results_from_s3(scan_id, csp)
        framework_data = aggregator.aggregate_by_framework(scan_results, csp, [framework])
        grouped = group_by_resource(framework_data, framework)
        return {
            'framework': framework,
            'scan_id': scan_id,
            'csp': csp,
            'grouped_by_resource': grouped,
            'total_resources': len(grouped)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error grouping resources: {str(e)}")


@app.get("/api/v1/compliance/frameworks/all")
async def list_all_frameworks(csp: str = Query(...)):
    """List all available frameworks from consolidated CSV."""
    try:
        csv_loader = ConsolidatedCSVLoader()
        frameworks = csv_loader.get_frameworks_list()
        return {
            'csp': csp,
            'frameworks': frameworks,
            'total': len(frameworks),
            'source': 'consolidated_csv'
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing frameworks: {str(e)}")


@app.get("/api/v1/compliance/framework/{framework}/structure")
async def get_framework_structure(
    framework: str,
    csp: str = Query(...)
):
    """Get framework structure from consolidated CSV."""
    try:
        csv_loader = ConsolidatedCSVLoader()
        structure = csv_loader.get_framework_structure(framework)
        if not structure:
            raise HTTPException(status_code=404, detail=f"Framework structure not found: {framework}")
        return {
            'framework': framework,
            'csp': csp,
            'structure': structure
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting framework structure: {str(e)}")


@app.post("/api/v1/compliance/mock/generate")
async def generate_mock_data(
    account_id: str = Query("123456789012"),
    num_resources: int = Query(20, ge=1, le=1000),
    pass_rate: float = Query(0.6, ge=0.0, le=1.0)
):
    """Generate mock scan results for testing."""
    try:
        from pathlib import Path
        
        generator = ComplianceMockDataGenerator()
        mock_data = generator.generate_scan_results(
            account_id=account_id,
            num_resources=num_resources,
            pass_rate=pass_rate
        )
        
        # Save mock data to expected location so other endpoints can find it
        scan_id = mock_data['scan_id']
        csp = mock_data.get('csp', 'aws')
        
        from pathlib import Path
        root = get_project_root()
        configscan_folder = f"engine_configscan_{csp}"
        engines_output_dir = root / "engine_output" / configscan_folder / "output" / scan_id
        engines_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Also try to save to OUTPUT_DIR if it's writable (for container environments)
        output_dir_env = os.getenv("OUTPUT_DIR", "/output")
        output_dir = None
        if output_dir_env and output_dir_env != "/output":  # Avoid read-only /output
            if output_dir_env.startswith('/'):
                output_dir = Path(output_dir_env) / scan_id
            else:
                output_dir = root / output_dir_env / scan_id
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
            except (PermissionError, OSError):
                output_dir = None  # Skip if not writable
        
        # Save results.ndjson (NDJSON format - one JSON per line)
        # Save to both locations for compatibility (if output_dir is writable)
        save_dirs = [engines_output_dir]
        if output_dir:
            save_dirs.append(output_dir)
        
        for save_dir in save_dirs:
            results_file = save_dir / "results.ndjson"
            with open(results_file, 'w', encoding='utf-8') as f:
                for result in mock_data['results']:
                    # Convert to NDJSON format expected by load_scan_results_from_s3
                    ndjson_entry = {
                        'account_id': result.get('account_id'),
                        'region': result.get('region'),
                        'service': result.get('service'),
                        'checks': result.get('checks', [])
                    }
                    f.write(json.dumps(ndjson_entry) + '\n')
            
            # Save summary.json
            summary_file = save_dir / "summary.json"
            summary = {
                'scan_id': scan_id,
                'csp': csp,
                'account_id': account_id,
                'scanned_at': mock_data.get('scanned_at'),
                'total_resources': num_resources,
                'total_checks': sum(len(r.get('checks', [])) for r in mock_data['results'])
            }
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2)
        
        return {
            'status': 'success',
            'scan_id': scan_id,
            'mock_data': mock_data,
            'saved_to': str(output_dir),
            'parameters': {
                'account_id': account_id,
                'num_resources': num_resources,
                'pass_rate': pass_rate
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating mock data: {str(e)}")


@app.post("/api/v1/compliance/generate/detailed")
async def generate_detailed_reports(
    scan_id: str = Query(...),
    csp: str = Query(...),
    save_separate_files: bool = Query(True),
    background_tasks: BackgroundTasks = None
):
    """Generate detailed compliance reports with separate files per framework."""
    try:
        from pathlib import Path
        scan_results = load_scan_results_from_s3(scan_id, csp)
        root = get_project_root()
        output_base = root / "engine_output" / "engine_compliance" / "output"
        scan_output_dir = output_base / scan_id
        scan_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate executive summary
        dashboard = executive_dashboard.generate(scan_results, csp, None)
        summary_file = scan_output_dir / "executive_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(dashboard, f, indent=2)
        
        # Generate framework reports
        framework_data = aggregator.aggregate_by_framework(scan_results, csp, None)
        frameworks_detected = list(framework_data.keys())
        
        framework_files = {}
        for framework in frameworks_detected:
            fw_report = framework_report.generate(scan_results, csp, framework)
            fw_report['grouped_by_control'] = group_by_control(framework_data, framework)
            fw_report['grouped_by_resource'] = group_by_resource(framework_data, framework)
            
            safe_framework_name = framework.replace(" ", "_").replace("/", "_").replace("\\", "_")
            framework_file = scan_output_dir / f"{safe_framework_name}_compliance_report.json"
            with open(framework_file, 'w') as f:
                json.dump(fw_report, f, indent=2)
            framework_files[framework] = str(framework_file.name)
        
        # Create index
        index_data = {
            'scan_id': scan_id,
            'csp': csp,
            'account_id': scan_results.get('account_id'),
            'scanned_at': scan_results.get('scanned_at'),
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'output_directory': str(scan_output_dir),
            'executive_summary': 'executive_summary.json',
            'frameworks': {
                fw: {
                    'file': Path(f).name,
                    'compliance_score': framework_report.generate(scan_results, csp, fw).get('compliance_score', 0)
                }
                for fw, f in framework_files.items()
            },
            'summary': dashboard.get('summary', {})
        }
        index_file = scan_output_dir / "index.json"
        with open(index_file, 'w') as f:
            json.dump(index_data, f, indent=2)
        
        return {
            'status': 'completed',
            'scan_id': scan_id,
            'output_directory': str(scan_output_dir),
            'index_file': str(index_file.name),
            'executive_summary': 'executive_summary.json',
            'framework_files': framework_files,
            'total_frameworks': len(framework_files)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating detailed reports: {str(e)}")


@app.get("/api/v1/compliance/framework/{framework}/download/pdf")
async def download_framework_pdf(
    framework: str,
    scan_id: str = Query(...),
    csp: str = Query(...)
):
    """Download framework report as PDF."""
    try:
        if not PDF_AVAILABLE:
            raise HTTPException(status_code=501, detail="PDF export not available. Install reportlab: pip install reportlab")
        
        from fastapi.responses import Response
        
        scan_results = load_scan_results_from_s3(scan_id, csp)
        fw_report = framework_report.generate(scan_results, csp, framework)
        framework_data = aggregator.aggregate_by_framework(scan_results, csp, [framework])
        fw_report['grouped_by_control'] = group_by_control(framework_data, framework)
        fw_report['grouped_by_resource'] = group_by_resource(framework_data, framework)
        
        pdf_exporter = PDFExporter()
        pdf_bytes = pdf_exporter.export_executive_summary(fw_report)
        
        safe_framework_name = framework.replace(" ", "_").replace("/", "_")
        filename = f"{safe_framework_name}_compliance_report_{scan_id}.pdf"
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating PDF: {str(e)}")


@app.get("/api/v1/compliance/framework/{framework}/download/excel")
async def download_framework_excel(
    framework: str,
    scan_id: str = Query(...),
    csp: str = Query(...)
):
    """Download framework report as Excel (XLSX)."""
    try:
        if not EXCEL_AVAILABLE:
            raise HTTPException(status_code=501, detail="Excel export not available. Install openpyxl: pip install openpyxl")
        
        from fastapi.responses import Response
        
        scan_results = load_scan_results_from_s3(scan_id, csp)
        fw_report = framework_report.generate(scan_results, csp, framework)
        framework_data = aggregator.aggregate_by_framework(scan_results, csp, [framework])
        fw_report['grouped_by_control'] = group_by_control(framework_data, framework)
        fw_report['grouped_by_resource'] = group_by_resource(framework_data, framework)
        
        excel_exporter = ExcelExporter()
        excel_bytes = excel_exporter.export_framework_report(fw_report)
        
        safe_framework_name = framework.replace(" ", "_").replace("/", "_")
        filename = f"{safe_framework_name}_compliance_report_{scan_id}.xlsx"
        
        return Response(
            content=excel_bytes,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating Excel: {str(e)}")


@app.get("/api/v1/compliance/report/{report_id}/download/pdf")
async def download_report_pdf(report_id: str):
    """Download full compliance report as PDF."""
    if report_id not in reports:
        raise HTTPException(status_code=404, detail="Report not found")
    if not PDF_AVAILABLE:
        raise HTTPException(status_code=501, detail="PDF export not available. Install reportlab: pip install reportlab")
    
    from fastapi.responses import Response
    
    report = reports[report_id]
    pdf_exporter = PDFExporter()
    pdf_bytes = pdf_exporter.export_executive_summary(report.get('executive_dashboard', {}))
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=compliance_report_{report_id}.pdf"}
    )


@app.get("/api/v1/compliance/report/{report_id}/download/excel")
async def download_report_excel(report_id: str):
    """Download full compliance report as Excel."""
    if report_id not in reports:
        raise HTTPException(status_code=404, detail="Report not found")
    if not EXCEL_AVAILABLE:
        raise HTTPException(status_code=501, detail="Excel export not available. Install openpyxl: pip install openpyxl")
    
    from fastapi.responses import Response
    
    report = reports[report_id]
    excel_exporter = ExcelExporter()
    excel_bytes = excel_exporter.export_executive_summary(report.get('executive_dashboard', {}))
    
    return Response(
        content=excel_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename=compliance_report_{report_id}.xlsx"}
    )


@app.get("/health")
async def simple_health():
    """Simple health check — no DB (for LB target-group checks)."""
    return {"status": "ok"}


@app.get("/api/v1/health/live")
async def liveness():
    """Kubernetes liveness probe — returns 200 if process is alive."""
    return {"status": "alive"}


@app.get("/api/v1/health/ready")
async def readiness():
    """Kubernetes readiness probe — DB ping."""
    try:
        conn = psycopg2.connect(
            host=os.getenv("COMPLIANCE_DB_HOST", "localhost"),
            port=int(os.getenv("COMPLIANCE_DB_PORT", "5432")),
            dbname=os.getenv("COMPLIANCE_DB_NAME", "compliance"),
            user=os.getenv("COMPLIANCE_DB_USER", "postgres"),
            password=os.getenv("COMPLIANCE_DB_PASSWORD", ""),
            connect_timeout=3,
        )
        conn.close()
        return {"status": "ready"}
    except Exception as e:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content={"status": "not ready", "error": str(e)})


@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    import time
    start = time.time()

    health_status = {
        "status": "healthy",
        "service": "engine-compliance",
        "version": "1.0.0"
    }

    duration_ms = (time.time() - start) * 1000
    logger.info("Health check", extra={
        "extra_fields": {
            "status": "healthy",
            "duration_ms": duration_ms
        }
    })

    return health_status


# ============================================================================
# NEW DB-DRIVEN ENDPOINTS FOR UI
# ============================================================================

@app.get("/api/v1/compliance/dashboard")
async def get_compliance_dashboard(
    tenant_id: str = Query(...),
    scan_id: Optional[str] = Query("latest")
):
    """
    Executive compliance dashboard - all frameworks summary.
    
    Uses: compliance_control_detail VIEW + resource_compliance_status
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        host = os.getenv("COMPLIANCE_DB_HOST", "localhost")
        port = os.getenv("COMPLIANCE_DB_PORT", "5432")
        db = os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance")
        user = os.getenv("COMPLIANCE_DB_USER", "compliance_user")
        pwd = os.getenv("COMPLIANCE_DB_PASSWORD", "compliance_password")
        conn_str = f"postgresql://{user}:{pwd}@{host}:{port}/{db}"
        
        conn = psycopg2.connect(conn_str)
        
        # Get framework summary
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    compliance_framework,
                    COUNT(*) as total_controls,
                    SUM(CASE WHEN avg_compliance_score >= 80 THEN 1 ELSE 0 END) as passed_controls,
                    SUM(CASE WHEN avg_compliance_score < 50 THEN 1 ELSE 0 END) as failed_controls,
                    SUM(CASE WHEN avg_compliance_score >= 50 AND avg_compliance_score < 80 THEN 1 ELSE 0 END) as partial_controls,
                    ROUND(AVG(avg_compliance_score), 2) as framework_score
                FROM compliance_control_detail
                GROUP BY compliance_framework
                ORDER BY framework_score DESC
            """)
            frameworks = [dict(row) for row in cur.fetchall()]
        
        # Calculate overall metrics
        total_frameworks = len(frameworks)
        passing_frameworks = sum(1 for f in frameworks if f['framework_score'] >= 80)
        partial_frameworks = sum(1 for f in frameworks if 50 <= f['framework_score'] < 80)
        failing_frameworks = sum(1 for f in frameworks if f['framework_score'] < 50)
        
        overall_score = sum(f['framework_score'] for f in frameworks) / total_frameworks if total_frameworks > 0 else 0
        
        conn.close()
        
        return {
            "scan_id": scan_id,
            "tenant_id": tenant_id,
            "overall_score": round(overall_score, 2),
            "frameworks": {
                "total": total_frameworks,
                "passing": passing_frameworks,
                "partial": partial_frameworks,
                "failing": failing_frameworks
            },
            "framework_scores": frameworks
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard: {str(e)}")


@app.get("/api/v1/compliance/framework-detail/{framework}")
async def get_framework_detail(
    framework: str,
    tenant_id: str = Query(...),
    scan_id: Optional[str] = Query("latest")
):
    """
    Detailed framework compliance view.
    
    Uses: compliance_control_detail VIEW
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        host = os.getenv("COMPLIANCE_DB_HOST", "localhost")
        port = os.getenv("COMPLIANCE_DB_PORT", "5432")
        db = os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance")
        user = os.getenv("COMPLIANCE_DB_USER", "compliance_user")
        pwd = os.getenv("COMPLIANCE_DB_PASSWORD", "compliance_password")
        conn_str = f"postgresql://{user}:{pwd}@{host}:{port}/{db}"
        
        conn = psycopg2.connect(conn_str)
        
        # Get all controls for this framework
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    control_id,
                    control_description,
                    resources_checked,
                    total_checks,
                    total_passed,
                    total_failed,
                    avg_compliance_score as compliance_score,
                    CASE 
                        WHEN avg_compliance_score >= 80 THEN 'PASS'
                        WHEN avg_compliance_score >= 50 THEN 'PARTIAL'
                        ELSE 'FAIL'
                    END as status,
                    mapped_rule_ids,
                    failed_resources,
                    passed_resources
                FROM compliance_control_detail
                WHERE compliance_framework = %s
                ORDER BY control_id
            """, (framework,))
            controls = [dict(row) for row in cur.fetchall()]
        
        conn.close()
        
        # Calculate summary
        total_controls = len(controls)
        passed = sum(1 for c in controls if c['status'] == 'PASS')
        failed = sum(1 for c in controls if c['status'] == 'FAIL')
        partial = sum(1 for c in controls if c['status'] == 'PARTIAL')
        avg_score = sum(c['compliance_score'] for c in controls) / total_controls if total_controls > 0 else 0
        
        return {
            "framework": framework,
            "scan_id": scan_id,
            "tenant_id": tenant_id,
            "summary": {
                "total_controls": total_controls,
                "passed_controls": passed,
                "failed_controls": failed,
                "partial_controls": partial,
                "framework_score": round(avg_score, 2)
            },
            "controls": controls
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get framework detail: {str(e)}")


@app.get("/api/v1/compliance/control-detail/{framework}/{control_id}")
async def get_control_detail_by_tenant(
    framework: str,
    control_id: str,
    tenant_id: str = Query(...),
    scan_id: Optional[str] = Query("latest")
):
    """
    Detailed control view with affected resources (tenant-scoped, DB-backed).

    Uses: compliance_control_detail + resource_compliance_status
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        host = os.getenv("COMPLIANCE_DB_HOST", "localhost")
        port = os.getenv("COMPLIANCE_DB_PORT", "5432")
        db = os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance")
        user = os.getenv("COMPLIANCE_DB_USER", "compliance_user")
        pwd = os.getenv("COMPLIANCE_DB_PASSWORD", "compliance_password")
        conn_str = f"postgresql://{user}:{pwd}@{host}:{port}/{db}"
        
        conn = psycopg2.connect(conn_str)
        
        # Get control summary
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM compliance_control_detail
                WHERE compliance_framework = %s AND control_id = %s
            """, (framework, control_id))
            control = cur.fetchone()
        
        if not control:
            raise HTTPException(status_code=404, detail="Control not found")
        
        # Get detailed resource status
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    resource_uid,
                    resource_type,
                    account_id,
                    total_checks,
                    passed_checks,
                    failed_checks,
                    compliance_score
                FROM resource_compliance_status
                WHERE compliance_framework = %s 
                  AND requirement_id = %s
                ORDER BY failed_checks DESC, resource_uid
            """, (framework, control_id))
            resources = [dict(row) for row in cur.fetchall()]
        
        conn.close()
        
        return {
            **dict(control),
            "affected_resources": resources,
            "failed_resource_count": len([r for r in resources if r['failed_checks'] > 0]),
            "passed_resource_count": len([r for r in resources if r['failed_checks'] == 0])
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get control detail: {str(e)}")


@app.get("/api/v1/compliance/resource/{resource_uid:path}/compliance")
async def get_resource_compliance(
    resource_uid: str,
    tenant_id: str = Query(...)
):
    """
    Show all compliance frameworks/controls applicable to a specific resource.
    
    Uses: resource_compliance_status
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        host = os.getenv("COMPLIANCE_DB_HOST", "localhost")
        port = os.getenv("COMPLIANCE_DB_PORT", "5432")
        db = os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance")
        user = os.getenv("COMPLIANCE_DB_USER", "compliance_user")
        pwd = os.getenv("COMPLIANCE_DB_PASSWORD", "compliance_password")
        conn_str = f"postgresql://{user}:{pwd}@{host}:{port}/{db}"
        
        conn = psycopg2.connect(conn_str)
        
        # Get all compliance controls for this resource
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    compliance_framework,
                    requirement_id as control_id,
                    requirement_name as control_name,
                    total_checks,
                    passed_checks,
                    failed_checks,
                    compliance_score
                FROM resource_compliance_status
                WHERE resource_uid = %s
                ORDER BY compliance_framework, requirement_id
            """, (resource_uid,))
            controls = [dict(row) for row in cur.fetchall()]
        
        conn.close()
        
        if not controls:
            raise HTTPException(status_code=404, detail="Resource not found or no compliance data")
        
        # Group by framework
        by_framework = {}
        for c in controls:
            fw = c['compliance_framework']
            if fw not in by_framework:
                by_framework[fw] = []
            by_framework[fw].append(c)
        
        # Calculate framework summaries
        framework_summaries = []
        for fw, fw_controls in by_framework.items():
            total = len(fw_controls)
            passed = sum(1 for c in fw_controls if c['failed_checks'] == 0)
            failed = sum(1 for c in fw_controls if c['failed_checks'] > 0)
            avg_score = sum(c['compliance_score'] for c in fw_controls) / total if total > 0 else 0
            
            framework_summaries.append({
                "framework": fw,
                "total_controls": total,
                "passed_controls": passed,
                "failed_controls": failed,
                "compliance_score": round(avg_score, 2)
            })
        
        return {
            "resource_uid": resource_uid,
            "frameworks_applicable": len(by_framework),
            "total_controls_applicable": len(controls),
            "framework_summaries": framework_summaries,
            "controls": controls
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get resource compliance: {str(e)}")


# Include unified UI data router
try:
    from .api.ui_data_router import router as ui_data_router
    app.include_router(ui_data_router)
except ImportError as e:
    logger.warning("UI data router not available", extra={"extra_fields": {"error": str(e)}})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

