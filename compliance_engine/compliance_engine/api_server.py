"""
Compliance Engine API Server

FastAPI server for generating compliance reports from CSP scan results.
"""

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
import json
import os
from datetime import datetime

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


class GenerateReportRequest(BaseModel):
    """Request to generate compliance report."""
    scan_id: str
    csp: str  # aws, azure, gcp, alicloud, oci, ibm
    frameworks: Optional[List[str]] = None  # Optional: filter specific frameworks


class GenerateEnterpriseReportRequest(BaseModel):
    """Request to generate enterprise-grade compliance report."""
    scan_id: str
    csp: str  # aws, azure, gcp, alicloud, oci, ibm
    tenant_id: str
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
                print(f"Warning: Could not generate PDF: {e}")
        
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
                    print(f"Warning: Could not generate PDF for {framework}: {e}")
        
        print(f"Report saved to S3: s3://{s3_bucket}/{s3_base_path}/")
    
    except Exception as e:
        print(f"Error saving report to S3: {e}")


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
    engines-output/{csp}-configScan-engine/output/{scan_id}/results.ndjson
    engines-output/{csp}-configScan-engine/output/{scan_id}/summary.json
    
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
                    except:
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
        print(f"Error loading from S3: {e}")
    
    # Fallback: try local file system
    # Try local engines-output directory (matches workspace structure)
    workspace_root = os.getenv("WORKSPACE_ROOT", "/Users/apple/Desktop/threat-engine")
    
    # Try configScan-engine path first (where scan engines save results)
    configscan_path = os.path.join(workspace_root, "engines-output", f"{csp}-configScan-engine", "output", scan_id, "results.ndjson")
    if os.path.exists(configscan_path):
        local_path = configscan_path
    else:
        # Try compliance-engine path (alternative structure)
        csp_s3_path = get_csp_s3_path(csp)
        local_base = csp_s3_path.replace("-configScan-engine/output", "-configScan-engine/output")
        local_path = os.path.join(workspace_root, "engines-output", local_base.replace("-configScan-engine/output", ""), "output", scan_id, "results.ndjson")
        
        # Also try OUTPUT_DIR if set (for container environments)
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
                except:
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
    report_id = str(uuid.uuid4())
    
    try:
        # Load scan results
        scan_results = load_scan_results_from_s3(request.scan_id, request.csp)
        
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
            'scan_id': request.scan_id,
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


@app.get("/api/v1/compliance/report/{report_id}")
async def get_compliance_report(report_id: str):
    """Get compliance report by ID."""
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


@app.post("/api/v1/compliance/generate/enterprise")
async def generate_enterprise_report(
    request: GenerateEnterpriseReportRequest,
    background_tasks: BackgroundTasks
):
    """
    Generate enterprise-grade compliance report (cspm_misconfig_report.v1).
    
    Features:
    - Deduplicated findings with stable IDs
    - Evidence stored by reference (S3)
    - Controls linked to findings
    - Asset snapshots
    - PostgreSQL export (optional)
    """
    report_id = str(uuid.uuid4())
    
    try:
        # Load scan results
        scan_results = load_scan_results_from_s3(request.scan_id, request.csp)
        
        # Create scan context
        from .schemas.enterprise_report_schema import (
            ScanContext, TriggerType, Cloud, CollectionMode
        )
        
        scan_run_id = request.scan_id  # Use scan_id as scan_run_id
        trigger_type = TriggerType(request.trigger_type)
        cloud = Cloud(request.csp)
        collection_mode = CollectionMode(request.collection_mode)
        
        # Get timestamps from scan results if available
        started_at = scan_results.get('scanned_at', datetime.utcnow().isoformat() + 'Z')
        completed_at = datetime.utcnow().isoformat() + 'Z'
        
        scan_context = ScanContext(
            scan_run_id=scan_run_id,
            trigger_type=trigger_type,
            cloud=cloud,
            collection_mode=collection_mode,
            started_at=started_at,
            completed_at=completed_at
        )
        
        # Generate enterprise report
        s3_bucket = os.getenv("S3_BUCKET", "cspm-lgtech")
        reporter = EnterpriseReporter(
            tenant_id=request.tenant_id,
            s3_bucket=s3_bucket
        )
        
        enterprise_report = reporter.generate_report(
            scan_results=scan_results,
            scan_context=scan_context,
            tenant_name=request.tenant_name
        )
        
        # Export to database if requested
        if request.export_to_db and DB_AVAILABLE:
            try:
                db_exporter = DatabaseExporter()
                db_exporter.create_schema()  # Ensure schema exists
                db_report_id = db_exporter.export_report(enterprise_report)
                background_tasks.add_task(
                    lambda: print(f"Report exported to database: {db_report_id}")
                )
            except Exception as e:
                # Log error but don't fail the request
                print(f"Warning: Database export failed: {e}")
        
        # Save to S3 in background
        background_tasks.add_task(
            save_enterprise_report_to_s3,
            enterprise_report,
            request.csp
        )
        
        # Store in memory (for API retrieval)
        reports[report_id] = enterprise_report.model_dump()
        
        return {
            'report_id': report_id,
            'status': 'completed',
            'enterprise_report': enterprise_report.model_dump()
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
    
    Returns paginated list of reports with metadata.
    """
    try:
        # Filter reports
        filtered_reports = []
        
        for report_id, report in reports.items():
            # Filter by tenant_id if provided (for enterprise reports)
            if tenant_id:
                if isinstance(report, dict):
                    report_tenant = report.get('tenant', {}).get('tenant_id') if isinstance(report.get('tenant'), dict) else None
                    if report_tenant != tenant_id:
                        continue
            
            # Filter by csp if provided
            if csp:
                report_csp = report.get('csp') if isinstance(report, dict) else None
                if report_csp != csp:
                    continue
            
            filtered_reports.append({
                'report_id': report_id,
                'scan_id': report.get('scan_id') if isinstance(report, dict) else None,
                'csp': report.get('csp') if isinstance(report, dict) else None,
                'generated_at': report.get('generated_at') if isinstance(report, dict) else None,
                'tenant_id': report.get('tenant', {}).get('tenant_id') if isinstance(report, dict) and isinstance(report.get('tenant'), dict) else None
            })
        
        # Sort by generated_at descending
        filtered_reports.sort(key=lambda x: x.get('generated_at') or '', reverse=True)
        
        # Paginate
        total = len(filtered_reports)
        paginated = filtered_reports[offset:offset + limit]
        
        return {
            'total': total,
            'limit': limit,
            'offset': offset,
            'reports': paginated
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
    if report_id not in reports:
        raise HTTPException(status_code=404, detail="Report not found")
    
    report = reports[report_id]
    
    return {
        'report_id': report_id,
        'status': 'completed',  # In-memory reports are always completed
        'generated_at': report.get('generated_at') if isinstance(report, dict) else None,
        'scan_id': report.get('scan_id') if isinstance(report, dict) else None,
        'csp': report.get('csp') if isinstance(report, dict) else None
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
        
        # Determine output path (matching load_scan_results_from_s3 logic)
        workspace_root = Path(os.getenv("WORKSPACE_ROOT", "/Users/apple/Desktop/threat-engine"))
        
        # Save to engines-output directory (writable location)
        engines_output_dir = workspace_root / "engines-output" / f"{csp}-configScan-engine" / "output" / scan_id
        engines_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Also try to save to OUTPUT_DIR if it's writable (for container environments)
        output_dir_env = os.getenv("OUTPUT_DIR", "/output")
        output_dir = None
        if output_dir_env and output_dir_env != "/output":  # Avoid read-only /output
            if output_dir_env.startswith('/'):
                output_dir = Path(output_dir_env) / scan_id
            else:
                output_dir = workspace_root / output_dir_env / scan_id
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
        
        # Create output directory
        workspace_root = Path("/Users/apple/Desktop/threat-engine")
        output_base = workspace_root / "engines-output" / "complaince-engine" / "output"
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


@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "compliance-engine",
        "version": "1.0.0"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

