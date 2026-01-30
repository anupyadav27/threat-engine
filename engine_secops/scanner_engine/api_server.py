"""
FastAPI server for vulnerability scanning - Docker + Jenkins ready
Input folder: /app/scan_input - Jenkins clones repos here
Output folder: /app/scan_output - Scan results stored here
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import json
from typing import Optional
from datetime import datetime
from scan_local import scan_path
from scanner_plugin import get_supported_languages

# Folders for input (git repos) and output (results)
INPUT_FOLDER = os.getenv("SCAN_INPUT_PATH", "/app/scan_input")
OUTPUT_FOLDER = os.getenv("SCAN_OUTPUT_PATH", "/app/scan_output")

# Ensure folders exist
os.makedirs(INPUT_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Initialize FastAPI
app = FastAPI(
    title="SecOps Vulnerability Scanner API",
    description="Multi-language security scanner supporting: Python, Java, C#, JavaScript, Terraform, Azure ARM, CloudFormation, Docker, Kubernetes, Ansible",
    version="2.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============= Models =============
class ScanRequest(BaseModel):
    project_name: str  # Name of project (folder name in scan_input)
    save_results: Optional[bool] = True
    fail_on_findings: Optional[bool] = False
    scan_id: Optional[str] = None   # Unified scan ID (persist to engine_secops when set with tenant_id)
    customer_id: Optional[str] = None
    tenant_id: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    input_folder: str
    output_folder: str
    supported_languages: list

# ============= Endpoints =============

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "input_folder": INPUT_FOLDER,
        "output_folder": OUTPUT_FOLDER,
        "supported_languages": list(get_supported_languages())
    }

@app.post("/scan")
async def scan_project(request: ScanRequest):
    """
    Scan a project from the input folder
    
    Request:
    {
        "project_name": "my-repo",  // folder name in scan_input
        "save_results": true,        // save to scan_output
        "fail_on_findings": false    // return error if vulnerabilities found
    }
    
    Jenkins workflow:
    1. Jenkins clones repo to scan_input/{project_name}
    2. Jenkins calls this API with project_name
    3. Scanner scans scan_input/{project_name}
    4. Results saved to scan_output/{project_name}/scan_results.json
    5. Jenkins reads results from scan_output
    """
    
    project_name = request.project_name.strip()
    if not project_name:
        raise HTTPException(status_code=400, detail="project_name is required")
    
    # Security: prevent path traversal
    if ".." in project_name or "/" in project_name or "\\" in project_name:
        raise HTTPException(status_code=400, detail="Invalid project_name")
    
    # Build input path
    input_path = os.path.join(INPUT_FOLDER, project_name)
    
    # Validate input exists
    if not os.path.exists(input_path):
        raise HTTPException(
            status_code=404, 
            detail=f"Project not found in input folder: {project_name}. "
                   f"Expected path: {input_path}"
        )
    
    try:
        started_at = datetime.utcnow()
        print(f"[SCAN] Starting scan for: {input_path}")
        scan_result = scan_path(input_path)

        total_files = len(scan_result.get("results", []))
        total_findings = sum(
            len(r.get("findings", [])) for r in scan_result.get("results", [])
        )
        total_errors = len(scan_result.get("errors", []))

        response = {
            "success": True,
            "project_name": project_name,
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "files_scanned": total_files,
                "total_findings": total_findings,
                "total_errors": total_errors,
            },
            "scan_data": scan_result,
        }

        # Persist to engine_secops when DATABASE_URL + tenant_id (and optionally scan_id) provided
        if os.getenv("DATABASE_URL") and request.tenant_id:
            try:
                from secops_db import persist_scan, persist_findings
                scan_id = request.scan_id or f"secops-{project_name}-{started_at.strftime('%Y%m%d%H%M%S')}"
                completed_at = datetime.utcnow()
                persist_scan(
                    scan_id=scan_id,
                    tenant_id=request.tenant_id,
                    project_name=project_name,
                    status="completed" if total_errors == 0 else "completed_with_errors",
                    started_at=started_at,
                    completed_at=completed_at,
                    customer_id=request.customer_id,
                    metadata={"total_findings": total_findings, "total_files": total_files},
                )
                n = persist_findings(
                    scan_id=scan_id,
                    tenant_id=request.tenant_id,
                    project_name=project_name,
                    results=scan_result.get("results", []),
                    customer_id=request.customer_id,
                )
                response["scan_id"] = scan_id
                response["db_findings_stored"] = n
            except Exception as e:
                print(f"[SCAN] DB persist failed: {e}")
                response["db_persist_error"] = str(e)

        # Save results to output folder
        if request.save_results:
            output_path = os.path.join(OUTPUT_FOLDER, project_name)
            os.makedirs(output_path, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            result_file = os.path.join(output_path, f"scan_results_{timestamp}.json")
            latest_file = os.path.join(output_path, "scan_results_latest.json")
            
            with open(result_file, "w", encoding="utf-8") as f:
                json.dump(response, f, indent=2)
            
            # Also save as latest
            with open(latest_file, "w", encoding="utf-8") as f:
                json.dump(response, f, indent=2)
            
            response["output_file"] = result_file
            response["latest_file"] = latest_file
            
            print(f"[SCAN] Results saved to: {result_file}")
        
        # Check if should fail on findings
        if request.fail_on_findings and total_findings > 0:
            raise HTTPException(
                status_code=422, 
                detail=f"Scan found {total_findings} security findings",
                headers={"X-Scan-Findings": str(total_findings)}
            )
        
        return JSONResponse(content=response)
        
    except HTTPException:
        raise
    except Exception as e:
        error_response = {
            "success": False,
            "project_name": project_name,
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }
        
        # Save error to output
        if request.save_results:
            output_path = os.path.join(OUTPUT_FOLDER, project_name)
            os.makedirs(output_path, exist_ok=True)
            error_file = os.path.join(output_path, "scan_error.json")
            with open(error_file, "w", encoding="utf-8") as f:
                json.dump(error_response, f, indent=2)
        
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.get("/results/{project_name}")
async def get_latest_results(project_name: str):
    """Get latest scan results for a project (file-based)."""
    if ".." in project_name or "/" in project_name or "\\" in project_name:
        raise HTTPException(status_code=400, detail="Invalid project_name")
    latest_file = os.path.join(OUTPUT_FOLDER, project_name, "scan_results_latest.json")
    if not os.path.exists(latest_file):
        raise HTTPException(
            status_code=404,
            detail=f"No scan results found for project: {project_name}",
        )
    try:
        with open(latest_file, "r", encoding="utf-8") as f:
            results = json.load(f)
        return JSONResponse(content=results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read results: {str(e)}")


# ---------- API v1 SecOps (DB-backed; use scan_id, tenant_id, customer_id) ----------

@app.get("/api/v1/secops/scans")
async def list_secops_scans(
    tenant_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    limit: int = 50,
):
    """List SecOps scans (from engine_secops). Filter by tenant_id, customer_id, scan_id."""
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        from secops_db import list_scans
        rows = list_scans(tenant_id=tenant_id, customer_id=customer_id, scan_id=scan_id, limit=limit)
        return JSONResponse(content={"scans": rows})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/secops/scans/{scan_id}")
async def get_secops_scan(scan_id: str):
    """Get a single SecOps scan by scan_id."""
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        from secops_db import get_scan
        row = get_scan(scan_id)
        if not row:
            raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")
        return JSONResponse(content=row)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/secops/scans/{scan_id}/findings")
async def get_secops_findings(scan_id: str, limit: int = 500):
    """Get findings for a SecOps scan."""
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        from secops_db import get_findings
        rows = get_findings(scan_id=scan_id, limit=limit)
        return JSONResponse(content={"findings": rows})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
async def root():
    """API documentation"""
    return {
        "service": "SecOps Vulnerability Scanner API",
        "version": "2.0.0",
        "workflow": {
            "step1": "Jenkins clones repo to scan_input/{project_name}",
            "step2": "Jenkins calls POST /scan with project_name",
            "step3": "Scanner scans and saves to scan_output/{project_name}",
            "step4": "Jenkins reads results from scan_output"
        },
        "endpoints": {
            "health": "GET /health",
            "scan": "POST /scan (JSON: {project_name, save_results, fail_on_findings})",
            "results": "GET /results/{project_name}"
        },
        "folders": {
            "input": INPUT_FOLDER,
            "output": OUTPUT_FOLDER
        },
        "documentation": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

