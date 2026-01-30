"""
Unified API Gateway for Threat Engine Platform
Consolidates access to all engine services with consistent auth, logging, and routing.
"""

import os
import sys
from fastapi import FastAPI, Request, HTTPException, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import httpx
import json
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any, Union
import logging

# Add common to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from engine_common.logger import setup_logger, LogContext
from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware

# Import orchestration (local module)
try:
    from orchestration import OrchestrationService, OrchestrationRequest
except ImportError:
    # Fallback if orchestration module not available
    OrchestrationService = None
    OrchestrationRequest = None

logger = setup_logger(__name__, engine_name="api-gateway")

# Initialize orchestration service (if available)
orchestration_service = OrchestrationService() if OrchestrationService else None

# Service discovery configuration - Battle-tested engines
SERVICE_ROUTES = {
    # ConfigScan Engines - Multi-CSP Support
    "configscan-aws": {
        "url": os.getenv("CONFIGSCAN_AWS_URL", "http://localhost:8001"),
        "prefix": "/api/v1/configscan/aws",
        "health_endpoint": "/health",
        "csp": "aws"
    },
    "configscan-azure": {
        "url": os.getenv("CONFIGSCAN_AZURE_URL", "http://localhost:8002"), 
        "prefix": "/api/v1/configscan/azure",
        "health_endpoint": "/health",
        "csp": "azure"
    },
    "configscan-gcp": {
        "url": os.getenv("CONFIGSCAN_GCP_URL", "http://localhost:8003"),
        "prefix": "/api/v1/configscan/gcp",
        "health_endpoint": "/health",
        "csp": "gcp"
    },
    "configscan-alicloud": {
        "url": os.getenv("CONFIGSCAN_ALICLOUD_URL", "http://localhost:8004"),
        "prefix": "/api/v1/configscan/alicloud", 
        "health_endpoint": "/health",
        "csp": "alicloud"
    },
    "configscan-ibm": {
        "url": os.getenv("CONFIGSCAN_IBM_URL", "http://localhost:8005"),
        "prefix": "/api/v1/configscan/ibm",
        "health_endpoint": "/health",
        "csp": "ibm"
    },
    "configscan-oci": {
        "url": os.getenv("CONFIGSCAN_OCI_URL", "http://localhost:8006"),
        "prefix": "/api/v1/configscan/oci",
        "health_endpoint": "/health",
        "csp": "oci"
    },
    
    # Core Business Logic Engines
    "onboarding": {
        "url": os.getenv("ONBOARDING_ENGINE_URL", "http://localhost:8010"),
        "prefix": "/api/v1/onboarding",
        "health_endpoint": "/health"
    },
    "rule": {
        "url": os.getenv("RULE_ENGINE_URL", "http://localhost:8011"),
        "prefix": "/api/v1/rule",
        "health_endpoint": "/health"
    },
    
    # Legacy/Placeholder engines (to be implemented)
    "threat": {
        "url": os.getenv("THREAT_ENGINE_URL", "http://localhost:8020"),
        "prefix": "/api/v1/threat",
        "health_endpoint": "/health"
    },
    "compliance": {
        "url": os.getenv("COMPLIANCE_ENGINE_URL", "http://localhost:8021"),
        "prefix": "/api/v1/compliance", 
        "health_endpoint": "/health"
    },
    "inventory": {
        "url": os.getenv("INVENTORY_ENGINE_URL", "http://localhost:8022"),
        "prefix": "/api/v1/inventory",
        "health_endpoint": "/health" 
    },
}

class ServiceRegistry:
    """Manages service discovery and health checking"""
    
    def __init__(self):
        self.services = SERVICE_ROUTES.copy()
        self.healthy_services = set()
    
    async def check_service_health(self, service_name: str) -> bool:
        """Check if a service is healthy"""
        service = self.services.get(service_name)
        if not service:
            return False
            
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{service['url']}{service['health_endpoint']}")
                is_healthy = response.status_code == 200
                
                if is_healthy:
                    self.healthy_services.add(service_name)
                else:
                    self.healthy_services.discard(service_name)
                    
                return is_healthy
        except Exception as e:
            logger.warning(f"Service health check failed for {service_name}: {e}")
            self.healthy_services.discard(service_name)
            return False
    
    async def get_service_url(self, service_name: str) -> Optional[str]:
        """Get service URL if healthy"""
        if service_name not in self.services:
            return None
            
        # Check health if not recently checked
        if service_name not in self.healthy_services:
            await self.check_service_health(service_name)
            
        return self.services[service_name]["url"] if service_name in self.healthy_services else None

service_registry = ServiceRegistry()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup - check service health
    logger.info("API Gateway starting - checking service health")
    for service_name in SERVICE_ROUTES:
        await service_registry.check_service_health(service_name)
        
    healthy_count = len(service_registry.healthy_services)
    logger.info(f"API Gateway started - {healthy_count}/{len(SERVICE_ROUTES)} services healthy")
    
    yield
    
    # Shutdown
    logger.info("API Gateway shutting down")

app = FastAPI(
    title="Threat Engine API Gateway",
    description="Unified API gateway for all threat engine services",
    version="1.0.0",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(CorrelationIDMiddleware)
app.add_middleware(RequestLoggingMiddleware, engine_name="api-gateway")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_target_service(path: str) -> Optional[str]:
    """Determine which service should handle this request"""
    for service_name, config in SERVICE_ROUTES.items():
        if path.startswith(config["prefix"]):
            return service_name
    return None

def get_configscan_service_by_csp(csp: str) -> Optional[str]:
    """Get the appropriate ConfigScan service for a given CSP"""
    csp_mapping = {
        "aws": "configscan-aws",
        "azure": "configscan-azure", 
        "gcp": "configscan-gcp",
        "alicloud": "configscan-alicloud",
        "ibm": "configscan-ibm",
        "oci": "configscan-oci"
    }
    return csp_mapping.get(csp.lower())

async def extract_csp_from_request(request: Request) -> Optional[str]:
    """Extract CSP parameter from request body or query params"""
    # Try query parameter first
    csp = request.query_params.get("csp")
    if csp:
        return csp.lower()
    
    # Try request body for POST requests
    if request.method in ["POST", "PUT", "PATCH"]:
        try:
            body = await request.body()
            if body:
                body_data = json.loads(body.decode())
                if isinstance(body_data, dict) and "csp" in body_data:
                    return body_data["csp"].lower()
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    
    return None

def get_tenant_context(request: Request) -> Dict[str, Any]:
    """Extract tenant context from request for logging/auth"""
    tenant_id = (
        request.query_params.get("tenant_id") or 
        request.headers.get("X-Tenant-ID") or
        getattr(request.state, "tenant_id", None)
    )
    
    return {
        "tenant_id": tenant_id,
        "user_id": request.headers.get("X-User-ID"),
        "correlation_id": request.headers.get("X-Correlation-ID")
    }

@app.middleware("http")
async def route_requests(request: Request, call_next):
    """Main routing middleware - forwards requests to appropriate services"""
    
    # Skip gateway routes
    if request.url.path.startswith("/gateway/"):
        return await call_next(request)
    
    # Handle unified ConfigScan endpoint
    if request.url.path.startswith("/api/v1/configscan") and not any(
        request.url.path.startswith(config["prefix"]) 
        for config in SERVICE_ROUTES.values() 
        if "csp" in config
    ):
        # This is a unified ConfigScan request, route based on CSP parameter
        csp = await extract_csp_from_request(request)
        if not csp:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "CSP parameter required for unified ConfigScan endpoint",
                    "supported_csps": ["aws", "azure", "gcp", "alicloud", "ibm", "oci"],
                    "usage": "Include 'csp' parameter in query string or request body"
                }
            )
        
        target_service = get_configscan_service_by_csp(csp)
        if not target_service:
            return JSONResponse(
                status_code=400,
                content={
                    "error": f"Unsupported CSP: {csp}",
                    "supported_csps": ["aws", "azure", "gcp", "alicloud", "ibm", "oci"]
                }
            )
    else:
        # Standard routing
        target_service = get_target_service(request.url.path)
        if not target_service:
            return JSONResponse(
                status_code=404,
                content={"error": "Service not found", "path": request.url.path}
            )
    
    # Get service URL
    service_url = await service_registry.get_service_url(target_service)
    if not service_url:
        return JSONResponse(
            status_code=503, 
            content={"error": f"Service {target_service} unavailable"}
        )
    
    # Get tenant context for logging
    tenant_context = get_tenant_context(request)
    
    with LogContext(**{k: v for k, v in tenant_context.items() if v}):
        logger.info(f"Routing request to {target_service}", extra={
            "extra_fields": {
                "target_service": target_service,
                "method": request.method,
                "path": request.url.path,
                "service_url": service_url
            }
        })
        
        try:
            # Forward request to target service
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Handle path processing for unified vs direct CSP routing
                if request.url.path.startswith("/api/v1/configscan") and not any(
                    request.url.path.startswith(config["prefix"]) 
                    for config in SERVICE_ROUTES.values() 
                    if "csp" in config
                ):
                    # Unified ConfigScan request - remove /api/v1/configscan prefix
                    internal_path = request.url.path[len("/api/v1/configscan"):]
                    if not internal_path.startswith("/"):
                        internal_path = "/" + internal_path
                else:
                    # Direct service routing - remove service prefix from path
                    service_prefix = SERVICE_ROUTES[target_service]["prefix"]
                    internal_path = request.url.path
                    if internal_path.startswith(service_prefix):
                        internal_path = internal_path[len(service_prefix):]
                
                # Build target URL
                target_url = f"{service_url}{internal_path}"
                if request.url.query:
                    target_url += f"?{request.url.query}"
                
                # Forward headers (add/modify as needed)
                headers = dict(request.headers)
                headers["X-Forwarded-For"] = request.client.host
                headers["X-Forwarded-Proto"] = "http"
                
                # Forward request
                if request.method == "GET":
                    response = await client.get(target_url, headers=headers)
                elif request.method == "POST":
                    body = await request.body()
                    response = await client.post(target_url, headers=headers, content=body)
                elif request.method == "PUT":
                    body = await request.body()
                    response = await client.put(target_url, headers=headers, content=body)
                elif request.method == "DELETE":
                    response = await client.delete(target_url, headers=headers)
                elif request.method == "PATCH":
                    body = await request.body()
                    response = await client.patch(target_url, headers=headers, content=body)
                else:
                    return JSONResponse(
                        status_code=405,
                        content={"error": f"Method {request.method} not supported"}
                    )
                
                # Return response
                return JSONResponse(
                    status_code=response.status_code,
                    content=response.json() if response.headers.get("content-type", "").startswith("application/json") else {"data": response.text},
                    headers={k: v for k, v in response.headers.items() 
                            if k.lower() not in ["content-length", "transfer-encoding"]}
                )
                
        except httpx.TimeoutException:
            logger.error(f"Request to {target_service} timed out")
            return JSONResponse(
                status_code=504,
                content={"error": "Service request timed out"}
            )
        except Exception as e:
            logger.error(f"Error forwarding to {target_service}: {e}", exc_info=True)
            return JSONResponse(
                status_code=502,
                content={"error": "Service request failed"}
            )

# Gateway management endpoints
@app.get("/")
async def root():
    """Root endpoint"""
    configscan_services = [name for name in SERVICE_ROUTES.keys() if name.startswith("configscan-")]
    other_services = [name for name in SERVICE_ROUTES.keys() if not name.startswith("configscan-")]
    
    return {
        "service": "threat-engine-api-gateway",
        "version": "2.0.0",
        "status": "running",
        "architecture": "hybrid-battle-tested-engines",
        "available_services": list(SERVICE_ROUTES.keys()),
        "configscan_services": configscan_services,
        "other_services": other_services,
        "supported_csps": [
            config.get("csp") for config in SERVICE_ROUTES.values() 
            if config.get("csp")
        ],
        "unified_configscan_endpoint": "/api/v1/configscan"
    }

@app.get("/gateway/health")
async def gateway_health():
    """Gateway health check"""
    return {
        "gateway": "healthy",
        "services": {
            name: name in service_registry.healthy_services
            for name in SERVICE_ROUTES
        }
    }

@app.get("/gateway/services")
async def list_services():
    """List all available services and their health status"""
    services_status = {}
    for service_name in SERVICE_ROUTES:
        is_healthy = await service_registry.check_service_health(service_name)
        services_status[service_name] = {
            "url": SERVICE_ROUTES[service_name]["url"],
            "prefix": SERVICE_ROUTES[service_name]["prefix"], 
            "healthy": is_healthy
        }
    
    return {
        "total_services": len(SERVICE_ROUTES),
        "healthy_services": len(service_registry.healthy_services),
        "services": services_status
    }

@app.post("/gateway/services/{service_name}/health-check")
async def force_health_check(service_name: str):
    """Force health check for a specific service"""
    if service_name not in SERVICE_ROUTES:
        raise HTTPException(status_code=404, detail="Service not found")
    
    is_healthy = await service_registry.check_service_health(service_name)
    return {
        "service": service_name,
        "healthy": is_healthy,
        "url": SERVICE_ROUTES[service_name]["url"]
    }

@app.get("/gateway/configscan/csps")
async def list_supported_csps():
    """List all supported CSPs and their service endpoints"""
    csp_services = {}
    for service_name, config in SERVICE_ROUTES.items():
        if service_name.startswith("configscan-") and "csp" in config:
            csp = config["csp"]
            is_healthy = service_name in service_registry.healthy_services
            csp_services[csp] = {
                "service_name": service_name,
                "url": config["url"],
                "prefix": config["prefix"],
                "healthy": is_healthy
            }
    
    return {
        "supported_csps": list(csp_services.keys()),
        "total_csp_count": len(csp_services),
        "healthy_csp_count": sum(1 for info in csp_services.values() if info["healthy"]),
        "services": csp_services,
        "unified_endpoint": "/api/v1/configscan",
        "direct_endpoints": [config["prefix"] for config in csp_services.values()]
    }

@app.get("/gateway/configscan/route-test")
async def test_configscan_routing(csp: str):
    """Test ConfigScan routing for a specific CSP"""
    target_service = get_configscan_service_by_csp(csp)
    if not target_service:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported CSP: {csp}. Supported: aws, azure, gcp, alicloud, ibm, oci"
        )
    
    service_config = SERVICE_ROUTES[target_service]
    is_healthy = target_service in service_registry.healthy_services
    
    return {
        "csp": csp,
        "target_service": target_service,
        "service_url": service_config["url"],
        "service_prefix": service_config["prefix"],
        "healthy": is_healthy,
        "unified_endpoint": f"/api/v1/configscan?csp={csp}",
        "direct_endpoint": service_config["prefix"]
    }

# Orchestration endpoint
if orchestration_service and OrchestrationRequest:
    @app.post("/gateway/orchestrate")
    async def orchestrate_scan(request: OrchestrationRequest):
        """
        Orchestrate complete scan pipeline: Discovery → Check → Threat → (Compliance + IAM + DataSec) → Inventory
        
        Flow:
        1. Discovery → threat_engine_discoveries
        2. Check → threat_engine_check (reads discoveries)
        3. Threat → threat report (reads check DB)
        4. Compliance / IAM / DataSec in parallel (Compliance from check DB, IAM/DataSec from threat)
        5. Inventory → threat_engine_inventory (reads discoveries)
        
        This endpoint can be called by onboarding engine based on schedule.
        """
        with LogContext(tenant_id=request.tenant_id):
            logger.info("Orchestration request received", extra={
                "extra_fields": {
                    "customer_id": request.customer_id,
                    "tenant_id": request.tenant_id,
                    "provider": request.provider,
                    "hierarchy_id": request.hierarchy_id
                }
            })
        
        try:
            result = await orchestration_service.run_orchestration(request)
            return result
        except Exception as e:
            logger.error(f"Orchestration failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)