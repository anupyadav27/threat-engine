"""
FastAPI server for YAML Rule Builder
"""
import os

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional, Literal
from pathlib import Path

# Import RuleBuilderAPI
try:
    from api import RuleBuilderAPI
    from models.rule import Rule
    from models.field_selection import FieldSelection
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from api import RuleBuilderAPI
    from models.rule import Rule
    from models.field_selection import FieldSelection

app = FastAPI(
    title="YAML Rule Builder API",
    description="API for building compliance rules",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize API
rule_builder_api = RuleBuilderAPI()

# In-memory rule storage (use DB in production)
rules_storage = {}


def _get_check_db_connection():
    """Return a psycopg2 connection to the check engine database.

    Uses CHECK_DB_* env vars with fallback to generic DB_* vars.
    """
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CHECK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=10,
    )


class ConditionInput(BaseModel):
    """Single condition (field/operator/value) selected in the UI."""
    field_name: str = Field(..., description="Field key from /providers/{provider}/services/{service}/fields")
    operator: str = Field(..., description="Operator supported by the field (e.g., equals, not_equals, exists, in, contains)")
    value: Any = Field(None, description="Value for the operator; use null for operators like 'exists'")


class RuleCreateRequest(BaseModel):
    """Request to create a rule"""
    provider: str  # REQUIRED: Provider name (e.g., 'aws', 'azure')
    service: str
    title: str
    description: str
    remediation: str
    rule_id: str  # Must start with {provider}.
    conditions: List[ConditionInput]
    logical_operator: Literal["single", "all", "any"] = "single"  # single, AND (all), OR (any)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "provider": "aws",
                    "service": "accessanalyzer",
                    "title": "This is a test",
                    "description": "Access Analyzer enabled",
                    "remediation": "Enable AWS IAM Access Analyzer for the account/region",
                    "rule_id": "aws.accessanalyzer.analyzer.this_is_a_test",
                    "logical_operator": "all",
                    "conditions": [
                        {"field_name": "Status", "operator": "equals", "value": "ACTIVE"},
                        {"field_name": "AnalyzerArn", "operator": "exists", "value": None},
                    ],
                }
            ]
        }
    }


class RuleValidateRequest(BaseModel):
    """Request to validate a rule"""
    provider: str  # REQUIRED: Provider name
    service: str
    rule_id: str  # Must start with {provider}.
    conditions: List[ConditionInput]
    logical_operator: Literal["single", "all", "any"] = "single"

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "provider": "aws",
                    "service": "accessanalyzer",
                    "rule_id": "aws.accessanalyzer.analyzer.this_is_a_test",
                    "logical_operator": "single",
                    "conditions": [
                        {"field_name": "Status", "operator": "equals", "value": "ACTIVE"}
                    ],
                }
            ]
        }
    }


@app.get("/api/v1/providers")
async def get_providers():
    """Get list of available CSP providers (AWS, Azure, GCP, OCI, AliCloud, IBM, K8s)"""
    try:
        providers = rule_builder_api.get_providers()
        return {"providers": providers}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/providers/status")
async def get_all_providers_status():
    """Get comprehensive status for all registered providers"""
    try:
        status = rule_builder_api.get_all_providers_status()
        return {
            "providers_status": status,
            "total_providers": len(status),
            "ready_providers": sum(1 for s in status.values() if s.get("readiness_percentage", 0) >= 90)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/providers/{provider}/status")
async def get_provider_status(provider: str):
    """Get detailed status for a specific provider"""
    try:
        status = rule_builder_api.get_provider_status(provider)
        return status
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/providers/{provider}/services")
async def get_provider_services(provider: str):
    """Get all available services for a specific provider"""
    try:
        services = rule_builder_api.get_available_services(provider)
        return {"provider": provider, "services": services}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/providers/{provider}/services/{service}/fields")
async def get_service_fields(provider: str, service: str):
    """Get all available fields for a service in a specific provider"""
    try:
        fields = rule_builder_api.get_service_fields(provider, service)
        return {"provider": provider, "service": service, "fields": fields}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/rules/validate")
async def validate_rule(request: RuleValidateRequest):
    """Validate a rule before generation with two-phase matching"""
    try:
        # Validate provider matches rule_id prefix
        if not request.rule_id.startswith(f"{request.provider}."):
            raise HTTPException(
                status_code=400,
                detail=f"rule_id '{request.rule_id}' must start with provider prefix '{request.provider}.'"
            )
        
        # Create rule object with explicit provider
        rule = rule_builder_api.create_rule_from_ui_input({
            "provider": request.provider,  # Explicit provider
            "service": request.service,
            "title": "Validation",
            "description": "Validation",
            "remediation": "Validation",
            "rule_id": request.rule_id,
            "conditions": [c.model_dump() for c in request.conditions],
            "logical_operator": request.logical_operator
        })
        
        # Validate with provider (two-phase matching)
        validation = rule_builder_api.validate_rule(rule, request.provider)
        return validation
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/rules/generate")
async def generate_rule(request: RuleCreateRequest):
    """Generate YAML and metadata for a rule (with merging capability)"""
    try:
        # Validate provider matches rule_id prefix
        if not request.rule_id.startswith(f"{request.provider}."):
            raise HTTPException(
                status_code=400,
                detail=f"rule_id '{request.rule_id}' must start with provider prefix '{request.provider}.'"
            )
        
        # Create rule object with explicit provider
        rule = rule_builder_api.create_rule_from_ui_input({
            "provider": request.provider,  # Explicit provider
            "service": request.service,
            "title": request.title,
            "description": request.description,
            "remediation": request.remediation,
            "rule_id": request.rule_id,
            "conditions": [c.model_dump() for c in request.conditions],
            "logical_operator": request.logical_operator
        })
        
        # Generate with provider (includes YAML merging)
        result = rule_builder_api.generate_rule(rule, request.provider)
        
        # Store rule with provider
        from datetime import datetime
        rules_storage[request.rule_id] = {
            "rule_id": request.rule_id,
            "provider": request.provider,  # Include provider
            "service": request.service,
            "title": request.title,
            "description": request.description,
            "remediation": request.remediation,
            "conditions": [c.model_dump() for c in request.conditions],
            "logical_operator": request.logical_operator,
            "yaml_path": result.get("yaml_path"),
            "metadata_path": result.get("metadata_path"),
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rules/{rule_id}")
async def get_rule(rule_id: str):
    """Get specific rule details"""
    if rule_id not in rules_storage:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule_data = rules_storage[rule_id]
    return {
        "rule_id": rule_id,
        "provider": rule_data.get("provider"),
        "service": rule_data.get("service"),
        "title": rule_data.get("title"),
        "description": rule_data.get("description"),
        "remediation": rule_data.get("remediation"),
        "conditions": rule_data.get("conditions"),
        "logical_operator": rule_data.get("logical_operator"),
        "yaml_path": rule_data.get("yaml_path"),
        "metadata_path": rule_data.get("metadata_path"),
        "created_at": rule_data.get("created_at"),
        "updated_at": rule_data.get("updated_at")
    }


@app.delete("/api/v1/rules/{rule_id}")
async def delete_rule(rule_id: str):
    """Delete a rule"""
    if rule_id not in rules_storage:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule_data = rules_storage[rule_id]
    
    # TODO: Delete actual YAML and metadata files if they exist
    # import os
    # if rule_data.get("yaml_path") and os.path.exists(rule_data["yaml_path"]):
    #     os.remove(rule_data["yaml_path"])
    # if rule_data.get("metadata_path") and os.path.exists(rule_data["metadata_path"]):
    #     os.remove(rule_data["metadata_path"])
    
    del rules_storage[rule_id]
    
    return {
        "rule_id": rule_id,
        "status": "deleted",
        "message": "Rule deleted successfully"
    }


@app.put("/api/v1/rules/{rule_id}")
async def update_rule(rule_id: str, request: RuleCreateRequest):
    """Update an existing rule"""
    if rule_id not in rules_storage:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    try:
        # Validate provider matches rule_id prefix
        if not request.rule_id.startswith(f"{request.provider}."):
            raise HTTPException(
                status_code=400,
                detail=f"rule_id '{request.rule_id}' must start with provider prefix '{request.provider}.'"
            )
        
        # Create updated rule object with explicit provider
        rule = rule_builder_api.create_rule_from_ui_input({
            "provider": request.provider,  # Explicit provider
            "service": request.service,
            "title": request.title,
            "description": request.description,
            "remediation": request.remediation,
            "rule_id": rule_id,
            "conditions": [c.model_dump() for c in request.conditions],
            "logical_operator": request.logical_operator
        })
        
        # Generate updated rule with provider
        result = rule_builder_api.generate_rule(rule, request.provider)
        
        # Update stored rule
        from datetime import datetime
        rules_storage[rule_id].update({
            "provider": request.provider,  # Include provider
            "service": request.service,
            "title": request.title,
            "description": request.description,
            "remediation": request.remediation,
            "conditions": [c.model_dump() for c in request.conditions],
            "logical_operator": request.logical_operator,
            "yaml_path": result.get("yaml_path"),
            "metadata_path": result.get("metadata_path"),
            "updated_at": datetime.utcnow().isoformat()
        })
        
        return {
            "rule_id": rule_id,
            "status": "updated",
            "result": result
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/providers/{provider}/services/{service}/rules")
async def list_service_rules(provider: str, service: str):
    """List all rules for a specific service in a provider"""
    service_rules = [
        {
            "rule_id": rule_id,
            "provider": rule_data.get("provider"),
            "title": rule_data.get("title"),
            "description": rule_data.get("description"),
            "created_at": rule_data.get("created_at"),
            "updated_at": rule_data.get("updated_at")
        }
        for rule_id, rule_data in rules_storage.items()
        if rule_data.get("provider") == provider and rule_data.get("service") == service
    ]
    
    service_rules.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    
    return {
        "provider": provider,
        "service": service,
        "rules": service_rules,
        "total": len(service_rules)
    }


@app.get("/api/v1/health/live")
async def liveness_check():
    """Kubernetes liveness probe — no DB, no external calls."""
    return {"status": "ok", "service": "yaml-rule-builder"}


@app.get("/api/v1/health/ready")
async def readiness_check():
    """Kubernetes readiness probe — verifies DB connectivity."""
    try:
        conn = _get_check_db_connection()
        conn.cursor().execute("SELECT 1")
        conn.close()
        return {"status": "ready", "database": "connected"}
    except Exception as e:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "database": "disconnected", "error": str(e)}
        )


@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint with provider status"""
    try:
        providers = rule_builder_api.get_providers()
        provider_status = rule_builder_api.get_all_providers_status()
        
        # Calculate overall readiness
        total_services = sum(s.get("total_services", 0) for s in provider_status.values())
        ready_services = sum(s.get("ready_services", 0) for s in provider_status.values())
        overall_readiness = (ready_services / total_services * 100) if total_services > 0 else 0
        
        return {
            "status": "healthy",
            "service": "yaml-rule-builder",
            "version": "1.0.0",
            "providers_enabled": providers,
            "total_providers": len(providers),
            "total_services": total_services,
            "ready_services": ready_services,
            "overall_readiness": f"{overall_readiness:.1f}%"
        }
    except Exception as e:
        return {
            "status": "error",
            "service": "yaml-rule-builder",
            "version": "1.0.0",
            "error": str(e)
        }


# ============================================================================
# Additional API Endpoints for Enhanced UI Functionality
# ============================================================================

@app.get("/api/v1/rules/search")
async def search_rules(
    q: str,
    provider: Optional[str] = None,
    service: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """Full-text search across rules"""
    try:
        query_lower = q.lower()
        matching_rules = []
        
        for rule_id, rule_data in rules_storage.items():
            # Filter by provider/service if specified
            if provider and rule_data.get("provider") != provider:
                continue
            if service and rule_data.get("service") != service:
                continue
            
            # Search in title, description, rule_id
            title = rule_data.get("title", "").lower()
            description = rule_data.get("description", "").lower()
            rule_id_lower = rule_id.lower()
            
            if (query_lower in title or 
                query_lower in description or 
                query_lower in rule_id_lower):
                matching_rules.append({
                    "rule_id": rule_id,
                    "provider": rule_data.get("provider"),
                    "service": rule_data.get("service"),
                    "title": rule_data.get("title"),
                    "description": rule_data.get("description", "")[:200],  # Truncate
                    "created_at": rule_data.get("created_at"),
                    "updated_at": rule_data.get("updated_at")
                })
        
        # Sort by relevance (simple: title match > description match)
        matching_rules.sort(key=lambda x: (
            query_lower not in x["title"].lower(),
            x.get("created_at") or ""
        ), reverse=True)
        
        return {
            "query": q,
            "rules": matching_rules[offset:offset+limit],
            "total": len(matching_rules),
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rules/statistics")
async def get_rule_statistics():
    """Get rule statistics (counts by provider/service)"""
    try:
        stats = {
            "total_rules": len(rules_storage),
            "by_provider": {},
            "by_service": {},
            "custom_rules_count": 0,
            "recent_rules": []
        }
        
        # Count by provider and service
        for rule_id, rule_data in rules_storage.items():
            provider = rule_data.get("provider", "unknown")
            service = rule_data.get("service", "unknown")
            
            # Count by provider
            if provider not in stats["by_provider"]:
                stats["by_provider"][provider] = 0
            stats["by_provider"][provider] += 1
            
            # Count by service (with provider prefix)
            service_key = f"{provider}.{service}"
            if service_key not in stats["by_service"]:
                stats["by_service"][service_key] = 0
            stats["by_service"][service_key] += 1
            
            # Count custom rules (rules with "custom" in rule_id or marked as custom)
            if "custom" in rule_id.lower() or rule_data.get("is_custom", False):
                stats["custom_rules_count"] += 1
        
        # Get recent rules (last 10)
        recent = sorted(
            [
                {
                    "rule_id": rule_id,
                    "provider": rule_data.get("provider"),
                    "service": rule_data.get("service"),
                    "title": rule_data.get("title"),
                    "created_at": rule_data.get("created_at")
                }
                for rule_id, rule_data in rules_storage.items()
            ],
            key=lambda x: x.get("created_at") or "",
            reverse=True
        )[:10]
        stats["recent_rules"] = recent
        
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/rules/{rule_id}/copy")
async def copy_rule(rule_id: str):
    """Duplicate an existing rule"""
    try:
        if rule_id not in rules_storage:
            raise HTTPException(status_code=404, detail="Rule not found")
        
        original_rule = rules_storage[rule_id]
        
        # Generate new rule_id (append _copy or _copy_N)
        base_rule_id = original_rule.get("rule_id", rule_id)
        new_rule_id = f"{base_rule_id}_copy"
        counter = 1
        while new_rule_id in rules_storage:
            new_rule_id = f"{base_rule_id}_copy_{counter}"
            counter += 1
        
        # Create copy with new rule_id
        from datetime import datetime
        copied_rule = original_rule.copy()
        copied_rule["rule_id"] = new_rule_id
        copied_rule["title"] = f"{copied_rule.get('title', 'Rule')} (Copy)"
        copied_rule["created_at"] = datetime.utcnow().isoformat()
        copied_rule["updated_at"] = datetime.utcnow().isoformat()
        
        # Generate new rule files
        rule = rule_builder_api.create_rule_from_ui_input({
            "provider": copied_rule["provider"],
            "service": copied_rule["service"],
            "title": copied_rule["title"],
            "description": copied_rule["description"],
            "remediation": copied_rule["remediation"],
            "rule_id": new_rule_id,
            "conditions": copied_rule["conditions"],
            "logical_operator": copied_rule["logical_operator"]
        })
        
        result = rule_builder_api.generate_rule(rule, copied_rule["provider"])
        
        # Update paths
        copied_rule["yaml_path"] = result.get("yaml_path")
        copied_rule["metadata_path"] = result.get("metadata_path")
        
        # Store copied rule
        rules_storage[new_rule_id] = copied_rule
        
        return {
            "rule_id": new_rule_id,
            "original_rule_id": rule_id,
            "status": "copied",
            "result": result
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/rules/preview")
async def preview_rule(request: RuleValidateRequest):
    """Preview YAML without generating files"""
    try:
        # Validate provider matches rule_id prefix
        if not request.rule_id.startswith(f"{request.provider}."):
            raise HTTPException(
                status_code=400,
                detail=f"rule_id '{request.rule_id}' must start with provider prefix '{request.provider}.'"
            )
        
        # Create rule object
        rule = rule_builder_api.create_rule_from_ui_input({
            "provider": request.provider,
            "service": request.service,
            "title": "Preview",
            "description": "Preview",
            "remediation": "Preview",
            "rule_id": request.rule_id,
            "conditions": [c.model_dump() for c in request.conditions],
            "logical_operator": request.logical_operator
        })
        
        # Validate rule
        validation = rule_builder_api.validate_rule(rule, request.provider)
        
        if not validation["valid"]:
            return {
                "valid": False,
                "errors": validation["errors"],
                "warnings": validation["warnings"],
                "yaml_preview": None
            }
        
        # Generate YAML preview (without saving)
        from pathlib import Path
        from tempfile import NamedTemporaryFile
        import os
        
        try:
            from core.data_loader import DataLoader
        except ImportError:
            from .core.data_loader import DataLoader
        
        loader = DataLoader(rule_builder_api.config)
        service_data = loader.load_service_data(request.service, request.provider)
        
        try:
            from core.yaml_generator import YAMLGenerator
        except ImportError:
            from .core.yaml_generator import YAMLGenerator
        
        generator = YAMLGenerator(request.service, request.provider, service_data, rule_builder_api.config)
        
        # Use temporary file for preview
        with NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
            tmp_path = Path(tmp.name)
            yaml_str = generator.generate(
                rule.conditions,
                tmp_path,
                logical_operator=rule.logical_operator,
                rule_id=rule.rule_id
            )
            # Read back the generated YAML
            with open(tmp_path, 'r') as f:
                yaml_preview = f.read()
            # Clean up
            os.unlink(tmp_path)
        
        return {
            "valid": True,
            "errors": [],
            "warnings": validation["warnings"],
            "existing_rules": validation["existing_rules"],
            "yaml_preview": yaml_preview
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/rules/bulk-delete")
async def bulk_delete_rules(rule_ids: List[str]):
    """Delete multiple rules"""
    try:
        deleted = []
        not_found = []
        errors = []
        
        for rule_id in rule_ids:
            if rule_id not in rules_storage:
                not_found.append(rule_id)
                continue
            
            try:
                rule_data = rules_storage[rule_id]
                
                # TODO: Delete actual YAML and metadata files if they exist
                # import os
                # if rule_data.get("yaml_path") and os.path.exists(rule_data["yaml_path"]):
                #     os.remove(rule_data["yaml_path"])
                # if rule_data.get("metadata_path") and os.path.exists(rule_data["metadata_path"]):
                #     os.remove(rule_data["metadata_path"])
                
                del rules_storage[rule_id]
                deleted.append(rule_id)
            except Exception as e:
                errors.append({"rule_id": rule_id, "error": str(e)})
        
        return {
            "deleted": deleted,
            "not_found": not_found,
            "errors": errors,
            "total_deleted": len(deleted)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rules/export")
async def export_rules(
    format: str = "json",
    provider: Optional[str] = None,
    service: Optional[str] = None,
    rule_ids: Optional[str] = None  # Comma-separated list
):
    """Export rules in JSON or YAML format"""
    try:
        # Filter rules
        filtered_rules = []
        rule_id_list = rule_ids.split(",") if rule_ids else None
        
        for rule_id, rule_data in rules_storage.items():
            # Filter by provider
            if provider and rule_data.get("provider") != provider:
                continue
            # Filter by service
            if service and rule_data.get("service") != service:
                continue
            # Filter by specific rule IDs
            if rule_id_list and rule_id not in rule_id_list:
                continue
            
            filtered_rules.append(rule_data)
        
        if format.lower() == "yaml":
            import yaml
            return {
                "format": "yaml",
                "rules": yaml.dump(filtered_rules, default_flow_style=False),
                "count": len(filtered_rules)
            }
        else:  # json
            return {
                "format": "json",
                "rules": filtered_rules,
                "count": len(filtered_rules)
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/rules/import")
async def import_rules(rules: List[Dict[str, Any]]):
    """Import rules from JSON/YAML"""
    try:
        imported = []
        errors = []
        
        for rule_data in rules:
            try:
                # Validate required fields
                required_fields = ["provider", "service", "title", "description", 
                                 "remediation", "rule_id", "conditions"]
                missing = [f for f in required_fields if f not in rule_data]
                if missing:
                    errors.append({
                        "rule_id": rule_data.get("rule_id", "unknown"),
                        "error": f"Missing required fields: {', '.join(missing)}"
                    })
                    continue
                
                # Check if rule already exists
                rule_id = rule_data["rule_id"]
                if rule_id in rules_storage:
                    errors.append({
                        "rule_id": rule_id,
                        "error": "Rule already exists"
                    })
                    continue
                
                # Ensure conditions are in correct format
                conditions = rule_data.get("conditions", [])
                if conditions and isinstance(conditions[0], dict):
                    # Already in dict format, good
                    pass
                else:
                    # Convert ConditionInput objects to dicts if needed
                    conditions = [c.model_dump() if hasattr(c, 'model_dump') else c for c in conditions]
                    rule_data["conditions"] = conditions
                
                # Create and generate rule
                rule = rule_builder_api.create_rule_from_ui_input(rule_data)
                result = rule_builder_api.generate_rule(rule, rule_data["provider"])
                
                if not result["success"]:
                    errors.append({
                        "rule_id": rule_id,
                        "error": "; ".join(result.get("errors", []))
                    })
                    continue
                
                # Store rule
                from datetime import datetime
                rule_data["yaml_path"] = result.get("yaml_path")
                rule_data["metadata_path"] = result.get("metadata_path")
                rule_data["created_at"] = rule_data.get("created_at") or datetime.utcnow().isoformat()
                rule_data["updated_at"] = datetime.utcnow().isoformat()
                
                rules_storage[rule_id] = rule_data
                imported.append(rule_id)
                
            except Exception as e:
                errors.append({
                    "rule_id": rule_data.get("rule_id", "unknown"),
                    "error": str(e)
                })
        
        return {
            "imported": imported,
            "errors": errors,
            "total_imported": len(imported),
            "total_failed": len(errors)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/providers/{provider}/services/{service}/capabilities")
async def get_service_capabilities(provider: str, service: str):
    """Get service capabilities and supported operations"""
    try:
        # Get service fields (which includes operations)
        fields = rule_builder_api.get_service_fields(provider, service)
        
        # Extract unique operations
        operations = set()
        field_details = {}
        
        for field_name, field_info in fields.items():
            field_ops = field_info.get("operations", [])
            operations.update(field_ops)
            field_details[field_name] = {
                "type": field_info.get("type"),
                "operators": field_info.get("operators", []),
                "operations": field_ops,
                "enum": field_info.get("enum", False),
                "possible_values": field_info.get("possible_values")
            }
        
        # Get provider status for this service
        provider_status = rule_builder_api.get_provider_status(provider)
        service_ready = service in provider_status.get("ready_services_list", [])
        
        return {
            "provider": provider,
            "service": service,
            "ready": service_ready,
            "total_fields": len(fields),
            "total_operations": len(operations),
            "operations": sorted(list(operations)),
            "fields": field_details
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rules/templates")
async def get_rule_templates(
    provider: Optional[str] = None,
    service: Optional[str] = None
):
    """Get rule templates"""
    try:
        # For now, return common rule templates
        # In future, this could load from a templates file/database
        templates = [
            {
                "template_id": "status_check",
                "name": "Status Check",
                "description": "Check if resource status equals a value",
                "provider": "all",
                "service": "all",
                "conditions": [
                    {
                        "field_name": "Status",
                        "operator": "equals",
                        "value": "ACTIVE"
                    }
                ],
                "logical_operator": "single"
            },
            {
                "template_id": "encryption_check",
                "name": "Encryption Enabled",
                "description": "Check if encryption is enabled",
                "provider": "all",
                "service": "all",
                "conditions": [
                    {
                        "field_name": "EncryptionEnabled",
                        "operator": "equals",
                        "value": True
                    }
                ],
                "logical_operator": "single"
            },
            {
                "template_id": "public_access_blocked",
                "name": "Public Access Blocked",
                "description": "Check if public access is blocked",
                "provider": "all",
                "service": "all",
                "conditions": [
                    {
                        "field_name": "PublicAccessBlocked",
                        "operator": "equals",
                        "value": True
                    }
                ],
                "logical_operator": "single"
            }
        ]
        
        # Filter by provider/service if specified
        if provider:
            templates = [t for t in templates if t["provider"] == "all" or t["provider"] == provider]
        if service:
            templates = [t for t in templates if t["service"] == "all" or t["service"] == service]
        
        return {
            "templates": templates,
            "total": len(templates)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/rules/templates/{template_id}/create")
async def create_rule_from_template(
    template_id: str,
    request: RuleCreateRequest
):
    """Create a rule from a template"""
    try:
        # Get template
        templates_response = await get_rule_templates()
        template = None
        for t in templates_response["templates"]:
            if t["template_id"] == template_id:
                template = t
                break
        
        if not template:
            raise HTTPException(status_code=404, detail="Template not found")
        
        # Merge template conditions with request
        # Use template conditions as base, but allow override
        conditions = request.conditions if request.conditions else template["conditions"]
        logical_operator = request.logical_operator if request.logical_operator else template["logical_operator"]
        
        # Create rule with merged data
        rule = rule_builder_api.create_rule_from_ui_input({
            "provider": request.provider,
            "service": request.service,
            "title": request.title or template["name"],
            "description": request.description or template["description"],
            "remediation": request.remediation,
            "rule_id": request.rule_id,
            "conditions": [c.model_dump() if hasattr(c, 'model_dump') else c for c in conditions],
            "logical_operator": logical_operator
        })
        
        # Generate rule
        result = rule_builder_api.generate_rule(rule, request.provider)
        
        # Store rule
        from datetime import datetime
        rules_storage[request.rule_id] = {
            "rule_id": request.rule_id,
            "provider": request.provider,
            "service": request.service,
            "title": request.title or template["name"],
            "description": request.description or template["description"],
            "remediation": request.remediation,
            "conditions": [c.model_dump() if hasattr(c, 'model_dump') else c for c in conditions],
            "logical_operator": logical_operator,
            "yaml_path": result.get("yaml_path"),
            "metadata_path": result.get("metadata_path"),
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "template_id": template_id
        }
        
        return {
            "rule_id": request.rule_id,
            "template_id": template_id,
            "status": "created",
            "result": result
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Update list_rules to support custom filter
@app.get("/api/v1/rules")
async def list_rules(
    provider: Optional[str] = None,
    service: Optional[str] = None,
    custom: Optional[bool] = None,
    created_after: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """List all generated rules, optionally filtered by provider, service, custom flag, and creation date"""
    filtered_rules = []
    
    for rule_id, rule_data in rules_storage.items():
        # Filter by provider
        if provider and rule_data.get("provider") != provider:
            continue
        # Filter by service
        if service and rule_data.get("service") != service:
            continue
        # Filter by custom flag
        if custom is not None:
            is_custom = "custom" in rule_id.lower() or rule_data.get("is_custom", False)
            if custom != is_custom:
                continue
        # Filter by creation date
        if created_after:
            created_at = rule_data.get("created_at", "")
            if created_at < created_after:
                continue
        
        filtered_rules.append({
            "rule_id": rule_id,
            "provider": rule_data.get("provider"),
            "service": rule_data.get("service"),
            "title": rule_data.get("title"),
            "created_at": rule_data.get("created_at"),
            "updated_at": rule_data.get("updated_at")
        })
    
    # Sort by created_at descending
    filtered_rules.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    
    return {
        "rules": filtered_rules[offset:offset+limit],
        "total": len(filtered_rules),
        "limit": limit,
        "offset": offset
    }


# ---------------------------------------------------------------------------
# Unified UI data endpoint
# ---------------------------------------------------------------------------

import logging as _logging

_ui_data_logger = _logging.getLogger(__name__)


@app.get("/api/v1/rules/ui-data")
async def rules_ui_data(
    tenant_id: Optional[str] = None,
    limit: int = 500,
):
    """Consolidated rule data for the frontend dashboard.

    Reads from the check DB's ``rule_metadata`` and ``rule_discoveries``
    tables — the authoritative source of truth — instead of the transient
    in-memory ``rules_storage`` dict.

    Args:
        tenant_id: Optional tenant filter (currently unused — rules are global).
        limit: Maximum number of sample rules to return.

    Returns:
        Dict with rules, total_rules, statistics, templates, and
        providers_status.
    """
    conn = None
    try:
        # 1. Provider status from filesystem catalog --------------------------
        try:
            providers_status = rule_builder_api.get_all_providers_status()
        except Exception as ps_err:
            _ui_data_logger.warning("Failed to load provider status: %s", ps_err)
            providers_status = {}

        # 2. Query rule_metadata + rule_discoveries from check DB -------------
        conn = _get_check_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # --- Total rules count -----------------------------------------------
        cur.execute("SELECT COUNT(*) AS cnt FROM rule_metadata")
        total_rules: int = cur.fetchone()["cnt"]

        # --- Rules by provider ------------------------------------------------
        cur.execute(
            "SELECT LOWER(provider) AS provider, COUNT(*) AS cnt "
            "FROM rule_metadata GROUP BY LOWER(provider) ORDER BY cnt DESC"
        )
        by_provider: Dict[str, int] = {
            row["provider"]: row["cnt"] for row in cur.fetchall()
        }

        # --- Rules by severity ------------------------------------------------
        cur.execute(
            "SELECT UPPER(severity) AS severity, COUNT(*) AS cnt "
            "FROM rule_metadata GROUP BY UPPER(severity) ORDER BY cnt DESC"
        )
        by_severity: Dict[str, int] = {
            row["severity"]: row["cnt"] for row in cur.fetchall()
        }

        # --- Rules by service (top 20) ----------------------------------------
        cur.execute(
            "SELECT service, COUNT(*) AS cnt "
            "FROM rule_metadata GROUP BY service "
            "ORDER BY cnt DESC LIMIT 20"
        )
        by_service: List[Dict[str, Any]] = [
            {"service": row["service"], "count": row["cnt"]}
            for row in cur.fetchall()
        ]

        # --- Rules by domain / subcategory ------------------------------------
        cur.execute(
            "SELECT COALESCE(domain, 'Uncategorized') AS domain, COUNT(*) AS cnt "
            "FROM rule_metadata GROUP BY COALESCE(domain, 'Uncategorized') "
            "ORDER BY cnt DESC"
        )
        by_domain: List[Dict[str, Any]] = [
            {"domain": row["domain"], "count": row["cnt"]}
            for row in cur.fetchall()
        ]

        # --- Active services from rule_discoveries ----------------------------
        cur.execute(
            "SELECT COUNT(*) AS cnt FROM rule_discoveries WHERE is_active = TRUE"
        )
        active_services: int = cur.fetchone()["cnt"]

        # --- Sample rules list ------------------------------------------------
        cur.execute(
            "SELECT rule_id, title, provider, service, severity, "
            "       domain, subcategory, threat_category, risk_score, "
            "       created_at, updated_at "
            "FROM rule_metadata "
            "ORDER BY created_at DESC NULLS LAST "
            "LIMIT %s",
            (limit,),
        )
        rules_list: List[Dict[str, Any]] = []
        for row in cur.fetchall():
            rules_list.append({
                "rule_id": row["rule_id"],
                "title": row["title"],
                "provider": row["provider"],
                "service": row["service"],
                "severity": row["severity"],
                "domain": row["domain"],
                "subcategory": row["subcategory"],
                "threat_category": row["threat_category"],
                "risk_score": row["risk_score"],
                "created_at": str(row["created_at"]) if row["created_at"] else None,
                "updated_at": str(row["updated_at"]) if row["updated_at"] else None,
            })

        cur.close()

        # 3. Templates --------------------------------------------------------
        try:
            templates_resp = await get_rule_templates()
            templates = templates_resp.get("templates", [])
        except Exception:
            templates = []

        return {
            "rules": rules_list,
            "total_rules": total_rules,
            "statistics": {
                "total": total_rules,
                "by_provider": by_provider,
                "by_severity": by_severity,
                "by_service": by_service,
                "by_domain": by_domain,
                "active_services": active_services,
            },
            "templates": templates,
            "providers_status": providers_status,
        }

    except Exception as exc:
        _ui_data_logger.error("rules/ui-data error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)

