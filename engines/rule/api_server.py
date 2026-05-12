"""
FastAPI server for YAML Rule Builder
"""
import os

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Request
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

# Initialize API — non-fatal if pythonsdk-database is missing (ui-data endpoint uses check DB directly)
try:
    rule_builder_api = RuleBuilderAPI()
except Exception as _rule_init_err:
    import logging as _log
    _log.getLogger(__name__).warning("RuleBuilderAPI unavailable: %s", _rule_init_err)
    rule_builder_api = None

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


# ── Response models (STORY-ENG-PYDANTIC-COVERAGE) ──────────────────────────


class _RuleBase(BaseModel):
    model_config = {"extra": "allow"}


class HealthResponse(BaseModel):
    status: str


class RuleLenientResponse(_RuleBase):
    """Catch-all for rule engine endpoints with heterogeneous JSON shapes."""


@app.get("/api/v1/providers", response_model=RuleLenientResponse, response_model_exclude_none=False)
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
        from datetime import datetime, timezone
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
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rules/{rule_id}")
async def get_rule(rule_id: str, request: Request):
    """Get specific rule details"""
    # Static sub-paths registered after this parameterized route — forward them here.
    if rule_id == "ui-data":
        return await rules_ui_data()
    if rule_id == "suppressions":
        return await list_suppressions(request)
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
        from datetime import datetime, timezone
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
            "updated_at": datetime.now(timezone.utc).isoformat()
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


# =============================================================================
# User Rules — stored in user_check_rules + user_check_discoveries (check DB)
# =============================================================================

class UserRuleRequest(BaseModel):
    """Payload sent by the Rule Builder wizard to persist a user-created rule."""
    rule_id: str
    service: str
    provider: str
    severity: str = "medium"
    category: Optional[str] = "configuration"
    title: str
    description: Optional[str] = ""
    for_each: str                           # discovery_id this rule iterates over
    conditions: Dict[str, Any]              # condition tree as JSON object
    condition_logic: str = "all"            # all | any
    frameworks: List[str] = []
    # Discovery fields
    discovery_id: str
    discovery_action: str                   # yaml_action / python_method
    discovery_items_for: Optional[str] = None
    discovery_item_fields: Dict[str, Any] = {}
    # Multi-tenancy
    tenant_id: Optional[str] = None
    customer_id: Optional[str] = None


class DuplicateCheckRequest(BaseModel):
    """Check whether any user rule already uses a given for_each value."""
    service: str
    provider: str
    for_each: str                           # discovery_id to check against
    tenant_id: Optional[str] = None


@app.post("/api/v1/user-rules/check-duplicate")
async def check_user_rule_duplicate(request: DuplicateCheckRequest):
    """Return any user_check_rules that already iterate over the same discovery."""
    try:
        conn = _get_check_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            clauses = [
                "service = %s", "provider = %s",
                "for_each = %s", "is_active = TRUE",
            ]
            params: list = [request.service, request.provider, request.for_each]
            if request.tenant_id:
                clauses.append("tenant_id = %s")
                params.append(request.tenant_id)

            cur.execute(
                f"SELECT rule_id, title, severity, created_at "
                f"FROM user_check_rules WHERE {' AND '.join(clauses)}",
                params,
            )
            rows = [dict(r) for r in cur.fetchall()]
            # Serialise datetimes
            for r in rows:
                if r.get("created_at"):
                    r["created_at"] = r["created_at"].isoformat()
            return {"duplicates": rows}
        finally:
            cur.close()
            conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/user-rules")
async def create_user_rule(request: UserRuleRequest):
    """
    Insert a user-created rule into user_check_rules and its discovery into
    user_check_discoveries.  Uses ON CONFLICT DO UPDATE so re-saving the same
    rule_id is idempotent (updates metadata, conditions).
    """
    try:
        conn = _get_check_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            # Build check_config compatible with the check engine expectation
            check_config = {
                "for_each": request.for_each,
                "conditions": request.conditions,
                "condition_logic": request.condition_logic,
            }

            # ── user_check_rules ────────────────────────────────────────────
            cur.execute(
                """
                INSERT INTO user_check_rules
                    (rule_id, service, provider, severity, category, title, description,
                     for_each, conditions, condition_logic, frameworks,
                     check_config, source, generated_by, tenant_id, customer_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'user','rule_builder',%s,%s)
                ON CONFLICT (rule_id, tenant_id) DO UPDATE SET
                    severity        = EXCLUDED.severity,
                    category        = EXCLUDED.category,
                    title           = EXCLUDED.title,
                    description     = EXCLUDED.description,
                    for_each        = EXCLUDED.for_each,
                    conditions      = EXCLUDED.conditions,
                    condition_logic = EXCLUDED.condition_logic,
                    frameworks      = EXCLUDED.frameworks,
                    check_config    = EXCLUDED.check_config,
                    updated_at      = NOW()
                RETURNING id, rule_id, created_at, updated_at
                """,
                (
                    request.rule_id, request.service, request.provider,
                    request.severity.lower(), request.category,
                    request.title, request.description,
                    request.for_each,
                    psycopg2.extras.Json(request.conditions),
                    request.condition_logic,
                    psycopg2.extras.Json(request.frameworks),
                    psycopg2.extras.Json(check_config),
                    request.tenant_id, request.customer_id,
                ),
            )
            rule_row = dict(cur.fetchone())

            # ── user_check_discoveries ──────────────────────────────────────
            discoveries_data = [
                {
                    "discovery_id": request.discovery_id,
                    "calls": [
                        {
                            "action": request.discovery_action,
                            "save_as": "response",
                            "on_error": "continue",
                        }
                    ],
                    "emit": {
                        "as": "item",
                        "items_for": request.discovery_items_for,
                        "item": request.discovery_item_fields,
                    },
                }
            ]
            cur.execute(
                """
                INSERT INTO user_check_discoveries
                    (discovery_id, service, provider, action, items_for, item_fields,
                     discoveries_data, source, generated_by, tenant_id, customer_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,'user','rule_builder',%s,%s)
                ON CONFLICT (discovery_id, tenant_id) DO NOTHING
                RETURNING id, discovery_id, created_at
                """,
                (
                    request.discovery_id, request.service, request.provider,
                    request.discovery_action, request.discovery_items_for,
                    psycopg2.extras.Json(request.discovery_item_fields),
                    psycopg2.extras.Json(discoveries_data),
                    request.tenant_id, request.customer_id,
                ),
            )
            disc_result = cur.fetchone()
            disc_row = dict(disc_result) if disc_result else {"discovery_id": request.discovery_id}

            conn.commit()

            # Serialise datetimes
            for row in (rule_row, disc_row):
                for k in ("created_at", "updated_at"):
                    if row.get(k) and hasattr(row[k], "isoformat"):
                        row[k] = row[k].isoformat()

            return {
                "success": True,
                "rule": rule_row,
                "discovery": disc_row,
                "message": f"Rule '{request.rule_id}' saved to user_check_rules",
            }
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/user-rules")
async def list_user_rules(
    provider: Optional[str] = None,
    service: Optional[str] = None,
    tenant_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
):
    """List user-created rules from user_check_rules, newest first."""
    try:
        conn = _get_check_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            clauses = ["is_active = TRUE"]
            params: list = []
            if provider:
                clauses.append("provider = %s")
                params.append(provider)
            if service:
                clauses.append("service = %s")
                params.append(service)
            if tenant_id:
                clauses.append("tenant_id = %s")
                params.append(tenant_id)

            cur.execute(
                f"SELECT * FROM user_check_rules WHERE {' AND '.join(clauses)} "
                f"ORDER BY created_at DESC LIMIT %s OFFSET %s",
                params + [limit, offset],
            )
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                for k in ("created_at", "updated_at"):
                    if r.get(k) and hasattr(r[k], "isoformat"):
                        r[k] = r[k].isoformat()
            return {"rules": rows, "total": len(rows)}
        finally:
            cur.close()
            conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Rule Suppressions — per-tenant / per-account suppression of rules/services/techs
# =============================================================================

VALID_SCOPE_TYPES = {"rule", "service", "technology", "provider"}


class SuppressRequest(BaseModel):
    """Payload to create a rule suppression."""
    scope_level: Literal["tenant", "account"] = "tenant"
    account_id: Optional[str] = None           # required when scope_level='account'
    scope_type: str                            # rule | service | technology | provider
    scope_value: str                           # rule_id | service | tech_category | provider
    provider: Optional[str] = None            # None = all providers
    reason: Optional[str] = None
    expires_at: Optional[str] = None          # ISO 8601 or None for permanent


class SuppressionOut(BaseModel):
    """Suppression record returned by list/create."""
    model_config = {"extra": "allow"}


def _parse_auth_ctx(request: Request) -> dict:
    """Parse X-Auth-Context header into a plain dict. Returns {} if missing/invalid."""
    import json as _json
    raw = request.headers.get("X-Auth-Context") or request.headers.get("x-auth-context")
    if not raw:
        return {}
    try:
        return _json.loads(raw)
    except Exception:
        return {}


def _tenant_from_header(request: Request) -> str:
    """Extract tenant_id from X-Auth-Context header. Raises 401 if missing."""
    active = request.headers.get("x-active-tenant-id") or request.headers.get("X-Active-Tenant-Id")
    if active:
        return active
    ctx = _parse_auth_ctx(request)
    if ctx:
        tid = ctx.get("engine_tenant_id") or (ctx.get("tenant_ids") or [None])[0]
        if tid:
            return tid
    raise HTTPException(status_code=401, detail="Authentication required — no tenant context")


def _require_permission(request: Request, permission: str) -> None:
    """Raise 403 if the authenticated user does not hold the given permission.

    permission 'rules:read'  → analyst, tenant_admin, org_admin, platform_admin
    permission 'rules:write' → tenant_admin, org_admin, platform_admin
    """
    ctx = _parse_auth_ctx(request)
    permissions: list = ctx.get("permissions") or []
    role: str = ctx.get("role") or ""
    # Viewer has no suppression access at all
    if role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot manage suppressions")
    if permission and permission not in permissions:
        raise HTTPException(
            status_code=403,
            detail=f"Permission '{permission}' required for this action",
        )


# Only org_admin and platform_admin may create/lift suppressions
_SUPPRESS_ADMIN_ROLES = {"org_admin", "platform_admin"}


def _require_suppress_admin(request: Request) -> None:
    """Raise 403 unless the caller is org_admin or platform_admin."""
    ctx = _parse_auth_ctx(request)
    role: str = ctx.get("role") or ""
    if role not in _SUPPRESS_ADMIN_ROLES:
        raise HTTPException(
            status_code=403,
            detail="Only org_admin or platform_admin can manage suppressions",
        )


def _suppressed_by_from_header(request: Request) -> tuple[str, str]:
    """Return (suppressed_by_email_or_id, role) from the auth context."""
    ctx = _parse_auth_ctx(request)
    user = ctx.get("user_email") or ctx.get("email") or ctx.get("user_id") or "unknown"
    role = ctx.get("role") or "unknown"
    return user, role


@app.post("/api/v1/rules/suppress")
async def create_suppression(request: Request, body: SuppressRequest):
    """Create a tenant-wide or account-level rule suppression. Requires org_admin or platform_admin."""
    _require_suppress_admin(request)
    tenant_id = _tenant_from_header(request)

    if body.scope_type not in VALID_SCOPE_TYPES:
        raise HTTPException(status_code=400, detail=f"scope_type must be one of {VALID_SCOPE_TYPES}")
    if not body.scope_value or not body.scope_value.strip():
        raise HTTPException(status_code=400, detail="scope_value is required")
    if body.scope_level == "account" and not body.account_id:
        raise HTTPException(status_code=400, detail="account_id is required when scope_level='account'")

    account_id = body.account_id if body.scope_level == "account" else None
    suppressed_by, _role = _suppressed_by_from_header(request)

    try:
        conn = _get_check_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cur.execute(
                """
                INSERT INTO rule_suppressions
                    (tenant_id, account_id, scope_type, scope_value, provider,
                     reason, suppressed_by, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s,
                        %s::timestamptz)
                ON CONFLICT (tenant_id, COALESCE(account_id, ''), scope_type, scope_value, COALESCE(provider, ''))
                    DO UPDATE SET
                        reason        = EXCLUDED.reason,
                        suppressed_by = EXCLUDED.suppressed_by,
                        suppressed_at = now(),
                        expires_at    = EXCLUDED.expires_at
                RETURNING id, tenant_id, account_id, scope_type, scope_value,
                          provider, reason, suppressed_by, suppressed_at, expires_at
                """,
                (
                    tenant_id, account_id, body.scope_type, body.scope_value.strip(),
                    body.provider, body.reason, suppressed_by, body.expires_at,
                ),
            )
            row = dict(cur.fetchone())
            conn.commit()
            for k in ("suppressed_at", "expires_at"):
                if row.get(k) and hasattr(row[k], "isoformat"):
                    row[k] = row[k].isoformat()
            row["id"] = str(row["id"])
            return {"success": True, "suppression": row}
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/v1/rules/suppressions")
async def list_suppressions(
    request: Request,
    include_expired: bool = False,
):
    """List active rule-scope suppressions for the authenticated tenant. Requires rules:read."""
    _require_permission(request, "rules:read")
    tenant_id = _tenant_from_header(request)

    try:
        conn = _get_check_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            expiry_clause = "" if include_expired else "AND (expires_at IS NULL OR expires_at > now())"
            cur.execute(
                f"""
                SELECT id, tenant_id, account_id, scope_type, scope_value,
                       provider, reason, suppressed_by, suppressed_at, expires_at
                FROM   rule_suppressions
                WHERE  tenant_id = %s
                  {expiry_clause}
                ORDER  BY suppressed_at DESC
                """,
                (tenant_id,),
            )
            rows = []
            for r in cur.fetchall():
                row = dict(r)
                row["id"] = str(row["id"])
                for k in ("suppressed_at", "expires_at"):
                    if row.get(k) and hasattr(row[k], "isoformat"):
                        row[k] = row[k].isoformat()
                row["scope_level"] = "account" if row.get("account_id") else "tenant"
                rows.append(row)

            tenant_wide = sum(1 for r in rows if r["scope_level"] == "tenant")
            account_level = len(rows) - tenant_wide
            from datetime import datetime, timezone, timedelta
            soon = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
            expiring_soon = sum(
                1 for r in rows
                if r.get("expires_at") and r["expires_at"] <= soon
            )

            return {
                "suppressions": rows,
                "total": len(rows),
                "kpi": {
                    "tenant_wide": tenant_wide,
                    "account_level": account_level,
                    "expiring_soon": expiring_soon,
                    "by_scope_type": {
                        st: sum(1 for r in rows if r["scope_type"] == st)
                        for st in VALID_SCOPE_TYPES
                    },
                },
            }
        finally:
            cur.close()
            conn.close()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.delete("/api/v1/rules/suppressions/{suppression_id}")
async def delete_suppression(request: Request, suppression_id: str):
    """Lift (remove) a rule-scope suppression. Requires org_admin or platform_admin."""
    _require_suppress_admin(request)
    tenant_id = _tenant_from_header(request)

    try:
        conn = _get_check_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cur.execute(
                "SELECT id FROM rule_suppressions WHERE id = %s::uuid AND tenant_id = %s",
                (suppression_id, tenant_id),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Suppression not found or not in your tenant")
            cur.execute(
                "DELETE FROM rule_suppressions WHERE id = %s::uuid AND tenant_id = %s",
                (suppression_id, tenant_id),
            )
            conn.commit()
            return {"success": True, "deleted_id": suppression_id}
        except HTTPException:
            conn.rollback()
            raise
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# =============================================================================
# Finding Suppressions — resource-level (analyst+)
# =============================================================================


class FindingSuppressRequest(BaseModel):
    """Payload to suppress a specific resource-level finding."""
    account_id:  str                   # required — always account-scoped
    rule_id:     str                   # rule that produced the finding
    resource_uid: Optional[str] = None # specific resource ARN/ID; None = all resources for rule in account
    finding_id:  Optional[str] = None  # sha256 finding_id from check_findings (most precise)
    reason:      Optional[str] = None
    expires_at:  Optional[str] = None  # ISO 8601


@app.post("/api/v1/findings/suppress")
async def create_finding_suppression(request: Request, body: FindingSuppressRequest):
    """Suppress a specific finding at resource level. Requires org_admin or platform_admin."""
    _require_suppress_admin(request)
    tenant_id = _tenant_from_header(request)
    suppressed_by, role = _suppressed_by_from_header(request)

    if not body.account_id or not body.account_id.strip():
        raise HTTPException(status_code=400, detail="account_id is required")
    if not body.rule_id or not body.rule_id.strip():
        raise HTTPException(status_code=400, detail="rule_id is required")

    try:
        conn = _get_check_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cur.execute(
                """
                INSERT INTO finding_suppressions
                    (tenant_id, account_id, rule_id, resource_uid, finding_id,
                     reason, suppressed_by, suppressed_by_role, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::timestamptz)
                ON CONFLICT (tenant_id, account_id, rule_id,
                             COALESCE(resource_uid, ''), COALESCE(finding_id, ''))
                    DO UPDATE SET
                        reason             = EXCLUDED.reason,
                        suppressed_by      = EXCLUDED.suppressed_by,
                        suppressed_by_role = EXCLUDED.suppressed_by_role,
                        suppressed_at      = now(),
                        expires_at         = EXCLUDED.expires_at
                RETURNING id, tenant_id, account_id, rule_id, resource_uid, finding_id,
                          reason, suppressed_by, suppressed_by_role, suppressed_at, expires_at
                """,
                (
                    tenant_id, body.account_id.strip(), body.rule_id.strip(),
                    body.resource_uid, body.finding_id,
                    body.reason, suppressed_by, role, body.expires_at,
                ),
            )
            row = dict(cur.fetchone())
            conn.commit()
            row["id"] = str(row["id"])
            for k in ("suppressed_at", "expires_at"):
                if row.get(k) and hasattr(row[k], "isoformat"):
                    row[k] = row[k].isoformat()
            return {"success": True, "suppression": row, "suppression_type": "finding"}
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/v1/findings/suppressions")
async def list_finding_suppressions(
    request: Request,
    account_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    include_expired: bool = False,
):
    """List finding-level suppressions for the authenticated tenant. Requires rules:read."""
    _require_permission(request, "rules:read")
    tenant_id = _tenant_from_header(request)

    try:
        conn = _get_check_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            clauses = ["tenant_id = %s"]
            params: list = [tenant_id]
            if account_id:
                clauses.append("account_id = %s")
                params.append(account_id)
            if rule_id:
                clauses.append("rule_id = %s")
                params.append(rule_id)
            if not include_expired:
                clauses.append("(expires_at IS NULL OR expires_at > now())")

            cur.execute(
                f"SELECT * FROM finding_suppressions WHERE {' AND '.join(clauses)} ORDER BY suppressed_at DESC",
                params,
            )
            rows = []
            for r in cur.fetchall():
                row = dict(r)
                row["id"] = str(row["id"])
                for k in ("suppressed_at", "expires_at"):
                    if row.get(k) and hasattr(row[k], "isoformat"):
                        row[k] = row[k].isoformat()
                row["suppression_type"] = "finding"
                rows.append(row)

            from datetime import datetime, timezone, timedelta
            soon = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
            return {
                "suppressions": rows,
                "total": len(rows),
                "kpi": {
                    "total": len(rows),
                    "expiring_soon": sum(
                        1 for r in rows if r.get("expires_at") and r["expires_at"] <= soon
                    ),
                    "resource_specific": sum(1 for r in rows if r.get("resource_uid")),
                    "rule_in_account": sum(1 for r in rows if not r.get("resource_uid")),
                },
            }
        finally:
            cur.close()
            conn.close()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.delete("/api/v1/findings/suppressions/{suppression_id}")
async def delete_finding_suppression(request: Request, suppression_id: str):
    """Lift a finding suppression.
    rules:read → analyst can lift their own.
    rules:write → tenant_admin+ can lift anyone's.
    """
    _require_permission(request, "rules:read")
    tenant_id = _tenant_from_header(request)
    ctx = _parse_auth_ctx(request)
    can_lift_any = "rules:write" in (ctx.get("permissions") or [])
    current_user, _role = _suppressed_by_from_header(request)

    try:
        conn = _get_check_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cur.execute(
                "SELECT id, suppressed_by FROM finding_suppressions WHERE id = %s::uuid AND tenant_id = %s",
                (suppression_id, tenant_id),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Finding suppression not found")
            if not can_lift_any and dict(row).get("suppressed_by") != current_user:
                raise HTTPException(status_code=403, detail="You can only lift your own suppressions")
            cur.execute(
                "DELETE FROM finding_suppressions WHERE id = %s::uuid AND tenant_id = %s",
                (suppression_id, tenant_id),
            )
            conn.commit()
            return {"success": True, "deleted_id": suppression_id}
        except HTTPException:
            conn.rollback()
            raise
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# =============================================================================
# Health checks
# =============================================================================

@app.get("/api/v1/health/live", response_model=HealthResponse)
async def liveness_check():
    """Kubernetes liveness probe — no DB, no external calls."""
    return {"status": "ok", "service": "yaml-rule-builder"}


@app.get("/api/v1/health/ready", response_model=HealthResponse)
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


@app.get("/api/v1/health", response_model=RuleLenientResponse, response_model_exclude_none=False)
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

@app.get("/api/v1/rules/search", response_model=RuleLenientResponse, response_model_exclude_none=False)
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


@app.get("/api/v1/rules/statistics", response_model=RuleLenientResponse, response_model_exclude_none=False)
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
        from datetime import datetime, timezone
        copied_rule = original_rule.copy()
        copied_rule["rule_id"] = new_rule_id
        copied_rule["title"] = f"{copied_rule.get('title', 'Rule')} (Copy)"
        copied_rule["created_at"] = datetime.now(timezone.utc).isoformat()
        copied_rule["updated_at"] = datetime.now(timezone.utc).isoformat()
        
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
                from datetime import datetime, timezone
                rule_data["yaml_path"] = result.get("yaml_path")
                rule_data["metadata_path"] = result.get("metadata_path")
                rule_data["created_at"] = rule_data.get("created_at") or datetime.now(timezone.utc).isoformat()
                rule_data["updated_at"] = datetime.now(timezone.utc).isoformat()
                
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
        from datetime import datetime, timezone
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
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
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
@app.get("/api/v1/rules", response_model=RuleLenientResponse, response_model_exclude_none=False)
async def list_rules(
    request: Request,
    provider: Optional[str] = None,
    service: Optional[str] = None,
    custom: Optional[bool] = None,
    created_after: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """List all generated rules, optionally filtered by provider, service, custom flag, and creation date"""
    # Fetch suppressed rule_ids for current tenant to annotate is_suppressed
    suppressed_rule_ids: set = set()
    try:
        tenant_id = _tenant_from_header(request)
        if tenant_id:
            conn = _get_check_db_connection()
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT scope_value FROM rule_suppressions "
                    "WHERE tenant_id = %s AND scope_type = 'rule' "
                    "AND (expires_at IS NULL OR expires_at > now())",
                    (tenant_id,),
                )
                suppressed_rule_ids = {row[0] for row in cur.fetchall()}
            finally:
                cur.close()
                conn.close()
    except Exception:
        pass  # suppression lookup is best-effort; don't break the rules list

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
            "updated_at": rule_data.get("updated_at"),
            "is_suppressed": rule_id in suppressed_rule_ids,
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


@app.get("/api/v1/rules/ui-data", response_model=RuleLenientResponse, response_model_exclude_none=False)
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

