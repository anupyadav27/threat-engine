"""
Deterministic contract matcher — replaces LLM field-correlation with Python logic.

Applies semantic matching rules:
  - snake_case ↔ camelCase normalization
  - Array path inference  (orgs[].org_id  → BFF has orgs + engine has org_id)
  - Nested path inference (pagination.total → BFF has pagination + engine has total)
  - Special prefix stripping ([chart:dataKey], [table:col], [filter:key])
  - JSONB coverage (any child of a JSONB column is implicitly covered)
  - Passthrough inference (BFF passes list from engine → engine model fields are covered)
  - Computed/aggregated fields skip DB-column requirement

Returns FieldGap objects with severity populated but suggestion left empty.
The caller fills suggestion via a cheap LLM call on confirmed gaps only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ── Computed / aggregated fields that never need a DB column ─────────────────

_COMPUTED: frozenset[str] = frozenset({
    # billing
    "monthly_amount_usd", "total_billable", "avg_billable_30d",
    # scores / ratios
    "coverage_score", "compliance_score", "risk_score", "risk_level",
    "blast_radius_score", "exposure_score", "posture_score",
    # counts
    "total_orgs", "total_findings", "total_accounts", "total_resources",
    "total_scans", "total_pipelines", "total_rules",
    "critical_count", "high_count", "medium_count", "low_count", "info_count",
    "passed_count", "failed_count", "error_count", "warning_count",
    "breaking_count", "open_count", "closed_count",
    # pagination
    "total", "page", "page_size", "total_pages",
    # derived display
    "status_color", "severity_color", "latency_ms", "age_days",
    "duration_seconds", "pod_count", "last_checked", "version",
    # metrics
    "trials_expiring_7d", "past_due_orgs", "active_pipelines",
    "total_scans_this_month", "orgs_by_tier",
    # severity-level aggregation counts (chart series / KPI cards)
    "critical", "high", "medium", "low", "info", "informational",
    # date/time chart axis values (aggregated per period)
    "date", "week", "month", "day", "hour",
    # chart rendering pass-rate / score series
    "pass_rate", "passRate", "pass_score", "passScore", "score",
    # Recharts Radar chart axis label + reference line (never a BFF field)
    "subject", "target",
    # Generic count (computed in BFF aggregation — no DB column needed)
    "count",
    # Pass / fail / failing counts (always derived from findings aggregation)
    "fail", "pass", "fail_count", "pass_count", "failing_count", "passing_count",
    "failed", "passed", "fail_rate", "pass_rate_pct",
    # Resource identifier aliases
    "resource_arn",   # alias for resource_uid in AWS — derived from ARN parsing
    # Family / group name (derived from category grouping)
    "family", "family_name",
    # IAM identity / role display fields — BFF-assembled from engine identity data
    "account",           # display alias for account_id in CSPM UI tables
    "mfa",               # boolean identity attribute (has MFA enabled)
    "username",          # BFF-assembled identity display name
    "user",              # BFF-assembled role / resource user name
    "posture_category",  # derived category classification label
    "auto_remediable",   # rule-level boolean from rule_metadata JSONB
    # Billing / Stripe API pass-through fields (not stored in engine DB)
    "amount",            # Stripe invoice amount
    "currency",          # Stripe invoice currency
    "hosted_invoice_url",  # Stripe invoice URL
    "checkout_url",      # Stripe checkout session URL (dynamically generated, not BFF view data)
    "tier",              # subscription tier (derived from plan_name, not a raw DB column)
    # FAIR risk model computed outputs (derived from multiple DB columns)
    "expected_loss",     # BFF/engine computed monetary loss (primary_loss_likely × probability)
})

# ── Container/aggregated response keys — never have a direct DB column ────────
#
# These are list/object top-level response keys assembled by the engine from
# DB rows.  The DB backing is through individual columns on the child rows,
# not a single column named "orgs" or "pricing".

_SKIP_DB_CHECK: frozenset[str] = frozenset({
    "orgs", "accounts", "findings", "items", "results", "records", "rows",
    "csv_rows", "pricing", "pagination", "metrics", "scenarios", "engines",
    "filters", "networks", "resources", "policies", "rules", "users",
    "tenants", "frameworks", "controls", "domains", "services", "clusters",
    "nodes", "edges", "paths", "groups", "tags", "labels", "permissions",
    "mismatches", "layers", "summary", "charts", "trends", "pulse_stats",
    "attack_paths", "techniques", "assets", "vulnerabilities", "alerts",
    "events", "checks", "scan_runs", "reports", "exports", "snapshots",
    # billing / subscription response keys
    "subscription", "invoices", "invoice", "usage", "checkout",
    "payment_method", "payment_methods", "stripe",
    # IAM/identity sub-objects
    "identities", "roles", "access_keys", "mfa_config",
    # topology / network sub-objects
    "topology", "security_groups", "waf", "load_balancers",
    # kpi / cards aggregation keys
    "kpi_groups", "kpiGroups", "kpis", "cards",
    # scan context / page context
    "scan_context", "pageContext", "page_context",
    # IAM sub-modules (aggregated from findings, not direct DB columns)
    "privilegeEscalation", "privilege_escalation", "scanTrend", "scan_trend",
    "serviceAccounts", "service_accounts", "findingsByModule", "findings_by_module",
    # Network security aggregation keys
    "activeModuleScores", "active_module_scores", "domainBreakdown", "domain_breakdown",
    "internet_exposure",
    # Nested summary sub-fields (assembled by BFF)
    "by_service", "byService", "severity_counts", "status_counts", "top_rules",
    "by_module", "by_severity", "by_account", "by_region",
    # Compliance BFF-assembled arrays and SQL-alias fields
    "ciem_checks", "config_checks",
    "filteredControls", "filtered_controls",
    "modes",
    "control_id", "control_name",   # SQL aliases for requirement_id / requirement_name
    # Billing BFF response keys
    "banner",
    "plans",
})

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class FieldGap:
    field_path: str
    layer_from: str     # "UI" | "BFF" | "Engine"
    layer_to: str       # "BFF" | "Engine" | "DB"
    issue: str          # "missing_in_target" | "extra_allow_gap"
    severity: str       # "breaking" | "warning" | "info"
    suggestion: str = ""


# ── Name normalization ────────────────────────────────────────────────────────

def _to_snake(name: str) -> str:
    s1 = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def _to_camel(snake: str) -> str:
    parts = snake.split('_')
    return parts[0] + ''.join(p.title() for p in parts[1:])


def _aliases(name: str) -> frozenset[str]:
    """All equivalent forms of a field name (lower, snake, camel)."""
    lo = name.lower()
    snake = _to_snake(name)
    camel = _to_camel(snake)
    return frozenset({lo, snake, camel.lower()})


def _norm_set(fields: list[str]) -> frozenset[str]:
    """Flat set of all aliases for a list of field names."""
    out: set[str] = set()
    for f in fields:
        out.update(_aliases(f))
    return frozenset(out)


def _matches(name: str, norm: frozenset[str]) -> bool:
    return bool(_aliases(name) & norm)


def _is_computed(name: str) -> bool:
    return _to_snake(name) in _COMPUTED or name.lower() in _COMPUTED


# ── Field path parsing ────────────────────────────────────────────────────────

def _strip_prefix(raw: str) -> tuple[str, str]:
    """
    Strip [chart:dataKey] / [table:col] / [filter:key] prefix.
    Returns (bare_field, prefix_type).  prefix_type = "" when none.
    """
    m = re.match(r'^\[(\w+):\w+\]\s+(\S+)$', raw)
    if m:
        return m.group(2), m.group(1)
    return raw, ""


def _parse_array_path(path: str) -> tuple[str, str]:
    """
    Parse 'arr[].item_field'.  Returns (array_name, item_field) or ("", path).
    """
    m = re.match(r'^(\w+)\[\]\.(\w+)$', path)
    if m:
        return m.group(1), m.group(2)
    return "", path


def _parse_nested_path(path: str) -> tuple[str, str]:
    """
    Parse 'parent.child'.  Returns (parent, child) or ("", path).
    Dots inside [] are not nested paths.
    """
    if '[' in path or path.count('.') == 0:
        return "", path
    parent, _, child = path.partition('.')
    return parent, child


# ── Core coverage logic ───────────────────────────────────────────────────────

def _bff_covers(
    bare: str,
    bff_norm: frozenset[str],
    bff_fields_raw: list[str],
    engine_norm: frozenset[str],
    array_name: str,
    item_field: str,
    prefix_type: str = "",
    db_norm: frozenset[str] = frozenset(),
    jsonb_norm: frozenset[str] = frozenset(),
) -> bool:
    """Return True if BFF definitively covers this UI field."""

    # Computed/aggregated fields never need a BFF field declaration
    check = item_field if array_name else bare
    if _is_computed(check):
        return True

    # Filter-key fields only require that BFF exposes `filterSchema` — the key
    # names themselves are parameter labels, not response data fields.
    if prefix_type == "filter":
        return _matches("filterSchema", bff_norm) or _matches("filter_schema", bff_norm)

    # Table-column fields come from engine/DB rows — if the engine or DB declares
    # the field, the BFF implicitly returns it through the data array.
    if prefix_type == "table" and not array_name:
        if (
            _matches(check, engine_norm) or _matches(check, db_norm)
            or _matches(check, jsonb_norm)
        ):
            return True
        # Table accessorKey fields from BFF-assembled container arrays are always covered
        if _to_snake(check) in _SKIP_DB_CHECK or check in _SKIP_DB_CHECK:
            return True

    if array_name:
        # orgs[].org_id — BFF must expose the array key,
        # and either has an explicit nested path or the engine provides the item field.
        if not _matches(array_name, bff_norm):
            return False
        # BFF-assembled arrays (identities[], ciem_checks[], etc.) cover all item fields
        if _to_snake(array_name) in _SKIP_DB_CHECK or array_name in _SKIP_DB_CHECK:
            return True
        # Check explicit nested path in BFF fields (e.g. "orgs.org_id")
        nested_variants = {
            f"{array_name}.{item_field}".lower(),
            f"{_to_snake(array_name)}.{_to_snake(item_field)}".lower(),
            f"{array_name}[].{item_field}".lower(),
        }
        if nested_variants & {f.lower() for f in bff_fields_raw}:
            return True
        # Passthrough inference: engine model declares item_field
        if _matches(item_field, engine_norm):
            return True
        # Computed item fields (e.g. age_days in a findings list)
        if _is_computed(item_field):
            return True
        # DB passthrough: item field is a regular or JSONB column in the backing DB
        # (e.g. findings[].compliance_frameworks from check_findings.compliance_frameworks JSONB)
        if _matches(item_field, db_norm) or _matches(item_field, jsonb_norm):
            return True
        return False

    # Simple field or nested path
    if _matches(bare, bff_norm):
        return True

    # Nested path: pagination.total  /  summary.by_service
    parent, child = _parse_nested_path(bare)
    if parent and _matches(parent, bff_norm):
        # Parent is a known aggregation container — all children are BFF-assembled
        if _to_snake(parent) in _SKIP_DB_CHECK or parent in _SKIP_DB_CHECK:
            return True
        if (
            _matches(child, bff_norm) or _matches(child, engine_norm)
            or _matches(child, db_norm) or _matches(child, jsonb_norm)
            or _is_computed(child)
        ):
            return True

    return False


def _engine_covers(check_field: str, engine_norm: frozenset[str], has_extra_allow: bool) -> bool:
    if _is_computed(check_field):
        return True
    return _matches(check_field, engine_norm)


def _db_covers(
    bare: str,
    check_field: str,
    db_norm: frozenset[str],
    jsonb_norm: frozenset[str],
    is_array: bool,
) -> bool:
    if _is_computed(check_field):
        return True
    # Array item fields come from joins — engine model is authoritative
    if is_array:
        return True
    # Container/aggregated response keys (list/nested objects in response)
    if _to_snake(check_field) in _SKIP_DB_CHECK:
        return True
    # Nested path handling (e.g. subscription.status)
    parent, child = _parse_nested_path(bare)
    if parent:
        if _matches(parent, jsonb_norm):
            return True
        if _to_snake(parent) in _SKIP_DB_CHECK:
            return True
        # For nested paths, check the leaf field (child) against DB columns
        # e.g. subscription.status → check if 'status' is a DB column
        return _matches(child, db_norm)
    # Direct JSONB column
    if _matches(bare, jsonb_norm):
        return True
    # Simple field — check directly
    return _matches(bare, db_norm)


# ── Main entry point ──────────────────────────────────────────────────────────

def diff_layers(
    ui_data: dict,
    bff_data: dict,
    engine_data: dict,
    db_data: dict,
) -> list[FieldGap]:
    """
    Deterministically find contract gaps across UI → BFF → Engine → DB.

    Returns FieldGap list (suggestion="" on each — caller fills via LLM).
    """
    bff_fields_raw: list[str] = bff_data.get("fields", [])
    engine_fields: list[str]  = engine_data.get("fields", [])
    db_columns: list[str]     = db_data.get("columns", [])
    jsonb_columns: list[str]  = db_data.get("jsonb_columns", [])
    has_extra_allow: bool      = engine_data.get("has_extra_allow", False)

    bff_norm    = _norm_set(bff_fields_raw)
    engine_norm = _norm_set(engine_fields)
    db_norm     = _norm_set(db_columns)
    jsonb_norm  = _norm_set(jsonb_columns)

    # Combine all UI fields with their category
    all_ui: list[tuple[str, str]] = (
        [(f, "object") for f in ui_data.get("object_fields", [])]
        + [(f, "chart")  for f in ui_data.get("chart_fields", [])]
        + [(f, "table")  for f in ui_data.get("table_columns", [])]
        + [(f, "filter") for f in ui_data.get("filter_keys", [])]
    )

    # Pre-compute: bare item field names that are already covered as array paths.
    # e.g. "orgs[].org_id" being covered means bare "org_id" isn't a real UI→BFF gap.
    covered_as_array_item: set[str] = set()
    for raw, _ in all_ui:
        bare_, pfx_ = _strip_prefix(raw)
        arr, item = _parse_array_path(bare_)
        if arr and item:
            if _bff_covers(bare_, bff_norm, bff_fields_raw, engine_norm, arr, item,
                           pfx_, db_norm, jsonb_norm):
                covered_as_array_item.add(item.lower())
                covered_as_array_item.update(_aliases(item))

    gaps: list[FieldGap] = []
    seen: set[str] = set()

    for raw_field, _category in all_ui:
        bare, _prefix_type = _strip_prefix(raw_field)
        array_name, item_field = _parse_array_path(bare)
        is_array = bool(array_name)

        # For nested paths (parent.child), use child for engine/DB checks
        parent_nested, child_nested = _parse_nested_path(bare)
        if parent_nested and not is_array:
            check_field = child_nested
        else:
            check_field = item_field if is_array else bare

        # ── UI → BFF ─────────────────────────────────────────────────────────
        bff_ok = _bff_covers(bare, bff_norm, bff_fields_raw, engine_norm, array_name, item_field,
                             _prefix_type, db_norm, jsonb_norm)

        if not bff_ok:
            # Suppress false positive: this bare field is already covered as
            # an array item path elsewhere in the UI fields list.
            if bare.lower() in covered_as_array_item:
                continue

            gap_key = f"UI→BFF:{raw_field}"
            if gap_key not in seen:
                seen.add(gap_key)
                gaps.append(FieldGap(
                    field_path=raw_field,
                    layer_from="UI", layer_to="BFF",
                    issue="missing_in_target",
                    severity="breaking",
                ))
            continue   # can't check further layers without BFF coverage

        # BFF-assembled arrays (SKIP_DB_CHECK): item fields are fully owned by BFF
        # assembly logic — no engine Pydantic model or DB column required.
        if is_array and (
            _to_snake(array_name) in _SKIP_DB_CHECK or array_name in _SKIP_DB_CHECK
        ):
            continue

        # ── BFF → Engine ──────────────────────────────────────────────────────
        engine_ok = _engine_covers(check_field, engine_norm, has_extra_allow)

        # DB passthrough inference: engine implicitly covers fields that are DB
        # columns / JSONB entries (engine reads from DB and returns raw dicts).
        if not engine_ok and (
            _matches(check_field, db_norm) or _matches(check_field, jsonb_norm)
        ):
            engine_ok = True

        # Container/aggregation keys have no engine Pydantic declaration —
        # they are assembled from DB rows and returned as response-level keys.
        if not engine_ok and (
            _to_snake(check_field) in _SKIP_DB_CHECK or check_field in _SKIP_DB_CHECK
        ):
            engine_ok = True

        # Nested path where parent is a BFF-assembled container — child is always covered
        if not engine_ok and parent_nested and (
            _to_snake(parent_nested) in _SKIP_DB_CHECK or parent_nested in _SKIP_DB_CHECK
        ):
            engine_ok = True

        # Filter-key schema fields never need explicit engine model coverage.
        if not engine_ok and _prefix_type == "filter":
            engine_ok = True

        gap_key = f"BFF→Engine:{raw_field}"
        if not engine_ok and gap_key not in seen:
            seen.add(gap_key)
            issue = "extra_allow_gap" if has_extra_allow else "missing_in_target"
            sev   = "warning"         if has_extra_allow else "breaking"
            gaps.append(FieldGap(
                field_path=raw_field,
                layer_from="BFF", layer_to="Engine",
                issue=issue, severity=sev,
            ))
            continue

        # ── Engine → DB ───────────────────────────────────────────────────────
        # Filter keys are UI-parameter labels, not DB columns — skip DB check.
        if _prefix_type == "filter":
            continue

        # Table-column fields: engine model is authoritative. If engine declares
        # the field (even if computed from multiple DB columns), DB check is satisfied.
        if _prefix_type == "table" and engine_ok:
            continue

        db_ok = _db_covers(bare, check_field, db_norm, jsonb_norm, is_array)

        gap_key = f"Engine→DB:{raw_field}"
        if not db_ok and gap_key not in seen:
            seen.add(gap_key)
            gaps.append(FieldGap(
                field_path=raw_field,
                layer_from="Engine", layer_to="DB",
                issue="missing_in_target",
                severity="warning",  # engine can join/compute; not always breaking
            ))

    return gaps
