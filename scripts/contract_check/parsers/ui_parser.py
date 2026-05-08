"""
UI Parser — extracts field accesses from Next.js JSX/TSX components.

Covers all field-access patterns in this codebase:

  OBJECT FIELDS
    data.field / data?.field
    Destructuring: const { field1, field2 } = data
    Nested:        data.pulse_stats.critical_count

  CHART FIELDS (Recharts)
    dataKey="field"                    → Bar, Line, Area, Cell, XAxis, YAxis
    dataKey={variable}                 → dynamic series keys (logged as note)
    <BarChartComponent data={...} />   → prop-passed data shape

  TABLE FIELDS (TanStack React Table)
    accessorKey: "field"
    accessorFn: (row) => row.field
    cell: (info) => info.getValue()    (inferred from column position)
    header: "Label" + accessorKey "field"

  FILTER / KPI OBJECTS
    filterSchema[].key                 → filter field names
    kpiGroups[].items[].label/value    → KPI field names
    { key: "field", label: "..." }     → object shape keys
"""

from __future__ import annotations
import glob
import os
import re

REPO_ROOT = "/Users/apple/Desktop/threat-engine"
FRONTEND_DOMAIN = os.path.join(REPO_ROOT, "frontend/src/components/domain")
FRONTEND_SHARED = os.path.join(REPO_ROOT, "frontend/src/components/shared")
FRONTEND_CHARTS = os.path.join(REPO_ROOT, "frontend/src/components/charts")
FRONTEND_PAGES  = os.path.join(REPO_ROOT, "frontend/src/app")

# ── View → file globs mapping (relative to REPO_ROOT) ────────────────────────
# Covers all 25 pages discovered in frontend/src/app/

_VIEW_FILE_MAP: dict[str, list[str]] = {
    # Threat
    "threat-command-room": [
        "frontend/src/components/domain/threats/CommandRoom.jsx",
        "frontend/src/components/domain/threats/ThreatTrendChart.jsx",
        "frontend/src/components/domain/threats/ScenarioDetailPanel.jsx",
        "frontend/src/components/domain/threats/ThreatSubNav.jsx",
        "frontend/src/app/threats/page.jsx",
    ],
    "threats": [
        "frontend/src/app/threats/page.jsx",
        "frontend/src/components/domain/threats/*.jsx",
    ],
    "threats-graph": [
        "frontend/src/app/threats/graph/page.jsx",
        "frontend/src/components/graph/CVEDetailPanel.jsx",
        "frontend/src/components/graph/ConfigPropertiesTable.jsx",
        "frontend/src/components/threats/NodeInvestigationPanel.jsx",
    ],
    # Risk
    "risk": [
        "frontend/src/app/risk/page.jsx",
        "frontend/src/components/domain/risk/*.jsx",
    ],
    # Compliance
    "compliance": [
        "frontend/src/app/compliance/page.jsx",
        "frontend/src/components/domain/compliance/*.jsx",
    ],
    # Network security
    "network-security": [
        "frontend/src/app/network-security/page.jsx",
        "frontend/src/components/domain/network-security/*.jsx",
    ],
    # IAM / Misconfig
    "iam": [
        "frontend/src/app/misconfig/page.jsx",
        "frontend/src/app/iam/page.jsx",
        "frontend/src/components/domain/iam/*.jsx",
    ],
    # Data security
    "datasec": [
        "frontend/src/app/datasec/page.jsx",
        "frontend/src/components/domain/datasec/*.jsx",
    ],
    # Vulnerability
    "vulnerability": [
        "frontend/src/app/vulnerability/page.jsx",
        "frontend/src/app/vulnerabilities/page.jsx",
        "frontend/src/components/domain/vulnerability*.jsx",
        "frontend/src/components/domain/vulnerability/*.jsx",
    ],
    # CIEM
    "ciem": [
        "frontend/src/app/ciem/page.jsx",
        "frontend/src/components/domain/ciem/*.jsx",
    ],
    # SecOps
    "secops": [
        "frontend/src/app/secops/page.jsx",
        "frontend/src/components/domain/secops/*.jsx",
    ],
    # Billing (customer-facing — nav removed but file kept)
    "billing": [
        "frontend/src/app/billing/page.jsx",
        "frontend/src/components/domain/billing/*.jsx",
    ],
    # Admin billing (platform_admin only)
    "admin-billing": [
        "frontend/src/app/admin/billing/page.jsx",
    ],
    # Inventory
    "inventory": [
        "frontend/src/components/domain/inventory/*.jsx",
    ],
    # Container security
    "container-security": [
        "frontend/src/app/container-security/page.jsx",
        "frontend/src/components/domain/container-security/*.jsx",
        "frontend/src/components/domain/container_security/*.jsx",
    ],
    # Encryption
    "encryption": [
        "frontend/src/app/encryption/page.jsx",
        "frontend/src/components/domain/encryption/*.jsx",
    ],
    # Database security
    "database-security": [
        "frontend/src/app/database-security/page.jsx",
        "frontend/src/components/domain/database-security/*.jsx",
        "frontend/src/components/domain/database_security/*.jsx",
    ],
    # AI Security
    "ai-security": [
        "frontend/src/app/ai-security/page.jsx",
        "frontend/src/components/domain/ai-security/*.jsx",
        "frontend/src/components/domain/ai_security/*.jsx",
    ],
    # CNAPP
    "cnapp": [
        "frontend/src/app/cnapp/page.jsx",
        "frontend/src/components/domain/cnapp/*.jsx",
    ],
    # CWPP
    "cwpp": [
        "frontend/src/app/cwpp/page.jsx",
        "frontend/src/components/domain/cwpp/*.jsx",
    ],
    # Scans
    "scans": [
        "frontend/src/app/scans/page.jsx",
        "frontend/src/components/domain/scans/*.jsx",
    ],
    # Onboarding
    "onboarding": [
        "frontend/src/app/onboarding/**/*.jsx",
        "frontend/src/components/domain/onboarding/*.jsx",
    ],
    # Policies / Rules
    "policies": [
        "frontend/src/app/policies/page.jsx",
        "frontend/src/components/domain/policies/*.jsx",
    ],
    "rules": [
        "frontend/src/app/rules/page.jsx",
        "frontend/src/components/domain/rules/*.jsx",
    ],
    # Reports
    "reports": [
        "frontend/src/app/reports/page.jsx",
        "frontend/src/components/domain/reports/*.jsx",
    ],
    # Findings (shared panel)
    "findings": [
        "frontend/src/app/finding/**/*.jsx",
        "frontend/src/components/finding/*.jsx",
    ],
    # Dashboard / home
    "dashboard": [
        "frontend/src/app/dashboard/page.jsx",
        "frontend/src/app/page.jsx",
        "frontend/src/components/domain/dashboard/*.jsx",
    ],
}


# ── File resolver ─────────────────────────────────────────────────────────────

def _resolve_files(view_name: str) -> list[str]:
    globs = _VIEW_FILE_MAP.get(view_name, [])
    if not globs:
        globs = [
            f"frontend/src/app/{view_name}/page.jsx",
            f"frontend/src/components/domain/{view_name}/*.jsx",
        ]
    resolved = []
    for pattern in globs:
        for path in glob.glob(os.path.join(REPO_ROOT, pattern), recursive=True):
            if os.path.isfile(path) and path not in resolved:
                resolved.append(path)
    return resolved


# ── Field extraction helpers ──────────────────────────────────────────────────

# JSX/React internals that are not data fields
_JSX_NOISE = {
    'window', 'console', 'Math', 'Object', 'Array', 'React', 'router',
    'params', 'event', 'props', 'style', 'className', 'onClick', 'onChange',
    'onSubmit', 'e', 'el', 'ref', 'ctx', 'err', 'res', 'req', 'fn', 'cb',
    'children', 'key', 'index', 'idx', 'i', 'j', 'k', 'n', 't', 'x', 'v',
    'true', 'false', 'null', 'undefined', 'length', 'toString', 'push',
    'filter', 'map', 'find', 'reduce', 'forEach', 'slice', 'sort', 'join',
    'parseInt', 'parseFloat', 'String', 'Number', 'Boolean', 'Date',
    'toFixed', 'toLocaleString', 'toUpperCase', 'toLowerCase',
    'useState', 'useEffect', 'useMemo', 'useCallback', 'useRef',
    'className', 'style', 'href', 'src', 'alt', 'type', 'name',
    'placeholder', 'disabled', 'loading', 'error', 'isLoading', 'isError',
    # HTTP exception fields — not BFF contract fields
    'detail',
    # BFF response root — not itself a data field
    'data',
    # TanStack: row.original is an accessor, not a BFF data field
    'original',
    # HTML element shorthands
    'td', 'th', 'tr',
}

def _clean(field: str) -> bool:
    """Return True if the field name is worth keeping."""
    return (
        len(field) > 1
        and field not in _JSX_NOISE
        and not field.startswith('_')
        and re.match(r'^[a-zA-Z]\w*$', field) is not None
        and not field[0].isupper()          # skip component names (PascalCase)
    )


# ── Module-level lookup tables for _extract_object_fields ────────────────────

# Variables that represent browser APIs, auth context, or UI-only state.
# Accesses like user.role, event.target, current.focus are NOT BFF data fields.
_SKIP_VARS: frozenset[str] = frozenset({
    # Browser / framework
    'user', 'auth', 'session', 'navigator', 'window', 'target',
    'event', 'router', 'params', 'env', 'process', 'document',
    'location', 'history', 'storage',
    # UI / display state
    'ss', 'ts', 'styles', 'style', 'theme', 'config', 'opts', 'options',
    'active', 'selected', 'current', 'prev', 'next', 'first', 'last',
    # Recharts tooltip / animation callback vars
    'payload', 'entry', 'tick', 'dot', 'active',
    # HTML element shortcuts / framework object refs (not BFF fields)
    'info', 'win', 'td', 'th', 'tr', 'el', 'ref',
    # TanStack Table: row.original.field — original is an accessor, not a BFF field
    'original',
    # TanStack Table: row is the framework row object — accessorKey already captures the field
    'row',
    # Loop vars for locally computed aggregations (not top-level BFF response keys)
    'cat',   # posture_category bucket iterator
    'grp',   # group/bucket iterator
    'svc',   # service breakdown items (derived from summary.by_service, not a BFF services[] key)
    'rule',  # rule breakdown items (derived from summary.top_rules, not a BFF rules[] key)
    # Locally computed array variable names that hold derived/aggregated data
    'byService', 'byAccount', 'byRegion', 'topRules', 'topFindings',
    'radarData', 'chartData', 'trendPoints', 'sparkData',
    # Compliance framework loop var (fw iterates local var from finding.compliance_frameworks)
    'fw', 'fwk',
    # Database/datastore local variable (used as a generic object in network-security UI)
    'db',
    # Check/control loop var (ck iterates ciem_checks or config_checks items)
    'ck',
    # HTTP response vars
    'resp', 'res', 'req',
    # Domain string fragments (from URLs / emails in code)
    'cspm', 'http', 'https',
    # Shorthand tab / chart-series vars
    'tab', 'ch', 'meta',
    # JS built-in call-target bases
    'text', 'date', 'time', 'keys', 'values', 'partial',
    # Set / iterator vars
    'entries', 'iter',
    # Common local aliases (assigned from BFF response fields before iteration)
    'allFindings', 'activeScanTrend', 'scanTrendData', 'topServices',
    'donutSlices', 'domainBreakdown', 'kpiGroups',
    # KPI / display card vars (nested inside kpiGroups items, not top-level BFF fields)
    'card', 'kpi',
})

# Variables that represent the BFF response root.
# data.field → emit "field";  data.parent.child → emit "parent" + "parent.child"
_RESPONSE_VARS: frozenset[str] = frozenset({
    'data', 'response', 'view', 'viewData', 'result', 'pageData',
    'apiData', 'bffData', 'responseData', 'viewResult',
})

# Loop / array-element variable → canonical array name in the BFF response.
# var.field  →  arr[].field  (+ bare field as a secondary form)
_LOOP_VAR_MAP: dict[str, str] = {
    'org':      'orgs',
    'acct':     'accounts',
    'account':  'accounts',
    'item':     'items',
    'finding':  'findings',
    'scan':     'scans',
    'record':   'records',
    'node':     'nodes',
    'edge':     'edges',
    'tenant':   'tenants',
    'rule':     'rules',
    'policy':   'policies',
    # Finance / billing
    'inv':      'invoices',
    'invoice':  'invoices',
    'plan':     'plans',
    # IAM / compliance
    'svc':      'services',
    'service':  'services',
    'fw':       'frameworks',
    'ctrl':     'controls',
    'control':  'controls',
    'fam':      'families',
    # Threat / risk
    'sc':       'scenarios',
    'scenario': 'scenarios',
    # NOTE: 'cat' omitted — it always iterates locally computed category buckets, not a BFF 'categories' key.
    # NOTE: kpi/card intentionally omitted — they map to nested items[] inside kpiGroups,
    # not a top-level 'kpis' array.  Let those accesses be caught by items[].field patterns.
    # TanStack row.original → underlying row data
    'original': 'rows',
    # Infrastructure
    'cluster':  'clusters',
    'vuln':     'vulnerabilities',
    'alert':    'alerts',
    'repo':     'repositories',
    'bucket':   'buckets',
}

# JavaScript built-in method names.  When the second part of `p.c` is one of
# these it is a method call, not a data field access — skip entirely.
_JS_METHODS: frozenset[str] = frozenset({
    # String
    'includes', 'startsWith', 'endsWith', 'match', 'matchAll', 'search',
    'replace', 'replaceAll', 'split', 'trim', 'trimStart', 'trimEnd',
    'padStart', 'padEnd', 'repeat', 'charAt', 'charCodeAt',
    'substring', 'indexOf', 'lastIndexOf', 'normalize',
    # Array
    'some', 'every', 'find', 'findIndex', 'fill', 'flat', 'flatMap',
    'copyWithin', 'isArray',
    # Set / Map
    'add', 'delete', 'has', 'clear', 'get', 'set',
    # Promise
    'then', 'catch', 'finally', 'resolve', 'reject', 'all', 'race', 'any',
    # DOM / Browser
    'focus', 'blur', 'click', 'submit', 'reset', 'scroll',
    'dispatchEvent', 'addEventListener', 'removeEventListener',
    'querySelector', 'getElementById', 'createElement',
    'getAttribute', 'setAttribute',
    # Fetch / HTTP
    'json', 'text', 'blob', 'formData', 'clone', 'ok',
    # Console
    'log', 'error', 'warn', 'debug',
    # Router
    'navigate', 'back', 'forward',
    # Conversion / format
    'toString', 'valueOf', 'toFixed', 'toLocaleString', 'toJSON',
    'assign', 'freeze',
    # File-extension-like suffixes (from filename.csv etc.)
    'csv', 'xlsx', 'pdf', 'png', 'jpg', 'svg', 'xml',
    # DOM event / attribute-like
    'contains', 'document', 'location',
    # Misc patterns seen in this codebase
    'from', 'of', 'size',
    # TanStack Table accessor (row.original is the full data object, not a field)
    'original',
})


def _extract_object_fields(content: str) -> set[str]:
    """data.field, data?.field, const {f1, f2} = data, data.parent.child."""
    fields: set[str] = set()

    # Destructuring from hook results / response objects
    for m in re.finditer(
        r'const\s*\{([^}]+)\}\s*=\s*(?:data|response|viewData|result|view|pageData)',
        content,
    ):
        for token in m.group(1).split(','):
            token = token.strip()
            field = token.split(':')[0].strip()
            if field and _clean(field):
                fields.add(field)

    # data.field  /  data?.field  (single level)
    # `data` IS the BFF response — emit just the field name, not "data.field"
    for m in re.finditer(r'\bdata\??\.(\w+)\b', content):
        if _clean(m.group(1)):
            fields.add(m.group(1))

    # data.parent.child  (two levels) — data is the BFF response
    for m in re.finditer(r'\bdata\??\.(\w+)\??\.(\w+)\b', content):
        p, c = m.group(1), m.group(2)
        if _clean(p):
            fields.add(p)
        if _clean(p) and _clean(c) and c not in _JS_METHODS:
            fields.add(f"{p}.{c}")

    # Named variable.field (pulse_stats.critical_count, scenario.severity, etc.)
    for m in re.finditer(r'\b([a-z][a-z_]+)\??\.([a-z][a-z_]+)\b', content):
        p, c = m.group(1), m.group(2)
        if not _clean(p) or not _clean(c):
            continue
        if p in _SKIP_VARS:
            continue        # auth context / browser API / UI state
        if c in _JS_METHODS:
            continue        # p.method() call, not a field access
        if p in _RESPONSE_VARS:
            fields.add(c)   # data.orgs → emit "orgs"
        elif p in _LOOP_VAR_MAP:
            array_name = _LOOP_VAR_MAP[p]
            fields.add(f"{array_name}[].{c}")
            fields.add(c)
        else:
            fields.add(f"{p}.{c}")

    return fields


def _extract_array_items(content: str) -> set[str]:
    """scenarios.map(s => s.severity) → scenarios[].severity."""
    fields: set[str] = set()
    for m in re.finditer(
        r'(\w+)\.map\s*\(\s*(?:\w+\s*,\s*)?\(?(\w+)\)?\s*=>\s*(?:[({].*?)?'
        r'\b\2\??\.(\w+)\b',
        content,
        re.DOTALL,
    ):
        array_name, item_field = m.group(1), m.group(3)
        # Skip if the array variable is the BFF response root, a UI-only alias, or a React/JS built-in
        if array_name in _RESPONSE_VARS or array_name in _SKIP_VARS or not _clean(array_name):
            continue
        if not _clean(item_field) or item_field in _JS_METHODS:
            continue
        # Resolve loop var alias → canonical array name
        canonical = _LOOP_VAR_MAP.get(array_name, array_name)
        fields.add(canonical)
        fields.add(f"{canonical}[].{item_field}")
    return fields


def _extract_chart_fields(content: str) -> tuple[set[str], list[str]]:
    """
    Recharts dataKey="field" or dataKey={variable}.
    Returns (static_fields, notes_for_dynamic).
    """
    static: set[str] = set()
    notes: list[str] = []

    # dataKey="fieldName"  (static string literal)
    for m in re.finditer(r'dataKey\s*=\s*["\'](\w+)["\']', content):
        field = m.group(1)
        if _clean(field):
            static.add(f"[chart:dataKey] {field}")
            static.add(field)   # also emit bare field for contract matching

    # dataKey={variable}  (dynamic — note it)
    for m in re.finditer(r'dataKey\s*=\s*\{([^"\'}\s]+)\}', content):
        var = m.group(1).strip()
        if not var.startswith('"') and not var.startswith("'"):
            notes.append(f"Dynamic chart dataKey={{{var}}} — field name determined at runtime")

    # XAxis/YAxis dataKey (axis field) — same pattern, already caught above
    return static, notes


def _extract_table_columns(content: str) -> set[str]:
    """
    TanStack React Table column definitions.
    accessorKey: "field"
    accessorFn: (row) => row.field
    """
    fields: set[str] = set()

    # accessorKey: "field"  or  accessorKey: 'field'
    for m in re.finditer(r'accessorKey\s*:\s*["\'](\w+)["\']', content):
        if _clean(m.group(1)):
            fields.add(f"[table:col] {m.group(1)}")
            fields.add(m.group(1))

    # accessorFn: (row) => row.fieldName
    for m in re.finditer(r'accessorFn\s*:\s*\(\w+\)\s*=>\s*\w+\.(\w+)', content):
        if _clean(m.group(1)):
            fields.add(f"[table:col] {m.group(1)}")
            fields.add(m.group(1))

    # Legacy: accessor: "field" (react-table v7 style, may appear in older components)
    for m in re.finditer(r'\baccessor\s*:\s*["\'](\w+)["\']', content):
        if _clean(m.group(1)):
            fields.add(m.group(1))

    return fields


def _extract_filter_keys(content: str) -> set[str]:
    """
    filterSchema / filter config key:"field" patterns.
    { key: "severity", label: "Severity" }
    """
    fields: set[str] = set()
    for m in re.finditer(r'\bkey\s*:\s*["\'](\w+)["\']', content):
        if _clean(m.group(1)):
            fields.add(f"[filter:key] {m.group(1)}")
            fields.add(m.group(1))
    return fields


def _extract_kpi_fields(content: str) -> set[str]:
    """KPI / stat card value references: value: item.count, label: item.title, etc."""
    fields: set[str] = set()
    for m in re.finditer(r'\b(?:value|label|count|score|total|trend)\s*:\s*\w+\.(\w+)', content):
        if _clean(m.group(1)):
            fields.add(m.group(1))
    return fields


# ── Public API ─────────────────────────────────────────────────────────────────

def extract_ui_fields(view_name: str) -> dict:
    """
    Parse all UI files for `view_name` and return extracted field paths,
    covering object fields, chart dataKeys, table columns, filter keys, and KPIs.

    Returns:
        {
          "fields":            ["pulse_stats.critical_count", "[chart:dataKey] risk_score", ...],
          "object_fields":     [...],
          "chart_fields":      [...],   # dataKey references
          "table_columns":     [...],   # accessorKey references
          "filter_keys":       [...],   # filter schema key references
          "source_files":      [...],
          "notes":             [...]
        }
    """
    files = _resolve_files(view_name)
    notes: list[str] = []

    all_object: set[str]  = set()
    all_arrays: set[str]  = set()
    all_charts: set[str]  = set()
    all_tables: set[str]  = set()
    all_filters: set[str] = set()
    all_kpis: set[str]    = set()

    if not files:
        notes.append(
            f"No UI files found for view '{view_name}'. "
            f"Patterns tried: {_VIEW_FILE_MAP.get(view_name, ['(fallback glob)'])}"
        )
        return {
            "fields": [],
            "object_fields": [],
            "chart_fields": [],
            "table_columns": [],
            "filter_keys": [],
            "source_files": [],
            "notes": notes,
        }

    for filepath in files:
        try:
            content = open(filepath, encoding="utf-8").read()
        except OSError as exc:
            notes.append(f"Could not read {filepath}: {exc}")
            continue

        all_object  |= _extract_object_fields(content)
        all_arrays  |= _extract_array_items(content)
        chart_fields, chart_notes = _extract_chart_fields(content)
        all_charts  |= chart_fields
        notes.extend(chart_notes)
        all_tables  |= _extract_table_columns(content)
        all_filters |= _extract_filter_keys(content)
        all_kpis    |= _extract_kpi_fields(content)

    # Combined deduplicated field set
    all_fields = all_object | all_arrays | all_charts | all_tables | all_filters | all_kpis

    return {
        "fields":        sorted(all_fields),
        "object_fields": sorted(all_object | all_arrays),
        "chart_fields":  sorted(f for f in all_charts  if f.startswith("[chart")),
        "table_columns": sorted(f for f in all_tables  if f.startswith("[table")),
        "filter_keys":   sorted(f for f in all_filters if f.startswith("[filter")),
        "source_files":  files,
        "notes":         notes,
    }
