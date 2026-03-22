"""
Threat UI Improvement — Agent Orchestration Script

Executes 7 specialized agents in dependency order using the Claude Agent SDK.
Each agent has a focused task with enough context to work autonomously.

Dependency Graph:
  Phase 1 (parallel):
    Agent 1: schema-migrator
    Agent 3: analytics-endpoints
    Agent 4: ui-field-fix

  Phase 1b (sequential, after Agent 1):
    Agent 2: threat-detail-endpoint

  Phase 2 (parallel, after Agent 2):
    Agent 5: threat-detail-ui
    Agent 7: bff-enrichment

  Phase 2b (sequential, after Agent 7):
    Agent 6: threat-list-indicators

Usage:
    pip install claude-agent-sdk
    python THREAT_UI_AGENT_ORCHESTRATOR.py
"""

import anyio
from claude_agent_sdk import (
    query,
    ClaudeAgentOptions,
    ResultMessage,
    SystemMessage,
    CLINotFoundError,
    CLIConnectionError,
)

CWD = "/Users/apple/Desktop/threat-engine"
PLAN_DOC = ".claude/documentation/THREAT_UI_MASTER_PLAN.md"

# ── Agent Configurations ───────────────────────────────────────────

AGENTS = {
    # ── Phase 1: Fix Plumbing ──────────────────────────────────────

    "schema-migrator": {
        "description": "Database migration specialist — adds missing columns to threat_findings table",
        "tools": ["Read", "Write", "Edit", "Bash", "Grep", "Glob"],
        "max_turns": 25,
        "prompt": f"""You are a database migration specialist for a PostgreSQL-based CSPM platform.

TASK: Add 5 new columns to the `threat_findings` table and create an Alembic migration.

NEW COLUMNS:
1. assignee VARCHAR(255) — Who is assigned to investigate
2. assigned_at TIMESTAMP — When assigned
3. status_history JSONB DEFAULT '[]'::jsonb — Array of {{status, timestamp, actor}}
4. attack_path_id VARCHAR(255) — Attack path ID (populated by graph build)
5. blast_radius_count INT DEFAULT 0 — Reachable resource count

STEPS:
1. Read: {CWD}/shared/database/schemas/threat_schema.sql
2. Add the 5 columns after `created_at` in the CREATE TABLE statement
3. Add indexes: idx_tf_assignee (WHERE assignee IS NOT NULL), idx_tf_attack_path_id
4. Read existing Alembic migrations: {CWD}/shared/database/alembic/versions/threat/
5. Create new migration: {CWD}/shared/database/alembic/versions/threat/add_assignee_timeline_indicators.py
   - upgrade(): op.add_column() for each, op.create_index() for indexes
   - downgrade(): op.drop_index(), op.drop_column()

RULES:
- All columns nullable or with defaults (backward-compatible)
- Follow naming conventions of existing migrations
- No hardcoded connection strings
""",
    },

    "analytics-endpoints": {
        "description": "FastAPI developer — creates 3 missing analytics/graph endpoints",
        "tools": ["Read", "Write", "Edit", "Bash", "Grep", "Glob"],
        "max_turns": 30,
        "prompt": f"""You are a Python/FastAPI backend developer for a CSPM threat engine.

TASK: Create 3 new API endpoints in a new router file.

ENDPOINTS:

1. GET /api/v1/threat/analytics/mitre
   Query params: tenant_id (required), scan_run_id (optional)
   Response: {{matrix: [{{technique_id, technique_name, tactics: [], count, severity_base}}]}}
   SQL:
     SELECT mt.technique_id, mt.technique_name, mt.tactics, mt.severity_base,
            COUNT(DISTINCT tf.id) as count
     FROM threat_findings tf,
          jsonb_array_elements_text(tf.mitre_techniques) AS tech_id
     JOIN mitre_technique_reference mt ON mt.technique_id = tech_id
     WHERE tf.tenant_id = %s
     GROUP BY mt.technique_id, mt.technique_name, mt.tactics, mt.severity_base
     ORDER BY count DESC

2. GET /api/v1/threat/analytics/top-services
   Query params: tenant_id (required), limit (optional, default 10)
   Response: {{services: [{{service, count, critical, high, medium, low}}]}}
   SQL:
     SELECT COALESCE(resource_type, 'unknown') as service, COUNT(*) as count,
            SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END) as low
     FROM threat_findings WHERE tenant_id = %s
     GROUP BY service ORDER BY count DESC LIMIT %s

3. GET /api/v1/graph/toxic-combinations/matrix
   Query params: tenant_id (required)
   Response: {{matrix: [{{category1, category2, co_occurrence_count, example_resources: []}}]}}
   SQL:
     SELECT tf1.threat_category as cat1, tf2.threat_category as cat2,
            COUNT(DISTINCT tf1.resource_uid) as co_occurrence_count,
            ARRAY_AGG(DISTINCT tf1.resource_uid ORDER BY tf1.resource_uid) FILTER (WHERE ...) as example_resources
     FROM threat_findings tf1
     JOIN threat_findings tf2 ON tf1.resource_uid = tf2.resource_uid
       AND tf1.threat_category < tf2.threat_category AND tf1.tenant_id = tf2.tenant_id
     WHERE tf1.tenant_id = %s
     GROUP BY cat1, cat2 ORDER BY co_occurrence_count DESC

IMPLEMENTATION:
1. Create: {CWD}/engines/threat/threat_engine/api/analytics_router.py
2. Use FastAPI APIRouter
3. Follow DB connection pattern from: {CWD}/engines/threat/threat_engine/api/ui_data_router.py
4. Mount in: {CWD}/engines/threat/threat_engine/api_server.py

Reference for DB connection: Read ui_data_router.py to see how it connects to PostgreSQL.
""",
    },

    "ui-field-fix": {
        "description": "React developer — fixes field name mismatches between BFF and UI",
        "tools": ["Read", "Edit", "Grep"],
        "max_turns": 15,
        "prompt": f"""You are a React/Next.js frontend developer fixing field name mismatches.

TASK: Fix field references in the threats list page to match BFF output.

The BFF normalize_threat() (in {CWD}/shared/api_gateway/bff/_transforms.py) returns:
  - mitre_technique (string)
  - mitre_tactic (string)
  - risk_score AND riskScore (both provided for compatibility)
  - affected_resources (integer)
  - status (lowercase string)
  - provider (uppercase string)
  - account (string)
  - region (string)

FIX in {CWD}/ui_samples/src/app/threats/page.jsx:
1. Find all references to `mitreTactic` and change to `mitre_tactic`
2. Find all references to `mitreTechnique` and change to `mitre_technique`
3. Find all references to `affectedResources` and change to `affected_resources`
4. Verify DataTable column accessorKeys match these field names
5. Verify filter option extraction uses correct field names

Also check for any camelCase references that should be snake_case by reading the
normalize_threat() function output fields.
""",
    },

    # ── Phase 1b: Detail Endpoint (depends on schema-migrator) ─────

    "threat-detail-endpoint": {
        "description": "FastAPI developer — creates comprehensive threat detail endpoint with cross-DB queries",
        "tools": ["Read", "Write", "Edit", "Bash", "Grep", "Glob"],
        "max_turns": 40,
        "prompt": f"""You are a Python/FastAPI backend developer building the threat detail endpoint.

TASK: Create GET /api/v1/threat/{{threat_id}}/detail that returns ALL data for the threat detail page.

DATA CONTRACT (what the endpoint must return):
{{
  "threat": {{full threat_findings row}},
  "exposure": {{is_internet_exposed, exposure_type, exposure_path}},
  "attack_path": {{exists, path_id, title, severity, steps: [...], affected_resources}},
  "affected_resources": [{{resource_uid, resource_type, account_id, region, role}}],
  "blast_radius": {{reachable_count, resources_with_threats, max_depth, depth_distribution}},
  "supporting_findings": [{{finding_id, rule_id, rule_name, severity, resource_uid, status, remediation}}],
  "remediation": {{priority, auto_remediable, steps: [{{order, action, command}}]}},
  "mitre_context": {{technique_id, technique_name, tactics, description, platforms, detection_guidance, remediation_guidance}},
  "timeline": [{{timestamp, event, actor, details}}]
}}

See full contract: {CWD}/{PLAN_DOC} section 4.2

IMPLEMENTATION:
1. Create: {CWD}/engines/threat/threat_engine/api/detail_router.py
2. Main query: SELECT * FROM threat_findings WHERE finding_id = %s AND tenant_id = %s
3. Supporting findings: Connect to check DB (threat_engine_check) and query check_findings
4. MITRE context: JOIN mitre_technique_reference WHERE technique_id = first technique from mitre_techniques JSONB
5. Blast radius: If Neo4j available, query graph. Otherwise return empty summary.
6. Attack path: If Neo4j available, check for paths. Otherwise return {{exists: false}}.
7. Timeline: Build from first_seen_at, last_seen_at, status_history JSONB
8. Exposure: Extract from evidence JSONB (look for internet_exposed, public_access keys)
9. Remediation: Extract from finding_data JSONB (look for remediation, auto_remediable keys)
10. Affected resources: Parse from evidence.affected_assets or related resource UIDs

REFERENCE FILES:
- DB connection pattern: {CWD}/engines/threat/threat_engine/api/ui_data_router.py
- API server (to mount router): {CWD}/engines/threat/threat_engine/api_server.py
- DB schema: {CWD}/shared/database/schemas/threat_schema.sql

CROSS-DB QUERY PATTERN:
The threat engine connects to its own DB (threat_engine_threat).
For supporting findings, connect to threat_engine_check using same RDS host:
  import os
  CHECK_DB = os.getenv("CHECK_DB_NAME", "threat_engine_check")
  # Use same host/port/user, different database name

ERROR HANDLING:
- 404 if threat not found
- Graceful degradation: if Neo4j/check-DB unavailable, return empty for those sections
- Log warnings for failed cross-DB queries
""",
    },

    # ── Phase 2: UI Rebuild (depends on detail endpoint) ───────────

    "threat-detail-ui": {
        "description": "React developer — rebuilds the threat detail page with 11 investigation blocks",
        "tools": ["Read", "Write", "Edit", "Glob", "Grep"],
        "max_turns": 50,
        "prompt": f"""You are a senior React/Next.js frontend developer building the threat detail page.

TASK: Completely rebuild {CWD}/ui_samples/src/app/threats/[threatId]/page.jsx

The page must have 11 blocks in this order:
1. ThreatHeader — Always visible. Severity badge, title, MITRE code badge, risk score progress bar, provider/account/region, assignee dropdown, status toggle
2. ExposureContext — HIDDEN if no exposure data. Internet → Resource path diagram, exposure type, public since date
3. AttackPathRibbon — HIDDEN if no attack path. Horizontal step chain: Resource ──(Technique)──→ Resource
4. AffectedResources — Always visible. DataTable: resource_uid, type, account, region, role
5. BlastRadiusSummary — COLLAPSED by default. "Blast Radius: N reachable · M with threats". Expand for depth distribution
6. SupportingFindings — Always visible. DataTable: rule_id, rule_name, severity, resource, status. "View in Findings" link
7. RemediationSteps — Always visible. Ordered list with copy-to-clipboard commands
8. EvidencePanel — COLLAPSED. JSON pretty-print of evidence JSONB
9. MitreContextPanel — COLLAPSED. Technique details + detection guidance lists
10. ActivityTimeline — COLLAPSED. Vertical timeline with events
11. HuntActions — COLLAPSED. Links to /threats/hunting, /threats/graph, /threats/blast-radius with context params

DATA SOURCE: getFromEngine('threat', `/api/v1/threat/${{threatId}}/detail`)

DESIGN SYSTEM:
- CSS variables: var(--bg-card), var(--bg-secondary), var(--bg-tertiary), var(--text-primary), var(--text-secondary), var(--text-muted), var(--accent-primary), var(--accent-danger), var(--accent-warning), var(--accent-success), var(--border)
- Icons: lucide-react (Shield, AlertTriangle, Activity, Globe, Zap, Target, FileText, Lock, Clock, Search, ChevronDown, ChevronRight, Copy, ExternalLink)
- Shared components: SeverityBadge, DataTable, StatusIndicator (import from @/components/shared/)
- API: import {{ getFromEngine }} from '@/lib/api'
- useGlobalFilter: import {{ useGlobalFilter }} from '@/lib/global-filter-context'

COLLAPSIBLE BLOCK PATTERN:
Create a reusable CollapsibleBlock component:
  - Props: title, icon, badge (optional count/text), defaultOpen (bool), hidden (bool)
  - When hidden=true, render nothing
  - ChevronDown/ChevronRight toggle icon
  - Smooth expand animation

REFERENCE PAGES (for component patterns):
- Attack path visualization: {CWD}/ui_samples/src/app/threats/attack-paths/page.jsx
- Blast radius graph: {CWD}/ui_samples/src/app/threats/blast-radius/page.jsx
- Current detail page: {CWD}/ui_samples/src/app/threats/[threatId]/page.jsx
- Threat list (for shared components): {CWD}/ui_samples/src/app/threats/page.jsx

WIREFRAME: See {CWD}/{PLAN_DOC} section 4.1 for ASCII wireframe layout.
""",
    },

    "bff-enrichment": {
        "description": "Python developer — adds indicator enrichment and cross-linking to BFF",
        "tools": ["Read", "Write", "Edit", "Grep"],
        "max_turns": 20,
        "prompt": f"""You are a Python backend developer enhancing the BFF threats view.

TASK: Add indicator enrichment to the BFF threats view.

CHANGES TO {CWD}/shared/api_gateway/bff/threats.py:

1. After calling normalize_threat() on each threat, add an "indicators" dict:
   t["indicators"] = {{
       "internet_exposed": bool(t_raw.get("evidence", {{}}).get("internet_exposed", False)),
       "has_attack_path": bool(t_raw.get("attack_path_id")),
       "blast_radius_count": t_raw.get("blast_radius_count", 0),
       "auto_remediable": bool((t_raw.get("finding_data") or {{}}).get("auto_remediable", False)),
       "has_sensitive_data": "data_exposure" in (t_raw.get("threat_category") or ""),
       "has_identity_risk": "iam" in (t_raw.get("threat_category") or ""),
   }}

2. Update normalize_threat() in {CWD}/shared/api_gateway/bff/_transforms.py:
   Add pass-through fields:
   - "threat_category": t.get("threat_category", ""),
   - "attack_path_id": t.get("attack_path_id"),
   - "blast_radius_count": t.get("blast_radius_count", 0),
   - "evidence": t.get("evidence", {{}}),  # pass through for indicator extraction
   - "finding_data": t.get("finding_data", {{}}),  # pass through for auto_remediable

   Note: The raw engine response has these fields. normalize_threat() currently
   doesn't pass them through. Add them to the returned dict.

3. Keep the existing normalization intact — just ADD the new fields.
""",
    },

    # ── Phase 2b: List Indicators (depends on bff-enrichment) ──────

    "threat-list-indicators": {
        "description": "React developer — adds indicator chips and enhanced filters to threat list",
        "tools": ["Read", "Write", "Edit", "Grep", "Glob"],
        "max_turns": 30,
        "prompt": f"""You are a React/Next.js frontend developer enhancing the threat list page.

TASK: Add indicator chips and enhanced filtering to {CWD}/ui_samples/src/app/threats/page.jsx

CHANGES:

1. INDICATOR CHIPS — below each threat title in the DataTable, render chips:
   - If threat.indicators.internet_exposed: blue chip "Internet Exposed" with Globe icon
   - If threat.indicators.has_attack_path: orange chip "Attack Path" with Zap icon
   - If threat.indicators.blast_radius_count > 5: red chip "Blast: N" with Target icon
   - If threat.indicators.auto_remediable: green chip "Auto-Fix" with CheckCircle icon
   - If threat.indicators.has_identity_risk: purple chip "Identity Risk" with KeyRound icon

   Chip style: inline-flex, rounded-full, px-2 py-0.5, text-xs, gap-1, items-center
   Use the DataTable cell renderer for the title column to show title + chips below

2. ENHANCED FILTERS — add to the existing FilterBar:
   - Provider: multi-select dropdown (options from threats data)
   - Account: multi-select dropdown (options from threats data)
   - Region: multi-select dropdown (options from threats data)
   - Category: multi-select dropdown (options derived from threat_category)
   Extract unique values with useMemo

3. DEFAULT SORT — set initial sort to risk_score descending

4. URL PARAMS — persist filter state in URL search params using useSearchParams
   When filters change, update URL. On page load, read filters from URL.

REFERENCE:
- FilterBar component: {CWD}/ui_samples/src/components/shared/FilterBar.jsx
- Current page: {CWD}/ui_samples/src/app/threats/page.jsx
- BFF response: threats[] array with .indicators object (added by bff-enrichment agent)
""",
    },
}


async def run_agent(name: str, config: dict) -> str:
    """Run a single agent and return its result."""
    print(f"  Starting: {name}")
    result = ""
    async for message in query(
        prompt=config["prompt"],
        options=ClaudeAgentOptions(
            cwd=CWD,
            allowed_tools=config["tools"],
            permission_mode="acceptEdits",
            system_prompt=f"You are the '{name}' agent. {config['description']}. "
                          f"Read {PLAN_DOC} for full context if needed.",
            max_turns=config.get("max_turns", 30),
        ),
    ):
        if isinstance(message, ResultMessage):
            result = message.result
            print(f"  Completed: {name}")
    return result


async def main():
    """Execute all agents in dependency order."""

    print("=" * 60)
    print("THREAT UI IMPROVEMENT — AGENT ORCHESTRATION")
    print("=" * 60)

    # ── Phase 1: Parallel (no dependencies) ──────────────────────
    print("\n--- Phase 1: Fix Plumbing (3 agents in parallel) ---\n")

    results = {}

    async with anyio.create_task_group() as tg:

        async def _run(name):
            results[name] = await run_agent(name, AGENTS[name])

        tg.start_soon(_run, "schema-migrator")
        tg.start_soon(_run, "analytics-endpoints")
        tg.start_soon(_run, "ui-field-fix")

    print(f"\nPhase 1 complete: {len(results)} agents finished\n")

    # ── Phase 1b: Detail Endpoint (needs schema columns) ────────
    print("--- Phase 1b: Threat Detail Endpoint ---\n")
    results["threat-detail-endpoint"] = await run_agent(
        "threat-detail-endpoint", AGENTS["threat-detail-endpoint"]
    )
    print()

    # ── Phase 2: Parallel (UI + BFF, both need detail endpoint) ──
    print("--- Phase 2: UI Rebuild + BFF Enrichment (parallel) ---\n")

    async with anyio.create_task_group() as tg:
        tg.start_soon(_run, "threat-detail-ui")
        tg.start_soon(_run, "bff-enrichment")

    print(f"\nPhase 2 complete\n")

    # ── Phase 2b: List Indicators (needs BFF enrichment) ────────
    print("--- Phase 2b: Threat List Indicators ---\n")
    results["threat-list-indicators"] = await run_agent(
        "threat-list-indicators", AGENTS["threat-list-indicators"]
    )

    # ── Summary ──────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("ALL AGENTS COMPLETE")
    print("=" * 60)
    for name, result in results.items():
        status = "OK" if result else "EMPTY"
        print(f"  [{status}] {name}")

    print("\nNext steps:")
    print("  1. Review changes: git diff")
    print("  2. Build & test: docker build + dev server")
    print("  3. Deploy: update K8s manifests with new image tags")


if __name__ == "__main__":
    try:
        anyio.run(main)
    except CLINotFoundError:
        print("ERROR: Claude Code CLI not found. Install: pip install claude-agent-sdk")
    except CLIConnectionError as e:
        print(f"ERROR: Connection failed: {e}")
    except KeyboardInterrupt:
        print("\nAborted by user.")
