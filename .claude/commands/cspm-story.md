# /cspm-story

Create a CSPM-native story file for any engine or feature. Invokes `cspm-po` to generate a story with all platform-specific acceptance criteria pre-wired.

## Usage
```
/cspm-story <story-id> "<story-title>"
/cspm-story <story-id> "<story-title>" --engine <engine-name>
```

Examples:
```
/cspm-story AP-P2-08 "Add choke-point confidence scoring to attack path engine"
/cspm-story SF-P4-01 "Wire secops findings into security_findings unified layer" --engine secops
/cspm-story BFF-01 "Add /views/posture-summary endpoint for dashboard"
```

## What gets generated

The story file is written to `.claude/planning/stories/<prefix>/<story-id>-<slug>.md` and contains:

- **Context** — engine, pipeline stage, DB, BFF, K8s service name
- **User story** — As a [role], I want [capability], so that [outcome]
- **Acceptance criteria** — CSPM-native checklist:
  - [ ] Engine routing correct (pipeline stage, port, svc name)
  - [ ] Standard 15 DB columns present on any new findings table
  - [ ] `scan_run_id` + `tenant_id` on every DB write
  - [ ] `require_permission()` on every new endpoint
  - [ ] BFF contract test written if view handler added
  - [ ] RBAC matrix: all 5 roles × all new endpoints tested
  - [ ] No `latest` image tag in K8s manifest
  - [ ] No BFF fallback/mock data
  - [ ] JSONB not passed through `json.loads()`
  - [ ] Post-deploy smoke checklist reference included
- **Technical notes** — DB schema changes, migration file name, BFF contract shape, Argo step if pipeline-touching
- **Security gate** — which gates apply (bmad-security-architect / bmad-security-reviewer / bmad-security-po)
- **Definition of done** — deploy + post-deploy checklist + MEMORY.md tag update

## Process

1. Read `.claude/context/agents.ndjson` — identify the engine from story title/engine arg
2. **Read `.claude/agents/<engine>.md`** — extract: DB table names, K8s svc name, port, pipeline_stage, known gotchas
3. **Read `.claude/agents/cspm-po.md`** — load the PO persona and mandatory AC checklist
4. Read `.claude/context/bff_contract.ndjson` — check if a BFF view is involved
5. Using the loaded agent context, write the story file to `.claude/planning/stories/<prefix>/<story-id>-<slug>.md`
6. Print the file path and a summary of the key ACs

## Agents loaded (in order)
1. `.claude/agents/<engine>.md` — provides: DB schema, API endpoints, K8s svc, pipeline stage, gotchas
2. `.claude/agents/cspm-po.md` — provides: story file format, mandatory AC checklist, security gate rules

## Rules
- Never create a story without loading the target engine's agent file first
- Story ID prefix must match the epic folder (e.g. `AP-` → `attack-path/`, `SF-` → `security-findings/`)
- If the story touches a new engine, endpoint, or DB schema → flag that `bmad-security-architect` gate is required before dev starts
- If the story is for a security engine rule → flag that `bmad-security-po` gate is required
- Every story must include the Definition of Done with post-deploy checklist reference