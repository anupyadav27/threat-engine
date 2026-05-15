# CSPM Tool Decision Matrix
_refreshed_at: 2026-05-15 | stale_after_days: 30_

| Task | Use This | Never This |
|------|----------|-----------|
| Query engine database | `/cspm-db-query` skill | raw `kubectl exec psql` |
| View engine logs | `/cspm-k8s-logs` skill | raw `kubectl logs` |
| Deploy engine to EKS | `/cspm-deploy` skill | manual `kubectl apply` alone |
| Check K8s pod/svc state | `/cspm-k8s-status` skill | raw `kubectl get` |
| Trigger a scan run | `/cspm-scan-trigger` skill | direct Argo API call |
| Monitor scan progress | `/cspm-scan-status` skill | DB query alone |
| Apply DB migration | `/cspm-db-migrate` skill | ad-hoc SQL exec in pod |
| Scaffold new engine | `/cspm-new-engine` skill | manual file-by-file creation |
| Author new check rule | `/cspm-new-rule` skill | manual YAML editing |
| Scaffold new BFF view | `/cspm-new-bff-view` skill | manual bff/ file creation |
| Code + security review | `/cspm-review` skill | inline check only |
| Read single known file | `Read` tool | spawn agent |
| Explore unknown codebase area | `Explore` subagent | sequential `Read` calls |
| Engine-specific analysis or change | spawn engine `Agent` (see agents.ndjson) | `Read` tools alone |
| Cross-engine / pipeline work | spawn `cspm-engine-orchestrator` agent | individual engine agents |
| Task routing (what agent to use) | spawn `cspm-orchestrator` agent | guess without routing |
| Security gate — code review | spawn `bmad-security-reviewer` | skip entirely |
| Security gate — new engine design | spawn `bmad-security-architect` first | start dev without design gate |
| Story generation | spawn `cspm-po` agent | `bmad-po` agent |
| QA / acceptance testing | spawn `cspm-qa` agent | `bmad-qa` agent |
| Git operations | `Bash` tool | — |
| Docker build | `Bash` tool | — |
| Docker push | `Bash` tool (confirm with user first) | push without confirmation |
| Update navigation files | `Edit` or `Write` tool (single NDJSON line) | rewrite whole file |

## Tool Selection Rules

<rules>
  <rule>Skills wrap complex multi-step operations — always prefer skill over raw Bash for CSPM ops</rule>
  <rule>Spawning an agent costs a tool call — only spawn when the task needs full engine context</rule>
  <rule>Never use raw kubectl for DB access — RDS is not publicly accessible; use cspm-db-query</rule>
  <rule>Docker push requires explicit user confirmation — confirm image tag and registry before push</rule>
  <rule>For NDJSON updates: find the line by primary key, replace only that line — never rewrite the file</rule>
</rules>