# Story PC-P3-01: Container Runtime Security — Architecture Design (ADR)

## Status: ready

## Metadata
- **Phase**: P3 — Tier C (long planning; requires external agent integration)
- **Sprint**: Posture Coverage Enhancement — Planning Track
- **Points**: 5 (design only; implementation = separate sprint)
- **Priority**: P3
- **Depends on**: PC-P1-03 (static container posture signals baseline)
- **Blocks**: Container runtime implementation sprint
- **RACI**: R=SA A=DL C=DEV,SR I=PO
- **Security Gate**: bmad-security-architect — new external agent integration; bmad-security-reviewer for ADR

## Gap Being Closed

**Current state:** Container security analysis is 100% static — it reads check findings from discovery snapshots. A container running a privileged process RIGHT NOW, or a pod that spawned a shell at 03:00 AM, is completely invisible until the next discovery scan (typically daily).

**What's needed:** Runtime detection that captures:
- Container escape attempts (pivot to host)
- Unexpected process execution inside containers (shell in production pod)
- File system modifications in read-only containers
- Network connections to unexpected destinations from pods
- Privilege escalation syscalls (setuid, ptrace)

## Design Decisions to Make (ADR scope)

### Option A: Falco (OSS — recommended starting point)
- **What:** CNCF-graduated runtime security agent; runs as DaemonSet on every K8s node
- **How:** Monitors syscalls via eBPF/kernel module; alerts on policy violations
- **Pros:** Industry standard, AWS EKS-compatible, MITRE ATT&CK mapped rules, no vendor lock-in
- **Cons:** Requires cluster-level DaemonSet deployment (infra change); kernel module vs eBPF compatibility needs EKS version check
- **Integration:** Falco outputs JSON alerts → forward to CDR engine (cdr_findings) → posture signals update `container_escape_risk=TRUE`

### Option B: AWS GuardDuty for EKS Runtime Monitoring
- **What:** Managed AWS service; no agent deployment needed on EKS
- **Pros:** Zero operational overhead; integrates with existing CloudTrail pipeline
- **Cons:** AWS-only (doesn't cover GCP/Azure K8s); cost per cluster/hour; findings come via GuardDuty not our CDR
- **Integration:** GuardDuty findings → EventBridge → Lambda → cdr_findings (or direct DB insert)

### Option C: Tetragon (Cilium — eBPF-native)
- **What:** Kubernetes-native eBPF security observability; richer process tree data than Falco
- **Pros:** Low overhead; network + process + file syscalls in one; Cilium already may be in use
- **Cons:** Newer, less community rule coverage than Falco; requires Cilium CNI

## New Posture Columns Needed (for runtime signals)

```sql
-- Add in a future migration (PC-P3 implementation sprint):
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS container_escape_attempt  BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS runtime_shell_detected    BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS unexpected_process_exec   BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS runtime_net_anomaly       BOOLEAN  NOT NULL DEFAULT FALSE;
```

## Deliverables for This Story

1. **ADR document:** `_bmad-output/planning-artifacts/adr-container-runtime-security.md`
   - Decision: Option A (Falco) or B (GuardDuty) with rationale
   - EKS node group compatibility check (kernel module vs eBPF)
   - Estimated operational overhead
   - Integration path to CDR engine

2. **Spike results:**
   - Deploy Falco (or GuardDuty) to a test EKS node group
   - Verify findings arrive in expected format
   - Measure performance overhead (CPU/memory per node)

3. **Story files for implementation sprint:** Generate PC-P3-01a through PC-P3-01d covering: Falco deployment, alert routing, CDR integration, posture signal update

## Acceptance Criteria

- [ ] AC-1: ADR written with clear decision (Option A/B/C) and rationale
- [ ] AC-2: Spike completed — at least one runtime event captured and verified (e.g. `docker exec -it <pod> bash` detected)
- [ ] AC-3: Performance impact measured: CPU overhead < 5% per node, memory < 128MB per DaemonSet pod
- [ ] AC-4: Integration path to CDR engine documented (how Falco alerts → cdr_findings)
- [ ] AC-5: New posture columns documented and migration SQL written (ready for implementation sprint)
- [ ] AC-6: Implementation story files generated (PC-P3-01a through PC-P3-01d) as ready stories

## Definition of Done
- [ ] ADR committed to `_bmad-output/planning-artifacts/`
- [ ] Spike results documented
- [ ] Implementation stories written and in `.claude/planning/stories/container-runtime/`
