#!/usr/bin/env python3
"""
Update all .claude/agents/*.md files to reference the new framework context layer.

Inserts a small block right after the Self-Update Protocol closing separator (---).
The block differs by agent type:
  - Engine agents  → ## Routing Metadata  (points to agents.ndjson entry)
  - BMad agents    → ## CSPM Platform Note (redirects to cspm-* process agents)

Idempotent: skips files that already have the block.
Already-done agents (cspm-orchestrator, cspm-po, cspm-qa, cspm-engine-orchestrator) are skipped.

Run:
    python3 scripts/update_agent_framework.py           # live update
    python3 scripts/update_agent_framework.py --dry-run  # preview only
    python3 scripts/update_agent_framework.py --verify   # report status, no writes
"""

from __future__ import annotations
import argparse
import sys
from pathlib import Path

AGENTS_DIR = Path(__file__).resolve().parent.parent / ".claude" / "agents"

# Already updated — skip entirely
SKIP = {
    "cspm-orchestrator.md",
    "cspm-po.md",
    "cspm-qa.md",
    "cspm-engine-orchestrator.md",
}

# BMad process agents — get redirect note instead of routing metadata
BMAD_AGENTS = {
    "bmad-analyst.md",
    "bmad-architect.md",
    "bmad-dev.md",
    "bmad-orchestrator.md",
    "bmad-pm.md",
    "bmad-po.md",
    "bmad-qa.md",
    "bmad-security-architect.md",
    "bmad-security-po.md",
    "bmad-security-reviewer.md",
    "bmad-sm.md",
}

# Sentinel strings — used for idempotency check
ENGINE_SENTINEL = "## Routing Metadata"
BMAD_SENTINEL   = "## CSPM Platform Note"

# Self-Update Protocol closing marker — unique across all agent files
PROTOCOL_CLOSE_MARKER = "trust the code and flag the discrepancy."
PROTOCOL_CLOSE_SEP    = "\n---\n"

ENGINE_BLOCK = """
## Routing Metadata

Read your entry in `.claude/context/agents.ndjson` before acting. It is the authoritative source for:
- `pipeline_stage` — your position in the Argo DAG
- `depends_on` / `feeds` — what you read from and write to
- `k8s_svc` / `svc_port` / `target_port` — K8s service coordinates
- `gateway_prefixes` — ingress paths routed to you
- `security_gates` — mandatory security agents for this engine (never skip)
- `tools` — which skills to use (never raw `kubectl exec psql` for DB queries)

**Session-end protocol**: After any code change → update the matching line in `agents.ndjson` if svc/port/prefix changed; update image tag row in `MEMORY.md`.

---

"""

BMAD_BLOCK = """
## CSPM Platform Note

For CSPM platform work use the CSPM-native process agents — they have engine routing, pipeline constraints, and CSPM-specific ACs pre-wired:

| Task | Use instead |
|------|-------------|
| Story generation | `cspm-po` — pipeline_stage, DB columns, BFF contract, RBAC matrix all wired |
| QA / acceptance testing | `cspm-qa` — 10-level stack: BFF contract, RBAC matrix, post-deploy smoke |
| Task routing (unclear engine) | `cspm-orchestrator` — reads `agents.ndjson`, routes deterministically |

Use this BMad agent for: strategic planning, sprint retrospectives, ADRs, generic SDLC questions where CSPM platform context is not required.

---

"""


def find_insert_position(content: str) -> int:
    """Return the character index to insert at (right after Self-Update Protocol ---)."""
    marker_pos = content.find(PROTOCOL_CLOSE_MARKER)
    if marker_pos == -1:
        return -1
    sep_pos = content.find(PROTOCOL_CLOSE_SEP, marker_pos)
    if sep_pos == -1:
        return -1
    # Position right after the "\n---\n" separator
    return sep_pos + len(PROTOCOL_CLOSE_SEP)


def agent_type(filename: str) -> str:
    if filename in SKIP:
        return "skip"
    if filename in BMAD_AGENTS:
        return "bmad"
    return "engine"


def needs_update(content: str, kind: str) -> bool:
    sentinel = BMAD_SENTINEL if kind == "bmad" else ENGINE_SENTINEL
    return sentinel not in content


def apply_update(content: str, kind: str) -> str | None:
    """Return updated content, or None if insert point not found."""
    block = BMAD_BLOCK if kind == "bmad" else ENGINE_BLOCK
    pos = find_insert_position(content)
    if pos == -1:
        return None
    return content[:pos] + block + content[pos:]


def run(dry_run: bool, verify: bool) -> None:
    files = sorted(AGENTS_DIR.glob("*.md"))

    counts = {"updated": 0, "already_done": 0, "skipped": 0, "error": 0}
    errors = []

    for f in files:
        kind = agent_type(f.name)

        if kind == "skip":
            counts["skipped"] += 1
            if verify:
                print(f"  SKIP  {f.name}")
            continue

        content = f.read_text()

        if not needs_update(content, kind):
            counts["already_done"] += 1
            if verify:
                print(f"  OK    {f.name}")
            continue

        updated = apply_update(content, kind)
        if updated is None:
            counts["error"] += 1
            errors.append(f.name)
            print(f"  ERROR {f.name} — Self-Update Protocol marker not found")
            continue

        if verify or dry_run:
            tag = "DRY-RUN" if dry_run else "NEEDS UPDATE"
            print(f"  [{tag}] {f.name}  ({kind})")

        if not dry_run and not verify:
            f.write_text(updated)
            print(f"  UPDATED {f.name}")

        counts["updated"] += 1

    print(f"\nSummary: {counts['updated']} updated | {counts['already_done']} already done | "
          f"{counts['skipped']} skipped | {counts['error']} errors")
    if errors:
        print(f"Errors: {errors}")


def main() -> None:
    p = argparse.ArgumentParser(description="Update agent files with framework context block.")
    p.add_argument("--dry-run", action="store_true", help="Preview changes, no writes")
    p.add_argument("--verify", action="store_true", help="Report status only, no writes")
    args = p.parse_args()

    if args.verify:
        print("=== Agent Framework Status ===")
        run(dry_run=False, verify=True)
    elif args.dry_run:
        print("=== DRY RUN — no files written ===")
        run(dry_run=True, verify=False)
    else:
        print("=== Updating agent files ===")
        run(dry_run=False, verify=False)


if __name__ == "__main__":
    main()
