# Archive — Old Threat UI Documents (v1)

These files were the **first iteration** of the threat UI improvement plan (2026-03-17).
They have been **fully superseded** by the modular documents in the parent `threats-redesign/` folder.

## Mapping

| Old File | Replaced By |
|----------|-------------|
| `THREAT_UI_MASTER_PLAN.md` | `00-MASTER-PLAN.md` + `01-09` page-specific docs |
| `THREAT_UI_DATA_FLOW.md` | Data flow sections in each page doc + `10-GAP-ANALYSIS.md` |
| `THREAT_UI_AGENT_ORCHESTRATOR.py` | `12-AGENT-DEFINITIONS.md` (declarative, not runnable script) |

## Why Archived (Not Deleted)

- Contains some raw SQL queries that may be useful for reference
- Has a `normalize_threat()` field mapping table
- Python orchestrator script shows v1 agent approach (7 agents vs current 7 agents with different scoping)

**Do not use these for new development.** Use the parent folder docs instead.
