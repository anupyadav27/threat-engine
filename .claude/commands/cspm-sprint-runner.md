---
name: cspm-sprint-runner
description: Stateful sprint run-loop. Reads .claude/planning/{sprint_id}_state.json, determines next action, spawns the correct agent, and advances state. Use instead of manually tracking which story and stage is next.
---

# /cspm-sprint-runner

Stateful sprint orchestrator. On each invocation: reads sprint state → finds current story + stage → spawns the right agent → waits for output → advances state → prints next action.

## Usage

```
/cspm-sprint-runner                        # resume active sprint, do next action
/cspm-sprint-runner status                 # print sprint board (no action)
/cspm-sprint-runner resume <sprint_id>     # resume a specific sprint
/cspm-sprint-runner new <sprint_id> <goal> # create a new sprint
/cspm-sprint-runner add <sprint_id> <story_id> "<title>" <engine> [touches...]
```

---

## Step 1 — Load state

```bash
python3 .claude/scripts/sprint_runner.py list
python3 .claude/scripts/sprint_runner.py next [sprint_id]
```

`next` tells you: current story, current stage, which agent to spawn, which gates are pending.

---

## Step 2 — Dispatch the right agent

### Short-running stages (foreground — run to completion, no resume needed)

| Stage | How to spawn |
|-------|-------------|
| `intake` | `Agent(subagent_type="bmad-analyst", prompt=...)` |
| `design` | `Agent(subagent_type="bmad-architect", prompt=...)` |
| `story` | `Agent(subagent_type="cspm-po", prompt=...)` |
| `security-review` | `Agent(subagent_type="bmad-security-reviewer", prompt=...)` |
| `qa` | `Agent(subagent_type="cspm-qa", prompt=...)` |
| `deploy` | Run `/cspm-deploy` skill |
| `post-deploy` | Run `/cspm-post-deploy` skill |

### Long-running stages (background — must track agent ID for resume)

The `dev` stage runs in the background so the orchestrator remains free to handle consultations.

```
# 1. Spawn dev agent in background — capture the returned agent ID
agent_id = Agent(
  description="Implement <story_id>: <title>",
  subagent_type="bmad-dev",
  run_in_background=True,
  prompt="..."   # include engine agent file content + story file content
)

# 2. Store the agent ID in sprint state immediately
python3 .claude/scripts/sprint_runner.py set-agent <sprint_id> <story_id> <agent_id>
```

You will be **notified automatically** when the background agent completes or signals a consultation. Do not poll — wait for the notification.

---

## Step 3 — Handle CONSULT signals (agent-to-agent via `to` field)

When a background dev agent outputs a line starting with `CONSULT:`, the sprint runner mediates:

```
CONSULT: Does this endpoint pattern need require_permission? → agent: bmad-security-reviewer
```

**Handle it:**

```
# 1. Retrieve the waiting agent ID
agent_id=$(python3 .claude/scripts/sprint_runner.py get-agent <sprint_id> <story_id>)

# 2. Run the consultant FOREGROUND (fast — returns one answer)
consultant_result = Agent(
  description="Security consultation for <story_id>",
  subagent_type="bmad-security-reviewer",
  prompt="<specific question from CONSULT line> — answer concisely, this feeds back to dev agent"
)

# 3. Resume the background dev agent with the answer — full context preserved
Agent(
  description="Resume <story_id> dev with consultation answer",
  to=agent_id,
  prompt="Consultation answer from bmad-security-reviewer: <consultant_result>. Continue implementation."
)
```

The `to=agent_id` field resumes the exact background agent that sent the CONSULT signal — its full context (files read, code written, reasoning so far) is preserved. No context is lost.

**Key rule**: never have one agent directly spawn another. Always route consultations through the sprint runner using the `to` field.

---

## Step 4 — After agent completes, advance state

```bash
# Move to next stage
python3 .claude/scripts/sprint_runner.py advance <sprint_id> <story_id> <next_stage>

# Record gate result
python3 .claude/scripts/sprint_runner.py gate <sprint_id> <story_id> security-review pass
python3 .claude/scripts/sprint_runner.py gate <sprint_id> <story_id> security-review fail "Missing require_permission on /api/v1/findings"

# Mark complete
python3 .claude/scripts/sprint_runner.py advance <sprint_id> <story_id> done
```

When marking `done`: clear `active_agent_id` and update `.claude/agent_state/{engine}.json` with the new image tag.

---

## Step 5 — Loop

```bash
python3 .claude/scripts/sprint_runner.py next [sprint_id]
```

Repeat Steps 2–4 until sprint status = `complete`.

---

## Full consultation flow (concrete example)

```
Sprint: DBSEC-S2  |  Story: DBSEC-S2-01  |  Stage: dev

① Sprint runner spawns dev agent in background:
   Agent(subagent_type="bmad-dev", run_in_background=True, prompt="Implement audit log export endpoint...")
   → agent_id = "agent-x7f2k"
   → sprint_runner.py set-agent DBSEC-S2 DBSEC-S2-01 agent-x7f2k

② Dev agent is writing code. It hits an auth pattern question and outputs:
   "CONSULT: Should /api/v1/dbsec/audit-log use require_permission('dbsec:read') or ('dbsec:sensitive')?
    → agent: bmad-security-reviewer"

③ Sprint runner receives notification, runs reviewer foreground:
   Agent(subagent_type="bmad-security-reviewer",
         prompt="Should /api/v1/dbsec/audit-log use require_permission('dbsec:read') or ('dbsec:sensitive')?")
   → "Use dbsec:sensitive — audit logs contain credential refs and connection strings."

④ Sprint runner resumes dev agent with answer:
   Agent(to="agent-x7f2k",
         prompt="Consultation answer: use require_permission('dbsec:sensitive'). Continue implementing.")

⑤ Dev agent continues from exact point it paused — all context intact.
   Eventually outputs: "Implementation complete. Files changed: engines/dbsec/..."

⑥ Sprint runner advances:
   sprint_runner.py advance DBSEC-S2 DBSEC-S2-01 security-review
```

---

## Rules

- `dev` stage always uses `run_in_background=True` — store the agent ID immediately after spawn
- Never have Agent A directly spawn Agent B — always route through the sprint runner
- `security-review` gate is required whenever `touches` contains endpoint, auth, db, or http
- `design` gate is required only for new-engine stories
- A `fail` verdict on any gate sets the story to `blocked` — fix and re-run before advancing
- `post-deploy` gate must pass before story is `done`
- After every `done`: update `.claude/agent_state/{engine}.json` image_tag and MEMORY.md production table

---

## Example: starting a new sprint

```bash
python3 .claude/scripts/sprint_runner.py new-sprint DBSEC-S2 "Add audit-log export and connection limits"
python3 .claude/scripts/sprint_runner.py add-story DBSEC-S2 DBSEC-S2-01 "Audit log export endpoint" dbsec endpoint db
python3 .claude/scripts/sprint_runner.py add-story DBSEC-S2 DBSEC-S2-02 "Connection limit checks" dbsec db

/cspm-sprint-runner resume DBSEC-S2
```