---
description: Kick off a JNY sprint story by summoning every agent on its RACI. Loads each agent's persona from .claude/agents/, stitches the story file + task, and invokes via general-purpose Agent. Pass the story ID as argument (e.g. /jny-kickoff JNY-01). Optionally pass `design`, `dev`, `review`, or `qa` as second arg to scope to one phase.
---

# /jny-kickoff — Story team kickoff orchestrator

You are the orchestrator for kicking off a JNY sprint story. Your inputs:

1. **First positional arg** — story ID (e.g. `JNY-01`, `JNY-15.7` for sub-tasks).
2. **Second positional arg (optional)** — phase: `design` | `dev` | `review` | `qa` | `all` (default `all`).

## Steps

### 1. Read the story + ADR
- Open `.claude/planning/stories/{STORY_ID}_*.md`.
- Open `.claude/documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md`, jump to §4.3.1 for the RACI table row matching `STORY_ID`.
- For sub-task IDs (e.g. `JNY-15.7`), look up the parent (JNY-15) in §4.3.2 and locate the row matching the sub.

### 2. Compute the agent invocation list
From the RACI row, build an ordered list:

| Phase | Agents to invoke | Order |
|-------|------------------|-------|
| design | every cell with **A** in the design column (`bmad-security-architect`, `bmad-architect`, etc.), then **C** consulted engine agents | sequential — design must finish before dev |
| dev | every cell with **R** that is NOT already in design | parallel where possible |
| review | `cspm-code-reviewer`, then `cspm-security-reviewer` + `bmad-security-reviewer` | sequential |
| qa | `cspm-qa-engineer` + `bmad-qa` | parallel |

If user passed a phase arg, only invoke that phase's agents.

### 3. Invoke each agent

For each agent in the list:

```
prompt = run_shell(
  "python3 .claude/scripts/invoke_cspm_agent.py "
  "--agent {AGENT_NAME} --story {STORY_ID} "
  "--task '{phase-specific task description}'"
)

invoke Agent(
  description="{STORY_ID} — {AGENT_NAME} {phase}",
  subagent_type="general-purpose",
  prompt=prompt,
  run_in_background=True   # for parallel phases
)
```

### 4. Phase-specific task descriptions

| Phase | Task template |
|-------|---------------|
| design | "Produce a design proposal for {story_id}. Cover: schema/contract decisions, security threat model (STRIDE), tenant scoping, edge cases, dependencies on other stories. Output a 1-page handoff at `.claude/planning/stories/{story_id}_handoff_{agent}.md`." |
| dev | "Implement the work described in the story file under your area. Read the design handoffs from earlier agents (`*_handoff_*.md` siblings of the story file). Write code, do not write story-narrative. When done, list every file you modified and summarize at the bottom of `{story_id}_handoff_{agent}.md`." |
| review | "Run the cspm-code-reviewer / cspm-security-reviewer / bmad-security-reviewer checklist on the code changes for {story_id}. Cite OWASP, STRIDE, CSPM Constitution sections. Output a pass/block verdict." |
| qa | "Verify acceptance criteria from the story file by inspecting code, running tests, hitting endpoints. Output AC checklist with [x]/[ ]." |

### 5. After all agents return

Summarize for the user:
- Which agents completed cleanly
- Which produced handoff docs (cite paths)
- Which raised blockers — quote them
- Recommended next step (which phase to run next, or which checkpoint gate to convene)

## Examples

```
/jny-kickoff JNY-01 design
→ Invokes bmad-security-architect (CP-1 design gate), threat-engine (consult), cspm-db-engineer (consult).
  Each produces a design handoff. CP-1 reviewer aggregates.

/jny-kickoff JNY-15.7  (sub-task — IAM engine contract tests)
→ Sole invocation: iam-engine agent with task = "create Pydantic response models +
  black-box tests for engines/iam/iam_engine/api_server.py per JNY-15 sub-task 7".

/jny-kickoff JNY-08 dev
→ Fans out 7 parallel iam-engine, network-security, datasec, encryption,
  container-security, dbsec, ai-security invocations + cspm-ui-dev coordinator.
```

## Hard rules

- ALWAYS use `python3 .claude/scripts/invoke_cspm_agent.py` to build prompts — never construct them inline. The helper guarantees agent persona + story file + constitution reference are loaded.
- For sub-tasks, the parent story file is the source of truth; the sub ID just selects which row of §4.3.2 the agent owns.
- Run agents in `run_in_background=true` whenever the phase allows parallelism (multi-engine fan-out, or independent reviewers).
- Sequential phases — design (must finish first) → dev → review → qa.
- After every phase, check the `_handoff_*.md` files exist; if any is missing, the phase is incomplete.
- If a security checkpoint (CP-1..CP-4) gates the next phase per ADR §4.3.3, halt and tell the user "checkpoint review needed before proceeding."

## Files this skill touches

- Reads: `.claude/planning/stories/{STORY_ID}_*.md`, `.claude/agents/*.md`, `.claude/documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md`
- Writes: `.claude/planning/stories/{STORY_ID}_handoff_*.md` (per agent)
- Invokes: `.claude/scripts/invoke_cspm_agent.py` + `Agent(subagent_type=general-purpose)` per agent on RACI
