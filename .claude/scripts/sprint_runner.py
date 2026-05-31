#!/usr/bin/env python3
"""
CSPM Sprint Runner — stateful sprint orchestrator CLI.

Usage:
  python3 .claude/scripts/sprint_runner.py status [sprint_id]
  python3 .claude/scripts/sprint_runner.py next [sprint_id]
  python3 .claude/scripts/sprint_runner.py advance <sprint_id> <story_id> <stage>
  python3 .claude/scripts/sprint_runner.py gate <sprint_id> <story_id> <gate> pass|fail [notes]
  python3 .claude/scripts/sprint_runner.py block <sprint_id> <story_id> <reason>
  python3 .claude/scripts/sprint_runner.py unblock <sprint_id> <story_id>
  python3 .claude/scripts/sprint_runner.py new-sprint <sprint_id> <goal>
  python3 .claude/scripts/sprint_runner.py add-story <sprint_id> <story_id> <title> <engine> [touches...]
  python3 .claude/scripts/sprint_runner.py list
  python3 .claude/scripts/sprint_runner.py set-agent <sprint_id> <story_id> <agent_id>
  python3 .claude/scripts/sprint_runner.py get-agent <sprint_id> <story_id>

Stages (ordered):
  intake → design → story → dev → security-review → qa → deploy → post-deploy → done

Gates (mandatory unless required=false):
  design         → bmad-security-architect  (new-engine tasks only)
  security-review → bmad-security-reviewer  (any endpoint/auth/DB/HTTP touch)
  qa             → cspm-qa
  post-deploy    → cspm-post-deploy
"""

import json
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

PLANNING_DIR = Path(__file__).parent.parent / "planning"
TEMPLATE_FILE = PLANNING_DIR / "sprint_state_template.json"

STAGES = ["intake", "design", "story", "dev", "security-review", "qa", "deploy", "post-deploy", "done"]

STAGE_AGENT = {
    "intake":          "bmad-analyst (if unclear) — or skip directly to 'story' stage",
    "design":          "bmad-architect + bmad-security-architect (new-engine only)",
    "story":           "cspm-po",
    "dev":             "bmad-dev  +  .claude/agents/{engine}.md  as context",
    "security-review": "bmad-security-reviewer  [mandatory if endpoint/auth/DB/HTTP touched]",
    "qa":              "cspm-qa",
    "deploy":          "/cspm-deploy skill",
    "post-deploy":     "/cspm-post-deploy skill",
    "done":            "(complete)",
}

STATUS_ICON = {
    "done": "✅", "in_progress": "🔄", "blocked": "🚫",
    "pending": "⏳", "passed": "✅", "failed": "❌", "skip": "⏭️",
}


# ── helpers ──────────────────────────────────────────────────────────────────

def state_path(sprint_id: str) -> Path:
    return PLANNING_DIR / f"{sprint_id}_state.json"


def load(sprint_id: str) -> dict:
    p = state_path(sprint_id)
    if not p.exists():
        print(f"ERROR: sprint state not found: {p}", file=sys.stderr)
        sys.exit(1)
    return json.loads(p.read_text())


def save(sprint_id: str, state: dict):
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    state_path(sprint_id).write_text(json.dumps(state, indent=2))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def find_story(state: dict, story_id: str) -> dict:
    for s in state["stories"]:
        if s["story_id"] == story_id:
            return s
    print(f"ERROR: story {story_id!r} not found in sprint {state['sprint_id']!r}", file=sys.stderr)
    sys.exit(1)


def next_stage(current: str) -> str:
    idx = STAGES.index(current)
    return STAGES[idx + 1] if idx + 1 < len(STAGES) else "done"


def active_sprints() -> list[Path]:
    return sorted(PLANNING_DIR.glob("*_state.json"))


# ── commands ─────────────────────────────────────────────────────────────────

def cmd_list():
    files = active_sprints()
    if not files:
        print("No sprint state files found.")
        return
    for f in files:
        s = json.loads(f.read_text())
        icon = STATUS_ICON.get(s.get("status", ""), "•")
        print(f"  {icon}  {s['sprint_id']:30s}  {s['status']:12s}  {s['sprint_goal']}")


def cmd_status(sprint_id: str):
    state = load(sprint_id)
    print(f"\n{'='*60}")
    print(f"  Sprint : {state['sprint_id']}")
    print(f"  Goal   : {state['sprint_goal']}")
    print(f"  Status : {state['status']}")
    print(f"  Current: {state.get('current_story_id') or '—'}")
    print(f"{'='*60}")
    for s in state["stories"]:
        icon = STATUS_ICON.get(s["status"], "•")
        blocked = f"  ⚠️  {s['blocked_reason']}" if s.get("blocked_reason") else ""
        print(f"\n  {icon} [{s['stage']:14s}] {s['story_id']}  —  {s['title']}{blocked}")
        for gate, info in s["gates"].items():
            g_icon = STATUS_ICON.get(info["status"], "•")
            req = "" if info.get("required", True) else " (optional)"
            print(f"         {g_icon} gate:{gate}{req}")
    print()


def cmd_next(sprint_id: str):
    state = load(sprint_id)
    # find first non-done, non-blocked story
    for s in state["stories"]:
        if s["status"] in ("pending", "in_progress"):
            stage = s["stage"]
            agent = STAGE_AGENT.get(stage, "unknown")
            gate_info = s["gates"].get(stage)
            print(f"\n▶  Next action for sprint {sprint_id!r}:")
            print(f"   Story  : {s['story_id']} — {s['title']}")
            print(f"   Stage  : {stage}")
            print(f"   Agent  : {agent}")
            if gate_info and gate_info["status"] == "pending" and gate_info.get("required", True):
                print(f"   Gate   : {stage} gate PENDING — run {gate_info['agent']} before advancing")
            story_file = PLANNING_DIR / "stories" / f"{s['story_id']}_*.md"
            candidates = list(PLANNING_DIR.glob(f"stories/{s['story_id']}*.md"))
            if candidates:
                print(f"   File   : {candidates[0]}")
            print(f"\n   Command to advance after completion:")
            ns = next_stage(stage)
            print(f"   python3 .claude/scripts/sprint_runner.py advance {sprint_id} {s['story_id']} {ns}")
            return
    print(f"  All stories done or blocked in sprint {sprint_id!r}.")


def cmd_advance(sprint_id: str, story_id: str, new_stage: str):
    if new_stage not in STAGES:
        print(f"ERROR: invalid stage {new_stage!r}. Valid: {STAGES}", file=sys.stderr)
        sys.exit(1)
    state = load(sprint_id)
    story = find_story(state, story_id)

    # check gate for current stage is not blocking
    current = story["stage"]
    gate = story["gates"].get(current)
    if gate and gate.get("required", True) and gate["status"] == "pending":
        print(f"WARNING: gate '{current}' is still PENDING. Pass it first with:")
        print(f"  python3 .claude/scripts/sprint_runner.py gate {sprint_id} {story_id} {current} pass")
        print("Advancing anyway (override) …")

    story["stage"] = new_stage
    story["status"] = "done" if new_stage == "done" else "in_progress"
    if new_stage == "done":
        state.setdefault("completed_stories", [])
        if story_id not in state["completed_stories"]:
            state["completed_stories"].append(story_id)
        state.setdefault("gate_log", []).append(
            {"story_id": story_id, "event": "story_complete", "at": now_iso()}
        )
        # auto-advance current_story_id to next pending
        for s in state["stories"]:
            if s["status"] == "pending":
                state["current_story_id"] = s["story_id"]
                s["status"] = "in_progress"
                break
        else:
            state["current_story_id"] = None
            state["status"] = "complete"
    else:
        state["current_story_id"] = story_id
    save(sprint_id, state)
    print(f"✅  {story_id} → {new_stage}")


def cmd_gate(sprint_id: str, story_id: str, gate: str, verdict: str, notes: str = ""):
    state = load(sprint_id)
    story = find_story(state, story_id)
    if gate not in story["gates"]:
        print(f"ERROR: gate {gate!r} not in story. Valid: {list(story['gates'].keys())}", file=sys.stderr)
        sys.exit(1)
    story["gates"][gate]["status"] = "passed" if verdict == "pass" else "failed"
    story["gates"][gate]["at"] = now_iso()
    story["gates"][gate]["notes"] = notes
    state.setdefault("gate_log", []).append({
        "story_id": story_id, "gate": gate, "verdict": verdict,
        "agent": story["gates"][gate].get("agent", ""), "at": now_iso(), "notes": notes,
    })
    if verdict == "fail":
        story["status"] = "blocked"
        story["blocked_reason"] = f"Gate '{gate}' FAILED — {notes}"
        state.setdefault("blocked_stories", [])
        if story_id not in state["blocked_stories"]:
            state["blocked_stories"].append(story_id)
    save(sprint_id, state)
    icon = "✅" if verdict == "pass" else "❌"
    print(f"{icon}  Gate '{gate}' {verdict.upper()} for {story_id}")


def cmd_block(sprint_id: str, story_id: str, reason: str):
    state = load(sprint_id)
    story = find_story(state, story_id)
    story["status"] = "blocked"
    story["blocked_reason"] = reason
    state.setdefault("blocked_stories", [])
    if story_id not in state["blocked_stories"]:
        state["blocked_stories"].append(story_id)
    save(sprint_id, state)
    print(f"🚫  {story_id} blocked: {reason}")


def cmd_unblock(sprint_id: str, story_id: str):
    state = load(sprint_id)
    story = find_story(state, story_id)
    story["status"] = "in_progress"
    story["blocked_reason"] = None
    state["blocked_stories"] = [s for s in state.get("blocked_stories", []) if s != story_id]
    save(sprint_id, state)
    print(f"✅  {story_id} unblocked")


def cmd_new_sprint(sprint_id: str, goal: str):
    p = state_path(sprint_id)
    if p.exists():
        print(f"ERROR: sprint {sprint_id!r} already exists at {p}", file=sys.stderr)
        sys.exit(1)
    state = {
        "_meta": {"schema_version": "1.0"},
        "sprint_id": sprint_id,
        "sprint_goal": goal,
        "status": "planning",
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "current_story_id": None,
        "stories": [],
        "gate_log": [],
        "completed_stories": [],
        "blocked_stories": [],
    }
    p.write_text(json.dumps(state, indent=2))
    print(f"✅  Sprint {sprint_id!r} created at {p}")


def cmd_set_agent(sprint_id: str, story_id: str, agent_id: str):
    """Store the background agent ID for a story so it can be resumed later."""
    state = load(sprint_id)
    story = find_story(state, story_id)
    story["active_agent_id"] = agent_id
    save(sprint_id, state)
    print(f"✅  Agent ID {agent_id!r} stored for {story_id}")


def cmd_get_agent(sprint_id: str, story_id: str):
    """Print the stored background agent ID for a story (used by sprint runner to resume)."""
    state = load(sprint_id)
    story = find_story(state, story_id)
    agent_id = story.get("active_agent_id")
    if not agent_id:
        print(f"(none)  — no background agent stored for {story_id}")
    else:
        print(agent_id)


def cmd_add_story(sprint_id: str, story_id: str, title: str, engine: str, touches: list[str]):
    state = load(sprint_id)
    needs_design = engine == "new-engine"
    needs_sec_review = bool({"endpoint", "auth", "db", "http"} & set(touches))
    story = {
        "story_id": story_id,
        "title": title,
        "primary_engine": engine,
        "touches": touches,
        "stage": "intake",
        "status": "pending",
        "gates": {
            "design":          {"required": needs_design,    "status": "skip" if not needs_design else "pending",    "agent": "bmad-security-architect", "at": None, "notes": ""},
            "security-review": {"required": needs_sec_review,"status": "skip" if not needs_sec_review else "pending","agent": "bmad-security-reviewer",  "at": None, "notes": ""},
            "qa":              {"required": True,             "status": "pending", "agent": "cspm-qa",               "at": None, "notes": ""},
            "post-deploy":     {"required": True,             "status": "pending", "agent": "cspm-post-deploy",      "at": None, "notes": ""},
        },
        "artifacts": [],
        "image_tag": None,
        "active_agent_id": None,
        "blocked_reason": None,
        "notes": [],
    }
    state["stories"].append(story)
    if state["current_story_id"] is None:
        state["current_story_id"] = story_id
        story["status"] = "in_progress"
    save(sprint_id, state)
    print(f"✅  Story {story_id!r} added to sprint {sprint_id!r}")
    print(f"   design gate required : {needs_design}")
    print(f"   security-review gate : {needs_sec_review}")


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(0)

    cmd = args[0]

    if cmd == "list":
        cmd_list()
    elif cmd == "status":
        sprint_id = args[1] if len(args) > 1 else _pick_active()
        cmd_status(sprint_id)
    elif cmd == "next":
        sprint_id = args[1] if len(args) > 1 else _pick_active()
        cmd_next(sprint_id)
    elif cmd == "advance":
        cmd_advance(args[1], args[2], args[3])
    elif cmd == "gate":
        notes = args[5] if len(args) > 5 else ""
        cmd_gate(args[1], args[2], args[3], args[4], notes)
    elif cmd == "block":
        cmd_block(args[1], args[2], " ".join(args[3:]))
    elif cmd == "unblock":
        cmd_unblock(args[1], args[2])
    elif cmd == "new-sprint":
        cmd_new_sprint(args[1], " ".join(args[2:]))
    elif cmd == "set-agent":
        cmd_set_agent(args[1], args[2], args[3])
    elif cmd == "get-agent":
        cmd_get_agent(args[1], args[2])
    elif cmd == "add-story":
        touches = args[5:] if len(args) > 5 else []
        cmd_add_story(args[1], args[2], args[3], args[4], touches)
    else:
        print(f"Unknown command: {cmd!r}\n{__doc__}", file=sys.stderr)
        sys.exit(1)


def _pick_active() -> str:
    files = active_sprints()
    if not files:
        print("ERROR: no sprint state files found. Create one with: new-sprint <id> <goal>", file=sys.stderr)
        sys.exit(1)
    # prefer in_progress over planning
    for f in files:
        s = json.loads(f.read_text())
        if s.get("status") == "in_progress":
            return s["sprint_id"]
    return json.loads(files[-1].read_text())["sprint_id"]


if __name__ == "__main__":
    main()