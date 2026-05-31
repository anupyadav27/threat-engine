#!/usr/bin/env python3
"""
CSPM Agent Invocation Helper.

Loads a .claude/agents/<name>.md persona + optional context files into a
self-contained prompt for the general-purpose Agent tool. Agent routing is
driven by .claude/context/agents.ndjson — not hardcoded here.

CLI usage:
    python3 .claude/scripts/invoke_cspm_agent.py --agent cspm-po \
            --task "generate story for AI security BFF view"

    python3 .claude/scripts/invoke_cspm_agent.py --agent check \
            --story CHECK-S03 --task "implement rule filter endpoint"

    python3 .claude/scripts/invoke_cspm_agent.py --agent cspm-orchestrator \
            --task "route: add suppress button to IAM findings table"

Outputs a self-contained prompt to stdout — pass to Agent(prompt=...).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
AGENT_DIR  = REPO_ROOT / ".claude" / "agents"
STORY_DIR  = REPO_ROOT / ".claude" / "planning" / "stories"
CONTEXT_DIR = REPO_ROOT / ".claude" / "context"

# Agents that receive Tier 0 context (agents.ndjson + tools.md + process.xml).
TIER0_AGENTS = {"cspm-orchestrator", "cspm-po", "cspm-qa"}

# Agents that also receive Tier 1 context (api_patterns.xml + bff_contract.ndjson).
TIER1_AGENTS = {"cspm-orchestrator"}

# Agent name aliases — only for names that differ from their .md filename.
# Routing source of truth is .claude/context/agents.ndjson, not this map.
NAME_ALIASES = {
    "threat-engine":    "threat",
    "iam-engine":       "iam",
    "inventory-engine": "inventory",
    "cdr-engine":       "cdr",
}


def load_agent_context(agent_name: str) -> str:
    """Read .claude/agents/<agent>.md — falls back to agent_name as filename."""
    fname = NAME_ALIASES.get(agent_name, agent_name)
    path = AGENT_DIR / f"{fname}.md"
    if not path.exists():
        return f"<agent file not found: {agent_name} (looked for {path})>"
    return path.read_text()


def load_story(story_id: str) -> str:
    """Read .claude/planning/stories/{story_id}_*.md — returns empty if not found."""
    if not story_id:
        return ""
    matches = list(STORY_DIR.glob(f"{story_id}_*.md"))
    if not matches:
        # Also try exact filename match
        exact = STORY_DIR / f"{story_id}.md"
        if exact.exists():
            return exact.read_text()
        return f"<story file not found: {story_id}>"
    return matches[0].read_text()


def load_context_file(filename: str) -> str:
    """Read .claude/context/<filename> — returns warning string if missing."""
    path = CONTEXT_DIR / filename
    return path.read_text() if path.exists() else f"<context file not found: {filename}>"


def build_prompt(agent_name: str, story_id: str, task: str) -> str:
    """Build a self-contained prompt for the general-purpose Agent.

    Sections injected:
      1. Agent persona (.claude/agents/<name>.md)
      2. Tier 0 context — routing manifest (process agents only)
      3. Tier 1 context — UI/BFF data flow (cspm-orchestrator only)
      4. Story file (if story_id provided)
      5. Task + hard rules
    """
    agent_ctx = load_agent_context(agent_name)
    story_md  = load_story(story_id)

    tier0_block = ""
    if agent_name in TIER0_AGENTS:
        tier0_block = f"""
================ TIER 0 CONTEXT (routing manifest) ================

--- agents.ndjson ---
{load_context_file("agents.ndjson")}

--- tools.md ---
{load_context_file("tools.md")}

--- process.xml ---
{load_context_file("process.xml")}
"""

    tier1_block = ""
    if agent_name in TIER1_AGENTS:
        tier1_block = f"""
================ TIER 1 CONTEXT (UI / BFF data flow) ================

--- api_patterns.xml ---
{load_context_file("api_patterns.xml")}

--- bff_contract.ndjson ---
{load_context_file("bff_contract.ndjson")}
"""

    story_block = f"""
================ STORY FILE ====================================

{story_md}
""" if story_md and not story_md.startswith("<story file not found") else ""

    handoff_rule = (
        f"4. Write a handoff at .claude/planning/stories/{story_id}_handoff_{agent_name}.md "
        f"— decisions made, open questions, next agent's pickup point."
        if story_id else
        "4. Summarise your output and any open questions at the end of your response."
    )

    return f"""You are the **{agent_name}** specialist agent. Stay in role — do not impersonate other agents.

================ AGENT PERSONA & DOMAIN CONTEXT ================

{agent_ctx}
{tier0_block}{tier1_block}{story_block}
================ TASK ==========================================

{task}

================ HARD RULES ====================================

1. Read .claude/documentation/CSPM_CONSTITUTION.md before producing any design or code.
2. If your role is Consulted (C) in the story RACI, give feedback only — do not do the Responsible agent's work.
3. Apply domain-specific gotchas listed in your persona above.
{handoff_rule}
5. Never add fallback/mock data in BFF handlers. Never use `latest` image tag. Never call json.loads() on JSONB.
"""


def main() -> None:
    p = argparse.ArgumentParser(description="Build a CSPM agent invocation prompt.")
    p.add_argument("--agent", required=True,
                   help="Agent name — matches .claude/agents/<name>.md (e.g. check, cspm-po, threat)")
    p.add_argument("--story", default="",
                   help="Story ID — optional (e.g. CHECK-S03, AI-S01)")
    p.add_argument("--task", required=True,
                   help="Task description for the agent")
    args = p.parse_args()

    sys.stdout.write(build_prompt(args.agent, args.story, args.task))


if __name__ == "__main__":
    main()
