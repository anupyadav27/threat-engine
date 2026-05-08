#!/usr/bin/env python3
"""
CSPM/BMad Agent Invocation Helper.

The CSPM and BMad agents under .claude/agents/*.md are Claude Code subagents
with full domain context. In environments where they aren't exposed as
`subagent_type` values, we wrap them via the `general-purpose` agent by
loading the .claude/agents/<name>.md file as the leading context of the
prompt.

Usage from a Claude session:
    1. Pick the story you want to work on (e.g. JNY-01).
    2. Resolve the RACI from .claude/planning/stories/JNY-01_*.md.
    3. For each Responsible agent, build a prompt with `build_prompt(...)`.
    4. Invoke via the standard `Agent` tool with `subagent_type=general-purpose`.

CLI usage:
    python3 .claude/scripts/invoke_cspm_agent.py --agent threat-engine \\
            --story JNY-01 --task "review the design for the mitre_technique_reference table"

Outputs a single self-contained prompt to stdout — paste into Agent(prompt=...).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Map of human story IDs to their canonical agent set (from ADR §4.3.1).
# Keep this in sync when stories or RACI change.
STORY_AGENTS: dict[str, dict[str, list[str]]] = {
    "JNY-01": {"R": ["threat-engine", "cspm-db-engineer"], "A_design": ["bmad-security-architect"], "BMad": ["bmad-dev"]},
    "JNY-02": {"R": ["cspm-bff-dev"], "C": ["inventory-engine"], "BMad": ["bmad-dev"]},
    "JNY-03": {"R": ["cspm-django-engineer", "cspm-rbac-guardian"], "A_design": ["bmad-security-architect"], "BMad": ["bmad-security-po"]},
    "JNY-04": {"R": ["cspm-deploy"]},
    "JNY-05": {"R": ["cspm-ui-dev"], "C": ["inventory-engine", "threat-engine", "ciem-engine"], "A_design": ["bmad-security-architect", "bmad-architect"], "BMad": ["bmad-dev", "bmad-agent-ux-designer"]},
    "JNY-06": {"R": ["cspm-bff-dev"], "C": ["all-engine-agents"], "A_design": ["bmad-security-architect"], "BMad": ["bmad-dev"]},
    "JNY-07": {"R": ["cspm-ui-dev"], "BMad": ["bmad-architect", "bmad-agent-ux-designer", "bmad-dev"]},
    "JNY-08": {"R": ["cspm-ui-dev"], "C": ["iam-engine", "network-security", "datasec", "encryption", "container-security", "dbsec", "ai-security"], "BMad": ["bmad-dev"]},
    "JNY-09": {"R": ["cspm-ui-dev"], "C": ["threat-engine"], "BMad": ["bmad-dev"]},
    "JNY-10": {"R": ["ciem-engine"], "BMad": ["bmad-dev"]},
    "JNY-11": {"R": ["cspm-ui-dev"], "BMad": ["bmad-architect", "bmad-dev"]},
    "JNY-12": {"R": ["cspm-ui-dev", "cspm-bff-dev"], "C": ["risk", "vulnerability"], "BMad": ["bmad-dev"]},
    "JNY-13": {"R": ["cspm-bff-dev"], "C": ["all-engine-agents"], "A_design": ["bmad-security-architect"], "BMad": ["bmad-qa"]},
    "JNY-14": {"R": ["cspm-ui-dev", "cspm-bff-dev"], "BMad": ["bmad-architect", "bmad-dev"]},
    "JNY-15": {"R": ["all-22-engine-agents"], "A_design": ["bmad-security-architect"], "BMad": ["bmad-dev", "bmad-qa"]},
    "JNY-16": {"R": ["cspm-ui-dev", "cspm-bff-dev"], "C": ["onboarding", "vulnerability", "cspm-django-engineer"], "BMad": ["bmad-dev"]},
    "JNY-17": {"R": ["cspm-ui-dev", "cspm-bff-dev"], "C": ["onboarding", "vulnerability", "cspm-django-engineer"], "A_design": ["bmad-security-architect"], "BMad": ["bmad-dev"]},
    "JNY-18": {"R": ["cspm-standards-guardian"], "BMad": ["bmad-architect"]},
}

# Sub-task fan-outs (one prompt per sub-task).
SUBTASKS: dict[str, list[tuple[str, str, str]]] = {
    "JNY-08": [
        ("JNY-08.1", "iam-engine", "frontend/src/app/iam/page.jsx"),
        ("JNY-08.2", "network-security", "frontend/src/app/network-security/page.jsx"),
        ("JNY-08.3", "datasec", "frontend/src/app/datasec/page.jsx"),
        ("JNY-08.4", "encryption", "frontend/src/app/encryption/page.jsx"),
        ("JNY-08.5", "container-security", "frontend/src/app/container-security/page.jsx"),
        ("JNY-08.6", "dbsec", "frontend/src/app/database-security/page.jsx"),
        ("JNY-08.7", "ai-security", "frontend/src/app/ai-security/page.jsx"),
    ],
    "JNY-15": [
        (f"JNY-15.{i+1}", agent, f"engines/{agent.replace('-engine','').replace('-','_')}/")
        for i, agent in enumerate([
            "discoveries", "inventory-engine", "check", "threat-engine", "compliance",
            "iam-engine", "datasec", "encryption", "secops", "risk",
            "onboarding", "rule-catalog", "network-security", "ciem-engine", "ai-security",
            "container-security", "cnapp", "cwpp", "vulnerability", "dbsec",
            "billing", "platform-admin",
        ])
    ],
    "JNY-17": [
        ("JNY-17.1", "onboarding", "/onboarding/api/v1/cloud-accounts → /api/v1/views/onboarding/cloud_accounts"),
        ("JNY-17.2", "vulnerability", "/vulnerability/api/v1/* → /api/v1/views/vulnerability/*"),
        ("JNY-17.3", "vulnerability", "/sbom/api/v1/* → /api/v1/views/sbom/*"),
        ("JNY-17.4", "cspm-django-engineer", "lock /cspm/api/auth/* to whitelist"),
    ],
}


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
AGENT_DIR = REPO_ROOT / ".claude" / "agents"
STORY_DIR = REPO_ROOT / ".claude" / "planning" / "stories"


def load_agent_context(agent_name: str) -> str:
    """Read the .claude/agents/<agent>.md file as the agent's persona+context."""
    # Try by the in-frontmatter name first (e.g. threat-engine -> threat.md),
    # then fall back to filename match.
    name_to_filename = {
        "threat-engine": "threat",
        "iam-engine": "iam",
        "ciem-engine": "ciem",
        "inventory-engine": "inventory",
        "rule-catalog": "rule",
    }
    fname = name_to_filename.get(agent_name, agent_name)
    candidate = AGENT_DIR / f"{fname}.md"
    if not candidate.exists():
        return f"<agent file not found: {agent_name} (looked for {candidate})>"
    return candidate.read_text()


def load_story(story_id: str) -> str:
    """Read the JNY-NN_*.md story file."""
    matches = list(STORY_DIR.glob(f"{story_id}_*.md"))
    if not matches:
        return f"<story file not found: {story_id}>"
    return matches[0].read_text()


def build_prompt(agent_name: str, story_id: str, task: str) -> str:
    """Construct a self-contained prompt for the general-purpose Agent.

    The prompt:
      1. Loads the agent persona (.claude/agents/<name>.md) as system context.
      2. Loads the story file as the work order.
      3. States the specific task the agent must perform.
      4. References the constitution and binding map.
    """
    agent_ctx = load_agent_context(agent_name)
    story_md = load_story(story_id)

    prompt = f"""You are operating as the **{agent_name}** specialist agent. Your full
context is loaded below. Stay strictly in role — do not impersonate other
agents.

================ AGENT PERSONA & DOMAIN CONTEXT ================

{agent_ctx}

================ STORY FILE ====================================

{story_md}

================ YOUR TASK =====================================

{task}

================ HARD RULES ====================================

1. Read .claude/documentation/CSPM_CONSTITUTION.md before producing any
   design or code.
2. Honor the RACI in the story file. If your role is Consulted (C), produce
   feedback for the Responsible agent(s) — do NOT do their work.
3. Apply your domain-specific gotchas (listed in your persona above).
4. When you finish, write a one-page handoff at:
   .claude/planning/stories/{story_id}_handoff_{agent_name}.md
   summarizing decisions made, open questions, and what the next agent
   should pick up.
5. Do not modify the story file's RACI, AC, or Phase fields.
"""
    return prompt


def main():
    p = argparse.ArgumentParser(description="Build a CSPM/BMad agent invocation prompt.")
    p.add_argument("--agent", required=True, help="Agent name (e.g. threat-engine, bmad-security-architect)")
    p.add_argument("--story", required=True, help="Story ID (e.g. JNY-01)")
    p.add_argument("--task", required=True, help="Specific task description for the agent")
    args = p.parse_args()

    prompt = build_prompt(args.agent, args.story, args.task)
    sys.stdout.write(prompt)


if __name__ == "__main__":
    main()
