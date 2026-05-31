"""
LLM prompt templates for the Attack Path Narrative Engine.

Two prompts are defined:
  - chain_of_consequence: one-sentence consequence summary for executive audience
  - stakes_narrative: 3-4 sentence paragraph for the Scenario Detail Panel

Security note (PASTA):
  LLM prompt injection mitigation — data from DB appears only in the `user` prompt,
  clearly delimited. The `system` prompt never contains data from untrusted sources.
"""

from typing import Any


# ── Chain of Consequence ───────────────────────────────────────────────────────

CHAIN_SYSTEM = (
    "You are a security analyst writing executive summaries for CISOs. "
    "Be specific and concise. Use business language, not technical jargon. "
    "Never mention CVE numbers, rule IDs, or internal identifiers. "
    "Write one sentence only, maximum 60 words."
)

CHAIN_USER_TEMPLATE = """Generate a Chain of Consequence sentence for this attack path:

- Chain type: {chain_type}
- Entry point: {entry_point_type} ({entry_point_uid})
- Target (crown jewel): {crown_jewel_type} ({crown_jewel_uid})
- Attack vector: {attack_vector_type} — MITRE tactics: {tactic_sequence}
- Path severity: {severity} (score {path_score}/100)
- Misconfiguration count: {misconfig_count}
- Data classification at risk: {data_classification}
- Blast radius: {blast_radius_count} reachable resources
- Compliance frameworks at risk: {framework_list}

Format your response as exactly one sentence beginning with:
"If this attack path executes, an attacker could [action], [consequence including business/regulatory impact]."

Do not include any text before or after the sentence."""


# ── Stakes Narrative ───────────────────────────────────────────────────────────

STAKES_SYSTEM = (
    "You are a security analyst writing attack path summaries for a CSPM platform. "
    "Write 3-4 sentences. Use business language. Be specific about business impact. "
    "Do not use bullet points. Do not mention internal system names or CVE IDs."
)

STAKES_USER_TEMPLATE = """Write a 3-4 sentence Stakes Narrative paragraph for this attack path.

Context:
- {chain_of_consequence}  (use this as the opening sentence)
- Entry vector: {entry_point_type} into {chain_type}
- Crown jewel: {crown_jewel_type}, data classification: {data_classification}
- MITRE tactic sequence: {tactic_sequence}
- Misconfiguration exposures: {misconfig_count}, threat signals: {threat_count}
- Blast radius: {blast_radius_count} reachable resources
- Confidence: {confidence_level}
- Compliance risk: {framework_list}

Write the paragraph. Do not include any heading or prefix."""


# ── Data preparation helpers ───────────────────────────────────────────────────

def build_tactic_sequence_display(tactic_sequence: Any) -> str:
    """Convert tactic_sequence JSONB to readable arrow-separated string.

    Args:
        tactic_sequence: List of tactic names or None.

    Returns:
        e.g. "initial-access → lateral-movement → exfiltration"
    """
    if not tactic_sequence:
        return "multi-stage attack"
    if isinstance(tactic_sequence, list):
        return " → ".join(str(t) for t in tactic_sequence[:5] if t)
    if isinstance(tactic_sequence, str):
        return tactic_sequence
    return "multi-stage attack"


def build_mitre_display(mitre_techniques: Any) -> str:
    """Format MITRE techniques list for prompt display.

    Args:
        mitre_techniques: List of technique IDs or None.

    Returns:
        e.g. "T1190, T1078, T1003"
    """
    if not mitre_techniques:
        return "unknown"
    if isinstance(mitre_techniques, list):
        return ", ".join(str(t) for t in mitre_techniques[:5] if t)
    return str(mitre_techniques)


def build_chain_user_prompt(ctx: dict) -> str:
    """Render the chain_of_consequence user prompt from a path context dict.

    Args:
        ctx: Dict produced by db_reader.read_path_context(). All fields
            must be present (db_reader guarantees safe fallback values).

    Returns:
        Rendered prompt string ready to send to the LLM.
    """
    return CHAIN_USER_TEMPLATE.format(
        chain_type=ctx.get("chain_type") or "unknown chain",
        entry_point_type=ctx.get("entry_point_type") or "unknown",
        entry_point_uid=ctx.get("entry_point_uid") or "unknown resource",
        crown_jewel_type=ctx.get("crown_jewel_type") or "unknown asset",
        crown_jewel_uid=ctx.get("crown_jewel_uid") or "unknown resource",
        attack_vector_type=ctx.get("attack_vector_type") or "T1",
        tactic_sequence=ctx.get("tactic_sequence_display") or "multi-stage attack",
        severity=ctx.get("severity") or "medium",
        path_score=ctx.get("path_score") or 0,
        misconfig_count=ctx.get("misconfig_count") or 0,
        data_classification=ctx.get("data_classification") or "unknown classification",
        blast_radius_count=ctx.get("blast_radius_count") or 0,
        framework_list=ctx.get("framework_list") or "none identified",
    )


def build_stakes_user_prompt(ctx: dict, chain_of_consequence: str) -> str:
    """Render the stakes_narrative user prompt from a path context dict.

    Args:
        ctx: Dict produced by db_reader.read_path_context().
        chain_of_consequence: The already-generated chain sentence.

    Returns:
        Rendered prompt string ready to send to the LLM.
    """
    return STAKES_USER_TEMPLATE.format(
        chain_of_consequence=chain_of_consequence,
        entry_point_type=ctx.get("entry_point_type") or "unknown",
        chain_type=ctx.get("chain_type") or "unknown chain",
        crown_jewel_type=ctx.get("crown_jewel_type") or "unknown asset",
        data_classification=ctx.get("data_classification") or "unknown classification",
        tactic_sequence=ctx.get("tactic_sequence_display") or "multi-stage attack",
        misconfig_count=ctx.get("misconfig_count") or 0,
        threat_count=ctx.get("threat_count") or 0,
        blast_radius_count=ctx.get("blast_radius_count") or 0,
        confidence_level=ctx.get("confidence_level") or "speculative",
        framework_list=ctx.get("framework_list") or "none identified",
    )


# ── Legacy helpers kept for backward compatibility ─────────────────────────────

def build_attack_chain_description(attack_chain: Any) -> str:
    """Convert attack_chain JSONB to a readable description."""
    if not attack_chain:
        return "multi-stage attack path"
    if isinstance(attack_chain, str):
        return attack_chain or "multi-stage attack path"
    if isinstance(attack_chain, list):
        steps = attack_chain
    elif isinstance(attack_chain, dict):
        steps = attack_chain.get("steps") or attack_chain.get("chain", [])
    else:
        return "unknown attack path"
    if not steps:
        return "multi-stage attack path"
    parts = []
    for s in steps[:4]:
        if isinstance(s, dict):
            tech = s.get("technique_id") or s.get("technique", "")
            desc = s.get("description") or s.get("action", tech)
            label = desc or tech
            if label:
                parts.append(label)
        elif isinstance(s, str):
            if s:
                parts.append(s)
    return " → ".join(parts) if parts else "multi-stage attack path"


def build_estimated_impact_display(estimated_impact: Any) -> str:
    """Format estimated financial impact for prompt display."""
    if estimated_impact is None:
        return "unknown financial impact"
    try:
        value = float(estimated_impact)
        if value <= 0:
            return "unknown financial impact"
        return f"~${value:,.0f}"
    except (TypeError, ValueError):
        return "unknown financial impact"


def build_identity_description(ciem_row: dict | None) -> str:
    """Format CIEM identity signal for prompt display."""
    if not ciem_row:
        return "no identity signal contributing"
    privilege_level = ciem_row.get("privilege_level") or ""
    identity_type = ciem_row.get("identity_type") or ""
    principal_name = ciem_row.get("principal_name") or ""
    parts = [p for p in [privilege_level, identity_type] if p]
    label = " ".join(parts) if parts else "identity"
    if principal_name:
        return f"{label} ({principal_name})"
    return label or "no identity signal contributing"
