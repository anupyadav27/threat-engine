"""
LLM prompt templates for the Threat Narrative Engine.

Two prompts are defined:
  - chain_of_consequence: one-sentence consequence summary for executive audience
  - stakes_narrative: 3-4 sentence paragraph for the Scenario Detail Panel (Chapter 3)

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

CHAIN_USER_TEMPLATE = """Generate a Chain of Consequence sentence for this threat scenario:

- Scenario type: {scenario_type}
- Attack chain: {attack_chain_description}
- Attacker entry technique: {entry_technique_description}
- Target asset: {resource_name} ({resource_type})
- Data classification: {data_classification}
- Blast radius score: {blast_radius_score}/100, affects {affected_resource_count} resources
- Estimated financial impact: {estimated_impact_display}
- Compliance frameworks at risk: {framework_list}

Format your response as exactly one sentence beginning with:
"If this scenario executes, [actor] could [action] your [asset], [consequence including regulatory/financial impact]."

Do not include any text before or after the sentence."""


# ── Stakes Narrative ───────────────────────────────────────────────────────────

STAKES_SYSTEM = (
    "You are a security analyst writing threat scenario summaries. "
    "Write 3-4 sentences. Use business language. Be specific about business impact. "
    "Do not use bullet points. Do not mention internal system names or CVE IDs."
)

STAKES_USER_TEMPLATE = """Write a 3-4 sentence Stakes Narrative paragraph for this threat scenario.

Context:
- {chain_of_consequence}  (use this as the opening sentence)
- Primary resource: {resource_name} ({resource_type}) in {region}
- Attack path: {attack_chain_description}
- Data classification: {data_classification}, estimated {estimated_record_count} records
- Blast radius: {blast_radius_score}/100, {affected_resource_count} reachable resources
- Compliance risk: {framework_list}
- Identity involved: {identity_description}

Write the paragraph. Do not include any heading or prefix."""


# ── Data preparation helpers ───────────────────────────────────────────────────

def build_attack_chain_description(attack_chain: Any) -> str:
    """Convert attack_chain JSONB to a readable description for LLM prompt.

    Args:
        attack_chain: The attack_chain value from threat_detections — may be a
            list of step dicts, a dict with a 'steps' or 'chain' key, a plain
            string, or None.

    Returns:
        Human-readable arrow-separated description, e.g.
        "Initial Access → Credential Dumping → Lateral Movement → Data Exfiltration"
    """
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
    for s in steps[:4]:  # cap at 4 steps to keep prompt length manageable
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
    """Format estimated financial impact for prompt display.

    Args:
        estimated_impact: Numeric value (int/float) or None.

    Returns:
        Formatted string such as "~$1,250,000" or "unknown financial impact".
    """
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
    """Format CIEM identity signal for prompt display.

    Args:
        ciem_row: Dict with keys identity_type, privilege_level, principal_name,
            or None if no CIEM finding was found for the resource.

    Returns:
        e.g. "admin IAM role (data-processor-role)" or
        "no identity signal contributing".
    """
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


def build_chain_user_prompt(ctx: dict) -> str:
    """Render the chain_of_consequence user prompt from a context dict.

    Args:
        ctx: Dict produced by db_reader.read_detection_context(). All fields
            must be present (db_reader guarantees safe fallback values).

    Returns:
        Rendered prompt string ready to send to the LLM.
    """
    return CHAIN_USER_TEMPLATE.format(
        scenario_type=ctx.get("scenario_type") or "threat scenario",
        attack_chain_description=ctx.get("attack_chain_description") or "multi-stage attack path",
        entry_technique_description=ctx.get("entry_technique_description") or "initial access",
        resource_name=ctx.get("resource_name") or ctx.get("resource_uid") or "cloud resource",
        resource_type=ctx.get("resource_type") or "resource",
        data_classification=ctx.get("data_classification") or "unknown classification",
        blast_radius_score=ctx.get("blast_radius_score") or 0,
        affected_resource_count=ctx.get("affected_resource_count") or 0,
        estimated_impact_display=ctx.get("estimated_impact_display") or "unknown financial impact",
        framework_list=ctx.get("framework_list") or "none identified",
    )


def build_stakes_user_prompt(ctx: dict, chain_of_consequence: str) -> str:
    """Render the stakes_narrative user prompt from a context dict.

    Args:
        ctx: Dict produced by db_reader.read_detection_context().
        chain_of_consequence: The already-generated chain sentence (used as
            the opening sentence of the paragraph).

    Returns:
        Rendered prompt string ready to send to the LLM.
    """
    return STAKES_USER_TEMPLATE.format(
        chain_of_consequence=chain_of_consequence,
        resource_name=ctx.get("resource_name") or ctx.get("resource_uid") or "cloud resource",
        resource_type=ctx.get("resource_type") or "resource",
        region=ctx.get("region") or "unknown region",
        attack_chain_description=ctx.get("attack_chain_description") or "multi-stage attack path",
        data_classification=ctx.get("data_classification") or "unknown classification",
        estimated_record_count=ctx.get("estimated_record_count") or "an unknown number of",
        blast_radius_score=ctx.get("blast_radius_score") or 0,
        affected_resource_count=ctx.get("affected_resource_count") or 0,
        framework_list=ctx.get("framework_list") or "none identified",
        identity_description=ctx.get("identity_description") or "no identity signal contributing",
    )
