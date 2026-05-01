#!/usr/bin/env python3
"""
Pilot — generate check YAMLs for 5 rules via DeepSeek.
Validates each against PASS/FAIL fixtures before saving.

Usage:
    python pilot_generate.py
"""

import json
import re
import sys
import time
import pathlib
import importlib.util

import yaml
from openai import OpenAI

# ── Config ─────────────────────────────────────────────────────────
BASE     = pathlib.Path(__file__).parent
DEEPSEEK = OpenAI(
    api_key="sk-3d7acb8511ad4da18e8b0c89733f472b",
    base_url="https://api.deepseek.com",
)

# ── Load fixture index ─────────────────────────────────────────────
with open(BASE / "fixtures" / "index.json") as f:
    FX_IDX = json.load(f)


# ── Load all golden examples (for few-shot) ────────────────────────
def _load_goldens():
    goldens = []
    for py in (BASE / "golden").rglob("*.py"):
        if py.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(py.stem, py)
        mod  = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception:
            continue
        if hasattr(mod, "SPEC") and hasattr(mod, "FIXTURE_PASS"):
            goldens.append({
                "rule_id":      mod.SPEC.rule_id,
                "for_each":     mod.SPEC.for_each,
                "severity":     mod.SPEC.severity,
                "pattern":      mod.SPEC.pattern,
                "conditions":   mod.SPEC.conditions,
                "fixture_pass": mod.FIXTURE_PASS,
            })
    return goldens

GOLDENS = _load_goldens()
print(f"Loaded {len(GOLDENS)} golden examples")


# ── Fixture helpers ────────────────────────────────────────────────
def _load_fixture(path_or_dict):
    if path_or_dict is None:
        return None
    if isinstance(path_or_dict, dict):
        return path_or_dict
    p = BASE / path_or_dict
    return json.loads(p.read_text()) if p.exists() else None


def get_fixtures(for_each: str):
    entry = FX_IDX.get(for_each)
    if not entry:
        return None, None
    return _load_fixture(entry.get("fixture_pass")), _load_fixture(entry.get("fixture_fail"))


def find_for_each_candidates(rule_id: str) -> list:
    """Find all fixture ops whose service matches the rule's CSP.service segment."""
    parts = rule_id.split(".")          # e.g. ['gcp', 'compute', 'instance', 'serial_port…']
    csp   = parts[0]                    # 'gcp'
    svc   = parts[1] if len(parts) > 1 else ""
    return [k for k in FX_IDX if k.startswith(f"{csp}.{svc}.")]


# ── Pick 3 most relevant golden examples ──────────────────────────
_KEYWORD_PATTERNS = {
    ("_enabled", "_activated", "_required"):           ["scalar-exists", "boolean-equals-true"],
    ("_disabled", "no_", "_restricted"):               ["boolean-is-false", "array-not-contains"],
    ("_age_", "_threshold", "_days", "_length"):       ["numeric-threshold"],
    ("unrestricted_", "no_open_", "no_wildcard"):      ["array-not-contains"],
    ("_compliant", "_policy_", "_all_"):               ["array-all-condition"],
    ("_configured", "_present", "_defined"):           ["array-not-empty", "not-empty"],
    ("_version", "_tls_", "_protocol_"):               ["value-in-list"],
}

def pick_goldens(rule_id: str, n: int = 3) -> list:
    leaf = rule_id.split(".")[-1]
    matched_patterns: list[str] = []
    for kws, patterns in _KEYWORD_PATTERNS.items():
        if any(kw in leaf for kw in kws):
            matched_patterns.extend(patterns)
    matched_patterns = list(dict.fromkeys(matched_patterns))      # deduplicate
    # Fill to n from defaults
    defaults = ["scalar-exists", "boolean-equals-true", "array-not-contains",
                "numeric-threshold", "array-not-empty"]
    for d in defaults:
        if len(matched_patterns) >= n:
            break
        if d not in matched_patterns:
            matched_patterns.append(d)
    want = matched_patterns[:n]
    result = []
    for pat in want:
        match = next((g for g in GOLDENS if g["pattern"] == pat), None)
        if match:
            result.append(match)
    # Pad with any remaining goldens
    for g in GOLDENS:
        if len(result) >= n:
            break
        if g not in result:
            result.append(g)
    return result[:n]


# ── Build LLM prompt ───────────────────────────────────────────────
def build_prompt(rule_id: str, severity: str, candidates: list[dict], examples: list[dict], retry_error: str = "") -> str:
    # Format candidates: show for_each op + its PASS fixture (truncated)
    cand_text = ""
    for c in candidates[:4]:
        fx_pass, _ = get_fixtures(c["op"])
        if fx_pass:
            cand_text += f"\n  Op: {c['op']}\n  Fields: {json.dumps(fx_pass, indent=2)[:600]}\n"

    # Format golden examples
    ex_text = ""
    for i, ex in enumerate(examples, 1):
        ex_text += f"""
Example {i} (pattern: {ex['pattern']}):
  rule_id:   {ex['rule_id']}
  for_each:  {ex['for_each']}
  fixture:   {json.dumps(ex['fixture_pass'], indent=2)[:350]}
  conditions: {json.dumps(ex['conditions'], indent=2)}
"""

    retry = f"\n⚠ Previous attempt failed: {retry_error}\nFix the error.\n" if retry_error else ""

    return f"""You generate security check specs for a CSPM platform.

Rule to generate:
  rule_id:  {rule_id}
  severity: {severity}

Available discovery ops and their emitted fields (pick the BEST matching op as for_each):
{cand_text}

Reference examples (same output format required):
{ex_text}
{retry}
Operators: exists, not_exists, is_true, is_false, equals, not_equals,
           gt, gte, lt, lte, contains, not_contains, in, not_in,
           length_gte, length_gt, not_empty, is_empty

Path rules:
- Use dot notation: item.field.nested
- Arrays: item.list[].field  (collects from all elements)
- Indexed: item.Rules[0].field  (first element only)
- For boolean fields use is_true / is_false (no value needed)
- For existence checks use exists (no value needed)
- For compound: {{"all": [...]}} or {{"any": [...]}}

CRITICAL RULE: Conditions must evaluate to TRUE for a COMPLIANT (healthy) resource.
- ✓ CORRECT: {{"var": "item.Status", "op": "equals", "value": "ACTIVE"}}   ← True when resource is good
- ✗ WRONG:   {{"var": "item.Status", "op": "not_equals", "value": "ACTIVE"}} ← True when resource is BAD

The PASS fixture shows a COMPLIANT resource — your conditions must return True for it.
The FAIL fixture shows a NON-COMPLIANT resource — your conditions must return False for it.

OUTPUT: a single JSON object with exactly two keys: "for_each" and "conditions".
No markdown, no explanation, no code blocks — just the raw JSON object.

Example output:
  {{"for_each": "gcp.compute.instances.list", "conditions": {{"var": "item.shieldedInstanceConfig.enableVtpm", "op": "is_true"}}}}
"""


# ── Parse LLM response ─────────────────────────────────────────────
def parse_response(text: str) -> dict | None:
    text = text.strip()
    # Strip markdown fences
    text = re.sub(r"^```[a-z]*\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\s*```$",        "", text, flags=re.MULTILINE)
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass
    return None


# ── Validate conditions against fixtures ──────────────────────────
sys.path.insert(0, str(BASE))
from python_to_yaml_generator import CheckSpec, emit_yaml, evaluate_conditions


def validate(rule_id: str, for_each: str, severity: str, conditions: dict) -> tuple[bool, str]:
    """Validate conditions against PASS/FAIL fixtures using evaluate_conditions directly."""
    fx_pass, fx_fail = get_fixtures(for_each)

    # Skip validation if fixture has no real data (all example-value fields)
    def is_trivial(fx):
        if fx is None:
            return True
        flat = json.dumps(fx)
        return flat.count("example-value") > len(fx) * 0.5   # >50% placeholder values

    if fx_pass is not None and not is_trivial(fx_pass):
        ok = evaluate_conditions(fx_pass, conditions)
        if not ok:
            return False, "PASS fixture returned FAIL — conditions too strict or wrong field/path"

    if fx_fail is not None and not is_trivial(fx_fail):
        ok = evaluate_conditions(fx_fail, conditions)
        if ok:
            return False, "FAIL fixture returned PASS — conditions too loose or wrong field"

    return True, ""


# ── Call DeepSeek ──────────────────────────────────────────────────
def call_deepseek(prompt: str) -> str:
    resp = DEEPSEEK.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": "Output only valid JSON. No markdown, no explanation."},
            {"role": "user",   "content": prompt},
        ],
        temperature=0.1,
        max_tokens=512,
    )
    return resp.choices[0].message.content.strip()


# ── Pilot rules ────────────────────────────────────────────────────
def pick_pilot_rules(n: int = 5) -> list[dict]:
    """Pick n diverse rules that have fixture coverage."""
    pilots = []
    seen_svcs = set()

    for yaml_file in sorted(BASE.glob("*_full_scope_assertions.yaml")):
        with open(yaml_file) as f:
            data = yaml.safe_load(f)

        rows = []
        if isinstance(data, list):
            rows = data
        elif isinstance(data, dict):
            for v1 in data.values():
                if isinstance(v1, dict):
                    for v2 in v1.values():
                        if isinstance(v2, list):
                            rows.extend(v2)
                elif isinstance(v1, list):
                    rows.extend(v1)

        for r in rows:
            if not isinstance(r, dict):
                continue
            if r.get("implementable") != "SCAN_ABLE":
                continue
            rule_id = r.get("rule_id", "")
            svc_key  = ".".join(rule_id.split(".")[:2])
            if svc_key in seen_svcs:
                continue
            if not find_for_each_candidates(rule_id):
                continue
            pilots.append({
                "rule_id":  rule_id,
                "severity": r.get("severity", "medium"),
            })
            seen_svcs.add(svc_key)
            if len(pilots) >= n:
                return pilots
    return pilots


# ── Main ───────────────────────────────────────────────────────────
def main():
    pilots = pick_pilot_rules(5)
    print(f"\n{'='*60}")
    print(f"Pilot: generating {len(pilots)} rules")
    print(f"{'='*60}\n")

    results = []

    for rule in pilots:
        rule_id  = rule["rule_id"]
        severity = rule["severity"]
        cands_raw = find_for_each_candidates(rule_id)

        # Build candidate list with fixtures for the prompt
        cands = [{"op": op} for op in cands_raw[:6]]
        examples = pick_goldens(rule_id)

        print(f"► {rule_id}")
        print(f"  severity: {severity}  |  candidates: {len(cands_raw)}")

        success    = False
        conditions = None
        for_each   = None
        last_err   = ""

        for attempt in range(3):
            prompt     = build_prompt(rule_id, severity, cands, examples, last_err if attempt else "")
            raw        = call_deepseek(prompt)
            parsed     = parse_response(raw)

            print(f"  attempt {attempt+1} raw: {raw[:200]}")

            if parsed is None:
                last_err = f"Could not parse JSON: {raw[:120]}"
                print(f"  attempt {attempt+1}: parse failed — {last_err}")
                continue

            for_each   = parsed.get("for_each", "")
            conditions = parsed.get("conditions")

            if not for_each or not conditions:
                last_err = f"Missing for_each or conditions in: {parsed}"
                print(f"  attempt {attempt+1}: missing keys — {last_err}")
                continue

            print(f"  attempt {attempt+1}: for_each={for_each}  conditions={json.dumps(conditions)}")

            ok, err = validate(rule_id, for_each, severity, conditions)
            if ok:
                success = True
                break
            else:
                last_err = err
                print(f"  attempt {attempt+1}: validation failed — {err}")

            time.sleep(0.3)

        if success:
            yaml_out = emit_yaml(CheckSpec(
                rule_id=rule_id, for_each=for_each,
                severity=severity.upper(), pattern="generated",
                conditions=conditions,
            ))
            out_dir = BASE / "generated_pilot"
            out_dir.mkdir(exist_ok=True)
            csp = rule_id.split(".")[0]
            svc = rule_id.split(".")[1]
            (out_dir / csp).mkdir(exist_ok=True)
            out_path = out_dir / csp / f"{rule_id}.yaml"
            out_path.write_text(yaml_out)
            print(f"  ✓  for_each: {for_each}")
            print(f"     conditions: {json.dumps(conditions)}")
            print(f"     saved: {out_path.relative_to(BASE)}")
        else:
            print(f"  ✗  FAILED after 3 attempts: {last_err}")

        results.append({"rule_id": rule_id, "success": success, "for_each": for_each,
                         "conditions": conditions, "error": last_err if not success else ""})
        print()

    passed = sum(1 for r in results if r["success"])
    print(f"{'='*60}")
    print(f"Pilot result: {passed}/{len(results)} passed")

    if passed == len(results):
        print("\nAll passed — ready to run full generation.")
        print("Next: python generate_checks.py")


if __name__ == "__main__":
    main()
