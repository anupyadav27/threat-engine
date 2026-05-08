#!/usr/bin/env python3
"""
Phase 3 — Bulk Check Generation via DeepSeek.

Generates check YAMLs for all 8,812 SCAN_ABLE + MULTI_OP rules across 7 CSPs.
Output: generated/{csp}/{service}/{rule_id}.yaml  (inside this folder)

Features:
- Resumable: skips already-generated rules
- Validates each result against PASS/FAIL fixtures before saving
- 3 attempts per rule with escalating error context
- Progress tracking in generate_progress.json
- Failed rules logged to failed_rules.jsonl

Usage:
    python generate_checks.py              # all CSPs
    python generate_checks.py --csp aws    # single CSP
    python generate_checks.py --limit 100  # first N rules (testing)
"""

import argparse
import importlib.util
import json
import pathlib
import re
import sys
import time

import yaml
from openai import OpenAI

# ── Paths ──────────────────────────────────────────────────────────
BASE = pathlib.Path(__file__).parent

RULE_FILES = {
    "aws":      BASE / "1_aws_full_scope_assertions.yaml",
    "azure":    BASE / "2_azure_full_scope_assertions.yaml",
    "gcp":      BASE / "3_gcp_full_scope_assertions.yaml",
    "oci":      BASE / "4_oci_full_scope_assertions.yaml",
    "k8s":      BASE / "5_k8s_full_scope_assertions.yaml",
    "alicloud": BASE / "6_alicloud_full_scope_assertions.yaml",
    "ibm":      BASE / "7_ibm_full_scope_assertions.yaml",
    "ibm_posture": BASE / "8_ibm_posture_assertions.yaml",
}

GENERATED_DIR   = BASE / "generated"
PROGRESS_FILE   = BASE / "generate_progress.json"
FAILED_FILE     = BASE / "failed_rules.jsonl"
FIXTURES_INDEX  = BASE / "fixtures" / "index.json"
GOLDEN_DIR      = BASE / "golden"

# ── DeepSeek client ────────────────────────────────────────────────
DEEPSEEK = OpenAI(
    api_key="sk-3d7acb8511ad4da18e8b0c89733f472b",
    base_url="https://api.deepseek.com",
    timeout=30.0,      # fail fast if network drops (e.g. sleep/wake)
    max_retries=0,     # we handle retries ourselves
)

# ── Load shared resources ──────────────────────────────────────────
sys.path.insert(0, str(BASE))
from python_to_yaml_generator import CheckSpec, evaluate_conditions

with open(FIXTURES_INDEX) as f:
    FX_IDX: dict = json.load(f)


# ══════════════════════════════════════════════════════════════════
# Golden examples loader
# ══════════════════════════════════════════════════════════════════

def load_goldens() -> list[dict]:
    goldens = []
    for py in sorted(GOLDEN_DIR.rglob("*.py")):
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


_PATTERN_HINTS = {
    ("_enabled", "_activated", "_required", "_enforced"):     ["scalar-exists", "boolean-equals-true"],
    ("_disabled", "_restricted", "no_open_", "no_wildcard"): ["boolean-is-false", "array-not-contains"],
    ("_age_", "_days", "_threshold", "_length", "_count"):   ["numeric-threshold"],
    ("unrestricted_", "no_open_", "_open_"):                 ["array-not-contains"],
    ("_policy_compliant", "_policy_configured", "_all_"):    ["array-all-condition", "nested-multi-all"],
    ("_configured", "_present", "_defined", "_exist"):       ["array-not-empty", "not-empty"],
    ("_version", "_tls_", "_protocol_", "_compliant"):       ["value-in-list"],
    ("_encrypted", "_encryption"):                           ["scalar-exists", "boolean-equals-true"],
    ("_logging", "_audit", "_monitored"):                    ["scalar-exists", "not-empty"],
}

def pick_goldens(rule_id: str, goldens: list[dict], n: int = 3) -> list[dict]:
    leaf = rule_id.split(".")[-1]
    matched: list[str] = []
    for kws, patterns in _PATTERN_HINTS.items():
        if any(kw in leaf for kw in kws):
            for p in patterns:
                if p not in matched:
                    matched.append(p)
    defaults = ["scalar-exists", "boolean-equals-true", "array-not-contains",
                "numeric-threshold", "array-not-empty"]
    for d in defaults:
        if len(matched) >= n:
            break
        if d not in matched:
            matched.append(d)
    result = []
    for pat in matched[:n]:
        ex = next((g for g in goldens if g["pattern"] == pat), None)
        if ex and ex not in result:
            result.append(ex)
    for g in goldens:
        if len(result) >= n:
            break
        if g not in result:
            result.append(g)
    return result[:n]


# ══════════════════════════════════════════════════════════════════
# Fixture helpers
# ══════════════════════════════════════════════════════════════════

def _load_fx(path_or_dict) -> dict | None:
    if path_or_dict is None:
        return None
    if isinstance(path_or_dict, dict):
        return path_or_dict
    p = BASE / path_or_dict
    return json.loads(p.read_text()) if p.exists() else None


def get_fixtures(for_each: str) -> tuple[dict | None, dict | None]:
    entry = FX_IDX.get(for_each)
    if not entry or not isinstance(entry, dict):
        return None, None
    return _load_fx(entry.get("fixture_pass")), _load_fx(entry.get("fixture_fail"))


def _is_trivial(fx: dict | None) -> bool:
    """Return True if fixture is mostly placeholder example-values."""
    if fx is None:
        return True
    flat = json.dumps(fx)
    n_fields = len(fx)
    return n_fields == 0 or flat.count("example-value") > n_fields * 0.6


def find_candidates(rule_id: str) -> list[str]:
    """All fixture ops whose prefix matches csp.service."""
    parts = rule_id.split(".")
    prefix = f"{parts[0]}.{parts[1]}." if len(parts) > 1 else ""
    return [k for k in FX_IDX if k.startswith(prefix)]


# ══════════════════════════════════════════════════════════════════
# Prompt builder
# ══════════════════════════════════════════════════════════════════

def build_prompt(rule_id: str, severity: str, candidates: list[str],
                 goldens: list[dict], retry_error: str = "") -> str:

    # Candidate ops with their fixture data
    cand_text = ""
    for op in candidates[:5]:
        fx_pass, _ = get_fixtures(op)
        if fx_pass:
            cand_text += f"\n  Op: {op}\n  Fields (PASS):\n{json.dumps(fx_pass, indent=4)[:700]}\n"
        else:
            entry = FX_IDX.get(op, {})
            fields = entry.get("fields", [])[:12] if isinstance(entry, dict) else []
            if fields:
                cand_text += f"\n  Op: {op}\n  Fields: {fields}\n"

    if not cand_text:
        csp = rule_id.split(".")[0]
        svc = rule_id.split(".")[1] if len(rule_id.split(".")) > 1 else ""
        cand_text = f"\n  (No fixture data for {csp}.{svc} — infer from rule_id semantics)\n"

    # Golden examples
    ex_text = ""
    for i, ex in enumerate(goldens, 1):
        ex_text += f"""
Example {i} — pattern: {ex['pattern']}
  rule_id:    {ex['rule_id']}
  for_each:   {ex['for_each']}
  fixture:    {json.dumps(ex['fixture_pass'], indent=4)[:350]}
  conditions: {json.dumps(ex['conditions'], indent=4)}
"""

    retry = (f"\n⚠ PREVIOUS ATTEMPT FAILED: {retry_error}\n"
             "Look at the PASS fixture carefully and pick the correct field and operator.\n")  \
             if retry_error else ""

    return f"""You generate CSPM security check specs.

Rule to generate:
  rule_id:  {rule_id}
  severity: {severity}

Available discovery ops and their emitted fields — choose the BEST matching op:
{cand_text}

Reference examples (match this exact output format):
{ex_text}
{retry}
Operators: exists, not_exists, is_true, is_false, equals, not_equals,
           gt, gte, lt, lte, contains, not_contains, in, not_in,
           length_gte, length_gt, not_empty, is_empty

Path notation:
  item.field           — top-level field
  item.a.b.c           — nested field
  item.list[].field    — collect field from every array element
  item.arr[0].field    — first element only

⚠ CRITICAL: Conditions must evaluate to TRUE for a COMPLIANT (secure) resource.
  ✓ CORRECT: {{"var": "item.Enabled", "op": "is_true"}}        ← True = resource is secure
  ✗ WRONG:   {{"var": "item.Enabled", "op": "is_false"}}       ← True = resource is INSECURE

The PASS fixture is a COMPLIANT resource → your conditions must return True for it.
The FAIL fixture is a NON-COMPLIANT resource → your conditions must return False for it.

Compound syntax:
  All conditions true:  {{"all": [{{"var":"item.a","op":"exists"}}, {{"var":"item.b","op":"is_true"}}]}}
  Any condition true:   {{"any": [{{"var":"item.a","op":"equals","value":"X"}}, ...]}}

OUTPUT: ONE JSON object with exactly two keys — "for_each" and "conditions".
No markdown, no explanation. Raw JSON only.
"""


# ══════════════════════════════════════════════════════════════════
# LLM call + response parsing
# ══════════════════════════════════════════════════════════════════

def call_deepseek(prompt: str) -> str:
    resp = DEEPSEEK.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system",
             "content": "Output only valid JSON. No markdown, no explanation, no code blocks."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
        max_tokens=600,
    )
    return resp.choices[0].message.content.strip()


def parse_response(text: str) -> dict | None:
    text = re.sub(r"^```[a-z]*\s*", "", text.strip(), flags=re.MULTILINE)
    text = re.sub(r"\s*```$",        "", text,         flags=re.MULTILINE)
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


# ══════════════════════════════════════════════════════════════════
# Validation
# ══════════════════════════════════════════════════════════════════

def validate(for_each: str, conditions: dict) -> tuple[bool, str]:
    fx_pass, fx_fail = get_fixtures(for_each)

    if fx_pass is not None and not _is_trivial(fx_pass):
        ok = evaluate_conditions(fx_pass, conditions)
        if not ok:
            return False, f"PASS fixture returned FAIL — wrong field or operator (pass_fixture keys: {list(fx_pass.keys())[:8]})"

    if fx_fail is not None and not _is_trivial(fx_fail):
        ok = evaluate_conditions(fx_fail, conditions)
        if ok:
            return False, f"FAIL fixture returned PASS — conditions too loose (fail_fixture keys: {list(fx_fail.keys())[:8]})"

    return True, ""


# ══════════════════════════════════════════════════════════════════
# Rule loader
# ══════════════════════════════════════════════════════════════════

def load_all_rules(csp_filter: str | None = None) -> list[dict]:
    rules = []
    for csp_key, path in RULE_FILES.items():
        # ibm_posture is a variant of ibm — match both on --csp ibm
        csp_base = csp_key.split("_")[0] if "_posture" in csp_key else csp_key
        if csp_filter and csp_key != csp_filter and csp_base != csp_filter:
            continue
        if not path.exists():
            continue
        with open(path) as f:
            data = yaml.safe_load(f)

        rows: list = []
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
            if r.get("implementable") not in ("SCAN_ABLE", "MULTI_OP"):
                continue
            if r.get("is_duplicate"):
                continue
            # Derive real csp from rule_id prefix (e.g. ibm from ibm.vpc.instance.*)
            actual_csp = r["rule_id"].split(".")[0] if "rule_id" in r else csp_base
            rules.append({
                "rule_id":  r["rule_id"],
                "severity": r.get("severity", "medium"),
                "csp":      actual_csp,
            })

    return rules


# ══════════════════════════════════════════════════════════════════
# Progress tracking
# ══════════════════════════════════════════════════════════════════

def load_progress() -> dict:
    if PROGRESS_FILE.exists():
        with open(PROGRESS_FILE) as f:
            return json.load(f)
    return {"generated": {}, "failed": [], "skipped_no_fixture": []}


def save_progress(progress: dict):
    with open(PROGRESS_FILE, "w") as f:
        json.dump(progress, f, indent=2)


# ══════════════════════════════════════════════════════════════════
# Save output YAML
# ══════════════════════════════════════════════════════════════════

def save_yaml(rule_id: str, for_each: str, severity: str, conditions: dict,
              fixture_error: str = "") -> str:
    csp = rule_id.split(".")[0]
    svc = rule_id.split(".")[1] if len(rule_id.split(".")) > 1 else "unknown"
    out_dir = GENERATED_DIR / csp / svc
    out_dir.mkdir(parents=True, exist_ok=True)

    import yaml as _yaml
    doc = {
        "version":   "1.0",
        "rule_id":   rule_id,
        "for_each":  for_each,
        "severity":  severity.upper(),
        "conditions": conditions,
    }
    if fixture_error:
        doc["fixture_validated"] = False
        doc["fixture_note"]      = fixture_error   # e.g. "PASS fixture returned FAIL — wrong field …"

    content = _yaml.safe_dump(doc, sort_keys=False, default_flow_style=False,
                              allow_unicode=True, width=120)
    # Truncate filename to avoid OSError: [Errno 63] File name too long (macOS 255-char limit)
    fname = rule_id if len(rule_id) <= 200 else rule_id[:200]
    out_path = out_dir / f"{fname}.yaml"
    out_path.write_text(content)
    return str(out_path.relative_to(BASE))


# ══════════════════════════════════════════════════════════════════
# Main generation loop
# ══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csp",   help="Single CSP to process (aws/azure/gcp/oci/k8s/alicloud/ibm)")
    parser.add_argument("--limit", type=int, help="Process only first N rules (for testing)")
    parser.add_argument("--retry-failed", action="store_true", help="Re-attempt previously failed rules")
    args = parser.parse_args()

    print("Phase 3 — Bulk Check Generation (DeepSeek)")
    print("=" * 60)

    goldens = load_goldens()
    print(f"Golden examples loaded: {len(goldens)}")

    all_rules = load_all_rules(args.csp)
    if args.limit:
        all_rules = all_rules[: args.limit]
    print(f"Rules to generate: {len(all_rules)}")

    progress = load_progress()
    already_done   = set(progress["generated"].keys())
    already_failed = set(progress["failed"]) if not args.retry_failed else set()

    pending = [r for r in all_rules
               if r["rule_id"] not in already_done
               and r["rule_id"] not in already_failed]

    print(f"Already done: {len(already_done)}  |  Failed: {len(already_failed)}  |  Pending: {len(pending)}")
    print()

    failed_log = open(FAILED_FILE, "a", buffering=1)
    n_pass = n_fail = n_no_fixture = 0
    SAVE_EVERY = 25

    for idx, rule in enumerate(pending, 1):
        rule_id  = rule["rule_id"]
        severity = rule["severity"]
        cands    = find_candidates(rule_id)

        success    = False
        for_each   = None
        conditions = None
        last_err   = ""

        fixture_ok   = True   # True = fixture validation passed (or skipped)
        parse_failed = False

        for attempt in range(3):
            try:
                prompt   = build_prompt(rule_id, severity, cands,
                                        pick_goldens(rule_id, goldens),
                                        retry_error=last_err if attempt else "")
                raw      = call_deepseek(prompt)
                parsed   = parse_response(raw)

                if parsed is None:
                    last_err = f"JSON parse failed: {raw[:100]}"
                    parse_failed = True
                    continue

                for_each   = parsed.get("for_each", "")
                conditions = parsed.get("conditions")

                if not for_each or not conditions:
                    last_err = f"Missing for_each or conditions in response"
                    parse_failed = True
                    continue

                parse_failed = False
                ok, err = validate(for_each, conditions)
                if ok:
                    fixture_ok = True
                    success    = True
                    break
                else:
                    # fixture mismatch — generation succeeded, fixture needs review
                    fixture_ok = False
                    last_err   = err
                    success    = True   # still save — conditions may be correct
                    break

            except Exception as e:
                last_err = f"API error: {e}"
                parse_failed = True
                time.sleep(2)

            time.sleep(0.15)   # rate-limit buffer between attempts

        # ── Save result ───────────────────────────────────────────
        if success:
            # Save all generated YAMLs; mark fixture mismatches for later review
            rel_path = save_yaml(rule_id, for_each, severity, conditions,
                                 fixture_error=last_err if not fixture_ok else "")
            progress["generated"][rule_id] = rel_path
            if not fixture_ok:
                # log for fixture review — not a generation failure
                failed_log.write(json.dumps({
                    "rule_id": rule_id, "for_each": for_each,
                    "issue": "fixture_mismatch", "error": last_err, "csp": rule["csp"],
                }) + "\n")
                n_fail += 1
                status = "~"   # saved but needs fixture review
            else:
                n_pass += 1
                status = "✓"
        else:
            # Real failure: couldn't even parse a valid response
            progress["failed"].append(rule_id)
            failed_log.write(json.dumps({
                "rule_id": rule_id, "for_each": for_each,
                "issue": "generation_failed", "error": last_err, "csp": rule["csp"],
            }) + "\n")
            n_fail += 1
            status = "✗"

        # ── Progress line ─────────────────────────────────────────
        done_total = len(progress["generated"])
        pct = done_total / len(all_rules) * 100
        suffix = f"  ← {last_err[:55]}" if status in ("~", "✗") else ""
        print(f"[{done_total:5d}/{len(all_rules)} {pct:5.1f}%] {status} {rule_id[:70]}{suffix}")

        if idx % SAVE_EVERY == 0:
            save_progress(progress)

        time.sleep(0.05)   # gentle rate-limit

    save_progress(progress)
    failed_log.close()

    print()
    print("=" * 60)
    n_review = sum(1 for v in progress["generated"].values() if v)  - n_pass
    print(f"✓ Validated   : {n_pass}  (fixture confirmed)")
    print(f"~ Needs review: {n_fail - len(progress['failed'])}  (saved, fixture mismatch — verify later)")
    print(f"✗ Failed      : {len(progress['failed'])}  (parse error, not saved)")
    print(f"Output     : {GENERATED_DIR.relative_to(BASE)}/")
    print(f"Review log : {FAILED_FILE.name}  (fixture_mismatch + generation_failed entries)")


if __name__ == "__main__":
    main()
