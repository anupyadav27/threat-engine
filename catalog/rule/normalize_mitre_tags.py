#!/usr/bin/env python3
"""
Post-run normalizer for AI-generated MITRE ATT&CK tags.

Fixes 4 quality issues after tag_mitre_ai.py completes:
  1. Tactic format: underscore → hyphen in mitre_tactics
  2. Rogue tactic: remove resource_development / resource-development
  3. Error files: fallback tagging for rules with empty mitre_techniques
  4. Validate all technique IDs (flag non-T#### format)
  5. Ensure threat_category is present and uses underscore format
  6. Output QA report with per-CSP coverage + anomaly list

Usage:
    python normalize_mitre_tags.py            # fix + report
    python normalize_mitre_tags.py --dry-run  # report only, no writes
    python normalize_mitre_tags.py --report-only
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

CATALOG_DIR = Path(__file__).parent
REPORT_FILE = CATALOG_DIR / "mitre_quality_report.json"

# ── Valid ATT&CK tactics (hyphen format) ─────────────────────────────────────
VALID_TACTICS = {
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "exfiltration", "command-and-control", "impact",
    "reconnaissance", "resource-development",  # included for completeness
}

TACTIC_NORMALIZE = {t.replace("-", "_"): t for t in VALID_TACTICS}

TACTIC_TO_CATEGORY = {t: t.replace("-", "_") for t in VALID_TACTICS}

# ── Domain → fallback tactic/technique ───────────────────────────────────────
DOMAIN_FALLBACK: dict[str, dict[str, Any]] = {
    "network_security":              {"techniques": ["T1190"],     "tactics": ["initial-access"]},
    "network_security_and_connect":  {"techniques": ["T1190"],     "tactics": ["initial-access"]},
    "iam_and_access":                {"techniques": ["T1548.005"], "tactics": ["privilege-escalation"]},
    "identity_and_access":           {"techniques": ["T1548.005"], "tactics": ["privilege-escalation"]},
    "logging_and_monitoring":        {"techniques": ["T1562.008"], "tactics": ["defense-evasion"]},
    "audit_and_logging":             {"techniques": ["T1562.008"], "tactics": ["defense-evasion"]},
    "data_protection":               {"techniques": ["T1486"],     "tactics": ["impact"]},
    "data_security":                 {"techniques": ["T1486"],     "tactics": ["impact"]},
    "configuration":                 {"techniques": ["T1562.001"], "tactics": ["defense-evasion"]},
    "configuration_and_change":      {"techniques": ["T1562.001"], "tactics": ["defense-evasion"]},
    "encryption":                    {"techniques": ["T1486"],     "tactics": ["impact"]},
    "access_control":                {"techniques": ["T1078.004"], "tactics": ["defense-evasion"]},
    "backup":                        {"techniques": ["T1485"],     "tactics": ["impact"]},
    "storage":                       {"techniques": ["T1530"],     "tactics": ["collection"]},
    "container":                     {"techniques": ["T1611"],     "tactics": ["privilege-escalation"]},
    "kubernetes":                    {"techniques": ["T1611"],     "tactics": ["privilege-escalation"]},
    "compute":                       {"techniques": ["T1190"],     "tactics": ["initial-access"]},
    "database":                      {"techniques": ["T1190"],     "tactics": ["initial-access"]},
    "serverless":                    {"techniques": ["T1190"],     "tactics": ["initial-access"]},
}

DEFAULT_FALLBACK = {"techniques": ["T1190"], "tactics": ["initial-access"]}

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
ROGUE_TACTICS = {"resource_development", "resource-development", "reconnaissance"}

# ── CSP metadata dirs ─────────────────────────────────────────────────────────
CSP_DIRS = [
    "aws_rule_metadata", "azure_rule_metadata", "azure_rule_metadata_policy",
    "gcp_rule_metadata", "oci_rule_metadata", "alicloud_rule_metadata",
    "ibm_rule_metadata", "k8s_rule_metadata", "container_rule_metadata",
    "linux_rule_metadata", "database_rule_metadata", "data_rule_metadata",
    "devops_rule_metadata", "networking_rule_metadata", "cloud_saas_rule_metadata",
    "virtualization_rule_metadata", "web_server_rule_metadata",
]


def get_domain_fallback(data: dict[str, Any]) -> dict[str, Any]:
    domain = (data.get("domain") or "").lower()
    for key, fb in DOMAIN_FALLBACK.items():
        if key in domain:
            return fb
    service = (data.get("service") or "").lower()
    for key, fb in DOMAIN_FALLBACK.items():
        if key in service:
            return fb
    return DEFAULT_FALLBACK


def normalize_tactics(tactics: list[str]) -> list[str]:
    """Convert underscore tactics to hyphen; remove rogues; deduplicate."""
    result = []
    for t in tactics:
        normalized = TACTIC_NORMALIZE.get(t, t)
        if normalized in ROGUE_TACTICS:
            continue
        if normalized in VALID_TACTICS:
            result.append(normalized)
    return list(dict.fromkeys(result))  # deduplicate preserving order


def fix_rule(data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Apply all fixes to a rule dict. Returns (fixed_data, list_of_changes)."""
    changes: list[str] = []

    techniques: list[str] = data.get("mitre_techniques") or []
    tactics: list[str] = data.get("mitre_tactics") or []
    category: str = data.get("threat_category") or ""

    # Fix 1: normalize tactic format
    normalized_tactics = normalize_tactics(tactics)
    if normalized_tactics != tactics:
        changes.append(f"tactics normalized: {tactics} → {normalized_tactics}")
        tactics = normalized_tactics

    # Fix 2: remove rogue tactics; if tactic list empty → use domain fallback
    if not tactics:
        fb = get_domain_fallback(data)
        tactics = fb["tactics"]
        changes.append(f"tactic fallback from domain: {tactics}")

    # Fix 3: validate technique IDs — remove invalid ones
    valid_techniques = [t for t in techniques if TECHNIQUE_RE.match(str(t))]
    invalid = [t for t in techniques if not TECHNIQUE_RE.match(str(t))]
    if invalid:
        changes.append(f"removed invalid techniques: {invalid}")
    techniques = valid_techniques

    # Fix 4: if techniques empty → domain fallback
    if not techniques:
        fb = get_domain_fallback(data)
        techniques = fb["techniques"]
        tactics = fb["tactics"]
        changes.append(f"technique fallback from domain: {techniques}")

    # Fix 5: ensure threat_category exists and uses underscore
    primary_tactic = tactics[0] if tactics else "initial-access"
    expected_category = primary_tactic.replace("-", "_")
    if not category or category != expected_category:
        changes.append(f"category: {category!r} → {expected_category!r}")
        category = expected_category

    # Fix 6: ensure threat_tags exists
    if not data.get("threat_tags"):
        data["threat_tags"] = [primary_tactic.replace("-", "_")]
        changes.append("added missing threat_tags")

    data["mitre_techniques"] = techniques
    data["mitre_tactics"] = tactics
    data["threat_category"] = category
    return data, changes


def find_all_rule_files() -> list[Path]:
    files: list[Path] = []
    for d in CSP_DIRS:
        base = CATALOG_DIR / d
        if base.exists():
            files.extend(base.glob("**/*.yaml"))
    return sorted(files)


def csp_from_path(path: Path) -> str:
    for d in CSP_DIRS:
        if d in str(path):
            return d.replace("_rule_metadata", "").replace("_policy", "")
    return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize MITRE tags post-AI-tagger")
    parser.add_argument("--dry-run",     action="store_true", help="Report only, no writes")
    parser.add_argument("--report-only", action="store_true", help="Print QA report, no fixes")
    args = parser.parse_args()

    dry_run = args.dry_run or args.report_only
    if dry_run:
        print("DRY RUN / REPORT ONLY — no files will be written.\n")

    files = find_all_rule_files()
    print(f"Found {len(files)} rule files across {len(CSP_DIRS)} metadata dirs.\n")

    # ── Stats ─────────────────────────────────────────────────────────────────
    stats: dict[str, int] = {
        "total": 0, "tagged": 0, "untagged": 0, "fixed": 0,
        "fallback_applied": 0, "invalid_technique_removed": 0,
        "write_errors": 0,
    }
    technique_counter: Counter[str] = Counter()
    tactic_counter:   Counter[str] = Counter()
    csp_coverage:     dict[str, dict[str, int]] = defaultdict(lambda: {"tagged": 0, "total": 0})
    anomalies:        list[dict[str, Any]] = []
    changes_log:      list[dict[str, Any]] = []

    for path in files:
        stats["total"] += 1
        csp = csp_from_path(path)
        csp_coverage[csp]["total"] += 1

        try:
            content = path.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
        except Exception as e:
            anomalies.append({"file": str(path), "issue": f"parse error: {e}"})
            continue

        if not isinstance(data, dict) or "rule_id" not in data:
            continue

        # Skip deprecated rules — they must never reach PatternExecutor
        rule_id = data.get("rule_id", "")
        title   = (data.get("title") or "").lower()
        if "deprecated" in rule_id.lower() or "deprecated" in title:
            stats.setdefault("deprecated_skipped", 0)
            stats["deprecated_skipped"] += 1
            continue

        has_techniques = bool(data.get("mitre_techniques"))
        if not has_techniques:
            stats["untagged"] += 1
        else:
            stats["tagged"] += 1
            csp_coverage[csp]["tagged"] += 1

        if args.report_only:
            # Just count for report
            for t in data.get("mitre_techniques") or []:
                technique_counter[t] += 1
            for t in data.get("mitre_tactics") or []:
                tactic_counter[t] += 1
            continue

        # Apply fixes
        fixed_data, changes = fix_rule(data)

        if changes:
            stats["fixed"] += 1
            if any("fallback" in c for c in changes):
                stats["fallback_applied"] += 1
            if any("invalid" in c for c in changes):
                stats["invalid_technique_removed"] += 1
            changes_log.append({
                "rule_id": data.get("rule_id"),
                "file": str(path.relative_to(CATALOG_DIR)),
                "changes": changes,
            })

        # Count after fix
        for t in fixed_data.get("mitre_techniques") or []:
            technique_counter[t] += 1
        for t in fixed_data.get("mitre_tactics") or []:
            tactic_counter[t] += 1
        csp_coverage[csp]["tagged"] = csp_coverage[csp].get("tagged", 0)
        if fixed_data.get("mitre_techniques"):
            csp_coverage[csp]["tagged"] = csp_coverage[csp]["tagged"] + (1 if not has_techniques else 0) + (1 if has_techniques else 0)

        if not dry_run:
            try:
                path.write_text(
                    yaml.dump(fixed_data, default_flow_style=False, allow_unicode=True, sort_keys=False),
                    encoding="utf-8"
                )
            except Exception as e:
                stats["write_errors"] += 1
                anomalies.append({"file": str(path), "issue": f"write error: {e}"})

    # ── Print report ──────────────────────────────────────────────────────────
    print("=" * 60)
    print("MITRE TAG QUALITY REPORT")
    print("=" * 60)

    total = stats["total"]
    tagged = stats["tagged"] + stats.get("fallback_applied", 0)
    coverage_pct = 100 * tagged / total if total else 0
    print(f"\nOverall coverage: {tagged}/{total} ({coverage_pct:.1f}%)")
    print(f"Fixed:            {stats['fixed']} files")
    print(f"Fallbacks applied:{stats['fallback_applied']} files")
    print(f"Invalid techs removed: {stats['invalid_technique_removed']}")
    print(f"Write errors:     {stats['write_errors']}")

    print("\n── Per-CSP Coverage ─────────────────────────────────────────")
    for csp, counts in sorted(csp_coverage.items()):
        t = counts["total"]
        g = counts["tagged"]
        pct = 100 * g / t if t else 0
        status = "✓" if pct >= 80 else "✗"
        print(f"  {status} {csp:<22} {g:>5}/{t:<5} ({pct:5.1f}%)")

    print("\n── Top 25 Techniques ────────────────────────────────────────")
    for tech, count in technique_counter.most_common(25):
        bar = "█" * (count // 25)
        print(f"  {tech:<15} {count:>5}  {bar}")

    print("\n── Tactic Distribution ──────────────────────────────────────")
    for tactic, count in tactic_counter.most_common():
        flag = " ⚠ INVALID" if tactic not in VALID_TACTICS else ""
        print(f"  {tactic:<30} {count:>5}{flag}")

    invalid_tactics = [(t, c) for t, c in tactic_counter.items() if t not in VALID_TACTICS]
    if invalid_tactics:
        print(f"\n⚠  {len(invalid_tactics)} invalid tactic value(s) found — fix required")
    else:
        print("\n✓  All tactic values valid.")

    invalid_techs = [(t, c) for t, c in technique_counter.items() if not TECHNIQUE_RE.match(str(t))]
    if invalid_techs:
        print(f"\n⚠  {len(invalid_techs)} invalid technique ID(s) found:")
        for t, c in invalid_techs:
            print(f"   {t} ({c} occurrences)")
    else:
        print("✓  All technique IDs pass T####(.###) format check.")

    if anomalies:
        print(f"\n── Anomalies ({len(anomalies)}) ──────────────────────────────────")
        for a in anomalies[:20]:
            print(f"  {a['file']}: {a['issue']}")

    print("\n── Files Changed ────────────────────────────────────────────")
    if not args.report_only:
        print(f"  {len(changes_log)} files modified.")
        if changes_log:
            print("  Sample changes (first 10):")
            for entry in changes_log[:10]:
                print(f"    {entry['rule_id']}: {'; '.join(entry['changes'])}")
    else:
        print("  (report-only mode — no changes written)")

    # ── Save JSON report ──────────────────────────────────────────────────────
    report = {
        "summary": {
            "total_rules": total,
            "tagged_rules": tagged,
            "coverage_pct": round(coverage_pct, 2),
            "fixed_count": stats["fixed"],
            "fallback_count": stats["fallback_applied"],
            "anomaly_count": len(anomalies),
        },
        "csp_coverage": {
            csp: {
                "tagged": v["tagged"],
                "total": v["total"],
                "pct": round(100 * v["tagged"] / v["total"], 2) if v["total"] else 0
            }
            for csp, v in sorted(csp_coverage.items())
        },
        "top_techniques": dict(technique_counter.most_common(30)),
        "tactic_distribution": dict(tactic_counter.most_common()),
        "invalid_tactics": invalid_tactics,
        "invalid_techniques": invalid_techs,
        "anomalies": anomalies[:50],
        "changes_sample": changes_log[:50],
    }
    REPORT_FILE.write_text(json.dumps(report, indent=2))
    print(f"\nFull report saved to: {REPORT_FILE}")
    print("=" * 60)

    # Exit non-zero if coverage < 80%
    if coverage_pct < 80:
        print(f"\n✗ COVERAGE GATE FAILED: {coverage_pct:.1f}% < 80% threshold")
        sys.exit(1)
    else:
        print(f"\n✓ COVERAGE GATE PASSED: {coverage_pct:.1f}% ≥ 80%")


if __name__ == "__main__":
    main()
