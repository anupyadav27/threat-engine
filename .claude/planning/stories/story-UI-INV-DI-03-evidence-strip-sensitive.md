# Story DI-03: Extend `strip_sensitive_fields()` in Threat Engine for Evidence Tab

**Epic:** UI Investigation Journeys Sprint
**Status:** Ready for Dev
**Story Points:** 2
**Depends On:** None
**Blocks:** DI-07 (Evidence tab wiring)

## Context

The Evidence tab in the Threat Detail investigation journey (`/threats/[threatId]`) shows structured evidence from `threat_detections.evidence` JSONB. This JSONB can contain `raw_event` (raw CloudTrail JSON), `log_entry` (raw log line), and `actor_credentials` (temporary credential metadata). These fields must be stripped before data reaches the BFF for roles below `tenant_admin` (level 4). The existing `strip_sensitive_fields()` function in the threat engine already strips `credential_ref`/`credential_type` and `raw_data`/`evidence` at different role thresholds — but the current logic removes the entire `evidence` key for roles >= 4 (analyst and above), which is backwards from what we need.

**Note on current logic (lines 56-62 of `engines/threat/threat_engine/api/ui_data_router.py`):**
```python
if auth is not None and auth.level >= 4:
    r.pop("raw_data", None)
    r.pop("evidence", None)  # BUG: this removes evidence for analyst+, should be the opposite
```
This story fixes the bug AND adds granular evidence field stripping.

## Scope

Modify `strip_sensitive_fields()` in `engines/threat/threat_engine/api/ui_data_router.py` to:
1. Fix the inverted level check for `evidence`
2. Add per-field stripping of `raw_event`, `log_entry`, `actor_credentials` from the `evidence` JSONB for roles with `level < 4` (below tenant_admin)

**Out of scope:** Frontend Evidence tab component (DI-07), BFF changes, any other engine.

## Files to Create/Modify

- `/Users/apple/Desktop/threat-engine/engines/threat/threat_engine/api/ui_data_router.py` — modify `strip_sensitive_fields()` function (lines 41-63)

## Implementation Notes

**Current function (lines 41-63):**
```python
def strip_sensitive_fields(data: List[Dict[str, Any]], auth: Any) -> List[Dict[str, Any]]:
    if not isinstance(data, list):
        return data
    stripped = []
    for row in data:
        r = dict(row) if not isinstance(row, dict) else row.copy()
        if auth is not None and auth.level > 1:
            r.pop("credential_ref", None)
            r.pop("credential_type", None)
        if auth is not None and auth.level >= 4:
            r.pop("raw_data", None)
            r.pop("evidence", None)
        stripped.append(r)
    return stripped
```

**Required replacement:**
```python
# Sensitive evidence sub-keys that require tenant_admin (level 4) or above
_EVIDENCE_SENSITIVE_KEYS = {"raw_event", "log_entry", "actor_credentials"}


def strip_sensitive_fields(data: List[Dict[str, Any]], auth: Any) -> List[Dict[str, Any]]:
    """Remove credential and raw-evidence fields based on caller's auth level.

    Role levels:
        1 = platform_admin (unrestricted)
        2 = org_admin
        4 = tenant_admin, analyst, viewer

    Stripping rules:
        - level > 1: remove credential_ref, credential_type (infra-level secrets)
        - level < 4 (below tenant_admin): strip raw_event, log_entry,
          actor_credentials FROM the evidence dict (not the whole key)
        - raw_data: always strip (was incorrectly gated on level >= 4 before)

    Args:
        data: List of threat finding/detection dicts.
        auth: AuthContext instance (or None when auth is unavailable).

    Returns:
        New list with sensitive fields removed; original dicts are not mutated.
    """
    if not isinstance(data, list):
        return data
    stripped = []
    for row in data:
        r = dict(row) if not isinstance(row, dict) else row.copy()

        # Strip infra-level secrets from all non-platform-admin callers
        if auth is not None and auth.level > 1:
            r.pop("credential_ref", None)
            r.pop("credential_type", None)

        # Strip raw_data always (internal debug field, never for UI)
        r.pop("raw_data", None)

        # Strip sensitive sub-keys from evidence for roles below tenant_admin
        # tenant_admin = level 4; analyst = level 4; viewer = level 4
        # But viewer should NOT see raw evidence — use permissions check:
        # Strip for viewer (no ciem:sensitive) and any level < 4
        if auth is not None and auth.level < 4:
            evidence = r.get("evidence")
            if isinstance(evidence, dict):
                clean_evidence = {
                    k: v for k, v in evidence.items()
                    if k not in _EVIDENCE_SENSITIVE_KEYS
                }
                r["evidence"] = clean_evidence
            # If evidence is None or not dict — leave unchanged

        stripped.append(r)
    return stripped
```

**Evidence JSONB structure (from `threat_detections.evidence` column):**
```json
{
  "finding_refs": ["uuid1", "uuid2"],
  "affected_assets": ["arn:aws:ec2:..."],
  "remediation": {"steps": [...]},
  "contributing_rules": ["rule_id_1"],
  "finding_count": 3,
  "source": "check",
  "raw_event": "{\"eventName\": \"AssumeRole\", ...}",
  "log_entry": "2026-01-01T00:00:00Z INFO AssumeRole ...",
  "actor_credentials": {"access_key_id": "ASIA...", "session_token": "..."}
}
```

After stripping for level < 4, `raw_event`, `log_entry`, `actor_credentials` keys are absent. `finding_refs`, `affected_assets`, `remediation`, `contributing_rules`, `finding_count`, `source` remain.

**JSONB note:** `evidence` is already a Python dict when read via psycopg2 `RealDictCursor` — NEVER call `json.loads()` on it.

**Unit tests to add in `tests/test_strip_sensitive_fields.py`** (create new file):

```python
from engines.threat.threat_engine.api.ui_data_router import strip_sensitive_fields

class FakeAuth:
    def __init__(self, level):
        self.level = level

def test_strips_evidence_sub_keys_for_level_below_4():
    auth = FakeAuth(level=4)  # analyst/viewer is level 4 — but we check < 4
    # Actually test level 3 (hypothetical sub-analyst role)
    auth3 = FakeAuth(level=3)
    evidence = {"finding_refs": ["x"], "raw_event": "raw", "log_entry": "log", "actor_credentials": {"k": "v"}}
    row = [{"id": "1", "evidence": evidence}]
    result = strip_sensitive_fields(row, auth3)
    ev = result[0]["evidence"]
    assert "raw_event" not in ev
    assert "log_entry" not in ev
    assert "actor_credentials" not in ev
    assert "finding_refs" in ev

def test_tenant_admin_level_4_keeps_full_evidence():
    auth = FakeAuth(level=4)
    evidence = {"finding_refs": ["x"], "raw_event": "raw"}
    row = [{"id": "1", "evidence": evidence}]
    result = strip_sensitive_fields(row, auth)
    # level 4 is NOT < 4, so evidence intact
    assert "raw_event" in result[0]["evidence"]

def test_evidence_none_handled_gracefully():
    auth = FakeAuth(level=3)
    row = [{"id": "1", "evidence": None}]
    result = strip_sensitive_fields(row, auth)
    assert result[0]["evidence"] is None

def test_evidence_not_present_no_error():
    auth = FakeAuth(level=3)
    row = [{"id": "1"}]
    result = strip_sensitive_fields(row, auth)
    assert "evidence" not in result[0]

def test_credential_ref_stripped_for_level_above_1():
    auth = FakeAuth(level=2)
    row = [{"credential_ref": "secret/path", "evidence": None}]
    result = strip_sensitive_fields(row, auth)
    assert "credential_ref" not in result[0]

def test_raw_data_always_stripped():
    auth = FakeAuth(level=1)
    row = [{"raw_data": "debug_payload"}]
    result = strip_sensitive_fields(row, auth)
    assert "raw_data" not in result[0]
```

**Note on auth.level for existing roles:** `platform_admin=1`, `org_admin=2`, `tenant_admin=4`, `analyst=4`, `viewer=4`. The level-based check here means all tenant-scoped roles are treated equally at level 4. For viewer-specific suppression beyond this (e.g., full evidence hiding based on `ciem:sensitive` permission), that is enforced at the BFF layer. This function protects the engine output.

## Acceptance Criteria

- [ ] `strip_sensitive_fields()` no longer removes the entire `evidence` key for any role
- [ ] For `auth.level < 4`: `raw_event`, `log_entry`, `actor_credentials` absent from `evidence` dict
- [ ] For `auth.level >= 4` (tenant_admin/analyst): full `evidence` dict returned including `raw_event`
- [ ] `evidence = None` → returned as `None`, no AttributeError
- [ ] `evidence = {}` → returned as `{}`, no error
- [ ] `raw_data` is stripped for all callers (level 1 through 4)
- [ ] `credential_ref` and `credential_type` still stripped for level > 1
- [ ] All 6 unit tests pass
- [ ] Existing tests in the threat engine test suite still pass (regression)

## Security Gates

- **B-3 (engine-layer stripping):** Sensitive evidence fields stripped in engine before BFF receives data — not in gateway layer. This ensures even direct engine callers (with valid auth) cannot receive raw events below tenant_admin.
- **JSONB never `json.loads()`:** Evidence is already a dict from psycopg2 RealDictCursor — no deserialization needed.

## Definition of Done

- [ ] Code written and passes linter
- [ ] 6 unit tests in `tests/test_strip_sensitive_fields.py` pass
- [ ] No regression in existing threat engine tests
- [ ] bmad-security-reviewer approved (auth logic change)
- [ ] bmad-qa acceptance test run
