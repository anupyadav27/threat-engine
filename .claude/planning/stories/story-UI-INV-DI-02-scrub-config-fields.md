# Story DI-02: `scrub_config_fields()` Shared Utility

**Epic:** UI Investigation Journeys Sprint
**Status:** Ready for Dev
**Story Points:** 2
**Depends On:** None
**Blocks:** DI-07 (Drift tab), DI-10 (Configuration tab)

## Context

The Asset Investigation Journey shows raw cloud resource configuration data in the Configuration tab and diff payloads in the Drift tab. Both tabs pull JSONB `config` blobs directly from the inventory engine. These blobs can contain plaintext credentials, connection strings, and API keys that were captured during discovery. Before the BFF returns config data to the frontend, it must recursively redact sensitive values.

## Scope

Create `scrub_config_fields(data)` as a pure Python utility in `shared/common/` with full unit test coverage. This is stdlib-only — no new dependencies.

**Out of scope:** Integrating the function into BFF endpoints (done in DI-07 and DI-10), any engine changes.

## Files to Create/Modify

- `/Users/apple/Desktop/threat-engine/shared/common/scrub_config.py` — create new file with the function
- `/Users/apple/Desktop/threat-engine/shared/common/__init__.py` — add export: `from .scrub_config import scrub_config_fields`
- `/Users/apple/Desktop/threat-engine/tests/test_scrub_config_fields.py` — create unit tests (7+ tests)

## Implementation Notes

**Function signature:**
```python
from typing import Any

def scrub_config_fields(data: Any) -> Any:
    """Recursively redact sensitive credential values from cloud config blobs.

    Traverses dicts and lists. When a dict key matches a sensitive pattern
    (case-insensitive substring match), its value is replaced with
    "[REDACTED]". Keys are preserved unchanged.

    Args:
        data: Arbitrary Python value — dict, list, str, int, None, etc.
              Only dicts and lists are recursed into.

    Returns:
        A new object (never mutates the original) with sensitive values
        redacted. Returns None unchanged. Returns non-traversable types
        (str, int, float, bool) unchanged.
    """
```

**Sensitive key patterns (case-insensitive substring match — all must be checked):**
```python
SENSITIVE_KEYS = {
    "password", "passwd", "secret", "secret_key", "access_key",
    "access_key_id", "connection_string", "jdbc", "token",
    "auth_token", "private_key", "credential", "api_key",
}
```

**Matching logic:** `any(pattern in key.lower() for pattern in SENSITIVE_KEYS)` where `key` is the dict key as a string. This means `"db_password"` matches `"password"`, `"secretsmanager_arn"` does NOT match (substring "secret" is present — it DOES match — document this edge case in a comment).

**Algorithm:**
```python
def scrub_config_fields(data: Any) -> Any:
    if data is None:
        return None
    if isinstance(data, dict):
        return {
            k: "[REDACTED]" if _is_sensitive_key(k) else scrub_config_fields(v)
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [scrub_config_fields(item) for item in data]
    return data  # str, int, float, bool, etc. — pass through unchanged
```

**`_is_sensitive_key(key: str) -> bool`:** private helper — `return any(p in str(key).lower() for p in SENSITIVE_KEYS)`

**Important behaviors:**
- Does NOT redact the key itself — only the value. Key `"password"` remains `"password"`, value becomes `"[REDACTED]"`
- If value is already `"[REDACTED]"` → remains `"[REDACTED]"` (idempotent — the substring check applies to keys not values)
- `None` input → returns `None`
- Empty dict `{}` → returns `{}`
- Empty list `[]` → returns `[]`
- Tags dict like `{"tags": {"password": "secret123"}}` → `{"tags": {"password": "[REDACTED]"}}` (nested recursion)

**Unit tests — all required in `tests/test_scrub_config_fields.py`:**

```python
import pytest
from shared.common.scrub_config import scrub_config_fields

def test_flat_dict_sensitive_key_redacted():
    assert scrub_config_fields({"password": "secret123"}) == {"password": "[REDACTED]"}

def test_non_sensitive_key_unchanged():
    assert scrub_config_fields({"bucket_name": "my-bucket"}) == {"bucket_name": "my-bucket"}

def test_nested_dict_recursive_redaction():
    inp = {"db": {"host": "localhost", "password": "hunter2"}}
    out = scrub_config_fields(inp)
    assert out["db"]["password"] == "[REDACTED]"
    assert out["db"]["host"] == "localhost"

def test_list_of_dicts_each_processed():
    inp = [{"access_key": "AKIA...", "region": "us-east-1"}, {"name": "prod"}]
    out = scrub_config_fields(inp)
    assert out[0]["access_key"] == "[REDACTED]"
    assert out[0]["region"] == "us-east-1"
    assert out[1]["name"] == "prod"

def test_none_input_returns_none():
    assert scrub_config_fields(None) is None

def test_already_redacted_value_unchanged():
    assert scrub_config_fields({"password": "[REDACTED]"}) == {"password": "[REDACTED]"}

def test_tags_nested_redaction():
    inp = {"tags": {"env": "prod", "password": "secret123"}}
    out = scrub_config_fields(inp)
    assert out["tags"]["password"] == "[REDACTED]"
    assert out["tags"]["env"] == "prod"

def test_empty_dict():
    assert scrub_config_fields({}) == {}

def test_empty_list():
    assert scrub_config_fields([]) == []

def test_non_dict_non_list_unchanged():
    assert scrub_config_fields("plain string") == "plain string"
    assert scrub_config_fields(42) == 42
```

**No external imports** — stdlib `typing` only. `re` module is NOT needed (substring check is sufficient).

## Acceptance Criteria

- [ ] `scrub_config_fields` is importable via `from shared.common import scrub_config_fields`
- [ ] All 10 unit tests in `tests/test_scrub_config_fields.py` pass with `pytest`
- [ ] `None` input returns `None` without raising
- [ ] `{"password": "x"}` → `{"password": "[REDACTED]"}` (key preserved, value replaced)
- [ ] `{"tags": {"password": "x"}}` → nested redaction works
- [ ] Function is pure — original input dicts/lists are NOT mutated
- [ ] No stdlib imports beyond `typing`
- [ ] `black` and `pylint` pass

## Security Gates

- **No external deps:** stdlib-only prevents supply-chain risk in shared utility layer
- **Pure function:** no side effects, safe to call from BFF request handlers concurrently

## Definition of Done

- [ ] Code written and passes linter
- [ ] 10 unit tests all pass
- [ ] Export added to `shared/common/__init__.py`
- [ ] No external imports
- [ ] bmad-qa acceptance test run