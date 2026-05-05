from engines.threat.threat_engine.api.ui_data_router import strip_sensitive_fields


class FakeAuth:
    def __init__(self, level, role=None):
        self.level = level
        self.role = role


def test_analyst_strips_evidence_sensitive_sub_keys():
    auth = FakeAuth(level=4, role="analyst")
    evidence = {"finding_refs": ["x"], "raw_event": "raw", "log_entry": "log", "actor_credentials": {"k": "v"}}
    result = strip_sensitive_fields([{"id": "1", "evidence": evidence}], auth)
    ev = result[0]["evidence"]
    assert "raw_event" not in ev
    assert "log_entry" not in ev
    assert "actor_credentials" not in ev
    assert "finding_refs" in ev


def test_viewer_strips_entire_evidence():
    auth = FakeAuth(level=4, role="viewer")
    evidence = {"finding_refs": ["x"], "raw_event": "raw"}
    result = strip_sensitive_fields([{"id": "1", "evidence": evidence}], auth)
    assert result[0]["evidence"] is None


def test_tenant_admin_keeps_full_evidence():
    auth = FakeAuth(level=4, role="tenant_admin")
    evidence = {"finding_refs": ["x"], "raw_event": "raw"}
    result = strip_sensitive_fields([{"id": "1", "evidence": evidence}], auth)
    assert "raw_event" in result[0]["evidence"]


def test_org_admin_keeps_full_evidence():
    auth = FakeAuth(level=2, role="org_admin")
    evidence = {"finding_refs": ["x"], "raw_event": "raw"}
    result = strip_sensitive_fields([{"id": "1", "evidence": evidence}], auth)
    assert "raw_event" in result[0]["evidence"]


def test_platform_admin_keeps_full_evidence():
    auth = FakeAuth(level=1, role="platform_admin")
    evidence = {"finding_refs": ["x"], "raw_event": "raw"}
    result = strip_sensitive_fields([{"id": "1", "evidence": evidence}], auth)
    assert "raw_event" in result[0]["evidence"]


def test_evidence_none_handled_gracefully():
    auth = FakeAuth(level=4, role="analyst")
    result = strip_sensitive_fields([{"id": "1", "evidence": None}], auth)
    assert result[0]["evidence"] is None


def test_evidence_not_present_no_error():
    auth = FakeAuth(level=4, role="analyst")
    result = strip_sensitive_fields([{"id": "1"}], auth)
    assert "evidence" not in result[0]


def test_credential_ref_stripped_for_level_above_1():
    auth = FakeAuth(level=2, role="org_admin")
    result = strip_sensitive_fields([{"credential_ref": "secret/path", "evidence": None}], auth)
    assert "credential_ref" not in result[0]


def test_platform_admin_keeps_credential_ref():
    auth = FakeAuth(level=1, role="platform_admin")
    result = strip_sensitive_fields([{"credential_ref": "secret/path"}], auth)
    assert "credential_ref" in result[0]


def test_raw_data_always_stripped():
    auth = FakeAuth(level=1, role="platform_admin")
    result = strip_sensitive_fields([{"raw_data": "debug_payload"}], auth)
    assert "raw_data" not in result[0]


def test_strips_evidence_sub_keys_for_level_below_4():
    # level < 4 with unknown role: treated same as analyst (sub-key strip)
    auth = FakeAuth(level=3, role=None)
    evidence = {"finding_refs": ["x"], "raw_event": "raw", "log_entry": "log", "actor_credentials": {"k": "v"}}
    result = strip_sensitive_fields([{"id": "1", "evidence": evidence}], auth)
    ev = result[0]["evidence"]
    assert "raw_event" not in ev
    assert "log_entry" not in ev
    assert "actor_credentials" not in ev
    assert "finding_refs" in ev
