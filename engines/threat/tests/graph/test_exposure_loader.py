"""ExposureLoader validation tests (GRAPH-S3-04).

Tests:
  1. rule_id with injection chars (<script>, SQL) → row skipped
  2. sg_id with invalid hex (sg-GGGG) → row skipped
  3. cidr_range 999.999.0.0/0 (invalid) → row skipped
  4. Valid row (rule_id=aws.sg.001, sg_id=sg-1234abcd, cidr=0.0.0.0/0) → passes
  5. Fallback triggered when network_db_host is empty

Framework: pytest + unittest.mock (no live DB or Neo4j required).
"""

from __future__ import annotations

from typing import Any, Dict, Tuple
from unittest.mock import MagicMock, patch

import pytest


def _make_neo4j_session_mock() -> Tuple[MagicMock, MagicMock]:
    """Return (mock_driver, mock_session) with session.run returning count=0."""
    mock_result = MagicMock()
    mock_result.single.return_value = {"written": 0, "created": 0}
    mock_session = MagicMock()
    mock_session.run.return_value = mock_result
    mock_session.__enter__ = MagicMock(return_value=mock_session)
    mock_session.__exit__ = MagicMock(return_value=False)
    mock_driver = MagicMock()
    mock_driver.session.return_value = mock_session
    return mock_driver, mock_session


def _make_loader(host: str = "net-host") -> Any:
    """Return an ExposureLoader with a mock neo4j driver."""
    from engines.threat.threat_engine.graph.exposure_loader import ExposureLoader

    mock_driver, _ = _make_neo4j_session_mock()
    return ExposureLoader(
        neo4j_driver=mock_driver,
        network_db_config={
            "host": host,
            "dbname": "threat_engine_network",
            "user": "u",
            "password": "p",
            "port": 5432,
        },
    )


def _make_raw_row(
    rule_id: str = "aws.sg.001",
    sg_id: str = "sg-1234abcd",
    cidr_range: str = "0.0.0.0/0",
    resource_uid: str = "i-0abc123def",
    severity: str = "critical",
    port: int = 22,
    protocol: str = "tcp",
) -> Dict[str, Any]:
    """Build a raw row dict as returned by _fetch_network_findings."""
    return {
        "resource_uid": resource_uid,
        "rule_id": rule_id,
        "severity": severity,
        "finding_metadata": {
            "sg_id": sg_id,
            "cidr_range": cidr_range,
            "port": port,
            "protocol": protocol,
            "exposed_resource_uid": None,
        },
    }


# ---------------------------------------------------------------------------
# Test 1 — rule_id injection rejection
# ---------------------------------------------------------------------------


class TestRuleIdValidation:
    """Rows with rule_ids containing injection characters must be rejected."""

    @pytest.mark.parametrize(
        "bad_rule_id",
        [
            "<script>alert(1)</script>",
            "'; DROP TABLE network_findings; --",
            "rule WITH SPACE",
            "rule\nwith\nnewlines",
            "",
            "a" * 256,  # exceeds 255 char limit
            "rule$special",
            "rule!bang",
        ],
    )
    def test_injection_rule_id_skipped(self, bad_rule_id: str) -> None:
        """Any rule_id that fails RULE_ID_RE must be skipped (returns empty list)."""
        loader = _make_loader()
        raw_rows = [_make_raw_row(rule_id=bad_rule_id)]

        validated = loader._validate_rows(raw_rows)

        assert validated == [], (
            f"Expected row with rule_id={repr(bad_rule_id)!r} to be skipped, "
            f"but got {validated}"
        )

    def test_valid_rule_id_passes(self) -> None:
        """A well-formed rule_id (alphanumeric + dots/dashes/underscores) must pass."""
        loader = _make_loader()
        raw_rows = [_make_raw_row(rule_id="aws.sg.001")]

        validated = loader._validate_rows(raw_rows)

        assert len(validated) == 1
        assert validated[0]["rule_id"] == "aws.sg.001"

    def test_script_tag_exactly_skipped(self) -> None:
        """Explicit <script> tag in rule_id → skipped."""
        loader = _make_loader()
        raw_rows = [_make_raw_row(rule_id="<script>xss</script>")]
        validated = loader._validate_rows(raw_rows)
        assert validated == []

    def test_sql_injection_in_rule_id_skipped(self) -> None:
        """SQL injection attempt in rule_id → skipped."""
        loader = _make_loader()
        raw_rows = [_make_raw_row(rule_id="1' OR '1'='1")]
        validated = loader._validate_rows(raw_rows)
        assert validated == []


# ---------------------------------------------------------------------------
# Test 2 — sg_id invalid hex rejection
# ---------------------------------------------------------------------------


class TestSgIdValidation:
    """Rows with sg_ids that fail the SG_ID_RE pattern must be rejected."""

    @pytest.mark.parametrize(
        "bad_sg_id",
        [
            "sg-GGGG",       # G is not valid hex
            "sg-ZZZZZZZZ",   # Z is not valid hex
            "sg-123",        # too short (< 8 chars after sg-)
            "i-1234abcd",    # EC2 instance prefix, not sg-
            "SG-1234abcd",   # uppercase SG not allowed
            "sg-1234abcd-extra",  # extra suffix
            "1234abcd",      # missing sg- prefix
            "<script>",      # injection in sg_id field
        ],
    )
    def test_invalid_sg_id_skipped(self, bad_sg_id: str) -> None:
        """Any sg_id that does not match sg-[0-9a-f]{8,17} must cause row rejection."""
        loader = _make_loader()
        raw_rows = [_make_raw_row(sg_id=bad_sg_id)]

        validated = loader._validate_rows(raw_rows)

        assert validated == [], (
            f"Expected row with sg_id={repr(bad_sg_id)!r} to be skipped, "
            f"but got {validated}"
        )

    def test_valid_sg_id_passes(self) -> None:
        """Well-formed sg-[8 hex chars] must pass validation."""
        loader = _make_loader()
        raw_rows = [_make_raw_row(sg_id="sg-1234abcd")]

        validated = loader._validate_rows(raw_rows)

        assert len(validated) == 1
        assert validated[0]["sg_id"] == "sg-1234abcd"

    def test_valid_sg_id_17_hex_chars_passes(self) -> None:
        """sg- followed by 17 lowercase hex chars must also pass."""
        loader = _make_loader()
        raw_rows = [_make_raw_row(sg_id="sg-" + "a" * 17)]
        validated = loader._validate_rows(raw_rows)
        assert len(validated) == 1

    def test_absent_sg_id_does_not_reject_row(self) -> None:
        """Rows without sg_id (empty string or None) must pass — sg_id is optional."""
        loader = _make_loader()
        raw_rows = [_make_raw_row(sg_id="")]
        validated = loader._validate_rows(raw_rows)
        assert len(validated) == 1
        assert validated[0]["sg_id"] is None  # normalised to None


# ---------------------------------------------------------------------------
# Test 3 — cidr_range invalid → row skipped
# ---------------------------------------------------------------------------


class TestCidrValidation:
    """Rows with invalid CIDR ranges must be rejected."""

    @pytest.mark.parametrize(
        "bad_cidr",
        [
            "999.999.0.0/0",       # octets out of range
            "256.0.0.1/32",        # first octet > 255
            "not-an-ip/0",         # plain text
            "192.168.1.1/33",      # prefix length > 32 for IPv4
            "::ffff:192.0.2.0/129",  # IPv6 prefix too long
            "10.0.0.1.2/24",       # extra octet
            "garbage",
        ],
    )
    def test_invalid_cidr_skipped(self, bad_cidr: str) -> None:
        """Any cidr_range that ipaddress.ip_network() rejects must cause row rejection."""
        loader = _make_loader()
        raw_rows = [_make_raw_row(cidr_range=bad_cidr)]

        validated = loader._validate_rows(raw_rows)

        assert validated == [], (
            f"Expected row with cidr={repr(bad_cidr)!r} to be skipped, "
            f"but got {validated}"
        )

    def test_valid_cidr_0_0_0_0_0_passes(self) -> None:
        """0.0.0.0/0 is the canonical public-exposure CIDR — must pass."""
        loader = _make_loader()
        raw_rows = [_make_raw_row(cidr_range="0.0.0.0/0")]
        validated = loader._validate_rows(raw_rows)
        assert len(validated) == 1
        assert validated[0]["cidr"] == "0.0.0.0/0"

    def test_valid_cidr_192_168_passes(self) -> None:
        """Private subnet CIDR must also pass (security context, not just public)."""
        loader = _make_loader()
        raw_rows = [_make_raw_row(cidr_range="192.168.0.0/16")]
        validated = loader._validate_rows(raw_rows)
        assert len(validated) == 1

    def test_valid_ipv6_cidr_passes(self) -> None:
        """IPv6 CIDR must pass _validate_cidr."""
        loader = _make_loader()
        raw_rows = [_make_raw_row(cidr_range="::/0")]
        validated = loader._validate_rows(raw_rows)
        assert len(validated) == 1

    def test_absent_cidr_does_not_reject_row(self) -> None:
        """Rows without cidr_range (empty string) must pass — cidr is optional."""
        loader = _make_loader()
        raw_rows = [_make_raw_row(cidr_range="")]
        validated = loader._validate_rows(raw_rows)
        assert len(validated) == 1
        assert validated[0]["cidr"] is None  # normalised to None


# ---------------------------------------------------------------------------
# Test 4 — Fully valid row passes all validation
# ---------------------------------------------------------------------------


class TestValidRowPassesValidation:
    """A canonical valid row must survive all validation checks unchanged."""

    def test_canonical_valid_row_passes(self) -> None:
        """rule_id=aws.sg.001, sg_id=sg-1234abcd, cidr=0.0.0.0/0 must all pass."""
        loader = _make_loader()
        raw_rows = [
            _make_raw_row(
                rule_id="aws.sg.001",
                sg_id="sg-1234abcd",
                cidr_range="0.0.0.0/0",
                resource_uid="arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def",
                severity="critical",
                port=22,
                protocol="tcp",
            )
        ]

        validated = loader._validate_rows(raw_rows)

        assert len(validated) == 1
        row = validated[0]
        assert row["rule_id"] == "aws.sg.001"
        assert row["sg_id"] == "sg-1234abcd"
        assert row["cidr"] == "0.0.0.0/0"
        assert row["port"] == "22"
        assert row["protocol"] == "tcp"
        assert row["severity"] == "critical"
        assert row["layer"] == "L4_security_group"

    def test_valid_row_without_optional_fields_passes(self) -> None:
        """Valid rule_id with empty sg_id and empty cidr_range must pass."""
        loader = _make_loader()
        raw_rows = [_make_raw_row(rule_id="aws.sg.001", sg_id="", cidr_range="")]
        validated = loader._validate_rows(raw_rows)
        assert len(validated) == 1

    def test_multiple_valid_rows_all_pass(self) -> None:
        """A batch of 5 valid rows must all pass validation."""
        loader = _make_loader()
        raw_rows = [
            _make_raw_row(rule_id=f"aws.rule.{i:03d}", sg_id="sg-1234abcd")
            for i in range(5)
        ]
        validated = loader._validate_rows(raw_rows)
        assert len(validated) == 5

    def test_mixed_valid_invalid_only_valid_returned(self) -> None:
        """Mixed batch: only the valid rows must survive."""
        loader = _make_loader()
        raw_rows = [
            _make_raw_row(rule_id="aws.sg.001"),               # valid
            _make_raw_row(rule_id="<script>xss</script>"),      # invalid
            _make_raw_row(rule_id="aws.sg.002", sg_id="sg-GGGG"),  # invalid sg_id
            _make_raw_row(rule_id="aws.sg.003", cidr_range="999.999.0.0/0"),  # invalid cidr
            _make_raw_row(rule_id="aws.sg.004"),               # valid
        ]

        validated = loader._validate_rows(raw_rows)

        assert len(validated) == 2
        assert validated[0]["rule_id"] == "aws.sg.001"
        assert validated[1]["rule_id"] == "aws.sg.004"


# ---------------------------------------------------------------------------
# Test 5 — Fallback triggered when network_db_host is empty
# ---------------------------------------------------------------------------


class TestExposureLoaderFallback:
    """ExposureLoader must fall back to inferred exposure when host is empty."""

    def test_empty_host_calls_infer_fallback(self) -> None:
        """When NETWORK_DB_HOST is empty, _infer_internet_exposure must be called."""
        loader = _make_loader(host="")

        with patch.object(loader, "_infer_internet_exposure", return_value=5) as mock_infer:
            result = loader.load(tenant_id="tenant-A", scan_run_id="scan-001")

        mock_infer.assert_called_once_with("tenant-A")
        assert result == {"exposes_edges": 0, "inferred_edges": 5}

    def test_empty_host_returns_zero_exposes_edges(self) -> None:
        """exposes_edges must be 0 when falling back (no network DB available)."""
        loader = _make_loader(host="")

        with patch.object(loader, "_infer_internet_exposure", return_value=0):
            result = loader.load(tenant_id="tenant-A")

        assert result["exposes_edges"] == 0

    def test_empty_host_never_attempts_pg_connection(self) -> None:
        """No psycopg2.connect call must occur when host is empty."""
        loader = _make_loader(host="")

        with patch("psycopg2.connect") as mock_connect, \
             patch.object(loader, "_infer_internet_exposure", return_value=0):
            loader.load(tenant_id="tenant-A")

        mock_connect.assert_not_called()

    def test_zero_db_rows_also_triggers_fallback(self) -> None:
        """When the DB returns 0 rows, inferred exposure fallback must be used."""
        loader = _make_loader(host="net-host")

        with patch.object(loader, "_fetch_network_findings", return_value=[]) as mock_fetch, \
             patch.object(loader, "_infer_internet_exposure", return_value=3) as mock_infer:
            result = loader.load(tenant_id="tenant-A", scan_run_id="scan-001")

        mock_fetch.assert_called_once()
        mock_infer.assert_called_once_with("tenant-A")
        assert result == {"exposes_edges": 0, "inferred_edges": 3}

    def test_infer_fallback_scoped_to_correct_tenant(self) -> None:
        """_infer_internet_exposure must receive the correct tenant_id."""
        loader = _make_loader(host="")

        with patch.object(loader, "_infer_internet_exposure", return_value=0) as mock_infer:
            loader.load(tenant_id="tenant-specific-uuid")

        mock_infer.assert_called_once_with("tenant-specific-uuid")
