"""Local test harness for network-security engine mappers.

Network-security is the special-case engine: its analyzers read
``raw_response`` (envelope-preserving) NOT ``emitted_fields``. The audit
in commit 115da3fa9 marked the 6 nested-access hits here as false
positives precisely because of that. This harness pins the contract:
nested raw shape in → topology objects out.

  python3 tests/engine_mappers/test_network_security_mappers.py
  python3 -m pytest tests/engine_mappers/test_network_security_mappers.py -v
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "engines" / "network-security"))

from network_security_engine.analyzers.network_topology_analyzer import build_topology  # noqa: E402

FIXTURE_DIR = ROOT / "tests" / "dcat_fixtures"


def _load(name):
    with (FIXTURE_DIR / name).open() as fh:
        return json.load(fh)


def test_topology_vpc_count_and_default_flag():
    data = _load("aws_ec2_describe_security_groups.json")
    topo = build_topology(data, account_id="111")
    assert len(topo.vpcs) == 2, f"expected 2 VPCs, got {len(topo.vpcs)}"
    assert "vpc-1" in topo.vpcs
    assert "vpc-default" in topo.vpcs
    assert topo.vpcs["vpc-default"].is_default is True
    assert topo.vpcs["vpc-1"].is_default is False
    print("✓ network topology VPC count + IsDefault flag")


def test_topology_cidr_block_association_set():
    """raw.CidrBlockAssociationSet[i].CidrBlock — nested access by design."""
    data = _load("aws_ec2_describe_security_groups.json")
    topo = build_topology(data, account_id="111")
    cidrs = topo.vpcs["vpc-1"].cidr_blocks
    assert "10.0.0.0/16" in cidrs
    assert "10.1.0.0/16" in cidrs, f"secondary CIDR association dropped — got {cidrs}"
    print("✓ network topology CidrBlockAssociationSet nested parse")


def test_topology_subnet_attachment_to_vpc():
    data = _load("aws_ec2_describe_security_groups.json")
    topo = build_topology(data, account_id="111")
    vpc1 = topo.vpcs["vpc-1"]
    assert "subnet-1" in vpc1.subnets
    assert "subnet-2" in vpc1.subnets
    assert vpc1.subnets["subnet-1"].map_public_ip_on_launch is True
    assert vpc1.subnets["subnet-1"].availability_zone == "us-east-1a"
    print("✓ network topology subnet → vpc attachment")


def test_topology_security_group_rules_parsed():
    data = _load("aws_ec2_describe_security_groups.json")
    topo = build_topology(data, account_id="111")
    sgs = topo.vpcs["vpc-1"].security_groups
    assert "sg-1" in sgs
    sg = sgs["sg-1"]
    assert sg.sg_name == "web-sg"
    assert len(sg.inbound_rules) >= 1
    assert sg.is_default is False
    default_sg = sgs["sg-default"]
    assert default_sg.is_default is True
    print("✓ network topology SG inbound/outbound + default flag")


def test_topology_igw_attachment_propagates_to_vpc():
    """raw.Attachments[i].VpcId nested access — must set vpc.igw_id."""
    data = _load("aws_ec2_describe_security_groups.json")
    topo = build_topology(data, account_id="111")
    assert topo.vpcs["vpc-1"].igw_id == "igw-1", (
        f"IGW attachment lost — vpc.igw_id={topo.vpcs['vpc-1'].igw_id}"
    )
    print("✓ network topology IGW attachment → vpc.igw_id")


def test_topology_flow_log_enabled_flag():
    data = _load("aws_ec2_describe_security_groups.json")
    topo = build_topology(data, account_id="111")
    assert topo.vpcs["vpc-1"].flow_log_enabled is True
    assert topo.vpcs["vpc-default"].flow_log_enabled is False
    print("✓ network topology flow_log_enabled flag")


if __name__ == "__main__":
    tests = [
        test_topology_vpc_count_and_default_flag,
        test_topology_cidr_block_association_set,
        test_topology_subnet_attachment_to_vpc,
        test_topology_security_group_rules_parsed,
        test_topology_igw_attachment_propagates_to_vpc,
        test_topology_flow_log_enabled_flag,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as exc:
            print(f"✗ {t.__name__}: {exc}")
            failed += 1
        except Exception as exc:
            print(f"✗ {t.__name__}: {type(exc).__name__}: {exc}")
            failed += 1
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(0 if failed == 0 else 1)
