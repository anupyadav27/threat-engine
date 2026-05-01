"""
Pattern : not-empty
Rule    : oci.networking.vcn.security_list_configured
ForEach : oci.virtual_network.list_vcns
Severity: HIGH

Check: Every OCI VCN must have at least one Security List (or NSG) attached.
`defaultSecurityListId` is set when a default security list exists.
If the VCN was created without one, this field will be absent / null.
"""

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent))
from python_to_yaml_generator import CheckSpec, GoldenCheck

SPEC = CheckSpec(
    rule_id   = "oci.networking.vcn.security_list_configured",
    for_each  = "oci.virtual_network.list_vcns",
    severity  = "HIGH",
    pattern   = "not-empty",
    conditions = {
        "var": "item.defaultSecurityListId",
        "op" : "exists",
    },
)

FIXTURE_PASS = {
    "id"                  : "ocid1.vcn.oc1.ap-mumbai-1.aaaaaa",
    "displayName"         : "prod-vcn",
    "lifecycleState"      : "AVAILABLE",
    "cidrBlock"           : "10.0.0.0/16",
    "defaultSecurityListId": "ocid1.securitylist.oc1..aaaaaa",   # security list exists → PASS
}

FIXTURE_FAIL = {
    "id"            : "ocid1.vcn.oc1.ap-mumbai-1.bbbbb",
    "displayName"   : "bare-vcn",
    "lifecycleState": "AVAILABLE",
    "cidrBlock"     : "172.16.0.0/16",
    # defaultSecurityListId absent → FAIL
}

GOLDEN = GoldenCheck(
    spec         = SPEC,
    fixture_pass = FIXTURE_PASS,
    fixture_fail = FIXTURE_FAIL,
    description  = "OCI VCN must have a defaultSecurityListId (security list is configured)",
)

if __name__ == "__main__":
    from python_to_yaml_generator import run_golden, emit_yaml
    ok = run_golden(GOLDEN)
    print(emit_yaml(SPEC))
    sys.exit(0 if ok else 1)
