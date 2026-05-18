# Story PC-P1-05: Network Engine — Write Missing is_in_private_subnet and network_detail Signals

## Status: done

## Metadata
- **Phase**: P1 — Tier A (column already in table, writer exists but doesn't write these 2 signals)
- **Sprint**: Posture Coverage Enhancement
- **Points**: 2
- **Priority**: P1
- **Depends on**: AP-P0-01, AP-P0-02
- **Blocks**: PC-P1-07 (composite flags need network signals to be complete)
- **RACI**: R=DEV A=DL C=SA I=PO,QA

## Gap Being Closed

**Current state:** `network_security_engine/posture_signals.py` exists and writes `is_internet_exposed`, `has_waf`, `has_load_balancer`, `network_exposure_score`. However **two columns are never written**:
- `is_in_private_subnet` — always FALSE (default). Attack-path engine cannot distinguish public vs private resources.
- `network_detail` — always NULL. The JSONB detail blob (SG rules, open ports, VPC ID) is never populated, so asset detail panel shows no network context.

**Why Tier A:** `network_findings.finding_data` already contains `{vpc_id, subnet_id, is_private, open_ports, sg_rules}`. This is a 10-line change to the existing `_aggregate_network_signals()` function.

## Changes Required

**File:** `engines/network-security/network_security_engine/posture_signals.py`

In `_aggregate_network_signals()`, extend the per-row processing:

```python
# Add to the signals dict per uid:

# is_in_private_subnet: TRUE if any finding marks resource in private subnet
finding_data = row.get("finding_data") or {}  # already dict (JSONB auto-deserialized)
if finding_data.get("is_private") or finding_data.get("subnet_type") == "private":
    sig["is_in_private_subnet"] = True

# network_detail: accumulate SG rules + open ports + VPC ID
if "network_detail" not in sig:
    sig["network_detail"] = {
        "vpc_id": finding_data.get("vpc_id"),
        "open_ports": [],
        "sg_rules": [],
        "nacl_violations": [],
    }
if finding_data.get("open_ports"):
    sig["network_detail"]["open_ports"].extend(finding_data["open_ports"])
if finding_data.get("sg_rules"):
    sig["network_detail"]["sg_rules"].extend(finding_data["sg_rules"])
```

After the loop, deduplicate `open_ports` and `sg_rules` lists before upsert.

**`network_detail` is a JSONB column** — it must be passed as `psycopg2.extras.Json(sig["network_detail"])` to the posture_writer. The `_coerce_jsonb()` function in `posture_writer.py` handles this automatically since `network_detail` is in `_JSONB_COLS`.

## Acceptance Criteria

- [ ] AC-1: After network scan, `is_in_private_subnet=TRUE` for EC2 instances in private subnets (verify with a known private-subnet resource)
- [ ] AC-2: `is_in_private_subnet=FALSE` for internet-facing resources (ELBs, public EC2s)
- [ ] AC-3: `network_detail` is non-NULL JSONB for resources with network findings — contains `vpc_id`, `open_ports`, `sg_rules`
- [ ] AC-4: Existing signals (`is_internet_exposed`, `network_exposure_score`) remain unchanged
- [ ] AC-5: `open_ports` list is deduplicated (no duplicate port entries)
- [ ] AC-6: New image: `yadavanup84/engine-network-security:v-net-posture1`

## Definition of Done
- [ ] `posture_signals.py` updated — 2 new signals added to existing aggregation loop
- [ ] Integration test: network scan → both new signals populated
- [ ] Post-deploy: `SELECT COUNT(*) FROM resource_security_posture WHERE is_in_private_subnet=TRUE` > 0 for real scan