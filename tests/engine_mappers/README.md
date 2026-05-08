# Engine Mapper Tests

Local pre-deploy validation for engine mapper code (`build_*_inventory` and friends).

## Why this exists

Engine mappers project flat fields from `discovery_findings.emitted_fields`
into engine-specific inventory tables (e.g. `encryption_key_inventory`).
Bug class regressions we've shipped:

- Catalog field renames silently broke downstream column population
- Multi-row stitch (list_keys + describe_key) lost rich data when sparse
  source landed first
- Order-dependent merge logic dropped fields when sibling discovery_ids
  arrived in unexpected order
- Non-cert resource types (account_configuration) leaked into cert tables

Each test fixture in `tests/dcat_fixtures/` simulates a realistic mix of
discovery_findings rows for one resource type. Tests assert that the
mapper produces the expected output shape regardless of input row order.

## Running

```bash
# Direct (no pytest needed)
python3 tests/engine_mappers/test_encryption_mappers.py

# Via pytest if you have it
python3 -m pytest tests/engine_mappers/ -v
```

Both paths exit non-zero on any failure.

## Coverage

| Engine | Test file | Reads from | Notes |
| --- | --- | --- | --- |
| encryption-security | test_encryption_mappers.py | emitted_fields | KMS / ACM / Secrets — order-independent merge regression for Bug 5 |
| ai-security | test_ai_security_mappers.py | emitted_fields | Sagemaker / Bedrock — pins PrimaryContainer.Image nested fallback |
| database-security | test_database_security_mappers.py | configuration | DynamoDB nested→flat (PointInTimeRecoveryStatus, BillingMode); RDS / snapshot filter |
| container-security | test_container_security_mappers.py | configuration | EKS / ECS / ECR / Lambda extractors |
| datasec | test_datasec_mappers.py | raw_response | S3 VersioningStatus flat + nested fallback; RDS GB→bytes; DynamoDB ItemCount |
| network-security | test_network_security_mappers.py | raw_response | Special-case: envelope-preserving by design — VPC topology builder |

## When to add a fixture

1. New engine mapper or new fixture-worthy regression
2. New resource type joining the inventory
3. After a catalog field rename — capture the new shape

Fixture format: a JSON list of `discovery_findings`-shaped rows. Each row
must have `discovery_id`, `resource_uid`, `account_id`, `provider`,
`region`, `service`, and `emitted_fields`. Optional: `resource_type` if
the mapper filters by it.

## Adding a test

```python
def test_my_new_mapper_thing():
    rows = _load("aws_some_service.json")
    inv = build_my_inventory(rows)
    assert len(inv) == EXPECTED_COUNT
    assert inv[0]["my_column"] == EXPECTED_VALUE
```

## CI integration

Run as part of every PR touching `engines/**` or `catalog/**`. Fast
(<5s for the full suite, no network/DB).
