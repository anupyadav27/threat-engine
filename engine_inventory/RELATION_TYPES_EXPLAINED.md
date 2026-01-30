# How Relation Types Work

## The Problem
We added **35 relation types** to `relation_types.json`, but they won't appear in `relationships.ndjson` until we tell the system **which AWS resource fields map to which relation types**.

## The Solution: CORE_RELATION_MAP

In `scripts/build_relationship_index.py`, there's a list called `CORE_RELATION_MAP` that maps:
- **Resource type** (e.g., `ec2.route-table`)
- **Field name** (e.g., `Routes.GatewayId`)
- **→ Relation type** (e.g., `routes_to`)
- **→ Target resource** (e.g., `ec2.internet-gateway`)

## Example: How `routes_to` Works

**Before (old way):**
```python
# Route table → internet gateway was just "attached_to" (not specific)
{"from_type": "ec2.route-table", "relation_type": "attached_to", ...}
```

**After (new way):**
```python
# Route table → internet gateway is now "routes_to" (more specific!)
{"from_type": "ec2.route-table", 
 "relation_type": "routes_to",  # ← NEW relation type
 "to_type": "ec2.internet-gateway",
 "source_field": "Routes", 
 "source_field_item": "GatewayId",
 "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:internet-gateway/{GatewayId}"}
```

## What Happens When You Run the Index Builder

1. **`build_relationship_index.py`** reads `CORE_RELATION_MAP`
2. It generates `aws_relationship_index.json` with all the mappings
3. **`relationship_builder.py`** uses that index to extract relationships from assets
4. When it finds a route table with `Routes[].GatewayId`, it creates a `routes_to` relationship

## Examples We Just Added

✅ **`routes_to`** - Route tables → gateways (IGW, NAT, TGW, VPC endpoints)
✅ **`serves_traffic_for`** - ALB → target groups → EC2 instances
✅ **`invokes`** - API Gateway → Lambda functions
✅ **`exposed_through`** - Services behind API Gateway/CloudFront
✅ **`publishes_to`** / **`subscribes_to`** - SNS/SQS messaging
✅ **`resolves_to`** - Route53 records → ALB/CloudFront
✅ **`runs_on`** - ECS tasks → EC2 instances
✅ **`triggers`** - EventBridge rules → Lambda

## Next Steps

1. **Rebuild the index**: Run `python scripts/build_relationship_index.py`
2. **Re-run inventory scan**: The new relations will appear in `relationships.ndjson`
3. **Add more mappings**: Look at your AWS asset metadata and add more `CORE_RELATION_MAP` entries

## How to Add Your Own Mappings

```python
{
    "from_type": "your.resource-type",      # Source resource
    "relation_type": "your_relation_type",  # One of the 35 types
    "to_type": "target.resource-type",      # Target resource
    "source_field": "FieldName",            # Field in asset.metadata
    "source_field_item": "NestedField",     # Optional: if field is array
    "target_uid_pattern": "arn:aws:.../{FieldName}"  # How to build target UID
}
```
