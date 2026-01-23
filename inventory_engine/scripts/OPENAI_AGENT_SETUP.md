# OpenAI Agent for Relationship Generation

## Status
✅ Scripts created and ready
❌ API quota exceeded - need to resolve billing/quota with OpenAI

## Files Created

1. **`generate_relationships_with_openai.py`** - Main script to generate relationships for a single service
2. **`batch_generate_relationships.py`** - Batch processor for multiple services

## Usage

### Single Service
```bash
cd /Users/apple/Desktop/threat-engine/inventory-engine
python3 scripts/generate_relationships_with_openai.py <service_name> \
  --model gpt-4o \
  --api-key YOUR_API_KEY
```

### Batch Processing (Priority Services)
```bash
python3 scripts/batch_generate_relationships.py YOUR_API_KEY \
  --model gpt-4o \
  --priority-only
```

### Batch Processing (All Services)
```bash
python3 scripts/batch_generate_relationships.py YOUR_API_KEY \
  --model gpt-4o
```

## Priority Services (CSPM High-Impact)

The batch script processes these first:
- eks (EKS clusters, nodegroups)
- backup (Backup vaults, plans)
- cloudwatch (Log groups, alarms)
- config (Config rules, recorders)
- autoscaling (Auto scaling groups)
- batch (Batch compute)
- appsync (GraphQL APIs)
- athena (Query service)
- cognito (User pools)
- codebuild (CI/CD)

## Output

Generated relationships are saved to:
```
inventory-engine/inventory_engine/config/generated_relationships_<service>.json
```

Each file contains:
- Service name
- Generation timestamp
- Model used
- Validated relationships in CORE_RELATION_MAP format

## Next Steps After Generation

1. Review generated relationships for quality
2. Add valid ones to `CORE_RELATION_MAP` in `build_relationship_index.py`
3. Rebuild relationship index: `python3 scripts/build_relationship_index.py`

## Current Issue

**API Quota Exceeded**: The provided API key has insufficient quota. 

**Resolution Options**:
1. Check OpenAI billing dashboard and add credits
2. Use a different API key with available quota
3. Wait for quota reset (if applicable)
4. Use a different model (gpt-4o-mini is cheaper but still requires quota)

## Quality Review Checklist

When reviewing generated relationships:
- ✅ `from_type` matches service resource types
- ✅ `relation_type` is from valid relation types
- ✅ `to_type` is a valid target resource type
- ✅ `source_field` exists in discovery YAML emit fields
- ✅ `target_uid_pattern` uses correct ARN format with placeholders
- ✅ Arrays use `source_field_item` when needed
- ✅ Relationships make logical sense for CSPM threat detection

## Model Recommendations

- **gpt-4o**: Best quality, higher cost (~$2.50 per 1M input tokens)
- **gpt-4o-mini**: Good quality, lower cost (~$0.15 per 1M input tokens)
- **gpt-4-turbo**: Alternative if available

For batch processing 300+ services, gpt-4o-mini is recommended to reduce costs while maintaining quality.
