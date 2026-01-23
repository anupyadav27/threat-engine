# Threat Engine Integration - Implementation Complete

## Overview

The compliance engine now supports loading check results from threat engine output and mapping them to compliance frameworks using rule metadata files.

## What Was Implemented

### 1. Threat Engine Loader (`loader/threat_engine_loader.py`)
- Loads check results from `findings.ndjson` files
- Converts threat engine format to compliance engine format
- Supports filtering by `tenant_id` and `scan_id`
- Handles NDJSON parsing and caching

**Key Methods:**
- `load_check_results()` - Loads check results from NDJSON
- `convert_to_scan_results_format()` - Converts to compliance engine format
- `load_and_convert()` - Combined load and convert operation

### 2. Metadata Loader (`loader/metadata_loader.py`)
- Loads rule metadata files from `rule_db/default/services/{service}/metadata/`
- Extracts compliance mappings from metadata YAML files
- Parses compliance strings to FrameworkControl objects
- Supports multiple compliance frameworks (CISA, HIPAA, NIST, ISO 27001, PCI, GDPR, etc.)

**Key Methods:**
- `load_metadata_file()` - Loads metadata for a rule_id
- `parse_compliance_string()` - Parses compliance strings to FrameworkControl
- `get_compliance_mappings()` - Gets all compliance mappings for a rule
- `load_all_metadata_mappings()` - Loads all metadata mappings for a CSP

### 3. Framework Loader Updates (`mapper/framework_loader.py`)
- Added `load_rule_mappings_from_metadata()` method
- Updated `get_rule_mappings()` to support `use_metadata` parameter
- Falls back to metadata files if CSV/YAML mappings not found

### 4. Rule Mapper Updates (`mapper/rule_mapper.py`)
- Updated `get_controls_for_rule()` to support `use_metadata` parameter
- Automatically loads from metadata if no mappings found in cache

### 5. API Endpoint (`api_server.py`)
- Added `POST /api/v1/compliance/generate/from-threat-engine` endpoint
- Accepts `tenant_id`, `scan_id`, `csp`, and optional `frameworks` filter
- Automatically uses metadata loader for compliance mappings

## Usage

### API Endpoint

```bash
curl -X POST http://localhost:8000/api/v1/compliance/generate/from-threat-engine \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "multi_account_tenant_001",
    "scan_id": "rule_check_20260122_210506",
    "csp": "aws",
    "frameworks": ["CIS", "HIPAA"]
  }'
```

### Programmatic Usage

```python
from compliance_engine.loader.threat_engine_loader import ThreatEngineLoader
from compliance_engine.loader.metadata_loader import MetadataLoader

# Load check results from threat engine
loader = ThreatEngineLoader()
scan_results = loader.load_and_convert(
    tenant_id="multi_account_tenant_001",
    scan_id="rule_check_20260122_210506",
    csp="aws"
)

# Load compliance mappings from metadata
metadata_loader = MetadataLoader()
mappings = metadata_loader.load_all_metadata_mappings(csp="aws")
```

## Data Flow

```
Threat Engine Output (findings.ndjson)
    ↓
ThreatEngineLoader.load_check_results()
    ↓
ThreatEngineLoader.convert_to_scan_results_format()
    ↓
Compliance Engine Format
    ↓
MetadataLoader.get_compliance_mappings(rule_id)
    ↓
RuleMapper.get_controls_for_rule(rule_id, use_metadata=True)
    ↓
ResultAggregator.aggregate_by_framework()
    ↓
ScoreCalculator.calculate_framework_score()
    ↓
Compliance Report
```

## File Locations

### Threat Engine Output
- Default: `/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output/configscan/rule_check/rule_check_*/findings.ndjson`

### Rule Metadata
- Default: `/Users/apple/Desktop/threat-engine/engines-input/aws-configScan-engine/input/rule_db/default/services/{service}/metadata/{rule_id}.yaml`

## Compliance Mapping Format

Metadata files contain compliance mappings in the `compliance:` section:

```yaml
rule_id: aws.s3.bucket.block_public_access_enabled
compliance:
  - cisa_ce_v1_multi_cloud_Your_Systems-3_0008
  - hipaa_multi_cloud_164_308_a_1_ii_b_0002
  - nist_800_171_r2_multi_cloud_3_13_2_3.13.2_Employ_architectural_designs_softw_0008
  - iso27001_2022_multi_cloud_A.8.3_0085
```

These are automatically parsed and converted to FrameworkControl objects.

## Supported Frameworks

- CISA Cybersecurity Essentials
- HIPAA
- NIST 800-171
- ISO 27001
- PCI DSS
- GDPR
- RBI Bank
- CIS
- (And more via pattern matching)

## Next Steps

1. Test with real threat engine output
2. Add more compliance framework parsers if needed
3. Optimize metadata loading (cache all at once)
4. Add error handling for malformed metadata files
