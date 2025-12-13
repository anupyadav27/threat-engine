# Sequential Agent Runner - All Services

## ✅ What's Set Up

- **104 AWS services** configured in agent1
- **Path fixed**: `../services/{service}/metadata` 
- **Orchestration files removed** - clean sequential processing
- **Ready to process all services**

## Quick Start

### Option 1: Test with 5 Services First (Recommended)

```bash
cd /Users/apple/Desktop/threat-engine/aws_compliance_python_engine/Agent-rulesid-rule-yaml

export OPENAI_API_KEY='your-key'

./test_first_5.sh
```

**Services**: accessanalyzer, acm, apigateway, apigatewayv2, appstream  
**Duration**: ~5-10 minutes  
**Purpose**: Verify everything works before full run

### Option 2: Process All 104 Services

```bash
cd /Users/apple/Desktop/threat-engine/aws_compliance_python_engine/Agent-rulesid-rule-yaml

export OPENAI_API_KEY='your-key'

./run_sequential_all.sh
```

**Duration**: 1-2 hours  
**Processing**: All 104 services sequentially  
**Output**: `output/` directory

## What Happens

```
Agent 1 (GPT-4o) → Reads metadata, generates requirements
   ↓
Agent 2 → Validates boto3 function names
   ↓
Agent 3 → Validates field names
   ↓
Agent 4 → Generates YAML files
```

## Output Files

All in `output/` directory:

```
output/
├── requirements_initial.json          ← Raw AI output
├── requirements_with_functions.json   ← Boto3 validated functions
├── requirements_validated.json        ← Final validated (USE THIS)
└── *_generated.yaml                   ← YAML files per service
```

## Monitoring Progress

The agents will print progress as they run:

```
Processing service: accessanalyzer
  Found 2 metadata files
  Generating requirements...
  ✅ 2 requirements generated

Processing service: acm
  Found 5 metadata files
  Generating requirements...
  ✅ 5 requirements generated
...
```

## Expected Results

Based on previous pilot runs:

- **~90-92%** validation rate
- **~2000+** total rules processed
- **~1800+** successfully validated

Per service examples:
- accessanalyzer: 2 rules (100% validated)
- acm: 5 rules (100% validated)
- s3: 26 rules (~89% validated)
- apigateway: 41 rules (~98% validated)

## After Completion

1. **Check results**:
```bash
cat output/requirements_validated.json | python3 -m json.tool | head -50
```

2. **Count statistics**:
```bash
python3 << 'EOF'
import json
with open('output/requirements_validated.json') as f:
    data = json.load(f)
    
services = len(data)
total = sum(len(rules) for rules in data.values())
validated = sum(1 for svc in data.values() for r in svc if r.get('all_fields_valid'))

print(f"Services: {services}")
print(f"Total rules: {total}")
print(f"Validated: {validated} ({validated/total*100:.1f}%)")
EOF
```

3. **List generated YAMLs**:
```bash
ls -lh output/*.yaml
```

## Troubleshooting

### If Agent 1 fails:
- Check `OPENAI_API_KEY` is set
- Verify metadata files exist: `ls ../services/accessanalyzer/metadata/`
- Check path is correct: agent1 uses `../services/{service}/metadata`

### If no rules generated:
- Some services may have no metadata files
- Check specific service: `ls ../services/{service}/metadata/*.yaml`

### If validation rate is low:
- This is normal for first run
- Use agents 5-7 for error correction
- Expect 90%+ after corrections

## Next Steps After Sequential Run

1. **Review validated requirements**
2. **Test generated YAMLs with engine**
3. **Run agents 5-7 for error correction** (if needed)
4. **Deploy YAMLs to services/** (when ready)

## Files Created

- ✅ `run_sequential_all.sh` - Process all 104 services
- ✅ `test_first_5.sh` - Test with 5 services
- ✅ Agent1 updated with all 104 services
- ✅ Path fixed: `../services/{service}/metadata`
- ✅ Orchestration files removed

## Clean Setup

```
Agent-rulesid-rule-yaml/
├── agent1_requirements_generator.py ← All 104 services
├── agent2_function_validator.py
├── agent3_field_validator.py
├── agent4_yaml_generator.py
├── run_sequential_all.sh ← Run all
├── test_first_5.sh ← Test run
├── boto3_dependencies_with_python_names.json
└── output/ ← Results appear here
```

Ready to run! 🚀

