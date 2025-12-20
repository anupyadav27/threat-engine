# CURSOR AI - IMMEDIATE ACTION PROMPT

## 🎯 TASK: Build Agentic AWS YAML Generator

Copy this entire prompt to Cursor and ask it to implement:

---

**Hey Cursor, I need you to build a complete agentic AI system for AWS YAML generation.**

### Context

I have two directories with AWS data:

1. **Metadata**: `/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services/`
   - 108 AWS services (s3, ec2, iam, etc.)
   - Each has `metadata/*.yaml` files with security requirements

2. **Operations**: `/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/`
   - Each service has `operation_registry.json` with AWS API details

### What to Build

**5 AI Agents using OpenAI API:**

```
Orchestrator
    ├── Agent 1: AWS SDK Expert (gets exact AWS field names)
    ├── Agent 2: Metadata Analyzer (understands requirements)
    ├── Agent 3: Discovery Generator (creates discovery sections)
    ├── Agent 4: Check Generator (creates check conditions)
    └── Agent 5: Validator (validates & scores confidence)
```

### Critical Requirements

1. **Use OpenAI GPT-4** to power all agents
2. **Get EXACT AWS field names** - NOT guesses
   - S3 uses "Status" NOT "VersioningStatus"
   - Values are "Enabled" NOT "ENABLED"
3. **Generate confidence scores** for each check
4. **Flag checks < 0.8 confidence** for manual review
5. **Target: 85-90% accuracy**

### Directory Structure to Create

```
aws-yaml-generator/
├── agents/
│   ├── __init__.py
│   ├── base_agent.py           # Base class with OpenAI client
│   ├── aws_sdk_expert.py       # Agent 1
│   ├── metadata_analyzer.py    # Agent 2
│   ├── discovery_generator.py  # Agent 3
│   ├── check_generator.py      # Agent 4
│   ├── validator.py            # Agent 5
│   └── orchestrator.py         # Coordinates all agents
├── generated_yamls/            # Output directory
├── config.py                   # Configuration
├── generate_service_yamls.py   # Main script
├── requirements.txt
├── .env.example
└── README.md
```

### Key Implementation Points

**Agent 1 Prompt Template:**
```python
prompt = f"""
You are an AWS SDK expert. Provide EXACT field names from AWS API responses.

Service: {service}
Operation: {operation}

CRITICAL: Field names must be EXACTLY as AWS returns them.
- S3 GetBucketVersioning returns "Status" NOT "VersioningStatus"
- Values are "Enabled" NOT "ENABLED"

Return JSON with:
- sdk_method (snake_case)
- parameters (list with name, type, required)
- response_structure (exact fields)
- example_response (with real values)
"""
```

**Output Format:**
```yaml
version: '1.0'
provider: aws
service: s3

discovery:
  - discovery_id: aws.s3.get_bucket_versioning
    calls:
      - action: get_bucket_versioning
        params:
          Bucket: '{{ item.Name }}'
    emit:
      item:
        Status: '{{ response.Status }}'  # EXACT field from AWS

checks:
  - rule_id: aws.s3.bucket.versioning_enabled
    for_each: aws.s3.get_bucket_versioning
    conditions:
      var: item.Status
      op: equals
      value: Enabled
```

### Files I've Already Created

I have these files ready for you:
- `CURSOR_IMPLEMENTATION_GUIDE.md` - Complete detailed guide
- `project_README.md` - Project README
- `requirements.txt` - Python dependencies
- `.env.example` - Environment template
- `agentic_yaml_generator.py` - Prototype (needs OpenAI integration)

### What You Need to Do

1. **Read** `CURSOR_IMPLEMENTATION_GUIDE.md` for full details
2. **Create** all 5 agent files in `agents/` directory
3. **Implement** OpenAI API calls in each agent
4. **Create** `config.py` with paths
5. **Create** `generate_service_yamls.py` main script
6. **Test** with S3 service first
7. **Ensure** confidence scores work
8. **Generate** validation reports

### Success Criteria

- ✅ All 5 agents implemented with OpenAI
- ✅ Main script generates YAML for any service
- ✅ Confidence scores calculated (target: 80%+ for most)
- ✅ Field names match AWS SDK exactly
- ✅ Validation report shows high/medium/low confidence breakdown
- ✅ Test run on S3 produces valid YAML

### Environment Setup

```bash
# Install dependencies
pip install openai pyyaml python-dotenv boto3

# Set API key
export OPENAI_API_KEY="sk-..."

# Run
python generate_service_yamls.py --service s3
```

### Important Notes

- Use **GPT-4** for accuracy (not GPT-3.5)
- Use **temperature=0.1** for consistent results
- **Parse AWS SDK docs** to get exact field names
- **Validate** each check's field exists in discovery emit
- **Return confidence scores** with every check
- **Flag low confidence** checks for human review

### Start Here

Begin with `agents/base_agent.py` and `agents/aws_sdk_expert.py` - these are the foundation.

Ask me questions if anything is unclear!

---

**Reference Documents:**
- Full guide: `CURSOR_IMPLEMENTATION_GUIDE.md`
- Architecture: `AGENTIC_AI_SYSTEM_DESIGN.md`
- Testing: `REALISTIC_TESTING_GUIDE.md`
