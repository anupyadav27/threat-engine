# Cursor AI Implementation Guide - Agentic AWS YAML Generator

## 📋 Quick Start for Cursor

Copy and paste this entire prompt into Cursor AI:

---

## CURSOR AI TASK: Implement Agentic AWS Service YAML Generator

### Context
I have two directories with AWS compliance data that need to be combined into YAML files:

1. **Metadata Directory**: `/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services/`
   - Contains 108 AWS service folders (s3, ec2, iam, etc.)
   - Each service has a `metadata/` subdirectory with YAML files
   - Each metadata file defines a security/compliance check

2. **Operations Directory**: `/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/`
   - Contains 108 AWS service folders
   - Each has `operation_registry.json` with AWS API details
   - Defines exact field names and response structures

### Goal
Build an **agentic AI system** using OpenAI API that generates accurate AWS service YAML files by:
1. Reading metadata files to understand requirements
2. Querying AWS SDK documentation for exact field names
3. Generating discovery sections with correct API operations
4. Creating checks with validated field names
5. Producing confidence scores and flagging uncertain checks

### Architecture

```
5 Specialized AI Agents:
├── Agent 1: AWS SDK Expert (knows exact AWS API field names)
├── Agent 2: Metadata Analyzer (understands requirements)
├── Agent 3: Discovery Generator (creates discovery sections)
├── Agent 4: Check Generator (creates check conditions)
└── Agent 5: Validator (validates and scores confidence)
```

### Implementation Requirements

#### 1. Create Agent System with OpenAI

```python
# File: agents/aws_sdk_expert.py
class AWSSDKExpertAgent:
    """
    Agent that knows EXACT AWS API response structures
    Uses OpenAI to query AWS SDK documentation
    """
    
    def get_operation_details(self, service: str, operation: str) -> dict:
        """
        Call OpenAI with AWS SDK knowledge to get:
        - Exact field names (e.g., 'Status' not 'VersioningStatus')
        - Exact values (e.g., 'Enabled' not 'ENABLED')
        - Response structure
        - Example responses
        """
        
        prompt = f"""
You are an AWS SDK expert with perfect knowledge of AWS API responses.

Task: Provide EXACT field names and structures for this AWS operation.

Service: {service}
Operation: {operation}

Critical requirements:
1. Field names must be EXACTLY as AWS returns them (case-sensitive)
2. Values must be EXACTLY as AWS returns them
3. Do NOT guess - only provide what you're certain about
4. Include example response with real values

Examples of correct accuracy:
- S3 GetBucketVersioning returns "Status" NOT "VersioningStatus"
- Value is "Enabled" NOT "ENABLED"
- EC2 DescribeInstances returns "State.Name" NOT "Status"

Provide response as JSON:
{{
  "sdk_method": "snake_case_method_name",
  "parameters": [
    {{"name": "ParamName", "type": "string", "required": true}}
  ],
  "response_structure": {{
    "ExactFieldName": "type"
  }},
  "example_response": {{
    "ExactFieldName": "ExactValue"
  }},
  "notes": "any important details"
}}
"""
        
        # Call OpenAI API
        response = self.openai_client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are an AWS SDK expert. Provide only accurate, verified information about AWS APIs."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1  # Low temperature for accuracy
        )
        
        # Parse JSON response
        return json.loads(response.choices[0].message.content)
```

#### 2. Implement All 5 Agents

Create these files in `agents/` directory:
- `aws_sdk_expert.py` - Agent 1
- `metadata_analyzer.py` - Agent 2
- `discovery_generator.py` - Agent 3
- `check_generator.py` - Agent 4
- `validator.py` - Agent 5
- `orchestrator.py` - Coordinates all agents

Each agent should:
- Have clear purpose and prompt
- Use OpenAI API with appropriate temperature
- Return structured data (JSON/dict)
- Include confidence scores where applicable

#### 3. Main Generator Script

```python
# File: generate_service_yamls.py

from agents.orchestrator import OrchestratorAgent
from pathlib import Path
import yaml
import os

# Configuration
METADATA_BASE = "/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services"
DATABASE_BASE = "/Users/apple/Desktop/threat-engine/pythonsdk-database/aws"
OUTPUT_DIR = "./generated_yamls"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")  # Set this in environment

def generate_all_services():
    """Generate YAML files for all AWS services"""
    
    orchestrator = OrchestratorAgent(api_key=OPENAI_API_KEY)
    
    # Get all services
    services = [d.name for d in Path(METADATA_BASE).iterdir() 
                if d.is_dir() and (d / "metadata").exists()]
    
    print(f"Found {len(services)} services to process")
    
    results = {
        'total': len(services),
        'high_confidence': 0,
        'medium_confidence': 0,
        'low_confidence': 0,
        'failed': 0
    }
    
    for service in services:
        print(f"\n{'='*80}")
        print(f"Processing: {service}")
        print(f"{'='*80}")
        
        try:
            # Load metadata files
            metadata_dir = Path(METADATA_BASE) / service / "metadata"
            metadata_files = []
            for yaml_file in metadata_dir.glob("*.yaml"):
                with open(yaml_file) as f:
                    metadata_files.append(yaml.safe_load(f))
            
            # Load operation registry
            registry_file = Path(DATABASE_BASE) / service / "operation_registry.json"
            with open(registry_file) as f:
                operation_registry = json.load(f)
            
            # Generate with agents
            result = orchestrator.generate_service_yaml(
                service=service,
                metadata_files=metadata_files,
                operation_registry=operation_registry
            )
            
            # Save YAML
            output_file = Path(OUTPUT_DIR) / f"{service}.yaml"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Remove validation metadata before saving
            clean_result = {k: v for k, v in result.items() if not k.startswith('_')}
            
            with open(output_file, 'w') as f:
                yaml.dump(clean_result, f, default_flow_style=False, sort_keys=False)
            
            # Track confidence
            confidence = result['_validation']['confidence_score']
            if confidence >= 0.8:
                results['high_confidence'] += 1
            elif confidence >= 0.5:
                results['medium_confidence'] += 1
            else:
                results['low_confidence'] += 1
            
            print(f"✅ Saved with {confidence:.1%} confidence")
            
        except Exception as e:
            print(f"❌ Failed: {e}")
            results['failed'] += 1
    
    # Print summary
    print(f"\n{'='*80}")
    print(f"GENERATION COMPLETE")
    print(f"{'='*80}")
    print(f"Total services: {results['total']}")
    print(f"High confidence (≥80%): {results['high_confidence']}")
    print(f"Medium confidence (50-79%): {results['medium_confidence']}")
    print(f"Low confidence (<50%): {results['low_confidence']}")
    print(f"Failed: {results['failed']}")
    print(f"\nOutput directory: {OUTPUT_DIR}")

if __name__ == "__main__":
    generate_all_services()
```

#### 4. OpenAI Configuration

Create `.env` file:
```
OPENAI_API_KEY=your_api_key_here
OPENAI_MODEL=gpt-4
OPENAI_TEMPERATURE=0.1
```

Install dependencies:
```bash
pip install openai pyyaml python-dotenv
```

#### 5. Expected Output Structure

Each generated YAML should have:

```yaml
version: '1.0'
provider: aws
service: s3
services:
  client: s3
  module: boto3.client

discovery:
  - discovery_id: aws.s3.list_buckets
    calls:
      - action: list_buckets
        save_as: response
    emit:
      items_for: '{{ response.Buckets }}'
      as: bucket
      item:
        Name: '{{ bucket.Name }}'  # EXACT field name from AWS
        
  - discovery_id: aws.s3.get_bucket_versioning
    calls:
      - action: get_bucket_versioning
        params:
          Bucket: '{{ item.Name }}'
    for_each: aws.s3.list_buckets
    emit:
      item:
        Status: '{{ response.Status }}'  # NOT VersioningStatus!

checks:
  - rule_id: aws.s3.bucket.versioning_enabled
    for_each: aws.s3.get_bucket_versioning
    conditions:
      var: item.Status  # Exact field from discovery
      op: equals
      value: Enabled    # Exact value from AWS (not ENABLED)
```

### Key Implementation Details

#### Agent 1 (AWS SDK Expert) Prompt Template
```
You are an AWS SDK documentation expert.

Critical: You must provide EXACT field names as they appear in AWS API responses.

Service: {service}
Operation: {operation}

Common mistakes to AVOID:
- S3 GetBucketVersioning: Field is "Status" NOT "VersioningStatus"
- S3 values are "Enabled" NOT "ENABLED"
- EC2 uses "State.Name" NOT "Status"
- RDS uses "StorageEncrypted" NOT "Encrypted"

Provide ONLY verified information from AWS SDK documentation.
If uncertain, explicitly state uncertainty.

Return JSON with exact field names and example values.
```

#### Agent 4 (Check Generator) Logic
```python
def generate_check(self, metadata, sdk_details, discovery_id, available_fields):
    """
    Generate check with validation against available fields
    """
    
    # Extract requirement
    requirement = metadata['requirement'].lower()
    
    # Find matching field in SDK response
    if 'versioning' in requirement:
        # Look for exact field in sdk_details
        if 'Status' in available_fields:
            field = 'Status'
            value = 'Enabled'  # From SDK example
            confidence = 0.95
        else:
            field = 'VersioningStatus'  # Fallback
            value = 'Enabled'
            confidence = 0.5
    
    # Generate check
    check = {
        'rule_id': metadata['rule_id'],
        'for_each': discovery_id,
        'conditions': {
            'var': f'item.{field}',
            'op': 'equals',
            'value': value
        }
    }
    
    # Add confidence metadata
    if confidence < 0.8:
        check['_needs_review'] = True
        check['_confidence'] = confidence
    
    return check, confidence
```

### Testing Strategy

1. **Start with S3** (well-documented, consistent patterns)
2. **Test with real AWS account** (if available)
3. **Validate field names** against AWS CLI responses
4. **Check confidence scores** - should be 80%+ for most

### Success Criteria

- ✅ 85-90% of checks should have confidence ≥ 0.8
- ✅ All YAML files should be syntactically valid
- ✅ Field names should match AWS SDK exactly
- ✅ Discovery emit should include fields used by checks
- ✅ Generated files ready for testing with minimal manual review

### Deliverables

1. Complete agent system in `agents/` directory
2. Main generator script `generate_service_yamls.py`
3. Generated YAML files in `generated_yamls/` directory
4. Validation report showing confidence scores
5. List of checks needing manual review (confidence < 0.8)

### Additional Files Needed

Create these helper files:

**agents/base_agent.py**
```python
from openai import OpenAI
import json

class BaseAgent:
    """Base class for all agents"""
    
    def __init__(self, api_key: str):
        self.client = OpenAI(api_key=api_key)
        self.model = "gpt-4"
        self.temperature = 0.1
    
    def call_openai(self, system_prompt: str, user_prompt: str, 
                    temperature: float = None) -> str:
        """Call OpenAI API with error handling"""
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=temperature or self.temperature
        )
        
        return response.choices[0].message.content
    
    def call_openai_json(self, system_prompt: str, user_prompt: str) -> dict:
        """Call OpenAI and parse JSON response"""
        
        response_text = self.call_openai(system_prompt, user_prompt)
        
        # Extract JSON from response (handle markdown code blocks)
        if "```json" in response_text:
            json_text = response_text.split("```json")[1].split("```")[0]
        else:
            json_text = response_text
        
        return json.loads(json_text.strip())
```

**config.py**
```python
import os
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4")
OPENAI_TEMPERATURE = float(os.getenv("OPENAI_TEMPERATURE", "0.1"))

METADATA_BASE = "/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services"
DATABASE_BASE = "/Users/apple/Desktop/threat-engine/pythonsdk-database/aws"
OUTPUT_DIR = "./generated_yamls"

# Validation thresholds
HIGH_CONFIDENCE_THRESHOLD = 0.8
MEDIUM_CONFIDENCE_THRESHOLD = 0.5
```

### Directory Structure

```
aws-yaml-generator/
├── agents/
│   ├── __init__.py
│   ├── base_agent.py
│   ├── aws_sdk_expert.py
│   ├── metadata_analyzer.py
│   ├── discovery_generator.py
│   ├── check_generator.py
│   ├── validator.py
│   └── orchestrator.py
├── generated_yamls/
│   └── (output files will go here)
├── config.py
├── generate_service_yamls.py
├── requirements.txt
├── .env
└── README.md
```

### Requirements.txt
```
openai>=1.0.0
pyyaml>=6.0
python-dotenv>=1.0.0
```

---

### Instructions for Cursor

1. **Read all context above**
2. **Create the complete directory structure**
3. **Implement all 5 agents** following the templates provided
4. **Use OpenAI API** to power each agent
5. **Ensure agents use exact AWS field names** from SDK documentation
6. **Test with S3 service first** before running on all services
7. **Generate confidence scores** for all checks
8. **Flag checks with confidence < 0.8** for manual review

Start by implementing Agent 1 (AWS SDK Expert) first, as it's the foundation for accurate field names.

Ask me if you need clarification on any part!
