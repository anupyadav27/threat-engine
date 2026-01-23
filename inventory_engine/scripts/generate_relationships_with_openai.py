#!/usr/bin/env python3
"""
OpenAI Agent for Generating Relationship Definitions

Uses OpenAI API (GPT-4o or GPT-5) to generate relationship definitions for AWS services
one at a time, speeding up the relationship index build process.

Usage:
    python generate_relationships_with_openai.py <service_name> [--model gpt-4o] [--api-key KEY]
    python generate_relationships_with_openai.py eks
    python generate_relationships_with_openai.py eks --model gpt-4o-mini
"""

import json
import os
import re
import sys
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from datetime import datetime

# Paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIGSCAN_SERVICES = PROJECT_ROOT / "configScan_engines" / "aws-configScan-engine" / "services"
CONFIG_DIR = PROJECT_ROOT / "inventory-engine" / "inventory_engine" / "config"
CLASSIFICATION_INDEX_FILE = CONFIG_DIR / "aws_inventory_classification_index.json"
RELATION_TYPES_FILE = CONFIG_DIR / "relation_types.json"

def load_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_yaml(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None

def get_service_discovery_yaml(service_name: str) -> Optional[Dict[str, Any]]:
    """Load discovery YAML for a service."""
    service_dir = CONFIGSCAN_SERVICES / service_name
    if not service_dir.exists():
        return None
    discovery_file = service_dir / "discoveries" / f"{service_name}.discoveries.yaml"
    return load_yaml(discovery_file)

def get_service_resource_types(service_name: str, classification: Dict[str, Any]) -> List[str]:
    """Extract resource types for a service from classification index."""
    resource_types = []
    c = classification.get("classifications", {})
    by_sr = c.get("by_service_resource", {}) or {}
    by_op = c.get("by_discovery_operation", {}) or {}
    
    for sr_key, info in by_sr.items():
        if not isinstance(sr_key, str) or "." not in sr_key:
            continue
        svc, _raw_rt = sr_key.split(".", 1)
        if svc == service_name:
            norm_rt = (info or {}).get("normalized_type") or (info or {}).get("resource_type") or _raw_rt
            norm_rt = re.sub(r"_+", "-", str(norm_rt)).strip("-")
            if norm_rt:
                resource_types.append(f"{service_name}.{norm_rt}")
    
    for op_key, info in by_op.items():
        svc = (info or {}).get("service")
        if svc == service_name:
            norm_rt = (info or {}).get("normalized_type") or (info or {}).get("resource_type")
            if norm_rt:
                norm_rt = re.sub(r"_+", "-", str(norm_rt)).strip("-")
                resource_types.append(f"{service_name}.{norm_rt}")
    
    return sorted(list(set(resource_types)))

def extract_emit_fields(discovery_yaml: Dict[str, Any]) -> Dict[str, List[str]]:
    """Extract emitted fields from discovery YAML."""
    fields_by_discovery = {}
    discoveries = discovery_yaml.get("discovery", []) or []
    
    for disc in discoveries:
        disc_id = disc.get("discovery_id", "")
        emit = disc.get("emit", {})
        item_fields = emit.get("item", {})
        
        if isinstance(item_fields, dict):
            field_names = list(item_fields.keys())
            if field_names:
                fields_by_discovery[disc_id] = field_names
    
    return fields_by_discovery

def call_openai_api(prompt: str, model: str = "gpt-4o", api_key: Optional[str] = None) -> Optional[str]:
    """Call OpenAI API to generate relationship definitions."""
    try:
        from openai import OpenAI
    except ImportError:
        print("ERROR: openai package not installed. Install with: pip install openai")
        return None
    
    api_key = api_key or os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: OPENAI_API_KEY not set. Set it as environment variable or pass --api-key")
        return None
    
    client = OpenAI(api_key=api_key)
    
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an AWS CSPM expert. Generate relationship definitions in JSON format."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            response_format={"type": "json_object"}
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"ERROR: OpenAI API call failed: {e}")
        return None

def build_prompt(service_name: str, discovery_yaml: Dict[str, Any], 
                resource_types: List[str], relation_types: List[Dict], 
                examples: List[Dict]) -> str:
    """Build the prompt for OpenAI."""
    
    discoveries = discovery_yaml.get("discovery", []) or []
    emit_fields = extract_emit_fields(discovery_yaml)
    
    rt_summary = "\n".join([f"- {rt['id']}: {rt['description']} ({rt['category']})" 
                            for rt in relation_types[:20]])
    
    examples_str = "\n".join([f"  {json.dumps(ex)}," for ex in examples[:10]])
    
    prompt = f"""Analyze AWS service "{service_name}" and generate relationship definitions.

SERVICE RESOURCE TYPES:
{json.dumps(resource_types, indent=2)}

DISCOVERY OPERATIONS:
{json.dumps([d.get('discovery_id') for d in discoveries], indent=2)}

EMITTED FIELDS (available for relationship extraction):
{json.dumps(emit_fields, indent=2)}

AVAILABLE RELATION TYPES:
{rt_summary}

EXAMPLES OF RELATIONSHIP DEFINITIONS:
[
{examples_str}
]

TASK:
1. Analyze the service's discovery YAML and emitted fields
2. Identify relationships this service's resources have to other AWS resources
3. Generate relationship definitions in the exact format shown in examples
4. Include relationships for all resource types listed above
5. Use appropriate relation types from the available list
6. Construct proper target_uid_pattern using {{field}}, {{region}}, {{account_id}} placeholders
7. For arrays, use source_field_item if needed

CRITICAL RULES:
- Use EXACT resource types from SERVICE RESOURCE TYPES list above (from_type and to_type)
- For cross-service relationships, use correct service prefixes:
  * IAM roles/policies: ALWAYS use "iam.role" or "iam.policy" (NOT service.role or service.policy)
  * KMS keys: ALWAYS use "kms.key" (NOT service.key or backup.key)
  * SNS topics: ALWAYS use "sns.topic" (NOT service.topic or config.topic)
  * EC2 resources: Use "ec2.vpc", "ec2.subnet", "ec2.security-group", "ec2.instance", etc.
  * CloudWatch Logs: Use "logs.group" (NOT cloudwatch.log-group)
- If a resource type doesn't exist in SERVICE RESOURCE TYPES, DO NOT create relationships for it
- Only use resource types that are explicitly listed in SERVICE RESOURCE TYPES

OUTPUT FORMAT (JSON):
{{
  "relationships": [
    {{
      "from_type": "service.resource-type",
      "relation_type": "relation_type_id",
      "to_type": "target_service.resource-type",
      "source_field": "FieldName",
      "target_uid_pattern": "arn:aws:service:{{region}}:{{account_id}}:resource/{{FieldName}}",
      "source_field_item": "ItemField"
    }}
  ],
  "reasoning": "Brief explanation"
}}

Return ONLY valid JSON, no markdown formatting."""
    
    return prompt

def parse_openai_response(response: str) -> Optional[List[Dict[str, Any]]]:
    """Parse OpenAI response and extract relationships."""
    # Try to extract JSON from markdown code blocks if present
    if "```json" in response:
        start = response.find("```json") + 7
        end = response.find("```", start)
        if end > start:
            response = response[start:end].strip()
    elif "```" in response:
        start = response.find("```") + 3
        end = response.find("```", start)
        if end > start:
            response = response[start:end].strip()
    
    try:
        data = json.loads(response)
        relationships = data.get("relationships", [])
        return relationships
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse OpenAI response: {e}")
        print(f"Response (first 1000 chars): {response[:1000]}")
        # Try to find JSON object in the response
        import re
        json_match = re.search(r'\{[^{}]*"relationships"[^{}]*\[.*?\]', response, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(0))
                relationships = data.get("relationships", [])
                print(f"Found JSON in response, extracted {len(relationships)} relationships")
                return relationships
            except:
                pass
        return None
    except Exception as e:
        print(f"ERROR: Unexpected error parsing response: {e}")
        print(f"Response (first 1000 chars): {response[:1000]}")
        return None

def validate_relationship(rel: Dict[str, Any], valid_relation_types: Set[str]) -> bool:
    """Validate a relationship definition."""
    required = ["from_type", "relation_type", "to_type", "source_field", "target_uid_pattern"]
    for field in required:
        if field not in rel:
            print(f"WARNING: Missing required field '{field}' in {rel}")
            return False
    
    if rel["relation_type"] not in valid_relation_types:
        print(f"WARNING: Invalid relation_type '{rel['relation_type']}' in {rel}")
        return False
    
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_relationships_with_openai.py <service_name> [--model gpt-4o] [--api-key KEY]")
        sys.exit(1)
    
    service_name = sys.argv[1]
    model = "gpt-4o"
    api_key = None
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--model" and i + 1 < len(sys.argv):
            model = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--api-key" and i + 1 < len(sys.argv):
            api_key = sys.argv[i + 1]
            i += 2
        else:
            i += 1
    
    print(f"Generating relationships for service: {service_name}")
    print(f"Using model: {model}")
    
    classification = load_json(CLASSIFICATION_INDEX_FILE)
    if not classification:
        print(f"ERROR: Could not load classification index")
        sys.exit(1)
    
    relation_types_data = load_json(RELATION_TYPES_FILE)
    if not relation_types_data:
        print(f"ERROR: Could not load relation types")
        sys.exit(1)
    
    discovery_yaml = get_service_discovery_yaml(service_name)
    if not discovery_yaml:
        print(f"ERROR: Could not find discovery YAML for service '{service_name}'")
        sys.exit(1)
    
    resource_types = get_service_resource_types(service_name, classification)
    relation_types = relation_types_data.get("relation_types", [])
    valid_relation_types = {rt["id"] for rt in relation_types}
    
    examples = [
        {"from_type": "ec2.subnet", "relation_type": "contained_by", "to_type": "ec2.vpc",
         "source_field": "VpcId", "target_uid_pattern": "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}"},
        {"from_type": "lambda.resource", "relation_type": "uses", "to_type": "iam.role",
         "source_field": "Role", "target_uid_pattern": "{Role}"},
        {"from_type": "rds.instance", "relation_type": "encrypted_by", "to_type": "kms.key",
         "source_field": "KmsKeyId", "target_uid_pattern": "arn:aws:kms:{region}:{account_id}:key/{KmsKeyId}"},
    ]
    
    prompt = build_prompt(service_name, discovery_yaml, resource_types, relation_types, examples)
    
    print("\nCalling OpenAI API...")
    response = call_openai_api(prompt, model=model, api_key=api_key)
    
    if not response:
        print("Failed to get response from OpenAI")
        sys.exit(1)
    
    relationships = parse_openai_response(response)
    if relationships is None:
        print("Failed to parse relationships from OpenAI response")
        sys.exit(1)
    
    if len(relationships) == 0:
        print(f"⚠️  No relationships generated for {service_name} (service may not have relationships or discovery fields don't contain relationship data)")
        # Still save an empty file to mark as processed
        output_file = CONFIG_DIR / f"generated_relationships_{service_name}.json"
        output_data = {
            "service": service_name,
            "generated_at": datetime.now().isoformat(),
            "model": model,
            "relationships": []
        }
        with open(output_file, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"Saved empty relationships file: {output_file}")
        sys.exit(0)
    
    valid_relationships = []
    for rel in relationships:
        if validate_relationship(rel, valid_relation_types):
            valid_relationships.append(rel)
    
    print(f"\nGenerated {len(valid_relationships)} valid relationships:")
    print(json.dumps(valid_relationships, indent=2))
    
    output_file = CONFIG_DIR / f"generated_relationships_{service_name}.json"
    with open(output_file, "w") as f:
        json.dump({
            "service": service_name,
            "generated_at": datetime.now().isoformat(),
            "model": model,
            "relationships": valid_relationships
        }, f, indent=2)
    
    print(f"\nSaved to: {output_file}")
    print("\nNext steps:")
    print("1. Review the generated relationships")
    print("2. Add them to CORE_RELATION_MAP in build_relationship_index.py")
    print("3. Rebuild the relationship index")

if __name__ == "__main__":
    main()
