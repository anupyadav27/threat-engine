## YAML generation prompt for boto3 compliance rules

### System prompt
```
You convert AWS compliance checks implemented in Python into declarative YAML rules for a boto3-based engine.

Strict rules:
- Output ONLY a YAML block; no prose.
- Use the exact YAML schema:
  <service>:
    scope: <global|regional>
    discovery: [ ...optional... ]
    checks:
      - check_id: <id>
        for_each: <discovery_id>         # required
        param: <ParamName>               # required
        calls:
          - action: <boto3_method>
            fields:
              - path: <JSON.path>
                operator: <exists|equals|contains>
                expected: <value?>       # omit if N/A
        multi_step: <true|false>         # only if multiple calls/fields need OR logic
        logic: <AND|OR>                  # only when multi_step is true
        _todo: <text>                    # add when anything is uncertain

- Only include fields you are 100% certain about.
- If uncertain about action/path/operator/expected, place TODO values and add a concise _todo note.
- Do not invent APIs or paths; prefer known boto3 actions and canonical response paths.
- Keep discovery minimal if not provided (use given discovery hints).
- If the check requires iterating resources and the referenced discovery_id does not exist yet, include a minimal discovery entry that produces that discovery_id. Never duplicate existing discovery_ids. Prefer discovery_id names matching the primary action (e.g., list_buckets, describe_volumes).
```

### User prompt template
```
service: {{service_name}}
scope: {{scope}}                         # global or regional
resource_accessor: {{accessor}}          # e.g., get_all_buckets → for_each: list_buckets, param: Bucket
existing_discovery_ids: {{[ids]}}        # e.g., [list_buckets, get_bucket_location]
discovery_hints:
{{discovery_hints_yaml}}                 # optional pre-specified discovery blocks, else leave empty

known_action_path_templates:
{{action_path_templates_yaml}}           # list of safe action→paths mappings to reuse

check_source_file: {{path/to/check.py}}
check_source_snippet:
"""
{{trimmed_python_check_code}}
"""

Generate one YAML block for this single check, following the schema and rules. Output only YAML.
```

### Example 1: S3 default encryption (confident mapping)

User:
```
service: s3
scope: global
resource_accessor: get_all_buckets → for_each: list_buckets, param: Bucket
discovery_hints:
s3:
  scope: global
  discovery:
    - discovery_id: list_buckets
      calls:
        - action: list_buckets
          fields:
            - path: Buckets[].Name
              var: Bucket
    - discovery_id: get_bucket_location
      for_each: list_buckets
      param: Bucket
      calls:
        - action: get_bucket_location
          fields:
            - path: LocationConstraint
              var: region
              map:
                "": us-east-1
                US: us-east-1
                EU: eu-west-1

known_action_path_templates:
- action: get_bucket_encryption
  fields:
    - path: ServerSideEncryptionConfiguration.Rules[].ApplyServerSideEncryptionByDefault.SSEAlgorithm
- action: get_bucket_versioning
  fields:
    - path: Status
    - path: MFADelete

check_source_file: services/s3/s3_bucket_default_encryption/s3_bucket_default_encryption.py
check_source_snippet:
"""
for bucket in service.get_all_buckets():
    has_encryption = bool(bucket.encryption)
    # pass if encryption present
"""

Generate one YAML block for this single check, following the schema and rules. Output only YAML.
```

LLM Output:
```yaml
s3:
  scope: global
  checks:
    - check_id: s3_bucket_default_encryption
      for_each: list_buckets
      param: Bucket
      calls:
        - action: get_bucket_encryption
          fields:
            - path: ServerSideEncryptionConfiguration.Rules[].ApplyServerSideEncryptionByDefault.SSEAlgorithm
              operator: exists
```

### Example 2: S3 secure transport policy (needs manual policy parsing → TODOs)

User:
```
service: s3
scope: global
resource_accessor: get_all_buckets → for_each: list_buckets, param: Bucket
discovery_hints:
s3:
  scope: global
  discovery:
    - discovery_id: list_buckets
      calls:
        - action: list_buckets
          fields:
            - path: Buckets[].Name
              var: Bucket

known_action_path_templates:
- action: get_bucket_policy
  fields:
    - path: Statement[].Principal
    - path: Statement[].Action
    - path: Statement[].Effect
    - path: Statement[].Condition

check_source_file: services/s3/s3_bucket_secure_transport_policy/s3_bucket_secure_transport_policy.py
check_source_snippet:
"""
# Ensures bucket policy enforces aws:SecureTransport = true
# Review Principal/Action/Condition semantics and deny missing TLS
"""

Generate one YAML block for this single check, following the schema and rules. Output only YAML.
```

LLM Output:
```yaml
s3:
  scope: global
  checks:
    - check_id: s3_bucket_secure_transport_policy
      for_each: list_buckets
      param: Bucket
      calls:
        - action: get_bucket_policy
          fields:
            - path: Statement[].Condition
              operator: TODO_OPERATOR
              expected: TODO_EXPECTED
      _todo: "Manual review: parse policy for aws:SecureTransport == true (deny non-TLS), verify Principal/Action scope"
```

### Example 3: EC2 EBS volume encryption (confident mapping)

User:
```
service: ec2
scope: regional
resource_accessor: get volumes → for_each: describe_volumes, param: VolumeIds
discovery_hints:
ec2:
  scope: regional
  discovery:
    - discovery_id: describe_volumes
      calls:
        - action: describe_volumes
          fields:
            - path: Volumes[].VolumeId
              var: VolumeIds

known_action_path_templates:
- action: describe_volumes
  fields:
    - path: Volumes[].Encrypted

check_source_file: services/ec2/ec2_ebs_volume_encryption/ec2_ebs_volume_encryption.py
check_source_snippet:
"""
# For each EBS volume, Encrypted must be true
"""

Generate one YAML block for this single check, following the schema and rules. Output only YAML.
```

LLM Output:
```yaml
ec2:
  scope: regional
  checks:
    - check_id: ec2_ebs_volume_encryption
      for_each: describe_volumes
      param: VolumeIds
      calls:
        - action: describe_volumes
          fields:
            - path: Volumes[].Encrypted
              operator: equals
              expected: true
```

### Notes
- Start with a small set of known action/path templates per service to boost accuracy.
- Always review outputs; fill TODOs using the check’s metadata and AWS docs.
- You can batch multiple checks by repeating the User payload per check.
