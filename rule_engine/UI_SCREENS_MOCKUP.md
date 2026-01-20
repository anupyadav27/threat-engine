# Rule Builder UI - Screen Mockups

## UI Flow & Data Mapping

---

## 🏠 Screen 1: Rule Builder Dashboard

**URL**: `/dashboard`

**Purpose**: Overview of rule library and provider status

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  RULE BUILDER DASHBOARD                    [➕ Create New Rule]   │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  PROVIDER STATUS                                                  │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ ☁️ AWS        │ ☁️ Azure     │ ☁️ GCP        │ ☁️ OCI        │  │
│  │ 95% Ready    │ 87% Ready    │ 92% Ready    │ 78% Ready    │  │
│  │ 450 services │ 320 services │ 280 services │ 210 services │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│  ┌──────────────┬──────────────┐                                │
│  │ ☁️ AliCloud   │ ☁️ IBM        │                                │
│  │ 82% Ready    │ 75% Ready    │                                │
│  │ 195 services │ 165 services │                                │
│  └──────────────┴──────────────┘                                │
│                                                                   │
│  RULE LIBRARY STATISTICS                                         │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 📋 1,245     │ ✏️ 342       │ 🏷️ 6         │ 📊 89%       │  │
│  │ Total Rules  │ Custom Rules │ Providers    │ Coverage     │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  RECENT RULES                                    [View All →]     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ aws.iam.resource.user_active                               │ │
│  │ AWS | IAM | Created: 2 hours ago | [View] [Edit] [Delete]  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ azure.compute.vm.encryption_enabled                        │ │
│  │ Azure | Compute | Created: 5 hours ago | [View] [Edit]    │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ gcp.storage.bucket.public_access_blocked                  │ │
│  │ GCP | Storage | Created: 1 day ago | [View] [Edit]       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  QUICK ACTIONS                                                    │
│  [📥 Import Rules] [📤 Export Rules] [🔍 Search Rules]          │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// On page load
const providers = await fetch('/api/v1/providers')
const providersStatus = await fetch('/api/v1/providers/status')
const recentRules = await fetch('/api/v1/rules?limit=10&offset=0')

// Calculate statistics
const totalRules = recentRules.total
const customRules = recentRules.rules.filter(r => r.rule_id.includes('.custom.'))
const providersCount = providers.providers.length
```

---

## ➕ Screen 2: Create New Rule

**URL**: `/rules/create`

**Purpose**: Step-by-step rule creation wizard

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  CREATE NEW RULE                    [Step 1 of 4] [Cancel]       │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  STEP 1: SELECT PROVIDER & SERVICE                                │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Provider: [AWS ▼]                                           │ │
│  │   ☁️ AWS | ☁️ Azure | ☁️ GCP | ☁️ OCI | ☁️ AliCloud | ☁️ IBM│ │
│  │                                                             │ │
│  │ Service: [Select service... ▼]                            │ │
│  │   🔍 [Search services...]                                  │ │
│  │   • accessanalyzer (95% ready)                            │ │
│  │   • account (100% ready)                                   │ │
│  │   • acm (98% ready)                                        │ │
│  │   • iam (100% ready)                                        │ │
│  │   • s3 (100% ready)                                         │ │
│  │   ...                                                       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [Next: Define Conditions →]                                    │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load providers
const providers = await fetch('/api/v1/providers')

// Load services for selected provider
const services = await fetch(`/api/v1/providers/${selectedProvider}/services`)

// Load provider status
const providerStatus = await fetch(`/api/v1/providers/${selectedProvider}/status`)
```

---

## 🔧 Screen 3: Define Rule Conditions

**URL**: `/rules/create?step=2`

**Purpose**: Build rule conditions (field + operator + value)

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  CREATE NEW RULE                    [Step 2 of 4] [← Back]       │
├──────────────────────────────────────────────────────────────────┤
│  Provider: AWS | Service: IAM                                    │
│                                                                   │
│  RULE CONDITIONS                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Logical Operator: [All conditions must be true ▼]          │ │
│  │   • All conditions (AND)                                   │ │
│  │   • Any condition (OR)                                      │ │
│  │   • Single condition                                        │ │
│  │                                                             │ │
│  │ Condition 1:                                                │ │
│  │   Field: [Status ▼]                    [Remove]           │ │
│  │     • Status                                                │ │
│  │     • UserName                                              │ │
│  │     • CreateDate                                            │ │
│  │     • PasswordLastUsed                                       │ │
│  │     ...                                                     │ │
│  │                                                             │ │
│  │   Operator: [equals ▼]                                     │ │
│  │     • equals                                                │ │
│  │     • not_equals                                            │ │
│  │     • in                                                    │ │
│  │     • not_in                                                │ │
│  │     • exists                                                │ │
│  │     • not_exists                                            │ │
│  │     • greater_than                                          │ │
│  │     • less_than                                             │ │
│  │     ...                                                     │ │
│  │                                                             │ │
│  │   Value: [ACTIVE ▼]                                         │ │
│  │     • ACTIVE                                                │ │
│  │     • CREATING                                              │ │
│  │     • DISABLED                                              │ │
│  │     • FAILED                                                │ │
│  │     [Custom value...]                                       │ │
│  │                                                             │ │
│  │   Preview: Status equals "ACTIVE"                           │ │
│  │                                                             │ │
│  │ [+ Add Another Condition]                                   │ │
│  │                                                             │ │
│  │ Condition 2: (if multiple)                                 │ │
│  │   Field: [PasswordLastUsed ▼]              [Remove]         │ │
│  │   Operator: [exists ▼]                                     │ │
│  │   Value: [null]                                             │ │
│  │   Preview: PasswordLastUsed exists                         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  RULE PREVIEW                                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ IF (Status equals "ACTIVE" AND PasswordLastUsed exists)    │ │
│  │ THEN PASS                                                   │ │
│  │ ELSE FAIL                                                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [← Back] [Next: Rule Details →]                                 │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load fields for selected service
const fields = await fetch(`/api/v1/providers/${provider}/services/${service}/fields`)

// Example response:
// {
//   "provider": "aws",
//   "service": "iam",
//   "fields": {
//     "Status": {
//       "operators": ["equals", "not_equals", "in"],
//       "type": "string",
//       "enum": true,
//       "possible_values": ["ACTIVE", "CREATING", "DISABLED"],
//       "operations": ["ListUsers", "GetUser"]
//     },
//     ...
//   }
// }

// Validate condition as user types
const validation = await fetch('/api/v1/rules/validate', {
  method: 'POST',
  body: JSON.stringify({
    provider: provider,
    service: service,
    rule_id: `${provider}.${service}.resource.temp`,
    conditions: [
      { field_name: "Status", operator: "equals", value: "ACTIVE" }
    ],
    logical_operator: "single"
  })
})
```

---

## 📝 Screen 4: Rule Details & Metadata

**URL**: `/rules/create?step=3`

**Purpose**: Enter rule metadata (title, description, remediation)

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  CREATE NEW RULE                    [Step 3 of 4] [← Back]       │
├──────────────────────────────────────────────────────────────────┤
│  Provider: AWS | Service: IAM                                    │
│  Conditions: Status equals "ACTIVE" AND PasswordLastUsed exists  │
│                                                                   │
│  RULE ID                                                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ aws.iam.resource.user_active_and_password_used            │ │
│  │ [Auto-generate from title] [Edit]                          │ │
│  │ Format: {provider}.{service}.{type}.{name}                 │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  RULE METADATA                                                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Title: *                                                    │ │
│  │ [IAM User Active with Password Used]                       │ │
│  │                                                             │ │
│  │ Description: *                                              │ │
│  │ [Ensures IAM users are active and have used their          │ │
│  │  password at least once. This helps identify unused         │ │
│  │  accounts that may pose a security risk.]                  │ │
│  │                                                             │ │
│  │ Remediation Steps: *                                       │ │
│  │ [1. Navigate to AWS IAM Console                            │ │
│  │  2. Select the user account                                 │ │
│  │  3. If user is inactive, activate the account               │ │
│  │  4. If password never used, reset password and notify user  │ │
│  │  5. Review user access permissions]                         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  EXISTING RULES CHECK                                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ ⚠️ Similar rule found: aws.iam.resource.user_active        │ │
│  │    Matches: Status equals "ACTIVE"                         │ │
│  │    [View Existing Rule] [Use Existing] [Create New Anyway]   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [← Back] [Next: Review & Generate →]                           │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Validate rule with full details
const validation = await fetch('/api/v1/rules/validate', {
  method: 'POST',
  body: JSON.stringify({
    provider: provider,
    service: service,
    rule_id: ruleId,
    conditions: conditions,
    logical_operator: logicalOperator
  })
})

// Check for existing rules (returned in validation response)
if (validation.existing_rules.length > 0) {
  // Show warning to user
}
```

---

## ✅ Screen 5: Review & Generate

**URL**: `/rules/create?step=4`

**Purpose**: Final review before generating rule files

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  CREATE NEW RULE                    [Step 4 of 4] [← Back]       │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  RULE SUMMARY                                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Provider: AWS                                                │ │
│  │ Service: IAM                                                 │ │
│  │ Rule ID: aws.iam.resource.user_active_and_password_used    │ │
│  │                                                             │ │
│  │ Title: IAM User Active with Password Used                  │ │
│  │                                                             │ │
│  │ Conditions:                                                 │ │
│  │   • Status equals "ACTIVE"                                  │ │
│  │   • PasswordLastUsed exists                                 │ │
│  │   Logical Operator: ALL (AND)                               │ │
│  │                                                             │ │
│  │ Description:                                                │ │
│  │   Ensures IAM users are active and have used their         │ │
│  │   password at least once...                                 │ │
│  │                                                             │ │
│  │ Remediation:                                                │ │
│  │   1. Navigate to AWS IAM Console                            │ │
│  │   2. Select the user account...                             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  VALIDATION STATUS                                                │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ ✅ All fields valid                                          │ │
│  │ ✅ No duplicate rules found                                  │ │
│  │ ✅ Conditions compatible                                     │ │
│  │ ⚠️ 1 similar rule exists (non-blocking)                     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  OUTPUT FILES                                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ YAML: aws_compliance_python_engine/services/iam/rules/... │ │
│  │ Metadata: aws_compliance_python_engine/services/iam/...   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [← Back] [Generate Rule]                                        │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Generate rule
const result = await fetch('/api/v1/rules/generate', {
  method: 'POST',
  body: JSON.stringify({
    provider: provider,
    service: service,
    title: title,
    description: description,
    remediation: remediation,
    rule_id: ruleId,
    conditions: conditions,
    logical_operator: logicalOperator
  })
})

// Response:
// {
//   "success": true,
//   "yaml_path": "/path/to/iam.yaml",
//   "metadata_path": "/path/to/metadata/rule_id.yaml",
//   "existing_rules_found": [],
//   "errors": []
// }
```

---

## 📚 Screen 6: Rule Library

**URL**: `/rules`

**Purpose**: Browse and manage all rules

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  RULE LIBRARY                    [➕ Create New] [📥 Import]    │
├──────────────────────────────────────────────────────────────────┤
│  FILTERS                                                          │
│  Provider: [All ▼] | Service: [All ▼] | Type: [All ▼]           │
│  Search: [Search rules...]                                       │
│                                                                   │
│  📊 Showing 1,245 rules | 6 providers | 342 custom rules         │
│                                                                   │
│  GROUP BY: [Provider ▼]                    [📋 List] [🗃️ Cards] │
│                                                                   │
│  ▼ AWS (650 rules)                                               │
│    ├─ ▼ IAM (125 rules)                          [View All →]   │
│    │   ┌──────────────────────────────────────────────────────┐ │
│    │   │ aws.iam.resource.user_active                         │ │
│    │   │ Status equals "ACTIVE"                                │ │
│    │   │ Created: 2025-01-15 | Updated: 2025-01-18            │ │
│    │   │ [View] [Edit] [Delete] [Copy]                         │ │
│    │   └──────────────────────────────────────────────────────┘ │
│    │   ┌──────────────────────────────────────────────────────┐ │
│    │   │ aws.iam.resource.mfa_enabled                         │ │
│    │   │ MfaActive equals true                                 │ │
│    │   │ Created: 2025-01-14 | Custom: ✅                     │ │
│    │   │ [View] [Edit] [Delete]                                │ │
│    │   └──────────────────────────────────────────────────────┘ │
│    │                                                             │
│    ├─ ▶ S3 (89 rules)                                           │
│    └─ ▶ EC2 (156 rules)                                         │
│                                                                   │
│  ▼ Azure (320 rules)                                             │
│  ▼ GCP (180 rules)                                               │
│  ▼ OCI (95 rules)                                                │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load all rules with filters
const rules = await fetch(`/api/v1/rules?provider=${provider}&service=${service}&limit=100&offset=0`)

// Group by provider/service in UI
const grouped = {}
rules.rules.forEach(rule => {
  if (!grouped[rule.provider]) grouped[rule.provider] = {}
  if (!grouped[rule.provider][rule.service]) grouped[rule.provider][rule.service] = []
  grouped[rule.provider][rule.service].push(rule)
})
```

---

## 🔍 Screen 7: Rule Detail View

**URL**: `/rules/{rule_id}`

**Purpose**: View complete rule details

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back to Library                                               │
├──────────────────────────────────────────────────────────────────┤
│  aws.iam.resource.user_active_and_password_used                  │
│                                                                   │
│  RULE INFORMATION                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Provider: AWS                                                │ │
│  │ Service: IAM                                                 │ │
│  │ Rule ID: aws.iam.resource.user_active_and_password_used    │ │
│  │ Type: Custom Rule                                            │ │
│  │ Created: 2025-01-15 14:30:00                                │ │
│  │ Updated: 2025-01-18 10:15:00                                │ │
│  │ Created By: yaml_rule_builder                                │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  TITLE & DESCRIPTION                                              │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ IAM User Active with Password Used                         │ │
│  │                                                             │ │
│  │ Ensures IAM users are active and have used their          │ │
│  │ password at least once. This helps identify unused         │ │
│  │ accounts that may pose a security risk.                    │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  CONDITIONS                                                       │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Logical Operator: ALL (AND)                                 │ │
│  │                                                             │ │
│  │ Condition 1:                                                │ │
│  │   Field: Status                                             │ │
│  │   Operator: equals                                          │ │
│  │   Value: "ACTIVE"                                           │ │
│  │   Preview: Status equals "ACTIVE"                           │ │
│  │                                                             │ │
│  │ Condition 2:                                                │ │
│  │   Field: PasswordLastUsed                                  │ │
│  │   Operator: exists                                          │ │
│  │   Value: null                                               │ │
│  │   Preview: PasswordLastUsed exists                         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  REMEDIATION STEPS                                                │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 1. Navigate to AWS IAM Console                              │ │
│  │ 2. Select the user account                                  │ │
│  │ 3. If user is inactive, activate the account                │ │
│  │ 4. If password never used, reset password and notify user  │ │
│  │ 5. Review user access permissions                           │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  FILES                                                            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ YAML: /path/to/iam.yaml                                     │ │
│  │ Metadata: /path/to/metadata/rule_id.yaml                     │ │
│  │ [View YAML] [View Metadata] [Download]                      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [Edit Rule] [Delete Rule] [Copy Rule] [Export]                 │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load rule details
const rule = await fetch(`/api/v1/rules/${ruleId}`)

// Response:
// {
//   "rule_id": "aws.iam.resource.user_active_and_password_used",
//   "provider": "aws",
//   "service": "iam",
//   "title": "IAM User Active with Password Used",
//   "description": "...",
//   "remediation": "...",
//   "conditions": [...],
//   "logical_operator": "all",
//   "yaml_path": "/path/to/iam.yaml",
//   "metadata_path": "/path/to/metadata/rule_id.yaml",
//   "created_at": "2025-01-15T14:30:00",
//   "updated_at": "2025-01-18T10:15:00"
// }
```

---

## ✏️ Screen 8: Edit Rule

**URL**: `/rules/{rule_id}/edit`

**Purpose**: Edit existing rule

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  EDIT RULE: aws.iam.resource.user_active_and_password_used      │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  [Same form as Create Rule, but pre-filled with existing data]   │
│                                                                   │
│  RULE CONDITIONS (Editable)                                       │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Logical Operator: [All conditions must be true ▼]          │ │
│  │                                                             │ │
│  │ Condition 1:                                                │ │
│  │   Field: [Status ▼]                    [Remove]           │ │
│  │   Operator: [equals ▼]                                     │ │
│  │   Value: [ACTIVE ▼]                                        │ │
│  │                                                             │ │
│  │ [+ Add Another Condition]                                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  RULE METADATA (Editable)                                        │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Title: [IAM User Active with Password Used]                │ │
│  │ Description: [...]                                          │ │
│  │ Remediation: [...]                                          │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [Cancel] [Save Changes]                                          │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load existing rule
const rule = await fetch(`/api/v1/rules/${ruleId}`)

// Update rule
const result = await fetch(`/api/v1/rules/${ruleId}`, {
  method: 'PUT',
  body: JSON.stringify({
    provider: provider,
    service: service,
    title: title,
    description: description,
    remediation: remediation,
    rule_id: ruleId,
    conditions: conditions,
    logical_operator: logicalOperator
  })
})
```

---

## ☁️ Screen 9: Provider Status Dashboard

**URL**: `/providers`

**Purpose**: View provider capabilities and readiness

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  PROVIDER STATUS DASHBOARD                                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  OVERALL STATUS                                                   │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 6 Providers  │ 1,620        │ 1,442        │ 89%           │  │
│  │ Registered   │ Total        │ Ready        │ Overall       │  │
│  │              │ Services      │ Services     │ Readiness     │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  PROVIDER DETAILS                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ ☁️ AWS                                                       │ │
│  │ Readiness: 95% ████████████████████░░                       │ │
│  │ Services: 428 ready / 450 total                             │ │
│  │ Rules: 650 | Custom: 120                                   │ │
│  │ [View Services] [View Rules]                                │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ ☁️ Azure                                                     │ │
│  │ Readiness: 87% ██████████████████░░░                        │ │
│  │ Services: 278 ready / 320 total                             │ │
│  │ Rules: 320 | Custom: 95                                    │ │
│  │ [View Services] [View Rules]                                │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ ☁️ GCP                                                       │ │
│  │ Readiness: 92% ████████████████████░                        │ │
│  │ Services: 258 ready / 280 total                             │ │
│  │ Rules: 180 | Custom: 45                                    │ │
│  │ [View Services] [View Rules]                                │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [Refresh Status]                                                 │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load all providers status
const status = await fetch('/api/v1/providers/status')

// Load specific provider status
const providerStatus = await fetch(`/api/v1/providers/${provider}/status`)

// Response:
// {
//   "provider": "aws",
//   "readiness_percentage": 95,
//   "total_services": 450,
//   "ready_services": 428,
//   "partial_services": 15,
//   "missing_services": 7,
//   "ready_services_list": [...],
//   "partial_services_list": [...],
//   "missing_services_list": [...]
// }
```

---

## 📊 Screen 10: Service Rules View

**URL**: `/providers/{provider}/services/{service}/rules`

**Purpose**: View all rules for a specific service

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back to Provider                                              │
├──────────────────────────────────────────────────────────────────┤
│  AWS > IAM Rules                                                 │
│                                                                   │
│  SERVICE INFORMATION                                              │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Service: IAM                                                │ │
│  │ Provider: AWS                                                │ │
│  │ Status: 100% Ready                                          │ │
│  │ Total Rules: 125                                            │ │
│  │ Custom Rules: 23                                             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  RULES (125)                    [➕ Create Rule for IAM]        │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 🔍 [Search rules...]                                        │ │
│  │ Filter: [All ▼] | Sort: [Newest First ▼]                  │ │
│  │                                                             │ │
│  │ ┌─────────────────────────────────────────────────────────┐ │ │
│  │ │ aws.iam.resource.user_active                            │ │ │
│  │ │ Status equals "ACTIVE"                                  │ │ │
│  │ │ Created: 2025-01-15 | [View] [Edit] [Delete]           │ │ │
│  │ └─────────────────────────────────────────────────────────┘ │ │
│  │                                                             │ │
│  │ ┌─────────────────────────────────────────────────────────┐ │ │
│  │ │ aws.iam.resource.mfa_enabled                            │ │ │
│  │ │ MfaActive equals true                                    │ │ │
│  │ │ Custom: ✅ | Created: 2025-01-14 | [View] [Edit]       │ │ │
│  │ └─────────────────────────────────────────────────────────┘ │ │
│  │                                                             │ │
│  │ ┌─────────────────────────────────────────────────────────┐ │ │
│  │ │ aws.iam.resource.user_active_and_password_used          │ │ │
│  │ │ Status equals "ACTIVE" AND PasswordLastUsed exists      │ │ │
│  │ │ Custom: ✅ | Created: 2025-01-12 | [View] [Edit]        │ │ │
│  │ └─────────────────────────────────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [Load More]                                                      │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load rules for specific service
const serviceRules = await fetch(`/api/v1/providers/${provider}/services/${service}/rules`)

// Response:
// {
//   "provider": "aws",
//   "service": "iam",
//   "rules": [
//     {
//       "rule_id": "aws.iam.resource.user_active",
//       "provider": "aws",
//       "title": "IAM User Active",
//       "description": "...",
//       "created_at": "2025-01-15T14:30:00",
//       "updated_at": "2025-01-18T10:15:00"
//     },
//     ...
//   ],
//   "total": 125
// }
```

---

## 📋 Data Fields Reference

### Provider Status (`/providers/status`)
```json
{
  "providers_status": {
    "aws": {
      "provider": "aws",
      "readiness_percentage": 95,
      "total_services": 450,
      "ready_services": 428,
      "partial_services": 15,
      "missing_services": 7,
      "ready_services_list": ["iam", "s3", "ec2", ...],
      "partial_services_list": ["lambda", ...],
      "missing_services_list": ["newservice", ...]
    }
  },
  "total_providers": 6,
  "ready_providers": 4
}
```

### Service Fields (`/providers/{provider}/services/{service}/fields`)
```json
{
  "provider": "aws",
  "service": "iam",
  "fields": {
    "Status": {
      "operators": ["equals", "not_equals", "in"],
      "type": "string",
      "enum": true,
      "possible_values": ["ACTIVE", "CREATING", "DISABLED"],
      "operations": ["ListUsers", "GetUser"]
    },
    "UserName": {
      "operators": ["equals", "not_equals", "contains", "starts_with"],
      "type": "string",
      "enum": false,
      "possible_values": null,
      "operations": ["ListUsers", "GetUser"]
    }
  }
}
```

### Rule Validation (`/rules/validate`)
```json
{
  "valid": true,
  "errors": [],
  "warnings": [],
  "existing_rules": [
    {
      "rule_id": "aws.iam.resource.existing_rule",
      "source_file": "/path/to/iam.yaml",
      "for_each": "aws.iam.list_users",
      "note": "Exact match (Phase 2 with for_each)"
    }
  ]
}
```

### Rule Generation (`/rules/generate`)
```json
{
  "success": true,
  "yaml_path": "/path/to/iam.yaml",
  "metadata_path": "/path/to/metadata/rule_id.yaml",
  "existing_rules_found": [],
  "errors": []
}
```

### Rule Object (`/rules/{rule_id}`)
```json
{
  "rule_id": "aws.iam.resource.user_active",
  "provider": "aws",
  "service": "iam",
  "title": "IAM User Active",
  "description": "Ensures IAM users have ACTIVE status",
  "remediation": "Activate the IAM user",
  "conditions": [
    {
      "field_name": "Status",
      "operator": "equals",
      "value": "ACTIVE"
    }
  ],
  "logical_operator": "single",
  "yaml_path": "/path/to/iam.yaml",
  "metadata_path": "/path/to/metadata/rule_id.yaml",
  "created_at": "2025-01-15T14:30:00",
  "updated_at": "2025-01-18T10:15:00"
}
```

---

## 🎨 UI Component Library Recommendations

1. **Form Builder**: React Hook Form or Formik for rule creation forms
2. **Step Wizard**: React Step Wizard or custom stepper component
3. **Dropdowns**: React Select for provider/service/field selection
4. **Code Editor**: Monaco Editor or CodeMirror for YAML preview
5. **Tables**: TanStack Table for rule library
6. **Charts**: Recharts for provider readiness visualization
7. **Framework**: React, Vue, or Angular
8. **State**: Redux/Zustand or React Query for API caching

---

## ✅ Implementation Checklist for Frontend

- [ ] Dashboard with provider status cards
- [ ] Rule creation wizard (4 steps)
- [ ] Provider selection with status indicators
- [ ] Service selection with search
- [ ] Field/operator/value selection with validation
- [ ] Multiple conditions builder (AND/OR)
- [ ] Rule metadata form (title, description, remediation)
- [ ] Rule validation with existing rule detection
- [ ] Rule generation with file paths
- [ ] Rule library with filters and search
- [ ] Rule detail view
- [ ] Rule edit functionality
- [ ] Rule delete with confirmation
- [ ] Provider status dashboard
- [ ] Service rules view
- [ ] YAML/Metadata file viewer
- [ ] Export/Import functionality
- [ ] Real-time validation feedback

---

## 🔍 Missing API Endpoints (To Be Created)

Based on the UI requirements, here are potential missing endpoints:

### 1. Rule Search & Advanced Filtering
- `GET /api/v1/rules/search?q={query}` - Full-text search across rules
- `GET /api/v1/rules?custom=true` - Filter custom rules only
- `GET /api/v1/rules?created_after={date}` - Filter by creation date

### 2. Rule Import/Export
- `POST /api/v1/rules/import` - Import rules from file
- `GET /api/v1/rules/export?format=json|yaml` - Export rules

### 3. Rule Copy/Duplicate
- `POST /api/v1/rules/{rule_id}/copy` - Duplicate existing rule

### 4. Rule Validation Preview
- `POST /api/v1/rules/preview` - Preview YAML without generating files

### 5. Bulk Operations
- `POST /api/v1/rules/bulk-delete` - Delete multiple rules
- `POST /api/v1/rules/bulk-export` - Export multiple rules

### 6. Rule Statistics
- `GET /api/v1/rules/statistics` - Get rule statistics (counts by provider/service)

### 7. Service Capabilities
- `GET /api/v1/providers/{provider}/services/{service}/capabilities` - Get service capabilities and supported operations

### 8. Rule Templates
- `GET /api/v1/rules/templates` - Get rule templates
- `POST /api/v1/rules/templates/{template_id}/create` - Create rule from template

---

**All existing APIs are ready - UI can be built immediately!**



