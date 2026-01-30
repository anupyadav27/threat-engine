# Onboarding Engine UI - Screen Mockups

## UI Flow & Data Mapping

This document defines the UI layout, API endpoints, and identifies missing endpoints needed for CSPM compliance engine integration. Similar to the data-security-engine UI_SCREENS_MOCKUP.md structure.

---

## 🏠 Screen 1: Onboarding Dashboard

**URL**: `/onboarding/dashboard`

**Purpose**: Overview of tenants, accounts, and onboarding status

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ONBOARDING OVERVIEW                    [➕ Add Account]          │
├──────────────────────────────────────────────────────────────────┤
│  KEY METRICS                                                      │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 🏢 3         │ ☁️ 12         │ ✅ 8          │ ⏰ 4          │  │
│  │ Tenants      │ Accounts     │ Active       │ Pending      │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│  ACCOUNTS BY PROVIDER                                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ ☁️ AWS          ████████████░░░░  8 accounts (67%)         │ │
│  │ ☁️ Azure       ████░░░░░░░░░░░░  2 accounts (17%)         │ │
│  │ ☁️ GCP         ██░░░░░░░░░░░░░░  1 account (8%)            │ │
│  └────────────────────────────────────────────────────────────┘ │
│  RECENT ONBOARDING ACTIVITY                                      │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ ✅ AWS Account: Production (155052200811)                 │ │
│  │    Onboarded: 2 hours ago | Status: Active               │ │
│  │    [View Details] [Manage Schedules]                      │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// On page load
const tenants = await fetch('/api/v1/onboarding/tenants')
const accounts = await fetch('/api/v1/onboarding/accounts')
const providers = await fetch('/api/v1/onboarding/providers')

// Calculate metrics
const totalTenants = tenants.length
const totalAccounts = accounts.length
const activeAccounts = accounts.filter(a => a.status === 'active').length
const pendingAccounts = accounts.filter(a => a.onboarding_status === 'pending').length
```

---

## ☁️ Screen 2: Account Onboarding - Multi-Step Flow

**URL**: `/onboarding/accounts/new`

**Step 1: Select Provider**
- **API**: No API call needed (static list)
- **UI**: Provider selection cards (AWS, Azure, GCP, AliCloud, OCI, IBM)

**Step 2: Select Tenant**
- **API**: `GET /api/v1/onboarding/tenants`
- **UI**: Tenant selection or create new tenant

**Step 3: Account Information**
- **API**: 
  - `GET /api/v1/onboarding/{provider}/methods` - Get auth methods
  - `POST /api/v1/onboarding/{provider}/init` - Initialize onboarding
- **UI**: Account name, authentication method selection

**Step 4: Credentials Configuration**
- **API**:
  - `GET /api/v1/onboarding/aws/cloudformation-template?external_id={id}` - Get CF template (AWS)
  - `POST /api/v1/onboarding/{provider}/validate` - Validate credentials
  - `POST /api/v1/onboarding/aws/validate-json` - Validate from CF JSON (AWS)
- **UI**: Credential input based on auth method (IAM Role, Access Key, etc.)

---

## 📋 Screen 3: Account List

**URL**: `/onboarding/accounts`

**Purpose**: View and manage all accounts

**API Calls**:
```javascript
// List all accounts
const accounts = await fetch('/api/v1/onboarding/accounts?tenant_id=tenant-acme-001')

// Get account details
const account = await fetch(`/api/v1/onboarding/accounts/${accountId}`)

// Delete account
await fetch(`/api/v1/onboarding/accounts/${accountId}`, { method: 'DELETE' })
```

**Data Display**:
- Account cards with provider, status, tenant
- Filter by tenant, provider, status
- Actions: View Details, Manage Schedules, Edit Credentials, Delete

---

## 🔍 Screen 4: Account Detail

**URL**: `/onboarding/accounts/{account_id}`

**Purpose**: View account details, credentials, and schedules

**API Calls**:
```javascript
// Get account details
const account = await fetch(`/api/v1/onboarding/accounts/${accountId}`)

// Get credentials
const credentials = await fetch(`/api/v1/accounts/${accountId}/credentials`)

// Validate credentials
const validation = await fetch(`/api/v1/accounts/${accountId}/credentials/validate`, {
  method: 'GET'
})

// Get schedules for account
const schedules = await fetch(`/api/v1/schedules?account_id=${accountId}`)
```

**Tabs**:
- Overview: Account info, status, statistics
- Credentials: Auth method, credential details, validation status
- Schedules: List of schedules for this account
- Executions: Execution history

---

## ⏰ Screen 5: Schedule Management

**URL**: `/onboarding/schedules`

**Purpose**: Create and manage scan schedules

**API Calls**:
```javascript
// List schedules
const schedules = await fetch('/api/v1/schedules?tenant_id=tenant-acme-001')

// Get schedule details
const schedule = await fetch(`/api/v1/schedules/${scheduleId}`)

// Create schedule
const newSchedule = await fetch('/api/v1/schedules', {
  method: 'POST',
  body: JSON.stringify({
    tenant_id: 'tenant-acme-001',
    account_id: 'account-uuid',
    name: 'Daily Full Scan',
    schedule_type: 'cron',
    cron_expression: '0 2 * * *',
    timezone: 'UTC',
    regions: [],
    services: []
  })
})

// Update schedule
await fetch(`/api/v1/schedules/${scheduleId}`, {
  method: 'PUT',
  body: JSON.stringify({ enabled: false })
})

// Trigger schedule manually
await fetch(`/api/v1/schedules/${scheduleId}/trigger`, {
  method: 'POST'
})

// Delete schedule
await fetch(`/api/v1/schedules/${scheduleId}`, { method: 'DELETE' })
```

---

## 📊 Screen 6: Execution History

**URL**: `/onboarding/schedules/{schedule_id}/executions`

**Purpose**: View scan execution history

**API Calls**:
```javascript
// Get executions for schedule
const executions = await fetch(`/api/v1/schedules/${scheduleId}/executions`)
```

**Data Display**:
- Execution list with status (running, success, failed)
- Execution details: start time, duration, scan ID, results
- Actions: View Results, View Logs, Retry (for failed)

---

## 🏢 Screen 7: Tenant Management

**URL**: `/onboarding/tenants`

**Purpose**: Create and manage tenants

**API Calls**:
```javascript
// List all tenants
const tenants = await fetch('/api/v1/onboarding/tenants')

// Get tenant details
const tenant = await fetch(`/api/v1/onboarding/tenants/${tenantId}`)

// Create tenant
const newTenant = await fetch('/api/v1/onboarding/tenants', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    tenant_id: 'tenant-acme-001',
    tenant_name: 'Acme Corporation',
    description: 'Main production tenant'
  })
})
```

---

## 🔧 Screen 8: Provider Management

**URL**: `/onboarding/providers`

**Purpose**: View and manage cloud providers

**API Calls**:
```javascript
// List providers
const providers = await fetch('/api/v1/onboarding/providers?tenant_id=tenant-acme-001')

// Get provider details
const provider = await fetch(`/api/v1/onboarding/providers/${providerId}`)

// Create provider (usually auto-created during onboarding)
const newProvider = await fetch('/api/v1/onboarding/providers', {
  method: 'POST',
  body: JSON.stringify({
    tenant_id: 'tenant-acme-001',
    provider_type: 'aws'
  })
})
```

---

## 🚨 Missing API Endpoints for CSPM Compliance Engine Integration

Based on the UI mockups above, here are the **missing API endpoints** that should be created:

### 1. **Account Health & Status**
```
GET /api/v1/accounts/{account_id}/health
```
**Purpose**: Get real-time health status of account (credentials valid, last scan status, etc.)

**Response**:
```json
{
  "account_id": "account-uuid",
  "health_status": "healthy|degraded|unhealthy",
  "credentials_valid": true,
  "last_validation": "2025-01-18T10:30:00Z",
  "last_scan": "2025-01-18T08:00:00Z",
  "last_scan_status": "success|failed|running",
  "issues": []
}
```

### 2. **Account Statistics**
```
GET /api/v1/accounts/{account_id}/statistics
```
**Purpose**: Get account statistics (total scans, success rate, average scan duration, etc.)

**Response**:
```json
{
  "account_id": "account-uuid",
  "total_scans": 150,
  "successful_scans": 145,
  "failed_scans": 5,
  "success_rate": 96.67,
  "average_scan_duration_seconds": 900,
  "last_7_days_scans": 7,
  "last_30_days_scans": 30
}
```

### 3. **Account Compliance Status**
```
GET /api/v1/accounts/{account_id}/compliance-status
```
**Purpose**: Get compliance status summary for an account (requires integration with compliance engine)

**Response**:
```json
{
  "account_id": "account-uuid",
  "last_scan_id": "scan-20250118-020015",
  "compliance_score": 85.5,
  "total_checks": 1234,
  "passed_checks": 1100,
  "failed_checks": 134,
  "critical_findings": 5,
  "high_findings": 25,
  "medium_findings": 104,
  "frameworks": {
    "GDPR": { "score": 82, "status": "compliant" },
    "PCI-DSS": { "score": 88, "status": "compliant" }
  }
}
```

### 4. **Execution Logs**
```
GET /api/v1/schedules/{schedule_id}/executions/{execution_id}/logs
```
**Purpose**: Get detailed logs for a specific execution

### 5. **Real-time Execution Status**
```
GET /api/v1/schedules/{schedule_id}/executions/{execution_id}/status
WebSocket /api/v1/schedules/{schedule_id}/executions/{execution_id}/stream
```
**Purpose**: Get real-time status updates for running executions

### 6. **Schedule Statistics**
```
GET /api/v1/schedules/{schedule_id}/statistics
```
**Purpose**: Get schedule performance metrics

### 7. **Bulk Account Operations**
```
POST /api/v1/accounts/bulk/validate
POST /api/v1/accounts/bulk/delete
```
**Purpose**: Validate or delete multiple accounts at once

### 8. **Account Credential Rotation**
```
POST /api/v1/accounts/{account_id}/credentials/rotate
```
**Purpose**: Rotate credentials for an account

### 9. **Tenant Statistics**
```
GET /api/v1/onboarding/tenants/{tenant_id}/statistics
```
**Purpose**: Get tenant-level statistics (total accounts, active accounts, scan success rates, etc.)

### 10. **Provider Capabilities**
```
GET /api/v1/onboarding/{provider}/capabilities
```
**Purpose**: Get provider-specific capabilities (supported regions, services, auth methods, etc.)

### 11. **Onboarding Progress Tracking**
```
GET /api/v1/onboarding/{onboarding_id}/progress
WebSocket /api/v1/onboarding/{onboarding_id}/progress/stream
```
**Purpose**: Track onboarding progress in real-time

### 12. **Schedule Templates**
```
GET /api/v1/schedules/templates
POST /api/v1/schedules/templates
```
**Purpose**: Create and manage schedule templates for common use cases

### 13. **Account Groups/Tags**
```
POST /api/v1/accounts/{account_id}/tags
GET /api/v1/accounts?tags=production,aws
```
**Purpose**: Tag accounts for better organization and filtering

### 14. **Notification Channels**
```
GET /api/v1/notifications/channels
POST /api/v1/notifications/channels
PUT /api/v1/notifications/channels/{channel_id}
```
**Purpose**: Manage notification channels (email, Slack, webhook, etc.)

### 15. **Integration with Compliance Engine**
```
GET /api/v1/accounts/{account_id}/scan-results
GET /api/v1/accounts/{account_id}/scan-results/{scan_id}
POST /api/v1/accounts/{account_id}/trigger-scan
```
**Purpose**: Direct integration endpoints to trigger scans and retrieve results from compliance engine

---

## 📝 Notes

1. **API Base URL**: All endpoints should be prefixed with `/api/v1/`
2. **Authentication**: All endpoints require authentication (not shown in mockups)
3. **Error Handling**: All endpoints should return consistent error responses
4. **Pagination**: List endpoints should support pagination (`?page=1&limit=50`)
5. **Filtering**: List endpoints should support filtering by various fields
6. **Real-time Updates**: Consider WebSocket support for live updates on dashboards

---

## 🔄 Integration Points with CSPM Compliance Engine

The onboarding engine should integrate with the compliance engine to:
1. Trigger scans when schedules execute
2. Retrieve scan results and status
3. Display compliance scores and findings in the UI
4. Link account details to compliance reports

**Required Compliance Engine Endpoints** (to be implemented):
- `POST /api/v1/compliance/scan` - Trigger a scan
- `GET /api/v1/compliance/scan/{scan_id}/status` - Get scan status
- `GET /api/v1/compliance/scan/{scan_id}/results` - Get scan results
- `GET /api/v1/compliance/accounts/{account_id}/summary` - Get account compliance summary

---

## 📚 Existing API Endpoints Reference

### Health
- `GET /api/v1/health` - Health check

### Onboarding
- `GET /api/v1/onboarding/{provider}/methods` - Get auth methods
- `POST /api/v1/onboarding/{provider}/init` - Initialize onboarding
- `GET /api/v1/onboarding/aws/cloudformation-template` - Get CF template (AWS)
- `POST /api/v1/onboarding/{provider}/validate` - Validate credentials
- `POST /api/v1/onboarding/aws/validate-json` - Validate from CF JSON (AWS)
- `GET /api/v1/onboarding/accounts` - List accounts
- `GET /api/v1/onboarding/accounts/{account_id}` - Get account
- `DELETE /api/v1/onboarding/accounts/{account_id}` - Delete account
- `POST /api/v1/onboarding/tenants` - Create tenant
- `GET /api/v1/onboarding/tenants` - List tenants
- `GET /api/v1/onboarding/tenants/{tenant_id}` - Get tenant
- `POST /api/v1/onboarding/providers` - Create provider
- `GET /api/v1/onboarding/providers` - List providers
- `GET /api/v1/onboarding/providers/{provider_id}` - Get provider

### Credentials
- `POST /api/v1/accounts/{account_id}/credentials` - Store credentials
- `GET /api/v1/accounts/{account_id}/credentials/validate` - Validate credentials
- `DELETE /api/v1/accounts/{account_id}/credentials` - Delete credentials

### Schedules
- `POST /api/v1/schedules` - Create schedule
- `GET /api/v1/schedules` - List schedules
- `GET /api/v1/schedules/{schedule_id}` - Get schedule
- `PUT /api/v1/schedules/{schedule_id}` - Update schedule
- `DELETE /api/v1/schedules/{schedule_id}` - Delete schedule
- `POST /api/v1/schedules/{schedule_id}/trigger` - Trigger schedule
- `GET /api/v1/schedules/{schedule_id}/executions` - List executions



