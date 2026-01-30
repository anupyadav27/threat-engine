# Admin Portal Backend - API Documentation

## Base URL
```
http://admin-backend-service:8001/api/admin
```

## Authentication
All endpoints require authentication. Include authentication token in headers:
```
Authorization: Bearer <token>
```

## Endpoints

### Monitoring

#### List All Tenants
```
GET /api/admin/tenants/
```
Returns list of all tenants with their current status and metrics.

**Response:**
```json
{
  "results": [
    {
      "tenant_id": "uuid",
      "tenant_name": "Tenant Name",
      "status": "active",
      "created_at": "2026-01-23T10:00:00Z",
      "metrics": {
        "active_scans": 0,
        "compliance_score": 85.5,
        "findings_critical": 5,
        "findings_high": 25,
        "resources_count": 1000,
        "last_scan_timestamp": "2026-01-23T09:00:00Z"
      }
    }
  ]
}
```

#### Get Tenant Status
```
GET /api/admin/tenants/{tenant_id}/status
```
Get real-time status for a specific tenant.

**Response:**
```json
{
  "tenant_id": "uuid",
  "status": "active",
  "active_scans": 0,
  "compliance_score": 85.5,
  "findings_critical": 5,
  "findings_high": 25,
  "findings_medium": 50,
  "findings_low": 100,
  "resources_count": 1000,
  "scan_success_rate": 95.0,
  "last_scan_timestamp": "2026-01-23T09:00:00Z",
  "providers": ["aws", "azure"]
}
```

#### Get Tenant Metrics
```
GET /api/admin/tenants/{tenant_id}/metrics
```
Get detailed metrics for a tenant.

#### Dashboard Overview
```
GET /api/admin/dashboard/overview
```
Get platform-wide dashboard overview.

**Response:**
```json
{
  "total_tenants": 100,
  "active_tenants": 95,
  "total_scans_24h": 500,
  "total_scans_7d": 3500,
  "total_scans_30d": 15000,
  "average_compliance_score": 82.5,
  "total_findings_critical": 50,
  "total_findings_high": 250,
  "recent_tenants": [...]
}
```

### Analytics

#### Platform Overview
```
GET /api/admin/analytics/overview
```
Get comprehensive platform analytics.

**Response:**
```json
{
  "total_tenants": 100,
  "active_tenants": 95,
  "inactive_tenants": 5,
  "total_scans_24h": 500,
  "total_scans_7d": 3500,
  "total_scans_30d": 15000,
  "average_compliance_score": 82.5,
  "top_failing_rules": [
    {"rule_id": "rule-1", "failures": 100}
  ],
  "resource_distribution": {
    "aws": 500,
    "azure": 300,
    "gcp": 200
  },
  "scan_success_rate": 95.0,
  "findings_distribution": {
    "critical": 50,
    "high": 250,
    "medium": 500,
    "low": 1000
  }
}
```

#### Compliance Analytics
```
GET /api/admin/analytics/compliance
```
Get compliance analytics across all tenants.

**Response:**
```json
{
  "overall_average": 82.5,
  "by_framework": {
    "GDPR": 85.0,
    "PCI-DSS": 80.0,
    "HIPAA": 82.5
  },
  "by_tenant": [
    {"tenant_id": "uuid", "score": 90.0}
  ],
  "trends": [
    {"date": "2026-01-23", "score": 82.5}
  ]
}
```

#### Scan Analytics
```
GET /api/admin/analytics/scans
```
Get scan statistics.

**Response:**
```json
{
  "total_scans": 15000,
  "successful_scans": 14250,
  "failed_scans": 750,
  "success_rate": 95.0,
  "average_duration": 900.5,
  "scans_by_provider": {
    "aws": 8000,
    "azure": 5000,
    "gcp": 2000
  },
  "scans_by_tenant": [
    {"tenant_id": "uuid", "count": 500}
  ]
}
```

#### Trends
```
GET /api/admin/analytics/trends?metric=scans&days=30
```
Get time-series trend data.

**Query Parameters:**
- `metric`: Metric name (scans, compliance)
- `days`: Number of days (default: 30)

### Management

#### List Users
```
GET /api/admin/users/?page=1&page_size=50
```
List all users with pagination.

#### Create User
```
POST /api/admin/users/
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure-password",
  "first_name": "John",
  "last_name": "Doe",
  "is_active": true,
  "roles": ["admin"]
}
```

#### Update User
```
PUT /api/admin/users/{user_id}/
Content-Type: application/json

{
  "email": "user@example.com",
  "first_name": "John",
  "is_active": true
}
```

#### Deactivate User
```
DELETE /api/admin/users/{user_id}/
```

#### Get User's Tenants
```
GET /api/admin/users/{user_id}/tenants
```

#### Assign Tenant to User
```
POST /api/admin/users/{user_id}/assign-tenant
Content-Type: application/json

{
  "tenant_id": "uuid",
  "role": "member"
}
```

#### List Tenants (Management)
```
GET /api/admin/tenants-management/
```

#### Create Tenant
```
POST /api/admin/tenants-management/
Content-Type: application/json

{
  "tenant_name": "New Tenant",
  "status": "active",
  "description": "Description"
}
```

#### Update Tenant
```
PUT /api/admin/tenants-management/{tenant_id}/
```

#### Suspend Tenant
```
POST /api/admin/tenants-management/{tenant_id}/suspend
```

#### Activate Tenant
```
POST /api/admin/tenants-management/{tenant_id}/activate
```

#### Get Tenant's Users
```
GET /api/admin/tenants-management/{tenant_id}/users
```

#### Get Tenant's Accounts
```
GET /api/admin/tenants-management/{tenant_id}/accounts
```

### Health

#### Engine Health
```
GET /api/admin/health/engines
```
Get health status of all engines.

**Response:**
```json
{
  "configscan_aws": {
    "engine": "configscan_aws",
    "status": "healthy",
    "url": "http://aws-configscan-engine:8000"
  },
  "compliance": {
    "engine": "compliance",
    "status": "healthy"
  }
}
```

#### Database Health
```
GET /api/admin/health/database
```

#### System Health Summary
```
GET /api/admin/health/summary
```

### Audit

#### List Audit Logs
```
GET /api/admin/audit/logs/?admin_user_id=uuid&resource_type=user&date_from=2026-01-01
```

**Query Parameters:**
- `admin_user_id`: Filter by admin user
- `resource_type`: Filter by resource type
- `resource_id`: Filter by resource ID
- `action_type`: Filter by action type
- `date_from`: Start date
- `date_to`: End date

#### Get User Audit Trail
```
GET /api/admin/audit/logs/users/?user_id=uuid
```

#### Get Tenant Audit Trail
```
GET /api/admin/audit/logs/tenants/?tenant_id=uuid
```

#### List Alerts
```
GET /api/admin/audit/alerts/?status=open&severity=high
```

#### Acknowledge Alert
```
POST /api/admin/audit/alerts/{alert_id}/acknowledge
```

#### Resolve Alert
```
POST /api/admin/audit/alerts/{alert_id}/resolve
```

## Error Responses

All errors follow this format:
```json
{
  "error": "Error message",
  "error_code": "ERROR_CODE",
  "details": {}
}
```

Common status codes:
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `500` - Internal Server Error
- `503` - Service Unavailable
