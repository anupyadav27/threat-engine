# Logging Admin Guide for Operations Team

## Overview

This guide helps operations teams configure, monitor, and troubleshoot logging in the CSPM platform.

## Configuration

### Environment Variables

#### Basic Configuration

```bash
# Log format: 'json' (for aggregation) or 'human' (for console)
LOG_FORMAT=json

# Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL=INFO

# Optional: Log file path
LOG_FILE=/var/log/cspm/engine.log
```

#### Log Rotation

```bash
# Maximum file size before rotation (bytes)
LOG_MAX_BYTES=104857600  # 100MB

# Number of backup files to keep
LOG_BACKUP_COUNT=10

# Time-based rotation (optional): 'midnight', 'H' (hourly), 'D' (daily)
LOG_ROTATION_WHEN=midnight
```

#### CloudWatch Logs

```bash
# CloudWatch log group name
CLOUDWATCH_LOG_GROUP=/cspm/engines

# Optional: Log stream name (defaults to engine name)
CLOUDWATCH_LOG_STREAM=my-engine
```

#### ELK Stack

```bash
# Logstash endpoint
ELK_ENDPOINT=tcp://logstash:5000
```

#### DataDog

```bash
# DataDog API key
DATADOG_API_KEY=your-api-key
```

## Log Structure

### JSON Format (Production)

```json
{
  "timestamp": "2026-01-23T16:19:55.824698Z",
  "level": "INFO",
  "logger": "onboarding.api.onboarding",
  "message": "Scan started",
  "tenant_id": "tenant-456",
  "scan_run_id": "execution-123",
  "account_id": "account-789",
  "engine_name": "onboarding",
  "module": "onboarding",
  "function": "create_scan",
  "line": 150,
  "request_id": "req-abc123",
  "correlation_id": "corr-xyz789"
}
```

### Audit Logs

```json
{
  "timestamp": "2026-01-23T16:19:55.824698Z",
  "level": "INFO",
  "event_type": "audit",
  "action": "account_created",
  "resource": "account:account-789",
  "user_id": "user-123",
  "tenant_id": "tenant-456",
  "result": "success",
  "details": {
    "account_name": "Production Account",
    "provider_type": "aws"
  }
}
```

### Security Event Logs

```json
{
  "timestamp": "2026-01-23T16:19:55.824698Z",
  "level": "ERROR",
  "event_type": "security",
  "security_event_type": "auth_failure",
  "severity": "medium",
  "description": "Authentication failed for /api/v1/scan",
  "user_id": "user-123",
  "tenant_id": "tenant-456",
  "ip_address": "192.168.1.100",
  "correlation_id": "corr-xyz789"
}
```

### Transaction Logs

```json
{
  "timestamp": "2026-01-23T16:19:55.824698Z",
  "level": "INFO",
  "event_type": "transaction",
  "operation": "create_tenant",
  "table_name": "tenants",
  "operation_type": "create",
  "record_id": "tenant-456",
  "user_id": "user-123",
  "tenant_id": "tenant-456",
  "correlation_id": "corr-xyz789",
  "details": {
    "tenant_name": "Acme Corp",
    "plan": "enterprise"
  }
}
```

### Business Event Logs

```json
{
  "timestamp": "2026-01-23T16:19:55.824698Z",
  "level": "INFO",
  "event_type": "business_event",
  "business_event_type": "scan_completed",
  "event_name": "AWS ConfigScan Completed",
  "status": "completed",
  "tenant_id": "tenant-456",
  "account_id": "account-789",
  "scan_run_id": "scan-123",
  "correlation_id": "corr-xyz789",
  "metrics": {
    "resources_scanned": 1000,
    "findings_found": 25,
    "duration_seconds": 120
  }
}
```

### Data Access Logs

```json
{
  "timestamp": "2026-01-23T16:19:55.824698Z",
  "level": "INFO",
  "event_type": "data_access",
  "resource_type": "report",
  "resource_id": "report-123",
  "action": "read",
  "success": true,
  "user_id": "user-123",
  "tenant_id": "tenant-456",
  "ip_address": "192.168.1.100",
  "correlation_id": "corr-xyz789",
  "details": {
    "report_type": "compliance",
    "framework": "SOC2"
  }
}
```

### Activity Logs

```json
{
  "timestamp": "2026-01-23T16:19:55.824698Z",
  "level": "INFO",
  "event_type": "activity",
  "activity_type": "page_view",
  "activity_name": "Dashboard Viewed",
  "user_id": "user-123",
  "tenant_id": "tenant-456",
  "ip_address": "192.168.1.100",
  "session_id": "session-abc123",
  "correlation_id": "corr-xyz789",
  "details": {
    "page": "/dashboard",
    "duration_seconds": 45
  }
}
```

### Compliance Event Logs

```json
{
  "timestamp": "2026-01-23T16:19:55.824698Z",
  "level": "INFO",
  "event_type": "compliance",
  "compliance_framework": "SOC2",
  "requirement_id": "CC6.1",
  "compliance_event_type": "control_passed",
  "description": "Access control mechanism verified",
  "severity": "info",
  "tenant_id": "tenant-456",
  "account_id": "account-789",
  "scan_run_id": "scan-123",
  "correlation_id": "corr-xyz789",
  "details": {
    "evidence": "access_logs_verified",
    "timestamp": "2026-01-23T10:00:00Z"
  }
}
```

## Log Aggregation

### CloudWatch Logs

1. **Set up log group**:
   ```bash
   aws logs create-log-group --log-group-name /cspm/engines
   ```

2. **Configure retention**:
   ```bash
   aws logs put-retention-policy \
     --log-group-name /cspm/engines \
     --retention-in-days 30
   ```

3. **Query logs**:
   ```bash
   aws logs filter-log-events \
     --log-group-name /cspm/engines \
     --filter-pattern "tenant_id tenant-456"
   ```

### ELK Stack

1. **Configure Logstash** to receive logs
2. **Index logs** in Elasticsearch by tenant_id, scan_run_id
3. **Create dashboards** in Kibana

### DataDog

1. **Configure API key** in environment
2. **Tags** are automatically added (engine, tenant, scan)
3. **Query logs** in DataDog UI

## Monitoring

### Key Metrics to Monitor

1. **Error Rate**: Count of ERROR/CRITICAL logs per tenant
2. **Performance**: Duration metrics from log_duration()
3. **Security Events**: Count of security_event_log() entries
4. **Audit Trail**: All audit_log() entries for compliance
5. **Transactions**: Critical database operations via transaction_log()
6. **Business Events**: Business milestones via business_event_log()
7. **Data Access**: Data access patterns via data_access_log()
8. **User Activity**: User behavior via activity_log()
9. **Compliance Events**: Compliance requirements via compliance_event_log()

### Log Queries

#### Find all errors for a tenant

```bash
# CloudWatch
aws logs filter-log-events \
  --log-group-name /cspm/engines \
  --filter-pattern "{ $.level = ERROR && $.tenant_id = tenant-456 }"

# ELK (Kibana)
level:ERROR AND tenant_id:tenant-456
```

#### Find all logs for a scan

```bash
# CloudWatch
aws logs filter-log-events \
  --log-group-name /cspm/engines \
  --filter-pattern "scan_run_id scan-123"

# ELK
scan_run_id:scan-123
```

#### Find security events

```bash
# CloudWatch
aws logs filter-log-events \
  --log-group-name /cspm/engines \
  --filter-pattern "{ $.event_type = security }"

# ELK
event_type:security
```

#### Find audit logs

```bash
# CloudWatch
aws logs filter-log-events \
  --log-group-name /cspm/engines \
  --filter-pattern "{ $.event_type = audit }"

# ELK
event_type:audit
```

#### Find transaction logs

```bash
# CloudWatch
aws logs filter-log-events \
  --log-group-name /cspm/engines \
  --filter-pattern "{ $.event_type = transaction }"

# ELK
event_type:transaction
```

#### Find business events

```bash
# CloudWatch
aws logs filter-log-events \
  --log-group-name /cspm/engines \
  --filter-pattern "{ $.event_type = business_event }"

# ELK
event_type:business_event
```

#### Find data access logs

```bash
# CloudWatch
aws logs filter-log-events \
  --log-group-name /cspm/engines \
  --filter-pattern "{ $.event_type = data_access }"

# ELK
event_type:data_access AND action:read
```

#### Find compliance events

```bash
# CloudWatch
aws logs filter-log-events \
  --log-group-name /cspm/engines \
  --filter-pattern "{ $.event_type = compliance && $.compliance_framework = SOC2 }"

# ELK
event_type:compliance AND compliance_framework:SOC2
```

## Troubleshooting

### Logs Not Appearing

1. **Check log level**: Ensure LOG_LEVEL is set correctly
2. **Check file permissions**: Ensure log directory is writable
3. **Check disk space**: Ensure sufficient disk space
4. **Check aggregation**: Verify CloudWatch/ELK connectivity

### Performance Issues

1. **Reduce log level**: Use INFO instead of DEBUG in production
2. **Enable log rotation**: Set LOG_MAX_BYTES and LOG_BACKUP_COUNT
3. **Filter logs**: Use appropriate log levels to reduce volume

### Missing Context

1. **Ensure LogContext**: All operations should use LogContext
2. **Check middleware**: Ensure RequestLoggingMiddleware is added
3. **Verify propagation**: Check that context variables are set

## Log Retention

### File-Based Logs

- **Size-based rotation**: Logs rotate when LOG_MAX_BYTES is reached
- **Time-based rotation**: Logs rotate daily/weekly if LOG_ROTATION_WHEN is set
- **Backup count**: Keep LOG_BACKUP_COUNT old log files
- **Manual cleanup**: Old logs can be archived to S3

### CloudWatch Logs

- **Retention policy**: Set via AWS Console or CLI
- **Default**: Logs retained indefinitely
- **Recommended**: 30-90 days for production

### ELK Stack

- **Index lifecycle**: Configure via Index Lifecycle Management (ILM)
- **Recommended**: 30 days hot, 90 days warm, archive older

## Security Considerations

1. **Sensitive Data**: Never log passwords, tokens, or secrets
2. **PII**: Be careful with user data in logs
3. **Access Control**: Restrict log access to authorized personnel
4. **Encryption**: Encrypt logs at rest and in transit
5. **Audit Logs**: Store audit logs separately with stricter access

## Health Checks

All engines log health check requests:

```json
{
  "timestamp": "2026-01-23T16:19:55.824698Z",
  "level": "INFO",
  "message": "Health check",
  "extra_fields": {
    "status": "healthy",
    "duration_ms": 2.5
  }
}
```

Monitor health check duration for performance issues.

## Alerting

### Error Rate Alerts

Alert when error rate exceeds threshold:
- **Threshold**: > 5% of requests result in errors
- **Window**: 5-minute rolling window

### Security Event Alerts

Alert on security events:
- **Critical**: Immediate alert
- **High**: Alert within 1 minute
- **Medium**: Alert within 5 minutes

### Performance Alerts

Alert on slow operations:
- **Threshold**: Operations taking > 10 seconds
- **Monitor**: log_duration() entries

## Best Practices

1. **Use JSON format** in production for aggregation
2. **Set appropriate log levels** (INFO for production)
3. **Enable log rotation** to prevent disk space issues
4. **Monitor log volume** to detect issues early
5. **Set up alerts** for errors and security events
6. **Regular review** of audit logs for compliance
7. **Archive old logs** to long-term storage
8. **Test log aggregation** regularly
