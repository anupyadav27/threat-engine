# IBM Cloud Compliance Engine - Quick Start Guide

## 🚀 Quick Setup (3 Steps)

### Step 1: Install Dependencies

```bash
cd /Users/apple/Desktop/threat-engine/ibm_compliance_python_engine
pip install -r requirements.txt
```

### Step 2: Configure Credentials

```bash
export IBM_CLOUD_API_KEY="your-ibm-cloud-api-key"
export IBM_CLOUD_REGION="us-south"  # Optional, defaults to us-south
```

### Step 3: Run Compliance Scan

```bash
python run_engine.py
```

## 📋 What Gets Scanned

By default, **5 services** are enabled:

| Service | Rules | Description |
|---------|-------|-------------|
| **IAM** | 84 | Identity & access management |
| **VPC** | 128 | Virtual private cloud resources |
| **Databases** | 119 | Cloud database instances |
| **Containers** | 97 | Kubernetes clusters |
| **Object Storage** | 28 | Cloud object storage buckets |
| **TOTAL** | **456** | **Total active checks** |

## 📊 Understanding Results

Results are saved in `reporting/reporting_<timestamp>/`:

```
reporting/reporting_20251204T120000Z/
├── index.json                    # Scan summary
├── account_<account_id>/
│   ├── <account>_<region>_vpc_checks.json
│   ├── <account>_global_iam_checks.json
│   └── ...
```

### Sample Result

```json
{
  "check_id": "ibm.iam.user.mfa_required",
  "title": "Enforce Multi-Factor Authentication for IBM Cloud IAM Users",
  "severity": "high",
  "result": "FAIL",
  "resource_id": "user-123",
  "resource_name": "john.doe@example.com",
  "mfa_traits.mfa_enabled": false,
  "timestamp": "2025-12-04T12:00:00Z"
}
```

## ⚙️ Enable More Services

Edit `config/service_list.json`:

```json
{
  "name": "key_protect",
  "enabled": true,        ← Change this
  "scope": "regional",
  "rule_count": 42
}
```

Available services (33 more):
- key_protect (42 rules)
- activity_tracker (22 rules)
- monitoring (36 rules)
- security_advisor (107 rules)
- [See full list in IMPLEMENTATION_COMPLETE.md]

## 🔧 Customization

### Modify Check Logic

Edit service files in `services/{service}/rules/{service}.yaml`:

```yaml
checks:
- check_id: ibm.iam.user.mfa_required
  title: Enforce MFA
  severity: high
  for_each: iam_users
  calls:
  - client: iam_identity
    action: list_users
    params:
      user_id: '{{ user_id }}'
    fields:
    - path: mfa_traits.mfa_enabled  # ← Customize this
      operator: equals                # ← or this
      expected: true                  # ← or this
```

### Supported Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `exists` | Value is present | `encryption_key exists` |
| `equals` | Exact match | `public_access equals false` |
| `contains` | Contains value | `actions not_contains *` |
| `greater_than` | Numeric comparison | `min_length > 14` |
| `age_days` | Resource age | `last_rotation age_days 90` |
| `not_expired` | Date check | `expiration not_expired` |

## 🎯 Common Use Cases

### 1. Scan Specific Service Only

Edit `config/service_list.json` - set `enabled: false` for all except target service.

### 2. Generate New Service Files

```bash
python3 generate_service_files_enhanced.py
```

This regenerates all 38 service files from `rule_ids_GPT4_ENHANCED.yaml`.

### 3. Add Custom Rules

1. Add rule to `rule_ids_GPT4_ENHANCED.yaml`
2. Run generator: `python3 generate_service_files_enhanced.py`
3. Customize generated check logic if needed

## 📈 Performance Tuning

### Adjust Worker Threads

```bash
export COMPLIANCE_ENGINE_MAX_WORKERS=8  # Default: 4
python run_engine.py
```

### Adjust Log Level

```bash
export LOG_LEVEL=DEBUG  # Options: DEBUG, INFO, WARNING, ERROR
python run_engine.py
```

## 🛠️ Troubleshooting

### Authentication Fails

```
❌ IBM Cloud authentication failed
```

**Solutions:**
1. Verify API key: `echo $IBM_CLOUD_API_KEY`
2. Check key permissions in IBM Cloud Console
3. Ensure key is not expired
4. Try different region: `export IBM_CLOUD_REGION=eu-gb`

### No Resources Found

```
⚠️  Found 0 resources
```

**Solutions:**
1. Verify resources exist in IBM Cloud Console
2. Check API key has read permissions
3. Verify correct region is set
4. Review service scope in `service_list.json`

### Module Import Errors

```
ModuleNotFoundError: No module named 'ibm_cloud_sdk_core'
```

**Solution:**
```bash
pip install -r requirements.txt --upgrade
```

## 📚 Documentation

- **Full Implementation Details:** `IMPLEMENTATION_COMPLETE.md`
- **Architecture:** `README.md`
- **SDK Mappings:** `generate_service_files_enhanced.py`

## 🔐 Security Best Practices

1. **Never commit API keys** to version control
2. **Use environment variables** for credentials
3. **Rotate API keys regularly** (90 days recommended)
4. **Limit API key scope** to read-only for scanning
5. **Store results securely** - they may contain sensitive info

## 📞 Support

For issues or questions:
1. Check logs in `logs/compliance_local.log`
2. Review `IMPLEMENTATION_COMPLETE.md`
3. Examine service YAML files for check logic
4. Verify IBM Cloud SDK documentation

---

**Happy Scanning! 🎉**





