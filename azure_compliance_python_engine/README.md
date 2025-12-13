# Azure Compliance Engine

Multi-subscription, multi-location Azure compliance scanning.

---

## 🚀 Quick Start

### Scan Entire Tenant

```bash
python -m engine.main_scanner --tenant-id YOUR_TENANT_ID
```

### Scan Single Subscription

```bash
python -m engine.main_scanner --subscription YOUR_SUBSCRIPTION_ID
```

### Scan Specific Location

```bash
python -m engine.main_scanner --subscription xxx --location eastus
```

---

## ✨ Features

✅ **Multi-Subscription** - Scan all subscriptions in tenant  
✅ **Multi-Location** - Scan all Azure locations  
✅ **Flexible Granularity** - Tenant → Subscription → Location → Service → Resource  
✅ **Parallel Scanning** - 5-14x speedup  
✅ **Chunked Output** - 100 resources per file, GZIP compressed  
✅ **Resource-Centric** - Inventory + compliance per resource  
✅ **Exception Management** - Skip/exempt checks with expiration  
✅ **Automated Remediation** - Fix failures automatically  

---

## 📋 Prerequisites

- Azure credentials (Service Principal or Managed Identity)
- Read access to subscriptions
- Optional: Tenant-level access for multi-subscription scanning

---

## 🎯 Usage Examples

### All Subscriptions in Tenant
```bash
python -m engine.main_scanner --tenant-id YOUR_TENANT_ID
```

### Specific Subscriptions
```bash
python -m engine.main_scanner \
  --include-subscriptions "sub1-xxx,sub2-yyy,sub3-zzz"
```

### Single Subscription + Location
```bash
python -m engine.main_scanner \
  --subscription xxx-xxx-xxx \
  --location eastus
```

### Single Service
```bash
python -m engine.main_scanner \
  --subscription xxx \
  --location eastus \
  --service storage
```

### Single Resource
```bash
python -m engine.main_scanner \
  --subscription xxx \
  --location eastus \
  --service storage \
  --resource mystorageaccount
```

---

## 🔧 Configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `AZURE_TENANT_ID` | Azure tenant ID | `xxx-xxx-xxx` |
| `AZURE_SUBSCRIPTION_ID` | Default subscription | `yyy-yyy-yyy` |
| `AZURE_CLIENT_ID` | Service principal client ID | `zzz-zzz-zzz` |
| `AZURE_CLIENT_SECRET` | Service principal secret | `secret` |

---

## 📁 Output Structure

```
output/scan_TIMESTAMP/
├── logs/
│   ├── scan.log
│   └── errors.log
├── metadata.json
├── summary.json
└── subscription_xxx/
    └── location/
        └── service/
            ├── index.json
            └── chunk_*.json.gz
```

---

## ⚡ Performance

### Default (Balanced)
```bash
--max-subscription-workers 3 --max-workers 10
```
**Speed:** 🚀 5x faster than sequential

### Aggressive (Fastest)
```bash
--max-subscription-workers 5 --max-workers 15
```
**Speed:** 🚀🚀 14x faster (watch for throttling!)

---

See `SCANNER_QUICK_REFERENCE.md` for more examples.
