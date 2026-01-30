# GCP Compliance Engine

Multi-project, multi-region GCP compliance scanning.

---

## 🚀 Quick Start

### Scan All Projects

```bash
python -m engine.main_scanner
```

### Scan Single Project

```bash
python -m engine.main_scanner --project YOUR_PROJECT_ID
```

### Scan Specific Region

```bash
python -m engine.main_scanner --project xxx --region us-central1
```

---

## ✨ Features

✅ **Multi-Project** - Scan all projects in organization  
✅ **Multi-Region** - Scan all GCP regions  
✅ **Flexible Granularity** - Org → Project → Region → Service → Resource  
✅ **Parallel Scanning** - 5-14x speedup  
✅ **Chunked Output** - 100 resources per file, GZIP compressed  
✅ **Resource-Centric** - Inventory + compliance per resource  
✅ **Exception Management** - Skip/exempt checks  
✅ **Automated Remediation** - Fix failures  

---

## 🎯 Usage Examples

```bash
# All projects
python -m engine.main_scanner

# Specific projects
python -m engine.main_scanner --include-projects "proj1,proj2"

# Single project + region
python -m engine.main_scanner --project my-project --region us-central1

# Single service
python -m engine.main_scanner --project my-project --service compute

# Single resource
python -m engine.main_scanner --project my-project --service compute --resource instance-1
```

---

See AWS README.md for detailed documentation (same structure).
