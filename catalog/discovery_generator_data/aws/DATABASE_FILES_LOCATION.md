# Final JSON Database Files Location

## 📁 File Structure

### 1. Main Consolidated File (All Services)
**Location:** `pythonsdk-database/aws/boto3_dependencies_with_python_names_fully_enriched.json`

- **Size:** 35 MB
- **Contains:** All 411 AWS services in a single file
- **Format:** 
  ```json
  {
    "service1": { ... },
    "service2": { ... },
    ...
  }
  ```
- **Last Updated:** December 15, 2024 (with enum enrichment)

### 2. Per-Service Files (Individual Services)
**Location:** `pythonsdk-database/aws/<service_name>/boto3_dependencies_with_python_names_fully_enriched.json`

- **Total Files:** 411 per-service files
- **Structure:** One file per service folder
- **Example Locations:**
  - `pythonsdk-database/aws/acm/boto3_dependencies_with_python_names_fully_enriched.json`
  - `pythonsdk-database/aws/s3/boto3_dependencies_with_python_names_fully_enriched.json`
  - `pythonsdk-database/aws/iam/boto3_dependencies_with_python_names_fully_enriched.json`
  - `pythonsdk-database/aws/ec2/boto3_dependencies_with_python_names_fully_enriched.json`

## 📊 File Contents

Each enriched file contains:
- **Operations:** All boto3 operations for the service
- **Parameters:** Required and optional parameters
- **Output Fields:** All output fields with types and descriptions
- **Item Fields:** Fields within list/collection items
- **Enum Values:** `possible_values` array for enum fields (11,199 total across all services)
- **Compliance Categories:** Security, identity, general classifications
- **Operators:** Suggested operators for each field

## 🔍 Quick Access Examples

### Access Main File
```bash
# View main consolidated file
cat pythonsdk-database/aws/boto3_dependencies_with_python_names_fully_enriched.json

# Check file size
ls -lh pythonsdk-database/aws/boto3_dependencies_with_python_names_fully_enriched.json
```

### Access Per-Service File
```bash
# View ACM service file
cat pythonsdk-database/aws/acm/boto3_dependencies_with_python_names_fully_enriched.json

# View S3 service file
cat pythonsdk-database/aws/s3/boto3_dependencies_with_python_names_fully_enriched.json
```

### Find All Service Files
```bash
# List all per-service enriched files
find pythonsdk-database/aws -name "boto3_dependencies_with_python_names_fully_enriched.json" -type f

# Count total files
find pythonsdk-database/aws -name "boto3_dependencies_with_python_names_fully_enriched.json" -type f | wc -l
```

## 📈 Statistics

- **Total Services:** 411
- **Total Enum Fields:** 11,199
- **Average Enums per Service:** 31.1
- **Enrichment Quality:** 98.9% accuracy
- **Last Enrichment:** December 15, 2024

## 🎯 Usage in Code

### Python Example
```python
import json
from pathlib import Path

# Load main consolidated file
with open('pythonsdk-database/aws/boto3_dependencies_with_python_names_fully_enriched.json') as f:
    all_services = json.load(f)

# Access specific service
acm_data = all_services['acm']

# Load per-service file
acm_file = Path('pythonsdk-database/aws/acm/boto3_dependencies_with_python_names_fully_enriched.json')
with open(acm_file) as f:
    acm_data = json.load(f)
```

## 📝 Related Files

In the same directory, you may also find:
- `operation_registry.json` - Operation registry per service
- `adjacency.json` - Dependency adjacency graph
- `direct_vars.json` - Direct variables (read-only)
- `manual_review.json` - Manual review items
- `validation_report.json` - Validation results

## ✅ Verification

To verify files are up-to-date:
```bash
# Check enrichment status
python tools/check_enrichment_status.py

# Quality check
python tools/quality_check_enrichment.py
```

