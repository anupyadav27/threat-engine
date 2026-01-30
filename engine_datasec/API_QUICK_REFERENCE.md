# Data Security Engine - API Quick Reference

## 🚀 Start API Server

\`\`\`bash
cd /Users/apple/Desktop/threat-engine/data-security-engine
python3 -m uvicorn data_security_engine.api_server:app --reload --host 0.0.0.0 --port 8000
\`\`\`

**Swagger UI**: http://localhost:8000/docs

---

## 📋 All 17 Endpoints

| # | Method | Endpoint | Purpose |
|---|--------|----------|---------|
| 1 | GET | `/` | Root |
| 2 | GET | `/health` | Health check |
| 3 | POST | `/api/v1/data-security/scan` | Generate report |
| 4 | GET | `/api/v1/data-security/catalog` | Data catalog |
| 5 | GET | `/api/v1/data-security/findings` | All findings |
| 6 | GET | `/api/v1/data-security/governance/{resource_id}` | Governance for resource |
| 7 | GET | `/api/v1/data-security/protection/{resource_id}` | Protection for resource |
| 8 | GET | `/api/v1/data-security/classification` | Classification results |
| 9 | GET | `/api/v1/data-security/lineage` | Data lineage |
| 10 | GET | `/api/v1/data-security/residency` | Residency compliance |
| 11 | GET | `/api/v1/data-security/activity` | Activity monitoring |
| 12 | GET | `/api/v1/data-security/compliance` | Compliance status |
| 13 | GET | `/api/v1/data-security/accounts/{account_id}` | Account overview |
| 14 | GET | `/api/v1/data-security/services/{service}` | Service overview |
| 15 | GET | `/api/v1/data-security/modules` | List modules |
| 16 | GET | `/api/v1/data-security/modules/{module}/rules` | Rules by module |
| 17 | GET | `/api/v1/data-security/rules/{rule_id}` | Rule details |

---

## 🎯 Common API Calls

\`\`\`bash
# Executive Dashboard
curl "http://localhost:8000/api/v1/data-security/findings?csp=aws&scan_id=latest"
curl "http://localhost:8000/api/v1/data-security/catalog?csp=aws&scan_id=latest"

# Resource Detail
curl "http://localhost:8000/api/v1/data-security/findings?csp=aws&scan_id=latest&resource_id=arn:aws:dynamodb:ap-south-1:155052200811:table/threat-engine-accounts"
curl "http://localhost:8000/api/v1/data-security/classification?csp=aws&scan_id=latest&resource_id=arn:aws:dynamodb:ap-south-1:155052200811:table/threat-engine-accounts"

# Module Dashboards
curl "http://localhost:8000/api/v1/data-security/findings?csp=aws&scan_id=latest&module=data_protection_encryption&status=FAIL"
curl "http://localhost:8000/api/v1/data-security/compliance?csp=aws&scan_id=latest&framework=gdpr"

# Account/Service Views
curl "http://localhost:8000/api/v1/data-security/accounts/155052200811?csp=aws&scan_id=latest"
curl "http://localhost:8000/api/v1/data-security/services/rds?csp=aws&scan_id=latest"
\`\`\`

---

## 📊 Output Files (Alternative to API)

\`\`\`bash
# Latest scan output
ls /Users/apple/Desktop/threat-engine/engines-output/data-security-engine/output/

# Example: Account 155052200811, Region ap-south-1
cd /Users/apple/Desktop/threat-engine/engines-output/data-security-engine/output/20260118_151257/155052200811/aws/ap-south-1/

# Read discovery catalog
cat discovery/data_catalog.ndjson

# Read governance findings
cat governance/access_analysis.ndjson

# Read encryption findings
cat protection/encryption_status.ndjson

# Read summary
cat summary.json
\`\`\`
