# Compliance Engine Architecture

## System Design

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│         CSP Compliance Engines (Existing)                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │   AWS    │  │  Azure   │  │   GCP    │  │  Others  │  │
│  │  Engine  │  │  Engine  │  │  Engine  │  │  Engine  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       │             │              │              │         │
│       └─────────────┴──────────────┴──────────────┘         │
│                    │                                         │
│                    ▼                                         │
│         ┌──────────────────────────┐                        │
│         │  Unified Scan Results    │                        │
│         │  (JSON/NDJSON format)    │                        │
│         └────────────┬─────────────┘                        │
└──────────────────────┼─────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│         Compliance Engine Generator                         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  1. Compliance Mapper                                │  │
│  │     - Loads compliance framework mappings            │  │
│  │     - Maps rule_id → compliance controls              │  │
│  │     - Supports multi-framework mapping                │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  2. Result Aggregator                                 │  │
│  │     - Groups by framework/control                     │  │
│  │     - Calculates compliance scores                    │  │
│  │     - Tracks trends over time                         │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  3. Report Generator                                  │  │
│  │     - Executive dashboard                             │  │
│  │     - Framework compliance reports                    │  │
│  │     - Resource-level drill-down                       │  │
│  │     - Remediation roadmap                             │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  4. Data Exporter                                     │  │
│  │     - JSON API responses                              │  │
│  │     - PDF reports (audit-ready)                      │  │
│  │     - CSV exports                                     │  │
│  │     - Database tables (PostgreSQL/DynamoDB)          │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                       │
                       ▼
         ┌──────────────────────────┐
         │  Compliance Reports       │
         │  - Framework scores       │
         │  - Control status         │
         │  - Evidence/audit trail   │
         └──────────────────────────┘
```

## Component Details

### 1. Compliance Mapper (`mapper/`)

**Purpose**: Map security check `rule_id` to compliance framework controls.

**Components**:
- `framework_loader.py`: Load framework definitions from CSV/YAML
- `rule_mapper.py`: Map rule_id → framework controls

**Input**:
- Framework mapping files (`data/frameworks/*.csv`)
- Rule-to-framework mappings (`data/mappings/*.yaml`)

**Output**:
- Mapping dictionary: `{rule_id: [framework_controls]}`

**Example**:
```python
{
  "aws.accessanalyzer.resource.access_analyzer_enabled": [
    {
      "framework": "CIS AWS Foundations Benchmark",
      "version": "2.0",
      "control_id": "2.1.1",
      "control_title": "Ensure IAM Access Analyzer is enabled"
    },
    {
      "framework": "ISO 27001:2022",
      "control_id": "A.8.3.0085"
    }
  ]
}
```

### 2. Result Aggregator (`aggregator/`)

**Purpose**: Group scan results by framework/control and calculate compliance scores.

**Components**:
- `result_aggregator.py`: Group results by framework/control
- `score_calculator.py`: Calculate compliance percentages

**Input**:
- Scan results (JSON from CSP engines)
- Compliance mappings (from Mapper)

**Output**:
- Aggregated compliance data:
  - Per-control status (PASS/FAIL/NOT_APPLICABLE)
  - Per-framework score (0-100%)
  - Per-category score
  - Overall posture score

**Scoring Logic**:
```
Compliance Score = (Controls Passed / Total Applicable Controls) × 100
```

### 3. Report Generator (`reporter/`)

**Purpose**: Generate different types of compliance reports.

**Components**:
- `executive_dashboard.py`: High-level summary
- `framework_report.py`: Framework-specific detailed reports
- `resource_drilldown.py`: Resource-level compliance
- `remediation_roadmap.py`: Prioritized fix list

**Report Types**:

1. **Executive Dashboard**
   - Overall compliance score
   - Framework status summary
   - Top 5 critical findings
   - Trend visualization

2. **Framework Report**
   - Control-by-control status
   - Evidence per control
   - Audit trail
   - Remediation steps

3. **Resource Drill-down**
   - Per-resource compliance status
   - Failed checks per resource
   - Resource risk score

4. **Remediation Roadmap**
   - Prioritized list of fixes
   - Grouped by service/team
   - Estimated effort
   - Automated vs manual

### 4. Data Exporter (`exporter/`)

**Purpose**: Export compliance reports in various formats.

**Components**:
- `json_exporter.py`: JSON API responses
- `pdf_exporter.py`: PDF reports (using reportlab/weasyprint)
- `csv_exporter.py`: CSV exports for spreadsheet analysis
- `db_exporter.py`: Database integration (PostgreSQL/DynamoDB)

**Export Formats**:
- **JSON**: For API/UI consumption
- **PDF**: Audit-ready reports (executive + detailed)
- **CSV**: Spreadsheet analysis
- **Database**: Historical storage and querying

### 5. Storage (`storage/`)

**Purpose**: Track compliance trends over time.

**Components**:
- `trend_tracker.py`: Store and retrieve historical compliance scores

**Data Stored**:
- Compliance scores per framework (timestamped)
- Control status changes
- Improvement/degradation metrics

**Use Cases**:
- Trend visualization (30/90/365 days)
- Compliance improvement tracking
- Audit history

## Data Flow

### 1. Scan Results Input
```
CSP Engine → Scan Results (JSON/NDJSON)
  ↓
Compliance Engine API receives scan_id
  ↓
Load scan results from S3/storage
```

### 2. Compliance Mapping
```
Scan Results → Extract rule_ids
  ↓
Compliance Mapper → Load framework mappings
  ↓
Map rule_id → framework controls
```

### 3. Aggregation
```
Mapped Results → Group by framework/control
  ↓
Calculate compliance scores
  ↓
Generate aggregated compliance data
```

### 4. Report Generation
```
Aggregated Data → Report Generator
  ↓
Generate reports (executive, framework, resource)
  ↓
Store reports (in-memory cache or database)
```

### 5. Export
```
Generated Reports → Exporter
  ↓
Export to JSON/PDF/CSV/DB
  ↓
Return to API client
```

## Database Schema (Optional)

If using database for historical tracking:

```sql
-- Compliance Framework Mappings
CREATE TABLE compliance_framework_mappings (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(255) NOT NULL,
    csp VARCHAR(50) NOT NULL,
    framework VARCHAR(100) NOT NULL,
    framework_version VARCHAR(50),
    control_id VARCHAR(100) NOT NULL,
    control_title TEXT,
    control_category VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Compliance Scan Results
CREATE TABLE compliance_scan_results (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL,
    csp VARCHAR(50) NOT NULL,
    account_id VARCHAR(100),
    framework VARCHAR(100) NOT NULL,
    control_id VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL,  -- PASS, FAIL, NOT_APPLICABLE
    rule_id VARCHAR(255),
    resource_arn TEXT,
    severity VARCHAR(20),
    scanned_at TIMESTAMP NOT NULL,
    evidence JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Compliance Scores (Aggregated)
CREATE TABLE compliance_scores (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL,
    csp VARCHAR(50) NOT NULL,
    account_id VARCHAR(100),
    framework VARCHAR(100) NOT NULL,
    overall_score DECIMAL(5,2),
    controls_total INTEGER,
    controls_passed INTEGER,
    controls_failed INTEGER,
    scanned_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Compliance Trends
CREATE TABLE compliance_trends (
    id SERIAL PRIMARY KEY,
    csp VARCHAR(50) NOT NULL,
    account_id VARCHAR(100),
    framework VARCHAR(100) NOT NULL,
    score DECIMAL(5,2),
    scanned_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
```

## API Design

### RESTful Endpoints

```
POST   /api/v1/compliance/generate
GET    /api/v1/compliance/report/{report_id}
GET    /api/v1/compliance/framework/{framework}/status
GET    /api/v1/compliance/trends
GET    /api/v1/compliance/report/{report_id}/export
DELETE /api/v1/compliance/report/{report_id}
```

### Request/Response Examples

**Generate Compliance Report**:
```json
POST /api/v1/compliance/generate
{
  "scan_id": "9c5ebb5b-5e68-4b9f-9851-6c5697f1d1f0",
  "csp": "aws",
  "frameworks": ["CIS", "ISO27001"]  // Optional: filter
}

Response:
{
  "report_id": "uuid",
  "status": "completed",
  "compliance_report": {...}
}
```

**Get Compliance Report**:
```json
GET /api/v1/compliance/report/{report_id}

Response:
{
  "report_id": "uuid",
  "scan_id": "uuid",
  "csp": "aws",
  "generated_at": "2026-01-13T07:30:00Z",
  "compliance_report": {...}
}
```

## Integration Points

### With CSP Engines
- **Input**: Scan results JSON/NDJSON from CSP engines
- **Location**: S3 bucket (`s3://cspm-lgtech/{csp}-compliance-engine/output/`)
- **Format**: Unified JSON structure (see README.md)

### With Onboarding API
- **Trigger**: After scan completion, onboarding API can trigger compliance report generation
- **Storage**: Compliance reports stored in S3 or database

### With UI/Frontend
- **API**: RESTful JSON API for dashboard consumption
- **Real-time**: WebSocket support for live updates (future)

## Performance Considerations

- **Caching**: Cache framework mappings in memory
- **Async Processing**: Large reports generated asynchronously
- **Streaming**: For large scan results, use streaming JSON parser
- **Database Indexing**: Index on scan_id, framework, control_id for fast queries

## Security

- **Authentication**: API key or OAuth2
- **Authorization**: Role-based access control
- **Data Privacy**: Mask sensitive data in reports
- **Audit Logging**: Log all compliance report access

## Scalability

- **Horizontal Scaling**: Stateless API, can scale horizontally
- **Database Sharding**: Shard by CSP or account_id if needed
- **Caching Layer**: Redis for frequently accessed reports
- **Message Queue**: Use SQS/RabbitMQ for async report generation

