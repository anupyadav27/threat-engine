#!/usr/bin/env python3
"""Full compliance flow test including DB + file writes"""

import sys
import os
import json
import uuid
from datetime import datetime

sys.path.insert(0, '/app')
os.chdir('/app')

print("=" * 70)
print("FULL COMPLIANCE FLOW TEST (with DB + File Writes)")
print("=" * 70)

# Load check results
print("\n[1/4] Loading check results...")
from compliance_engine.loader.check_db_loader import CheckDBLoader
with CheckDBLoader() as loader:
    scan_results = loader.load_and_convert(
        scan_id='check_20260201_044813',
        tenant_id='dbeaver-demo',
        csp='aws'
    )
print(f"✅ Loaded {sum(len(r.get('checks', [])) for r in scan_results.get('results', []))} checks")

# Generate compliance report
print("\n[2/4] Generating compliance report...")
from compliance_engine.mapper.rule_mapper import RuleMapper
from compliance_engine.mapper.framework_loader import FrameworkLoader
from compliance_engine.aggregator.result_aggregator import ResultAggregator
from compliance_engine.aggregator.score_calculator import ScoreCalculator
from compliance_engine.reporter.executive_dashboard import ExecutiveDashboard
from compliance_engine.reporter.framework_report import FrameworkReport

rule_mapper = RuleMapper()
rule_mapper.framework_loader = FrameworkLoader()
agg = ResultAggregator(rule_mapper)
sc = ScoreCalculator(agg)
ed = ExecutiveDashboard(agg, sc)
fr = FrameworkReport(agg, sc)

dashboard = ed.generate(scan_results, 'aws', None)
fw_list = [x.get('framework') for x in dashboard.get('frameworks', [])[:2] if isinstance(x, dict) and x.get('framework')]

framework_reports = {}
for fw_name in fw_list:
    framework_reports[fw_name] = fr.generate(scan_results, 'aws', fw_name)

report = {
    "report_id": str(uuid.uuid4()),
    "scan_id": scan_results.get("scan_id"),
    "csp": "aws",
    "tenant_id": "dbeaver-demo",
    "generated_at": datetime.utcnow().isoformat() + "Z",
    "executive_dashboard": dashboard,
    "framework_reports": framework_reports,
}

print(f"✅ Generated report with {len(framework_reports)} frameworks")

# Write to /output
print("\n[3/4] Writing to /output...")
try:
    output_dir = os.getenv("OUTPUT_DIR", "/output")
    compliance_dir = os.path.join(output_dir, "compliance", "dbeaver-demo", scan_results.get("scan_id"))
    os.makedirs(compliance_dir, exist_ok=True)
    
    with open(os.path.join(compliance_dir, "full_report.json"), "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"✅ Wrote files to {compliance_dir}")
    print(f"   Files: {os.listdir(compliance_dir)}")
except Exception as e:
    print(f"❌ File write failed: {e}")

# Write to database
print("\n[4/4] Writing to database...")
try:
    from compliance_engine.storage.compliance_db_writer import save_compliance_report_to_db
    
    # Note: git version might expect different parameters
    saved_id = save_compliance_report_to_db(report)
    print(f"✅ Saved to database: {saved_id}")
    
    # Verify
    import psycopg2
    conn = psycopg2.connect(
        host=os.getenv('COMPLIANCE_DB_HOST'),
        database=os.getenv('COMPLIANCE_DB_NAME'),
        user=os.getenv('COMPLIANCE_DB_USER'),
        password=os.getenv('COMPLIANCE_DB_PASSWORD')
    )
    with conn.cursor() as cur:
        cur.execute('SELECT COUNT(*) FROM report_index')
        count = cur.fetchone()[0]
        print(f"✅ Verified: {count} reports in DB")
    conn.close()
except Exception as e:
    print(f"❌ DB write failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 70)
print("✅ FULL FLOW COMPLETE!")
print("=" * 70)
