#!/usr/bin/env python3
"""
Test compliance engine flow directly in the pod.
Run this inside the compliance-engine pod to identify where it hangs.
"""

import sys
import os

sys.path.insert(0, '/app')
os.chdir('/app')

print("=" * 60)
print("COMPLIANCE ENGINE TEST")
print("=" * 60)

# Step 1: Check DB connections
print("\n[1/6] Testing CHECK DB connection...")
try:
    import psycopg2
    conn = psycopg2.connect(
        host=os.getenv('CHECK_DB_HOST'),
        port=int(os.getenv('CHECK_DB_PORT', '5432')),
        database=os.getenv('CHECK_DB_NAME'),
        user=os.getenv('CHECK_DB_USER'),
        password=os.getenv('CHECK_DB_PASSWORD')
    )
    with conn.cursor() as cur:
        cur.execute('SELECT COUNT(*) FROM check_results WHERE scan_id = %s', ('check_20260201_044813',))
        count = cur.fetchone()[0]
        print(f"✅ CHECK DB: {count} check_results for scan")
    conn.close()
except Exception as e:
    print(f"❌ CHECK DB failed: {e}")
    sys.exit(1)

print("\n[2/6] Testing COMPLIANCE DB connection...")
try:
    conn = psycopg2.connect(
        host=os.getenv('COMPLIANCE_DB_HOST'),
        database=os.getenv('COMPLIANCE_DB_NAME'),
        user=os.getenv('COMPLIANCE_DB_USER'),
        password=os.getenv('COMPLIANCE_DB_PASSWORD')
    )
    with conn.cursor() as cur:
        cur.execute('SELECT COUNT(*) FROM compliance_control_mappings')
        count = cur.fetchone()[0]
        print(f"✅ COMPLIANCE DB: {count} compliance_control_mappings")
        
        cur.execute('SELECT COUNT(*) FROM report_index')
        report_count = cur.fetchone()[0]
        print(f"✅ COMPLIANCE DB: {report_count} existing reports")
    conn.close()
except Exception as e:
    print(f"❌ COMPLIANCE DB failed: {e}")
    sys.exit(1)

print("\n[3/6] Loading check results from DB...")
try:
    from compliance_engine.loader.check_db_loader import CheckDBLoader
    
    with CheckDBLoader() as loader:
        scan_results = loader.load_and_convert(
            scan_id='check_20260201_044813',
            tenant_id='dbeaver-demo',
            csp='aws'
        )
    
    num_results = len(scan_results.get('results', []))
    total_checks = sum(len(r.get('checks', [])) for r in scan_results.get('results', []))
    print(f"✅ Loaded {num_results} result groups with {total_checks} total checks")
except Exception as e:
    print(f"❌ Load failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n[4/6] Initializing compliance components...")
try:
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
    
    print("✅ All components initialized")
except Exception as e:
    print(f"❌ Component init failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n[5/6] Generating compliance dashboard...")
try:
    dashboard = ed.generate(scan_results, 'aws', None)
    frameworks = dashboard.get('frameworks', [])
    print(f"✅ Dashboard generated with {len(frameworks)} frameworks")
    
    for fw in frameworks[:3]:
        if isinstance(fw, dict):
            print(f"   - {fw.get('framework')}: {fw.get('compliance_score')}% ({fw.get('status')})")
except Exception as e:
    print(f"❌ Dashboard generation failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n[6/6] Generating framework reports...")
try:
    framework_reports = {}
    fw_list = [x.get('framework') for x in dashboard.get('frameworks', []) if isinstance(x, dict) and x.get('framework')]
    
    for fw_name in fw_list[:2]:  # Test first 2
        print(f"   Generating {fw_name}...")
        fw_report = fr.generate(scan_results, 'aws', fw_name)
        framework_reports[fw_name] = fw_report
        print(f"   ✅ {fw_name}: {len(fw_report.get('controls', []))} controls")
    
    print(f"✅ Generated {len(framework_reports)} framework reports")
except Exception as e:
    print(f"❌ Framework report generation failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 60)
print("✅ ALL TESTS PASSED - Engine core logic works!")
print("=" * 60)
print(f"\nReady to write {len(framework_reports)} reports to DB and /output")
