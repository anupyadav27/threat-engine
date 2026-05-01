-- Database: threat_engine_onboarding
-- All queries use scan_run_id (renamed from orchestration_id, 2026-03-21)
-- scan_orchestration has NO per-engine scan ID columns — those were dropped

-- Full pipeline status for a scan
SELECT scan_run_id, provider, tenant_id, account_id,
       overall_status, engines_requested, engines_completed,
       credential_type, credential_ref,
       started_at, completed_at,
       completed_at - started_at AS duration
FROM scan_orchestration
WHERE scan_run_id = $1;

-- Latest scans for a tenant (most recent first)
SELECT scan_run_id, provider, account_id, overall_status, started_at, completed_at
FROM scan_orchestration
WHERE tenant_id = $1
ORDER BY started_at DESC LIMIT 10;

-- Running scans (flag if stuck > 2 hours)
SELECT scan_run_id, tenant_id, provider, overall_status, started_at, engines_completed
FROM scan_orchestration
WHERE overall_status = 'running'
AND started_at < NOW() - INTERVAL '2 hours'
ORDER BY started_at;

-- Scans completed in the last 24 hours
SELECT scan_run_id, provider, overall_status, started_at,
       completed_at - started_at AS duration
FROM scan_orchestration
WHERE started_at > NOW() - INTERVAL '24 hours'
ORDER BY started_at DESC;

-- Which engines are still pending for a scan
SELECT scan_run_id,
       engines_requested,
       engines_completed,
       (SELECT jsonb_agg(e)
        FROM jsonb_array_elements_text(engines_requested) e
        WHERE e NOT IN (SELECT jsonb_array_elements_text(engines_completed))
       ) AS pending_engines
FROM scan_orchestration
WHERE scan_run_id = $1;

-- Count by status (overall health)
SELECT overall_status, COUNT(*) FROM scan_orchestration
WHERE started_at > NOW() - INTERVAL '7 days'
GROUP BY overall_status;
