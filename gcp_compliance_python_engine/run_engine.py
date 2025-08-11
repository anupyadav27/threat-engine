import os
import json
from gcp_compliance_python_engine.engine.gcp_engine import main as engine_main
from gcp_compliance_python_engine.utils.inventory_reporter import save_scan_results, save_split_scan_results
from gcp_compliance_python_engine.auth.gcp_auth import get_default_project_id

if __name__ == "__main__":
    results_json = []
    # engine_main currently prints JSON; refactor to return instead for consistency
    # For now, call and capture via import; re-run the core to get JSON
    from gcp_compliance_python_engine.engine import gcp_engine
    all_outputs = []
    # Execute and collect
    from io import StringIO
    import sys
    buf = StringIO()
    _stdout = sys.stdout
    try:
        sys.stdout = buf
        gcp_engine.main()
    finally:
        sys.stdout = _stdout
    try:
        all_outputs = json.loads(buf.getvalue())
    except Exception:
        print(buf.getvalue())
        all_outputs = []
    print(json.dumps(all_outputs, indent=2))
    # Save
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'output'))
    proj = get_default_project_id() or "unknown"
    path = save_scan_results(all_outputs, out_dir, proj)
    print(f"Saved gcp engine results to: {path}")
    folder = save_split_scan_results(all_outputs, out_dir, proj)
    print(f"Saved split results under: {folder}") 