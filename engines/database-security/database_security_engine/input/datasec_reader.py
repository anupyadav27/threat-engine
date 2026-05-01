"""DataSec reader for Database Security Engine."""

from engine_common.base_datasec_reader import BaseDatasecReader


class DataSecReader(BaseDatasecReader):
    def load_db_classification(self, scan_run_id: str, tenant_id: str):
        return self.load_findings(scan_run_id, tenant_id)

    def load_enhanced_db_data(self, scan_run_id: str, tenant_id: str):
        return self.load_enhanced_data(scan_run_id, tenant_id)
