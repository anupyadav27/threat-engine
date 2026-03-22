"""
Response Recorder - In-memory accumulator for attack responses.
Results are passed directly to the vulnerability detector; no files are written.
"""

from typing import Dict, Any, List


class ResponseRecorder:
    """Accumulates attack results in memory during a scan session."""

    def __init__(self, config=None):
        self.config = config
        self._results: List[Dict[str, Any]] = []

    def record(self, result: Dict[str, Any]):
        """Append a single attack result to the in-memory store."""
        self._results.append(result)

    def finalize(self):
        """No-op — kept for interface compatibility."""

    def get_results(self) -> List[Dict[str, Any]]:
        """Return all recorded results."""
        return list(self._results)
