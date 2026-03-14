"""VMDR fixture loader for eval/benchmark mocking.

When VMDR_MOCK_FIXTURES=1 is set, call install_vmdr_mocks() to replace
live VMDR API calls with fixture data.
"""

import json
import os
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent


def load_fixture(name):
    """Load a JSON fixture file by name (without extension)."""
    path = FIXTURES_DIR / f"{name}.json"
    with open(path) as f:
        return json.load(f)


def install_vmdr_mocks(qualys_module):
    """Monkeypatch qualys_mcp to use fixture data instead of live API calls.

    Replaces get_detections and get_qds_for_qids with fixture-backed stubs.
    Call this AFTER importing qualys_mcp but BEFORE running any tools.
    """
    detections = load_fixture("vmdr_detections")
    qds_map = load_fixture("vmdr_qds")

    def mock_get_detections(severity=5, limit=0, use_cache=True, days=30, qds_min=0, fetch_all=True):
        filtered = [d for d in detections if d["severity"] >= severity]
        if qds_min > 0:
            filtered = [d for d in filtered if d.get("qds", 0) >= qds_min]
        if limit > 0:
            filtered = filtered[:limit]
        return filtered

    def mock_get_qds_for_qids(qids):
        return {q: qds_map.get(str(q), 0) for q in qids}

    qualys_module.get_detections = mock_get_detections
    qualys_module.get_qds_for_qids = mock_get_qds_for_qids


def should_mock():
    """Return True if VMDR_MOCK_FIXTURES env var is set."""
    return os.environ.get("VMDR_MOCK_FIXTURES", "").lower() in ("1", "true", "yes")
