"""Unit tests for report exporters (JSON and CSV)."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from portscope.models import (
    PortResult,
    PortStatus,
    ScanMetadata,
    ScanReport,
)
from portscope.reporters import export_csv, export_json


class TestReporters(unittest.TestCase):
    """Test suite for validating JSON and CSV output integrity."""

    def setUp(self):
        self.metadata = ScanMetadata(
            timestamp="2026-10-08T01:00:00Z",
            target="127.0.0.1",
            resolved_address="127.0.0.1",
            timeout_seconds=1.0,
            port_count=2,
            duration_ms=45.67,
            workers=4,
        )
        self.results = [
            PortResult(
                port=80,
                protocol="tcp",
                status=PortStatus.OPEN,
                latency_ms=1.23,
                error=None,
            ),
            PortResult(
                port=81,
                protocol="tcp",
                status=PortStatus.CLOSED,
                latency_ms=0.45,
                error="Connection refused",
            ),
        ]
        self.report = ScanReport(metadata=self.metadata, results=self.results)
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_export_json_structure(self):
        """Export JSON generates valid schema with metadata and results."""
        out_file = Path(self.temp_dir.name) / "scan.json"
        export_json(self.report, out_file)

        self.assertTrue(out_file.exists())
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("scan_metadata", data)
        self.assertIn("summary", data)
        self.assertIn("results", data)

        meta = data["scan_metadata"]
        self.assertEqual(meta["target"], "127.0.0.1")
        self.assertEqual(meta["resolved_address"], "127.0.0.1")
        self.assertEqual(meta["timeout_seconds"], 1.0)
        self.assertEqual(meta["port_count"], 2)

        summary = data["summary"]
        self.assertEqual(summary["total_scanned"], 2)
        self.assertEqual(summary["open_count"], 1)
        self.assertEqual(summary["closed_count"], 1)
        self.assertEqual(summary["filtered_count"], 0)

        results = data["results"]
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["port"], 80)
        self.assertEqual(results[0]["status"], "open")
        self.assertEqual(results[1]["port"], 81)
        self.assertEqual(results[1]["status"], "closed")

    def test_export_csv_structure(self):
        """Export CSV generates matching header and rows."""
        out_file = Path(self.temp_dir.name) / "scan.csv"
        export_csv(self.report, out_file)

        self.assertTrue(out_file.exists())
        with open(out_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        expected_headers = [
            "timestamp",
            "target",
            "resolved_address",
            "port",
            "protocol",
            "status",
            "latency_ms",
            "error",
        ]
        self.assertEqual(reader.fieldnames, expected_headers)
        self.assertEqual(len(rows), 2)

        self.assertEqual(rows[0]["port"], "80")
        self.assertEqual(rows[0]["status"], "open")
        self.assertEqual(rows[0]["latency_ms"], "1.23")

        self.assertEqual(rows[1]["port"], "81")
        self.assertEqual(rows[1]["status"], "closed")
        self.assertEqual(rows[1]["error"], "Connection refused")


if __name__ == "__main__":
    unittest.main()
