import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from sentineltrace.models import SecurityEvent
from sentineltrace.engine import analyze_events
from sentineltrace.reporter import (
    build_report,
    write_json_report,
    write_markdown_report,
)


class TestReporter(unittest.TestCase):

    def make_finding(self):
        event = SecurityEvent(
            timestamp=datetime(2026, 11, 25, 10, 0, tzinfo=timezone.utc),
            event_id="1",
            source="Sysmon",
            host="WIN-TEST",
            event_type="Process creation",
            process_name="powershell.exe",
            command_line="powershell.exe -EncodedCommand SQBFAFgA",
        )
        return analyze_events([event])

    def test_build_report(self):
        findings = self.make_finding()
        report = build_report(findings)

        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["findings"][0]["rule_id"], "ST-002")
        self.assertTrue(report["findings"][0]["recommendations"])

    def test_write_json_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_json_report(self.make_finding(), directory)

            self.assertTrue(path.is_file())
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["finding_count"], 1)

    def test_write_markdown_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_markdown_report(self.make_finding(), directory)
            content = path.read_text(encoding="utf-8")

            self.assertIn("ST-002", content)
            self.assertIn("Analyst recommendations", content)
            self.assertIn("WIN-TEST", content)

    def test_empty_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_markdown_report([], directory)
            content = path.read_text(encoding="utf-8")

            self.assertIn("No findings", content)


if __name__ == "__main__":
    unittest.main()
