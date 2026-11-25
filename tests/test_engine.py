import unittest
from datetime import datetime, timedelta, timezone

from sentineltrace.engine import analyze_events
from sentineltrace.models import SecurityEvent


class TestDetectionEngine(unittest.TestCase):

    def test_engine_runs_both_detection_rules(self):
        base = datetime(2026, 11, 25, 10, 0, tzinfo=timezone.utc)

        events = []

        for minute in range(5):
            events.append(
                SecurityEvent(
                    timestamp=base + timedelta(minutes=minute),
                    event_id="4625",
                    source="Windows Security",
                    host="WIN-TEST",
                    event_type="Login failure",
                    username="analyst",
                    source_ip="192.168.1.50",
                    logon_type="3",
                )
            )

        events.append(
            SecurityEvent(
                timestamp=base + timedelta(minutes=5),
                event_id="4624",
                source="Windows Security",
                host="WIN-TEST",
                event_type="Login success",
                username="analyst",
                source_ip="192.168.1.50",
                logon_type="3",
            )
        )

        events.append(
            SecurityEvent(
                timestamp=base + timedelta(minutes=6),
                event_id="1",
                source="Sysmon",
                host="WIN-TEST",
                event_type="Process creation",
                process_name="powershell.exe",
                command_line="powershell.exe -EncodedCommand SQBFAFgA",
            )
        )

        findings = analyze_events(events)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("ST-001", rule_ids)
        self.assertIn("ST-002", rule_ids)
        self.assertEqual(len(findings), 2)


if __name__ == "__main__":
    unittest.main()
