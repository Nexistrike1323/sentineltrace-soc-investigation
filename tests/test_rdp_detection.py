import unittest
from datetime import datetime, timezone

from sentineltrace.models import SecurityEvent
from sentineltrace.detections import detect_public_ip_rdp_logons
from sentineltrace.engine import analyze_events


class TestRDPDetection(unittest.TestCase):

    def make_event(self, source_ip="1.1.1.1", logon_type="10",
                   event_id="4624"):
        return SecurityEvent(
            timestamp=datetime(
                2026, 11, 25, 10, 0, tzinfo=timezone.utc
            ),
            event_id=event_id,
            source="Windows Security",
            host="WIN-TEST",
            event_type="Successful login",
            username="analyst",
            source_ip=source_ip,
            logon_type=logon_type,
        )

    def test_detects_public_ip_rdp_logon(self):
        findings = detect_public_ip_rdp_logons([self.make_event()])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "ST-003")
        self.assertEqual(findings[0].severity, "low")
        self.assertEqual(findings[0].source_ip, "1.1.1.1")

    def test_ignores_private_ip(self):
        event = self.make_event(source_ip="192.168.1.50")
        self.assertEqual(detect_public_ip_rdp_logons([event]), [])

    def test_ignores_missing_source_ip(self):
        event = self.make_event(source_ip=None)
        self.assertEqual(detect_public_ip_rdp_logons([event]), [])

    def test_ignores_invalid_source_ip(self):
        event = self.make_event(source_ip="not-an-ip")
        self.assertEqual(detect_public_ip_rdp_logons([event]), [])

    def test_ignores_non_rdp_logon(self):
        event = self.make_event(logon_type="2")
        self.assertEqual(detect_public_ip_rdp_logons([event]), [])

    def test_ignores_failed_rdp_logon(self):
        event = self.make_event(event_id="4625")
        self.assertEqual(detect_public_ip_rdp_logons([event]), [])

    def test_engine_runs_rdp_detection(self):
        event = self.make_event()
        findings = analyze_events([event])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "ST-003")


if __name__ == "__main__":
    unittest.main()
