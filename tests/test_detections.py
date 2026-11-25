import unittest
from datetime import datetime, timedelta, timezone

from sentineltrace.models import SecurityEvent
from sentineltrace.detections import detect_failed_login_then_success


class TestLoginDetection(unittest.TestCase):

    def make_event(
        self,
        event_id,
        minutes,
        username="analyst",
        source_ip="192.168.1.50",
        host="WIN-TEST",
        logon_type="3",
    ):
        return SecurityEvent(
            timestamp=datetime(
                2026, 11, 25, 10, 0, tzinfo=timezone.utc
            ) + timedelta(minutes=minutes),
            event_id=event_id,
            source="Windows Security",
            host=host,
            event_type="Login event",
            username=username,
            source_ip=source_ip,
            logon_type=logon_type,
        )

    def test_detects_failed_logins_followed_by_success(self):
        events = [
            self.make_event("4625", 0),
            self.make_event("4625", 1),
            self.make_event("4625", 2),
            self.make_event("4625", 3),
            self.make_event("4625", 4),
            self.make_event("4624", 5),
        ]

        findings = detect_failed_login_then_success(events)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "ST-001")
        self.assertEqual(len(findings[0].evidence), 6)

    def test_no_detection_below_threshold(self):
        events = [
            self.make_event("4625", 0),
            self.make_event("4625", 1),
            self.make_event("4624", 2),
        ]

        self.assertEqual(detect_failed_login_then_success(events), [])

    def test_no_detection_for_different_source_ip(self):
        events = [
            self.make_event("4625", 0),
            self.make_event("4625", 1),
            self.make_event("4625", 2),
            self.make_event("4625", 3),
            self.make_event("4625", 4),
            self.make_event("4624", 5, source_ip="10.0.0.20"),
        ]

        self.assertEqual(detect_failed_login_then_success(events), [])

    def test_no_detection_outside_time_window(self):
        events = [
            self.make_event("4625", 0),
            self.make_event("4625", 1),
            self.make_event("4625", 2),
            self.make_event("4625", 3),
            self.make_event("4625", 4),
            self.make_event("4624", 20),
        ]

        self.assertEqual(detect_failed_login_then_success(events), [])

    def test_missing_source_ip_is_not_correlated(self):
        events = [
            self.make_event("4625", 0, source_ip=None),
            self.make_event("4625", 1, source_ip=None),
            self.make_event("4625", 2, source_ip=None),
            self.make_event("4625", 3, source_ip=None),
            self.make_event("4625", 4, source_ip=None),
            self.make_event("4624", 5, source_ip=None),
        ]

        self.assertEqual(detect_failed_login_then_success(events), [])

    def test_fingerprint_distinguishes_logon_types(self):
        network = self.make_event("4624", 5, logon_type="3")
        service = self.make_event("4624", 5, logon_type="5")
        self.assertNotEqual(network.fingerprint, service.fingerprint)

    def test_service_logons_are_not_correlated(self):
        events = [
            self.make_event("4625", 0, logon_type="5"),
            self.make_event("4625", 1, logon_type="5"),
            self.make_event("4625", 2, logon_type="5"),
            self.make_event("4625", 3, logon_type="5"),
            self.make_event("4625", 4, logon_type="5"),
            self.make_event("4624", 5, logon_type="5"),
        ]

        self.assertEqual(detect_failed_login_then_success(events), [])


if __name__ == "__main__":
    unittest.main()
