import unittest
from datetime import datetime, timedelta, timezone

from sentineltrace.models import SecurityEvent
from sentineltrace.detections import (
    detect_failed_login_then_success,
    detect_suspicious_powershell,
    detect_password_spray,
    detect_security_log_cleared,
)
from sentineltrace.parser import normalize_event


BASE = datetime(2026, 11, 25, 10, 0, tzinfo=timezone.utc)


def make_event(event_id, minute=0, **kwargs):
    values = {
        "timestamp": BASE + timedelta(minutes=minute),
        "event_id": event_id,
        "source": "Security",
        "host": "WIN-TEST",
        "event_type": "Windows event",
        "logon_type": "3",
    }
    values.update(kwargs)
    return SecurityEvent(**values)


class DetectionQualityTests(unittest.TestCase):

    def test_st001_correlates_case_insensitive_account_and_host(self):
        events = [
            make_event("4625", i, username="Admin",
                       source_ip="192.168.1.10")
            for i in range(5)
        ]
        events.append(make_event(
            "4624", 5, username="admin", host="win-test",
            source_ip="192.168.1.10",
        ))
        self.assertEqual(len(detect_failed_login_then_success(events)), 1)

    def test_st001_rejects_invalid_ip(self):
        events = [
            make_event("4625", i, source_ip="not-an-ip")
            for i in range(5)
        ]
        events.append(make_event("4624", 5, source_ip="not-an-ip"))
        self.assertEqual(detect_failed_login_then_success(events), [])

    def test_st001_accepts_exact_window_boundary(self):
        events = [
            make_event(
                "4625", i, username="analyst",
                source_ip="192.0.2.10",
            )
            for i in range(5)
        ]
        events.append(make_event(
            "4624", 15, username="analyst",
            source_ip="192.0.2.10"
        ))
        self.assertEqual(len(detect_failed_login_then_success(events)), 1)

    def test_st002_does_not_infer_process_from_arguments(self):
        event = make_event(
            "1",
            source="Sysmon",
            process_name="notepad.exe",
            command_line="notepad.exe powershell.exe -EncodedCommand ABC",
        )
        self.assertEqual(detect_suspicious_powershell([event]), [])

    def test_st002_detects_actual_pwsh_executable(self):
        event = make_event(
            "1",
            source="Sysmon",
            process_name="/usr/bin/pwsh.exe",
            command_line="pwsh.exe -EncodedCommand ABC",
        )
        self.assertEqual(len(detect_suspicious_powershell([event])), 1)

    def test_st004_deduplicates_case_variants_of_account(self):
        events = [
            make_event(
                "4625", i, username=name,
                source_ip="192.0.2.20", logon_type="3",
            )
            for i, name in enumerate([
                "Administrator", "administrator", "ADMINISTRATOR",
                "Admin", "admin",
            ])
        ]
        self.assertEqual(detect_password_spray(events), [])

    def test_st004_detects_distinct_accounts(self):
        events = [
            make_event(
                "4625", i, username=f"user{i}",
                source_ip="192.0.2.20", logon_type="3",
            )
            for i in range(5)
        ]
        self.assertEqual(len(detect_password_spray(events)), 1)

    def test_st005_requires_security_channel(self):
        event = make_event(
            "1102",
            source="Application",
            provider="Microsoft-Windows-Security-Auditing",
        )
        self.assertEqual(detect_security_log_cleared([event]), [])

    def test_st005_rejects_wrong_provider(self):
        event = make_event(
            "1102",
            provider="Other-Provider",
        )
        self.assertEqual(detect_security_log_cleared([event]), [])

    def test_st005_accepts_valid_provider(self):
        event = make_event(
            "1102",
            provider="Microsoft-Windows-Security-Auditing",
        )
        findings = detect_security_log_cleared([event])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, "medium")

    def test_st005_accepts_missing_provider_with_lower_confidence(self):
        event = make_event("1102")
        findings = detect_security_log_cleared([event])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, "low")

    def test_parser_extracts_provider(self):
        event = normalize_event({
            "timestamp": "2026-11-25T10:00:00Z",
            "event_id": "1102",
            "source": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "host": "WIN-TEST",
            "event_type": "Windows Event 1102",
        })
        self.assertEqual(
            event.provider,
            "Microsoft-Windows-Security-Auditing",
        )


if __name__ == "__main__":
    unittest.main()
