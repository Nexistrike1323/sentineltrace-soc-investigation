import unittest
from datetime import datetime, timezone

from sentineltrace.models import SecurityEvent
from sentineltrace.detections import detect_suspicious_powershell


class TestPowerShellDetection(unittest.TestCase):

    def make_event(self, process, command):
        return SecurityEvent(
            timestamp=datetime(2026, 11, 25, 10, 0, tzinfo=timezone.utc),
            event_id="1",
            source="Sysmon",
            host="WIN-TEST",
            event_type="Process creation",
            process_name=process,
            command_line=command,
        )

    def test_detects_encoded_command(self):
        event = self.make_event(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -EncodedCommand SQBFAFgA",
        )
        findings = detect_suspicious_powershell([event])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "ST-002")

    def test_detects_download_string(self):
        event = self.make_event(
            "powershell.exe",
            "powershell.exe -Command $client.DownloadString('https://example.test')",
        )
        self.assertEqual(len(detect_suspicious_powershell([event])), 1)

    def test_ignores_normal_powershell(self):
        event = self.make_event(
            "powershell.exe",
            "powershell.exe -Command Get-Process",
        )
        self.assertEqual(detect_suspicious_powershell([event]), [])

    def test_ignores_non_powershell_process(self):
        event = self.make_event(
            "notepad.exe",
            "notepad.exe document.txt",
        )
        self.assertEqual(detect_suspicious_powershell([event]), [])


if __name__ == "__main__":
    unittest.main()
