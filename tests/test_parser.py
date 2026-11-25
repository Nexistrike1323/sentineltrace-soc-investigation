import unittest

from sentineltrace.parser import normalize_event


class TestEventParser(unittest.TestCase):

    def test_wazuh_windows_event(self):
        raw = {
            "timestamp": "2026-11-25T10:30:00+00:00",
            "agent": {"name": "WIN-TEST"},
            "rule": {"level": 10, "description": "Windows login failure"},
            "data": {
                "win": {
                    "system": {
                        "eventID": "4625",
                        "computer": "WIN-TEST",
                        "channel": "Security",
                        "systemTime": "2026-11-25T10:30:00+00:00"
                    },
                    "eventdata": {
                        "targetUserName": "analyst",
                        "ipAddress": "192.168.1.50"
                    }
                }
            }
        }

        event = normalize_event(raw)

        self.assertEqual(event.event_id, "4625")
        self.assertEqual(event.host, "WIN-TEST")
        self.assertEqual(event.username, "analyst")
        self.assertEqual(event.source_ip, "192.168.1.50")
        self.assertEqual(event.severity, "medium")
        self.assertEqual(event.source, "Security")

    def test_missing_required_fields(self):
        with self.assertRaises(ValueError):
            normalize_event({"message": "Incomplete event"})

    def test_timezone_is_required(self):
        raw = {
            "timestamp": "2026-11-25T10:30:00",
            "event_id": "4625",
            "host": "WIN-TEST",
            "event_type": "Login failure"
        }

        with self.assertRaises(ValueError):
            normalize_event(raw)

    def test_fingerprint_is_stable(self):
        raw = {
            "timestamp": "2026-11-25T10:30:00+00:00",
            "event_id": "4625",
            "host": "WIN-TEST",
            "event_type": "Login failure"
        }

        first = normalize_event(raw)
        second = normalize_event(raw)

        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(len(first.fingerprint), 64)

    def test_terminalservices_session_fields(self):
        raw = {
            "timestamp": "2026-11-25T04:48:35.9506414+00:00",
            "event_id": "21",
            "source": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "host": "DELL",
            "event_type": "RDP session logon succeeded",
            "username": r"DELL\neera",
            "session_id": "4",
            "session_address": "LOCAL",
        }

        event = normalize_event(raw)

        self.assertEqual(event.username, r"DELL\neera")
        self.assertEqual(event.session_id, "4")
        self.assertEqual(event.session_address, "LOCAL")
        self.assertIsNone(event.source_ip)
        self.assertIsNone(event.logon_type)

    def test_terminalservices_missing_session_fields(self):
        raw = {
            "timestamp": "2026-11-25T04:48:35+00:00",
            "event_id": "21",
            "source": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "host": "DELL",
            "event_type": "RDP session logon succeeded",
        }

        event = normalize_event(raw)

        self.assertIsNone(event.session_id)
        self.assertIsNone(event.session_address)

    def test_session_fields_change_fingerprint(self):
        base = {
            "timestamp": "2026-11-25T04:48:35+00:00",
            "event_id": "21",
            "source": "TerminalServices",
            "host": "DELL",
            "event_type": "RDP session logon succeeded",
            "username": r"DELL\neera",
        }

        first = normalize_event({
            **base,
            "session_id": "3",
            "session_address": "LOCAL",
        })

        second = normalize_event({
            **base,
            "session_id": "4",
            "session_address": "LOCAL",
        })

        self.assertNotEqual(first.fingerprint, second.fingerprint)


if __name__ == "__main__":
    unittest.main()
