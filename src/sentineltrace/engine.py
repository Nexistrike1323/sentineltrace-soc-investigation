"""Orchestrates SentinelTrace detection rules."""

from sentineltrace.detections import (
    Finding,
    detect_failed_login_then_success,
    detect_suspicious_powershell,
    detect_public_ip_rdp_logons,
    detect_password_spray,
    detect_security_log_cleared,
)
from sentineltrace.models import SecurityEvent


def analyze_events(events: list[SecurityEvent]) -> list[Finding]:
    """Run enabled rules and return deterministic finding order."""

    findings = []
    findings.extend(detect_failed_login_then_success(events))
    findings.extend(detect_suspicious_powershell(events))
    findings.extend(detect_public_ip_rdp_logons(events))
    findings.extend(detect_password_spray(events))
    findings.extend(detect_security_log_cleared(events))

    return sorted(
        findings,
        key=lambda finding: (
            finding.first_seen,
            finding.rule_id,
            finding.host,
            finding.source_ip or "",
        ),
    )
