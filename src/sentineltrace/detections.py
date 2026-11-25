"""Evidence-based SOC detection rules."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
import ipaddress
import re

from sentineltrace.models import SecurityEvent


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    description: str
    host: str
    username: str | None
    source_ip: str | None
    first_seen: str
    last_seen: str
    evidence: list[dict]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "host": self.host,
            "username": self.username,
            "source_ip": self.source_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "evidence": self.evidence,
        }


def _evidence(event: SecurityEvent) -> dict:
    return {
        "event_id": event.event_id,
        "provider": event.provider,
        "timestamp": event.timestamp.isoformat(),
        "fingerprint": event.fingerprint,
        "event_type": event.event_type,
        "host": event.host,
        "username": event.username,
        "source_ip": event.source_ip,
        "logon_type": event.logon_type,
        "process_name": event.process_name,
        "command_line": event.command_line,
    }



def _identity(value: str | None) -> str | None:
    """Normalize an identity for correlation without changing source evidence."""
    if value is None:
        return None
    normalized = value.strip().casefold()
    return normalized or None


def _normalized_ip(value: str | None) -> str | None:
    """Return canonical IP representation; reject invalid addresses."""
    if not value:
        return None
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError:
        return None



def detect_failed_login_then_success(
    events: list[SecurityEvent],
    threshold: int = 5,
    window_minutes: int = 15,
) -> list[Finding]:
    """Correlate failed logons with a later success without reusing evidence."""

    if threshold < 1 or window_minutes < 1:
        raise ValueError("threshold and window_minutes must be positive")

    ordered = sorted(events, key=lambda e: e.timestamp)
    failures_by_key: dict[tuple, list[SecurityEvent]] = defaultdict(list)
    findings = []
    window = timedelta(minutes=window_minutes)

    for event in ordered:
        if event.event_id not in {"4624", "4625"}:
            continue

        username = _identity(event.username)
        host = _identity(event.host)
        source_ip = _normalized_ip(event.source_ip)

        if not username or not host or not source_ip:
            continue
        if event.logon_type not in {"3", "10"}:
            continue

        key = (host, username, source_ip, event.logon_type)
        failures = failures_by_key[key]

        failures[:] = [
            item for item in failures
            if event.timestamp - item.timestamp <= window
        ]

        if event.event_id == "4625":
            failures.append(event)
            continue

        if len(failures) < threshold:
            continue

        evidence_events = sorted(
            failures + [event],
            key=lambda item: item.timestamp,
        )

        findings.append(Finding(
            rule_id="ST-001",
            title="Failed Login Burst Followed by Successful Login",
            severity="high",
            confidence="medium",
            description=(
                f"{len(failures)} failed login attempts were followed by "
                "a successful login for the same normalized host, account, "
                f"source IP and logon type within {window_minutes} minutes. "
                "This is an investigation lead, not proof of compromise."
            ),
            host=event.host,
            username=event.username,
            source_ip=event.source_ip,
            first_seen=evidence_events[0].timestamp.isoformat(),
            last_seen=event.timestamp.isoformat(),
            evidence=[_evidence(item) for item in evidence_events],
        ))

        failures.clear()

    return findings


def detect_suspicious_powershell(
    events: list[SecurityEvent],
) -> list[Finding]:
    """Flag suspicious indicators in confirmed PowerShell process events."""

    indicators = {
        "encoded_command": r"(?i)(?:^|\s)-(?:e|ec|enc|encodedcommand)(?:\s|:|$)",
        "download_string": r"(?i)\bdownloadstring\b",
        "invoke_expression": r"(?i)\b(?:invoke-expression|iex)\b",
        "base64_decode": r"(?i)\bfrombase64string\b",
        "web_request": r"(?i)\binvoke-webrequest\b",
        "bits_transfer": r"(?i)\bstart-bitstransfer\b",
    }

    findings = []

    for event in events:
        command = event.command_line or ""
        process = (event.process_name or "").replace("/", "\\").lower()
        executable = process.rsplit("\\", 1)[-1]

        # Do not infer the process executable from arbitrary command arguments.
        if executable not in {"powershell.exe", "pwsh.exe"}:
            continue
        if not command:
            continue

        matched = [
            name for name, pattern in indicators.items()
            if re.search(pattern, command)
        ]

        if not matched:
            continue

        findings.append(Finding(
            rule_id="ST-002",
            title="Suspicious PowerShell Command-Line Indicators",
            severity="medium",
            confidence="low",
            description=(
                "PowerShell command line contains suspicious indicators: "
                + ", ".join(matched)
                + ". Static indicators do not prove malicious execution."
            ),
            host=event.host,
            username=event.username,
            source_ip=event.source_ip,
            first_seen=event.timestamp.isoformat(),
            last_seen=event.timestamp.isoformat(),
            evidence=[{
                **_evidence(event),
                "matched_indicators": matched,
            }],
        ))

    return findings

def detect_public_ip_rdp_logons(
    events: list[SecurityEvent],
) -> list[Finding]:
    """Identify successful RDP logons from globally routable IP addresses."""

    findings = []
    for event in events:
        if event.event_id != "4624" or event.logon_type != "10":
            continue
        if not event.source_ip:
            continue

        try:
            address = ipaddress.ip_address(event.source_ip)
        except ValueError:
            continue

        if not address.is_global:
            continue

        findings.append(Finding(
            rule_id="ST-003",
            title="Successful RDP Logon from Public IP",
            severity="low",
            confidence="low",
            description=(
                "A successful Remote Interactive logon originated from "
                "a globally routable IP address. Public IP origin alone "
                "does not establish malicious activity."
            ),
            host=event.host,
            username=event.username,
            source_ip=event.source_ip,
            first_seen=event.timestamp.isoformat(),
            last_seen=event.timestamp.isoformat(),
            evidence=[_evidence(event)],
        ))
    return findings



def detect_password_spray(
    events: list[SecurityEvent],
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[Finding]:
    """Detect one source IP failing against many distinct accounts."""

    if threshold < 2 or window_minutes < 1:
        raise ValueError("threshold must be >= 2 and window_minutes positive")

    grouped: dict[tuple, list[SecurityEvent]] = defaultdict(list)

    for event in sorted(events, key=lambda e: e.timestamp):
        host = _identity(event.host)
        source_ip = _normalized_ip(event.source_ip)
        username = _identity(event.username)

        if (
            event.event_id == "4625"
            and host
            and source_ip
            and username
            and event.logon_type in {"3", "10"}
        ):
            grouped[(host, source_ip)].append(event)

    findings = []
    window = timedelta(minutes=window_minutes)

    for (host_key, source_ip), records in grouped.items():
        active = []
        alerted = False

        for event in records:
            active = [
                item for item in active
                if event.timestamp - item.timestamp <= window
            ]
            active.append(event)

            distinct_users = {
                _identity(item.username)
                for item in active
                if _identity(item.username)
            }

            if len(distinct_users) >= threshold and not alerted:
                evidence_events = sorted(
                    active,
                    key=lambda item: item.timestamp,
                )

                findings.append(Finding(
                    rule_id="ST-004",
                    title="Possible Password Spraying Activity",
                    severity="medium",
                    confidence="medium",
                    description=(
                        f"One source IP generated failed logons against "
                        f"{len(distinct_users)} distinct normalized accounts "
                        f"on the same host within {window_minutes} minutes. "
                        "Validate NAT, proxy and approved testing activity."
                    ),
                    host=event.host,
                    username=None,
                    source_ip=event.source_ip,
                    first_seen=evidence_events[0].timestamp.isoformat(),
                    last_seen=event.timestamp.isoformat(),
                    evidence=[_evidence(item) for item in evidence_events],
                ))
                alerted = True

            if len(distinct_users) < threshold:
                alerted = False

    return findings


def detect_security_log_cleared(
    events: list[SecurityEvent],
) -> list[Finding]:
    """Detect Windows Security event 1102 with channel/provider validation."""

    findings = []

    for event in events:
        if event.event_id != "1102":
            continue

        # Event 1102 must originate from the Windows Security channel.
        if (event.source or "").strip().casefold() != "security":
            continue

        provider = (event.provider or "").strip()
        if provider and provider.casefold() != (
            "microsoft-windows-security-auditing"
        ):
            continue

        findings.append(Finding(
            rule_id="ST-005",
            title="Windows Security Audit Log Cleared",
            severity="high",
            confidence="medium" if provider else "low",
            description=(
                "Windows Security event 1102 indicates that the Security "
                "audit log was cleared. Confirm the actor, authorization, "
                "maintenance activity and surrounding event coverage."
            ),
            host=event.host,
            username=event.username,
            source_ip=event.source_ip,
            first_seen=event.timestamp.isoformat(),
            last_seen=event.timestamp.isoformat(),
            evidence=[_evidence(event)],
        ))

    return findings
