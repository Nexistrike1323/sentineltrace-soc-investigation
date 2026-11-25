"""Canonical event model used by SentinelTrace."""

from dataclasses import asdict, dataclass, field
from datetime import datetime
import hashlib
import json
from typing import Any


@dataclass
class SecurityEvent:
    timestamp: datetime
    event_id: str
    source: str
    host: str
    event_type: str
    severity: str = "unknown"
    username: str | None = None
    source_ip: str | None = None
    logon_type: str | None = None
    session_id: str | None = None
    session_address: str | None = None
    destination_ip: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    message: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    provider: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.timestamp, datetime):
            raise TypeError("timestamp must be a datetime object")

        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must include timezone information")

        for name in ("event_id", "source", "host", "event_type"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")

        allowed_severities = {
            "critical", "high", "medium", "low", "informational", "unknown"
        }
        if self.severity not in allowed_severities:
            raise ValueError(
                f"severity must be one of: {', '.join(sorted(allowed_severities))}"
            )

    @property
    def fingerprint(self) -> str:
        """Stable hash for identifying duplicate source events."""
        payload = {
            "timestamp": self.timestamp.isoformat(),
            "event_id": self.event_id,
            "source": self.source,
            "provider": self.provider,
            "host": self.host,
            "event_type": self.event_type,
            "username": self.username,
            "source_ip": self.source_ip,
            "logon_type": self.logon_type,
            "session_id": self.session_id,
            "session_address": self.session_address,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "message": self.message,
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        result["fingerprint"] = self.fingerprint
        return result
