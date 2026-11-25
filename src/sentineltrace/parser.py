"""JSON and Wazuh event normalization."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from sentineltrace.models import SecurityEvent


def first_value(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Event timestamp is missing or invalid")

    normalized = value.strip().replace("Z", "+00:00")

    try:
        result = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"Unsupported timestamp: {value}") from exc

    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("Timestamp must include timezone information")

    return result


def nested(data: dict, *keys: str) -> Any:
    current: Any = data

    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)

    return current


def normalize_event(raw: dict[str, Any]) -> SecurityEvent:
    if not isinstance(raw, dict):
        raise ValueError("Each event must be a JSON object")

    win_system = nested(raw, "data", "win", "system") or {}
    win_data = nested(raw, "data", "win", "eventdata") or {}
    rule = raw.get("rule") or {}
    agent = raw.get("agent") or {}
    provider_data = win_system.get("provider") or {}
    provider = first_value(
        raw.get("provider"),
        raw.get("provider_name"),
        win_system.get("providerName"),
        provider_data.get("name") if isinstance(provider_data, dict) else None,
    )

    timestamp = first_value(
        raw.get("timestamp"),
        raw.get("@timestamp"),
        raw.get("time"),
        win_system.get("systemTime"),
    )

    event_id = first_value(
        raw.get("event_id"),
        raw.get("eventID"),
        win_system.get("eventID"),
        raw.get("id"),
    )

    host = first_value(
        raw.get("host"),
        raw.get("hostname"),
        nested(raw, "computer"),
        win_system.get("computer"),
        agent.get("name"),
    )

    source = first_value(
        raw.get("source"),
        raw.get("channel"),
        win_system.get("channel"),
        "wazuh" if agent else "json",
    )

    event_type = first_value(
        raw.get("event_type"),
        raw.get("type"),
        rule.get("description"),
        f"Windows Event {event_id}" if event_id else None,
    )

    severity_value = first_value(
        raw.get("severity"),
        rule.get("level"),
    )

    severity = "unknown"
    if isinstance(severity_value, str):
        candidate = severity_value.lower()
        if candidate in {
            "critical", "high", "medium", "low", "informational", "unknown"
        }:
            severity = candidate
    elif isinstance(severity_value, (int, float)):
        if severity_value >= 12:
            severity = "high"
        elif severity_value >= 7:
            severity = "medium"
        elif severity_value > 0:
            severity = "low"

    username = first_value(
        raw.get("username"),
        raw.get("user"),
        win_data.get("targetUserName"),
        win_data.get("subjectUserName"),
        nested(raw, "data", "srcuser"),
    )

    source_ip = first_value(
        raw.get("source_ip"),
        raw.get("src_ip"),
        win_data.get("ipAddress"),
        nested(raw, "data", "srcip"),
    )

    logon_type = first_value(
        raw.get("logon_type"),
        win_data.get("logonType"),
    )

    session_id = first_value(raw.get("session_id"))
    session_address = first_value(raw.get("session_address"))

    destination_ip = first_value(
        raw.get("destination_ip"),
        raw.get("dst_ip"),
        nested(raw, "data", "dstip"),
    )

    process_name = first_value(
        raw.get("process_name"),
        win_data.get("image"),
        nested(raw, "data", "process", "name"),
    )

    command_line = first_value(
        raw.get("command_line"),
        win_data.get("commandLine"),
        nested(raw, "data", "process", "command_line"),
    )

    message = first_value(
        raw.get("message"),
        rule.get("description"),
    )

    required = {
        "timestamp": timestamp,
        "event_id": event_id,
        "host": host,
        "event_type": event_type,
    }

    missing = [key for key, value in required.items() if value is None]
    if missing:
        raise ValueError(f"Missing required event fields: {', '.join(missing)}")

    return SecurityEvent(
        timestamp=parse_timestamp(timestamp),
        event_id=str(event_id),
        source=str(source),
        host=str(host),
        event_type=str(event_type),
        severity=severity,
        username=str(username) if username is not None else None,
        source_ip=str(source_ip) if source_ip is not None else None,
        logon_type=str(logon_type) if logon_type is not None else None,
        session_id=str(session_id) if session_id is not None else None,
        session_address=(
            str(session_address) if session_address is not None else None
        ),
        destination_ip=(
            str(destination_ip) if destination_ip is not None else None
        ),
        process_name=str(process_name) if process_name is not None else None,
        command_line=str(command_line) if command_line is not None else None,
        message=str(message) if message is not None else None,
        raw=raw,
        provider=str(provider) if provider is not None else None,
    )


def load_events(path: str | Path) -> tuple[list[SecurityEvent], list[dict]]:
    """Load JSON array, single JSON object, or JSONL events."""
    file_path = Path(path)

    if not file_path.is_file():
        raise FileNotFoundError(f"Input file not found: {file_path}")

    content = file_path.read_text(encoding="utf-8-sig").strip()
    if not content:
        return [], []

    try:
        document = json.loads(content)
        records = document if isinstance(document, list) else [document]
    except json.JSONDecodeError:
        records = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                records.append({
                    "_parse_error": f"Line {line_number}: {exc}"
                })

    events = []
    errors = []

    for index, record in enumerate(records, start=1):
        try:
            events.append(normalize_event(record))
        except (ValueError, TypeError, AttributeError) as exc:
            errors.append({
                "record": index,
                "error": str(exc),
            })

    return events, errors
