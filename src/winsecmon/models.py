"""Core data types shared across modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")
_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def severity_rank(severity: str) -> int:
    return _RANK[severity]


@dataclass(frozen=True)
class EventDefinition:
    """One monitored event ID, as declared in the configuration file."""

    event_id: int
    name: str
    category: str
    severity: str
    enabled: bool = True
    description: str = ""


def fallback_definition(event_id: int) -> EventDefinition:
    """Used for IDs that appear in a log or on the command line but not in the config."""
    return EventDefinition(
        event_id, f"Event {event_id}", "custom", "info", True, "Not defined in the configuration."
    )


@dataclass(frozen=True)
class SecurityEvent:
    event_id: int
    time_utc: datetime
    computer: str
    channel: str = ""
    provider: str = ""
    record_id: int | None = None
    level: int | None = None
    outcome: str | None = None  # "success" / "failure" from the audit keywords
    name: str = ""
    category: str = "custom"
    severity: str = "info"
    account: str | None = None  # the account the event is primarily about, DOMAIN\user
    subject_user: str | None = None
    subject_domain: str | None = None
    target_user: str | None = None
    target_domain: str | None = None
    object_name: str | None = None  # e.g. the group in a group-membership change
    logon_type: int | None = None
    logon_type_name: str | None = None
    source_ip: str | None = None
    workstation: str | None = None
    process_name: str | None = None
    status: str | None = None
    message: str = ""
    data: dict[str, str] = field(default_factory=dict)  # every EventData field

    def time_iso(self) -> str:
        stamp = self.time_utc.astimezone(timezone.utc).isoformat(timespec="milliseconds")
        return stamp.replace("+00:00", "Z")

    def to_record(self) -> dict[str, Any]:
        """Flat, ordered representation used by the CSV and JSON exporters."""
        return {
            "time_utc": self.time_iso(),
            "event_id": self.event_id,
            "event_name": self.name,
            "category": self.category,
            "severity": self.severity,
            "outcome": self.outcome,
            "computer": self.computer,
            "account": self.account,
            "subject_user": self.subject_user,
            "subject_domain": self.subject_domain,
            "target_user": self.target_user,
            "target_domain": self.target_domain,
            "object_name": self.object_name,
            "logon_type": self.logon_type,
            "logon_type_name": self.logon_type_name,
            "source_ip": self.source_ip,
            "workstation": self.workstation,
            "process_name": self.process_name,
            "status": self.status,
            "message": self.message,
            "record_id": self.record_id,
            "channel": self.channel,
            "provider": self.provider,
            "details": dict(self.data),
        }


RECORD_FIELDS = tuple(
    SecurityEvent(0, datetime(2000, 1, 1, tzinfo=timezone.utc), "").to_record().keys()
)
