"""Event filtering. Event-ID, category and severity filters are pushed down into the Windows
query; user and computer filters are applied after reading."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime

from .models import EventDefinition, SecurityEvent, fallback_definition, severity_rank


def _matches_any(value_set: Iterable[str], patterns: Iterable[str]) -> bool:
    values = list(value_set)
    return any(fnmatch.fnmatchcase(v, p) for p in patterns for v in values)


def _account_names(event: SecurityEvent) -> set[str]:
    names: set[str] = set()
    for user, domain in (
        (event.subject_user, event.subject_domain),
        (event.target_user, event.target_domain),
    ):
        if user:
            names.add(user.lower())
            if domain:
                names.add(f"{domain}\\{user}".lower())
    if event.account:
        names.add(event.account.lower())
    return names


@dataclass(frozen=True)
class EventFilter:
    start: datetime | None = None  # UTC, inclusive
    end: datetime | None = None  # UTC, inclusive
    users: tuple[str, ...] = ()
    computers: tuple[str, ...] = ()
    event_ids: tuple[int, ...] = ()  # explicit IDs; override the config's enabled list
    categories: frozenset[str] = frozenset()
    severities: frozenset[str] = frozenset()
    min_severity: str | None = None
    exclude_users: tuple[str, ...] = field(default=())

    def _definition_allowed(self, definition: EventDefinition) -> bool:
        if self.categories and definition.category not in self.categories:
            return False
        if self.severities and definition.severity not in self.severities:
            return False
        if self.min_severity and severity_rank(definition.severity) < severity_rank(self.min_severity):
            return False
        return True

    def select_event_ids(self, definitions: Mapping[int, EventDefinition]) -> list[int]:
        """The event IDs worth asking Windows for, after category/severity filters."""
        if self.event_ids:
            candidates = list(dict.fromkeys(self.event_ids))
        else:
            candidates = [i for i, d in definitions.items() if d.enabled]
        return [
            i for i in candidates if self._definition_allowed(definitions.get(i) or fallback_definition(i))
        ]

    def matches(self, event: SecurityEvent) -> bool:
        """Time, category, severity, user and computer checks (exclusions are separate)."""
        if self.start and event.time_utc < self.start:
            return False
        if self.end and event.time_utc > self.end:
            return False
        if self.categories and event.category not in self.categories:
            return False
        if self.severities and event.severity not in self.severities:
            return False
        if self.min_severity and severity_rank(event.severity) < severity_rank(self.min_severity):
            return False
        if self.users:
            if not _matches_any(_account_names(event), (u.lower() for u in self.users)):
                return False
        if self.computers:
            computer = event.computer.lower()
            if not _matches_any({computer, computer.split(".")[0]}, (c.lower() for c in self.computers)):
                return False
        return True

    def is_excluded(self, event: SecurityEvent) -> bool:
        if not self.exclude_users or not event.account:
            return False
        name = event.account.lower()
        bare = name.rsplit("\\", 1)[-1]
        return _matches_any({name, bare}, (p.lower() for p in self.exclude_users))

    def describe(self) -> dict[str, object]:
        """A JSON-friendly summary of the active filters, for reports and exports."""
        return {
            "start_utc": self.start.isoformat().replace("+00:00", "Z") if self.start else None,
            "end_utc": self.end.isoformat().replace("+00:00", "Z") if self.end else None,
            "users": list(self.users),
            "computers": list(self.computers),
            "event_ids": list(self.event_ids),
            "categories": sorted(self.categories),
            "severities": sorted(self.severities, key=severity_rank),
            "min_severity": self.min_severity,
            "exclude_users": list(self.exclude_users),
        }
