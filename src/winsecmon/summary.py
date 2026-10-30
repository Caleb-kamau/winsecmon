"""Aggregate events into the figures shown in the terminal dashboard and HTML report."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone, tzinfo

from .describe import qualified
from .models import SEVERITIES, SecurityEvent, severity_rank

HOURLY_MAX_BUCKETS = 72
DAILY_MAX_BUCKETS = 90


@dataclass(frozen=True)
class Highlight:
    severity: str
    text: str


@dataclass
class Summary:
    total: int = 0
    first_time: datetime | None = None
    last_time: datetime | None = None
    by_severity: dict[str, int] = field(default_factory=lambda: {s: 0 for s in SEVERITIES})
    by_event: list[tuple[int, str, str, int]] = field(default_factory=list)  # id, name, severity, n
    by_category: list[tuple[str, int]] = field(default_factory=list)
    outcomes: dict[str, int] = field(default_factory=dict)
    top_accounts: list[tuple[str, int]] = field(default_factory=list)
    top_computers: list[tuple[str, int]] = field(default_factory=list)
    top_failed_accounts: list[tuple[str, int]] = field(default_factory=list)
    top_failed_sources: list[tuple[str, int]] = field(default_factory=list)
    timeline: list[tuple[str, int]] = field(default_factory=list)
    timeline_unit: str = "hour"
    timeline_note: str = ""
    highlights: list[Highlight] = field(default_factory=list)
    failed_logons: int = 0
    distinct_accounts: int = 0


def is_failed_logon(event: SecurityEvent) -> bool:
    return event.event_id == 4625 or (
        event.outcome == "failure" and event.category == "authentication"
    )


def format_time(value: datetime, tz: tzinfo | None, with_seconds: bool = True) -> str:
    local = value.astimezone(tz)  # tz=None means the system's local time zone
    return local.strftime("%Y-%m-%d %H:%M:%S" if with_seconds else "%Y-%m-%d %H:%M")


def _top(counter: Counter[str], n: int) -> list[tuple[str, int]]:
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]


def _timeline(events: list[SecurityEvent], tz: tzinfo | None) -> tuple[list[tuple[str, int]], str, str]:
    first = min(e.time_utc for e in events)
    last = max(e.time_utc for e in events)
    if last - first <= timedelta(hours=HOURLY_MAX_BUCKETS):
        counts: Counter[datetime] = Counter(
            e.time_utc.replace(minute=0, second=0, microsecond=0) for e in events
        )
        cursor, rows = first.replace(minute=0, second=0, microsecond=0), []
        while cursor <= last:
            rows.append((format_time(cursor, tz, with_seconds=False), counts.get(cursor, 0)))
            cursor += timedelta(hours=1)
        return rows, "hour", ""
    day_counts: Counter[date] = Counter(
        e.time_utc.astimezone(tz).date() for e in events
    )
    day = min(day_counts)
    end_day = max(day_counts)
    rows_d: list[tuple[str, int]] = []
    while day <= end_day:
        rows_d.append((day.isoformat(), day_counts.get(day, 0)))
        day += timedelta(days=1)
    note = ""
    if len(rows_d) > DAILY_MAX_BUCKETS:
        note = f"Latest {DAILY_MAX_BUCKETS} days shown."
        rows_d = rows_d[-DAILY_MAX_BUCKETS:]
    return rows_d, "day", note


def build_summary(
    events: list[SecurityEvent], *, tz: tzinfo | None, top_n: int, failed_logon_threshold: int
) -> Summary:
    summary = Summary(total=len(events))
    if not events:
        return summary

    summary.first_time = min(e.time_utc for e in events)
    summary.last_time = max(e.time_utc for e in events)

    by_event: Counter[tuple[int, str, str]] = Counter()
    categories: Counter[str] = Counter()
    outcomes: Counter[str] = Counter()
    accounts: Counter[str] = Counter()
    computers: Counter[str] = Counter()
    failed_accounts: Counter[str] = Counter()
    failed_sources: Counter[str] = Counter()
    accounts_per_source: dict[str, set[str]] = defaultdict(set)

    for e in events:
        summary.by_severity[e.severity] += 1
        by_event[(e.event_id, e.name, e.severity)] += 1
        categories[e.category] += 1
        if e.outcome:
            outcomes[e.outcome] += 1
        if e.account:
            accounts[e.account] += 1
        computers[e.computer] += 1
        if is_failed_logon(e):
            summary.failed_logons += 1
            if e.account:
                failed_accounts[e.account] += 1
            origin = e.source_ip or e.workstation
            if origin:
                failed_sources[origin] += 1
                if e.account:
                    accounts_per_source[origin].add(e.account)

    summary.distinct_accounts = len(accounts)
    summary.by_event = sorted(
        ((i, n, s, c) for (i, n, s), c in by_event.items()), key=lambda r: (-r[3], r[0])
    )
    summary.by_category = _top(categories, 100)
    summary.outcomes = dict(outcomes)
    summary.top_accounts = _top(accounts, top_n)
    summary.top_computers = _top(computers, top_n)
    summary.top_failed_accounts = _top(failed_accounts, top_n)
    summary.top_failed_sources = _top(failed_sources, top_n)
    summary.timeline, summary.timeline_unit, summary.timeline_note = _timeline(events, tz)

    # ---- highlights: simple, documented heuristics (not alerts) --------------------
    notes: list[Highlight] = []
    latest_by_id: dict[int, SecurityEvent] = {}
    for e in events:
        current = latest_by_id.get(e.event_id)
        if current is None or e.time_utc > current.time_utc:
            latest_by_id[e.event_id] = e
    for (event_id, name, severity), count in sorted(by_event.items()):
        if severity_rank(severity) >= severity_rank("high"):
            latest = latest_by_id[event_id]
            actor = qualified(latest.subject_user, latest.subject_domain)
            by = f" by {actor}" if actor else ""
            notes.append(Highlight(
                severity,
                f"{count} x {name} (event {event_id}); most recent {format_time(latest.time_utc, tz)}{by}",
            ))
    for account, count in failed_accounts.items():
        if count >= failed_logon_threshold:
            notes.append(Highlight("medium", f"{count} failed logons for account {account}"))
    for source, count in failed_sources.items():
        distinct = len(accounts_per_source[source])
        if distinct >= failed_logon_threshold:
            notes.append(Highlight(
                "high",
                f"Possible password spraying: {count} failed logons from {source} across {distinct} accounts",
            ))
        elif count >= failed_logon_threshold:
            notes.append(Highlight("medium", f"{count} failed logons from {source}"))
    summary.highlights = sorted(notes, key=lambda h: (-severity_rank(h.severity), h.text))
    return summary
