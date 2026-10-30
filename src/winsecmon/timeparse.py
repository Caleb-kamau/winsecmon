"""Parsing of relative durations and ISO 8601 timestamps. All results are UTC-aware."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

_DURATION = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def parse_duration(text: str) -> timedelta:
    match = _DURATION.match(text or "")
    if not match:
        raise ValueError(
            f"invalid duration {text!r}; use a number and a unit, e.g. 30m, 24h, 7d, 2w"
        )
    amount = int(match.group(1))
    if amount <= 0:
        raise ValueError(f"invalid duration {text!r}; it must be greater than zero")
    try:
        return timedelta(**{_UNITS[match.group(2).lower()]: amount})
    except OverflowError:
        raise ValueError(f"invalid duration {text!r}; the value is too large") from None


def parse_datetime(text: str) -> datetime:
    """Parse ISO 8601. A timestamp without a zone is interpreted as local time."""
    try:
        parsed = datetime.fromisoformat(text.strip())
    except ValueError:
        raise ValueError(
            f"invalid date/time {text!r}; use ISO 8601, e.g. 2026-10-28, "
            "2026-10-28T14:30:00 (local time) or 2026-10-28T14:30:00Z (UTC)"
        ) from None
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()  # naive -> assume local time
    return parsed.astimezone(timezone.utc)


def resolve_range(
    *,
    since: str | None,
    start: str | None,
    end: str | None,
    default_lookback: timedelta | None,
    now: datetime | None = None,
) -> tuple[datetime | None, datetime | None]:
    """Turn CLI time options into (start, end) in UTC. Either may be None (open-ended)."""
    now = now or datetime.now(timezone.utc)
    if since and start:
        raise ValueError("use either --since or --start, not both")
    end_dt = parse_datetime(end) if end else None
    try:
        if since:
            start_dt: datetime | None = (end_dt or now) - parse_duration(since)
        elif start:
            start_dt = parse_datetime(start)
        elif default_lookback is not None:
            start_dt = (end_dt or now) - default_lookback
        else:
            start_dt = None
    except OverflowError:
        raise ValueError("the requested time range is out of bounds") from None
    if start_dt and end_dt and end_dt <= start_dt:
        raise ValueError("the end of the time range must be after its start")
    return start_dt, end_dt
