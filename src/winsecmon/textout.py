"""Plain-text (ASCII-only) rendering for the terminal."""

from __future__ import annotations

import shutil
from datetime import tzinfo

from .models import SEVERITIES, SecurityEvent
from .summary import Summary, format_time


def safe_text(value: object) -> str:
    """Make untrusted text safe to print: control characters (including ANSI escape
    sequences that could rewrite the terminal) are shown as visible escapes."""
    text = "" if value is None else str(value)
    out = []
    for char in text:
        if char.isprintable():
            out.append(char)
        elif ord(char) <= 0xFF:
            out.append(f"\\x{ord(char):02x}")
        else:
            out.append(f"\\u{ord(char):04x}")
    return "".join(out)


def _fit(text: str, width: int) -> str:
    text = safe_text(text)
    if len(text) <= width:
        return text.ljust(width)
    return text[: max(width - 3, 0)] + "..." if width > 3 else text[:width]


def bar(value: int, maximum: int, width: int = 30) -> str:
    if maximum <= 0 or value <= 0:
        return ""
    return "#" * max(1, round(width * value / maximum))


def render_table(events: list[SecurityEvent], tz: tzinfo | None, width: int | None = None) -> str:
    width = width or shutil.get_terminal_size((120, 24)).columns
    computer_w = min(max((len(safe_text(e.computer)) for e in events), default=8), 18)
    account_w = min(max((len(safe_text(e.account or "-")) for e in events), default=7), 26)
    fixed = 19 + 5 + 8 + computer_w + account_w + 5 * 2
    message_w = max(24, width - fixed)
    header = "  ".join(
        [_fit("TIME", 19), _fit("ID", 5), _fit("SEVERITY", 8), _fit("COMPUTER", computer_w),
         _fit("ACCOUNT", account_w), "MESSAGE"]
    )
    lines = [header, "-" * min(len(header) + message_w - 7, width)]
    for e in events:
        lines.append("  ".join([
            format_time(e.time_utc, tz), _fit(str(e.event_id), 5), _fit(e.severity, 8),
            _fit(e.computer, computer_w), _fit(e.account or "-", account_w),
            _fit(e.message, message_w).rstrip(),
        ]))
    return "\n".join(lines)


def render_details(event: SecurityEvent, tz: tzinfo | None) -> str:
    lines = [
        f"[{format_time(event.time_utc, tz)}] Event {event.event_id}: {safe_text(event.name)}",
        f"  Severity : {event.severity}   Category: {event.category}"
        + (f"   Outcome: {event.outcome}" if event.outcome else ""),
        f"  Computer : {safe_text(event.computer)}",
        f"  Summary  : {safe_text(event.message)}",
    ]
    rows = [
        ("Account", event.account),
        ("Subject", _pair(event.subject_domain, event.subject_user)),
        ("Target", _pair(event.target_domain, event.target_user)),
        ("Object", event.object_name),
        ("Logon type", f"{event.logon_type} ({event.logon_type_name})" if event.logon_type is not None and event.logon_type_name else event.logon_type),
        ("Source IP", event.source_ip),
        ("Workstation", event.workstation),
        ("Process", event.process_name),
        ("Status", event.status),
        ("Record ID", event.record_id),
        ("Provider", event.provider),
    ]
    for label, value in rows:
        if value not in (None, ""):
            lines.append(f"  {label:<11}: {safe_text(value)}")
    if event.data:
        lines.append("  Raw fields:")
        for key, value in event.data.items():
            lines.append(f"    {safe_text(key)} = {safe_text(value)[:300]}")
    return "\n".join(lines)


def _pair(domain: str | None, user: str | None) -> str | None:
    if not user:
        return None
    return f"{domain}\\{user}" if domain else user


def _ranked(title: str, rows: list[tuple[str, int]], label_w: int = 34) -> list[str]:
    if not rows:
        return []
    peak = max(n for _, n in rows)
    out = ["", title]
    for label, count in rows:
        out.append(f"  {_fit(label, label_w)} {count:>6}  {bar(count, peak, 24)}")
    return out


def render_summary(summary: Summary, tz: tzinfo | None, title: str, context: str) -> str:
    lines = [title, "=" * len(title), context]
    if summary.total == 0:
        lines += ["", "No matching events."]
        return "\n".join(lines)
    lines += [
        "",
        f"Events: {summary.total}   Accounts seen: {summary.distinct_accounts}   "
        f"Failed logons: {summary.failed_logons}",
        f"First: {format_time(summary.first_time, tz)}   Last: {format_time(summary.last_time, tz)}"
        if summary.first_time and summary.last_time else "",
    ]
    if summary.highlights:
        lines += ["", "Needs attention"]
        for h in summary.highlights:
            lines.append(f"  [{h.severity.upper():<8}] {safe_text(h.text)}")
    peak = max(summary.by_severity.values())
    lines += ["", "By severity"]
    for sev in reversed(SEVERITIES):
        n = summary.by_severity[sev]
        lines.append(f"  {sev:<9}{n:>7}  {bar(n, peak, 30)}")
    events_peak = summary.by_event[0][3]
    lines += ["", "By event ID"]
    for event_id, name, severity, count in summary.by_event:
        lines.append(
            f"  {event_id:<6}{_fit(name, 34)} {severity:<9}{count:>6}  {bar(count, events_peak, 20)}"
        )
    lines += _ranked("By category", summary.by_category)
    lines += _ranked("Top accounts", summary.top_accounts)
    lines += _ranked("Top computers", summary.top_computers)
    lines += _ranked("Failed logons by account", summary.top_failed_accounts)
    lines += _ranked("Failed logons by source address", summary.top_failed_sources)
    if summary.timeline:
        unit = summary.timeline_unit
        lines += ["", f"Timeline by {unit}" + (f" - {summary.timeline_note}" if summary.timeline_note else "")]
        peak_t = max(n for _, n in summary.timeline)
        for label, count in summary.timeline:
            lines.append(f"  {label:<17}{count:>6}  {bar(count, peak_t, 30)}")
    return "\n".join(line for line in lines if line is not None)
