"""Self-contained HTML report: no scripts, no external resources, every value escaped."""

from __future__ import annotations

import html
from datetime import datetime, timezone, tzinfo

from . import __version__
from .models import SEVERITIES, SecurityEvent
from .summary import Summary, format_time
from .textout import safe_text

_CSS = """
:root{--bg:#f3f5f7;--panel:#fff;--ink:#16202a;--muted:#5b6b79;--line:#d9e0e6;--accent:#1f5f7a;
--info:#6b7c8c;--low:#2f6fb0;--medium:#b7791f;--high:#c2410c;--critical:#a3122a;--bar:#1f5f7a}
@media (prefers-color-scheme:dark){:root{--bg:#10171d;--panel:#18222b;--ink:#e6edf3;--muted:#98a8b6;
--line:#2a3743;--accent:#6fb4d4;--info:#8fa1b2;--low:#6aa9e6;--medium:#e0a93f;--high:#f0803f;
--critical:#ff6b7f;--bar:#6fb4d4}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 20px 56px}
h1{font-size:1.7rem;margin:0 0 4px;font-weight:650;letter-spacing:-.01em}
h2{font-size:1.05rem;margin:32px 0 10px;font-weight:650}
.sub{color:var(--muted);margin:0}
.sub b{color:var(--ink);font-weight:600}
.facts{display:flex;flex-wrap:wrap;gap:6px 28px;margin:18px 0 0;padding:14px 0;border-block:1px solid var(--line)}
.facts div{min-width:110px}.facts dt{color:var(--muted);font-size:.85rem}.facts dd{margin:0;font-size:1.35rem;font-variant-numeric:tabular-nums;font-weight:600}
.attn{list-style:none;margin:0;padding:0;background:var(--panel);border:1px solid var(--line);border-radius:6px}
.attn li{display:flex;gap:12px;padding:10px 14px;border-top:1px solid var(--line)}
.attn li:first-child{border-top:0}
.none{color:var(--muted);background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:10px 14px;margin:0}
.chip{flex:none;min-width:4.6rem;text-align:center;font-size:.8rem;font-weight:650;border:1.5px solid currentColor;border-radius:4px;padding:1px 6px;height:1.55rem}
.s-info{color:var(--info)}.s-low{color:var(--low)}.s-medium{color:var(--medium)}.s-high{color:var(--high)}.s-critical{color:var(--critical)}
.stack{display:flex;height:16px;border-radius:4px;overflow:hidden;background:var(--line)}
.stack span{display:block;height:100%}
.bg-info{background:var(--info)}.bg-low{background:var(--low)}.bg-medium{background:var(--medium)}.bg-high{background:var(--high)}.bg-critical{background:var(--critical)}
.legend{display:flex;flex-wrap:wrap;gap:4px 18px;margin:8px 0 0;font-size:.9rem;font-variant-numeric:tabular-nums}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:4px 32px}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--muted);font-size:.85rem}
td.n,th.n{text-align:right;white-space:nowrap}
.meter{display:block;height:8px;border-radius:2px;background:var(--bar);min-width:2px}
.wrap{overflow-x:auto}
.tl{display:flex;align-items:flex-end;gap:2px;height:96px;padding-top:4px;border-bottom:1px solid var(--line)}
.tl span{flex:1;min-width:2px;background:var(--bar);border-radius:2px 2px 0 0}
.tl span.z{background:transparent}
.axis{display:flex;justify-content:space-between;color:var(--muted);font-size:.8rem;margin-top:4px}
details summary{cursor:pointer;list-style:none}
details summary::-webkit-details-marker{display:none}
details[open] summary{font-weight:600}
dl.raw{display:grid;grid-template-columns:max-content 1fr;gap:2px 14px;margin:8px 0 4px;font-size:.88rem}
dl.raw dt{color:var(--muted)}dl.raw dd{margin:0;overflow-wrap:anywhere}
.mono{font-family:Consolas,"Cascadia Mono",monospace;font-size:.9em}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
footer{margin-top:40px;color:var(--muted);font-size:.85rem}
@media print{body{background:#fff}.chip{border-width:1px}}
"""


def _e(value: object) -> str:
    return html.escape(safe_text(value), quote=True)


def _ranked_table(title: str, rows: list[tuple[str, int]], head: str) -> str:
    if not rows:
        return ""
    peak = max(n for _, n in rows)
    body = "".join(
        f'<tr><td>{_e(label)}</td><td class="n">{count}</td>'
        f'<td style="width:34%"><span class="meter" style="width:{max(2, round(100 * count / peak))}%"></span></td></tr>'
        for label, count in rows
    )
    return (
        f"<section><h2>{_e(title)}</h2><div class=\"wrap\"><table>"
        f"<thead><tr><th>{_e(head)}</th><th class=\"n\">Events</th><th></th></tr></thead>"
        f"<tbody>{body}</tbody></table></div></section>"
    )


_FILTER_LABELS = {
    "start_utc": "From", "end_utc": "To", "users": "Accounts", "computers": "Computers",
    "event_ids": "Event IDs", "categories": "Categories", "severities": "Severity",
    "min_severity": "Minimum severity", "exclude_users": "Hidden accounts",
}


def _describe_filters(filters: dict[str, object], tz: tzinfo | None, tz_label: str) -> list[str]:
    parts = []
    for key, value in filters.items():
        if value in (None, [], "", False):
            continue
        if key in ("start_utc", "end_utc"):
            moment = datetime.fromisoformat(str(value))
            shown = f"{format_time(moment, tz, with_seconds=False)} ({tz_label})"
        else:
            shown = ", ".join(map(str, value)) if isinstance(value, list) else str(value)
        parts.append(f"<b>{_e(_FILTER_LABELS.get(key, key))}</b> {_e(shown)}")
    return parts


def render_html(
    *,
    title: str,
    events: list[SecurityEvent],
    summary: Summary,
    tz: tzinfo | None,
    tz_label: str,
    source: str,
    filters: dict[str, object],
    warnings: list[str],
    max_rows: int,
) -> str:
    generated = datetime.now(timezone.utc).astimezone(tz)
    active = _describe_filters(filters, tz, tz_label)
    span = (
        f"{_e(format_time(summary.first_time, tz))} to {_e(format_time(summary.last_time, tz))} ({_e(tz_label)})"
        if summary.first_time and summary.last_time else "no events in range"
    )
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta name="referrer" content="no-referrer">',
        f"<title>{_e(title)}</title><style>{_CSS}</style></head><body><main>",
        f"<h1>{_e(title)}</h1>",
        f'<p class="sub">Source: {_e(source)}. Events from {span}.</p>',
        f'<p class="sub">Filters: {" &middot; ".join(active) if active else "none beyond the monitored event list"}</p>',
        '<dl class="facts">'
        f"<div><dt>Events</dt><dd>{summary.total}</dd></div>"
        f"<div><dt>High or critical</dt><dd>{summary.by_severity['high'] + summary.by_severity['critical']}</dd></div>"
        f"<div><dt>Failed logons</dt><dd>{summary.failed_logons}</dd></div>"
        f"<div><dt>Accounts seen</dt><dd>{summary.distinct_accounts}</dd></div></dl>",
    ]
    for warning in warnings:
        parts.append(f'<p class="sub">Note: {_e(warning)}</p>')

    parts.append("<section><h2>Needs attention</h2>")
    if summary.highlights:
        items = "".join(
            f'<li><span class="chip s-{h.severity}">{h.severity}</span><span>{_e(h.text)}</span></li>'
            for h in summary.highlights
        )
        parts.append(f'<ul class="attn">{items}</ul>')
    else:
        parts.append('<p class="none">Nothing crossed the high-severity or failed-logon thresholds in this range.</p>')
    parts.append("</section>")

    if summary.total:
        total = summary.total
        stack = "".join(
            f'<span class="bg-{s}" style="width:{100 * summary.by_severity[s] / total:.2f}%" '
            f'title="{s}: {summary.by_severity[s]}"></span>'
            for s in SEVERITIES if summary.by_severity[s]
        )
        legend = "".join(
            f'<span><i class="bg-{s}"></i>{s} {summary.by_severity[s]}</span>' for s in reversed(SEVERITIES)
        )
        parts.append(f'<section><h2>Severity</h2><div class="stack" role="img" aria-label="Events by severity">{stack}</div><div class="legend">{legend}</div></section>')

        peak = max(n for _, n in summary.timeline)
        bars = "".join(
            f'<span class="{"z" if n == 0 else ""}" style="height:{max(3, round(100 * n / peak))}%" '
            f'title="{_e(label)}: {n}"></span>'
            for label, n in summary.timeline
        )
        unit = "hour" if summary.timeline_unit == "hour" else "day"
        parts.append(
            f'<section><h2>Activity by {unit}</h2><div class="tl" role="img" aria-label="Events over time">{bars}</div>'
            f'<div class="axis"><span>{_e(summary.timeline[0][0])}</span><span>{_e(summary.timeline[-1][0])}</span></div>'
            + (f'<p class="sub">{_e(summary.timeline_note)}</p>' if summary.timeline_note else "")
            + "</section>"
        )

        by_event_rows = "".join(
            f'<tr><td class="mono">{i}</td><td>{_e(n)}</td><td><span class="s-{s}">{s}</span></td><td class="n">{c}</td></tr>'
            for i, n, s, c in summary.by_event
        )
        parts.append(
            '<section><h2>By event ID</h2><div class="wrap"><table><thead><tr><th>ID</th><th>Event</th>'
            f'<th>Severity</th><th class="n">Events</th></tr></thead><tbody>{by_event_rows}</tbody></table></div></section>'
        )
        parts.append('<div class="cols">')
        parts.append(_ranked_table("Top accounts", summary.top_accounts, "Account"))
        parts.append(_ranked_table("Top computers", summary.top_computers, "Computer"))
        parts.append(_ranked_table("Failed logons by account", summary.top_failed_accounts, "Account"))
        parts.append(_ranked_table("Failed logons by source", summary.top_failed_sources, "Address"))
        parts.append("</div>")

        rows = []
        for e in events[:max_rows]:
            raw = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in e.data.items())
            rows.append(
                f'<tr><td class="mono">{_e(format_time(e.time_utc, tz))}</td><td class="mono">{e.event_id}</td>'
                f'<td><span class="s-{e.severity}">{e.severity}</span></td><td>{_e(e.computer)}</td>'
                f'<td>{_e(e.account or "-")}</td>'
                f'<td><details><summary>{_e(e.message)}</summary><dl class="raw">{raw}</dl></details></td></tr>'
            )
        note = f" (newest {max_rows} of {len(events)})" if len(events) > max_rows else ""
        parts.append(
            f'<section><h2>Events{note}</h2><div class="wrap"><table><thead><tr><th>Time</th><th>ID</th><th>Severity</th>'
            f'<th>Computer</th><th>Account</th><th>Details</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div></section>'
        )

    parts.append(
        f"<footer>Generated {_e(format_time(generated, tz))} ({_e(tz_label)}) by winsecmon {__version__}. "
        "This file contains account names, addresses and other sensitive log data: store and share it accordingly.</footer>"
        "</main></body></html>"
    )
    return "".join(parts)
