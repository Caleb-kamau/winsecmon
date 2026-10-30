"""Command-line interface."""

from __future__ import annotations

import argparse
import platform
import sys
from datetime import datetime, timezone, tzinfo
from pathlib import Path

from . import __version__
from .config import Config, default_config_text, load_config
from .errors import UsageError, WinSecMonError
from .export import export_events, open_output
from .filters import EventFilter
from .htmlreport import render_html
from .models import SEVERITIES
from .query import QueryOptions, QueryResult, run_query
from .reader import WindowsLogReader, powershell_path, wevtutil_path
from .summary import build_summary
from .textout import render_details, render_summary, render_table, safe_text
from .timeparse import resolve_range

AUDITPOL_HINT = (
    "If you expected events, check that the matching audit policy is enabled "
    "(read-only check: auditpol /get /category:*). winsecmon never changes audit policy."
)


# ------------------------------------------------------------------ argument parsing


def _split(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def _parents() -> tuple[argparse.ArgumentParser, argparse.ArgumentParser]:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", metavar="FILE", help="configuration file (TOML)")

    f = argparse.ArgumentParser(add_help=False)
    t = f.add_argument_group("time range (default: the config's default_lookback for the live log)")
    t.add_argument("--since", metavar="DURATION", help="only events from the last N, e.g. 30m, 24h, 7d, 2w")
    t.add_argument("--start", metavar="TIME", help="start of range, ISO 8601 (no zone = local time)")
    t.add_argument("--end", metavar="TIME", help="end of range, ISO 8601")
    g = f.add_argument_group("filters (repeat a flag or use commas for several values)")
    g.add_argument("--user", action="append", metavar="NAME", help="account name; DOMAIN\\user, * and ? wildcards allowed")
    g.add_argument("--computer", action="append", metavar="NAME", help="computer name; wildcards allowed")
    g.add_argument("--event-id", action="append", metavar="ID", help="event ID(s); overrides the config's event list")
    g.add_argument("--category", action="append", metavar="NAME", help="category from the config, e.g. authentication")
    g.add_argument("--severity", action="append", metavar="LEVEL", help=f"exact severity: {', '.join(SEVERITIES)}")
    g.add_argument("--min-severity", metavar="LEVEL", help="this severity and above")
    g.add_argument("--no-exclude", action="store_true", help="do not hide accounts listed in the config's exclude_users")
    s = f.add_argument_group("source (default: the live log on this computer)")
    src = s.add_mutually_exclusive_group()
    src.add_argument("--evtx", metavar="FILE", help="read an archived .evtx file (Windows only)")
    src.add_argument("--xml", metavar="FILE", help="read XML exported with `wevtutil qe ... /f:xml` (any OS)")
    s.add_argument("--backend", choices=("wevtutil", "powershell"), help="override the config's backend")
    s.add_argument("--max-events", type=int, metavar="N", help="read at most N events (default from config)")
    return common, f


def build_parser() -> argparse.ArgumentParser:
    common, filt = _parents()
    parser = argparse.ArgumentParser(
        prog="winsecmon",
        description="Read-only monitoring of the Windows Security event log.",
        epilog="Run `winsecmon check` first to verify permissions and the environment.",
    )
    parser.add_argument("--version", action="version", version=f"winsecmon {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("show", parents=[common, filt], help="list matching events")
    p.add_argument("--limit", type=int, default=50, metavar="N", help="events to display (default 50)")
    p.add_argument("--details", action="store_true", help="show every field of each event")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("summary", parents=[common, filt], help="dashboard of counts, top accounts and highlights")
    p.set_defaults(func=cmd_summary)

    p = sub.add_parser("report", parents=[common, filt], help="write a self-contained HTML report")
    p.add_argument("-o", "--output", default="winsecmon-report.html", metavar="FILE")
    p.add_argument("--force", action="store_true", help="overwrite the output file if it exists")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("export", parents=[common, filt], help="export matching events to CSV or JSON")
    p.add_argument("-o", "--output", required=True, metavar="FILE", help="output file, or - for stdout")
    p.add_argument("--format", choices=("csv", "json"), help="default: from the file extension")
    p.add_argument("--force", action="store_true", help="overwrite the output file if it exists")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("events", parents=[common], help="list the monitored event definitions")
    p.set_defaults(func=cmd_events)

    p = sub.add_parser("check", parents=[common], help="diagnose permissions, tools and configuration")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("init-config", help="write a sample configuration file")
    p.add_argument("path", nargs="?", default="winsecmon.toml")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init_config)
    return parser


# ------------------------------------------------------------------------- helpers


def display_tz(config: Config) -> tuple[tzinfo | None, str]:
    """(tzinfo, label). tzinfo None means the system's local zone."""
    if config.display_timezone == "utc":
        return timezone.utc, "UTC"
    return None, datetime.now().astimezone().tzname() or "local time"


def _validated(values: list[str], allowed: tuple[str, ...] | set[str], what: str) -> list[str]:
    for value in values:
        if value not in allowed:
            raise UsageError(f"Unknown {what} '{value}'. Valid values: {', '.join(sorted(allowed))}.")
    return values


def prepare(args: argparse.Namespace) -> tuple[Config, QueryOptions, str]:
    config_loaded = load_config(args.config)
    config = config_loaded.config
    source = "xml" if args.xml else "evtx" if args.evtx else "live"
    try:
        start, end = resolve_range(
            since=args.since, start=args.start, end=args.end,
            default_lookback=config.default_lookback if source == "live" else None,
        )
    except ValueError as exc:
        raise UsageError(str(exc)) from None

    try:
        event_ids = tuple(int(x) for x in _split(args.event_id))
    except ValueError:
        raise UsageError("--event-id must be whole numbers, e.g. --event-id 4624,4625") from None
    if any(not 0 < i <= 65535 for i in event_ids):
        raise UsageError("--event-id values must be between 1 and 65535")
    categories = {d.category for d in config.events.values()} | {"custom"}
    max_events = args.max_events
    if max_events is not None and not 1 <= max_events <= 200_000:
        raise UsageError("--max-events must be between 1 and 200000")
    min_sev = args.min_severity
    if min_sev:
        _validated([min_sev], SEVERITIES, "severity")

    flt = EventFilter(
        start=start, end=end,
        users=tuple(_split(args.user)), computers=tuple(_split(args.computer)),
        event_ids=event_ids,
        categories=frozenset(_validated([c.lower() for c in _split(args.category)], categories, "category")),
        severities=frozenset(_validated([s.lower() for s in _split(args.severity)], SEVERITIES, "severity")),
        min_severity=min_sev,
        exclude_users=() if args.no_exclude else config.exclude_users,
    )
    options = QueryOptions(
        filter=flt, source=source, source_path=args.xml or args.evtx,
        backend=args.backend, max_events=max_events, apply_exclusions=not args.no_exclude,
    )
    return config, options, config_loaded.source


def run(args: argparse.Namespace) -> tuple[Config, QueryResult]:
    config, options, _ = prepare(args)
    result = run_query(config, options)
    for warning in result.warnings:
        print(f"warning: {safe_text(warning)}", file=sys.stderr)
    return config, result


def _range_text(result: QueryResult, tz: tzinfo | None, label: str) -> str:
    from .summary import format_time

    f = result.filter
    start = format_time(f.start, tz, False) if f.start else "beginning"
    end = format_time(f.end, tz, False) if f.end else "now"
    return f"Source: {result.source_description}. Range: {start} to {end} ({label})."


# ------------------------------------------------------------------------ commands


def cmd_show(args: argparse.Namespace) -> int:
    config, result = run(args)
    tz, label = display_tz(config)
    events = result.events
    if not events:
        print("No matching events.")
        if result.source_description.startswith("live"):
            print(AUDITPOL_HINT)
        return 0
    limit = max(1, args.limit)
    print(f"{len(events)} matching event(s), newest first, times in {label}. Showing {min(limit, len(events))}.\n")
    if args.details:
        print("\n\n".join(render_details(e, tz) for e in events[:limit]))
    else:
        print(render_table(events[:limit], tz))
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    config, result = run(args)
    tz, label = display_tz(config)
    summary = build_summary(
        result.events, tz=tz, top_n=config.top_n, failed_logon_threshold=config.failed_logon_threshold
    )
    print(render_summary(summary, tz, config.report_title, _range_text(result, tz, label)))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    config, result = run(args)
    tz, label = display_tz(config)
    summary = build_summary(
        result.events, tz=tz, top_n=config.top_n, failed_logon_threshold=config.failed_logon_threshold
    )
    document = render_html(
        title=config.report_title, events=result.events, summary=summary, tz=tz, tz_label=label,
        source=result.source_description, filters=result.filter.describe(),
        warnings=result.warnings, max_rows=config.report_max_events,
    )
    with open_output(args.output, args.force, "utf-8") as handle:
        handle.write(document)
    print(f"Report written to {Path(args.output).resolve()} ({len(result.events)} events).")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    fmt = args.format
    if fmt is None:
        suffix = Path(args.output).suffix.lower()
        fmt = {".csv": "csv", ".json": "json"}.get(suffix)
        if fmt is None:
            raise UsageError("Cannot tell the format from the file name.", hint="Add --format csv or --format json.")
    _, result = run(args)
    export_events(
        result.events, fmt, args.output, force=args.force,
        query={**result.filter.describe(), "source": result.source_description},
        truncated=result.truncated,
    )
    destination = sys.stderr if args.output == "-" else sys.stdout
    where = "stdout" if args.output == "-" else str(Path(args.output).resolve())
    print(f"Exported {len(result.events)} event(s) as {fmt.upper()} to {where}.", file=destination)
    return 0


def cmd_events(args: argparse.Namespace) -> int:
    loaded = load_config(args.config)
    print(f"Configuration: {loaded.source}\n")
    print(f"{'ID':<6}{'ENABLED':<9}{'SEVERITY':<10}{'CATEGORY':<20}NAME")
    for d in sorted(loaded.config.events.values(), key=lambda d: (d.category, d.event_id)):
        print(f"{d.event_id:<6}{'yes' if d.enabled else 'no':<9}{d.severity:<10}{d.category:<20}{d.name}")
    return 0


def _is_elevated() -> str:
    if sys.platform != "win32":
        return "not applicable"
    try:
        import ctypes

        return "yes" if ctypes.windll.shell32.IsUserAnAdmin() else "no"  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - purely informational
        return "unknown"


def cmd_check(args: argparse.Namespace) -> int:
    loaded = load_config(args.config)
    config = loaded.config
    enabled = sum(d.enabled for d in config.events.values())
    print("winsecmon environment check\n")
    print(f"  Platform       : {platform.platform()}")
    print(f"  Python         : {platform.python_version()}")
    print(f"  Configuration  : {loaded.source} (valid; {enabled} of {len(config.events)} events enabled)")
    tool = wevtutil_path() if config.backend == "wevtutil" else powershell_path()
    print(f"  Backend        : {config.backend} -> {tool or 'NOT FOUND'}")
    print(f"  Elevated       : {_is_elevated()}")
    if sys.platform != "win32":
        print(f"  Log '{config.log_name}': cannot be read on this operating system")
        print("\nResult: live log reading needs Windows. XML exported with wevtutil can be analysed with --xml FILE.")
        return 4
    try:
        reader = WindowsLogReader(
            backend=config.backend, target=config.log_name, is_file=False,
            timeout=config.query_timeout_seconds, definitions=config.events,
        )
        sample = reader.read(None, None, None, 1)
    except WinSecMonError as exc:
        print(f"  Log '{config.log_name}': FAILED - {exc}")
        if exc.hint:
            print(f"\n{exc.hint}")
        return exc.exit_code
    print(f"  Log '{config.log_name}': readable ({len(sample.events)} sample event read)")
    print("\nResult: OK. " + AUDITPOL_HINT)
    return 0


def cmd_init_config(args: argparse.Namespace) -> int:
    with open_output(args.path, args.force, "utf-8") as handle:
        handle.write(default_config_text())
    print(f"Sample configuration written to {Path(args.path).resolve()}")
    return 0


# ---------------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")  # never crash on an unprintable character
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except WinSecMonError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if exc.hint:
            print(f"hint: {exc.hint}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
