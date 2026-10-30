"""Glue: read events from the chosen source, then filter them."""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import Config
from .filters import EventFilter
from .models import SecurityEvent
from .reader import Runner, WindowsLogReader, XmlFileReader, run_command


@dataclass(frozen=True)
class QueryOptions:
    filter: EventFilter
    source: str = "live"  # "live" | "evtx" | "xml"
    source_path: str | None = None
    backend: str | None = None
    max_events: int | None = None
    apply_exclusions: bool = True


@dataclass
class QueryResult:
    events: list[SecurityEvent] = field(default_factory=list)  # newest first
    warnings: list[str] = field(default_factory=list)
    total_read: int = 0
    malformed_count: int = 0
    truncated: bool = False
    excluded_count: int = 0
    source_description: str = ""
    filter: EventFilter = field(default_factory=EventFilter)
    max_events: int = 0


def run_query(
    config: Config,
    options: QueryOptions,
    *,
    runner: Runner = run_command,
    require_windows: bool = True,
) -> QueryResult:
    flt = options.filter
    max_events = options.max_events or config.max_events
    result = QueryResult(filter=flt, max_events=max_events)

    ids = flt.select_event_ids(config.events)
    backend = options.backend or config.backend

    if options.source == "xml":
        reader: WindowsLogReader | XmlFileReader = XmlFileReader(options.source_path or "", config.events)
        result.source_description = f"XML export {options.source_path}"
    elif options.source == "evtx":
        reader = WindowsLogReader(
            backend=backend, target=options.source_path or "", is_file=True,
            timeout=config.query_timeout_seconds, definitions=config.events,
            runner=runner, require_windows=require_windows,
        )
        result.source_description = f"EVTX file {options.source_path}"
    else:
        reader = WindowsLogReader(
            backend=backend, target=config.log_name, is_file=False,
            timeout=config.query_timeout_seconds, definitions=config.events,
            runner=runner, require_windows=require_windows,
        )
        result.source_description = f"live '{config.log_name}' log"

    if not ids:
        result.warnings.append(
            "No event IDs are selected. Enable events in the config, or relax --category/--severity/--event-id."
        )
        return result

    read = reader.read(ids, flt.start, flt.end, max_events)
    result.total_read = len(read.events)
    result.malformed_count = len(read.malformed)
    result.truncated = read.truncated
    if read.malformed:
        shown = "; ".join(read.malformed[:3])
        more = f" (+{len(read.malformed) - 3} more)" if len(read.malformed) > 3 else ""
        result.warnings.append(
            f"Skipped {len(read.malformed)} malformed event(s): {shown}{more}"
        )

    wanted = set(ids)
    kept = [e for e in read.events if e.event_id in wanted and flt.matches(e)]
    if options.apply_exclusions and flt.exclude_users:
        visible = [e for e in kept if not flt.is_excluded(e)]
        result.excluded_count = len(kept) - len(visible)
        kept = visible
    if len(kept) > max_events:
        kept = kept[:max_events]
        result.truncated = True
    result.events = kept

    if result.truncated:
        result.warnings.append(
            f"Result limit of {max_events} events reached; older events were not read. "
            "Narrow the time range or filters, or raise --max-events."
        )
    if result.excluded_count:
        result.warnings.append(
            f"{result.excluded_count} event(s) hidden by exclude_users in the config (use --no-exclude to show them)."
        )
    return result
