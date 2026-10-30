"""CSV and JSON export. Output files are never overwritten unless --force is given."""

from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

from . import __version__
from .errors import OutputError
from .models import RECORD_FIELDS, SecurityEvent

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def neutralise_formula(value: str) -> str:
    """Event fields can contain attacker-chosen text (a failed logon records whatever user name
    was typed). Spreadsheet programs run cells that start with = + - @ as formulas, so such cells
    are prefixed with an apostrophe in CSV output."""
    return "'" + value if value.startswith(_FORMULA_PREFIXES) else value


def open_output(path: str, force: bool, encoding: str) -> IO[str]:
    target = Path(path)
    if not target.parent.exists():
        raise OutputError(f"The folder for the output file does not exist: {target.parent}")
    try:
        return target.open("w" if force else "x", encoding=encoding, newline="")
    except FileExistsError:
        raise OutputError(
            f"{target} already exists; nothing was written.", hint="Choose another name or pass --force."
        ) from None
    except OSError as exc:
        raise OutputError(f"Cannot write {target}: {exc.strerror or exc}") from None


def _csv_cell(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return neutralise_formula(value) if isinstance(value, str) else value


def write_csv(events: list[SecurityEvent], handle: IO[str]) -> None:
    writer = csv.writer(handle, lineterminator="\r\n")
    writer.writerow(RECORD_FIELDS)
    for event in events:
        record = event.to_record()
        writer.writerow([_csv_cell(record[name]) for name in RECORD_FIELDS])


def write_json(
    events: list[SecurityEvent], handle: IO[str], *, query: dict[str, object], truncated: bool
) -> None:
    document = {
        "tool": f"winsecmon {__version__}",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "query": query,
        "count": len(events),
        "truncated": truncated,
        "events": [event.to_record() for event in events],
    }
    json.dump(document, handle, ensure_ascii=False, indent=2)
    handle.write("\n")


def export_events(
    events: list[SecurityEvent],
    fmt: str,
    output: str,
    *,
    force: bool,
    query: dict[str, object],
    truncated: bool,
) -> None:
    if output == "-":
        if fmt == "csv":
            write_csv(events, sys.stdout)
        else:
            write_json(events, sys.stdout, query=query, truncated=truncated)
        return
    handle = open_output(output, force, "utf-8-sig" if fmt == "csv" else "utf-8")  # BOM: Excel
    with handle:
        if fmt == "csv":
            write_csv(events, handle)
        else:
            write_json(events, handle, query=query, truncated=truncated)
