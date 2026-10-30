"""Read-only access to Windows event logs.

Two backends are supported, both of which are built into Windows and only ever READ:
  * wevtutil.exe  (`wevtutil qe`)                       - default
  * PowerShell    (`Get-WinEvent -FilterXPath ...`)

Commands are run without a shell, with arguments passed as a list, so nothing taken from
the configuration or the command line can be interpreted as shell syntax. Tools are located
under %SystemRoot%\\System32 first, not via PATH.
"""

from __future__ import annotations

import codecs
import locale
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

from .errors import (
    LogUnavailableError,
    PermissionDeniedError,
    QueryError,
    UnsupportedPlatformError,
    UsageError,
)
from .models import EventDefinition, SecurityEvent
from .parser import parse_events_from_text

# Windows limits the complexity of an XPath filter, so large ID lists are split into
# several queries and merged.
CHUNK_SIZE = 12
MAX_XML_FILE_BYTES = 256 * 1024 * 1024
_LOG_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _./-]{0,127}$")


class CommandResult(NamedTuple):
    returncode: int
    stdout: bytes
    stderr: bytes


Runner = Callable[[Sequence[str], float], CommandResult]


@dataclass
class ReadResult:
    events: list[SecurityEvent] = field(default_factory=list)
    malformed: list[str] = field(default_factory=list)
    truncated: bool = False  # the read cap was hit, so older events may be missing
    queries_run: int = 0


# --------------------------------------------------------------------------- helpers


def _system32_tool(*parts: str) -> str | None:
    root = os.environ.get("SystemRoot") or os.environ.get("windir")
    if root:
        candidate = Path(root, "System32", *parts)
        if candidate.is_file():
            return str(candidate)
    return None


def wevtutil_path() -> str | None:
    return _system32_tool("wevtutil.exe") or shutil.which("wevtutil")


def powershell_path() -> str | None:
    return _system32_tool("WindowsPowerShell", "v1.0", "powershell.exe") or shutil.which("powershell")


def decode_output(data: bytes) -> str:
    if data.startswith(codecs.BOM_UTF8):
        return data[3:].decode("utf-8", errors="replace")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode(locale.getpreferredencoding(False), errors="replace")


def run_command(argv: Sequence[str], timeout: float) -> CommandResult:
    try:
        done = subprocess.run(  # noqa: S603 - fixed executable, list args, no shell
            list(argv), capture_output=True, timeout=timeout, check=False, stdin=subprocess.DEVNULL
        )
    except FileNotFoundError:
        raise LogUnavailableError(f"Required Windows tool not found: {argv[0]}") from None
    except subprocess.TimeoutExpired:
        raise QueryError(
            f"The Windows query did not finish within {timeout:.0f} seconds.",
            hint="Narrow the time range or event IDs, or raise query_timeout_seconds in the config.",
        ) from None
    except OSError as exc:
        raise QueryError(f"Could not start {argv[0]}: {exc.strerror or exc}") from None
    return CommandResult(done.returncode, done.stdout, done.stderr)


def build_xpath(event_ids: Sequence[int] | None, start: datetime | None, end: datetime | None) -> str:
    """Build an event-log XPath filter. Only integers and formatted timestamps are inserted."""
    conditions: list[str] = []
    if event_ids:
        conditions.append("(" + " or ".join(f"EventID={int(i)}" for i in event_ids) + ")")
    times: list[str] = []
    if start:
        times.append(f"@SystemTime>='{_xpath_time(start)}'")
    if end:
        times.append(f"@SystemTime<='{_xpath_time(end)}'")
    if times:
        conditions.append("TimeCreated[" + " and ".join(times) + "]")
    return "*[System[" + " and ".join(conditions) + "]]" if conditions else "*"


def _xpath_time(value: datetime) -> str:
    utc = value.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def classify_failure(returncode: int, stderr: str, stdout: str, target: str) -> Exception:
    """Map a failed wevtutil / PowerShell run to a specific, actionable error."""
    text = f"{stderr}\n{stdout}".lower()
    first_line = next((ln.strip() for ln in (stderr or stdout).splitlines() if ln.strip()), "")
    if returncode == 5 or "access is denied" in text or "unauthorized operation" in text:
        return PermissionDeniedError(
            f"Access denied reading the '{target}' log.",
            hint=(
                "Reading the Security log needs an elevated (Run as administrator) prompt, or an account "
                "in the 'Event Log Readers' group (a local administrator is not needed for that). "
                "winsecmon never changes permissions for you."
            ),
        )
    if (
        returncode in (2, 3, 15007)
        or "not an event log" in text
        or "could not be found" in text
        or "cannot find" in text
        or "channel" in text and "not found" in text
        or "no such" in text
    ):
        return LogUnavailableError(
            f"The log or file '{target}' is not available: {first_line or 'not found'}",
            hint="Check log_name in the config (`wevtutil el` lists channels) or the file path, "
            "and that the Windows Event Log service is running.",
        )
    if returncode == 15001 or "query is invalid" in text or "invalid query" in text:
        return QueryError(f"Windows rejected the query: {first_line}")
    return QueryError(
        f"The Windows tool failed (exit code {returncode}): {first_line or 'no error text'}",
        hint="Run `winsecmon check` to diagnose the environment.",
    )


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


# ------------------------------------------------------------------------ live / evtx


class WindowsLogReader:
    """Reads a live channel (e.g. Security) or an archived .evtx file."""

    def __init__(
        self,
        *,
        backend: str,
        target: str,
        is_file: bool,
        timeout: float,
        definitions: Mapping[int, EventDefinition],
        runner: Runner = run_command,
        require_windows: bool = True,
    ) -> None:
        self._backend = backend
        self._target = target
        self._is_file = is_file
        self._timeout = timeout
        self._definitions = definitions
        self._runner = runner
        self._require_windows = require_windows
        if is_file:
            path = Path(target)
            if not path.is_file():
                raise LogUnavailableError(f"Log file not found: {target}")
            self._target = str(path.resolve())  # absolute, so it can never look like an option
        elif not _LOG_NAME.match(target):
            raise UsageError(f"Unsupported log name: {target!r}")

    def _tool(self) -> str:
        if self._backend == "wevtutil":
            path = wevtutil_path()
            name = "wevtutil.exe"
        else:
            path = powershell_path()
            name = "powershell.exe"
        if path:
            return path
        if not self._require_windows:
            return name
        raise LogUnavailableError(
            f"{name} was not found.", hint="winsecmon needs a Windows system with the built-in tools."
        )

    def argv(self, xpath: str, max_events: int) -> list[str]:
        tool = self._tool()
        if self._backend == "wevtutil":
            command = [tool, "qe", self._target, f"/q:{xpath}", "/f:xml", "/rd:true", f"/c:{max_events}"]
            if self._is_file:
                command.append("/lf:true")
            return command
        source = f"-Path {_ps_quote(self._target)}" if self._is_file else f"-LogName {_ps_quote(self._target)}"
        script = (
            "$ErrorActionPreference='Stop';"
            "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
            "try{"
            f"Get-WinEvent {source} -FilterXPath {_ps_quote(xpath)} -MaxEvents {max_events}"
            " | ForEach-Object { $_.ToXml() }"
            "}catch{"
            "if($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*'){exit 0};"
            "[Console]::Error.WriteLine($_.Exception.Message);exit 1}"
        )
        return [tool, "-NoProfile", "-NonInteractive", "-Command", script]

    def read(
        self,
        event_ids: Sequence[int] | None,
        start: datetime | None,
        end: datetime | None,
        max_events: int,
    ) -> ReadResult:
        if self._require_windows and sys.platform != "win32":
            raise UnsupportedPlatformError(
                "Reading Windows event logs requires Windows.",
                hint="On other systems, analyse a wevtutil XML export with --xml FILE.",
            )
        chunks: list[Sequence[int] | None] = (
            [event_ids[i : i + CHUNK_SIZE] for i in range(0, len(event_ids), CHUNK_SIZE)]
            if event_ids
            else [None]
        )
        result = ReadResult()
        seen: set[tuple[str, str, int]] = set()
        for chunk in chunks:
            xpath = build_xpath(chunk, start, end)
            outcome = self._runner(self.argv(xpath, max_events), self._timeout)
            result.queries_run += 1
            stdout, stderr = decode_output(outcome.stdout), decode_output(outcome.stderr)
            if outcome.returncode != 0:
                raise classify_failure(outcome.returncode, stderr, stdout, self._target)
            events, problems, blocks = parse_events_from_text(stdout, self._definitions)
            result.malformed.extend(problems)
            if blocks >= max_events:
                result.truncated = True
            for event in events:
                if event.record_id is not None:
                    key = (event.computer, event.channel, event.record_id)
                    if key in seen:
                        continue
                    seen.add(key)
                result.events.append(event)
        result.events.sort(key=lambda e: (e.time_utc, e.record_id or 0), reverse=True)
        if len(result.events) > max_events:
            del result.events[max_events:]
            result.truncated = True
        return result


# ----------------------------------------------------------------------- XML export


class XmlFileReader:
    """Reads event XML previously exported with `wevtutil qe ... /f:xml`. Works on any OS."""

    def __init__(self, path: str, definitions: Mapping[int, EventDefinition]) -> None:
        self._path = Path(path)
        self._definitions = definitions
        if not self._path.is_file():
            raise LogUnavailableError(f"XML file not found: {path}")

    def read(
        self,
        event_ids: Sequence[int] | None,
        start: datetime | None,
        end: datetime | None,
        max_events: int,
    ) -> ReadResult:
        try:
            size = self._path.stat().st_size
            if size > MAX_XML_FILE_BYTES:
                raise QueryError(
                    f"{self._path} is {size // (1024 * 1024)} MiB; the limit is "
                    f"{MAX_XML_FILE_BYTES // (1024 * 1024)} MiB.",
                    hint="Export a narrower time range or fewer event IDs.",
                )
            text = decode_output(self._path.read_bytes())
        except PermissionError:
            raise PermissionDeniedError(f"Permission denied reading {self._path}.") from None
        except OSError as exc:
            raise LogUnavailableError(f"Cannot read {self._path}: {exc.strerror or exc}") from None
        events, problems, _ = parse_events_from_text(text, self._definitions)
        events.sort(key=lambda e: (e.time_utc, e.record_id or 0), reverse=True)
        return ReadResult(events=events, malformed=problems, truncated=False, queries_run=1)
