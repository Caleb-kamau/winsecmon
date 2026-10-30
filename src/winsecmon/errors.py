"""Exception types. Each carries a process exit code and an optional hint."""

from __future__ import annotations


class WinSecMonError(Exception):
    """Base class for errors that should be shown to the user without a traceback."""

    exit_code = 1

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


class UsageError(WinSecMonError):
    exit_code = 2


class ConfigError(WinSecMonError):
    exit_code = 2


class PermissionDeniedError(WinSecMonError):
    exit_code = 3


class LogUnavailableError(WinSecMonError):
    exit_code = 4


class UnsupportedPlatformError(WinSecMonError):
    exit_code = 4


class QueryError(WinSecMonError):
    exit_code = 5


class OutputError(WinSecMonError):
    exit_code = 6


class MalformedEventError(ValueError):
    """A single event could not be parsed. Handled per event, never fatal."""
