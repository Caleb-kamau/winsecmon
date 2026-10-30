"""Configuration loading and validation.

Configuration is TOML, kept entirely outside the code. Unknown keys are rejected so a typo
cannot silently disable a setting.
"""

from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from importlib import resources
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .models import SEVERITIES, EventDefinition
from .timeparse import parse_duration

BACKENDS = ("wevtutil", "powershell")
TIMEZONES = ("local", "utc")

_SECTION_KEYS: dict[str, set[str]] = {
    "general": {
        "log_name", "backend", "default_lookback", "max_events",
        "query_timeout_seconds", "display_timezone",
    },
    "filters": {"exclude_users"},
    "summary": {"top_n", "failed_logon_threshold"},
    "report": {"title", "max_events_shown"},
}
_EVENT_KEYS = {"id", "name", "category", "severity", "enabled", "description"}
_LOG_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _./-]{0,127}$")
_CATEGORY = re.compile(r"^[a-z0-9_]{1,40}$")


@dataclass(frozen=True)
class Config:
    log_name: str
    backend: str
    default_lookback: timedelta
    max_events: int
    query_timeout_seconds: int
    display_timezone: str
    exclude_users: tuple[str, ...]
    top_n: int
    failed_logon_threshold: int
    report_title: str
    report_max_events: int
    events: dict[int, EventDefinition]


@dataclass(frozen=True)
class LoadedConfig:
    config: Config
    source: str  # file path or "built-in defaults"


def default_config_text() -> str:
    return resources.files("winsecmon").joinpath("default_config.toml").read_text(encoding="utf-8")


def discover_config_path(
    explicit: str | None, env: Mapping[str, str] | None = None, cwd: Path | None = None
) -> Path | None:
    env = os.environ if env is None else env
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise ConfigError(f"Config file not found: {path}")
        return path
    from_env = env.get("WINSECMON_CONFIG")
    if from_env:
        path = Path(from_env)
        if not path.is_file():
            raise ConfigError(f"WINSECMON_CONFIG points to a file that does not exist: {path}")
        return path
    local = (cwd or Path.cwd()) / "winsecmon.toml"
    if local.is_file():
        return local
    appdata = env.get("APPDATA")
    if appdata:
        candidate = Path(appdata) / "winsecmon" / "winsecmon.toml"
        if candidate.is_file():
            return candidate
    return None


def load_config(explicit: str | None = None, env: Mapping[str, str] | None = None) -> LoadedConfig:
    defaults = tomllib.loads(default_config_text())
    path = discover_config_path(explicit, env)
    if path is None:
        return LoadedConfig(parse_config(defaults, "built-in defaults"), "built-in defaults")
    try:
        with path.open("rb") as handle:
            user = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from None
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read config file: {exc.strerror or exc}") from None
    return LoadedConfig(parse_config(_merge(defaults, user, str(path)), str(path)), str(path))


def _merge(defaults: dict[str, Any], user: dict[str, Any], origin: str) -> dict[str, Any]:
    for key in user:
        if key not in _SECTION_KEYS and key != "events":
            raise ConfigError(
                f"{origin}: unknown top-level key or section '{key}'. "
                f"Valid sections: {', '.join([*_SECTION_KEYS, 'events'])}."
            )
    merged: dict[str, Any] = {}
    for section in _SECTION_KEYS:
        values = user.get(section, {})
        if not isinstance(values, dict):
            raise ConfigError(f"{origin}: '{section}' must be a table, e.g. [{section}]")
        unknown = set(values) - _SECTION_KEYS[section]
        if unknown:
            raise ConfigError(
                f"{origin}: unknown key '{sorted(unknown)[0]}' in [{section}]. "
                f"Valid keys: {', '.join(sorted(_SECTION_KEYS[section]))}."
            )
        merged[section] = {**defaults.get(section, {}), **values}
    merged["events"] = user["events"] if "events" in user else defaults["events"]
    return merged


def _int(section: dict[str, Any], key: str, low: int, high: int, origin: str, where: str) -> int:
    value = section[key]
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{origin}: [{where}] {key} must be an integer from {low} to {high}")
    return value


def _str(section: dict[str, Any], key: str, origin: str, where: str) -> str:
    value = section[key]
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{origin}: [{where}] {key} must be a non-empty string")
    return value.strip()


def parse_config(data: dict[str, Any], origin: str) -> Config:
    general, filters, summary, report = (data[s] for s in ("general", "filters", "summary", "report"))

    log_name = _str(general, "log_name", origin, "general")
    if not _LOG_NAME.match(log_name):
        raise ConfigError(f"{origin}: [general] log_name contains unsupported characters: {log_name!r}")
    backend = _str(general, "backend", origin, "general").lower()
    if backend not in BACKENDS:
        raise ConfigError(f"{origin}: [general] backend must be one of: {', '.join(BACKENDS)}")
    display_tz = _str(general, "display_timezone", origin, "general").lower()
    if display_tz not in TIMEZONES:
        raise ConfigError(f"{origin}: [general] display_timezone must be one of: {', '.join(TIMEZONES)}")
    try:
        lookback = parse_duration(_str(general, "default_lookback", origin, "general"))
    except ValueError as exc:
        raise ConfigError(f"{origin}: [general] default_lookback: {exc}") from None

    exclude = filters["exclude_users"]
    if not isinstance(exclude, list) or not all(isinstance(x, str) and x.strip() for x in exclude):
        raise ConfigError(f"{origin}: [filters] exclude_users must be a list of non-empty strings")

    raw_events = data["events"]
    if not isinstance(raw_events, list):
        raise ConfigError(f"{origin}: events must be written as [[events]] tables")
    definitions: dict[int, EventDefinition] = {}
    for index, item in enumerate(raw_events, start=1):
        label = f"[[events]] entry #{index}"
        if not isinstance(item, dict):
            raise ConfigError(f"{origin}: {label} must be a table")
        unknown = set(item) - _EVENT_KEYS
        if unknown:
            raise ConfigError(
                f"{origin}: {label}: unknown key '{sorted(unknown)[0]}'. "
                f"Valid keys: {', '.join(sorted(_EVENT_KEYS))}."
            )
        event_id = item.get("id")
        if isinstance(event_id, bool) or not isinstance(event_id, int) or not 0 < event_id <= 65535:
            raise ConfigError(f"{origin}: {label}: id must be an integer from 1 to 65535")
        label = f"[[events]] id {event_id}"
        if event_id in definitions:
            raise ConfigError(f"{origin}: {label} is defined more than once")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"{origin}: {label}: name is required")
        category = item.get("category", "custom")
        if not isinstance(category, str) or not _CATEGORY.match(category):
            raise ConfigError(f"{origin}: {label}: category must be lowercase letters, digits or _")
        severity = item.get("severity", "info")
        if severity not in SEVERITIES:
            raise ConfigError(f"{origin}: {label}: severity must be one of: {', '.join(SEVERITIES)}")
        enabled = item.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigError(f"{origin}: {label}: enabled must be true or false")
        description = item.get("description", "")
        if not isinstance(description, str):
            raise ConfigError(f"{origin}: {label}: description must be a string")
        definitions[event_id] = EventDefinition(
            event_id, name.strip(), category, severity, enabled, description
        )

    return Config(
        log_name=log_name,
        backend=backend,
        default_lookback=lookback,
        max_events=_int(general, "max_events", 1, 200_000, origin, "general"),
        query_timeout_seconds=_int(general, "query_timeout_seconds", 5, 3600, origin, "general"),
        display_timezone=display_tz,
        exclude_users=tuple(x.strip() for x in exclude),
        top_n=_int(summary, "top_n", 1, 100, origin, "summary"),
        failed_logon_threshold=_int(summary, "failed_logon_threshold", 2, 10_000, origin, "summary"),
        report_title=_str(report, "title", origin, "report"),
        report_max_events=_int(report, "max_events_shown", 1, 5000, origin, "report"),
        events=definitions,
    )
