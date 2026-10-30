# Repository inspection and conventions

## Inspection result

The working directory was **empty**: no source files, no `.git`, no `README`, no build or lint
configuration, no CI. Only the interpreter toolchain was present (Python 3.12 with `tomllib`, Node.js;
no PowerShell, no ruff / mypy / pytest). There were therefore no existing language, framework,
layout, or style conventions to follow, so the choices below were made and are documented here.

## Stack choice

**Python 3.11+, standard library only.**

- Windows-friendly: one installer, no compiler, runs in PowerShell or cmd.
- Administrators can read and audit the whole tool (about 2,300 lines of Python, no dependencies, no supply chain).
- `tomllib` (3.11+) gives a comment-friendly config format without a dependency.
- Reading goes through Windows' own tools via `subprocess`, which keeps privileges and parsing behaviour
  identical to what an administrator would run by hand.
- Alternatives considered: PowerShell-only (harder to unit test and to export/format portably); C#/.NET
  (needs a build toolchain and is heavier for a first version); `pywin32` (extra dependency, no advantage here).

## Layout

```
src/winsecmon/
  cli.py          argument parsing and commands (thin; no logic worth testing lives only here)
  config.py       TOML loading, merging, strict validation
  default_config.toml   built-in defaults (copy: config/winsecmon.sample.toml, checked by a test)
  reader.py       wevtutil / PowerShell / XML-file readers, XPath building, error mapping
  parser.py       defensive event XML -> SecurityEvent
  describe.py     logon types, failure reasons, per-event messages
  filters.py      time / user / computer / ID / category / severity filtering
  query.py        read + filter pipeline, warnings
  summary.py      aggregation and highlight heuristics
  textout.py      ASCII terminal rendering with control-character escaping
  htmlreport.py   self-contained HTML dashboard
  export.py       CSV / JSON writers
  errors.py       exceptions carrying exit codes and hints
tests/            unittest suite (no dependencies)
examples/         synthetic sample events + generator
config/           sample configuration
docs/             this file and the security review
```

## Conventions adopted

- `src/` layout, packaged with `pyproject.toml` (setuptools), console script `winsecmon`.
- Type hints throughout, `from __future__ import annotations`, frozen dataclasses for data.
- User-facing failures are `WinSecMonError` subclasses with an exit code and optional hint; no tracebacks for expected problems.
- Warnings and diagnostics go to stderr; data goes to stdout.
- Tests: `unittest` so there are no dev dependencies; Windows tools are replaced by an injectable runner.
- Config is data (TOML), strictly validated; behaviour is never hard-coded to event lists in code.
