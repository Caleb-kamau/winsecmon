# winsecmon

Read-only monitoring of the **Windows Security event log** from the command line.
Query the events you care about, filter them, see a summary dashboard, and export to CSV or JSON.

- Standard library only (Python 3.11+): nothing to install but Python itself.
- Uses Windows' own tools to read the log: `wevtutil.exe` (default) or PowerShell `Get-WinEvent`.
- **Read-only and local.** It never changes audit policy, never clears logs, never changes
  permissions, and never sends data anywhere (no network code at all).

> **Verification status.** The 52 automated tests ran on Linux with synthetic events and a mocked
> Windows tool runner. In addition, the tool has been run by hand on a real Windows 11 machine
> (Python 3.13, administrator prompt) and confirmed working for: `check`, `summary`, `show`
> (including `--details`), CSV and JSON export, the HTML report, and both the `wevtutil` and
> `powershell` backends, on a live log of a few hundred events per day. **Not yet exercised on
> Windows:** rarer event types (group changes, account creation, lockouts, audit log cleared),
> running without elevation via the Event Log Readers group, `--evtx` files, and very busy logs.
> See [Limitations](#limitations).

## Quick start (Windows)

```powershell
# 1. Install Python 3.11+ from python.org, then in this folder:
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .

# (or, without installing:  $env:PYTHONPATH = "src"  and use  py -m winsecmon ...)

# 2. Verify tools, configuration and permission to read the Security log
winsecmon check

# 3. Look at the last 24 hours
winsecmon summary
winsecmon show --min-severity medium
```

Try it on any OS with the bundled synthetic data (no Windows needed):

```
winsecmon summary --xml examples/sample_events.xml
```

## Permissions and least privilege

Reading the Security log is protected by Windows. You need **one** of:

| Option | Notes |
|---|---|
| Member of the local **Event Log Readers** group | Recommended. Read access to the log without administrator rights. Sign out and in after being added. |
| An **elevated** (Run as administrator) prompt | Works, but grants far more power than this tool needs. |

Everything else (`show/summary/report/export` on an XML export, `events`, `init-config`) needs only
normal file access to the folders you name. If access is denied, winsecmon says so (exit code 3) and
explains the options above. It does not try to elevate or change permissions.

**What winsecmon will never do:** modify audit policy, clear or write to any event log, change
group membership or ACLs, install anything, start services, make network connections, or upload data.
Audit policy decides which events exist at all; if you expect events that are missing, check it with
the read-only `auditpol /get /category:*` yourself and change it deliberately through your normal
change process.

## Commands

| Command | Purpose |
|---|---|
| `winsecmon check` | Diagnose platform, tool path, configuration validity, elevation, and whether the log is readable. |
| `winsecmon show` | List matching events (newest first). `--details` prints every field; `--limit N` (default 50). |
| `winsecmon summary` | Terminal dashboard: highlights, severity/event/category breakdowns, top accounts/computers/sources, timeline. |
| `winsecmon report -o report.html` | Self-contained HTML dashboard (no scripts, no external resources). |
| `winsecmon export -o out.csv` / `out.json` | Export all matching events. `-o -` writes to stdout (needs `--format`). |
| `winsecmon events` | Show the monitored event definitions and which are enabled. |
| `winsecmon init-config [PATH]` | Write the sample configuration (never overwrites without `--force`). |

### Filters (all commands that read events)

| Flag | Meaning |
|---|---|
| `--since 30m\|24h\|7d\|2w` | Relative time range. |
| `--start TIME` / `--end TIME` | Absolute range, ISO 8601. No zone = local time; `Z` or `+02:00` for explicit zones. |
| `--user NAME` | Account name. Matches `alice`, `CORP\alice`, wildcards like `svc-*`. Matches the acting account and the target account. Case-insensitive, whole-name match. |
| `--computer NAME` | Computer name, FQDN or short name, wildcards allowed. |
| `--event-id 4624,4625` | Event IDs. Overrides the config's list (can include disabled or undefined IDs). |
| `--category NAME` | `authentication`, `account_management`, `group_changes`, `privilege_use`, `audit_changes`, or your own. |
| `--severity high` / `--min-severity medium` | Exact level(s) or a minimum: `info < low < medium < high < critical`. |
| `--no-exclude` | Show accounts hidden by `exclude_users` (they are always counted in a warning). |
| `--evtx FILE` / `--xml FILE` | Read an archived `.evtx` (Windows) or wevtutil XML export (any OS) instead of the live log. |
| `--backend wevtutil\|powershell` | Override the configured backend. |
| `--max-events N` | Cap on events read. |

Repeat a flag or use commas for several values. With no time flags, the live log uses the config's
`default_lookback` (24h). For `--evtx`/`--xml` files, no time limit is applied unless you give one.

### Example queries

```powershell
# Failed logons in the last 4 hours, with reasons
winsecmon show --event-id 4625 --since 4h

# Everything one account did, last 7 days, as CSV
winsecmon export --user 'CORP\alice' --since 7d -o alice.csv

# Anything high or critical today, in a shareable HTML dashboard
winsecmon report --min-severity high --since 24h -o today.html

# Group-membership changes on one server, with full detail
winsecmon show --category group_changes --computer SRV01 --since 30d --details

# Audit log cleared or audit policy changed, ever (within the 5000-event cap)
winsecmon show --event-id 1102,4719,4912 --start 2020-01-01

# Wildcards: all service accounts, authentication events only
winsecmon summary --user 'svc-*' --category authentication --since 2d

# Analyse an archived log or a colleague's XML export
winsecmon summary --evtx D:\archive\Security-2026-10.evtx
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /f:xml /rd:true /c:2000 > fails.xml
winsecmon summary --xml fails.xml
```

### Exit codes

`0` success · `2` bad arguments or configuration · `3` permission denied · `4` log, file, or
Windows tool unavailable (or not running on Windows) · `5` Windows query failed · `6` output file
problem (exists, folder missing) · `130` interrupted.
Warnings (skipped malformed events, truncated results, hidden accounts) go to stderr so exports to
stdout stay clean.

## Configuration

Configuration lives in a TOML file, separate from the code. Generate one and edit it:

```powershell
winsecmon init-config winsecmon.toml
```

Lookup order: `--config FILE`, `%WINSECMON_CONFIG%`, `.\winsecmon.toml`,
`%APPDATA%\winsecmon\winsecmon.toml`, then built-in defaults. `config/winsecmon.sample.toml` is the
fully commented sample (identical to the built-in default; a test enforces that).

- Omitted settings keep their defaults. **Unknown keys are errors**, so typos can't silently disable a setting.
- `[[events]]` entries define what is monitored (id, name, category, severity, `enabled`). If you define
  any, your list **replaces** the default list. Use `enabled = false` to park an entry.
- Severities are triage hints chosen in the config. Windows does not assign them. Tune them to your environment.
- `exclude_users` hides noisy accounts (default `DWM-*`, `UMFD-*`) and always reports how many events were hidden.
- `[summary] failed_logon_threshold` controls the burst highlights (see below).

### Default monitored events

| Category | Event IDs |
|---|---|
| Authentication | 4624 logon (info), 4625 failed logon (medium), 4648 explicit credentials (low), 4740 lockout (high), 4767 unlock (low) |
| Account management | 4720 created, 4724 password reset, 4725 disabled, 4726 deleted (medium); 4722, 4723, 4738 (low) |
| Group changes | 4728 / 4732 / 4756 member added (high); 4729 / 4733 / 4757 removed, 4731 / 4734 group created/deleted (medium) |
| Privilege use | 4672 special privileges assigned, 4673, 4674 (low) |
| Audit log / policy | 1102 log cleared (critical); 4719, 4912 audit policy changed (high) |
| Disabled by default | 4634 logoff, 4776 NTLM validation, 4688 process creation, 4697 service installed, 4698 scheduled task |

### "Needs attention" highlights

Simple heuristics, not alerts: every high/critical event type present (count, latest time and actor);
an account or source address with at least `failed_logon_threshold` failed logons; and a single source
address failing against at least that many *different* accounts (possible password spraying).

## Output

- **CSV**: one row per event, UTF-8 with BOM (opens correctly in Excel), UTC timestamps, raw fields
  in a `details` JSON column. Cells starting with `=`, `+`, `-`, `@` are prefixed with `'` so that
  attacker-chosen text (e.g. a user name typed at a failed logon) cannot run as a spreadsheet formula.
- **JSON**: `{tool, generated_utc, query, count, truncated, events[]}`; values are unmodified.
- **HTML report**: single file, inline CSS, a restrictive Content-Security-Policy, all data escaped.
- Output files are never overwritten without `--force`.
- **Treat every export and report as sensitive** (account names, addresses, process names). Save them
  somewhere with appropriate permissions; winsecmon does not set file ACLs.

## Windows versions

- Security event IDs and the `wevtutil` / `Get-WinEvent` tools are the same on Windows Vista / Server 2008 and later.
  Windows XP / Server 2003 use different event IDs and are **not supported**.
- Target systems: Windows 10, Windows 11, Windows Server 2016-2025. Python 3.11+ must itself run on your
  version (see python.org for its requirements). The `powershell` backend uses Windows PowerShell 5.1 (`powershell.exe`).
- Field layouts differ slightly between versions (for example 4624 gained fields in Windows 10). Missing fields
  are simply left blank.
- Domain controllers log account and group events (4720, 4728, 4740...) on the DC, not on member servers. Run
  winsecmon there, or on an archived DC log.

## Limitations

- Only partly verified on real Windows (see the status note at the top). Run `winsecmon check`; report any failure with its exit code and message.
- Local, point-in-time reads only: no live tail, alerting, remote collection, or forwarding. Use `--evtx`/`--xml` for logs from other machines.
- Events are described from their fields and the config, not Windows' localized message text.
- At most `max_events` (default 5000) events are read per run, newest first. A warning appears when the cap is hit.
  Event ID, category, severity, and time filters are applied inside the Windows query; `--user` and `--computer` are
  applied afterwards, so with a very busy log narrow the time range first.
- Large ID lists are split into several Windows queries (12 IDs each) because Windows limits XPath filter complexity.
- `wevtutil` output encoding depends on the console; non-ASCII names are decoded as UTF-8 and fall back to the system code page.
  The PowerShell backend forces UTF-8.
- `--user` does not match group *members* in group-change events (they are shown by SID or distinguished name).
- Times are displayed in local time or UTC only (`display_timezone`). Exports are always UTC.
- XML export files larger than 256 MiB are refused; export a narrower range.
- Highlights are heuristics, and an attacker with rights to clear logs can remove the evidence this tool reads.

## Development

```
python -m unittest discover -s tests -v      # 51 tests, no dependencies
python examples/make_sample_events.py        # regenerate the synthetic sample
```

See [docs/REPOSITORY_NOTES.md](docs/REPOSITORY_NOTES.md) for layout and design decisions and
[docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) for the security review.
