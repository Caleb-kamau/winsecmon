# Security and usability review

Reviewed before release of 0.1.0. "Fixed" means a change was made during review and a test covers it.

## Threat model

winsecmon is run by an administrator on a machine whose logs may contain attacker-influenced text
(for example the user name typed into a failed network logon, or process names). It reads sensitive
data and writes files, so the main risks are: unintended side effects on the system, injection through
log content into the terminal, spreadsheets, HTML or the parser, and leakage of the data it handles.

## Findings

| # | Issue | Status |
|---|---|---|
| 1 | **Events could be silently dropped.** A user name containing a control character (invalid in XML 1.0) made the event unparseable, so an attacker could hide failed logons. | Fixed: invalid characters, raw or as numeric references, are replaced with U+FFFD before parsing; the event is kept. Genuinely unparseable events are skipped but counted and reported. |
| 2 | **CSV formula injection.** Logged text such as `=HYPERLINK(...)` would execute when the CSV is opened in Excel. | Fixed: cells starting with `= + - @ TAB CR` get a leading `'` in CSV. JSON is unmodified. |
| 3 | **Terminal escape injection.** Control sequences in event fields could repaint or spoof the console. | Fixed: all untrusted text is printed through `safe_text`, which shows control characters (including C1 such as U+009B) as `\xNN`. |
| 4 | **HTML injection.** Event text rendered in the report. | Mitigated: every value is escaped; no scripts; CSP `default-src 'none'`; no external resources (tested). |
| 5 | **XML entity expansion / DTDs.** | Mitigated: any DOCTYPE or ENTITY declaration rejects that event before parsing. |
| 6 | **Command injection.** | Mitigated: no shell; argument lists only; XPath contains only integers and formatted timestamps; log names validated against a strict pattern; file paths made absolute; PowerShell string values quote-escaped. No `eval`/`exec`. |
| 7 | **Tool hijacking via PATH** when run elevated. | Mitigated: `wevtutil.exe` and `powershell.exe` are resolved under `%SystemRoot%\System32` first. |
| 8 | **Accidental data loss / overwrite.** | Mitigated: outputs use exclusive create unless `--force`. |
| 9 | **System changes.** | None possible by design: only `wevtutil qe` and `Get-WinEvent` are issued (a test asserts the PowerShell script has no mutating cmdlets); `auditpol` appears only as advice text. No network imports exist. |
| 10 | **Resource exhaustion.** | Mitigated: event cap (default 5000, max 200000), query timeout, 256 MiB limit on XML input files, bounded timeline buckets. |
| 11 | **Hidden filtering misleading the reader.** `exclude_users` and the event cap could hide events unnoticed. | Fixed: both always produce a warning with counts; `--no-exclude` shows everything. |
| 12 | **Windows XPath complexity limits** could make large ID lists fail. | Fixed: IDs are queried in chunks of 12 and merged, with de-duplication. |

## Residual risks and things to verify on Windows

- **Partly verified on real Windows.** Live reads with both backends, the access-denied path (non-elevated run), output
  decoding and parsing were confirmed by hand on Windows 11. Still unverified there: the other exit-code mappings
  (15007 = channel not found, 15001 = invalid query, which are mocked in tests), `--evtx` files, Event Log Readers
  (non-elevated) access, and heavily loaded logs.
- Exported files and reports are sensitive and inherit the folder's ACLs; protect them accordingly.
- Anyone able to clear the Security log can erase the evidence; forward logs to a protected collector for real assurance.
- Severity values are opinionated defaults, not Microsoft classifications.
- Highlight heuristics (burst/spray thresholds) can produce false positives (for example a service retrying a stale password).

## Usability notes

- Every failure has a specific message and, where useful, a hint (permissions, log name, narrowing a query).
- `winsecmon check` gives one place to diagnose the environment.
- Empty results on a live log point to the audit-policy question without changing anything.
