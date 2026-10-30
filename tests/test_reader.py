import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import helpers
from helpers import event_xml
from winsecmon.errors import (
    LogUnavailableError, PermissionDeniedError, QueryError, UnsupportedPlatformError, UsageError,
)
from winsecmon.reader import CHUNK_SIZE, CommandResult, WindowsLogReader, build_xpath

T0 = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)


def reader(runner, backend="wevtutil", target="Security", is_file=False):
    return WindowsLogReader(
        backend=backend, target=target, is_file=is_file, timeout=5,
        definitions=helpers.default_config().events, runner=runner, require_windows=False,
    )


class ReaderTests(unittest.TestCase):
    def test_xpath(self):
        self.assertEqual(build_xpath(None, None, None), "*")
        xp = build_xpath([4624, 4625], T0, T0.replace(hour=13))
        self.assertEqual(
            xp,
            "*[System[(EventID=4624 or EventID=4625) and TimeCreated[@SystemTime>='2026-10-28T12:00:00.000Z' "
            "and @SystemTime<='2026-10-28T13:00:00.000Z']]]",
        )

    def test_large_id_lists_are_chunked_and_merged(self):
        calls = []

        def runner(argv, timeout):
            calls.append(argv)
            n = len(calls)
            return CommandResult(0, event_xml(4624, T0, n, data={"TargetUserName": "a"}).encode(), b"")

        ids = list(range(4000, 4000 + CHUNK_SIZE * 2 + 3))
        result = reader(runner).read(ids, T0, None, 100)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result.queries_run, 3)
        for argv in calls:
            self.assertLessEqual(argv[3].count("EventID="), CHUNK_SIZE)
            self.assertEqual(argv[:3][1:], ["qe", "Security"])
            self.assertIn("/f:xml", argv)
        self.assertEqual(len(result.events), 3)

    def test_duplicates_across_chunks_are_removed(self):
        def runner(argv, timeout):
            return CommandResult(0, event_xml(4624, T0, 7, data={}).encode(), b"")

        result = reader(runner).read(list(range(4000, 4030)), None, None, 100)
        self.assertEqual(len(result.events), 1)

    def test_truncation_flag(self):
        out = "".join(event_xml(4624, T0, i, data={}) for i in range(5)).encode()
        result = reader(lambda a, t: CommandResult(0, out, b"")).read([4624], None, None, 5)
        self.assertTrue(result.truncated)
        result = reader(lambda a, t: CommandResult(0, out, b"")).read([4624], None, None, 50)
        self.assertFalse(result.truncated)

    def test_failures_map_to_specific_errors(self):
        cases = [
            (5, "Failed to query log. Access is denied.", PermissionDeniedError),
            (1, "Attempted to perform an unauthorized operation.", PermissionDeniedError),
            (15007, "The specified channel could not be found.", LogUnavailableError),
            (1, "There is not an event log on the localhost computer that matches 'Foo'.", LogUnavailableError),
            (15001, "The query is invalid.", QueryError),
            (9, "something odd", QueryError),
        ]
        for code, text, expected in cases:
            with self.subTest(text=text):
                r = reader(lambda a, t, c=code, x=text: CommandResult(c, b"", x.encode()))
                with self.assertRaises(expected) as ctx:
                    r.read([4624], None, None, 10)
                self.assertTrue(str(ctx.exception))
                if expected is PermissionDeniedError:
                    self.assertIn("Event Log Readers", ctx.exception.hint)

    def test_empty_output_is_fine(self):
        self.assertEqual(reader(lambda a, t: CommandResult(0, b"", b"")).read([4624], None, None, 10).events, [])

    def test_powershell_command_is_read_only_and_quoted(self):
        d = tempfile.mkdtemp()
        f = Path(d, "o'brien.evtx")
        f.write_bytes(b"")
        r = reader(lambda a, t: CommandResult(0, b"", b""), backend="powershell", target=str(f), is_file=True)
        argv = r.argv("*[System[(EventID=4624)]]", 5)
        self.assertEqual(argv[1:4], ["-NoProfile", "-NonInteractive", "-Command"])
        script = argv[4]
        self.assertIn("Get-WinEvent -Path", script)
        self.assertIn("o''brien.evtx", script)
        for forbidden in ("Clear-EventLog", "wevtutil cl", "auditpol /set", "Invoke-Expression", "Set-"):
            self.assertNotIn(forbidden, script)

    def test_wevtutil_file_mode_flags(self):
        d = tempfile.mkdtemp()
        f = Path(d, "a.evtx")
        f.write_bytes(b"")
        argv = reader(lambda a, t: CommandResult(0, b"", b""), target=str(f), is_file=True).argv("*", 3)
        self.assertIn("/lf:true", argv)
        self.assertIn("/c:3", argv)
        self.assertTrue(Path(argv[2]).is_absolute())

    def test_input_validation(self):
        with self.assertRaises(UsageError):
            reader(lambda a, t: None, target="/c:1 /q:x")
        with self.assertRaises(LogUnavailableError):
            reader(lambda a, t: None, target="missing.evtx", is_file=True)

    @unittest.skipIf(sys.platform == "win32", "checks the non-Windows message")
    def test_live_reading_refused_off_windows(self):
        r = WindowsLogReader(backend="wevtutil", target="Security", is_file=False, timeout=5,
                             definitions={}, require_windows=True)
        with self.assertRaises(UnsupportedPlatformError):
            r.read([4624], None, None, 1)


if __name__ == "__main__":
    unittest.main()
