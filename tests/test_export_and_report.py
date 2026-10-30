import csv
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import helpers
from helpers import event_xml
from winsecmon.errors import OutputError
from winsecmon.export import export_events, neutralise_formula, write_csv
from winsecmon.htmlreport import render_html
from winsecmon.parser import parse_event
from winsecmon.summary import build_summary
from winsecmon.textout import render_details, render_table, safe_text

T0 = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)
EVIL = '=HYPERLINK("http://evil.example","x")'


class ExportTests(unittest.TestCase):
    def setUp(self):
        defs = helpers.default_config().events
        self.events = [
            parse_event(event_xml(4625, T0, 1, data={"TargetUserName": EVIL, "TargetDomainName": "CORP", "LogonType": 3}), defs),
            parse_event(event_xml(4624, T0, 2, data={"TargetUserName": "alice", "TargetDomainName": "CORP"}), defs),
        ]
        self.dir = Path(tempfile.mkdtemp())

    def test_csv_formula_injection_is_neutralised(self):
        self.assertEqual(neutralise_formula("=1+1"), "'=1+1")
        for s in ("+x", "-x", "@x", "\tx"):
            self.assertTrue(neutralise_formula(s).startswith("'"))
        self.assertEqual(neutralise_formula("S-1-5-21"), "S-1-5-21")
        buf = io.StringIO()
        write_csv(self.events, buf)
        rows = list(csv.DictReader(io.StringIO(buf.getvalue())))
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[0]["target_user"].startswith("'="))
        self.assertFalse(any(v.startswith("=") for r in rows for v in r.values()))

    def test_csv_and_json_files(self):
        c, j = str(self.dir / "o.csv"), str(self.dir / "o.json")
        export_events(self.events, "csv", c, force=False, query={}, truncated=False)
        export_events(self.events, "json", j, force=False, query={"users": []}, truncated=True)
        self.assertTrue(Path(c).read_bytes().startswith(b"\xef\xbb\xbf"))  # BOM for Excel
        doc = json.loads(Path(j).read_text(encoding="utf-8"))
        self.assertEqual((doc["count"], doc["truncated"]), (2, True))
        self.assertEqual(doc["events"][0]["time_utc"], "2026-10-28T12:00:00.000Z")
        self.assertEqual(doc["events"][0]["target_user"], EVIL)  # JSON is not altered
        self.assertIsInstance(doc["events"][0]["details"], dict)

    def test_no_overwrite_without_force(self):
        p = str(self.dir / "o.json")
        export_events(self.events, "json", p, force=False, query={}, truncated=False)
        with self.assertRaises(OutputError):
            export_events(self.events, "json", p, force=False, query={}, truncated=False)
        export_events(self.events[:1], "json", p, force=True, query={}, truncated=False)
        self.assertEqual(json.loads(Path(p).read_text())["count"], 1)

    def test_missing_folder(self):
        with self.assertRaises(OutputError):
            export_events(self.events, "csv", str(self.dir / "nope" / "x.csv"), force=False, query={}, truncated=False)


class RenderTests(unittest.TestCase):
    def setUp(self):
        defs = helpers.default_config().events
        self.events = [
            parse_event(event_xml(4625, T0, 1, data={"TargetUserName": '<script>alert(1)</script>', "TargetDomainName": "CORP"}), defs),
            parse_event(event_xml(4624, T0, 2, data={"TargetUserName": "a\u009b31m", "TargetDomainName": "CORP"}), defs),
        ]

    def test_safe_text_escapes_controls(self):
        self.assertEqual(safe_text("a\x1b[2Jb\n"), "a\\x1b[2Jb\\x0a")
        self.assertEqual(safe_text("\u009b"), "\\x9b")
        self.assertEqual(safe_text(None), "")
        for e in self.events:
            for out in (render_table([e], None, 120), render_details(e, None)):
                self.assertFalse(any(ord(c) < 32 and c != "\n" for c in out))
                self.assertNotIn("\u009b", out)

    def test_html_report_is_escaped_and_script_free(self):
        summary = build_summary(self.events, tz=timezone.utc, top_n=5, failed_logon_threshold=2)
        doc = render_html(title="T <b>", events=self.events, summary=summary, tz=timezone.utc, tz_label="UTC",
                          source="x", filters={"users": ["<img src=x>"]}, warnings=["<i>w</i>"], max_rows=10)
        self.assertNotIn("<script", doc.lower().replace("&lt;script", ""))
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", doc)
        self.assertNotIn("<img", doc)
        self.assertIn("Content-Security-Policy", doc)
        self.assertNotIn("http://", doc.replace("http-equiv", ""))  # no external resources

    def test_empty_report_renders(self):
        summary = build_summary([], tz=timezone.utc, top_n=5, failed_logon_threshold=2)
        doc = render_html(title="T", events=[], summary=summary, tz=timezone.utc, tz_label="UTC",
                          source="x", filters={}, warnings=[], max_rows=10)
        self.assertIn("no events in range", doc)


if __name__ == "__main__":
    unittest.main()


class RegressionFromRealRun(unittest.TestCase):
    """Issues seen in the first run on a real Windows machine."""

    def test_html_filters_are_readable_and_in_display_zone(self):
        summary = build_summary([], tz=timezone.utc, top_n=5, failed_logon_threshold=2)
        doc = render_html(title="T", events=[], summary=summary, tz=timezone.utc, tz_label="UTC", source="x",
                          filters={"start_utc": "2026-10-29T08:29:22.606189Z", "exclude_users": ["DWM-*"]},
                          warnings=[], max_rows=10)
        self.assertIn("<b>From</b> 2026-10-29 08:29 (UTC)", doc)
        self.assertIn("<b>Hidden accounts</b> DWM-*", doc)
        self.assertNotIn("start_utc", doc)

    def test_failed_logon_without_ip_is_attributed_to_workstation(self):
        defs = helpers.default_config().events
        ev = [parse_event(event_xml(4625, T0, i, data={"TargetUserName": "user", "TargetDomainName": "PC",
              "LogonType": 2, "IpAddress": "-", "WorkstationName": "PC"}), defs) for i in range(3)]
        summary = build_summary(ev, tz=timezone.utc, top_n=5, failed_logon_threshold=3)
        self.assertEqual(summary.top_failed_sources, [("PC", 3)])
