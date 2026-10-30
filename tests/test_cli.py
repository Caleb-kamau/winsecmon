import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

import helpers
from winsecmon.cli import main

XML = str(helpers.SAMPLE_XML)


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def test_show_default_hides_noise_and_reports_it(self):
        code, out, err = run("show", "--xml", XML, "--limit", "100")
        self.assertEqual(code, 0)
        self.assertIn("hidden by exclude_users", err)
        self.assertIn("Skipped 2 malformed", err)
        self.assertNotIn("DWM-1", out)
        code, out, _ = run("show", "--xml", XML, "--limit", "100", "--no-exclude")
        self.assertIn("DWM-1", out)

    def test_filters_end_to_end(self):
        _, out, _ = run("show", "--xml", XML, "--event-id", "1102,4719", "--limit", "10")
        self.assertIn("1102", out)
        self.assertNotIn("4625", out)
        _, out, _ = run("show", "--xml", XML, "--min-severity", "critical")
        self.assertIn("Audit log cleared", out)
        self.assertNotIn("4719", out)
        _, out, _ = run("show", "--xml", XML, "--user", "alice", "--category", "group_changes")
        self.assertIn("4732", out)
        self.assertNotIn("4624", out)
        _, out, _ = run("show", "--xml", XML, "--computer", "srv01")
        self.assertIn("SRV01", out)
        self.assertNotIn("WS01", out)
        _, out, _ = run("show", "--xml", XML, "--start", "2026-10-28T14:00:00Z", "--end", "2026-10-28T15:30:00Z")
        self.assertIn("1102", out)
        self.assertNotIn("4720", out)
        _, out, _ = run("show", "--xml", XML, "--since", "1h")  # relative to now: nothing from 2026-10-28
        self.assertIn("No matching events", out)

    def test_summary_highlights(self):
        code, out, _ = run("summary", "--xml", XML)
        self.assertEqual(code, 0)
        for text in ("Audit log cleared", "password spraying", "failed logons for account CORP\\administrator", "Timeline"):
            self.assertIn(text, out)
        self.assertNotIn("\x1b", out)

    def test_export_csv_json_and_stdout(self):
        c, j = str(self.dir / "e.csv"), str(self.dir / "e.json")
        self.assertEqual(run("export", "--xml", XML, "-o", c)[0], 0)
        self.assertEqual(run("export", "--xml", XML, "-o", j, "--min-severity", "high")[0], 0)
        data = json.loads(Path(j).read_text(encoding="utf-8"))
        self.assertTrue(data["count"] >= 4 and all(e["severity"] in ("high", "critical") for e in data["events"]))
        self.assertIn("event_id", Path(c).read_text(encoding="utf-8-sig").splitlines()[0])
        code, out, _ = run("export", "--xml", XML, "-o", "-", "--format", "json", "--event-id", "1102")
        self.assertEqual(json.loads(out)["count"], 1)
        code, _, err = run("export", "--xml", XML, "-o", c)
        self.assertEqual(code, 6)
        self.assertIn("already exists", err)
        self.assertEqual(run("export", "--xml", XML, "-o", str(self.dir / "x.txt"))[0], 2)

    def test_report(self):
        p = str(self.dir / "r.html")
        code, out, _ = run("report", "--xml", XML, "-o", p)
        self.assertEqual(code, 0)
        doc = Path(p).read_text(encoding="utf-8")
        self.assertIn("Needs attention", doc)
        self.assertNotIn('=HYPERLINK("', doc)  # quotes are escaped
        self.assertEqual(run("report", "--xml", XML, "-o", p)[0], 6)

    def test_error_exit_codes(self):
        self.assertEqual(run("show", "--xml", XML, "--since", "soon")[0], 2)
        self.assertEqual(run("show", "--xml", XML, "--event-id", "abc")[0], 2)
        self.assertEqual(run("show", "--xml", XML, "--severity", "scary")[0], 2)
        self.assertEqual(run("show", "--xml", XML, "--category", "nope")[0], 2)
        self.assertEqual(run("show", "--xml", XML, "--since", "1h", "--start", "2026-01-01")[0], 2)
        self.assertEqual(run("show", "--config", str(self.dir / "none.toml"))[0], 2)
        code, _, err = run("show", "--xml", str(self.dir / "missing.xml"))
        self.assertEqual(code, 4)
        self.assertIn("not found", err)
        bad = self.dir / "garbage.xml"
        bad.write_text("not xml at all", encoding="utf-8")
        self.assertEqual(run("show", "--xml", str(bad))[0], 5)
        self.assertEqual(run()[0], 2)

    @unittest.skipIf(sys.platform == "win32", "non-Windows behaviour")
    def test_live_and_check_off_windows(self):
        code, _, err = run("show")
        self.assertEqual(code, 4)
        self.assertIn("requires Windows", err)
        self.assertEqual(run("check")[0], 4)

    def test_init_config_and_events(self):
        p = str(self.dir / "winsecmon.toml")
        self.assertEqual(run("init-config", p)[0], 0)
        self.assertEqual(run("init-config", p)[0], 6)  # never overwrites silently
        code, out, _ = run("events", "--config", p)
        self.assertIn("Audit log cleared", out)

    def test_custom_config_changes_behaviour(self):
        cfg = self.dir / "c.toml"
        cfg.write_text('[filters]\nexclude_users = []\n[[events]]\nid = 1102\nname = "Cleared"\nseverity = "critical"\n', encoding="utf-8")
        code, out, _ = run("show", "--xml", XML, "--config", str(cfg))
        self.assertIn("1102", out)
        self.assertNotIn("4624", out)


if __name__ == "__main__":
    unittest.main()
