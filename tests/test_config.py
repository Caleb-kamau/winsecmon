import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401
from winsecmon.config import default_config_text, discover_config_path, load_config
from winsecmon.errors import ConfigError

ROOT = Path(helpers.ROOT)


class ConfigTests(unittest.TestCase):
    def write(self, text):
        d = tempfile.mkdtemp()
        p = Path(d, "c.toml")
        p.write_text(text, encoding="utf-8")
        return str(p)

    def test_sample_matches_packaged_default(self):
        sample = (ROOT / "config" / "winsecmon.sample.toml").read_text(encoding="utf-8")
        self.assertEqual(sample, default_config_text())

    def test_defaults_cover_required_categories(self):
        cfg = helpers.default_config()
        enabled = {d.category for d in cfg.events.values() if d.enabled}
        self.assertTrue({"authentication", "account_management", "group_changes", "privilege_use", "audit_changes"} <= enabled)
        for i in (4624, 4625, 1102, 4719, 4672, 4732, 4720):
            self.assertTrue(cfg.events[i].enabled, i)

    def test_partial_file_merges_with_defaults(self):
        loaded = load_config(self.write("[general]\nmax_events = 10\n"), env={})
        self.assertEqual(loaded.config.max_events, 10)
        self.assertEqual(loaded.config.backend, "wevtutil")
        self.assertIn(4625, loaded.config.events)

    def test_user_events_replace_defaults(self):
        cfg = load_config(self.write('[[events]]\nid = 4625\nname = "Bad logon"\nseverity = "high"\n'), env={}).config
        self.assertEqual(list(cfg.events), [4625])
        self.assertEqual(cfg.events[4625].severity, "high")

    def test_rejects_bad_values_with_clear_messages(self):
        cases = {
            "[general]\nbackend = 'x'\n": "backend",
            "[general]\nmax_events = 0\n": "max_events",
            "[general]\nmax_events = true\n": "max_events",
            "[general]\ndefault_lookback = 'soon'\n": "default_lookback",
            "[general]\nlog_name = 'Sec; calc'\n": "log_name",
            "[general]\ntypo = 1\n": "unknown key 'typo'",
            "[nonsense]\nx = 1\n": "nonsense",
            "[[events]]\nid = 1\nname = 'a'\nseverity = 'scary'\n": "severity",
            "[[events]]\nid = 1\nname = 'a'\n[[events]]\nid = 1\nname = 'b'\n": "more than once",
            "[[events]]\nid = 70000\nname = 'a'\n": "id",
            "[[events]]\nid = 5\n": "name",
            "[filters]\nexclude_users = 'x'\n": "exclude_users",
            "this is not toml": "invalid TOML",
        }
        for text, needle in cases.items():
            with self.subTest(text=text), self.assertRaises(ConfigError) as ctx:
                load_config(self.write(text), env={})
            self.assertIn(needle, str(ctx.exception))

    def test_discovery_order(self):
        with self.assertRaises(ConfigError):
            discover_config_path("does-not-exist.toml", {})
        p = self.write("")
        self.assertEqual(discover_config_path(None, {"WINSECMON_CONFIG": p}), Path(p))
        self.assertEqual(discover_config_path(p, {"WINSECMON_CONFIG": "ignored"}), Path(p))
        self.assertIsNone(discover_config_path(None, {}, cwd=Path(tempfile.mkdtemp())))


if __name__ == "__main__":
    unittest.main()
