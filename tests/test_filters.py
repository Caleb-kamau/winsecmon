import unittest
from datetime import datetime, timedelta, timezone

import helpers
from helpers import event_xml
from winsecmon.filters import EventFilter
from winsecmon.parser import parse_event
from winsecmon.timeparse import parse_datetime, parse_duration, resolve_range

T0 = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.defs = helpers.default_config().events

    def ev(self, event_id, **data):
        return parse_event(event_xml(event_id, T0, 1, computer=data.pop("computer", "WS01.corp.local"), data=data), self.defs)

    def test_select_ids_respects_enabled_category_and_severity(self):
        ids = EventFilter().select_event_ids(self.defs)
        self.assertIn(4624, ids)
        self.assertNotIn(4688, ids)  # disabled by default
        high = EventFilter(min_severity="high").select_event_ids(self.defs)
        self.assertTrue({1102, 4719, 4740} <= set(high) and 4624 not in high)
        auth = EventFilter(categories=frozenset({"authentication"})).select_event_ids(self.defs)
        self.assertTrue(all(self.defs[i].category == "authentication" for i in auth))
        self.assertEqual(EventFilter(event_ids=(4688, 9999)).select_event_ids(self.defs), [4688, 9999])
        self.assertEqual(EventFilter(event_ids=(4624,), severities=frozenset({"high"})).select_event_ids(self.defs), [])

    def test_user_matching(self):
        e = self.ev(4625, TargetUserName="alice", TargetDomainName="CORP", SubjectUserName="WS01$", SubjectDomainName="CORP")
        for pattern in ("alice", "ALICE", "corp\\alice", "al*", "ws01$"):
            self.assertTrue(EventFilter(users=(pattern,)).matches(e), pattern)
        self.assertFalse(EventFilter(users=("bob",)).matches(e))
        self.assertFalse(EventFilter(users=("lic",)).matches(e))  # no implicit substring match

    def test_computer_matches_fqdn_or_short_name(self):
        e = self.ev(4624, TargetUserName="a", computer="WS01.corp.local")
        self.assertTrue(EventFilter(computers=("ws01",)).matches(e))
        self.assertTrue(EventFilter(computers=("WS01.corp.local",)).matches(e))
        self.assertTrue(EventFilter(computers=("*.corp.local",)).matches(e))
        self.assertFalse(EventFilter(computers=("ws02",)).matches(e))

    def test_time_bounds_are_inclusive(self):
        e = self.ev(4624, TargetUserName="a")
        self.assertTrue(EventFilter(start=T0, end=T0).matches(e))
        self.assertFalse(EventFilter(start=T0 + timedelta(seconds=1)).matches(e))
        self.assertFalse(EventFilter(end=T0 - timedelta(seconds=1)).matches(e))

    def test_exclusions(self):
        noisy = self.ev(4672, SubjectUserName="DWM-3", SubjectDomainName="Window Manager")
        real = self.ev(4672, SubjectUserName="alice", SubjectDomainName="CORP")
        f = EventFilter(exclude_users=("DWM-*",))
        self.assertTrue(f.is_excluded(noisy))
        self.assertFalse(f.is_excluded(real))


class TimeTests(unittest.TestCase):
    def test_durations(self):
        self.assertEqual(parse_duration("90m"), timedelta(minutes=90))
        self.assertEqual(parse_duration("2w"), timedelta(weeks=2))
        for bad in ("", "0h", "-1h", "h", "5", "1.5h", "99999999999999d"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_duration(bad)

    def test_datetimes(self):
        self.assertEqual(parse_datetime("2026-10-28T12:00:00Z"), T0)
        self.assertEqual(parse_datetime("2026-10-28T14:00:00+02:00"), T0)
        self.assertEqual(parse_datetime("2026-10-28").tzinfo, timezone.utc)
        with self.assertRaises(ValueError):
            parse_datetime("yesterday")

    def test_resolve_range(self):
        now = T0
        self.assertEqual(resolve_range(since="1h", start=None, end=None, default_lookback=None, now=now), (T0 - timedelta(hours=1), None))
        self.assertEqual(resolve_range(since=None, start=None, end=None, default_lookback=timedelta(days=1), now=now)[0], T0 - timedelta(days=1))
        self.assertEqual(resolve_range(since=None, start=None, end=None, default_lookback=None, now=now), (None, None))
        with self.assertRaises(ValueError):
            resolve_range(since="1h", start="2026-01-01", end=None, default_lookback=None, now=now)
        with self.assertRaises(ValueError):
            resolve_range(since=None, start="2026-10-02", end="2026-10-01", default_lookback=None, now=now)


if __name__ == "__main__":
    unittest.main()
