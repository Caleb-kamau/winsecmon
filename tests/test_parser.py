import unittest
from datetime import datetime, timezone

import helpers
from helpers import FAILURE, event_xml
from winsecmon.errors import MalformedEventError, QueryError
from winsecmon.parser import parse_event, parse_events_from_text


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.defs = helpers.default_config().events
        self.when = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)

    def test_failed_logon_fields(self):
        xml = event_xml(4625, self.when, 5, keywords=FAILURE, data={
            "TargetUserName": "alice", "TargetDomainName": "CORP", "LogonType": 10,
            "SubStatus": "0xc000006a", "IpAddress": "::ffff:10.1.2.3", "SubjectUserName": "-"})
        e = parse_event(xml, self.defs)
        self.assertEqual((e.event_id, e.severity, e.category), (4625, "medium", "authentication"))
        self.assertEqual(e.account, "CORP\\alice")
        self.assertEqual(e.outcome, "failure")
        self.assertEqual(e.source_ip, "10.1.2.3")
        self.assertEqual(e.logon_type_name, "RemoteInteractive")
        self.assertIn("Wrong password", e.message)
        self.assertIsNone(e.subject_user)  # "-" normalised

    def test_group_change_names_group_and_actor(self):
        xml = event_xml(4732, self.when, 6, data={
            "MemberSid": "S-1-5-21-1", "TargetUserName": "Administrators", "TargetDomainName": "Builtin",
            "SubjectUserName": "alice", "SubjectDomainName": "CORP"})
        e = parse_event(xml, self.defs)
        self.assertEqual(e.account, "CORP\\alice")
        self.assertEqual(e.object_name, "Builtin\\Administrators")
        self.assertIn("added S-1-5-21-1 to group Administrators", e.message)

    def test_userdata_event_1102(self):
        xml = event_xml(1102, self.when, 7, user_data={"SubjectUserName": "mallory", "SubjectDomainName": "CORP"})
        e = parse_event(xml, self.defs)
        self.assertEqual((e.severity, e.account), ("critical", "CORP\\mallory"))

    def test_unknown_event_gets_fallback_definition(self):
        e = parse_event(event_xml(9999, self.when, 8, data={"A": "b"}), self.defs)
        self.assertEqual((e.name, e.category, e.severity), ("Event 9999", "custom", "info"))

    def test_seven_digit_fraction(self):
        e = parse_event(event_xml(4624, self.when.replace(microsecond=123456), 9, data={}), self.defs)
        self.assertEqual(e.time_utc.microsecond, 123456)

    def test_malformed_variants(self):
        ns = "xmlns='http://schemas.microsoft.com/win/2004/08/events/event'"
        bad = [
            "<Event", "<Other/>", f"<Event {ns}/>",
            f"<Event {ns}><System><EventID>abc</EventID></System></Event>",
            f"<Event {ns}><System><EventID>4624</EventID></System></Event>",
            f"<Event {ns}><System><EventID>4624</EventID><TimeCreated SystemTime='2026-13-45T99:00:00Z'/></System></Event>",
            f"<Event {ns}><!DOCTYPE a [<!ENTITY x 'y'>]><System/></Event>",
        ]
        for xml in bad:
            with self.subTest(xml=xml), self.assertRaises(MalformedEventError):
                parse_event(xml, self.defs)

    def test_control_characters_are_neutralised_not_fatal(self):
        raw = event_xml(4625, self.when, 10, data={"TargetUserName": "bad\x1bname"})
        ref = raw.replace("bad\x1bname", "bad&#27;name")
        for xml in (raw, ref):
            e = parse_event(xml, self.defs)
            self.assertNotIn("\x1b", e.target_user)
            self.assertTrue(e.target_user.startswith("bad"))

    def test_stream_isolates_bad_events(self):
        text = event_xml(4624, self.when, 1, data={}) + "\n<Event><broken>" + "</Event>\n" + event_xml(4624, self.when, 2, data={})
        events, problems, blocks = parse_events_from_text(text, self.defs)
        self.assertEqual((len(events), len(problems), blocks), (2, 1, 3))

    def test_output_without_events_is_an_error(self):
        with self.assertRaises(QueryError):
            parse_events_from_text("Some unexpected tool message", self.defs)
        self.assertEqual(parse_events_from_text("  \n", self.defs), ([], [], 0))


if __name__ == "__main__":
    unittest.main()


class ProcessInMessageTests(unittest.TestCase):
    def test_failed_logon_message_names_the_process(self):
        defs = helpers.default_config().events
        when = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)
        e = parse_event(event_xml(4625, when, 1, keywords=FAILURE, data={
            "TargetUserName": "user", "TargetDomainName": "PC", "LogonType": 2, "SubStatus": "0xc000006a",
            "WorkstationName": "PC", "ProcessName": "C:\\Program Files\\Hola\\app\\chromium\\hola_cr.exe"}), defs)
        self.assertIn("via hola_cr.exe", e.message)
        self.assertIn("Wrong password", e.message)
        self.assertEqual(e.process_name, "C:\\Program Files\\Hola\\app\\chromium\\hola_cr.exe")  # full path kept
