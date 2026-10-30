"""Generate examples/sample_events.xml: SYNTHETIC events for trying winsecmon on any OS.

All names, addresses and times are invented. Run:  python examples/make_sample_events.py
The output has the same shape as `wevtutil qe Security /f:xml`.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
SUCCESS, FAILURE = "0x8020000000000000", "0x8010000000000000"


def event_xml(event_id, when, record, computer="WS01.corp.local", data=None, keywords=SUCCESS,
              user_data=None):
    body = ""
    if data:
        items = "".join(f"<Data Name='{k}'>{escape(str(v))}</Data>" for k, v in data.items())
        body = f"<EventData>{items}</EventData>"
    elif user_data:
        items = "".join(f"<{k}>{escape(str(v))}</{k}>" for k, v in user_data.items())
        body = f"<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>{items}</LogFileCleared></UserData>"
    stamp = when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond:06d}0Z"
    return (
        f"<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-Security-Auditing' "
        f"Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/><EventID>{event_id}</EventID><Version>0</Version>"
        f"<Level>0</Level><Task>0</Task><Opcode>0</Opcode><Keywords>{keywords}</Keywords>"
        f"<TimeCreated SystemTime='{stamp}'/><EventRecordID>{record}</EventRecordID>"
        f"<Correlation/><Execution ProcessID='700' ThreadID='9000'/><Channel>Security</Channel>"
        f"<Computer>{computer}</Computer><Security/></System>{body}</Event>"
    )


def build_sample() -> str:
    base = datetime(2026, 10, 28, 8, 0, 0, tzinfo=timezone.utc)
    out: list[str] = []
    record = [1000]

    def add(event_id, minutes, **kw):
        record[0] += 1
        out.append(event_xml(event_id, base + timedelta(minutes=minutes, seconds=record[0] % 50), record[0], **kw))

    # Ordinary interactive logons
    for i, user in enumerate(["alice", "bob", "carol", "alice", "bob"]):
        add(4624, 5 + i * 40, data={"SubjectUserName": "WS01$", "SubjectDomainName": "CORP", "TargetUserName": user,
            "TargetDomainName": "CORP", "LogonType": 2, "IpAddress": "127.0.0.1", "WorkstationName": "WS01"})
    add(4672, 6, data={"SubjectUserName": "alice", "SubjectDomainName": "CORP",
                       "PrivilegeList": "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeDebugPrivilege"})
    # Display-manager noise that exclude_users hides by default
    for _ in range(3):
        add(4624, 7, data={"SubjectUserName": "WS01$", "SubjectDomainName": "CORP", "TargetUserName": "DWM-1",
                           "TargetDomainName": "Window Manager", "LogonType": 2})
        add(4672, 7, data={"SubjectUserName": "DWM-1", "SubjectDomainName": "Window Manager", "PrivilegeList": "SeAssignPrimaryTokenPrivilege"})
    # Brute force against one account, then a lockout
    for n in range(8):
        add(4625, 120 + n, keywords=FAILURE, data={"SubjectUserName": "-", "SubjectDomainName": "-",
            "TargetUserName": "administrator", "TargetDomainName": "CORP", "LogonType": 3, "Status": "0xc000006d",
            "SubStatus": "0xc000006a", "IpAddress": "198.51.100.23", "WorkstationName": "KALI"})
    add(4740, 129, computer="DC01.corp.local", data={"TargetUserName": "administrator", "TargetDomainName": "DC01",
        "SubjectUserName": "DC01$", "SubjectDomainName": "CORP"})
    # Password spray: one source, many accounts
    for n, user in enumerate(["alice", "bob", "carol", "dave", "erin", "frank"]):
        add(4625, 200 + n, keywords=FAILURE, data={"TargetUserName": user, "TargetDomainName": "CORP", "LogonType": 3,
            "Status": "0xc000006d", "SubStatus": "0xc000006a", "IpAddress": "::ffff:203.0.113.50"})
    # Hostile user names typed at a logon prompt (must never execute or repaint the terminal)
    add(4625, 230, keywords=FAILURE, data={"TargetUserName": '=HYPERLINK("http://evil.example","click")',
        "TargetDomainName": "CORP", "LogonType": 3, "SubStatus": "0xc0000064", "IpAddress": "203.0.113.77"})
    add(4625, 231, keywords=FAILURE, data={"TargetUserName": "\x1b[2J\x1b[31mRED", "TargetDomainName": "CORP",
        "LogonType": 3, "SubStatus": "0xc0000064", "IpAddress": "203.0.113.77"})
    # Account and group changes
    add(4720, 300, computer="DC01.corp.local", data={"TargetUserName": "svc_backup2", "TargetDomainName": "CORP",
        "SubjectUserName": "alice", "SubjectDomainName": "CORP"})
    add(4724, 301, computer="DC01.corp.local", data={"TargetUserName": "svc_backup2", "TargetDomainName": "CORP",
        "SubjectUserName": "alice", "SubjectDomainName": "CORP"})
    add(4732, 302, data={"MemberName": "-", "MemberSid": "S-1-5-21-1111111111-2222222222-3333333333-1105",
        "TargetUserName": "Administrators", "TargetDomainName": "Builtin", "SubjectUserName": "alice", "SubjectDomainName": "CORP"})
    add(4733, 340, data={"MemberSid": "S-1-5-21-1111111111-2222222222-3333333333-1099",
        "TargetUserName": "Remote Desktop Users", "TargetDomainName": "Builtin", "SubjectUserName": "bob", "SubjectDomainName": "CORP"})
    # Tampering
    add(4719, 400, keywords=SUCCESS, data={"SubjectUserName": "mallory", "SubjectDomainName": "CORP",
        "CategoryId": "%%8274", "SubcategoryId": "%%12544", "AuditPolicyChanges": "%%8448, %%8450"})
    add(1102, 401, user_data={"SubjectUserName": "mallory", "SubjectDomainName": "CORP", "SubjectUserSid": "S-1-5-21-1-2-3-1666"})
    # Another host
    add(4624, 420, computer="SRV01.corp.local", data={"TargetUserName": "svc_backup2", "TargetDomainName": "CORP",
        "LogonType": 10, "IpAddress": "10.0.0.42", "WorkstationName": "ADMIN-PC"})
    out.append("<Event xmlns='%s'><System><EventID>4624</EventID><Computer>WS01</Computer></System></Event>" % NS)  # no time
    out.append("<Event xmlns='%s'><!DOCTYPE x [<!ENTITY a 'b'>]><System/></Event>" % NS)  # DTD must be rejected
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    target = Path(__file__).with_name("sample_events.xml")
    target.write_text(build_sample(), encoding="utf-8")
    print(f"wrote {target} ({target.stat().st_size} bytes)", file=sys.stderr)
