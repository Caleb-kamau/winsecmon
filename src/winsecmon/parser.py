"""Turn raw Windows event XML into SecurityEvent objects.

Parsing is defensive: one bad event never stops a run. Event XML comes from a log that
unprivileged users and remote hosts can influence (for example the user name typed into a
failed logon), so DTDs are rejected outright and every value is treated as untrusted text.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from datetime import datetime, timezone

from .describe import (
    GROUP_EVENT_IDS,
    LOGON_TYPES,
    TARGET_ACCOUNT_IDS,
    build_message,
    clean,
    qualified,
)
from .errors import MalformedEventError, QueryError
from .models import EventDefinition, SecurityEvent, fallback_definition

_DTD = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)
_EVENT_BLOCK = re.compile(r"<Event\b.*?</Event\s*>", re.DOTALL)
_RECORD_ID = re.compile(r"<EventRecordID>\s*(\d+)\s*<")
_TIME = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z?$")

# Characters that XML 1.0 cannot represent (raw, or as numeric references). A user name typed at a
# logon prompt can contain them; replacing them keeps the event instead of letting an attacker
# hide activity by making its record unparseable.
_INVALID_XML_CHARS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")
_CHAR_REF = re.compile(r"&#(x[0-9a-fA-F]+|[0-9]+);")

_KEYWORD_SUCCESS = 0x0020000000000000
_KEYWORD_FAILURE = 0x0010000000000000


def _replace_bad_ref(match: re.Match[str]) -> str:
    text = match.group(1)
    try:
        code = int(text[1:], 16) if text[0] == "x" else int(text)
    except ValueError:
        return "\ufffd"
    valid = code in (9, 10, 13) or 0x20 <= code <= 0xD7FF or 0xE000 <= code <= 0xFFFD or 0x10000 <= code <= 0x10FFFF
    return match.group(0) if valid else "\ufffd"


def sanitize_xml_text(text: str) -> str:
    return _INVALID_XML_CHARS.sub("\ufffd", _CHAR_REF.sub(_replace_bad_ref, text))


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(parent: ET.Element, name: str) -> ET.Element | None:
    for node in parent:
        if _local(node.tag) == name:
            return node
    return None


def _text(parent: ET.Element, name: str) -> str | None:
    node = _child(parent, name)
    return node.text.strip() if node is not None and node.text else None


def parse_system_time(value: str | None) -> datetime:
    match = _TIME.match((value or "").strip())
    if not match:
        raise MalformedEventError(f"invalid TimeCreated value {value!r}")
    year, month, day, hour, minute, second, fraction = match.groups()
    micro = int((fraction or "0")[:6].ljust(6, "0"))
    try:
        return datetime(
            int(year), int(month), int(day), int(hour), int(minute), int(second), micro,
            tzinfo=timezone.utc,
        )
    except ValueError as exc:
        raise MalformedEventError(f"invalid TimeCreated value {value!r}: {exc}") from None


def _event_data(root: ET.Element) -> dict[str, str]:
    data: dict[str, str] = {}
    for section in root:
        kind = _local(section.tag)
        if kind == "EventData":
            for index, item in enumerate(section, start=1):
                if _local(item.tag) == "Data":
                    data[item.get("Name") or f"Data{index}"] = (item.text or "").strip()
        elif kind == "UserData":  # e.g. event 1102 wraps its fields in a payload element
            for payload in section:
                for item in payload:
                    data[_local(item.tag)] = (item.text or "").strip()
    return data


def _strip_mapped_ipv4(address: str | None) -> str | None:
    address = clean(address)
    if address and address.lower().startswith("::ffff:") and "." in address:
        return address[7:]
    return address


def parse_event(
    xml_text: str, definitions: Mapping[int, EventDefinition] | None = None
) -> SecurityEvent:
    """Parse one <Event> element. Raises MalformedEventError if it is unusable."""
    if _DTD.search(xml_text):
        raise MalformedEventError("contains a DTD or entity declaration (rejected for safety)")
    try:
        root = ET.fromstring(sanitize_xml_text(xml_text))
    except ET.ParseError as exc:
        raise MalformedEventError(f"invalid XML: {exc}") from None
    if _local(root.tag) != "Event":
        raise MalformedEventError(f"unexpected root element <{_local(root.tag)}>")
    system = _child(root, "System")
    if system is None:
        raise MalformedEventError("missing <System> section")

    raw_id = _text(system, "EventID")
    try:
        event_id = int(raw_id or "")
    except ValueError:
        raise MalformedEventError(f"invalid EventID {raw_id!r}") from None
    if not 0 <= event_id <= 65535:
        raise MalformedEventError(f"EventID {event_id} out of range")

    time_node = _child(system, "TimeCreated")
    time_utc = parse_system_time(time_node.get("SystemTime") if time_node is not None else None)

    record_text = _text(system, "EventRecordID")
    level_text = _text(system, "Level")
    provider = _child(system, "Provider")
    keywords = _text(system, "Keywords")
    outcome = None
    if keywords:
        try:
            bits = int(keywords, 16)
            outcome = "success" if bits & _KEYWORD_SUCCESS else "failure" if bits & _KEYWORD_FAILURE else None
        except ValueError:
            pass

    data = _event_data(root)
    definition = (definitions or {}).get(event_id) or fallback_definition(event_id)

    subject_user, subject_domain = clean(data.get("SubjectUserName")), clean(data.get("SubjectDomainName"))
    target_user, target_domain = clean(data.get("TargetUserName")), clean(data.get("TargetDomainName"))
    subject = qualified(subject_user, subject_domain)
    target = qualified(target_user, target_domain)

    if event_id in GROUP_EVENT_IDS:
        account, object_name = subject, qualified(target_user, target_domain)
    elif event_id in TARGET_ACCOUNT_IDS:
        account, object_name = target or subject, None
    else:
        account, object_name = subject or target, None

    logon_type = None
    raw_type = clean(data.get("LogonType"))
    if raw_type is not None:
        try:
            logon_type = int(raw_type)
        except ValueError:
            pass
    logon_type_name = LOGON_TYPES.get(logon_type) if logon_type is not None else None

    source_ip = _strip_mapped_ipv4(data.get("IpAddress"))
    workstation = clean(data.get("WorkstationName"))
    process_name = (
        clean(data.get("NewProcessName")) or clean(data.get("ProcessName"))
        or clean(data.get("CallerProcessName"))
    )
    status = clean(data.get("SubStatus"))
    if status is None or status.lower() == "0x0":
        status = clean(data.get("Status"))

    message = build_message(
        event_id,
        definition.name,
        subject=subject,
        target=target,
        data=data,
        logon_type_name=logon_type_name,
        logon_type=logon_type,
        source_ip=source_ip,
        workstation=workstation,
        process_name=process_name,
        status=status if event_id == 4625 else None,
    )

    return SecurityEvent(
        event_id=event_id,
        time_utc=time_utc,
        computer=_text(system, "Computer") or "(unknown)",
        channel=_text(system, "Channel") or "",
        provider=(provider.get("Name") or "") if provider is not None else "",
        record_id=int(record_text) if record_text and record_text.isdigit() else None,
        level=int(level_text) if level_text and level_text.isdigit() else None,
        outcome=outcome,
        name=definition.name,
        category=definition.category,
        severity=definition.severity,
        account=account,
        subject_user=subject_user,
        subject_domain=subject_domain,
        target_user=target_user,
        target_domain=target_domain,
        object_name=object_name,
        logon_type=logon_type,
        logon_type_name=logon_type_name,
        source_ip=source_ip,
        workstation=workstation,
        process_name=process_name,
        status=status,
        message=message,
        data=data,
    )


def parse_events_from_text(
    text: str, definitions: Mapping[int, EventDefinition] | None = None
) -> tuple[list[SecurityEvent], list[str], int]:
    """Split wevtutil / Get-WinEvent XML output into events.

    Returns (events, malformed_reasons, blocks_seen). Each event is parsed independently.
    """
    blocks = _EVENT_BLOCK.findall(text)
    if not blocks:
        if text.strip():
            snippet = " ".join(text.split())[:160]
            raise QueryError(
                f"The Windows tool returned output that contains no events: {snippet!r}",
                hint="Run `winsecmon check` to diagnose the environment.",
            )
        return [], [], 0
    events: list[SecurityEvent] = []
    problems: list[str] = []
    for position, block in enumerate(blocks, start=1):
        try:
            events.append(parse_event(block, definitions))
        except MalformedEventError as exc:
            record = _RECORD_ID.search(block)
            where = f"record {record.group(1)}" if record else f"event #{position} in output"
            problems.append(f"{where}: {exc}")
    return events, problems, len(blocks)
