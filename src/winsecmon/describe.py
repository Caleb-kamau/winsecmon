"""Human-readable descriptions built from raw event fields."""

from __future__ import annotations

from collections.abc import Mapping

LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}

# NTSTATUS / SubStatus values commonly seen in event 4625.
FAILURE_STATUS = {
    "0xc000006d": "Bad user name or authentication information",
    "0xc000006a": "Wrong password",
    "0xc0000064": "User name does not exist",
    "0xc0000234": "Account locked out",
    "0xc0000072": "Account disabled",
    "0xc000006f": "Logon outside allowed hours",
    "0xc0000070": "Workstation restriction",
    "0xc0000071": "Password expired",
    "0xc0000193": "Account expired",
    "0xc0000224": "Password must be changed at next logon",
    "0xc000015b": "Logon type not granted",
    "0xc0000133": "Clock difference too large",
}

_ACCOUNT_VERBS = {
    4720: "created account",
    4722: "enabled account",
    4723: "attempted a password change for",
    4724: "attempted a password reset for",
    4725: "disabled account",
    4726: "deleted account",
    4738: "changed account",
    4767: "unlocked account",
}
_GROUP_ADD = {4728, 4732, 4751, 4756}
_GROUP_REMOVE = {4729, 4733, 4752, 4757}
_GROUP_CREATE = {4727, 4731, 4754}
_GROUP_DELETE = {4730, 4734, 4758}
_GROUP_CHANGE = {4735, 4737, 4755}
GROUP_EVENT_IDS = _GROUP_ADD | _GROUP_REMOVE | _GROUP_CREATE | _GROUP_DELETE | _GROUP_CHANGE

# Events where the *target* fields name the account the event is about.
TARGET_ACCOUNT_IDS = {
    4624, 4625, 4648, 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767, 4768, 4769, 4771, 4776,
}


def clean(value: str | None) -> str | None:
    """Normalise Windows placeholders: empty and '-' mean 'not applicable'."""
    if value is None:
        return None
    value = value.strip()
    return None if value in ("", "-") else value


def failure_reason(status: str | None) -> str | None:
    if not status:
        return None
    return FAILURE_STATUS.get(status.strip().lower())


def qualified(user: str | None, domain: str | None) -> str | None:
    if not user:
        return None
    return f"{domain}\\{user}" if domain else user


def _privileges(data: Mapping[str, str]) -> str | None:
    raw = clean(data.get("PrivilegeList"))
    if not raw:
        return None
    names = raw.split()
    shown = ", ".join(names[:3])
    return shown + (f" (+{len(names) - 3} more)" if len(names) > 3 else "")


def build_message(
    event_id: int,
    name: str,
    *,
    subject: str | None,
    target: str | None,
    data: Mapping[str, str],
    logon_type_name: str | None,
    logon_type: int | None,
    source_ip: str | None,
    workstation: str | None,
    process_name: str | None,
    status: str | None,
) -> str:
    who = subject or "unknown"
    if event_id in (4624, 4625):
        kind = "Successful logon" if event_id == 4624 else "Failed logon"
        parts = [kind]
        if logon_type is not None:
            parts.append(f"type {logon_type}" + (f" ({logon_type_name})" if logon_type_name else ""))
        text = ", ".join(parts)
        if event_id == 4625 and process_name:
            text += ", via " + process_name.replace("\\", "/").rsplit("/", 1)[-1]
        origin = source_ip or workstation
        if origin:
            text += f" from {origin}"
            if source_ip and workstation and workstation != source_ip:
                text += f" ({workstation})"
        if event_id == 4625:
            reason = failure_reason(status)
            if reason:
                text += f": {reason}"
            elif status:
                text += f": status {status}"
        return text
    if event_id == 4648:
        server = clean(data.get("TargetServerName"))
        text = f"{who} used explicit credentials for {target or 'unknown'}"
        return text + (f" to reach {server}" if server else "")
    if event_id == 4672:
        privs = _privileges(data)
        return "Special privileges assigned" + (f": {privs}" if privs else "")
    if event_id in (4673, 4674):
        privs = _privileges(data)
        text = f"{who} used a privileged operation"
        if process_name:
            text += f" via {process_name}"
        return text + (f" ({privs})" if privs else "")
    if event_id == 4740:
        caller = clean(data.get("TargetDomainName"))
        text = f"Account {target or 'unknown'} locked out"
        return text + (f" (caller: {caller})" if caller else "")
    if event_id in _ACCOUNT_VERBS:
        return f"{who} {_ACCOUNT_VERBS[event_id]} {target or 'unknown'}"
    if event_id in GROUP_EVENT_IDS:
        group = clean(data.get("TargetUserName")) or "unknown group"
        member = clean(data.get("MemberName")) or clean(data.get("MemberSid"))
        if event_id in _GROUP_ADD:
            return f"{who} added {member or 'a member'} to group {group}"
        if event_id in _GROUP_REMOVE:
            return f"{who} removed {member or 'a member'} from group {group}"
        if event_id in _GROUP_CREATE:
            return f"{who} created group {group}"
        if event_id in _GROUP_DELETE:
            return f"{who} deleted group {group}"
        return f"{who} changed group {group}"
    if event_id == 1102:
        return f"Audit log cleared by {who}"
    if event_id == 4719:
        changes = clean(data.get("AuditPolicyChanges"))
        return f"System audit policy changed by {who}" + (f" (changes: {changes})" if changes else "")
    if event_id == 4912:
        return f"Per-user audit policy changed by {who}"
    if event_id == 4688:
        return f"Process created: {clean(data.get('NewProcessName')) or 'unknown'} by {who}"
    return name
