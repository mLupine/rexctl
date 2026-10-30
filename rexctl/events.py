from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .connection import Connection
from .errors import ApiError, RexError, UnreachableError, UsageError, WaitTimeoutError

DROP_CLOSE_CODES = {1001, 1006, 1008, 1011, 1012, 1013}
TERMINAL_EVENT_NAMES = {
    "bell",
    "child_exited",
    "clipboard_written",
    "desktop_notification",
    "process_changed",
    "program_status_changed",
    "program_status_removed",
    "progress_report",
    "pwd_changed",
    "selection_copied",
    "size_changed",
    "title_changed",
    "url_clicked",
}
SENSITIVE_EVENTS = {"clipboard_written", "selection_copied"}
EVENT_ALIASES = {
    "cwd_changed": "pwd_changed",
    "cwd": "pwd_changed",
    "title": "title_changed",
    "status": "program_status_changed",
    "exit": "child_exited",
    "closed": "block_closed",
}


def unwrap_session_event(payload: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    if payload.get("type") == "session_event":
        inner = payload.get("payload") or {}
        return inner.get("session_id"), inner.get("event") or {}
    return None, payload


def normalize_event(message: dict[str, Any]) -> dict[str, Any]:
    session_id, event = unwrap_session_event(message.get("payload") or {})
    name, body = event.get("type", ""), event.get("payload") or {}
    normal: dict[str, Any] = {
        "seq": message.get("seq"),
        "name": name,
        "session_id": session_id,
        "block_id": body.get("block_id"),
        "payload": body,
    }
    if name == "block_event":
        normal.update(name=body.get("name", ""), creator=body.get("creator_name"), payload=body.get("payload") or {})
    return normal


def redact_event(normal: dict[str, Any]) -> dict[str, Any]:
    if normal["name"] not in SENSITIVE_EVENTS:
        return normal
    payload = dict(normal["payload"])
    text = payload.pop("text", None)
    if text is not None:
        payload["text_redacted_chars"] = len(text)
    return {**normal, "payload": payload, "redacted": True}


def canonical_event_names(names: list[str] | None) -> set[str]:
    wanted: set[str] = set()
    for entry in names or []:
        wanted.update(EVENT_ALIASES.get(n.strip(), n.strip()) for n in entry.split(",") if n.strip())
    return wanted


def dig(value: Any, path: str) -> Any:
    for part in path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return None
    return value


def compile_regex(pattern: str, flags: int = 0) -> re.Pattern[str]:
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise UsageError(f"bad regular expression {pattern!r}: {exc}") from None


def parse_where(conditions: list[str] | None) -> list[tuple[str, str, str]]:
    parsed = []
    for condition in conditions or []:
        match = re.fullmatch(r"([\w.]+)(=|~)(.*)", condition, re.DOTALL)
        if not match:
            raise UsageError(f"bad --where {condition!r}; use PATH=VALUE or PATH~REGEX, e.g. record.state=blocked")
        if match.group(2) == "~":
            compile_regex(match.group(3))
        parsed.append((match.group(1), match.group(2), match.group(3)))
    return parsed


def matches_where(normal: dict[str, Any], conditions: list[tuple[str, str, str]]) -> bool:
    for path, operator, expected in conditions:
        actual = dig(normal["payload"], path)
        if actual is None:
            actual = dig(normal, path)
        text = "" if actual is None else str(actual)
        if (operator == "=" and text != expected) or (operator == "~" and not re.search(expected, text)):
            return False
    return True


@dataclass
class EventFilter:
    names: set[str] = field(default_factory=set)
    session_id: str | None = None
    block_id: str | None = None
    where: list[tuple[str, str, str]] = field(default_factory=list)

    def accepts(self, normal: dict[str, Any]) -> bool:
        if self.names and normal["name"] not in self.names:
            return False
        if self.session_id and normal["session_id"] != self.session_id:
            return False
        if self.block_id and normal["block_id"] != self.block_id:
            return False
        return matches_where(normal, self.where)

    @property
    def needs_block_events(self) -> bool:
        return bool(self.names & TERMINAL_EVENT_NAMES) or self.block_id is not None


def next_event(conn: Connection, timeout: float) -> dict[str, Any] | None:
    if conn.pending_events:
        return conn.pending_events.pop(0)
    try:
        message = conn.read_message(timeout)
    except WaitTimeoutError:
        return None
    return message if message.get("type") == "event" else None


def is_dropped(exc: RexError) -> bool:
    return isinstance(exc, UnreachableError) or exc.details.get("code") in DROP_CLOSE_CODES


def resilient_event(conn: Connection, timeout: float, reconnect: bool = True) -> tuple[str, Any] | None:
    try:
        message = next_event(conn, timeout)
    except (UnreachableError, ApiError) as exc:
        if not reconnect or not is_dropped(exc):
            raise
        return "reconnected", conn.reconnect()
    return ("event", message) if message else None


def reconnect_marker(host: str, resumed: bool) -> dict[str, Any]:
    return {
        "host": host,
        "event": "rexctl_reconnected",
        "resumed": resumed,
        "note": "events during the gap are lost; re-read state (ls/status)",
    }


def event_line(host: str, normal: dict[str, Any]) -> dict[str, Any]:
    return {
        "host": host,
        "seq": normal["seq"],
        "name": normal["name"],
        "session_id": normal["session_id"],
        "block_id": normal["block_id"],
        "payload": normal["payload"],
        **({"redacted": True} if normal.get("redacted") else {}),
    }
