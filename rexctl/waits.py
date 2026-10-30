from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

from .connection import Connection, RpcConnection
from .errors import ApiError, UsageError, WaitTimeoutError
from .events import (
    EventFilter,
    compile_regex,
    normalize_event,
    redact_event,
    resilient_event,
)
from .protocol import TERMINAL
from .read import pick_status, read_tail, root_status, trim_lines
from .stream import TerminalFeed
from .target import Target

STREAM_TEXT_WINDOW = 1 << 20
STREAM_DEBOUNCE = 0.1


def poll_until(
    check: Callable[[], dict[str, Any] | None], timeout: float, interval: float, what: str
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        value = check()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise WaitTimeoutError(f"timed out after {timeout:g}s waiting for {what}")
        time.sleep(min(interval, max(0.0, deadline - time.monotonic())))


def wait_for_text(
    conn: Connection,
    t: Target,
    pattern: str,
    timeout: float,
    interval: float,
    feed: TerminalFeed | None = None,
    new: bool = False,
) -> dict[str, Any]:
    regex = compile_regex(pattern, re.MULTILINE)

    def check() -> dict[str, Any] | None:
        content = read_tail(conn, t, 200)["content"]
        found = regex.search(content)
        return {"matched": True, "match": found.group(0), "tail": trim_lines(content, 15)} if found else None

    if new:
        if feed is None:
            raise UsageError("--new needs the live data stream, which is off (--no-stream) or could not be opened")
        return {**stream_until_text(feed, regex, lambda: None, timeout, interval), "via": "stream"}
    if feed is None:
        return {**poll_until(check, timeout, interval, f"text /{pattern}/"), "via": "poll"}
    return {**stream_until_text(feed, regex, check, timeout, interval), "via": "stream"}


def stream_until_text(
    feed: TerminalFeed,
    regex: re.Pattern[str],
    check: Callable[[], dict[str, Any] | None],
    timeout: float,
    interval: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    seen = ""
    found = check()
    while not found:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WaitTimeoutError(f"timed out after {timeout:g}s waiting for text /{regex.pattern}/")
        items = feed.poll(min(remaining, interval))
        text = "".join(i.get("text", "") for i in items)
        if text:
            seen = (seen + text)[-STREAM_TEXT_WINDOW:]
            quiet_until = time.monotonic() + STREAM_DEBOUNCE
            while time.monotonic() < quiet_until:
                more = feed.poll(STREAM_DEBOUNCE)
                seen = (seen + "".join(i.get("text", "") for i in more))[-STREAM_TEXT_WINDOW:]
                if any(i.get("text") for i in more):
                    quiet_until = time.monotonic() + STREAM_DEBOUNCE
            in_stream = regex.search(seen)
            found = check()
            if not found and in_stream:
                found = {"matched": True, "match": in_stream.group(0), "tail": trim_lines(seen, 15)}
        if feed.ended and not found:
            raise ApiError(f"data stream ended ({feed.ended.get('reason')}) before the text appeared")
    return found


def wait_for_idle(
    conn: Connection, t: Target, quiet: float, timeout: float, interval: float, feed: TerminalFeed | None = None
) -> dict[str, Any]:
    if feed is not None:
        return {**stream_until_idle(conn, t, feed, quiet, timeout), "via": "stream"}
    state: dict[str, Any] = {"content": None, "since": time.monotonic()}

    def check() -> dict[str, Any] | None:
        content = read_tail(conn, t, 200)["content"]
        now = time.monotonic()
        if content != state["content"]:
            state.update(content=content, since=now)
        if now - state["since"] >= quiet:
            return {"matched": True, "idle_seconds": round(now - state["since"], 2), "tail": trim_lines(content, 15)}
        return None

    return {**poll_until(check, timeout, interval, f"{quiet:g}s of screen idle"), "via": "poll"}


def stream_until_idle(conn: Connection, t: Target, feed: TerminalFeed, quiet: float, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_output = time.monotonic()
    while True:
        now = time.monotonic()
        if now - last_output >= quiet:
            tail = trim_lines(read_tail(conn, t, 200)["content"], 15)
            return {"matched": True, "idle_seconds": round(now - last_output, 2), "tail": tail}
        if now >= deadline:
            raise WaitTimeoutError(f"timed out after {timeout:g}s waiting for {quiet:g}s of terminal idle")
        items = feed.poll(min(deadline - now, last_output + quiet - now))
        if any(i["kind"] == "output" for i in items):
            last_output = time.monotonic()
        if feed.ended:
            raise ApiError(f"data stream ended ({feed.ended.get('reason')}) while waiting for idle")


def status_check(conn: RpcConnection, t: Target, states: set[str]) -> Callable[[], dict[str, Any] | None]:
    def check() -> dict[str, Any] | None:
        status = root_status(conn.block_call(f"{TERMINAL}.program_status", t.session_id, t.block_id or "", {}))
        return {"matched": True, "status": status} if status and status.get("state") in states else None

    return check


def close_check(conn: RpcConnection, t: Target) -> Callable[[], dict[str, Any] | None]:
    def check() -> dict[str, Any] | None:
        try:
            return None if block_exists(conn, t) else {"matched": True, "closed": True}
        except ApiError as exc:
            if exc.details.get("code") == "session_not_found":
                return {"matched": True, "closed": True, "session_gone": True}
            raise

    return check


def wait_for_status(
    conn: RpcConnection, t: Target, states: set[str], timeout: float, interval: float
) -> dict[str, Any]:
    return poll_until(status_check(conn, t, states), timeout, interval, f"program status in {sorted(states)}")


def event_matches_target(normal: dict[str, Any], t: Target) -> bool:
    if normal["session_id"] != t.session_id:
        return False
    return normal["block_id"] in (None, t.block_id) or normal["name"] == "session_destroyed"


def wait_on_events(
    conn: Connection,
    t: Target,
    accept: Callable[[dict[str, Any]], dict[str, Any] | None],
    recheck: Callable[[], dict[str, Any] | None] | None,
    timeout: float,
    what: str,
) -> dict[str, Any]:
    conn.call("session.attach_all", {"event_scope": "all"})
    result = recheck() if recheck else None
    deadline = time.monotonic() + timeout
    while not result:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WaitTimeoutError(f"timed out after {timeout:g}s waiting for {what}")
        got = resilient_event(conn, min(remaining, 1.0))
        if got is None:
            continue
        if got[0] == "reconnected":
            result = recheck() if recheck else None
            continue
        normal = normalize_event(got[1])
        if event_matches_target(normal, t):
            result = accept(normal)
    return {**result, "via": "events"}


def status_from_event(normal: dict[str, Any]) -> dict[str, Any]:
    record = normal["payload"].get("record") or {}
    return pick_status(record)


def wait_for_status_events(conn: Connection, t: Target, states: set[str], timeout: float) -> dict[str, Any]:
    def accept(normal: dict[str, Any]) -> dict[str, Any] | None:
        if normal["name"] != "program_status_changed":
            return None
        status = status_from_event(normal)
        return {"matched": True, "status": status} if status.get("state") in states else None

    return wait_on_events(
        conn, t, accept, status_check(conn, t, states), timeout, f"program status in {sorted(states)}"
    )


def wait_for_close_events(conn: Connection, t: Target, timeout: float) -> dict[str, Any]:
    def accept(normal: dict[str, Any]) -> dict[str, Any] | None:
        if normal["name"] == "session_destroyed":
            return {"matched": True, "closed": True, "session_gone": True}
        return {"matched": True, "closed": True} if normal["name"] == "block_closed" else None

    return wait_on_events(conn, t, accept, close_check(conn, t), timeout, "block to close")


def wait_for_named_event(conn: Connection, t: Target, flt: EventFilter, timeout: float, what: str) -> dict[str, Any]:
    def accept(normal: dict[str, Any]) -> dict[str, Any] | None:
        redacted = redact_event(normal)  # before filtering, so --where cannot probe hidden text
        if not flt.accepts(redacted):
            return None
        return {"matched": True, "event": {"name": redacted["name"], "payload": redacted["payload"]}}

    return wait_on_events(conn, t, accept, None, timeout, what)


def regex_where(path: str, pattern: str | None) -> list[tuple[str, str, str]]:
    if not pattern:
        return []
    compile_regex(pattern)
    return [(path, "~", pattern)]


def block_exists(conn: RpcConnection, t: Target) -> bool:
    blocks = conn.call("session.list_blocks", {"session_id": t.session_id})["blocks"] or []
    return any(b["block_id"] == t.block_id for b in blocks)


def wait_for_close(conn: RpcConnection, t: Target, timeout: float, interval: float) -> dict[str, Any]:
    return poll_until(close_check(conn, t), timeout, interval, "block to close")
