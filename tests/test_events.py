import json
import socket
from typing import Any

import pytest

from conftest import FakeRexServer
from rexctl import cli, connection
from rexctl.errors import UnreachableError, UsageError, WaitTimeoutError
from rexctl.events import (
    EventFilter,
    canonical_event_names,
    normalize_event,
    parse_where,
    redact_event,
    resilient_event,
)
from rexctl.output import emit
from rexctl.target import Target
from rexctl.waits import regex_where, wait_for_close_events, wait_for_named_event, wait_for_status_events
from rexctl.ws import WebSocket

SID, BID = "session:1", "block:1"


def drop(server: FakeRexServer) -> None:
    server.server_sock.shutdown(socket.SHUT_RDWR)


def block_event(name: str, payload: dict[str, Any] | None = None, block_id: str = BID) -> dict[str, Any]:
    body: dict[str, Any] = {"block_id": block_id, "creator_name": "com.superlogical.terminal", "name": name}
    if payload is not None:
        body["payload"] = payload
    return {"type": "block_event", "payload": body}


def message(event: dict[str, Any], session: bool = True, seq: int = 1) -> dict[str, Any]:
    payload = {"type": "session_event", "payload": {"session_id": SID, "event": event}} if session else event
    return {"type": "event", "seq": seq, "payload": payload}


def target() -> Target:
    return Target("h", "https://fake.invalid", SID, BID)


def test_normalize_block_and_session_events():
    normal = normalize_event(message(block_event("title_changed", {"title": "vim"}), seq=5))
    assert (normal["name"], normal["session_id"], normal["block_id"], normal["payload"]) == (
        "title_changed",
        SID,
        BID,
        {"title": "vim"},
    )
    closed = normalize_event(message({"type": "block_closed", "payload": {"block_id": BID}}))
    assert closed["name"] == "block_closed" and closed["block_id"] == BID
    server_level = normalize_event(message({"type": "session_created", "payload": {"session": {}}}, session=False))
    assert server_level["session_id"] is None


def test_event_filter_names_aliases_and_where():
    flt = EventFilter(names=canonical_event_names(["cwd,bell"]), where=parse_where(["pwd~^file:///tmp"]))
    assert flt.names == {"pwd_changed", "bell"} and flt.needs_block_events
    assert flt.accepts(normalize_event(message(block_event("pwd_changed", {"pwd": "file:///tmp/x"}))))
    assert not flt.accepts(normalize_event(message(block_event("pwd_changed", {"pwd": "file:///home"}))))
    assert not flt.accepts(normalize_event(message(block_event("title_changed", {"title": "x"}))))


def test_where_reaches_nested_record_state():
    flt = EventFilter(where=parse_where(["record.state=blocked"]))
    event = message(block_event("program_status_changed", {"id": "a", "record": {"state": "blocked"}}))
    assert flt.accepts(normalize_event(event))


def test_bad_where_is_usage_error():
    with pytest.raises(UsageError):
        parse_where(["nonsense"])


def test_clipboard_text_is_redacted():
    normal = normalize_event(message(block_event("clipboard_written", {"text": "hunter2", "bytes": 7})))
    redacted = redact_event(normal)
    assert "text" not in redacted["payload"] and redacted["payload"]["text_redacted_chars"] == 7


def test_emit_scrubs_tokens(capsys):
    emit({"client": {"reconnect_token": "SECRET", "id": "c"}, "list": [{"ticket": "T"}]})
    out = capsys.readouterr().out
    assert "SECRET" not in out and '"T"' not in out and "c" in out


def test_connection_repr_hides_welcome_token():
    conn = connection.Connection(url="https://x", welcome={"client": {"reconnect_token": "SECRET"}})
    assert "SECRET" not in repr(conn) and conn.reconnect_token == "SECRET"


def test_reconnect_sends_token_and_restores_attachment(fake_server, monkeypatch):
    first = fake_server(lambda m, s: s.respond(m))
    first.welcome_extra = {"client": {"id": "client:1", "reconnect_token": "TOK-A"}}
    conn = first.connection()
    conn.call("session.attach_all", {"event_scope": "all"})
    second = fake_server(lambda m, s: s.respond(m))
    second.welcome_extra = {"client": {"id": "client:1", "reconnect_token": "TOK-B", "resumed": True}}
    monkeypatch.setattr(WebSocket, "connect", classmethod(lambda cls, *a, **k: WebSocket(second.client_sock)))
    drop(first)
    got = resilient_event(conn, 1)
    assert got == ("reconnected", True)
    assert second.received[0]["reconnect_token"] == "TOK-A"
    assert [m["method"] for m in second.received[1:]] == ["session.attach_all"]
    assert second.received[1]["payload"] == {"event_scope": "all"} and conn.reconnect_token == "TOK-B"


def test_reconnect_gives_up_with_unreachable(fake_server, monkeypatch):
    first = fake_server(lambda m, s: s.respond(m))
    conn = first.connection()

    def refuse(cls, *a, **k):
        raise UnreachableError("down")

    monkeypatch.setattr(WebSocket, "connect", classmethod(refuse))
    monkeypatch.setattr(connection, "RECONNECT_BACKOFF", 0.0)
    drop(first)
    with pytest.raises(UnreachableError):
        resilient_event(conn, 1)


def test_no_reconnect_raises_on_drop(fake_server):
    first = fake_server(lambda m, s: s.respond(m))
    conn = first.connection()
    drop(first)
    with pytest.raises(UnreachableError):
        resilient_event(conn, 1, reconnect=False)


def waiting_server(fake_server, events: list[dict[str, Any]], status_state: str | None = None):
    sent: list[bool] = []

    def handler(msg: dict[str, Any], server: FakeRexServer) -> None:
        if msg["method"] == "session.attach_all":
            server.respond(msg, {"sessions": []})
            if not sent:
                sent.append(True)
                for index, event in enumerate(events, 1):
                    server.send(events_message(event, index))
        elif msg["method"].endswith("program_status"):
            records = [{"state": status_state, "updated_at": "1"}] if status_state else []
            server.respond(msg, {"records": records})
        elif msg["method"] == "session.list_blocks":
            server.respond(msg, {"blocks": [{"block_id": BID}]})
        else:
            server.respond(msg)

    return fake_server(handler).connection()


def events_message(event: dict[str, Any], seq: int) -> dict[str, Any]:
    return message(event, seq=seq)


def test_wait_for_bell(fake_server):
    conn = waiting_server(fake_server, [block_event("title_changed", {"title": "a"}), block_event("bell")])
    flt = EventFilter(names={"bell"})
    result = wait_for_named_event(conn, target(), flt, 3, "bell")
    assert result["via"] == "events" and result["event"]["name"] == "bell"


def test_wait_for_ignores_other_blocks(fake_server):
    conn = waiting_server(fake_server, [block_event("bell", block_id="block:other")])
    with pytest.raises(WaitTimeoutError):
        wait_for_named_event(conn, target(), EventFilter(names={"bell"}), 0.5, "bell")


def test_wait_for_title_regex(fake_server):
    events = [block_event("title_changed", {"title": "bash"}), block_event("title_changed", {"title": "vim file"})]
    conn = waiting_server(fake_server, events)
    flt = EventFilter(names={"title_changed"}, where=regex_where("title", "^vim"))
    assert wait_for_named_event(conn, target(), flt, 3, "title")["event"]["payload"]["title"] == "vim file"


def test_a_where_filter_cannot_probe_redacted_clipboard_text(fake_server):
    conn = waiting_server(fake_server, [block_event("clipboard_written", {"text": "hunter2", "bytes": 7})])
    flt = EventFilter(names={"clipboard_written"}, where=parse_where(["text~^h"]))
    with pytest.raises(WaitTimeoutError):
        wait_for_named_event(conn, target(), flt, 0.5, "clipboard")


def test_a_bad_title_regex_is_a_usage_error():
    with pytest.raises(UsageError):
        regex_where("title", "[")


def test_wait_for_status_event_blocked(fake_server):
    record = {"id": "a", "record": {"state": "blocked", "app": "claude"}}
    conn = waiting_server(
        fake_server,
        [
            block_event("program_status_changed", {"id": "a", "record": {"state": "working"}}),
            block_event("program_status_changed", record),
        ],
        status_state="working",
    )
    result = wait_for_status_events(conn, target(), {"blocked", "done"}, 3)
    assert result["status"]["state"] == "blocked" and result["via"] == "events"


def test_wait_for_status_already_satisfied_without_event(fake_server):
    conn = waiting_server(fake_server, [], status_state="done")
    assert wait_for_status_events(conn, target(), {"done"}, 2)["status"]["state"] == "done"


def test_wait_for_closed_by_event(fake_server):
    conn = waiting_server(fake_server, [{"type": "block_closed", "payload": {"block_id": BID}}])
    assert wait_for_close_events(conn, target(), 3)["closed"] is True


def test_wait_for_session_destroyed_counts_as_closed(fake_server):
    conn = waiting_server(fake_server, [{"type": "session_destroyed", "payload": {}}])
    assert wait_for_close_events(conn, target(), 3)["session_gone"] is True


def test_cli_events_filters_and_redacts(fake_server, monkeypatch, capsys):
    events = [
        block_event("bell"),
        block_event("clipboard_written", {"text": "secret", "bytes": 6}),
        block_event("title_changed", {"title": "t"}),
    ]
    conn = waiting_server(fake_server, events)
    conn.call = _call_with_fixed_sessions(conn.call)
    monkeypatch.setattr(conn, "close", lambda: None)
    monkeypatch.setattr(connection, "connect", lambda url, timeout=10.0: conn)
    code = cli.main(["-H", "alpha", "events", "--duration", "1.5", "--filter", "bell,clipboard_written"])
    lines = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert code == 0 and [x["name"] for x in lines] == ["bell", "clipboard_written"]
    assert "secret" not in json.dumps(lines) and lines[1]["redacted"] is True


def _call_with_fixed_sessions(original):
    def call(method, payload=None, timeout=None):
        return original(method, payload, timeout)

    return call
