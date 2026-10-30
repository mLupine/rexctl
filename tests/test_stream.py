import json
import time
from typing import Any

import pytest

from conftest import MARKER, NONCE, FakeDataServer, FakeRexServer, rex_message, welcome_bytes
from rexctl import cli, connection
from rexctl.errors import ApiError, UnreachableError, UsageError, WaitTimeoutError
from rexctl.stream import (
    MAX_APC_BYTES,
    DataRejectedError,
    StreamClosed,
    StreamDecoder,
    TerminalFeed,
    VtTextStripper,
    decode_ticket,
    hello_message,
    parse_welcome,
    resume_message,
)
from rexctl.target import Target
from rexctl.waits import poll_until, wait_for_idle, wait_for_text
from rexctl.ws import WebSocket


@pytest.fixture
def data_server():
    server = FakeDataServer()
    yield server
    server.shutdown()


def test_ticket_and_handshake_messages():
    assert hello_message("AAECAwQFBgcICQoLDA0ODw") == b"\x01" + bytes(range(16))
    assert resume_message(b"R" * 16, 258) == b"\x02" + b"R" * 16 + (258).to_bytes(8, "little")
    with pytest.raises(ApiError):
        decode_ticket("AAEC")


def test_parse_welcome_and_reject():
    welcome = parse_welcome(welcome_bytes(b"K" * 16, 60000, 99))
    assert (welcome.token, welcome.keep_ms, welcome.nonce) == (b"K" * 16, 60000, 99)
    with pytest.raises(DataRejectedError) as err:
        parse_welcome(b"\x82\x07")
    assert err.value.details["reason"] == 7 and "subprotocol" in err.value.message
    with pytest.raises(ApiError):
        parse_welcome(b"\x81short")


def test_hello_is_sent_and_welcome_parsed(data_server):
    data_stream = data_server.accept()
    assert data_server.first_message == b"\x01" + bytes(range(16))
    assert data_stream.welcome.nonce == NONCE


def test_decoder_skips_snapshot_split_across_chunks():
    decoder = StreamDecoder(NONCE)
    raw = b"SNAPSHOT\x00\x01binary" + rex_message({"type": "resize", "cols": 80, "rows": 24}) + b"hello \x1b[1mworld"
    items = []
    for i in range(0, len(raw), 7):
        items += decoder.feed(raw[i : i + 7])
    kinds = [k for k, _ in items]
    assert kinds[0] == "message" and items[0][1]["cols"] == 80
    assert b"".join(v for k, v in items if k == "output") == b"hello \x1b[1mworld"
    assert decoder.snapshot_bytes == len(b"SNAPSHOT\x00\x01binary")


def test_decoder_ignores_lookalike_with_other_nonce():
    decoder = StreamDecoder(NONCE)
    fake = rex_message({"type": "child_exited"}, nonce=1)
    items = decoder.feed(
        b"snap" + MARKER + b"{}\x1b\\" + b"a" + fake + b"b" + rex_message({"type": "child_exited", "exit_code": 3})
    )
    outputs = b"".join(v for k, v in items if k == "output")
    assert outputs == b"a" + fake + b"b"
    assert items[-1] == ("message", {"type": "child_exited", "exit_code": 3})


def test_decoder_holds_partial_marker_until_complete():
    decoder = StreamDecoder(NONCE)
    decoder.feed(b"snap" + MARKER + b"{}\x1b\\")
    first = decoder.feed(b"text\x1b_rex1;42")
    assert first == [("output", b"text")]
    rest = decoder.feed(b"4242;" + b'{"type":"theme"}' + b"\x1b\\after")
    assert rest == [("message", {"type": "theme"}), ("output", b"after")]


def strip(*chunks: bytes) -> str:
    stripper = VtTextStripper()
    return "".join(stripper.feed(c) for c in chunks)


def test_stripper_removes_sequences():
    data = b"\x1b[31mred\x1b[0m \x1b]0;title\x07ok\x1b]8;;http://x\x1b\\ link\x1b(B \x1b[?2004hprompt"
    assert strip(data) == "red ok link prompt"


def test_stripper_line_endings_and_backspace():
    assert strip(b"one\r\ntwo\r\x1b[Kthree\rfour") == "one\ntwo\nthree\nfour"
    assert strip(b"abc\x08d") == "abd"


def test_stripper_handles_utf8_and_escape_split_across_chunks():
    raw = "zażółć \x1b[38;5;2m✓".encode()
    assert strip(raw[:5], raw[5:12], raw[12:]) == "zażółć ✓"


def test_stream_read_counts_bytes_and_resumes(data_server, monkeypatch):
    stream = data_server.accept()
    data_server.send(b"x" * 100)
    assert len(stream.read(1)) == 100 and stream.received == 100
    second = FakeDataServer()
    try:
        second.send(welcome_bytes(b"N" * 16))
        monkeypatch.setattr(WebSocket, "connect", classmethod(lambda cls, *a, **k: second.client_ws()))
        data_server.close_with(1001, "keepalive timeout")
        assert stream.read(1) == b""
        assert second.read_client_message() == b"\x02" + b"T" * 16 + (100).to_bytes(8, "little")
        assert stream.welcome.token == b"N" * 16
    finally:
        second.shutdown()


def test_stream_close_block_closed_is_final(data_server):
    stream = data_server.accept()
    data_server.close_with(4000, "block closed")
    with pytest.raises(StreamClosed) as err:
        stream.read(1)
    assert err.value.end_reason == "block_closed" and not err.value.resumable


class FeedConn:
    def __init__(self, server: FakeRexServer, screen: list[str]) -> None:
        self.inner = server.connection()
        self.ws = self.inner.ws
        self.screen = screen
        self.calls: list[str] = []
        self.timeout = 3

    def __enter__(self) -> "FeedConn":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def service_control(self) -> None:
        self.inner.service_control()

    def call(self, method, payload=None, timeout=None):
        self.calls.append(method)
        return {}

    def block_call(self, method, session_id, block_id, args=None, timeout=None):
        if method.endswith(".format"):
            return {"content": self.screen[0], "total": len(self.screen[0]), "eof": True}
        return {"rows": 24}


def make_feed(data_server, fake_server, screen):
    control = fake_server(lambda message, server: None)
    conn = FeedConn(control, screen)
    stream = data_server.accept()
    data_server.send(b"SNAP" + rex_message({"type": "resize", "cols": 80, "rows": 24}))
    return TerminalFeed(conn, stream), conn


def target() -> Target:
    return Target("h", "https://fake.invalid", "session:1", "block:1")


def test_wait_for_text_matches_stream_text_without_screen(data_server, fake_server):
    feed, conn = make_feed(data_server, fake_server, ["nothing yet"])
    data_server.send(b"\x1b[32mBUILD OK\x1b[0m\r\n")
    result = wait_for_text(conn, target(), r"BUILD (OK|FAILED)", 3, 0.2, feed)
    assert result["via"] == "stream" and result["match"] == "BUILD OK"


def test_wait_for_text_matches_screen_immediately(data_server, fake_server):
    feed, conn = make_feed(data_server, fake_server, ["already DONE here"])
    result = wait_for_text(conn, target(), "DONE", 3, 0.2, feed)
    assert result["match"] == "DONE"


def test_wait_for_text_times_out(data_server, fake_server):
    feed, conn = make_feed(data_server, fake_server, ["nope"])
    with pytest.raises(WaitTimeoutError):
        wait_for_text(conn, target(), "never", 0.6, 0.2, feed)


def test_wait_for_text_reports_stream_end(data_server, fake_server):
    feed, conn = make_feed(data_server, fake_server, ["nope"])
    data_server.close_with(4000, "block closed")
    with pytest.raises(ApiError) as err:
        wait_for_text(conn, target(), "never", 3, 0.2, feed)
    assert "block_closed" in err.value.message


def test_wait_for_idle_resets_on_output(data_server, fake_server):
    feed, conn = make_feed(data_server, fake_server, ["screen"])
    for _ in range(3):
        data_server.send(b"tick\n")
        time.sleep(0.15)
    started = time.monotonic()
    result = wait_for_idle(conn, target(), 0.4, 3, 0.2, feed)
    assert result["via"] == "stream" and time.monotonic() - started >= 0.35


def test_wait_for_text_falls_back_to_polling_without_feed(fake_server):
    conn = FeedConn(fake_server(lambda m, s: None), ["hello polled"])
    result = wait_for_text(conn, target(), "polled", 2, 0.1)
    assert result["via"] == "poll"


def test_feed_surfaces_child_exit_message(data_server, fake_server):
    feed, conn = make_feed(data_server, fake_server, ["x"])
    data_server.send(rex_message({"type": "child_exited", "exit_code": 7}))
    items = []
    deadline = time.monotonic() + 2
    while not any(i.get("exit_code") == 7 for i in items) and time.monotonic() < deadline:
        items += feed.poll(0.2)
    assert any(i.get("exit_code") == 7 for i in items)


def test_cli_stream_json_lines_and_max_bytes(data_server, fake_server, monkeypatch, capsys):
    feed, conn = make_feed(data_server, fake_server, ["screen text"])
    monkeypatch.setattr(connection, "connect", lambda url, timeout=10.0: conn)
    monkeypatch.setattr(cli, "target_for", lambda *a, **k: target())
    monkeypatch.setattr(cli, "open_feed", lambda *a, **k: feed)
    data_server.send(b"line one\r\nline two\r\n")
    code = cli.main(["-H", "alpha", "stream", "--duration", "5", "--max-bytes", "10", "--with-screen"])
    lines = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert code == 0
    assert [x["event"] for x in lines][0] == "screen" and lines[-1]["event"] == "end"
    assert lines[-1]["reason"] == "max_bytes"
    text = "".join(x["text"] for x in lines if x["event"] == "data")
    assert text.startswith("line one\nline two")
    assert any(x["event"] == "rex" and x["message"]["type"] == "resize" for x in lines)
    assert "session.detach" in conn.calls


def test_cli_stream_text_mode(data_server, fake_server, monkeypatch, capsys):
    feed, conn = make_feed(data_server, fake_server, ["s"])
    monkeypatch.setattr(connection, "connect", lambda url, timeout=10.0: conn)
    monkeypatch.setattr(cli, "target_for", lambda *a, **k: target())
    monkeypatch.setattr(cli, "open_feed", lambda *a, **k: feed)
    data_server.send(b"\x1b[1mplain\x1b[0m\n")
    data_server.close_with(4000, "block closed")
    assert cli.main(["-H", "alpha", "stream", "--duration", "5", "--text"]) == 0
    assert capsys.readouterr().out == "plain\n"


def test_wait_for_new_text_ignores_what_is_already_on_screen(data_server, fake_server):
    feed, conn = make_feed(data_server, fake_server, ["old $ prompt"])
    with pytest.raises(WaitTimeoutError):
        wait_for_text(conn, target(), r"\$", 0.5, 0.1, feed, new=True)
    data_server.send(b"build done\r\nnew $ ")
    result = wait_for_text(conn, target(), r"new \$", 3, 0.1, feed, new=True)
    assert result["match"] == "new $"


def test_wait_for_new_text_needs_the_stream(fake_server):
    conn = FeedConn(fake_server(lambda m, s: None), ["x"])
    with pytest.raises(UsageError):
        wait_for_text(conn, target(), "x", 1, 0.1, None, new=True)


def test_unterminated_rex_message_does_not_grow_without_bound():
    decoder = StreamDecoder(NONCE)
    decoder.feed(MARKER + b"{}\x1b\\")
    items = decoder.feed(MARKER + b"x" * (MAX_APC_BYTES + 1))
    assert (
        items[-1] == ("message", {"type": "invalid", "reason": "unterminated Rex message"}) and decoder.pending == b""
    )


def test_poll_until_does_not_sleep_past_its_deadline():
    started = time.monotonic()
    with pytest.raises(WaitTimeoutError):
        poll_until(lambda: None, 0.2, 5.0, "nothing")
    assert time.monotonic() - started < 1.0


def test_feed_reconnects_a_dropped_control_connection(data_server, fake_server):
    control = fake_server(lambda message, server: None)
    conn = FeedConn(control, ["x"])
    feed = TerminalFeed(conn, data_server.accept())
    reconnects = []

    def dropped():
        raise UnreachableError("connection lost")

    conn.service_control = dropped
    conn.reconnect = lambda: reconnects.append(1)
    control.send({"type": "event", "event": "x"})
    deadline = time.monotonic() + 2
    while not reconnects and time.monotonic() < deadline:
        feed.poll(0.2)
    assert reconnects and feed.ended is None
