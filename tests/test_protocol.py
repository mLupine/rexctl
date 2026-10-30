import socket
import ssl
import threading

import pytest

from conftest import load_fixture
from rexctl import cli
from rexctl.errors import EXIT_API_ERROR, EXIT_DENIED, AccessDeniedError, ApiError, UnreachableError, UsageError
from rexctl.protocol import CONTROL_SUBPROTOCOL, TERMINAL
from rexctl.target import flatten_view
from rexctl.ws import (
    OP_CLOSE,
    OP_CONT,
    OP_PING,
    OP_TEXT,
    WebSocket,
    WebSocketClosed,
    accept_key,
    apply_mask,
    encode_frame,
)


def respond(server, message, payload=None, error=None):
    body = {"type": "response", "id": message["id"], "seq": 0}
    if error:
        body["error"] = error
    else:
        body["payload"] = payload if payload is not None else {}
    server.send(body)


def test_frame_roundtrip_uses_mask_and_length_extension():
    payload = b"x" * 300
    frame = encode_frame(OP_TEXT, payload, mask_key=b"\x01\x02\x03\x04")
    assert frame[0] == 0x81 and frame[1] == 0x80 | 126
    assert frame[4:8] == b"\x01\x02\x03\x04"
    unmasked = bytes(b ^ b"\x01\x02\x03\x04"[i % 4] for i, b in enumerate(frame[8:]))
    assert unmasked == payload


def test_accept_key_matches_rfc_example():
    assert accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_hello_and_call(fake_server):
    server = fake_server(lambda m, s: respond(s, m, {"rex_version": "x"}))
    conn = server.connection()
    assert conn.welcome["protocol"] == "rex.control.v1"
    assert conn.call("server.version") == {"rex_version": "x"}
    assert server.received[1]["method"] == "server.version"
    assert server.received[1]["type"] == "request"


def test_error_response_becomes_api_error(fake_server):
    err = {"code": "not_found", "message": "block not found", "status": 404}
    server = fake_server(lambda m, s: respond(s, m, error=err))
    conn = server.connection()
    with pytest.raises(ApiError) as info:
        conn.call("session.view", {"session_id": "session:x"})
    assert info.value.details["code"] == "not_found"
    assert info.value.exit_code == EXIT_API_ERROR


def test_events_before_response_are_kept(fake_server):
    def handler(message, server):
        server.send({"type": "event", "seq": 1, "payload": {"type": "session_created", "payload": {}}})
        respond(server, message, {"ok": 1})

    conn = fake_server(handler).connection()
    assert conn.call("server.version") == {"ok": 1}
    assert [e["seq"] for e in conn.pending_events] == [1]


def test_call_many_matches_out_of_order_responses(fake_server):
    batch = []

    def handler(message, server):
        batch.append(message)
        if len(batch) == 3:
            for m in reversed(batch):
                if m["method"] == "boom":
                    respond(server, m, error={"code": "internal", "message": "x", "status": 500})
                else:
                    respond(server, m, {"method": m["method"]})

    conn = fake_server(handler).connection()
    results = conn.call_many([("a", None), ("boom", None), ("c", None)])
    assert results[0] == {"method": "a"} and results[2] == {"method": "c"}
    assert isinstance(results[1], ApiError)


def test_ping_is_answered_and_skipped(fake_server):
    def handler(message, server):
        server.send_raw_frame(OP_PING, b"hi")
        respond(server, message, {"v": 1})

    conn = fake_server(handler).connection()
    assert conn.call("server.version") == {"v": 1}


def test_close_frame_is_reported(fake_server):
    def handler(message, server):
        server.send_raw_frame(OP_CLOSE, (1008).to_bytes(2, "big") + b"event backlog exceeded")

    conn = fake_server(handler).connection()
    with pytest.raises(ApiError) as info:
        conn.call("server.version")
    assert "1008" in info.value.message


def test_block_call_wraps_args(fake_server):
    server = fake_server(lambda m, s: respond(s, m, {"title": "t"}))
    conn = server.connection()
    conn.block_call("com.superlogical.terminal.title", "session:1", "block:2", {})
    payload = server.received[-1]["payload"]
    assert payload == {"session_id": "session:1", "block_id": "block:2", "args": {}}


def test_help_fixture_lists_terminal_block_methods():
    names = {m["name"] for m in cli.all_methods(load_fixture("help-methods.json"))}
    for required in (
        "session.view",
        "session.create",
        "block.close",
        f"{TERMINAL}.format",
        f"{TERMINAL}.write",
        f"{TERMINAL}.program_status",
    ):
        assert required in names


def test_view_fixture_flatten():
    fx = load_fixture("session-view.json")
    blocks = flatten_view(fx["view"])
    assert blocks and blocks[0]["focused"] and blocks[0]["active_window"]
    assert blocks[0]["creator_name"] == TERMINAL


def test_handshake_403_is_access_denied():
    import socket
    import threading

    client, server = socket.socketpair()

    def serve():
        server.recv(4096)
        body = b'{"error":"tailscale user not allowed"}'
        server.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: %d\r\n\r\n" % len(body) + body)

    threading.Thread(target=serve, daemon=True).start()
    sock = WebSocket(client)
    with pytest.raises(AccessDeniedError) as info:
        sock.handshake("h", "/api/control", CONTROL_SUBPROTOCOL)
    assert info.value.exit_code == EXIT_DENIED and "not allowed" in info.value.message


def server_frame(opcode, payload, fin=True):
    return bytes([(0x80 if fin else 0) | opcode, len(payload)]) + payload


def test_timeout_mid_frame_keeps_the_stream_in_sync():
    a, b = socket.socketpair()
    sock = WebSocket(a)
    first = server_frame(OP_TEXT, b'{"seq":1}')
    b.sendall(first[:3])
    with pytest.raises(TimeoutError):
        sock.recv_message(0.05)
    b.sendall(first[3:] + server_frame(OP_TEXT, b'{"seq":2}'))
    assert sock.recv_message(1) == (OP_TEXT, b'{"seq":1}')
    assert sock.recv_message(1) == (OP_TEXT, b'{"seq":2}')


def test_timeout_between_fragments_keeps_the_first_fragment():
    a, b = socket.socketpair()
    sock = WebSocket(a)
    b.sendall(server_frame(OP_TEXT, b"hel", fin=False))
    with pytest.raises(TimeoutError):
        sock.recv_message(0.05)
    b.sendall(server_frame(OP_CONT, b"lo"))
    assert sock.recv_message(1) == (OP_TEXT, b"hello")


@pytest.mark.parametrize(
    "frames",
    [
        [server_frame(OP_CONT, b"orphan")],
        [server_frame(OP_TEXT, b"hel", fin=False), server_frame(OP_TEXT, b"{}")],
    ],
    ids=["continuation-without-start", "new-message-before-the-last-ended"],
)
def test_fragment_sequences_that_break_the_protocol_are_api_errors(frames):
    a, b = socket.socketpair()
    b.sendall(b"".join(frames))
    with pytest.raises(ApiError):
        WebSocket(a).recv_message(1)


def test_an_oversized_http_head_that_arrives_in_one_read_is_refused():
    a, _ = socket.socketpair()
    sock = WebSocket(a)
    sock.buffer = b"HTTP/1.1 101 OK\r\n" + b"X: y\r\n" * 4000 + b"\r\n"
    with pytest.raises(ApiError):
        sock.read_http_response()


def test_oversized_and_reserved_frames_are_api_errors():
    a, b = socket.socketpair()
    sock = WebSocket(a, max_message=4)
    b.sendall(server_frame(OP_TEXT, b"12345"))
    with pytest.raises(ApiError):
        sock.recv_message(1)
    a, b = socket.socketpair()
    sock = WebSocket(a)
    b.sendall(bytes([0xC1, 0]))
    with pytest.raises(ApiError):
        sock.recv_message(1)


def test_masking_roundtrips():
    key = b"\x01\x02\x03\x04"
    data = bytes(range(256)) * 3
    assert apply_mask(apply_mask(data, key), key) == data
    assert apply_mask(b"\x00\x00\x00\x00\x00", key) == b"\x01\x02\x03\x04\x01"


def test_handshake_timeout_is_a_rex_error(monkeypatch):
    a, b = socket.socketpair()
    a.settimeout(0.05)
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kw: a)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", lambda self, sock, **kw: sock)
    with pytest.raises(UnreachableError):
        WebSocket.connect("https://example.test", "/api/control", "rex.control.v1", 0.05)


def test_malformed_http_status_is_an_api_error():
    a, b = socket.socketpair()
    b.sendall(b"garbage\r\n\r\n")
    with pytest.raises(ApiError):
        WebSocket(a).read_http_response()


def test_sends_over_the_server_limit_are_refused():
    a, b = socket.socketpair()
    sock = WebSocket(a)
    sock.max_send = 8
    with pytest.raises(UsageError):
        sock.send_text("x" * 9)


def test_masked_server_frames_and_huge_http_heads_are_refused():
    a, b = socket.socketpair()
    b.sendall(bytes([0x81, 0x80 | 2]) + b"\x00\x00\x00\x00hi")
    with pytest.raises(ApiError):
        WebSocket(a).recv_message(1)
    a, b = socket.socketpair()
    a.settimeout(2)
    threading.Thread(target=b.sendall, args=(b"HTTP/1.1 101 OK\r\n" + b"X: y\r\n" * 4000,), daemon=True).start()
    with pytest.raises(ApiError):
        WebSocket(a).read_http_response()


def test_server_close_is_echoed():
    a, b = socket.socketpair()
    b.sendall(server_frame(OP_CLOSE, (1000).to_bytes(2, "big")))
    with pytest.raises(WebSocketClosed):
        WebSocket(a).recv_message(1)
    echoed = b.recv(16)
    assert echoed[0] == 0x80 | OP_CLOSE and apply_mask(echoed[6:8], echoed[2:6]) == (1000).to_bytes(2, "big")


def test_tls_verifies_certificates_and_hostname(monkeypatch):
    seen = {}
    a, b = socket.socketpair()
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kw: a)

    def wrap(self, sock, server_hostname=None, **kw):
        seen.update(verify=self.verify_mode, check=self.check_hostname, sni=server_hostname)
        raise ssl.SSLError("stop here")

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
    with pytest.raises(UnreachableError):
        WebSocket.connect("https://rex.example.test:8443", "/api/control", "rex.control.v1", 1)
    assert seen == {"verify": ssl.CERT_REQUIRED, "check": True, "sni": "rex.example.test"}


def test_a_send_on_a_dead_socket_is_unreachable_not_internal():
    a, b = socket.socketpair()
    b.close()
    sock = WebSocket(a)
    with pytest.raises(UnreachableError):
        for _ in range(100):  # the first write can still land in the kernel buffer
            sock.send_text("x" * 65536)


LONG_PING = bytes([0x80 | OP_PING, 126]) + (126).to_bytes(2, "big") + b"x" * 126


@pytest.mark.parametrize("frame", [server_frame(OP_PING, b"x", fin=False), LONG_PING])
def test_fragmented_or_long_control_frames_are_refused(frame):
    a, b = socket.socketpair()
    b.sendall(frame)
    with pytest.raises(ApiError):
        WebSocket(a).recv_message(1)
