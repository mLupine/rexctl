import json
import os
import socket
import stat
import threading
import time

import pytest

from rexctl import cli, connection, daemon
from rexctl.context import Context
from rexctl.errors import ApiError, UnreachableError, UsageError
from rexctl.ws import WebSocket
from test_events import drop

URL = "https://fake.invalid"
REAL_DAEMON_CONNECTION = daemon.daemon_connection
CTX = Context(daemon.connect_rpc)


@pytest.fixture
def daemon_state(monkeypatch):
    monkeypatch.delenv("REXCTL_NO_DAEMON")
    daemon.private_dir()
    server = daemon.bind_server(daemon.socket_path(), daemon.DaemonState(upstream_idle=900))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(daemon, "daemon_connection", must_use_daemon(daemon.daemon_connection))
    yield server.state
    server.shutdown()
    server.server_close()


def must_use_daemon(real):
    def connection(url, timeout=10.0):
        conn = real(url, timeout)
        assert conn is not None, "the client fell back to a direct connection instead of the daemon"
        return conn

    return connection


def route_sockets(monkeypatch, *servers):
    queue = list(servers)
    monkeypatch.setattr(WebSocket, "connect", classmethod(lambda cls, *a, **k: WebSocket(queue.pop(0).client_sock)))


def echo(message, server):
    if message["method"] == "boom":
        server.respond(message, error={"code": "bad_request", "status": 400, "message": "no"})
    else:
        server.respond(message, {"echo": message["method"], "payload": message.get("payload")})


def test_peer_uid_is_the_callers_uid():
    a, b = socket.socketpair(socket.AF_UNIX)
    assert daemon.peer_uid(a) == os.getuid()


def test_socket_and_directory_are_private(daemon_state):
    assert stat.S_IMODE(daemon.socket_path().stat().st_mode) == 0o600
    assert stat.S_IMODE(daemon.cache_dir().stat().st_mode) == 0o700


def test_calls_share_one_upstream_connection_across_clients(daemon_state, fake_server, monkeypatch):
    server = fake_server(echo)
    server.welcome_extra = {"client": {"id": "client:1", "reconnect_token": "SECRET-TOKEN"}}
    route_sockets(monkeypatch, server)
    with CTX.rpc(URL) as first:
        assert first.call("a.one", {"x": 1})["echo"] == "a.one"
        assert "SECRET-TOKEN" not in json.dumps(first.welcome) and first.welcome["client"]["id"] == "client:1"
    with CTX.rpc(URL) as second:
        assert second.call("a.two")["echo"] == "a.two"
    assert [m["type"] for m in server.received].count("hello") == 1
    assert [m["method"] for m in server.received if m["type"] == "request"] == ["a.one", "a.two"]


def test_call_many_and_errors_map_to_exceptions(daemon_state, fake_server, monkeypatch):
    route_sockets(monkeypatch, fake_server(echo))
    with CTX.rpc(URL) as conn:
        results = conn.call_many([("x.a", None), ("boom", None), ("x.b", None)])
        assert results[0]["echo"] == "x.a" and results[2]["echo"] == "x.b"
        assert isinstance(results[1], ApiError) and results[1].details["status"] == 400
        with pytest.raises(ApiError) as err:
            conn.call("boom")
        assert err.value.details["code"] == "bad_request"


def test_block_call_wraps_args(daemon_state, fake_server, monkeypatch):
    server = fake_server(echo)
    route_sockets(monkeypatch, server)
    with CTX.rpc(URL) as conn:
        out = conn.block_call("com.x.m", "session:s", "block:b", {"k": 1})
    assert out["payload"] == {"session_id": "session:s", "block_id": "block:b", "args": {"k": 1}}


def test_cli_commands_use_the_daemon_transparently(daemon_state, fake_server, monkeypatch, capsys):
    server = fake_server(echo)
    route_sockets(monkeypatch, server)
    for _ in range(2):
        assert cli.main(["-H", "https://fake.invalid", "api", "call", "server.version"]) == 0
        assert json.loads(capsys.readouterr().out)["result"]["echo"] == "server.version"
    assert [m["type"] for m in server.received].count("hello") == 1


def test_no_daemon_flag_bypasses_it(daemon_state, fake_server, monkeypatch, capsys):
    monkeypatch.setattr(daemon, "daemon_connection", REAL_DAEMON_CONNECTION)
    server = fake_server(echo)
    route_sockets(monkeypatch, server)
    assert cli.main(["--no-daemon", "-H", "https://fake.invalid", "api", "call", "server.version"]) == 0
    assert [m["type"] for m in server.received].count("hello") == 1 and not daemon_state.upstreams


def test_missing_daemon_falls_back_to_direct_connection(monkeypatch, fake_server):
    monkeypatch.delenv("REXCTL_NO_DAEMON")
    server = fake_server(echo)
    route_sockets(monkeypatch, server)
    with CTX.rpc(URL) as conn:
        assert isinstance(conn, connection.Connection) and conn.call("m")["echo"] == "m"


def test_stale_socket_file_falls_back(monkeypatch, fake_server):
    monkeypatch.delenv("REXCTL_NO_DAEMON")
    daemon.private_dir()
    dead = socket.socket(socket.AF_UNIX)
    dead.bind(str(daemon.socket_path()))
    dead.close()
    route_sockets(monkeypatch, fake_server(echo))
    with CTX.rpc(URL) as conn:
        assert isinstance(conn, connection.Connection)


def test_client_ignores_a_daemon_in_a_directory_others_can_reach(daemon_state, fake_server, monkeypatch):
    monkeypatch.setattr(daemon, "daemon_connection", REAL_DAEMON_CONNECTION)
    route_sockets(monkeypatch, fake_server(echo))
    daemon.cache_dir().chmod(0o755)
    try:
        with CTX.rpc(URL) as conn:
            assert isinstance(conn, connection.Connection) and not daemon_state.upstreams
    finally:
        daemon.cache_dir().chmod(0o700)


def test_dropped_upstream_is_resumed_before_the_next_call(daemon_state, fake_server, monkeypatch):
    first = fake_server(echo)
    first.welcome_extra = {"client": {"id": "client:1", "reconnect_token": "TOK-A"}}
    second = fake_server(echo)
    second.welcome_extra = {"client": {"id": "client:1", "reconnect_token": "TOK-B", "resumed": True}}
    route_sockets(monkeypatch, first, second)
    with CTX.rpc(URL) as conn:
        conn.call("session.attach_all", {"event_scope": "session"})
        drop(first)
        time.sleep(0.1)
        assert conn.call("after")["echo"] == "after"
    assert second.received[0]["reconnect_token"] == "TOK-A"
    assert [m["method"] for m in second.received[1:]] == ["session.attach_all", "after"]


def test_unreachable_upstream_is_reported_not_retried_as_direct(daemon_state, monkeypatch):
    def refuse(cls, *a, **k):
        raise UnreachableError("down")

    monkeypatch.setattr(WebSocket, "connect", classmethod(refuse))
    with pytest.raises(UnreachableError):
        with CTX.rpc(URL):
            pass


def test_daemon_refuses_non_https(daemon_state):
    with pytest.raises(UsageError):
        with CTX.rpc("http://example.test"):
            pass


def test_events_do_not_pile_up(daemon_state, fake_server, monkeypatch):
    def noisy(message, server):
        server.send({"type": "event", "seq": 1, "payload": {"type": "x"}})
        server.respond(message, {})

    route_sockets(monkeypatch, fake_server(noisy))
    with CTX.rpc(URL) as conn:
        for _ in range(5):
            conn.call("m")
    assert daemon_state.upstreams[URL].conn.pending_events == []


def test_idle_upstreams_are_closed_and_reopened_on_demand(daemon_state, fake_server, monkeypatch):
    first, second = fake_server(echo), fake_server(echo)
    route_sockets(monkeypatch, first, second)
    with CTX.rpc(URL) as conn:
        conn.call("m")
        daemon_state.upstream_idle = 0.0
        daemon_state.upstreams[URL].last_used -= 5
        daemon_state.reap_idle()
        assert daemon_state.upstreams[URL].conn is None
        assert conn.call("again")["echo"] == "again"
    assert [m["method"] for m in second.received if m["type"] == "request"] == ["again"]


def test_status_and_stop_ops(daemon_state, fake_server, monkeypatch):
    route_sockets(monkeypatch, fake_server(echo))
    with CTX.rpc(URL) as conn:
        conn.call("m")
    status = daemon.status_daemon()
    assert status["running"] and status["upstreams"][0]["url"] == URL and "token" not in json.dumps(status).lower()
    assert daemon.talk({"op": "stop"}, 2)["stopping"] and daemon_state.stop_event.is_set()


def test_bad_requests_return_errors(daemon_state):
    assert daemon.talk({"op": "nope", "url": URL}, 2)["error"]["kind"] == "usage"
    assert daemon.talk({"op": "call", "url": URL}, 2)["ok"] is False


def test_local_pool_connection_serves_calls_without_a_socket(fake_server, monkeypatch):
    server = fake_server(echo)
    route_sockets(monkeypatch, server)
    state = daemon.DaemonState(900)
    pooled = Context(daemon.pooled_connector(state))
    for _ in range(2):
        with pooled.rpc(URL) as conn:
            assert conn.call("m")["echo"] == "m"
    assert [m["type"] for m in server.received].count("hello") == 1 and not daemon.socket_path().exists()


def test_cache_dir_must_be_private(tmp_path, monkeypatch):
    loose = tmp_path / "loose"
    loose.mkdir(mode=0o755)
    loose.chmod(0o755)
    monkeypatch.setenv("REXCTL_CACHE_DIR", str(loose))
    with pytest.raises(UsageError):
        daemon.private_dir()
    assert stat.S_IMODE(loose.stat().st_mode) == 0o755
    monkeypatch.setenv("REXCTL_CACHE_DIR", str(tmp_path / "fresh"))
    assert stat.S_IMODE(daemon.private_dir().stat().st_mode) == 0o700


def test_a_second_daemon_leaves_the_running_one_alone(monkeypatch):
    monkeypatch.setattr(daemon, "probe_daemon", lambda: False)  # both starters missed each other's probe
    held = daemon.take_daemon_lock()
    path = daemon.socket_path()
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(path))
    before = path.stat()
    try:
        assert held is not None and daemon.serve() == 0
        assert os.path.samestat(path.stat(), before)
    finally:
        listener.close()
        path.unlink(missing_ok=True)
        os.close(held)


def test_a_request_that_is_not_an_object_gets_an_error_and_the_connection_survives(daemon_state):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5)
        sock.connect(str(daemon.socket_path()))
        sock.sendall(b"[1]\n" + json.dumps({"op": "ping"}).encode() + b"\n")
        stream = sock.makefile()
        replies = [json.loads(stream.readline()) for _ in range(2)]
    assert replies[0]["ok"] is False and replies[1]["ok"] is True


def test_a_client_with_another_uid_gets_no_answer(daemon_state, monkeypatch):
    monkeypatch.setattr(daemon, "peer_uid", lambda sock: os.getuid() + 1)
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5)
        sock.connect(str(daemon.socket_path()))
        try:
            sock.sendall(json.dumps({"op": "ping"}).encode() + b"\n")
            answer = sock.recv(4096)
        except (BrokenPipeError, ConnectionResetError):  # the daemon may hang up before the request is written
            answer = b""
        assert answer == b""
