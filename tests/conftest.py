import json
import os
import socket
import struct
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIXTURES = ROOT / "fixtures"
TEST_HOSTS = {"alpha": "https://alpha.example.test", "beta": "https://beta.example.test"}

from rexctl import connection  # noqa: E402
from rexctl.hosts import load_hosts, resolve_host  # noqa: E402
from rexctl.stream import DataStream, handshake_data_socket, hello_message  # noqa: E402
from rexctl.ws import OP_BIN, OP_CLOSE, OP_PONG, OP_TEXT, WebSocket  # noqa: E402


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--live",
        metavar="HOST",
        help="run the live tests against this Rex server (label from your "
        "hosts file, or an https:// URL); they create and close sessions",
    )


def pytest_configure(config: pytest.Config) -> None:
    host = config.getoption("--live")
    if host:
        os.environ["REXCTL_LIVE_URL"] = resolve_host(host, load_hosts())[1]


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--live"):
        return
    skip = pytest.mark.skip(reason="needs --live HOST")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)


def server_frame(opcode: int, payload: bytes) -> bytes:
    head = bytes([0x80 | opcode])
    if len(payload) < 126:
        return head + bytes([len(payload)]) + payload
    return head + bytes([126]) + struct.pack(">H", len(payload)) + payload


def read_client_frame(sock: socket.socket) -> tuple[int, bytes]:
    def exact(n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    first, second = exact(2)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack(">H", exact(2))[0]
    mask = exact(4)
    body = bytes(b ^ mask[i % 4] for i, b in enumerate(exact(length)))
    return first & 0x0F, body


class FakeRexServer:
    def __init__(self, handler: Callable[[dict[str, Any], "FakeRexServer"], None]) -> None:
        self.client_sock, self.server_sock = socket.socketpair()
        self.handler = handler
        self.received: list[dict[str, Any]] = []
        self.welcome_extra: dict[str, Any] = {}
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def send(self, message: dict[str, Any]) -> None:
        self.server_sock.sendall(server_frame(OP_TEXT, json.dumps(message).encode()))

    def send_raw_frame(self, opcode: int, payload: bytes) -> None:
        self.server_sock.sendall(server_frame(opcode, payload))

    def serve(self) -> None:
        try:
            while True:
                opcode, body = read_client_frame(self.server_sock)
                if opcode == OP_CLOSE:
                    return
                if opcode == OP_PONG:
                    continue
                message = json.loads(body)
                self.received.append(message)
                if message["type"] == "hello":
                    self.send(
                        {
                            "type": "welcome",
                            "protocol": "rex.control.v1",
                            "api_revision": 7,
                            "limits": {"max_message_bytes": 1048576},
                            **self.welcome_extra,
                        }
                    )
                else:
                    self.handler(message, self)
        except (EOFError, OSError):
            return

    def respond(self, message: dict[str, Any], payload: Any = None, error: dict[str, Any] | None = None) -> None:
        reply: dict[str, Any] = {"type": "response", "id": message["id"], "seq": 0}
        if error:
            reply["error"] = error
        else:
            reply["payload"] = {} if payload is None else payload
        self.send(reply)

    def send_event(self, seq: int, event: dict[str, Any], session_id: str | None = None) -> None:
        payload = (
            {"type": "session_event", "payload": {"session_id": session_id, "event": event}} if session_id else event
        )
        self.send({"type": "event", "seq": seq, "payload": payload})

    def connection(self) -> "connection.Connection":
        conn = connection.Connection(url="https://fake.invalid", timeout=3)
        conn.ws = WebSocket(self.client_sock)
        conn.ws.send_text(json.dumps({"type": "hello", "api_revision": 7}))
        conn.welcome = conn.read_welcome()
        return conn


@pytest.fixture
def fake_server() -> Callable[[Callable[[dict[str, Any], FakeRexServer], None]], FakeRexServer]:
    servers: list[FakeRexServer] = []

    def make(handler: Callable[[dict[str, Any], FakeRexServer], None]) -> FakeRexServer:
        server = FakeRexServer(handler)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.client_sock.close()
        server.server_sock.close()


NONCE = 424242
MARKER = b"\x1b_rex1;%d;" % NONCE


def rex_message(body: dict[str, Any], nonce: int = NONCE) -> bytes:
    return b"\x1b_rex1;%d;" % nonce + json.dumps(body).encode() + b"\x1b\\"


def welcome_bytes(token: bytes = b"T" * 16, keep_ms: int = 60000, nonce: int = NONCE) -> bytes:
    return b"\x81" + token + b"\x00\x00\x00" + struct.pack("<I", keep_ms) + struct.pack("<Q", nonce)


class FakeDataServer:
    def __init__(self) -> None:
        self.client_sock, self.server_sock = socket.socketpair()
        self.first_message: bytes | None = None

    def send(self, payload: bytes) -> None:
        self.server_sock.sendall(server_frame(OP_BIN, payload))

    def close_with(self, code: int, reason: str = "") -> None:
        self.server_sock.sendall(server_frame(OP_CLOSE, struct.pack(">H", code) + reason.encode()))

    def read_client_message(self) -> bytes:
        opcode, body = read_client_frame(self.server_sock)
        assert opcode == OP_BIN
        return body

    def client_ws(self) -> "WebSocket":
        return WebSocket(self.client_sock)

    def accept(self, token: bytes = b"T" * 16) -> "DataStream":
        self.send(welcome_bytes(token))
        ws = self.client_ws()
        welcome = handshake_data_socket(ws, hello_message("AAECAwQFBgcICQoLDA0ODw"), 3)
        self.first_message = self.read_client_message()
        return DataStream(url="https://fake.invalid", ws=ws, welcome=welcome, timeout=3)

    def shutdown(self) -> None:
        self.client_sock.close()
        self.server_sock.close()


@pytest.fixture(autouse=True)
def isolate_daemon(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> None:
    monkeypatch.setenv("REXCTL_NO_DAEMON", "1")
    monkeypatch.setenv("REXCTL_CACHE_DIR", str(tmp_path_factory.mktemp("rx")))
    hosts = tmp_path_factory.mktemp("config") / "hosts.json"
    hosts.write_text(json.dumps(TEST_HOSTS))
    monkeypatch.setenv("REXCTL_HOSTS", str(hosts))
    monkeypatch.delenv("REXCTL_HOST", raising=False)
