"""Persistent per-host Rex connections behind a private unix socket (newline-delimited JSON)."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import signal
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Self

from . import connection
from .connection import Connection, RpcConnection
from .context import Connector
from .errors import (
    EXIT_OK,
    AccessDeniedError,
    ApiError,
    LocalOnlyError,
    RexError,
    TargetNotFoundError,
    UnreachableError,
    UsageError,
    WaitTimeoutError,
)
from .flags import seconds
from .output import emit, eprint
from .ws import wait_ready

PROTOCOL = 1
MAX_REQUEST_BYTES = 16 << 20
DEFAULT_UPSTREAM_IDLE = 900.0
STARTUP_WAIT = 8.0
LOG_NAME = "daemon.log"
KIND_TO_ERROR: dict[str, type[RexError]] = {
    "usage": UsageError,
    "unreachable": UnreachableError,
    "access_denied": AccessDeniedError,
    "api_error": ApiError,
    "local_only": LocalOnlyError,
    "target_not_found": TargetNotFoundError,
    "timeout": WaitTimeoutError,
}


class DaemonUnavailable(Exception):
    pass


def cache_dir() -> Path:
    return Path(os.environ.get("REXCTL_CACHE_DIR") or Path.home() / ".cache" / "rexctl")


def socket_path() -> Path:
    return cache_dir() / "rexctl.sock"


def owned_privately(path: Path, kind: int) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_IFMT(info.st_mode) == kind and info.st_uid == os.getuid() and not info.st_mode & 0o077


def private_dir() -> Path:
    path = cache_dir()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not owned_privately(path, stat.S_IFDIR):
        raise UsageError(
            f"{path} must be a real directory owned by you with mode 0700 (set REXCTL_CACHE_DIR to use another one)"
        )
    return path


def error_payload(exc: RexError) -> dict[str, Any]:
    return {"ok": False, "error": exc.to_dict()["error"]}


def error_from_payload(payload: dict[str, Any]) -> RexError:
    body = dict(payload)
    kind, message = body.pop("kind", "error"), body.pop("message", "")
    return KIND_TO_ERROR.get(kind, RexError)(message, **body)


def safe_welcome(welcome: dict[str, Any]) -> dict[str, Any]:
    client = {k: v for k, v in (welcome.get("client") or {}).items() if k != "reconnect_token"}
    return {**welcome, "client": client}


def drain(conn: Connection) -> None:
    while conn.ws and wait_ready([conn.ws], 0.001):
        message = conn.read_message(1.0)
        if message.get("type") == "event":
            conn.queue_event(message)


class Upstream:
    def __init__(self, url: str) -> None:
        self.url = url
        self.lock = threading.Lock()
        self.conn: Connection | None = None
        self.last_used = time.monotonic()
        self.opened_at = 0.0

    def ready(self, timeout: float) -> Connection:
        if self.conn is not None and self.healthy(self.conn):
            self.conn.timeout = timeout
            return self.conn
        return self.reopen(timeout)

    def healthy(self, conn: Connection) -> bool:
        try:
            drain(conn)
            return conn.ws is not None
        except (RexError, OSError):
            return self.try_resume(conn)

    def try_resume(self, conn: Connection) -> bool:
        try:
            conn.reconnect(attempts=2)
            return True
        except (RexError, OSError):
            return False

    def reopen(self, timeout: float) -> Connection:
        self.close()
        conn = Connection(url=self.url, timeout=timeout)
        conn.open()
        self.conn, self.opened_at = conn, time.time()
        return conn

    def close(self) -> None:
        if self.conn is not None:
            try:
                self.conn.close()
            except OSError:
                pass
            self.conn = None

    def finish(self) -> None:
        self.last_used = time.monotonic()
        if self.conn is not None:
            self.conn.pending_events.clear()


class DaemonState:
    def __init__(self, upstream_idle: float) -> None:
        self.upstreams: dict[str, Upstream] = {}
        self.guard = threading.Lock()
        self.upstream_idle = upstream_idle
        self.started_at = time.time()
        self.stop_event = threading.Event()

    def upstream(self, url: str) -> Upstream:
        if not url.startswith("https://"):
            raise UsageError("daemon only connects to https:// Rex URLs")
        with self.guard:
            return self.upstreams.setdefault(url, Upstream(url))

    def reap_idle(self) -> None:
        now = time.monotonic()
        for up in list(self.upstreams.values()):
            if up.conn is not None and now - up.last_used > self.upstream_idle and up.lock.acquire(blocking=False):
                try:
                    up.close()
                finally:
                    up.lock.release()

    def status(self) -> dict[str, Any]:
        now = time.monotonic()
        rows = [
            {
                "url": up.url,
                "connected": up.conn is not None and up.conn.ws is not None,
                "idle_seconds": round(now - up.last_used, 1),
                "opened_at": up.opened_at or None,
                "attached_sessions": sorted(up.conn.attached_sessions) if up.conn else [],
            }
            for up in self.upstreams.values()
        ]
        return {"pid": os.getpid(), "protocol": PROTOCOL, "started_at": self.started_at, "upstreams": rows}


RPC_OPS = {"open", "call", "call_many"}


def check_rpc(request: dict[str, Any]) -> None:
    op = request.get("op")
    if op not in RPC_OPS:
        raise UsageError(f"unknown daemon op {op!r}")
    if op == "call" and not request.get("method"):
        raise UsageError("call needs a method")
    if op == "call_many" and not isinstance(request.get("calls"), list):
        raise UsageError("call_many needs calls")


def run_rpc(state: DaemonState, request: dict[str, Any]) -> dict[str, Any]:
    check_rpc(request)
    timeout = float(request.get("timeout") or 10.0)
    up = state.upstream(str(request.get("url")))
    with up.lock:
        try:
            conn = up.ready(timeout)
            return execute(conn, request)
        except OSError as exc:
            up.close()
            raise UnreachableError(f"connection to {up.url} failed: {exc.strerror or exc}") from None
        finally:
            up.finish()


def execute(conn: Connection, request: dict[str, Any]) -> dict[str, Any]:
    op = request.get("op")
    if op == "open":
        return {"ok": True, "welcome": safe_welcome(conn.welcome)}
    if op == "call":
        return {"ok": True, "result": conn.call(request["method"], request.get("payload"))}
    if op == "call_many":
        calls = [(m, p) for m, p in request["calls"]]
        results = conn.call_many(calls)
        return {
            "ok": True,
            "results": [error_payload(r) if isinstance(r, RexError) else {"ok": True, "result": r} for r in results],
        }
    raise UsageError(f"unknown daemon op {op!r}")


def handle_request(state: DaemonState, request: dict[str, Any]) -> dict[str, Any]:
    op = request.get("op")
    try:
        if op == "ping":
            return {"ok": True, "protocol": PROTOCOL, "pid": os.getpid()}
        if op == "status":
            return {"ok": True, **state.status()}
        if op == "stop":
            state.stop_event.set()
            return {"ok": True, "stopping": True}
        return run_rpc(state, request)
    except RexError as exc:
        return error_payload(exc)
    except (KeyError, TypeError, ValueError) as exc:
        return error_payload(UsageError(f"bad daemon request: {exc}"))


SOL_LOCAL = 0
XUCRED = "IIh16I"


def peer_uid(sock: socket.socket) -> int | None:
    """The connecting process's uid: struct ucred {pid, uid, gid} on Linux, struct xucred on macOS/BSD."""
    if hasattr(socket, "SO_PEERCRED"):
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        return int(struct.unpack("3i", creds)[1])
    if hasattr(socket, "LOCAL_PEERCRED"):
        creds = sock.getsockopt(SOL_LOCAL, socket.LOCAL_PEERCRED, struct.calcsize(XUCRED))
        return int(struct.unpack(XUCRED, creds)[1])
    return None


def read_line(rfile: Any) -> bytes:
    line: bytes = rfile.readline(MAX_REQUEST_BYTES + 1)
    return line


class Handler(socketserver.StreamRequestHandler):
    server: Server

    def handle(self) -> None:
        state = self.server.state
        if peer_uid(self.request) != os.getuid():
            return
        for line in iter(lambda: read_line(self.rfile), b""):
            if len(line) > MAX_REQUEST_BYTES:
                return
            try:
                request = json.loads(line)
                if not isinstance(request, dict):
                    raise json.JSONDecodeError("not an object", "", 0)
                reply = handle_request(state, request)
            except json.JSONDecodeError:
                reply = error_payload(UsageError("request is not a JSON object"))
            self.wfile.write(json.dumps(reply).encode() + b"\n")
            self.wfile.flush()


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str, state: DaemonState) -> None:
        self.state = state
        super().__init__(path, Handler)


def bind_server(path: Path, state: DaemonState) -> Server:
    if path.is_symlink() or (path.exists() and not stat.S_ISSOCK(path.stat().st_mode)):
        raise UsageError(f"{path} exists and is not a socket; remove it yourself if it is stale")
    path.unlink(missing_ok=True)
    previous = os.umask(0o177)
    try:
        server = Server(str(path), state)
    finally:
        os.umask(previous)
    path.chmod(0o600)
    return server


def take_daemon_lock() -> int | None:
    """An exclusive lock held for the daemon's lifetime, so two starters cannot both bind (and unlink) the socket."""
    fd = os.open(private_dir() / "daemon.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    return fd


def serve(upstream_idle: float = DEFAULT_UPSTREAM_IDLE) -> int:
    lock = take_daemon_lock()
    if lock is None or probe_daemon():
        eprint("rexctl: daemon already running")
        return EXIT_OK
    try:
        state = DaemonState(upstream_idle)
        server = bind_server(socket_path(), state)
        signal.signal(signal.SIGTERM, lambda *_: state.stop_event.set())
        threading.Thread(target=server.serve_forever, daemon=True).start()
        wait_for_stop(state)
        server.shutdown()
        for up in state.upstreams.values():
            up.close()
        cleanup_files()
    finally:
        os.close(lock)
    return EXIT_OK


def wait_for_stop(state: DaemonState) -> None:
    while not state.stop_event.wait(30):
        state.reap_idle()


def cleanup_files() -> None:
    socket_path().unlink(missing_ok=True)


def talk(request: dict[str, Any], timeout: float) -> dict[str, Any]:
    path = socket_path()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(path))
        sock.sendall(json.dumps(request).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(1 << 16)
            if not chunk:
                raise DaemonUnavailable("daemon closed the connection")
            data += chunk
    except (
        TimeoutError,
        FileNotFoundError,
        ConnectionRefusedError,
        ConnectionResetError,
        BrokenPipeError,
        OSError,
    ) as exc:
        raise DaemonUnavailable(str(exc)) from exc
    finally:
        sock.close()
    reply: dict[str, Any] = json.loads(data)
    return reply


def probe_daemon() -> bool:
    if not socket_path().exists():
        return False
    try:
        return bool(talk({"op": "ping"}, 2.0).get("ok"))
    except DaemonUnavailable:
        return False


def unwrap(reply: dict[str, Any]) -> Any:
    if not reply.get("ok"):
        raise error_from_payload(reply["error"])
    return reply


class DaemonConnection(RpcConnection):
    def __init__(self, url: str, timeout: float = 10.0) -> None:
        self.url = url
        self.timeout = timeout
        self.welcome: dict[str, Any] = {}

    def __enter__(self) -> Self:
        self.welcome = unwrap(self.send({"op": "open"}))["welcome"]
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def send(self, request: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
        wait = timeout or self.timeout
        return talk({**request, "url": self.url, "timeout": wait}, wait + 5.0)

    def call(self, method: str, payload: dict[str, Any] | None = None, timeout: float | None = None) -> Any:
        return unwrap(self.send({"op": "call", "method": method, "payload": payload}, timeout))["result"]

    def call_many(self, calls: list[tuple[str, dict[str, Any] | None]], timeout: float | None = None) -> list[Any]:
        reply = unwrap(
            self.send(
                {"op": "call_many", "calls": [list(c) for c in calls]}, (timeout or self.timeout) + 0.2 * len(calls)
            )
        )
        return [item["result"] if item.get("ok") else error_from_payload(item["error"]) for item in reply["results"]]


class LocalConnection(DaemonConnection):
    """Same interface, served by a connection pool inside this process (used by `rexctl mcp`)."""

    def __init__(self, state: DaemonState, url: str, timeout: float = 10.0) -> None:
        super().__init__(url, timeout)
        self.state = state

    def send(self, request: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
        wait = timeout or self.timeout
        return handle_request(self.state, {**request, "url": self.url, "timeout": wait})


def pooled_connector(state: DaemonState) -> Connector:
    def connect_pooled(url: str, timeout: float) -> RpcConnection:
        return daemon_connection(url, timeout) or LocalConnection(state, url, timeout)

    return connect_pooled


def daemon_connection(url: str, timeout: float) -> DaemonConnection | None:
    if os.environ.get("REXCTL_NO_DAEMON"):
        return None
    if not (owned_privately(cache_dir(), stat.S_IFDIR) and owned_privately(socket_path(), stat.S_IFSOCK)):
        return None  # missing, or a socket someone else could have planted: connect directly instead
    conn = DaemonConnection(url, timeout)
    try:
        conn.welcome = unwrap(conn.send({"op": "open"}))["welcome"]
    except DaemonUnavailable:
        return None
    return conn


def connect_rpc(url: str, timeout: float) -> RpcConnection:
    return daemon_connection(url, timeout) or connection.connect(url, timeout)


def start_background(upstream_idle: float) -> dict[str, Any]:
    if probe_daemon():
        return {"running": True, "started": False, "socket": str(socket_path())}
    private_dir()
    log_path = cache_dir() / LOG_NAME
    with open(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "ab") as log:
        subprocess.Popen(
            [sys.executable, "-m", "rexctl", "daemon", "run", "--upstream-idle", str(upstream_idle)],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
    deadline = time.monotonic() + STARTUP_WAIT
    while time.monotonic() < deadline:
        if probe_daemon():
            return {"running": True, "started": True, "socket": str(socket_path())}
        time.sleep(0.1)
    raise RexError("daemon did not start; see " + str(cache_dir() / LOG_NAME))


def stop_daemon() -> dict[str, Any]:
    if not probe_daemon():
        cleanup_files()
        return {"running": False, "stopped": False}
    talk({"op": "stop"}, 5.0)
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and socket_path().exists():
        time.sleep(0.1)
    return {"running": False, "stopped": True}


def status_daemon() -> dict[str, Any]:
    if not probe_daemon():
        return {"running": False}
    return {
        "running": True,
        "socket": str(socket_path()),
        **{k: v for k, v in talk({"op": "status"}, 5.0).items() if k != "ok"},
    }


def cmd_daemon(args: argparse.Namespace) -> int:
    if args.daemon_cmd == "run":
        return serve(args.upstream_idle)
    if args.daemon_cmd == "start":
        result = start_background(args.upstream_idle)
    elif args.daemon_cmd == "stop":
        result = stop_daemon()
    else:
        result = status_daemon()
    emit({"ok": True, **result})
    return EXIT_OK


def register(sub: Any) -> None:
    p = sub.add_parser(
        "daemon", help="persistent per-host connections on a private unix socket (CLI uses them automatically)"
    )
    verbs = p.add_subparsers(dest="daemon_cmd", required=True)
    for name, text in (
        ("start", "start in the background"),
        ("run", "run in the foreground"),
        ("stop", "stop it"),
        ("status", "show connections"),
    ):
        v = verbs.add_parser(name, help=text)
        if name in ("start", "run"):
            v.add_argument(
                "--upstream-idle",
                type=seconds,
                default=DEFAULT_UPSTREAM_IDLE,
                help="close a host connection after this many idle seconds (it reopens on demand)",
            )
