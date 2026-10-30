from __future__ import annotations

import json
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Self

from . import __version__
from .errors import (
    AccessDeniedError,
    ApiError,
    LocalOnlyError,
    RexError,
    UnreachableError,
    WaitTimeoutError,
)
from .output import eprint
from .protocol import API_REVISION, CONTROL_SUBPROTOCOL
from .ws import WebSocket, WebSocketClosed

MAX_PENDING_EVENTS = 5000
RECONNECT_ATTEMPTS = 5
RECONNECT_BACKOFF = 0.5
WARNED_REVISIONS: set[tuple[str, Any]] = set()


def warn_on_revision(url: str, revision: Any) -> None:
    if revision == API_REVISION or (url, revision) in WARNED_REVISIONS:
        return
    WARNED_REVISIONS.add((url, revision))
    eprint(
        f"warning: {url} speaks API revision {revision}, this client targets {API_REVISION}; "
        "continuing, some methods may differ (check 'rexctl api list')"
    )


def server_json(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ApiError(f"server sent a message that is not JSON: {exc}") from None
    if not isinstance(value, dict):
        raise ApiError("server sent a JSON message that is not an object")
    return value


def client_platform() -> str:
    names = {"darwin": "macos", "linux": "linux", "win32": "windows"}
    return names.get(sys.platform, "freebsd" if sys.platform.startswith("freebsd") else "other")


class RpcConnection(ABC):
    """What the commands need from a control connection, whether it is direct, via the daemon or pooled."""

    welcome: dict[str, Any]

    @abstractmethod
    def __enter__(self) -> Self: ...

    @abstractmethod
    def __exit__(self, *exc: Any) -> None: ...

    @abstractmethod
    def call(self, method: str, payload: dict[str, Any] | None = None, timeout: float | None = None) -> Any: ...

    @abstractmethod
    def call_many(self, calls: list[tuple[str, dict[str, Any] | None]], timeout: float | None = None) -> list[Any]: ...

    def block_call(
        self,
        method: str,
        session_id: str,
        block_id: str,
        args: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> Any:
        payload: dict[str, Any] = {"session_id": session_id, "block_id": block_id}
        if args is not None:
            payload["args"] = args
        return self.call(method, payload, timeout)


@dataclass
class Connection(RpcConnection):
    url: str
    timeout: float = 10.0
    ws: WebSocket | None = None
    welcome: dict[str, Any] = field(default_factory=dict, repr=False)
    pending_events: list[dict[str, Any]] = field(default_factory=list, repr=False)
    next_id: int = 1
    attach_scope: str | None = None
    attached_sessions: set[str] = field(default_factory=set)

    def __enter__(self) -> Self:
        if self.ws is None:
            self.open()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def open(self, reconnect_token: str | None = None) -> None:
        self.ws = WebSocket.connect(self.url, "/api/control", CONTROL_SUBPROTOCOL, self.timeout)
        hello: dict[str, Any] = {
            "type": "hello",
            "api_revision": API_REVISION,
            "client": {"kind": "agent", "platform": client_platform(), "name": "rexctl", "version": __version__},
        }
        if reconnect_token:
            hello["reconnect_token"] = reconnect_token
        self.ws.send_text(json.dumps(hello))
        self.welcome = self.read_welcome()

    @property
    def reconnect_token(self) -> str | None:
        return (self.welcome.get("client") or {}).get("reconnect_token")

    @property
    def resumed(self) -> bool:
        return bool((self.welcome.get("client") or {}).get("resumed"))

    def reconnect(self, attempts: int = RECONNECT_ATTEMPTS) -> bool:
        token = self.reconnect_token
        last: RexError | None = None
        for attempt in range(attempts):
            self.drop_socket()
            try:
                self.open(token)
                self.restore_attachments()
                return self.resumed
            except (UnreachableError, ApiError) as exc:
                last = exc
                time.sleep(min(RECONNECT_BACKOFF * 2**attempt, 8.0))
        raise UnreachableError(f"could not reconnect after {attempts} attempts: {last.message if last else ''}")

    def drop_socket(self) -> None:
        if self.ws:
            try:
                self.ws.sock.close()
            except OSError:
                pass
            self.ws = None

    def restore_attachments(self) -> None:
        if self.attach_scope:
            self.call("session.attach_all", {"event_scope": self.attach_scope})
        for session_id in sorted(self.attached_sessions):
            self.call("session.attach", {"session_id": session_id})

    def track_attachment(self, method: str, payload: dict[str, Any] | None) -> None:
        payload = payload or {}
        if method == "session.attach_all":
            self.attach_scope = payload.get("event_scope")
        elif method == "session.attach":
            self.attached_sessions.add(payload.get("session_id", ""))
        elif method == "session.detach":
            self.attached_sessions.discard(payload.get("session_id", ""))

    def require_ws(self) -> WebSocket:
        if self.ws is None:
            raise UnreachableError("connection is closed")
        return self.ws

    def read_welcome(self) -> dict[str, Any]:
        ws = self.require_ws()
        try:
            message = server_json(ws.recv_text(self.timeout))
        except WebSocketClosed as exc:
            raise ApiError(f"server closed the connection during hello: {exc.code} {exc.reason}") from exc
        except TimeoutError as exc:
            raise UnreachableError("no welcome from server within timeout") from exc
        if message.get("type") != "welcome" or message.get("protocol") != CONTROL_SUBPROTOCOL:
            raise ApiError("unexpected first message from server", received=message)
        warn_on_revision(self.url, message.get("api_revision"))
        limit = (message.get("limits") or {}).get("max_message_bytes")
        if isinstance(limit, int) and limit > 0:
            ws.max_send = min(ws.max_message, limit)
        return message

    def close(self) -> None:
        if self.ws:
            self.ws.close()
            self.ws = None

    def send_request(self, method: str, payload: dict[str, Any] | None) -> str:
        request_id = str(self.next_id)
        self.next_id += 1
        message: dict[str, Any] = {"type": "request", "id": request_id, "method": method}
        if payload is not None:
            message["payload"] = payload
        self.require_ws().send_text(json.dumps(message))
        return request_id

    def call(self, method: str, payload: dict[str, Any] | None = None, timeout: float | None = None) -> Any:
        request_id = self.send_request(method, payload)
        deadline = time.monotonic() + (timeout or self.timeout)
        while True:
            message = self.read_message(max(0.05, deadline - time.monotonic()))
            if message.get("type") == "event":
                self.queue_event(message)
            elif message.get("type") == "response" and message.get("id") == request_id:
                result = unwrap_response(method, message)
                self.track_attachment(method, payload)
                return result

    def call_many(self, calls: list[tuple[str, dict[str, Any] | None]], timeout: float | None = None) -> list[Any]:
        ids = {self.send_request(method, payload): index for index, (method, payload) in enumerate(calls)}
        results: list[Any] = [None] * len(calls)
        deadline = time.monotonic() + (timeout or self.timeout) + 0.2 * len(calls)
        while ids:
            message = self.read_message(max(0.05, deadline - time.monotonic()))
            if message.get("type") == "event":
                self.queue_event(message)
            elif message.get("type") == "response" and message.get("id") in ids:
                index = ids.pop(message["id"])
                try:
                    results[index] = unwrap_response(calls[index][0], message)
                except ApiError as exc:
                    results[index] = exc
        return results

    def read_message(self, timeout: float) -> dict[str, Any]:
        try:
            return server_json(self.require_ws().recv_text(timeout))
        except WebSocketClosed as exc:
            raise ApiError(f"server closed the connection: {exc.code} {exc.reason}", code=exc.code) from exc
        except TimeoutError as exc:
            raise WaitTimeoutError("no response from server within timeout") from exc

    def service_control(self) -> None:
        while self.ws and self.ws.readable():
            message = self.read_message(self.timeout)
            if message.get("type") == "event":
                self.queue_event(message)

    def queue_event(self, message: dict[str, Any]) -> None:
        self.pending_events.append(message)
        if len(self.pending_events) > MAX_PENDING_EVENTS:
            del self.pending_events[: len(self.pending_events) - MAX_PENDING_EVENTS]


LOCAL_ONLY_MARKER = "local unix socket"


def raise_special_status(method: str, error: dict[str, Any]) -> None:
    status, text = error.get("status"), str(error.get("message", ""))
    details = {"code": error.get("code"), "status": status, "method": method}
    if status == 403 and LOCAL_ONLY_MARKER in text.lower():
        raise LocalOnlyError(
            f"{method} only works on the server's local Unix socket, not over Tailscale: {text}",
            hint="run it on that host itself (not available through rexctl remote)",
            **details,
        )
    if status in (401, 403):
        raise AccessDeniedError(
            f"{method}: server refused this principal ({status}): {text}",
            hint="see 'If access is denied' in README; the Tailscale identity needs access",
            **details,
        )


def unwrap_response(method: str, message: dict[str, Any]) -> Any:
    error = message.get("error")
    if error:
        raise_special_status(method, error)
        raise ApiError(
            f"{method}: {error.get('message', '')} (code={error.get('code')} status={error.get('status')})",
            code=error.get("code"),
            status=error.get("status"),
            method=method,
        )
    return message.get("payload")


def connect(url: str, timeout: float = 10.0) -> Connection:
    conn = Connection(url=url, timeout=timeout)
    conn.open()
    return conn
