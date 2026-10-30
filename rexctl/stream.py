from __future__ import annotations

import base64
import codecs
import json
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .connection import RECONNECT_ATTEMPTS, RECONNECT_BACKOFF, Connection
from .errors import AccessDeniedError, ApiError, RexError, UnreachableError
from .output import eprint
from .target import Target
from .ws import OP_BIN, WebSocket, WebSocketClosed, wait_ready

DATA_SUBPROTOCOL = "rex.data.terminal.v1"
MSG_HELLO, MSG_RESUME, MSG_WELCOME, MSG_REJECT = 0x01, 0x02, 0x81, 0x82
WELCOME_SIZE = 32
STREAM_END_CODES = {
    1000: "stream_ended",
    4000: "block_closed",
    1013: "reconnect_required",
    1008: "provider_unavailable",
    1011: "provider_failed",
}
REJECT_REASONS = {
    1: "ticket or token unknown, expired, used, issued to someone else, or session gone",
    2: "this client already has a connection to this block's data source",
    3: "stream unavailable (block closed, or resume byte count too low)",
    4: "limit reached, try later",
    5: "malformed or late handshake, or resume byte count too high",
    6: "server failure",
    7: "ticket issued for a different subprotocol",
}


class DataRejectedError(ApiError):
    kind = "data_rejected"


class StreamClosed(Exception):
    def __init__(self, code: int, reason: str) -> None:
        super().__init__(f"data connection closed {code} {reason}")
        self.code = code
        self.reason = reason

    @property
    def end_reason(self) -> str:
        return STREAM_END_CODES.get(self.code, f"closed_{self.code}")

    @property
    def resumable(self) -> bool:
        return self.code == 1001 and self.reason != "data provider canceled"


def decode_ticket(ticket: str) -> bytes:
    raw = base64.urlsafe_b64decode(ticket + "=" * (-len(ticket) % 4))
    if len(raw) != 16:
        raise ApiError("data.connect returned a ticket that is not 16 bytes")
    return raw


def hello_message(ticket: str) -> bytes:
    return bytes([MSG_HELLO]) + decode_ticket(ticket)


def resume_message(token: bytes, received: int) -> bytes:
    return bytes([MSG_RESUME]) + token + struct.pack("<Q", received)


@dataclass
class Welcome:
    token: bytes
    keep_ms: int
    nonce: int


def parse_welcome(data: bytes) -> Welcome:
    if data[:1] == bytes([MSG_REJECT]):
        reason = data[1] if len(data) > 1 else 0
        raise DataRejectedError(
            f"data handshake rejected: {REJECT_REASONS.get(reason, 'unknown reason')}", reason=reason
        )
    if len(data) != WELCOME_SIZE or data[0] != MSG_WELCOME:
        raise ApiError("data handshake returned a malformed WELCOME")
    keep_ms = struct.unpack("<I", data[20:24])[0]
    nonce = struct.unpack("<Q", data[24:32])[0]
    return Welcome(token=data[1:17], keep_ms=keep_ms, nonce=nonce)


def handshake_data_socket(ws: WebSocket, first_message: bytes, timeout: float) -> Welcome:
    ws.send_binary(first_message)
    try:
        opcode, data = ws.recv_message(timeout)
    except WebSocketClosed as exc:
        raise ApiError(f"data connection closed during handshake: {exc.code} {exc.reason}") from exc
    except TimeoutError as exc:
        raise UnreachableError("no data WELCOME within timeout") from exc
    if opcode != OP_BIN:
        raise ApiError("data handshake answered with a text message")
    return parse_welcome(data)


RESUME_RETRY_REASONS = {2, 3}


def resume_retryable(exc: RexError) -> bool:
    return isinstance(exc, UnreachableError) or exc.details.get("reason") in RESUME_RETRY_REASONS


@dataclass
class DataStream:
    url: str
    ws: WebSocket
    welcome: Welcome
    timeout: float = 10.0
    received: int = 0

    @classmethod
    def open(cls, url: str, ticket: str, timeout: float = 10.0) -> DataStream:
        ws = WebSocket.connect(url, "/api/data", DATA_SUBPROTOCOL, timeout)
        try:
            welcome = handshake_data_socket(ws, hello_message(ticket), timeout)
        except RexError:
            ws.close()
            raise
        return cls(url=url, ws=ws, welcome=welcome, timeout=timeout)

    def resume(self, attempts: int = RECONNECT_ATTEMPTS) -> None:
        self.ws.close()
        for attempt in range(attempts):
            try:
                self.ws = self.resume_once()
                return
            except (UnreachableError, DataRejectedError) as exc:
                if attempt == attempts - 1 or not resume_retryable(exc):
                    raise
                time.sleep(min(RECONNECT_BACKOFF * 2**attempt, 4.0))

    def resume_once(self) -> WebSocket:
        ws = WebSocket.connect(self.url, "/api/data", DATA_SUBPROTOCOL, self.timeout)
        try:
            self.welcome = handshake_data_socket(ws, resume_message(self.welcome.token, self.received), self.timeout)
        except RexError:
            ws.close()
            raise
        return ws

    def read(self, timeout: float) -> bytes:
        try:
            return self.read_once(timeout)
        except (UnreachableError, StreamClosed) as exc:
            if isinstance(exc, StreamClosed) and not exc.resumable:
                raise
            self.resume()
            return b""

    def read_once(self, timeout: float) -> bytes:
        try:
            opcode, data = self.ws.recv_message(timeout)
        except TimeoutError:
            return b""
        except WebSocketClosed as exc:
            raise StreamClosed(exc.code, exc.reason) from exc
        if opcode != OP_BIN:
            return b""
        self.received += len(data)
        return data

    def close(self) -> None:
        self.ws.close()


def partial_suffix_len(data: bytes, marker: bytes) -> int:
    for size in range(min(len(marker) - 1, len(data)), 0, -1):
        if data.endswith(marker[:size]):
            return size
    return 0


MAX_APC_BYTES = 1 << 20


class StreamDecoder:
    """Splits the terminal stream into program output and Rex APC messages; skips the opening snapshot."""

    def __init__(self, nonce: int) -> None:
        self.marker = b"\x1b_rex1;%d;" % nonce
        self.pending = b""
        self.snapshot_done = False
        self.snapshot_bytes = 0

    def feed(self, data: bytes) -> list[tuple[str, Any]]:
        self.pending += data
        if not self.snapshot_done and not self.finish_snapshot():
            return []
        return self.drain_pending()

    def finish_snapshot(self) -> bool:
        index = self.pending.find(self.marker)
        if index < 0:
            keep = partial_suffix_len(self.pending, self.marker)
            self.snapshot_bytes += len(self.pending) - keep
            self.pending = self.pending[len(self.pending) - keep :]
            return False
        self.snapshot_bytes += index
        self.pending = self.pending[index:]
        self.snapshot_done = True
        return True

    def drain_pending(self) -> list[tuple[str, Any]]:
        items: list[tuple[str, Any]] = []
        while self.pending:
            index = self.pending.find(self.marker)
            if index < 0:
                keep = partial_suffix_len(self.pending, self.marker)
                if len(self.pending) > keep:
                    items.append(("output", self.pending[: len(self.pending) - keep]))
                self.pending = self.pending[len(self.pending) - keep :]
                break
            if index:
                items.append(("output", self.pending[:index]))
            end = self.pending.find(b"\x1b\\", index + len(self.marker))
            if end < 0 and len(self.pending) - index > MAX_APC_BYTES:
                items.append(("message", {"type": "invalid", "reason": "unterminated Rex message"}))
                self.pending = b""
                break
            if end < 0:
                self.pending = self.pending[index:]
                break
            items.append(("message", parse_rex_message(self.pending[index + len(self.marker) : end])))
            self.pending = self.pending[end + 2 :]
        return items


def parse_rex_message(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"type": "invalid"}
    return value if isinstance(value, dict) else {"type": "invalid"}


class VtTextStripper:
    """Turns terminal output bytes into linear plain text by dropping escape sequences and control codes."""

    def __init__(self) -> None:
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.state: Callable[[str, list[str]], None] = self.on_ground
        self.carriage_return = False

    def feed(self, data: bytes) -> str:
        out: list[str] = []
        for char in self.decoder.decode(data):
            self.state(char, out)
        return "".join(out)

    def on_ground(self, char: str, out: list[str]) -> None:
        if char == "\x1b":
            self.state = self.on_esc
        elif char == "\r":
            self.carriage_return = True
        elif char == "\n":
            self.carriage_return = False
            out.append("\n")
        elif char == "\b":
            if out and out[-1] != "\n":
                out.pop()
        elif char == "\t" or (char >= " " and char != "\x7f"):
            if self.carriage_return:
                self.carriage_return = False
                out.append("\n")
            out.append(char)

    def on_esc(self, char: str, out: list[str]) -> None:
        if char == "[":
            self.state = self.on_csi
        elif char in "]P_^X":
            self.state = self.on_string
        elif " " <= char <= "/":
            self.state = self.on_esc_intermediate
        else:
            self.state = self.on_ground

    def on_esc_intermediate(self, char: str, out: list[str]) -> None:
        if not " " <= char <= "/":
            self.state = self.on_ground

    def on_csi(self, char: str, out: list[str]) -> None:
        if "@" <= char <= "~":
            self.state = self.on_ground
        elif char == "\x1b":
            self.state = self.on_esc

    def on_string(self, char: str, out: list[str]) -> None:
        if char == "\x07":
            self.state = self.on_ground
        elif char == "\x1b":
            self.state = self.on_string_esc

    def on_string_esc(self, char: str, out: list[str]) -> None:
        if char == "\\":
            self.state = self.on_ground
        else:
            self.state = self.on_esc
            self.on_esc(char, out)


class TerminalFeed:
    """Read-only live view of one terminal: decoded stream items, with the control connection kept serviced."""

    def __init__(self, conn: Connection, stream: DataStream, reopen: Callable[[], DataStream] | None = None) -> None:
        self.conn = conn
        self.stream = stream
        self.reopen = reopen
        self.reopens = 0
        self.decoder = StreamDecoder(stream.welcome.nonce)
        self.stripper = VtTextStripper()
        self.output_bytes = 0
        self.ended: dict[str, Any] | None = None

    def poll(self, timeout: float) -> list[dict[str, Any]]:
        if self.ended:
            return []
        ready = wait_ready([ws for ws in (self.stream.ws, self.conn.ws) if ws], timeout)
        if self.conn.ws is not None and self.conn.ws in ready:
            try:
                self.conn.service_control()
            except (UnreachableError, ApiError):
                self.conn.reconnect()
        if self.stream.ws not in ready:
            return []
        try:
            data = self.stream.read(timeout)
        except StreamClosed as exc:
            self.ended = {"kind": "end", "reason": exc.end_reason, "code": exc.code}
            return [self.ended]
        except RexError as exc:
            return self.reopen_after(exc)
        return self.decode(data)

    def reopen_after(self, lost: RexError) -> list[dict[str, Any]]:
        if self.reopen is None or self.reopens >= RECONNECT_ATTEMPTS or isinstance(lost, AccessDeniedError):
            self.ended = {"kind": "end", "reason": "stream_lost", "error": lost.message}
            return [self.ended]
        self.reopens += 1
        try:
            self.stream = self.reopen()
        except RexError as exc:
            self.ended = {"kind": "end", "reason": "stream_lost", "error": exc.message}
            return [self.ended]
        self.decoder = StreamDecoder(self.stream.welcome.nonce)
        self.stripper = VtTextStripper()
        return [{"kind": "gap", "reason": "resume_rejected", "note": "output during the gap may be missing"}]

    def decode(self, data: bytes) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for kind, value in self.decoder.feed(data):
            if kind == "output":
                self.output_bytes += len(value)
                items.append({"kind": "output", "raw": value, "text": self.stripper.feed(value)})
            else:
                items.append({"kind": "message", "message": value})
                if value.get("type") == "child_exited":
                    items[-1]["exit_code"] = value.get("exit_code")
        return items

    def close(self, session_id: str) -> None:
        self.stream.close()
        try:
            self.conn.call("session.detach", {"session_id": session_id})
        except (RexError, OSError):
            pass


def open_feed(conn: Connection, url: str, t: Target, timeout: float) -> TerminalFeed:
    conn.call("session.attach", {"session_id": t.session_id})

    def open_stream() -> DataStream:
        ticket = conn.call(
            "data.connect",
            {
                "session_id": t.session_id,
                "block_id": t.block_id,
                "data_ref_id": "terminal",
                "subprotocol": DATA_SUBPROTOCOL,
            },
        )["ticket"]
        return DataStream.open(url, ticket, timeout)

    return TerminalFeed(conn, open_stream(), reopen=open_stream)


def try_open_feed(conn: Connection, url: str, t: Target, timeout: float) -> TerminalFeed | None:
    try:
        return open_feed(conn, url, t, timeout)
    except AccessDeniedError:
        raise
    except RexError as exc:
        eprint(f"rexctl: data stream unavailable ({exc.message}); falling back to polling")
        return None
