from __future__ import annotations

import base64
import hashlib
import secrets
import select
import socket
import ssl
import struct
from urllib.parse import urlsplit

from .errors import AccessDeniedError, ApiError, RexError, UnreachableError, UsageError
from .hosts import require_https

MAX_HTTP_HEAD = 16 * 1024
OP_CONT, OP_TEXT, OP_BIN, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WebSocketClosed(Exception):
    def __init__(self, code: int, reason: str) -> None:
        super().__init__(f"websocket closed {code} {reason}")
        self.code = code
        self.reason = reason


def encode_frame(opcode: int, payload: bytes, mask_key: bytes | None = None) -> bytes:
    key = mask_key if mask_key is not None else secrets.token_bytes(4)
    length = len(payload)
    head = bytes([0x80 | opcode])
    if length < 126:
        head += bytes([0x80 | length])
    elif length < 65536:
        head += bytes([0x80 | 126]) + struct.pack(">H", length)
    else:
        head += bytes([0x80 | 127]) + struct.pack(">Q", length)
    return head + key + apply_mask(payload, key)


def apply_mask(data: bytes, key: bytes) -> bytes:
    size = len(data)
    pad = (key * (size // 4 + 1))[:size]
    return (int.from_bytes(data, "big") ^ int.from_bytes(pad, "big")).to_bytes(size, "big")


def parse_frame(buffer: bytes, limit: int) -> tuple[bool, int, bytes, int] | None:
    """The first complete frame in `buffer` as (fin, opcode, payload, bytes used), or None if more bytes are needed.

    Nothing is consumed until a whole frame is present, so a read timeout mid-frame leaves the stream intact."""
    if len(buffer) < 2:
        return None
    first, second = buffer[0], buffer[1]
    if first & 0x70:
        raise ApiError("websocket frame uses reserved bits (no extension was negotiated)")
    offset, length = 2, second & 0x7F
    if length >= 126:
        size = 2 if length == 126 else 8
        if len(buffer) < offset + size:
            return None
        length = int.from_bytes(buffer[offset : offset + size], "big")
        offset += size
    if second & 0x80:
        raise ApiError("server sent a masked websocket frame")
    if length > limit:
        raise ApiError(f"websocket frame of {length} bytes exceeds the {limit} byte limit")
    end = offset + length
    if len(buffer) < end:
        return None
    return bool(first & 0x80), first & 0x0F, buffer[offset:end], end


def accept_key(client_key: str) -> str:
    return base64.b64encode(hashlib.sha1((client_key + WS_GUID).encode()).digest()).decode()


SEND_TIMEOUT = 30.0


class WebSocket:
    def __init__(self, sock: socket.socket, max_message: int = 4 * 1024 * 1024) -> None:
        self.sock = sock
        self.buffer = b""
        self.max_message = max_message
        self.max_send = max_message
        self.closed = False
        self.fragments: list[bytes] = []
        self.fragment_opcode: int | None = None  # opcode of the message being reassembled, if any

    @classmethod
    def connect(cls, url: str, path: str, subprotocol: str, timeout: float) -> WebSocket:
        parts = urlsplit(require_https(url))
        port = parts.port or 443
        try:
            raw = socket.create_connection((parts.hostname, port), timeout=timeout)
            tls = ssl.create_default_context().wrap_socket(raw, server_hostname=parts.hostname)
        except (OSError, ssl.SSLError) as exc:
            raise UnreachableError(f"cannot connect to {parts.hostname}:{port}: {exc}", url=url) from exc
        tls.settimeout(timeout)
        ws = cls(tls)
        try:
            ws.handshake(parts.netloc, path, subprotocol)
        except TimeoutError as exc:
            ws.sock.close()
            raise UnreachableError(
                f"no websocket upgrade from {parts.hostname}:{port} within {timeout:g}s", url=url
            ) from exc
        except RexError:
            ws.sock.close()
            raise
        return ws

    def handshake(self, netloc: str, path: str, subprotocol: str) -> None:
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {netloc}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: {subprotocol}\r\n\r\n"
        )
        self.sock.sendall(request.encode())
        status, headers, body = self.read_http_response()
        if status in (401, 403):
            raise AccessDeniedError(
                f"server refused this principal (HTTP {status}): {body.strip()[:300]}", status=status
            )
        if status != 101:
            raise ApiError(f"websocket upgrade failed with HTTP {status}: {body.strip()[:300]}", status=status)
        if headers.get("sec-websocket-accept") != accept_key(key):
            raise ApiError("websocket upgrade returned a bad Sec-WebSocket-Accept")
        if headers.get("sec-websocket-protocol") != subprotocol:
            raise ApiError(f"server did not select subprotocol {subprotocol}")

    def read_http_response(self) -> tuple[int, dict[str, str], str]:
        while b"\r\n\r\n" not in self.buffer:
            if len(self.buffer) > MAX_HTTP_HEAD:
                raise ApiError(f"HTTP response head is over {MAX_HTTP_HEAD} bytes")
            self.buffer += self.recv_some()
        head, _, rest = self.buffer.partition(b"\r\n\r\n")
        if len(head) > MAX_HTTP_HEAD:
            raise ApiError(f"HTTP response head is over {MAX_HTTP_HEAD} bytes")
        lines = head.decode("latin-1").split("\r\n")
        headers = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:])}
        try:
            status = int(lines[0].split()[1])
            length = int(headers.get("content-length", "0"))
        except (IndexError, ValueError) as exc:
            raise ApiError(f"malformed HTTP response from server: {lines[0][:100]!r}") from exc
        self.buffer = rest
        body = ""
        if status != 101:
            length = min(length, MAX_HTTP_HEAD)  # only the start of an error body is ever shown
            while len(self.buffer) < length:
                self.buffer += self.recv_some()
            body = self.buffer[:length].decode("utf-8", "replace")
            self.buffer = self.buffer[length:]
        return status, headers, body

    def recv_some(self) -> bytes:
        try:
            chunk = self.sock.recv(65536)
        except TimeoutError as exc:
            raise TimeoutError("socket read timed out") from exc
        except (OSError, ssl.SSLError) as exc:
            raise UnreachableError(f"connection lost: {exc}") from exc
        if not chunk:
            raise UnreachableError("connection closed by peer without a close frame")
        return chunk

    def read_frame(self) -> tuple[bool, int, bytes]:
        while (frame := parse_frame(self.buffer, self.max_message)) is None:
            self.buffer += self.recv_some()
        fin, opcode, payload, used = frame
        self.buffer = self.buffer[used:]
        return fin, opcode, payload

    def send(self, opcode: int, data: bytes) -> None:
        if len(data) > self.max_send:
            raise UsageError(f"message of {len(data)} bytes exceeds the server limit of {self.max_send} bytes")
        self.sock.settimeout(SEND_TIMEOUT)  # not whatever short timeout the last poll left behind
        try:
            self.sock.sendall(encode_frame(opcode, data))
        except (OSError, ssl.SSLError) as exc:
            raise UnreachableError(f"connection lost while sending: {exc}") from exc

    def send_text(self, text: str) -> None:
        self.send(OP_TEXT, text.encode())

    def send_binary(self, data: bytes) -> None:
        self.send(OP_BIN, data)

    def readable(self) -> bool:
        if self.buffer:
            return True
        pending = getattr(self.sock, "pending", None)
        return bool(pending and pending() > 0)

    def recv_message(self, timeout: float | None) -> tuple[int, bytes]:
        """One whole message. Partial fragments stay on the instance, so a timeout can be retried."""
        self.sock.settimeout(timeout)
        while True:
            fin, opcode, payload = self.read_frame()
            if opcode >= OP_CLOSE and (not fin or len(payload) > 125):
                raise ApiError("websocket control frame is fragmented or longer than 125 bytes")
            if opcode == OP_PING:
                self.sock.sendall(encode_frame(OP_PONG, payload))
            elif opcode == OP_PONG:
                continue
            elif opcode == OP_CLOSE:
                self.echo_close(payload[:2])
                code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 1005
                raise WebSocketClosed(code, payload[2:].decode("utf-8", "replace"))
            elif opcode not in (OP_TEXT, OP_BIN, OP_CONT):
                raise ApiError(f"unknown websocket opcode {opcode}")
            else:
                if (opcode == OP_CONT) != (self.fragment_opcode is not None):
                    raise ApiError("websocket continuation frame does not match an open message")
                if self.fragment_opcode is None:
                    self.fragments, self.fragment_opcode = [], opcode
                kind = self.fragment_opcode
                self.fragments.append(payload)
                if sum(map(len, self.fragments)) > self.max_message:
                    raise ApiError(f"websocket message exceeds the {self.max_message} byte limit")
                if fin:
                    message = b"".join(self.fragments)
                    self.fragments, self.fragment_opcode = [], None
                    return kind, message

    def recv_text(self, timeout: float | None) -> str:
        opcode, message = self.recv_message(timeout)
        if opcode == OP_BIN:
            raise ApiError("unexpected binary message on control connection")
        try:
            return message.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ApiError("server sent a text message that is not UTF-8") from exc

    def echo_close(self, code: bytes) -> None:
        self.closed = True
        try:
            self.sock.sendall(encode_frame(OP_CLOSE, code))
        except OSError:
            pass

    def close(self) -> None:
        if not self.closed:
            try:
                self.sock.sendall(encode_frame(OP_CLOSE, struct.pack(">H", 1000)))
            except OSError:
                pass
            self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass


def wait_ready(sockets: list[WebSocket], timeout: float) -> list[WebSocket]:
    ready = [ws for ws in sockets if ws.readable()]
    if ready or timeout <= 0:
        return ready
    chosen, _, _ = select.select([ws.sock for ws in sockets], [], [], timeout)
    return [ws for ws in sockets if ws.sock in chosen]
