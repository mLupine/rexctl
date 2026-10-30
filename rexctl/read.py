from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .connection import RpcConnection
from .errors import ApiError
from .protocol import TERMINAL
from .target import Target, flatten_view, pick_session


def trim_lines(text: str, lines: int | None) -> str:
    rows = text.rstrip("\n").split("\n")
    while rows and not rows[-1].strip():
        rows.pop()
    if lines is not None and lines >= 0:
        rows = rows[-lines:] if lines else []
    return "\n".join(rows)


def read_format(
    conn: RpcConnection, t: Target, fmt: str = "text", unwrap: bool = False, max_bytes: int = 983040
) -> dict[str, Any]:
    args = {"format": fmt, "trim": True, "unwrap": unwrap, "max_bytes": max_bytes}
    first = conn.block_call(f"{TERMINAL}.format", t.session_id, t.block_id or "", args)
    content = first["content"]
    result = {"content": content, "truncated": False, "total_bytes": first.get("total", len(content.encode()))}
    if first.get("id") and not first.get("eof", False):
        result["truncated"] = True
        result["blob_id"] = first["id"]
    return result


def read_tail(
    conn: RpcConnection, t: Target, lines: int, unwrap: bool = False, max_bytes: int = 983040
) -> dict[str, Any]:
    result = read_format(conn, t, unwrap=unwrap, max_bytes=max_bytes)
    if result["truncated"]:
        result["content"] = read_blob_tail(conn, t, result["blob_id"], result["total_bytes"], max_bytes)
        result["truncated"] = False
        result["partial_scrollback"] = True
    result["content"] = trim_lines(result["content"], lines)
    result["lines"] = len(result["content"].split("\n")) if result["content"] else 0
    return result


def read_blob_tail(conn: RpcConnection, t: Target, blob_id: int, total: int, window: int) -> str:
    offset = max(0, total - window // 2)
    for _ in range(4):
        try:
            part = conn.block_call(
                f"{TERMINAL}.blob_read",
                t.session_id,
                t.block_id or "",
                {"id": blob_id, "offset": offset, "max_bytes": 983040},
            )
            return str(part["data"])
        except ApiError as exc:
            if exc.details.get("code") != "bad_request":
                raise
            offset += 1  # the offset fell inside a multi-byte UTF-8 character; step to the next byte
    raise ApiError("could not read tail of large screen output")


def visible_rows(conn: RpcConnection, t: Target) -> int:
    size = conn.block_call(f"{TERMINAL}.size", t.session_id, t.block_id or "", {})
    return int(size.get("rows") or 60)


def screen_result(conn: RpcConnection, t: Target, lines: int | None, unwrap: bool) -> dict[str, Any]:
    result = read_tail(conn, t, lines if lines is not None else visible_rows(conn, t), unwrap=unwrap)
    return {"ok": True, "target": t.describe(), **{k: result[k] for k in ("content", "lines", "total_bytes")}}


def block_summary(block: dict[str, Any]) -> dict[str, Any]:
    info = {
        k: block.get(k)
        for k in (
            "block_id",
            "label",
            "flavor",
            "focused",
            "window_id",
            "window_label",
            "active_window",
            "layer_kind",
            "owner",
        )
    }
    info["short_id"] = (block.get("block_id") or "")[-8:]
    return info


def facts_for_blocks(conn: RpcConnection, pairs: list[tuple[str, str]]) -> dict[str, dict[str, Any]]:
    calls: list[tuple[str, dict[str, Any] | None]] = [
        (f"{TERMINAL}.{method}", {"session_id": sid, "block_id": bid, "args": {}})
        for sid, bid in pairs
        for _, method, _ in FACT_PICKERS
    ]
    results = conn.call_many(calls)
    width = len(FACT_PICKERS)
    facts: dict[str, dict[str, Any]] = {}
    for index, (_, bid) in enumerate(pairs):
        facts[bid] = pick_facts(results[index * width : (index + 1) * width])
    return facts


def pick_facts(results: list[Any]) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    for (key, _, picker), result in zip(FACT_PICKERS, results, strict=True):
        if isinstance(result, ApiError):
            facts[key] = None
            facts.setdefault("errors", {})[key] = result.message
        else:
            facts[key] = picker(result)
    return facts


def foreground_name(result: dict[str, Any]) -> Any:
    for key in ("foreground", "foreground_process"):
        proc = result.get(key)
        if isinstance(proc, dict):
            return proc.get("name")
    procs = result.get("processes")
    if isinstance(procs, list) and procs:
        return procs[-1].get("name")
    return None


STATUS_KEYS = ("id", "state", "kind", "app", "title", "msg", "updated_at")


def pick_status(record: dict[str, Any]) -> dict[str, Any]:
    return {k: record.get(k) for k in STATUS_KEYS if record.get(k)}


def root_status(result: dict[str, Any]) -> dict[str, Any] | None:
    records = result.get("records") or []
    if not records:
        return None
    best = max(records, key=lambda r: r.get("updated_at", ""))
    status = pick_status(best)
    if len(status.get("msg", "")) > 200:
        status["msg"] = status["msg"][:200] + "..."
    return status


FACT_PICKERS: list[tuple[str, str, Callable[[dict[str, Any]], Any]]] = [
    ("title", "title", lambda r: r.get("title")),
    ("pwd", "pwd", lambda r: r.get("pwd")),
    ("foreground", "process", foreground_name),
    ("status", "program_status", root_status),
]


def block_about(conn: RpcConnection, t: Target) -> dict[str, Any]:
    """What a human needs to recognise the block in a plan. Written by programs, so it is shown, never trusted."""
    if not t.block_id:
        return {}
    view = conn.call("session.view", {"session_id": t.session_id})
    label = next((b.get("label") for b in flatten_view(view) if b.get("block_id") == t.block_id), None)
    facts = facts_for_blocks(conn, [(t.session_id, t.block_id)])[t.block_id]
    return {"block_label": label, **{k: facts.get(k) for k in ("title", "pwd", "foreground")}}


def list_sessions(conn: RpcConnection, session: str | None, detail: bool) -> list[dict[str, Any]]:
    sessions = conn.call("session.attach_all", {"event_scope": "session"})["sessions"] or []
    chosen = [s for s in sessions if s["session_id"] == pick_session(sessions, session)] if session else sessions
    views = conn.call_many([("session.view", {"session_id": s["session_id"]}) for s in chosen])
    for view in views:
        if isinstance(view, ApiError):
            raise view
    facts: dict[str, dict[str, Any]] = {}
    if detail:
        pairs = [
            (s["session_id"], b["block_id"])
            for s, v in zip(chosen, views, strict=True)
            for b in flatten_view(v)
            if b.get("creator_name") == TERMINAL
        ]
        facts = facts_for_blocks(conn, pairs)
    return [
        {
            "session_id": s["session_id"],
            "label": s["label"],
            "revision": v.get("revision"),
            "windows": windows_summary(v, facts),
        }
        for s, v in zip(chosen, views, strict=True)
    ]


def windows_summary(view: dict[str, Any], facts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    blocks = flatten_view(view)
    out = []
    for window in view.get("windows") or []:
        wid = window.get("window_id")
        out.append(
            {
                "window_id": wid,
                "label": window.get("label"),
                "active": wid == view.get("active_window_id"),
                "blocks": [
                    {**block_summary(b), **facts.get(b["block_id"], {})} for b in blocks if b["window_id"] == wid
                ],
            }
        )
    return out
