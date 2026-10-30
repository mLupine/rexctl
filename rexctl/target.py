from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .connection import RpcConnection
from .errors import TargetNotFoundError, UsageError
from .protocol import TERMINAL


def flatten_view(view: dict[str, Any]) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    for window in view.get("windows") or []:
        for layer in window.get("layers") or []:
            for block in layer.get("blocks") or []:
                blocks.append(
                    {
                        **block,
                        "window_id": window.get("window_id"),
                        "window_label": window.get("label"),
                        "layer_kind": layer.get("kind"),
                        "focused": block.get("block_id") == window.get("focused_block_id"),
                        "active_window": window.get("window_id") == view.get("active_window_id"),
                    }
                )
    return blocks


MIN_FRAGMENT = 4


def id_fragment_matches(fragment: str, ident: str) -> bool:
    bare = ident.split(":", 1)[-1]
    return len(fragment) >= MIN_FRAGMENT and (bare.startswith(fragment) or bare.endswith(fragment))


def match_one(kind: str, needle: str, candidates: list[tuple[str, str]]) -> str:
    """Exact id or label first, then a unique label prefix or id prefix/suffix of at least MIN_FRAGMENT characters."""
    fragment = needle.split(":", 1)[-1]
    exact = [i for i, label in candidates if needle in (i, label)]
    if len(exact) == 1:
        return exact[0]
    pool = exact or [
        i for i, label in candidates if id_fragment_matches(fragment, i) or (label and label.startswith(needle))
    ]
    if len(pool) == 1:
        return pool[0]
    if not pool:
        raise TargetNotFoundError(
            f"no {kind} matches {needle!r}", candidates=[{"id": i, "label": label} for i, label in candidates]
        )
    raise TargetNotFoundError(f"{kind} {needle!r} is ambiguous", matches=pool)


def resolve_session(conn: RpcConnection, needle: str | None) -> str:
    return pick_session(conn.call("session.list")["sessions"] or [], needle)


def pick_session(sessions: list[dict[str, Any]], needle: str | None) -> str:
    if needle is None:
        if len(sessions) == 1:
            return str(sessions[0]["session_id"])
        raise UsageError(
            "several sessions exist; pass -s/--session",
            sessions=[{"session_id": s["session_id"], "label": s["label"]} for s in sessions],
        )
    return match_one("session", needle, [(s["session_id"], s["label"]) for s in sessions])


def resolve_window(view: dict[str, Any], needle: str) -> str:
    windows = view.get("windows") or []
    if needle == "active" and view.get("active_window_id"):
        return str(view["active_window_id"])
    if needle.isdigit() and 1 <= int(needle) <= len(windows):
        return str(windows[int(needle) - 1]["window_id"])
    return match_one("window", needle, [(w["window_id"], w.get("label") or "") for w in windows])


def blocks_in_window(view: dict[str, Any], window: str | None) -> list[dict[str, Any]]:
    blocks = flatten_view(view)
    if window is None:
        return blocks
    window_id = resolve_window(view, window)
    return [b for b in blocks if b["window_id"] == window_id]


def focused_block(blocks: list[dict[str, Any]], window: str | None) -> str:
    focused = [b for b in blocks if b["focused"] and (window is not None or b["active_window"])]
    if focused:
        return str(focused[0]["block_id"])
    raise TargetNotFoundError("no focused block here; pass -b/--block")


def block_titles(conn: RpcConnection, session_id: str, blocks: list[dict[str, Any]]) -> list[tuple[str, str]]:
    terminals = [b for b in blocks if b.get("creator_name") == TERMINAL]
    results = conn.call_many(
        [(f"{TERMINAL}.title", {"session_id": session_id, "block_id": b["block_id"], "args": {}}) for b in terminals]
    )
    return [
        (b["block_id"], r.get("title") or "") for b, r in zip(terminals, results, strict=True) if isinstance(r, dict)
    ]


def match_title(needle: str, titles: list[tuple[str, str]]) -> str | None:
    """Exact (case-insensitive) titles only: any program can set its title, so a fragment must not pick a pane."""
    found = [i for i, t in titles if t.lower() == needle.lower()]
    if len(found) == 1:
        return found[0]
    if found:
        raise TargetNotFoundError(f"title {needle!r} is ambiguous", matches=found)
    return None


def resolve_block(conn: RpcConnection, session_id: str, needle: str | None, window: str | None = None) -> str:
    view = conn.call("session.view", {"session_id": session_id})
    return pick_block(conn, session_id, blocks_in_window(view, window), needle, window)


def pick_block(conn: Any, session_id: str, blocks: list[dict[str, Any]], needle: str | None, window: str | None) -> str:
    if needle is None or needle == "focused":
        return focused_block(blocks, window)
    try:
        return match_one("block", needle, [(b["block_id"], b.get("label") or "") for b in blocks])
    except TargetNotFoundError as exc:
        if "matches" in exc.details:
            raise
        found = match_title(needle, block_titles(conn, session_id, blocks))
        if found is None:
            raise
        return found


@dataclass
class Target:
    host: str
    url: str
    session_id: str
    block_id: str | None = None
    session_label: str = ""

    def describe(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "url": self.url,
            "session_id": self.session_id,
            "session_label": self.session_label,
            "block_id": self.block_id,
        }


def resolve_target(
    conn: RpcConnection,
    host: str,
    url: str,
    session: str | None,
    block: str | None,
    need_block: bool = True,
    window: str | None = None,
) -> Target:
    sessions = conn.call("session.attach_all", {"event_scope": "session"})["sessions"] or []
    session_id = pick_session(sessions, session)
    label = next((s["label"] for s in sessions if s["session_id"] == session_id), "")
    block_id = resolve_block(conn, session_id, block, window) if need_block else None
    return Target(host=host, url=url, session_id=session_id, block_id=block_id, session_label=label)
