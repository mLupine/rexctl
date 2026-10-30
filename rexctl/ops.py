"""Table-driven wrappers around Rex API methods: one Op per method, shared argparse, resolving and guard logic."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import keys
from .connection import RpcConnection
from .context import Context
from .errors import EXIT_DRY_RUN, EXIT_OK, UsageError
from .flags import TARGET_HELP, add_admin_arg, add_guard_arg, finite_float
from .inputs import parse_payload
from .output import emit, eprint, guard
from .protocol import SHELL_FLAVOR, TERMINAL
from .target import (
    Target,
    blocks_in_window,
    match_one,
    pick_block,
    resolve_session,
    resolve_target,
    resolve_window,
)

LOCAL_ONLY_NOTE = (
    "server-local method: Rex only accepts it on its Unix socket, so over Tailscale it answers 403 "
    "(not usable from this box)"
)
REF_KINDS = {"block", "window", "layer", "session", "client"}


@dataclass(frozen=True)
class Param:
    dest: str
    kind: str = "str"
    help: str = ""
    required: bool = False
    choices: tuple[str, ...] = ()
    default: Any = None
    key: str | None = None
    short: str | None = None
    local: bool = False
    parent: str | None = None

    @property
    def flag(self) -> str:
        return "--" + self.dest.replace("_", "-")

    @property
    def payload_key(self) -> str:
        return self.key or self.dest


@dataclass(frozen=True)
class Op:
    group: str
    name: str
    method: str
    help: str
    params: tuple[Param, ...] = ()
    scope: str = "session"
    mutating: bool = True
    destructive: str = ""
    admin: bool = False
    sensitive: bool = False
    block_default: bool = False
    local_only: bool = False
    attach: bool = False
    plan: Callable[[argparse.Namespace], list[tuple[str, dict[str, Any]]]] | None = None


def param_help(p: Param) -> str:
    return p.help + (" (required)" if p.required else "")


def add_ref_param(parser: argparse.ArgumentParser, p: Param) -> None:
    flags = [p.flag] + ([p.short] if p.short else [])
    parser.add_argument(*flags, dest=p.dest, help=param_help(p) + " - id, label or unique id fragment")


def add_layout_params(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--flavor", default=SHELL_FLAVOR, help="block flavor for the new block (default: shell)")
    parser.add_argument("--cwd", help="working directory of the new shell")
    parser.add_argument("--block-label", help="label of the new block")
    parser.add_argument(
        "--layout-json", help="raw layout object (JSON or @file); overrides --flavor/--cwd/--block-label"
    )


def add_param(parser: argparse.ArgumentParser, p: Param) -> None:
    if p.kind in REF_KINDS:
        add_ref_param(parser, p)
    elif p.kind == "blocks":
        parser.add_argument(p.flag, dest=p.dest, help=param_help(p) + " - comma-separated block ids/labels")
    elif p.kind == "layout":
        add_layout_params(parser)
    elif p.kind == "list":
        parser.add_argument(p.flag, dest=p.dest, default=p.default, help=param_help(p) + " - comma-separated")
    elif p.kind == "bool":
        parser.add_argument(p.flag, dest=p.dest, action="store_true", help=p.help)
    elif p.kind == "secret_file":
        parser.add_argument(
            p.flag,
            dest=p.dest,
            metavar="FILE",
            help=param_help(p) + " - path of a file holding the secret (never printed)",
        )
    elif p.kind == "tri":
        parser.add_argument(p.flag, dest=p.dest, action=argparse.BooleanOptionalAction, default=None, help=p.help)
    elif p.kind == "choice":
        parser.add_argument(p.flag, dest=p.dest, choices=p.choices, default=p.default, help=param_help(p))
    elif p.kind in ("int", "float"):
        parser.add_argument(
            p.flag, dest=p.dest, type=int if p.kind == "int" else finite_float, default=p.default, help=param_help(p)
        )
    elif p.kind == "bounds":
        parser.add_argument(
            p.flag,
            dest=p.dest,
            metavar="X,Y,W,H",
            help=param_help(p) + " - fractions of the window, e.g. 0.1,0.1,0.5,0.5",
        )
    else:
        parser.add_argument(p.flag, dest=p.dest, default=p.default, help=param_help(p))


def add_op_args(parser: argparse.ArgumentParser, op: Op) -> None:
    if op.scope in ("session", "block"):
        parser.add_argument(
            "-s", "--session", help="session id, label or unique id fragment (optional if only one exists)"
        )
        parser.add_argument("-t", "--target", help=TARGET_HELP)
    if op.scope == "block":
        parser.add_argument("-b", "--block", help="block id, label or unique id fragment (default: focused block)")
    for p in op.params:
        add_param(parser, p)
    if op.mutating:
        add_guard_arg(parser)
    if op.admin:
        add_admin_arg(parser)


def file_flags(op: Op) -> set[str]:
    """Flags whose value may name a local file to read (`@path`, or a secret file)."""
    flags = {p.flag for p in op.params if p.kind in ("json", "secret_file")}
    return flags | ({"--layout-json"} if any(p.kind == "layout" for p in op.params) else set())


def op_flags(op: Op) -> set[str]:
    parser = argparse.ArgumentParser(add_help=False)
    add_op_args(parser, op)
    return {flag for action in parser._actions for flag in action.option_strings}


class Resolver:
    def __init__(self, conn: RpcConnection, session_id: str, window: str | None = None) -> None:
        self.conn = conn
        self.session_id = session_id
        self.in_window = window
        self.cached_view: dict[str, Any] | None = None

    def view(self) -> dict[str, Any]:
        if self.cached_view is None:
            self.cached_view = self.conn.call("session.view", {"session_id": self.session_id})
        return self.cached_view

    def block(self, needle: str | None) -> str:
        blocks = blocks_in_window(self.view(), self.in_window)
        return pick_block(self.conn, self.session_id, blocks, needle, self.in_window)

    def window(self, needle: str) -> str:
        return resolve_window(self.view(), needle)

    def layer(self, needle: str) -> str:
        layers = [
            (layer["layer_id"], layer.get("kind") or "")
            for w in self.view().get("windows") or []
            for layer in w.get("layers") or []
        ]
        return match_one("layer", needle, layers)

    def session(self, needle: str) -> str:
        return resolve_session(self.conn, needle)

    def client(self, needle: str) -> str:
        clients = self.conn.call("client.list", {}).get("clients") or []
        return match_one("client", needle, [(c["client_id"], client_label(c)) for c in clients])


def client_label(client: dict[str, Any]) -> str:
    info = client.get("info") or {}
    return info.get("label") or client.get("label") or ""


def parse_bounds(raw: str) -> list[float]:
    try:
        x, y, w, h = (float(part) for part in raw.split(","))
    except ValueError:
        raise UsageError(f"bounds must be X,Y,W,H numbers, got {raw!r}") from None
    if min(x, y) < 0 or min(w, h) <= 0 or x + w > 1.0 + 1e-9 or y + h > 1.0 + 1e-9:
        raise UsageError("bounds are fractions of the window and must fit inside it (x,y>=0; w,h>0; x+w<=1; y+h<=1)")
    return [x, y, w, h]


def parse_json_arg(raw: str) -> Any:
    if raw.strip().startswith(("{", "@")):
        return parse_payload(raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UsageError(f"not valid JSON: {raw[:80]!r} ({exc})") from None


def read_secret_file(path: str) -> str:
    try:
        text = Path(path).expanduser().read_text().strip()
    except OSError as exc:
        raise UsageError(f"cannot read secret file {path}: {exc.strerror}") from None
    if not text:
        raise UsageError(f"secret file {path} is empty")
    return text


def build_layout(args: argparse.Namespace) -> dict[str, Any]:
    if getattr(args, "layout_json", None):
        return parse_payload(args.layout_json)
    block: dict[str, Any] = {"flavor": args.flavor}
    if args.block_label:
        block["label"] = args.block_label
    if args.cwd:
        block["options"] = {"cwd": args.cwd}
    return {"block": block}


def resolve_ref(resolver: Resolver, p: Param, value: str) -> Any:
    if p.kind == "block":
        return resolver.block(value)
    if p.kind == "window":
        return resolver.window(value)
    if p.kind == "layer":
        return resolver.layer(value)
    if p.kind == "session":
        return resolver.session(value)
    if p.kind == "client":
        return resolver.client(value)
    return [resolver.block(part) for part in value.split(",") if part]


def param_value(p: Param, args: argparse.Namespace, resolver: Resolver | None) -> Any:
    if p.kind == "layout":
        return build_layout(args)
    value = getattr(args, p.dest, None)
    if value is None or (value is False and p.kind == "bool"):
        return None
    if p.kind in REF_KINDS or p.kind == "blocks":
        if resolver is None:
            raise UsageError(f"{p.flag} needs a session to resolve against")
        return resolve_ref(resolver, p, value)
    if p.kind == "bounds":
        return parse_bounds(value)
    if p.kind == "shell_cwd":
        return {"cwd": value}
    if p.kind == "list":
        return [part for part in value.split(",") if part]
    if p.kind == "json":
        return parse_json_arg(value)
    if p.kind == "secret_file":
        return read_secret_file(value)
    return value


def build_payload(op: Op, args: argparse.Namespace, resolver: Resolver | None) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if resolver is not None and op.scope == "session":
        payload["session_id"] = resolver.session_id
    for p in (p for p in op.params if not p.local):
        value = param_value(p, args, resolver)
        if value is None:
            if p.required:
                raise UsageError(f"{op.group} {op.name}: {p.flag} is required")
            if op.block_default and p.kind == "block" and resolver is not None:
                value = resolver.block(None)
            else:
                continue
        if p.parent:
            payload.setdefault(p.parent, {})[p.payload_key] = value
        else:
            payload[p.payload_key] = value
    return payload


def plan_target(host: str, url: str, session_id: str | None, label: str, payload: dict[str, Any]) -> dict[str, Any]:
    target: dict[str, Any] = {"host": host, "url": url}
    if session_id:
        target.update(session_id=session_id, session_label=label)
    ids = {k: v for k, v in payload.items() if k.endswith("_id") or k.endswith("_ids")}
    return {**target, **ids}


def authorise(
    args: argparse.Namespace,
    op: Op,
    target: dict[str, Any],
    payload: dict[str, Any],
    method_override: str | None = None,
) -> bool:
    detail: dict[str, Any] = {"method": method_override or op.method, "payload": payload}
    if op.destructive:
        detail["warning"] = op.destructive
    if op.local_only:
        detail["limit"] = LOCAL_ONLY_NOTE
    if not guard(args, f"{op.group} {op.name} ({op.method})", target, detail, admin=op.admin):
        return False
    if op.destructive:
        eprint(f"rexctl: WARNING {op.destructive}")
    return True


def session_context(conn: RpcConnection, host: str, url: str, args: argparse.Namespace) -> tuple[Target, Resolver]:
    t = resolve_target(conn, host, url, getattr(args, "session", None), None, need_block=False)
    return t, Resolver(conn, t.session_id, getattr(args, "target_window", None))


def run_session_op(op: Op, args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    with ctx.rpc(url, args.timeout) as conn:
        t, resolver = session_context(conn, host, url, args)
        payload = build_payload(op, args, resolver)
        target = plan_target(host, url, t.session_id, t.session_label, payload)
        if op.mutating and not authorise(args, op, target, payload):
            return EXIT_DRY_RUN
        if op.attach:
            conn.call("session.attach", {"session_id": t.session_id})
        result = conn.call(op.method, payload)
    return emit_result(op, target, result, args)


def run_server_op(op: Op, args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    if not any(p.kind in REF_KINDS for p in op.params):
        payload = build_payload(op, args, None)
        target = plan_target(host, url, None, "", payload)
        if op.mutating and not authorise(args, op, target, payload):
            return EXIT_DRY_RUN
        with ctx.rpc(url, args.timeout) as conn:
            return emit_result(op, target, conn.call(op.method, payload), args)
    with ctx.rpc(url, args.timeout) as conn:
        payload = build_payload(op, args, Resolver(conn, ""))
        target = plan_target(host, url, None, "", payload)
        if op.mutating and not authorise(args, op, target, payload):
            return EXIT_DRY_RUN
        return emit_result(op, target, conn.call(op.method, payload), args)


def block_calls(
    op: Op, args: argparse.Namespace, session_id: str, block_id: str, resolver: Resolver
) -> list[tuple[str, dict[str, Any]]]:
    if op.plan is not None:
        return [
            (method, {"session_id": session_id, "block_id": block_id, **fields}) for method, fields in op.plan(args)
        ]
    fields = build_payload(op, args, resolver)
    fields.pop("session_id", None)
    return [(op.method, {"session_id": session_id, "block_id": block_id, **fields})]


def execute_call(conn: RpcConnection, method: str, payload: dict[str, Any]) -> Any:
    if method.startswith("com."):
        extra = {k: v for k, v in payload.items() if k not in ("session_id", "block_id")}
        return conn.block_call(method, payload["session_id"], payload["block_id"], extra)
    return conn.call(method, payload)


def run_block_op(op: Op, args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    with ctx.rpc(url, args.timeout) as conn:
        t = resolve_target(conn, host, url, getattr(args, "session", None), None, need_block=False)
        resolver = Resolver(conn, t.session_id, getattr(args, "target_window", None))
        t.block_id = resolver.block(getattr(args, "block", None))
        calls = block_calls(op, args, t.session_id, t.block_id, resolver)
        target = t.describe()
        if op.mutating and not authorise_calls(args, op, target, calls):
            return EXIT_DRY_RUN
        results = [execute_call(conn, method, payload) for method, payload in calls]
    return emit_result(op, target, results[0] if len(results) == 1 else results, args)


def authorise_calls(
    args: argparse.Namespace, op: Op, target: dict[str, Any], calls: list[tuple[str, dict[str, Any]]]
) -> bool:
    shown = [
        {"method": m, "payload": {k: v for k, v in p.items() if k not in ("session_id", "block_id")}} for m, p in calls
    ]
    plan: dict[str, Any] = {"calls": shown} if len(shown) > 1 else shown[0]
    return authorise(args, op, target, plan.get("payload", plan), method_override=plan.get("method"))


def redact_sensitive(result: Any) -> Any:
    if isinstance(result, dict) and isinstance(result.get("data"), str):
        size = len(result["data"].encode())
        return {**result, "data": f"<redacted {size} bytes: sensitive text, pass --show to print it>"}
    return result


def emit_result(op: Op, target: dict[str, Any], result: Any, args: argparse.Namespace) -> int:
    if op.sensitive and not getattr(args, "show", False):
        result = redact_sensitive(result)
    emit({"ok": True, "target": target, "method": op.method, "result": result})
    return EXIT_OK


RUNNERS: dict[str, Callable[[Op, argparse.Namespace, str, str, Context], int]] = {
    "session": run_session_op,
    "server": run_server_op,
    "block": run_block_op,
}


def run_op(args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    op: Op = args.op_spec
    return RUNNERS[op.scope](op, args, host, url, ctx)


def window_param(required: bool = True) -> Param:
    return Param("window", "window", "target window", required, key="window_id", short="-w")


def block_param(dest: str = "block", required: bool = True, help: str = "target block") -> Param:
    return Param(dest, "block", help, required, key=dest + "_id", short="-b" if dest == "block" else None)


def layer_param(dest: str = "layer", required: bool = True) -> Param:
    return Param(dest, "layer", "floating layer", required, key=dest + "_id")


BOUNDS = Param("bounds", "bounds", "x,y,w,h as fractions of the window", True)
FOCUS = Param("focus", "tri", "make the new block/window active and focused")
WRAP = Param("wrap", "bool", "wrap around at the edge")
LABEL = Param("label", "str", "new label (empty restores the default)", True)
DIRECTION = Param("direction", "choice", "split orientation", True, ("horizontal", "vertical"))
SIDE = Param("side", "choice", "which side the moved block goes", False, ("before", "after"))
RATIO = Param("ratio", "float", "fraction the before part gets, between 0 and 1")

LAYOUT_OPS: tuple[Op, ...] = (
    Op(
        "layout",
        "new-window",
        "session.new_window",
        "new window with one new block",
        (Param("window_label", "str", "window label"), Param("layout", "layout"), FOCUS),
    ),
    Op(
        "layout",
        "new-block",
        "session.new_block",
        "new detached block (place it with move-block)",
        (
            Param("flavor", "str", "block flavor", False, default=SHELL_FLAVOR),
            Param("label", "str", "block label"),
            Param("cwd", "shell_cwd", "working directory (shell options)", key="options"),
        ),
    ),
    Op(
        "layout",
        "new-layer",
        "session.new_layer",
        "new floating layer with a new block",
        (window_param(False), BOUNDS, Param("layout", "layout"), FOCUS),
    ),
    Op(
        "layout",
        "move-block",
        "session.move_block",
        "move a block beside an anchor block",
        (
            block_param(),
            block_param("anchor_block", help="block to place it beside"),
            Param("direction", "choice", "how to divide the anchor", False, ("horizontal", "vertical")),
            SIDE,
            RATIO,
        ),
    ),
    Op(
        "layout",
        "move-window",
        "session.move_window",
        "reorder a window (tab)",
        (
            window_param(),
            Param("before_window", "window", "place it just before this window (default: end)", key="before_window_id"),
        ),
    ),
    Op(
        "layout",
        "move-session",
        "session.move",
        "reorder the session in the session list",
        (
            Param(
                "before_session", "session", "place it just before this session (default: end)", key="before_session_id"
            ),
        ),
    ),
    Op(
        "layout",
        "swap-blocks",
        "session.swap_blocks",
        "swap two blocks",
        (block_param(), block_param("other_block", help="the other block")),
    ),
    Op(
        "layout",
        "resize-pane",
        "session.resize_pane",
        "move the border between two blocks",
        (
            DIRECTION,
            block_param("before_block", help="block left of / above the border"),
            block_param("after_block", help="block right of / below the border"),
            Param("ratio", "float", "fraction for the before part (0..1)", True),
        ),
    ),
    Op("layout", "resize-layer", "session.resize_layer", "move or resize a floating layer", (layer_param(), BOUNDS)),
    Op(
        "layout",
        "float-block",
        "session.float_block",
        "turn a tiled block into a floating layer",
        (block_param(), BOUNDS),
    ),
    Op(
        "layout",
        "zoom-block",
        "session.zoom_block",
        "zoom a block, or restore the layout",
        (
            block_param(required=False),
            window_param(False),
            Param("zoom", "tri", "true=zoom, false=restore, omitted=toggle"),
        ),
    ),
    Op("layout", "focus-block", "session.focus_block", "focus a block (also activates its window)", (block_param(),)),
    Op("layout", "focus-window", "session.focus_window", "make a window active", (window_param(),)),
    Op(
        "layout",
        "focus-direction",
        "session.focus_direction",
        "move focus left/right/up/down",
        (Param("direction", "choice", "where to move", True, ("left", "right", "up", "down")), WRAP),
    ),
    Op("layout", "focus-next-pane", "session.focus_next_pane", "focus the next block", (WRAP,)),
    Op("layout", "focus-previous-pane", "session.focus_previous_pane", "focus the previous block", (WRAP,)),
    Op("layout", "focus-next-window", "session.focus_next_window", "activate the next window", (WRAP,)),
    Op("layout", "focus-previous-window", "session.focus_previous_window", "activate the previous window", (WRAP,)),
    Op(
        "layout",
        "close-window",
        "session.close_window",
        "close a window and every program in it",
        (window_param(),),
        destructive="closes every block in the window and ends its programs",
    ),
    Op(
        "layout",
        "close-layer",
        "session.close_layer",
        "close a floating layer and its blocks",
        (layer_param(),),
        destructive="closes every block in the layer and ends its programs",
    ),
    Op("layout", "set-session-label", "session.set_label", "rename the session", (LABEL,)),
    Op("layout", "set-window-label", "session.set_window_label", "rename a window", (window_param(), LABEL)),
    Op("layout", "set-block-label", "session.set_block_label", "rename a block", (block_param(), LABEL)),
    Op(
        "layout",
        "lower-layer",
        "session.lower_layer",
        "move a floating layer back",
        (layer_param(), layer_param("relative_layer", False)),
    ),
    Op(
        "layout",
        "raise-layer",
        "session.raise_layer",
        "move a floating layer forward",
        (layer_param(), layer_param("relative_layer", False)),
    ),
)


def key_calls(args: argparse.Namespace) -> list[tuple[str, dict[str, Any]]]:
    try:
        parsed = keys.parse_keys(args.keys)
    except keys.KeyNameError as exc:
        raise UsageError(str(exc), examples=keys.KEY_EXAMPLES) from None
    if not parsed:
        raise UsageError("no keys given")
    objects = [keys.key_object(key) for key in parsed]
    if args.via == "client-key":
        return [("client.key", {"key": obj}) for obj in objects]
    return [("block.event", {"event": {"type": "key", "payload": obj}}) for obj in objects]


def paste_calls(args: argparse.Namespace) -> list[tuple[str, dict[str, Any]]]:
    return [("block.event", {"event": {"type": "paste", "payload": {"text": args.text}}})]


def focus_calls(args: argparse.Namespace) -> list[tuple[str, dict[str, Any]]]:
    return [("block.event", {"event": {"type": "focus", "payload": {"action": args.action}}})]


def raw_event_calls(args: argparse.Namespace) -> list[tuple[str, dict[str, Any]]]:
    event_type = getattr(args, "event_type", None) or args.op_spec.name
    if event_type not in ("key", "paste", "mouse", "wheel", "focus"):
        raise UsageError(f"clients may only send key, paste, mouse, wheel and focus events, not {event_type!r}")
    return [
        (
            "block.event",
            {"event": {"type": event_type, "payload": parse_json_arg(args.payload) if args.payload else {}}},
        )
    ]


PAYLOAD = Param("payload", "json", "event payload as JSON object or @file (shape is not specified by the API)")
INPUT_OPS: tuple[Op, ...] = (
    Op(
        "input",
        "key",
        "block.event",
        "press keys as a user would (names: Enter C-c Esc Up F5 M-x ...)",
        (
            Param("keys", "str", "key names, comma/space separated", True),
            Param(
                "via",
                "choice",
                "block-event (default, straight to the block) or client-key (Lua key bindings first)",
                False,
                ("block-event", "client-key"),
                "block-event",
            ),
        ),
        scope="block",
        plan=key_calls,
    ),
    Op(
        "input",
        "paste",
        "block.event",
        "paste text as a bracketed paste event",
        (Param("text", "str", "text to paste", True),),
        scope="block",
        plan=paste_calls,
    ),
    Op(
        "input",
        "focus",
        "block.event",
        "send a focus in/out event",
        (Param("action", "choice", "in or out", True, ("in", "out")),),
        scope="block",
        plan=focus_calls,
    ),
    Op("input", "mouse", "block.event", "send a raw mouse event", (PAYLOAD,), scope="block", plan=raw_event_calls),
    Op("input", "wheel", "block.event", "send a raw wheel event", (PAYLOAD,), scope="block", plan=raw_event_calls),
    Op(
        "input",
        "event",
        "block.event",
        "send any client-allowed block event",
        (Param("event_type", "choice", "event type", True, ("key", "paste", "mouse", "wheel", "focus")), PAYLOAD),
        scope="block",
        plan=raw_event_calls,
    ),
)

TERM = TERMINAL + "."
SHOW = Param("show", "bool", "print the sensitive text (redacted by default)", local=True)
READ_WINDOW = (
    Param("id", "int", "result id from an event/earlier reply (0 = latest)"),
    Param("offset", "int", "start byte"),
    Param("max_bytes", "int", "most bytes to return"),
)
TERM_OPS: tuple[Op, ...] = (
    Op(
        "term",
        "clipboard-read",
        TERM + "clipboard_read",
        "text a program copied to the clipboard (sensitive)",
        READ_WINDOW + (SHOW,),
        scope="block",
        mutating=False,
        sensitive=True,
    ),
    Op(
        "term",
        "blob-read",
        TERM + "blob_read",
        "read a large result by id, e.g. selection_copied (sensitive)",
        READ_WINDOW + (SHOW,),
        scope="block",
        mutating=False,
        sensitive=True,
    ),
    Op(
        "term",
        "list-dir",
        TERM + "list_dir",
        "list directories (and files) as the terminal's program sees them",
        (
            Param("path", "str", "directory, ~ or relative to the program's cwd"),
            Param("prefix", "str", "name prefix filter"),
            Param("limit", "int", "most entries"),
            Param("files", "bool", "include files"),
        ),
        scope="block",
        mutating=False,
    ),
    Op(
        "term",
        "modes",
        TERM + "modes",
        "terminal modes (alt screen, bracketed paste, mouse reporting)",
        scope="block",
        mutating=False,
    ),
    Op(
        "term",
        "input-mode",
        TERM + "input_mode",
        "echo/canonical/signals state (password prompt detection)",
        scope="block",
        mutating=False,
    ),
    Op(
        "term",
        "size",
        TERM + "size",
        "terminal size, owner and per-client requested sizes",
        scope="block",
        mutating=False,
    ),
    Op(
        "term",
        "resize",
        TERM + "resize",
        "request a terminal size (applies at once if nobody owns the block)",
        (
            Param("columns", "int", "columns 1..65535", True),
            Param("rows", "int", "rows 1..65535", True),
            Param("cell_width_px", "int", "cell width px (with cell height)"),
            Param("cell_height_px", "int", "cell height px"),
        ),
        scope="block",
        destructive="changes the terminal size for every viewer; programs get SIGWINCH",
    ),
    Op(
        "term",
        "reset",
        TERM + "reset",
        "reset the terminal and clear screen and scrollback",
        scope="block",
        destructive="clears the screen and scrollback; the program keeps running",
    ),
    Op(
        "term",
        "clear",
        TERM + "clear",
        "clear screen and scrollback",
        scope="block",
        destructive="clears the screen and scrollback",
    ),
    Op(
        "term",
        "set-theme",
        TERM + "set_theme",
        "replace default colors",
        (
            Param("foreground", "str", "RRGGBB"),
            Param("background", "str", "RRGGBB"),
            Param("cursor", "str", "RRGGBB"),
            Param("scheme", "choice", "light or dark", False, ("light", "dark")),
            Param("palette", "list", "index=RRGGBB entries"),
        ),
        scope="block",
    ),
)

ONBOARDING = "com.superlogical.onboarding."
ONBOARDING_OPS: tuple[Op, ...] = (
    Op(
        "onboarding",
        "state",
        ONBOARDING + "state",
        "step the onboarding walkthrough block is on",
        scope="block",
        mutating=False,
    ),
    Op(
        "onboarding",
        "set-step",
        ONBOARDING + "set_step",
        "move the onboarding walkthrough to another step",
        (Param("step", "str", "step name (empty = first step)", True),),
        scope="block",
    ),
)

CLIENT = Param("client", "client", "client id or label", True, key="client_id")
ADMIN_OPS: tuple[Op, ...] = (
    Op(
        "admin",
        "server-status",
        "server.status",
        "server identity, session count, config, Tailscale",
        scope="server",
        mutating=False,
    ),
    Op(
        "admin",
        "privacy-status",
        "server.apple.privacy_status",
        "macOS privacy permissions (server-local: Unix socket only)",
        scope="server",
        mutating=False,
        local_only=True,
    ),
    Op("admin", "hosts-list", "hosts.list", "the server's saved host list", scope="server", mutating=False),
    Op(
        "admin",
        "client-list",
        "client.list",
        "connected clients (apps, agents)",
        (
            Param("session", "session", "only clients attached to this session"),
            Param("kinds", "list", "client kinds, e.g. app"),
        ),
        scope="server",
        mutating=False,
    ),
    Op(
        "admin",
        "client-inspect",
        "client.inspect",
        "one client's details and actions",
        (CLIENT,),
        scope="server",
        mutating=False,
    ),
    Op(
        "admin",
        "help-all",
        "help.all",
        "every method the server provides, with schemas (same as api list)",
        scope="server",
        mutating=False,
    ),
    Op(
        "admin",
        "block-creators",
        "block_creator.list",
        "block creators and their flavors",
        scope="server",
        mutating=False,
    ),
    Op(
        "admin",
        "keymap",
        "client.keymap",
        "this connection's key bindings and the actions they can call",
        scope="server",
        mutating=False,
    ),
    Op(
        "admin",
        "server-config-reload",
        "server.config_reload",
        "reload the configuration file; every client refetches its keymap",
        destructive="reloads the Rex configuration file for every client",
        scope="server",
        admin=True,
        local_only=True,
    ),
    Op(
        "admin",
        "server-stop",
        "server.stop",
        "shut the server down (--if-idle: only when unused)",
        (Param("if_idle", "bool", "stop only if no sessions and no other client"),),
        destructive=(
            "STOPS the Rex server: every session and program ends and this host cannot be controlled "
            "until Rex.app restarts it"
        ),
        scope="server",
        admin=True,
        local_only=True,
    ),
    Op(
        "admin",
        "tailscale-enable",
        "server.tailscale.enable",
        "turn on built-in Tailscale",
        (
            Param(
                "allow_tailnet_members",
                "tri",
                "true lets in anyone the tailnet ACLs allow; false only the signing-in user",
                True,
            ),
            Param("hostname", "str", "device name"),
            Param("auth_key_file", "secret_file", "Tailscale auth key", key="auth_key"),
            Param("advertise_tags", "list", "tags such as tag:rex"),
        ),
        destructive="changes who can reach the Rex server over Tailscale",
        scope="server",
        admin=True,
        local_only=True,
    ),
    Op(
        "admin",
        "tailscale-disable",
        "server.tailscale.disable",
        "turn off built-in Tailscale (keeps sign-in)",
        destructive="turns Tailscale off: this box (and every remote client) loses access to this Rex server",
        scope="server",
        admin=True,
        local_only=True,
    ),
    Op(
        "admin",
        "tailscale-login",
        "server.tailscale.login",
        "ask Tailscale for a sign-in link",
        scope="server",
        admin=True,
        local_only=True,
    ),
    Op(
        "admin",
        "tailscale-logout",
        "server.tailscale.logout",
        "sign out of Tailscale and turn it off",
        destructive=(
            "signs the server out of Tailscale and turns it off: remote access is lost until someone signs in again"
        ),
        scope="server",
        admin=True,
        local_only=True,
    ),
    Op(
        "admin",
        "tailscale-rename",
        "server.tailscale.rename",
        "rename the Tailscale device",
        (Param("hostname", "str", "1-63 ASCII letters, digits, hyphens", True),),
        destructive="changes the server's tailnet name, so its URL changes",
        scope="server",
        admin=True,
        local_only=True,
    ),
    Op(
        "admin",
        "hosts-put",
        "hosts.put",
        "add or replace a host in the server's host list",
        (
            Param("id", "str", "host id (server creates one if omitted)", parent="host"),
            Param("label", "str", "name to connect by", True, parent="host"),
            Param("endpoints", "list", "addresses to try, in order", parent="host"),
            Param("icon", "str", "icon name", parent="host"),
            Param("host_id", "str", "host_id reported by its server.status", parent="host"),
        ),
        scope="server",
        admin=True,
    ),
    Op(
        "admin",
        "hosts-remove",
        "hosts.remove",
        "remove a host from the server's host list",
        (Param("id", "str", "host id", True),),
        destructive="removes the saved host entry",
        scope="server",
        admin=True,
    ),
    Op(
        "admin",
        "client-set-label",
        "client.set_label",
        "set this connection's client label (empty removes)",
        (Param("label", "str", "label up to 64 bytes", True),),
        scope="server",
        admin=True,
    ),
    Op(
        "admin",
        "client-perform",
        "client.perform",
        "ask another client (e.g. Rex.app) to perform one of its actions",
        (
            CLIENT,
            Param("action", "str", "action name from client-inspect", True),
            Param("args", "json", "action args as JSON"),
            Param("origin", "str", "origin passed to the client"),
            Param("session", "session", "session the action applies to"),
            Param("block_id", "str", "block id to act on"),
            Param("timeout_ms", "int", "wait up to this long (max 30000)"),
        ),
        destructive="makes another client (the user's Rex app) do something",
        scope="server",
        admin=True,
    ),
    Op(
        "admin",
        "client-action",
        "client.action",
        "perform a config-file or block action as this client",
        (
            Param("action", "str", "action name (client.keymap lists them)", True),
            Param("args", "json", "action args as JSON"),
            Param("origin", "choice", "origin", False, ("api", "key", "palette")),
            Param("session", "session", "session the action applies to"),
            Param("block_id", "str", "block id to act on"),
        ),
        destructive="runs a configuration-file (Lua) or block action with this client's authority",
        scope="server",
        admin=True,
    ),
)

OWN_MODE = Param(
    "mode", "choice", "take: become owner now; request: only blocks without an owner", False, ("take", "request")
)
BLOCKS = Param("blocks", "blocks", "blocks (default: every block of the session)", key="block_ids")
CONN_OPS: tuple[Op, ...] = (
    Op(
        "conn",
        "bootstrap",
        "session.bootstrap",
        "first-call setup: receive events, list sessions, attach",
        (
            Param("event_scope", "choice", "events to receive", False, ("session", "all"), default="session"),
            Param("preferred_session_id", "str", "session to attach if it exists"),
            Param("attach_session_ids", "list", "session ids to attach, in order (none: empty value)"),
        ),
        scope="server",
        mutating=False,
    ),
    Op(
        "conn",
        "attach",
        "session.attach",
        "attach this connection to a session; returns client_id and the view",
        mutating=False,
    ),
    Op(
        "conn",
        "detach",
        "session.detach",
        "detach this connection from a session (a no-op for one-shot commands)",
        mutating=False,
    ),
    Op(
        "conn",
        "list-blocks",
        "session.list_blocks",
        "every block in the session, detached ones included",
        mutating=False,
    ),
    Op(
        "conn",
        "list-clients",
        "session.list_clients",
        "clients attached to the session (Rex apps, agents)",
        mutating=False,
    ),
    Op("conn", "session-help", "session.help", "methods this session and its block creators provide", mutating=False),
    Op(
        "conn",
        "describe-block",
        "session.describe_block",
        "block details plus the methods, events and actions it provides",
        (block_param(required=False),),
        mutating=False,
        block_default=True,
    ),
    Op(
        "conn",
        "own-block",
        "session.own_block",
        "claim blocks for this connection; terminal size then follows it",
        (BLOCKS, OWN_MODE),
        attach=True,
        destructive="makes this client the block owner; its terminal size wins until the connection ends",
    ),
    Op(
        "conn",
        "disown-block",
        "session.disown_block",
        "give up this connection's claim on blocks",
        (BLOCKS,),
        attach=True,
    ),
    Op(
        "conn",
        "detach-block",
        "session.detach_block",
        "take a block out of its window; it keeps running",
        (block_param(),),
        destructive="the block leaves its window (the window or layer closes if it was the last block)",
    ),
)
TARGET_OPS: tuple[Op, ...] = (
    Op(
        "target",
        "resolve",
        "target.resolve",
        "server-side lookup of names, labels, positions and short ids",
        (
            Param(
                "kinds",
                "list",
                "session,window,block or client (default: session,window,block)",
                default="session,window,block",
            ),
            Param("queries", "list", "names to look up, comma separated", True),
            Param("scope_session", "str", "limit to this session", key="session", parent="scope"),
            Param("scope_window", "str", "limit a block search to this window", key="window", parent="scope"),
            Param(
                "context_session", "str", "caller session for empty/default queries", key="session_id", parent="context"
            ),
        ),
        scope="server",
        mutating=False,
    ),
    Op(
        "target",
        "complete",
        "target.complete",
        "names, positions and short ids starting with a prefix",
        (
            Param(
                "kinds",
                "list",
                "session,window,block or client (default: session,window,block)",
                default="session,window,block",
            ),
            Param("prefix", "str", "text typed so far", True),
            Param("scope_session", "str", "limit to this session", key="session", parent="scope"),
            Param("scope_window", "str", "limit a block search to this window", key="window", parent="scope"),
            Param("context_session", "str", "caller session", key="session_id", parent="context"),
        ),
        scope="server",
        mutating=False,
    ),
)

GROUP_HELP = {
    "conn": "attach, ownership and block description (connection-scoped; mostly useful via daemon/mcp)",
    "target": "server-side name resolution and completion",
    "admin": "server administration: status, tailscale, hosts, clients (mutating verbs need two flags)",
    "term": "terminal block methods: clipboard, list-dir, modes, resize, reset, clear, theme",
    "layout": "windows, blocks, layers, focus and labels (guarded)",
    "input": "user-like input events: keys, paste, mouse (guarded)",
    "onboarding": "methods of the onboarding walkthrough block (com.superlogical.onboarding)",
}
OPS: tuple[Op, ...] = LAYOUT_OPS + INPUT_OPS + TERM_OPS + ONBOARDING_OPS + ADMIN_OPS + CONN_OPS + TARGET_OPS


def groups() -> dict[str, list[Op]]:
    grouped: dict[str, list[Op]] = {}
    for op in OPS:
        grouped.setdefault(op.group, []).append(op)
    return grouped


def register(sub: Any) -> None:
    for group, ops in groups().items():
        group_parser = sub.add_parser(group, help=GROUP_HELP.get(group, group))
        verbs = group_parser.add_subparsers(dest="op", required=True)
        for op in ops:
            verb = verbs.add_parser(op.name, help=op.help + (" (guarded)" if op.mutating else ""))
            add_op_args(verb, op)
            verb.set_defaults(op_spec=op)
