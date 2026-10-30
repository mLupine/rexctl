from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import __version__, connection, daemon, mcp, ops
from .connection import Connection, RpcConnection
from .context import Connector, Context
from .errors import (
    EXIT_DRY_RUN,
    EXIT_ERROR,
    EXIT_OK,
    AccessDeniedError,
    ApiError,
    RexError,
    TargetNotFoundError,
    UnreachableError,
    UsageError,
)
from .events import (
    EventFilter,
    canonical_event_names,
    event_line,
    normalize_event,
    parse_where,
    reconnect_marker,
    redact_event,
    resilient_event,
)
from .flags import (
    TARGET_HELP,
    Parser,
    add_admin_arg,
    add_guard_arg,
    add_target_args,
    apply_target_spec,
    seconds,
)
from .hosts import load_hosts, require_https, resolve_host
from .inputs import build_input, parse_payload, read_text_file, shell_layout
from .output import emit, emit_text, eprint, guard
from .protocol import TERMINAL
from .read import block_about, list_sessions, read_tail, screen_result
from .stream import TerminalFeed, open_feed, try_open_feed
from .target import Target, resolve_block, resolve_session, resolve_target
from .waits import (
    regex_where,
    wait_for_close,
    wait_for_close_events,
    wait_for_idle,
    wait_for_named_event,
    wait_for_status,
    wait_for_status_events,
    wait_for_text,
)


def cmd_hosts(args: argparse.Namespace, hosts: dict[str, str]) -> int:
    rows = []
    for label, url in sorted(hosts.items()):
        row: dict[str, Any] = {"host": label, "url": url}
        if args.check:
            row.update(probe_host(url))
        rows.append(row)
    emit({"ok": True, "hosts": rows})
    return EXIT_OK


def probe_host(url: str) -> dict[str, Any]:
    try:
        with connection.connect(url, timeout=8) as conn:
            version = conn.call("server.version")
            who = conn.call("server.whoami")
        return {
            "reachable": True,
            "allowed": True,
            "rex_version": version.get("rex_version"),
            "platform": version.get("platform"),
            "principal": who.get("principal", {}).get("display"),
        }
    except AccessDeniedError as exc:
        return {"reachable": True, "allowed": False, "error": exc.message}
    except RexError as exc:
        return {"reachable": False, "error": exc.message}


def cmd_version(args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    with ctx.rpc(url, args.timeout) as conn:
        version = conn.call("server.version")
        who = conn.call("server.whoami")
        emit(
            {
                "ok": True,
                "host": host,
                "url": url,
                "server": version,
                "whoami": who,
                "negotiated_api_revision": conn.welcome.get("api_revision"),
                "client": {"name": "rexctl", "version": __version__},
            }
        )
    return EXIT_OK


def cmd_ls(args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    with ctx.rpc(url, args.timeout) as conn:
        emit({"ok": True, "host": host, "sessions": list_sessions(conn, args.session, not args.brief)})
    return EXIT_OK


def cmd_api(args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    if args.api_action == "list":
        return api_list(args, host, url)
    if args.api_action == "describe":
        return api_describe(args, host, url)
    return api_call(args, host, url, ctx)


def fetch_help(url: str, timeout: float) -> dict[str, Any]:
    import urllib.error
    import urllib.request

    request = urllib.request.Request(f"{require_https(url)}/api/help")
    direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # same route as the WebSocket connections
    try:
        with direct.open(request, timeout=timeout) as response:
            help_doc: dict[str, Any] = json.load(response)
            return help_doc
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise AccessDeniedError(
                f"server refused this principal (HTTP {exc.code}): {exc.read().decode('utf-8', 'replace')[:300]}",
                status=exc.code,
            ) from exc
        raise ApiError(f"GET /api/help failed with HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise UnreachableError(f"cannot reach {url}: {exc}") from exc


def all_methods(doc: dict[str, Any]) -> list[dict[str, Any]]:
    methods = list(doc.get("methods") or [])
    for block_type in doc.get("block_types") or []:
        for m in block_type.get("methods") or []:
            methods.append(
                {
                    **m,
                    "input_schema": m.get("args_schema"),
                    "block_method": True,
                    "name": m.get("invoke", {}).get("method", m.get("name")),
                }
            )
    return methods


def api_list(args: argparse.Namespace, host: str, url: str) -> int:
    methods = all_methods(fetch_help(url, args.timeout))
    emit(
        {
            "ok": True,
            "host": host,
            "methods": [
                {
                    "name": m["name"],
                    "description": m.get("description", ""),
                    "block_method": bool(m.get("block_method")),
                }
                for m in methods
            ],
        }
    )
    return EXIT_OK


def api_describe(args: argparse.Namespace, host: str, url: str) -> int:
    for m in all_methods(fetch_help(url, args.timeout)):
        if m["name"] == args.method:
            emit({"ok": True, "host": host, "method": m})
            return EXIT_OK
    raise TargetNotFoundError(f"no such API method {args.method!r}")


READ_ONLY_METHODS = {
    "server.version",
    "server.whoami",
    "server.status",
    "session.list",
    "session.view",
    "session.list_blocks",
    "session.list_clients",
    "session.describe_block",
    "session.help",
    "help.all",
    "hosts.list",
    "client.list",
    "client.inspect",
    "block_creator.list",
    "target.resolve",
    "target.complete",
    "client.keymap",
    "session.attach_all",
    "session.attach",
    "session.detach",
    f"{TERMINAL}.format",
    f"{TERMINAL}.pwd",
    f"{TERMINAL}.title",
    f"{TERMINAL}.process",
    f"{TERMINAL}.program_status",
    f"{TERMINAL}.size",
    f"{TERMINAL}.modes",
    f"{TERMINAL}.input_mode",
    f"{TERMINAL}.list_dir",
    "com.superlogical.onboarding.state",
}


def api_call(args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    payload = parse_payload(args.payload)
    target = {"host": host, "session_id": payload.get("session_id"), "block_id": payload.get("block_id")}
    if args.method not in READ_ONLY_METHODS and not api_call_authorised(args, target, payload):
        return EXIT_DRY_RUN
    with ctx.rpc(url, args.timeout) as conn:
        conn.call("session.attach_all", {"event_scope": "session"})
        result = conn.call(args.method, payload)
    emit({"ok": True, "host": host, "method": args.method, "result": result})
    return EXIT_OK


# Methods that rexctl's own commands send, beyond the op table. Anything else through `api call` is treated as admin.
COMMAND_METHODS = {
    "session.create", "session.new_split", "session.destroy", "block.close", "session.attach", "session.detach",
    f"{TERMINAL}.write",
}  # fmt: skip


def api_call_authorised(args: argparse.Namespace, target: dict[str, Any], payload: dict[str, Any]) -> bool:
    admin = next((op for op in ops.OPS if op.method == args.method and op.admin), None)
    if admin:
        return ops.authorise(args, admin, target, payload)
    known = args.method in COMMAND_METHODS or any(op.method == args.method for op in ops.OPS)
    detail = {"method": args.method, "payload": payload}
    return guard(args, f"api call {args.method}", target, detail, admin=not known)


def target_for(args: argparse.Namespace, conn: RpcConnection, host: str, url: str, need_block: bool = True) -> Target:
    return resolve_target(
        conn, host, url, args.session, getattr(args, "block", None), need_block, getattr(args, "target_window", None)
    )


def cmd_screen(args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    with ctx.rpc(url, args.timeout) as conn:
        t = target_for(args, conn, host, url)
        result = screen_result(conn, t, args.lines, args.unwrap)
    if args.text:
        emit_text(result)
    else:
        emit(result)
    return EXIT_OK


def cmd_tail(args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    with ctx.rpc(url, args.timeout) as conn:
        t = target_for(args, conn, host, url)
        result = read_tail(conn, t, args.lines, unwrap=args.unwrap)
    if args.text:
        emit_text(result)
    else:
        emit({"ok": True, "target": t.describe(), **{k: v for k, v in result.items() if k != "blob_id"}})
    return EXIT_OK


def cmd_fact(args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    method = {"pwd": "pwd", "title": "title", "process": "process", "status": "program_status"}[args.command]
    with ctx.rpc(url, args.timeout) as conn:
        t = target_for(args, conn, host, url)
        result = conn.block_call(f"{TERMINAL}.{method}", t.session_id, t.block_id or "", {})
    emit({"ok": True, "target": t.describe(), "result": result})
    return EXIT_OK


def build_event_filter(conn: Connection, args: argparse.Namespace) -> EventFilter:
    names = canonical_event_names((args.filter or []) + (args.type or []))
    flt = EventFilter(names=names, where=parse_where(args.where))
    if args.session or args.block:
        flt.session_id = resolve_session(conn, args.session)
        if args.block:
            flt.block_id = resolve_block(conn, flt.session_id, args.block, getattr(args, "target_window", None))
    return flt


def cmd_events(args: argparse.Namespace, host: str, url: str, _ctx: Context) -> int:
    count = 0
    with connection.connect(url, args.timeout) as conn:
        conn.call("session.attach_all", {"event_scope": "session"})
        flt = build_event_filter(conn, args)
        scope = "all" if args.scope == "all" or flt.needs_block_events else "session"
        conn.call("session.attach_all", {"event_scope": scope})
        deadline = time.monotonic() + args.duration
        while time.monotonic() < deadline:
            got = resilient_event(conn, min(1.0, max(0.05, deadline - time.monotonic())), not args.no_reconnect)
            if got is None:
                continue
            if got[0] == "reconnected":
                emit(reconnect_marker(host, got[1]))
                continue
            normal = normalize_event(got[1])
            if not args.show_clipboard:
                normal = redact_event(normal)  # before filtering, so --where cannot probe hidden text
            if not flt.accepts(normal):
                continue
            emit(event_line(host, normal))
            count += 1
            if args.max_events and count >= args.max_events:
                break
    eprint(f"rexctl: {count} events")
    return EXIT_OK


def cmd_wait_for(args: argparse.Namespace, host: str, url: str, _ctx: Context) -> int:
    with connection.connect(url, args.timeout) as conn:
        t = target_for(args, conn, host, url)
        feed = open_wait_feed(args, conn, url, t)
        try:
            result = run_wait(args, conn, t, feed)
        finally:
            if feed:
                feed.close(t.session_id)
    emit({"ok": True, "target": t.describe(), **result})
    return EXIT_OK


def open_wait_feed(args: argparse.Namespace, conn: Connection, url: str, t: Target) -> TerminalFeed | None:
    wants_stream = (args.text or args.idle is not None) and not args.no_stream
    return try_open_feed(conn, url, t, args.timeout) if wants_stream else None


EVENT_WAITS: dict[str, tuple[str, str | None]] = {
    "bell": ("bell", None),
    "title_changed": ("title_changed", "title"),
    "cwd_changed": ("pwd_changed", "pwd"),
    "child_exited": ("child_exited", None),
}


def run_wait(args: argparse.Namespace, conn: Connection, t: Target, feed: TerminalFeed | None) -> dict[str, Any]:
    if args.text:
        return wait_for_text(conn, t, args.text, args.wait_timeout, args.interval, feed, args.new)
    if args.idle is not None:
        return wait_for_idle(conn, t, args.idle, args.wait_timeout, args.interval, feed)
    if args.status:
        states = set(args.status.split(","))
        if args.no_stream:
            return wait_for_status(conn, t, states, args.wait_timeout, args.interval)
        return wait_for_status_events(conn, t, states, args.wait_timeout)
    if args.closed:
        if args.no_stream:
            return wait_for_close(conn, t, args.wait_timeout, args.interval)
        return wait_for_close_events(conn, t, args.wait_timeout)
    return run_event_wait(args, conn, t)


def event_wait_filter(args: argparse.Namespace) -> tuple[EventFilter, str]:
    if args.event:
        return EventFilter(
            names=canonical_event_names([args.event]), where=parse_where(args.where)
        ), f"event {args.event}"
    for flag, (name, path) in EVENT_WAITS.items():
        value = getattr(args, flag)
        if value:
            pattern = None if value is True else value
            return EventFilter(names={name}, where=regex_where(path, pattern) if path else []), f"event {name}"
    raise UsageError("no wait condition given")


def run_event_wait(args: argparse.Namespace, conn: Connection, t: Target) -> dict[str, Any]:
    if args.no_stream:
        raise UsageError("--no-stream cannot be combined with event conditions (bell, title-changed, ...)")
    flt, what = event_wait_filter(args)
    return wait_for_named_event(conn, t, flt, args.wait_timeout, what)


def cmd_stream(args: argparse.Namespace, host: str, url: str, _ctx: Context) -> int:
    with connection.connect(url, args.timeout) as conn:
        t = target_for(args, conn, host, url)
        screen = screen_result(conn, t, None, False) if args.with_screen else None
        feed = open_feed(conn, url, t, args.timeout)
        try:
            summary = run_stream(args, feed, t, screen)
        finally:
            feed.close(t.session_id)
    if not args.text:
        emit({"ok": True, "event": "end", **summary})
    return EXIT_OK


def stream_line(args: argparse.Namespace, item: dict[str, Any], started: float, index: int) -> dict[str, Any] | None:
    stamp = round(time.monotonic() - started, 3)
    if item["kind"] == "output":
        line = {"event": "data", "seq": index, "t": stamp, "text": item["text"], "bytes": len(item["raw"])}
        if args.raw:
            line["raw_b64"] = base64.b64encode(item["raw"]).decode()
        return line
    if item["kind"] == "message":
        return {"event": "rex", "t": stamp, "message": item["message"]}
    if item["kind"] == "gap":
        return {"event": "gap", "t": stamp, "reason": item["reason"], "note": item["note"]}
    return None


def run_stream(
    args: argparse.Namespace, feed: TerminalFeed, t: Target, screen: dict[str, Any] | None
) -> dict[str, Any]:
    started = time.monotonic()
    deadline = started + args.duration
    index = 0
    reason = "duration"
    if screen and not args.text:
        emit({"ok": True, "event": "screen", "target": t.describe(), "content": screen["content"]})
    elif screen:
        emit_text(screen)
    while time.monotonic() < deadline and not feed.ended:
        for item in feed.poll(min(0.5, deadline - time.monotonic())):
            index += 1 if item["kind"] == "output" else 0
            emit_stream_item(args, item, started, index)
        if args.max_bytes and feed.output_bytes >= args.max_bytes:
            reason = "max_bytes"
            break
    if feed.ended:
        reason = feed.ended.get("reason", "ended")
    return {
        "target": t.describe(),
        "reason": reason,
        "output_bytes": feed.output_bytes,
        "snapshot_bytes_skipped": feed.decoder.snapshot_bytes,
    }


def emit_stream_item(args: argparse.Namespace, item: dict[str, Any], started: float, index: int) -> None:
    if args.text:
        if item["kind"] == "output":
            sys.stdout.write(item["text"])
            sys.stdout.flush()
        return
    line = stream_line(args, item, started, index)
    if line:
        emit(line)


def send_detail(data: str, hidden: bool) -> dict[str, Any]:
    if hidden:
        return {"input": {"hidden": True, "bytes": len(data.encode())}}  # no hash: it could be brute-forced
    return {"data_json": json.dumps(data), "bytes": len(data.encode())}


def cmd_send(args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    if args.text is not None and args.secret_file:
        raise UsageError("give --text or --secret-file, not both")
    text = read_text_file(args.secret_file) if args.secret_file else args.text
    data = build_input(text, args.enter, args.keys)
    with ctx.rpc(url, args.timeout) as conn:
        t = target_for(args, conn, host, url)
        detail = send_detail(data, bool(args.secret_file))
        if not guard(args, "send input to terminal", t.describe(), detail, about=lambda: block_about(conn, t)):
            return EXIT_DRY_RUN
        result = conn.block_call(f"{TERMINAL}.write", t.session_id, t.block_id or "", {"data": data})
    emit({"ok": True, "target": t.describe(), "result": result})
    return EXIT_OK


def cmd_new_session(args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    payload = {"label": args.label, "initial_windows": [{"layout": shell_layout(None, args.cwd)}]}
    if not guard(args, "create new session", {"host": host, "url": url}, {"payload": payload}):
        return EXIT_DRY_RUN
    with ctx.rpc(url, args.timeout) as conn:
        result = conn.call("session.create", payload)
    emit({"ok": True, "host": host, "result": result})
    return EXIT_OK


def cmd_split(args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    with ctx.rpc(url, args.timeout) as conn:
        t = target_for(args, conn, host, url)
        payload = {
            "session_id": t.session_id,
            "anchor_id": t.block_id,
            "direction": args.direction,
            "side": "after",
            "layout": shell_layout(args.label, args.cwd),
            "focus": False,
        }
        about = lambda: block_about(conn, t)  # noqa: E731
        if not guard(args, "split block (creates a new shell)", t.describe(), {"payload": payload}, about=about):
            return EXIT_DRY_RUN
        result = conn.call("session.new_split", payload)
    emit({"ok": True, "target": t.describe(), "result": result})
    return EXIT_OK


def cmd_kill(args: argparse.Namespace, host: str, url: str, ctx: Context) -> int:
    with ctx.rpc(url, args.timeout) as conn:
        t = target_for(args, conn, host, url, need_block=not args.whole_session)
        method, payload = (
            ("session.destroy", {"session_id": t.session_id})
            if args.whole_session
            else ("block.close", {"session_id": t.session_id, "block_id": t.block_id})
        )
        detail = {"method": method, "payload": payload}
        if not guard(args, f"kill ({method})", t.describe(), detail, about=lambda: block_about(conn, t)):
            return EXIT_DRY_RUN
        result = conn.call(method, payload)
    emit({"ok": True, "target": t.describe(), "result": result})
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = Parser(prog="rexctl", description="Agent-oriented Rex client. JSON on stdout, diagnostics on stderr.")
    p.add_argument(
        "--host",
        "-H",
        default=os.environ.get("REXCTL_HOST"),
        help="host label from the hosts file, or an https:// Rex URL (default: $REXCTL_HOST)",
    )
    p.add_argument(
        "--hosts-file",
        type=Path,
        help="label-to-URL JSON file (default: $REXCTL_HOSTS, else $XDG_CONFIG_HOME/rexctl/hosts.json)",
    )
    p.add_argument("--no-daemon", action="store_true", help="do not use the persistent daemon even if it runs")
    p.add_argument("--timeout", type=seconds, default=10.0, help="per-request timeout in seconds")
    sub = p.add_subparsers(dest="command", required=True)

    hosts = sub.add_parser("hosts", help="list configured hosts")
    hosts.add_argument("--check", action="store_true", help="connect to each host and report access")
    sub.add_parser("version", help="server version, whoami and negotiated API revision")

    ls = sub.add_parser("ls", help="sessions, windows and blocks (with title, pwd, foreground, status)")
    ls.add_argument("-s", "--session")
    ls.add_argument("--brief", action="store_true", help="skip per-terminal title/pwd/status calls")

    api = sub.add_parser("api", help="list, describe or call raw API methods")
    api_sub = api.add_subparsers(dest="api_action", required=True)
    api_sub.add_parser("list")
    describe = api_sub.add_parser("describe")
    describe.add_argument("method")
    call = api_sub.add_parser("call")
    call.add_argument("method")
    call.add_argument("payload", nargs="?", help="JSON object, or @file")
    add_guard_arg(call)
    add_admin_arg(call)

    screen = sub.add_parser("screen", help="read the terminal screen as trimmed text")
    add_target_args(screen)
    screen.add_argument(
        "--lines", type=int, default=None, help="last N lines (default: the terminal's visible row count)"
    )
    screen.add_argument("--unwrap", action="store_true")
    screen.add_argument("--text", action="store_true", help="print plain text instead of JSON")

    tail = sub.add_parser("tail", help="bounded scrollback read: last N lines")
    add_target_args(tail)
    tail.add_argument("--lines", type=int, default=200)
    tail.add_argument("--unwrap", action="store_true")
    tail.add_argument("--text", action="store_true")

    for name, text in (
        ("pwd", "reported working directory"),
        ("title", "terminal title"),
        ("process", "foreground process info"),
        ("status", "program status protocol records"),
    ):
        add_target_args(sub.add_parser(name, help=text))

    events = sub.add_parser("events", help="stream server events as JSON lines")
    events.add_argument("--duration", type=seconds, default=10.0, help="seconds to listen")
    events.add_argument("--max-events", type=int, default=0)
    events.add_argument("--scope", choices=("session", "all"), default="session")
    events.add_argument("--type", action="append", help="alias of --filter")
    events.add_argument(
        "--filter",
        action="append",
        metavar="NAME[,NAME]",
        help="only these event names, e.g. bell,title_changed,program_status_changed,block_closed "
        "(aliases: cwd, title, status, exit, closed); block events switch the scope to all",
    )
    events.add_argument(
        "--where",
        action="append",
        metavar="PATH=VALUE|PATH~REGEX",
        help="payload field condition (repeatable), e.g. record.state=blocked",
    )
    events.add_argument("-s", "--session", help="only events of this session")
    events.add_argument("-b", "--block", help="only events of this block (needs -s unless one session exists)")
    events.add_argument("-t", "--target", help=TARGET_HELP)
    events.add_argument("--no-reconnect", action="store_true", help="do not resume after a dropped connection")
    events.add_argument(
        "--show-clipboard",
        action="store_true",
        help="print clipboard_written/selection_copied text (redacted by default)",
    )

    wait = sub.add_parser("wait-for", help="wait for text, screen idle, program status or block close")
    add_target_args(wait)
    kind = wait.add_mutually_exclusive_group(required=True)
    kind.add_argument("--text", help="regex that must appear on screen/scrollback tail")
    kind.add_argument("--idle", type=seconds, help="seconds the screen must stay unchanged")
    kind.add_argument("--status", help="comma-separated program status states, e.g. done,blocked,idle")
    kind.add_argument("--closed", action="store_true", help="block no longer exists (block_closed event)")
    kind.add_argument("--bell", action="store_true", help="the terminal rings the bell")
    kind.add_argument(
        "--title-changed",
        nargs="?",
        const=True,
        metavar="REGEX",
        help="the terminal title changes (optionally to a title matching REGEX)",
    )
    kind.add_argument(
        "--cwd-changed",
        nargs="?",
        const=True,
        metavar="REGEX",
        help="the reported working directory changes (optionally matching REGEX)",
    )
    kind.add_argument("--child-exited", action="store_true", help="the terminal's program exits")
    kind.add_argument("--event", metavar="NAME", help="any server/block event name; combine with --where")
    wait.add_argument(
        "--where",
        action="append",
        metavar="PATH=VALUE|PATH~REGEX",
        help="with --event: payload field condition (repeatable), e.g. record.state=blocked",
    )
    wait.add_argument("--wait-timeout", type=seconds, default=60.0)
    wait.add_argument("--interval", type=seconds, default=0.5)
    wait.add_argument("--no-stream", action="store_true", help="poll the screen instead of using the data stream")
    wait.add_argument(
        "--new",
        action="store_true",
        help="with --text: match only output that arrives after the wait starts, not what is on screen",
    )

    stream = sub.add_parser(
        "stream", help="read-only live output stream of a terminal block (joins the session as a client)"
    )
    add_target_args(stream)
    stream.add_argument("--duration", type=seconds, default=10.0, help="seconds to listen")
    stream.add_argument("--max-bytes", type=int, default=0, help="stop after this many output bytes (0 = no limit)")
    stream.add_argument("--text", action="store_true", help="plain text on stdout instead of JSON lines")
    stream.add_argument("--raw", action="store_true", help="add the raw bytes as base64 (raw_b64) to each data line")
    stream.add_argument("--with-screen", action="store_true", help="print the current screen first")

    send = sub.add_parser("send", help="type into a terminal (guarded)")
    add_target_args(send)
    send.add_argument("--text", help="literal text to type")
    send.add_argument(
        "--secret-file",
        metavar="FILE",
        help="type the contents of FILE (e.g. a password); the plan shows only its length and hash",
    )
    send.add_argument("--enter", action="store_true", help="press Enter after the text")
    send.add_argument(
        "--keys",
        help=(
            "comma/space-separated key names: Enter Esc Tab Up PageDown F1..F12 C-c ctrl+d M-x S-Tab "
            "ctrl+shift+Up Space or a character"
        ),
    )
    add_guard_arg(send)

    new = sub.add_parser("new-session", help="create a session with one shell (guarded)")
    new.add_argument("--label", help="session label")
    new.add_argument("--cwd")
    add_guard_arg(new)

    split = sub.add_parser("split", help="split a block with a new shell (guarded)")
    add_target_args(split)
    split.add_argument("--direction", choices=("horizontal", "vertical"), default="horizontal")
    split.add_argument("--label")
    split.add_argument("--cwd")
    add_guard_arg(split)

    kill = sub.add_parser("kill", help="close a block, or a whole session (guarded)")
    add_target_args(kill)
    kill.add_argument("--whole-session", action="store_true", help="destroy the session, not just the block")
    add_guard_arg(kill)
    ops.register(sub)
    daemon.register(sub)
    mcp.register(sub)
    return p


COMMANDS: dict[str, Callable[[argparse.Namespace, str, str, Context], int]] = {
    "version": cmd_version,
    "ls": cmd_ls,
    "api": cmd_api,
    "screen": cmd_screen,
    "tail": cmd_tail,
    "pwd": cmd_fact,
    "title": cmd_fact,
    "process": cmd_fact,
    "status": cmd_fact,
    "events": cmd_events,
    "wait-for": cmd_wait_for,
    "stream": cmd_stream,
    "send": cmd_send,
    "new-session": cmd_new_session,
    "split": cmd_split,
    "kill": cmd_kill,
}


def dispatch(args: argparse.Namespace, ctx: Context) -> int:
    hosts = load_hosts(args.hosts_file)
    if args.command == "hosts":
        return cmd_hosts(args, hosts)
    if args.command == "mcp":
        return mcp.cmd_mcp(args, main)
    if args.command == "daemon":
        return daemon.cmd_daemon(args)
    if not args.host:
        raise UsageError("--host is required", known=sorted(hosts))
    host, url = resolve_host(args.host, hosts)
    apply_target_spec(args)
    if hasattr(args, "op_spec"):
        return ops.run_op(args, host, url, ctx)
    return COMMANDS[args.command](args, host, url, ctx)


def main(argv: list[str] | None = None, connector: Connector | None = None) -> int:
    args = build_parser().parse_args(argv)
    ctx = Context(connector or daemon.connect_rpc, use_daemon=not args.no_daemon)
    try:
        return dispatch(args, ctx)
    except RexError as exc:
        emit(exc.to_dict())
        return exc.exit_code
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return EXIT_OK
    except Exception as exc:
        eprint(traceback.format_exc().rstrip())
        emit({"ok": False, "error": {"kind": "internal", "message": f"{type(exc).__name__}: {exc}"}})
        return EXIT_ERROR
