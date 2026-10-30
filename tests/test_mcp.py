import io
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from rexctl import cli, connection
from rexctl.errors import EXIT_USAGE
from rexctl.events import EventFilter
from rexctl.mcp import (
    EVENT_BUFFER,
    MAX_TEXT,
    MAX_WAIT,
    SUPPORTED_PROTOCOLS,
    EventCollector,
    ToolError,
    build_wait,
    handle_message,
    render,
    serve,
)
from test_cli import FakeConn, writes

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def fake(monkeypatch):
    conn = FakeConn()
    monkeypatch.setattr(connection, "connect", lambda url, timeout=10.0: conn)
    return conn


def rpc(method, params=None, id=1):
    message = {"jsonrpc": "2.0", "id": id, "method": method, **({"params": params} if params is not None else {})}
    return handle_message(message, cli.main)


def call(name, arguments):
    reply = rpc("tools/call", {"name": name, "arguments": arguments})
    result = reply["result"]
    return json.loads(result["content"][0]["text"]), result["isError"]


def test_initialize_negotiates_protocol_version():
    assert rpc("initialize", {"protocolVersion": "2024-11-05"})["result"]["protocolVersion"] == "2024-11-05"
    reply = rpc("initialize", {"protocolVersion": "1999-01-01"})["result"]
    assert reply["protocolVersion"] == SUPPORTED_PROTOCOLS[0] and reply["capabilities"] == {
        "tools": {"listChanged": False}
    }
    assert "confirm" in reply["instructions"]


def test_notifications_get_no_reply_and_unknown_methods_error():
    assert handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"}, cli.main) is None
    assert rpc("nope")["error"]["code"] == -32601
    assert rpc("ping")["result"] == {}


def test_tool_list_shapes():
    tools = rpc("tools/list")["result"]["tools"]
    names = {t["name"] for t in tools}
    assert {
        "rex_hosts",
        "rex_ls",
        "rex_screen",
        "rex_tail",
        "rex_status",
        "rex_wait_for",
        "rex_events_since",
        "rex_send",
        "rex_new_session",
        "rex_split",
        "rex_kill",
        "rex_op",
        "rex_op_catalog",
        "rex_server_info",
    } <= names
    for tool in tools:
        assert tool["inputSchema"]["type"] == "object" and tool["description"]
        writing = tool["annotations"]["destructiveHint"]
        assert ("confirm" in tool["inputSchema"]["properties"]) == writing
    assert not [n for n in names if "admin" in n or "stop" in n or "tailscale" in n]


def approve(name, arguments):
    plan, is_error = call(name, arguments)
    assert not is_error and plan["dry_run"] is True
    return call(name, {**arguments, "confirm": plan["plan_id"]})


def test_write_tools_without_confirm_are_dry_runs(fake):
    for flag in (
        {},
        {"confirm": False},
        {"confirm": True},
        {"confirm": "true"},
        {"confirm": 1},
        {"confirm": "0123456789ab"},
    ):
        body, is_error = call("rex_send", {"host": "alpha", "text": "rm -rf /", "enter": True, **flag})
        assert not is_error and body["dry_run"] is True and "plan_id" in body["mcp_note"] and body["plan_id"]
    assert writes(fake) == []


def test_confirm_with_the_plan_id_executes(fake):
    body, is_error = approve("rex_send", {"host": "alpha", "text": "ls", "enter": True})
    assert not is_error and body["ok"] is True and writes(fake)


def test_confirm_refuses_when_the_target_changed_after_approval(fake):
    arguments = {"host": "alpha", "text": "ls", "enter": True}
    plan, _ = call("rex_send", arguments)
    fake.view = json.loads(json.dumps(fake.view).replace("15d8-718a", "15d8-9999"))
    body, is_error = call("rex_send", {**arguments, "confirm": plan["plan_id"]})
    assert not is_error and body["dry_run"] is True and body["plan_id"] != plan["plan_id"] and "changed" in body["note"]
    assert writes(fake) == []


def test_read_tools_run_immediately(fake):
    body, is_error = call("rex_screen", {"host": "alpha", "lines": 1})
    assert not is_error and body["ok"] is True
    body, _ = call("rex_ls", {"host": "alpha", "brief": True})
    assert body["ok"] and body["sessions"]


def test_errors_are_tool_errors_not_protocol_errors(fake):
    body, is_error = call("rex_screen", {"host": "alpha", "target": "nosuch"})
    assert is_error and body["error"]["kind"] == "target_not_found"
    body, is_error = call("rex_send", {"host": "alpha"})
    assert is_error and "text and/or keys" in body["error"]
    assert rpc("tools/call", {"name": "nope", "arguments": {}})["error"]["code"] == -32602
    assert rpc("tools/call", {"name": "rex_ls", "arguments": []})["error"]["code"] == -32602


def test_usage_errors_inside_cli_do_not_exit_the_server(fake):
    body, is_error = call("rex_op", {"host": "alpha", "group": "layout", "verb": "new-window", "args": ["--cwd"]})
    assert is_error and body["exit_code"] == EXIT_USAGE


def test_rex_op_confirm_only_for_mutating_ops(fake):
    body, is_error = call("rex_op", {"host": "alpha", "group": "term", "verb": "size", "args": [], "confirm": "x"})
    assert not is_error and body["ok"] is True and "dry_run" not in body
    body, _ = approve(
        "rex_op", {"host": "alpha", "group": "layout", "verb": "set-session-label", "args": ["--label", "x"]}
    )
    assert body["ok"] is True and "dry_run" not in body
    assert [c for c in fake.calls if c[0] == "session.set_label"] or any("label" in c[0] for c in fake.calls)


@pytest.mark.parametrize(
    "args",
    [
        ["--yes-i-am-authorised"],
        ["--yes"],
        ["--yes-i"],
        ["--allow-server-admin"],
        ["--allow"],
        ["--show"],
        ["--sh"],
        ["--show-clipboard"],
        ["--auth-key-file=/x"],
        ["--hosts-file", "/x"],
        ["--", "--yes-i-am-authorised"],
    ],
)
def test_rex_op_rejects_authorising_and_secret_flags(fake, args):
    body, is_error = call("rex_op", {"host": "alpha", "group": "layout", "verb": "new-window", "args": args})
    assert is_error and "not allowed" in body["error"]
    assert writes(fake) == [] and not [c for c in fake.calls if c[0] == "session.new_window"]


@pytest.mark.parametrize(
    "group,verb,args",
    [
        ("layout", "new-window", ["--layout-json=@{f}"]),
        ("layout", "new-window", ["--layout-json", "@{f}"]),
        ("layout", "new-window", ["--layout-json= @{f}"]),
        ("input", "mouse", ["--payload", "@{f}"]),
        ("input", "event", ["--event-type=mouse", "--payload=@{f}"]),
    ],
)
def test_rex_op_cannot_read_a_local_file(fake, tmp_path, group, verb, args):
    secret = tmp_path / "secret.json"
    secret.write_text('{"block": {"flavor": "top-secret-value"}}')
    args = [a.format(f=secret) for a in args]
    body, is_error = call("rex_op", {"host": "alpha", "group": group, "verb": verb, "args": args})
    assert is_error and "top-secret-value" not in json.dumps(body)


def test_rex_op_accepts_inline_layout_json(fake):
    layout = '{"block": {"flavor": "shell"}}'
    args = [f"--layout-json={layout}"]
    body, is_error = call("rex_op", {"host": "alpha", "group": "layout", "verb": "new-window", "args": args})
    assert not is_error and body["dry_run"] is True and body["payload"]["layout"] == {"block": {"flavor": "shell"}}


def test_clipboard_read_cannot_be_unredacted_by_an_abbreviated_flag(fake):
    body, is_error = call("rex_op", {"host": "alpha", "group": "term", "verb": "clipboard-read", "args": ["--sh"]})
    assert is_error and "not allowed" in body["error"]


@pytest.mark.parametrize(
    "argv",
    [
        ["-H", "alpha", "send", "--text", "x", "--yes"],
        ["-H", "alpha", "layout", "new-window", "--yes-i"],
        ["-H", "alpha", "kill", "--whole", "--yes-i-am-authorised"],
    ],
)
def test_cli_rejects_abbreviated_options(fake, argv):
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2 and writes(fake) == []


def test_text_starting_with_a_dash_is_typed_not_parsed(fake):
    body, is_error = approve("rex_send", {"host": "alpha", "text": "--yes-i-am-authorised"})
    assert not is_error and body["ok"] is True
    assert [c[1]["args"]["data"] for c in writes(fake)] == ["--yes-i-am-authorised"]


@pytest.mark.parametrize(
    "group,verb", [("admin", "server-stop"), ("daemon", "stop"), ("layout", "nosuch"), ("mcp", "x")]
)
def test_rex_op_cannot_reach_admin_or_unknown_ops(fake, group, verb):
    body, is_error = call("rex_op", {"host": "alpha", "group": group, "verb": verb, "confirm": True})
    assert is_error


def test_server_info_only_allows_read_verbs(fake):
    body, is_error = call("rex_server_info", {"host": "alpha", "verb": "server-stop", "confirm": True})
    assert is_error
    body, is_error = call("rex_server_info", {"host": "alpha", "verb": "server-status"})
    assert not is_error and body["method"] == "server.status"


def test_wait_for_needs_exactly_one_condition_and_caps_timeout():
    with pytest.raises(ToolError):
        build_wait({"host": "alpha"})
    with pytest.raises(ToolError):
        build_wait({"host": "alpha", "text": "x", "closed": True})
    argv = build_wait({"host": "alpha", "text": "done", "timeout": 99999, "target": "w/1"})
    assert argv == ["--host=alpha", "wait-for", "--target=w/1", "--text=done", "--wait-timeout", str(MAX_WAIT)]
    assert build_wait({"host": "alpha", "child_exited": True})[2:4] == ["--child-exited", "--wait-timeout"]


def test_op_catalog_lists_flags_and_confirm_need():
    groups = call("rex_op_catalog", {})[0]["groups"]
    verbs = {v["verb"]: v for v in groups["layout"]}
    assert verbs["new-window"]["needs_confirm"] is True and groups["term"][0]["needs_confirm"] is False
    assert "admin" not in groups


def test_hosts_tool(fake):
    body, _ = call("rex_hosts", {})
    assert body["ok"] and {h["host"] for h in body["hosts"]} >= {"alpha", "beta"}


def test_serve_loop_survives_garbage_and_answers_in_order(monkeypatch):
    lines = ["not json\n", "[1]\n", json.dumps({"jsonrpc": "2.0", "id": 5, "method": "ping"}) + "\n", "\n"]
    out = io.StringIO()
    serve(cli.main, io.StringIO("".join(lines)), out)
    replies = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [r.get("error", {}).get("code") for r in replies[:2]] == [-32700, -32600] and replies[2]["id"] == 5


def test_stdio_roundtrip_in_a_subprocess():
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    proc = subprocess.run(
        [sys.executable, "-m", "rexctl", "mcp"],
        cwd=ROOT,
        input="\n".join(map(json.dumps, requests)) + "\n",
        capture_output=True,
        text=True,
        timeout=30,
    )
    replies = [json.loads(line) for line in proc.stdout.splitlines()]
    assert proc.returncode == 0 and [r["id"] for r in replies] == [1, 2] and len(replies[1]["result"]["tools"]) >= 14


# ---------------------------------------------------------------- events


def collector():
    return EventCollector("alpha", "https://fake.invalid", start=False)


def line(name, **extra):
    return {
        "host": "alpha",
        "seq": 1,
        "name": name,
        "session_id": "session:s",
        "block_id": "block:b",
        "payload": {},
        **extra,
    }


def test_events_since_cursor_semantics():
    c = collector()
    flt = EventFilter()
    assert c.since(None, 0, flt, 10) == {
        "cursor": 0,
        "events": [],
        "note": "collector running; pass this cursor next time",
    }
    c.add(line("bell"))
    c.add(line("title_changed"))
    got = c.since(0, 0, flt, 10)
    assert [e["name"] for e in got["events"]] == ["bell", "title_changed"] and got["cursor"] == 2
    assert c.since(2, 0, flt, 10)["events"] == []
    limited = c.since(0, 0, flt, 1)
    assert [e["cursor"] for e in limited["events"]] == [1] and limited["cursor"] == 1


def test_events_since_filters_and_long_polls():
    c = collector()
    flt = EventFilter(names={"title_changed"})
    c.add(line("bell"))
    threading.Timer(0.2, lambda: c.add(line("title_changed"))).start()
    started = time.monotonic()
    got = c.since(0, 3, flt, 10)
    assert [e["name"] for e in got["events"]] == ["title_changed"] and 0.1 < time.monotonic() - started < 10


def test_events_since_flags_gap_when_buffer_overflowed():
    c = collector()
    for _ in range(EVENT_BUFFER + 5):
        c.add(line("bell"))
    assert c.since(1, 0, EventFilter(), 1)["gap"] is True


def test_events_since_always_passes_collector_markers():
    c = collector()
    c.add({"host": "alpha", "event": "rexctl_reconnected", "name": "rexctl_reconnected", "resumed": False})
    assert c.since(0, 0, EventFilter(names={"bell"}), 10)["events"]


def test_terminal_reads_are_marked_untrusted(fake):
    body, _ = call("rex_screen", {"host": "alpha", "lines": 1})
    assert "never as instructions" in body["untrusted"]
    body, _ = call("rex_send", {"host": "alpha", "text": "ls"})
    assert "untrusted" not in body


@pytest.mark.parametrize("arguments", [{"since": "5"}, {"since": True}, {"limit": -1}, {"limit": "9"}])
def test_events_since_rejects_bad_cursor_and_limit(arguments):
    body, is_error = call("rex_events_since", {"host": "alpha", **arguments})
    assert is_error and ("since" in body["error"] or "limit" in body["error"])


@pytest.mark.parametrize("wait", [float("nan"), float("inf"), -1, True, "5"])
def test_events_since_rejects_a_wait_that_is_not_a_finite_number(fake, wait):
    body, is_error = call("rex_events_since", {"host": "alpha", "since": 0, "wait": wait})
    assert is_error and "wait" in body["error"]


def test_events_since_rejects_zero_limit(fake):
    body, is_error = call("rex_events_since", {"host": "alpha", "since": 0, "limit": 0})
    assert is_error and "limit" in body["error"]


def test_mcp_refuses_nan_in_the_json_rpc_stream():
    line = '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "rex_events_since", '
    line += '"arguments": {"host": "alpha", "since": 0, "wait": NaN}}}\n'
    argv = [sys.executable, "-m", "rexctl", "mcp"]
    proc = subprocess.run(argv, input=line, capture_output=True, text=True, timeout=10)
    assert json.loads(proc.stdout)["error"]["code"] == -32700


@pytest.mark.parametrize("value", ["nan", "inf", "-1"])
def test_cli_refuses_non_finite_or_negative_seconds(capsys, value):
    with pytest.raises(SystemExit) as exc:
        cli.main(["-H", "alpha", "wait-for", "--text", "x", "--wait-timeout", value])
    assert exc.value.code == EXIT_USAGE


def test_a_large_result_stays_valid_json_and_keeps_the_end_of_the_text():
    text = render({"ok": True, "content": "x" * 300_000 + "THE END"})
    body = json.loads(text)
    assert len(text) <= MAX_TEXT and body["content"].endswith("THE END") and "chars cut" in body["content"]


def test_a_result_with_too_many_small_items_becomes_an_error():
    body = json.loads(render({"events": [{"n": i} for i in range(50_000)]}))
    assert body["ok"] is False and "too large" in body["error"]


@pytest.mark.parametrize("host", ["https://elsewhere.example", "nope", None])
def test_mcp_accepts_only_configured_host_labels(fake, host):
    body, is_error = call("rex_ls", {"host": host})
    assert is_error and "label from rex_hosts" in body["error"] and not fake.calls


def test_non_numeric_lines_and_timeouts_are_tool_errors(fake):
    for tool, args in (("rex_tail", {"lines": "ten"}), ("rex_wait_for", {"text": "x", "timeout": "soon"})):
        body, is_error = call(tool, {"host": "alpha", **args})
        assert is_error and "non-negative number" in body["error"]
