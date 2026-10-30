import json
from pathlib import Path

import pytest

from conftest import load_fixture
from rexctl.errors import EXIT_DRY_RUN, EXIT_OK
from rexctl.flags import GUARD_FLAG
from rexctl.ops import OPS, Op
from rexctl.protocol import TERMINAL
from test_quality import run_wire, serve_with

VIEW = load_fixture("session-view.json")
SESSIONS = VIEW["sessions"]["sessions"]
COMMANDS = [
    ["version"],
    ["ls"],
    ["screen"],
    ["tail"],
    ["pwd"],
    ["title"],
    ["process"],
    ["status"],
    ["send", "--text", "x", GUARD_FLAG],
    ["new-session", GUARD_FLAG],
    ["split", GUARD_FLAG],
    ["kill", GUARD_FLAG],
    ["kill", "--whole-session", GUARD_FLAG],
    ["wait-for", "--text", "x", "--wait-timeout", "0"],
    ["admin", "client-list", "--session", SESSIONS[0]["label"]],
    ["input", "key", "--keys", "a", "--via", "client-key", GUARD_FLAG],
]
DELIBERATE_EXCLUSIONS = {
    "block.method": "generic form of <creator>.<method>; rexctl calls block methods by full name",
    "client.reply": "answers client_call_requested for Lua/client actions this client never declares",
    "client.set_script": "loads Lua into this client; Lua is out of scope",
    "server.apple.grant_file_access": "server-local (Unix socket) and needs macOS sandbox tokens",
}


def methods_sent_by_commands(fake_server, monkeypatch, capsys) -> set[str]:
    methods: set[str] = set()
    for argv in COMMANDS:
        server = serve_with(fake_server, monkeypatch, answer)
        run_wire(capsys, argv)
        methods |= {m["method"] for m in server.received if m["type"] == "request"}
    return methods


def help_methods() -> set[str]:
    doc = load_fixture("help-methods.json")
    names = {m["name"] for m in doc["methods"]}
    names |= {m["invoke"]["method"] for bt in doc["block_types"] for m in bt["methods"]}
    return names


def test_every_server_method_is_wrapped_or_deliberately_excluded(fake_server, monkeypatch, capsys):
    wrapped = {op.method for op in OPS} | methods_sent_by_commands(fake_server, monkeypatch, capsys)
    assert help_methods() - wrapped - set(DELIBERATE_EXCLUSIONS) == set()


def test_exclusions_are_documented_in_coverage_md():
    text = (Path(__file__).resolve().parent.parent / "COVERAGE.md").read_text()
    assert all(f"`{name}`" in text for name in DELIBERATE_EXCLUSIONS)


def answer(message, server):
    method = message["method"]
    if method == "session.attach_all":
        server.respond(message, {"sessions": SESSIONS})
    elif method == "session.list":
        server.respond(message, {"sessions": SESSIONS})
    elif method == "session.view":
        server.respond(message, VIEW["view"])
    else:
        server.respond(message, {})


def no_required(op: Op) -> bool:
    return not any(p.required for p in op.params)


def scoped_ops(mutating: bool) -> list[Op]:
    return [
        op
        for op in OPS
        if op.scope in ("session", "block") and op.mutating == mutating and no_required(op) and op.plan is None
    ]


def sent(server) -> list[str]:
    return [m["method"] for m in server.received if m["type"] == "request"]


@pytest.mark.parametrize("op", scoped_ops(False), ids=lambda op: f"{op.group}-{op.name}")
def test_every_session_and_block_read_op_goes_over_the_wire(op, fake_server, monkeypatch, capsys):
    server = serve_with(fake_server, monkeypatch, answer)
    code, out, _ = run_wire(capsys, [op.group, op.name])
    assert code == EXIT_OK, out
    assert op.method in sent(server)


@pytest.mark.parametrize("op", scoped_ops(True), ids=lambda op: f"{op.group}-{op.name}")
def test_every_session_and_block_mutating_op_is_a_dry_run_on_the_wire(op, fake_server, monkeypatch, capsys):
    server = serve_with(fake_server, monkeypatch, answer)
    code, out, _ = run_wire(capsys, [op.group, op.name])
    assert code == EXIT_DRY_RUN and json.loads(out)["dry_run"] is True
    assert op.method not in sent(server)
    server = serve_with(fake_server, monkeypatch, answer)
    code, out, _ = run_wire(capsys, [op.group, op.name, GUARD_FLAG])
    assert code == EXIT_OK and op.method in sent(server), out


def test_onboarding_set_step_is_guarded_and_nests_args(fake_server, monkeypatch, capsys):
    server = serve_with(fake_server, monkeypatch, answer)
    code, out, _ = run_wire(capsys, ["onboarding", "set-step", "--step", "intro"])
    assert code == EXIT_DRY_RUN and "com.superlogical.onboarding.set_step" not in sent(server)
    server = serve_with(fake_server, monkeypatch, answer)
    code, out, _ = run_wire(capsys, ["onboarding", "set-step", "--step", "intro", GUARD_FLAG])
    request = [m for m in server.received if m.get("method") == "com.superlogical.onboarding.set_step"][0]
    assert code == EXIT_OK and request["payload"]["args"] == {"step": "intro"}


def test_raw_api_blob_read_is_guarded_because_it_can_return_clipboard_text(fake_server, monkeypatch, capsys):
    server = serve_with(fake_server, monkeypatch, answer)
    payload = json.dumps({"session_id": SESSIONS[0]["session_id"], "block_id": "b", "args": {"id": 0}})
    code, _, _ = run_wire(capsys, ["api", "call", f"{TERMINAL}.blob_read", payload])
    assert code == EXIT_DRY_RUN and not sent(server)


def test_target_resolution_reuses_attach_all_sessions(fake_server, monkeypatch, capsys):
    server = serve_with(fake_server, monkeypatch, answer)
    code, _, _ = run_wire(capsys, ["term", "size"])
    assert code == EXIT_OK and "session.list" not in sent(server)
