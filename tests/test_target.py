import json

import pytest

from rexctl import connection
from rexctl.errors import EXIT_DRY_RUN, EXIT_NOT_FOUND, EXIT_USAGE, TargetNotFoundError, UsageError
from rexctl.flags import split_target_spec
from rexctl.protocol import TERMINAL
from rexctl.target import match_one
from test_cli import FakeConn, run
from test_layout import S, two_window_view

TITLES = {"block:a": "vim notes.md", "block:b": "htop", "block:d": "tail -f app.log"}


class TargetConn(FakeConn):
    def call(self, method, payload=None, timeout=None):
        if method == f"{TERMINAL}.title":
            self.calls.append((method, payload))
            return {"title": TITLES.get(payload["block_id"], "")}
        if method == "target.resolve":
            self.calls.append((method, payload))
            return {"results": [{"query": q, "status": "not_found"} for q in payload["queries"]]}
        if method in ("session.own_block", "session.disown_block"):
            self.calls.append((method, payload))
            return {"blocks": [{"block_id": b, "owner": "client:me"} for b in payload.get("block_ids") or []]}
        return super().call(method, payload, timeout)


@pytest.fixture
def fake(monkeypatch):
    conn = TargetConn()
    conn.sessions = [{"session_id": S, "label": "work"}]
    conn.view = two_window_view()
    for window in conn.view["windows"]:
        for layer in window["layers"]:
            for block in layer["blocks"]:
                block["creator_name"] = TERMINAL
    monkeypatch.setattr(connection, "connect", lambda url, timeout=10.0: conn)
    return conn


def screen_target(capsys, *extra):
    code, out, _ = run(capsys, ["-H", "alpha", "tail", *extra])
    return code, json.loads(out)


def methods(conn):
    return [c[0] for c in conn.calls]


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("work", ("work", None, None)),
        ("work/2", ("work", "2", None)),
        ("work/logs/tail", ("work", "logs", "tail")),
        ("work//right", ("work", None, "right")),
        ("/editor/left", (None, "editor", "left")),
        ("session:abc/window:def/block:123", ("session:abc", "window:def", "block:123")),
    ],
)
def test_split_target_spec(spec, expected):
    assert split_target_spec(spec) == expected


@pytest.mark.parametrize("spec", ["", "/", "a/b/c/d", "//"])
def test_bad_target_spec_is_usage_error(spec):
    with pytest.raises(UsageError):
        split_target_spec(spec)


def test_target_selects_block_in_named_window_by_label(fake, capsys):
    code, body = screen_target(capsys, "-t", "work/logs/tail")
    assert code == 0 and body["target"]["block_id"] == "block:d"


def test_target_window_by_position_and_default_focus(fake, capsys):
    code, body = screen_target(capsys, "--target", "work/2")
    assert body["target"]["block_id"] == "block:d"
    code, body = screen_target(capsys, "--target", "work/editor")
    assert body["target"]["block_id"] == "block:a"


def test_block_can_be_named_by_terminal_title(fake, capsys):
    code, body = screen_target(capsys, "-s", "work", "-b", "htop")
    assert code == 0 and body["target"]["block_id"] == "block:b"
    code, body = screen_target(capsys, "-t", "work//TAIL -F APP.LOG")
    assert body["target"]["block_id"] == "block:d"


def test_a_title_fragment_does_not_pick_a_block(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "tail", "-s", "work", "-b", "tail -f"])
    assert code == EXIT_NOT_FOUND


FRAGMENT_IDS = [("block:01a183b9-15d8-718a-8d99-96273bffd829", ""), ("block:01a183b9-15d8-7aaa-0000-111122223333", "")]


@pytest.mark.parametrize(
    "needle,expected",
    [
        ("bffd829", "block:01a183b9-15d8-718a-8d99-96273bffd829"),
        ("01a183b9-15d8-7aaa", "block:01a183b9-15d8-7aaa-0000-111122223333"),
    ],
)
def test_id_fragment_is_a_unique_prefix_or_suffix(needle, expected):
    assert match_one("block", needle, FRAGMENT_IDS) == expected


@pytest.mark.parametrize("needle", ["829", "96273", "8d99"])
def test_short_or_inner_id_fragments_do_not_match(needle):
    with pytest.raises(TargetNotFoundError):
        match_one("block", needle, FRAGMENT_IDS)


def test_label_wins_over_title_and_ambiguous_title_fails(fake, capsys):
    TITLES["block:c"] = "htop"
    try:
        code, out, _ = run(capsys, ["-H", "alpha", "tail", "-s", "work", "-b", "htop"])
        assert code == EXIT_NOT_FOUND and "ambiguous" in json.loads(out)["error"]["message"]
    finally:
        del TITLES["block:c"]


def test_block_outside_named_window_is_not_found(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "tail", "-t", "work/logs/left"])
    assert code == EXIT_NOT_FOUND


def test_target_conflicts_with_session_flag(fake, capsys):
    code, _, _ = run(capsys, ["-H", "alpha", "tail", "-t", "work/1/left", "-s", "work"])
    assert code == EXIT_USAGE


def test_target_works_on_op_commands(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "term", "size", "-t", "work/logs/tail"])
    assert code == 0 and json.loads(out)["target"]["block_id"] == "block:d"


def test_target_works_on_layout_ops_window_scope(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "layout", "focus-block", "-t", "work/editor", "-b", "right"])
    assert code == EXIT_DRY_RUN and json.loads(out)["payload"]["block_id"] == "block:b"


def test_conn_describe_block_defaults_to_focused_and_needs_no_flag(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "conn", "describe-block"])
    assert code == 0 and ("session.describe_block", {"session_id": S, "block_id": "block:a"}) in fake.calls


def test_own_block_is_guarded_and_attaches_first(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "conn", "own-block", "--blocks", "left,tail", "--mode", "request"])
    plan = json.loads(out)
    assert code == EXIT_DRY_RUN and plan["payload"] == {
        "session_id": S,
        "block_ids": ["block:a", "block:d"],
        "mode": "request",
    }
    assert "session.own_block" not in methods(fake)
    code, out, err = run(capsys, ["-H", "alpha", "conn", "own-block", "--blocks", "left", "--yes-i-am-authorised"])
    ms = methods(fake)
    assert code == 0 and ms.index("session.attach") < ms.index("session.own_block")


def test_disown_all_blocks_sends_no_block_ids(fake, capsys):
    run(capsys, ["-H", "alpha", "conn", "disown-block", "--yes-i-am-authorised"])
    call = [c for c in fake.calls if c[0] == "session.disown_block"][0]
    assert call[1] == {"session_id": S}


def test_detach_block_needs_guard_and_warns(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "conn", "detach-block", "-b", "right"])
    assert code == EXIT_DRY_RUN and json.loads(out)["warning"]
    code, _, err = run(capsys, ["-H", "alpha", "conn", "detach-block", "-b", "right", "--yes-i-am-authorised"])
    assert (
        code == 0
        and "WARNING" in err
        and ("session.detach_block", {"session_id": S, "block_id": "block:b"}) in fake.calls
    )


def test_attach_detach_bootstrap_are_read_only(fake, capsys):
    for argv, method in ((["attach"], "session.attach"), (["detach"], "session.detach")):
        code, _, _ = run(capsys, ["-H", "alpha", "conn", *argv])
        assert code == 0 and (method, {"session_id": S}) in fake.calls
    code, _, _ = run(capsys, ["-H", "alpha", "conn", "bootstrap", "--attach-session-ids", ""])
    assert code == 0 and ("session.bootstrap", {"event_scope": "session", "attach_session_ids": []}) in fake.calls


def test_target_resolve_builds_nested_payload(fake, capsys):
    code, out, _ = run(
        capsys,
        ["-H", "alpha", "target", "resolve", "--queries", "work,2", "--scope-window", "logs", "--context-session", S],
    )
    assert code == 0
    call = [c for c in fake.calls if c[0] == "target.resolve"][0][1]
    assert call == {
        "kinds": ["session", "window", "block"],
        "queries": ["work", "2"],
        "scope": {"window": "logs"},
        "context": {"session_id": S},
    }


def test_target_complete(fake, capsys):
    run(capsys, ["-H", "alpha", "target", "complete", "--prefix", "wo", "--kinds", "session"])
    call = [c for c in fake.calls if c[0] == "target.complete"]
    assert call and call[0][1] == {"kinds": ["session"], "prefix": "wo"}


def test_send_plan_shows_the_block_label_and_title_without_hashing_them(fake, capsys):
    argv = ["-H", "alpha", "send", "-s", "work", "-b", "right", "--text", "q"]
    code, out, _ = run(capsys, argv)
    plan = json.loads(out)
    assert code == EXIT_DRY_RUN and plan["about"]["title"] == "htop" and plan["about"]["block_label"] == "right"
    TITLES["block:b"] = "htop - renamed"
    try:
        _, out, _ = run(capsys, argv)
    finally:
        TITLES["block:b"] = "htop"
    assert json.loads(out)["about"]["title"] == "htop - renamed" and json.loads(out)["plan_id"] == plan["plan_id"]
