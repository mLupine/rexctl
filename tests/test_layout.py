import json
from typing import Any

import pytest

from rexctl import connection
from rexctl.errors import EXIT_DRY_RUN, EXIT_NOT_FOUND, EXIT_OK, EXIT_USAGE
from rexctl.flags import GUARD_FLAG
from rexctl.protocol import SHELL_FLAVOR
from test_cli import FakeConn, run

W1, W2 = "window:w1", "window:w2"
S = "session:s1"


def two_window_view() -> dict[str, Any]:
    def block(i: str, label: str) -> dict[str, Any]:
        return {"block_id": f"block:{i}", "label": label, "flavor": SHELL_FLAVOR}

    def window(
        wid: str, label: str, blocks: list[dict[str, Any]], layers: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        return {
            "window_id": wid,
            "label": label,
            "focused_block_id": blocks[0]["block_id"],
            "layers": [{"layer_id": f"layer:t-{wid[-2:]}", "kind": "tiled", "blocks": blocks}, *(layers or [])],
        }

    floating = {
        "layer_id": "layer:f1",
        "kind": "floating",
        "bounds": [0.1, 0.1, 0.5, 0.5],
        "blocks": [block("c", "float")],
    }
    return {
        "revision": 1,
        "session_id": S,
        "label": "work",
        "active_window_id": W1,
        "windows": [
            window(W1, "editor", [block("a", "left"), block("b", "right")], [floating]),
            window(W2, "logs", [block("d", "tail")]),
        ],
    }


@pytest.fixture
def fake(monkeypatch):
    conn = FakeConn()
    conn.sessions = [{"session_id": S, "label": "work"}]
    conn.view = two_window_view()
    monkeypatch.setattr(connection, "connect", lambda url, timeout=10.0: conn)
    return conn


def mutations(conn: FakeConn) -> list[tuple[str, Any]]:
    return [
        c
        for c in conn.calls
        if c[0].startswith("session.") and c[0] not in ("session.attach_all", "session.list", "session.view")
    ]


CASES = [
    (
        ["new-window", "--window-label", "x"],
        "session.new_window",
        {"session_id": S, "window_label": "x", "layout": {"block": {"flavor": SHELL_FLAVOR}}},
    ),
    (
        ["new-window", "--cwd", "/tmp", "--block-label", "b", "--no-focus"],
        "session.new_window",
        {
            "session_id": S,
            "layout": {"block": {"flavor": SHELL_FLAVOR, "label": "b", "options": {"cwd": "/tmp"}}},
            "focus": False,
        },
    ),
    (
        ["new-block", "--label", "bg", "--cwd", "/x"],
        "session.new_block",
        {"session_id": S, "flavor": SHELL_FLAVOR, "label": "bg", "options": {"cwd": "/x"}},
    ),
    (
        ["new-layer", "--bounds", "0.1,0.1,0.5,0.5"],
        "session.new_layer",
        {"session_id": S, "bounds": [0.1, 0.1, 0.5, 0.5], "layout": {"block": {"flavor": SHELL_FLAVOR}}},
    ),
    (
        [
            "move-block",
            "-b",
            "left",
            "--anchor-block",
            "tail",
            "--direction",
            "vertical",
            "--side",
            "after",
            "--ratio",
            "0.3",
        ],
        "session.move_block",
        {
            "session_id": S,
            "block_id": "block:a",
            "anchor_block_id": "block:d",
            "direction": "vertical",
            "side": "after",
            "ratio": 0.3,
        },
    ),
    (
        ["move-window", "-w", "logs", "--before-window", "editor"],
        "session.move_window",
        {"session_id": S, "window_id": W2, "before_window_id": W1},
    ),
    (
        ["swap-blocks", "-b", "left", "--other-block", "right"],
        "session.swap_blocks",
        {"session_id": S, "block_id": "block:a", "other_block_id": "block:b"},
    ),
    (
        [
            "resize-pane",
            "--direction",
            "horizontal",
            "--before-block",
            "left",
            "--after-block",
            "right",
            "--ratio",
            "0.7",
        ],
        "session.resize_pane",
        {
            "session_id": S,
            "direction": "horizontal",
            "before_block_id": "block:a",
            "after_block_id": "block:b",
            "ratio": 0.7,
        },
    ),
    (
        ["resize-layer", "--layer", "floating", "--bounds", "0,0,1,1"],
        "session.resize_layer",
        {"session_id": S, "layer_id": "layer:f1", "bounds": [0.0, 0.0, 1.0, 1.0]},
    ),
    (
        ["float-block", "-b", "right", "--bounds", "0.2,0.2,0.4,0.4"],
        "session.float_block",
        {"session_id": S, "block_id": "block:b", "bounds": [0.2, 0.2, 0.4, 0.4]},
    ),
    (
        ["zoom-block", "-b", "right", "--zoom"],
        "session.zoom_block",
        {"session_id": S, "block_id": "block:b", "zoom": True},
    ),
    (["focus-block", "-b", "tail"], "session.focus_block", {"session_id": S, "block_id": "block:d"}),
    (["focus-window", "-w", "active"], "session.focus_window", {"session_id": S, "window_id": W1}),
    (
        ["focus-direction", "--direction", "left", "--wrap"],
        "session.focus_direction",
        {"session_id": S, "direction": "left", "wrap": True},
    ),
    (["focus-next-window"], "session.focus_next_window", {"session_id": S}),
    (["close-window", "-w", "logs"], "session.close_window", {"session_id": S, "window_id": W2}),
    (["close-layer", "--layer", "layer:f1"], "session.close_layer", {"session_id": S, "layer_id": "layer:f1"}),
    (["set-session-label", "--label", "new"], "session.set_label", {"session_id": S, "label": "new"}),
    (
        ["set-window-label", "-w", "logs", "--label", "L"],
        "session.set_window_label",
        {"session_id": S, "window_id": W2, "label": "L"},
    ),
    (
        ["set-block-label", "-b", "tail", "--label", ""],
        "session.set_block_label",
        {"session_id": S, "block_id": "block:d", "label": ""},
    ),
    (
        ["raise-layer", "--layer", "floating", "--relative-layer", "layer:f1"],
        "session.raise_layer",
        {"session_id": S, "layer_id": "layer:f1", "relative_layer_id": "layer:f1"},
    ),
    (["lower-layer", "--layer", "floating"], "session.lower_layer", {"session_id": S, "layer_id": "layer:f1"}),
    (["focus-next-pane"], "session.focus_next_pane", {"session_id": S}),
    (["focus-previous-pane"], "session.focus_previous_pane", {"session_id": S}),
    (["focus-previous-window"], "session.focus_previous_window", {"session_id": S}),
    (["move-session"], "session.move", {"session_id": S}),
    (["move-session", "--before-session", "work"], "session.move", {"session_id": S, "before_session_id": S}),
]


@pytest.mark.parametrize("argv,method,payload", CASES, ids=[c[1] + str(i) for i, c in enumerate(CASES)])
def test_layout_ops_dry_run_then_execute(fake, capsys, argv, method, payload):
    code, out, _ = run(capsys, ["-H", "alpha", "layout", *argv])
    plan = json.loads(out)
    assert code == EXIT_DRY_RUN and plan["dry_run"] is True and plan["payload"] == payload and plan["method"] == method
    assert mutations(fake) == []
    code, out, err = run(capsys, ["-H", "alpha", "layout", *argv, GUARD_FLAG])
    assert code == EXIT_OK and json.loads(out)["ok"] is True and "EXECUTING" in err
    assert mutations(fake) == [(method, payload)]


def test_close_window_warns_when_executed(fake, capsys):
    _, out, _ = run(capsys, ["-H", "alpha", "layout", "close-window", "-w", "logs"])
    assert "ends its programs" in json.loads(out)["warning"]
    _, _, err = run(capsys, ["-H", "alpha", "layout", "close-window", "-w", "logs", GUARD_FLAG])
    assert "WARNING" in err


@pytest.mark.parametrize(
    "argv",
    [
        ["new-layer", "--bounds", "0.5,0.5,0.9,0.9"],
        ["new-layer", "--bounds", "a,b"],
        ["float-block", "-b", "left"],
        ["close-window"],
    ],
)
def test_bad_or_missing_arguments_are_usage_errors(fake, capsys, argv):
    code, out, _ = run(capsys, ["-H", "alpha", "layout", *argv])
    assert code == EXIT_USAGE and mutations(fake) == []


def test_unknown_block_label_is_target_not_found(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "layout", "focus-block", "-b", "nope", GUARD_FLAG])
    assert code == EXIT_NOT_FOUND and mutations(fake) == []


def test_ambiguous_layer_needs_exact_id(fake, capsys):
    fake.view["windows"][1]["layers"].append({"layer_id": "layer:f2", "kind": "floating", "blocks": []})
    code, _, _ = run(capsys, ["-H", "alpha", "layout", "close-layer", "--layer", "floating", GUARD_FLAG])
    assert code == EXIT_NOT_FOUND and mutations(fake) == []
