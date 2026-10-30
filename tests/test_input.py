import json

import pytest

from rexctl import connection
from rexctl.errors import EXIT_DRY_RUN, UsageError
from rexctl.flags import GUARD_FLAG
from rexctl.inputs import keys_to_data
from rexctl.keys import key_bytes, key_object, parse_key, parse_keys
from test_cli import FakeConn, run


@pytest.fixture
def fake(monkeypatch):
    conn = FakeConn()
    monkeypatch.setattr(connection, "connect", lambda url, timeout=10.0: conn)
    return conn


def keys_bytes(spec):
    return "".join(key_bytes(key) for key in parse_keys(spec))


def sent(conn):
    return [c for c in conn.calls if c[0] in ("block.event", "client.key") or c[0].endswith(".write")]


@pytest.mark.parametrize(
    "name,expected",
    [
        ("Enter", "\r"),
        ("Esc", "\x1b"),
        ("Tab", "\t"),
        ("S-Tab", "\x1b[Z"),
        ("C-c", "\x03"),
        ("ctrl+d", "\x04"),
        ("ctrl-[", "\x1b"),
        ("M-x", "\x1bx"),
        ("Up", "\x1b[A"),
        ("PageDown", "\x1b[6~"),
        ("F1", "\x1bOP"),
        ("F5", "\x1b[15~"),
        ("F12", "\x1b[24~"),
        ("ctrl+shift+Up", "\x1b[1;6A"),
        ("alt+Left", "\x1b[1;3D"),
        ("Space", " "),
        ("A", "A"),
        ("ctrl+space", "\x00"),
        ("BS", "\x7f"),
        ("comma", ","),
        ("plus", "+"),
        ("minus", "-"),
        ("M-comma", "\x1b,"),
    ],
)
def test_key_names_to_bytes(name, expected):
    assert keys_bytes(name) == expected


def test_key_lists_split_on_commas_and_spaces():
    assert keys_bytes("C-c, Up  Enter") == "\x03\x1b[A\r"


@pytest.mark.parametrize("bad", ["hyper-q", "F13", "ctrl+-", "Foo"])
def test_unknown_or_unmappable_keys_are_usage_errors(bad):
    with pytest.raises(UsageError):
        keys_to_data(bad)


def test_key_object_matches_client_key_schema():
    assert key_object(parse_key("C-c")) == {
        "key": "key_c",
        "mods": "ctrl",
        "consumed_mods": "",
        "text": "",
        "unshifted_codepoint": 99,
        "composing": False,
        "action": "press",
    }
    upper = key_object(parse_key("A"))
    assert (
        upper["key"] == "key_a"
        and upper["mods"] == "shift"
        and upper["text"] == "A"
        and upper["consumed_mods"] == "shift"
    )
    assert key_object(parse_key("F5"))["key"] == "f5"
    assert key_object(parse_key("Space"))["text"] == " "


def test_send_keys_dry_run_then_bytes(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "send", "--keys", "C-c Esc F2"])
    assert code == EXIT_DRY_RUN and json.loads(out)["data_json"] == json.dumps("\x03\x1b\x1bOQ") and sent(fake) == []
    code, _, _ = run(capsys, ["-H", "alpha", "send", "--keys", "C-c", GUARD_FLAG])
    assert code == 0 and sent(fake)[0][1]["args"] == {"data": "\x03"}


def test_input_key_block_event_per_key(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "input", "key", "--keys", "C-c Enter"])
    plan = json.loads(out)
    assert (
        code == EXIT_DRY_RUN
        and plan["method"] == "block.event"
        and len(plan["payload"]["calls"]) == 2
        and sent(fake) == []
    )
    code, _, _ = run(capsys, ["-H", "alpha", "input", "key", "--keys", "C-c Enter", GUARD_FLAG])
    events = [c[1]["event"] for c in sent(fake)]
    assert code == 0 and [e["type"] for e in events] == ["key", "key"] and events[0]["payload"]["key"] == "key_c"
    assert sent(fake)[0][1]["block_id"].startswith("block:") and sent(fake)[0][1]["session_id"].startswith("session:")


def test_input_key_via_client_key(fake, capsys):
    run(capsys, ["-H", "alpha", "input", "key", "--keys", "x", "--via", "client-key", GUARD_FLAG])
    method, payload = sent(fake)[0]
    assert method == "client.key" and payload["key"]["key"] == "key_x" and "event" not in payload


def test_input_paste_and_focus(fake, capsys):
    run(capsys, ["-H", "alpha", "input", "paste", "--text", "a\nb", GUARD_FLAG])
    run(capsys, ["-H", "alpha", "input", "focus", "--action", "out", GUARD_FLAG])
    assert [c[1]["event"] for c in sent(fake)] == [
        {"type": "paste", "payload": {"text": "a\nb"}},
        {"type": "focus", "payload": {"action": "out"}},
    ]


def test_input_raw_mouse_and_event_type_whitelist(fake, capsys):
    run(capsys, ["-H", "alpha", "input", "mouse", "--payload", '{"x":1}', GUARD_FLAG])
    assert sent(fake)[0][1]["event"] == {"type": "mouse", "payload": {"x": 1}}
    with pytest.raises(SystemExit):
        run(capsys, ["-H", "alpha", "input", "event", "--event-type", "resize", GUARD_FLAG])


def test_input_commands_never_write_without_flag(fake, capsys):
    for argv in (["key", "--keys", "a"], ["paste", "--text", "x"], ["focus", "--action", "in"], ["wheel"]):
        code, _, _ = run(capsys, ["-H", "alpha", "input", *argv])
        assert code == EXIT_DRY_RUN
    assert sent(fake) == []
