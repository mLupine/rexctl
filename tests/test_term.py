import json

import pytest

from rexctl import connection
from rexctl.errors import EXIT_DRY_RUN, EXIT_USAGE
from rexctl.flags import GUARD_FLAG
from rexctl.protocol import TERMINAL
from test_cli import FakeConn, run

TERM = TERMINAL + "."


class TermConn(FakeConn):
    def block_call(self, method, session_id, block_id, args=None, timeout=None):
        self.calls.append((method, {"block_id": block_id, "args": args}))
        if method.endswith(("clipboard_read", "blob_read")):
            return {"id": 3, "data": "s3cret-token", "total": 12, "eof": True}
        if method.endswith("modes"):
            return {"screen": "primary", "modes": []}
        return {}


@pytest.fixture
def fake(monkeypatch):
    conn = TermConn()
    monkeypatch.setattr(connection, "connect", lambda url, timeout=10.0: conn)
    return conn


def term_calls(conn):
    return [
        c
        for c in conn.calls
        if c[0].startswith(TERM) and not c[0].endswith(("format", "size")) or c[0].endswith("modes")
    ]


@pytest.mark.parametrize("verb", ["clipboard-read", "blob-read"])
def test_sensitive_reads_are_redacted_without_show(fake, capsys, verb):
    code, out, _ = run(capsys, ["-H", "alpha", "term", verb, "--id", "3"])
    body = json.loads(out)
    assert code == 0 and "s3cret" not in out and body["result"]["data"].startswith("<redacted 12 bytes")
    assert body["result"]["total"] == 12 and fake.calls[-1][1]["args"] == {"id": 3}


def test_clipboard_read_show_prints_text_but_show_is_not_sent(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "term", "clipboard-read", "--show", "--offset", "4", "--max-bytes", "8"])
    assert json.loads(out)["result"]["data"] == "s3cret-token"
    assert fake.calls[-1] == (
        TERM + "clipboard_read",
        {"block_id": fake.calls[-1][1]["block_id"], "args": {"offset": 4, "max_bytes": 8}},
    )


def test_read_only_term_methods_run_without_guard(fake, capsys):
    for argv, method, args in (
        (["modes"], "modes", {}),
        (["input-mode"], "input_mode", {}),
        (
            ["list-dir", "--path", "/tmp", "--files", "--limit", "5"],
            "list_dir",
            {"path": "/tmp", "files": True, "limit": 5},
        ),
    ):
        code, _, _ = run(capsys, ["-H", "alpha", "term", *argv])
        assert code == 0 and fake.calls[-1][0] == TERM + method and fake.calls[-1][1]["args"] == args


@pytest.mark.parametrize(
    "argv,method,args",
    [
        (["resize", "--columns", "100", "--rows", "30"], "resize", {"columns": 100, "rows": 30}),
        (["reset"], "reset", {}),
        (["clear"], "clear", {}),
        (
            ["set-theme", "--foreground", "d6deeb", "--scheme", "dark", "--palette", "1=ff0000,2=00ff00"],
            "set_theme",
            {"foreground": "d6deeb", "scheme": "dark", "palette": ["1=ff0000", "2=00ff00"]},
        ),
    ],
)
def test_mutating_term_methods_are_guarded(fake, capsys, argv, method, args):
    code, out, _ = run(capsys, ["-H", "alpha", "term", *argv])
    plan = json.loads(out)
    assert code == EXIT_DRY_RUN and plan["method"] == TERM + method and plan["payload"] == args
    assert not [c for c in fake.calls if c[0] == TERM + method]
    code, _, err = run(capsys, ["-H", "alpha", "term", *argv, GUARD_FLAG])
    assert code == 0 and [c[1]["args"] for c in fake.calls if c[0] == TERM + method] == [args]
    assert "WARNING" in err or method == "set_theme"


def test_resize_requires_dimensions(fake, capsys):
    code, _, _ = run(capsys, ["-H", "alpha", "term", "resize", "--columns", "80", GUARD_FLAG])
    assert code == EXIT_USAGE and not [c for c in fake.calls if c[0].endswith("resize")]
