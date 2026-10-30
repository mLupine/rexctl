import json
from typing import Any

import pytest

from conftest import load_fixture
from rexctl import cli, connection
from rexctl.errors import EXIT_DRY_RUN, EXIT_ERROR, EXIT_OK, EXIT_USAGE, ApiError, UsageError
from rexctl.flags import GUARD_FLAG
from rexctl.hosts import require_https
from rexctl.output import scrub
from rexctl.read import read_blob_tail
from rexctl.target import Target


class FakeConn:
    def __init__(self) -> None:
        fx = load_fixture("session-view.json")
        self.view = fx["view"]
        self.sessions = fx["sessions"]["sessions"]
        self.calls: list[tuple[str, Any]] = []
        self.welcome = {"api_revision": 7}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def call(self, method, payload=None, timeout=None):
        self.calls.append((method, payload))
        if method == "session.attach_all":
            return self.sessions and {"sessions": self.sessions}
        if method == "session.list":
            return {"sessions": self.sessions}
        if method == "session.view":
            return self.view
        return {}

    def block_call(self, method, session_id, block_id, args=None, timeout=None):
        self.calls.append((method, {"block_id": block_id, "args": args}))
        if method.endswith(".write"):
            return {"bytes_written": len(args["data"].encode())}
        if method.endswith(".format"):
            return {"content": "line1\nline2\n\n", "total": 12, "eof": True}
        if method.endswith(".size"):
            return {"rows": 2, "columns": 80}
        return {}

    def call_many(self, calls, timeout=None):
        return [self.call(m, p) for m, p in calls]


@pytest.fixture
def fake(monkeypatch):
    conn = FakeConn()
    monkeypatch.setattr(connection, "connect", lambda url, timeout=10.0: conn)
    return conn


def run(capsys, argv):
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def writes(conn):
    return [c for c in conn.calls if c[0].endswith(".write")]


def test_send_is_dry_run_by_default(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "send", "--text", "rm -rf /", "--enter"])
    body = json.loads(out)
    assert code == EXIT_DRY_RUN and body["dry_run"] is True
    assert body["target"]["host"] == "alpha" and body["target"]["block_id"].startswith("block:")
    assert writes(fake) == []


def test_send_executes_only_with_flag(fake, capsys):
    code, out, err = run(capsys, ["-H", "alpha", "send", "--text", "ls", "--enter", GUARD_FLAG])
    assert code == EXIT_OK and json.loads(out)["result"]["bytes_written"] == 3
    assert "EXECUTING" in err and "host=alpha" in err
    assert len(writes(fake)) == 1


@pytest.mark.parametrize(
    "argv",
    [
        ["new-session"],
        ["split"],
        ["kill"],
        ["kill", "--whole-session"],
        ["api", "call", "block.close", '{"session_id":"s","block_id":"b"}'],
    ],
)
def test_dangerous_commands_dry_run_by_default(fake, capsys, argv):
    code, out, _ = run(capsys, ["-H", "alpha", *argv])
    assert code == EXIT_DRY_RUN and json.loads(out)["dry_run"] is True
    mutating = {"session.create", "session.new_split", "block.close", "session.destroy"}
    assert not [c for c in fake.calls if c[0] in mutating]


def test_api_call_of_an_admin_method_needs_the_second_flag(fake, capsys):
    code, out, _ = run(capsys, ["-H", "beta", "api", "call", "server.stop", "{}", "--yes-i-am-authorised"])
    assert code == EXIT_DRY_RUN and json.loads(out)["dry_run"] is True
    assert not [c for c in fake.calls if c[0] == "server.stop"]
    code, out, _ = run(
        capsys, ["-H", "beta", "api", "call", "server.stop", "{}", "--yes-i-am-authorised", "--allow-server-admin"]
    )
    assert code == EXIT_OK and [c for c in fake.calls if c[0] == "server.stop"]


@pytest.mark.parametrize("method", ["server.apple.grant_file_access", "client.set_script", "server.future_thing"])
def test_api_call_of_an_unwrapped_method_needs_the_second_flag(fake, capsys, method):
    code, out, _ = run(capsys, ["-H", "beta", "api", "call", method, "{}", "--yes-i-am-authorised"])
    assert code == EXIT_DRY_RUN and "--allow-server-admin" in json.loads(out)["note"]
    assert not [c for c in fake.calls if c[0] == method]
    code, _, _ = run(
        capsys, ["-H", "beta", "api", "call", method, "{}", "--yes-i-am-authorised", "--allow-server-admin"]
    )
    assert code == EXIT_OK and [c for c in fake.calls if c[0] == method]


def test_api_call_of_a_wrapped_method_needs_one_flag(fake, capsys):
    code, _, _ = run(capsys, ["-H", "beta", "api", "call", "session.set_label", "{}", "--yes-i-am-authorised"])
    assert code == EXIT_OK and [c for c in fake.calls if c[0] == "session.set_label"]


def test_api_call_read_only_method_runs_without_flag(fake, capsys):
    code, out, _ = run(capsys, ["-H", "beta", "api", "call", "session.list"])
    assert code == EXIT_OK and json.loads(out)["ok"] is True


def test_screen_trims_and_uses_visible_rows(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "screen"])
    body = json.loads(out)
    assert code == 0 and body["content"] == "line1\nline2" and body["lines"] == 2


def test_screen_text_mode(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "screen", "--text", "--lines", "1"])
    assert out == "line2\n"


def test_ls_brief_has_short_ids(fake, capsys):
    code, out, _ = run(capsys, ["-H", "alpha", "ls", "--brief"])
    block = json.loads(out)["sessions"][0]["windows"][0]["blocks"][0]
    assert block["short_id"] == block["block_id"][-8:] and "title" not in block


def test_missing_host_is_usage_error(capsys):
    code, out, _ = run(capsys, ["version"])
    assert code == EXIT_USAGE and json.loads(out)["error"]["kind"] == "usage"


def test_plain_http_host_is_refused(capsys):
    code, out, _ = run(capsys, ["-H", "http://rex.example.test", "version"])
    assert code == EXIT_USAGE


@pytest.mark.parametrize(
    "argv,kind",
    [
        (["-H", "alpha", "wait-for", "--text", "(", "--wait-timeout", "0.1", "--no-stream"], "usage"),
        (["-H", "alpha", "events", "--where", "a~(", "--duration", "0"], "usage"),
        (["-H", "alpha", "api", "call", "session.list", "@/nonexistent/payload.json"], "usage"),
        (["-H", "alpha", "admin", "client-action", "--action", "x", "--args", "nope"], "usage"),
    ],
)
def test_bad_input_is_a_json_error_not_a_traceback(fake, capsys, argv, kind):
    code, out, _ = run(capsys, argv)
    assert code == EXIT_USAGE and json.loads(out)["error"]["kind"] == kind


def test_unexpected_exceptions_still_end_in_json(fake, capsys, monkeypatch):
    monkeypatch.setitem(cli.COMMANDS, "version", lambda *a: 1 / 0)
    code, out, err = run(capsys, ["-H", "alpha", "version"])
    assert code == EXIT_ERROR and json.loads(out)["error"]["kind"] == "internal" and "ZeroDivisionError" in err


def test_guard_flag_with_a_stale_plan_id_does_nothing(fake, capsys):
    argv = ["-H", "alpha", "send", "--text", "ls", "--enter"]
    _, out, _ = run(capsys, argv)
    plan = json.loads(out)["plan_id"]
    code, out, _ = run(capsys, [*argv, f"--yes-i-am-authorised={'0' * 12}"])
    assert code == EXIT_DRY_RUN and "changed" in json.loads(out)["note"] and writes(fake) == []
    code, _, _ = run(capsys, [*argv, f"--yes-i-am-authorised={plan}"])
    assert code == EXIT_OK and writes(fake)


def test_secret_file_is_typed_but_never_printed(fake, capsys, tmp_path):
    secret = tmp_path / "pw"
    secret.write_text("hunter2\n")
    argv = ["-H", "alpha", "send", "--secret-file", str(secret), "--enter"]
    _, out, _ = run(capsys, argv)
    assert json.loads(out)["input"] == {"hidden": True, "bytes": len("hunter2\r")}
    secret.write_text("hunter3\n")
    _, other, _ = run(capsys, argv)
    assert json.loads(other)["plan_id"] == json.loads(out)["plan_id"]  # the plan says nothing about the contents
    secret.write_text("hunter2\n")
    code, out, err = run(capsys, [*argv, "--yes-i-am-authorised"])
    assert code == EXIT_OK and "hunter2" not in out + err
    assert [c[1]["args"]["data"] for c in writes(fake)] == ["hunter2\r"]


def test_scrub_hides_any_key_that_names_a_secret():
    assert scrub({"api_token": "a", "client_secret": "b", "Password": "c", "label": "d"}) == {
        "api_token": "***",
        "client_secret": "***",
        "Password": "***",
        "label": "d",
    }


@pytest.mark.parametrize("url", ["https://user:pw@example.test", "http://example.test", "https://"])
def test_host_urls_must_be_plain_https(url):
    with pytest.raises(UsageError):
        require_https(url)


def test_ls_session_accepts_the_same_names_as_other_commands(fake, capsys):
    label = fake.sessions[0]["label"]
    code, out, _ = run(capsys, ["-H", "alpha", "ls", "--brief", "-s", label[:5]])
    assert code == EXIT_OK and [s["label"] for s in json.loads(out)["sessions"]] == [label]


def test_target_block_part_is_refused_where_no_block_applies(fake, capsys):
    code, _, _ = run(capsys, ["-H", "alpha", "layout", "set-session-label", "--label", "x", "-t", "s//b"])
    assert code == EXIT_USAGE


class BlobConn(FakeConn):
    def __init__(self, error_code):
        super().__init__()
        self.error_code = error_code
        self.offsets = []

    def block_call(self, method, session_id, block_id, args=None, timeout=None):
        self.offsets.append(args["offset"])
        if len(self.offsets) == 1:
            raise ApiError("nope", code=self.error_code)
        return {"data": "tail"}


def test_blob_tail_steps_over_a_split_character_but_not_other_errors():
    t = Target("h", "https://x.test", "session:1", "block:1")
    conn = BlobConn("bad_request")
    assert read_blob_tail(conn, t, 1, 100, 20) == "tail" and conn.offsets == [90, 91]
    with pytest.raises(ApiError):
        read_blob_tail(BlobConn("not_found"), t, 1, 100, 20)


def test_an_approved_admin_plan_without_the_second_flag_says_so(fake, capsys):
    _, out, _ = run(capsys, ["-H", "beta", "api", "call", "server.stop", "{}"])
    pid = json.loads(out)["plan_id"]
    code, out, _ = run(capsys, ["-H", "beta", "api", "call", "server.stop", "{}", f"--yes-i-am-authorised={pid}"])
    assert code == EXIT_DRY_RUN and "--allow-server-admin" in json.loads(out)["note"]
    assert "plan changed" not in json.loads(out)["note"]
