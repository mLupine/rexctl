import json

import pytest

from rexctl.errors import (
    EXIT_API_ERROR,
    EXIT_DENIED,
    EXIT_DRY_RUN,
    EXIT_ERROR,
    EXIT_NOT_FOUND,
    EXIT_OK,
    EXIT_TIMEOUT,
    EXIT_UNREACHABLE,
    EXIT_USAGE,
    AccessDeniedError,
    TargetNotFoundError,
    UsageError,
)
from rexctl.events import normalize_event
from rexctl.hosts import default_hosts_file, load_hosts, require_https, resolve_host
from rexctl.inputs import build_input, key_to_bytes, keys_to_data, parse_payload
from rexctl.read import root_status, trim_lines
from rexctl.target import match_one


def test_require_https_rejects_plain_http_and_ws():
    for url in ("http://x.ts.net", "ws://x.ts.net", "x.ts.net", "https://x.ts.net:abc"):
        with pytest.raises(UsageError):
            require_https(url)
    assert require_https("https://x.ts.net/path") == "https://x.ts.net"


def test_resolve_host_label_and_url():
    hosts = {"a": "https://a.ts.net"}
    assert resolve_host("a", hosts) == ("a", "https://a.ts.net")
    assert resolve_host("https://b.ts.net", hosts)[1] == "https://b.ts.net"
    with pytest.raises(UsageError):
        resolve_host("nope", hosts)


def test_hosts_come_only_from_the_hosts_file(tmp_path, monkeypatch):
    path = tmp_path / "hosts.json"
    path.write_text(json.dumps({"extra": "https://e.example.test"}))
    assert load_hosts(path) == {"extra": "https://e.example.test"}
    monkeypatch.delenv("REXCTL_HOSTS")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty"))
    assert load_hosts() == {}
    assert default_hosts_file() == tmp_path / "empty" / "rexctl" / "hosts.json"


def test_load_hosts_rejects_bad_json(tmp_path):
    path = tmp_path / "hosts.json"
    path.write_text("[1]")
    with pytest.raises(UsageError):
        load_hosts(path)


CANDIDATES = [("block:01a1-aaaa", "shell"), ("block:01a1-bbbb", "logs"), ("block:01a1-cccc", "shell")]


def test_match_one_by_suffix_label_and_exact():
    assert match_one("block", "bbbb", CANDIDATES) == "block:01a1-bbbb"
    assert match_one("block", "logs", CANDIDATES) == "block:01a1-bbbb"
    assert match_one("block", "block:01a1-cccc", CANDIDATES) == "block:01a1-cccc"


def test_match_one_ambiguous_and_missing():
    with pytest.raises(TargetNotFoundError):
        match_one("block", "shell", CANDIDATES)
    with pytest.raises(TargetNotFoundError):
        match_one("block", "zzz", CANDIDATES)


def test_trim_lines():
    assert trim_lines("a\nb\nc\n\n\n", 2) == "b\nc"
    assert trim_lines("a\nb\n   \n", None) == "a\nb"
    assert trim_lines("a\nb", 0) == ""


def test_keys():
    assert keys_to_data("ctrl-c") == "\x03"
    assert keys_to_data("up,enter") == "\x1b[A\r"
    with pytest.raises(UsageError):
        key_to_bytes("hyper-q")


def test_build_input():
    assert build_input("ls", True, None) == "ls\r"
    with pytest.raises(UsageError):
        build_input(None, False, None)


def test_parse_payload(tmp_path):
    assert parse_payload(None) == {}
    assert parse_payload('{"a":1}') == {"a": 1}
    path = tmp_path / "p.json"
    path.write_text('{"b":2}')
    assert parse_payload(f"@{path}") == {"b": 2}
    with pytest.raises(UsageError):
        parse_payload("[1]")


def test_normalize_event_unwraps_session_events():
    inner = {"type": "session_event", "payload": {"session_id": "s", "event": {"type": "block_created"}}}
    assert normalize_event({"payload": inner})["name"] == "block_created"
    assert normalize_event({"payload": {"type": "session_created"}})["name"] == "session_created"


def test_root_status_truncates_and_picks_latest():
    records = {
        "records": [{"state": "idle", "updated_at": "1"}, {"state": "done", "msg": "x" * 500, "updated_at": "2"}]
    }
    status = root_status(records)
    assert status["state"] == "done" and len(status["msg"]) == 203


def test_exit_codes_are_distinct():
    codes = [
        EXIT_OK,
        EXIT_ERROR,
        EXIT_USAGE,
        EXIT_UNREACHABLE,
        EXIT_DENIED,
        EXIT_API_ERROR,
        EXIT_NOT_FOUND,
        EXIT_TIMEOUT,
        EXIT_DRY_RUN,
    ]
    assert len(set(codes)) == len(codes)


def test_denied_error_serialises():
    err = AccessDeniedError("nope", status=403)
    body = err.to_dict()
    assert body["ok"] is False and body["error"]["kind"] == "access_denied" and err.exit_code == EXIT_DENIED
