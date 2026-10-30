import json

import pytest

from rexctl import cli, connection, daemon
from rexctl.errors import EXIT_API_ERROR, EXIT_DENIED, EXIT_DRY_RUN, EXIT_OK, EXIT_USAGE, ApiError, LocalOnlyError
from rexctl.ops import OPS
from rexctl.ws import WebSocket

URL = "https://fake.invalid"


def serve_with(fake_server, monkeypatch, handler, extra=None):
    server = fake_server(handler)
    server.welcome_extra = extra or {}
    monkeypatch.setattr(WebSocket, "connect", classmethod(lambda cls, *a, **k: WebSocket(server.client_sock)))
    return server


def run_wire(capsys, argv):
    code = cli.main(["--host", URL, *argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def refuse(status, message):
    return lambda msg, server: server.respond(msg, error={"code": "internal", "status": status, "message": message})


def test_local_only_403_is_a_clear_error(fake_server, monkeypatch, capsys):
    serve_with(fake_server, monkeypatch, refuse(403, "server.config_reload requires the local Unix socket"))
    code, out, _ = run_wire(capsys, ["admin", "server-config-reload", "--yes-i-am-authorised", "--allow-server-admin"])
    error = json.loads(out)["error"]
    assert (
        code == EXIT_API_ERROR and error["kind"] == "local_only" and "Unix socket" in error["message"] and error["hint"]
    )


def test_other_403_is_access_denied_exit_4(fake_server, monkeypatch, capsys):
    serve_with(fake_server, monkeypatch, refuse(403, "principal not allowed"))
    code, out, _ = run_wire(capsys, ["admin", "server-status"])
    error = json.loads(out)["error"]
    assert code == EXIT_DENIED and error["kind"] == "access_denied" and error["status"] == 403


def test_401_is_access_denied_too(fake_server, monkeypatch, capsys):
    serve_with(fake_server, monkeypatch, refuse(401, "unauthenticated"))
    assert run_wire(capsys, ["admin", "server-status"])[0] == EXIT_DENIED


def test_non_auth_errors_stay_api_errors(fake_server, monkeypatch, capsys):
    serve_with(fake_server, monkeypatch, refuse(400, "bad input"))
    assert run_wire(capsys, ["admin", "server-status"])[0] == EXIT_API_ERROR


def test_daemon_error_mapping_keeps_local_only_kind():
    exc = daemon.error_from_payload({"kind": "local_only", "message": "m", "status": 403})
    assert isinstance(exc, LocalOnlyError) and isinstance(exc, ApiError)


def test_mismatched_revision_warns_once_and_still_works(fake_server, monkeypatch, capsys):
    connection.WARNED_REVISIONS.clear()
    server = serve_with(fake_server, monkeypatch, lambda m, s: s.respond(m, {"ok": 1}), {"api_revision": 9})
    server.welcome_extra = {"api_revision": 9}
    code, out, err = run_wire(capsys, ["admin", "server-status"])
    assert code == EXIT_OK and "API revision 9" in err and "targets 7" in err
    connection.warn_on_revision(URL, 9)
    assert capsys.readouterr().err == ""


def test_matching_revision_is_silent(fake_server, monkeypatch, capsys):
    connection.WARNED_REVISIONS.clear()
    serve_with(fake_server, monkeypatch, lambda m, s: s.respond(m, {"ok": 1}))
    assert run_wire(capsys, ["admin", "server-status"])[2] == ""


def runnable_server_reads():
    return [
        op
        for op in OPS
        if op.scope == "server" and not op.mutating and not op.local_only and not any(p.required for p in op.params)
    ]


@pytest.mark.parametrize("op", runnable_server_reads(), ids=lambda op: f"{op.group}-{op.name}")
def test_every_server_read_op_sends_its_method_over_the_wire(op, fake_server, monkeypatch, capsys):
    server = serve_with(fake_server, monkeypatch, lambda m, s: s.respond(m, {"items": []}))
    code, out, _ = run_wire(capsys, [op.group, op.name])
    sent = [m["method"] for m in server.received if m["type"] == "request"]
    assert code == EXIT_OK and op.method in sent, out


def guarded_server_ops():
    return [op for op in OPS if op.scope == "server" and op.mutating and not any(p.required for p in op.params)]


@pytest.mark.parametrize("op", guarded_server_ops(), ids=lambda op: f"{op.group}-{op.name}")
def test_every_mutating_server_op_is_a_dry_run_without_flags(op, fake_server, monkeypatch, capsys):
    server = serve_with(fake_server, monkeypatch, lambda m, s: s.respond(m, {}))
    code, out, _ = run_wire(capsys, [op.group, op.name])
    assert code in (EXIT_DRY_RUN, EXIT_USAGE)
    assert not [m for m in server.received if m["type"] == "request"]


def test_admin_ops_with_only_the_first_flag_stay_dry_runs(fake_server, monkeypatch, capsys):
    server = serve_with(fake_server, monkeypatch, lambda m, s: s.respond(m, {}))
    for verb in ("server-stop", "server-config-reload"):
        code, out, _ = run_wire(capsys, ["admin", verb, "--yes-i-am-authorised"])
        assert code == EXIT_DRY_RUN and "--allow-server-admin" in out
    assert not [m for m in server.received if m["type"] == "request"]
