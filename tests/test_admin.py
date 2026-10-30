import json

import pytest

from rexctl import connection
from rexctl.errors import EXIT_DRY_RUN, EXIT_NOT_FOUND, EXIT_USAGE
from rexctl.flags import ADMIN_FLAG, GUARD_FLAG
from test_cli import FakeConn, run

BOTH = [GUARD_FLAG, ADMIN_FLAG]


class AdminConn(FakeConn):
    def call(self, method, payload=None, timeout=None):
        if method == "client.list":
            self.calls.append((method, payload))
            return {
                "clients": [
                    {"client_id": "client:abc", "info": {"label": "studio", "kind": "app"}},
                    {"client_id": "client:def", "label": ""},
                ]
            }
        return super().call(method, payload, timeout)


@pytest.fixture
def fake(monkeypatch):
    conn = AdminConn()
    monkeypatch.setattr(connection, "connect", lambda url, timeout=10.0: conn)
    return conn


def calls(conn, method):
    return [c for c in conn.calls if c[0] == method]


MUTATING = [
    (["server-config-reload"], "server.config_reload", {}),
    (["server-stop", "--if-idle"], "server.stop", {"if_idle": True}),
    (
        ["tailscale-enable", "--no-allow-tailnet-members", "--hostname", "box"],
        "server.tailscale.enable",
        {"allow_tailnet_members": False, "hostname": "box"},
    ),
    (["tailscale-disable"], "server.tailscale.disable", {}),
    (["tailscale-login"], "server.tailscale.login", {}),
    (["tailscale-logout"], "server.tailscale.logout", {}),
    (["tailscale-rename", "--hostname", "new-name"], "server.tailscale.rename", {"hostname": "new-name"}),
    (
        ["hosts-put", "--label", "studio", "--endpoints", "a.ts.net,b.ts.net"],
        "hosts.put",
        {"host": {"label": "studio", "endpoints": ["a.ts.net", "b.ts.net"]}},
    ),
    (["hosts-remove", "--id", "host:1"], "hosts.remove", {"id": "host:1"}),
    (["client-set-label", "--label", "agent"], "client.set_label", {"label": "agent"}),
    (
        ["client-perform", "--client", "studio", "--action", "pane.split", "--args", '{"direction":"right"}'],
        "client.perform",
        {"client_id": "client:abc", "action": "pane.split", "args": {"direction": "right"}},
    ),
    (
        ["client-action", "--action", "dev_layout", "--origin", "api"],
        "client.action",
        {"action": "dev_layout", "origin": "api"},
    ),
]


@pytest.mark.parametrize("argv,method,payload", MUTATING, ids=[m[1] for m in MUTATING])
def test_admin_mutations_need_both_flags(fake, capsys, argv, method, payload):
    for extra in ([], [GUARD_FLAG], [ADMIN_FLAG]):
        code, out, _ = run(capsys, ["-H", "alpha", "admin", *argv, *extra])
        plan = json.loads(out)
        assert (
            code == EXIT_DRY_RUN and plan["dry_run"] is True and plan["method"] == method and plan["payload"] == payload
        )
        assert ADMIN_FLAG in plan["note"] and calls(fake, method) == []
    code, out, err = run(capsys, ["-H", "alpha", "admin", *argv, *BOTH])
    assert code == 0 and "EXECUTING" in err and [c[1] for c in calls(fake, method)] == [payload]


@pytest.mark.parametrize(
    "argv,method",
    [
        (["server-stop"], "server.stop"),
        (["tailscale-disable"], "server.tailscale.disable"),
        (["tailscale-logout"], "server.tailscale.logout"),
        (["hosts-remove", "--id", "x"], "hosts.remove"),
    ],
)
def test_dangerous_admin_ops_warn_in_plan_and_on_execute(fake, capsys, argv, method):
    _, out, _ = run(capsys, ["-H", "alpha", "admin", *argv])
    assert json.loads(out)["warning"]
    _, _, err = run(capsys, ["-H", "alpha", "admin", *argv, *BOTH])
    assert "WARNING" in err


def test_dry_run_does_not_even_connect_for_plain_server_ops(monkeypatch, capsys):
    monkeypatch.setattr(connection, "connect", lambda *a, **k: pytest.fail("connected during dry run"))
    code, _, _ = run(capsys, ["-H", "alpha", "admin", "server-stop"])
    assert code == EXIT_DRY_RUN


def test_auth_key_is_read_from_file_and_never_printed(fake, capsys, tmp_path):
    key = tmp_path / "key"
    key.write_text("tskey-auth-SECRET123\n")
    argv = ["-H", "alpha", "admin", "tailscale-enable", "--allow-tailnet-members", "--auth-key-file", str(key)]
    code, out, err = run(capsys, argv)
    assert code == EXIT_DRY_RUN and "SECRET123" not in out + err and json.loads(out)["payload"]["auth_key"] == "***"
    code, out, err = run(capsys, [*argv, *BOTH])
    assert code == 0 and "SECRET123" not in out + err
    assert calls(fake, "server.tailscale.enable")[0][1]["auth_key"] == "tskey-auth-SECRET123"


def test_tailscale_enable_requires_explicit_tailnet_choice(fake, capsys):
    code, _, _ = run(capsys, ["-H", "alpha", "admin", "tailscale-enable", *BOTH])
    assert code == EXIT_USAGE and calls(fake, "server.tailscale.enable") == []


def test_missing_secret_file_is_usage_error(fake, capsys):
    code, _, _ = run(
        capsys,
        ["-H", "alpha", "admin", "tailscale-enable", "--allow-tailnet-members", "--auth-key-file", "/nonexistent/key"],
    )
    assert code == EXIT_USAGE


@pytest.mark.parametrize(
    "argv,method",
    [
        (["server-status"], "server.status"),
        (["hosts-list"], "hosts.list"),
        (["client-list"], "client.list"),
        (["privacy-status"], "server.apple.privacy_status"),
        (["client-inspect", "--client", "client:def"], "client.inspect"),
    ],
)
def test_read_only_admin_ops_need_no_flags(fake, capsys, argv, method):
    code, out, _ = run(capsys, ["-H", "alpha", "admin", *argv])
    assert code == 0 and json.loads(out)["ok"] is True and calls(fake, method)


def test_client_label_resolution_is_exact_or_ambiguous(fake, capsys):
    code, _, _ = run(capsys, ["-H", "alpha", "admin", "client-inspect", "--client", "nobody"])
    assert code == EXIT_NOT_FOUND


def test_local_only_methods_are_flagged_in_the_plan(fake, capsys):
    _, out, _ = run(capsys, ["-H", "alpha", "admin", "server-stop"])
    assert "Unix socket" in json.loads(out)["limit"]
    _, out, _ = run(capsys, ["-H", "alpha", "admin", "hosts-remove", "--id", "x"])
    assert "limit" not in json.loads(out)
