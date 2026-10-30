import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from live_helpers import (  # noqa: E402
    LIVE_HOST,
    MCP_HOST,
    destroy_selftest_sessions,
    live_url,
    mcp_env,
    throwaway_session,
)
from rexctl import connection  # noqa: E402
from rexctl.errors import EXIT_API_ERROR, EXIT_DRY_RUN  # noqa: E402
from rexctl.events import resilient_event  # noqa: E402
from rexctl.protocol import TERMINAL  # noqa: E402
from rexctl.stream import open_feed  # noqa: E402
from rexctl.target import resolve_target  # noqa: E402

pytestmark = pytest.mark.live
HOSTS = [LIVE_HOST]
CLI = [sys.executable, "-m", "rexctl"]


def rexctl_run(*args, env=None, timeout=90):
    proc = subprocess.run([*CLI, *args], cwd=ROOT, capture_output=True, text=True, timeout=timeout, env=env)
    return proc.returncode, proc.stdout, proc.stderr


def body(stdout):
    return json.loads(stdout.strip().splitlines()[-1])


def start(*args):
    return subprocess.Popen(
        [*CLI, "--no-daemon", "-H", LIVE_HOST, *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def finish(proc, timeout=60):
    out, err = proc.communicate(timeout=timeout)
    return proc.returncode, out, err


def send(sid, bid, text):
    code, out, _ = rexctl_run(
        "--no-daemon", "-H", LIVE_HOST, "send", "-s", sid, "-b", bid, "--text", text, "--enter", "--yes-i-am-authorised"
    )
    assert code == 0, out


READ_ONLY = [
    ["conn", "list-blocks"],
    ["conn", "list-clients"],
    ["admin", "block-creators"],
    ["admin", "keymap"],
    ["admin", "server-status"],
    ["admin", "hosts-list"],
    ["admin", "client-list"],
    ["term", "modes"],
    ["term", "input-mode"],
    ["term", "size"],
    ["conn", "describe-block"],
    ["target", "complete", "--prefix", "1"],
]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("argv", READ_ONLY, ids=lambda a: "-".join(a[:2]))
def test_read_only_wrappers_on_both_hosts(host, argv):
    code, out, _ = rexctl_run("--no-daemon", "-H", host, *argv)
    assert code == 0 and body(out)["ok"] is True, out


@pytest.mark.parametrize("host", HOSTS)
def test_local_only_method_is_a_clear_403_on_both_hosts(host):
    code, out, _ = rexctl_run("--no-daemon", "-H", host, "admin", "privacy-status")
    assert code == EXIT_API_ERROR and body(out)["error"]["kind"] == "local_only"


@pytest.mark.parametrize("host", HOSTS)
def test_events_stream_delivers_on_both_hosts(host):
    code, out, err = rexctl_run(
        "--no-daemon",
        "-H",
        host,
        "events",
        "--duration",
        "6",
        "--scope",
        "all",
        "--max-events",
        "1",
        "--filter",
        "client_joined,client_left,session_view_changed,active_window_changed,size_changed",
    )
    assert code == 0 and "events" in err


def test_event_waits_fire_on_throwaway_session():
    with throwaway_session() as (label, sid, bid):
        t = ["-s", sid, "-b", bid, "--wait-timeout", "40"]
        waits = {
            "bell": start("wait-for", *t, "--bell"),
            "title": start("wait-for", *t, "--title-changed", "rexctl-t"),
            "status": start("wait-for", *t, "--status", "blocked"),
            "cwd": start("wait-for", *t, "--cwd-changed"),
            "where": start("wait-for", *t, "--event", "program_status_changed", "--where", "record.state=blocked"),
            "text": start("wait-for", *t, "--text", "MARK-4[2]"),
        }
        events = start("events", "--duration", "25", "-s", sid, "--filter", "bell,title,status,cwd")
        time.sleep(6)
        send(
            sid,
            bid,
            r"printf '\a\033]0;rexctl-t1\007\033]7;file://localhost/private/tmp\007\033]7501;state=blocked\007';"
            r" echo MARK-$((40+2))",
        )
        results = {name: finish(p) for name, p in waits.items()}
        for name, (code, out, _) in results.items():
            assert code == 0 and body(out)["matched"] is True, (name, out)
        assert body(results["text"][1])["via"] == "stream"
        assert all(body(results[n][1])["via"] == "events" for n in ("bell", "title", "status", "cwd", "where"))
        _, out, _ = finish(events)
        names = {json.loads(line)["name"] for line in out.splitlines()}
        assert {"bell", "title_changed", "pwd_changed", "program_status_changed"} <= names
        closed = start("wait-for", "-s", sid, "-b", bid, "--closed", "--wait-timeout", "40")
        time.sleep(5)
        code, out, _ = rexctl_run("--no-daemon", "-H", LIVE_HOST, "kill", "-s", sid, "-b", bid, "--yes-i-am-authorised")
        assert code == 0, out
        code, out, _ = finish(closed)
        assert code == 0 and body(out)["closed"] is True and body(out)["via"] == "events"


def test_stream_and_poll_fallbacks_on_throwaway_session():
    with throwaway_session() as (label, sid, bid):
        streamer = start("stream", "-s", sid, "-b", bid, "--duration", "15", "--text")
        time.sleep(5)
        send(sid, bid, "echo STREAM-$((6*7))")
        code, out, _ = finish(streamer)
        assert code == 0 and "STREAM-42" in out
        for extra in (["--text", "STREAM-42"], ["--idle", "2"]):
            code, out, _ = rexctl_run(
                "--no-daemon",
                "-H",
                LIVE_HOST,
                "wait-for",
                "-s",
                sid,
                "-b",
                bid,
                *extra,
                "--no-stream",
                "--wait-timeout",
                "20",
            )
            assert code == 0 and body(out)["via"] == "poll", out


def test_control_reconnect_resumes_with_token_and_keeps_scope():
    with connection.connect(live_url()) as conn:
        conn.call("session.attach_all", {"event_scope": "all"})
        conn.ws.sock.shutdown(__import__("socket").SHUT_RDWR)
        got = resilient_event(conn, 2.0)
        assert got == ("reconnected", True)
        assert conn.call("server.version")["api_revision"] >= 7


def test_data_stream_resumes_after_drop_on_throwaway_session():
    with throwaway_session() as (label, sid, bid):
        with connection.connect(live_url()) as conn:
            t = resolve_target(conn, LIVE_HOST, live_url(), sid, bid)
            feed = open_feed(conn, live_url(), t, 10)
            try:
                feed.poll(2.0)
                feed.stream.ws.sock.shutdown(__import__("socket").SHUT_RDWR)
                conn.block_call(f"{TERMINAL}.write", sid, bid, {"data": "echo RESUMED-$((1+1))\r"})
                seen = ""
                deadline = time.monotonic() + 25
                while "RESUMED-2" not in seen and time.monotonic() < deadline and not feed.ended:
                    items = feed.poll(1.0)
                    if any(i["kind"] == "gap" for i in items):
                        conn.block_call(f"{TERMINAL}.write", sid, bid, {"data": "echo RESUMED-$((1+1))\r"})
                    seen += "".join(i.get("text", "") for i in items if i["kind"] == "output")
                assert "RESUMED-2" in seen, (feed.ended, seen[-300:])
            finally:
                feed.close(sid)


def lay(sid, *args):
    code, out, _ = rexctl_run("--no-daemon", "-H", LIVE_HOST, "layout", *args, "-s", sid, "--yes-i-am-authorised")
    assert code == 0, (args, out)
    return body(out)


def view(sid):
    code, out, _ = rexctl_run(
        "--no-daemon", "-H", LIVE_HOST, "api", "call", "session.view", json.dumps({"session_id": sid})
    )
    return body(out)["result"]


def test_remaining_layout_conn_and_input_ops_on_throwaway_session():
    with throwaway_session() as (label, sid, bid):
        code, out, _ = rexctl_run(
            "--no-daemon",
            "-H",
            LIVE_HOST,
            "split",
            "-s",
            sid,
            "-b",
            bid,
            "--direction",
            "horizontal",
            "--yes-i-am-authorised",
        )
        assert code == 0, out
        blocks = [b["block_id"] for w in view(sid)["windows"] for layer in w["layers"] for b in layer["blocks"]]
        other = [b for b in blocks if b != bid][0]
        lay(
            sid,
            "resize-pane",
            "--direction",
            "horizontal",
            "--before-block",
            bid,
            "--after-block",
            other,
            "--ratio",
            "0.3",
        )
        lay(sid, "focus-block", "-b", bid)
        lay(sid, "focus-direction", "--direction", "right", "--wrap")
        lay(sid, "focus-next-pane", "--wrap")
        lay(sid, "focus-previous-pane", "--wrap")
        lay(sid, "new-window", "--window-label", "w2")
        lay(sid, "move-window", "-w", "w2", "--before-window", "1")
        lay(sid, "focus-previous-window", "--wrap")
        lay(sid, "move-block", "-b", other, "--anchor-block", bid, "--direction", "vertical", "--side", "after")
        made = lay(sid, "new-block", "--label", "detached")["result"]
        assert made
        code, out, _ = rexctl_run(
            "--no-daemon", "-H", LIVE_HOST, "conn", "detach-block", "-s", sid, "-b", other, "--yes-i-am-authorised"
        )
        assert code == 0, out
        placed = [b["block_id"] for w in view(sid)["windows"] for layer in w["layers"] for b in layer["blocks"]]
        assert other not in placed
        for argv in (["input", "focus", "--action", "out"], ["input", "focus", "--action", "in"], ["term", "reset"]):
            code, out, _ = rexctl_run(
                "--no-daemon", "-H", LIVE_HOST, *argv, "-s", sid, "-b", bid, "--yes-i-am-authorised"
            )
            assert code == 0, (argv, out)
        for argv in (["conn", "attach"], ["conn", "detach"], ["conn", "session-help"]):
            code, out, _ = rexctl_run("--no-daemon", "-H", LIVE_HOST, *argv, "-s", sid)
            assert code == 0, (argv, out)
        code, out, _ = rexctl_run("--no-daemon", "-H", LIVE_HOST, "layout", "move-session", "-s", sid)
        assert code == EXIT_DRY_RUN


def test_daemon_socket_is_private_and_used_then_stops():
    cache = tempfile.mkdtemp(prefix="rxd", dir="/tmp")
    env = {**os.environ, "REXCTL_CACHE_DIR": cache}
    env.pop("REXCTL_NO_DAEMON", None)
    try:
        assert rexctl_run("daemon", "start", env=env)[0] == 0
        sock = Path(cache) / "rexctl.sock"
        assert stat.S_IMODE(sock.stat().st_mode) == 0o600 and stat.S_IMODE(Path(cache).stat().st_mode) == 0o700
        assert rexctl_run("-H", LIVE_HOST, "ls", "--brief", env=env)[0] == 0
        began = time.monotonic()
        assert rexctl_run("-H", LIVE_HOST, "ls", "--brief", env=env)[0] == 0
        warm = time.monotonic() - began
        began = time.monotonic()
        assert rexctl_run("--no-daemon", "-H", LIVE_HOST, "ls", "--brief", env=env)[0] == 0
        assert warm < time.monotonic() - began
        status = body(rexctl_run("daemon", "status", env=env)[1])
        assert [u["url"] for u in status["upstreams"]] == [live_url()]
    finally:
        rexctl_run("daemon", "stop", env=env)
    assert not body(rexctl_run("daemon", "status", env=env)[1])["running"]
    assert not (Path(cache) / "rexctl.sock").exists()


def mcp(requests, tmp_dir):
    lines = [json.dumps({"jsonrpc": "2.0", "id": i, **r}) for i, r in enumerate(requests, 1)]
    proc = subprocess.run(
        [*CLI, "mcp"],
        cwd=ROOT,
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
        timeout=180,
        env=mcp_env(tmp_dir),
    )
    return {reply["id"]: reply for reply in map(json.loads, proc.stdout.splitlines())}


def call(name, **arguments):
    return {"method": "tools/call", "params": {"name": name, "arguments": arguments}}


def test_mcp_stdio_session_reads_and_dry_runs_writes(tmp_path):
    host = MCP_HOST
    replies = mcp(
        [
            {
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}},
            },
            {"method": "tools/list"},
            call("rex_ls", host=host),
            call("rex_send", host=host, text="never typed", enter=True),
            call("rex_server_info", host=host, verb="keymap"),
            call("rex_op", host=host, group="layout", verb="focus-next-pane"),
        ],
        tmp_path,
    )
    assert replies[1]["result"]["serverInfo"]
    names = {t["name"] for t in replies[2]["result"]["tools"]}
    assert {"rex_ls", "rex_send", "rex_op", "rex_events_since"} <= names
    assert json.loads(replies[3]["result"]["content"][0]["text"])["ok"] is True
    for i in (4, 6):
        assert json.loads(replies[i]["result"]["content"][0]["text"])["dry_run"] is True
    assert not replies[5]["result"].get("isError")


def test_no_selftest_sessions_left_on_either_host():
    destroy_selftest_sessions()
    for host in HOSTS:
        code, out, _ = rexctl_run("--no-daemon", "-H", host, "ls", "--brief")
        assert code == 0 and not [s for s in body(out)["sessions"] if s["label"].startswith("rexctl-selftest-")]
