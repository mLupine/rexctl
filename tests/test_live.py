import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from live_helpers import LIVE_HOST  # noqa: E402

HOSTS = [LIVE_HOST]
pytestmark = pytest.mark.live


def rexctl(*args):
    proc = subprocess.run([sys.executable, "-m", "rexctl", *args], cwd=ROOT, capture_output=True, text=True, timeout=90)
    return proc.returncode, json.loads(proc.stdout) if proc.stdout.strip().startswith("{") else proc.stdout


@pytest.mark.parametrize("host", HOSTS)
def test_version_and_identity(host):
    code, body = rexctl("-H", host, "version")
    assert code == 0 and body["server"]["api_revision"] >= 7
    assert body["whoami"]["principal"]["kind"]


@pytest.mark.parametrize("host", HOSTS)
def test_ls_has_terminals(host):
    code, body = rexctl("-H", host, "ls", "--brief")
    blocks = [b for s in body["sessions"] for w in s["windows"] for b in w["blocks"]]
    assert code == 0 and blocks


@pytest.mark.parametrize("host", HOSTS)
def test_screen_read_of_first_block(host):
    _, ls = rexctl("-H", host, "ls", "--brief")
    session = ls["sessions"][0]
    block = session["windows"][0]["blocks"][0]
    code, body = rexctl("-H", host, "screen", "-s", session["session_id"], "-b", block["block_id"], "--lines", "5")
    assert code == 0 and body["lines"] <= 5


@pytest.mark.parametrize("host", HOSTS)
def test_api_list_matches_help(host):
    code, body = rexctl("-H", host, "api", "list")
    names = {m["name"] for m in body["methods"]}
    assert code == 0 and "session.view" in names and "com.superlogical.terminal.format" in names


def selftest(*args):
    sys.path.insert(0, str(ROOT / "tests"))
    from live_helpers import throwaway_session

    return throwaway_session()


def run_ok(*args):
    code, body = rexctl("-H", LIVE_HOST, *args, "--yes-i-am-authorised")
    assert code == 0, (args, body)
    return body


def lay(sid, verb, *args):
    return run_ok("layout", verb, "-s", sid, *args)


def view_of(session_id):
    code, body = rexctl("-H", LIVE_HOST, "api", "call", "session.view", json.dumps({"session_id": session_id}))
    assert code == 0, body
    return body["result"]


def test_layout_lifecycle_on_throwaway_session():
    with selftest() as (label, sid, bid):
        lay(sid, "new-window", "--window-label", "second")
        assert len(view_of(sid)["windows"]) == 2
        lay(sid, "set-window-label", "-w", "second", "--label", "renamed")
        run_ok("split", "-s", sid, "-b", bid, "--direction", "horizontal")
        blocks = [b["block_id"] for w in view_of(sid)["windows"] for layer in w["layers"] for b in layer["blocks"]]
        assert len(blocks) == 3
        lay(sid, "set-block-label", "-b", bid, "--label", "mine")
        lay(sid, "swap-blocks", "-b", "mine", "--other-block", [b for b in blocks if b != bid][0])
        lay(sid, "float-block", "-b", "mine", "--bounds", "0.2,0.2,0.5,0.5")
        layers = [layer for w in view_of(sid)["windows"] for layer in w["layers"] if layer["kind"] != "tiled"]
        assert len(layers) == 1
        lid = layers[0]["layer_id"]
        lay(sid, "resize-layer", "--layer", lid, "--bounds", "0.1,0.1,0.6,0.6")
        lay(sid, "lower-layer", "--layer", lid)
        lay(sid, "raise-layer", "--layer", lid)
        lay(sid, "zoom-block", "-b", "mine", "--zoom")
        lay(sid, "zoom-block", "-b", "mine", "--no-zoom")
        lay(sid, "focus-next-window", "--wrap")
        lay(sid, "focus-window", "-w", "renamed")
        lay(sid, "new-layer", "--bounds", "0.5,0.5,0.4,0.4")
        lay(sid, "close-layer", "--layer", lid)
        lay(sid, "close-window", "-w", "renamed")
        lay(sid, "set-session-label", "--label", label)
        assert len(view_of(sid)["windows"]) == 1
    code, ls = rexctl("-H", LIVE_HOST, "ls", "--brief")
    assert not [s for s in ls["sessions"] if s["label"].startswith("rexctl-selftest-")]


def screen_text(sid, bid):
    code, out = rexctl("-H", LIVE_HOST, "screen", "-s", sid, "-b", bid, "--lines", "40")
    assert code == 0
    return out["content"]


def wait_screen(sid, bid, needle, timeout=10.0):

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if needle in screen_text(sid, bid):
            return True
        time.sleep(0.4)
    return False


def test_input_keys_paste_and_split_on_throwaway_session():
    with selftest() as (label, sid, bid):
        run_ok("input", "key", "-s", sid, "-b", bid, "--keys", "e c h o Space k 1 Enter")
        assert wait_screen(sid, bid, "\nk1\n") or wait_screen(sid, bid, "k1")
        run_ok("input", "key", "-s", sid, "-b", bid, "--via", "client-key", "--keys", "e c h o Space k 2 Enter")
        assert wait_screen(sid, bid, "k2")
        run_ok("input", "paste", "-s", sid, "-b", bid, "--text", "echo k3\n")
        assert wait_screen(sid, bid, "k3")
        # SIGINT ends sleep with status 130. Retry in case C-c lands while the slow shell is still reading the line.
        for attempt in range(3):
            run_ok("send", "-s", sid, "-b", bid, "--text", "sleep 60", "--enter")
            time.sleep(3)
            run_ok("send", "-s", sid, "-b", bid, "--keys", "C-c")
            run_ok("send", "-s", sid, "-b", bid, "--text", f"echo rc{attempt}-$?", "--enter")
            if wait_screen(sid, bid, f"rc{attempt}-130", timeout=15):
                break
        else:
            pytest.fail("C-c never interrupted the foreground command:\n" + screen_text(sid, bid))
        before = len([b for w in view_of(sid)["windows"] for layer in w["layers"] for b in layer["blocks"]])
        run_ok("split", "-s", sid, "-b", bid, "--direction", "vertical")
        after = len([b for w in view_of(sid)["windows"] for layer in w["layers"] for b in layer["blocks"]])
        assert after == before + 1


def read_ok(*args):
    code, body = rexctl("-H", LIVE_HOST, *args)
    assert code == 0, (args, body)
    return body["result"]


def poll_clipboard(t, timeout=15.0):

    deadline = time.monotonic() + timeout
    while True:
        code, body = rexctl("-H", LIVE_HOST, "term", "clipboard-read", *t)
        if code == 0 or time.monotonic() > deadline:
            assert code == 0, body
            return body["result"]
        time.sleep(0.5)


def test_term_methods_on_throwaway_session():
    with selftest() as (label, sid, bid):
        t = ["-s", sid, "-b", bid]
        assert "screen" in read_ok("term", "modes", *t)
        assert set(read_ok("term", "input-mode", *t)) >= {"echo", "canonical", "signals"}
        assert read_ok("term", "list-dir", *t, "--path", "/tmp", "--limit", "2")["status"] == "ok"
        run_ok("term", "resize", *t, "--columns", "90", "--rows", "25")
        run_ok("term", "set-theme", *t, "--scheme", "dark")
        run_ok("term", "clear", *t)
        run_ok("send", *t, "--text", "printf '\\033]52;c;aGVsbG8=\\007'", "--keys", "Enter")
        clip = poll_clipboard(t)
        assert clip["data"].startswith("<redacted") and clip["total"] == 5
        assert read_ok("term", "clipboard-read", *t, "--show")["data"] == "hello"


def test_target_spec_attach_and_ownership_on_throwaway_session():
    with selftest() as (label, sid, bid):
        spec = f"{label}/1/{bid}"
        out = read_ok("conn", "describe-block", "-t", spec)
        assert out["block"]["block_id"] == bid
        lay(sid, "set-block-label", "-b", bid, "--label", "mine")
        code, sized = rexctl("-H", LIVE_HOST, "term", "size", "-t", f"{label}/1/mine")
        assert code == 0 and sized["target"]["block_id"] == bid
        resolved = read_ok(
            "target", "resolve", "--kinds", "window,block", "--queries", "1,mine", "--scope-session", sid
        )
        assert [r["status"] for r in resolved["results"]] == ["resolved", "resolved"]
        owned = run_ok("conn", "own-block", "-s", sid, "--blocks", bid, "--yes-i-am-authorised")["result"]["blocks"]
        assert owned[0]["block_id"] == bid and owned[0]["owner"]
        run_ok("conn", "disown-block", "-s", sid, "--yes-i-am-authorised")
        dry = rexctl("-H", LIVE_HOST, "conn", "detach-block", "-s", sid, "-b", bid)
        assert dry[0] == 10


def mcp_session(requests, tmp_dir):
    import subprocess as sp

    from live_helpers import mcp_env

    lines = [json.dumps({"jsonrpc": "2.0", "id": i, **r}) for i, r in enumerate(requests, 1)]
    proc = sp.run(
        [sys.executable, "-m", "rexctl", "mcp"],
        cwd=ROOT,
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
        timeout=240,
        env=mcp_env(tmp_dir),
    )
    return [json.loads(line) for line in proc.stdout.splitlines()]


def tool(name, **arguments):
    return {"method": "tools/call", "params": {"name": name, "arguments": arguments}}


def tool_body(reply):
    return json.loads(reply["result"]["content"][0]["text"])


def test_mcp_roundtrip_on_throwaway_session(tmp_path):
    import secrets

    sys.path.insert(0, str(ROOT / "tests"))
    from live_helpers import destroy_selftest_sessions

    label = "rexctl-selftest-" + secrets.token_hex(3)
    try:
        new = {"host": "live", "label": label, "cwd": "/tmp"}
        dry = tool_body(mcp_session([tool("rex_new_session", **new)], tmp_path)[0])
        assert dry["dry_run"] is True
        (made,) = mcp_session([tool("rex_new_session", **new, confirm=dry["plan_id"])], tmp_path)
        assert tool_body(made)["ok"] is True and "dry_run" not in tool_body(made)
        send = {"host": "live", "target": label, "text": "echo mcp-$((20+22))", "enter": True}
        plan = tool_body(mcp_session([tool("rex_send", **send)], tmp_path)[0])["plan_id"]
        replies = mcp_session(
            [
                tool("rex_events_since", host="live"),
                tool("rex_send", **send, confirm=plan),
                tool("rex_wait_for", host="live", target=label, text="mcp-42", timeout=40),
                tool("rex_tail", host="live", target=label, lines=5),
                tool("rex_status", host="live", target=label, fact="pwd"),
                tool("rex_op", host="live", group="term", verb="size", args=["-t", label]),
            ],
            tmp_path,
        )
        assert tool_body(replies[1])["ok"] is True and "dry_run" not in tool_body(replies[1])
        assert tool_body(replies[2])["ok"] is True
        assert "mcp-42" in tool_body(replies[3])["content"]
        assert tool_body(replies[5])["ok"] is True
    finally:
        destroy_selftest_sessions()
    code, ls = rexctl("-H", LIVE_HOST, "ls", "--brief")
    assert not [s for s in ls["sessions"] if s["label"].startswith("rexctl-selftest-")]
