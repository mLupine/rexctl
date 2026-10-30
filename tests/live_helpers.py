import json
import os
import secrets
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from rexctl import connection  # noqa: E402
from rexctl.inputs import shell_layout  # noqa: E402

LIVE_HOST = os.environ.get("REXCTL_LIVE_URL", "")
LABEL_PREFIX = "rexctl-selftest-"


MCP_HOST = "live"  # MCP takes only labels from the hosts file


def live_url() -> str:
    return LIVE_HOST


def mcp_env(tmp_dir: Path) -> dict[str, str]:
    """Environment for an MCP subprocess whose hosts file names the live server as MCP_HOST."""
    hosts = tmp_dir / "live-hosts.json"
    hosts.write_text(json.dumps({MCP_HOST: LIVE_HOST}))
    return {**os.environ, "REXCTL_HOSTS": str(hosts)}


def selftest_sessions(conn: "connection.Connection") -> list[dict]:
    sessions = conn.call("session.attach_all", {"event_scope": "session"})["sessions"] or []
    return [s for s in sessions if s["label"].startswith(LABEL_PREFIX)]


def destroy_selftest_sessions() -> int:
    with connection.connect(live_url()) as conn:
        found = selftest_sessions(conn)
        for session in found:
            conn.call("session.destroy", {"session_id": session["session_id"]})
        leftover = selftest_sessions(conn)
    if leftover:
        raise RuntimeError(f"throwaway sessions still present: {leftover}")
    return len(found)


def wait_for_prompt(session_id: str, block_id: str) -> None:
    """Keys sent while the shell is still starting are lost, so wait until its startup output goes quiet."""
    target = ["-H", live_url(), "wait-for", "-s", session_id, "-b", block_id]
    argv = [sys.executable, "-m", "rexctl", "--no-daemon", *target, "--idle", "2", "--wait-timeout", "40"]
    subprocess.run(argv, capture_output=True, timeout=60, check=True)


@contextmanager
def throwaway_session() -> Iterator[tuple[str, str, str]]:
    label = LABEL_PREFIX + secrets.token_hex(3)
    session_id = ""
    try:
        with connection.connect(live_url()) as conn:
            created = conn.call(
                "session.create", {"label": label, "initial_windows": [{"layout": shell_layout(None, "/tmp")}]}
            )
            session_id = created["session_id"]
            block_id = created["initial_windows"][0]["block_ids"][0]
        wait_for_prompt(session_id, block_id)
        yield label, session_id, block_id
    finally:
        destroy_selftest_sessions()


if __name__ == "__main__":
    print(f"destroyed {destroy_selftest_sessions()} throwaway session(s)")
