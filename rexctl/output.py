from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Callable
from typing import Any

from .flags import ADMIN_FLAG, GUARD_FLAG


def plan_id(plan: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(plan, sort_keys=True, default=str).encode()).hexdigest()[:12]


def guard(
    args: argparse.Namespace,
    action: str,
    target: dict[str, Any],
    detail: dict[str, Any],
    admin: bool = False,
    about: Callable[[], dict[str, Any]] | None = None,
) -> bool:
    """Run only with the guard flag, and when it names a plan id, only if this run's plan still has that id."""
    plan = {"action": action, "target": target, **detail}
    pid = plan_id(plan)
    approval = getattr(args, "yes_i_am_authorised", False)
    admin_ok = not admin or getattr(args, "allow_server_admin", False)
    if (approval is True or approval == pid) and admin_ok:
        eprint(
            f"rexctl: EXECUTING {action} plan={pid} on host={target.get('host')} session={target.get('session_id')} "
            f"block={target.get('block_id')}"
        )
        return True
    flags = f"{GUARD_FLAG}={pid}" + (f" {ADMIN_FLAG}" if admin else "")
    note = f"dry run: nothing was changed. After the user approved this exact action, re-run with {flags}."
    if approval == pid:
        note = f"plan {pid} is approved, but it also needs {ADMIN_FLAG}; nothing was changed."
    elif isinstance(approval, str):
        note = (
            f"plan changed since it was approved ({approval} -> {pid}), so nothing was changed. "
            f"Show this plan to the user; if they approve it, re-run with {flags}."
        )
    shown = {"about": about()} if about else {}  # not part of plan_id: a title change must not void an approval
    emit({"ok": True, "dry_run": True, "plan_id": pid, **plan, **shown, "note": note})
    return False


SECRET_WORDS = ("token", "ticket", "secret", "password", "passwd", "auth_key", "authkey")


def secret_key(key: str) -> bool:
    return any(word in key.lower() for word in SECRET_WORDS)


def scrub(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: "***" if secret_key(k) else scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


def emit(obj: Any) -> None:
    sys.stdout.write(json.dumps(scrub(obj), ensure_ascii=False) + "\n")
    sys.stdout.flush()


def eprint(message: str) -> None:
    sys.stderr.write(message + "\n")


def emit_text(result: dict[str, Any]) -> None:
    sys.stdout.write(result.get("content", "") + "\n")
