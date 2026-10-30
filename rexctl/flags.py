from __future__ import annotations

import argparse
import math
from typing import Any

from .errors import UsageError

GUARD_FLAG = "--yes-i-am-authorised"
ADMIN_FLAG = "--allow-server-admin"


def split_target_spec(spec: str) -> tuple[str | None, str | None, str | None]:
    parts = spec.split("/")
    if len(parts) > 3 or not any(parts):
        raise UsageError(
            f"bad --target {spec!r}; use SESSION[/WINDOW[/BLOCK]], each an id, label, position, id fragment "
            "(blocks also by terminal title); leave a part empty for the default"
        )
    padded = [part or None for part in parts] + [None] * (3 - len(parts))
    return padded[0], padded[1], padded[2]


def apply_target_spec(args: argparse.Namespace) -> None:
    spec = getattr(args, "target", None)
    if spec is None:
        return
    session, window, block = split_target_spec(spec)
    for name, value in (("session", session), ("block", block)):
        if value is not None and not hasattr(args, name):
            raise UsageError(f"this command takes no {name}; drop that part of --target")
        if value is not None and getattr(args, name, None):
            raise UsageError(f"--target already names the {name}; drop -{name[0]}/--{name}")
        if value is not None:
            setattr(args, name, value)
    args.target_window = window


TARGET_HELP = (
    "SESSION[/WINDOW[/BLOCK]] in one string; parts are id, label, position, id fragment (blocks also terminal title)"
)


def add_target_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("-s", "--session", help="session id, label or unique id prefix (optional if only one exists)")
    p.add_argument("-b", "--block", help="block id, label, terminal title or unique id prefix (default: focused block)")
    p.add_argument("-t", "--target", help=TARGET_HELP)


def add_guard_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        GUARD_FLAG,
        dest="yes_i_am_authorised",
        nargs="?",
        const=True,
        default=False,
        metavar="PLAN_ID",
        help="actually perform the action; without it the command is a dry run. With the plan_id of an "
        "approved dry run, it runs only if the plan is still the same",
    )


def add_admin_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        ADMIN_FLAG,
        dest="allow_server_admin",
        action="store_true",
        help=f"second guard for server administration; needed in addition to {GUARD_FLAG}",
    )


class Parser(argparse.ArgumentParser):
    """Sub-parsers inherit this class, so no option anywhere accepts an abbreviation."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)


def finite_float(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {raw!r}") from None
    if not math.isfinite(value):
        raise argparse.ArgumentTypeError(f"not a finite number: {raw!r}")
    return value


def seconds(raw: str) -> float:
    value = finite_float(raw)
    if value < 0:
        raise argparse.ArgumentTypeError(f"seconds cannot be negative: {raw!r}")
    return value
