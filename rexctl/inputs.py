from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import keys
from .errors import UsageError
from .protocol import SHELL_FLAVOR


def key_to_bytes(name: str) -> str:
    try:
        return keys.key_bytes(keys.parse_key(name))
    except keys.KeyNameError as exc:
        raise UsageError(str(exc), examples=keys.KEY_EXAMPLES) from None


def keys_to_data(spec: str) -> str:
    return "".join(key_to_bytes(name) for name in keys.split_names(spec))


def build_input(text: str | None, enter: bool, key_spec: str | None) -> str:
    data = (text or "") + ("\r" if enter else "") + (keys_to_data(key_spec) if key_spec else "")
    if not data:
        raise UsageError("nothing to send: give --text, --enter or --keys")
    return data


def shell_layout(label: str | None, cwd: str | None) -> dict[str, Any]:
    block: dict[str, Any] = {"flavor": SHELL_FLAVOR}
    if label:
        block["label"] = label
    if cwd:
        block["options"] = {"cwd": cwd}
    return {"block": block}


def parse_payload(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        text = Path(raw[1:]).expanduser().read_text() if raw.startswith("@") else raw
    except OSError as exc:
        raise UsageError(f"cannot read {raw[1:]}: {exc.strerror}") from None
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UsageError(f"payload is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise UsageError("payload must be a JSON object")
    return value


def read_text_file(path: str) -> str:
    try:
        return Path(path).expanduser().read_text().removesuffix("\n")
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc.strerror}") from None
