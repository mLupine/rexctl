"""Key names (Enter, C-c, M-x, F5, ctrl+shift+Up, ...) -> terminal bytes or Rex key objects."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

MOD_ORDER = ("shift", "ctrl", "alt", "super")
MOD_ALIASES = {
    "c": "ctrl",
    "ctrl": "ctrl",
    "control": "ctrl",
    "m": "alt",
    "alt": "alt",
    "meta": "alt",
    "opt": "alt",
    "option": "alt",
    "s": "shift",
    "shift": "shift",
    "super": "super",
    "cmd": "super",
    "command": "super",
    "win": "super",
}
NAMED = {
    "enter": "enter",
    "return": "enter",
    "tab": "tab",
    "esc": "escape",
    "escape": "escape",
    "space": "space",
    "backspace": "backspace",
    "bs": "backspace",
    "up": "arrow_up",
    "down": "arrow_down",
    "left": "arrow_left",
    "right": "arrow_right",
    "home": "home",
    "end": "end",
    "pageup": "page_up",
    "pgup": "page_up",
    "pagedown": "page_down",
    "pgdn": "page_down",
    "insert": "insert",
    "ins": "insert",
    "delete": "delete",
    "del": "delete",
}
CHAR_ALIASES = {"comma": ",", "plus": "+", "minus": "-"}
PUNCT = {
    "-": "minus",
    "=": "equal",
    "[": "bracket_left",
    "]": "bracket_right",
    "\\": "backslash",
    ";": "semicolon",
    "'": "quote",
    ",": "comma",
    ".": "period",
    "/": "slash",
    "`": "backquote",
}
CSI_LETTER = {"arrow_up": "A", "arrow_down": "B", "arrow_right": "C", "arrow_left": "D", "home": "H", "end": "F"}
CSI_TILDE = {
    "insert": 2,
    "delete": 3,
    "page_up": 5,
    "page_down": 6,
    "f5": 15,
    "f6": 17,
    "f7": 18,
    "f8": 19,
    "f9": 20,
    "f10": 21,
    "f11": 23,
    "f12": 24,
}
SS3_FUNCTION = {"f1": "P", "f2": "Q", "f3": "R", "f4": "S"}
PLAIN_BYTES = {"enter": "\r", "tab": "\t", "escape": "\x1b", "space": " ", "backspace": "\x7f"}
KEY_EXAMPLES = [
    "Enter",
    "Esc",
    "Tab",
    "S-Tab",
    "C-c",
    "ctrl+d",
    "M-x",
    "Up",
    "PageDown",
    "F1..F12",
    "ctrl+shift+Up",
    "a",
    "Space",
]


class KeyNameError(ValueError):
    pass


@dataclass(frozen=True)
class Key:
    code: str
    mods: tuple[str, ...] = ()
    char: str = ""

    @property
    def mods_text(self) -> str:
        return "+".join(m for m in MOD_ORDER if m in self.mods)


def split_names(spec: str) -> list[str]:
    return [part for part in re.split(r"[,\s]+", spec.strip()) if part]


def split_mods(name: str) -> tuple[tuple[str, ...], str]:
    mods: list[str] = []
    rest = name
    while True:
        match = re.match(r"^([A-Za-z]+)[-+](.+)$", rest)
        if not match or match.group(1).lower() not in MOD_ALIASES:
            return tuple(mods), rest
        mods.append(MOD_ALIASES[match.group(1).lower()])
        rest = match.group(2)


def char_code(lower: str) -> str:
    if lower.isascii() and lower.isalpha():
        return "key_" + lower
    if lower.isascii() and lower.isdigit():
        return "digit_" + lower
    return PUNCT.get(lower, "unidentified")


def char_key(char: str, mods: tuple[str, ...]) -> Key:
    lower = char.lower()
    shifted = mods + ("shift",) if char != lower and "shift" not in mods else mods
    return Key(char_code(lower), shifted, char)


def parse_key(name: str) -> Key:
    mods, base = split_mods(name)
    lowered = base.lower()
    if lowered in NAMED:
        return Key(NAMED[lowered], mods)
    if lowered in CHAR_ALIASES:
        return char_key(CHAR_ALIASES[lowered], mods)
    if re.fullmatch(r"f([1-9]|1\d|2[0-5])", lowered):
        return Key(lowered, mods)
    if len(base) == 1:
        return char_key(base, mods)
    raise KeyNameError(f"unknown key {name!r}")


def parse_keys(spec: str) -> list[Key]:
    return [parse_key(name) for name in split_names(spec)]


def modifier_param(mods: tuple[str, ...]) -> int:
    return 1 + ("shift" in mods) + 2 * ("alt" in mods) + 4 * ("ctrl" in mods) + 8 * ("super" in mods)


def csi_bytes(key: Key) -> str | None:
    param = modifier_param(key.mods)
    if key.code in CSI_LETTER:
        return f"\x1b[1;{param}{CSI_LETTER[key.code]}" if param > 1 else f"\x1b[{CSI_LETTER[key.code]}"
    if key.code in CSI_TILDE:
        return f"\x1b[{CSI_TILDE[key.code]};{param}~" if param > 1 else f"\x1b[{CSI_TILDE[key.code]}~"
    if key.code in SS3_FUNCTION:
        return f"\x1b[1;{param}{SS3_FUNCTION[key.code]}" if param > 1 else f"\x1bO{SS3_FUNCTION[key.code]}"
    return None


def control_char(char: str) -> str:
    if char == " ":
        return "\x00"
    if char == "?":
        return "\x7f"
    if char.lower() in "abcdefghijklmnopqrstuvwxyz[\\]^_@":
        return chr(ord(char.lower()) & 0x1F)
    raise KeyNameError(f"ctrl+{char!r} has no terminal byte")


def base_bytes(key: Key) -> str:
    if key.code == "tab" and "shift" in key.mods:
        return "\x1b[Z"
    csi = csi_bytes(key)
    if csi is not None:
        return csi
    if key.code == "space" and "ctrl" in key.mods:
        return "\x00"
    if key.code in PLAIN_BYTES:
        return PLAIN_BYTES[key.code]
    if not key.char:
        raise KeyNameError(f"{key.code} has no plain terminal bytes; use --via client-key or block-event")
    return control_char(key.char) if "ctrl" in key.mods else key.char


def key_bytes(key: Key) -> str:
    if (
        key.code.startswith("f")
        and key.code[1:].isdigit()
        and key.code not in SS3_FUNCTION
        and key.code not in CSI_TILDE
    ):
        raise KeyNameError(f"{key.code} has no standard terminal bytes; use --via client-key or block-event")
    data = base_bytes(key)
    return (
        "\x1b" + data if "alt" in key.mods and not data.startswith("\x1b[") and key.code not in SS3_FUNCTION else data
    )


def key_object(key: Key, action: str = "press") -> dict[str, Any]:
    plain = key.code.startswith(("key_", "digit_")) or key.code in PUNCT.values()
    typed = (
        key.char
        if plain and not ({"ctrl", "alt", "super"} & set(key.mods))
        else (" " if key.code == "space" and not key.mods else "")
    )
    consumed = "shift" if key.char and key.char != key.char.lower() else ""
    return {
        "key": key.code,
        "mods": key.mods_text,
        "consumed_mods": consumed,
        "text": typed,
        "unshifted_codepoint": ord(key.char.lower()) if plain and key.char else (32 if key.code == "space" else 0),
        "composing": False,
        "action": action,
    }
