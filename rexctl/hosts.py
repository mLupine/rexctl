from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from .errors import UsageError


def default_hosts_file() -> Path:
    if os.environ.get("REXCTL_HOSTS"):
        return Path(os.environ["REXCTL_HOSTS"])
    config = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return config / "rexctl" / "hosts.json"


def load_hosts(path: Path | None = None) -> dict[str, str]:
    path = path or default_hosts_file()
    hosts: dict[str, str] = {}
    if path.exists():
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise UsageError(f"cannot read hosts file {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise UsageError(f"hosts file {path} must hold a JSON object of label to URL")
        hosts.update({str(k): str(v) for k, v in data.items()})
    return hosts


def require_https(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise UsageError(f"refusing non-HTTPS host URL {url!r}; only https:// endpoints are allowed")
    if not parts.hostname:
        raise UsageError(f"host URL {url!r} has no hostname")
    try:
        _ = parts.port  # raises on a non-numeric or out-of-range port
    except ValueError:
        raise UsageError(f"host URL {url!r} has a bad port") from None
    if parts.username or parts.password:
        raise UsageError("host URLs must not carry user:password@; Rex authenticates the connection itself")
    return f"https://{parts.netloc}"


def resolve_host(spec: str, hosts: dict[str, str]) -> tuple[str, str]:
    if spec in hosts:
        return spec, require_https(hosts[spec])
    if "://" in spec:
        url = require_https(spec)
        return urlsplit(url).hostname or url, url
    known = ", ".join(sorted(hosts)) or f"none (add labels to {default_hosts_file()})"
    raise UsageError(f"unknown host {spec!r}; known: {known}; or pass an https:// URL")
