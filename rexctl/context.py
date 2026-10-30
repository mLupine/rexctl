from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from . import connection
from .connection import RpcConnection

Connector = Callable[[str, float], RpcConnection]


@dataclass(frozen=True)
class Context:
    """State `main` hands to the commands: how to reach a host and whether the daemon may be used."""

    connector: Connector
    use_daemon: bool = True

    def rpc(self, url: str, timeout: float = 10.0) -> RpcConnection:
        if self.use_daemon:
            return self.connector(url, timeout)
        return connection.connect(url, timeout)
