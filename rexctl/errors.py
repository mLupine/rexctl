from __future__ import annotations

from typing import Any

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_UNREACHABLE = 3
EXIT_DENIED = 4
EXIT_API_ERROR = 5
EXIT_NOT_FOUND = 6
EXIT_TIMEOUT = 7
EXIT_DRY_RUN = 10


class RexError(Exception):
    exit_code = EXIT_ERROR
    kind = "error"

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {"ok": False, "error": {"kind": self.kind, "message": self.message, **self.details}}


class UsageError(RexError):
    exit_code = EXIT_USAGE
    kind = "usage"


class UnreachableError(RexError):
    exit_code = EXIT_UNREACHABLE
    kind = "unreachable"


class AccessDeniedError(RexError):
    exit_code = EXIT_DENIED
    kind = "access_denied"


class ApiError(RexError):
    exit_code = EXIT_API_ERROR
    kind = "api_error"


class LocalOnlyError(ApiError):
    kind = "local_only"


class TargetNotFoundError(RexError):
    exit_code = EXIT_NOT_FOUND
    kind = "target_not_found"


class WaitTimeoutError(RexError):
    exit_code = EXIT_TIMEOUT
    kind = "timeout"
