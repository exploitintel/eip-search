"""Contained user-facing failures and stable exit categories."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(eq=False)
class CliError(Exception):
    message: str
    exit_code: int
    status_code: int | None = None
    retry_after: int | None = None

    def __str__(self) -> str:
        return self.message


class NotFoundError(CliError):
    def __init__(self, message: str) -> None:
        super().__init__(message, 3, 404)


class InputError(CliError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message, 2, status_code)


class UnavailableError(CliError):
    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(message, 4, status_code, retry_after)


class RateLimitedError(CliError):
    def __init__(self, message: str, retry_after: int | None = None) -> None:
        super().__init__(message, 5, 429, retry_after)


class TransportError(CliError):
    def __init__(self, message: str) -> None:
        super().__init__(message, 6)


class LocalFileError(CliError):
    def __init__(self, message: str) -> None:
        super().__init__(message, 7)
