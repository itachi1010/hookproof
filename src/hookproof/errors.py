"""Exception hierarchy for :mod:`hookproof`.

Every error raised by this library is a subclass of :class:`HookProofError`, so
callers that only care about "did verification fail" can catch the base class,
while callers that want to distinguish *why* it failed can catch the specific
subclasses.
"""

from __future__ import annotations

__all__ = [
    "ExpiredSignatureError",
    "HookProofError",
    "InvalidSignatureError",
    "MalformedHeaderError",
]


class HookProofError(Exception):
    """Base class for all errors raised by hookproof."""


class MalformedHeaderError(HookProofError):
    """The signature header could not be parsed or decoded."""


class InvalidSignatureError(HookProofError):
    """No candidate signature in the header matched the computed MAC."""


class ExpiredSignatureError(HookProofError):
    """The signed timestamp fell outside the allowed tolerance window."""
