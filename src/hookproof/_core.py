"""The verification engine: timing-safe compare, replay window, sync and async."""

from __future__ import annotations

import hmac
from collections.abc import Awaitable
from datetime import timedelta
from time import time
from typing import TYPE_CHECKING, Callable, Literal, Union, overload

from .errors import ExpiredSignatureError, HookProofError, InvalidSignatureError
from .schemes import HexScheme, Scheme

if TYPE_CHECKING:
    from typing import Optional

__all__ = ["Verifier", "averify", "verify"]

#: A shared-secret value.
Secret = Union[str, bytes]
#: A zero-argument callable that returns a secret (handy for per-tenant lookups).
SecretResolver = Callable[[], Secret]
#: An awaitable variant, for resolving the secret from an async source.
AsyncSecretResolver = Callable[[], Awaitable[Secret]]

#: Used when the caller does not specify a scheme: the whole header is hex.
DEFAULT_SCHEME: Scheme = HexScheme()


def _to_bytes(value: Secret) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else value


def _tolerance_seconds(tolerance: Union[int, float, timedelta, None]) -> Optional[float]:
    if tolerance is None:
        return None
    if isinstance(tolerance, timedelta):
        return tolerance.total_seconds()
    return float(tolerance)


def _check(
    payload: bytes,
    header: str,
    secret: bytes,
    scheme: Scheme,
    algorithm: str,
    tolerance: Optional[float],
    now: Optional[float],
) -> None:
    """Raise a :class:`HookProofError` subclass if verification fails."""
    parsed = scheme.parse(header)

    if tolerance is not None:
        if parsed.timestamp is None:
            raise ExpiredSignatureError("a tolerance was set but the header carries no timestamp")
        current = time() if now is None else now
        if abs(current - parsed.timestamp) > tolerance:
            raise ExpiredSignatureError(
                f"signed timestamp {parsed.timestamp} is outside the {tolerance:g}s tolerance"
            )

    expected = hmac.new(secret, scheme.message(payload, parsed), algorithm).digest()
    if not any(hmac.compare_digest(expected, candidate) for candidate in parsed.signatures):
        raise InvalidSignatureError("no candidate signature matched the computed MAC")


@overload
def verify(
    payload: Secret,
    header: str,
    secret: Secret,
    *,
    scheme: Scheme = ...,
    algorithm: str = ...,
    tolerance: Union[int, float, timedelta, None] = ...,
    now: Optional[float] = ...,
    raise_on_error: Literal[True],
) -> Literal[True]: ...


@overload
def verify(
    payload: Secret,
    header: str,
    secret: Secret,
    *,
    scheme: Scheme = ...,
    algorithm: str = ...,
    tolerance: Union[int, float, timedelta, None] = ...,
    now: Optional[float] = ...,
    raise_on_error: bool = ...,
) -> bool: ...


def verify(
    payload: Secret,
    header: str,
    secret: Secret,
    *,
    scheme: Scheme = DEFAULT_SCHEME,
    algorithm: str = "sha256",
    tolerance: Union[int, float, timedelta, None] = None,
    now: Optional[float] = None,
    raise_on_error: bool = False,
) -> bool:
    """Verify that ``header`` is a valid signature of ``payload`` under ``secret``.

    :param payload: The raw request body, exactly as received (bytes preferred;
        a ``str`` is encoded as UTF-8).
    :param header: The signature header value sent by the provider.
    :param secret: The shared signing secret.
    :param scheme: How the header is framed. Defaults to a plain hex digest;
        see :mod:`hookproof.providers` for ready-made presets.
    :param algorithm: Any digest name :func:`hmac.new` accepts, e.g. ``"sha256"``.
    :param tolerance: Maximum age of a signed timestamp, in seconds or as a
        :class:`datetime.timedelta`. Requires a timestamped ``scheme``.
    :param now: Current Unix time, for deterministic testing of ``tolerance``.
    :param raise_on_error: When ``True``, raise a :class:`HookProofError` subclass
        instead of returning ``False``.
    :returns: ``True`` if the signature is valid, else ``False``
        (unless ``raise_on_error`` is set).
    """
    try:
        _check(
            _to_bytes(payload),
            header,
            _to_bytes(secret),
            scheme,
            algorithm,
            _tolerance_seconds(tolerance),
            now,
        )
    except HookProofError:
        if raise_on_error:
            raise
        return False
    return True


async def _resolve(secret: Union[Secret, SecretResolver, AsyncSecretResolver]) -> Secret:
    if isinstance(secret, (str, bytes)):
        return secret
    produced = secret()
    if isinstance(produced, (str, bytes)):
        return produced
    return await produced


async def averify(
    payload: Secret,
    header: str,
    secret: Union[Secret, SecretResolver, AsyncSecretResolver],
    *,
    scheme: Scheme = DEFAULT_SCHEME,
    algorithm: str = "sha256",
    tolerance: Union[int, float, timedelta, None] = None,
    now: Optional[float] = None,
    raise_on_error: bool = False,
) -> bool:
    """Async counterpart of :func:`verify`.

    HMAC itself is cheap and synchronous, so the win here is ``secret``: it may
    be a value, a callable, or an *awaitable* callable. That lets you resolve a
    per-tenant secret from a vault or database without blocking the event loop,
    which is the part of webhook verification that is actually I/O-bound.
    """
    resolved = await _resolve(secret)
    return verify(
        payload,
        header,
        resolved,
        scheme=scheme,
        algorithm=algorithm,
        tolerance=tolerance,
        now=now,
        raise_on_error=raise_on_error,
    )


class Verifier:
    """A reusable, pre-configured verifier.

    Construct it once with your secret and scheme, then call :meth:`verify`
    (or :meth:`averify`) per request. Instances are immutable after creation.
    """

    __slots__ = ("_secret", "algorithm", "scheme", "tolerance")

    def __init__(
        self,
        secret: Secret,
        *,
        scheme: Scheme = DEFAULT_SCHEME,
        algorithm: str = "sha256",
        tolerance: Union[int, float, timedelta, None] = None,
    ) -> None:
        self._secret = _to_bytes(secret)
        self.scheme = scheme
        self.algorithm = algorithm
        self.tolerance = _tolerance_seconds(tolerance)

    @overload
    def verify(
        self,
        payload: Secret,
        header: str,
        *,
        now: Optional[float] = ...,
        raise_on_error: Literal[True],
    ) -> Literal[True]: ...

    @overload
    def verify(
        self,
        payload: Secret,
        header: str,
        *,
        now: Optional[float] = ...,
        raise_on_error: bool = ...,
    ) -> bool: ...

    def verify(
        self,
        payload: Secret,
        header: str,
        *,
        now: Optional[float] = None,
        raise_on_error: bool = False,
    ) -> bool:
        """Verify ``header`` against ``payload`` using this verifier's configuration."""
        try:
            _check(
                _to_bytes(payload),
                header,
                self._secret,
                self.scheme,
                self.algorithm,
                self.tolerance,
                now,
            )
        except HookProofError:
            if raise_on_error:
                raise
            return False
        return True

    async def averify(
        self,
        payload: Secret,
        header: str,
        *,
        now: Optional[float] = None,
        raise_on_error: bool = False,
    ) -> bool:
        """Async-friendly wrapper around :meth:`verify` for use in async handlers."""
        return self.verify(payload, header, now=now, raise_on_error=raise_on_error)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(scheme={self.scheme!r}, "
            f"algorithm={self.algorithm!r}, tolerance={self.tolerance!r})"
        )
