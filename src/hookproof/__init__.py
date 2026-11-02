"""hookproof: timing-safe HMAC webhook signature verification.

Quick start::

    from hookproof import verify

    if not verify(request.body, request.headers["X-Signature"], secret):
        abort(400)

Or with a provider preset::

    from hookproof.providers import github

    verifier = github(secret)
    verifier.verify(request.body, request.headers["X-Hub-Signature-256"])
"""

from __future__ import annotations

from ._core import (
    AsyncSecretResolver,
    Secret,
    SecretResolver,
    Verifier,
    averify,
    verify,
)
from .errors import (
    ExpiredSignatureError,
    HookProofError,
    InvalidSignatureError,
    MalformedHeaderError,
)
from .schemes import (
    Base64Scheme,
    HexScheme,
    ParsedSignature,
    PrefixedHexScheme,
    Scheme,
    SignedTimestampScheme,
)

__version__ = "0.1.0"

__all__ = [
    "AsyncSecretResolver",
    "Base64Scheme",
    "ExpiredSignatureError",
    "HexScheme",
    "HookProofError",
    "InvalidSignatureError",
    "MalformedHeaderError",
    "ParsedSignature",
    "PrefixedHexScheme",
    "Scheme",
    "Secret",
    "SecretResolver",
    "SignedTimestampScheme",
    "Verifier",
    "__version__",
    "averify",
    "verify",
]
