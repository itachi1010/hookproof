"""Ready-made :class:`~hookproof._core.Verifier` presets for common providers.

These are thin conveniences over :class:`Verifier`; nothing here is privileged.
If your provider is not listed, build a verifier directly with the matching
:mod:`~hookproof.schemes` scheme — or open an issue and we will add it.

The framing (encoding, labels, algorithm) is drawn from each provider's public
webhook documentation. Always confirm against the current docs for your account.
"""

from __future__ import annotations

from typing import Union

from ._core import Secret, Verifier
from .schemes import Base64Scheme, HexScheme, PrefixedHexScheme, SignedTimestampScheme

__all__ = ["generic_hmac", "github", "paystack", "shopify", "stripe"]


def github(secret: Secret) -> Verifier:
    """GitHub webhooks: ``X-Hub-Signature-256: sha256=<hex>``."""
    return Verifier(secret, scheme=PrefixedHexScheme("sha256"), algorithm="sha256")


def stripe(secret: Secret, *, tolerance: Union[int, float] = 300) -> Verifier:
    """Stripe webhooks: ``Stripe-Signature: t=...,v1=<hex>`` with a replay window."""
    return Verifier(
        secret,
        scheme=SignedTimestampScheme(signature_label="v1", timestamp_label="t"),
        algorithm="sha256",
        tolerance=tolerance,
    )


def paystack(secret: Secret) -> Verifier:
    """Paystack webhooks: ``X-Paystack-Signature: <hex>`` (HMAC-SHA512)."""
    return Verifier(secret, scheme=HexScheme(), algorithm="sha512")


def shopify(secret: Secret) -> Verifier:
    """Shopify webhooks: ``X-Shopify-Hmac-Sha256: <base64>``."""
    return Verifier(secret, scheme=Base64Scheme(), algorithm="sha256")


def generic_hmac(secret: Secret, *, algorithm: str = "sha256") -> Verifier:
    """A plain hex HMAC digest as the entire header value."""
    return Verifier(secret, scheme=HexScheme(), algorithm=algorithm)
