"""Signature schemes: how a provider encodes a signature header.

A :class:`Scheme` knows two things and nothing else:

* how to :meth:`~Scheme.parse` a raw header string into one or more candidate
  signatures (decoded to raw bytes) plus an optional signed timestamp, and
* how to build the exact :meth:`~Scheme.message` that was signed, given the
  request body and the parsed header.

Keeping these two concerns behind a :class:`typing.Protocol` means the core
verification routine never has to know which provider it is talking to, and
users can add a provider we have never heard of without subclassing anything.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .errors import MalformedHeaderError

__all__ = [
    "Base64Scheme",
    "HexScheme",
    "ParsedSignature",
    "PrefixedHexScheme",
    "Scheme",
    "SignedTimestampScheme",
]


@dataclass(frozen=True)
class ParsedSignature:
    """The result of parsing a signature header.

    :param signatures: One or more candidate MAC values, decoded to raw bytes.
        More than one appears when a provider is rotating secrets and sends
        every valid signature.
    :param timestamp: The signed Unix timestamp, when the scheme carries one.
    """

    signatures: tuple[bytes, ...]
    timestamp: int | None = None


@runtime_checkable
class Scheme(Protocol):
    """How a provider frames a signature header."""

    def parse(self, header: str) -> ParsedSignature:
        """Decode ``header`` into candidate signatures and an optional timestamp."""
        ...

    def message(self, payload: bytes, parsed: ParsedSignature) -> bytes:
        """Reconstruct the exact bytes that were signed for ``payload``."""
        ...


def _decode_hex(value: str) -> bytes:
    try:
        return bytes.fromhex(value.strip())
    except ValueError as exc:
        raise MalformedHeaderError(f"not a valid hex signature: {value!r}") from exc


def _decode_base64(value: str) -> bytes:
    try:
        return base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MalformedHeaderError(f"not a valid base64 signature: {value!r}") from exc


def _split(header: str) -> list[str]:
    return [part.strip() for part in header.split(",") if part.strip()]


@dataclass(frozen=True)
class HexScheme:
    """The whole header is a hex-encoded HMAC digest (e.g. Paystack).

    Comma-separated values are treated as several candidate signatures.
    """

    def parse(self, header: str) -> ParsedSignature:
        parts = _split(header)
        if not parts:
            raise MalformedHeaderError("empty signature header")
        return ParsedSignature(tuple(_decode_hex(part) for part in parts))

    def message(self, payload: bytes, parsed: ParsedSignature) -> bytes:
        return payload


@dataclass(frozen=True)
class Base64Scheme:
    """The whole header is a base64-encoded HMAC digest (e.g. Shopify)."""

    def parse(self, header: str) -> ParsedSignature:
        parts = _split(header)
        if not parts:
            raise MalformedHeaderError("empty signature header")
        return ParsedSignature(tuple(_decode_base64(part) for part in parts))

    def message(self, payload: bytes, parsed: ParsedSignature) -> bytes:
        return payload


@dataclass(frozen=True)
class PrefixedHexScheme:
    """Each signature is labelled, ``"<label>=<hex>"`` (e.g. GitHub ``sha256=...``).

    Entries whose label does not match :attr:`label` are ignored, which lets a
    header carry several algorithms at once.
    """

    label: str = "sha256"

    def parse(self, header: str) -> ParsedSignature:
        signatures: list[bytes] = []
        for part in _split(header):
            label, sep, value = part.partition("=")
            if sep and label.strip() == self.label:
                signatures.append(_decode_hex(value))
            elif not sep:
                signatures.append(_decode_hex(part))
        if not signatures:
            raise MalformedHeaderError(
                f"no {self.label!r} signature found in header {header!r}"
            )
        return ParsedSignature(tuple(signatures))

    def message(self, payload: bytes, parsed: ParsedSignature) -> bytes:
        return payload


@dataclass(frozen=True)
class SignedTimestampScheme:
    """A timestamped, comma-delimited header (e.g. Stripe ``t=...,v1=...``).

    The signed message is ``"<timestamp>.<payload>"``. Pair this scheme with a
    ``tolerance`` on the verifier to reject replayed requests.
    """

    signature_label: str = "v1"
    timestamp_label: str = "t"
    separator: bytes = b"."

    def parse(self, header: str) -> ParsedSignature:
        timestamp: int | None = None
        signatures: list[bytes] = []
        for item in _split(header):
            key, sep, value = item.partition("=")
            if not sep:
                raise MalformedHeaderError(f"malformed header element: {item!r}")
            key = key.strip()
            if key == self.timestamp_label:
                try:
                    timestamp = int(value)
                except ValueError as exc:
                    raise MalformedHeaderError(
                        f"non-integer timestamp: {value!r}"
                    ) from exc
            elif key == self.signature_label:
                signatures.append(_decode_hex(value))
        if not signatures:
            raise MalformedHeaderError(
                f"no {self.signature_label!r} signature found in header {header!r}"
            )
        return ParsedSignature(tuple(signatures), timestamp=timestamp)

    def message(self, payload: bytes, parsed: ParsedSignature) -> bytes:
        if parsed.timestamp is None:
            raise MalformedHeaderError("signed-timestamp scheme requires a timestamp")
        return str(parsed.timestamp).encode("ascii") + self.separator + payload
