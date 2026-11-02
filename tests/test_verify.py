from __future__ import annotations

import pytest

from conftest import sign_base64, sign_hex, sign_stripe
from hookproof import (
    Base64Scheme,
    ExpiredSignatureError,
    HexScheme,
    InvalidSignatureError,
    MalformedHeaderError,
    PrefixedHexScheme,
    SignedTimestampScheme,
    Verifier,
    verify,
)

SECRET = b"shhh-very-secret"
PAYLOAD = b'{"event":"charge.success","amount":5000}'


def test_valid_hex_signature_returns_true() -> None:
    header = sign_hex(SECRET, PAYLOAD)
    assert verify(PAYLOAD, header, SECRET) is True


def test_tampered_payload_returns_false() -> None:
    header = sign_hex(SECRET, PAYLOAD)
    assert verify(PAYLOAD + b"x", header, SECRET) is False


def test_wrong_secret_returns_false() -> None:
    header = sign_hex(SECRET, PAYLOAD)
    assert verify(PAYLOAD, header, b"wrong-secret") is False


def test_str_payload_and_secret_are_utf8_encoded() -> None:
    header = sign_hex(SECRET, PAYLOAD)
    assert verify(PAYLOAD.decode(), header, SECRET.decode()) is True


def test_raise_on_error_raises_invalid_signature() -> None:
    with pytest.raises(InvalidSignatureError):
        verify(PAYLOAD, sign_hex(SECRET, PAYLOAD), b"nope", raise_on_error=True)


def test_malformed_hex_header_raises() -> None:
    with pytest.raises(MalformedHeaderError):
        verify(PAYLOAD, "not-hex!!", SECRET, raise_on_error=True)


def test_empty_header_is_rejected() -> None:
    assert verify(PAYLOAD, "", SECRET) is False


def test_base64_scheme() -> None:
    header = sign_base64(SECRET, PAYLOAD)
    assert verify(PAYLOAD, header, SECRET, scheme=Base64Scheme()) is True


def test_prefixed_hex_scheme_github_style() -> None:
    header = "sha256=" + sign_hex(SECRET, PAYLOAD)
    assert verify(PAYLOAD, header, SECRET, scheme=PrefixedHexScheme("sha256")) is True


def test_prefixed_hex_ignores_other_labels() -> None:
    header = "sha1=deadbeef," + "sha256=" + sign_hex(SECRET, PAYLOAD)
    assert verify(PAYLOAD, header, SECRET, scheme=PrefixedHexScheme("sha256")) is True


def test_key_rotation_multiple_candidate_signatures() -> None:
    good = sign_hex(SECRET, PAYLOAD)
    header = f"{'00' * 32},{good}"
    assert verify(PAYLOAD, header, SECRET, scheme=HexScheme()) is True


def test_sha512_algorithm() -> None:
    header = sign_hex(SECRET, PAYLOAD, "sha512")
    assert verify(PAYLOAD, header, SECRET, algorithm="sha512") is True


def test_verifier_is_reusable_and_immutable() -> None:
    verifier = Verifier(SECRET)
    header = sign_hex(SECRET, PAYLOAD)
    assert verifier.verify(PAYLOAD, header) is True
    assert verifier.verify(b"other", header) is False
    assert "shhh" not in repr(verifier)  # secret must not leak in repr


class TestSignedTimestamp:
    scheme = SignedTimestampScheme()

    def test_valid_within_tolerance(self) -> None:
        header = sign_stripe(SECRET, PAYLOAD, timestamp=1_000_000)
        assert (
            verify(
                PAYLOAD,
                header,
                SECRET,
                scheme=self.scheme,
                tolerance=300,
                now=1_000_100,
            )
            is True
        )

    def test_expired_outside_tolerance(self) -> None:
        header = sign_stripe(SECRET, PAYLOAD, timestamp=1_000_000)
        with pytest.raises(ExpiredSignatureError):
            verify(
                PAYLOAD,
                header,
                SECRET,
                scheme=self.scheme,
                tolerance=300,
                now=1_000_600,
                raise_on_error=True,
            )

    def test_tolerance_without_timestamp_is_expired(self) -> None:
        header = sign_hex(SECRET, PAYLOAD)
        with pytest.raises(ExpiredSignatureError):
            verify(PAYLOAD, header, SECRET, tolerance=300, raise_on_error=True)

    def test_non_integer_timestamp_is_malformed(self) -> None:
        with pytest.raises(MalformedHeaderError):
            verify(
                PAYLOAD,
                "t=abc,v1=deadbeef",
                SECRET,
                scheme=self.scheme,
                raise_on_error=True,
            )
