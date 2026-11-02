from __future__ import annotations

from conftest import sign_base64, sign_hex, sign_stripe
from hookproof import providers

SECRET = b"provider-secret"
PAYLOAD = b'{"id":"evt_123"}'


def test_github_preset() -> None:
    header = "sha256=" + sign_hex(SECRET, PAYLOAD)
    assert providers.github(SECRET).verify(PAYLOAD, header) is True


def test_paystack_preset_uses_sha512() -> None:
    header = sign_hex(SECRET, PAYLOAD, "sha512")
    assert providers.paystack(SECRET).verify(PAYLOAD, header) is True


def test_shopify_preset_uses_base64() -> None:
    header = sign_base64(SECRET, PAYLOAD)
    assert providers.shopify(SECRET).verify(PAYLOAD, header) is True


def test_stripe_preset_within_window() -> None:
    header = sign_stripe(SECRET, PAYLOAD, timestamp=1_700_000_000)
    verifier = providers.stripe(SECRET, tolerance=300)
    assert verifier.verify(PAYLOAD, header, now=1_700_000_010) is True


def test_stripe_preset_rejects_replay() -> None:
    header = sign_stripe(SECRET, PAYLOAD, timestamp=1_700_000_000)
    verifier = providers.stripe(SECRET, tolerance=300)
    assert verifier.verify(PAYLOAD, header, now=1_700_001_000) is False


def test_generic_hmac_preset() -> None:
    header = sign_hex(SECRET, PAYLOAD)
    assert providers.generic_hmac(SECRET).verify(PAYLOAD, header) is True
