# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-02

### Added

- `verify()` and `averify()` for one-shot synchronous and asynchronous
  verification, and a reusable `Verifier` class.
- Timing-safe comparison via `hmac.compare_digest`.
- Pluggable signature schemes behind a `Scheme` protocol: `HexScheme`,
  `Base64Scheme`, `PrefixedHexScheme`, and `SignedTimestampScheme`.
- Replay protection through a `tolerance` window on timestamped schemes.
- Support for multiple candidate signatures in one header (secret rotation).
- Provider presets: `github`, `stripe`, `paystack`, `shopify`, `generic_hmac`.
- Async secret resolution: `averify` accepts a value, a callable, or an
  awaitable callable so secrets can be fetched without blocking the event loop.
- A typed exception hierarchy rooted at `HookProofError`.
- `py.typed` marker; the package ships complete type information.

[Unreleased]: https://github.com/itachi1010/hookproof/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/itachi1010/hookproof/releases/tag/v0.1.0
