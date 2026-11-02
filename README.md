# hookproof

Timing-safe HMAC webhook signature verification for Python — fully typed, with
synchronous and asynchronous APIs and zero runtime dependencies.

Verifying a webhook signature is a small job that is easy to get subtly wrong:
a non-constant-time string compare, a signature decoded as text instead of
bytes, a missing replay window, or silently trusting the wrong digest
algorithm. `hookproof` does the fiddly parts correctly and gets out of the way.

```python
from hookproof import verify

ok = verify(request.body, request.headers["X-Signature"], secret)
if not ok:
    abort(400)
```

## Install

```bash
pip install hookproof
```

Python 3.9+. No dependencies.

## Why

- **Timing-safe.** Every comparison goes through `hmac.compare_digest`, on the
  raw digest bytes, never on the hex/base64 text.
- **Fully typed.** Ships a `py.typed` marker and passes `mypy --strict`.
  Overloads give `verify(..., raise_on_error=True)` a `Literal[True]` return,
  so your type checker knows the non-raising path is the only one that returns.
- **Sync and async.** `verify` for ordinary handlers, `averify` for async ones.
- **Provider presets, not magic.** `hookproof.providers` has GitHub, Stripe,
  Paystack and Shopify, each a three-line wrapper over the public API. Anything
  else, you compose yourself.
- **No dependencies, loose version floor.** Nothing to conflict with your app.

## Usage

### Provider presets

```python
from hookproof.providers import github, stripe, paystack, shopify

verifier = github(secret)
verifier.verify(request.body, request.headers["X-Hub-Signature-256"])

# Stripe-style, with a 5-minute replay window:
stripe(secret, tolerance=300).verify(body, request.headers["Stripe-Signature"])
```

### Raise instead of returning False

```python
from hookproof import verify, InvalidSignatureError, ExpiredSignatureError

try:
    verify(body, header, secret, tolerance=300, raise_on_error=True)
except ExpiredSignatureError:
    ...  # replayed or clock-skewed
except InvalidSignatureError:
    ...  # forged or wrong secret
```

### Compose your own scheme

A `Scheme` decides how a header is framed. The built-ins cover the common cases:

| Scheme | Header shape | Example provider |
| --- | --- | --- |
| `HexScheme` | `<hex>` | Paystack |
| `Base64Scheme` | `<base64>` | Shopify |
| `PrefixedHexScheme("sha256")` | `sha256=<hex>` | GitHub |
| `SignedTimestampScheme()` | `t=...,v1=<hex>` | Stripe |

```python
from hookproof import Verifier, PrefixedHexScheme

verifier = Verifier(secret, scheme=PrefixedHexScheme("sha256"), algorithm="sha256")
```

Anything with a `parse()` and a `message()` method satisfies the `Scheme`
protocol — no subclassing required.

### Async secret resolution

HMAC is cheap and synchronous; the part that is actually I/O-bound is fetching
the per-tenant secret. `averify` accepts a value, a sync callable, or an
awaitable callable, so you can resolve it without blocking the event loop:

```python
from hookproof import averify

async def secret_for(tenant_id):
    return await vault.get(tenant_id)

await averify(body, header, lambda: secret_for(tenant_id))
```

## Security notes

- Always verify against the **raw request body**, before any JSON parsing or
  re-encoding — a round-trip through a parser changes the bytes.
- Use `tolerance` with a timestamped scheme to reject replays.
- A `str` payload or secret is encoded as UTF-8; pass `bytes` when you have them.

## Development

```bash
pip install -e ".[dev]"
pytest
mypy
ruff check .
```

Every fix ships with a regression test. See [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).
