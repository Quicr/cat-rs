# CAT-4-MOQT

[![CI](https://github.com/suhasHere/cat.rs/actions/workflows/ci.yml/badge.svg)](https://github.com/suhasHere/cat.rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)

Rust implementation of [Common Access Token for Media Over QUIC Transport (CAT-4-MOQT)](https://github.com/moq-wg/CAT-4-MOQT) based on [CTA-5007-B](https://shop.cta.tech/products/common-access-token).

Tested on Linux, macOS, and Windows.

## Features

- Full CTA-5007-B CAT token support with CBOR/CWT encoding
- MOQT-specific claims: namespace/track authorization with binary matching
- DPoP (Demonstrating Proof-of-Possession) support
- Cryptographic algorithms: HMAC-SHA256, ES256, PS256
- Token revalidation support

## Build

```bash
# Build with MOQT support (default)
cargo build --release

# Build without MOQT (generic CAT only)
cargo build --release --no-default-features --features builtin-trie
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `moqt` | Yes | MOQT-specific claims, scopes, and DPoP validation |
| `builtin-trie` | Yes | Built-in trie for URI pattern matching |
| `qp-trie` | No | Use qp-trie crate instead of built-in trie |

For generic CAT tokens without MOQT, disable the `moqt` feature. See [`examples/generic_cat.rs`](examples/generic_cat.rs) for usage.

## Test

```bash
cargo test
```

## Benchmark

```bash
cargo bench
```

## Example

```rust
use cat_impl::*;
use cat_impl::moqt::{MoqtValidator, MoqtAuthRequest, MoqtScopeBuilder, roles};
use chrono::{Duration, Utc};

// Create a publisher token for live streaming
let scope = MoqtScopeBuilder::new()
    .publisher()
    .namespace_exact(b"cdn.example.com")
    .track_prefix(b"/live/")
    .build();

let token = CatTokenBuilder::new()
    .issuer("https://auth.example.com")
    .audience(vec!["relay.example.com".to_string()])
    .expires_at(Utc::now() + Duration::hours(1))
    .moqt_scope(scope)
    .moqt_reval(300.0)  // 5-minute revalidation
    .build();

// Validate authorization
let validator = MoqtValidator::new();
let request = MoqtAuthRequest::simple(
    MoqtAction::Publish,
    b"cdn.example.com",
    b"/live/stream1"
);

let result = validator.authorize(&token, &request);
assert!(result.authorized);
```

## Predefined Roles

```rust
// Publisher: PublishNamespace, Publish
let pub_scope = roles::publisher(b"example.com", b"/live/");

// Subscriber: SubscribeNamespace, Subscribe, Fetch  
let sub_scope = roles::subscriber(b"example.com", b"/vod/");

// Admin: all actions
let admin_scope = roles::admin(b"example.com");

// Read-only: Subscribe, Fetch only
let ro_scope = roles::read_only(b"example.com", b"/archive/");
```

## License

BSD-2-Clause
