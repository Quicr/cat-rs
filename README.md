# Common Access Token (CAT) Implementation

[![CI](https://github.com/suhasHere/cat.rs/actions/workflows/ci.yml/badge.svg)](https://github.com/suhasHere/cat.rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Tested on Linux, macOS, and Windows.

##  Overview

This project provides implementation of Common Access Tokens (CAT) as defined in the CTA-5007-B specification. CAT tokens use CBOR Web Token (CWT) format with CBOR encoding and base64URL transport encoding.

## Features

### Rust Implementation
- Full CTA-5007-B compliance with all 13 CAT-specific claims
- Core CWT claims: `iss`, `aud`, `exp`, `nbf`, `cti`
- CAT-specific claims: `catreplay`, `catpor`, `catv`, `catnip`, `catu`, `catm`, `catalpn`, `cath`, `catgeoiso3166`, `catgeocoord`, `geohash`, `catgeoalt`, `cattpk`
- Cryptographic algorithms: HMAC256/256, ES256 (ECDSA P-256), PS256 (RSA-PSS)
- CBOR Web Token encoding/decoding
- Base64URL transport encoding
- Comprehensive validation: time-based, geographic, audience/issuer verification
- CLI tool for token generation and verification

## Quick Start

### Prerequisites

- Rust 1.70+ and Cargo

### Installation

#### Using the Makefile (Recommended)

```bash
# Build everything
make build

# Run all tests
make test


# Run examples
make examples
```

#### Rust Only

```bash
# Build
cargo build --release

# Run tests
cargo test

# Try the CLI
cargo run --bin cat-cli generate-hmac
```

##  Usage Examples

###  API

```rust
use cat_impl::;
use chrono::{Duration, Utc};

// Create a CAT token
let now = Utc::now();
let token = CatTokenBuilder::new()
    .issuer("https://example.com")
    .audience(vec!["https://api.example.com".to_string()])
    .expires_at(now + Duration::hours(1))
    .not_before(now)
    .cwt_id("unique-token-id")
    .version("1.0")
    .usage_limit(100)
    .replay_protection("nonce-12345")
    .proof_of_possession(true)
    .geo_coordinate(37.7749, -122.4194, Some(100.0))
    .geohash("9q8yy")
    .build();

// Sign with HMAC256
let key = HmacSha256Algorithm::generate_key();
let algorithm = HmacSha256Algorithm::new(&key);
let encoded_token = encode_token(&token, &algorithm)?;

// Verify and decode
let decoded_token = decode_token(&encoded_token, &algorithm)?;

// Validate token
let validator = CatTokenValidator::new()
    .with_expected_issuers(vec!["https://example.com".to_string()])
    .with_expected_audiences(vec!["https://api.example.com".to_string()])
    .with_clock_skew_tolerance(60);

validator.validate(&decoded_token)?;
```

##  CAT Claims Support

### Core CWT Claims
- `iss` (Issuer) - Token issuer identifier
- `aud` (Audience) - Intended token recipients
- `exp` (Expiration) - Token expiration time
- `nbf` (Not Before) - Token validity start time
- `cti` (CWT ID) - Unique token identifier

### CAT-Specific Claims
- `catreplay` - Replay attack protection nonce
- `catpor` - Proof of possession flag
- `catv` - CAT version
- `catnip` - Network interface restrictions
- `catu` - Usage limit counter
- `catm` - HTTP method restrictions
- `catalpn` - ALPN protocol restrictions
- `cath` - Host/domain restrictions
- `catgeoiso3166` - Country code restrictions
- `catgeocoord` - Geographic coordinate restrictions
- `geohash` - Geohash-based location
- `catgeoalt` - Altitude restrictions
- `cattpk` - Token public key thumbprint

## Cryptographic Support

### Supported Algorithms
- HMAC256/256 (`alg: -4`) - HMAC with SHA-256
- ES256 (`alg: -7`) - ECDSA using P-256 and SHA-256
- PS256 (`alg: -37`) - RSASSA-PSS using SHA-256

### Key Features
- Secure random key generation
- Digital signature creation and verification
- Base64URL encoding/decoding
- CBOR encoding/decoding
- SHA-256 hashing
