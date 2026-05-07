// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_impl::*;
use chrono::{Duration, Utc};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <command> [args...]", args[0]);
        println!("Commands:");
        println!("  generate-hmac - Generate HMAC key and sample token");
        println!("  generate-es256 - Generate ES256 key pair and sample token");
        println!("  generate-ps256 - Generate PS256 key pair and sample token");
        println!("  verify <token> <algorithm> - Verify a token");
        return Ok(());
    }

    match args[1].as_str() {
        "generate-hmac" => generate_hmac_example()?,
        "generate-es256" => generate_es256_example()?,
        "generate-ps256" => generate_ps256_example()?,
        "verify" => {
            if args.len() < 4 {
                println!("Usage: {} verify <token> <algorithm>", args[0]);
                return Ok(());
            }
            verify_token(&args[2], &args[3])?;
        }
        _ => {
            println!("Unknown command: {}", args[1]);
            return Ok(());
        }
    }

    Ok(())
}

fn generate_hmac_example() -> Result<(), Box<dyn std::error::Error>> {
    let key = HmacSha256Algorithm::generate_key()?;
    let algorithm = HmacSha256Algorithm::from_secret_key(&key);

    let token = create_sample_token();
    let encoded = encode_token(&token, &algorithm)?;

    // Security: Do not print key material in production
    // To display the key, use: --show-key flag (not implemented in this example)
    println!(
        "HMAC256 Key: [REDACTED - {} bytes generated]",
        key.as_bytes().len()
    );
    println!("Sample CAT Token: {}", encoded);

    let decoded = decode_token(&encoded, &algorithm)?;
    println!("Token verified and decoded successfully!");
    println!("Issuer: {:?}", decoded.core.iss);
    println!("Audience: {:?}", decoded.core.aud);
    println!("Version: {:?}", decoded.cat.catv);

    Ok(())
}

fn generate_es256_example() -> Result<(), Box<dyn std::error::Error>> {
    let algorithm = Es256Algorithm::new_with_key_pair()?;

    let token = create_sample_token();
    let encoded = encode_token(&token, &algorithm)?;

    // Output public key as JWK for structured, portable format
    let jwk = cat_impl::Jwk::from_es256_verifying_key(algorithm.verifying_key())?;
    println!(
        "ES256 Public Key (JWK): {}",
        serde_json::to_string(&jwk).unwrap_or_else(|_| "Error serializing JWK".to_string())
    );
    println!("Sample CAT Token: {}", encoded);

    let decoded = decode_token(&encoded, &algorithm)?;
    println!("Token verified and decoded successfully!");
    println!("Issuer: {:?}", decoded.core.iss);
    println!("Audience: {:?}", decoded.core.aud);
    println!("Version: {:?}", decoded.cat.catv);

    Ok(())
}

fn generate_ps256_example() -> Result<(), Box<dyn std::error::Error>> {
    let algorithm = Ps256Algorithm::new_with_key_pair()?;

    let token = create_sample_token();
    let encoded = encode_token(&token, &algorithm)?;

    // Output public key as JWK for structured, portable format
    let jwk = cat_impl::Jwk::from_rsa_public_key(algorithm.public_key());
    println!(
        "PS256 Public Key (JWK): {}",
        serde_json::to_string(&jwk).unwrap_or_else(|_| "Error serializing JWK".to_string())
    );
    println!("Sample CAT Token: {}", encoded);

    let decoded = decode_token(&encoded, &algorithm)?;
    println!("Token verified and decoded successfully!");
    println!("Issuer: {:?}", decoded.core.iss);
    println!("Audience: {:?}", decoded.core.aud);
    println!("Version: {:?}", decoded.cat.catv);

    Ok(())
}

fn verify_token(token_str: &str, alg: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Token verification requires algorithm-specific keys.");
    println!("This is a placeholder for token verification logic.");
    println!("Token: {}", token_str);
    println!("Algorithm: {}", alg);
    Ok(())
}

fn create_sample_token() -> CatToken {
    let now = Utc::now();
    let exp = now + Duration::hours(1);

    CatTokenBuilder::new()
        .issuer("https://example.com")
        .audience(vec!["https://api.example.com".to_string()])
        .expires_at(exp)
        .not_before(now)
        .cwt_id(uuid::Uuid::new_v4().to_string())
        .version("1.0")
        .usage_limit(100)
        .replay_protection(uuid::Uuid::new_v4().to_string())
        .proof_of_possession(true)
        .geo_coordinate(37.7749, -122.4194, Some(100.0))
        .geohash("9q8yy")
        .build()
}
