use cat_impl::*;
use chrono::{Duration, Utc};

#[test]
fn test_cat_token_creation() {
    let now = Utc::now();
    let exp = now + Duration::hours(1);
    
    let token = CatTokenBuilder::new()
        .issuer("https://example.com")
        .audience(vec!["https://api.example.com".to_string()])
        .expires_at(exp)
        .not_before(now)
        .cwt_id("test-token-id")
        .version("1.0")
        .usage_limit(100)
        .replay_protection("nonce-12345")
        .proof_of_possession(true)
        .geo_coordinate(37.7749, -122.4194, Some(100.0))
        .geohash("9q8yy")
        .build();

    assert_eq!(token.core.iss, Some("https://example.com".to_string()));
    assert_eq!(token.core.aud, Some(vec!["https://api.example.com".to_string()]));
    assert_eq!(token.core.cti, Some("test-token-id".to_string()));
    assert_eq!(token.cat.catv, Some("1.0".to_string()));
    assert_eq!(token.cat.catu, Some(100));
    assert_eq!(token.cat.catreplay, Some("nonce-12345".to_string()));
    assert_eq!(token.cat.catpor, Some(true));
    assert_eq!(token.cat.geohash, Some("9q8yy".to_string()));
    
    if let Some(coords) = &token.cat.catgeocoord {
        assert_eq!(coords.lat, 37.7749);
        assert_eq!(coords.lon, -122.4194);
        assert_eq!(coords.accuracy, Some(100.0));
    } else {
        panic!("Expected geo coordinates");
    }
}

#[test]
fn test_hmac_token_encoding_decoding() {
    let key = HmacSha256Algorithm::generate_key();
    let algorithm = HmacSha256Algorithm::new(&key);
    
    let now = Utc::now();
    let exp = now + Duration::hours(1);
    
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .audience(vec!["https://api.test.com".to_string()])
        .expires_at(exp)
        .cwt_id("test-hmac-token")
        .version("1.0")
        .build();

    let encoded = encode_token(&token, &algorithm).unwrap();
    assert!(!encoded.is_empty());
    assert_eq!(encoded.split('.').count(), 3);

    let decoded = decode_token(&encoded, &algorithm).unwrap();
    assert_eq!(decoded.core.iss, token.core.iss);
    assert_eq!(decoded.core.aud, token.core.aud);
    assert_eq!(decoded.core.cti, token.core.cti);
    assert_eq!(decoded.cat.catv, token.cat.catv);
}

#[test]
fn test_es256_token_encoding_decoding() {
    let algorithm = Es256Algorithm::new_with_key_pair().unwrap();
    
    let now = Utc::now();
    let exp = now + Duration::hours(1);
    
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .audience(vec!["https://api.test.com".to_string()])
        .expires_at(exp)
        .cwt_id("test-es256-token")
        .version("1.0")
        .build();

    let encoded = encode_token(&token, &algorithm).unwrap();
    assert!(!encoded.is_empty());
    assert_eq!(encoded.split('.').count(), 3);

    let decoded = decode_token(&encoded, &algorithm).unwrap();
    assert_eq!(decoded.core.iss, token.core.iss);
    assert_eq!(decoded.core.aud, token.core.aud);
    assert_eq!(decoded.core.cti, token.core.cti);
    assert_eq!(decoded.cat.catv, token.cat.catv);
}

#[test]
fn test_ps256_token_encoding_decoding() {
    let algorithm = Ps256Algorithm::new_with_key_pair().unwrap();
    
    let now = Utc::now();
    let exp = now + Duration::hours(1);
    
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .audience(vec!["https://api.test.com".to_string()])
        .expires_at(exp)
        .cwt_id("test-ps256-token")
        .version("1.0")
        .build();

    let encoded = encode_token(&token, &algorithm).unwrap();
    assert!(!encoded.is_empty());
    assert_eq!(encoded.split('.').count(), 3);

    let decoded = decode_token(&encoded, &algorithm).unwrap();
    assert_eq!(decoded.core.iss, token.core.iss);
    assert_eq!(decoded.core.aud, token.core.aud);
    assert_eq!(decoded.core.cti, token.core.cti);
    assert_eq!(decoded.cat.catv, token.cat.catv);
}

#[test]
fn test_token_validation_success() {
    let now = Utc::now();
    let exp = now + Duration::hours(1);
    
    let token = CatTokenBuilder::new()
        .issuer("https://trusted-issuer.com")
        .audience(vec!["https://my-service.com".to_string()])
        .expires_at(exp)
        .not_before(now)
        .cwt_id("valid-token")
        .version("1.0")
        .geo_coordinate(40.7128, -74.0060, Some(50.0))
        .geohash("dr5reg")
        .build();

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://trusted-issuer.com".to_string()])
        .with_expected_audiences(vec!["https://my-service.com".to_string()])
        .with_clock_skew_tolerance(60);

    assert!(validator.validate(&token).is_ok());
}

#[test]
fn test_token_validation_expired() {
    let now = Utc::now();
    let exp = now - Duration::hours(1); // Expired 1 hour ago
    
    let token = CatTokenBuilder::new()
        .issuer("https://trusted-issuer.com")
        .audience(vec!["https://my-service.com".to_string()])
        .expires_at(exp)
        .cwt_id("expired-token")
        .build();

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://trusted-issuer.com".to_string()])
        .with_expected_audiences(vec!["https://my-service.com".to_string()]);

    let result = validator.validate(&token);
    assert!(matches!(result, Err(CatError::TokenExpired)));
}

#[test]
fn test_token_validation_not_yet_valid() {
    let now = Utc::now();
    let nbf = now + Duration::hours(1); // Valid starting 1 hour from now
    let exp = now + Duration::hours(2);
    
    let token = CatTokenBuilder::new()
        .issuer("https://trusted-issuer.com")
        .audience(vec!["https://my-service.com".to_string()])
        .expires_at(exp)
        .not_before(nbf)
        .cwt_id("future-token")
        .build();

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://trusted-issuer.com".to_string()])
        .with_expected_audiences(vec!["https://my-service.com".to_string()]);

    let result = validator.validate(&token);
    assert!(matches!(result, Err(CatError::TokenNotYetValid)));
}

#[test]
fn test_token_validation_invalid_issuer() {
    let now = Utc::now();
    let exp = now + Duration::hours(1);
    
    let token = CatTokenBuilder::new()
        .issuer("https://untrusted-issuer.com")
        .audience(vec!["https://my-service.com".to_string()])
        .expires_at(exp)
        .cwt_id("invalid-issuer-token")
        .build();

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://trusted-issuer.com".to_string()])
        .with_expected_audiences(vec!["https://my-service.com".to_string()]);

    let result = validator.validate(&token);
    assert!(matches!(result, Err(CatError::InvalidIssuer)));
}

#[test]
fn test_token_validation_invalid_audience() {
    let now = Utc::now();
    let exp = now + Duration::hours(1);
    
    let token = CatTokenBuilder::new()
        .issuer("https://trusted-issuer.com")
        .audience(vec!["https://other-service.com".to_string()])
        .expires_at(exp)
        .cwt_id("invalid-audience-token")
        .build();

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://trusted-issuer.com".to_string()])
        .with_expected_audiences(vec!["https://my-service.com".to_string()]);

    let result = validator.validate(&token);
    assert!(matches!(result, Err(CatError::InvalidAudience)));
}

#[test]
fn test_cwt_payload_encoding_decoding() {
    let now = Utc::now();
    let exp = now + Duration::hours(1);
    
    let token = CatTokenBuilder::new()
        .issuer("https://example.com")
        .audience(vec!["https://api.example.com".to_string()])
        .expires_at(exp)
        .not_before(now)
        .cwt_id("test-payload")
        .version("1.0")
        .usage_limit(50)
        .replay_protection("test-nonce")
        .proof_of_possession(false)
        .geo_coordinate(51.5074, -0.1278, None)
        .geohash("gcpvj")
        .build();

    let cwt = Cwt::new(-7, token.clone()); // ES256 algorithm
    let encoded_payload = cwt.encode_payload().unwrap();
    let decoded_token = Cwt::decode_payload(&encoded_payload).unwrap();

    assert_eq!(decoded_token.core.iss, token.core.iss);
    assert_eq!(decoded_token.core.aud, token.core.aud);
    assert_eq!(decoded_token.core.cti, token.core.cti);
    assert_eq!(decoded_token.cat.catv, token.cat.catv);
    assert_eq!(decoded_token.cat.catu, token.cat.catu);
    assert_eq!(decoded_token.cat.catreplay, token.cat.catreplay);
    assert_eq!(decoded_token.cat.catpor, token.cat.catpor);
    assert_eq!(decoded_token.cat.geohash, token.cat.geohash);
    
    if let (Some(orig_coords), Some(decoded_coords)) = 
        (&token.cat.catgeocoord, &decoded_token.cat.catgeocoord) {
        assert_eq!(orig_coords.lat, decoded_coords.lat);
        assert_eq!(orig_coords.lon, decoded_coords.lon);
        assert_eq!(orig_coords.accuracy, decoded_coords.accuracy);
    }
}

#[test]
fn test_all_cat_claims() {
    let token = CatToken {
        core: CoreClaims {
            iss: Some("https://issuer.com".to_string()),
            aud: Some(vec!["aud1".to_string(), "aud2".to_string()]),
            exp: Some(1234567890),
            nbf: Some(1234567800),
            cti: Some("unique-token-id".to_string()),
        },
        cat: CatClaims {
            catreplay: Some("replay-nonce".to_string()),
            catpor: Some(true),
            catv: Some("2.1".to_string()),
            catnip: Some(vec![
                NetworkIdentifier::IpRange("192.168.1.0/24".to_string()),
                NetworkIdentifier::IpRange("10.0.0.0/8".to_string()),
            ]),
            catu: Some(999),
            catm: Some("GET,POST".to_string()),
            catalpn: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
            cath: Some(vec![
                UriPattern::Exact("api.example.com".to_string()),
                UriPattern::Prefix("*.example.org".to_string()),
            ]),
            catgeoiso3166: Some(vec!["US".to_string(), "CA".to_string()]),
            catgeocoord: Some(GeoCoordinate {
                lat: 34.0522,
                lon: -118.2437,
                accuracy: Some(25.5),
            }),
            geohash: Some("9q5ct".to_string()),
            catgeoalt: Some(100),
            cattpk: Some("thumbprint-data".to_string()),
        },
        informational: InformationalClaims {
            sub: None,
            iat: None,
            catifdata: None,
        },
        dpop: DpopClaims {
            cnf: None,
            catdpop: None,
        },
        request: RequestClaims {
            catif: None,
            catr: None,
        },
        custom: std::collections::HashMap::new(),
    };

    let cwt = Cwt::new(-4, token.clone()); // HMAC256
    let encoded_payload = cwt.encode_payload().unwrap();
    let decoded_token = Cwt::decode_payload(&encoded_payload).unwrap();

    // Verify all core claims
    assert_eq!(decoded_token.core.iss, token.core.iss);
    assert_eq!(decoded_token.core.aud, token.core.aud);
    assert_eq!(decoded_token.core.exp, token.core.exp);
    assert_eq!(decoded_token.core.nbf, token.core.nbf);
    assert_eq!(decoded_token.core.cti, token.core.cti);

    // Verify all CAT claims
    assert_eq!(decoded_token.cat.catreplay, token.cat.catreplay);
    assert_eq!(decoded_token.cat.catpor, token.cat.catpor);
    assert_eq!(decoded_token.cat.catv, token.cat.catv);
    assert_eq!(decoded_token.cat.catnip, token.cat.catnip);
    assert_eq!(decoded_token.cat.catu, token.cat.catu);
    assert_eq!(decoded_token.cat.catm, token.cat.catm);
    assert_eq!(decoded_token.cat.catalpn, token.cat.catalpn);
    assert_eq!(decoded_token.cat.cath, token.cat.cath);
    assert_eq!(decoded_token.cat.catgeoiso3166, token.cat.catgeoiso3166);
    assert_eq!(decoded_token.cat.geohash, token.cat.geohash);
    assert_eq!(decoded_token.cat.catgeoalt, token.cat.catgeoalt);
    assert_eq!(decoded_token.cat.cattpk, token.cat.cattpk);

    // Verify geo coordinates
    if let (Some(orig), Some(decoded)) = (&token.cat.catgeocoord, &decoded_token.cat.catgeocoord) {
        assert_eq!(orig.lat, decoded.lat);
        assert_eq!(orig.lon, decoded.lon);
        assert_eq!(orig.accuracy, decoded.accuracy);
    }
}

#[test]
fn test_invalid_signature_verification() {
    let key1 = HmacSha256Algorithm::generate_key();
    let key2 = HmacSha256Algorithm::generate_key();
    let algorithm1 = HmacSha256Algorithm::new(&key1);
    let algorithm2 = HmacSha256Algorithm::new(&key2);
    
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .cwt_id("signature-test")
        .build();

    let encoded = encode_token(&token, &algorithm1).unwrap();
    
    // Try to verify with different key - should fail
    let result = decode_token(&encoded, &algorithm2);
    assert!(matches!(result, Err(CatError::SignatureVerificationFailed)));
}

#[test]
fn test_invalid_token_format() {
    let key = HmacSha256Algorithm::generate_key();
    let algorithm = HmacSha256Algorithm::new(&key);
    
    // Test with wrong number of parts
    let result = decode_token("invalid", &algorithm);
    assert!(matches!(result, Err(CatError::InvalidTokenFormat)));
    
    let result = decode_token("too.few", &algorithm);
    assert!(matches!(result, Err(CatError::InvalidTokenFormat)));
    
    let result = decode_token("too.many.parts.here", &algorithm);
    assert!(matches!(result, Err(CatError::InvalidTokenFormat)));
}

#[test]
fn test_geographic_validation() {
    let validator = CatTokenValidator::new();
    
    // Test invalid coordinates
    let mut token = CatToken::new();
    token.cat.catgeocoord = Some(GeoCoordinate {
        lat: 91.0, // Invalid latitude
        lon: 0.0,
        accuracy: None,
    });
    
    let result = validator.validate(&token);
    assert!(matches!(result, Err(CatError::GeographicValidationFailed(_))));
    
    // Test invalid geohash
    token.cat.catgeocoord = None;
    token.cat.geohash = Some("".to_string()); // Empty geohash
    
    let result = validator.validate(&token);
    assert!(matches!(result, Err(CatError::GeographicValidationFailed(_))));
}